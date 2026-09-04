//! Differential tests: the RustCrypto-backed `mlkem`/`mldsa` against the
//! clean-room implementations they replaced (`docs/DECISIONS.md#d-006`).
//!
//! The premise: two independent implementations of the same finalized
//! standard (FIPS 203, FIPS 204), fed the same deterministic inputs, must
//! produce identical outputs. Running both and asserting agreement is the
//! cheapest way to find out that one of them is wrong — cheaper than waiting
//! for ACVP vectors, and it catches a different class of bug than either
//! implementation's own round-trip tests do, because a symmetric bug (the
//! same mistake made the same way on both the encrypt and decrypt side of
//! one implementation) does not show up as a self-inconsistency.
//!
//! If any test in this file ever fails, the reference implementation is the
//! one to suspect first: it has never been validated against ACVP vectors,
//! and the RustCrypto crate has. Fix or delete the reference implementation;
//! do not "fix" the audited crate to match it.
//!
//! Key material formats differ between the two implementations by design —
//! `mlkem`'s decapsulation key is now a 64-byte seed where the reference's is
//! a 3,168-byte expanded key, and similarly for `mldsa`'s secret key (see
//! each module's docs) — so these tests compare the values that *are*
//! required to match bit-for-bit by the standard (public keys, ciphertexts,
//! shared secrets, deterministic signatures), and cross-verify the rest
//! (sign with one implementation, verify with the other) rather than
//! comparing internal representations that were never meant to agree.

use alloc::vec::Vec;

use crate::{mldsa, mldsa_reference, mlkem, mlkem_reference};

#[test]
fn mlkem_keygen_produces_the_same_encapsulation_key() {
    // KeyGen is a deterministic function of (d, z) per FIPS 203 — two correct
    // implementations must derive the same public key from the same seeds,
    // even though their private-key *storage* formats differ.
    for (d, z) in [
        ([1u8; 32], [2u8; 32]),
        ([0u8; 32], [0xFFu8; 32]),
        ([42u8; 32], [7u8; 32]),
    ] {
        let new = mlkem::keygen_derand(&d, &z);
        let reference = mlkem_reference::keygen_derand(&d, &z);
        assert_eq!(
            new.encaps_key, reference.encaps_key,
            "encapsulation keys diverged for seeds {d:?} / {z:?}"
        );
    }
}

#[test]
fn mlkem_encapsulation_produces_the_same_ciphertext_and_secret() {
    // Encapsulation is a deterministic function of (ek, m) per FIPS 203.
    let (d, z) = ([5u8; 32], [6u8; 32]);
    let ek = mlkem::keygen_derand(&d, &z).encaps_key.clone();
    let m = [9u8; 32];

    let (ct_new, ss_new) = mlkem::encaps_derand(&ek, &m).unwrap();
    let (ct_ref, ss_ref) = mlkem_reference::encaps_derand(&ek, &m).unwrap();

    assert_eq!(ct_new, ct_ref, "ciphertexts diverged");
    assert_eq!(ss_new, ss_ref, "shared secrets diverged");
}

#[test]
fn mlkem_decapsulation_agrees_across_implementations() {
    // Each implementation decapsulates with its own key (different storage
    // formats derived from the same seeds), and both must recover the exact
    // shared secret the other implementation's encapsulation produced.
    let (d, z) = ([11u8; 32], [12u8; 32]);
    let new_kp = mlkem::keygen_derand(&d, &z);
    let ref_kp = mlkem_reference::keygen_derand(&d, &z);
    assert_eq!(new_kp.encaps_key, ref_kp.encaps_key);

    let m = [13u8; 32];
    let (ct, expected_secret) = mlkem::encaps_derand(&new_kp.encaps_key, &m).unwrap();

    let recovered_by_new = mlkem::decaps(&new_kp.decaps_key, &ct).unwrap();
    let recovered_by_reference = mlkem_reference::decaps(&ref_kp.decaps_key, &ct).unwrap();

    assert_eq!(recovered_by_new, expected_secret);
    assert_eq!(recovered_by_reference, expected_secret);
}

#[test]
fn mlkem_implicit_rejection_agrees_on_a_tampered_ciphertext() {
    // Both implementations must silently substitute a pseudorandom secret
    // (FIPS 203 §7.3) for a tampered ciphertext rather than erroring — and,
    // since the implicit-rejection value is derived only from `z` and the
    // ciphertext, both must derive the *same* substitute secret when given
    // the same `z` and the same tampered bytes.
    let (d, z) = ([21u8; 32], [22u8; 32]);
    let new_kp = mlkem::keygen_derand(&d, &z);
    let ref_kp = mlkem_reference::keygen_derand(&d, &z);

    let m = [23u8; 32];
    let (mut ct, _) = mlkem::encaps_derand(&new_kp.encaps_key, &m).unwrap();
    ct[0] ^= 1;

    let new_rejected = mlkem::decaps(&new_kp.decaps_key, &ct).unwrap();
    let reference_rejected = mlkem_reference::decaps(&ref_kp.decaps_key, &ct).unwrap();
    assert_eq!(new_rejected, reference_rejected);
}

#[test]
fn mldsa_keygen_produces_the_same_public_key() {
    // KeyGen is a deterministic function of the seed per FIPS 204.
    for seed in [[1u8; 32], [0u8; 32], [0xFFu8; 32], [77u8; 32]] {
        let new = mldsa::keygen_derand(&seed);
        let reference = mldsa_reference::keygen_derand(&seed);
        assert_eq!(
            new.public, reference.public,
            "public keys diverged for seed {seed:?}"
        );
    }
}

#[test]
fn mldsa_deterministic_signatures_match_byte_for_byte() {
    // `mldsa::sign` uses FIPS 204's deterministic variant (D-018).
    // `mldsa_reference::sign_with_rnd` with an all-zero randomizer is that
    // same variant. Same key, same message, same variant: the signatures
    // must be identical, not merely both-valid.
    let seed = [31u8; 32];
    let new_kp = mldsa::keygen_derand(&seed);
    let ref_kp = mldsa_reference::keygen_derand(&seed);
    assert_eq!(new_kp.public, ref_kp.public);

    let message = b"the package is ready";
    let sig_new = mldsa::sign(&new_kp.secret, message).unwrap();
    let sig_ref = mldsa_reference::sign_with_rnd(&ref_kp.secret, message, &[0u8; 32]).unwrap();

    assert_eq!(sig_new, sig_ref, "deterministic signatures diverged");
}

#[test]
fn mldsa_signatures_cross_verify() {
    // Independent of whether the bytes match: a signature produced by one
    // implementation must verify under the other's `verify`, and vice versa.
    let seed = [41u8; 32];
    let new_kp = mldsa::keygen_derand(&seed);
    let ref_kp = mldsa_reference::keygen_derand(&seed);
    let message = b"cross-verification message";

    let sig_new = mldsa::sign(&new_kp.secret, message).unwrap();
    let sig_ref = mldsa_reference::sign_with_rnd(&ref_kp.secret, message, &[0u8; 32]).unwrap();

    assert!(mldsa_reference::verify(&ref_kp.public, message, &sig_new));
    assert!(mldsa::verify(&new_kp.public, message, &sig_ref));

    // And each implementation still verifies its own signature, obviously —
    // stated here so a failure above is read as a cross-compatibility bug,
    // not written off as "verify is broken".
    assert!(mldsa::verify(&new_kp.public, message, &sig_new));
    assert!(mldsa_reference::verify(&ref_kp.public, message, &sig_ref));
}

#[test]
fn mldsa_reference_entropy_based_convenience_functions_still_work() {
    // `mldsa_reference::keygen`/`sign` (system entropy, hedged) have no
    // caller left now that `traits.rs` points at the new `mldsa` module —
    // they used to be reachable from production code, and now they are
    // reachable only from here. Exercising them keeps the reference module
    // honest as a whole, not just its `_derand`/`_with_rnd` seams.
    let kp = mldsa_reference::keygen().unwrap();
    let sig = mldsa_reference::sign(&kp.secret, b"m").unwrap();
    assert!(mldsa_reference::verify(&kp.public, b"m", &sig));
}

#[test]
fn mldsa_a_tampered_signature_is_rejected_by_both() {
    let seed = [51u8; 32];
    let new_kp = mldsa::keygen_derand(&seed);
    let message = b"m";
    let mut sig: Vec<u8> = mldsa::sign(&new_kp.secret, message).unwrap();
    sig[0] ^= 1;
    assert!(!mldsa::verify(&new_kp.public, message, &sig));
    assert!(!mldsa_reference::verify(&new_kp.public, message, &sig));
}
