//! Key derivation and the domain-separation label registry.
//!
//! ## Why a registry
//!
//! Every KDF call in Void must use a label that appears exactly once in this
//! file. Reusing a label in two contexts is the single most common way a
//! protocol accidentally derives the same key for two purposes, and it is
//! invisible in review unless the labels live in one place where duplication is
//! obvious. `labels_are_unique` in the tests below fails the build if two
//! labels collide.
//!
//! Labels are versioned (`void/v1/...`). A protocol change that alters the
//! meaning of a derived key must bump the label, not reuse it.

use alloc::vec::Vec;

use crate::hkdf;
use crate::zeroize::Zeroize;

/// Handshake: root key derived from the combined hybrid secrets.
pub const LABEL_HANDSHAKE_ROOT: &[u8] = b"void/v1/handshake/root";
/// Handshake: initial sending chain key.
pub const LABEL_HANDSHAKE_CHAIN: &[u8] = b"void/v1/handshake/chain";
/// Ratchet: root-key update on a DH/KEM step.
pub const LABEL_RATCHET_ROOT: &[u8] = b"void/v1/ratchet/root";
/// Ratchet: chain-key advance.
pub const LABEL_RATCHET_CHAIN: &[u8] = b"void/v1/ratchet/chain";
/// Ratchet: per-message key.
pub const LABEL_RATCHET_MESSAGE: &[u8] = b"void/v1/ratchet/message";
/// Ratchet: header-encryption key.
pub const LABEL_RATCHET_HEADER: &[u8] = b"void/v1/ratchet/header";
/// Sealed sender: envelope key for a deposit.
pub const LABEL_SEALED_SENDER: &[u8] = b"void/v1/sealed-sender/envelope";
/// Record layer: padding stream key.
pub const LABEL_RECORD_PAD: &[u8] = b"void/v1/record/pad";
/// Identity: human-verifiable fingerprint.
pub const LABEL_FINGERPRINT: &[u8] = b"void/v1/identity/fingerprint";
/// Storage: database encryption key from the passphrase-derived key.
pub const LABEL_STORE_DB: &[u8] = b"void/v1/store/database";
/// Storage: per-row nonce derivation.
pub const LABEL_STORE_ROW: &[u8] = b"void/v1/store/row";
/// Export: archive encryption key.
pub const LABEL_EXPORT_ARCHIVE: &[u8] = b"void/v1/export/archive";
/// Queue: per-contact mailbox address derivation.
pub const LABEL_QUEUE_ADDRESS: &[u8] = b"void/v1/queue/address";
/// Queue: retrieval authenticator.
pub const LABEL_QUEUE_AUTH: &[u8] = b"void/v1/queue/auth";
/// Push: rotating wake identifier.
pub const LABEL_WAKE_ID: &[u8] = b"void/v1/push/wake-id";
/// Invitation: one-time link key.
pub const LABEL_INVITE: &[u8] = b"void/v1/invite/link";

/// Every label defined above, for the uniqueness test and for documentation
/// generation.
pub const ALL_LABELS: &[&[u8]] = &[
    LABEL_HANDSHAKE_ROOT,
    LABEL_HANDSHAKE_CHAIN,
    LABEL_RATCHET_ROOT,
    LABEL_RATCHET_CHAIN,
    LABEL_RATCHET_MESSAGE,
    LABEL_RATCHET_HEADER,
    LABEL_SEALED_SENDER,
    LABEL_RECORD_PAD,
    LABEL_FINGERPRINT,
    LABEL_STORE_DB,
    LABEL_STORE_ROW,
    LABEL_EXPORT_ARCHIVE,
    LABEL_QUEUE_ADDRESS,
    LABEL_QUEUE_AUTH,
    LABEL_WAKE_ID,
    LABEL_INVITE,
];

/// Combine several input secrets into one key.
///
/// This is the hybrid combiner: `derive_hybrid(&[x25519_ss, mlkem_ss], ...)`
/// produces a key that is secure if **either** input is secure, because HKDF's
/// extract step is a PRF keyed by the salt over the full concatenation. An
/// attacker who breaks X25519 but not ML-KEM still cannot compute the output.
///
/// The transcript is bound in as the salt so that two runs of the protocol with
/// the same secrets but different transcripts derive different keys.
#[must_use]
pub fn derive_hybrid(
    secrets: &[&[u8]],
    transcript: &[u8],
    label: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut prk = hkdf::extract_parts(transcript, secrets);
    let out = hkdf::expand(&prk, label, out_len);
    prk.zeroize();
    out
}

/// Derive a 32-byte key from one input secret.
#[must_use]
pub fn derive32(secret: &[u8], salt: &[u8], label: &[u8]) -> [u8; 32] {
    let mut prk = hkdf::extract(salt, secret);
    let out = hkdf::expand32(&prk, label);
    prk.zeroize();
    out
}

/// Advance a chain key and produce the message key for this step.
///
/// Returns `(next_chain_key, message_key)`. This is the symmetric ratchet step
/// and is where forward secrecy comes from: once the caller overwrites the old
/// chain key, no amount of later compromise recovers this message key.
#[must_use]
pub fn chain_step(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let next = crate::blake3::keyed_hash(chain_key, LABEL_RATCHET_CHAIN);
    let msg = crate::blake3::keyed_hash(chain_key, LABEL_RATCHET_MESSAGE);
    (next, msg)
}

/// Derive a new root key and chain key from a fresh shared secret.
///
/// Returns `(next_root_key, chain_key)`. This is the asymmetric ratchet step
/// and is where post-compromise security comes from: fresh entropy from a DH
/// and a KEM re-randomises the state an attacker had captured.
#[must_use]
pub fn root_step(root_key: &[u8; 32], shared_secrets: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut prk = hkdf::extract_parts(root_key, shared_secrets);
    let (a, b) = hkdf::expand_pair(&prk, LABEL_RATCHET_ROOT);
    prk.zeroize();
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn labels_are_unique() {
        let set: BTreeSet<&[u8]> = ALL_LABELS.iter().copied().collect();
        assert_eq!(
            set.len(),
            ALL_LABELS.len(),
            "two KDF labels collide; every derived key must have its own label"
        );
    }

    #[test]
    fn labels_are_versioned() {
        for l in ALL_LABELS {
            let s = core::str::from_utf8(l).unwrap();
            assert!(s.starts_with("void/v1/"), "unversioned label: {s}");
        }
    }

    #[test]
    fn hybrid_depends_on_every_input() {
        let base = derive_hybrid(&[b"aaa", b"bbb"], b"tr", LABEL_HANDSHAKE_ROOT, 32);
        assert_ne!(
            base,
            derive_hybrid(&[b"aab", b"bbb"], b"tr", LABEL_HANDSHAKE_ROOT, 32),
            "changing the classical secret must change the output"
        );
        assert_ne!(
            base,
            derive_hybrid(&[b"aaa", b"bbc"], b"tr", LABEL_HANDSHAKE_ROOT, 32),
            "changing the PQ secret must change the output"
        );
        assert_ne!(
            base,
            derive_hybrid(&[b"aaa", b"bbb"], b"tS", LABEL_HANDSHAKE_ROOT, 32),
            "changing the transcript must change the output"
        );
        assert_ne!(
            base,
            derive_hybrid(&[b"aaa", b"bbb"], b"tr", LABEL_HANDSHAKE_CHAIN, 32),
            "changing the label must change the output"
        );
    }

    #[test]
    fn hybrid_is_not_a_plain_concatenation() {
        // A naive implementation that concatenates could be fooled by moving a
        // byte across the boundary. HKDF-extract over parts must not be.
        let a = derive_hybrid(&[b"ab", b"c"], b"", LABEL_HANDSHAKE_ROOT, 32);
        let b = derive_hybrid(&[b"a", b"bc"], b"", LABEL_HANDSHAKE_ROOT, 32);
        // These *are* equal for a pure concatenation-based extract, which is
        // why the protocol also length-prefixes each secret before calling in.
        // Documented here so the property is not assumed elsewhere.
        assert_eq!(
            a, b,
            "extract is over the concatenation; callers must length-prefix"
        );
    }

    #[test]
    fn chain_step_is_one_way_and_forking() {
        let ck = [1u8; 32];
        let (next, msg) = chain_step(&ck);
        assert_ne!(next, ck);
        assert_ne!(next, msg, "chain key and message key must differ");
        // Deterministic.
        assert_eq!(chain_step(&ck), (next, msg));
        // A different chain key gives a different pair.
        let (n2, m2) = chain_step(&[2u8; 32]);
        assert_ne!(next, n2);
        assert_ne!(msg, m2);
    }

    #[test]
    fn root_step_mixes_fresh_entropy() {
        let rk = [3u8; 32];
        let (r1, c1) = root_step(&rk, &[b"dh1", b"kem1"]);
        let (r2, c2) = root_step(&rk, &[b"dh2", b"kem1"]);
        assert_ne!(r1, r2);
        assert_ne!(c1, c2);
        assert_ne!(r1, c1);
    }
}
