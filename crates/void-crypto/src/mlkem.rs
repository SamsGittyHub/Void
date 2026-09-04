//! ML-KEM-1024 (FIPS 203), via the RustCrypto `ml-kem` crate.
//!
//! The post-quantum half of Void's hybrid key agreement (FR-MSG-01). Parameter
//! selection is ML-KEM-1024, per `docs/DECISIONS.md#d-001`: it matches Signal's
//! PQXDH choice of Kyber-1024, and the 1,568-byte ciphertext fits Void's record
//! budget once ML-DSA signatures are confined to the handshake (§13.1 of the
//! PRD, resolved in D-002).
//!
//! ## D-006's migration, landed
//!
//! This module used to be a clean-room implementation written directly from
//! FIPS 203. It is now a thin wrapper over the RustCrypto `ml-kem` crate,
//! which is what NFR-SEC-01 asks for: a widely reviewed implementation of a
//! finalized standard, not a from-scratch one nobody but this codebase has
//! exercised. The clean-room implementation is kept as
//! [`crate::mlkem_reference`], compiled only for tests, and
//! `differential::mlkem` in this crate's test suite runs both against the
//! same inputs and asserts identical outputs — the cheapest way to find out
//! that one of them was wrong.
//!
//! Every function signature here is unchanged from the old implementation.
//! Nothing above this module — not `void-proto`, not the `Kem` trait impl in
//! `traits.rs` — needed to change for the swap.
//!
//! ## The decapsulation key is now a 64-byte seed, not a 3,168-byte expanded key
//!
//! FIPS 203 permits storing either form; the RustCrypto crate's own preferred
//! representation is the seed (`ExpandedKeyEncoding` — the 3,168-byte form —
//! is marked deprecated upstream). The decapsulation key never crosses the
//! wire — only [`ENCAPS_KEY_LEN`]-sized public keys and
//! [`CIPHERTEXT_LEN`]-sized ciphertexts do, both unchanged — so nothing
//! outside this crate depends on the old length, and re-deriving the
//! expanded key from its seed on every use costs nothing that matters: ML-KEM
//! ratchet steps happen every [`KEM_RATCHET_INTERVAL`](void_proto is not a
//! dependency of this crate, see `ratchet.rs`) DH steps, not every message.

use alloc::vec::Vec;

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem1024 as RcMlKem1024, Seed, B32};

use crate::{CryptoError, Result};

/// Encapsulation key length in bytes.
pub const ENCAPS_KEY_LEN: usize = 1568;
/// Decapsulation key length in bytes. The 64-byte seed form — see the module
/// docs for why this is smaller than FIPS 203's expanded-key encoding.
pub const DECAPS_KEY_LEN: usize = 64;
/// Ciphertext length in bytes.
pub const CIPHERTEXT_LEN: usize = 1568;
/// Shared secret length in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// An ML-KEM-1024 key pair.
pub struct KeyPair {
    /// Encapsulation (public) key.
    pub encaps_key: Vec<u8>,
    /// Decapsulation (secret) key — the 64-byte seed it was derived from.
    pub decaps_key: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.decaps_key);
    }
}

fn seed_from_parts(d: &[u8; 32], z: &[u8; 32]) -> Seed {
    let mut seed = Seed::default();
    seed[..32].copy_from_slice(d);
    seed[32..].copy_from_slice(z);
    seed
}

/// Deterministic key generation from the two 32-byte seeds `d` and `z`.
///
/// Exposed so that the handshake can regenerate a key pair from stored seed
/// material without keeping any expanded secret key resident longer than one
/// call needs it.
#[must_use]
pub fn keygen_derand(d: &[u8; 32], z: &[u8; 32]) -> KeyPair {
    let seed = seed_from_parts(d, z);
    let dk = DecapsulationKey::<RcMlKem1024>::from_seed(seed);
    let ek_bytes: Vec<u8> = dk.encapsulation_key().to_bytes().to_vec();
    KeyPair {
        encaps_key: ek_bytes,
        decaps_key: seed.to_vec(),
    }
}

/// Generate a key pair from system entropy.
pub fn keygen() -> Result<KeyPair> {
    let d = crate::rand::bytes32()?;
    let z = crate::rand::bytes32()?;
    Ok(keygen_derand(&d, &z))
}

fn encaps_key_from_bytes(ek: &[u8]) -> Result<EncapsulationKey<RcMlKem1024>> {
    if ek.len() != ENCAPS_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let arr: Array<u8, _> = Array::try_from(ek).map_err(|_| CryptoError::BadLength)?;
    EncapsulationKey::<RcMlKem1024>::new(&arr).map_err(|_| CryptoError::Invalid)
}

/// Validate an encapsulation key per FIPS 203 §7.2.
///
/// `EncapsulationKey::new` performs the modulus check FIPS 203 requires
/// (every packed 12-bit coefficient `< q`) as part of decoding — skipping it
/// is the classic way an implementation accepts a malformed key and produces
/// a shared secret the peer can predict.
pub fn validate_encaps_key(ek: &[u8]) -> Result<()> {
    encaps_key_from_bytes(ek).map(|_| ())
}

/// Deterministic encapsulation, given the 32-byte message `m`.
pub fn encaps_derand(ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    let key = encaps_key_from_bytes(ek)?;
    let m_arr = B32::try_from(m.as_slice()).map_err(|_| CryptoError::BadLength)?;
    let (ct, ss) = key.encapsulate_deterministic(&m_arr);
    let mut shared = [0u8; SHARED_SECRET_LEN];
    shared.copy_from_slice(ss.as_slice());
    Ok((ct.to_vec(), shared))
}

/// Encapsulate to a peer's encapsulation key.
pub fn encaps(ek: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    let m = crate::rand::bytes32()?;
    encaps_derand(ek, &m)
}

/// Decapsulate a ciphertext.
///
/// On any failure — wrong ciphertext, tampered ciphertext, mismatched key —
/// this returns a pseudorandom shared secret derived from the implicit
/// rejection value `z` (FIPS 203 §7.3), *not* an error. That is required: an
/// error here would be a decryption oracle. `ml-kem`'s `Decapsulate` trait is
/// infallible for exactly this reason — there is no `Err` path to reach for.
/// The caller learns that something is wrong only when the resulting session
/// fails to authenticate.
pub fn decaps(dk: &[u8], ct: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
    if dk.len() != DECAPS_KEY_LEN || ct.len() != CIPHERTEXT_LEN {
        return Err(CryptoError::BadLength);
    }
    let seed = Seed::try_from(dk).map_err(|_| CryptoError::BadLength)?;
    let key = DecapsulationKey::<RcMlKem1024>::from_seed(seed);
    let ss = key
        .decapsulate_slice(ct)
        .map_err(|_| CryptoError::BadLength)?;
    let mut shared = [0u8; SHARED_SECRET_LEN];
    shared.copy_from_slice(ss.as_slice());
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let kp = keygen().unwrap();
        assert_eq!(kp.encaps_key.len(), ENCAPS_KEY_LEN);
        assert_eq!(kp.decaps_key.len(), DECAPS_KEY_LEN);
        let (ct, ss1) = encaps(&kp.encaps_key).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        let ss2 = decaps(&kp.decaps_key, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn keygen_derand_is_deterministic() {
        let d = [7u8; 32];
        let z = [9u8; 32];
        let a = keygen_derand(&d, &z);
        let b = keygen_derand(&d, &z);
        assert_eq!(a.encaps_key, b.encaps_key);
        assert_eq!(a.decaps_key, b.decaps_key);
    }

    #[test]
    fn tampered_ciphertext_does_not_error_but_does_not_match() {
        let kp = keygen().unwrap();
        let (mut ct, ss) = encaps(&kp.encaps_key).unwrap();
        ct[0] ^= 1;
        // Implicit rejection: still `Ok`, just a different secret.
        let wrong = decaps(&kp.decaps_key, &ct).unwrap();
        assert_ne!(wrong, ss);
    }

    #[test]
    fn wrong_length_inputs_are_rejected() {
        assert!(matches!(
            validate_encaps_key(&[0u8; 10]),
            Err(CryptoError::BadLength)
        ));
        assert!(matches!(
            decaps(&[0u8; 10], &[0u8; CIPHERTEXT_LEN]),
            Err(CryptoError::BadLength)
        ));
        assert!(matches!(
            decaps(&[0u8; DECAPS_KEY_LEN], &[0u8; 10]),
            Err(CryptoError::BadLength)
        ));
    }

    #[test]
    fn malformed_encaps_key_is_rejected() {
        // Every coefficient at the max 12-bit value is >= q for at least one
        // slot, so this must fail the modulus check FIPS 203 requires.
        let bad = alloc::vec![0xFFu8; ENCAPS_KEY_LEN];
        assert!(validate_encaps_key(&bad).is_err());
    }
}
