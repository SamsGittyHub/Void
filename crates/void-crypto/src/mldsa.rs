//! ML-DSA-87 (FIPS 204), via the RustCrypto `ml-dsa` crate.
//!
//! The post-quantum half of Void's hybrid identity signature (FR-ID-01),
//! confined to the handshake and key-change events by `docs/DECISIONS.md#d-002`
//! — its 4,627-byte signature is too large to carry on every message.
//!
//! ## D-006's migration, landed
//!
//! This module used to be a clean-room implementation written directly from
//! FIPS 204. It is now a thin wrapper over the RustCrypto `ml-dsa` crate — see
//! `mlkem.rs`'s module docs for the reasoning, which applies identically
//! here. The clean-room implementation is kept as
//! [`crate::mldsa_reference`], compiled only for tests, and exercised by this
//! crate's differential tests.
//!
//! ## The secret key is now a 32-byte seed, not a 4,896-byte expanded key
//!
//! Same story as `mlkem.rs`'s decapsulation key: FIPS 204 permits storing
//! either the seed or the expanded signing key, the RustCrypto crate's
//! preferred representation is the seed, and the secret key never crosses
//! the wire — only [`PUBLIC_KEY_LEN`]-sized public keys and
//! [`SIGNATURE_LEN`]-sized signatures do, both unchanged. Signing re-derives
//! the expanded key from the seed each call, which costs nothing that
//! matters given D-002 already confines signing to rare events.
//!
//! ## Deterministic signing, not hedged (`docs/DECISIONS.md#d-018`)
//!
//! The old implementation's public `sign()` used FIPS 204's *hedged*
//! variant — a fresh random value mixed into every signature, defending
//! against fault-injection attacks. The RustCrypto crate's ergonomic
//! `Signer` implementation uses the *deterministic* variant instead (FIPS
//! 204 permits both). Fault injection is a threat model for smartcards and
//! HSMs under physical attacker control, not a phone running Void, so this
//! module follows the crate's default rather than bridging a custom RNG
//! adapter into `ExpandedSigningKey`'s randomized-signing path for a
//! property outside Void's threat model. See D-018 for the full reasoning
//! and how to reverse it if that judgement ever changes.

use alloc::vec::Vec;

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{MlDsa87 as RcMlDsa87, Seed, Signature, SigningKey, VerifyingKey};

use crate::{CryptoError, Result};

/// Public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 2592;
/// Secret key length in bytes — the 32-byte seed form; see the module docs.
pub const SECRET_KEY_LEN: usize = 32;
/// Signature length in bytes.
pub const SIGNATURE_LEN: usize = 4627;

/// An ML-DSA-87 key pair.
pub struct KeyPair {
    /// Public verification key.
    pub public: Vec<u8>,
    /// Secret signing key — the 32-byte seed it was derived from.
    pub secret: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

/// Deterministic key generation from a 32-byte seed.
#[must_use]
pub fn keygen_derand(xi: &[u8; 32]) -> KeyPair {
    let seed = Seed::from(*xi);
    let sk = SigningKey::<RcMlDsa87>::from_seed(&seed);
    let public = sk.verifying_key().encode().to_vec();
    KeyPair {
        public,
        secret: seed.to_vec(),
    }
}

/// Generate a key pair from system entropy.
pub fn keygen() -> Result<KeyPair> {
    Ok(keygen_derand(&crate::rand::bytes32()?))
}

/// Sign `message` with an empty context string, using ML-DSA's deterministic
/// variant (see the module docs on why this module does not offer the
/// hedged variant).
pub fn sign(sk: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != SECRET_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(sk);
    let seed = Seed::from(seed_bytes);
    let key = SigningKey::<RcMlDsa87>::from_seed(&seed);
    let sig: Signature<RcMlDsa87> = key.sign(message);
    Ok(sig.encode().to_vec())
}

/// Verify a signature produced by `sign`.
#[must_use]
pub fn verify(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    if pk.len() != PUBLIC_KEY_LEN || sig.len() != SIGNATURE_LEN {
        return false;
    }
    let Ok(pk_arr) = pk.try_into() else {
        return false;
    };
    let vk = VerifyingKey::<RcMlDsa87>::decode(&pk_arr);
    let Ok(sig_obj) = Signature::<RcMlDsa87>::try_from(sig) else {
        return false;
    };
    vk.verify(message, &sig_obj).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let kp = keygen().unwrap();
        assert_eq!(kp.public.len(), PUBLIC_KEY_LEN);
        assert_eq!(kp.secret.len(), SECRET_KEY_LEN);
        let sig = sign(&kp.secret, b"message").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(&kp.public, b"message", &sig));
        assert!(!verify(&kp.public, b"different", &sig));
    }

    #[test]
    fn keygen_derand_is_deterministic() {
        let seed = [11u8; 32];
        let a = keygen_derand(&seed);
        let b = keygen_derand(&seed);
        assert_eq!(a.public, b.public);
        assert_eq!(a.secret, b.secret);
    }

    #[test]
    fn signing_is_deterministic() {
        // Not required by FIPS 204 in general, but true of this module's
        // chosen variant (see the module docs) and worth pinning: it is what
        // makes the differential test's byte-for-byte comparison meaningful.
        let kp = keygen_derand(&[3u8; 32]);
        let a = sign(&kp.secret, b"m").unwrap();
        let b = sign(&kp.secret, b"m").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn tampering_is_rejected() {
        let kp = keygen().unwrap();
        let mut sig = sign(&kp.secret, b"m").unwrap();
        sig[0] ^= 1;
        assert!(!verify(&kp.public, b"m", &sig));
    }

    #[test]
    fn malformed_inputs_do_not_panic() {
        assert!(!verify(b"short", b"m", b"short"));
        assert!(sign(b"short", b"m").is_err());
    }
}
