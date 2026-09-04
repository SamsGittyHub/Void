//! Algorithm-agnostic traits.
//!
//! These exist for one reason: the crate-level warning says the ML-KEM and
//! ML-DSA implementations must be replaced with ACVP-validated crates before
//! production. Every consumer in `void-proto` and above is written against
//! these traits, so that swap is a one-line change in `void-crypto` and touches
//! no protocol code.
//!
//! They also make the hybrid construction explicit: `HybridKem` is not a KEM
//! that *might* be post-quantum, it is a KEM whose shared secret is the KDF of
//! both a classical and a post-quantum secret, so an attacker must break both.

use alloc::vec::Vec;

use crate::Result;

/// A key-encapsulation mechanism.
pub trait Kem {
    /// Length of an encapsulation (public) key.
    const ENCAPS_KEY_LEN: usize;
    /// Length of a decapsulation (secret) key.
    const DECAPS_KEY_LEN: usize;
    /// Length of a ciphertext.
    const CIPHERTEXT_LEN: usize;
    /// Length of a shared secret.
    const SHARED_SECRET_LEN: usize;

    /// Generate a key pair, returning `(encaps_key, decaps_key)`.
    fn keygen() -> Result<(Vec<u8>, Vec<u8>)>;

    /// Encapsulate to a peer's key, returning `(ciphertext, shared_secret)`.
    fn encaps(encaps_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate a ciphertext.
    fn decaps(decaps_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// A digital signature scheme.
pub trait SignatureScheme {
    /// Length of a public key.
    const PUBLIC_KEY_LEN: usize;
    /// Length of a secret key.
    const SECRET_KEY_LEN: usize;
    /// Length of a signature.
    const SIGNATURE_LEN: usize;

    /// Generate a key pair, returning `(public, secret)`.
    fn keygen() -> Result<(Vec<u8>, Vec<u8>)>;

    /// Sign a message.
    fn sign(secret: &[u8], message: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature. Never returns an error: a malformed key or
    /// signature is simply invalid, and distinguishing the two is a side
    /// channel with no legitimate use.
    fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// ML-KEM-1024 as a [`Kem`].
pub struct MlKem1024;

impl Kem for MlKem1024 {
    const ENCAPS_KEY_LEN: usize = crate::mlkem::ENCAPS_KEY_LEN;
    const DECAPS_KEY_LEN: usize = crate::mlkem::DECAPS_KEY_LEN;
    const CIPHERTEXT_LEN: usize = crate::mlkem::CIPHERTEXT_LEN;
    const SHARED_SECRET_LEN: usize = crate::mlkem::SHARED_SECRET_LEN;

    fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
        let kp = crate::mlkem::keygen()?;
        Ok((kp.encaps_key.clone(), kp.decaps_key.clone()))
    }

    fn encaps(encaps_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ct, ss) = crate::mlkem::encaps(encaps_key)?;
        Ok((ct, ss.to_vec()))
    }

    fn decaps(decaps_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(crate::mlkem::decaps(decaps_key, ciphertext)?.to_vec())
    }
}

/// ML-DSA-87 as a [`SignatureScheme`].
pub struct MlDsa87;

impl SignatureScheme for MlDsa87 {
    const PUBLIC_KEY_LEN: usize = crate::mldsa::PUBLIC_KEY_LEN;
    const SECRET_KEY_LEN: usize = crate::mldsa::SECRET_KEY_LEN;
    const SIGNATURE_LEN: usize = crate::mldsa::SIGNATURE_LEN;

    fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
        let kp = crate::mldsa::keygen()?;
        Ok((kp.public.clone(), kp.secret.clone()))
    }

    fn sign(secret: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        crate::mldsa::sign(secret, message)
    }

    fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
        crate::mldsa::verify(public, message, signature)
    }
}

/// Ed25519 as a [`SignatureScheme`].
pub struct Ed25519;

impl SignatureScheme for Ed25519 {
    const PUBLIC_KEY_LEN: usize = crate::ed25519::PUBLIC_KEY_LEN;
    const SECRET_KEY_LEN: usize = crate::ed25519::SECRET_KEY_LEN;
    const SIGNATURE_LEN: usize = crate::ed25519::SIGNATURE_LEN;

    fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
        let sk = crate::ed25519::SigningKey::generate()?;
        Ok((sk.public.to_vec(), sk.seed().to_vec()))
    }

    fn sign(secret: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        if secret.len() != 32 {
            return Err(crate::CryptoError::BadLength);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(secret);
        Ok(crate::ed25519::SigningKey::from_seed(seed)
            .sign(message)
            .to_vec())
    }

    fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if public.len() != 32 || signature.len() != 64 {
            return false;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(public);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature);
        crate::ed25519::verify(&pk, message, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_trait_roundtrips() {
        let (ek, dk) = MlKem1024::keygen().unwrap();
        assert_eq!(ek.len(), MlKem1024::ENCAPS_KEY_LEN);
        assert_eq!(dk.len(), MlKem1024::DECAPS_KEY_LEN);
        let (ct, ss) = MlKem1024::encaps(&ek).unwrap();
        assert_eq!(ct.len(), MlKem1024::CIPHERTEXT_LEN);
        assert_eq!(MlKem1024::decaps(&dk, &ct).unwrap(), ss);
    }

    #[test]
    fn signature_traits_roundtrip() {
        let (pk, sk) = Ed25519::keygen().unwrap();
        let sig = Ed25519::sign(&sk, b"m").unwrap();
        assert!(Ed25519::verify(&pk, b"m", &sig));
        assert!(!Ed25519::verify(&pk, b"n", &sig));

        let (pk, sk) = MlDsa87::keygen().unwrap();
        let sig = MlDsa87::sign(&sk, b"m").unwrap();
        assert!(MlDsa87::verify(&pk, b"m", &sig));
        assert!(!MlDsa87::verify(&pk, b"n", &sig));
    }

    #[test]
    fn malformed_inputs_do_not_panic() {
        assert!(!Ed25519::verify(b"short", b"m", b"short"));
        assert!(!MlDsa87::verify(b"short", b"m", b"short"));
        assert!(Ed25519::sign(b"short", b"m").is_err());
    }
}
