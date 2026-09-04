//! ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305.
//!
//! Void uses XChaCha20-Poly1305 everywhere a nonce might be chosen randomly
//! (storage records, sealed-sender envelopes) because its 192-bit nonce makes
//! random nonce collision negligible. It uses the 96-bit-nonce RFC 8439 variant
//! only where a counter is available and unambiguous (the ratchet, where the
//! message number *is* the nonce).
//!
//! ## Nonce discipline
//!
//! Reusing a (key, nonce) pair with ChaCha20-Poly1305 is catastrophic: it leaks
//! the XOR of two plaintexts and, worse, allows tag forgery for that key. Every
//! constructor here takes the nonce explicitly rather than managing a counter
//! internally, so that the nonce-uniqueness argument lives at the call site
//! where a reviewer can check it. `void-proto` documents the argument for each.

use alloc::vec::Vec;

use crate::chacha;
use crate::poly1305::Poly1305;
use crate::{CryptoError, Result};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length for the RFC 8439 variant.
pub const NONCE_LEN: usize = 12;
/// Nonce length for the extended-nonce variant.
pub const XNONCE_LEN: usize = 24;
/// Authentication tag length.
pub const TAG_LEN: usize = 16;

fn poly_key(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let b = chacha::block(key, 0, nonce);
    let mut k = [0u8; 32];
    k.copy_from_slice(&b[..32]);
    k
}

fn mac_over(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let mut p = Poly1305::new(otk);
    p.update(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    p.update(&[0u8; 16][..aad_pad]);
    p.update(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    p.update(&[0u8; 16][..ct_pad]);
    p.update(&(aad.len() as u64).to_le_bytes());
    p.update(&(ciphertext.len() as u64).to_le_bytes());
    p.finalize()
}

/// Encrypt in place, appending the tag. `buf` grows by `TAG_LEN`.
pub fn seal_in_place(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut Vec<u8>) {
    let mut otk = poly_key(key, nonce);
    chacha::apply_keystream(key, 1, nonce, buf);
    let tag = mac_over(&otk, aad, buf);
    buf.extend_from_slice(&tag);
    crate::zeroize::Zeroize::zeroize(&mut otk);
}

/// Encrypt, returning ciphertext || tag.
#[must_use]
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = plaintext.to_vec();
    seal_in_place(key, nonce, aad, &mut buf);
    buf
}

/// Decrypt ciphertext || tag. Returns `Invalid` on any authentication failure.
///
/// The plaintext is only written out after the tag verifies, so a caller can
/// never accidentally act on unauthenticated data.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    if sealed.len() < TAG_LEN {
        return Err(CryptoError::Invalid);
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let mut otk = poly_key(key, nonce);
    let expected = mac_over(&otk, aad, ct);
    crate::zeroize::Zeroize::zeroize(&mut otk);
    if !crate::ct::eq(&expected, tag) {
        return Err(CryptoError::Invalid);
    }
    let mut pt = ct.to_vec();
    chacha::apply_keystream(key, 1, nonce, &mut pt);
    Ok(pt)
}

/// XChaCha20-Poly1305 seal with a 24-byte nonce.
#[must_use]
pub fn xseal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let (subkey, subnonce) = xchacha_split(key, nonce);
    let out = seal(&subkey, &subnonce, aad, plaintext);
    let mut sk = subkey;
    crate::zeroize::Zeroize::zeroize(&mut sk);
    out
}

/// XChaCha20-Poly1305 open with a 24-byte nonce.
pub fn xopen(
    key: &[u8; KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let (subkey, subnonce) = xchacha_split(key, nonce);
    let out = open(&subkey, &subnonce, aad, sealed);
    let mut sk = subkey;
    crate::zeroize::Zeroize::zeroize(&mut sk);
    out
}

fn xchacha_split(
    key: &[u8; KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
) -> ([u8; KEY_LEN], [u8; NONCE_LEN]) {
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&nonce[..16]);
    let subkey = chacha::hchacha20(key, &n16);
    let mut subnonce = [0u8; NONCE_LEN];
    subnonce[4..].copy_from_slice(&nonce[16..]);
    (subkey, subnonce)
}

/// Build a 12-byte nonce from a 64-bit counter, with the top 4 bytes zero.
///
/// Used by the ratchet, where the nonce is the message number and uniqueness
/// follows from the chain key never being reused (see `void-proto::ratchet`).
#[must_use]
pub fn nonce_from_counter(counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::{hex, unhex};

    #[test]
    fn rfc8439_aead_vector() {
        let key =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let nonce = unhex("070000004041424344454647").unwrap();
        let mut n = [0u8; 12];
        n.copy_from_slice(&nonce);
        let aad = unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = seal(&k, &n, &aad, pt);
        assert_eq!(hex(&sealed[..16]), "d31a8d34648e60db7b86afbc53ef7ec2");
        assert_eq!(
            hex(&sealed[sealed.len() - 16..]),
            "1ae10b594f09e26a7e902ecbd0600691"
        );
        assert_eq!(open(&k, &n, &aad, &sealed).unwrap(), pt.to_vec());
    }

    #[test]
    fn tamper_is_rejected_everywhere() {
        let k = [1u8; 32];
        let n = [2u8; 12];
        let sealed = seal(&k, &n, b"aad", b"secret");
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(open(&k, &n, b"aad", &bad).is_err(), "byte {i} not detected");
        }
        assert!(open(&k, &n, b"different aad", &sealed).is_err());
        assert!(open(&[9u8; 32], &n, b"aad", &sealed).is_err());
        let mut n2 = n;
        n2[0] ^= 1;
        assert!(open(&k, &n2, b"aad", &sealed).is_err());
    }

    #[test]
    fn truncated_input_rejected() {
        let k = [1u8; 32];
        let n = [2u8; 12];
        assert!(open(&k, &n, b"", b"").is_err());
        assert!(open(&k, &n, b"", &[0u8; 15]).is_err());
    }

    #[test]
    fn xchacha_roundtrip_and_tamper() {
        let k = [3u8; 32];
        let n = [4u8; 24];
        let sealed = xseal(&k, &n, b"hdr", b"payload");
        assert_eq!(xopen(&k, &n, b"hdr", &sealed).unwrap(), b"payload".to_vec());
        let mut bad = sealed.clone();
        bad[0] ^= 0x80;
        assert!(xopen(&k, &n, b"hdr", &bad).is_err());
    }

    #[test]
    fn empty_plaintext_still_authenticates() {
        let k = [1u8; 32];
        let n = [2u8; 12];
        let sealed = seal(&k, &n, b"aad", b"");
        assert_eq!(sealed.len(), TAG_LEN);
        assert!(open(&k, &n, b"aad", &sealed).unwrap().is_empty());
        assert!(open(&k, &n, b"bad", &sealed).is_err());
    }

    #[test]
    fn counter_nonce_is_injective() {
        assert_ne!(nonce_from_counter(0), nonce_from_counter(1));
        assert_eq!(nonce_from_counter(1)[11], 1);
    }
}
