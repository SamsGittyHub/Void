//! HKDF-SHA-256 (RFC 5869).
//!
//! This is the KDF for the Double Ratchet chains in `void-proto::ratchet`,
//! matching the Signal specification. Every call site must supply a distinct,
//! hardcoded `info` label — see `void-crypto::kdf` for the label registry.

use alloc::vec::Vec;

use crate::hmac::hmac_sha256_parts;

/// HKDF-Extract: compress input keying material into a fixed-size PRK.
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(salt, &[ikm])
}

/// HKDF-Extract over several IKM parts. Used by the hybrid handshake, which
/// concatenates an X25519 shared secret and an ML-KEM shared secret.
#[must_use]
pub fn extract_parts(salt: &[u8], ikm_parts: &[&[u8]]) -> [u8; 32] {
    hmac_sha256_parts(salt, ikm_parts)
}

/// HKDF-Expand.
///
/// # Panics
/// Panics if `out_len > 255 * 32`, which is a programming error rather than an
/// attacker-controllable condition.
#[must_use]
pub fn expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    assert!(out_len <= 255 * 32, "hkdf: output too long");
    let mut out = Vec::with_capacity(out_len);
    let mut t: [u8; 32] = [0u8; 32];
    let mut counter: u8 = 1;
    let mut first = true;
    while out.len() < out_len {
        let block = if first {
            first = false;
            hmac_sha256_parts(prk, &[info, &[counter]])
        } else {
            hmac_sha256_parts(prk, &[&t, info, &[counter]])
        };
        t = block;
        let take = core::cmp::min(32, out_len - out.len());
        out.extend_from_slice(&t[..take]);
        counter = counter.wrapping_add(1);
    }
    crate::zeroize::Zeroize::zeroize(&mut t);
    out
}

/// Expand into a fixed-size 32-byte key.
#[must_use]
pub fn expand32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let v = expand(prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Expand into two 32-byte keys at once. This is the shape the ratchet needs
/// (next chain key + message key) and doing it in one call avoids a caller
/// splitting the buffer wrongly.
#[must_use]
pub fn expand_pair(prk: &[u8; 32], info: &[u8]) -> ([u8; 32], [u8; 32]) {
    let v = expand(prk, info, 64);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&v[..32]);
    b.copy_from_slice(&v[32..]);
    (a, b)
}

/// One-shot extract-then-expand.
#[must_use]
pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut prk = extract(salt, ikm);
    let out = expand(&prk, info, out_len);
    crate::zeroize::Zeroize::zeroize(&mut prk);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::{hex, unhex};

    #[test]
    fn rfc5869_test_case_1() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = unhex("000102030405060708090a0b0c").unwrap();
        let info = unhex("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let prk = extract(&salt, &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = expand(&prk, &info, 42);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn rfc5869_test_case_3_empty_salt_and_info() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let prk = extract(&[], &ikm);
        assert_eq!(
            hex(&prk),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );
        let okm = expand(&prk, &[], 42);
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn expand_pair_matches_manual_split() {
        let prk = [3u8; 32];
        let (a, b) = expand_pair(&prk, b"info");
        let v = expand(&prk, b"info", 64);
        assert_eq!(&a[..], &v[..32]);
        assert_eq!(&b[..], &v[32..]);
    }

    #[test]
    fn distinct_info_gives_distinct_output() {
        let prk = [3u8; 32];
        assert_ne!(expand32(&prk, b"a"), expand32(&prk, b"b"));
    }
}
