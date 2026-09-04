//! HMAC-SHA-256 (RFC 2104) and HMAC-SHA-512.

use crate::sha2::{Sha256, Sha512};

/// HMAC-SHA-256.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[data])
}

/// HMAC-SHA-256 over several parts, avoiding an intermediate concatenation.
#[must_use]
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = Sha256::BLOCK_LEN;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let out = outer.finalize();

    // The pads carry the key; wipe them.
    crate::zeroize::Zeroize::zeroize(&mut k);
    crate::zeroize::Zeroize::zeroize(&mut ipad);
    crate::zeroize::Zeroize::zeroize(&mut opad);
    out
}

/// HMAC-SHA-512.
#[must_use]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK: usize = Sha512::BLOCK_LEN;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..64].copy_from_slice(&Sha512::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha512::digest_parts(&[&ipad, data]);
    let out = Sha512::digest_parts(&[&opad, &inner]);
    crate::zeroize::Zeroize::zeroize(&mut k);
    crate::zeroize::Zeroize::zeroize(&mut ipad);
    crate::zeroize::Zeroize::zeroize(&mut opad);
    out
}

/// Constant-time HMAC verification. Always use this rather than comparing
/// tags with `==`.
#[must_use]
pub fn verify_sha256(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    crate::ct::eq(&hmac_sha256(key, data), tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::hex;

    #[test]
    fn rfc4231_case_1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha512(&key, b"Hi There")),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn rfc4231_case_2() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_case_3_long_key() {
        let key = [0xaau8; 131];
        assert_eq!(
            hex(&hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn parts_matches_concatenated() {
        let k = b"key";
        assert_eq!(
            hmac_sha256_parts(k, &[b"foo", b"bar"]),
            hmac_sha256(k, b"foobar")
        );
    }

    #[test]
    fn verify_rejects_tampered_tag() {
        let k = b"key";
        let mut tag = hmac_sha256(k, b"msg");
        assert!(verify_sha256(k, b"msg", &tag));
        tag[0] ^= 1;
        assert!(!verify_sha256(k, b"msg", &tag));
        assert!(!verify_sha256(k, b"msg", &tag[..16]));
    }
}
