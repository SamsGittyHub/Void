//! Constant-time helpers.
//!
//! NFR-SEC-03 requires that every secret-dependent operation runs in time
//! independent of the secret. Rust's `==` on slices short-circuits, so it must
//! never be used on key material, MACs, or plaintext-derived values.
//!
//! These helpers are written without `unsafe` and rely on `black_box` to stop
//! LLVM from reintroducing a branch. That is a best-effort guarantee at the
//! language level — the CI `dudect` job (see `.github/workflows/ci.yml`) is
//! what actually measures it on the built artifact.

use core::hint::black_box;

/// Constant-time equality for byte slices of equal length.
///
/// Returns `false` immediately for differing lengths — length is not secret in
/// any of Void's uses, and every record on the wire is a fixed size anyway
/// (FR-MSG-02).
#[must_use]
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    black_box(acc) == 0
}

/// Returns `0xFF` if `a == b`, else `0x00`. Branch-free.
#[must_use]
pub fn byte_eq_mask(a: u8, b: u8) -> u8 {
    let x = a ^ b;
    // x == 0  =>  (x | -x) >> 7 == 0
    let nz = (x | x.wrapping_neg()) >> 7; // 1 if x != 0, else 0
    nz.wrapping_sub(1)
}

/// Constant-time select: returns `a` if `choice` is 1, `b` if `choice` is 0.
///
/// `choice` must be exactly 0 or 1; other values produce garbage rather than a
/// panic, because panicking on a secret-derived value is itself a side channel.
#[must_use]
pub fn select_u8(choice: u8, a: u8, b: u8) -> u8 {
    let mask = choice.wrapping_neg(); // 0x00 or 0xFF
    b ^ (mask & (a ^ b))
}

/// Constant-time select over 32-bit words.
#[must_use]
pub fn select_u32(choice: u32, a: u32, b: u32) -> u32 {
    let mask = choice.wrapping_neg();
    b ^ (mask & (a ^ b))
}

/// Conditionally swap two byte arrays in constant time.
pub fn cswap(choice: u8, a: &mut [u8], b: &mut [u8]) {
    debug_assert_eq!(a.len(), b.len());
    let mask = choice.wrapping_neg();
    for i in 0..a.len().min(b.len()) {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Constant-time check that a slice is all zero.
#[must_use]
pub fn is_zero(a: &[u8]) -> bool {
    let mut acc = 0u8;
    for &x in a {
        acc |= x;
    }
    black_box(acc) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_matches_semantics() {
        assert!(eq(b"abc", b"abc"));
        assert!(!eq(b"abc", b"abd"));
        assert!(!eq(b"abc", b"ab"));
        assert!(eq(b"", b""));
    }

    #[test]
    fn masks_and_selects() {
        assert_eq!(byte_eq_mask(7, 7), 0xFF);
        assert_eq!(byte_eq_mask(7, 8), 0x00);
        assert_eq!(select_u8(1, 0xAA, 0xBB), 0xAA);
        assert_eq!(select_u8(0, 0xAA, 0xBB), 0xBB);
        assert_eq!(select_u32(1, 1234, 5678), 1234);
        assert_eq!(select_u32(0, 1234, 5678), 5678);
    }

    #[test]
    fn conditional_swap() {
        let (mut a, mut b) = ([1u8, 2, 3], [4u8, 5, 6]);
        cswap(0, &mut a, &mut b);
        assert_eq!((a, b), ([1, 2, 3], [4, 5, 6]));
        cswap(1, &mut a, &mut b);
        assert_eq!((a, b), ([4, 5, 6], [1, 2, 3]));
    }

    #[test]
    fn zero_detection() {
        assert!(is_zero(&[0, 0, 0]));
        assert!(!is_zero(&[0, 1, 0]));
    }
}
