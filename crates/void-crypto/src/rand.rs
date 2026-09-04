//! System entropy.
//!
//! Void's rule is that randomness comes from the operating system CSPRNG and
//! from nowhere else. There is no userspace PRNG to be seeded badly, no
//! fallback to a timestamp, and no "if the OS source fails, use this instead"
//! path — an entropy failure returns `CryptoError::NoEntropy` and the caller
//! fails closed. This mirrors non-negotiable #5: when the secure path is
//! unavailable, Void stops rather than degrading.
//!
//! On iOS and Android the FFI layer overrides this with `SecRandomCopyBytes`
//! and `/dev/urandom` respectively via the platform hooks in `void-ffi`; the
//! implementation here is what the Rust core, CLI, and tests use.

use crate::{CryptoError, Result};

/// Fill `buf` with cryptographically secure random bytes.
#[cfg(feature = "std")]
pub fn fill(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    // `/dev/urandom` is the correct choice on every platform Void targets:
    // after boot it is seeded and never blocks, and it is the same pool as
    // `getrandom(2)`. `/dev/random` would add blocking without adding entropy.
    let mut f = std::fs::File::open("/dev/urandom").map_err(|_| CryptoError::NoEntropy)?;
    f.read_exact(buf).map_err(|_| CryptoError::NoEntropy)?;
    Ok(())
}

#[cfg(not(feature = "std"))]
pub fn fill(_buf: &mut [u8]) -> Result<()> {
    // In `no_std` builds the embedder must supply entropy through the FFI
    // hook; there is no ambient source we are willing to guess at.
    Err(CryptoError::NoEntropy)
}

/// Return a fresh 32-byte random array.
pub fn bytes32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    fill(&mut b)?;
    Ok(b)
}

/// Return a fresh 16-byte random array.
pub fn bytes16() -> Result<[u8; 16]> {
    let mut b = [0u8; 16];
    fill(&mut b)?;
    Ok(b)
}

/// Return a fresh 24-byte random array (an XChaCha nonce).
pub fn bytes24() -> Result<[u8; 24]> {
    let mut b = [0u8; 24];
    fill(&mut b)?;
    Ok(b)
}

/// A uniformly random `u64`.
pub fn u64_() -> Result<u64> {
    let mut b = [0u8; 8];
    fill(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// A uniformly random value in `0..bound`, without modulo bias.
///
/// Used by the send scheduler's jitter (FR-MSG-07); bias there would be a
/// weak but real timing fingerprint.
pub fn below(bound: u64) -> Result<u64> {
    assert!(bound > 0, "rand::below: bound must be positive");
    if bound.is_power_of_two() {
        return Ok(u64_()? & (bound - 1));
    }
    // Rejection sampling against the largest multiple of `bound` that fits.
    let limit = u64::MAX - (u64::MAX % bound) - 1;
    loop {
        let v = u64_()?;
        if v <= limit {
            return Ok(v % bound);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_values() {
        let a = bytes32().unwrap();
        let b = bytes32().unwrap();
        assert_ne!(a, b, "two draws must not collide");
        assert!(!crate::ct::is_zero(&a), "draw must not be all zero");
    }

    #[test]
    fn below_respects_bound() {
        for bound in [1u64, 2, 3, 7, 16, 1000] {
            for _ in 0..200 {
                assert!(below(bound).unwrap() < bound);
            }
        }
    }

    #[test]
    fn below_covers_range() {
        let mut seen = [false; 8];
        for _ in 0..500 {
            seen[below(8).unwrap() as usize] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "sampler must cover the whole range"
        );
    }
}
