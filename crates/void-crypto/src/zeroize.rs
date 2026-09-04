//! Memory zeroization.
//!
//! FR-ID-02 requires that plaintext key material exists in process memory only
//! for the duration of an operation and is wiped immediately after.
//!
//! ## What this can and cannot promise
//!
//! The `zeroize` crate normally uses `write_volatile` to stop the optimizer
//! eliding a write to memory that is about to be freed. Void's core is
//! `#![forbid(unsafe_code)]` (NFR-SEC-02), so this module uses a safe
//! construction instead: overwrite, then pass a reference through
//! `black_box`, which is an optimization barrier the compiler must not see
//! through.
//!
//! What neither approach can promise, and what FR-ID-02a requires us to state
//! plainly: this does not reach copies the allocator, the scheduler, or the OS
//! made elsewhere — register spills, swap, or a core dump. Zeroization narrows
//! the window in which key material is recoverable from a live process. It does
//! not close it. The guarantee users are given is "not extractable from a
//! locked device", which rests on the Secure Enclave wrap in `void-store`, not
//! on this file.

use alloc::vec::Vec;
use core::hint::black_box;
use core::ops::{Deref, DerefMut};

/// Types whose memory can be wiped.
pub trait Zeroize {
    /// Overwrite the contents with zeroes.
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        for b in self.iter_mut() {
            *b = 0;
        }
        // Optimization barrier: the compiler cannot prove the zeroed buffer is
        // unobserved, so it cannot delete the loop above.
        let _ = black_box(&*self);
    }
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
        self.clear();
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Zeroize for u32 {
    fn zeroize(&mut self) {
        *self = 0;
        let _ = black_box(&*self);
    }
}

impl Zeroize for u64 {
    fn zeroize(&mut self) {
        *self = 0;
        let _ = black_box(&*self);
    }
}

// Rust has no specialization on stable, so a blanket `impl<T: Zeroize>
// Zeroize for Vec<T>` would collide with the `Vec<u8>` impl above. We provide
// the concrete container impls the protocol actually uses instead.
impl Zeroize for Vec<Vec<u8>> {
    fn zeroize(&mut self) {
        for item in self.iter_mut() {
            item.zeroize();
        }
        self.clear();
    }
}

impl Zeroize for Vec<[u8; 32]> {
    fn zeroize(&mut self) {
        for item in self.iter_mut() {
            item.zeroize();
        }
        self.clear();
    }
}

/// A wrapper that zeroizes its contents when dropped.
///
/// Use this for every intermediate secret: shared secrets, chain keys, message
/// keys, decrypted plaintext that is about to be handed to storage.
#[derive(Clone)]
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    /// Wrap a value so it is wiped on drop.
    pub fn new(value: T) -> Self {
        Zeroizing(value)
    }

    /// Consume the wrapper and return the inner value.
    ///
    /// The caller becomes responsible for wiping it. Named to be conspicuous
    /// in review.
    pub fn into_inner_unprotected(self) -> T
    where
        T: Clone,
    {
        // Clone before `Drop` runs, since dropping the wrapper would wipe the
        // value we are handing out.
        self.0.clone()
    }
}

impl<T: Zeroize> Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + core::fmt::Debug> core::fmt::Debug for Zeroizing<T> {
    /// Never prints the secret. A `Debug` impl that dumps key material into a
    /// log is one of the most common ways real products leak keys.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Zeroizing(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn array_is_wiped() {
        let mut k = [1u8; 32];
        k.zeroize();
        assert_eq!(k, [0u8; 32]);
    }

    #[test]
    fn vec_is_wiped_and_cleared() {
        let mut v = vec![9u8; 64];
        v.zeroize();
        assert!(v.is_empty());
    }

    #[test]
    fn debug_does_not_leak() {
        let z = Zeroizing::new([0xABu8; 32]);
        let s = alloc::format!("{:?}", z);
        assert!(!s.contains("171") && !s.contains("ab"));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn deref_works() {
        let z = Zeroizing::new([7u8; 4]);
        assert_eq!(z[0], 7);
    }
}
