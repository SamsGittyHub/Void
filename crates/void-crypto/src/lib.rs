//! # void-crypto
//!
//! Cryptographic primitives for Void.
//!
//! ## Scope and honesty statement
//!
//! Per NFR-SEC-01 every algorithm here is a finalized standard or a widely
//! reviewed construction. There is **no novel cryptography**: no new modes, no
//! new curves, no "improved" KDF chains. What is novel is only the *assembly*
//! of these standard pieces, which is what `void-proto` documents and what an
//! auditor reviews.
//!
//! ## What is implemented here
//!
//! | Primitive | Standard | Status |
//! |---|---|---|
//! | SHA-256 / SHA-512 | FIPS 180-4 | validated against published digests |
//! | SHA3-256 / SHAKE-128 / SHAKE-256 | FIPS 202 | validated against published digests |
//! | BLAKE2b | RFC 7693 | validated against published digests |
//! | BLAKE3 (hash + keyed + derive_key) | BLAKE3 spec | validated against published digests |
//! | HMAC-SHA-256, HKDF-SHA-256 | RFC 2104 / RFC 5869 | validated against RFC vectors |
//! | ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305 | RFC 8439 | validated against RFC vectors |
//! | X25519 | RFC 7748 | validated against RFC vectors |
//! | Ed25519 | RFC 8032 | validated against RFC vectors |
//! | Argon2id | RFC 9106 | validated against RFC vector |
//! | ML-KEM-1024 | FIPS 203 | RustCrypto `ml-kem` — see below |
//! | ML-DSA-87 | FIPS 204 | RustCrypto `ml-dsa` — see below |
//!
//! ## The post-quantum implementations (`docs/DECISIONS.md#d-006`)
//!
//! `mlkem` and `mldsa` are thin wrappers over the RustCrypto `ml-kem` and
//! `ml-dsa` crates — widely reviewed implementations of finalized standards,
//! which is what NFR-SEC-01 asks every algorithm in this crate to be. They
//! are not this codebase's own implementations, and this codebase does not
//! claim to have validated them against NIST's ACVP vector set itself; that
//! is upstream's claim to make, not this one's.
//!
//! What *was* here through most of this project's development — a
//! clean-room implementation written directly from FIPS 203 and FIPS 204 —
//! is kept as `mlkem_reference` and `mldsa_reference`, compiled only for
//! tests, purely as a differential-test oracle: `differential.rs` runs both
//! implementations against the same deterministic inputs and asserts
//! agreement, which is what actually gives this migration confidence rather
//! than just moving the warning to a different paragraph. It passes.
//!
//! Everything above the `Kem` and `SignatureScheme` traits — all of
//! `void-proto` and everything built on it — is written against `mlkem` and
//! `mldsa`'s function signatures, not their internals, so this migration
//! touched no protocol code. It did change two things a reader of
//! `void-proto` should know: the ML-KEM decapsulation key and the ML-DSA
//! secret key are now stored as their 64-byte and 32-byte seeds rather than
//! their expanded forms (see each module's docs — neither ever crossed the
//! wire, so nothing interoperability-relevant changed), and ML-DSA signing
//! is now deterministic rather than hedged (`docs/DECISIONS.md#d-018`).
//!
//! `scripts/check_deps.sh` enforces the allow-list this migration required:
//! exactly `ml-kem` and `ml-dsa`, exact-version-pinned, and nothing else.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
// These lints are correct for ordinary Rust and wrong here.
//
// `needless_range_loop` wants iterator adapters where this crate writes
// `for i in 0..8 { h[i] = ... }`. Every such loop transcribes a line of FIPS
// 180-4, FIPS 202, FIPS 203, FIPS 204, or an RFC, and the indexed form is what
// a reviewer checking the code against the standard needs to see. Rewriting
// them as zips would make the correspondence unverifiable, which for a
// from-scratch cryptographic implementation is a worse outcome than a lint.
//
// `should_implement_trait` fires on `Fe::add`, `Fe::sub`, `Fe::neg` and their
// Edwards counterparts. Those names are the mathematical operations they
// implement. Implementing `std::ops::Add` instead would let field arithmetic be
// written with `+`, which reads well and hides exactly the reduction steps that
// have to be auditable.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::should_implement_trait)]

extern crate alloc;

pub mod aead;
pub mod argon2;
pub mod blake2b;
pub mod blake3;
pub mod chacha;
pub mod ct;
#[cfg(test)]
mod differential;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod kdf;
pub mod mldsa;
/// The clean-room ML-DSA-87 implementation `mldsa` used to be, kept only as a
/// differential-test oracle (`docs/DECISIONS.md#d-006`). Not compiled outside
/// tests: it has no reason to ship.
#[cfg(test)]
mod mldsa_reference;
pub mod mlkem;
/// The clean-room ML-KEM-1024 implementation `mlkem` used to be, kept only as
/// a differential-test oracle (`docs/DECISIONS.md#d-006`). Not compiled
/// outside tests: it has no reason to ship.
#[cfg(test)]
mod mlkem_reference;
pub mod poly1305;
pub mod rand;
pub mod sha2;
pub mod sha3;
pub mod traits;
pub mod x25519;
pub mod zeroize;

pub use traits::{Kem, SignatureScheme};
pub use zeroize::{Zeroize, Zeroizing};

/// Errors returned by primitives in this crate.
///
/// Deliberately coarse. A caller must not be able to distinguish *why* a
/// decryption failed, because that distinction is exactly what padding-oracle
/// and invalid-curve attacks feed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Authentication failed, or the input was malformed. These are one error
    /// on purpose.
    Invalid,
    /// An input buffer had the wrong length for the algorithm.
    BadLength,
    /// The system entropy source was unavailable. Fail closed; never fall back
    /// to a weaker source.
    NoEntropy,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::Invalid => f.write_str("invalid ciphertext or input"),
            CryptoError::BadLength => f.write_str("incorrect input length"),
            CryptoError::NoEntropy => f.write_str("system entropy source unavailable"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, CryptoError>;
