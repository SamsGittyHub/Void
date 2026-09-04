//! # void-store
//!
//! Void's encrypted local storage, hardware key wrapping, duress destruction,
//! retention, and encrypted export.
//!
//! ## The requirement this crate exists to satisfy
//!
//! FR-STOR-02: a user under duress must be able to make their message history
//! permanently and unrecoverably unreadable in under 500 ms, from the lock
//! screen, with no interruption possible. Everything else here is arranged
//! around making that both true and fast:
//!
//! - The database is encrypted under a data-encryption key (DEK).
//! - The DEK is wrapped by a key the Secure Enclave or StrongBox holds and will
//!   not export ([`vault`]).
//! - Duress destroys the *wrapping* key. That is one operation, and it makes
//!   every byte of the database undecryptable — including bytes already copied
//!   elsewhere on the device, and bytes in a backup, if one somehow exists.
//!
//! ## What this crate does not do
//!
//! It does not provide plausible deniability, and it does not hide that a Void
//! database exists. PRD §7.4.1 gives four independent reasons, any one of which
//! is sufficient, and the strongest is that the feature would make users' legal
//! position *worse* in the jurisdictions where it matters most. The replacement
//! is short default retention plus fast destruction, and the honest sentence
//! the user is shown is in [`vault::DURESS_DISCLOSURE`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod db;
pub mod export;
pub mod model;
pub mod retention;
pub mod vault;

/// Errors from the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The backing store could not be read or written.
    Io,
    /// The stored bytes failed authentication or did not parse.
    ///
    /// NFR-REL-03: corruption never yields plaintext. This error means the
    /// database stayed encrypted, which is the correct outcome.
    Corrupt,
    /// The on-disk format is from a newer version.
    UnsupportedVersion,
    /// The hardware key is gone. After a duress destruction this is permanent.
    VaultDestroyed,
    /// The database is locked in memory and refuses operations.
    Locked,
    /// No such record.
    NotFound,
    /// A key could not be derived from the supplied material.
    KeyDerivation,
    /// The system entropy source failed. Void fails closed.
    Entropy,
    /// A configuration was rejected — for example a duress PIN equal to the
    /// unlock PIN.
    InvalidConfiguration,
    /// A protocol structure could not be encoded or decoded.
    Encoding,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            StoreError::Io => "storage could not be read or written",
            StoreError::Corrupt => "stored data failed authentication",
            StoreError::UnsupportedVersion => "database format is from a newer version",
            StoreError::VaultDestroyed => "the hardware key is gone; this data is unrecoverable",
            StoreError::Locked => "the database is locked",
            StoreError::NotFound => "no such record",
            StoreError::KeyDerivation => "key derivation failed",
            StoreError::Entropy => "system entropy unavailable",
            StoreError::InvalidConfiguration => "invalid configuration",
            StoreError::Encoding => "encoding error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for StoreError {}

impl From<void_proto::ProtoError> for StoreError {
    fn from(_: void_proto::ProtoError) -> Self {
        StoreError::Encoding
    }
}

/// Result alias for this crate.
pub type StoreResult<T> = Result<T, StoreError>;
