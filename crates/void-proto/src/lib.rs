//! # void-proto
//!
//! Void's wire protocol: identity, handshake, ratchet, records, queues, and
//! sealed deposits. This crate is pure logic — it performs no I/O, holds no
//! sockets, and knows nothing about Tor, relays, or storage. That separation is
//! deliberate: it means the whole protocol can be exercised by tests in
//! microseconds and audited without reasoning about concurrency.
//!
//! ## The shape of the system
//!
//! ```text
//!   Alice                        Relay (untrusted)                     Bob
//!   -----                        -----------------                     ---
//!   handshake::initiate
//!   ratchet::encrypt
//!   envelope::seal      --deposit(queue_id, sealed)-->  [queue_id] --> retrieve
//!                                                                      envelope::open
//!                                                                      ratchet::decrypt
//! ```
//!
//! The relay sees a queue identifier and a fixed-size opaque blob. It does not
//! see who deposited, cannot link two queues to one user, and cannot read
//! anything (G2, FR-MSG-03, FR-MSG-04).
//!
//! ## Module map
//!
//! | Module | PRD requirement |
//! |---|---|
//! | [`identity`] | FR-ID-01, FR-ID-04, FR-ID-05 |
//! | [`fingerprint`] | FR-ID-03, FR-DISC-04 |
//! | [`handshake`] | FR-MSG-01, FR-DISC-03 |
//! | [`ratchet`] | FR-MSG-01 |
//! | [`record`] | FR-MSG-02, FR-MSG-06 |
//! | [`envelope`] | FR-MSG-03 |
//! | [`queue`] | FR-MSG-04, FR-ABUSE-02, FR-ABUSE-03 |
//! | [`invite`] | FR-DISC-01, FR-DISC-02 |
//! | [`wake`] | FR-NOTIF-03 |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod call;
pub mod content;
pub mod envelope;
pub mod fingerprint;
pub mod handshake;
pub mod identity;
pub mod invite;
pub mod queue;
pub mod ratchet;
pub mod record;
pub mod wake;
pub mod wire;

/// Errors from protocol operations.
///
/// These are coarser than the internal failure modes on purpose. A caller —
/// and therefore anything observable to a peer — must not be able to tell a
/// bad MAC from a bad key from a bad length, because that distinction is a
/// decryption oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// The input did not parse as the expected structure.
    Malformed,
    /// A signature did not verify.
    BadSignature,
    /// A key was structurally invalid or degenerate.
    InvalidKey,
    /// Authenticated decryption failed.
    DecryptionFailed,
    /// The session is not in a state where this operation is defined — for
    /// example, sending before the handshake has produced a sending chain.
    NotReady,
    /// A peer asked us to skip more message keys than [`ratchet::MAX_SKIP`],
    /// or to retain more than [`ratchet::MAX_SKIPPED_STORED`].
    TooManySkipped,
    /// A payload did not fit the fixed record size, or fragments were
    /// inconsistent.
    RecordError,
    /// The underlying cryptographic primitive failed, including entropy
    /// failure. Void fails closed on this.
    Crypto,
    /// A one-time value (invitation, one-time prekey) was already used.
    AlreadyUsed,
    /// A value has passed its expiry.
    Expired,
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            ProtoError::Malformed => "malformed input",
            ProtoError::BadSignature => "signature verification failed",
            ProtoError::InvalidKey => "invalid key",
            ProtoError::DecryptionFailed => "decryption failed",
            ProtoError::NotReady => "session not ready for this operation",
            ProtoError::TooManySkipped => "too many skipped messages",
            ProtoError::RecordError => "record framing error",
            ProtoError::Crypto => "cryptographic operation failed",
            ProtoError::AlreadyUsed => "one-time value already used",
            ProtoError::Expired => "expired",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ProtoError {}

impl From<void_crypto::CryptoError> for ProtoError {
    fn from(e: void_crypto::CryptoError) -> Self {
        match e {
            void_crypto::CryptoError::BadLength => ProtoError::Malformed,
            _ => ProtoError::Crypto,
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, ProtoError>;

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u16 = 1;
