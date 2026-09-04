//! # void-relay
//!
//! An untrusted mailbox relay.
//!
//! ## What "untrusted" means here, precisely
//!
//! PRD §2.4: *"A relay that is fully compromised learns that some anonymous
//! party deposited a fixed-size blob into queue `X` and that some anonymous
//! party later collected it. It does not learn who either party is, and it
//! cannot join queue `X` to queue `Y`."*
//!
//! That is the entire security claim for this crate, and it is met by
//! *omission*: the relay is not trusted to behave well, it is built so that
//! behaving badly gains it nothing. [`store::QueueStore`] holds the complete
//! list of what a seized relay yields, and its module documentation enumerates
//! what must never be added to it.
//!
//! ## Threading model
//!
//! One thread per connection, standard-library sockets, no async runtime. This
//! is not a performance-optimal choice and it is deliberate: NFR-SEC-07 makes
//! every dependency in the trusted path expensive to justify, and an async
//! runtime is a very large one. A relay serves fixed-size frames over Tor,
//! where circuit latency dominates by orders of magnitude, so thread-per-
//! connection is comfortably sufficient. `docs/DECISIONS.md#d-008`.
//!
//! ## Deployment
//!
//! The relay listens on a Tor onion service. Clients authenticate the relay by
//! pinned onion key (FR-TRANS-04) — the onion address *is* the public key, so
//! there is no certificate authority anywhere in the design. The relay never
//! learns a client IP because Tor does not give it one.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod protocol;
pub mod server;
pub mod store;

/// Errors from the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// The frame did not parse.
    Malformed,
    /// The operation was refused.
    ///
    /// One error for every refusal — bad proof, unknown queue, rate limit,
    /// capacity. A relay that distinguished them would be an oracle for
    /// probing which queues exist and how busy they are.
    Refused,
    /// Entropy was unavailable. The relay fails closed.
    Entropy,
    /// A socket error.
    Io,
}

impl core::fmt::Display for RelayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            RelayError::Malformed => "malformed frame",
            RelayError::Refused => "refused",
            RelayError::Entropy => "entropy unavailable",
            RelayError::Io => "io error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for RelayError {}

/// Result alias for this crate.
pub type RelayResult<T> = Result<T, RelayError>;
