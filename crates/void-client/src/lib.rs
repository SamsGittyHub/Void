//! # void-client
//!
//! The client engine: transport abstraction, send scheduler, sessions, and
//! contact management.
//!
//! ## The three rules this crate enforces
//!
//! 1. **Fail closed.** If Tor is unavailable, messages queue. There is no
//!    fallback path, and [`transport::Transport`] has no method that could
//!    provide one (FR-TRANS-05, non-negotiable #5).
//! 2. **Constant rate.** Emission timing does not depend on whether the user is
//!    sending anything ([`scheduler`], FR-MSG-06).
//! 3. **Key changes block.** A contact whose identity key changed cannot be
//!    messaged until the user acknowledges it, enforced in exactly one place
//!    ([`engine::Engine::send`], FR-DISC-05).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod engine;
pub mod scheduler;
pub mod transport;

/// Errors from the client engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// Tor (or the configured transport) could not be reached.
    ///
    /// This is not a failure the caller should work around. It means "queue and
    /// retry", and any code that responds to it by trying another network path
    /// is a bug in the security model, not a resilience improvement.
    TorUnavailable,
    /// A protocol structure failed to encode, decode, or authenticate.
    Protocol,
    /// The engine was built in enforcing mode with a non-Tor transport.
    InsecureTransport,
    /// No session exists for that fingerprint.
    NoSuchContact,
    /// The contact's identity key changed; sending is blocked until the user
    /// acknowledges it (FR-DISC-05).
    ContactKeyChanged,
    /// A prekey bundle failed signature verification.
    UnverifiedBundle,
    /// An initial message arrived for a bundle we do not hold secrets for —
    /// typically because the one-time prekey was already consumed
    /// (FR-DISC-02).
    UnknownBundle,
    /// A call is already in progress with that contact.
    CallInProgress,
    /// No call is in progress with that contact.
    NoSuchCall,
    /// System entropy was unavailable.
    Entropy,
    /// The local encrypted store failed to read, write, or authenticate a
    /// record — including a persisted record that failed to decode, which
    /// means the same thing corruption at the store layer does.
    Storage,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            ClientError::TorUnavailable => "cannot reach the network over Tor; messages are queued",
            ClientError::Protocol => "protocol error",
            ClientError::InsecureTransport => {
                "refusing to run in enforcing mode over a non-Tor transport"
            }
            ClientError::NoSuchContact => "no such contact",
            ClientError::ContactKeyChanged => {
                "this contact's security code changed; check with them before sending"
            }
            ClientError::UnverifiedBundle => "the invitation's signature did not verify",
            ClientError::UnknownBundle => "this invitation has already been used",
            ClientError::CallInProgress => "already on a call with this contact",
            ClientError::NoSuchCall => "no call in progress with this contact",
            ClientError::Entropy => "system entropy unavailable",
            ClientError::Storage => "local storage failed to read, write, or authenticate",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ClientError {}

/// Result alias for this crate.
pub type ClientResult<T> = Result<T, ClientError>;
