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
    /// A conversation with this identity already exists.
    ///
    /// Starting a second one would replace the session on this side only: the
    /// peer keeps the first, the two ends derive different queues, and every
    /// message after that silently fails to arrive. Refusing is the only safe
    /// answer; the user can revoke the contact and start again deliberately.
    AlreadyConnected,
    /// The invitation is this engine's own. A handshake with ourselves would
    /// leave both halves of one session keyed by the same fingerprint.
    OwnInvite,
    /// The invitation link is not a Void invitation, or did not decrypt or
    /// verify.
    InvalidInvite,
    /// The invitation has expired.
    InviteExpired,
    /// The invitation is parked on a different relay from the one this engine
    /// uses, so it cannot be collected from here.
    WrongRelay,
    /// No invitation with that id is open.
    NoSuchInvite,
    /// A call is already in progress with that contact.
    CallInProgress,
    /// No call is in progress with that contact.
    NoSuchCall,
    /// System entropy was unavailable.
    Entropy,
    /// A file is larger than one message can carry
    /// (`void_proto::content::MAX_FILE_BYTES`), or its name or type is too
    /// long. Refused before any ratchet state is spent on it.
    TooLarge,
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
            ClientError::AlreadyConnected => "already connected to this person",
            ClientError::OwnInvite => "this is your own invitation",
            ClientError::InvalidInvite => "this is not a valid Void invitation",
            ClientError::InviteExpired => "this invitation has expired",
            ClientError::WrongRelay => "this invitation is on a different relay",
            ClientError::NoSuchInvite => "no such invitation",
            ClientError::CallInProgress => "already on a call with this contact",
            ClientError::NoSuchCall => "no call in progress with this contact",
            ClientError::Entropy => "system entropy unavailable",
            ClientError::TooLarge => "this file is too large to send in one message",
            ClientError::Storage => "local storage failed to read, write, or authenticate",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ClientError {}

/// Result alias for this crate.
pub type ClientResult<T> = Result<T, ClientError>;
