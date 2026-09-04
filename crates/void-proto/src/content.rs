//! What a decrypted message actually contains.
//!
//! Before calls existed, a ratchet plaintext was a bare UTF-8 string and the
//! receiver simply assumed so. That works exactly until something other than
//! text needs to travel the same way, at which point "assume it is text" turns
//! every non-text message into either a decoding error or, worse, mojibake
//! shown to a user as if a contact had sent it.
//!
//! So a plaintext now carries a one-byte kind ahead of its body. This is a
//! wire-format change with no backward compatibility, which is why
//! [`crate::handshake::PROTOCOL_ID`] changed with it: two clients that
//! disagree about this framing must fail to handshake rather than succeed and
//! then misread each other.
//!
//! ## Why the kind is inside the encryption
//!
//! It would be marginally simpler to put a content type in the record header,
//! where fragmentation could see it. It would also tell the relay which of
//! your messages are calls. The kind byte is inside the ratchet ciphertext, so
//! a signalling message and a text message are identical on the wire, in size
//! and in every observable field.

use alloc::string::String;
use alloc::vec::Vec;

use crate::call::CallSignal;
use crate::{ProtoError, Result};

/// The kind byte prefixed to every ratchet plaintext.
const KIND_TEXT: u8 = 1;
const KIND_CALL: u8 = 2;

/// A decrypted message's contents.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Content {
    /// An ordinary text message.
    Text(String),
    /// Call setup or teardown. Never shown to the user as a message.
    Call(CallSignal),
}

impl Content {
    /// Frame this content for encryption.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Content::Text(t) => {
                out.push(KIND_TEXT);
                out.extend_from_slice(t.as_bytes());
            }
            Content::Call(signal) => {
                out.push(KIND_CALL);
                out.extend_from_slice(&signal.encode());
            }
        }
        out
    }

    /// Parse a decrypted plaintext.
    ///
    /// An unknown kind is an error rather than something to skip past: a
    /// future version's message type must surface as "this client cannot read
    /// that" and not be silently dropped, which would look to the sender like
    /// delivery.
    pub fn decode(bytes: &[u8]) -> Result<Content> {
        let (&kind, body) = bytes.split_first().ok_or(ProtoError::Malformed)?;
        match kind {
            KIND_TEXT => {
                let text = core::str::from_utf8(body).map_err(|_| ProtoError::Malformed)?;
                Ok(Content::Text(String::from(text)))
            }
            KIND_CALL => Ok(Content::Call(CallSignal::decode(body)?)),
            _ => Err(ProtoError::Malformed),
        }
    }

    /// Convenience for the common case.
    #[must_use]
    pub fn text(s: &str) -> Content {
        Content::Text(String::from(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::{CallEnd, CallOffer, EndReason};

    #[test]
    fn text_roundtrips() {
        let c = Content::text("hello, and also 🜃");
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn an_empty_text_message_survives() {
        let c = Content::text("");
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn call_signals_roundtrip() {
        let offer = CallOffer::new("abc.onion", 9999).unwrap();
        let c = Content::Call(CallSignal::Offer(offer));
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);

        let e = Content::Call(CallSignal::End(CallEnd {
            call_id: [4u8; 16],
            reason: EndReason::HungUp,
        }));
        assert_eq!(Content::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn a_call_signal_is_never_mistaken_for_text() {
        // The failure this framing exists to prevent: signalling bytes shown
        // to a user as a message from their contact.
        let offer = CallOffer::new("abc.onion", 1).unwrap();
        let encoded = Content::Call(CallSignal::Offer(offer)).encode();
        match Content::decode(&encoded).unwrap() {
            Content::Call(_) => {}
            Content::Text(t) => panic!("signalling decoded as text: {t:?}"),
        }
    }

    #[test]
    fn an_empty_plaintext_is_malformed() {
        assert!(Content::decode(&[]).is_err());
    }

    #[test]
    fn an_unknown_kind_is_an_error_not_a_silent_drop() {
        assert!(Content::decode(&[99, 1, 2, 3]).is_err());
    }

    #[test]
    fn invalid_utf8_in_a_text_message_is_refused() {
        assert!(Content::decode(&[KIND_TEXT, 0xff, 0xfe]).is_err());
    }

    #[test]
    fn text_and_call_of_the_same_length_are_indistinguishable_in_shape() {
        // Both are "one kind byte then a body" — nothing about the framing
        // itself separates them, which is what keeps the relay unable to tell
        // a call from a message.
        let a = Content::text("xxxx").encode();
        assert_eq!(a[0], KIND_TEXT);
        let b = Content::Call(CallSignal::End(CallEnd {
            call_id: [0u8; 16],
            reason: EndReason::Missed,
        }))
        .encode();
        assert_eq!(b[0], KIND_CALL);
    }
}
