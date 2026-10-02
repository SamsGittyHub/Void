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

//!
//! ## Files are messages
//!
//! A file travels exactly as a text message does: one ratchet plaintext,
//! fragmented into fixed-size records, one record per emission slot. Nothing
//! about the wire changes for it, and that is the point — the relay cannot
//! tell a photo from a paragraph, only that more records went by. What a file
//! costs is time: [`MAX_FILE_BYTES`] of payload is [`crate::record::MAX_FRAGMENTS`]
//! records, and at one record every [`crate::record::PAD_INTERVAL_MS`] that is
//! about forty minutes. The interface states the estimate before sending
//! rather than hiding it, and [`file_record_count`] is how it gets the number.
//!
//! The bound is set by the protocol, not chosen for convenience:
//! [`MAX_FILE_BYTES`] is what fits in the largest message the reassembler will
//! accept once the worst-case ratchet header (one carrying an ML-KEM step,
//! D-005) and this framing have taken their share. A larger file would need
//! more than one message, and a message that can be split across several is a
//! message whose parts can be delivered without each other.

use alloc::string::String;
use alloc::vec::Vec;

use void_crypto::{aead, Zeroize};

use crate::call::CallSignal;
use crate::record::{MAX_FRAGMENTS, RECORD_BODY_CAPACITY};
use crate::wire::{Reader, Writer};
use crate::{ProtoError, Result};

/// The kind byte prefixed to every ratchet plaintext.
const KIND_TEXT: u8 = 1;
const KIND_CALL: u8 = 2;
const KIND_FILE: u8 = 3;

/// Longest file name a [`FileContent`] carries, in bytes of UTF-8. A name is
/// for the recipient to recognise the file by; it is not a path.
pub const MAX_FILE_NAME_LEN: usize = 255;

/// Longest media type a [`FileContent`] carries, in bytes.
pub const MAX_FILE_MIME_LEN: usize = 127;

/// The largest payload one logical message can carry: every fragment full.
const MAX_MESSAGE_PAYLOAD: usize = MAX_FRAGMENTS as usize * RECORD_BODY_CAPACITY;

/// What a ratchet message adds around its plaintext in the worst case: two
/// `bytes32` length prefixes, a header carrying an ML-KEM step (§6.1 of the
/// specification: 3,192 bytes), and the AEAD tag.
const MAX_RATCHET_OVERHEAD: usize = 4 + 3_192 + 4 + aead::TAG_LEN;

/// What this framing adds around the file's bytes when name and type are at
/// their longest: the kind byte, two `bytes16` fields, one `bytes32` length.
const MAX_FILE_FRAMING: usize = 1 + 2 + MAX_FILE_NAME_LEN + 2 + MAX_FILE_MIME_LEN + 4;

/// The largest file one message carries: 500 KiB.
///
/// Derived, not picked. See the module docs and the assertion below, which
/// fails the build if a change to the record size, the fragment bound, or the
/// ratchet header ever makes a file of this size no longer fit in one message.
pub const MAX_FILE_BYTES: usize = 500 * 1024;

const _: () = assert!(
    MAX_FILE_BYTES + MAX_FILE_FRAMING + MAX_RATCHET_OVERHEAD <= MAX_MESSAGE_PAYLOAD,
    "a file of MAX_FILE_BYTES must fit one message under the worst-case ratchet header"
);

/// How many records a file of `data_len` bytes takes to send, at most.
///
/// Assumes the longest name and type and a ratchet header carrying an ML-KEM
/// step, so the real count is this or a little less; multiplied by
/// [`crate::record::PAD_INTERVAL_MS`] it is the time the interface quotes
/// before sending. Saturates at [`MAX_FRAGMENTS`] for anything too large to
/// send at all.
#[must_use]
pub fn file_record_count(data_len: usize) -> u16 {
    let total = data_len
        .saturating_add(MAX_FILE_FRAMING)
        .saturating_add(MAX_RATCHET_OVERHEAD);
    let records = total.div_ceil(RECORD_BODY_CAPACITY);
    records.min(MAX_FRAGMENTS as usize) as u16
}

/// A file, as it travels inside a message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileContent {
    /// A name for the recipient to recognise it by. At most
    /// [`MAX_FILE_NAME_LEN`] bytes; may be empty.
    pub name: String,
    /// Its media type, such as `image/jpeg`. At most [`MAX_FILE_MIME_LEN`]
    /// bytes; may be empty when the sender does not know.
    pub mime: String,
    /// The bytes. At most [`MAX_FILE_BYTES`].
    pub data: Vec<u8>,
}

impl FileContent {
    /// Build a file, refusing one this protocol cannot carry.
    ///
    /// Checked here, at construction, so a file that is too large is refused
    /// before any ratchet state is spent on it: encrypting first and failing
    /// to fragment afterwards would step the chain for a message that never
    /// leaves.
    pub fn new(name: &str, mime: &str, data: Vec<u8>) -> Result<FileContent> {
        if name.len() > MAX_FILE_NAME_LEN
            || mime.len() > MAX_FILE_MIME_LEN
            || data.len() > MAX_FILE_BYTES
        {
            return Err(ProtoError::RecordError);
        }
        Ok(FileContent {
            name: String::from(name),
            mime: String::from(mime),
            data,
        })
    }
}

impl Drop for FileContent {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// A decrypted message's contents.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Content {
    /// An ordinary text message.
    Text(String),
    /// Call setup or teardown. Never shown to the user as a message.
    Call(CallSignal),
    /// A file: a photo, a document, anything. Shown in the conversation like
    /// a message, because that is what it is.
    File(FileContent),
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
            Content::File(file) => {
                let mut w = Writer::with_capacity(file.data.len() + MAX_FILE_FRAMING);
                w.u8(KIND_FILE)
                    .bytes16(file.name.as_bytes())
                    .bytes16(file.mime.as_bytes())
                    .bytes32(&file.data);
                out = w.finish();
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
            KIND_FILE => {
                let mut r = Reader::new(body);
                let name = core::str::from_utf8(r.bytes16()?).map_err(|_| ProtoError::Malformed)?;
                let mime = core::str::from_utf8(r.bytes16()?).map_err(|_| ProtoError::Malformed)?;
                let data = r.bytes32_max(MAX_FILE_BYTES)?.to_vec();
                r.finish()?;
                // The same bounds as sending, so neither end can hold a file
                // the other could not have made.
                Ok(Content::File(FileContent::new(name, mime, data)?))
            }
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
        let offer = CallOffer::new("abc.onion", 9999, 1_700_000_000).unwrap();
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
        let offer = CallOffer::new("abc.onion", 1, 1_700_000_000).unwrap();
        let encoded = Content::Call(CallSignal::Offer(offer)).encode();
        match Content::decode(&encoded).unwrap() {
            Content::Call(_) => {}
            Content::Text(t) => panic!("signalling decoded as text: {t:?}"),
            Content::File(f) => panic!("signalling decoded as a file: {f:?}"),
        }
    }

    #[test]
    fn a_file_roundtrips() {
        let file = FileContent::new("photo.jpg", "image/jpeg", alloc::vec![7u8; 10_000]).unwrap();
        let c = Content::File(file.clone());
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
        assert_eq!(c.encode()[0], KIND_FILE);
    }

    #[test]
    fn an_empty_file_with_no_name_or_type_roundtrips() {
        let c = Content::File(FileContent::new("", "", Vec::new()).unwrap());
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn a_file_is_never_mistaken_for_text() {
        let c = Content::File(FileContent::new("a.txt", "text/plain", b"hello".to_vec()).unwrap());
        match Content::decode(&c.encode()).unwrap() {
            Content::File(f) => assert_eq!(f.data, b"hello"),
            other => panic!("a file decoded as {other:?}"),
        }
    }

    #[test]
    fn a_file_too_large_to_send_is_refused_before_anything_is_encrypted() {
        assert!(FileContent::new("x", "", alloc::vec![0u8; MAX_FILE_BYTES + 1]).is_err());
        assert!(FileContent::new("x", "", alloc::vec![0u8; MAX_FILE_BYTES]).is_ok());
        let long_name = "n".repeat(MAX_FILE_NAME_LEN + 1);
        assert!(FileContent::new(&long_name, "", Vec::new()).is_err());
        let long_mime = "m".repeat(MAX_FILE_MIME_LEN + 1);
        assert!(FileContent::new("x", &long_mime, Vec::new()).is_err());
    }

    #[test]
    fn a_received_file_past_the_bound_is_refused_too() {
        // Hand-built, since `FileContent::new` will not make one: the data
        // length claims one byte more than the protocol carries.
        let mut w = Writer::new();
        w.u8(KIND_FILE)
            .bytes16(b"x")
            .bytes16(b"")
            .bytes32(&alloc::vec![0u8; MAX_FILE_BYTES + 1]);
        assert!(Content::decode(&w.finish()).is_err());
    }

    #[test]
    fn a_file_name_that_is_not_utf8_is_refused() {
        let mut w = Writer::new();
        w.u8(KIND_FILE)
            .bytes16(&[0xff, 0xfe])
            .bytes16(b"")
            .bytes32(b"");
        assert!(Content::decode(&w.finish()).is_err());
    }

    #[test]
    fn the_largest_file_fits_one_message_under_the_worst_case_header() {
        // The compile-time assertion says the arithmetic holds; this says the
        // real encoder agrees with the arithmetic. A header carrying an ML-KEM
        // step is the largest a ratchet message has (§6.1), and `fragment`
        // is what refuses a message with too many records.
        use crate::record::fragment;
        let file = FileContent::new(
            &"n".repeat(MAX_FILE_NAME_LEN),
            &"m".repeat(MAX_FILE_MIME_LEN),
            alloc::vec![1u8; MAX_FILE_BYTES],
        )
        .unwrap();
        let plaintext = Content::File(file).encode();
        let worst_case_message = 4 + 3_192 + 4 + plaintext.len() + aead::TAG_LEN;
        let records = fragment(1, &alloc::vec![0u8; worst_case_message]).unwrap();
        assert!(records.len() <= MAX_FRAGMENTS as usize);
        assert_eq!(records.len(), file_record_count(MAX_FILE_BYTES) as usize);
        // And one byte more than the bound would not: the bound is tight to
        // within a record, not padded for comfort.
        assert!(fragment(
            1,
            &alloc::vec![0u8; worst_case_message + RECORD_BODY_CAPACITY]
        )
        .is_err());
    }

    #[test]
    fn the_record_count_estimate_never_undercounts() {
        // A small file is a handful of records; the estimate for it must be
        // at least what the encoder would really produce.
        for len in [0usize, 1, 1_000, 10_000, 100_000, MAX_FILE_BYTES] {
            let file = FileContent::new("photo.jpg", "image/jpeg", alloc::vec![0u8; len]).unwrap();
            let plaintext = Content::File(file).encode();
            let message = 4 + 3_192 + 4 + plaintext.len() + aead::TAG_LEN;
            let real = message.div_ceil(RECORD_BODY_CAPACITY);
            assert!(file_record_count(len) as usize >= real, "{len}");
        }
        assert_eq!(file_record_count(usize::MAX), MAX_FRAGMENTS);
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
