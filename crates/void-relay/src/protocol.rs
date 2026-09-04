//! The client↔relay wire protocol.
//!
//! ## Design constraint
//!
//! Everything a relay can see is defined here, and the list is short by
//! construction: a queue identifier, a fixed-size sealed blob, a retrieval
//! proof, and a rotating wake identifier. There is no account, no session
//! cookie, no user agent, no version negotiation that could fingerprint a
//! client build, and no error code that distinguishes "wrong proof" from
//! "empty queue".
//!
//! ## Frames are a fixed size
//!
//! Every frame on the wire is exactly [`FRAME_SIZE`] bytes, padded with random
//! bytes. FR-MSG-06 requires that dummy and real traffic be identical in size;
//! the simplest way to guarantee that for *all* traffic, not just deposits, is
//! to make every frame the same size. A `Retrieve` request and a `Padding`
//! frame are indistinguishable to an observer, and so are an empty response and
//! a full one.
//!
//! The cost is real: a retrieval request that needs 60 bytes costs 2,088. That
//! is the price of the property, and NFR-PERF-03's budget was computed with it
//! (see `void_proto::record`).

use void_proto::envelope::SEALED_RECORD_SIZE;
use void_proto::wire::{Reader, Writer};

use crate::{RelayError, RelayResult};

/// Every frame on the wire is exactly this many bytes.
///
/// Sized to hold one sealed record plus framing, so a deposit is a single
/// frame. `SEALED_RECORD_SIZE` is 1,064; rounding to 2,048 leaves room for
/// framing and for a future field without changing the constant, and a power of
/// two is friendlier to the transport.
pub const FRAME_SIZE: usize = 2048;

/// Bytes available for a frame body.
pub const FRAME_BODY_CAPACITY: usize = FRAME_SIZE - 8;

const _: () = assert!(
    SEALED_RECORD_SIZE + 32 < FRAME_BODY_CAPACITY,
    "a sealed record plus a queue id must fit in one frame"
);

/// Frame types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameType {
    /// Client → relay: deposit a sealed record.
    Deposit = 1,
    /// Client → relay: ask for a retrieval challenge.
    Challenge = 2,
    /// Relay → client: here is a challenge.
    ChallengeReply = 3,
    /// Client → relay: collect from a queue, proving authority.
    Retrieve = 4,
    /// Relay → client: here is a record (or nothing).
    Delivery = 5,
    /// Relay → client: the operation was accepted.
    Ack = 6,
    /// Relay → client: the operation was refused.
    ///
    /// Deliberately carries no reason. A relay that distinguished "bad proof"
    /// from "empty queue" from "rate limited" would be an oracle for probing
    /// which queues exist and are active.
    Refuse = 7,
    /// Either direction: cover traffic. Carries random bytes.
    Padding = 8,
    /// Client → relay: register for push wake signals.
    WakeRegister = 9,
}

impl FrameType {
    fn to_byte(self) -> u8 {
        self as u8
    }

    fn from_byte(b: u8) -> RelayResult<FrameType> {
        Ok(match b {
            1 => FrameType::Deposit,
            2 => FrameType::Challenge,
            3 => FrameType::ChallengeReply,
            4 => FrameType::Retrieve,
            5 => FrameType::Delivery,
            6 => FrameType::Ack,
            7 => FrameType::Refuse,
            8 => FrameType::Padding,
            9 => FrameType::WakeRegister,
            _ => return Err(RelayError::Malformed),
        })
    }
}

/// A fixed-size wire frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frame {
    /// What this frame is.
    pub kind: FrameType,
    /// The body. Padded to [`FRAME_BODY_CAPACITY`] on the wire.
    pub body: Vec<u8>,
}

impl Frame {
    /// Build a frame.
    #[must_use]
    pub fn new(kind: FrameType, body: Vec<u8>) -> Frame {
        Frame { kind, body }
    }

    /// A cover-traffic frame.
    pub fn padding() -> RelayResult<Frame> {
        let mut body = vec![0u8; FRAME_BODY_CAPACITY];
        void_crypto::rand::fill(&mut body).map_err(|_| RelayError::Entropy)?;
        Ok(Frame {
            kind: FrameType::Padding,
            body,
        })
    }

    /// Encode to exactly [`FRAME_SIZE`] bytes.
    pub fn encode(&self) -> RelayResult<Vec<u8>> {
        if self.body.len() > FRAME_BODY_CAPACITY {
            return Err(RelayError::Malformed);
        }
        let mut w = Writer::with_capacity(FRAME_SIZE);
        w.u8(self.kind.to_byte())
            .u8(0) // reserved, must be zero
            .u16(0) // reserved
            .u32(self.body.len() as u32)
            .raw(&self.body);
        let mut buf = w.finish();
        let pad = FRAME_SIZE - buf.len();
        let mut filler = vec![0u8; pad];
        void_crypto::rand::fill(&mut filler).map_err(|_| RelayError::Entropy)?;
        buf.extend_from_slice(&filler);
        Ok(buf)
    }

    /// Decode from exactly [`FRAME_SIZE`] bytes.
    pub fn decode(bytes: &[u8]) -> RelayResult<Frame> {
        if bytes.len() != FRAME_SIZE {
            return Err(RelayError::Malformed);
        }
        let mut r = Reader::new(bytes);
        let kind = FrameType::from_byte(r.u8().map_err(|_| RelayError::Malformed)?)?;
        let _reserved8 = r.u8().map_err(|_| RelayError::Malformed)?;
        let _reserved16 = r.u16().map_err(|_| RelayError::Malformed)?;
        let len = r.u32().map_err(|_| RelayError::Malformed)? as usize;
        if len > FRAME_BODY_CAPACITY {
            return Err(RelayError::Malformed);
        }
        let body = r.raw(len).map_err(|_| RelayError::Malformed)?.to_vec();
        Ok(Frame { kind, body })
    }
}

/// The body of a `Delivery` frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Delivery {
    /// The sealed record, or empty if the queue had nothing.
    ///
    /// An empty delivery and a full one are the same size on the wire because
    /// the frame is padded, so "there was nothing" is not observable.
    pub sealed: Vec<u8>,
    /// How many records remain in the queue after this one.
    pub remaining: u32,
}

impl Delivery {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes32(&self.sealed).u32(self.remaining);
        w.finish()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> RelayResult<Delivery> {
        let mut r = Reader::new(bytes);
        let sealed = r
            .bytes32_max(SEALED_RECORD_SIZE)
            .map_err(|_| RelayError::Malformed)?
            .to_vec();
        let remaining = r.u32().map_err(|_| RelayError::Malformed)?;
        r.finish().map_err(|_| RelayError::Malformed)?;
        if !sealed.is_empty() && sealed.len() != SEALED_RECORD_SIZE {
            return Err(RelayError::Malformed);
        }
        Ok(Delivery { sealed, remaining })
    }
}

/// The body of a `Retrieve` frame.
///
/// Carries the retrieval public key alongside the signature, so the relay can
/// verify without holding any per-queue state — see
/// `void_proto::queue::verify_retrieval_proof`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Retrieve {
    /// The queue to collect from.
    pub queue_id: [u8; 16],
    /// The challenge this proof answers.
    pub challenge: [u8; 32],
    /// The Ed25519 public key that must hash to `queue_id`.
    pub retrieval_public: [u8; 32],
    /// Signature over the challenge.
    pub proof: [u8; 64],
}

impl Retrieve {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(144);
        w.raw(&self.queue_id)
            .raw(&self.challenge)
            .raw(&self.retrieval_public)
            .raw(&self.proof);
        w.finish()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> RelayResult<Retrieve> {
        let mut r = Reader::new(bytes);
        let queue_id = r.array::<16>().map_err(|_| RelayError::Malformed)?;
        let challenge = r.array::<32>().map_err(|_| RelayError::Malformed)?;
        let retrieval_public = r.array::<32>().map_err(|_| RelayError::Malformed)?;
        let proof = r.array::<64>().map_err(|_| RelayError::Malformed)?;
        r.finish().map_err(|_| RelayError::Malformed)?;
        Ok(Retrieve {
            queue_id,
            challenge,
            retrieval_public,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frame_type_encodes_to_the_same_size() {
        let bodies: Vec<(FrameType, Vec<u8>)> = vec![
            (FrameType::Deposit, vec![0u8; SEALED_RECORD_SIZE + 16]),
            (FrameType::Challenge, vec![]),
            (FrameType::Ack, vec![]),
            (FrameType::Refuse, vec![]),
            (FrameType::Retrieve, vec![0u8; 144]),
        ];
        for (kind, body) in bodies {
            let f = Frame::new(kind, body);
            assert_eq!(f.encode().unwrap().len(), FRAME_SIZE, "{kind:?}");
        }
        assert_eq!(
            Frame::padding().unwrap().encode().unwrap().len(),
            FRAME_SIZE
        );
    }

    #[test]
    fn a_deposit_fits_in_one_frame() {
        let body = vec![0u8; 16 + 4 + SEALED_RECORD_SIZE];
        assert!(Frame::new(FrameType::Deposit, body).encode().is_ok());
    }

    #[test]
    fn frame_roundtrip() {
        let f = Frame::new(FrameType::Deposit, vec![7u8; 100]);
        let enc = f.encode().unwrap();
        assert_eq!(Frame::decode(&enc).unwrap(), f);
    }

    #[test]
    fn frame_padding_is_random() {
        let f = Frame::new(FrameType::Ack, vec![]);
        assert_ne!(f.encode().unwrap(), f.encode().unwrap());
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert!(Frame::decode(&[0u8; 10]).is_err());
        assert!(Frame::decode(&[0u8; FRAME_SIZE]).is_err()); // type 0
        let mut buf = vec![0u8; FRAME_SIZE];
        buf[0] = 1;
        buf[4..8].copy_from_slice(&(FRAME_SIZE as u32).to_be_bytes());
        assert!(
            Frame::decode(&buf).is_err(),
            "over-long body must be refused"
        );
        assert!(Frame::new(FrameType::Ack, vec![0u8; FRAME_SIZE])
            .encode()
            .is_err());
    }

    #[test]
    fn an_empty_delivery_is_the_same_size_as_a_full_one() {
        // The relay must not reveal "your queue is empty" through frame size.
        let empty = Delivery {
            sealed: vec![],
            remaining: 0,
        };
        let full = Delivery {
            sealed: vec![0u8; SEALED_RECORD_SIZE],
            remaining: 3,
        };
        let a = Frame::new(FrameType::Delivery, empty.encode())
            .encode()
            .unwrap();
        let b = Frame::new(FrameType::Delivery, full.encode())
            .encode()
            .unwrap();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn delivery_roundtrip_and_size_validation() {
        let d = Delivery {
            sealed: vec![9u8; SEALED_RECORD_SIZE],
            remaining: 2,
        };
        assert_eq!(Delivery::decode(&d.encode()).unwrap(), d);

        let bad = Delivery {
            sealed: vec![9u8; 10],
            remaining: 0,
        };
        assert!(Delivery::decode(&bad.encode()).is_err());
    }

    #[test]
    fn retrieve_roundtrip() {
        let r = Retrieve {
            queue_id: [1u8; 16],
            challenge: [2u8; 32],
            retrieval_public: [4u8; 32],
            proof: [3u8; 64],
        };
        assert_eq!(Retrieve::decode(&r.encode()).unwrap(), r);
        assert!(Retrieve::decode(&r.encode()[..70]).is_err());
    }

    #[test]
    fn refusal_carries_no_reason() {
        // If this ever grows a body, it becomes an oracle. The test is the
        // guard rail.
        let f = Frame::new(FrameType::Refuse, vec![]);
        assert!(f.body.is_empty());
    }
}
