//! Push-to-talk calls: signalling over the queue, media over a direct circuit.
//!
//! ## The shape, and why it is this shape
//!
//! A call has two channels with opposite requirements. Setup must be
//! metadata-safe and can be slow; audio must be fast and is hopeless at hiding
//! anything about its own timing. Trying to carry both the same way makes one
//! of them bad, so they are carried differently:
//!
//! - **Signalling** — offer, answer, end — is an ordinary encrypted message.
//!   It rides the ratchet, fragments into records, and lands in the peer's
//!   mailbox queue like any other. The relay learns exactly what it learns
//!   about a text message: that a fixed-size record was deposited.
//! - **Media** is a direct connection between the two clients over paired
//!   ephemeral onion services. It never touches the relay at all.
//!
//! The retrieval schedule (`FR-MSG-07`) means an offer takes one polling slot
//! to arrive — a few seconds. That delay is not a defect here: it *is* the
//! ring, and a phone that rings for five seconds before connecting is a phone
//! behaving normally. The slow, metadata-safe path is used for the one part of
//! a call that can afford it.
//!
//! ## Who hosts
//!
//! The **caller** publishes the onion service and puts its address in the
//! offer; the callee connects. This is the right way round for two reasons.
//! The caller is the one who knows a call is starting, so it can begin
//! publishing its descriptor at the moment the user presses the button — and
//! the descriptor upload (a few seconds, measured) then overlaps the polling
//! delay the offer is already paying, instead of adding to it. It also means
//! the callee publishes nothing, so declining a call leaves no trace on any
//! HSDir.
//!
//! ## What the onion address does and does not authenticate
//!
//! A v3 onion address *is* an Ed25519 public key, so connecting to one is
//! authenticated against exactly that service and nothing else — no
//! certificate authority is involved. What it does not tell the callee is that
//! the service belongs to their contact. That comes from the offer having
//! arrived through the ratchet, which only the contact can write to.
//!
//! Media keys are therefore derived from a secret carried *inside* the
//! ratchet-encrypted offer, not from the transport. An attacker who somehow
//! reached the onion service holds no media key, and a compromised onion
//! service cannot decrypt what crosses it.
//!
//! ## Constant bitrate, and no voice activity detection
//!
//! [`MEDIA_PAYLOAD_LEN`] is fixed and every frame is padded to it, for the
//! same reason [`crate::record::RECORD_SIZE`] is fixed. A variable-bitrate
//! codec, or a silence-suppressing one, makes packet sizes track the shape of
//! speech — which leaks phonetics to anyone counting bytes, and is a published
//! attack, not a theoretical one. Frames are emitted on a fixed cadence
//! whether or not anyone is talking.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use void_crypto::{aead, blake3, rand, Zeroize};

use crate::wire::{Reader, Writer};
use crate::{ProtoError, Result};

/// Identifies one call. Random, and meaningful only inside a session.
pub type CallId = [u8; 16];

/// What the user must be told before a call connects (FR-UI-03, and
/// non-negotiable #8: every option states its cost, not just its benefit).
///
/// It lives here, next to the behaviour it describes, for the same reason
/// [`void_store::vault::DURESS_DISCLOSURE`] lives next to the vault: a copy in
/// Swift and another in Kotlin is two chances for someone to soften it.
///
/// ## Why it does not say "reveals your location"
///
/// Because that would be false, and a false security warning is worse than
/// none. Media runs over paired onion services — Tor both ways — so neither
/// end learns the other's IP address and neither does the relay. A user told
/// their location is exposed would reach for a VPN, conclude they are covered,
/// and never think about what a call actually costs them.
///
/// What it costs them is two things, and both are stated below. **Presence**:
/// a direct connection only works if both people are online at once, so a call
/// tells your contact you are there right now — which the mailbox model
/// otherwise hides completely. **Traffic shape**: messaging emits one
/// fixed-size record every `PAD_INTERVAL_MS` whether or not you are saying
/// anything, and a call cannot do that; it is a sustained bidirectional stream
/// for minutes. That is a far better correlation target for anyone watching
/// one or both ends than messaging has ever been. It is the closest real thing
/// to the worry that "a call exposes me", and it is worth saying plainly.
pub const CALL_DISCLOSURE: &str = "A call goes straight to this person over Tor. Your IP \
address stays hidden — from them and from the relay.\n\nTwo things change while a call is \
running.\n\nThey learn you are online right now. Messaging never tells them that.\n\nAnd a \
call is a steady stream of traffic for as long as it lasts, where messaging looks the same \
whether or not you are sending anything. Someone watching your internet connection can tell \
you are on a call, and someone watching both ends at once has a far easier time matching \
them up than they do with messages.";

/// Fixed plaintext size of one media frame's payload.
///
/// 120 bytes at one frame per 20 ms is 48 kbit/s of headroom, which covers
/// Opus comfortably at any bitrate worth using over a Tor circuit. Frames
/// shorter than this are padded; the real length travels encrypted inside.
pub const MEDIA_PAYLOAD_LEN: usize = 120;

/// How often a call emits a media frame, in milliseconds. Matches Opus's
/// default frame duration.
pub const MEDIA_FRAME_MS: u64 = 20;

/// On-wire size of one media frame: sequence, then the sealed payload.
pub const MEDIA_FRAME_LEN: usize = 4 + MEDIA_PAYLOAD_LEN + 2 + aead::TAG_LEN;

/// Largest onion address we will parse. A v3 address is 56 characters plus
/// `.onion`; the bound exists so a malformed offer cannot allocate freely.
const MAX_ONION_LEN: usize = 128;

/// Which end of a call this is. Decides which direction gets which key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Placed the call, and hosts the onion service.
    Caller,
    /// Received the offer, and connects to it.
    Callee,
}

/// Why a call ended. Carried so the other side can show something truthful
/// rather than guessing from a dropped connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EndReason {
    /// The user hung up.
    HungUp,
    /// The user declined an incoming call.
    Declined,
    /// Nobody answered in time.
    Missed,
    /// The media connection could not be established or was lost.
    Failed,
}

impl EndReason {
    fn to_byte(self) -> u8 {
        match self {
            EndReason::HungUp => 1,
            EndReason::Declined => 2,
            EndReason::Missed => 3,
            EndReason::Failed => 4,
        }
    }

    fn from_byte(b: u8) -> Result<EndReason> {
        Ok(match b {
            1 => EndReason::HungUp,
            2 => EndReason::Declined,
            3 => EndReason::Missed,
            4 => EndReason::Failed,
            _ => return Err(ProtoError::Malformed),
        })
    }
}

/// An invitation to a call, and everything needed to join it.
#[derive(Clone, PartialEq, Eq)]
pub struct CallOffer {
    /// Identifies this call within the session.
    pub call_id: CallId,
    /// The caller's ephemeral onion service, without a scheme.
    pub onion_address: String,
    /// The virtual port that service is listening on.
    pub port: u16,
    /// Fresh randomness both sides derive media keys from. Confidential: this
    /// offer only ever travels inside the ratchet.
    pub media_secret: [u8; 32],
}

impl Drop for CallOffer {
    fn drop(&mut self) {
        self.media_secret.zeroize();
    }
}

impl core::fmt::Debug for CallOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallOffer")
            .field("call_id", &self.call_id)
            .field("onion_address", &self.onion_address)
            .field("port", &self.port)
            .field("media_secret", &"<redacted>")
            .finish()
    }
}

impl CallOffer {
    /// Build an offer for a service already publishing at `onion_address`.
    pub fn new(onion_address: &str, port: u16) -> Result<CallOffer> {
        if onion_address.is_empty() || onion_address.len() > MAX_ONION_LEN {
            return Err(ProtoError::Malformed);
        }
        Ok(CallOffer {
            call_id: rand::bytes16().map_err(|_| ProtoError::Crypto)?,
            onion_address: String::from(onion_address),
            port,
            media_secret: rand::bytes32().map_err(|_| ProtoError::Crypto)?,
        })
    }
}

/// The answer to an offer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CallAnswer {
    /// The call being answered.
    pub call_id: CallId,
    /// Whether the callee is connecting. A decline is sent as an
    /// [`EndReason::Declined`] end rather than a false here, so that
    /// "answered no" and "hung up" travel the same way.
    pub accepted: bool,
}

/// The end of a call, from either side.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CallEnd {
    /// The call being ended.
    pub call_id: CallId,
    /// Why.
    pub reason: EndReason,
}

/// Anything a call needs to say over the signalling channel.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CallSignal {
    /// Ring.
    Offer(CallOffer),
    /// Answered; the callee is connecting.
    Answer(CallAnswer),
    /// Over.
    End(CallEnd),
}

impl CallSignal {
    /// The call this signal concerns.
    #[must_use]
    pub fn call_id(&self) -> CallId {
        match self {
            CallSignal::Offer(o) => o.call_id,
            CallSignal::Answer(a) => a.call_id,
            CallSignal::End(e) => e.call_id,
        }
    }

    /// Canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        match self {
            CallSignal::Offer(o) => {
                w.u8(1)
                    .raw(&o.call_id)
                    .bytes16(o.onion_address.as_bytes())
                    .u16(o.port)
                    .raw(&o.media_secret);
            }
            CallSignal::Answer(a) => {
                w.u8(2).raw(&a.call_id).u8(a.accepted as u8);
            }
            CallSignal::End(e) => {
                w.u8(3).raw(&e.call_id).u8(e.reason.to_byte());
            }
        }
        w.finish()
    }

    /// Decode, rejecting anything structurally wrong.
    pub fn decode(bytes: &[u8]) -> Result<CallSignal> {
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        let signal = match tag {
            1 => {
                let call_id = r.array::<16>()?;
                let addr = r.bytes16()?;
                if addr.is_empty() || addr.len() > MAX_ONION_LEN {
                    return Err(ProtoError::Malformed);
                }
                let onion_address =
                    core::str::from_utf8(addr).map_err(|_| ProtoError::Malformed)?;
                let port = r.u16()?;
                let media_secret = r.array::<32>()?;
                CallSignal::Offer(CallOffer {
                    call_id,
                    onion_address: String::from(onion_address),
                    port,
                    media_secret,
                })
            }
            2 => CallSignal::Answer(CallAnswer {
                call_id: r.array::<16>()?,
                accepted: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::Malformed),
                },
            }),
            3 => CallSignal::End(CallEnd {
                call_id: r.array::<16>()?,
                reason: EndReason::from_byte(r.u8()?)?,
            }),
            _ => return Err(ProtoError::Malformed),
        };
        r.finish()?;
        Ok(signal)
    }
}

/// The two directional keys for one call's media.
///
/// Separate keys per direction, so that both ends can start their sequence
/// numbers at zero without ever colliding on a nonce. Sharing one key and
/// splitting the sequence space would work too and would be one mistake away
/// from catastrophe; this is not.
pub struct MediaKeys {
    send: [u8; 32],
    recv: [u8; 32],
}

impl Drop for MediaKeys {
    fn drop(&mut self) {
        self.send.zeroize();
        self.recv.zeroize();
    }
}

impl MediaKeys {
    /// Derive this end's keys from the offer's secret.
    #[must_use]
    pub fn derive(media_secret: &[u8; 32], role: Role) -> MediaKeys {
        let caller_to_callee = blake3::derive_key_32("void/v1/call/media/c2e", media_secret);
        let callee_to_caller = blake3::derive_key_32("void/v1/call/media/e2c", media_secret);
        match role {
            Role::Caller => MediaKeys {
                send: caller_to_callee,
                recv: callee_to_caller,
            },
            Role::Callee => MediaKeys {
                send: callee_to_caller,
                recv: caller_to_callee,
            },
        }
    }
}

/// Encrypts and decrypts one call's media stream.
///
/// Sequence numbers are the nonce, so they must never repeat under one key.
/// [`MediaStream::seal`] refuses rather than wrapping — a call that somehow
/// ran past 2^32 frames (over two years of continuous audio) ends instead of
/// reusing a nonce.
pub struct MediaStream {
    keys: MediaKeys,
    call_id: CallId,
    next_send: u32,
    highest_recv: u32,
    started: bool,
}

impl MediaStream {
    /// Begin a media stream for `call_id`.
    #[must_use]
    pub fn new(media_secret: &[u8; 32], role: Role, call_id: CallId) -> MediaStream {
        MediaStream {
            keys: MediaKeys::derive(media_secret, role),
            call_id,
            next_send: 0,
            highest_recv: 0,
            started: false,
        }
    }

    /// Seal one audio frame into a wire frame of exactly [`MEDIA_FRAME_LEN`].
    ///
    /// `audio` is whatever the platform's encoder produced; this layer does
    /// not know or care what codec that was.
    pub fn seal(&mut self, audio: &[u8]) -> Result<Vec<u8>> {
        if audio.len() > MEDIA_PAYLOAD_LEN {
            return Err(ProtoError::Malformed);
        }
        let seq = self.next_send;
        self.next_send = seq.checked_add(1).ok_or(ProtoError::NotReady)?;

        // Length inside the encryption, payload padded outside it: the wire
        // frame is one size regardless of how much audio it carries.
        let mut plaintext = Vec::with_capacity(2 + MEDIA_PAYLOAD_LEN);
        plaintext.extend_from_slice(&(audio.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(audio);
        plaintext.resize(2 + MEDIA_PAYLOAD_LEN, 0);

        let nonce = aead::nonce_from_counter(seq as u64);
        let sealed = aead::seal(&self.keys.send, &nonce, &self.call_id, &plaintext);
        plaintext.zeroize();

        let mut out = Vec::with_capacity(MEDIA_FRAME_LEN);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), MEDIA_FRAME_LEN);
        Ok(out)
    }

    /// Open one wire frame, returning the audio it carried.
    ///
    /// Frames that do not authenticate are an error and must be dropped by the
    /// caller, not played. Late and duplicate frames are rejected here rather
    /// than left for the jitter buffer to trip over: a replayed frame is a
    /// repeated syllable, which is both audible and a way to feed the same
    /// audio twice.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() != MEDIA_FRAME_LEN {
            return Err(ProtoError::Malformed);
        }
        let seq = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        if self.started && seq <= self.highest_recv {
            return Err(ProtoError::DecryptionFailed);
        }

        let nonce = aead::nonce_from_counter(seq as u64);
        let mut plaintext = aead::open(&self.keys.recv, &nonce, &self.call_id, &frame[4..])
            .map_err(|_| ProtoError::DecryptionFailed)?;
        if plaintext.len() != 2 + MEDIA_PAYLOAD_LEN {
            plaintext.zeroize();
            return Err(ProtoError::Malformed);
        }
        let len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        if len > MEDIA_PAYLOAD_LEN {
            plaintext.zeroize();
            return Err(ProtoError::Malformed);
        }

        // Only now, with the frame authenticated, does the stream advance.
        self.highest_recv = seq;
        self.started = true;

        let audio = plaintext[2..2 + len].to_vec();
        plaintext.zeroize();
        Ok(audio)
    }

    /// How many frames this end has sent.
    #[must_use]
    pub fn frames_sent(&self) -> u32 {
        self.next_send
    }

    /// A frame of silence, for the cadence to keep running while nobody is
    /// speaking. Constant bitrate is the point; see the module docs.
    pub fn seal_silence(&mut self) -> Result<Vec<u8>> {
        self.seal(&[])
    }
}

/// Fill `buf` with a full media frame read from a stream, for callers doing
/// their own I/O. Present so the framing constant lives in exactly one place.
#[must_use]
pub fn media_frame_buffer() -> Vec<u8> {
    vec![0u8; MEDIA_FRAME_LEN]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> CallOffer {
        CallOffer::new(
            "5rnxosw3zlrt5dppafbkw4f2kpdp7gdliaghf5uo5l2rvd24hm5pwtqd.onion",
            9999,
        )
        .unwrap()
    }

    #[test]
    fn offer_roundtrips_through_the_wire() {
        let o = offer();
        let signal = CallSignal::Offer(o.clone());
        let decoded = CallSignal::decode(&signal.encode()).unwrap();
        match decoded {
            CallSignal::Offer(d) => {
                assert_eq!(d.call_id, o.call_id);
                assert_eq!(d.onion_address, o.onion_address);
                assert_eq!(d.port, o.port);
                assert_eq!(d.media_secret, o.media_secret);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn answer_and_end_roundtrip() {
        let id = [7u8; 16];
        for signal in [
            CallSignal::Answer(CallAnswer {
                call_id: id,
                accepted: true,
            }),
            CallSignal::End(CallEnd {
                call_id: id,
                reason: EndReason::Declined,
            }),
            CallSignal::End(CallEnd {
                call_id: id,
                reason: EndReason::Failed,
            }),
        ] {
            assert_eq!(CallSignal::decode(&signal.encode()).unwrap(), signal);
            assert_eq!(signal.call_id(), id);
        }
    }

    #[test]
    fn malformed_signals_are_refused() {
        assert!(CallSignal::decode(&[]).is_err());
        assert!(CallSignal::decode(&[9, 0, 0]).is_err(), "unknown tag");
        // An answer with a non-boolean flag.
        let mut bad = CallSignal::Answer(CallAnswer {
            call_id: [1u8; 16],
            accepted: true,
        })
        .encode();
        *bad.last_mut().unwrap() = 7;
        assert!(CallSignal::decode(&bad).is_err());
        // Trailing bytes.
        let mut extra = CallSignal::End(CallEnd {
            call_id: [1u8; 16],
            reason: EndReason::HungUp,
        })
        .encode();
        extra.push(0);
        assert!(CallSignal::decode(&extra).is_err());
    }

    #[test]
    fn an_offer_with_no_address_is_refused() {
        assert!(CallOffer::new("", 1).is_err());
        assert!(CallOffer::new(&"a".repeat(MAX_ONION_LEN + 1), 1).is_err());
    }

    #[test]
    fn media_roundtrips_between_the_two_roles() {
        let o = offer();
        let mut caller = MediaStream::new(&o.media_secret, Role::Caller, o.call_id);
        let mut callee = MediaStream::new(&o.media_secret, Role::Callee, o.call_id);

        let audio = b"opus frame bytes";
        let frame = caller.seal(audio).unwrap();
        assert_eq!(frame.len(), MEDIA_FRAME_LEN);
        assert_eq!(callee.open(&frame).unwrap(), audio);

        let back = callee.seal(b"and back").unwrap();
        assert_eq!(caller.open(&back).unwrap(), b"and back");
    }

    #[test]
    fn every_media_frame_is_the_same_size() {
        // The whole reason the length lives inside the encryption: an observer
        // counting bytes must not be able to tell a silent frame from a loud
        // one, because frame size tracking speech leaks phonetics.
        let o = offer();
        let mut s = MediaStream::new(&o.media_secret, Role::Caller, o.call_id);
        let a = s.seal(&[]).unwrap();
        let b = s.seal(&[0u8; MEDIA_PAYLOAD_LEN]).unwrap();
        let c = s.seal_silence().unwrap();
        assert_eq!(a.len(), MEDIA_FRAME_LEN);
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
    }

    #[test]
    fn the_two_directions_use_different_keys() {
        // Both ends start at sequence zero. If the directions shared a key
        // that would be an immediate nonce collision, so this is the test that
        // matters most in this file.
        let o = offer();
        let mut caller = MediaStream::new(&o.media_secret, Role::Caller, o.call_id);
        let mut caller_echo = MediaStream::new(&o.media_secret, Role::Caller, o.call_id);

        let sent = caller.seal(b"hello").unwrap();
        // A same-role stream must not be able to open its own direction.
        assert!(caller_echo.open(&sent).is_err());
    }

    #[test]
    fn a_replayed_frame_is_rejected() {
        let o = offer();
        let mut caller = MediaStream::new(&o.media_secret, Role::Caller, o.call_id);
        let mut callee = MediaStream::new(&o.media_secret, Role::Callee, o.call_id);

        let frame = caller.seal(b"once").unwrap();
        assert!(callee.open(&frame).is_ok());
        assert!(
            callee.open(&frame).is_err(),
            "a replayed frame is a repeated syllable"
        );
    }

    #[test]
    fn a_frame_from_another_call_does_not_open() {
        // call_id is the associated data, so media cannot be moved between
        // calls even when the same secret is somehow reused.
        let secret = [3u8; 32];
        let mut a = MediaStream::new(&secret, Role::Caller, [1u8; 16]);
        let mut b = MediaStream::new(&secret, Role::Callee, [2u8; 16]);
        let frame = a.seal(b"x").unwrap();
        assert!(b.open(&frame).is_err());
    }

    #[test]
    fn tampering_with_a_media_frame_is_caught() {
        let o = offer();
        let mut caller = MediaStream::new(&o.media_secret, Role::Caller, o.call_id);
        let mut callee = MediaStream::new(&o.media_secret, Role::Callee, o.call_id);
        let frame = caller.seal(b"authentic").unwrap();
        for i in [0usize, 4, 60, MEDIA_FRAME_LEN - 1] {
            let mut bad = frame.clone();
            bad[i] ^= 1;
            assert!(callee.open(&bad).is_err(), "tamper at {i} not caught");
        }
        // And a wrong-length frame never reaches the AEAD at all.
        assert!(callee.open(&frame[..MEDIA_FRAME_LEN - 1]).is_err());
    }

    #[test]
    fn out_of_order_frames_are_accepted_forward_only() {
        // Voice tolerates loss but not reordering into the past: a frame older
        // than one already played is dropped rather than played late.
        let o = offer();
        let mut caller = MediaStream::new(&o.media_secret, Role::Caller, o.call_id);
        let mut callee = MediaStream::new(&o.media_secret, Role::Callee, o.call_id);

        let frames: Vec<_> = (0..5u8).map(|i| caller.seal(&[i]).unwrap()).collect();
        assert_eq!(callee.open(&frames[0]).unwrap(), vec![0]);
        // Frames 1 and 2 are lost; 3 arrives and is fine.
        assert_eq!(callee.open(&frames[3]).unwrap(), vec![3]);
        // 2 turns up late and is refused — it would be heard out of order.
        assert!(callee.open(&frames[2]).is_err());
        assert_eq!(callee.open(&frames[4]).unwrap(), vec![4]);
    }

    #[test]
    fn a_media_secret_is_not_readable_from_debug_output() {
        let o = offer();
        let rendered = alloc::format!("{o:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(&alloc::format!("{:?}", o.media_secret)));
    }

    #[test]
    fn the_call_disclosure_says_what_is_true_and_not_what_is_not() {
        let d = CALL_DISCLOSURE;
        // The two real costs, both named.
        assert!(d.contains("online right now"), "presence must be stated");
        assert!(
            d.contains("steady stream of traffic"),
            "the traffic-shape change must be stated"
        );
        // And the thing users assume, corrected rather than left to assumption.
        assert!(d.contains("IP address stays hidden"));

        // A warning that claimed location exposure would be false for this
        // design and would send users after the wrong mitigation. If media
        // ever stops going over Tor, this assertion is where that shows up.
        let lowered = d.to_lowercase();
        assert!(
            !lowered.contains("reveals your location")
                && !lowered.contains("reveals their location"),
            "media runs over onion services; claiming location exposure is untrue"
        );
    }

    #[test]
    fn oversized_audio_is_refused_rather_than_truncated() {
        let o = offer();
        let mut s = MediaStream::new(&o.media_secret, Role::Caller, o.call_id);
        assert!(s.seal(&[0u8; MEDIA_PAYLOAD_LEN + 1]).is_err());
    }
}
