//! Calls: signalling over the queue, media over a direct circuit.
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
//! The retrieval schedule (`FR-MSG-07`) means an offer reaches the callee on
//! their next retrieval: usually within half a minute of being sent, and
//! sometimes over a minute when the offer is four records long (a ratchet step
//! carrying ML-KEM material, D-005). That delay is the ring, and the interface
//! says so. The
//! slow, metadata-safe path carries the one part of a call that can afford it.
//! The answer does not have to take it back: the caller treats the callee's
//! first authenticated media frame as the answer, so connecting costs one
//! mailbox delay, not two.
//!
//! An offer carries the time it was sent, inside the ciphertext. Offers wait in
//! a mailbox like any message, so one can arrive long after its caller gave up;
//! the receiving engine reports a stale one as a missed call instead of
//! ringing.
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
//!
//! ## Video calls
//!
//! A video call is the same call with a bigger frame ([`MediaMode::Video`]):
//! every frame carries its audio and a fixed-capacity video slice
//! ([`VIDEO_SLICE_LEN`]), sealed together, on the same cadence. Video does not
//! get packets of its own, because a video encoder's output tracks motion the
//! way a variable-bitrate voice codec tracks speech; [`crate::video`] cuts the
//! encoded stream into slices and pads the rest. The offer says which mode the
//! call is, inside the ciphertext, and both ends then use that frame size for
//! the whole call — so a video call is distinguishable from a voice call by its
//! rate, which [`VIDEO_CALL_DISCLOSURE`] says, and turning the camera off is
//! not distinguishable from leaving it on, which it also says.

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

/// Added to [`CALL_DISCLOSURE`] before a video call, in either direction.
///
/// The two things that are true of video and not of voice: what the other
/// person can see, which is the user's to manage, and that a video call is a
/// bigger stream than a voice call — to someone watching the connection, a
/// different shape, which is not. And one reassurance that is true because
/// the lane is constant-bitrate: switching the camera off changes nothing on
/// the wire.
pub const VIDEO_CALL_DISCLOSURE: &str = "On a video call they see what your camera sees until you \
turn it off. A video call is a bigger stream than a voice call, and someone watching your \
connection can tell the two apart. Turning your camera off does not change what they see: the \
stream stays the same size either way.";

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

/// Fixed capacity of one video call frame's video slice.
///
/// 560 bytes at one frame per 20 ms is a 224 kbit/s lane, of which the
/// platforms' encoders are asked to fill about two thirds on average, so a
/// keyframe drains in well under a second. With the audio, a video call is
/// about 280 kbit/s each way on the wire — sustained comfortably by an onion
/// circuit, where several times that is not.
pub const VIDEO_SLICE_LEN: usize = 560;

/// On-wire size of one video call media frame: sequence, then the sealed
/// audio and video slice.
pub const VIDEO_FRAME_LEN: usize = 4 + 2 + MEDIA_PAYLOAD_LEN + 2 + VIDEO_SLICE_LEN + aead::TAG_LEN;

/// Which frame a call uses, fixed for the call by its offer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MediaMode {
    /// Audio only: [`MEDIA_FRAME_LEN`]-byte frames.
    Audio,
    /// Audio and video: [`VIDEO_FRAME_LEN`]-byte frames.
    Video,
}

impl MediaMode {
    /// The mode an offer's video flag names.
    #[must_use]
    pub const fn for_call(video: bool) -> MediaMode {
        if video {
            MediaMode::Video
        } else {
            MediaMode::Audio
        }
    }

    /// Bytes of one frame on the wire.
    #[must_use]
    pub const fn frame_len(self) -> usize {
        match self {
            MediaMode::Audio => MEDIA_FRAME_LEN,
            MediaMode::Video => VIDEO_FRAME_LEN,
        }
    }

    /// Video bytes one frame can carry.
    #[must_use]
    pub const fn video_capacity(self) -> usize {
        match self {
            MediaMode::Audio => 0,
            MediaMode::Video => VIDEO_SLICE_LEN,
        }
    }

    const fn plaintext_len(self) -> usize {
        match self {
            MediaMode::Audio => 2 + MEDIA_PAYLOAD_LEN,
            MediaMode::Video => 2 + MEDIA_PAYLOAD_LEN + 2 + VIDEO_SLICE_LEN,
        }
    }
}

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
    /// The callee was already on another call, so this one never rang.
    Busy,
}

impl EndReason {
    fn to_byte(self) -> u8 {
        match self {
            EndReason::HungUp => 1,
            EndReason::Declined => 2,
            EndReason::Missed => 3,
            EndReason::Failed => 4,
            EndReason::Busy => 5,
        }
    }

    fn from_byte(b: u8) -> Result<EndReason> {
        Ok(match b {
            1 => EndReason::HungUp,
            2 => EndReason::Declined,
            3 => EndReason::Missed,
            4 => EndReason::Failed,
            5 => EndReason::Busy,
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
    /// Unix seconds when the caller sent it, by the caller's clock. Inside the
    /// ciphertext, so the relay learns nothing from it; the callee uses it to
    /// tell a live call from one that waited in the mailbox until its caller
    /// had long since given up.
    pub sent_at: u64,
    /// Whether this is a video call, and so which [`MediaMode`] both ends use.
    pub video: bool,
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
            .field("sent_at", &self.sent_at)
            .field("video", &self.video)
            .field("media_secret", &"<redacted>")
            .finish()
    }
}

impl CallOffer {
    /// Build an offer for a service already publishing at `onion_address`,
    /// sent at `now` (Unix seconds); a video call if `video`.
    pub fn new(onion_address: &str, port: u16, now: u64, video: bool) -> Result<CallOffer> {
        if onion_address.is_empty() || onion_address.len() > MAX_ONION_LEN {
            return Err(ProtoError::Malformed);
        }
        Ok(CallOffer {
            call_id: rand::bytes16().map_err(|_| ProtoError::Crypto)?,
            onion_address: String::from(onion_address),
            port,
            media_secret: rand::bytes32().map_err(|_| ProtoError::Crypto)?,
            sent_at: now,
            video,
        })
    }

    /// The frame this call uses.
    #[must_use]
    pub fn mode(&self) -> MediaMode {
        MediaMode::for_call(self.video)
    }
}

/// Bit 0 of an offer's flags byte: a video call.
const OFFER_VIDEO: u8 = 0x01;

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
                    .raw(&o.media_secret)
                    .u64(o.sent_at)
                    .u8(if o.video { OFFER_VIDEO } else { 0 });
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
                let sent_at = r.u64()?;
                let flags = r.u8()?;
                if flags & !OFFER_VIDEO != 0 {
                    return Err(ProtoError::Malformed);
                }
                CallSignal::Offer(CallOffer {
                    call_id,
                    onion_address: String::from(onion_address),
                    port,
                    media_secret,
                    sent_at,
                    video: flags & OFFER_VIDEO != 0,
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
/// [`MediaSealer::seal`] refuses rather than wrapping — a call that somehow
/// ran past 2^32 frames (over two years of continuous audio) ends instead of
/// reusing a nonce.
///
/// A call sends and receives at the same time, from two threads, so the
/// stream [`split`](MediaStream::split)s into a sealer and an opener that share
/// nothing: each owns its own key and its own counter.
pub struct MediaStream {
    sealer: MediaSealer,
    opener: MediaOpener,
}

/// The sending half of one call's media: seals frames under this end's key.
pub struct MediaSealer {
    key: [u8; 32],
    call_id: CallId,
    next_send: u32,
    mode: MediaMode,
}

/// The receiving half of one call's media: opens the other end's frames.
pub struct MediaOpener {
    key: [u8; 32],
    call_id: CallId,
    highest_recv: u32,
    started: bool,
    mode: MediaMode,
}

/// One opened media frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MediaFrame {
    /// Its sequence number, so a gap — frames the other end dropped — can be
    /// noticed (`crate::video::Depacketizer`).
    pub seq: u32,
    /// The encoded audio, empty for silence.
    pub audio: Vec<u8>,
    /// The video slice, empty in an audio call.
    pub video: Vec<u8>,
}

impl Drop for MediaSealer {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for MediaOpener {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl MediaStream {
    /// Begin an audio-only media stream for `call_id`.
    #[must_use]
    pub fn new(media_secret: &[u8; 32], role: Role, call_id: CallId) -> MediaStream {
        MediaStream::with_mode(media_secret, role, call_id, MediaMode::Audio)
    }

    /// Begin a media stream for `call_id` in the given mode — which must be the
    /// one the offer named, at both ends, or no frame will open.
    #[must_use]
    pub fn with_mode(
        media_secret: &[u8; 32],
        role: Role,
        call_id: CallId,
        mode: MediaMode,
    ) -> MediaStream {
        let keys = MediaKeys::derive(media_secret, role);
        MediaStream {
            sealer: MediaSealer {
                key: keys.send,
                call_id,
                next_send: 0,
                mode,
            },
            opener: MediaOpener {
                key: keys.recv,
                call_id,
                highest_recv: 0,
                started: false,
                mode,
            },
        }
    }

    /// Separate the halves, for a sending thread and a receiving thread.
    #[must_use]
    pub fn split(self) -> (MediaSealer, MediaOpener) {
        (self.sealer, self.opener)
    }

    /// See [`MediaSealer::seal`].
    pub fn seal(&mut self, audio: &[u8]) -> Result<Vec<u8>> {
        self.sealer.seal(audio)
    }

    /// See [`MediaOpener::open`].
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        self.opener.open(frame)
    }

    /// How many frames this end has sent.
    #[must_use]
    pub fn frames_sent(&self) -> u32 {
        self.sealer.frames_sent()
    }

    /// See [`MediaSealer::seal_silence`].
    pub fn seal_silence(&mut self) -> Result<Vec<u8>> {
        self.sealer.seal_silence()
    }

    /// See [`MediaSealer::seal_av`].
    pub fn seal_av(&mut self, audio: &[u8], video: &[u8]) -> Result<Vec<u8>> {
        self.sealer.seal_av(audio, video)
    }

    /// See [`MediaOpener::open_av`].
    pub fn open_av(&mut self, frame: &[u8]) -> Result<MediaFrame> {
        self.opener.open_av(frame)
    }
}

impl MediaSealer {
    /// Seal one audio frame into a wire frame of exactly this call's
    /// [`MediaMode::frame_len`] — in a video call, with an empty video slice.
    ///
    /// `audio` is whatever the platform's encoder produced; this layer does
    /// not know or care what codec that was.
    pub fn seal(&mut self, audio: &[u8]) -> Result<Vec<u8>> {
        self.seal_av(audio, &[])
    }

    /// Seal one frame of audio and, in a video call, one video slice.
    ///
    /// Both are length-prefixed inside the encryption and padded outside
    /// their lengths, so the wire frame is one size whatever either carries.
    pub fn seal_av(&mut self, audio: &[u8], video: &[u8]) -> Result<Vec<u8>> {
        if audio.len() > MEDIA_PAYLOAD_LEN || video.len() > self.mode.video_capacity() {
            return Err(ProtoError::Malformed);
        }
        let seq = self.next_send;
        self.next_send = seq.checked_add(1).ok_or(ProtoError::NotReady)?;

        let mut plaintext = Vec::with_capacity(self.mode.plaintext_len() + aead::TAG_LEN);
        plaintext.extend_from_slice(&(audio.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(audio);
        plaintext.resize(2 + MEDIA_PAYLOAD_LEN, 0);
        if self.mode == MediaMode::Video {
            plaintext.extend_from_slice(&(video.len() as u16).to_be_bytes());
            plaintext.extend_from_slice(video);
            plaintext.resize(self.mode.plaintext_len(), 0);
        }

        let nonce = aead::nonce_from_counter(seq as u64);
        let sealed = aead::seal(&self.key, &nonce, &self.call_id, &plaintext);
        plaintext.zeroize();

        let mut out = Vec::with_capacity(self.mode.frame_len());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), self.mode.frame_len());
        Ok(out)
    }

    /// This call's mode.
    #[must_use]
    pub fn mode(&self) -> MediaMode {
        self.mode
    }

    /// A frame of silence, for the cadence to keep running while nobody is
    /// speaking. Constant bitrate is the point; see the module docs.
    pub fn seal_silence(&mut self) -> Result<Vec<u8>> {
        self.seal(&[])
    }

    /// How many frames this end has sent.
    #[must_use]
    pub fn frames_sent(&self) -> u32 {
        self.next_send
    }
}

impl MediaOpener {
    /// Open one wire frame, returning the audio it carried — empty for an
    /// authenticated frame of silence.
    ///
    /// Frames that do not authenticate are an error and must be dropped by the
    /// caller, not played. Late and duplicate frames are rejected here rather
    /// than left for the jitter buffer to trip over: a replayed frame is a
    /// repeated syllable, which is both audible and a way to feed the same
    /// audio twice.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        Ok(self.open_av(frame)?.audio)
    }

    /// Open one wire frame of this call's mode, returning its sequence number,
    /// its audio, and its video slice. The same rules as [`MediaOpener::open`]:
    /// a frame that does not authenticate, or that is not newer than every
    /// frame already opened, is refused and changes nothing.
    pub fn open_av(&mut self, frame: &[u8]) -> Result<MediaFrame> {
        if frame.len() != self.mode.frame_len() {
            return Err(ProtoError::Malformed);
        }
        let seq = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        if self.started && seq <= self.highest_recv {
            return Err(ProtoError::DecryptionFailed);
        }

        let nonce = aead::nonce_from_counter(seq as u64);
        let mut plaintext = aead::open(&self.key, &nonce, &self.call_id, &frame[4..])
            .map_err(|_| ProtoError::DecryptionFailed)?;
        if plaintext.len() != self.mode.plaintext_len() {
            plaintext.zeroize();
            return Err(ProtoError::Malformed);
        }
        let audio_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        let video_at = 2 + MEDIA_PAYLOAD_LEN;
        let video_len = if self.mode == MediaMode::Video {
            u16::from_be_bytes([plaintext[video_at], plaintext[video_at + 1]]) as usize
        } else {
            0
        };
        if audio_len > MEDIA_PAYLOAD_LEN || video_len > self.mode.video_capacity() {
            plaintext.zeroize();
            return Err(ProtoError::Malformed);
        }

        // Only now, with the frame authenticated, does the stream advance.
        self.highest_recv = seq;
        self.started = true;

        let audio = plaintext[2..2 + audio_len].to_vec();
        let video = if video_len > 0 {
            plaintext[video_at + 2..video_at + 2 + video_len].to_vec()
        } else {
            Vec::new()
        };
        plaintext.zeroize();
        Ok(MediaFrame { seq, audio, video })
    }

    /// This call's mode.
    #[must_use]
    pub fn mode(&self) -> MediaMode {
        self.mode
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
            1_700_000_000,
            false,
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
                assert_eq!(d.sent_at, 1_700_000_000);
                assert!(!d.video);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn the_video_flag_travels_in_the_offer() {
        let o = CallOffer::new("abc.onion", 9999, 5, true).unwrap();
        assert_eq!(o.mode(), MediaMode::Video);
        match CallSignal::decode(&CallSignal::Offer(o.clone()).encode()).unwrap() {
            CallSignal::Offer(d) => assert!(d.video),
            _ => panic!("wrong variant"),
        }
        // An unknown flag bit is a newer client's offer, not a guess to make.
        let mut bytes = CallSignal::Offer(o).encode();
        *bytes.last_mut().unwrap() = 0x80;
        assert!(CallSignal::decode(&bytes).is_err());
    }

    #[test]
    fn a_video_frame_carries_audio_and_a_slice_at_one_size() {
        let o = CallOffer::new("abc.onion", 9999, 5, true).unwrap();
        let (mut send, _) =
            MediaStream::with_mode(&o.media_secret, Role::Caller, o.call_id, o.mode()).split();
        let mut callee = MediaStream::with_mode(&o.media_secret, Role::Callee, o.call_id, o.mode());

        let a = send.seal_av(b"opus", &[9u8; VIDEO_SLICE_LEN]).unwrap();
        let b = send.seal_av(&[], &[]).unwrap();
        let c = send.seal(b"just audio").unwrap();
        for f in [&a, &b, &c] {
            assert_eq!(
                f.len(),
                VIDEO_FRAME_LEN,
                "camera on or off, one size on the wire"
            );
        }
        let fa = callee.open_av(&a).unwrap();
        assert_eq!(
            (fa.seq, fa.audio.as_slice(), fa.video.len()),
            (0, &b"opus"[..], VIDEO_SLICE_LEN)
        );
        let fb = callee.open_av(&b).unwrap();
        assert!(fb.audio.is_empty() && fb.video.is_empty());
        assert_eq!(callee.open(&c).unwrap(), b"just audio");
    }

    #[test]
    fn the_two_modes_cannot_open_each_others_frames() {
        let secret = [5u8; 32];
        let id = [6u8; 16];
        let mut video = MediaStream::with_mode(&secret, Role::Caller, id, MediaMode::Video);
        let mut audio_callee = MediaStream::with_mode(&secret, Role::Callee, id, MediaMode::Audio);
        assert!(audio_callee.open(&video.seal(b"x").unwrap()).is_err());

        let mut audio = MediaStream::new(&secret, Role::Caller, id);
        let mut video_callee = MediaStream::with_mode(&secret, Role::Callee, id, MediaMode::Video);
        assert!(video_callee.open(&audio.seal(b"x").unwrap()).is_err());
        // And an audio call cannot carry video at all.
        assert!(audio.seal_av(b"x", b"y").is_err());
        assert!(video.seal_av(b"x", &[0u8; VIDEO_SLICE_LEN + 1]).is_err());
    }

    #[test]
    fn the_video_disclosure_says_what_is_true() {
        let d = VIDEO_CALL_DISCLOSURE;
        assert!(d.contains("bigger stream than a voice call"));
        assert!(d.contains("tell the two apart"));
        assert!(d.contains("does not change what they see"));
        assert!(!d.to_lowercase().contains("location"));
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
            CallSignal::End(CallEnd {
                call_id: id,
                reason: EndReason::Busy,
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
        assert!(CallOffer::new("", 1, 0, false).is_err());
        assert!(CallOffer::new(&"a".repeat(MAX_ONION_LEN + 1), 1, 0, false).is_err());
    }

    #[test]
    fn the_split_halves_talk_to_the_other_end_independently() {
        // Two threads — one sending, one receiving — each own one half. The
        // halves must interoperate with a whole stream on the other end, and
        // neither may depend on the other's counter.
        let o = offer();
        let (mut caller_send, mut caller_recv) =
            MediaStream::new(&o.media_secret, Role::Caller, o.call_id).split();
        let mut callee = MediaStream::new(&o.media_secret, Role::Callee, o.call_id);

        for i in 0..3u8 {
            let frame = caller_send.seal(&[i]).unwrap();
            assert_eq!(callee.open(&frame).unwrap(), vec![i]);
        }
        let back = callee.seal_silence().unwrap();
        assert_eq!(
            caller_recv.open(&back).unwrap(),
            Vec::<u8>::new(),
            "authenticated silence"
        );
        assert_eq!(caller_send.frames_sent(), 3);
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
