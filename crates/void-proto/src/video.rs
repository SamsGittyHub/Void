//! Video over a constant-bitrate lane (D-033).
//!
//! ## The constraint this module exists to meet
//!
//! A video encoder's output is anything but constant: a keyframe is ten times
//! the size of the frames around it, and how big each frame is tracks how much
//! moved in front of the camera. Packets that follow that shape tell anyone
//! counting bytes when someone moved, when the scene changed, and — as
//! [`crate::call`] already argues for speech — more than that with enough
//! effort. So video does not get packets of its own.
//!
//! Instead every media frame of a video call carries a slice of fixed capacity
//! ([`crate::call::VIDEO_SLICE_LEN`]), sealed with that frame's audio, on the
//! same 20 ms cadence. [`Packetizer`] cuts encoded video units into those
//! slices and pads the rest; when there is nothing to send — the camera is
//! off, or the encoder is between frames — the slice is empty and the frame on
//! the wire is exactly the size it always is. Turning the camera off changes
//! what the other person sees and nothing the network sees.
//!
//! ## What happens when the circuit falls behind
//!
//! The media writer drops whole frames rather than queue behind a stalled
//! circuit (D-028), so a video unit can lose a slice in the middle. Frames
//! carry sequence numbers, so [`Depacketizer`] notices the gap, throws the
//! broken unit away, and refuses every unit after it until a keyframe arrives
//! — a decoder fed a frame whose reference is missing shows garbage. While it
//! waits it asks for a keyframe in its own outgoing slices, and the other end's
//! [`Packetizer::needs_keyframe`] turns that into one, held off while one is
//! still on its way so that two ends cannot ask each other into a loop of
//! keyframes abandoning keyframes.
//!
//! ## What this module does not know
//!
//! Which codec. A unit is opaque bytes plus a keyframe flag, a rotation and a
//! timestamp; the platforms agree on H.264 Annex B between themselves, and
//! the core never parses it, exactly as it never parses Opus.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::call::VIDEO_SLICE_LEN;

/// Bytes of slice header: flags, unit sequence, offset.
pub const SLICE_HEADER_LEN: usize = 7;

/// Unit bytes one slice carries.
pub const SLICE_PAYLOAD_LEN: usize = VIDEO_SLICE_LEN - SLICE_HEADER_LEN;

/// Bytes of unit header: flags, timestamp, length.
pub const UNIT_HEADER_LEN: usize = 9;

/// The largest encoded video unit carried. A keyframe at the resolutions this
/// lane can carry is tens of kilobytes; anything near this is a broken
/// encoder, and refusing it bounds what a peer can make us buffer.
pub const MAX_UNIT_LEN: usize = 512 * 1024;

/// How much encoded video may wait for the lane, about one second of it. More
/// than that is delay that never goes away, so a frame that would exceed it is
/// dropped and the next one made a keyframe.
pub const MAX_QUEUED_BYTES: usize = SLICE_PAYLOAD_LEN * 50;

/// Slices after a keyframe finished sending during which a request for another
/// is ignored: one second, about what the request takes to stop arriving once
/// the keyframe has.
pub const KEYFRAME_HOLDOFF_SLICES: u32 = 50;

/// Completed units held for the platform to take. A platform that stops taking
/// them gets a fresh keyframe later rather than unbounded memory now.
const MAX_READY_UNITS: usize = 30;

const SLICE_HAS_DATA: u8 = 0x01;
const SLICE_WANTS_KEYFRAME: u8 = 0x02;
const SLICE_CAMERA_OFF: u8 = 0x04;
const SLICE_KNOWN_FLAGS: u8 = SLICE_HAS_DATA | SLICE_WANTS_KEYFRAME | SLICE_CAMERA_OFF;

const UNIT_KEYFRAME: u8 = 0x01;
const UNIT_ROTATION_SHIFT: u8 = 1;
const UNIT_KNOWN_FLAGS: u8 = UNIT_KEYFRAME | (0x03 << UNIT_ROTATION_SHIFT);

/// One encoded video frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VideoUnit {
    /// Whether this unit decodes on its own.
    pub keyframe: bool,
    /// Quarter turns clockwise the picture should be rotated to display
    /// upright, 0 to 3.
    pub rotation: u8,
    /// Milliseconds since the sender's call started, by the sender's clock.
    pub timestamp_ms: u32,
    /// The encoded frame. Opaque here.
    pub data: Vec<u8>,
}

impl VideoUnit {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(UNIT_HEADER_LEN + self.data.len());
        out.push(u8::from(self.keyframe) | ((self.rotation & 0x03) << UNIT_ROTATION_SHIFT));
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

/// What became of a unit handed to [`Packetizer::push`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Push {
    /// It will go out in the coming slices.
    Queued,
    /// It was dropped: too large, empty, or the lane is a second behind. The
    /// other end will be missing a frame its successors refer to, so
    /// [`Packetizer::needs_keyframe`] now says to encode a keyframe.
    Dropped,
}

struct Outgoing {
    seq: u16,
    keyframe: bool,
    bytes: Vec<u8>,
    offset: usize,
}

/// The sending side: encoded units in, fixed-capacity slices out, one per
/// media frame.
pub struct Packetizer {
    queue: VecDeque<(bool, Vec<u8>)>,
    queued_bytes: usize,
    current: Option<Outgoing>,
    next_seq: u16,
    camera_off: bool,
    wants_keyframe: bool,
    dropped_since_keyframe: bool,
    slices_since_keyframe_sent: u32,
}

impl Default for Packetizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Packetizer {
    /// A lane with nothing queued.
    #[must_use]
    pub fn new() -> Packetizer {
        Packetizer {
            queue: VecDeque::new(),
            queued_bytes: 0,
            current: None,
            next_seq: 0,
            camera_off: false,
            wants_keyframe: false,
            dropped_since_keyframe: false,
            slices_since_keyframe_sent: u32::MAX,
        }
    }

    /// Queue one encoded unit.
    ///
    /// A keyframe makes everything queued before it pointless — the other end
    /// can decode from it alone — so it replaces the queue, and a delta frame
    /// half sent. A keyframe already on its way is let finish.
    pub fn push(&mut self, unit: &VideoUnit) -> Push {
        if unit.data.is_empty() || unit.data.len() > MAX_UNIT_LEN {
            self.dropped_since_keyframe = true;
            return Push::Dropped;
        }
        let bytes = unit.encode();
        if unit.keyframe {
            self.queue.clear();
            self.queued_bytes = 0;
            if matches!(&self.current, Some(c) if !c.keyframe) {
                self.current = None;
            }
            self.dropped_since_keyframe = false;
        } else if self.queued_bytes + bytes.len() > MAX_QUEUED_BYTES {
            self.dropped_since_keyframe = true;
            return Push::Dropped;
        }
        self.queued_bytes += bytes.len();
        self.queue.push_back((unit.keyframe, bytes));
        Push::Queued
    }

    /// The next slice, for the next media frame: at most
    /// [`crate::call::VIDEO_SLICE_LEN`] bytes, carrying unit data if there is
    /// any and this end's flags either way.
    pub fn next_slice(&mut self) -> Vec<u8> {
        self.slices_since_keyframe_sent = self.slices_since_keyframe_sent.saturating_add(1);
        if self.current.is_none() {
            if let Some((keyframe, bytes)) = self.queue.pop_front() {
                self.queued_bytes -= bytes.len();
                let seq = self.next_seq;
                self.next_seq = self.next_seq.wrapping_add(1);
                self.current = Some(Outgoing {
                    seq,
                    keyframe,
                    bytes,
                    offset: 0,
                });
            }
        }

        let mut flags = 0u8;
        if self.wants_keyframe {
            flags |= SLICE_WANTS_KEYFRAME;
        }
        if self.camera_off {
            flags |= SLICE_CAMERA_OFF;
        }
        let mut out = Vec::with_capacity(VIDEO_SLICE_LEN);
        let mut finished_keyframe = None;
        match &mut self.current {
            Some(cur) => {
                out.push(flags | SLICE_HAS_DATA);
                out.extend_from_slice(&cur.seq.to_be_bytes());
                out.extend_from_slice(&(cur.offset as u32).to_be_bytes());
                let end = core::cmp::min(cur.offset + SLICE_PAYLOAD_LEN, cur.bytes.len());
                out.extend_from_slice(&cur.bytes[cur.offset..end]);
                cur.offset = end;
                if end == cur.bytes.len() {
                    finished_keyframe = Some(cur.keyframe);
                }
            }
            None => {
                out.push(flags);
                out.extend_from_slice(&[0u8; SLICE_HEADER_LEN - 1]);
            }
        }
        if let Some(was_keyframe) = finished_keyframe {
            self.current = None;
            if was_keyframe {
                self.slices_since_keyframe_sent = 0;
            }
        }
        out
    }

    /// The media writer dropped the frame that carried `slice`, because the
    /// circuit was backed up. If it carried unit data, the rest of that unit is
    /// worthless to the other end, so it is abandoned here at once, and the
    /// next unit must be a keyframe.
    pub fn note_dropped(&mut self, slice: &[u8]) {
        if slice.len() < SLICE_HEADER_LEN || slice[0] & SLICE_HAS_DATA == 0 {
            return;
        }
        self.dropped_since_keyframe = true;
        let seq = u16::from_be_bytes([slice[1], slice[2]]);
        if matches!(&self.current, Some(c) if c.seq == seq) {
            self.current = None;
        }
    }

    /// Whether the platform should make its next encoded frame a keyframe:
    /// because something was dropped since the last one, or because the other
    /// end asked (`peer_asked`) and no keyframe is queued, in flight, or less
    /// than [`KEYFRAME_HOLDOFF_SLICES`] behind us.
    #[must_use]
    pub fn needs_keyframe(&self, peer_asked: bool) -> bool {
        if self.dropped_since_keyframe {
            return true;
        }
        let pending = matches!(&self.current, Some(c) if c.keyframe)
            || self.queue.iter().any(|(keyframe, _)| *keyframe);
        peer_asked && !pending && self.slices_since_keyframe_sent >= KEYFRAME_HOLDOFF_SLICES
    }

    /// Say in every slice that this end's camera is off, so the other end shows
    /// a placeholder instead of the last frame frozen. Inside the encryption,
    /// and the slices are the same size either way.
    pub fn set_camera_off(&mut self, off: bool) {
        self.camera_off = off;
    }

    /// Ask the other end for a keyframe in every slice until this is cleared.
    pub fn set_wants_keyframe(&mut self, wants: bool) {
        self.wants_keyframe = wants;
    }

    /// Bytes of encoded video waiting for the lane.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
            + self
                .current
                .as_ref()
                .map(|c| c.bytes.len() - c.offset)
                .unwrap_or(0)
    }
}

struct Incoming {
    seq: u16,
    bytes: Vec<u8>,
    total: usize,
}

/// The receiving side: slices in, whole units out, broken ones never.
pub struct Depacketizer {
    partial: Option<Incoming>,
    last_frame: Option<u32>,
    awaiting_keyframe: bool,
    peer_wants_keyframe: bool,
    peer_camera_off: bool,
    ready: VecDeque<VideoUnit>,
}

impl Default for Depacketizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Depacketizer {
    /// A receiver waiting for its first keyframe.
    #[must_use]
    pub fn new() -> Depacketizer {
        Depacketizer {
            partial: None,
            last_frame: None,
            awaiting_keyframe: true,
            peer_wants_keyframe: false,
            peer_camera_off: false,
            ready: VecDeque::new(),
        }
    }

    /// Feed the video part of one authenticated media frame whose sequence
    /// number was `frame_seq`.
    ///
    /// Anything malformed is treated as loss — the unit it belongs to is
    /// dropped and a keyframe awaited — never as an error that could end the
    /// call: a peer's encoder misbehaving costs pictures, not the conversation.
    pub fn push(&mut self, frame_seq: u32, slice: &[u8]) {
        // Frames the other end dropped while its circuit was backed up show up
        // as a gap. Whatever unit spanned it is gone — and a whole small unit
        // may have been in it, leaving no partial here to notice, so any gap
        // means waiting for a keyframe.
        if let Some(last) = self.last_frame {
            if frame_seq != last.wrapping_add(1) {
                self.lose();
            }
        }
        self.last_frame = Some(frame_seq);

        if slice.len() < SLICE_HEADER_LEN {
            return;
        }
        let flags = slice[0];
        if flags & !SLICE_KNOWN_FLAGS != 0 {
            self.lose();
            return;
        }
        self.peer_camera_off = flags & SLICE_CAMERA_OFF != 0;
        if flags & SLICE_WANTS_KEYFRAME != 0 {
            self.peer_wants_keyframe = true;
        }
        if flags & SLICE_HAS_DATA == 0 {
            return;
        }
        let seq = u16::from_be_bytes([slice[1], slice[2]]);
        let offset = u32::from_be_bytes([slice[3], slice[4], slice[5], slice[6]]) as usize;
        let payload = &slice[SLICE_HEADER_LEN..];
        if payload.is_empty() {
            self.lose();
            return;
        }

        if offset == 0 {
            if payload.len() < UNIT_HEADER_LEN {
                self.lose();
                return;
            }
            let unit_flags = payload[0];
            let len = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]) as usize;
            if unit_flags & !UNIT_KNOWN_FLAGS != 0 || len == 0 || len > MAX_UNIT_LEN {
                self.lose();
                return;
            }
            let total = UNIT_HEADER_LEN + len;
            if payload.len() > total {
                self.lose();
                return;
            }
            // A unit that never finished is lost, and every delta frame after
            // it with it — unless what replaces it is a keyframe, which
            // needs nothing that came before.
            if self.partial.take().is_some() && unit_flags & UNIT_KEYFRAME == 0 {
                self.awaiting_keyframe = true;
            }
            let mut bytes = Vec::with_capacity(total);
            bytes.extend_from_slice(payload);
            self.partial = Some(Incoming { seq, bytes, total });
        } else {
            let fits = matches!(
                &self.partial,
                Some(p) if p.seq == seq && p.bytes.len() == offset && offset + payload.len() <= p.total
            );
            if !fits {
                self.lose();
                return;
            }
            if let Some(p) = &mut self.partial {
                p.bytes.extend_from_slice(payload);
            }
        }

        if matches!(&self.partial, Some(p) if p.bytes.len() == p.total) {
            if let Some(done) = self.partial.take() {
                self.finish(done);
            }
        }
    }

    fn lose(&mut self) {
        self.partial = None;
        self.awaiting_keyframe = true;
    }

    /// Forget everything in progress and wait for a keyframe — for a receiver
    /// whose platform stopped taking units and dropped the ones waiting.
    pub fn restart(&mut self) {
        self.lose();
        self.ready.clear();
    }

    fn finish(&mut self, unit: Incoming) {
        let flags = unit.bytes[0];
        let keyframe = flags & UNIT_KEYFRAME != 0;
        if !keyframe && self.awaiting_keyframe {
            // Its reference is missing. A decoder would show garbage.
            return;
        }
        if keyframe {
            self.awaiting_keyframe = false;
        }
        if self.ready.len() >= MAX_READY_UNITS {
            // Nobody is taking units. Dropping only the oldest would leave a
            // delta frame without its reference, so start over from a
            // keyframe instead.
            self.ready.clear();
            self.awaiting_keyframe = true;
            if !keyframe {
                return;
            }
            self.awaiting_keyframe = false;
        }
        let timestamp_ms =
            u32::from_be_bytes([unit.bytes[1], unit.bytes[2], unit.bytes[3], unit.bytes[4]]);
        self.ready.push_back(VideoUnit {
            keyframe,
            rotation: (flags >> UNIT_ROTATION_SHIFT) & 0x03,
            timestamp_ms,
            data: unit.bytes[UNIT_HEADER_LEN..].to_vec(),
        });
    }

    /// The next whole unit, oldest first.
    pub fn take_unit(&mut self) -> Option<VideoUnit> {
        self.ready.pop_front()
    }

    /// Whether the other end asked for a keyframe since this was last asked.
    pub fn take_keyframe_request(&mut self) -> bool {
        core::mem::take(&mut self.peer_wants_keyframe)
    }

    /// Whether the other end says its camera is off.
    #[must_use]
    pub fn peer_camera_off(&self) -> bool {
        self.peer_camera_off
    }

    /// Whether this end is discarding units until a keyframe arrives — and so
    /// should be asking for one.
    #[must_use]
    pub fn awaiting_keyframe(&self) -> bool {
        self.awaiting_keyframe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(keyframe: bool, len: usize, fill: u8) -> VideoUnit {
        VideoUnit {
            keyframe,
            rotation: 1,
            timestamp_ms: 1234,
            data: vec![fill; len],
        }
    }

    /// Drive `n` slices from a packetizer into a depacketizer, frame sequence
    /// numbers consecutive from `start`.
    fn pump(p: &mut Packetizer, d: &mut Depacketizer, start: u32, n: u32) -> u32 {
        for i in 0..n {
            let slice = p.next_slice();
            assert!(slice.len() <= VIDEO_SLICE_LEN);
            d.push(start + i, &slice);
        }
        start + n
    }

    #[test]
    fn units_cross_the_lane_whole_and_in_order() {
        let mut p = Packetizer::new();
        let mut d = Depacketizer::new();
        assert_eq!(p.push(&unit(true, 5000, 1)), Push::Queued);
        assert_eq!(p.push(&unit(false, 700, 2)), Push::Queued);
        assert_eq!(p.push(&unit(false, 10, 3)), Push::Queued);
        pump(&mut p, &mut d, 0, 40);
        let a = d.take_unit().unwrap();
        assert!(a.keyframe);
        assert_eq!(a.rotation, 1);
        assert_eq!(a.timestamp_ms, 1234);
        assert_eq!(a.data, vec![1u8; 5000]);
        assert_eq!(d.take_unit().unwrap().data, vec![2u8; 700]);
        assert_eq!(d.take_unit().unwrap().data, vec![3u8; 10]);
        assert!(d.take_unit().is_none());
        assert!(!d.awaiting_keyframe());
    }

    #[test]
    fn delta_frames_before_the_first_keyframe_are_not_shown() {
        let mut p = Packetizer::new();
        let mut d = Depacketizer::new();
        p.push(&unit(false, 100, 9));
        pump(&mut p, &mut d, 0, 5);
        assert!(d.take_unit().is_none(), "nothing to decode it against");
        assert!(d.awaiting_keyframe());
        p.push(&unit(true, 100, 1));
        pump(&mut p, &mut d, 5, 5);
        assert!(d.take_unit().unwrap().keyframe);
    }

    #[test]
    fn a_dropped_frame_mid_unit_loses_the_unit_and_asks_for_a_keyframe() {
        let mut p = Packetizer::new();
        let mut d = Depacketizer::new();
        p.push(&unit(true, 600, 1));
        let next = pump(&mut p, &mut d, 0, 3);
        assert!(d.take_unit().is_some());

        // A delta frame three slices long; the middle slice is lost on the way.
        p.push(&unit(false, 3 * SLICE_PAYLOAD_LEN - UNIT_HEADER_LEN, 2));
        d.push(next, &p.next_slice());
        let _lost = p.next_slice();
        d.push(next + 2, &p.next_slice());
        assert!(
            d.take_unit().is_none(),
            "a broken unit must never reach a decoder"
        );
        assert!(d.awaiting_keyframe());

        // Later delta frames are refused too: their reference is broken.
        p.push(&unit(false, 50, 3));
        pump(&mut p, &mut d, next + 3, 2);
        assert!(d.take_unit().is_none());

        // The request goes back in our own slices, and a keyframe ends it.
        let mut ours = Packetizer::new();
        ours.set_wants_keyframe(d.awaiting_keyframe());
        let mut theirs = Depacketizer::new();
        theirs.push(0, &ours.next_slice());
        assert!(theirs.take_keyframe_request());
        assert!(!theirs.take_keyframe_request(), "taken once");

        p.push(&unit(true, 50, 4));
        pump(&mut p, &mut d, next + 5, 2);
        assert_eq!(d.take_unit().unwrap().data, vec![4u8; 50]);
        assert!(!d.awaiting_keyframe());
    }

    #[test]
    fn a_keyframe_supersedes_queued_and_half_sent_delta_frames() {
        let mut p = Packetizer::new();
        let mut d = Depacketizer::new();
        p.push(&unit(true, 10, 1));
        let next = pump(&mut p, &mut d, 0, 1);
        d.take_unit().unwrap();

        p.push(&unit(false, 3 * SLICE_PAYLOAD_LEN, 2));
        p.push(&unit(false, 100, 3));
        let next = pump(&mut p, &mut d, next, 1); // the first delta frame is half sent
        p.push(&unit(true, 100, 4));
        pump(&mut p, &mut d, next, 5);
        let got = d.take_unit().unwrap();
        assert!(got.keyframe);
        assert_eq!(got.data, vec![4u8; 100]);
        assert!(d.take_unit().is_none());
        assert!(
            !d.awaiting_keyframe(),
            "a keyframe replacing a partial needs nothing else"
        );
    }

    #[test]
    fn a_keyframe_on_its_way_is_never_abandoned_for_another() {
        // Two ends asking each other for keyframes must not end up with each
        // keyframe cancelling the one before it, forever.
        let mut p = Packetizer::new();
        let mut d = Depacketizer::new();
        p.push(&unit(true, 4 * SLICE_PAYLOAD_LEN, 1));
        let next = pump(&mut p, &mut d, 0, 2);
        p.push(&unit(true, 10, 2));
        pump(&mut p, &mut d, next, 10);
        assert_eq!(d.take_unit().unwrap().data[0], 1);
        assert_eq!(d.take_unit().unwrap().data[0], 2);
    }

    #[test]
    fn keyframe_requests_are_held_off_while_one_is_on_its_way() {
        let mut p = Packetizer::new();
        assert!(p.needs_keyframe(true), "nothing sent yet");
        assert!(!p.needs_keyframe(false));
        p.push(&unit(true, 3000, 1));
        assert!(!p.needs_keyframe(true), "one is queued");
        for _ in 0..10 {
            p.next_slice();
        }
        assert!(!p.needs_keyframe(true), "it just finished");
        for _ in 0..KEYFRAME_HOLDOFF_SLICES {
            p.next_slice();
        }
        assert!(p.needs_keyframe(true), "the holdoff has passed");
    }

    #[test]
    fn falling_a_second_behind_drops_delta_frames_and_demands_a_keyframe() {
        let mut p = Packetizer::new();
        p.push(&unit(true, 10, 1));
        p.next_slice();
        for _ in 0..1000 {
            p.next_slice(); // clear any holdoff
        }
        let mut dropped = false;
        for _ in 0..200 {
            if p.push(&unit(false, 1000, 2)) == Push::Dropped {
                dropped = true;
                break;
            }
        }
        assert!(dropped);
        assert!(p.queued_bytes() <= MAX_QUEUED_BYTES);
        assert!(
            p.needs_keyframe(false),
            "the other end is now missing a reference"
        );
        p.push(&unit(true, 10, 3));
        assert!(!p.needs_keyframe(false));
    }

    #[test]
    fn a_slice_the_writer_dropped_abandons_its_unit_and_demands_a_keyframe() {
        let mut p = Packetizer::new();
        p.push(&unit(true, 3 * SLICE_PAYLOAD_LEN, 1));
        let first = p.next_slice();
        assert!(!p.needs_keyframe(false));
        p.note_dropped(&first);
        assert_eq!(
            p.queued_bytes(),
            0,
            "the rest of a broken unit is not worth sending"
        );
        assert!(p.needs_keyframe(false));
        // An idle slice dropped costs nothing.
        let mut q = Packetizer::new();
        let idle = q.next_slice();
        q.note_dropped(&idle);
        assert!(!q.needs_keyframe(false));
    }

    #[test]
    fn a_gap_with_no_unit_in_progress_still_waits_for_a_keyframe() {
        // A small delta frame fits in one slice; if that frame was dropped,
        // there is no partial to notice, only the gap.
        let mut p = Packetizer::new();
        let mut d = Depacketizer::new();
        p.push(&unit(true, 10, 1));
        pump(&mut p, &mut d, 0, 1);
        d.take_unit().unwrap();
        p.push(&unit(false, 10, 2));
        let _lost = p.next_slice();
        p.push(&unit(false, 10, 3));
        d.push(2, &p.next_slice());
        assert!(d.take_unit().is_none());
        assert!(d.awaiting_keyframe());
    }

    #[test]
    fn every_slice_fits_the_lane_whatever_is_queued() {
        let mut p = Packetizer::new();
        p.push(&unit(true, 100_000, 7));
        for _ in 0..300 {
            let s = p.next_slice();
            assert!(s.len() <= VIDEO_SLICE_LEN);
            assert!(s.len() >= SLICE_HEADER_LEN);
        }
        // Idle.
        assert_eq!(Packetizer::new().next_slice().len(), SLICE_HEADER_LEN);
    }

    #[test]
    fn camera_off_travels_in_every_slice() {
        let mut p = Packetizer::new();
        let mut d = Depacketizer::new();
        p.set_camera_off(true);
        d.push(0, &p.next_slice());
        assert!(d.peer_camera_off());
        p.set_camera_off(false);
        d.push(1, &p.next_slice());
        assert!(!d.peer_camera_off());
    }

    #[test]
    fn hostile_slices_cost_pictures_never_the_call() {
        let mut d = Depacketizer::new();
        let mut seq = 0u32;
        let mut feed = |d: &mut Depacketizer, s: &[u8]| {
            d.push(seq, s);
            seq += 1;
        };
        feed(&mut d, &[]);
        feed(&mut d, &[0xFF; VIDEO_SLICE_LEN]);
        // Claims an enormous unit.
        let mut huge = vec![SLICE_HAS_DATA, 0, 0, 0, 0, 0, 0, UNIT_KEYFRAME, 0, 0, 0, 0];
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        feed(&mut d, &huge);
        // A continuation of nothing.
        feed(&mut d, &[SLICE_HAS_DATA, 0, 5, 0, 0, 1, 0, 9, 9, 9]);
        // Data flagged but none carried.
        feed(&mut d, &[SLICE_HAS_DATA, 0, 0, 0, 0, 0, 0]);
        assert!(d.take_unit().is_none());
        assert!(d.awaiting_keyframe());

        // And a good keyframe still gets through afterwards.
        let mut p = Packetizer::new();
        p.push(&unit(true, 20, 5));
        let s = p.next_slice();
        d.push(seq, &s);
        assert_eq!(d.take_unit().unwrap().data, vec![5u8; 20]);
    }

    #[test]
    fn a_receiver_nobody_drains_starts_over_from_a_keyframe() {
        let mut p = Packetizer::new();
        let mut d = Depacketizer::new();
        p.push(&unit(true, 10, 0));
        let mut next = pump(&mut p, &mut d, 0, 1);
        for i in 0..(MAX_READY_UNITS as u8 + 5) {
            p.push(&unit(false, 10, i));
            next = pump(&mut p, &mut d, next, 1);
        }
        assert!(d.ready.len() <= MAX_READY_UNITS);
        assert!(d.awaiting_keyframe(), "it must ask for a fresh start");
    }
}
