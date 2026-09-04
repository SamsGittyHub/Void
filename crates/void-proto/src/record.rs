//! Fixed-size records and constant-rate padding (FR-MSG-02, FR-MSG-06).
//!
//! ## The size, and why it is what it is
//!
//! [`RECORD_SIZE`] is 1,024 bytes and is a **protocol constant**. It is not
//! configurable, per FR-MSG-02, and the reason is in PRD §2.3: v1.0 allowed a
//! user-configurable chaff rate, which partitions users into fingerprintable
//! buckets and destroys the anonymity set it was supposed to create. A setting
//! that varies per user is a per-user identifier.
//!
//! The value follows from NFR-PERF-03's 50 MB/month cover-traffic budget. At
//! one record every [`PAD_INTERVAL_MS`] while connected, a user with the app
//! open two hours a day emits roughly 43 MB/month. A 4 KB record — large enough
//! to hold a ratchet step in one piece — would be four times that and blow the
//! budget, so ratchet steps fragment instead.
//!
//! ## Fragmentation
//!
//! A ratchet step carries an ML-KEM encapsulation key and ciphertext, about
//! 3.2 KB, so it spans four or five records. Ordinary messages inside a chain
//! fit in one, which is what NFR-PERF-06 asks for.
//!
//! ## Dummy records
//!
//! [`Record::dummy`] produces a record that is byte-indistinguishable from a
//! real one to anyone who cannot decrypt it: same length, same structure, body
//! filled from the system CSPRNG. The type byte lives *inside* the encrypted
//! envelope, so an observer cannot separate padding from payload — only the
//! recipient can. The relay learns deposit timing regardless, which is
//! documented as residual risk §9.3.4 rather than papered over.

use alloc::vec;
use alloc::vec::Vec;

use void_crypto::rand;

use crate::wire::{Reader, Writer};
use crate::{ProtoError, Result};

/// The on-wire record size. A protocol constant, identical for every user.
pub const RECORD_SIZE: usize = 1024;

/// Bytes of framing overhead inside a record: type(1) + msg_id(8) + index(2)
/// + count(2) + body_len(2).
pub const RECORD_HEADER_SIZE: usize = 15;

/// Maximum payload carried by one record.
pub const RECORD_BODY_CAPACITY: usize = RECORD_SIZE - RECORD_HEADER_SIZE;

/// How often a connected client emits a record, real or dummy.
pub const PAD_INTERVAL_MS: u64 = 5_000;

/// Maximum fragments per logical message. Bounds the reassembly buffer a
/// hostile peer can force us to allocate.
pub const MAX_FRAGMENTS: u16 = 512;

/// What a record carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// A fragment of a real payload.
    Payload,
    /// Cover traffic. Carries random bytes and is discarded on receipt.
    Dummy,
}

impl RecordKind {
    fn to_byte(self) -> u8 {
        match self {
            RecordKind::Payload => 1,
            RecordKind::Dummy => 2,
        }
    }

    fn from_byte(b: u8) -> Result<RecordKind> {
        match b {
            1 => Ok(RecordKind::Payload),
            2 => Ok(RecordKind::Dummy),
            _ => Err(ProtoError::RecordError),
        }
    }
}

/// A single fixed-size record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// Payload or cover traffic.
    pub kind: RecordKind,
    /// Identifies the logical message this fragment belongs to.
    pub message_id: u64,
    /// Zero-based fragment index.
    pub index: u16,
    /// Total fragments in this message.
    pub count: u16,
    /// The fragment body. Always padded out to [`RECORD_BODY_CAPACITY`] on
    /// the wire; `body_len` records how much is real.
    pub body: Vec<u8>,
}

impl Record {
    /// Encode to exactly [`RECORD_SIZE`] bytes.
    ///
    /// The unused tail is filled with random bytes rather than zeroes. Zero
    /// padding is compressible and, more importantly, distinguishable from a
    /// full record after any transform that leaks entropy.
    pub fn encode(&self) -> Result<[u8; RECORD_SIZE]> {
        if self.body.len() > RECORD_BODY_CAPACITY {
            return Err(ProtoError::RecordError);
        }
        let mut w = Writer::with_capacity(RECORD_SIZE);
        w.u8(self.kind.to_byte())
            .u64(self.message_id)
            .u16(self.index)
            .u16(self.count)
            .u16(self.body.len() as u16)
            .raw(&self.body);
        let mut buf = w.finish();
        let pad_len = RECORD_SIZE - buf.len();
        let mut pad = vec![0u8; pad_len];
        rand::fill(&mut pad).map_err(|_| ProtoError::Crypto)?;
        buf.extend_from_slice(&pad);
        let mut out = [0u8; RECORD_SIZE];
        out.copy_from_slice(&buf);
        Ok(out)
    }

    /// Decode from exactly [`RECORD_SIZE`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<Record> {
        if bytes.len() != RECORD_SIZE {
            return Err(ProtoError::RecordError);
        }
        let mut r = Reader::new(bytes);
        let kind = RecordKind::from_byte(r.u8()?)?;
        let message_id = r.u64()?;
        let index = r.u16()?;
        let count = r.u16()?;
        let body_len = r.u16()? as usize;
        if body_len > RECORD_BODY_CAPACITY {
            return Err(ProtoError::RecordError);
        }
        let body = r.raw(body_len)?.to_vec();
        // The remainder is padding and is intentionally not examined.
        if count == 0 || count > MAX_FRAGMENTS || index >= count {
            return Err(ProtoError::RecordError);
        }
        Ok(Record {
            kind,
            message_id,
            index,
            count,
            body,
        })
    }

    /// Build a cover-traffic record.
    pub fn dummy() -> Result<Record> {
        let mut body = vec![0u8; RECORD_BODY_CAPACITY];
        rand::fill(&mut body).map_err(|_| ProtoError::Crypto)?;
        let message_id = rand::u64_().map_err(|_| ProtoError::Crypto)?;
        Ok(Record {
            kind: RecordKind::Dummy,
            message_id,
            index: 0,
            count: 1,
            body,
        })
    }
}

/// Split a payload into fixed-size records.
pub fn fragment(message_id: u64, payload: &[u8]) -> Result<Vec<Record>> {
    let count = payload.len().div_ceil(RECORD_BODY_CAPACITY).max(1);
    if count > MAX_FRAGMENTS as usize {
        return Err(ProtoError::RecordError);
    }
    let mut out = Vec::with_capacity(count);
    for (i, chunk) in payload
        .chunks(RECORD_BODY_CAPACITY)
        .chain(if payload.is_empty() {
            Some(&[][..])
        } else {
            None
        })
        .enumerate()
    {
        out.push(Record {
            kind: RecordKind::Payload,
            message_id,
            index: i as u16,
            count: count as u16,
            body: chunk.to_vec(),
        });
    }
    Ok(out)
}

/// Reassembles fragmented payloads.
///
/// Bounded on both axes: at most `max_messages` partial messages, each at most
/// [`MAX_FRAGMENTS`] fragments. A peer cannot make us hold unbounded state by
/// sending fragment 0 of a million different message IDs.
///
/// ## Why the bound evicts instead of failing
///
/// A partial message is not necessarily an attack, and it is never recoverable
/// once its missing fragments are gone. Records expire off the relay after
/// [`crate::queue::DEFAULT_TTL_SECONDS`], a queue can rotate mid-message, and a
/// hostile relay can redeliver one fragment of a five-fragment ratchet step it
/// kept from last month. Every one of those leaves a partial that will never
/// complete.
///
/// A full buffer that returns an error therefore turns any 64 such events —
/// hostile or not — into a conversation that stops receiving forever. So the
/// oldest partial is dropped to make room instead. Losing a stalled message we
/// were never going to reassemble costs nothing; losing the contact costs
/// everything.
pub struct Reassembler {
    partial: alloc::collections::BTreeMap<u64, Partial>,
    max_messages: usize,
    /// Monotonic tick, bumped on every touch, used to pick the eviction
    /// victim. Not a clock: this type has no business knowing the time, and
    /// relative order is all an eviction policy needs.
    tick: u64,
}

struct Partial {
    count: u16,
    fragments: alloc::collections::BTreeMap<u16, Vec<u8>>,
    /// Tick at which this message last received a fragment. A message still
    /// actively arriving must outrank one that stalled.
    last_touched: u64,
}

impl Reassembler {
    /// New reassembler holding at most `max_messages` incomplete messages.
    #[must_use]
    pub fn new(max_messages: usize) -> Reassembler {
        Reassembler {
            partial: alloc::collections::BTreeMap::new(),
            max_messages: max_messages.max(1),
            tick: 0,
        }
    }

    /// Drop the least recently touched partial message.
    fn evict_stalest(&mut self) {
        if let Some(victim) = self
            .partial
            .iter()
            .min_by_key(|(_, p)| p.last_touched)
            .map(|(id, _)| *id)
        {
            self.partial.remove(&victim);
        }
    }

    /// Feed one record. Returns the payload once the message is complete.
    ///
    /// Dummy records return `Ok(None)` and change no state — that is the whole
    /// point of them.
    pub fn push(&mut self, record: &Record) -> Result<Option<Vec<u8>>> {
        if record.kind == RecordKind::Dummy {
            return Ok(None);
        }
        if record.count == 1 {
            return Ok(Some(record.body.clone()));
        }

        // Check the bound before taking the entry, so the mutable borrow does
        // not overlap the length read.
        if !self.partial.contains_key(&record.message_id) && self.partial.len() >= self.max_messages
        {
            self.evict_stalest();
        }
        self.tick += 1;
        let tick = self.tick;
        let partial = self
            .partial
            .entry(record.message_id)
            .or_insert_with(|| Partial {
                count: record.count,
                fragments: alloc::collections::BTreeMap::new(),
                last_touched: tick,
            });

        // A fragment claiming a different total for the same message id is an
        // attempt to confuse reassembly.
        if partial.count != record.count {
            return Err(ProtoError::RecordError);
        }
        partial.last_touched = tick;
        partial.fragments.insert(record.index, record.body.clone());

        if partial.fragments.len() as u16 == partial.count {
            let mut out = Vec::new();
            for i in 0..partial.count {
                out.extend_from_slice(partial.fragments.get(&i).ok_or(ProtoError::RecordError)?);
            }
            self.partial.remove(&record.message_id);
            return Ok(Some(out));
        }
        Ok(None)
    }

    /// How many incomplete messages are being held.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.partial.len()
    }

    /// Discard all partial state.
    pub fn clear(&mut self) {
        self.partial.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_record_encodes_to_exactly_the_record_size() {
        let cases: Vec<Vec<u8>> = alloc::vec![
            alloc::vec![],
            alloc::vec![1u8],
            alloc::vec![2u8; RECORD_BODY_CAPACITY],
        ];
        for body in cases {
            let r = Record {
                kind: RecordKind::Payload,
                message_id: 1,
                index: 0,
                count: 1,
                body,
            };
            assert_eq!(r.encode().unwrap().len(), RECORD_SIZE);
        }
        assert_eq!(
            Record::dummy().unwrap().encode().unwrap().len(),
            RECORD_SIZE
        );
    }

    #[test]
    fn dummy_and_payload_records_are_the_same_size_on_the_wire() {
        // FR-MSG-06: identical in size. This test is the enforcement.
        let payload = Record {
            kind: RecordKind::Payload,
            message_id: 5,
            index: 0,
            count: 1,
            body: alloc::vec![7u8; 10],
        };
        assert_eq!(
            payload.encode().unwrap().len(),
            Record::dummy().unwrap().encode().unwrap().len()
        );
    }

    #[test]
    fn padding_is_not_constant() {
        // Two encodings of the same record must differ in their padding, or the
        // padding is compressible and therefore distinguishable.
        let r = Record {
            kind: RecordKind::Payload,
            message_id: 1,
            index: 0,
            count: 1,
            body: alloc::vec![1u8, 2, 3],
        };
        let a = r.encode().unwrap();
        let b = r.encode().unwrap();
        assert_ne!(a, b, "record padding must be randomised");
        assert_eq!(&a[..RECORD_HEADER_SIZE + 3], &b[..RECORD_HEADER_SIZE + 3]);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let r = Record {
            kind: RecordKind::Payload,
            message_id: 0xDEAD_BEEF_CAFE_0001,
            index: 2,
            count: 5,
            body: alloc::vec![9u8; 100],
        };
        let enc = r.encode().unwrap();
        assert_eq!(Record::decode(&enc).unwrap(), r);
    }

    #[test]
    fn malformed_records_are_rejected() {
        assert!(Record::decode(&[0u8; 10]).is_err());
        assert!(Record::decode(&[0u8; RECORD_SIZE]).is_err()); // kind 0
        let mut buf = [0u8; RECORD_SIZE];
        buf[0] = 1; // Payload
        buf[9] = 0;
        buf[10] = 3; // index 3
        buf[11] = 0;
        buf[12] = 2; // count 2 -> index >= count
        assert!(Record::decode(&buf).is_err());
    }

    #[test]
    fn oversized_body_is_refused() {
        let r = Record {
            kind: RecordKind::Payload,
            message_id: 1,
            index: 0,
            count: 1,
            body: alloc::vec![0u8; RECORD_BODY_CAPACITY + 1],
        };
        assert!(r.encode().is_err());
    }

    #[test]
    fn fragmentation_roundtrips_at_every_boundary() {
        for len in [
            0usize,
            1,
            RECORD_BODY_CAPACITY - 1,
            RECORD_BODY_CAPACITY,
            RECORD_BODY_CAPACITY + 1,
            3 * RECORD_BODY_CAPACITY,
            3 * RECORD_BODY_CAPACITY + 7,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let records = fragment(42, &payload).unwrap();
            let mut re = Reassembler::new(16);
            let mut got = None;
            for r in &records {
                // Round-trip each through the wire form as well.
                let decoded = Record::decode(&r.encode().unwrap()).unwrap();
                if let Some(v) = re.push(&decoded).unwrap() {
                    got = Some(v);
                }
            }
            assert_eq!(got.unwrap(), payload, "len {len}");
            assert_eq!(re.pending(), 0);
        }
    }

    #[test]
    fn a_ratchet_sized_payload_fragments_as_expected() {
        // ~3.2 KB, the size of a ratchet step with KEM material.
        let payload = alloc::vec![0u8; 3200];
        let records = fragment(1, &payload).unwrap();
        assert_eq!(records.len(), 4, "a ratchet step should span four records");
        // A typical text message must fit in one (NFR-PERF-06).
        assert_eq!(fragment(2, b"see you at the usual place").unwrap().len(), 1);
    }

    #[test]
    fn out_of_order_fragments_reassemble() {
        let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let records = fragment(9, &payload).unwrap();
        let mut re = Reassembler::new(16);
        let mut order: Vec<usize> = (0..records.len()).collect();
        order.reverse();
        let mut got = None;
        for i in order {
            if let Some(v) = re.push(&records[i]).unwrap() {
                got = Some(v);
            }
        }
        assert_eq!(got.unwrap(), payload);
    }

    #[test]
    fn dummy_records_are_discarded_and_do_not_disturb_reassembly() {
        let payload = alloc::vec![3u8; 3000];
        let records = fragment(11, &payload).unwrap();
        let mut re = Reassembler::new(16);
        let mut got = None;
        for r in &records {
            assert!(re.push(&Record::dummy().unwrap()).unwrap().is_none());
            if let Some(v) = re.push(r).unwrap() {
                got = Some(v);
            }
        }
        assert_eq!(got.unwrap(), payload);
    }

    fn frag(id: u64, index: u16, count: u16) -> Record {
        Record {
            kind: RecordKind::Payload,
            message_id: id,
            index,
            count,
            body: alloc::vec![0u8; 10],
        }
    }

    #[test]
    fn reassembler_bounds_are_enforced() {
        let mut re = Reassembler::new(2);
        assert!(re.push(&frag(1, 0, 4)).unwrap().is_none());
        assert!(re.push(&frag(2, 0, 4)).unwrap().is_none());
        assert!(re.push(&frag(3, 0, 4)).unwrap().is_none());
        assert_eq!(re.pending(), 2, "the bound must hold under pressure");
        re.clear();
        assert_eq!(re.pending(), 0);
    }

    #[test]
    fn a_flood_of_stalled_messages_does_not_block_a_real_one() {
        // A relay that keeps redelivering one fragment of old multi-fragment
        // messages must not be able to fill the buffer and stop delivery. The
        // stalled partials are evicted; the message actually arriving lands.
        let mut re = Reassembler::new(4);
        for id in 100..120 {
            assert!(re.push(&frag(id, 0, 4)).unwrap().is_none());
        }
        assert_eq!(re.pending(), 4);

        let payload = alloc::vec![9u8; 2500];
        let records = fragment(7, &payload).unwrap();
        let mut got = None;
        for r in &records {
            if let Some(v) = re.push(r).unwrap() {
                got = Some(v);
            }
        }
        assert_eq!(got.unwrap(), payload);
    }

    #[test]
    fn eviction_takes_the_stalest_message_not_an_arriving_one() {
        // Two messages interleave while a third stalls. The stalled one is the
        // one that goes, even though it was not the first to appear.
        let mut re = Reassembler::new(2);
        assert!(re.push(&frag(1, 0, 3)).unwrap().is_none()); // stalls here
        assert!(re.push(&frag(2, 0, 3)).unwrap().is_none());
        assert!(re.push(&frag(2, 1, 3)).unwrap().is_none()); // still arriving

        assert!(re.push(&frag(3, 0, 3)).unwrap().is_none()); // evicts 1
        assert_eq!(re.pending(), 2);

        // Message 2 kept both of its fragments, so its third completes it.
        assert!(re.push(&frag(2, 2, 3)).unwrap().is_some());
    }

    #[test]
    fn inconsistent_fragment_counts_are_rejected() {
        let mut re = Reassembler::new(4);
        let a = Record {
            kind: RecordKind::Payload,
            message_id: 1,
            index: 0,
            count: 3,
            body: alloc::vec![1u8],
        };
        let b = Record {
            kind: RecordKind::Payload,
            message_id: 1,
            index: 1,
            count: 4,
            body: alloc::vec![2u8],
        };
        assert!(re.push(&a).unwrap().is_none());
        assert!(re.push(&b).is_err());
    }

    #[test]
    fn cover_traffic_budget_matches_the_prd() {
        // NFR-PERF-03: under 50 MB/month. Two hours connected per day.
        let records_per_hour = 3_600_000 / PAD_INTERVAL_MS;
        let bytes_per_month = records_per_hour * (RECORD_SIZE as u64) * 2 * 30;
        assert!(
            bytes_per_month < 50 * 1024 * 1024,
            "cover traffic would be {} MB/month",
            bytes_per_month / 1024 / 1024
        );
    }
}
