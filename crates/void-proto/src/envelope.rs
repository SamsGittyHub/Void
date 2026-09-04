//! Sealed-sender deposits (FR-MSG-03, FR-MSG-04).
//!
//! ## What the relay is allowed to learn
//!
//! Exactly two things: a 16-byte queue identifier, and that a fixed-size opaque
//! blob was deposited into it. Not who deposited it, not what it says, not how
//! it relates to any other deposit.
//!
//! ```text
//!   Deposit on the wire:
//!   +------------------+--------------------------------------+
//!   | queue_id (16 B)  | sealed record (RECORD_SIZE bytes)    |
//!   +------------------+--------------------------------------+
//!                       ^ XChaCha20-Poly1305 under a key only
//!                         the queue owner can derive
//! ```
//!
//! ## Why there is no sender field, and why that is enough
//!
//! Signal's sealed sender encrypts a sender certificate inside the envelope
//! because its delivery address is per-*user*: the server knows the recipient,
//! so the sender must be hidden separately. Void's delivery address is
//! per-*contact-pair* (see [`crate::queue`]). The recipient already knows who
//! owns the queue, so there is nothing to put in a sender field, and the
//! cheapest way to not leak the sender is to never encode it. This is the one
//! place where the mailbox design is strictly simpler *and* strictly stronger
//! than the account-based alternative.
//!
//! ## Nonce discipline
//!
//! Each envelope carries a fresh 24-byte random nonce. With XChaCha20-Poly1305
//! the collision probability over any plausible number of deposits is
//! negligible, which is why this layer uses the extended-nonce variant while
//! the ratchet — where a counter is available and unambiguous — uses the
//! 96-bit form.

use alloc::vec::Vec;

use void_crypto::{aead, rand};

use crate::queue::{DepositKey, QueueId};
use crate::record::{Record, RECORD_SIZE};
use crate::wire::{Reader, Writer};
use crate::{ProtoError, Result};

/// Bytes added by sealing: nonce (24) + Poly1305 tag (16).
pub const SEAL_OVERHEAD: usize = aead::XNONCE_LEN + aead::TAG_LEN;

/// Total on-wire size of a sealed record.
pub const SEALED_RECORD_SIZE: usize = RECORD_SIZE + SEAL_OVERHEAD;

/// A deposit as it travels to and sits on the relay.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Deposit {
    /// The destination queue.
    pub queue_id: QueueId,
    /// The sealed record: always [`SEALED_RECORD_SIZE`] bytes.
    pub sealed: Vec<u8>,
}

impl Deposit {
    /// Canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(16 + 4 + self.sealed.len());
        w.raw(&self.queue_id).bytes32(&self.sealed);
        w.finish()
    }

    /// Decode, enforcing the fixed sealed size.
    ///
    /// The size check is a protocol invariant, not an optimisation: a relay
    /// that accepted variable-size deposits would leak message length, which
    /// is exactly what FR-MSG-02 exists to prevent.
    pub fn decode(bytes: &[u8]) -> Result<Deposit> {
        let mut r = Reader::new(bytes);
        let queue_id = r.array::<16>()?;
        let sealed = r.bytes32_max(SEALED_RECORD_SIZE)?.to_vec();
        r.finish()?;
        if sealed.len() != SEALED_RECORD_SIZE {
            return Err(ProtoError::RecordError);
        }
        Ok(Deposit { queue_id, sealed })
    }
}

/// Seal one record for deposit into the queue `key` addresses.
///
/// Takes a [`DepositKey`] rather than a `QueueSecret` so that the initiator of
/// a handshake — who holds only what a published prekey bundle gave them — can
/// call it. See that type's documentation for the capability split.
pub fn seal(key: &DepositKey, record: &Record) -> Result<Deposit> {
    let plaintext = record.encode()?;
    let nonce = rand::bytes24().map_err(|_| ProtoError::Crypto)?;

    // The queue id is authenticated as associated data, so a relay cannot move
    // a sealed record from one queue to another and have it still open.
    let mut sealed = Vec::with_capacity(SEALED_RECORD_SIZE);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&aead::xseal(
        &key.envelope_key,
        &nonce,
        &key.queue_id,
        &plaintext,
    ));

    debug_assert_eq!(sealed.len(), SEALED_RECORD_SIZE);
    Ok(Deposit {
        queue_id: key.queue_id,
        sealed,
    })
}

/// Open a deposit collected from the queue `key` addresses.
pub fn open(key: &DepositKey, deposit: &Deposit) -> Result<Record> {
    if deposit.sealed.len() != SEALED_RECORD_SIZE {
        return Err(ProtoError::RecordError);
    }
    if !void_crypto::ct::eq(&key.queue_id, &deposit.queue_id) {
        return Err(ProtoError::DecryptionFailed);
    }
    let mut nonce = [0u8; aead::XNONCE_LEN];
    nonce.copy_from_slice(&deposit.sealed[..aead::XNONCE_LEN]);
    let plaintext = aead::xopen(
        &key.envelope_key,
        &nonce,
        &deposit.queue_id,
        &deposit.sealed[aead::XNONCE_LEN..],
    )
    .map_err(|_| ProtoError::DecryptionFailed)?;
    Record::decode(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::QueueSecret;
    use crate::record::RecordKind;

    fn rec(body: &[u8]) -> Record {
        Record {
            kind: RecordKind::Payload,
            message_id: 77,
            index: 0,
            count: 1,
            body: body.to_vec(),
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let q = QueueSecret::from_parts([3u8; 32], 0).deposit_key();
        let r = rec(b"the payload");
        let d = seal(&q, &r).unwrap();
        assert_eq!(open(&q, &d).unwrap(), r);
    }

    #[test]
    fn every_deposit_is_exactly_the_same_size() {
        // The relay must not be able to distinguish a one-byte message from a
        // full record, or from cover traffic.
        let q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
        let a = seal(&q, &rec(b"a")).unwrap();
        let b = seal(&q, &rec(&alloc::vec![0u8; 900])).unwrap();
        let c = seal(&q, &Record::dummy().unwrap()).unwrap();
        assert_eq!(a.sealed.len(), SEALED_RECORD_SIZE);
        assert_eq!(a.sealed.len(), b.sealed.len());
        assert_eq!(a.sealed.len(), c.sealed.len());
        assert_eq!(a.encode().len(), c.encode().len());
    }

    #[test]
    fn the_deposit_contains_no_sender_field() {
        // FR-MSG-03 as an executable claim: the encoded deposit is exactly the
        // queue id, a length, and the sealed bytes. Nothing else fits.
        let q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
        let d = seal(&q, &rec(b"x")).unwrap();
        assert_eq!(d.encode().len(), 16 + 4 + SEALED_RECORD_SIZE);
    }

    #[test]
    fn ciphertexts_differ_across_seals_of_identical_content() {
        let q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
        let r = rec(b"same");
        let a = seal(&q, &r).unwrap();
        let b = seal(&q, &r).unwrap();
        assert_ne!(a.sealed, b.sealed, "nonce reuse would be catastrophic here");
        assert_eq!(a.queue_id, b.queue_id);
    }

    #[test]
    fn a_different_queue_cannot_open() {
        let mine = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
        let theirs = QueueSecret::from_parts([2u8; 32], 0).deposit_key();
        let d = seal(&mine, &rec(b"secret")).unwrap();
        assert!(open(&theirs, &d).is_err());
    }

    #[test]
    fn a_rotated_generation_cannot_open_the_old_queue() {
        let g0 = QueueSecret::from_parts([1u8; 32], 0);
        let d = seal(&g0.deposit_key(), &rec(b"old")).unwrap();
        assert!(open(
            &QueueSecret::from_parts([1u8; 32], 0).rotate().deposit_key(),
            &d
        )
        .is_err());
    }

    #[test]
    fn moving_a_deposit_between_queues_is_detected() {
        // A malicious relay tries to replay Alice's sealed blob into Carol's
        // queue. The queue id is authenticated, so it does not open.
        let q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
        let other = QueueSecret::from_parts([2u8; 32], 0).deposit_key();
        let mut d = seal(&q, &rec(b"x")).unwrap();
        d.queue_id = other.queue_id;
        assert!(open(&other, &d).is_err());
        assert!(open(&q, &d).is_err());
    }

    #[test]
    fn every_single_bit_of_tampering_is_caught() {
        let q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
        let d = seal(&q, &rec(b"integrity")).unwrap();
        for i in [0usize, 1, 23, 24, 100, SEALED_RECORD_SIZE - 1] {
            let mut bad = d.clone();
            bad.sealed[i] ^= 1;
            assert!(open(&q, &bad).is_err(), "tamper at {i} not detected");
        }
    }

    #[test]
    fn deposit_encoding_roundtrips_and_enforces_size() {
        let q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
        let d = seal(&q, &rec(b"x")).unwrap();
        let enc = d.encode();
        assert_eq!(Deposit::decode(&enc).unwrap(), d);

        let mut short = d.clone();
        short.sealed.truncate(10);
        assert!(Deposit::decode(&short.encode()).is_err());
    }

    #[test]
    fn dummy_records_survive_the_envelope_and_are_recognisable_only_to_us() {
        let q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
        let d = seal(&q, &Record::dummy().unwrap()).unwrap();
        let opened = open(&q, &d).unwrap();
        assert_eq!(opened.kind, RecordKind::Dummy);
    }
}
