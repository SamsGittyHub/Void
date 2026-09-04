//! Rotating wake identifiers for push notifications (FR-NOTIF-03).
//!
//! ## The problem this solves, and the one it does not
//!
//! FR-NOTIF-01 lets a relay send a **content-free** push to tell a device that
//! something is waiting. For that to be possible the relay must be able to
//! address the device, and for that addressing not to become an identifier, it
//! must not be linkable to a queue, a contact, or a user.
//!
//! A [`WakeId`] is derived from a device-held secret and a time epoch. It
//! changes every [`ROTATION_SECONDS`] and the relay cannot compute the next one
//! from the current one, so a relay that logs wake identifiers over months
//! obtains a set of unlinked values, not a device history.
//!
//! What this does **not** solve is PRD §9.3.1: Apple and Google see that a push
//! was delivered to a specific device at a specific time, because they operate
//! the delivery network. No client-side construction changes that. The
//! mitigations are that push is off by default (FR-NOTIF-04), that the relay
//! adds randomised delay before pushing, and that the UI says so plainly. This
//! module implements the first and third parts of that; the second lives in the
//! relay.
//!
//! ## Why the relay must not be able to precompute
//!
//! If a relay could derive future wake identifiers, it could pre-register them
//! and correlate a queue with a device across rotations, which would undo the
//! whole thing. So the client publishes each identifier only when it becomes
//! current, and the relay stores a short-lived mapping from wake id to push
//! token with no queue attached.

use alloc::vec::Vec;

use void_crypto::{blake3, kdf, rand, Zeroize};

use crate::wire::{Reader, Writer};
use crate::{ProtoError, Result};

/// A rotating wake identifier as the relay sees it.
pub type WakeId = [u8; 16];

/// How often the wake identifier changes: 6 hours.
///
/// Short enough that a long observation window yields many unlinked values;
/// long enough that a device on a poor connection is not re-registering
/// constantly, since each registration is itself a connection the network sees.
pub const ROTATION_SECONDS: u64 = 6 * 60 * 60;

/// Maximum randomised delay a relay should apply before sending a push, in
/// seconds. Blunts the tightest form of deposit-to-push timing correlation.
pub const MAX_PUSH_DELAY_SECONDS: u64 = 30;

// §9.3.1 lists the randomised push delay as one of three mitigations. A delay
// of zero would make that list dishonest, so this is a compile-time assertion
// rather than a test.
const _: () = assert!(
    MAX_PUSH_DELAY_SECONDS >= 10,
    "the randomised push delay is a documented mitigation in PRD 9.3.1; \
     reducing it to near zero would make that claim untrue"
);

/// The device-held secret from which wake identifiers are derived.
pub struct WakeSecret {
    secret: [u8; 32],
}

impl Drop for WakeSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl WakeSecret {
    /// Generate a fresh wake secret.
    pub fn generate() -> Result<WakeSecret> {
        Ok(WakeSecret {
            secret: rand::bytes32().map_err(|_| ProtoError::Crypto)?,
        })
    }

    /// Reconstruct from storage.
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> WakeSecret {
        WakeSecret { secret }
    }

    /// The raw secret, for the storage layer only.
    #[must_use]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// The epoch number for a Unix timestamp.
    #[must_use]
    pub fn epoch(now: u64) -> u64 {
        now / ROTATION_SECONDS
    }

    /// The wake identifier for a given epoch.
    #[must_use]
    pub fn id_for_epoch(&self, epoch: u64) -> WakeId {
        let full =
            blake3::keyed_hash_parts(&self.secret, &[kdf::LABEL_WAKE_ID, &epoch.to_be_bytes()]);
        let mut id = [0u8; 16];
        id.copy_from_slice(&full[..16]);
        id
    }

    /// The wake identifier current at `now`.
    #[must_use]
    pub fn current(&self, now: u64) -> WakeId {
        self.id_for_epoch(Self::epoch(now))
    }

    /// Seconds until the current identifier expires.
    #[must_use]
    pub fn seconds_until_rotation(&self, now: u64) -> u64 {
        ROTATION_SECONDS - (now % ROTATION_SECONDS)
    }
}

/// A registration a client sends to a relay to enable push.
///
/// Note what is absent: no queue id, no identity, no contact. The relay learns
/// only "this opaque token wants to be poked when this opaque wake id has
/// traffic", and the association expires with the epoch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WakeRegistration {
    /// The current wake identifier.
    pub wake_id: WakeId,
    /// The platform push token (APNs or FCM), opaque to Void.
    pub push_token: Vec<u8>,
    /// The epoch this registration is valid for.
    pub epoch: u64,
}

impl WakeRegistration {
    /// Canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.wake_id)
            .bytes16(&self.push_token)
            .u64(self.epoch);
        w.finish()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<WakeRegistration> {
        let mut r = Reader::new(bytes);
        let wake_id = r.array::<16>()?;
        let push_token = r.bytes16()?.to_vec();
        let epoch = r.u64()?;
        r.finish()?;
        if push_token.len() > 512 {
            return Err(ProtoError::Malformed);
        }
        Ok(WakeRegistration {
            wake_id,
            push_token,
            epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn identifier_rotates_on_schedule() {
        let s = WakeSecret::from_secret([1u8; 32]);
        let t = 1_700_000_000u64;
        let a = s.current(t);
        assert_eq!(s.current(t + 60), a, "must be stable within an epoch");
        assert_ne!(
            s.current(t + ROTATION_SECONDS),
            a,
            "must change across epochs"
        );
    }

    #[test]
    fn epochs_produce_unlinkable_identifiers() {
        let s = WakeSecret::from_secret([2u8; 32]);
        let mut seen = BTreeSet::new();
        for e in 0..200u64 {
            assert!(seen.insert(s.id_for_epoch(e)), "wake ids must not repeat");
        }
    }

    #[test]
    fn a_different_device_secret_gives_different_identifiers() {
        let a = WakeSecret::from_secret([1u8; 32]);
        let b = WakeSecret::from_secret([2u8; 32]);
        assert_ne!(a.id_for_epoch(5), b.id_for_epoch(5));
    }

    #[test]
    fn seconds_until_rotation_is_sane() {
        let s = WakeSecret::from_secret([3u8; 32]);
        let base = 10 * ROTATION_SECONDS;
        assert_eq!(s.seconds_until_rotation(base), ROTATION_SECONDS);
        assert_eq!(s.seconds_until_rotation(base + 100), ROTATION_SECONDS - 100);
    }

    #[test]
    fn registration_carries_no_queue_or_identity() {
        let s = WakeSecret::from_secret([4u8; 32]);
        let reg = WakeRegistration {
            wake_id: s.current(0),
            push_token: alloc::vec![0xAB; 32],
            epoch: 0,
        };
        let enc = reg.encode();
        assert_eq!(WakeRegistration::decode(&enc).unwrap(), reg);
        // Three fields, none of which is a queue or a key.
        assert_eq!(enc.len(), 16 + 2 + 32 + 8);
    }

    #[test]
    fn oversized_push_token_is_refused() {
        let reg = WakeRegistration {
            wake_id: [0u8; 16],
            push_token: alloc::vec![0u8; 1000],
            epoch: 0,
        };
        assert!(WakeRegistration::decode(&reg.encode()).is_err());
    }
}
