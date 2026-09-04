//! Per-contact mailbox queues (FR-MSG-04, FR-DISC-03, FR-ABUSE-02).
//!
//! ## The central unlinkability claim
//!
//! PRD §2.4: *"a mailbox address is per-contact, not per-user. Alice gives Bob a
//! queue that only Bob uses, and Carol a different queue. No relay ever holds an
//! identifier that maps to Alice — only a set of unlinked queue IDs."*
//!
//! This module is where that claim is made true. A [`QueueId`] is 16 bytes
//! derived from a per-pair secret via a KDF. There is no user identifier in it,
//! no structure a relay can group on, and no way to test two queue IDs for
//! common ownership without the secret.
//!
//! ## Deposit and retrieval authority are separate
//!
//! Anyone who knows the queue ID can deposit — that is what lets a sender stay
//! anonymous to the relay (FR-MSG-03). Only the holder of the retrieval key can
//! collect. The asymmetry is the point: deposits must be unauthenticated to be
//! unlinkable, retrievals must be authenticated or anyone could drain a queue.
//!
//! ## Why retrieval authority is a signature, not a MAC
//!
//! The obvious construction is a MAC over a relay-issued challenge. It does not
//! work, because a MAC is only checkable by someone who holds the key — so the
//! relay would need a *registry* of per-queue verification keys, which creates
//! two problems it cannot solve: a first-registration race (whoever claims a
//! queue id first owns it), and a pile of per-queue key material sitting on the
//! machine §9.1 assumes will eventually be seized.
//!
//! So the queue identifier **is** a hash of an Ed25519 public key:
//!
//! ```text
//!   retrieval seed  = KDF(queue secret, "queue/auth", generation)
//!   signing key     = Ed25519(retrieval seed)
//!   queue_id        = KDF("queue/address", signing key's public)[0..16]
//! ```
//!
//! A collector presents the public key and a signature over the relay's
//! challenge. The relay recomputes the identifier from the public key, checks it
//! matches the queue being addressed, and verifies the signature. It holds
//! nothing, registers nothing, and there is no race: only a party who can derive
//! the queue secret can produce a public key that hashes to that identifier.
//!
//! Publishing a [`DepositKey`] stays safe under this scheme, because it carries
//! the identifier — a hash of the public key — and never the public key itself,
//! let alone the seed.
//!
//! ## Rotation
//!
//! [`QueueSecret::rotate`] derives the next queue in a chain without a round
//! trip. Both parties can compute it, so a queue that is being flooded
//! (FR-ABUSE-03) can be abandoned without losing the contact. Revocation
//! (FR-ABUSE-02) is simply forgetting the secret: the peer's deposits go into a
//! queue nobody collects, and they are not told.

use alloc::vec::Vec;

use void_crypto::{blake3, ct, ed25519, kdf, rand, Zeroize};

use crate::{ProtoError, Result};

/// A queue identifier as seen by the relay.
pub type QueueId = [u8; 16];

/// Domain separator for retrieval signatures.
///
/// Present so that a signature produced for queue retrieval can never be
/// mistaken for — or replayed as — a signature of anything else Void signs.
pub const RETRIEVAL_CONTEXT: &[u8] = b"void/v1/queue/retrieve";

/// Compute a queue identifier from a retrieval public key.
///
/// This is the function a relay runs. It takes no secret and holds no state.
#[must_use]
pub fn queue_id_from_public(retrieval_public: &[u8; 32]) -> QueueId {
    let full = blake3::derive_key_32("void/v1/queue/address", retrieval_public);
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// Verify a retrieval proof. Callable by anyone; requires no secret.
///
/// Checks two things, both necessary:
///
/// 1. that `retrieval_public` actually addresses `queue_id` — otherwise a
///    collector could present a key they own for a queue they do not,
/// 2. that the signature over the challenge verifies under that key.
#[must_use]
pub fn verify_retrieval_proof(
    queue_id: &QueueId,
    retrieval_public: &[u8; 32],
    challenge: &[u8],
    proof: &[u8; 64],
) -> bool {
    if !ct::eq(&queue_id_from_public(retrieval_public)[..], &queue_id[..]) {
        return false;
    }
    let mut input = Vec::with_capacity(RETRIEVAL_CONTEXT.len() + challenge.len());
    input.extend_from_slice(RETRIEVAL_CONTEXT);
    input.extend_from_slice(challenge);
    ed25519::verify(retrieval_public, &input, proof)
}

/// The capability to **deposit** into a queue, and nothing else.
///
/// ## Why this type exists
///
/// Sealing a record requires the queue's envelope key. A sender who has never
/// met the recipient — the initiator of a handshake, holding only a published
/// prekey bundle — has no shared secret to derive one from. Publishing the
/// envelope key in the bundle solves that, but publishing the whole
/// [`QueueSecret`] would also hand out the retrieval key and let anyone drain
/// the queue.
///
/// So the two capabilities are split. `DepositKey` carries the queue id and the
/// envelope key; it can seal and open records but cannot prove retrieval
/// authority. The envelope key and the retrieval key are independent keyed
/// hashes of the queue secret, so holding one yields nothing about the other.
///
/// This is the type-level statement of the asymmetry the module documentation
/// describes: deposits are unauthenticated so senders stay anonymous,
/// retrievals are authenticated so queues cannot be drained.
#[derive(Clone, PartialEq, Eq)]
pub struct DepositKey {
    /// The queue to deposit into.
    pub queue_id: QueueId,
    /// The key that seals records for this queue.
    pub envelope_key: [u8; 32],
}

impl Drop for DepositKey {
    fn drop(&mut self) {
        self.envelope_key.zeroize();
    }
}

impl core::fmt::Debug for DepositKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DepositKey")
            .field("queue_id", &self.queue_id)
            .field("envelope_key", &"<redacted>")
            .finish()
    }
}

/// The shared per-contact secret from which queue identifiers and retrieval
/// keys are derived.
#[derive(Clone)]
pub struct QueueSecret {
    secret: [u8; 32],
    generation: u32,
}

impl Drop for QueueSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl QueueSecret {
    /// Create a fresh random queue secret.
    pub fn generate() -> Result<QueueSecret> {
        Ok(QueueSecret {
            secret: rand::bytes32().map_err(|_| ProtoError::Crypto)?,
            generation: 0,
        })
    }

    /// Reconstruct from stored material.
    #[must_use]
    pub fn from_parts(secret: [u8; 32], generation: u32) -> QueueSecret {
        QueueSecret { secret, generation }
    }

    /// The raw secret, for the storage layer only.
    #[must_use]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Which rotation generation this is.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The queue identifier the relay sees.
    ///
    /// Derived from the retrieval public key, so that a relay given that key
    /// can check it addresses this queue without holding any state.
    #[must_use]
    pub fn queue_id(&self) -> QueueId {
        queue_id_from_public(&self.retrieval_public())
    }

    /// The Ed25519 public key that authorises collection from this queue.
    #[must_use]
    pub fn retrieval_public(&self) -> [u8; 32] {
        self.retrieval_signing_key().public
    }

    fn retrieval_signing_key(&self) -> ed25519::SigningKey {
        let mut seed = blake3::keyed_hash_parts(
            &self.secret,
            &[kdf::LABEL_QUEUE_AUTH, &self.generation.to_be_bytes()],
        );
        let sk = ed25519::SigningKey::from_seed(seed);
        seed.zeroize();
        sk
    }

    /// The deposit capability for this queue: the id plus the envelope key.
    ///
    /// Safe to publish in a prekey bundle. It does **not** confer the ability
    /// to collect.
    #[must_use]
    pub fn deposit_key(&self) -> DepositKey {
        DepositKey {
            queue_id: self.queue_id(),
            envelope_key: self.envelope_key(),
        }
    }

    /// The key that seals records for this queue.
    #[must_use]
    pub fn envelope_key(&self) -> [u8; 32] {
        blake3::keyed_hash_parts(
            &self.secret,
            &[kdf::LABEL_SEALED_SENDER, &self.generation.to_be_bytes()],
        )
    }

    /// Prove authority to collect from this queue, over a relay challenge.
    ///
    /// The challenge must be fresh and relay-chosen; otherwise a captured
    /// signature is replayable by whoever saw it.
    #[must_use]
    pub fn prove_retrieval(&self, challenge: &[u8]) -> [u8; 64] {
        let mut input = Vec::with_capacity(RETRIEVAL_CONTEXT.len() + challenge.len());
        input.extend_from_slice(RETRIEVAL_CONTEXT);
        input.extend_from_slice(challenge);
        self.retrieval_signing_key().sign(&input)
    }

    /// Verify a retrieval proof against this queue's own key. Mostly for tests;
    /// a relay uses [`verify_retrieval_proof`], which needs no secret.
    #[must_use]
    pub fn verify_retrieval(&self, challenge: &[u8], proof: &[u8]) -> bool {
        if proof.len() != 64 {
            return false;
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(proof);
        verify_retrieval_proof(&self.queue_id(), &self.retrieval_public(), challenge, &sig)
    }

    /// Advance to the next queue in the chain.
    ///
    /// Both parties derive the same next queue from the same secret, so no
    /// negotiation is needed. The old queue ID cannot be computed from the new
    /// one, so a relay that has seen both cannot link them.
    #[must_use]
    pub fn rotate(&self) -> QueueSecret {
        let next = blake3::derive_key_32("void/v1/queue/rotate", &{
            let mut v = Vec::with_capacity(36);
            v.extend_from_slice(&self.secret);
            v.extend_from_slice(&self.generation.to_be_bytes());
            v
        });
        QueueSecret {
            secret: next,
            generation: self.generation + 1,
        }
    }
}

/// A relay's view of a queue: only what it is allowed to know.
///
/// This type exists so that the relay implementation cannot accidentally hold
/// anything else. If a field is not here, the relay does not have it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayQueueView {
    /// The opaque identifier.
    pub id: QueueId,
    /// How many sealed records are waiting.
    pub pending: usize,
    /// Unix seconds at which the oldest record expires.
    pub oldest_expiry: u64,
}

/// Default time-to-live for an undelivered record: 14 days (FR-MSG-08).
pub const DEFAULT_TTL_SECONDS: u64 = 14 * 24 * 60 * 60;

/// Default per-queue deposit rate limit (FR-ABUSE-03): deposits per hour.
pub const DEFAULT_DEPOSIT_RATE_PER_HOUR: u32 = 600;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn queue_ids_are_stable_and_secret_dependent() {
        let a = QueueSecret::from_parts([1u8; 32], 0);
        let b = QueueSecret::from_parts([1u8; 32], 0);
        assert_eq!(a.queue_id(), b.queue_id());
        let c = QueueSecret::from_parts([2u8; 32], 0);
        assert_ne!(a.queue_id(), c.queue_id());
    }

    #[test]
    fn generations_produce_unlinkable_ids() {
        let a = QueueSecret::from_parts([5u8; 32], 0);
        let mut seen = BTreeSet::new();
        let mut cur = a;
        for _ in 0..32 {
            assert!(seen.insert(cur.queue_id()), "queue ids must not repeat");
            cur = cur.rotate();
        }
        assert_eq!(seen.len(), 32);
    }

    #[test]
    fn rotation_is_forward_only_from_the_relays_view() {
        // The relay sees only IDs. Knowing generation N's id must not let it
        // compute generation N+1's — the ids are truncated keyed hashes of a
        // secret it does not have.
        let s = QueueSecret::from_parts([7u8; 32], 0);
        let id0 = s.queue_id();
        let id1 = s.rotate().queue_id();
        assert_ne!(id0, id1);
        // Sanity: the ids do not share structure.
        assert_ne!(&id0[..8], &id1[..8]);
    }

    #[test]
    fn retrieval_proof_verifies_and_is_challenge_bound() {
        let s = QueueSecret::from_parts([9u8; 32], 3);
        let challenge = b"relay-nonce-1";
        let proof = s.prove_retrieval(challenge);
        assert!(s.verify_retrieval(challenge, &proof));
        assert!(!s.verify_retrieval(b"relay-nonce-2", &proof));
        assert!(!s.verify_retrieval(challenge, &[0u8; 64]));
        assert!(!s.verify_retrieval(challenge, &proof[..16]));
    }

    #[test]
    fn a_relay_can_verify_without_any_stored_state() {
        // The property the whole design turns on: no registry, no race.
        let s = QueueSecret::from_parts([21u8; 32], 0);
        let challenge = b"fresh";
        let proof = s.prove_retrieval(challenge);
        assert!(verify_retrieval_proof(
            &s.queue_id(),
            &s.retrieval_public(),
            challenge,
            &proof
        ));
    }

    #[test]
    fn a_key_for_another_queue_is_rejected() {
        // Presenting a key you own, for a queue you do not, must fail on the
        // identifier check before the signature is even considered.
        let mine = QueueSecret::from_parts([1u8; 32], 0);
        let theirs = QueueSecret::from_parts([2u8; 32], 0);
        let challenge = b"c";
        let my_proof = mine.prove_retrieval(challenge);
        assert!(!verify_retrieval_proof(
            &theirs.queue_id(),
            &mine.retrieval_public(),
            challenge,
            &my_proof
        ));
    }

    #[test]
    fn the_queue_id_commits_to_the_retrieval_key() {
        let s = QueueSecret::from_parts([31u8; 32], 0);
        assert_eq!(s.queue_id(), queue_id_from_public(&s.retrieval_public()));
        let other = QueueSecret::from_parts([32u8; 32], 0);
        assert_ne!(
            s.queue_id(),
            queue_id_from_public(&other.retrieval_public())
        );
    }

    #[test]
    fn publishing_a_deposit_key_does_not_reveal_the_retrieval_key() {
        let s = QueueSecret::from_parts([41u8; 32], 0);
        let dk = s.deposit_key();
        // The deposit key carries a *hash* of the public key, not the key.
        assert_ne!(&dk.queue_id[..], &s.retrieval_public()[..16]);
        assert_ne!(dk.envelope_key, s.retrieval_public());
    }

    #[test]
    fn a_different_secret_cannot_prove_retrieval() {
        let mine = QueueSecret::from_parts([1u8; 32], 0);
        let theirs = QueueSecret::from_parts([2u8; 32], 0);
        let challenge = b"c";
        assert!(!mine.verify_retrieval(challenge, &theirs.prove_retrieval(challenge)));
    }

    #[test]
    fn a_captured_proof_does_not_work_on_a_fresh_challenge() {
        let s = QueueSecret::from_parts([51u8; 32], 0);
        let captured = s.prove_retrieval(b"challenge-1");
        assert!(!s.verify_retrieval(b"challenge-2", &captured));
    }

    #[test]
    fn generation_is_bound_into_both_id_and_key() {
        let g0 = QueueSecret::from_parts([4u8; 32], 0);
        let g1 = QueueSecret::from_parts([4u8; 32], 1);
        assert_ne!(g0.queue_id(), g1.queue_id());
        assert!(!g0.verify_retrieval(b"c", &g1.prove_retrieval(b"c")));
    }

    #[test]
    fn a_deposit_key_cannot_prove_retrieval() {
        // The whole point of the split: publishing the deposit capability must
        // not hand out the collection capability.
        let s = QueueSecret::from_parts([3u8; 32], 0);
        let dk = s.deposit_key();
        assert_eq!(dk.queue_id, s.queue_id());
        // The envelope key and the retrieval proof are independent derivations;
        // knowing one must not let you compute the other.
        let proof = s.prove_retrieval(b"challenge");
        assert_ne!(&dk.envelope_key[..], &proof[..32]);
        assert!(!s.verify_retrieval(b"challenge", &dk.envelope_key));
    }

    #[test]
    fn deposit_keys_are_generation_scoped() {
        let g0 = QueueSecret::from_parts([4u8; 32], 0);
        let g1 = g0.rotate();
        assert_ne!(g0.deposit_key().envelope_key, g1.deposit_key().envelope_key);
        assert_ne!(g0.deposit_key().queue_id, g1.deposit_key().queue_id);
    }

    #[test]
    fn deposit_key_debug_does_not_leak() {
        let s = QueueSecret::from_parts([5u8; 32], 0);
        let d = alloc::format!("{:?}", s.deposit_key());
        assert!(d.contains("redacted"));
    }

    #[test]
    fn relay_view_carries_no_identity() {
        // A compile-time-ish assertion of the design: this struct has three
        // fields and none of them is a user, key, or contact.
        let v = RelayQueueView {
            id: [0u8; 16],
            pending: 0,
            oldest_expiry: 0,
        };
        let debug = alloc::format!("{v:?}");
        assert!(!debug.contains("identity"));
        assert!(!debug.contains("sender"));
    }
}
