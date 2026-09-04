//! The client engine: sessions, contacts, sending and receiving.
//!
//! This ties the protocol, the transport, the scheduler, and the store
//! together. It is the layer the FFI exposes to Swift and Kotlin, so its API is
//! deliberately small and its state machine explicit.
//!
//! ## Ordering guarantees, and the one that matters
//!
//! [`Engine::send`] refuses to send to a contact whose trust state is
//! `KeyChanged` (FR-DISC-05). That check is in exactly one place — right here,
//! before anything is encrypted — so that no future code path can route around
//! it. A UI that forgot to grey out the send button still cannot send.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use void_crypto::Zeroize;
use void_proto::call::{CallAnswer, CallEnd, CallOffer, CallSignal, EndReason, Role};
use void_proto::content::Content;
use void_proto::envelope::{self, Deposit};
use void_proto::handshake::{self, Established, PrekeyBundle, PrekeySecrets};
use void_proto::identity::{Identity, IdentityPublic, IdentitySeeds};
use void_proto::queue::{DepositKey, QueueId, QueueSecret};
use void_proto::ratchet::{Message as RatchetMessage, Ratchet};
use void_proto::record::{self, Reassembler, RecordKind};
use void_proto::wire::{Reader, Writer};
use void_relay::protocol::{Delivery, Frame, FrameType, Retrieve};
use void_store::db::{Kind, Store};
use void_store::model::{Contact, DeliveryState, Direction, Settings, StoredMessage, TrustState};
use void_store::retention::{effective_expiry, RetentionPolicy};

use crate::scheduler::{Action, Scheduler};
use crate::transport::{Transport, TransportKind};
use crate::{ClientError, ClientResult};

/// One conversation.
///
/// The two queues live inside [`Established`], derived from the handshake
/// output rather than chosen by either party — see
/// `void_proto::handshake::derive_pair_queues`.
pub struct Session {
    /// The peer.
    pub contact: Contact,
    /// The ratchet and the per-direction queues.
    pub established: Established,
    /// Reassembles fragmented incoming payloads.
    reassembler: Reassembler,
}

/// A message waiting to be deposited.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutboxItem {
    /// Which conversation.
    pub contact_fingerprint: [u8; 32],
    /// The deposit, already sealed.
    pub deposit: Deposit,
    /// The stored-message record id this belongs to, so delivery state can be
    /// updated when it lands.
    pub message_id: u64,
    /// How many attempts have been made.
    pub attempts: u32,
    /// The store record id backing this item, if a store is attached. Not
    /// part of the wire encoding — it *is* the id of the record that holds
    /// the encoding, assigned when the record is inserted or restored.
    persisted_id: Option<u64>,
}

/// Bookkeeping for an attached store: which record id backs which in-memory
/// object, so a mutation updates the existing record instead of leaking a new
/// one on every change.
///
/// `Engine` holds this behind `Option` rather than being generic over
/// [`Store`], for the same reason it holds its transport as `Box<dyn
/// Transport>`: a caller that does not want persistence — most of this
/// crate's own tests — should not have to specify a backend to get an
/// `Engine`.
struct Persisted {
    store: Box<dyn Store>,
    settings_id: u64,
    contacts: BTreeMap<[u8; 32], u64>,
    sessions: BTreeMap<[u8; 32], u64>,
    queues: BTreeMap<[u8; 32], u64>,
    /// Engine-assigned outgoing message id → the `Kind::Message` record id,
    /// so the delivery state can be updated once every fragment of that
    /// message has left the outbox. Incoming messages need no entry here:
    /// nothing updates them again after they are stored.
    outgoing_messages: BTreeMap<u64, u64>,
}

/// Insert a record for `fingerprint` the first time it is seen, or overwrite
/// its existing one on every later call — the shared shape behind persisting
/// a contact, a session, or a queue pair, all of which are keyed by
/// fingerprint but have no natural record id of their own.
fn upsert(
    store: &mut dyn Store,
    ids: &mut BTreeMap<[u8; 32], u64>,
    fingerprint: [u8; 32],
    kind: Kind,
    payload: &[u8],
) -> ClientResult<()> {
    match ids.get(&fingerprint) {
        Some(&id) => store.update(id, payload).map_err(|_| ClientError::Storage),
        None => {
            let id = store
                .insert(kind, 0, payload)
                .map_err(|_| ClientError::Storage)?;
            ids.insert(fingerprint, id);
            Ok(())
        }
    }
}

/// Encode a `Kind::Session` record: the fingerprint it belongs to, plus the
/// ratchet state. The peer's identity is not repeated here — it is already
/// the contact's identity in the matching `Kind::Contact` record.
fn encode_session_record(fingerprint: [u8; 32], ratchet: &Ratchet) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(&fingerprint).bytes32(&ratchet.serialize());
    w.finish()
}

fn decode_session_record(bytes: &[u8]) -> ClientResult<([u8; 32], Ratchet)> {
    let mut r = Reader::new(bytes);
    let fingerprint = r.array::<32>().map_err(|_| ClientError::Storage)?;
    let ratchet = Ratchet::deserialize(r.bytes32_max(64 * 1024).map_err(|_| ClientError::Storage)?)
        .map_err(|_| ClientError::Storage)?;
    r.finish().map_err(|_| ClientError::Storage)?;
    Ok((fingerprint, ratchet))
}

/// Encode a `Kind::Queue` record: the fingerprint it belongs to, plus the
/// send and receive queue secrets for that conversation.
fn encode_queue_record(fingerprint: [u8; 32], send: &QueueSecret, recv: &QueueSecret) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(&fingerprint)
        .raw(send.secret())
        .u32(send.generation())
        .raw(recv.secret())
        .u32(recv.generation());
    w.finish()
}

fn decode_queue_record(bytes: &[u8]) -> ClientResult<([u8; 32], QueueSecret, QueueSecret)> {
    let mut r = Reader::new(bytes);
    let fingerprint = r.array::<32>().map_err(|_| ClientError::Storage)?;
    let send_secret = r.array::<32>().map_err(|_| ClientError::Storage)?;
    let send_generation = r.u32().map_err(|_| ClientError::Storage)?;
    let recv_secret = r.array::<32>().map_err(|_| ClientError::Storage)?;
    let recv_generation = r.u32().map_err(|_| ClientError::Storage)?;
    r.finish().map_err(|_| ClientError::Storage)?;
    Ok((
        fingerprint,
        QueueSecret::from_parts(send_secret, send_generation),
        QueueSecret::from_parts(recv_secret, recv_generation),
    ))
}

/// Encode a `Kind::Outbox` record. `persisted_id` is not part of the
/// encoding — it *is* the id of the record the encoding lives in.
fn encode_outbox_item(item: &OutboxItem) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(&item.contact_fingerprint)
        .u64(item.message_id)
        .u32(item.attempts)
        .bytes32(&item.deposit.encode());
    w.finish()
}

fn decode_outbox_item(bytes: &[u8]) -> ClientResult<OutboxItem> {
    let mut r = Reader::new(bytes);
    let contact_fingerprint = r.array::<32>().map_err(|_| ClientError::Storage)?;
    let message_id = r.u64().map_err(|_| ClientError::Storage)?;
    let attempts = r.u32().map_err(|_| ClientError::Storage)?;
    let deposit = Deposit::decode(r.bytes32_max(4096).map_err(|_| ClientError::Storage)?)
        .map_err(|_| ClientError::Storage)?;
    r.finish().map_err(|_| ClientError::Storage)?;
    Ok(OutboxItem {
        contact_fingerprint,
        deposit,
        message_id,
        attempts,
        persisted_id: None,
    })
}

/// Whether the engine will tolerate a non-Tor transport.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityMode {
    /// Production. Only a Tor transport is accepted.
    Enforcing,
    /// Tests and the reference CLI. A direct transport is accepted and the
    /// caller is expected to warn the user loudly and continuously.
    InsecureForTesting,
}

/// The client engine.
pub struct Engine {
    identity: Identity,
    settings: Settings,
    sessions: BTreeMap<[u8; 32], Session>,
    outbox: Vec<OutboxItem>,
    scheduler: Scheduler,
    transport: Box<dyn Transport>,
    mode: SecurityMode,
    next_message_id: u64,
    /// Prekey bundles we have published and their secrets, keyed by the
    /// bundle's queue id. Consumed on first use (FR-DISC-02).
    pending_bundles: BTreeMap<QueueId, PrekeySecrets>,
    /// The attached store, if any. See [`Engine::new_persisted`] and
    /// [`Engine::restore`].
    persisted: Option<Persisted>,
    /// Calls in progress, at most one per contact.
    ///
    /// Deliberately not persisted. A call does not survive the process that
    /// was carrying its audio, and restoring one from disk would put the UI in
    /// a ringing state for a media connection that no longer exists.
    calls: BTreeMap<[u8; 32], ActiveCall>,
    /// Call events waiting for the platform layer to collect.
    call_events: Vec<CallEvent>,
}

impl Engine {
    /// Build an engine.
    ///
    /// Refuses a non-Tor transport in [`SecurityMode::Enforcing`]. This is the
    /// enforcement point for FR-TRANS-03 at runtime; the CI check is the
    /// enforcement point at build time. Both exist because either alone has
    /// been enough to ship a bypass in other products.
    pub fn new(
        identity: Identity,
        settings: Settings,
        transport: Box<dyn Transport>,
        mode: SecurityMode,
        now_ms: u64,
    ) -> ClientResult<Engine> {
        if mode == SecurityMode::Enforcing && !transport.kind().is_acceptable_for_production() {
            return Err(ClientError::InsecureTransport);
        }
        Ok(Engine {
            identity,
            settings,
            sessions: BTreeMap::new(),
            outbox: Vec::new(),
            scheduler: Scheduler::new(now_ms)?,
            transport,
            mode,
            next_message_id: 1,
            pending_bundles: BTreeMap::new(),
            persisted: None,
            calls: BTreeMap::new(),
            call_events: Vec::new(),
        })
    }

    /// Build a fresh engine and start persisting it to `store` immediately.
    ///
    /// Writes the identity and settings before returning, so a process that
    /// crashes right after this call still has an identity to restore with
    /// [`Engine::restore`]. Everything created from here on — contacts,
    /// sessions, messages, and the outbox — is persisted as it happens.
    ///
    /// `identity_seeds` must be the seeds `identity` was built from
    /// ([`Identity::generate_with_seeds`] or the caller's own
    /// [`Identity::from_seeds`] call) — the store keeps the 96-byte seed
    /// triple, not the expanded keys, for the same reason the export archive
    /// does (`docs/PROTOCOL.md#13-export-archive`).
    pub fn new_persisted(
        identity: Identity,
        identity_seeds: &IdentitySeeds,
        settings: Settings,
        transport: Box<dyn Transport>,
        mode: SecurityMode,
        now_ms: u64,
        mut store: Box<dyn Store>,
    ) -> ClientResult<Engine> {
        store
            .insert(Kind::Identity, 0, &identity_seeds.encode())
            .map_err(|_| ClientError::Storage)?;
        let settings_id = store
            .insert(Kind::Setting, 0, &settings.encode())
            .map_err(|_| ClientError::Storage)?;
        store.flush().map_err(|_| ClientError::Storage)?;

        let mut engine = Engine::new(identity, settings, transport, mode, now_ms)?;
        engine.persisted = Some(Persisted {
            store,
            settings_id,
            contacts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            queues: BTreeMap::new(),
            outgoing_messages: BTreeMap::new(),
        });
        Ok(engine)
    }

    /// Rebuild an engine from a store a previous run persisted to
    /// (FR-STOR-01's restart-survival requirement).
    ///
    /// Restores the identity, every contact and session (joined by
    /// fingerprint — a fingerprint present in only one of the contact,
    /// session, or queue tables is treated as a corrupted partial write and
    /// dropped rather than reconstructed halfway), settings, and the outbox.
    /// Runs the retention sweep once before returning (FR-STOR-04); the same
    /// sweep [`Engine::tick`] runs periodically afterwards.
    ///
    /// Fails if `store` holds no identity record — there is nothing to
    /// restore an engine from, and reaching for a fresh one silently instead
    /// would replace an existing identity, which every contact would then see
    /// as a key change.
    pub fn restore(
        mut store: Box<dyn Store>,
        transport: Box<dyn Transport>,
        mode: SecurityMode,
        now_ms: u64,
    ) -> ClientResult<Engine> {
        let identity_records = store
            .list(Kind::Identity)
            .map_err(|_| ClientError::Storage)?;
        let seeds_payload = &identity_records
            .first()
            .ok_or(ClientError::Storage)?
            .payload;
        let identity = IdentitySeeds::decode(seeds_payload)
            .map_err(|_| ClientError::Storage)?
            .identity();

        let settings_records = store
            .list(Kind::Setting)
            .map_err(|_| ClientError::Storage)?;
        let (settings, settings_id) = match settings_records.first() {
            Some(r) => (
                Settings::decode(&r.payload).map_err(|_| ClientError::Storage)?,
                r.id,
            ),
            None => {
                let s = Settings::default();
                let id = store
                    .insert(Kind::Setting, 0, &s.encode())
                    .map_err(|_| ClientError::Storage)?;
                (s, id)
            }
        };

        let mut contact_ids = BTreeMap::new();
        let mut contacts_by_fp: BTreeMap<[u8; 32], Contact> = BTreeMap::new();
        for r in store
            .list(Kind::Contact)
            .map_err(|_| ClientError::Storage)?
        {
            let contact = Contact::decode(&r.payload).map_err(|_| ClientError::Storage)?;
            let fp = contact.fingerprint();
            contact_ids.insert(fp, r.id);
            contacts_by_fp.insert(fp, contact);
        }

        let mut session_ids = BTreeMap::new();
        let mut ratchets_by_fp: BTreeMap<[u8; 32], Ratchet> = BTreeMap::new();
        for r in store
            .list(Kind::Session)
            .map_err(|_| ClientError::Storage)?
        {
            let (fp, ratchet) = decode_session_record(&r.payload)?;
            session_ids.insert(fp, r.id);
            ratchets_by_fp.insert(fp, ratchet);
        }

        let mut queue_ids = BTreeMap::new();
        let mut queues_by_fp: BTreeMap<[u8; 32], (QueueSecret, QueueSecret)> = BTreeMap::new();
        for r in store.list(Kind::Queue).map_err(|_| ClientError::Storage)? {
            let (fp, send_queue, recv_queue) = decode_queue_record(&r.payload)?;
            queue_ids.insert(fp, r.id);
            queues_by_fp.insert(fp, (send_queue, recv_queue));
        }

        let mut sessions = BTreeMap::new();
        let fingerprints: Vec<[u8; 32]> = contacts_by_fp.keys().copied().collect();
        for fp in fingerprints {
            let (Some(contact), Some(ratchet), Some((send_queue, recv_queue))) = (
                contacts_by_fp.remove(&fp),
                ratchets_by_fp.remove(&fp),
                queues_by_fp.remove(&fp),
            ) else {
                continue;
            };
            let peer = contact.identity.clone();
            sessions.insert(
                fp,
                Session {
                    contact,
                    established: Established {
                        ratchet,
                        peer,
                        send_queue,
                        recv_queue,
                    },
                    reassembler: Reassembler::new(64),
                },
            );
        }

        let mut outbox = Vec::new();
        for r in store.list(Kind::Outbox).map_err(|_| ClientError::Storage)? {
            let mut item = decode_outbox_item(&r.payload)?;
            item.persisted_id = Some(r.id);
            outbox.push(item);
        }
        // message_id only has to avoid colliding with ids still live in the
        // outbox — once a message's last fragment is deposited, its id is
        // never referenced again, so there is nothing to recover it from.
        let next_message_id = outbox.iter().map(|i| i.message_id).max().unwrap_or(0) + 1;

        let mut engine = Engine::new(identity, settings, transport, mode, now_ms)?;
        engine.sessions = sessions;
        engine.outbox = outbox;
        engine.next_message_id = next_message_id;
        engine.persisted = Some(Persisted {
            store,
            settings_id,
            contacts: contact_ids,
            sessions: session_ids,
            queues: queue_ids,
            outgoing_messages: BTreeMap::new(),
        });

        engine.run_retention_sweep(now_ms / 1000)?;
        Ok(engine)
    }

    /// Whether a store is attached and being kept in sync.
    #[must_use]
    pub fn is_persisted(&self) -> bool {
        self.persisted.is_some()
    }

    /// Delete every expired message and outbox item (FR-STOR-04). A no-op if
    /// no store is attached. Called once on [`Engine::restore`] and
    /// periodically by [`Engine::tick`].
    pub fn run_retention_sweep(&mut self, now: u64) -> ClientResult<usize> {
        match &mut self.persisted {
            Some(p) => p.store.sweep_expired(now).map_err(|_| ClientError::Storage),
            None => Ok(0),
        }
    }

    /// The second half of duress destruction (FR-STOR-02), after the platform
    /// layer has already destroyed the hardware vault key.
    ///
    /// The vault key is what makes destruction *irreversible* — losing it
    /// makes every byte of the database permanently undecryptable, whether or
    /// not this method runs at all. What this method does is defence in
    /// depth and RAM hygiene: it erases the store's backing bytes so a
    /// forensic tool does not find intact ciphertext sitting next to an
    /// unrecoverable key, and it clears every session, contact, and queued
    /// message this process is holding, so nothing survives in memory for a
    /// tool that can read a live process to find.
    ///
    /// Always succeeds at the in-memory wipe, even if the store erase fails
    /// (a failed disk write must not leave old conversations reachable in
    /// RAM) — matching [`void_store::db::Database::destroy`]'s own
    /// "erase what we can, drop the rest regardless" contract.
    pub fn duress_destroy(&mut self) -> ClientResult<()> {
        self.sessions.clear();
        self.outbox.clear();
        self.pending_bundles.clear();

        match &mut self.persisted {
            Some(p) => {
                p.contacts.clear();
                p.sessions.clear();
                p.queues.clear();
                p.outgoing_messages.clear();
                p.store.destroy().map_err(|_| ClientError::Storage)
            }
            None => Ok(()),
        }
    }

    /// Write (insert or update) every persisted record for one session, if a
    /// store is attached. Idempotent and safe to call after any mutation to
    /// the session, even one that touched only the contact or only the
    /// ratchet — the other two records are simply rewritten unchanged.
    fn persist_session(&mut self, fingerprint: [u8; 32]) -> ClientResult<()> {
        if self.persisted.is_none() {
            return Ok(());
        }
        let Some(session) = self.sessions.get(&fingerprint) else {
            return Ok(());
        };
        let contact_payload = session.contact.encode();
        let session_payload = encode_session_record(fingerprint, &session.established.ratchet);
        let queue_payload = encode_queue_record(
            fingerprint,
            &session.established.send_queue,
            &session.established.recv_queue,
        );

        let persisted = self.persisted.as_mut().expect("checked above");
        upsert(
            &mut *persisted.store,
            &mut persisted.contacts,
            fingerprint,
            Kind::Contact,
            &contact_payload,
        )?;
        upsert(
            &mut *persisted.store,
            &mut persisted.sessions,
            fingerprint,
            Kind::Session,
            &session_payload,
        )?;
        upsert(
            &mut *persisted.store,
            &mut persisted.queues,
            fingerprint,
            Kind::Queue,
            &queue_payload,
        )?;
        persisted.store.flush().map_err(|_| ClientError::Storage)
    }

    /// Remove every persisted record for one contact: its contact, session,
    /// and queue records, plus any outbox items still queued for it.
    fn forget_persisted(&mut self, fingerprint: &[u8; 32]) {
        let Some(persisted) = &mut self.persisted else {
            return;
        };
        for map in [
            &mut persisted.contacts,
            &mut persisted.sessions,
            &mut persisted.queues,
        ] {
            if let Some(id) = map.remove(fingerprint) {
                let _ = persisted.store.delete(id);
            }
        }
        let _ = persisted.store.flush();
    }

    /// Our own identity fingerprint, for display and comparison.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.identity.fingerprint()
    }

    /// Our public identity.
    #[must_use]
    pub fn identity_public(&self) -> &IdentityPublic {
        &self.identity.public
    }

    /// The current settings.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Replace the settings.
    pub fn set_settings(&mut self, settings: Settings) {
        self.settings = settings;
        if let Some(persisted) = &mut self.persisted {
            let payload = self.settings.encode();
            let _ = persisted.store.update(persisted.settings_id, &payload);
            let _ = persisted.store.flush();
        }
    }

    /// Whether the engine is running with a transport that would be
    /// unacceptable in production. The UI must surface this permanently.
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        !self.transport.kind().is_acceptable_for_production()
    }

    /// The transport in use.
    #[must_use]
    pub fn transport_kind(&self) -> TransportKind {
        self.transport.kind()
    }

    /// Replace the transport — the hook the platform layer uses once it has
    /// bootstrapped Tor and opened a circuit (`void-tor`'s `TorHandle::connect`
    /// hands back exactly what belongs here).
    ///
    /// An `Engine` starts with [`transport::NullTransport`], which reports
    /// [`TransportKind::Tor`] while carrying nothing, so that every send
    /// queues from the moment the engine exists rather than only after this
    /// is called (FR-TRANS-05). This method enforces the same rule
    /// [`Engine::new`] does at construction: in [`SecurityMode::Enforcing`], a
    /// transport that is not production-acceptable is refused rather than
    /// swapped in, so a bug that hands this a direct transport cannot
    /// silently downgrade an already-running engine.
    ///
    /// [`transport::NullTransport`]: crate::transport::NullTransport
    pub fn set_transport(&mut self, transport: Box<dyn Transport>) -> ClientResult<()> {
        if self.mode == SecurityMode::Enforcing && !transport.kind().is_acceptable_for_production()
        {
            return Err(ClientError::InsecureTransport);
        }
        self.transport = transport;
        Ok(())
    }

    /// Publish a prekey bundle, to be rendered as a QR code or invitation link.
    ///
    /// Each call allocates a fresh queue and a fresh one-time prekey, so two
    /// invitations handed to two people share nothing a relay could correlate.
    pub fn create_bundle(
        &mut self,
        relay_hint: &[u8],
    ) -> ClientResult<(PrekeyBundle, QueueSecret)> {
        let intro_queue = QueueSecret::generate().map_err(|_| ClientError::Protocol)?;
        let queue_id = intro_queue.queue_id();
        let (bundle, secrets) =
            PrekeyBundle::create(&self.identity, &intro_queue, relay_hint, true)
                .map_err(|_| ClientError::Protocol)?;
        self.pending_bundles.insert(queue_id, secrets);
        Ok((bundle, intro_queue))
    }

    /// Begin a conversation from a peer's bundle (the initiator side).
    ///
    /// Verifies the bundle's signature before deriving anything; a bundle that
    /// fails verification produces an error and no session.
    pub fn start_conversation(
        &mut self,
        bundle: &PrekeyBundle,
        local_name: &str,
        first_message: &str,
        now: u64,
    ) -> ClientResult<[u8; 32]> {
        if !bundle.verify() {
            return Err(ClientError::UnverifiedBundle);
        }

        let (initial, established, intro_deposit) = handshake::initiate(
            &self.identity,
            bundle,
            &Content::text(first_message).encode(),
        )
        .map_err(|_| ClientError::Protocol)?;

        let fingerprint = bundle.identity.fingerprint();
        let contact = Contact::new(bundle.identity.clone(), local_name, now);

        self.sessions.insert(
            fingerprint,
            Session {
                contact,
                established,
                reassembler: Reassembler::new(64),
            },
        );
        self.persist_session(fingerprint)?;

        // The handshake itself goes to the bundle's published introduction
        // queue. Everything after it goes to the derived steady-state queue,
        // which only the two of us can address.
        let message_id = self.enqueue(fingerprint, &intro_deposit, &initial.encode())?;
        self.store_outgoing_message(fingerprint, first_message, now, message_id);
        Ok(fingerprint)
    }

    /// Accept an incoming initial message (the responder side).
    ///
    /// Returns the peer's fingerprint and their first plaintext.
    pub fn accept_conversation(
        &mut self,
        bundle_queue_id: QueueId,
        initial_bytes: &[u8],
        now: u64,
    ) -> ClientResult<([u8; 32], String)> {
        let secrets = self
            .pending_bundles
            .remove(&bundle_queue_id)
            .ok_or(ClientError::UnknownBundle)?;
        let initial =
            handshake::InitialMessage::decode(initial_bytes).map_err(|_| ClientError::Protocol)?;
        let (established, plaintext) = handshake::respond(&self.identity, &secrets, &initial)
            .map_err(|_| ClientError::Protocol)?;

        let fingerprint = initial.identity.fingerprint();
        let contact = Contact::new(initial.identity.clone(), "", now);

        self.sessions.insert(
            fingerprint,
            Session {
                contact,
                established,
                reassembler: Reassembler::new(64),
            },
        );
        self.persist_session(fingerprint)?;

        // Framed like every other plaintext, even though the first message is
        // text by construction — one rule about what a plaintext is, with no
        // exceptions to remember, is the point.
        let text = match Content::decode(&plaintext).map_err(|_| ClientError::Protocol)? {
            Content::Text(t) => t,
            Content::Call(_) => return Err(ClientError::Protocol),
        };
        self.store_incoming_message(fingerprint, &text, now);
        Ok((fingerprint, text))
    }

    /// Poll an introduction queue for a delivered handshake — the responder
    /// side of establishing a conversation from a bundle this engine
    /// published with [`Engine::create_bundle`].
    ///
    /// The engine does not retain the intro queue's [`QueueSecret`] itself
    /// (only the caller who published the bundle does, since it is what a QR
    /// code or invite link is generated from), so the caller passes it back
    /// in. Returns the raw initial-message bytes once fully reassembled —
    /// pass them to [`Engine::accept_conversation`] — or `None` if nothing
    /// has arrived yet. Safe to call repeatedly, e.g. from a platform-side
    /// timer while showing a "waiting for them to scan" screen.
    pub fn poll_intro_queue(&mut self, intro_queue: &QueueSecret) -> ClientResult<Option<Vec<u8>>> {
        let queue_id = intro_queue.queue_id();
        let deposit_key = intro_queue.deposit_key();
        let mut reassembler = Reassembler::new(16);

        // Bounded, like every other retrieval loop in this file: a hostile
        // relay must not be able to keep us here.
        for _ in 0..64 {
            let challenge_frame = Frame::new(FrameType::Challenge, queue_id.to_vec());
            let reply = self.transport.exchange(&challenge_frame)?;
            if reply.kind != FrameType::ChallengeReply || reply.body.len() != 32 {
                break;
            }
            let mut challenge = [0u8; 32];
            challenge.copy_from_slice(&reply.body);

            let req = Retrieve {
                queue_id,
                challenge,
                retrieval_public: intro_queue.retrieval_public(),
                proof: intro_queue.prove_retrieval(&challenge),
            };
            let resp = self
                .transport
                .exchange(&Frame::new(FrameType::Retrieve, req.encode()))?;
            if resp.kind != FrameType::Delivery {
                break;
            }
            let delivery = Delivery::decode(&resp.body).map_err(|_| ClientError::Protocol)?;
            if delivery.sealed.is_empty() {
                break;
            }

            let deposit = Deposit {
                queue_id,
                sealed: delivery.sealed,
            };
            if let Ok(record) = envelope::open(&deposit_key, &deposit) {
                if record.kind != RecordKind::Dummy {
                    // A record that will not reassemble is discarded on the
                    // same terms as one that will not open: it is corruption
                    // or a stranger probing, and this queue's deposit key is
                    // in every copy of the invite link, so strangers are
                    // expected. Aborting the poll would let one of them stop
                    // the invitation from ever completing.
                    if let Ok(Some(payload)) = reassembler.push(&record) {
                        return Ok(Some(payload));
                    }
                }
            }
            if delivery.remaining == 0 {
                break;
            }
        }
        Ok(None)
    }

    /// Send a message.
    ///
    /// Returns the local message id. The message is queued, not transmitted:
    /// transmission happens on the scheduler's constant-rate tick, so that the
    /// act of pressing send is not visible in the traffic timing.
    pub fn send(&mut self, fingerprint: &[u8; 32], text: &str, now: u64) -> ClientResult<u64> {
        let session = self
            .sessions
            .get_mut(fingerprint)
            .ok_or(ClientError::NoSuchContact)?;

        // FR-DISC-05, enforced once, here.
        if !session.contact.can_send() {
            return Err(ClientError::ContactKeyChanged);
        }

        let ratchet_message = session
            .established
            .ratchet
            .encrypt(&Content::text(text).encode())
            .map_err(|_| ClientError::Protocol)?;
        let payload = ratchet_message.encode();
        let deposit_key = session.established.send_queue.deposit_key();

        // The ratchet just stepped, so the persisted session record is stale
        // the instant this returns — write it before anything can observe it.
        self.persist_session(*fingerprint)?;

        let message_id = self.enqueue(*fingerprint, &deposit_key, &payload)?;
        self.store_outgoing_message(*fingerprint, text, now, message_id);
        Ok(message_id)
    }

    /// Queue a call signal to a contact.
    ///
    /// Goes out over exactly the same path as a text message — same ratchet,
    /// same fragmentation, same constant-rate scheduler — and is deliberately
    /// not stored in the message history, because a ringing phone is not a
    /// thing the user said.
    fn send_signal(&mut self, fingerprint: &[u8; 32], signal: CallSignal) -> ClientResult<u64> {
        let session = self
            .sessions
            .get_mut(fingerprint)
            .ok_or(ClientError::NoSuchContact)?;
        if !session.contact.can_send() {
            return Err(ClientError::ContactKeyChanged);
        }
        let ratchet_message = session
            .established
            .ratchet
            .encrypt(&Content::Call(signal).encode())
            .map_err(|_| ClientError::Protocol)?;
        let payload = ratchet_message.encode();
        let deposit_key = session.established.send_queue.deposit_key();
        self.persist_session(*fingerprint)?;
        self.enqueue(*fingerprint, &deposit_key, &payload)
    }

    /// Place a call to a contact, given an onion service the platform layer has
    /// already published.
    ///
    /// The address is passed in rather than opened here because publishing a
    /// service needs Tor, and Tor lives outside this crate by D-009. The
    /// platform starts publishing the moment the user presses call; by the time
    /// this offer surfaces on the peer's next retrieval slot the descriptor has
    /// had several seconds to reach the HSDirs, so the ring delay and the
    /// publish delay overlap instead of adding up.
    ///
    /// Returns the call id and the media secret both ends derive keys from.
    pub fn place_call(
        &mut self,
        fingerprint: &[u8; 32],
        onion_address: &str,
        port: u16,
    ) -> ClientResult<ActiveCall> {
        if self.calls.contains_key(fingerprint) {
            return Err(ClientError::CallInProgress);
        }
        let offer = CallOffer::new(onion_address, port).map_err(|_| ClientError::Protocol)?;
        let active = ActiveCall {
            call_id: offer.call_id,
            media_secret: offer.media_secret,
            role: Role::Caller,
            peer: *fingerprint,
            onion_address: String::from(onion_address),
            port,
            answered: false,
        };
        self.send_signal(fingerprint, CallSignal::Offer(offer))?;
        self.calls.insert(*fingerprint, active.clone());
        Ok(active)
    }

    /// Answer a call this engine reported as incoming.
    ///
    /// Returns what the platform layer needs to open the media connection: the
    /// address to dial and the secret to key it with.
    pub fn answer_call(&mut self, fingerprint: &[u8; 32]) -> ClientResult<ActiveCall> {
        let call = self
            .calls
            .get(fingerprint)
            .ok_or(ClientError::NoSuchCall)?
            .clone();
        if call.role != Role::Callee {
            return Err(ClientError::NoSuchCall);
        }
        self.send_signal(
            fingerprint,
            CallSignal::Answer(CallAnswer {
                call_id: call.call_id,
                accepted: true,
            }),
        )?;
        if let Some(c) = self.calls.get_mut(fingerprint) {
            c.answered = true;
        }
        Ok(call)
    }

    /// End a call — decline, hang up, or report a failure.
    ///
    /// Always clears local call state, even when the signal cannot be sent.
    /// A user who presses hang up has hung up; whether the peer hears about it
    /// is a delivery question, not a state question.
    pub fn end_call(&mut self, fingerprint: &[u8; 32], reason: EndReason) -> ClientResult<()> {
        let Some(call) = self.calls.remove(fingerprint) else {
            return Err(ClientError::NoSuchCall);
        };
        self.send_signal(
            fingerprint,
            CallSignal::End(CallEnd {
                call_id: call.call_id,
                reason,
            }),
        )
        .map(|_| ())
    }

    /// The call in progress with this contact, if any.
    #[must_use]
    pub fn active_call(&self, fingerprint: &[u8; 32]) -> Option<&ActiveCall> {
        self.calls.get(fingerprint)
    }

    /// Fragment a payload, seal each fragment to `deposit_key`, and queue them.
    ///
    /// Sealing happens here rather than at transmission time so that the
    /// scheduler's tick does no cryptography — a tick must take the same
    /// observable time whether it carries a message or a dummy record, and
    /// encrypting inside the tick would break that.
    fn enqueue(
        &mut self,
        fingerprint: [u8; 32],
        deposit_key: &DepositKey,
        payload: &[u8],
    ) -> ClientResult<u64> {
        let message_id = self.next_message_id;
        self.next_message_id += 1;
        let records = record::fragment(message_id, payload).map_err(|_| ClientError::Protocol)?;
        for rec in &records {
            let deposit = envelope::seal(deposit_key, rec).map_err(|_| ClientError::Protocol)?;
            let mut item = OutboxItem {
                contact_fingerprint: fingerprint,
                deposit,
                message_id,
                attempts: 0,
                persisted_id: None,
            };
            if let Some(persisted) = &mut self.persisted {
                let payload = encode_outbox_item(&item);
                if let Ok(id) = persisted.store.insert(Kind::Outbox, 0, &payload) {
                    item.persisted_id = Some(id);
                }
            }
            self.outbox.push(item);
        }
        if let Some(persisted) = &mut self.persisted {
            let _ = persisted.store.flush();
        }
        Ok(message_id)
    }

    /// Store an outgoing message (NFR-REL-04) and remember which record backs
    /// it, so [`Engine::tick`] can move its delivery state to `Deposited`
    /// once every outbox fragment carrying it has actually landed. A no-op if
    /// no store is attached.
    fn store_outgoing_message(
        &mut self,
        fingerprint: [u8; 32],
        text: &str,
        now: u64,
        message_id: u64,
    ) {
        if self.persisted.is_none() {
            return;
        }
        let expiry = self.message_expiry(&fingerprint, now);
        let msg = self.stored_message(fingerprint, text, Direction::Outgoing, now);
        let payload = msg.encode();
        let persisted = self.persisted.as_mut().expect("checked above");
        if let Ok(id) = persisted.store.insert(Kind::Message, expiry, &payload) {
            persisted.outgoing_messages.insert(message_id, id);
            let _ = persisted.store.flush();
        }
    }

    /// Store an incoming message (NFR-REL-04). A no-op if no store is
    /// attached.
    fn store_incoming_message(&mut self, fingerprint: [u8; 32], text: &str, now: u64) {
        if self.persisted.is_none() {
            return;
        }
        let expiry = self.message_expiry(&fingerprint, now);
        let msg = self.stored_message(fingerprint, text, Direction::Incoming, now);
        let payload = msg.encode();
        let persisted = self.persisted.as_mut().expect("checked above");
        let _ = persisted.store.insert(Kind::Message, expiry, &payload);
        let _ = persisted.store.flush();
    }

    /// Called once an outbox item has left the outbox, successfully
    /// deposited. If it was the last fragment of its message, moves that
    /// message's stored delivery state to `Deposited`.
    fn on_outbox_item_deposited(&mut self, removed: &OutboxItem) {
        let Some(persisted) = &mut self.persisted else {
            return;
        };
        if let Some(id) = removed.persisted_id {
            let _ = persisted.store.delete(id);
        }
        let message_id = removed.message_id;
        let still_pending = self.outbox.iter().any(|i| i.message_id == message_id);
        if still_pending {
            let _ = persisted.store.flush();
            return;
        }
        if let Some(record_id) = persisted.outgoing_messages.remove(&message_id) {
            if let Ok(Some(record)) = persisted.store.get(record_id) {
                if let Ok(mut msg) = StoredMessage::decode(&record.payload) {
                    msg.delivery = DeliveryState::Deposited;
                    let _ = persisted.store.update(record_id, &msg.encode());
                }
            }
        }
        let _ = persisted.store.flush();
    }

    /// Advance the scheduler by one tick.
    ///
    /// Returns what happened, so the caller (and tests) can observe the traffic
    /// shape. Errors from the transport are **not** propagated as failures of
    /// the tick: a transport failure means "queue and retry", which is
    /// FR-TRANS-05, and it is reported through [`TickOutcome::Offline`].
    pub fn tick(&mut self, now_ms: u64) -> ClientResult<TickOutcome> {
        self.scheduler
            .set_connected(self.transport.is_connected(), now_ms);
        let has_work = !self.outbox.is_empty();

        match self.scheduler.poll(now_ms, has_work)? {
            Action::Wait(d) => Ok(TickOutcome::Waiting(d)),
            Action::SendPadding => {
                let frame = Frame::padding().map_err(|_| ClientError::Protocol)?;
                match self.transport.exchange(&frame) {
                    Ok(_) => Ok(TickOutcome::SentPadding),
                    Err(_) => Ok(TickOutcome::Offline),
                }
            }
            Action::SendPayload => {
                let Some(item) = self.outbox.first().cloned() else {
                    return Ok(TickOutcome::SentPadding);
                };
                let frame = Frame::new(FrameType::Deposit, item.deposit.encode());
                match self.transport.exchange(&frame) {
                    Ok(resp) if resp.kind == FrameType::Ack => {
                        let removed = self.outbox.remove(0);
                        self.on_outbox_item_deposited(&removed);
                        Ok(TickOutcome::Deposited(item.message_id))
                    }
                    Ok(_) => {
                        // Refused. Count the attempt and keep it queued; the
                        // relay may be rate limiting, and giving up would lose
                        // the message.
                        if let Some(first) = self.outbox.first_mut() {
                            first.attempts += 1;
                        }
                        Ok(TickOutcome::Refused(item.message_id))
                    }
                    Err(_) => {
                        if let Some(first) = self.outbox.first_mut() {
                            first.attempts += 1;
                        }
                        Ok(TickOutcome::Offline)
                    }
                }
            }
            Action::Retrieve => {
                let received = self.collect_all(now_ms)?;
                // Piggybacks on the retrieval cadence rather than running
                // every tick: retrieval is already jittered to roughly
                // RETRIEVAL_JITTER_MS, so the sweep runs "periodically"
                // (FR-STOR-04) without adding a second timer to reason about.
                let _ = self.run_retention_sweep(now_ms / 1000);
                Ok(TickOutcome::Retrieved(received))
            }
        }
    }

    /// Poll every session's receive queue once.
    fn collect_all(&mut self, now_ms: u64) -> ClientResult<Vec<ReceivedMessage>> {
        let fingerprints: Vec<[u8; 32]> = self.sessions.keys().copied().collect();
        let mut out = Vec::new();
        for fp in fingerprints {
            match self.collect_one(&fp, now_ms) {
                Ok(mut msgs) => out.append(&mut msgs),
                // A single queue failing must not stop the others.
                Err(ClientError::TorUnavailable) => break,
                Err(_) => continue,
            }
        }
        Ok(out)
    }

    fn collect_one(
        &mut self,
        fingerprint: &[u8; 32],
        now_ms: u64,
    ) -> ClientResult<Vec<ReceivedMessage>> {
        let queue_id = {
            let s = self
                .sessions
                .get(fingerprint)
                .ok_or(ClientError::NoSuchContact)?;
            s.established.recv_queue.queue_id()
        };

        let mut messages = Vec::new();
        // Bounded: a hostile relay must not be able to keep us in this loop.
        for _ in 0..64 {
            let challenge_frame = Frame::new(FrameType::Challenge, queue_id.to_vec());
            let reply = self.transport.exchange(&challenge_frame)?;
            if reply.kind != FrameType::ChallengeReply || reply.body.len() != 32 {
                break;
            }
            let mut challenge = [0u8; 32];
            challenge.copy_from_slice(&reply.body);

            let (retrieval_public, proof) = {
                let s = self
                    .sessions
                    .get(fingerprint)
                    .ok_or(ClientError::NoSuchContact)?;
                (
                    s.established.recv_queue.retrieval_public(),
                    s.established.recv_queue.prove_retrieval(&challenge),
                )
            };
            let req = Retrieve {
                queue_id,
                challenge,
                retrieval_public,
                proof,
            };
            let resp = self
                .transport
                .exchange(&Frame::new(FrameType::Retrieve, req.encode()))?;
            if resp.kind != FrameType::Delivery {
                break;
            }
            let delivery = Delivery::decode(&resp.body).map_err(|_| ClientError::Protocol)?;
            if delivery.sealed.is_empty() {
                break;
            }

            let deposit = Deposit {
                queue_id,
                sealed: delivery.sealed,
            };
            let session = self
                .sessions
                .get_mut(fingerprint)
                .ok_or(ClientError::NoSuchContact)?;
            let record =
                match envelope::open(&session.established.recv_queue.deposit_key(), &deposit) {
                    Ok(r) => r,
                    // A record we cannot open is discarded silently. It is either
                    // corruption or an attacker probing; neither deserves a
                    // distinguishable response.
                    Err(_) => continue,
                };
            if record.kind == RecordKind::Dummy {
                continue;
            }
            let mut ratchet_mutated = false;
            let mut decrypted = None;
            // A record that will not reassemble is discarded, not fatal — see
            // the same decision in `poll_intro_queue`. A relay redelivering
            // one fragment of an old message must not be able to end the
            // collection, or it ends the conversation.
            if let Ok(Some(payload)) = session.reassembler.push(&record) {
                let Ok(ratchet_message) = RatchetMessage::decode(&payload) else {
                    continue;
                };
                match session.established.ratchet.decrypt(&ratchet_message) {
                    Ok(plaintext) => {
                        // The ratchet mutated its state (and, for a new chain,
                        // its skipped-key map) at the moment this
                        // authenticated, and only then — persist it below,
                        // whether or not the plaintext turns out to parse.
                        ratchet_mutated = true;
                        decrypted = Content::decode(&plaintext).ok();
                    }
                    Err(_) => continue,
                }
            }
            // `session`'s borrow ends here, so persistence (which needs
            // `&mut self`) can only start now.
            if ratchet_mutated {
                self.persist_session(*fingerprint)?;
            }
            match decrypted {
                Some(Content::Text(text)) => {
                    self.store_incoming_message(*fingerprint, &text, now_ms / 1000);
                    messages.push(ReceivedMessage {
                        contact_fingerprint: *fingerprint,
                        text,
                    });
                }
                Some(Content::Call(signal)) => {
                    // Signalling is never stored as a message and never shown
                    // in a conversation. It changes call state and nothing
                    // else.
                    if let Some(event) = self.apply_call_signal(*fingerprint, signal) {
                        self.call_events.push(event);
                    }
                }
                None => {}
            }
            if delivery.remaining == 0 {
                break;
            }
        }
        Ok(messages)
    }

    /// Fold one received call signal into call state, returning what the UI
    /// should be told about it.
    ///
    /// Signals that do not name the call in progress are dropped. A contact
    /// can only have one call at a time, so a stale `End` from a call that
    /// already finished must not tear down the one that replaced it — which is
    /// exactly what would happen if this matched on the contact alone.
    fn apply_call_signal(
        &mut self,
        fingerprint: [u8; 32],
        signal: CallSignal,
    ) -> Option<CallEvent> {
        match signal {
            CallSignal::Offer(offer) => {
                if self.calls.contains_key(&fingerprint) {
                    // Already on a call with them. Refuse rather than letting
                    // a second offer silently replace the first.
                    let _ = self.send_signal(
                        &fingerprint,
                        CallSignal::End(CallEnd {
                            call_id: offer.call_id,
                            reason: EndReason::Declined,
                        }),
                    );
                    return None;
                }
                let call = ActiveCall {
                    call_id: offer.call_id,
                    media_secret: offer.media_secret,
                    role: Role::Callee,
                    peer: fingerprint,
                    onion_address: offer.onion_address.clone(),
                    port: offer.port,
                    answered: false,
                };
                self.calls.insert(fingerprint, call.clone());
                Some(CallEvent::Incoming(call))
            }
            CallSignal::Answer(answer) => {
                let call = self.calls.get_mut(&fingerprint)?;
                if call.call_id != answer.call_id || call.role != Role::Caller {
                    return None;
                }
                call.answered = true;
                Some(CallEvent::Answered(call.clone()))
            }
            CallSignal::End(end) => {
                let call = self.calls.get(&fingerprint)?;
                if call.call_id != end.call_id {
                    return None;
                }
                self.calls.remove(&fingerprint);
                Some(CallEvent::Ended {
                    contact_fingerprint: fingerprint,
                    call_id: end.call_id,
                    reason: end.reason,
                })
            }
        }
    }

    /// Take everything that has happened to calls since this was last called.
    ///
    /// Drained rather than read, so a platform layer polling on a timer cannot
    /// show the same incoming call twice.
    pub fn take_call_events(&mut self) -> Vec<CallEvent> {
        core::mem::take(&mut self.call_events)
    }

    /// Mark a contact verified after an out-of-band fingerprint comparison.
    pub fn mark_verified(&mut self, fingerprint: &[u8; 32]) -> ClientResult<()> {
        self.sessions
            .get_mut(fingerprint)
            .ok_or(ClientError::NoSuchContact)?
            .contact
            .mark_verified();
        self.persist_session(*fingerprint)
    }

    /// Record that a contact's identity key changed. Blocks sending.
    pub fn note_key_change(
        &mut self,
        fingerprint: &[u8; 32],
        new_identity: IdentityPublic,
    ) -> ClientResult<()> {
        self.sessions
            .get_mut(fingerprint)
            .ok_or(ClientError::NoSuchContact)?
            .contact
            .note_key_change(new_identity);
        self.persist_session(*fingerprint)
    }

    /// The user acknowledged a key change.
    pub fn acknowledge_key_change(&mut self, fingerprint: &[u8; 32]) -> ClientResult<()> {
        self.sessions
            .get_mut(fingerprint)
            .ok_or(ClientError::NoSuchContact)?
            .contact
            .acknowledge_key_change();
        self.persist_session(*fingerprint)
    }

    /// Revoke a contact (FR-ABUSE-02).
    ///
    /// Destroys the shared queues by forgetting the secrets. The revoked
    /// contact's future deposits go into a queue nobody collects, and they are
    /// not notified — telling them would be a channel, and a hostile contact
    /// learning they were cut off is itself information.
    pub fn revoke_contact(&mut self, fingerprint: &[u8; 32]) -> ClientResult<()> {
        self.sessions
            .remove(fingerprint)
            .ok_or(ClientError::NoSuchContact)?;
        let doomed_outbox: Vec<u64> = self
            .outbox
            .iter()
            .filter(|i| &i.contact_fingerprint == fingerprint)
            .filter_map(|i| i.persisted_id)
            .collect();
        self.outbox
            .retain(|i| &i.contact_fingerprint != fingerprint);
        self.forget_persisted(fingerprint);
        if let Some(persisted) = &mut self.persisted {
            for id in doomed_outbox {
                let _ = persisted.store.delete(id);
            }
            let _ = persisted.store.flush();
        }
        Ok(())
    }

    /// Rotate a flooded queue without losing the contact (FR-ABUSE-03).
    pub fn rotate_queue(&mut self, fingerprint: &[u8; 32]) -> ClientResult<QueueId> {
        let s = self
            .sessions
            .get_mut(fingerprint)
            .ok_or(ClientError::NoSuchContact)?;
        s.established.recv_queue = s.established.recv_queue.rotate();
        let id = s.established.recv_queue.queue_id();
        self.persist_session(*fingerprint)?;
        Ok(id)
    }

    /// Contacts, for the conversation list.
    #[must_use]
    pub fn contacts(&self) -> Vec<&Contact> {
        self.sessions.values().map(|s| &s.contact).collect()
    }

    /// A contact by fingerprint.
    #[must_use]
    pub fn contact(&self, fingerprint: &[u8; 32]) -> Option<&Contact> {
        self.sessions.get(fingerprint).map(|s| &s.contact)
    }

    /// How many messages are waiting to be sent.
    #[must_use]
    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Build a stored-message record for the local database.
    #[must_use]
    pub fn stored_message(
        &self,
        fingerprint: [u8; 32],
        text: &str,
        direction: Direction,
        now: u64,
    ) -> StoredMessage {
        let timer = self
            .sessions
            .get(&fingerprint)
            .map(|s| s.contact.timer)
            .unwrap_or_default();
        let _ = effective_expiry(self.settings.retention, timer, now);
        StoredMessage {
            contact_fingerprint: fingerprint,
            direction,
            timestamp: now,
            body: text.to_string(),
            delivery: match direction {
                Direction::Outgoing => DeliveryState::Queued,
                Direction::Incoming => DeliveryState::Received,
            },
        }
    }

    /// The expiry a new message should be stored with.
    #[must_use]
    pub fn message_expiry(&self, fingerprint: &[u8; 32], now: u64) -> u64 {
        let timer = self
            .sessions
            .get(fingerprint)
            .map(|s| s.contact.timer)
            .unwrap_or_default();
        effective_expiry(self.settings.retention, timer, now)
    }

    /// The retention policy in force.
    #[must_use]
    pub fn retention(&self) -> RetentionPolicy {
        self.settings.retention
    }

    /// The security mode.
    #[must_use]
    pub fn mode(&self) -> SecurityMode {
        self.mode
    }

    /// Scheduler statistics, for the opt-in aggregate metrics in PRD §12.
    #[must_use]
    pub fn traffic_stats(&self) -> TrafficStats {
        TrafficStats {
            payload_records: self.scheduler.payload_count(),
            padding_records: self.scheduler.padding_count(),
            padding_bytes: self.scheduler.padding_bytes(),
        }
    }
}

/// What one scheduler tick did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TickOutcome {
    /// Nothing due; sleep this long.
    Waiting(std::time::Duration),
    /// A cover-traffic record was emitted.
    SentPadding,
    /// A real record was deposited.
    Deposited(u64),
    /// The relay refused the deposit; it stays queued.
    Refused(u64),
    /// Records were collected.
    Retrieved(Vec<ReceivedMessage>),
    /// The transport is unavailable. Messages stay queued; Void does not fall
    /// back to a direct connection (FR-TRANS-05).
    Offline,
}

/// A decrypted incoming message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceivedMessage {
    /// Who sent it.
    pub contact_fingerprint: [u8; 32],
    /// The text.
    pub text: String,
}

/// A call this engine is party to.
///
/// Carries everything the platform layer needs to open the media connection
/// and nothing it does not. The media secret lives here rather than being
/// re-derived, because it arrived inside a ratchet-encrypted offer and there
/// is nowhere else to get it from.
#[derive(Clone)]
pub struct ActiveCall {
    /// Identifies this call within the session.
    pub call_id: [u8; 16],
    /// Keys both directions of media. See `void_proto::call::MediaStream`.
    pub media_secret: [u8; 32],
    /// Which end this engine is.
    pub role: Role,
    /// The contact on the other end.
    pub peer: [u8; 32],
    /// The caller's onion service — dialled by the callee, published by the
    /// caller.
    pub onion_address: String,
    /// The virtual port that service listens on.
    pub port: u16,
    /// Whether the callee has answered yet.
    pub answered: bool,
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.media_secret.zeroize();
    }
}

impl core::fmt::Debug for ActiveCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ActiveCall")
            .field("call_id", &self.call_id)
            .field("role", &self.role)
            .field("onion_address", &self.onion_address)
            .field("answered", &self.answered)
            .field("media_secret", &"<redacted>")
            .finish()
    }
}

/// Something that happened to a call, for the platform layer to react to.
#[derive(Clone, Debug)]
pub enum CallEvent {
    /// A contact is calling. The phone should ring.
    Incoming(ActiveCall),
    /// A call this engine placed was answered; open the media connection.
    Answered(ActiveCall),
    /// A call ended, from either side.
    Ended {
        /// Who the call was with.
        contact_fingerprint: [u8; 32],
        /// Which call.
        call_id: [u8; 16],
        /// Why.
        reason: EndReason,
    },
}

/// Local traffic statistics.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TrafficStats {
    /// Records carrying real payload.
    pub payload_records: u64,
    /// Cover-traffic records.
    pub padding_records: u64,
    /// Bytes of cover traffic.
    pub padding_bytes: u64,
}

/// Convenience: a session's trust state.
#[must_use]
pub fn trust_of(engine: &Engine, fingerprint: &[u8; 32]) -> Option<TrustState> {
    engine.contact(fingerprint).map(|c| c.trust)
}

/// Shared clock for tests that drive an engine and a relay together.
pub type SharedClock = Arc<Mutex<u64>>;
