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

use void_crypto::{rand, Zeroize};
use void_proto::call::{CallAnswer, CallEnd, CallOffer, CallSignal, EndReason, Role};
use void_proto::content::Content;
use void_proto::envelope::{self, Deposit};
use void_proto::handshake::{self, Established, InitialMessage, PrekeyBundle, PrekeySecrets};
use void_proto::identity::{Identity, IdentityPublic, IdentitySeeds};
use void_proto::invite::{self, Invite, InviteBody, ShortInvite};
use void_proto::queue::{DepositKey, QueueId, QueueSecret, DEFAULT_TTL_SECONDS};
use void_proto::ratchet::{Message as RatchetMessage, Ratchet};
use void_proto::record::{self, Reassembler, Record, RecordKind, RECORD_SIZE};
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
    /// The `Kind::Message` record this fragment carries, if it carries one.
    /// Persisted with the item, so a restored outbox can still move that
    /// message to "Sent" once its last fragment lands.
    stored_message_id: Option<u64>,
    /// Whether this carries a call signal. Signals go out ahead of queued
    /// message fragments and are never written to disk: a call does not
    /// survive a restart, so neither does its ringing.
    signal: bool,
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
    /// Invitation id → its `Kind::Invite` record id.
    invites: BTreeMap<QueueId, u64>,
    /// Fragments of messages still arriving → their `Kind::Inbox` record ids.
    inbox: BTreeMap<(FragmentSource, u64), Vec<u64>>,
    /// Whether an inbox write is waiting for a flush. Fragments are written
    /// as they arrive and flushed once per retrieval, not once per fragment:
    /// a flush rewrites the whole file.
    inbox_dirty: bool,
}

/// Which reassembler a stored fragment belongs to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum FragmentSource {
    /// A session's receive queue, by the contact's fingerprint.
    Session([u8; 32]),
    /// An invitation's intro queue, by the invitation's id.
    Invite(QueueId),
}

impl Persisted {
    fn new(store: Box<dyn Store>, settings_id: u64) -> Persisted {
        Persisted {
            store,
            settings_id,
            contacts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            queues: BTreeMap::new(),
            outgoing_messages: BTreeMap::new(),
            invites: BTreeMap::new(),
            inbox: BTreeMap::new(),
            inbox_dirty: false,
        }
    }
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
/// encoding — it *is* the id of the record the encoding lives in. A
/// `stored_message_id` of zero means the item carries no stored message.
fn encode_outbox_item(item: &OutboxItem) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(&item.contact_fingerprint)
        .u64(item.message_id)
        .u32(item.attempts)
        .bytes32(&item.deposit.encode())
        .u64(item.stored_message_id.unwrap_or(0));
    w.finish()
}

fn decode_outbox_item(bytes: &[u8]) -> ClientResult<OutboxItem> {
    let mut r = Reader::new(bytes);
    let contact_fingerprint = r.array::<32>().map_err(|_| ClientError::Storage)?;
    let message_id = r.u64().map_err(|_| ClientError::Storage)?;
    let attempts = r.u32().map_err(|_| ClientError::Storage)?;
    let deposit = Deposit::decode(r.bytes32_max(4096).map_err(|_| ClientError::Storage)?)
        .map_err(|_| ClientError::Storage)?;
    let stored_message_id = r.u64().map_err(|_| ClientError::Storage)?;
    r.finish().map_err(|_| ClientError::Storage)?;
    Ok(OutboxItem {
        contact_fingerprint,
        deposit,
        message_id,
        attempts,
        persisted_id: None,
        stored_message_id: (stored_message_id != 0).then_some(stored_message_id),
        signal: false,
    })
}

/// Encode a `Kind::Invite` record: the intro queue, when to forget it, the
/// name for whoever accepts, and the prekey secrets. The caller zeroizes the
/// result once the store has copied it.
fn encode_invite_record(invite: &PendingInvite) -> Vec<u8> {
    let mut secrets = invite.secrets.serialize();
    let mut w = Writer::new();
    w.raw(invite.intro_queue.secret())
        .u32(invite.intro_queue.generation())
        .u64(invite.forget_after)
        .bytes16(invite.contact_label.as_bytes())
        .bytes32(&secrets)
        .bytes16(invite.link.as_bytes());
    match invite.drop_id {
        Some(id) => {
            w.u8(1).raw(&id);
        }
        None => {
            w.u8(0).raw(&[0u8; 16]);
        }
    }
    secrets.zeroize();
    w.finish()
}

fn decode_invite_record(bytes: &[u8]) -> ClientResult<PendingInvite> {
    let mut r = Reader::new(bytes);
    let secret = r.array::<32>().map_err(|_| ClientError::Storage)?;
    let generation = r.u32().map_err(|_| ClientError::Storage)?;
    let forget_after = r.u64().map_err(|_| ClientError::Storage)?;
    let label = r.bytes16().map_err(|_| ClientError::Storage)?;
    let contact_label = core::str::from_utf8(label)
        .map_err(|_| ClientError::Storage)?
        .to_string();
    let secrets =
        PrekeySecrets::deserialize(r.bytes32_max(8 * 1024).map_err(|_| ClientError::Storage)?)
            .map_err(|_| ClientError::Storage)?;
    let link = core::str::from_utf8(r.bytes16().map_err(|_| ClientError::Storage)?)
        .map_err(|_| ClientError::Storage)?
        .to_string();
    let has_drop = r.u8().map_err(|_| ClientError::Storage)?;
    let drop = r.array::<16>().map_err(|_| ClientError::Storage)?;
    r.finish().map_err(|_| ClientError::Storage)?;
    Ok(PendingInvite {
        secrets,
        intro_queue: QueueSecret::from_parts(secret, generation),
        reassembler: Reassembler::new(INVITE_REASSEMBLY_SLOTS),
        forget_after,
        contact_label,
        link,
        drop_id: match has_drop {
            0 => None,
            1 => Some(drop),
            _ => return Err(ClientError::Storage),
        },
    })
}

/// Encode a `Kind::Inbox` record: which reassembler the fragment belongs to,
/// then the fragment itself as it arrived.
fn encode_inbox_record(source: FragmentSource, record: &[u8; RECORD_SIZE]) -> Vec<u8> {
    let mut w = Writer::new();
    match source {
        FragmentSource::Session(fp) => {
            w.u8(1).raw(&fp);
        }
        FragmentSource::Invite(id) => {
            w.u8(2).raw(&id).raw(&[0u8; 16]);
        }
    }
    w.raw(record);
    w.finish()
}

fn decode_inbox_record(bytes: &[u8]) -> Option<(FragmentSource, Record)> {
    let mut r = Reader::new(bytes);
    let tag = r.u8().ok()?;
    let key = r.array::<32>().ok()?;
    let record = Record::decode(r.raw(RECORD_SIZE).ok()?).ok()?;
    r.finish().ok()?;
    let source = match tag {
        1 => FragmentSource::Session(key),
        2 => {
            let mut id = [0u8; 16];
            id.copy_from_slice(&key[..16]);
            FragmentSource::Invite(id)
        }
        _ => return None,
    };
    Some((source, record))
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

/// How long past its advertised expiry an invitation is still accepted.
///
/// The invitee's client checks the expiry when it opens the link (`invite::open`).
/// The handshake it sends after that is uploaded one record per emission
/// slot, so it takes minutes to land — or hours, if their phone went offline
/// right after they scanned. The initial message carries no timestamp to judge
/// it by, so the inviter keeps the prekey secrets for this long after the link
/// itself has stopped opening, rather than refusing a handshake that was
/// started in time.
pub const INVITE_ACCEPT_GRACE_SECONDS: u64 = 24 * 60 * 60;

/// How long an incoming call rings on the callee's screen before it is given up
/// as missed.
pub const RING_TIMEOUT_SECONDS: u64 = 60;

/// The oldest an offer can be when it arrives and still ring.
///
/// Offers wait in a mailbox like any message, so one can arrive long after its
/// caller gave up — an hour later, if the callee's phone was off. Ringing then
/// would put the user on a call with nobody. Past this age an offer is reported
/// as a missed call instead.
///
/// A live offer usually arrives within a minute, but not reliably. Whenever its
/// ratchet chain carries an ML-KEM step (D-005) it is four records, which
/// take four emission slots to leave, and the caller's own retrievals take some
/// of those slots. The callee's jittered retrieval then adds up to 35 seconds.
/// The age is also measured across two devices' clocks. Set to a minute, this
/// failed about one call in 300 in simulation, reporting as missed a call that
/// should have rung; two minutes covers the delay with room for clock skew.
pub const OFFER_MAX_AGE_SECONDS: u64 = 120;

/// How long the caller waits for an answer before giving up as missed.
///
/// Longer than the callee's ring, by exactly the oldest an offer may be when it
/// starts ringing: an offer that reaches the callee late still gets its full
/// ring, and the caller is still waiting when the callee picks up. A caller
/// timing out on the callee's clock would hang up on calls the callee answered.
///
/// A backstop, not the usual end: a callee whose ring runs out says so, and
/// the caller stops when that arrives. This timer is for a callee who went
/// offline mid-ring and never will.
pub const CALLER_TIMEOUT_SECONDS: u64 = OFFER_MAX_AGE_SECONDS + RING_TIMEOUT_SECONDS;

/// How long an opened short invitation is waited for before giving up.
///
/// Collection normally takes one retrieval. It takes longer only when the
/// person who made the invitation is still uploading it — they showed the code
/// the moment they made it — or is offline, in which case nothing will arrive
/// until they are back, and saying so is better than waiting forever.
pub const INVITE_FETCH_TIMEOUT_SECONDS: u64 = 10 * 60;

/// Longest local contact name kept, in bytes.
const MAX_CONTACT_NAME_LEN: usize = 128;

/// The longest prefix of `s` that fits `max` bytes and ends on a character
/// boundary.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The outbox owner recorded for an invitation's upload.
///
/// Outbox items are owned by a contact fingerprint, and an invitation has no
/// contact yet. This value cannot be a fingerprint in practice — sixteen fixed
/// bytes of a BLAKE3 output — so revoking a contact never touches an upload,
/// and cancelling the invitation can find its own.
fn invite_upload_owner(id: &QueueId) -> [u8; 32] {
    let mut owner = [0xFFu8; 32];
    owner[..16].copy_from_slice(id);
    owner
}

/// How many partial handshakes one invitation's reassembler holds.
///
/// A handshake is one message, so a single slot would do for an honest
/// invitee. The intro queue's deposit key is in every copy of the link,
/// though, so strangers depositing junk is expected — a little room keeps one
/// junk fragment from evicting the real handshake mid-arrival.
const INVITE_REASSEMBLY_SLOTS: usize = 16;

/// An invitation this engine published and is waiting for someone to accept.
///
/// Owned by the engine, not the platform layer, because accepting one is
/// part of the receive schedule: the intro queue is polled in the same
/// retrieval slot as every session queue (D-014), and the partial handshake
/// has to outlive any one poll.
struct PendingInvite {
    /// The prekey secrets the bundle was signed over. Consumed — and only
    /// then removed — when a handshake against them verifies (FR-DISC-02).
    secrets: PrekeySecrets,
    /// The queue the invitee deposits their handshake into.
    intro_queue: QueueSecret,
    /// Fragments of a handshake that has partly arrived.
    ///
    /// Kept across retrievals because the relay deletes each record as it
    /// hands it over. A handshake is about thirteen records uploaded one per
    /// emission slot, so a retrieval landing mid-upload is the normal case;
    /// a reassembler that lived only for one poll threw those records away
    /// and the contact never appeared.
    reassembler: Reassembler,
    /// Unix seconds after which this invitation is forgotten, including
    /// [`INVITE_ACCEPT_GRACE_SECONDS`].
    forget_after: u64,
    /// The local name for whoever accepts. Never transmitted.
    contact_label: String,
    /// The link, so the app can show the code again. Empty for a bundle made
    /// with [`Engine::create_bundle`], which has no link of its own.
    link: String,
    /// The relay queue this invitation's body is parked in, if it is a short
    /// invitation — so the engine recognises its own link when it is opened
    /// here, rather than collecting (and so destroying) its own parked body.
    drop_id: Option<QueueId>,
}

/// An invitation the user opened, while its parked body is collected.
struct PendingFetch {
    /// The short link being collected. `None` for a full link, which carried
    /// everything and was ready the moment it opened.
    short: Option<ShortInvite>,
    /// Fragments of the parked body collected so far. The relay deletes each
    /// as it hands it over, so they are kept between retrievals.
    reassembler: Reassembler,
    /// Unix seconds after which collection gives up.
    give_up_after: u64,
    /// The verified invitation, once collected — waiting for the user to
    /// confirm it with [`Engine::confirm_invite`].
    body: Option<InviteBody>,
}

/// Why an invitation the user opened could not be used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InviteFailure {
    /// It expired. The person who made it needs to make a new one.
    Expired,
    /// What was collected did not decrypt or verify.
    Invalid,
    /// Nothing arrived in [`INVITE_FETCH_TIMEOUT_SECONDS`] — the person who
    /// made it has probably not been online since, or it was already used.
    TimedOut,
}

/// An invitation ready to hand to someone.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CreatedInvite {
    /// The `void://` link. Also the QR payload.
    pub link: String,
    /// Identifies this invitation to [`Engine::cancel_invite`] and in
    /// [`ContactEvent`]s. It is the intro queue's id, which the relay already
    /// sees, so handing it to the platform layer reveals nothing new.
    pub id: QueueId,
}

/// Something that happened to a contact or an invitation, for the platform
/// layer to react to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ContactEvent {
    /// Someone accepted one of our invitations. A session with them exists.
    Added {
        /// Which invitation they used.
        invite_id: QueueId,
        /// Who they are.
        contact_fingerprint: [u8; 32],
        /// The local name given to them — the invitation's contact label.
        name: String,
        /// Their first message. Empty if they sent none.
        first_message: String,
    },
    /// An invitation passed its expiry unaccepted and was forgotten.
    InviteExpired {
        /// Which invitation.
        invite_id: QueueId,
    },
    /// An invitation the user opened has been collected and verified. Show who
    /// it is from, then connect with [`Engine::confirm_invite`].
    InviteReady {
        /// The id [`Engine::open_invite`] returned.
        fetch_id: QueueId,
        /// The name its maker put on it. Not an identity — anyone can type any
        /// name, which is what the fingerprint is for.
        inviter_label: String,
        /// Its maker's fingerprint, so the app can show their security code,
        /// and notice a person who is already a contact, before connecting.
        inviter_fingerprint: [u8; 32],
    },
    /// An invitation the user opened could not be used.
    InviteFailed {
        /// The id [`Engine::open_invite`] returned.
        fetch_id: QueueId,
        /// Why.
        reason: InviteFailure,
    },
}

/// What one queue retrieval collected.
struct Collected {
    /// Every deposit the relay handed over, in order.
    ///
    /// The relay deleted each one as it handed it over, so the caller must
    /// process every one of these — including when `error` is set. A retrieval
    /// that dropped what it had already collected because a later exchange
    /// failed would lose those messages permanently.
    deposits: Vec<Deposit>,
    /// Why retrieval stopped early, if it did.
    error: Option<ClientError>,
}

/// A fresh id for an outgoing message.
///
/// Random rather than a counter. The id travels inside the sealed record,
/// where only the recipient sees it, and it is what their reassembler groups
/// fragments by. A counter restarted at 1 whenever the outbox was empty at
/// launch, so a stalled partial left in the peer's reassembler from before
/// could absorb a new message's fragments and corrupt both; and on an intro
/// queue — whose deposit key is in every copy of the link — a predictable id
/// let a stranger aim junk fragments at a handshake that was still arriving.
fn new_message_id() -> ClientResult<u64> {
    rand::u64_().map_err(|_| ClientError::Entropy)
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
    /// Invitations we have published and are waiting on, keyed by their intro
    /// queue's id. Each is consumed by the first handshake that verifies
    /// against it (FR-DISC-02).
    pending_invites: BTreeMap<QueueId, PendingInvite>,
    /// Contact events waiting for the platform layer to collect.
    contact_events: Vec<ContactEvent>,
    /// Invitations the user opened, keyed by the id [`Engine::open_invite`]
    /// returned. Kept in memory only: collection takes seconds, and a restart
    /// in that window costs a rescan.
    fetches: BTreeMap<QueueId, PendingFetch>,
    /// The relay this engine reaches, as the platform addresses it — what a
    /// short invitation made here names, and what one opened here must name.
    relay: Option<String>,
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
            pending_invites: BTreeMap::new(),
            contact_events: Vec::new(),
            fetches: BTreeMap::new(),
            relay: None,
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
        engine.persisted = Some(Persisted::new(store, settings_id));
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
        let mut outgoing_messages = BTreeMap::new();
        for r in store.list(Kind::Outbox).map_err(|_| ClientError::Storage)? {
            let mut item = decode_outbox_item(&r.payload)?;
            item.persisted_id = Some(r.id);
            if let Some(stored) = item.stored_message_id {
                outgoing_messages.insert(item.message_id, stored);
            }
            outbox.push(item);
        }

        let mut invite_ids = BTreeMap::new();
        let mut pending_invites = BTreeMap::new();
        for r in store.list(Kind::Invite).map_err(|_| ClientError::Storage)? {
            let invite = decode_invite_record(&r.payload)?;
            let id = invite.intro_queue.queue_id();
            invite_ids.insert(id, r.id);
            pending_invites.insert(id, invite);
        }
        let inbox = store.list(Kind::Inbox).map_err(|_| ClientError::Storage)?;

        let mut engine = Engine::new(identity, settings, transport, mode, now_ms)?;
        engine.sessions = sessions;
        engine.outbox = outbox;
        engine.pending_invites = pending_invites;
        let mut persisted = Persisted::new(store, settings_id);
        persisted.contacts = contact_ids;
        persisted.sessions = session_ids;
        persisted.queues = queue_ids;
        persisted.outgoing_messages = outgoing_messages;
        persisted.invites = invite_ids;
        engine.persisted = Some(persisted);

        engine.refeed_inbox(inbox, now_ms);
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
        self.pending_invites.clear();
        self.contact_events.clear();
        self.fetches.clear();
        // Calls hold media secrets, and a pending event can hold a copy.
        self.calls.clear();
        self.call_events.clear();
        // The identity's secret keys are what would let this process go on
        // acting as the user. Replacing them drops the real ones, which wipe
        // themselves; the stand-in is derived from fixed zero seeds and belongs
        // to nobody. Nothing should use this engine after duress — the platform
        // frees it and shows a first-run screen — but anything that does acts
        // as no one.
        self.identity = Identity::from_seeds(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        // The name the user put on invitations, and the relay they used.
        self.settings = Settings::default();
        self.relay = None;

        // Dropped once destroyed, so no later call writes to a store that is
        // gone, and whatever key material the store holds is released.
        match self.persisted.take() {
            Some(mut p) => p.store.destroy().map_err(|_| ClientError::Storage),
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

    /// Publish a prekey bundle that never expires, returning it with its intro
    /// queue. The lower-level half of [`Engine::create_invite`], for tests and
    /// the reference CLI, which render the bundle themselves.
    ///
    /// Each call allocates a fresh queue and a fresh one-time prekey, so two
    /// invitations handed to two people share nothing a relay could correlate.
    /// The engine polls the intro queue on its own schedule from then on; see
    /// [`Engine::take_contact_events`].
    pub fn create_bundle(
        &mut self,
        relay_hint: &[u8],
    ) -> ClientResult<(PrekeyBundle, QueueSecret)> {
        self.register_invite(relay_hint, u64::MAX, "", String::new(), None)
    }

    /// Allocate an intro queue and a signed bundle over it, and start waiting
    /// for someone to accept it.
    fn register_invite(
        &mut self,
        relay_hint: &[u8],
        forget_after: u64,
        contact_label: &str,
        link: String,
        drop_id: Option<QueueId>,
    ) -> ClientResult<(PrekeyBundle, QueueSecret)> {
        let intro_queue = QueueSecret::generate().map_err(|_| ClientError::Protocol)?;
        let (bundle, secrets) =
            PrekeyBundle::create(&self.identity, &intro_queue, relay_hint, true)
                .map_err(|_| ClientError::Protocol)?;
        let id = intro_queue.queue_id();
        let invite = PendingInvite {
            secrets,
            intro_queue: intro_queue.clone(),
            reassembler: Reassembler::new(INVITE_REASSEMBLY_SLOTS),
            forget_after,
            contact_label: String::from(truncate_utf8(contact_label, MAX_CONTACT_NAME_LEN)),
            link,
            drop_id,
        };
        // Written before the link exists, so there is no moment when someone
        // could accept an invitation this device would not remember after a
        // restart. An invitation that cannot be written is refused outright.
        if let Some(persisted) = &mut self.persisted {
            let mut payload = encode_invite_record(&invite);
            // Zero means "never expires" to the store's sweep.
            let expires_at = if forget_after == u64::MAX {
                0
            } else {
                forget_after
            };
            let written = persisted
                .store
                .insert(Kind::Invite, expires_at, &payload)
                .and_then(|record_id| {
                    persisted.invites.insert(id, record_id);
                    persisted.store.flush()
                });
            payload.zeroize();
            written.map_err(|_| ClientError::Storage)?;
        }
        self.pending_invites.insert(id, invite);
        Ok((bundle, intro_queue))
    }

    /// Forget an invitation: its secrets, its stored record, and any fragments
    /// of a handshake that had started to arrive for it.
    fn forget_invite(&mut self, id: &QueueId) -> bool {
        let existed = self.pending_invites.remove(id).is_some();
        // Stop uploading it, too: a withdrawn invitation's body has no business
        // reaching the relay after the fact.
        let owner = invite_upload_owner(id);
        let doomed: Vec<u64> = self
            .outbox
            .iter()
            .filter(|i| i.contact_fingerprint == owner)
            .filter_map(|i| i.persisted_id)
            .collect();
        self.outbox.retain(|i| i.contact_fingerprint != owner);
        if let Some(persisted) = &mut self.persisted {
            if let Some(record_id) = persisted.invites.remove(id) {
                let _ = persisted.store.delete(record_id);
            }
            for record_id in doomed {
                let _ = persisted.store.delete(record_id);
            }
        }
        self.drop_all_fragments(FragmentSource::Invite(*id));
        if let Some(persisted) = &mut self.persisted {
            let _ = persisted.store.flush();
        }
        existed
    }

    /// Keep a fragment whose message has not finished arriving.
    ///
    /// The relay deleted it when it handed it over, so until the rest of the
    /// message arrives this is the only copy. Without it, a restart between
    /// two retrievals lost every multi-record message in flight — including a
    /// handshake, which is thirteen records long and so almost always spans
    /// several. Expires when the relay would have expired the rest.
    fn stash_fragment(&mut self, source: FragmentSource, record: &Record, now: u64) {
        let Some(persisted) = &mut self.persisted else {
            return;
        };
        let Ok(mut bytes) = record.encode() else {
            return;
        };
        let mut payload = encode_inbox_record(source, &bytes);
        bytes.zeroize();
        if let Ok(record_id) = persisted.store.insert(
            Kind::Inbox,
            now.saturating_add(DEFAULT_TTL_SECONDS),
            &payload,
        ) {
            persisted
                .inbox
                .entry((source, record.message_id))
                .or_default()
                .push(record_id);
            persisted.inbox_dirty = true;
        }
        payload.zeroize();
    }

    /// Delete the stored fragments of one message that has now arrived in full,
    /// whether or not it turned out to decrypt.
    fn drop_fragments(&mut self, source: FragmentSource, message_id: u64) {
        let Some(persisted) = &mut self.persisted else {
            return;
        };
        if let Some(ids) = persisted.inbox.remove(&(source, message_id)) {
            for id in ids {
                let _ = persisted.store.delete(id);
            }
            persisted.inbox_dirty = true;
        }
    }

    /// Delete every stored fragment belonging to one reassembler.
    fn drop_all_fragments(&mut self, source: FragmentSource) {
        let Some(persisted) = &mut self.persisted else {
            return;
        };
        let keys: Vec<(FragmentSource, u64)> = persisted
            .inbox
            .keys()
            .filter(|(s, _)| *s == source)
            .copied()
            .collect();
        for key in keys {
            if let Some(ids) = persisted.inbox.remove(&key) {
                for id in ids {
                    let _ = persisted.store.delete(id);
                }
            }
            persisted.inbox_dirty = true;
        }
    }

    /// Write out any fragment changes made during a retrieval.
    fn flush_inbox(&mut self) {
        if let Some(persisted) = &mut self.persisted {
            if persisted.inbox_dirty {
                persisted.inbox_dirty = false;
                let _ = persisted.store.flush();
            }
        }
    }

    /// Put the fragments a previous run stored back into their reassemblers.
    ///
    /// Best effort by design: a fragment whose reassembler no longer exists
    /// (the contact was revoked, the invitation was accepted or expired), or
    /// that no longer decodes, is deleted rather than failing the restore. A
    /// message those fragments complete is processed exactly as if it had
    /// just arrived — which is only possible if the previous run stopped in
    /// the moment between receiving a message's last fragment and deleting its
    /// others, and then the ratchet refuses it as a replay, as it should.
    fn refeed_inbox(&mut self, stored: Vec<void_store::db::Record>, now_ms: u64) {
        for r in stored {
            let Some((source, record)) = decode_inbox_record(&r.payload) else {
                if let Some(persisted) = &mut self.persisted {
                    let _ = persisted.store.delete(r.id);
                }
                continue;
            };
            let pushed = match source {
                FragmentSource::Session(fp) => self
                    .sessions
                    .get_mut(&fp)
                    .map(|s| s.reassembler.push(&record)),
                FragmentSource::Invite(id) => self
                    .pending_invites
                    .get_mut(&id)
                    .map(|p| p.reassembler.push(&record)),
            };
            match pushed {
                Some(Ok(None)) => {
                    if let Some(persisted) = &mut self.persisted {
                        persisted
                            .inbox
                            .entry((source, record.message_id))
                            .or_default()
                            .push(r.id);
                    }
                }
                Some(Ok(Some(payload))) => {
                    if let Some(persisted) = &mut self.persisted {
                        let _ = persisted.store.delete(r.id);
                    }
                    match source {
                        FragmentSource::Session(fp) => {
                            let _ = self.process_session_payload(&fp, &payload, now_ms);
                        }
                        FragmentSource::Invite(id) => {
                            self.receive_invite_payload(&id, &payload, now_ms / 1000);
                        }
                    }
                    self.drop_fragments(source, record.message_id);
                }
                None | Some(Err(_)) => {
                    if let Some(persisted) = &mut self.persisted {
                        let _ = persisted.store.delete(r.id);
                    }
                }
            }
        }
        if let Some(persisted) = &mut self.persisted {
            let _ = persisted.store.flush();
        }
    }

    /// Publish an invitation and return the link to share (FR-DISC-01,
    /// FR-DISC-02).
    ///
    /// The link is short — about 130 characters, one QR code — because the
    /// invitation itself is parked on the relay rather than carried in it (see
    /// [`ShortInvite`]). Parking it rides the ordinary outbox, one record per
    /// emission slot, so it is collectable about ten slots later;
    /// [`Engine::invite_upload_remaining`] says how far along it is, and
    /// whoever opens the link before then simply waits for it.
    ///
    /// `relay` is where it is parked — this engine's relay, as the platform
    /// addresses it. Empty means the one set with [`Engine::set_relay`].
    /// `my_label` travels inside the encrypted invitation and is shown to
    /// whoever opens it, so they know who it is from. `contact_label` never
    /// leaves this device: it becomes the name of whoever accepts, because an
    /// invitation is made for one person and whoever makes it knows who.
    ///
    /// Any number can be outstanding; each is forgotten
    /// [`INVITE_ACCEPT_GRACE_SECONDS`] after it expires.
    pub fn create_invite(
        &mut self,
        relay: &[u8],
        my_label: &str,
        contact_label: &str,
        now: u64,
        ttl_seconds: u64,
    ) -> ClientResult<CreatedInvite> {
        let relay = if relay.is_empty() {
            self.relay.clone().ok_or(ClientError::InvalidInvite)?
        } else {
            String::from(core::str::from_utf8(relay).map_err(|_| ClientError::InvalidInvite)?)
        };
        let short = ShortInvite::generate(&relay).map_err(|_| ClientError::InvalidInvite)?;
        let link = short.to_link();
        let drop = short.drop_queue();
        let forget_after = now
            .saturating_add(ttl_seconds)
            .saturating_add(INVITE_ACCEPT_GRACE_SECONDS);
        let (bundle, intro_queue) = self.register_invite(
            relay.as_bytes(),
            forget_after,
            contact_label,
            link.clone(),
            Some(drop.queue_id()),
        )?;
        let id = intro_queue.queue_id();

        let parked =
            match invite::create_with_key(&bundle, now, ttl_seconds, my_label, short.link_key()) {
                Ok(parked) => parked,
                Err(_) => {
                    self.forget_invite(&id);
                    return Err(ClientError::Protocol);
                }
            };
        let uploaded = new_message_id().and_then(|message_id| {
            self.enqueue(
                invite_upload_owner(&id),
                &drop.deposit_key(),
                &parked.ciphertext,
                message_id,
                None,
                false,
            )
        });
        if let Err(e) = uploaded {
            self.forget_invite(&id);
            return Err(e);
        }
        Ok(CreatedInvite { link, id })
    }

    /// Set the relay this engine reaches, as the platform addresses it (for
    /// example `"<onion>:<port>"`). Short invitations made here name it, and
    /// one opened here must name it too.
    pub fn set_relay(&mut self, relay: &str) {
        self.relay = Some(relay.to_ascii_lowercase());
    }

    /// The link of an outstanding invitation, so the app can show its code
    /// again. `None` once it is accepted, expired, or cancelled.
    #[must_use]
    pub fn invite_link(&self, id: &QueueId) -> Option<&str> {
        self.pending_invites
            .get(id)
            .map(|p| p.link.as_str())
            .filter(|l| !l.is_empty())
    }

    /// How many of an outstanding invitation's records are still waiting to be
    /// parked on the relay. Zero means whoever opens the link can collect it
    /// now; `None` means it is no longer outstanding.
    #[must_use]
    pub fn invite_upload_remaining(&self, id: &QueueId) -> Option<usize> {
        if !self.pending_invites.contains_key(id) {
            return None;
        }
        let owner = invite_upload_owner(id);
        Some(
            self.outbox
                .iter()
                .filter(|i| i.contact_fingerprint == owner)
                .count(),
        )
    }

    /// Open an invitation link someone gave us — scanned or pasted — and start
    /// collecting it.
    ///
    /// Returns an id naming this invitation in the [`ContactEvent::InviteReady`]
    /// or [`ContactEvent::InviteFailed`] that follows, and in
    /// [`Engine::confirm_invite`]. A full link carries everything, so it is
    /// ready at once. A short one is collected from the relay in the next
    /// emission slot (see `Scheduler::request_retrieval_next_slot`), or later
    /// if its maker is still uploading it.
    ///
    /// Nothing about the contact list changes until the user confirms.
    pub fn open_invite(&mut self, link: &str, now: u64) -> ClientResult<QueueId> {
        let link = link.trim();
        if link.starts_with(invite::SHORT_LINK_PREFIX) {
            let short = ShortInvite::from_link(link).map_err(|_| ClientError::InvalidInvite)?;
            if let Some(relay) = &self.relay {
                if relay != &short.relay {
                    return Err(ClientError::WrongRelay);
                }
            }
            let id = short.drop_queue().queue_id();
            // Collecting our own parked invitation would destroy it for the
            // person it was made for; the relay deletes as it hands over.
            if self.pending_invites.values().any(|p| p.drop_id == Some(id)) {
                return Err(ClientError::OwnInvite);
            }
            // Opening the same link twice keeps the first fetch and whatever it
            // has already collected; the relay will not hand those records over
            // a second time.
            self.fetches.entry(id).or_insert_with(|| PendingFetch {
                short: Some(short),
                reassembler: Reassembler::new(INVITE_REASSEMBLY_SLOTS),
                give_up_after: now.saturating_add(INVITE_FETCH_TIMEOUT_SECONDS),
                body: None,
            });
            self.scheduler.request_retrieval_next_slot();
            Ok(id)
        } else {
            let parsed = Invite::from_link(link).map_err(|_| ClientError::InvalidInvite)?;
            let body = match invite::open(&parsed, now) {
                Ok(body) => body,
                Err(void_proto::ProtoError::Expired) => return Err(ClientError::InviteExpired),
                Err(_) => return Err(ClientError::InvalidInvite),
            };
            let id = rand::bytes16().map_err(|_| ClientError::Entropy)?;
            self.contact_events.push(ContactEvent::InviteReady {
                fetch_id: id,
                inviter_label: body.label.clone(),
                inviter_fingerprint: body.bundle.identity.fingerprint(),
            });
            self.fetches.insert(
                id,
                PendingFetch {
                    short: None,
                    reassembler: Reassembler::new(1),
                    give_up_after: body.expires_at,
                    body: Some(body),
                },
            );
            Ok(id)
        }
    }

    /// Connect using an invitation the engine reported ready. Returns the new
    /// contact's fingerprint.
    ///
    /// An empty `local_name` takes the name the invitation's maker put on it.
    /// `first_message` may be empty, to connect without saying anything yet.
    pub fn confirm_invite(
        &mut self,
        fetch_id: &QueueId,
        local_name: &str,
        first_message: &str,
        now: u64,
    ) -> ClientResult<[u8; 32]> {
        let body = self
            .fetches
            .get(fetch_id)
            .and_then(|f| f.body.clone())
            .ok_or(ClientError::NoSuchInvite)?;
        if now > body.expires_at {
            self.fetches.remove(fetch_id);
            return Err(ClientError::InviteExpired);
        }
        let name = if local_name.trim().is_empty() {
            body.label.as_str()
        } else {
            local_name
        };
        let name = truncate_utf8(name, MAX_CONTACT_NAME_LEN);
        match self.start_conversation(&body.bundle, name, first_message, now) {
            Ok(fingerprint) => {
                self.fetches.remove(fetch_id);
                Ok(fingerprint)
            }
            Err(e) => {
                // Nothing left to try with an invitation that is the user's own
                // or names someone already a contact; a storage or entropy
                // failure may be worth retrying.
                if matches!(e, ClientError::AlreadyConnected | ClientError::OwnInvite) {
                    self.fetches.remove(fetch_id);
                }
                Err(e)
            }
        }
    }

    /// Stop waiting for an invitation the user opened. Returns whether it was
    /// still open.
    pub fn cancel_fetch(&mut self, fetch_id: &QueueId) -> bool {
        self.fetches.remove(fetch_id).is_some()
    }

    /// Collect every opened short invitation still waiting for its body.
    fn collect_fetches(&mut self, now: u64) -> Option<ClientError> {
        let waiting: Vec<(QueueId, QueueSecret)> = self
            .fetches
            .iter()
            .filter(|(_, f)| f.body.is_none())
            .filter_map(|(id, f)| f.short.as_ref().map(|s| (*id, s.drop_queue())))
            .collect();
        for (id, queue) in waiting {
            let collected = self.retrieve_queue(&queue);
            for deposit in &collected.deposits {
                self.receive_fetch_deposit(&id, &queue, deposit, now);
            }
            if collected.error.is_some() {
                return collected.error;
            }
        }
        None
    }

    fn receive_fetch_deposit(
        &mut self,
        id: &QueueId,
        queue: &QueueSecret,
        deposit: &Deposit,
        now: u64,
    ) {
        let outcome = {
            let Some(fetch) = self.fetches.get_mut(id) else {
                return;
            };
            if fetch.body.is_some() {
                return;
            }
            let Ok(record) = envelope::open(&queue.deposit_key(), deposit) else {
                return;
            };
            let Ok(Some(ciphertext)) = fetch.reassembler.push(&record) else {
                return;
            };
            let Some(short) = &fetch.short else {
                return;
            };
            short.open_parked(&ciphertext, now)
        };
        match outcome {
            Ok(body) => {
                self.contact_events.push(ContactEvent::InviteReady {
                    fetch_id: *id,
                    inviter_label: body.label.clone(),
                    inviter_fingerprint: body.bundle.identity.fingerprint(),
                });
                if let Some(fetch) = self.fetches.get_mut(id) {
                    fetch.give_up_after = body.expires_at;
                    fetch.body = Some(body);
                }
            }
            Err(e) => {
                self.fetches.remove(id);
                let reason = if e == void_proto::ProtoError::Expired {
                    InviteFailure::Expired
                } else {
                    InviteFailure::Invalid
                };
                self.contact_events.push(ContactEvent::InviteFailed {
                    fetch_id: *id,
                    reason,
                });
            }
        }
    }

    /// Give up on opened invitations that never arrived, and forget ready ones
    /// the user never confirmed once they expire.
    fn expire_fetches(&mut self, now: u64) {
        let expired: Vec<(QueueId, bool)> = self
            .fetches
            .iter()
            .filter(|(_, f)| now > f.give_up_after)
            .map(|(id, f)| (*id, f.body.is_none()))
            .collect();
        for (id, still_waiting) in expired {
            self.fetches.remove(&id);
            if still_waiting {
                self.contact_events.push(ContactEvent::InviteFailed {
                    fetch_id: id,
                    reason: InviteFailure::TimedOut,
                });
            }
        }
    }

    /// Withdraw an invitation. Returns whether it was still outstanding.
    ///
    /// The link keeps opening for whoever holds it — it is self-contained —
    /// but a handshake sent against it is never answered, because the secrets
    /// it needs are gone.
    pub fn cancel_invite(&mut self, id: &QueueId) -> bool {
        self.forget_invite(id)
    }

    /// Whether an invitation is still waiting to be accepted.
    #[must_use]
    pub fn has_pending_invite(&self, id: &QueueId) -> bool {
        self.pending_invites.contains_key(id)
    }

    /// Take everything that has happened to contacts and invitations since this
    /// was last called.
    ///
    /// Drained rather than read, like [`Engine::take_call_events`], so a
    /// platform layer polling on a timer cannot announce one contact twice.
    pub fn take_contact_events(&mut self) -> Vec<ContactEvent> {
        core::mem::take(&mut self.contact_events)
    }

    /// The contact record a new session with `identity` should carry.
    ///
    /// A fresh contact for a new identity. For one we already know — they
    /// started over with a new invitation from us — the fingerprint the user
    /// may have verified is unchanged, so the verification still holds, and so
    /// does the name they chose unless this handshake came with a new one.
    fn contact_for_new_session(&self, identity: IdentityPublic, name: &str, now: u64) -> Contact {
        match self.sessions.get(&identity.fingerprint()) {
            Some(existing) => {
                let mut contact = existing.contact.clone();
                if !name.is_empty() {
                    contact.local_name = String::from(name);
                }
                contact
            }
            None => Contact::new(identity, name, now),
        }
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
        let fingerprint = bundle.identity.fingerprint();
        if fingerprint == self.fingerprint() {
            return Err(ClientError::OwnInvite);
        }
        // Checked before anything is derived, so a refused rescan changes
        // nothing: not the existing session, not the outbox.
        if self.sessions.contains_key(&fingerprint) {
            return Err(ClientError::AlreadyConnected);
        }

        let (initial, established, intro_deposit) = handshake::initiate(
            &self.identity,
            bundle,
            &Content::text(first_message).encode(),
        )
        .map_err(|_| ClientError::Protocol)?;

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
        let message_id = new_message_id()?;
        // An empty first message is how someone connects without saying
        // anything yet; there is nothing to show in the history for it.
        let stored = if first_message.is_empty() {
            None
        } else {
            self.store_outgoing_message(fingerprint, first_message, now, message_id)
        };
        self.enqueue(
            fingerprint,
            &intro_deposit,
            &initial.encode(),
            message_id,
            stored,
            false,
        )?;
        Ok(fingerprint)
    }

    /// Accept a handshake delivered to one of our invitations (the responder
    /// side). Returns the peer's fingerprint and their first message.
    ///
    /// The engine calls this itself when a handshake reassembles on an intro
    /// queue during [`Engine::tick`], and reports the result through
    /// [`Engine::take_contact_events`]. It is public for the tests and the
    /// reference CLI, which collect a handshake by hand.
    ///
    /// ## Verify, then change state — never the other way round
    ///
    /// Anyone holding the link can deposit into the intro queue, so
    /// `initial_bytes` is a candidate, not a handshake. Every check runs first:
    /// decoding, the transcript signature, decryption of the first message, and
    /// that it is text. Only when all of them pass is the invitation consumed
    /// and a session created. A version that consumed the prekey secrets
    /// before checking let one junk deposit from anyone with the link destroy
    /// the invitation for the person it was meant for — the mistake D-021
    /// fixed in the ratchet, one layer up.
    pub fn accept_conversation(
        &mut self,
        invite_id: QueueId,
        initial_bytes: &[u8],
        now: u64,
    ) -> ClientResult<([u8; 32], String)> {
        let pending = self
            .pending_invites
            .get(&invite_id)
            .ok_or(ClientError::UnknownBundle)?;
        let initial = InitialMessage::decode(initial_bytes).map_err(|_| ClientError::Protocol)?;
        let (established, plaintext) =
            handshake::respond(&self.identity, &pending.secrets, &initial)
                .map_err(|_| ClientError::Protocol)?;
        // Framed like every other plaintext, even though the first message is
        // text by construction — one rule about what a plaintext is, with no
        // exceptions to remember, is the point.
        let text = match Content::decode(&plaintext).map_err(|_| ClientError::Protocol)? {
            Content::Text(t) => t,
            Content::Call(_) => return Err(ClientError::Protocol),
        };

        // Everything verified. Only now does anything change.
        let contact_label = pending.contact_label.clone();
        self.forget_invite(&invite_id);
        let fingerprint = initial.identity.fingerprint();
        let contact = self.contact_for_new_session(initial.identity.clone(), &contact_label, now);
        self.sessions.insert(
            fingerprint,
            Session {
                contact,
                established,
                reassembler: Reassembler::new(64),
            },
        );
        self.persist_session(fingerprint)?;

        // An empty first message is how someone connects without saying
        // anything yet. It is not a message, so it is neither stored nor shown.
        if !text.is_empty() {
            self.store_incoming_message(fingerprint, &text, now);
        }
        Ok((fingerprint, text))
    }

    /// Poll every outstanding invitation's intro queue once, accepting any
    /// handshake that completes and verifies.
    ///
    /// Runs inside the retrieval slot, after the session queues, so waiting
    /// for a contact adds no frame of its own and no timer to the platform
    /// layer (D-014). Returns the transport error that stopped it, if any.
    fn collect_invites(&mut self, now: u64) -> Option<ClientError> {
        let ids: Vec<QueueId> = self.pending_invites.keys().copied().collect();
        for id in ids {
            let Some(queue) = self.pending_invites.get(&id).map(|p| p.intro_queue.clone()) else {
                continue;
            };
            let collected = self.retrieve_queue(&queue);
            for deposit in &collected.deposits {
                self.receive_invite_deposit(&id, deposit, now);
            }
            if collected.error.is_some() {
                return collected.error;
            }
        }
        None
    }

    /// Feed one intro-queue deposit into its invitation, accepting the
    /// handshake if this completes one.
    fn receive_invite_deposit(&mut self, id: &QueueId, deposit: &Deposit, now: u64) {
        let Some(pending) = self.pending_invites.get_mut(id) else {
            // Accepted earlier in this batch. Anything after it is a second
            // person using a single-use link, or a stranger's junk; either way
            // there is nothing left to answer it with.
            return;
        };
        let Ok(record) = envelope::open(&pending.intro_queue.deposit_key(), deposit) else {
            return;
        };
        // A record that will not reassemble is discarded on the same terms as
        // one that will not open (D-022). Strangers are expected here: this
        // queue's deposit key is in every copy of the link.
        match pending.reassembler.push(&record) {
            Ok(Some(payload)) => {
                self.receive_invite_payload(id, &payload, now);
                self.drop_fragments(FragmentSource::Invite(*id), record.message_id);
            }
            Ok(None) if record.kind == RecordKind::Payload => {
                self.stash_fragment(FragmentSource::Invite(*id), &record, now);
            }
            _ => {}
        }
    }

    /// Try to accept a complete intro-queue payload, reporting the new contact
    /// if it verifies.
    fn receive_invite_payload(&mut self, id: &QueueId, payload: &[u8], now: u64) {
        // A complete payload is a candidate, not a handshake.
        // `accept_conversation` verifies it before changing anything, so a
        // candidate that fails costs nothing but itself.
        if let Ok((fingerprint, first_message)) = self.accept_conversation(*id, payload, now) {
            let name = self
                .sessions
                .get(&fingerprint)
                .map(|s| s.contact.local_name.clone())
                .unwrap_or_default();
            self.contact_events.push(ContactEvent::Added {
                invite_id: *id,
                contact_fingerprint: fingerprint,
                name,
                first_message,
            });
        }
    }

    /// Forget every invitation past its expiry and grace period.
    fn expire_invites(&mut self, now: u64) {
        let expired: Vec<QueueId> = self
            .pending_invites
            .iter()
            .filter(|(_, p)| now > p.forget_after)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.forget_invite(&id);
            self.contact_events
                .push(ContactEvent::InviteExpired { invite_id: id });
        }
    }

    /// Collect everything waiting in one queue.
    ///
    /// The one retrieval loop in the engine: session queues and intro queues
    /// are collected the same way, so they cannot drift apart.
    fn retrieve_queue(&mut self, queue: &QueueSecret) -> Collected {
        let queue_id = queue.queue_id();
        let mut deposits = Vec::new();
        // Bounded, like every loop that talks to the relay: a hostile relay
        // must not be able to keep us here.
        for _ in 0..64 {
            let reply = match self
                .transport
                .exchange(&Frame::new(FrameType::Challenge, queue_id.to_vec()))
            {
                Ok(reply) => reply,
                Err(error) => {
                    return Collected {
                        deposits,
                        error: Some(error),
                    }
                }
            };
            if reply.kind != FrameType::ChallengeReply || reply.body.len() != 32 {
                break;
            }
            let mut challenge = [0u8; 32];
            challenge.copy_from_slice(&reply.body);

            let request = Retrieve {
                queue_id,
                challenge,
                retrieval_public: queue.retrieval_public(),
                proof: queue.prove_retrieval(&challenge),
            };
            let response = match self
                .transport
                .exchange(&Frame::new(FrameType::Retrieve, request.encode()))
            {
                Ok(response) => response,
                Err(error) => {
                    return Collected {
                        deposits,
                        error: Some(error),
                    }
                }
            };
            if response.kind != FrameType::Delivery {
                break;
            }
            let Ok(delivery) = Delivery::decode(&response.body) else {
                return Collected {
                    deposits,
                    error: Some(ClientError::Protocol),
                };
            };
            if delivery.sealed.is_empty() {
                break;
            }
            let remaining = delivery.remaining;
            deposits.push(Deposit {
                queue_id,
                sealed: delivery.sealed,
            });
            if remaining == 0 {
                break;
            }
        }
        Collected {
            deposits,
            error: None,
        }
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

        let message_id = new_message_id()?;
        let stored = self.store_outgoing_message(*fingerprint, text, now, message_id);
        self.enqueue(
            *fingerprint,
            &deposit_key,
            &payload,
            message_id,
            stored,
            false,
        )?;
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
        let message_id = new_message_id()?;
        self.enqueue(*fingerprint, &deposit_key, &payload, message_id, None, true)?;
        Ok(message_id)
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
        now: u64,
    ) -> ClientResult<ActiveCall> {
        // One call at a time, with anyone: there is one microphone, and the
        // other end of a second call would hear nothing.
        if !self.calls.is_empty() {
            return Err(ClientError::CallInProgress);
        }
        let offer = CallOffer::new(onion_address, port, now).map_err(|_| ClientError::Protocol)?;
        let active = ActiveCall {
            call_id: offer.call_id,
            media_secret: offer.media_secret,
            role: Role::Caller,
            peer: *fingerprint,
            onion_address: String::from(onion_address),
            port,
            answered: false,
            started_at: now,
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

    /// The platform layer's report that media for this contact's call has
    /// authenticated: the first frame sealed with the call's media secret
    /// arrived. For the caller that is the answer — only the callee can produce
    /// it — so the ring stops here instead of waiting a mailbox delay for the
    /// relayed `Answer`. Returns whether a call was waiting on it.
    pub fn mark_call_connected(&mut self, fingerprint: &[u8; 32]) -> bool {
        match self.calls.get_mut(fingerprint) {
            Some(call) => {
                call.answered = true;
                true
            }
            None => false,
        }
    }

    /// Give up on calls nobody answered: after [`RING_TIMEOUT_SECONDS`] of
    /// ringing for the callee, after [`CALLER_TIMEOUT_SECONDS`] of waiting for
    /// the caller.
    ///
    /// Both ends time out on their own, so a caller whose phone died mid-ring
    /// never leaves the other one ringing for good. Whichever end gives up also
    /// tells the other. Usually that is the callee, whose ring is shorter, and
    /// telling the caller spares them up to another two minutes of ringing into
    /// nothing.
    fn expire_calls(&mut self, now: u64) {
        let unanswered: Vec<([u8; 32], [u8; 16])> = self
            .calls
            .values()
            .filter(|c| {
                let limit = match c.role {
                    Role::Caller => CALLER_TIMEOUT_SECONDS,
                    Role::Callee => RING_TIMEOUT_SECONDS,
                };
                !c.answered && now.saturating_sub(c.started_at) > limit
            })
            .map(|c| (c.peer, c.call_id))
            .collect();
        for (peer, call_id) in unanswered {
            self.calls.remove(&peer);
            let _ = self.send_signal(
                &peer,
                CallSignal::End(CallEnd {
                    call_id,
                    reason: EndReason::Missed,
                }),
            );
            self.call_events.push(CallEvent::Ended {
                contact_fingerprint: peer,
                call_id,
                reason: EndReason::Missed,
            });
        }
    }

    /// Fragment a payload, seal each fragment to `deposit_key`, and queue them.
    ///
    /// Sealing happens here rather than at transmission time so that the
    /// scheduler's tick does no cryptography — a tick must take the same
    /// observable time whether it carries a message or a dummy record, and
    /// encrypting inside the tick would break that.
    #[allow(clippy::too_many_arguments)]
    fn enqueue(
        &mut self,
        fingerprint: [u8; 32],
        deposit_key: &DepositKey,
        payload: &[u8],
        message_id: u64,
        stored_message_id: Option<u64>,
        signal: bool,
    ) -> ClientResult<()> {
        let records = record::fragment(message_id, payload).map_err(|_| ClientError::Protocol)?;
        // A call signal goes ahead of every queued message fragment, behind any
        // signal already waiting. Still one record per slot — this changes
        // which record fills the next slot, never when a slot happens — but a
        // ring no longer waits behind a long message or a parked invitation.
        let start = if signal {
            self.outbox
                .iter()
                .position(|i| !i.signal)
                .unwrap_or(self.outbox.len())
        } else {
            self.outbox.len()
        };
        for (position, rec) in (start..).zip(&records) {
            let deposit = envelope::seal(deposit_key, rec).map_err(|_| ClientError::Protocol)?;
            let mut item = OutboxItem {
                contact_fingerprint: fingerprint,
                deposit,
                message_id,
                attempts: 0,
                persisted_id: None,
                stored_message_id,
                signal,
            };
            if !signal {
                if let Some(persisted) = &mut self.persisted {
                    let payload = encode_outbox_item(&item);
                    if let Ok(id) = persisted.store.insert(Kind::Outbox, 0, &payload) {
                        item.persisted_id = Some(id);
                    }
                }
            }
            self.outbox.insert(position, item);
        }
        if let Some(persisted) = &mut self.persisted {
            let _ = persisted.store.flush();
        }
        Ok(())
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
    ) -> Option<u64> {
        self.persisted.as_ref()?;
        let expiry = self.message_expiry(&fingerprint, now);
        let msg = self.stored_message(fingerprint, text, Direction::Outgoing, now);
        let payload = msg.encode();
        let persisted = self.persisted.as_mut()?;
        let id = persisted
            .store
            .insert(Kind::Message, expiry, &payload)
            .ok()?;
        persisted.outgoing_messages.insert(message_id, id);
        let _ = persisted.store.flush();
        Some(id)
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
        let now = now_ms / 1000;
        self.expire_invites(now);
        self.expire_fetches(now);
        self.expire_calls(now);

        let connected = self.transport.is_connected();
        self.scheduler.set_connected(connected, now_ms);
        if !connected {
            // Nothing is emitted while disconnected, and the caller is told so
            // plainly rather than handed a `Waiting` indistinguishable from an
            // idle connection. The platform layer shows the offline state from
            // this, and decides from it when to re-attach Tor.
            return Ok(TickOutcome::Offline);
        }
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
                        // Refused. The relay says no more than that — a reason
                        // would be an oracle — and its reasons, one queue's
                        // deposit rate or capacity, pass. So keep it, and retry
                        // it, but behind everything else waiting: retried at
                        // the head, one queue's refusals held up every other
                        // contact's messages, one wasted slot at a time.
                        // Retrying costs nothing observable; the slot carries a
                        // frame either way.
                        let mut refused = self.outbox.remove(0);
                        refused.attempts += 1;
                        let back = if refused.signal {
                            self.outbox
                                .iter()
                                .position(|i| !i.signal)
                                .unwrap_or(self.outbox.len())
                        } else {
                            self.outbox.len()
                        };
                        self.outbox.insert(back, refused);
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
                let (received, mut error) = self.collect_all(now_ms);
                if error.is_none() {
                    error = self.collect_invites(now);
                }
                if error.is_none() {
                    error = self.collect_fetches(now);
                }
                self.flush_inbox();
                // Piggybacks on the retrieval cadence rather than running
                // every tick: retrieval is already jittered to roughly
                // RETRIEVAL_JITTER_MS, so the sweep runs "periodically"
                // (FR-STOR-04) without adding a second timer to reason about.
                let _ = self.run_retention_sweep(now);
                // Messages collected before the transport failed are still
                // delivered: the relay has already deleted them. Only a
                // retrieval that got nothing at all reports being offline.
                if received.is_empty() && error == Some(ClientError::TorUnavailable) {
                    return Ok(TickOutcome::Offline);
                }
                Ok(TickOutcome::Retrieved(received))
            }
        }
    }

    /// Poll every session's receive queue once.
    ///
    /// Returns what arrived and, if the transport failed partway, that error
    /// too — alongside the messages, never instead of them. The relay deleted
    /// those records as it handed them over and the ratchet has stepped past
    /// them, so a collection that dropped them on a later error lost them for
    /// good.
    fn collect_all(&mut self, now_ms: u64) -> (Vec<ReceivedMessage>, Option<ClientError>) {
        let fingerprints: Vec<[u8; 32]> = self.sessions.keys().copied().collect();
        let mut out = Vec::new();
        for fp in fingerprints {
            let (mut messages, error) = self.collect_one(&fp, now_ms);
            out.append(&mut messages);
            // A single queue failing must not stop the others — unless what
            // failed is the transport, which every other queue shares.
            if error == Some(ClientError::TorUnavailable) {
                return (out, error);
            }
        }
        (out, None)
    }

    fn collect_one(
        &mut self,
        fingerprint: &[u8; 32],
        now_ms: u64,
    ) -> (Vec<ReceivedMessage>, Option<ClientError>) {
        let Some(queue) = self
            .sessions
            .get(fingerprint)
            .map(|s| s.established.recv_queue.clone())
        else {
            return (Vec::new(), Some(ClientError::NoSuchContact));
        };
        let collected = self.retrieve_queue(&queue);
        let mut messages = Vec::new();
        let mut error = collected.error;
        for deposit in &collected.deposits {
            match self.receive_session_deposit(fingerprint, deposit, now_ms) {
                Ok(Some(message)) => messages.push(message),
                Ok(None) => {}
                // Keep going: the rest of this batch is already off the relay.
                // A failed write leaves the ratchet ahead of the disk, and the
                // next successful write catches the disk up.
                Err(e) => error = error.or(Some(e)),
            }
        }
        (messages, error)
    }

    /// Open, reassemble, and decrypt one deposit from a session's queue.
    ///
    /// Returns the text if this completed a text message. A call signal is
    /// folded into call state here and never returned: a ringing phone is not
    /// something the contact said. Anything that does not open, reassemble,
    /// or decrypt is discarded without a distinguishable response — it is
    /// corruption or an attacker probing, and neither deserves one.
    fn receive_session_deposit(
        &mut self,
        fingerprint: &[u8; 32],
        deposit: &Deposit,
        now_ms: u64,
    ) -> ClientResult<Option<ReceivedMessage>> {
        let Some(session) = self.sessions.get_mut(fingerprint) else {
            return Ok(None);
        };
        let Ok(record) = envelope::open(&session.established.recv_queue.deposit_key(), deposit)
        else {
            return Ok(None);
        };
        // A record that will not reassemble is discarded, not fatal. A relay
        // redelivering one fragment of an old message must not be able to end
        // the collection, or it ends the conversation (D-022).
        match session.reassembler.push(&record) {
            Ok(Some(payload)) => {
                let result = self.process_session_payload(fingerprint, &payload, now_ms);
                self.drop_fragments(FragmentSource::Session(*fingerprint), record.message_id);
                result
            }
            Ok(None) if record.kind == RecordKind::Payload => {
                self.stash_fragment(
                    FragmentSource::Session(*fingerprint),
                    &record,
                    now_ms / 1000,
                );
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Decrypt and act on one complete payload from a session's queue.
    fn process_session_payload(
        &mut self,
        fingerprint: &[u8; 32],
        payload: &[u8],
        now_ms: u64,
    ) -> ClientResult<Option<ReceivedMessage>> {
        let decrypted = {
            let Some(session) = self.sessions.get_mut(fingerprint) else {
                return Ok(None);
            };
            let Ok(ratchet_message) = RatchetMessage::decode(payload) else {
                return Ok(None);
            };
            let Ok(plaintext) = session.established.ratchet.decrypt(&ratchet_message) else {
                return Ok(None);
            };
            Content::decode(&plaintext).ok()
        };
        // The ratchet mutated its state (and, for a new chain, its skipped-key
        // map) at the moment this authenticated, and only then — persist it,
        // whether or not the plaintext turns out to parse.
        self.persist_session(*fingerprint)?;
        match decrypted {
            Some(Content::Text(text)) => {
                self.store_incoming_message(*fingerprint, &text, now_ms / 1000);
                Ok(Some(ReceivedMessage {
                    contact_fingerprint: *fingerprint,
                    text,
                }))
            }
            Some(Content::Call(signal)) => {
                // Signalling is never stored as a message and never shown in a
                // conversation. It changes call state and nothing else.
                if let Some(event) = self.apply_call_signal(*fingerprint, signal, now_ms / 1000) {
                    self.call_events.push(event);
                }
                Ok(None)
            }
            None => Ok(None),
        }
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
        now: u64,
    ) -> Option<CallEvent> {
        match signal {
            CallSignal::Offer(offer) => {
                // Waited in the mailbox until its caller had long given up.
                // Report it; do not ring for nobody.
                if now.saturating_sub(offer.sent_at) > OFFER_MAX_AGE_SECONDS {
                    return Some(CallEvent::Missed {
                        contact_fingerprint: fingerprint,
                        call_id: offer.call_id,
                    });
                }
                if !self.calls.is_empty() {
                    // Already on a call, with them or anyone else. Tell the
                    // caller, rather than letting a second offer silently
                    // replace the first or leaving them ringing into nothing,
                    // and tell the user they missed it.
                    let _ = self.send_signal(
                        &fingerprint,
                        CallSignal::End(CallEnd {
                            call_id: offer.call_id,
                            reason: EndReason::Busy,
                        }),
                    );
                    return Some(CallEvent::Missed {
                        contact_fingerprint: fingerprint,
                        call_id: offer.call_id,
                    });
                }
                let call = ActiveCall {
                    call_id: offer.call_id,
                    media_secret: offer.media_secret,
                    role: Role::Callee,
                    peer: fingerprint,
                    onion_address: offer.onion_address.clone(),
                    port: offer.port,
                    answered: false,
                    // Rung from when it arrived here, not when it was sent: the
                    // callee gets the full ring whatever the mailbox delay was.
                    started_at: now,
                };
                self.calls.insert(fingerprint, call.clone());
                Some(CallEvent::Incoming(call))
            }
            CallSignal::Answer(answer) => {
                let call = self.calls.get_mut(&fingerprint)?;
                if call.call_id != answer.call_id || call.role != Role::Caller {
                    return None;
                }
                // Usually the callee's media got here first and the call is
                // already connected (`mark_call_connected`); then the relayed
                // answer is just confirmation, with nothing left to announce.
                if call.answered {
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

    /// Change the name this device shows for a contact. Never transmitted.
    pub fn rename_contact(&mut self, fingerprint: &[u8; 32], name: &str) -> ClientResult<()> {
        self.sessions
            .get_mut(fingerprint)
            .ok_or(ClientError::NoSuchContact)?
            .contact
            .local_name = String::from(truncate_utf8(name.trim(), MAX_CONTACT_NAME_LEN));
        self.persist_session(*fingerprint)
    }

    /// Set the name this user puts on invitations they make.
    pub fn set_invite_name(&mut self, name: &str) {
        let mut settings = self.settings.clone();
        settings.invite_name = String::from(invite::truncate_label(name.trim()));
        self.set_settings(settings);
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
        self.drop_all_fragments(FragmentSource::Session(*fingerprint));
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

    /// The stored history with one contact, oldest first (NFR-REL-04).
    ///
    /// This is what a platform layer shows when it reopens a conversation after
    /// a restart. Empty when no store is attached. A record that fails to
    /// decode is skipped rather than failing the whole history: one damaged
    /// message must not hide every other one.
    pub fn messages(&self, fingerprint: &[u8; 32]) -> ClientResult<Vec<StoredMessage>> {
        let Some(persisted) = &self.persisted else {
            return Ok(Vec::new());
        };
        let records = persisted
            .store
            .list(Kind::Message)
            .map_err(|_| ClientError::Storage)?;
        Ok(records
            .iter()
            .filter_map(|r| StoredMessage::decode(&r.payload).ok())
            .filter(|m| &m.contact_fingerprint == fingerprint)
            .collect())
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
    /// Whether the call has been answered: for the callee, once they answer;
    /// for the caller, once the callee's media authenticates or their relayed
    /// answer arrives, whichever is first.
    pub answered: bool,
    /// Unix seconds when this end started ringing, for
    /// [`RING_TIMEOUT_SECONDS`] and [`CALLER_TIMEOUT_SECONDS`].
    pub started_at: u64,
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
    /// A contact called and it did not ring: the offer arrived too late to be
    /// live, or this device was already on a call. Show it as a missed call.
    Missed {
        /// Who called.
        contact_fingerprint: [u8; 32],
        /// Which call.
        call_id: [u8; 16],
    },
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
