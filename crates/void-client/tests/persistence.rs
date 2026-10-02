//! Restart-survival integration tests (FR-STOR-01).
//!
//! `void-store` was complete and tested for a long time before anything
//! called it from the engine — these tests are the proof that the wiring in
//! `Engine::new_persisted` / `Engine::restore` actually closes that gap: a
//! conversation must survive the process ending, not just a struct method
//! returning the right bytes in isolation.
//!
//! A real `FileBackend` is used rather than the in-memory one, so "the
//! process ends and a new one starts" is not a metaphor: the first `Engine`
//! and its `Database` are fully dropped, and the second is built from nothing
//! but the path on disk.

use std::sync::{Arc, Mutex};

use void_client::engine::{ContactEvent, Engine, SecurityMode, TickOutcome};
use void_client::transport::MemoryTransport;
use void_crypto::argon2;
use void_proto::identity::Identity;
use void_proto::record::PAD_INTERVAL_MS;
use void_relay::server::{NoPush, Relay};
use void_relay::store::Config;
use void_store::db::{Database, FileBackend};
use void_store::model::{DeliveryState, Settings, TrustState};
use void_store::vault::SoftwareVault;

fn relay() -> Arc<Relay> {
    Arc::new(Relay::new(Config::default(), Box::new(NoPush)))
}

fn bob(relay: Arc<Relay>, clock: Arc<Mutex<u64>>) -> Engine {
    let identity = Identity::from_seeds(&[2u8; 32], &[13u8; 32], &[17u8; 32]);
    Engine::new(
        identity,
        Settings::default(),
        Box::new(MemoryTransport::new(relay, clock)),
        SecurityMode::InsecureForTesting,
        0,
    )
    .unwrap()
}

/// A fresh path in the system temp directory, unique to this test process and
/// this call, so parallel test runs never collide.
fn temp_db_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "void-persistence-test-{}-{label}.voiddb",
        std::process::id()
    ))
}

fn drain(engine: &mut Engine, start_ms: u64, slots: u64) -> u64 {
    let mut t = start_ms;
    for _ in 0..slots {
        let _ = engine.tick(t);
        t += PAD_INTERVAL_MS;
        if engine.outbox_len() == 0 {
            break;
        }
    }
    t
}

fn pump(engine: &mut Engine, start_ms: u64, slots: u64) -> (u64, Vec<String>) {
    let mut t = start_ms;
    let mut received = Vec::new();
    for _ in 0..slots {
        if let Ok(TickOutcome::Retrieved(msgs)) = engine.tick(t) {
            received.extend(msgs.into_iter().map(|m| m.text));
        }
        t += PAD_INTERVAL_MS;
    }
    (t, received)
}

fn collect_raw(relay: &Arc<Relay>, queue: &void_proto::queue::QueueSecret) -> Option<Vec<u8>> {
    use void_relay::protocol::{Delivery, Frame, FrameType, Retrieve};
    let deposit_key = queue.deposit_key();
    let queue_id = queue.queue_id();
    let mut reassembler = void_proto::record::Reassembler::new(16);
    for _ in 0..64 {
        let ch = relay
            .handle(&Frame::new(FrameType::Challenge, queue_id.to_vec()), 0)
            .ok()?;
        if ch.kind != FrameType::ChallengeReply {
            return None;
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&ch.body);
        let resp = relay
            .handle(
                &Frame::new(
                    FrameType::Retrieve,
                    Retrieve {
                        queue_id,
                        challenge,
                        retrieval_public: queue.retrieval_public(),
                        proof: queue.prove_retrieval(&challenge),
                    }
                    .encode(),
                ),
                0,
            )
            .ok()?;
        if resp.kind != FrameType::Delivery {
            return None;
        }
        let d = Delivery::decode(&resp.body).ok()?;
        if d.sealed.is_empty() {
            return None;
        }
        let record = void_proto::envelope::open(
            &deposit_key,
            &void_proto::envelope::Deposit {
                queue_id,
                sealed: d.sealed,
            },
        )
        .ok()?;
        if let Ok(Some(payload)) = reassembler.push(&record) {
            return Some(payload);
        }
    }
    None
}

#[test]
fn a_restarted_engine_recovers_its_conversation_and_keeps_talking() {
    let path = temp_db_path("recovers-and-keeps-talking");
    let vault = SoftwareVault::from_raw([9u8; 32]);
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));

    let db = Database::create(
        FileBackend::new(&path),
        &vault,
        argon2::Params::TEST_ONLY_WEAK,
    )
    .unwrap();
    let (identity, seeds) = Identity::generate_with_seeds().unwrap();
    let mut alice = Engine::new_persisted(
        identity,
        &seeds,
        Settings::default(),
        Box::new(MemoryTransport::new(Arc::clone(&relay), Arc::clone(&clock))),
        SecurityMode::InsecureForTesting,
        0,
        Box::new(db),
    )
    .unwrap();
    let mut bob_engine = bob(Arc::clone(&relay), Arc::clone(&clock));

    let (bundle, bob_queue) = bob_engine.create_bundle(b"relay.onion").unwrap();
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "hello from before the restart", 1_000_000)
        .unwrap();
    let t = drain(&mut alice, 0, 40);
    assert_eq!(
        alice.outbox_len(),
        0,
        "the handshake must have been deposited"
    );

    let initial = collect_raw(&relay, &bob_queue).expect("bob should find the handshake");
    let (alice_fp, first) = bob_engine
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000_000)
        .unwrap();
    assert_eq!(first, "hello from before the restart");

    // One full round trip before the restart, crossing a ratchet step in
    // each direction.
    bob_engine
        .send(&alice_fp, "reply before restart", 1_000_100)
        .unwrap();
    let t2 = drain(&mut bob_engine, t, 40);
    let (t3, got) = pump(&mut alice, t2, 40);
    assert!(got.contains(&"reply before restart".to_string()));

    let alice_public = alice.identity_public().clone();
    let alice_fingerprint = alice.fingerprint();

    // The process ends. Everything `alice`'s `Engine` held in RAM — the
    // ratchet, the contact, the queues, the identity — is gone.
    drop(alice);

    // A new process starts, pointed at nothing but the same file.
    let db2 = Database::open(FileBackend::new(&path), &vault).unwrap();
    let mut alice2 = Engine::restore(
        Box::new(db2),
        Box::new(MemoryTransport::new(Arc::clone(&relay), Arc::clone(&clock))),
        SecurityMode::InsecureForTesting,
        t3,
    )
    .unwrap();

    // Same identity: the peer must not see this as a key change.
    assert_eq!(alice2.identity_public(), &alice_public);
    assert_eq!(alice2.fingerprint(), alice_fingerprint);

    // The contact and its trust state survived.
    let contact = alice2
        .contact(&bob_fp)
        .expect("bob's contact must survive a restart");
    assert_eq!(contact.local_name, "Bob");
    assert_eq!(contact.trust, TrustState::Unverified);

    // The conversation continues with no renegotiation: Bob sends, the
    // restored engine receives, and the restored engine can reply.
    bob_engine
        .send(&alice_fp, "does alice still hear me", 1_000_200)
        .unwrap();
    let t4 = drain(&mut bob_engine, t3, 40);
    let (t5, got2) = pump(&mut alice2, t4, 40);
    assert!(
        got2.contains(&"does alice still hear me".to_string()),
        "the restored engine must still be able to receive: got {got2:?}"
    );

    alice2
        .send(&bob_fp, "yes, still here after the restart", 1_000_300)
        .unwrap();
    let t6 = drain(&mut alice2, t5, 40);
    let (_, got3) = pump(&mut bob_engine, t6, 40);
    assert!(
        got3.contains(&"yes, still here after the restart".to_string()),
        "the restored engine must still be able to send: got {got3:?}"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn message_history_and_delivery_state_survive_a_restart() {
    let path = temp_db_path("history-survives");
    let vault = SoftwareVault::from_raw([11u8; 32]);
    let relay = relay();
    let clock = Arc::new(Mutex::new(2_000_000u64));

    let db = Database::create(
        FileBackend::new(&path),
        &vault,
        argon2::Params::TEST_ONLY_WEAK,
    )
    .unwrap();
    let (identity, seeds) = Identity::generate_with_seeds().unwrap();
    let mut alice = Engine::new_persisted(
        identity,
        &seeds,
        Settings::default(),
        Box::new(MemoryTransport::new(Arc::clone(&relay), Arc::clone(&clock))),
        SecurityMode::InsecureForTesting,
        0,
        Box::new(db),
    )
    .unwrap();
    let mut bob_engine = bob(Arc::clone(&relay), Arc::clone(&clock));

    let (bundle, bob_queue) = bob_engine.create_bundle(b"relay.onion").unwrap();
    alice
        .start_conversation(&bundle, "Bob", "message one", 2_000_000)
        .unwrap();
    let t = drain(&mut alice, 0, 40);
    // The handshake's own fragment is gone from the outbox and its message
    // record's delivery state moved to `Deposited` — proving the deposit
    // bookkeeping (`on_outbox_item_deposited`) reached the store, not just
    // the in-memory outbox.
    assert_eq!(alice.outbox_len(), 0);

    let initial = collect_raw(&relay, &bob_queue).expect("bob should find the handshake");
    bob_engine
        .accept_conversation(bundle.queue.queue_id, &initial, 2_000_000)
        .unwrap();

    drop(alice);

    let db2 = Database::open(FileBackend::new(&path), &vault).unwrap();
    let engine2 = Engine::restore(
        Box::new(db2),
        Box::new(MemoryTransport::new(Arc::clone(&relay), Arc::clone(&clock))),
        SecurityMode::InsecureForTesting,
        t,
    )
    .unwrap();

    // Re-open the raw store directly to inspect what actually persisted,
    // independent of whatever in-memory view the engine exposes.
    drop(engine2);
    let db3 = Database::open(FileBackend::new(&path), &vault).unwrap();
    let messages = db3.list(void_store::db::Kind::Message).unwrap();
    assert_eq!(
        messages.len(),
        1,
        "the first message must be stored exactly once"
    );
    let stored = void_store::model::StoredMessage::decode(&messages[0].payload).unwrap();
    assert_eq!(stored.body, "message one");
    assert_eq!(
        stored.delivery,
        DeliveryState::Deposited,
        "delivery state must have advanced past Queued once the handshake left the outbox"
    );

    let _ = std::fs::remove_file(&path);
}

/// A persisted engine for Bob, created fresh at `path`.
fn persisted_bob(
    path: &std::path::Path,
    vault: &SoftwareVault,
    relay: &Arc<Relay>,
    clock: &Arc<Mutex<u64>>,
) -> Engine {
    let db = Database::create(
        FileBackend::new(path),
        vault,
        argon2::Params::TEST_ONLY_WEAK,
    )
    .unwrap();
    let (identity, seeds) = Identity::generate_with_seeds().unwrap();
    Engine::new_persisted(
        identity,
        &seeds,
        Settings::default(),
        Box::new(MemoryTransport::new(Arc::clone(relay), Arc::clone(clock))),
        SecurityMode::InsecureForTesting,
        0,
        Box::new(db),
    )
    .unwrap()
}

/// Bob's engine again, rebuilt from nothing but the file.
fn restored(
    path: &std::path::Path,
    vault: &SoftwareVault,
    relay: &Arc<Relay>,
    clock: &Arc<Mutex<u64>>,
    now_ms: u64,
) -> Engine {
    let db = Database::open(FileBackend::new(path), vault).unwrap();
    Engine::restore(
        Box::new(db),
        Box::new(MemoryTransport::new(Arc::clone(relay), Arc::clone(clock))),
        SecurityMode::InsecureForTesting,
        now_ms,
    )
    .unwrap()
}

/// Tick `inviter` and `invitee` in turn until the inviter reports a contact.
fn until_added(inviter: &mut Engine, invitee: &mut Engine, start_ms: u64) -> Option<[u8; 32]> {
    let mut t = start_ms;
    for _ in 0..400 {
        let _ = invitee.tick(t);
        let _ = inviter.tick(t);
        for event in inviter.take_contact_events() {
            if let ContactEvent::Added {
                contact_fingerprint,
                ..
            } = event
            {
                return Some(contact_fingerprint);
            }
        }
        t += PAD_INTERVAL_MS;
    }
    None
}

#[test]
fn a_pending_invite_survives_a_restart() {
    // The person an invitation was sent to may accept it hours later, long
    // after the app that made it was killed. The prekey secrets have to be on
    // disk, or the handshake arrives to an inviter who can no longer answer.
    let path = temp_db_path("invite-survives");
    let vault = SoftwareVault::from_raw([21u8; 32]);
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));

    let mut bob_engine = persisted_bob(&path, &vault, &relay, &clock);
    let invite = bob_engine
        .create_invite(b"relay.onion", "Bob", "Alice", 1_000, 86_400)
        .unwrap();
    // Killed before it had parked a single record of the invitation.
    drop(bob_engine);

    let mut bob_engine = restored(&path, &vault, &relay, &clock, 0);
    assert!(bob_engine.has_pending_invite(&invite.id));
    assert_eq!(
        bob_engine.invite_link(&invite.id),
        Some(invite.link.as_str())
    );
    assert!(
        bob_engine.invite_upload_remaining(&invite.id).unwrap() > 0,
        "the unfinished upload survives with the invitation"
    );

    let mut alice = bob_like_alice(&relay, &clock);
    let fetch = alice.open_invite(&invite.link, 0).unwrap();
    let mut t = 0u64;
    let mut confirmed = false;
    for _ in 0..200 {
        let _ = bob_engine.tick(t);
        let _ = alice.tick(t);
        if alice
            .take_contact_events()
            .iter()
            .any(|e| matches!(e, ContactEvent::InviteReady { .. }))
        {
            alice
                .confirm_invite(&fetch, "", "sent after bob restarted", t / 1000)
                .unwrap();
            confirmed = true;
            break;
        }
        t += PAD_INTERVAL_MS;
    }
    assert!(
        confirmed,
        "the restored engine must finish parking the invitation"
    );
    let added = until_added(&mut bob_engine, &mut alice, t);
    assert_eq!(added, Some(alice.fingerprint()));
    assert_eq!(
        bob_engine.contact(&alice.fingerprint()).unwrap().local_name,
        "Alice",
        "the invitation's contact label survives the restart too"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_handshake_half_received_before_a_restart_still_completes() {
    // The relay deletes each record as it hands it over. A handshake spans
    // about thirteen records uploaded one per slot, so an inviter that
    // collects mid-upload and is then killed held the only copy of what it
    // had collected — in RAM. It has to be on disk.
    let path = temp_db_path("half-handshake");
    let vault = SoftwareVault::from_raw([22u8; 32]);
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));

    let mut bob_engine = persisted_bob(&path, &vault, &relay, &clock);
    let (bundle, _) = bob_engine.create_bundle(b"relay.onion").unwrap();
    let mut alice = bob_like_alice(&relay, &clock);
    alice
        .start_conversation(&bundle, "Bob", "split across a restart", 1_000)
        .unwrap();
    let total = alice.outbox_len();
    assert!(total > 4);

    // Alice uploads about half of the handshake.
    let mut t = 0u64;
    while alice.outbox_len() > total / 2 {
        alice.tick(t).unwrap();
        t += PAD_INTERVAL_MS;
    }
    assert!(relay.metrics().unwrap().records > 0);

    // Bob collects what is there — and so empties the relay of it.
    let mut collected = false;
    for _ in 0..20 {
        if let TickOutcome::Retrieved(_) = bob_engine.tick(t).unwrap() {
            collected = true;
            break;
        }
        t += PAD_INTERVAL_MS;
    }
    assert!(collected);
    assert_eq!(
        relay.metrics().unwrap().records,
        0,
        "the relay no longer holds the half bob collected"
    );
    assert!(bob_engine.take_contact_events().is_empty());

    // Bob's process dies with half a handshake. A new one starts from disk.
    drop(bob_engine);
    let mut bob_engine = restored(&path, &vault, &relay, &clock, t);

    // Alice uploads the rest; the restored Bob must finish the handshake.
    let added = until_added(&mut bob_engine, &mut alice, t);
    assert_eq!(
        added,
        Some(alice.fingerprint()),
        "the restored engine must complete the handshake from the fragments it kept"
    );
    let history = bob_engine.messages(&alice.fingerprint()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, "split across a restart");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_message_queued_before_a_restart_is_marked_sent_after_it() {
    // The outbox survives a restart; so must the link from each queued
    // fragment back to the stored message it carries, or the history shows
    // "Waiting to send" forever for a message that went out.
    let path = temp_db_path("queued-then-sent");
    let vault = SoftwareVault::from_raw([23u8; 32]);
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));

    let mut alice = persisted_bob(&path, &vault, &relay, &clock);
    let mut bob_engine = bob(Arc::clone(&relay), Arc::clone(&clock));
    let (bundle, bob_queue) = bob_engine.create_bundle(b"relay.onion").unwrap();
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "hello", 1_000)
        .unwrap();
    let t = drain(&mut alice, 0, 40);
    let initial = collect_raw(&relay, &bob_queue).unwrap();
    bob_engine
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000)
        .unwrap();

    // Offline: the message queues, and is stored as waiting to send.
    alice
        .set_transport(Box::new(void_client::transport::NullTransport::new()))
        .unwrap();
    alice.send(&bob_fp, "sent while offline", 1_100).unwrap();
    assert!(alice.outbox_len() > 0);
    drop(alice);

    let mut alice = restored(&path, &vault, &relay, &clock, t);
    let queued = alice.messages(&bob_fp).unwrap();
    assert_eq!(queued.last().unwrap().body, "sent while offline");
    assert_eq!(queued.last().unwrap().delivery, DeliveryState::Queued);

    drain(&mut alice, t, 60);
    assert_eq!(alice.outbox_len(), 0);
    let history = alice.messages(&bob_fp).unwrap();
    assert_eq!(
        history.last().unwrap().delivery,
        DeliveryState::Deposited,
        "a message that left the outbox after a restart must read as sent"
    );
    let _ = std::fs::remove_file(&path);
}

/// An unpersisted engine standing in for the other person.
fn bob_like_alice(relay: &Arc<Relay>, clock: &Arc<Mutex<u64>>) -> Engine {
    let identity = Identity::from_seeds(&[31u8; 32], &[32u8; 32], &[33u8; 32]);
    Engine::new(
        identity,
        Settings::default(),
        Box::new(MemoryTransport::new(Arc::clone(relay), Arc::clone(clock))),
        SecurityMode::InsecureForTesting,
        0,
    )
    .unwrap()
}

#[test]
fn a_renamed_contact_keeps_its_name_after_a_restart() {
    let path = temp_db_path("rename-persists");
    let vault = SoftwareVault::from_raw([24u8; 32]);
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));

    let mut alice = persisted_bob(&path, &vault, &relay, &clock);
    let mut bob_engine = bob(Arc::clone(&relay), Arc::clone(&clock));
    let (bundle, _) = bob_engine.create_bundle(b"relay.onion").unwrap();
    let bob_fp = alice.start_conversation(&bundle, "", "", 1_000).unwrap();
    alice
        .rename_contact(&bob_fp, "  Bob from the café  ")
        .unwrap();
    alice.set_invite_name("Alice");
    drop(alice);

    let alice = restored(&path, &vault, &relay, &clock, 0);
    assert_eq!(
        alice.contact(&bob_fp).unwrap().local_name,
        "Bob from the café",
        "a rename is stored, trimmed, and survives a restart"
    );
    assert_eq!(alice.settings().invite_name, "Alice");
    assert!(
        alice.messages(&bob_fp).unwrap().is_empty(),
        "connecting without a first message stores nothing to show"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_file_survives_a_restart_mid_upload_and_its_bytes_come_back() {
    // A photo is hundreds of records, so a restart while it is leaving is the
    // ordinary case, not an edge. The rest of it must go out after the
    // restart, behind nothing it was not already behind, the history must
    // say how much is left, and the bytes must still be there to show.
    let path = temp_db_path("file-mid-upload");
    let vault = SoftwareVault::from_raw([29u8; 32]);
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));

    let mut alice = persisted_bob(&path, &vault, &relay, &clock);
    let mut bob_engine = bob(Arc::clone(&relay), Arc::clone(&clock));
    let (bundle, bob_queue) = bob_engine.create_bundle(b"relay.onion").unwrap();
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "hello", 1_000)
        .unwrap();
    let t = drain(&mut alice, 0, 40);
    let initial = collect_raw(&relay, &bob_queue).unwrap();
    let (alice_fp, _) = bob_engine
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000)
        .unwrap();

    let photo: Vec<u8> = (0..30_000u32).map(|i| (i % 241) as u8).collect();
    alice
        .send_file(&bob_fp, "photo.jpg", "image/jpeg", photo.clone(), t / 1000)
        .unwrap();
    let queued = alice.outbox_len();
    assert!(queued >= 30);

    // A few records leave, then a reply is typed, then the app is killed.
    let mut now = t;
    let mut out = 0;
    while out < 3 {
        if let TickOutcome::Deposited(_) = alice.tick(now).unwrap() {
            out += 1;
        }
        now += PAD_INTERVAL_MS;
    }
    let before_reply = alice.outbox_len();
    alice
        .send(&bob_fp, "sent while the photo was leaving", now / 1000)
        .unwrap();
    // A reply early in a chain carries the ML-KEM step in its header (D-005),
    // so it can be several records; count rather than assume.
    let reply_records = alice.outbox_len() - before_reply;
    let history = alice.history(&bob_fp).unwrap();
    let file_entry = history
        .iter()
        .find(|e| e.message.attachment.is_some())
        .expect("the file is in the history");
    assert_eq!(file_entry.fragments_remaining as usize, queued - 3);
    assert!(
        file_entry
            .message
            .attachment
            .as_ref()
            .unwrap()
            .data
            .is_empty(),
        "listed without its bytes"
    );
    assert_eq!(
        file_entry.message.attachment.as_ref().unwrap().len as usize,
        photo.len()
    );
    assert_eq!(file_entry.message.delivery, DeliveryState::Queued);
    drop(alice);

    let mut alice = restored(&path, &vault, &relay, &clock, now);
    assert_eq!(alice.outbox_len(), queued - 3 + reply_records);
    let history = alice.history(&bob_fp).unwrap();
    let file_entry = history
        .iter()
        .find(|e| e.message.attachment.is_some())
        .unwrap();
    assert_eq!(
        file_entry.fragments_remaining as usize,
        queued - 3,
        "progress survives the restart"
    );
    // The bytes are there, from the id the history gave.
    let stored = alice
        .attachment(file_entry.id)
        .unwrap()
        .expect("the file's bytes");
    assert_eq!(stored.data, photo);
    assert_eq!(stored.name, "photo.jpg");
    // And an id that is not a message yields nothing, not someone else's record.
    assert!(alice.attachment(u64::MAX).unwrap().is_none());

    // The reply still goes out first after the restart, then the photo.
    let reply_first = loop {
        if let TickOutcome::Deposited(id) = alice.tick(now).unwrap() {
            break id;
        }
        now += PAD_INTERVAL_MS;
    };
    let text_entry = history
        .iter()
        .find(|e| e.message.body.starts_with("sent while"))
        .unwrap();
    assert_eq!(text_entry.fragments_remaining as usize, reply_records);
    assert_ne!(reply_first, 0);

    let mut received = Vec::new();
    for _ in 0..400 {
        alice.tick(now).unwrap();
        if let TickOutcome::Retrieved(msgs) = bob_engine.tick(now).unwrap() {
            received.extend(msgs);
        }
        if received.len() >= 2 {
            break;
        }
        now += PAD_INTERVAL_MS;
    }
    assert_eq!(received.len(), 2, "both arrive after the restart");
    assert_eq!(received[0].text, "sent while the photo was leaving");
    assert_eq!(
        received[1].attachment.as_ref().unwrap().len as usize,
        photo.len()
    );
    assert_eq!(received[1].contact_fingerprint, alice_fp);

    let history = alice.history(&bob_fp).unwrap();
    for entry in &history {
        assert_eq!(entry.fragments_remaining, 0);
        if entry.message.direction == void_store::model::Direction::Outgoing {
            assert_eq!(
                entry.message.delivery,
                DeliveryState::Deposited,
                "{:?}",
                entry.message.body
            );
        }
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_received_file_is_stored_with_its_bytes_and_survives_a_restart() {
    let path = temp_db_path("file-received");
    let vault = SoftwareVault::from_raw([31u8; 32]);
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));

    let mut bob_persisted = persisted_bob(&path, &vault, &relay, &clock);
    let mut alice = bob_like_alice(&relay, &clock);
    let (bundle, bob_queue) = bob_persisted.create_bundle(b"relay.onion").unwrap();
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "hello", 1_000)
        .unwrap();
    let t = drain(&mut alice, 0, 40);
    let initial = collect_raw(&relay, &bob_queue).unwrap();
    let (alice_fp, _) = bob_persisted
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000)
        .unwrap();

    let doc = vec![42u8; 5_000];
    alice
        .send_file(&bob_fp, "notes.txt", "text/plain", doc.clone(), t / 1000)
        .unwrap();
    let mut now = t;
    let mut got = 0;
    for _ in 0..200 {
        alice.tick(now).unwrap();
        if let TickOutcome::Retrieved(msgs) = bob_persisted.tick(now).unwrap() {
            got += msgs.len();
        }
        if got > 0 {
            break;
        }
        now += PAD_INTERVAL_MS;
    }
    assert_eq!(got, 1);
    drop(bob_persisted);

    let bob_again = restored(&path, &vault, &relay, &clock, now);
    let history = bob_again.history(&alice_fp).unwrap();
    let entry = history
        .iter()
        .find(|e| e.message.attachment.is_some())
        .expect("the file came back");
    assert_eq!(entry.message.delivery, DeliveryState::Received);
    let file = bob_again.attachment(entry.id).unwrap().unwrap();
    assert_eq!(file.name, "notes.txt");
    assert_eq!(file.mime, "text/plain");
    assert_eq!(file.data, doc);
    let _ = std::fs::remove_file(&path);
}
