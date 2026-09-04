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

use void_client::engine::{Engine, SecurityMode, TickOutcome};
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
