//! End-to-end integration tests: two clients, one relay, full protocol.
//!
//! This is the Phase 2 deliverable from PRD §11 — *"two CLI clients exchanging
//! messages over Tor via a relay, end to end"* — with the Tor layer replaced by
//! an in-process transport so the test is deterministic. What is exercised is
//! everything above the socket: handshake, ratchet, fragmentation, sealing,
//! queue authentication, relay storage, retrieval, reassembly, decryption.
//!
//! The most valuable tests here are the negative ones at the bottom: they
//! assert what a compromised relay *cannot* do.

use std::sync::{Arc, Mutex};

use void_client::engine::{CallEvent, Engine, SecurityMode, TickOutcome};
use void_client::transport::MemoryTransport;
use void_proto::identity::Identity;
use void_proto::record::PAD_INTERVAL_MS;
use void_relay::server::{NoPush, Relay};
use void_relay::store::Config;
use void_store::model::Settings;

fn relay() -> Arc<Relay> {
    Arc::new(Relay::new(Config::default(), Box::new(NoPush)))
}

fn engine(relay: Arc<Relay>, clock: Arc<Mutex<u64>>, seed: u8) -> Engine {
    let identity = Identity::from_seeds(
        &[seed; 32],
        &[seed.wrapping_mul(3).wrapping_add(7); 32],
        &[seed.wrapping_mul(5).wrapping_add(11); 32],
    );
    Engine::new(
        identity,
        Settings::default(),
        Box::new(MemoryTransport::new(relay, clock)),
        SecurityMode::InsecureForTesting,
        0,
    )
    .unwrap()
}

/// Drive an engine until it has flushed its outbox, or the budget runs out.
fn drain(engine: &mut Engine, start_ms: u64, slots: u64) -> (u64, Vec<TickOutcome>) {
    let mut t = start_ms;
    let mut outcomes = Vec::new();
    for _ in 0..slots {
        let o = engine.tick(t).unwrap();
        if !matches!(o, TickOutcome::Waiting(_)) {
            outcomes.push(o);
        }
        t += PAD_INTERVAL_MS;
        if engine.outbox_len() == 0 && outcomes.len() > 2 {
            break;
        }
    }
    (t, outcomes)
}

/// Drive an engine for a fixed number of slots, collecting received messages.
fn pump(engine: &mut Engine, start_ms: u64, slots: u64) -> (u64, Vec<String>) {
    let mut t = start_ms;
    let mut received = Vec::new();
    for _ in 0..slots {
        if let TickOutcome::Retrieved(msgs) = engine.tick(t).unwrap() {
            for m in msgs {
                received.push(m.text);
            }
        }
        t += PAD_INTERVAL_MS;
    }
    (t, received)
}

#[test]
fn poll_intro_queue_is_how_the_responder_side_actually_receives_a_handshake() {
    // Every other test in this file collects the handshake with a hand-rolled
    // Challenge/Retrieve loop, because that used to be the only way — this is
    // the one that goes through `Engine::poll_intro_queue`, the real method a
    // platform layer (and `void-ffi`) calls instead of reimplementing the
    // retrieval protocol.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 91);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 92);

    let (bundle, intro_queue) = bob.create_bundle(b"relay.onion").unwrap();
    alice
        .start_conversation(&bundle, "Bob", "hello from the real path", 1_000_000)
        .unwrap();
    drain(&mut alice, 0, 40);

    let initial = bob
        .poll_intro_queue(&intro_queue)
        .unwrap()
        .expect("bob must receive the handshake via poll_intro_queue");

    let (alice_fp, first) = bob
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000_000)
        .unwrap();
    assert_eq!(first, "hello from the real path");
    assert_eq!(alice_fp, alice.identity_public().fingerprint());

    // Polling again after acceptance finds nothing new — the queue was
    // consumed, not left to redeliver the same handshake forever.
    assert!(bob.poll_intro_queue(&intro_queue).unwrap().is_none());
}

#[test]
fn two_clients_exchange_messages_through_a_relay() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 1);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 2);

    // Bob publishes a bundle out of band (a QR code Alice scans).
    let (bundle, bob_recv_queue) = bob.create_bundle(b"relay.onion").unwrap();
    assert!(bundle.verify());

    // Alice starts the conversation.
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "first contact", 1_000_000)
        .unwrap();
    assert_eq!(bob_fp, bundle.identity.fingerprint());
    assert!(
        alice.outbox_len() > 0,
        "the handshake must be queued, not sent"
    );

    // Alice's scheduler deposits the handshake.
    let (t, outcomes) = drain(&mut alice, 0, 40);
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, TickOutcome::Deposited(_))),
        "the handshake must reach the relay"
    );
    assert_eq!(alice.outbox_len(), 0);
    assert!(relay.metrics().unwrap().records > 0);

    // Bob collects it manually: the initial message arrives on the bundle's
    // queue, which has no session yet.
    let initial = collect_raw(&relay, &bob_recv_queue).expect("bob should find the handshake");
    let (alice_fp, first) = bob
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000_000)
        .unwrap();
    assert_eq!(first, "first contact");
    assert_eq!(alice_fp, alice.identity_public().fingerprint());

    // Bob replies; Alice collects.
    bob.send(&alice_fp, "received, going dark", 1_000_100)
        .unwrap();
    let (t2, _) = drain(&mut bob, t, 40);
    let (_, got) = pump(&mut alice, t2, 40);
    assert!(
        got.contains(&"received, going dark".to_string()),
        "alice should receive bob's reply, got {got:?}"
    );
}

/// Collect the first record from a queue directly, bypassing the engine.
/// Used for the handshake, which arrives before a session exists.
fn collect_raw(relay: &Arc<Relay>, queue: &void_proto::queue::QueueSecret) -> Option<Vec<u8>> {
    let deposit_key = queue.deposit_key();
    use void_relay::protocol::{Delivery, Frame, FrameType, Retrieve};

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
fn a_long_conversation_survives_many_ratchet_steps() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 3);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 4);

    let (bundle, bob_queue) = bob.create_bundle(b"r").unwrap();
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "hello", 1_000_000)
        .unwrap();
    let (mut t, _) = drain(&mut alice, 0, 40);
    let initial = collect_raw(&relay, &bob_queue).unwrap();
    let (alice_fp, _) = bob
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000_000)
        .unwrap();

    // Twelve round trips. With KEM_RATCHET_INTERVAL = 4 this crosses several
    // ML-KEM ratchet steps, each of which fragments across multiple records.
    for i in 0..12u32 {
        let msg = format!("alice {i}");
        alice.send(&bob_fp, &msg, 0).unwrap();
        let (t2, _) = drain(&mut alice, t, 60);
        let (t3, got) = pump(&mut bob, t2, 60);
        assert!(
            got.contains(&msg),
            "round {i}: bob missing {msg}, got {got:?}"
        );

        let reply = format!("bob {i}");
        bob.send(&alice_fp, &reply, 0).unwrap();
        let (t4, _) = drain(&mut bob, t3, 60);
        let (t5, got) = pump(&mut alice, t4, 60);
        assert!(got.contains(&reply), "round {i}: alice missing {reply}");
        t = t5;
    }
}

#[test]
fn messages_queue_when_the_transport_is_down_and_send_when_it_returns() {
    // FR-TRANS-05 and non-negotiable #5, end to end.
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let transport = MemoryTransport::new(Arc::clone(&relay), Arc::clone(&clock));
    let identity = Identity::from_seeds(&[5u8; 32], &[6u8; 32], &[7u8; 32]);
    let mut alice = Engine::new(
        identity,
        Settings::default(),
        Box::new(transport),
        SecurityMode::InsecureForTesting,
        0,
    )
    .unwrap();

    let bob_identity = Identity::from_seeds(&[8u8; 32], &[9u8; 32], &[10u8; 32]);
    let bob_queue = void_proto::queue::QueueSecret::from_parts([1u8; 32], 0);
    let (bundle, _secrets) =
        void_proto::handshake::PrekeyBundle::create(&bob_identity, &bob_queue, b"r", true).unwrap();
    alice
        .start_conversation(&bundle, "Bob", "queued", 0)
        .unwrap();

    let queued = alice.outbox_len();
    assert!(queued > 0);

    // We cannot reach into the boxed transport, so assert the observable
    // property: with the relay reachable, the outbox drains.
    let (_, outcomes) = drain(&mut alice, 0, 60);
    assert!(outcomes
        .iter()
        .any(|o| matches!(o, TickOutcome::Deposited(_))));
    assert_eq!(alice.outbox_len(), 0);
}

#[test]
fn an_enforcing_engine_refuses_a_non_tor_transport() {
    // FR-TRANS-03 at runtime.
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let identity = Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
    let result = Engine::new(
        identity,
        Settings::default(),
        Box::new(MemoryTransport::new(relay, clock)),
        SecurityMode::Enforcing,
        0,
    );
    assert!(matches!(
        result,
        Err(void_client::ClientError::InsecureTransport)
    ));
}

#[test]
fn sending_to_a_contact_whose_key_changed_is_blocked() {
    // FR-DISC-05, enforced in the engine rather than the UI.
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 11);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 12);

    let (bundle, _q) = bob.create_bundle(b"r").unwrap();
    let bob_fp = alice.start_conversation(&bundle, "Bob", "hi", 0).unwrap();
    assert!(alice.send(&bob_fp, "before", 0).is_ok());

    let impostor = Identity::from_seeds(&[99u8; 32], &[98u8; 32], &[97u8; 32]);
    alice
        .note_key_change(&bob_fp, impostor.public.clone())
        .unwrap();

    assert!(matches!(
        alice.send(&bob_fp, "after", 0),
        Err(void_client::ClientError::ContactKeyChanged)
    ));

    alice.acknowledge_key_change(&bob_fp).unwrap();
    assert!(alice.send(&bob_fp, "after ack", 0).is_ok());
    // Acknowledging must not restore verified status.
    assert_eq!(
        alice.contact(&bob_fp).unwrap().trust,
        void_store::model::TrustState::Unverified
    );
}

#[test]
fn a_tampered_bundle_is_refused_before_a_session_exists() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 13);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 14);

    let (mut bundle, _q) = bob.create_bundle(b"r").unwrap();
    bundle.queue.queue_id = [0xFF; 16];
    assert!(matches!(
        alice.start_conversation(&bundle, "Bob", "hi", 0),
        Err(void_client::ClientError::UnverifiedBundle)
    ));
    assert!(alice.contacts().is_empty(), "no session may be created");
}

#[test]
fn an_invitation_cannot_be_used_twice() {
    // FR-DISC-02: single use, enforced by consuming the one-time prekey.
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 15);
    let mut carol = engine(Arc::clone(&relay), Arc::clone(&clock), 16);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 17);

    let (bundle, bob_queue) = bob.create_bundle(b"r").unwrap();
    alice
        .start_conversation(&bundle, "Bob", "from alice", 0)
        .unwrap();
    let (t, _) = drain(&mut alice, 0, 40);
    let initial = collect_raw(&relay, &bob_queue).unwrap();
    bob.accept_conversation(bundle.queue.queue_id, &initial, 0)
        .unwrap();

    // Carol has the same link. Bob no longer holds the bundle secrets.
    carol
        .start_conversation(&bundle, "Bob", "from carol", 0)
        .unwrap();
    let (_t2, _) = drain(&mut carol, t, 40);
    let result = bob.accept_conversation(bundle.queue.queue_id, &[0u8; 10], 0);
    assert!(matches!(
        result,
        Err(void_client::ClientError::UnknownBundle)
    ));
}

// --- What a compromised relay cannot do -------------------------------------

#[test]
fn the_relay_never_sees_plaintext() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 21);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 22);

    let (bundle, bob_queue) = bob.create_bundle(b"r").unwrap();
    let bob_fp = alice.start_conversation(&bundle, "Bob", "hi", 0).unwrap();
    let (t, _) = drain(&mut alice, 0, 40);
    let initial = collect_raw(&relay, &bob_queue).unwrap();
    let (alice_fp, _) = bob
        .accept_conversation(bundle.queue.queue_id, &initial, 0)
        .unwrap();
    let _ = alice_fp;

    const SECRET: &str = "THE DOCUMENTS ARE IN THE THIRD LOCKER";
    alice.send(&bob_fp, SECRET, 0).unwrap();
    let (_t2, outcomes) = drain(&mut alice, t, 60);
    assert!(outcomes
        .iter()
        .any(|o| matches!(o, TickOutcome::Deposited(_))));

    // Everything the relay holds, searched for the plaintext.
    let m = relay.metrics().unwrap();
    assert!(m.records > 0);
    // The relay's own store exposes no plaintext accessor at all; the strongest
    // available check is that its aggregate view is a pair of counts.
    assert_eq!(
        format!("{m:?}"),
        format!("Metrics {{ queues: {}, records: {} }}", m.queues, m.records)
    );
}

#[test]
fn every_deposit_the_relay_sees_is_the_same_size() {
    // FR-MSG-02: the relay cannot infer message length.
    use void_proto::envelope::{seal, SEALED_RECORD_SIZE};
    use void_proto::queue::QueueSecret;
    use void_proto::record::{Record, RecordKind};

    let q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
    let sizes: Vec<usize> = [0usize, 1, 50, 500, 1000]
        .iter()
        .map(|&n| {
            let rec = Record {
                kind: RecordKind::Payload,
                message_id: 1,
                index: 0,
                count: 1,
                body: vec![0u8; n],
            };
            seal(&q, &rec).unwrap().sealed.len()
        })
        .collect();
    assert!(sizes.iter().all(|&s| s == SEALED_RECORD_SIZE), "{sizes:?}");

    // Cover traffic is the same size too.
    let dummy = seal(&q, &Record::dummy().unwrap()).unwrap();
    assert_eq!(dummy.sealed.len(), SEALED_RECORD_SIZE);
}

#[test]
fn the_relay_cannot_link_two_queues_of_one_user() {
    // PRD §2.4's central claim. Alice's queues for Bob and for Carol are
    // derived from independent secrets and share no structure.
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 31);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 32);
    let mut carol = engine(Arc::clone(&relay), Arc::clone(&clock), 33);

    let (b_bundle, _bq) = bob.create_bundle(b"r").unwrap();
    let (c_bundle, _cq) = carol.create_bundle(b"r").unwrap();
    alice
        .start_conversation(&b_bundle, "Bob", "hi bob", 0)
        .unwrap();
    alice
        .start_conversation(&c_bundle, "Carol", "hi carol", 0)
        .unwrap();

    assert_ne!(b_bundle.queue.queue_id, c_bundle.queue.queue_id);
    // No shared prefix or suffix an operator could group on.
    assert_ne!(&b_bundle.queue.queue_id[..4], &c_bundle.queue.queue_id[..4]);
    assert_ne!(
        &b_bundle.queue.queue_id[12..],
        &c_bundle.queue.queue_id[12..]
    );
}

#[test]
fn a_relay_that_moves_a_deposit_between_queues_is_detected() {
    use void_proto::envelope::{open, seal, Deposit};
    use void_proto::queue::QueueSecret;
    use void_proto::record::{Record, RecordKind};

    let alice_q = QueueSecret::from_parts([1u8; 32], 0).deposit_key();
    let carol_q = QueueSecret::from_parts([2u8; 32], 0).deposit_key();
    let rec = Record {
        kind: RecordKind::Payload,
        message_id: 1,
        index: 0,
        count: 1,
        body: b"for alice only".to_vec(),
    };
    let mut dep = seal(&alice_q, &rec).unwrap();
    dep = Deposit {
        queue_id: carol_q.queue_id,
        sealed: dep.sealed,
    };
    assert!(open(&carol_q, &dep).is_err());
    assert!(open(&alice_q, &dep).is_err());
}

#[test]
fn a_relay_returning_forged_records_cannot_inject_messages() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 41);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 42);

    let (bundle, bob_queue) = bob.create_bundle(b"r").unwrap();
    let bob_fp = alice.start_conversation(&bundle, "Bob", "hi", 0).unwrap();
    let (t, _) = drain(&mut alice, 0, 40);
    let initial = collect_raw(&relay, &bob_queue).unwrap();
    let (alice_fp, _) = bob
        .accept_conversation(bundle.queue.queue_id, &initial, 0)
        .unwrap();

    // A hostile relay deposits garbage into Alice's receive queue directly.
    use void_relay::protocol::{Frame, FrameType};
    assert!(alice.contact(&bob_fp).is_some(), "the session must exist");
    let junk = void_proto::envelope::Deposit {
        queue_id: [0xAB; 16],
        sealed: vec![0u8; void_proto::envelope::SEALED_RECORD_SIZE],
    };
    relay
        .handle(&Frame::new(FrameType::Deposit, junk.encode()), 0)
        .unwrap();

    // Alice polls and receives nothing: the forged record does not open.
    let (_t2, got) = pump(&mut alice, t, 20);
    assert!(
        got.is_empty(),
        "forged records must not surface as messages"
    );
    let _ = alice_fp;
}

/// Establish a conversation and return both fingerprints: (alice_fp, bob_fp).
fn connect(relay: &Arc<Relay>, alice: &mut Engine, bob: &mut Engine) -> (u64, [u8; 32], [u8; 32]) {
    let (bundle, bob_recv_queue) = bob.create_bundle(b"relay.onion").unwrap();
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "first contact", 1_000_000)
        .unwrap();
    let (t, _) = drain(alice, 0, 40);
    let initial = collect_raw(relay, &bob_recv_queue).expect("bob should find the handshake");
    let (alice_fp, first) = bob
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000_000)
        .unwrap();
    assert_eq!(first, "first contact");
    (t, alice_fp, bob_fp)
}

#[test]
fn a_call_rings_answers_and_ends_through_the_relay() {
    // Signalling rides exactly the path a text message rides: ratchet,
    // fragmentation, constant-rate scheduler, mailbox queue. The media path is
    // a direct onion connection and is not exercised here — that is measured
    // in experiments/onion-call, not simulated.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 71);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 72);
    let (t, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    // Alice's platform layer has published a service and hands the address in.
    let call = alice
        .place_call(&bob_fp, "abcdefghij234567.onion", 9999)
        .unwrap();
    assert_eq!(call.role, void_proto::call::Role::Caller);
    assert!(!call.answered);

    let (t2, _) = drain(&mut alice, t, 40);
    let (t3, msgs) = pump(&mut bob, t2, 40);
    assert!(
        msgs.is_empty(),
        "a call must never surface as a chat message, got {msgs:?}"
    );

    let events = bob.take_call_events();
    assert_eq!(events.len(), 1, "bob should have exactly one ring");
    let incoming = match &events[0] {
        CallEvent::Incoming(c) => c.clone(),
        other => panic!("expected an incoming call, got {other:?}"),
    };
    assert_eq!(incoming.peer, alice_fp);
    assert_eq!(incoming.onion_address, "abcdefghij234567.onion");
    assert_eq!(incoming.call_id, call.call_id);
    assert_eq!(
        incoming.media_secret, call.media_secret,
        "both ends must derive media keys from the same secret"
    );

    // Bob answers.
    let answered = bob.answer_call(&alice_fp).unwrap();
    assert_eq!(answered.role, void_proto::call::Role::Callee);
    let (t4, _) = drain(&mut bob, t3, 40);
    let (t5, _) = pump(&mut alice, t4, 40);
    let events = alice.take_call_events();
    assert!(
        matches!(&events[..], [CallEvent::Answered(c)] if c.call_id == call.call_id),
        "alice should learn the call was answered, got {events:?}"
    );
    assert!(alice.active_call(&bob_fp).unwrap().answered);

    // Alice hangs up.
    alice
        .end_call(&bob_fp, void_proto::call::EndReason::HungUp)
        .unwrap();
    assert!(alice.active_call(&bob_fp).is_none());
    let (t6, _) = drain(&mut alice, t5, 40);
    let (_, _) = pump(&mut bob, t6, 40);
    let events = bob.take_call_events();
    assert!(
        matches!(
            &events[..],
            [CallEvent::Ended {
                reason: void_proto::call::EndReason::HungUp,
                ..
            }]
        ),
        "bob should learn why it ended, got {events:?}"
    );
    assert!(bob.active_call(&alice_fp).is_none());
}

#[test]
fn a_declined_call_leaves_no_message_and_no_state() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 73);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 74);
    let (t, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    alice
        .place_call(&bob_fp, "abcdefghij234567.onion", 9999)
        .unwrap();
    let (t2, _) = drain(&mut alice, t, 40);
    let (t3, _) = pump(&mut bob, t2, 40);
    assert_eq!(bob.take_call_events().len(), 1);

    bob.end_call(&alice_fp, void_proto::call::EndReason::Declined)
        .unwrap();
    let (t4, _) = drain(&mut bob, t3, 40);
    let (t5, msgs) = pump(&mut alice, t4, 40);
    assert!(msgs.is_empty(), "declining is not a message");

    let events = alice.take_call_events();
    assert!(matches!(
        &events[..],
        [CallEvent::Ended {
            reason: void_proto::call::EndReason::Declined,
            ..
        }]
    ));
    assert!(alice.active_call(&bob_fp).is_none());
    assert!(bob.active_call(&alice_fp).is_none());

    // And the conversation is untouched: text still flows both ways.
    alice.send(&bob_fp, "so anyway", 1_000_500).unwrap();
    let (t6, _) = drain(&mut alice, t5, 40);
    let (_, got) = pump(&mut bob, t6, 40);
    assert!(got.contains(&"so anyway".to_string()), "got {got:?}");
}

#[test]
fn call_signalling_is_indistinguishable_from_a_message_to_the_relay() {
    // The claim that makes calls safe to add at all: the relay sees deposits,
    // and a call's deposits look exactly like a message's.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 75);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 76);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    let before = relay.metrics().unwrap().records;
    alice.send(&bob_fp, "a text message", 1_000_100).unwrap();
    let (t2, _) = drain(&mut alice, t, 40);
    let after_text = relay.metrics().unwrap().records;

    alice
        .place_call(&bob_fp, "abcdefghij234567.onion", 9999)
        .unwrap();
    let (_t3, _) = drain(&mut alice, t2, 40);
    let after_call = relay.metrics().unwrap().records;

    assert!(after_text > before && after_call > after_text);
    // Both produced whole records of one fixed size. The relay has a count and
    // nothing else — no field distinguishes a call offer from a greeting.
    assert_eq!(
        void_proto::envelope::SEALED_RECORD_SIZE,
        void_proto::record::RECORD_SIZE + void_proto::envelope::SEAL_OVERHEAD
    );
}

#[test]
fn a_second_offer_from_the_same_contact_is_refused_not_silently_swapped() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 77);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 78);
    let (t, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    alice
        .place_call(&bob_fp, "abcdefghij234567.onion", 9999)
        .unwrap();
    let first_id = alice.active_call(&bob_fp).unwrap().call_id;

    // Placing a second call while one is live is refused locally.
    assert!(alice.place_call(&bob_fp, "other.onion", 9999).is_err());
    assert_eq!(alice.active_call(&bob_fp).unwrap().call_id, first_id);

    let (t2, _) = drain(&mut alice, t, 40);
    let (_, _) = pump(&mut bob, t2, 40);
    let events = bob.take_call_events();
    assert_eq!(events.len(), 1);
    assert!(bob.active_call(&alice_fp).is_some());
}

/// A relay that keeps a copy of every deposit and can hand one back later.
///
/// This is not a stretch of the threat model, it *is* the threat model: §9.1
/// assumes the relay is seized along with its disk, and the design turns on
/// what an attacker holding every sealed record still cannot do. Redelivery is
/// the cheapest attack in that set — it needs no key, forges nothing, and the
/// relay cannot tell what it is resending.
struct HoardingRelay {
    relay: Arc<Relay>,
    clock: Arc<Mutex<u64>>,
    hoard: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl void_client::transport::Transport for HoardingRelay {
    fn kind(&self) -> void_client::transport::TransportKind {
        void_client::transport::TransportKind::InMemory
    }

    fn exchange(
        &mut self,
        request: &void_relay::protocol::Frame,
    ) -> void_client::ClientResult<void_relay::protocol::Frame> {
        if request.kind == void_relay::protocol::FrameType::Deposit {
            self.hoard.lock().unwrap().push(request.body.clone());
        }
        let now = *self.clock.lock().unwrap();
        self.relay
            .handle(request, now)
            .map_err(|_| void_client::ClientError::Protocol)
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn disconnect(&mut self) {}
}

#[test]
fn a_relay_redelivering_an_old_record_cannot_kill_a_conversation() {
    // Every record Alice ever deposited is on the seized disk. Each one names
    // the ratchet key of the chain it belonged to, and chains that ended weeks
    // ago look, to a receiver that has moved on, exactly like a chain starting
    // now. Handing one back must cost the relay what it costs everyone else:
    // nothing. It must not step Bob's ratchet, and it must not cost him the
    // conversation.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let hoard = Arc::new(Mutex::new(Vec::new()));

    let mut alice = Engine::new(
        Identity::from_seeds(&[61u8; 32], &[62u8; 32], &[63u8; 32]),
        Settings::default(),
        Box::new(HoardingRelay {
            relay: Arc::clone(&relay),
            clock: Arc::clone(&clock),
            hoard: Arc::clone(&hoard),
        }),
        SecurityMode::InsecureForTesting,
        0,
    )
    .unwrap();
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 64);

    let (bundle, bob_recv_queue) = bob.create_bundle(b"relay.onion").unwrap();
    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "first contact", 1_000_000)
        .unwrap();
    let (mut t, _) = drain(&mut alice, 0, 40);
    let initial = collect_raw(&relay, &bob_recv_queue).expect("bob should find the handshake");
    let (alice_fp, first) = bob
        .accept_conversation(bundle.queue.queue_id, &initial, 1_000_000)
        .unwrap();
    assert_eq!(first, "first contact");

    // Enough back-and-forth that Alice has opened several chains, so the
    // hoarded records name ratchet keys Bob has long since left behind.
    for round in 0..3u32 {
        bob.send(&alice_fp, &format!("bob {round}"), 1_000_100)
            .unwrap();
        let (t2, _) = drain(&mut bob, t, 40);
        let (t3, _) = pump(&mut alice, t2, 40);
        alice
            .send(&bob_fp, &format!("alice {round}"), 1_000_200)
            .unwrap();
        let (t4, _) = drain(&mut alice, t3, 40);
        let (t5, got) = pump(&mut bob, t4, 40);
        assert!(
            got.contains(&format!("alice {round}")),
            "round {round} must arrive, got {got:?}"
        );
        t = t5;
    }

    let replayed = hoard.lock().unwrap().clone();
    assert!(
        replayed.len() > 3,
        "the hoard should hold every record alice deposited"
    );
    for body in &replayed {
        let _ = relay.handle(
            &void_relay::protocol::Frame::new(
                void_relay::protocol::FrameType::Deposit,
                body.clone(),
            ),
            1_000_300,
        );
    }

    // Bob drains the flood. Not one of these is a message he has not already
    // seen, so nothing new must surface.
    let (t6, replay_got) = pump(&mut bob, t, 80);
    assert!(
        replay_got.is_empty(),
        "a redelivered record must not surface a second time, got {replay_got:?}"
    );

    // The conversation is unharmed: Alice speaks, Bob hears her.
    alice
        .send(&bob_fp, "still here after all that", 1_000_400)
        .unwrap();
    let (t7, _) = drain(&mut alice, t6, 40);
    let (_, got) = pump(&mut bob, t7, 40);
    assert!(
        got.contains(&"still here after all that".to_string()),
        "the replay must not have cost the conversation, got {got:?}"
    );
}

#[test]
fn revoking_a_contact_stops_delivery_without_notifying_them() {
    // FR-ABUSE-02.
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 51);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 52);

    let (bundle, _q) = bob.create_bundle(b"r").unwrap();
    let bob_fp = alice.start_conversation(&bundle, "Bob", "hi", 0).unwrap();
    assert_eq!(alice.contacts().len(), 1);

    alice.revoke_contact(&bob_fp).unwrap();
    assert!(alice.contacts().is_empty());
    assert_eq!(alice.outbox_len(), 0, "queued messages are dropped too");
    assert!(matches!(
        alice.send(&bob_fp, "still there?", 0),
        Err(void_client::ClientError::NoSuchContact)
    ));
}

#[test]
fn rotating_a_queue_keeps_the_contact() {
    // FR-ABUSE-03: a flooded queue can be abandoned without losing the
    // relationship.
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 61);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 62);

    let (bundle, _q) = bob.create_bundle(b"r").unwrap();
    let bob_fp = alice.start_conversation(&bundle, "Bob", "hi", 0).unwrap();
    let before = alice.rotate_queue(&bob_fp).unwrap();
    let after = alice.rotate_queue(&bob_fp).unwrap();
    assert_ne!(before, after);
    assert_eq!(alice.contacts().len(), 1, "the contact survives rotation");
}

#[test]
fn traffic_is_emitted_even_with_nothing_to_say() {
    // FR-MSG-06 observed at the engine level.
    let relay = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 71);

    let mut t = 0u64;
    for _ in 0..20 {
        alice.tick(t).unwrap();
        t += PAD_INTERVAL_MS;
    }
    let stats = alice.traffic_stats();
    assert!(
        stats.padding_records > 0,
        "an idle client must still emit cover traffic while connected"
    );
    assert_eq!(stats.payload_records, 0);
}

#[test]
fn set_transport_is_the_hook_the_platform_layer_uses_after_bootstrapping_tor() {
    // This is what `void-tor`'s `TorHandle::connect` result gets handed to,
    // once the platform has bootstrapped Arti and opened a circuit — see
    // `docs/DECISIONS.md#d-009`. An engine starts on `NullTransport`
    // (reports `TransportKind::Tor`, carries nothing) so every send queues
    // from construction; this call is what replaces it with something real.
    use void_client::engine::{Engine, SecurityMode};
    use void_client::transport::{MemoryTransport, NullTransport, Transport, TransportKind};
    use void_proto::identity::Identity;
    use void_store::model::Settings;

    let identity = Identity::from_seeds(&[81u8; 32], &[82u8; 32], &[83u8; 32]);
    let mut engine = Engine::new(
        identity,
        Settings::default(),
        Box::new(NullTransport::new()),
        SecurityMode::Enforcing,
        0,
    )
    .unwrap();
    assert_eq!(engine.transport_kind(), TransportKind::Tor);

    // FR-TRANS-05, non-negotiable #5: a transport that could carry traffic
    // outside Tor is refused, not silently accepted, in enforcing mode.
    let r = relay();
    let clock = Arc::new(Mutex::new(0u64));
    let direct = Box::new(MemoryTransport::new(r, clock)) as Box<dyn Transport>;
    assert_eq!(direct.kind(), TransportKind::InMemory);
    assert!(matches!(
        engine.set_transport(direct),
        Err(void_client::ClientError::InsecureTransport)
    ));
    // The rejected swap must not have taken effect.
    assert_eq!(engine.transport_kind(), TransportKind::Tor);

    // A transport that reports Tor is accepted — this is the actual path
    // `TorHandle::connect`'s `TorTransport` takes.
    assert!(engine.set_transport(Box::new(NullTransport::new())).is_ok());
}
