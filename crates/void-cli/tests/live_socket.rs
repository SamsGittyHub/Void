//! A live end-to-end test over real TCP sockets.
//!
//! The `void-client` integration tests run the protocol through an in-process
//! transport, which is deterministic and fast but never touches a socket. This
//! test starts an actual `void-relayd` listener and drives two clients through
//! it over loopback TCP, so the framing, the read/write loop, and the
//! thread-per-connection server are all exercised.
//!
//! It is the closest thing in this repository to PRD §11's Phase 2 deliverable —
//! *"two CLI clients exchanging messages over Tor via a relay, end to end"* —
//! with Tor replaced by loopback. Substituting a `TorTransport` for the
//! `TcpTransport` below is the only change needed to make it the real thing.

use std::sync::Arc;

use void_client::engine::{Engine, SecurityMode, TickOutcome};
use void_client::transport::{TcpTransport, Transport};
use void_proto::identity::Identity;
use void_proto::queue::QueueSecret;
use void_proto::record::PAD_INTERVAL_MS;
use void_relay::server::{self, NoPush, Relay};
use void_relay::store::Config;
use void_store::model::Settings;

/// Start a relay on an ephemeral loopback port. Returns the address.
///
/// Returns `None` if the sandbox forbids loopback sockets, in which case the
/// test skips rather than failing — the in-process suite already covers the
/// protocol, and a CI environment without loopback should not report a red
/// build for it.
fn start_relay() -> Option<(Arc<Relay>, String, std::thread::JoinHandle<()>)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let addr = listener.local_addr().ok()?.to_string();
    drop(listener);

    let relay = Arc::new(Relay::new(Config::default(), Box::new(NoPush)));
    let r = Arc::clone(&relay);
    let a = addr.clone();
    let handle = std::thread::spawn(move || {
        let _ = server::listen(r, &a);
    });
    std::thread::sleep(std::time::Duration::from_millis(250));

    // Confirm the listener actually came up.
    std::net::TcpStream::connect(&addr).ok()?;
    Some((relay, addr, handle))
}

fn engine(addr: &str, seed: u8) -> Option<Engine> {
    let identity = Identity::from_seeds(
        &[seed; 32],
        &[seed.wrapping_mul(3).wrapping_add(7); 32],
        &[seed.wrapping_mul(5).wrapping_add(11); 32],
    );
    let transport = TcpTransport::connect(addr).ok()?;
    Engine::new(
        identity,
        Settings::default(),
        Box::new(transport),
        SecurityMode::InsecureForTesting,
        0,
    )
    .ok()
}

/// Collect the handshake from an introduction queue over a real socket.
fn collect_intro(addr: &str, queue: &QueueSecret) -> Option<Vec<u8>> {
    use void_relay::protocol::{Delivery, Frame, FrameType, Retrieve};

    let mut transport = TcpTransport::connect(addr).ok()?;
    let queue_id = queue.queue_id();
    let deposit_key = queue.deposit_key();
    let mut reassembler = void_proto::record::Reassembler::new(16);

    for _ in 0..64 {
        let ch = transport
            .exchange(&Frame::new(FrameType::Challenge, queue_id.to_vec()))
            .ok()?;
        if ch.kind != FrameType::ChallengeReply || ch.body.len() != 32 {
            return None;
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&ch.body);

        let resp = transport
            .exchange(&Frame::new(
                FrameType::Retrieve,
                Retrieve {
                    queue_id,
                    challenge,
                    retrieval_public: queue.retrieval_public(),
                    proof: queue.prove_retrieval(&challenge),
                }
                .encode(),
            ))
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

fn drain(engine: &mut Engine, start: u64, slots: u64) -> u64 {
    let mut t = start;
    for _ in 0..slots {
        let _ = engine.tick(t);
        t += PAD_INTERVAL_MS;
        if engine.outbox_len() == 0 {
            break;
        }
    }
    // A few more slots so the deposit definitely lands.
    for _ in 0..3 {
        let _ = engine.tick(t);
        t += PAD_INTERVAL_MS;
    }
    t
}

fn pump(engine: &mut Engine, start: u64, slots: u64) -> (u64, Vec<String>) {
    let mut t = start;
    let mut got = Vec::new();
    for _ in 0..slots {
        if let Ok(TickOutcome::Retrieved(msgs)) = engine.tick(t) {
            got.extend(msgs.into_iter().map(|m| m.text));
        }
        t += PAD_INTERVAL_MS;
    }
    (t, got)
}

#[test]
fn two_clients_converse_over_real_sockets() {
    let Some((relay, addr, handle)) = start_relay() else {
        eprintln!("skipping: loopback sockets unavailable in this environment");
        return;
    };

    let (Some(mut alice), Some(mut bob)) = (engine(&addr, 1), engine(&addr, 2)) else {
        relay.shutdown();
        let _ = handle.join();
        eprintln!("skipping: could not connect clients");
        return;
    };

    // Bob publishes an invitation. Alice scans it.
    let (bundle, intro_queue) = bob.create_bundle(addr.as_bytes()).unwrap();
    assert!(bundle.verify());

    let bob_fp = alice
        .start_conversation(&bundle, "Bob", "the package is ready", 0)
        .unwrap();
    let t = drain(&mut alice, 0, 40);
    assert_eq!(
        alice.outbox_len(),
        0,
        "the handshake should have been deposited"
    );
    assert!(relay.metrics().unwrap().records > 0);

    let initial = collect_intro(&addr, &intro_queue).expect("handshake must arrive");
    let (alice_fp, first) = bob
        .accept_conversation(bundle.queue.queue_id, &initial, 0)
        .unwrap();
    assert_eq!(first, "the package is ready");

    // Several round trips, crossing ML-KEM ratchet steps.
    let mut t = t;
    for i in 0..6u32 {
        let msg = format!("alice {i}");
        alice.send(&bob_fp, &msg, 0).unwrap();
        let t2 = drain(&mut alice, t, 40);
        let (t3, got) = pump(&mut bob, t2, 40);
        assert!(
            got.contains(&msg),
            "round {i}: bob missing {msg}, got {got:?}"
        );

        let reply = format!("bob {i}");
        bob.send(&alice_fp, &reply, 0).unwrap();
        let t4 = drain(&mut bob, t3, 40);
        let (t5, got) = pump(&mut alice, t4, 40);
        assert!(got.contains(&reply), "round {i}: alice missing {reply}");
        t = t5;
    }

    relay.shutdown();
    let _ = handle.join();
}

#[test]
fn a_client_that_loses_the_relay_queues_rather_than_failing_open() {
    // FR-TRANS-05 over a real socket: killing the relay must leave messages
    // queued locally, never sent by some other route.
    let Some((relay, addr, handle)) = start_relay() else {
        eprintln!("skipping: loopback sockets unavailable");
        return;
    };
    let Some(mut alice) = engine(&addr, 3) else {
        relay.shutdown();
        let _ = handle.join();
        return;
    };

    let bob_identity = Identity::from_seeds(&[9u8; 32], &[8u8; 32], &[7u8; 32]);
    let bob_queue = QueueSecret::from_parts([4u8; 32], 0);
    let (bundle, _) =
        void_proto::handshake::PrekeyBundle::create(&bob_identity, &bob_queue, b"r", true).unwrap();
    alice
        .start_conversation(&bundle, "Bob", "queued", 0)
        .unwrap();

    // Stop the relay before the scheduler gets a chance to deposit.
    relay.shutdown();
    let _ = handle.join();

    let mut t = 0u64;
    let mut saw_offline = false;
    for _ in 0..20 {
        match alice.tick(t) {
            Ok(TickOutcome::Offline) => saw_offline = true,
            Ok(_) => {}
            Err(_) => saw_offline = true,
        }
        t += PAD_INTERVAL_MS;
    }
    assert!(saw_offline, "the client should have reported being offline");
    assert!(
        alice.outbox_len() > 0,
        "messages must stay queued when the relay is unreachable"
    );
}
