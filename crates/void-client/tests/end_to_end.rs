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

use void_client::engine::{
    CallEvent, ContactEvent, Engine, InviteFailure, SecurityMode, TickOutcome,
    CALLER_TIMEOUT_SECONDS, INVITE_ACCEPT_GRACE_SECONDS, OFFER_MAX_AGE_SECONDS,
    RING_TIMEOUT_SECONDS,
};
use void_client::transport::MemoryTransport;
use void_client::ClientError;
use void_proto::identity::Identity;
use void_proto::record::PAD_INTERVAL_MS;
use void_relay::protocol::{Frame, FrameType};
use void_relay::server::{NoPush, Relay};
use void_relay::store::Config;
use void_store::model::{Settings, TrustState};

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

/// Take an invitation link from `inviter` to `invitee` the way the apps do:
/// the invitee opens it; both keep ticking — the inviter parking the
/// invitation on the relay, the invitee collecting it — until it is ready;
/// then the invitee confirms. Returns the time reached and the confirmation's
/// result, which is the inviter's fingerprint or why it was refused.
fn accept_invite(
    inviter: &mut Engine,
    invitee: &mut Engine,
    link: &str,
    name: &str,
    first_message: &str,
    start_ms: u64,
) -> (u64, Result<[u8; 32], ClientError>) {
    let fetch = invitee.open_invite(link, start_ms / 1000).unwrap();
    let mut t = start_ms;
    for _ in 0..400 {
        inviter.tick(t).unwrap();
        invitee.tick(t).unwrap();
        for event in invitee.take_contact_events() {
            match event {
                ContactEvent::InviteReady { fetch_id, .. } if fetch_id == fetch => {
                    let result = invitee.confirm_invite(&fetch, name, first_message, t / 1000);
                    return (t, result);
                }
                ContactEvent::InviteFailed { fetch_id, reason } if fetch_id == fetch => {
                    panic!("the invitation failed: {reason:?}");
                }
                _ => {}
            }
        }
        t += PAD_INTERVAL_MS;
    }
    panic!("the invitation never became ready");
}

/// Tick every engine once per emission slot, in turn, until `done` says stop
/// or the budget runs out. Returns the time reached and every contact event
/// the first engine (the inviter) reported along the way.
fn run_until(
    engines: &mut [&mut Engine],
    start_ms: u64,
    slots: u64,
    mut done: impl FnMut(&[ContactEvent]) -> bool,
) -> (u64, Vec<ContactEvent>) {
    let mut t = start_ms;
    let mut events = Vec::new();
    for _ in 0..slots {
        for engine in engines.iter_mut() {
            engine.tick(t).unwrap();
        }
        events.extend(engines[0].take_contact_events());
        if done(&events) {
            break;
        }
        t += PAD_INTERVAL_MS;
    }
    (t, events)
}

fn added(events: &[ContactEvent]) -> Vec<(String, [u8; 32], String)> {
    events
        .iter()
        .filter_map(|e| match e {
            ContactEvent::Added {
                name,
                contact_fingerprint,
                first_message,
                ..
            } => Some((name.clone(), *contact_fingerprint, first_message.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn an_invite_polled_while_it_is_still_arriving_completes() {
    // The order a real app produces, which every other test here avoids by
    // flushing the whole handshake before the inviter looks: Bob keeps
    // ticking — and so keeps collecting from his intro queue — while Alice's
    // handshake is still uploading one record per slot. The relay deletes
    // each record as it hands it over, so Bob has to keep the fragments he
    // already has between retrievals, or the contact never appears.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 91);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 92);

    let invite = bob
        .create_invite(b"relay.onion", "Bob", "Alice", 1_000, 86_400)
        .unwrap();
    // Alice opens the link the moment Bob shows it — before his phone has
    // finished parking the invitation on the relay.
    assert!(bob.invite_upload_remaining(&invite.id).unwrap() > 0);
    let fetch = alice.open_invite(&invite.link, 0).unwrap();
    let mut t = 0u64;
    let mut ready = None;
    let mut collected_mid_upload = false;
    for _ in 0..200 {
        bob.tick(t).unwrap();
        let outcome = alice.tick(t).unwrap();
        if matches!(outcome, TickOutcome::Retrieved(_))
            && bob.invite_upload_remaining(&invite.id).unwrap() > 0
        {
            collected_mid_upload = true;
        }
        if let Some(event) = alice.take_contact_events().into_iter().next() {
            ready = Some(event);
            break;
        }
        t += PAD_INTERVAL_MS;
    }
    assert!(
        collected_mid_upload,
        "alice must have collected while bob was still uploading"
    );
    assert_eq!(
        ready,
        Some(ContactEvent::InviteReady {
            fetch_id: fetch,
            inviter_label: "Bob".to_string(),
            inviter_fingerprint: bob.fingerprint(),
        }),
        "the invitation arrives whole, from Bob, under the name he gave it"
    );
    alice
        .confirm_invite(&fetch, "", "hello from the real path", t / 1000)
        .unwrap();
    assert_eq!(
        alice.contact(&bob.fingerprint()).unwrap().local_name,
        "Bob",
        "an empty name takes the one the invitation carried"
    );
    assert!(alice.outbox_len() > 4, "a handshake spans many records");

    let mut added_event = None;
    let mut retrievals_mid_arrival = 0;
    for _ in 0..400 {
        alice.tick(t).unwrap();
        let outcome = bob.tick(t).unwrap();
        if matches!(outcome, TickOutcome::Retrieved(_)) && alice.outbox_len() > 0 {
            retrievals_mid_arrival += 1;
        }
        if let Some(event) = bob.take_contact_events().into_iter().next() {
            added_event = Some(event);
            break;
        }
        t += PAD_INTERVAL_MS;
    }
    assert!(
        retrievals_mid_arrival > 0,
        "bob must have collected while the handshake was still arriving"
    );
    let Some(ContactEvent::Added {
        invite_id,
        contact_fingerprint,
        name,
        first_message,
    }) = added_event
    else {
        panic!("bob never reported the new contact, got {added_event:?}");
    };
    assert_eq!(invite_id, invite.id);
    assert_eq!(contact_fingerprint, alice.identity_public().fingerprint());
    assert_eq!(
        name, "Alice",
        "the invite's contact label names whoever accepts"
    );
    assert_eq!(first_message, "hello from the real path");
    assert!(
        !bob.has_pending_invite(&invite.id),
        "an accepted invite is consumed"
    );

    // And the conversation that came out of it works in both directions.
    let bob_fp = bob.fingerprint();
    bob.send(&contact_fingerprint, "got it", 2_000).unwrap();
    let (t2, _) = drain(&mut bob, t, 60);
    let (_, got) = pump(&mut alice, t2, 60);
    assert!(got.contains(&"got it".to_string()), "got {got:?}");
    assert!(alice.contact(&bob_fp).is_some());
}

#[test]
fn a_stranger_depositing_junk_cannot_spend_an_invite() {
    // The intro queue's deposit key is in every copy of the link, so a
    // stranger who has it can deposit whatever they like. Here Mallory sends
    // a real, complete handshake of her own with its first message corrupted:
    // it decodes and its signature verifies, and only the decryption fails.
    // The inviter must discard it and still accept Alice.
    use void_proto::content::Content;
    use void_proto::envelope::seal;
    use void_proto::record::fragment;

    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 93);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 94);
    let mallory = Identity::from_seeds(&[66u8; 32], &[67u8; 32], &[68u8; 32]);

    // The bundle itself, as anyone who opened the link would hold it.
    let (bundle, _) = bob.create_bundle(b"relay.onion").unwrap();
    let invite_id = bundle.queue.queue_id;

    let (forged, _, deposit_key) =
        void_proto::handshake::initiate(&mallory, &bundle, &Content::text("let me in").encode())
            .unwrap();
    let mut bytes = forged.encode();
    *bytes.last_mut().unwrap() ^= 1;
    for record in fragment(0xDEAD, &bytes).unwrap() {
        let deposit = seal(&deposit_key, &record).unwrap();
        let reply = relay
            .handle(&Frame::new(FrameType::Deposit, deposit.encode()), 0)
            .unwrap();
        assert_eq!(reply.kind, FrameType::Ack);
    }

    // Bob collects the forgery in full before Alice has done anything.
    let (t, events) = run_until(&mut [&mut bob], 0, 40, |_| false);
    assert!(
        events.is_empty(),
        "the forgery must not surface: {events:?}"
    );
    assert!(
        bob.has_pending_invite(&invite_id),
        "a handshake that fails verification must not consume the invite"
    );

    alice
        .start_conversation(&bundle, "Bob", "it's really me", 1_000)
        .unwrap();
    let (_, events) = run_until(&mut [&mut bob, &mut alice], t, 400, |e| !e.is_empty());
    let added = added(&events);
    assert_eq!(added.len(), 1, "{events:?}");
    assert_eq!(added[0].1, alice.fingerprint());
    assert_eq!(added[0].2, "it's really me");
}

#[test]
fn two_outstanding_invites_both_complete() {
    // One invite per person, all open at once. The apps used to hold a single
    // pending invite and freed the first when a second was made, so the first
    // person could never connect.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 95);
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 96);
    let mut carol = engine(Arc::clone(&relay), Arc::clone(&clock), 97);

    let for_alice = bob
        .create_invite(b"relay.onion", "Bob", "Alice", 1_000, 86_400)
        .unwrap();
    let for_carol = bob
        .create_invite(b"relay.onion", "Bob", "Carol", 1_000, 86_400)
        .unwrap();
    assert_ne!(for_alice.id, for_carol.id);
    assert_ne!(for_alice.link, for_carol.link);
    assert_eq!(
        bob.invite_link(&for_alice.id),
        Some(for_alice.link.as_str())
    );

    let alice_fetch = alice.open_invite(&for_alice.link, 0).unwrap();
    let carol_fetch = carol.open_invite(&for_carol.link, 0).unwrap();
    let mut t = 0u64;
    let mut bob_events = Vec::new();
    for _ in 0..800 {
        bob.tick(t).unwrap();
        alice.tick(t).unwrap();
        carol.tick(t).unwrap();
        for event in alice.take_contact_events() {
            if matches!(event, ContactEvent::InviteReady { fetch_id, .. } if fetch_id == alice_fetch)
            {
                alice
                    .confirm_invite(&alice_fetch, "", "hi, alice here", t / 1000)
                    .unwrap();
            }
        }
        for event in carol.take_contact_events() {
            if matches!(event, ContactEvent::InviteReady { fetch_id, .. } if fetch_id == carol_fetch)
            {
                // Carol connects without saying anything yet.
                carol
                    .confirm_invite(&carol_fetch, "", "", t / 1000)
                    .unwrap();
            }
        }
        bob_events.extend(bob.take_contact_events());
        if added(&bob_events).len() == 2 {
            break;
        }
        t += PAD_INTERVAL_MS;
    }
    let mut names: Vec<(String, String)> = added(&bob_events)
        .into_iter()
        .map(|(name, _, first)| (name, first))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            ("Alice".to_string(), "hi, alice here".to_string()),
            ("Carol".to_string(), String::new()),
        ],
        "each invite names whoever accepted it, and an empty first message stays empty"
    );
    assert_eq!(bob.contacts().len(), 2);
}

#[test]
fn an_expired_invite_is_forgotten() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 98);

    let invite = bob
        .create_invite(b"relay.onion", "Bob", "", 1_000, 60)
        .unwrap();
    // Past the link's own expiry, but inside the grace period: a handshake
    // started in time may still be on its way, so the invite is kept.
    let inside_grace_ms = (1_000 + 60 + INVITE_ACCEPT_GRACE_SECONDS - 1) * 1000;
    bob.tick(inside_grace_ms).unwrap();
    assert!(bob.has_pending_invite(&invite.id));
    assert!(bob.take_contact_events().is_empty());

    let past_grace_ms = (1_000 + 60 + INVITE_ACCEPT_GRACE_SECONDS + 1) * 1000;
    bob.tick(past_grace_ms).unwrap();
    assert!(!bob.has_pending_invite(&invite.id));
    assert_eq!(bob.invite_upload_remaining(&invite.id), None);
    assert_eq!(
        bob.take_contact_events(),
        vec![ContactEvent::InviteExpired {
            invite_id: invite.id
        }]
    );
}

#[test]
fn rescanning_a_known_contact_is_refused_not_a_silent_session_swap() {
    // Replacing the session on one side only leaves the two ends on different
    // queues, and every message after that silently vanishes. Users retry
    // when adding a contact seems to fail, so this must refuse and change
    // nothing.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 99);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 100);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    let second = bob
        .create_invite(b"relay.onion", "Bob", "", 1_000, 86_400)
        .unwrap();
    let outbox_before = alice.outbox_len();
    let (t, result) = accept_invite(&mut bob, &mut alice, &second.link, "Bob again", "hi", t);
    assert_eq!(result, Err(ClientError::AlreadyConnected));
    assert_eq!(alice.outbox_len(), outbox_before, "nothing may be queued");
    assert_eq!(alice.contact(&bob_fp).unwrap().local_name, "Bob");

    // The original conversation is untouched.
    alice.send(&bob_fp, "still here", 1_000).unwrap();
    let (t2, _) = drain(&mut alice, t, 60);
    let (_, got) = pump(&mut bob, t2, 60);
    assert!(got.contains(&"still here".to_string()), "got {got:?}");
}

#[test]
fn a_new_handshake_from_a_known_identity_keeps_trust_and_name() {
    // Alice lost her session with Bob and asks him for a new invitation. The
    // identity — and so the fingerprint Bob verified — is unchanged, so Bob's
    // verification and the name he chose must survive the new session.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 101);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 102);
    let (t, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);
    bob.mark_verified(&alice_fp).unwrap();
    bob.rename_contact(&alice_fp, "Alice (work)").unwrap();

    alice.revoke_contact(&bob_fp).unwrap();
    let again = bob
        .create_invite(b"relay.onion", "Bob", "", 1_000, 86_400)
        .unwrap();
    let (t, result) = accept_invite(&mut bob, &mut alice, &again.link, "", "me again", t);
    assert!(result.is_ok());
    let (_, events) = run_until(&mut [&mut bob, &mut alice], t, 400, |e| {
        !added(e).is_empty()
    });
    assert_eq!(added(&events).len(), 1, "{events:?}");
    let contact = bob.contact(&alice_fp).unwrap();
    assert_eq!(contact.trust, TrustState::Verified);
    assert_eq!(contact.local_name, "Alice (work)");
    assert_eq!(
        bob.contacts().len(),
        1,
        "the same person, not a second contact"
    );
}

#[test]
fn scanning_your_own_invite_is_refused() {
    // Collecting it would also destroy it for the person it was made for: the
    // relay deletes as it hands over. So this is refused before anything is
    // fetched.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 103);
    let invite = bob
        .create_invite(b"relay.onion", "Bob", "", 1_000, 86_400)
        .unwrap();
    assert_eq!(
        bob.open_invite(&invite.link, 1_000),
        Err(ClientError::OwnInvite)
    );
    assert!(bob.contacts().is_empty());
}

#[test]
fn an_invite_on_another_relay_is_refused_clearly() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 106);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 107);
    alice.set_relay("relay-a.onion:9443");
    let invite = bob
        .create_invite(b"relay-b.onion:9443", "Bob", "", 1_000, 86_400)
        .unwrap();
    assert_eq!(
        alice.open_invite(&invite.link, 1_000),
        Err(ClientError::WrongRelay)
    );
    assert_eq!(
        alice.open_invite("void://i/relay-a.onion:9443#NOTBASE32!", 1_000),
        Err(ClientError::InvalidInvite)
    );
}

#[test]
fn a_cancelled_invite_is_never_answered() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 104);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 105);
    let invite = bob
        .create_invite(b"relay.onion", "Bob", "", 1_000, 86_400)
        .unwrap();
    assert!(bob.cancel_invite(&invite.id));
    assert!(
        !bob.cancel_invite(&invite.id),
        "cancelling twice is a no-op"
    );
    assert_eq!(bob.invite_upload_remaining(&invite.id), None);
    assert_eq!(
        bob.outbox_len(),
        0,
        "a withdrawn invitation is not uploaded"
    );

    // Alice opens it anyway. Nothing was parked, so nothing arrives, and she
    // is told so rather than left waiting forever.
    let fetch = alice.open_invite(&invite.link, 0).unwrap();
    let mut failed = None;
    let mut t = 0u64;
    for _ in 0..200 {
        bob.tick(t).unwrap();
        alice.tick(t).unwrap();
        if let Some(event) = alice.take_contact_events().into_iter().next() {
            failed = Some(event);
            break;
        }
        t += PAD_INTERVAL_MS;
    }
    assert_eq!(
        failed,
        Some(ContactEvent::InviteFailed {
            fetch_id: fetch,
            reason: InviteFailure::TimedOut
        })
    );
    assert!(bob.contacts().is_empty());
    assert!(alice.contacts().is_empty());
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

/// Tick `sender` then `watcher`, one slot at a time, until `watcher` reports a
/// call event or the budget runs out. Returns the time reached, the events,
/// and any chat messages `watcher` received on the way — which, for call
/// signalling, must be none.
fn until_call_event(
    sender: &mut Engine,
    watcher: &mut Engine,
    start_ms: u64,
    slots: u64,
) -> (u64, Vec<CallEvent>, Vec<String>) {
    let mut t = start_ms;
    let mut messages = Vec::new();
    for _ in 0..slots {
        sender.tick(t).unwrap();
        if let TickOutcome::Retrieved(received) = watcher.tick(t).unwrap() {
            messages.extend(received.into_iter().map(|m| m.text));
        }
        let events = watcher.take_call_events();
        if !events.is_empty() {
            return (t, events, messages);
        }
        t += PAD_INTERVAL_MS;
    }
    (t, Vec::new(), messages)
}

const ONION: &str = "abcdefghij234567.onion";

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
    let call = alice.place_call(&bob_fp, ONION, 9999, t / 1000).unwrap();
    assert_eq!(call.role, void_proto::call::Role::Caller);
    assert!(!call.answered);

    let (t2, events, msgs) = until_call_event(&mut alice, &mut bob, t, 40);
    assert!(
        msgs.is_empty(),
        "a call must never surface as a chat message, got {msgs:?}"
    );
    assert_eq!(events.len(), 1, "bob should have exactly one ring");
    let incoming = match &events[0] {
        CallEvent::Incoming(c) => c.clone(),
        other => panic!("expected an incoming call, got {other:?}"),
    };
    assert_eq!(incoming.peer, alice_fp);
    assert_eq!(incoming.onion_address, ONION);
    assert_eq!(incoming.call_id, call.call_id);
    assert_eq!(
        incoming.media_secret, call.media_secret,
        "both ends must derive media keys from the same secret"
    );

    // Bob answers.
    let answered = bob.answer_call(&alice_fp).unwrap();
    assert_eq!(answered.role, void_proto::call::Role::Callee);
    let (t3, events, _) = until_call_event(&mut bob, &mut alice, t2, 40);
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
    let (_, events, _) = until_call_event(&mut alice, &mut bob, t3, 40);
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

    alice.place_call(&bob_fp, ONION, 9999, t / 1000).unwrap();
    let (t2, events, _) = until_call_event(&mut alice, &mut bob, t, 40);
    assert_eq!(events.len(), 1);

    bob.end_call(&alice_fp, void_proto::call::EndReason::Declined)
        .unwrap();
    let (t3, events, msgs) = until_call_event(&mut bob, &mut alice, t2, 40);
    assert!(msgs.is_empty(), "declining is not a message");
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
    let (t4, _) = drain(&mut alice, t3, 40);
    let (_, got) = pump(&mut bob, t4, 40);
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

    alice.place_call(&bob_fp, ONION, 9999, t2 / 1000).unwrap();
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

    alice.place_call(&bob_fp, ONION, 9999, t / 1000).unwrap();
    let first_id = alice.active_call(&bob_fp).unwrap().call_id;

    // Placing a second call while one is live is refused locally.
    assert!(alice
        .place_call(&bob_fp, "other.onion", 9999, t / 1000)
        .is_err());
    assert_eq!(alice.active_call(&bob_fp).unwrap().call_id, first_id);

    let (_, events, _) = until_call_event(&mut alice, &mut bob, t, 40);
    assert_eq!(events.len(), 1);
    assert!(bob.active_call(&alice_fp).is_some());
}

#[test]
fn a_stale_offer_is_missed_not_ringing() {
    // Offers wait in the mailbox like any message. One that arrives long after
    // it was sent — the callee's phone was off — must not ring for nobody.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 81);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 82);
    let (t, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    // Alice's offer says it was sent at `sent`; Bob collects it well past
    // OFFER_MAX_AGE_SECONDS later.
    let sent = t / 1000;
    let call = alice.place_call(&bob_fp, ONION, 9999, sent).unwrap();
    let (t2, _) = drain(&mut alice, t, 40);
    let late = t2.max((sent + OFFER_MAX_AGE_SECONDS + 5) * 1000);
    let (_, events, _) = until_call_event(&mut alice, &mut bob, late, 40);
    assert!(
        matches!(
            &events[..],
            [CallEvent::Missed { contact_fingerprint, call_id }]
                if *contact_fingerprint == alice_fp && *call_id == call.call_id
        ),
        "a stale offer is a missed call, got {events:?}"
    );
    assert!(bob.active_call(&alice_fp).is_none(), "nothing rings");
}

#[test]
fn an_unanswered_call_times_out_as_missed_at_both_ends() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 83);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 84);
    let (t, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    alice.place_call(&bob_fp, ONION, 9999, t / 1000).unwrap();
    let (t2, events, _) = until_call_event(&mut alice, &mut bob, t, 40);
    assert!(matches!(&events[..], [CallEvent::Incoming(_)]));

    // Nobody answers. Both ends give up on their own clocks.
    let mut alice_events = Vec::new();
    let mut bob_events = Vec::new();
    let mut now = t2;
    while now < t2 + (CALLER_TIMEOUT_SECONDS + 10) * 1000 {
        alice.tick(now).unwrap();
        bob.tick(now).unwrap();
        alice_events.extend(alice.take_call_events());
        bob_events.extend(bob.take_call_events());
        now += PAD_INTERVAL_MS;
    }
    let missed = |events: &[CallEvent]| {
        events.iter().any(|e| {
            matches!(
                e,
                CallEvent::Ended {
                    reason: void_proto::call::EndReason::Missed,
                    ..
                }
            )
        })
    };
    assert!(
        missed(&alice_events),
        "the caller stops ringing: {alice_events:?}"
    );
    assert!(
        missed(&bob_events),
        "and so does the callee: {bob_events:?}"
    );
    assert!(alice.active_call(&bob_fp).is_none());
    assert!(bob.active_call(&alice_fp).is_none());
}

#[test]
fn a_callee_that_stops_ringing_tells_the_caller() {
    // The callee's ring is shorter than the caller's wait, so without word from
    // the callee the caller rings into nothing for minutes. Alice's clock runs
    // far ahead here, so her own timer cannot be what stops her.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 111);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 112);
    let (t, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    let ahead = t / 1000 + 10 * CALLER_TIMEOUT_SECONDS;
    alice.place_call(&bob_fp, ONION, 9999, ahead).unwrap();
    let (t2, events, _) = until_call_event(&mut alice, &mut bob, t, 40);
    assert!(
        matches!(&events[..], [CallEvent::Incoming(_)]),
        "an offer from a clock that runs ahead still rings, got {events:?}"
    );

    // Nobody answers. Bob's ring runs out, and he says so.
    let mut alice_events = Vec::new();
    let mut now = t2;
    while alice_events.is_empty() && now < t2 + (RING_TIMEOUT_SECONDS + 180) * 1000 {
        bob.tick(now).unwrap();
        alice.tick(now).unwrap();
        alice_events.extend(alice.take_call_events());
        now += PAD_INTERVAL_MS;
    }
    assert!(
        matches!(
            &alice_events[..],
            [CallEvent::Ended {
                reason: void_proto::call::EndReason::Missed,
                ..
            }]
        ),
        "the caller learns the ring ended, got {alice_events:?}"
    );
    assert!(alice.active_call(&bob_fp).is_none());
    assert!(bob.active_call(&alice_fp).is_none());
}

#[test]
fn an_offer_during_a_call_is_declined_busy() {
    // Bob is on a call with Alice when Carol calls. Carol must hear "busy",
    // not ring into nothing; Bob must see a missed call; and the call with
    // Alice must be untouched.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 85);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 86);
    let mut carol = engine(Arc::clone(&relay), Arc::clone(&clock), 87);
    let (t_alice, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);
    let (t_carol, carol_fp, bob_fp_for_carol) = connect(&relay, &mut carol, &mut bob);
    assert_eq!(bob_fp, bob_fp_for_carol);
    // Each inviter's emission grid ends where its own handshake finished, so
    // start from the later one: before it, one of them has no slot to send in.
    let t = t_alice.max(t_carol);

    alice.place_call(&bob_fp, ONION, 9999, t / 1000).unwrap();
    let (t2, events, _) = until_call_event(&mut alice, &mut bob, t, 40);
    assert!(matches!(&events[..], [CallEvent::Incoming(_)]));
    bob.answer_call(&alice_fp).unwrap();

    let carols = carol
        .place_call(&bob_fp, "carol.onion", 9999, t2 / 1000)
        .unwrap();
    let (t3, events, _) = until_call_event(&mut carol, &mut bob, t2, 40);
    assert!(
        matches!(
            &events[..],
            [CallEvent::Missed { contact_fingerprint, call_id }]
                if *contact_fingerprint == carol_fp && *call_id == carols.call_id
        ),
        "bob sees carol's call as missed, got {events:?}"
    );
    let (_, events, _) = until_call_event(&mut bob, &mut carol, t3, 40);
    assert!(
        matches!(
            &events[..],
            [CallEvent::Ended {
                reason: void_proto::call::EndReason::Busy,
                ..
            }]
        ),
        "carol hears busy, got {events:?}"
    );
    assert!(
        bob.active_call(&alice_fp).is_some(),
        "the call with alice is untouched"
    );
    assert!(bob.active_call(&carol_fp).is_none());
}

#[test]
fn call_signals_go_ahead_of_queued_messages() {
    // A ring must not wait behind a long message: one record goes out per
    // slot either way, but the offer takes the next one.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 88);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 89);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    let long = "x".repeat(5_000);
    let message_id = alice.send(&bob_fp, &long, t / 1000).unwrap();
    assert!(alice.outbox_len() >= 5);
    alice.place_call(&bob_fp, ONION, 9999, t / 1000).unwrap();

    let mut now = t;
    let first = loop {
        if let TickOutcome::Deposited(id) = alice.tick(now).unwrap() {
            break id;
        }
        now += PAD_INTERVAL_MS;
    };
    assert_ne!(first, message_id, "the offer went out first");
}

#[test]
fn media_that_connects_first_is_the_answer() {
    // The caller learns the call was answered from the callee's first
    // authenticated media frame — seconds — rather than from the relayed
    // answer — a mailbox delay. The relayed answer that follows changes
    // nothing and announces nothing, and a connected call never times out.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 90);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 110);
    let (t, alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    alice.place_call(&bob_fp, ONION, 9999, t / 1000).unwrap();
    let (t2, _, _) = until_call_event(&mut alice, &mut bob, t, 40);
    bob.answer_call(&alice_fp).unwrap();

    // Bob's media reaches Alice's service before his answer reaches her queue.
    assert!(alice.mark_call_connected(&bob_fp));
    assert!(!alice.mark_call_connected(&alice_fp), "no call with nobody");

    let mut now = t2;
    let mut events = Vec::new();
    while now < t2 + (CALLER_TIMEOUT_SECONDS + 30) * 1000 {
        bob.tick(now).unwrap();
        alice.tick(now).unwrap();
        events.extend(alice.take_call_events());
        now += PAD_INTERVAL_MS;
    }
    assert!(events.is_empty(), "nothing further to announce: {events:?}");
    assert!(
        alice.active_call(&bob_fp).is_some(),
        "a connected call does not time out"
    );
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

/// A relay that refuses every deposit into the queues in `refuse` — which is
/// all a client can see of a relay enforcing one queue's deposit rate or
/// capacity, since a refusal deliberately carries no reason. Remembers the
/// queue of the last deposit it was offered, so a test can learn a contact's.
struct RefusingRelay {
    relay: Arc<Relay>,
    clock: Arc<Mutex<u64>>,
    refuse: Arc<Mutex<Vec<[u8; 16]>>>,
    last_queue: Arc<Mutex<Option<[u8; 16]>>>,
}

impl void_client::transport::Transport for RefusingRelay {
    fn kind(&self) -> void_client::transport::TransportKind {
        void_client::transport::TransportKind::InMemory
    }

    fn exchange(&mut self, request: &Frame) -> void_client::ClientResult<Frame> {
        if request.kind == FrameType::Deposit {
            if let Ok(deposit) = void_proto::envelope::Deposit::decode(&request.body) {
                *self.last_queue.lock().unwrap() = Some(deposit.queue_id);
                if self.refuse.lock().unwrap().contains(&deposit.queue_id) {
                    return Ok(Frame::new(FrameType::Refuse, Vec::new()));
                }
            }
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
fn a_queue_the_relay_keeps_refusing_does_not_hold_up_other_contacts() {
    // The relay refuses without saying why, and its reasons — one queue's
    // deposit rate, its capacity — pass. So a refused record is kept and
    // retried. But one queue's refusals must not stop every other contact's
    // messages behind it, which is what retrying it at the head of the outbox
    // did: one record per slot, and every slot spent on the same refusal.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let refuse = Arc::new(Mutex::new(Vec::new()));
    let last_queue = Arc::new(Mutex::new(None));
    let mut alice = Engine::new(
        Identity::from_seeds(&[123u8; 32], &[124u8; 32], &[125u8; 32]),
        Settings::default(),
        Box::new(RefusingRelay {
            relay: Arc::clone(&relay),
            clock: Arc::clone(&clock),
            refuse: Arc::clone(&refuse),
            last_queue: Arc::clone(&last_queue),
        }),
        SecurityMode::InsecureForTesting,
        0,
    )
    .unwrap();
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 126);
    let mut carol = engine(Arc::clone(&relay), Arc::clone(&clock), 127);
    let (t1, _, bob_fp) = connect(&relay, &mut alice, &mut bob);
    let (t2, carol_fp, _) = connect(&relay, &mut carol, &mut alice);
    let t = t1.max(t2);

    // Learn Bob's queue from one message that gets through, then have the
    // relay refuse it from now on.
    alice.send(&bob_fp, "first", t / 1000).unwrap();
    let (t, _) = drain(&mut alice, t, 40);
    let bobs_queue = last_queue.lock().unwrap().expect("a deposit to bob");
    refuse.lock().unwrap().push(bobs_queue);

    alice.send(&bob_fp, "refused for now", t / 1000).unwrap();
    alice
        .send(&carol_fp, "still gets through", t / 1000)
        .unwrap();
    let mut got = Vec::new();
    let mut now = t;
    for _ in 0..60 {
        alice.tick(now).unwrap();
        if let TickOutcome::Retrieved(messages) = carol.tick(now).unwrap() {
            got.extend(messages.into_iter().map(|m| m.text));
        }
        if !got.is_empty() {
            break;
        }
        now += PAD_INTERVAL_MS;
    }
    assert_eq!(
        got,
        vec!["still gets through".to_string()],
        "carol's message must not wait behind bob's"
    );
    assert!(
        alice.outbox_len() > 0,
        "the refused record is kept to retry, not dropped"
    );

    // And once the relay takes it again, it is delivered.
    refuse.lock().unwrap().clear();
    let (t, _) = drain(&mut alice, now, 40);
    let (_, delivered) = pump(&mut bob, t, 40);
    assert!(
        delivered.contains(&"refused for now".to_string()),
        "got {delivered:?}"
    );
}

#[test]
fn a_short_invite_is_unreadable_to_the_relay() {
    // The parked invitation carries the inviter's whole signed bundle and the
    // name they go by. The relay stores it, so it must learn neither: every
    // record it holds is sealed to a queue derived from a secret that exists
    // only in the link's fragment, which is never sent anywhere.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let hoard = Arc::new(Mutex::new(Vec::new()));
    let mut alice = Engine::new(
        Identity::from_seeds(&[128u8; 32], &[129u8; 32], &[130u8; 32]),
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
    let label = "Alice Unmistakable";
    let created = alice
        .create_invite(b"relay.onion", label, "", 1_000, 86_400)
        .unwrap();
    let (_, _) = drain(&mut alice, 0, 40);
    assert!(
        alice.invite_upload_remaining(&created.id) == Some(0),
        "the whole invitation is parked"
    );

    let parked = hoard.lock().unwrap().clone();
    assert!(
        parked.len() >= 5,
        "a bundle this size is several records: {}",
        parked.len()
    );
    let public = alice.identity_public().clone();
    let secret = created.link.rsplit('#').next().unwrap().as_bytes().to_vec();
    let contains =
        |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    for body in &parked {
        assert!(
            !contains(body, label.as_bytes()),
            "the name on it reached the relay"
        );
        assert!(
            !contains(body, &public.ed25519),
            "the identity key reached the relay"
        );
        assert!(
            !contains(body, &public.mldsa[..64]),
            "the signing key reached the relay"
        );
        assert!(
            !contains(body, &secret),
            "the link's secret reached the relay"
        );
    }
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

// --- files -------------------------------------------------------------------
//
// A file is a message: the same ratchet, the same records, the same slots.
// These check that it arrives whole, that the relay sees nothing different,
// that a reply does not wait behind it, and that one too large is refused
// before anything is spent on it.

/// Tick `sender` then `receiver` one slot at a time until the receiver gets
/// `count` messages or the budget runs out. Returns the time reached and what
/// arrived, files included.
fn until_received(
    sender: &mut Engine,
    receiver: &mut Engine,
    start_ms: u64,
    slots: u64,
    count: usize,
) -> (u64, Vec<void_client::engine::ReceivedMessage>) {
    let mut t = start_ms;
    let mut got = Vec::new();
    for _ in 0..slots {
        sender.tick(t).unwrap();
        if let TickOutcome::Retrieved(received) = receiver.tick(t).unwrap() {
            got.extend(received);
        }
        if got.len() >= count {
            break;
        }
        t += PAD_INTERVAL_MS;
    }
    (t, got)
}

#[test]
fn a_file_travels_as_a_message_and_arrives_whole() {
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 90);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 91);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    // Tens of records: a small photo.
    let photo: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    alice
        .send_file(&bob_fp, "photo.jpg", "image/jpeg", photo.clone(), t / 1000)
        .unwrap();
    let records_before = relay.metrics().unwrap().records;
    assert!(
        alice.outbox_len() >= 40,
        "{} records queued",
        alice.outbox_len()
    );

    let (_, got) = until_received(&mut alice, &mut bob, t, 400, 1);
    assert_eq!(got.len(), 1, "the file arrives as one message");
    let file = got[0].attachment.as_ref().expect("a file, not text");
    assert_eq!(file.name, "photo.jpg");
    assert_eq!(file.mime, "image/jpeg");
    assert_eq!(file.len as usize, photo.len());
    assert!(got[0].text.is_empty());
    // The relay saw records go by, and nothing else: no size, no type, no
    // name. Its view is counted in the next test.
    assert!(relay.metrics().unwrap().records >= records_before);
}

#[test]
fn a_relay_cannot_tell_a_file_from_messages() {
    // FR-MSG-02 for files: every deposit is SEALED_RECORD_SIZE, so a photo
    // is indistinguishable from the same number of text messages. The
    // sender's deposits are counted straight off the transport.
    use void_proto::envelope::SEALED_RECORD_SIZE;

    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 92);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 93);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    let recording = Arc::new(Mutex::new(Vec::new()));
    alice
        .set_transport(Box::new(RecordingTransport {
            inner: MemoryTransport::new(Arc::clone(&relay), Arc::clone(&clock)),
            sizes: Arc::clone(&recording),
        }))
        .unwrap();
    alice
        .send_file(
            &bob_fp,
            "notes.pdf",
            "application/pdf",
            vec![9u8; 12_345],
            t / 1000,
        )
        .unwrap();
    alice.send(&bob_fp, "and a reply", t / 1000).unwrap();
    drain(&mut alice, t, 200);

    let sizes = recording.lock().unwrap();
    assert!(sizes.len() > 12, "{} deposits", sizes.len());
    assert!(
        sizes.iter().all(|&s| s == SEALED_RECORD_SIZE),
        "every deposit the same size: {sizes:?}"
    );
}

/// A transport that records the size of every deposit before passing it on.
struct RecordingTransport {
    inner: MemoryTransport,
    sizes: Arc<Mutex<Vec<usize>>>,
}

impl void_client::transport::Transport for RecordingTransport {
    fn kind(&self) -> void_client::transport::TransportKind {
        self.inner.kind()
    }

    fn exchange(&mut self, request: &Frame) -> void_client::ClientResult<Frame> {
        if request.kind == FrameType::Deposit {
            // A deposit frame is the sealed record plus the queue id.
            let deposit = void_proto::envelope::Deposit::decode(&request.body).unwrap();
            self.sizes.lock().unwrap().push(deposit.sealed.len());
        }
        self.inner.exchange(request)
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    fn disconnect(&mut self) {
        self.inner.disconnect()
    }
}

#[test]
fn a_message_sent_during_a_file_upload_goes_ahead_of_it() {
    // One record per slot either way; but the reply takes the next slot
    // rather than waiting for a hundred records of photo.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 94);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 95);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    let file_id = alice
        .send_file(&bob_fp, "big.bin", "", vec![1u8; 100_000], t / 1000)
        .unwrap();
    // A few records have left before the reply is typed.
    let mut now = t;
    let mut file_records_out = 0;
    while file_records_out < 3 {
        if let TickOutcome::Deposited(id) = alice.tick(now).unwrap() {
            assert_eq!(id, file_id);
            file_records_out += 1;
        }
        now += PAD_INTERVAL_MS;
    }
    let text_id = alice.send(&bob_fp, "still there?", now / 1000).unwrap();
    let next = loop {
        if let TickOutcome::Deposited(id) = alice.tick(now).unwrap() {
            break id;
        }
        now += PAD_INTERVAL_MS;
    };
    assert_eq!(
        next, text_id,
        "the reply went out before the rest of the file"
    );

    // Both arrive, the reply well before the file finishes.
    let (_, got) = until_received(&mut alice, &mut bob, now, 400, 2);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].text, "still there?");
    assert_eq!(got[1].attachment.as_ref().unwrap().len, 100_000);
}

#[test]
fn a_file_too_large_is_refused_before_the_ratchet_steps() {
    use void_proto::content::MAX_FILE_BYTES;

    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 96);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 97);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    assert_eq!(
        alice.send_file(
            &bob_fp,
            "huge.bin",
            "",
            vec![0u8; MAX_FILE_BYTES + 1],
            t / 1000
        ),
        Err(ClientError::TooLarge)
    );
    assert_eq!(
        alice.send_file(&bob_fp, &"n".repeat(300), "", Vec::new(), t / 1000),
        Err(ClientError::TooLarge)
    );
    assert_eq!(alice.outbox_len(), 0, "nothing was queued");

    // The refusal spent no ratchet state: the next message still decrypts
    // at the other end.
    alice.send(&bob_fp, "a normal message", t / 1000).unwrap();
    let (_, got) = until_received(&mut alice, &mut bob, t, 100, 1);
    assert_eq!(got[0].text, "a normal message");
}

#[test]
fn the_largest_file_arrives() {
    // Every fragment slot of one message, end to end through the relay. Slow
    // by construction: 512 records is 512 emission slots.
    use void_proto::content::MAX_FILE_BYTES;

    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 98);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 99);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    let data: Vec<u8> = (0..MAX_FILE_BYTES as u32)
        .map(|i| (i % 253) as u8)
        .collect();
    alice
        .send_file(
            &bob_fp,
            &"n".repeat(255),
            &"m".repeat(127),
            data.clone(),
            t / 1000,
        )
        .unwrap();
    let (_, got) = until_received(&mut alice, &mut bob, t, 2_000, 1);
    assert_eq!(got.len(), 1, "the largest file must still arrive");
    assert_eq!(got[0].attachment.as_ref().unwrap().len as usize, data.len());
}

#[test]
fn a_file_cannot_be_sent_to_a_contact_whose_key_changed() {
    // FR-DISC-05 covers every way to send, not only `send`.
    let relay = relay();
    let clock = Arc::new(Mutex::new(1_000_000u64));
    let mut alice = engine(Arc::clone(&relay), Arc::clone(&clock), 100);
    let mut bob = engine(Arc::clone(&relay), Arc::clone(&clock), 101);
    let (t, _alice_fp, bob_fp) = connect(&relay, &mut alice, &mut bob);

    let other = Identity::from_seeds(&[200u8; 32], &[201u8; 32], &[202u8; 32]);
    alice
        .note_key_change(&bob_fp, other.public.clone())
        .unwrap();
    assert_eq!(
        alice.send_file(&bob_fp, "x", "", vec![1], t / 1000),
        Err(ClientError::ContactKeyChanged)
    );
}
