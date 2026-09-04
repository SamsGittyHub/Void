//! `void` — the reference CLI client.
//!
//! This is the Phase 2 deliverable from PRD §11: a client that exchanges
//! messages with another client through a relay, end to end. It is a
//! development and audit tool, not a product — the products are the iOS and
//! Android apps in `ios/` and `android/`.
//!
//! ## It prints a warning constantly, on purpose
//!
//! The CLI connects over plain TCP, not Tor. That makes it useful for
//! development and useless for safety, so every invocation says so and
//! [`SecurityMode::InsecureForTesting`] is passed explicitly rather than
//! defaulted. A tool that is *quietly* insecure is how a bypass ends up in a
//! release.

use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use void_client::engine::{Engine, SecurityMode, TickOutcome};
use void_client::transport::{TcpTransport, Transport};
use void_proto::fingerprint;
use void_proto::identity::Identity;
use void_proto::invite::{self, Invite};
use void_proto::queue::QueueSecret;
use void_proto::record::PAD_INTERVAL_MS;
use void_store::model::Settings;

const INSECURE_BANNER: &str = "\
┌────────────────────────────────────────────────────────────────────────┐
│  This is the Void development CLI. It connects over plain TCP.         │
│  It is NOT routed through Tor and provides NO anonymity.               │
│  Do not use it for anything that matters. Use the iOS or Android app.  │
└────────────────────────────────────────────────────────────────────────┘";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn usage() -> ! {
    eprintln!(
        "{INSECURE_BANNER}

Usage:
  void identity                        Generate an identity and print its fingerprint
  void invite   <relay-addr>           Publish an invitation link and wait for a reply
  void accept   <relay-addr> <link>    Accept an invitation and start a conversation
  void chat     <relay-addr>           Interactive chat (after invite/accept)
  void verify   <fingerprint-words>    Compare a fingerprint you were read aloud

Environment:
  VOID_SEED   32 hex bytes; the identity seed. Generated if unset.
"
    );
    std::process::exit(2);
}

fn identity_from_env() -> Identity {
    match std::env::var("VOID_SEED")
        .ok()
        .and_then(|s| void_crypto::sha2::unhex(&s).filter(|v| v.len() == 32))
    {
        Some(v) => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&v);
            // Three independent seeds derived from the one the user supplied,
            // so a single memorable value reconstructs the whole identity.
            let ed = void_crypto::blake3::derive_key_32("void/v1/cli/ed", &seed);
            let pq = void_crypto::blake3::derive_key_32("void/v1/cli/mldsa", &seed);
            let x = void_crypto::blake3::derive_key_32("void/v1/cli/x25519", &seed);
            Identity::from_seeds(&ed, &pq, &x)
        }
        None => Identity::generate().expect("system entropy unavailable"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    eprintln!("{INSECURE_BANNER}\n");

    match args[0].as_str() {
        "identity" => cmd_identity(),
        "invite" if args.len() >= 2 => cmd_invite(&args[1]),
        "accept" if args.len() >= 3 => cmd_accept(&args[1], &args[2]),
        "verify" if args.len() >= 2 => cmd_verify(&args[1..].join(" ")),
        _ => usage(),
    }
}

fn cmd_identity() {
    let id = identity_from_env();
    let fp = id.fingerprint();
    println!("Your security code — read these aloud to compare:\n");
    println!("{}\n", fingerprint::to_words(&fp));
    println!("Or as numbers:\n");
    println!("{}\n", fingerprint::to_numbers(&fp));
    println!("Set VOID_SEED to reuse this identity across runs.");
}

fn connect(addr: &str) -> Box<dyn Transport> {
    match TcpTransport::connect(addr) {
        Ok(t) => Box::new(t),
        Err(_) => {
            // FR-TRANS-05: fail closed. There is no fallback to try.
            eprintln!("Could not reach the relay at {addr}. Messages would queue.");
            std::process::exit(1);
        }
    }
}

fn cmd_invite(addr: &str) {
    let id = identity_from_env();
    let mut engine = Engine::new(
        id,
        Settings::default(),
        connect(addr),
        SecurityMode::InsecureForTesting,
        now_ms(),
    )
    .expect("engine");

    let (bundle, intro_queue) = engine.create_bundle(addr.as_bytes()).expect("bundle");
    let inv = invite::create(
        &bundle,
        now_secs(),
        invite::DEFAULT_INVITE_TTL_SECONDS,
        "void-cli",
    )
    .expect("invite");

    println!("Send this link to the person you want to talk to.");
    println!("It works once, and expires in 24 hours.\n");
    println!("{}\n", inv.to_link());
    println!(
        "Your security code:\n{}\n",
        fingerprint::to_words(&engine.fingerprint())
    );
    println!("Waiting for them to accept…");

    wait_for_handshake(&mut engine, &bundle, &intro_queue, addr);
}

fn wait_for_handshake(
    engine: &mut Engine,
    bundle: &void_proto::handshake::PrekeyBundle,
    intro_queue: &QueueSecret,
    addr: &str,
) {
    // Poll the introduction queue directly: the handshake arrives before any
    // session exists, so the engine's per-session retrieval does not cover it.
    let mut transport = connect(addr);
    loop {
        if let Some(initial) = poll_intro_queue(&mut *transport, intro_queue) {
            match engine.accept_conversation(bundle.queue.queue_id, &initial, now_secs()) {
                Ok((fp, first)) => {
                    println!("\nConnected.");
                    println!("Their security code:\n{}\n", fingerprint::to_words(&fp));
                    println!("Compare it with them out of band before trusting it.\n");
                    println!("< {first}");
                    chat_loop(engine, fp);
                    return;
                }
                Err(e) => {
                    eprintln!("Handshake failed: {e}");
                    return;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(PAD_INTERVAL_MS));
    }
}

fn poll_intro_queue(transport: &mut dyn Transport, queue: &QueueSecret) -> Option<Vec<u8>> {
    use void_relay::protocol::{Delivery, Frame, FrameType, Retrieve};

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

fn cmd_accept(addr: &str, link: &str) {
    let id = identity_from_env();
    let inv = match Invite::from_link(link) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("That does not look like a Void invitation: {e}");
            std::process::exit(1);
        }
    };
    let body = match invite::open(&inv, now_secs()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("The invitation could not be opened: {e}");
            std::process::exit(1);
        }
    };

    let mut engine = Engine::new(
        id,
        Settings::default(),
        connect(addr),
        SecurityMode::InsecureForTesting,
        now_ms(),
    )
    .expect("engine");

    println!(
        "Their security code:\n{}\n",
        fingerprint::to_words(&body.bundle.identity.fingerprint())
    );
    println!("Compare it with them out of band before trusting it.\n");

    let fp = engine
        .start_conversation(&body.bundle, &body.label, "hello", now_secs())
        .expect("handshake");
    println!(
        "Your security code:\n{}\n",
        fingerprint::to_words(&engine.fingerprint())
    );
    chat_loop(&mut engine, fp);
}

fn chat_loop(engine: &mut Engine, peer: [u8; 32]) {
    println!("Type a message and press enter. Ctrl-D to quit.\n");

    let outbox = Arc::new(Mutex::new(Vec::<String>::new()));
    let outbox_reader = Arc::clone(&outbox);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(text) if !text.trim().is_empty() => {
                    outbox_reader.lock().unwrap().push(text);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        std::process::exit(0);
    });

    loop {
        // Hand anything typed to the engine, which queues it for the next
        // scheduled slot rather than sending immediately — that is what keeps
        // send timing independent of typing timing.
        let pending: Vec<String> = {
            let mut g = outbox.lock().unwrap();
            g.drain(..).collect()
        };
        for text in pending {
            if let Err(e) = engine.send(&peer, &text, now_secs()) {
                eprintln!("! {e}");
            }
        }

        match engine.tick(now_ms()) {
            Ok(TickOutcome::Retrieved(msgs)) => {
                for m in msgs {
                    println!("< {}", m.text);
                    let _ = std::io::stdout().flush();
                }
            }
            Ok(TickOutcome::Offline) => {
                eprintln!("! offline — messages are queued, nothing is being sent in the clear");
            }
            Ok(TickOutcome::Waiting(d)) => std::thread::sleep(d),
            Ok(_) => {}
            Err(e) => {
                eprintln!("! {e}");
                std::thread::sleep(std::time::Duration::from_millis(PAD_INTERVAL_MS));
            }
        }
    }
}

fn cmd_verify(input: &str) {
    let id = identity_from_env();
    let mine = id.fingerprint();
    if fingerprint::verify_match(&mine, input) {
        println!("MATCH — this is the code for the identity in VOID_SEED.");
    } else {
        println!("NO MATCH — the codes are different.");
        println!("\nThis can mean they reinstalled Void or switched devices.");
        println!("It can also mean someone is intercepting the conversation.");
        std::process::exit(1);
    }
}
