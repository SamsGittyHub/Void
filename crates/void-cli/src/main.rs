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

use void_client::engine::{ContactEvent, Engine, SecurityMode, TickOutcome};
use void_client::transport::{TcpTransport, Transport};
use void_proto::fingerprint;
use void_proto::identity::Identity;
use void_proto::invite;
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

    let invite = engine
        .create_invite(
            addr.as_bytes(),
            "void-cli",
            "",
            now_secs(),
            invite::DEFAULT_INVITE_TTL_SECONDS,
        )
        .expect("invite");

    println!("Send this link to the person you want to talk to.");
    println!("It works once, and expires in 24 hours.\n");
    println!("{}\n", invite.link);
    println!(
        "Your security code:\n{}\n",
        fingerprint::to_words(&engine.fingerprint())
    );
    println!("Waiting for them to accept…");

    wait_for_contact(&mut engine);
}

/// Tick until someone accepts the invitation.
///
/// The engine polls its own intro queues inside the scheduler's retrieval
/// slot and keeps a partly arrived handshake between polls, so there is
/// nothing to do here but keep ticking and watch for the contact.
fn wait_for_contact(engine: &mut Engine) {
    loop {
        match engine.tick(now_ms()) {
            Ok(TickOutcome::Waiting(d)) => std::thread::sleep(d),
            Ok(TickOutcome::Offline) | Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(PAD_INTERVAL_MS));
            }
            Ok(_) => {}
        }
        // The CLI makes exactly one invitation, so the first event is the only
        // one there can be.
        if let Some(event) = engine.take_contact_events().into_iter().next() {
            match event {
                ContactEvent::Added {
                    contact_fingerprint,
                    first_message,
                    ..
                } => {
                    println!("\nConnected.");
                    println!(
                        "Their security code:\n{}\n",
                        fingerprint::to_words(&contact_fingerprint)
                    );
                    println!("Compare it with them out of band before trusting it.\n");
                    if !first_message.is_empty() {
                        println!("< {first_message}");
                    }
                    chat_loop(engine, contact_fingerprint);
                    return;
                }
                ContactEvent::InviteExpired { .. } => {
                    eprintln!("The invitation expired before anyone accepted it.");
                    std::process::exit(1);
                }
                // Only an invitation this side opens produces these, and the
                // inviting side opens none.
                ContactEvent::InviteReady { .. } | ContactEvent::InviteFailed { .. } => {}
            }
        }
    }
}

fn cmd_accept(addr: &str, link: &str) {
    let id = identity_from_env();
    let mut engine = Engine::new(
        id,
        Settings::default(),
        connect(addr),
        SecurityMode::InsecureForTesting,
        now_ms(),
    )
    .expect("engine");
    engine.set_relay(addr);

    let fetch = match engine.open_invite(link, now_secs()) {
        Ok(fetch) => fetch,
        Err(e) => {
            eprintln!("The invitation could not be opened: {e}");
            std::process::exit(1);
        }
    };
    println!("Collecting the invitation from the relay…");

    let fp = 'collect: loop {
        match engine.tick(now_ms()) {
            Ok(TickOutcome::Waiting(d)) => std::thread::sleep(d),
            Ok(TickOutcome::Offline) | Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(PAD_INTERVAL_MS));
            }
            Ok(_) => {}
        }
        for event in engine.take_contact_events() {
            match event {
                ContactEvent::InviteReady {
                    inviter_label,
                    inviter_fingerprint,
                    ..
                } => {
                    println!(
                        "Their security code:\n{}\n",
                        fingerprint::to_words(&inviter_fingerprint)
                    );
                    println!("Compare it with them out of band before trusting it.\n");
                    match engine.confirm_invite(&fetch, &inviter_label, "hello", now_secs()) {
                        Ok(fp) => break 'collect fp,
                        Err(e) => {
                            eprintln!("Could not connect: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                ContactEvent::InviteFailed { reason, .. } => {
                    eprintln!("The invitation could not be used: {reason:?}");
                    std::process::exit(1);
                }
                _ => {}
            }
        }
    };
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
                std::thread::sleep(std::time::Duration::from_millis(PAD_INTERVAL_MS));
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
