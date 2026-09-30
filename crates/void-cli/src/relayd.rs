//! `void-relayd` — the mailbox relay daemon.
//!
//! ## Operating a relay
//!
//! The relay binds a loopback port and expects a Tor onion service to forward
//! to it. It never binds a public interface, and it never learns a client IP,
//! because Tor does not give it one. A typical `torrc` fragment:
//!
//! ```text
//! HiddenServiceDir /var/lib/tor/void-relay/
//! HiddenServicePort 9443 127.0.0.1:9443
//! ```
//!
//! The generated `hostname` is the relay's address *and* its public key —
//! FR-TRANS-04's pinning is satisfied by clients knowing that string, with no
//! certificate authority anywhere.
//!
//! ## There is no key registry
//!
//! Retrieval authority is verified intrinsically: a queue identifier is a hash
//! of an Ed25519 public key, and a collector presents that key plus a signature
//! over a relay-issued challenge. So this daemon stores no verification keys,
//! has no registration step, and has no first-registration race. A seized relay
//! yields sealed blobs and nothing else.
//!
//! ## What an operator can and cannot see
//!
//! Cannot: message contents, who sent anything, any client's IP address, or
//! — from the queue ids themselves — which queues belong to one person. Can:
//! that a fixed-size blob was deposited into an opaque queue id, and that one
//! was later collected. `void_relay::store` is written so that adding to that
//! list requires an obvious code change.
//!
//! One thing this daemon deliberately does not record, but an operator who
//! modified it could: which queues one connection collects, in one burst.
//! That groups a client's queues together, and pairing the connection that
//! deposits into a queue with the one that collects from it is a contact edge.
//! See "Retrieval shape" under *Open* in docs/DECISIONS.md.
//!
//! The metrics this daemon prints are aggregate counts only. There is
//! deliberately no per-queue reporting: an operator who could watch one queue's
//! activity would have a surveillance capability the design promises not to
//! build.

use std::sync::Arc;

use void_proto::wake::WakeSecret;
use void_relay::server::{self, NoPush, PushSender, Relay};
use void_relay::store::Config;

/// A push sender that logs what it would have sent.
///
/// A real deployment substitutes an APNs/FCM client here. Note the signature:
/// it receives a rotating wake identifier and a delay, and nothing else. There
/// is no parameter it could use to include a sender, a preview, or a queue,
/// which is FR-NOTIF-01 enforced by the type system rather than by discipline.
struct LoggingPush;

impl PushSender for LoggingPush {
    fn wake(&self, wake_id: &[u8; 16], delay_seconds: u64) {
        // Only the first four bytes, and only at debug level: a relay log full
        // of wake identifiers is a record we promised not to keep.
        eprintln!(
            "wake {}… in {delay_seconds}s",
            void_crypto::sha2::hex(&wake_id[..4])
        );
    }
}

fn usage() -> ! {
    eprintln!(
        "\
void-relayd — Void mailbox relay

Usage:
  void-relayd [--listen ADDR] [--ttl-days N] [--rate N]

Options:
  --listen ADDR   Loopback address to bind (default 127.0.0.1:9443).
                  Point a Tor onion service at this; never expose it directly.
  --ttl-days N    How long an undelivered record is held (default 14).
  --rate N        Deposits allowed per queue per hour (default 600).

The relay stores sealed blobs against opaque queue ids. It cannot read them,
cannot tell who deposited them, and keeps no record linking one client's
queues (docs/DECISIONS.md, \"Retrieval shape\", says what a modified relay could).
"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen = "127.0.0.1:9443".to_string();
    let mut ttl_days = 14u64;
    let mut rate = 600u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                listen = args[i + 1].clone();
                i += 2;
            }
            "--ttl-days" if i + 1 < args.len() => {
                ttl_days = args[i + 1].parse().unwrap_or_else(|_| usage());
                i += 2;
            }
            "--rate" if i + 1 < args.len() => {
                rate = args[i + 1].parse().unwrap_or_else(|_| usage());
                i += 2;
            }
            _ => usage(),
        }
    }

    if !listen.starts_with("127.0.0.1:") && !listen.starts_with("[::1]:") {
        eprintln!(
            "Refusing to bind {listen}: the relay must listen on loopback only, \n\
             with a Tor onion service forwarding to it. Binding a public interface \n\
             would expose client IP addresses that the design promises never to see."
        );
        std::process::exit(1);
    }

    let config = Config {
        ttl_seconds: ttl_days * 24 * 60 * 60,
        deposit_rate_per_hour: rate,
        ..Config::default()
    };

    let push: Box<dyn PushSender> = if std::env::var("VOID_PUSH_LOG").is_ok() {
        Box::new(LoggingPush)
    } else {
        // FR-NOTIF-04 makes push opt-in, so a relay with no push configured is
        // a perfectly valid deployment and the default.
        Box::new(NoPush)
    };

    let relay = Arc::new(Relay::new(config, push));

    // Retention sweep (FR-MSG-08) and wake-registration expiry.
    let sweeper = Arc::clone(&relay);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(300));
        let now = server::now();
        let epoch = WakeSecret::epoch(now);
        match sweeper.sweep(now, epoch) {
            Ok(n) if n > 0 => eprintln!("swept {n} expired records"),
            Ok(_) => {}
            Err(e) => eprintln!("sweep failed: {e}"),
        }
    });

    eprintln!("void-relayd listening on {listen}");
    eprintln!("ttl: {ttl_days}d, rate limit: {rate}/queue/hour");
    eprintln!("Point a Tor onion service at this address.");

    if let Err(e) = server::listen(relay, &listen) {
        eprintln!("relay stopped: {e}");
        std::process::exit(1);
    }
}
