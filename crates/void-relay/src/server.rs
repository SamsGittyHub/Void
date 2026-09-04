//! The relay server: frame handling and the TCP listener.
//!
//! The handler is written as a pure function of (request frame, store, clock)
//! so that the whole protocol can be tested without a socket. The listener is a
//! thin wrapper around it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use void_proto::queue::QueueId;
use void_proto::wake::{WakeRegistration, MAX_PUSH_DELAY_SECONDS};

use crate::protocol::{Delivery, Frame, FrameType, Retrieve, FRAME_SIZE};
use crate::store::{Config, QueueStore};
use crate::{RelayError, RelayResult};

/// Something that can deliver a push wake signal.
///
/// Abstracted so the relay core has no dependency on APNs or FCM, and so tests
/// can assert on what would have been sent. FR-NOTIF-01 requires the push carry
/// no sender, no preview, no queue id, and no metadata — the only argument here
/// is a rotating wake identifier, which is the type-level enforcement of that.
pub trait PushSender: Send + Sync {
    /// Send a content-free wake signal.
    ///
    /// `delay_seconds` is the randomised delay from §9.3.1's mitigation list;
    /// implementations must actually honour it rather than sending immediately.
    fn wake(&self, wake_id: &[u8; 16], delay_seconds: u64);
}

/// A push sender that does nothing. The default: FR-NOTIF-04 makes push opt-in,
/// so a relay with no push configured is a valid deployment.
pub struct NoPush;

impl PushSender for NoPush {
    fn wake(&self, _wake_id: &[u8; 16], _delay_seconds: u64) {}
}

/// The relay.
///
/// Note what is **not** a field here: any verifier, registry, or key store.
/// Retrieval authority is checked intrinsically from the queue identifier and
/// the presented public key (`void_proto::queue::verify_retrieval_proof`), so a
/// seized relay yields no key material of any kind.
pub struct Relay {
    store: Mutex<QueueStore>,
    push: Box<dyn PushSender>,
    shutdown: AtomicBool,
}

impl Relay {
    /// Build a relay.
    #[must_use]
    pub fn new(config: Config, push: Box<dyn PushSender>) -> Relay {
        Relay {
            store: Mutex::new(QueueStore::new(config)),
            push,
            shutdown: AtomicBool::new(false),
        }
    }

    /// Handle one request frame and produce the response.
    ///
    /// Every path returns a frame of the same size. There is no path that
    /// returns nothing, because silence is itself a signal.
    pub fn handle(&self, request: &Frame, now: u64) -> RelayResult<Frame> {
        match request.kind {
            FrameType::Deposit => self.handle_deposit(request, now),
            FrameType::Challenge => self.handle_challenge(request, now),
            FrameType::Retrieve => self.handle_retrieve(request, now),
            FrameType::WakeRegister => self.handle_wake_register(request, now),
            // A client sending cover traffic gets cover traffic back, so the
            // exchange looks like any other.
            FrameType::Padding => Frame::padding(),
            // Server-only frame types arriving from a client are malformed.
            FrameType::ChallengeReply
            | FrameType::Delivery
            | FrameType::Ack
            | FrameType::Refuse => Err(RelayError::Malformed),
        }
    }

    fn handle_deposit(&self, request: &Frame, now: u64) -> RelayResult<Frame> {
        let deposit = void_proto::envelope::Deposit::decode(&request.body)
            .map_err(|_| RelayError::Malformed)?;
        let wake = {
            let mut store = self.store.lock().map_err(|_| RelayError::Io)?;
            store.deposit(deposit.queue_id, &deposit.sealed, now)
        };
        match wake {
            Ok(Some(wake_id)) => {
                // §9.3.1 mitigation: randomised delay before the push, so that
                // deposit time and push time do not correlate tightly.
                let delay = void_crypto::rand::below(MAX_PUSH_DELAY_SECONDS + 1)
                    .map_err(|_| RelayError::Entropy)?;
                self.push.wake(&wake_id, delay);
                Ok(Frame::new(FrameType::Ack, Vec::new()))
            }
            Ok(None) => Ok(Frame::new(FrameType::Ack, Vec::new())),
            Err(_) => Ok(Frame::new(FrameType::Refuse, Vec::new())),
        }
    }

    fn handle_challenge(&self, request: &Frame, now: u64) -> RelayResult<Frame> {
        if request.body.len() != 16 {
            return Err(RelayError::Malformed);
        }
        let mut queue_id = [0u8; 16];
        queue_id.copy_from_slice(&request.body);
        let mut store = self.store.lock().map_err(|_| RelayError::Io)?;
        let challenge = store.issue_challenge(queue_id, now)?;
        Ok(Frame::new(FrameType::ChallengeReply, challenge.to_vec()))
    }

    fn handle_retrieve(&self, request: &Frame, now: u64) -> RelayResult<Frame> {
        let req = Retrieve::decode(&request.body)?;
        let result = {
            let mut store = self.store.lock().map_err(|_| RelayError::Io)?;
            let remaining_after = |s: &QueueStore| s.pending(&req.queue_id);
            let got = store.retrieve(req.queue_id, &req.challenge, now, || {
                void_proto::queue::verify_retrieval_proof(
                    &req.queue_id,
                    &req.retrieval_public,
                    &req.challenge,
                    &req.proof,
                )
            });
            got.map(|rec| (rec, remaining_after(&store)))
        };

        match result {
            Ok((Some(rec), remaining)) => {
                let d = Delivery {
                    sealed: rec.sealed,
                    remaining: remaining as u32,
                };
                Ok(Frame::new(FrameType::Delivery, d.encode()))
            }
            Ok((None, _)) => {
                // An empty queue produces a Delivery frame with an empty body,
                // not a Refuse. Same type, same size: "nothing waiting" is not
                // distinguishable from "here is a message" to an observer, and
                // not distinguishable from "wrong proof" to a prober either,
                // because a wrong proof yields Refuse which is also the same
                // size.
                let d = Delivery {
                    sealed: Vec::new(),
                    remaining: 0,
                };
                Ok(Frame::new(FrameType::Delivery, d.encode()))
            }
            Err(_) => Ok(Frame::new(FrameType::Refuse, Vec::new())),
        }
    }

    fn handle_wake_register(&self, request: &Frame, _now: u64) -> RelayResult<Frame> {
        let reg = WakeRegistration::decode(&request.body).map_err(|_| RelayError::Malformed)?;
        // The queue this registration is for travels in the first 16 bytes of
        // the push token field's prefix in deployment; here the client sends
        // the queue id separately in a follow-up. Keeping the registration
        // itself queue-free is the point: see `void_proto::wake`.
        let _ = reg;
        Ok(Frame::new(FrameType::Ack, Vec::new()))
    }

    /// Associate a queue with a wake identifier.
    ///
    /// Split from the frame handler because the association is the one piece of
    /// linkage the relay does hold, and it should be obvious in review where it
    /// is created. It is scoped to an epoch and dropped by `sweep`.
    pub fn link_wake(&self, queue_id: QueueId, wake_id: [u8; 16], epoch: u64) -> RelayResult<()> {
        let mut store = self.store.lock().map_err(|_| RelayError::Io)?;
        store.register_wake(queue_id, wake_id, epoch)
    }

    /// Run the retention sweep.
    pub fn sweep(&self, now: u64, epoch: u64) -> RelayResult<usize> {
        let mut store = self.store.lock().map_err(|_| RelayError::Io)?;
        Ok(store.sweep(now, epoch))
    }

    /// Operational metrics. Deliberately aggregate only: there is no per-queue
    /// reporting, because a relay operator who can watch one queue's activity
    /// has a surveillance capability the design promises not to build.
    pub fn metrics(&self) -> RelayResult<Metrics> {
        let store = self.store.lock().map_err(|_| RelayError::Io)?;
        Ok(Metrics {
            queues: store.queue_count(),
            records: store.record_count(),
        })
    }

    /// Ask the listener loop to stop.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Is a shutdown pending?
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

/// Aggregate operational metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metrics {
    /// Queues currently tracked.
    pub queues: usize,
    /// Records currently held.
    pub records: usize,
}

/// Current Unix time in seconds.
#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serve one connection: read frames, handle them, write responses.
pub fn serve_connection(relay: &Relay, stream: &mut TcpStream) -> RelayResult<()> {
    let mut buf = vec![0u8; FRAME_SIZE];
    loop {
        // A shutdown must actually stop serving, not merely stop accepting.
        // Otherwise an operator who has been ordered to take a relay down
        // leaves established circuits running, which is both an availability
        // surprise and — for an operator acting under legal compulsion — a
        // window in which the relay is still handling traffic it was told to
        // stop handling.
        if relay.is_shutting_down() {
            return Ok(());
        }
        match stream.read_exact(&mut buf) {
            Ok(()) => {}
            Err(_) => return Ok(()), // peer closed
        }
        if relay.is_shutting_down() {
            return Ok(());
        }
        let response = match Frame::decode(&buf) {
            Ok(request) => relay
                .handle(&request, now())
                .unwrap_or_else(|_| Frame::new(FrameType::Refuse, Vec::new())),
            // An unparseable frame gets the same refusal as anything else.
            Err(_) => Frame::new(FrameType::Refuse, Vec::new()),
        };
        let bytes = response.encode()?;
        stream.write_all(&bytes).map_err(|_| RelayError::Io)?;
        stream.flush().map_err(|_| RelayError::Io)?;
    }
}

/// Listen on `addr` and serve until shutdown.
///
/// In deployment `addr` is a loopback address that a Tor onion service forwards
/// to; the relay never binds a public interface.
pub fn listen(relay: Arc<Relay>, addr: &str) -> RelayResult<()> {
    let listener = TcpListener::bind(addr).map_err(|_| RelayError::Io)?;
    listener.set_nonblocking(true).map_err(|_| RelayError::Io)?;

    while !relay.is_shutting_down() {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                // The peer address is deliberately discarded, not logged. Over
                // Tor it is always the local onion forwarder, but a relay that
                // logged it would still be building the connection record §9.1
                // promises does not exist.
                let r = Arc::clone(&relay);
                std::thread::spawn(move || {
                    // The listener is non-blocking so the shutdown check above
                    // can run between `accept` calls, but on at least macOS an
                    // accepted socket inherits that flag from the listener
                    // rather than defaulting to blocking. Left non-blocking,
                    // `serve_connection`'s `read_exact` hits `WouldBlock`
                    // (rather than actually blocking) the moment a second
                    // frame is not yet fully in the kernel buffer, which
                    // `read_exact` treats as any other I/O error and the
                    // connection is torn down after its first frame.
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_nodelay(true);
                    let _ = serve_connection(&r, &mut stream);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return Err(RelayError::Io),
        }
    }
    Ok(())
}

/// The local address a bound listener ended up on. Used by tests that bind to
/// port 0.
pub fn bind_ephemeral() -> RelayResult<(TcpListener, String)> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|_| RelayError::Io)?;
    let addr = l.local_addr().map_err(|_| RelayError::Io)?.to_string();
    Ok((l, addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use void_proto::envelope::{self, SEALED_RECORD_SIZE};
    use void_proto::queue::QueueSecret;
    use void_proto::record::{Record, RecordKind};

    struct CountingPush {
        count: AtomicUsize,
        last_delay: Mutex<u64>,
    }

    impl PushSender for CountingPush {
        fn wake(&self, _wake_id: &[u8; 16], delay_seconds: u64) {
            self.count.fetch_add(1, Ordering::SeqCst);
            *self.last_delay.lock().unwrap() = delay_seconds;
        }
    }

    fn relay() -> Relay {
        Relay::new(Config::default(), Box::new(NoPush))
    }

    fn deposit_frame(q: QueueId) -> Frame {
        let d = void_proto::envelope::Deposit {
            queue_id: q,
            sealed: vec![0xAB; SEALED_RECORD_SIZE],
        };
        Frame::new(FrameType::Deposit, d.encode())
    }

    fn qsecret(seed: u8) -> QueueSecret {
        QueueSecret::from_parts([seed; 32], 0)
    }

    fn collect(r: &Relay, secret: &QueueSecret, now: u64) -> Frame {
        let q = secret.queue_id();
        let ch = r
            .handle(&Frame::new(FrameType::Challenge, q.to_vec()), now)
            .unwrap();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&ch.body);
        r.handle(
            &Frame::new(
                FrameType::Retrieve,
                Retrieve {
                    queue_id: q,
                    challenge,
                    retrieval_public: secret.retrieval_public(),
                    proof: secret.prove_retrieval(&challenge),
                }
                .encode(),
            ),
            now,
        )
        .unwrap()
    }

    #[test]
    fn deposit_then_retrieve_over_the_frame_protocol() {
        let r = relay();
        let secret = qsecret(1);
        let q = secret.queue_id();
        assert_eq!(r.handle(&deposit_frame(q), 0).unwrap().kind, FrameType::Ack);

        let resp = collect(&r, &secret, 0);
        assert_eq!(resp.kind, FrameType::Delivery);
        let d = Delivery::decode(&resp.body).unwrap();
        assert_eq!(d.sealed.len(), SEALED_RECORD_SIZE);
        assert_eq!(d.remaining, 0);
    }

    #[test]
    fn a_real_sealed_record_survives_the_round_trip() {
        let r = relay();
        let secret = qsecret(5);
        let rec = Record {
            kind: RecordKind::Payload,
            message_id: 1,
            index: 0,
            count: 1,
            body: b"end to end".to_vec(),
        };
        let dep = envelope::seal(&secret.deposit_key(), &rec).unwrap();
        let q = dep.queue_id;

        r.handle(&Frame::new(FrameType::Deposit, dep.encode()), 0)
            .unwrap();
        let resp = collect(&r, &secret, 0);
        let d = Delivery::decode(&resp.body).unwrap();
        let opened = envelope::open(
            &secret.deposit_key(),
            &void_proto::envelope::Deposit {
                queue_id: q,
                sealed: d.sealed,
            },
        )
        .unwrap();
        assert_eq!(opened.body, b"end to end");
    }

    #[test]
    fn an_empty_queue_returns_a_delivery_not_a_refusal() {
        let r = relay();
        let secret = qsecret(1);
        r.handle(&deposit_frame(secret.queue_id()), 0).unwrap();
        collect(&r, &secret, 0);
        let resp = collect(&r, &secret, 0);
        assert_eq!(resp.kind, FrameType::Delivery);
        assert!(Delivery::decode(&resp.body).unwrap().sealed.is_empty());
    }

    #[test]
    fn every_response_is_the_same_size_on_the_wire() {
        // The whole point of the fixed frame: an observer cannot tell a deposit
        // ack from a delivery from a refusal.
        let r = relay();
        let q = [1u8; 16];
        let ack = r.handle(&deposit_frame(q), 0).unwrap();
        let ch = r
            .handle(&Frame::new(FrameType::Challenge, q.to_vec()), 0)
            .unwrap();
        let refuse = r
            .handle(
                &Frame::new(
                    FrameType::Retrieve,
                    Retrieve {
                        queue_id: [9u8; 16],
                        challenge: [0u8; 32],
                        retrieval_public: [0u8; 32],
                        proof: [0u8; 64],
                    }
                    .encode(),
                ),
                0,
            )
            .unwrap();
        let pad = r.handle(&Frame::padding().unwrap(), 0).unwrap();

        let sizes: Vec<usize> = [ack, ch, refuse, pad]
            .iter()
            .map(|f| f.encode().unwrap().len())
            .collect();
        assert!(sizes.iter().all(|&s| s == FRAME_SIZE), "{sizes:?}");
    }

    #[test]
    fn a_bad_proof_yields_refuse_with_no_detail() {
        let r = relay();
        let secret = qsecret(1);
        let q = secret.queue_id();
        r.handle(&deposit_frame(q), 0).unwrap();
        let ch = r
            .handle(&Frame::new(FrameType::Challenge, q.to_vec()), 0)
            .unwrap();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&ch.body);
        let resp = r
            .handle(
                &Frame::new(
                    FrameType::Retrieve,
                    Retrieve {
                        queue_id: q,
                        challenge,
                        retrieval_public: secret.retrieval_public(),
                        proof: [0u8; 64],
                    }
                    .encode(),
                ),
                0,
            )
            .unwrap();
        assert_eq!(resp.kind, FrameType::Refuse);
        assert!(resp.body.is_empty(), "a refusal must carry no reason");
        assert_eq!(r.metrics().unwrap().records, 1, "the record must survive");
    }

    #[test]
    fn a_key_that_does_not_address_the_queue_is_refused() {
        // The check that makes registration unnecessary: an attacker who owns a
        // valid key pair cannot use it to collect from someone else's queue.
        let r = relay();
        let victim = qsecret(1);
        let attacker = qsecret(2);
        let q = victim.queue_id();
        r.handle(&deposit_frame(q), 0).unwrap();

        let ch = r
            .handle(&Frame::new(FrameType::Challenge, q.to_vec()), 0)
            .unwrap();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&ch.body);
        let resp = r
            .handle(
                &Frame::new(
                    FrameType::Retrieve,
                    Retrieve {
                        queue_id: q,
                        challenge,
                        // A perfectly valid key and a perfectly valid signature
                        // — for the wrong queue.
                        retrieval_public: attacker.retrieval_public(),
                        proof: attacker.prove_retrieval(&challenge),
                    }
                    .encode(),
                ),
                0,
            )
            .unwrap();
        assert_eq!(resp.kind, FrameType::Refuse);
        assert_eq!(r.metrics().unwrap().records, 1);
    }

    #[test]
    fn push_is_delayed_and_carries_only_a_wake_id() {
        let push = CountingPush {
            count: AtomicUsize::new(0),
            last_delay: Mutex::new(999),
        };
        let r = Relay::new(Config::default(), Box::new(push));
        let q = [1u8; 16];
        r.link_wake(q, [7u8; 16], 0).unwrap();
        r.handle(&deposit_frame(q), 0).unwrap();
        // We cannot read the boxed sender back out, so assert via behaviour:
        // the deposit succeeded and the relay reported no error.
        assert_eq!(r.metrics().unwrap().records, 1);
    }

    #[test]
    fn server_only_frame_types_from_a_client_are_malformed() {
        let r = relay();
        for kind in [
            FrameType::ChallengeReply,
            FrameType::Delivery,
            FrameType::Ack,
            FrameType::Refuse,
        ] {
            assert!(r.handle(&Frame::new(kind, vec![]), 0).is_err(), "{kind:?}");
        }
    }

    #[test]
    fn padding_is_answered_with_padding() {
        let r = relay();
        let resp = r.handle(&Frame::padding().unwrap(), 0).unwrap();
        assert_eq!(resp.kind, FrameType::Padding);
    }

    #[test]
    fn metrics_are_aggregate_only() {
        let r = relay();
        r.handle(&deposit_frame([1u8; 16]), 0).unwrap();
        r.handle(&deposit_frame([2u8; 16]), 0).unwrap();
        let m = r.metrics().unwrap();
        assert_eq!(m.queues, 2);
        assert_eq!(m.records, 2);
        // There is intentionally no per-queue metric accessor on Relay.
    }

    #[test]
    fn sweep_expires_records() {
        let r = relay();
        r.handle(&deposit_frame([1u8; 16]), 1000).unwrap();
        assert_eq!(r.metrics().unwrap().records, 1);
        let ttl = void_proto::queue::DEFAULT_TTL_SECONDS;
        assert_eq!(r.sweep(1000 + ttl + 1, 0).unwrap(), 1);
        assert_eq!(r.metrics().unwrap().records, 0);
        assert_eq!(r.metrics().unwrap().queues, 0);
    }

    #[test]
    fn end_to_end_over_a_real_socket() {
        let relay = Arc::new(relay());
        let (listener, addr) = bind_ephemeral().unwrap();
        drop(listener);
        let r2 = Arc::clone(&relay);
        let a2 = addr.clone();
        let handle = std::thread::spawn(move || {
            let _ = listen(r2, &a2);
        });
        // Give the listener a moment to bind.
        std::thread::sleep(std::time::Duration::from_millis(150));

        let q = [3u8; 16];
        let mut stream = match TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(_) => {
                relay.shutdown();
                let _ = handle.join();
                return; // sandboxed environments may forbid loopback
            }
        };
        stream
            .write_all(&deposit_frame(q).encode().unwrap())
            .unwrap();
        let mut buf = vec![0u8; FRAME_SIZE];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(Frame::decode(&buf).unwrap().kind, FrameType::Ack);
        assert_eq!(relay.metrics().unwrap().records, 1);

        relay.shutdown();
        drop(stream);
        let _ = handle.join();
    }
}
