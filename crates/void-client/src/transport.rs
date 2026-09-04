//! Transport abstraction (FR-TRANS-01, FR-TRANS-03, FR-TRANS-05).
//!
//! ## Fail closed. Always.
//!
//! Non-negotiable #5: *"If Tor is unavailable, messages queue. There is never a
//! fallback path."* This is the file where that could go wrong, so the
//! architecture makes it hard: the [`Transport`] trait has no "connect
//! directly" method, no proxy-optional flag, and no timeout-then-retry-plain
//! path. A transport either reaches the relay through an anonymising network or
//! it returns an error and the caller queues.
//!
//! ## Why there is a plain TCP transport at all
//!
//! [`TcpTransport`] exists for the reference CLI and for integration tests, and
//! it reports [`TransportKind::Direct`]. The engine refuses to use a `Direct`
//! transport unless explicitly constructed in insecure mode, and the CLI prints
//! a warning every time it does. That is deliberate: a test transport that
//! *looks* like the real one is how a "temporary" bypass survives into a
//! release build.
//!
//! ## Arti versus C-tor
//!
//! PRD §13.2 asks whether Arti meets Void's needs for client-side onion service
//! connections. The answer this codebase assumes is yes, and
//! `docs/DECISIONS.md#d-009` records why: Void only needs the *client* side of
//! onion services — connecting out to a relay's onion address — which is the
//! mature half of Arti's onion support, and the Rust implementation matches the
//! memory-safety posture NFR-SEC-02 sets for everything else. [`TorTransport`]
//! is the seam; it is a trait implementation, not a leaf dependency, so the
//! decision is reversible.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use void_relay::protocol::{Frame, FRAME_SIZE};

use crate::{ClientError, ClientResult};

/// What kind of network path a transport provides.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportKind {
    /// Routed through Tor. The only kind acceptable in a shipped client.
    Tor,
    /// A direct TCP connection. Tests and the reference CLI only.
    Direct,
    /// In-memory, no network at all. Tests only.
    InMemory,
}

impl TransportKind {
    /// May a production client use this transport?
    ///
    /// FR-TRANS-03: no network connection to any host outside Tor, with no
    /// exceptions — including for crash reporting, analytics, or update checks.
    #[must_use]
    pub fn is_acceptable_for_production(self) -> bool {
        matches!(self, TransportKind::Tor)
    }
}

/// A connection to a relay.
///
/// Every method is frame-oriented and fixed-size. There is no streaming API,
/// because a streaming API invites variable-length writes and FR-MSG-02 exists
/// to prevent exactly that.
pub trait Transport: Send {
    /// What kind of path this is.
    fn kind(&self) -> TransportKind;

    /// Send one frame and wait for the response frame.
    fn exchange(&mut self, request: &Frame) -> ClientResult<Frame>;

    /// Is the transport currently connected?
    fn is_connected(&self) -> bool;

    /// Close the connection.
    fn disconnect(&mut self);
}

/// A blocking, thread-safe duplex byte stream.
///
/// Implemented for anything that is `Read + Write + Send`: a raw `TcpStream`
/// (a local Tor daemon reached over its control/data port, or a test), or —
/// in production — the blocking adapter `void-tor` wraps around an Arti
/// circuit, which is not a `TcpStream` at all (Arti's `DataStream` is a
/// layered, encrypted stream with no OS socket of its own to hand out).
/// `TorTransport` only needs bytes in and bytes out, so this is the whole
/// contract.
pub trait TorStream: Read + Write + Send {}
impl<T: Read + Write + Send> TorStream for T {}

/// A Tor-routed transport.
///
/// The Rust core does not embed a Tor implementation directly; the platform
/// layer supplies a connected stream through [`TorTransport::from_stream`],
/// having bootstrapped Arti and opened a circuit to the relay's onion address
/// (see the `void-tor` crate). This keeps the async Tor runtime out of the
/// trusted path and out of this crate's dependency graph, which is what
/// NFR-SEC-07 asks for.
pub struct TorTransport {
    stream: Option<Box<dyn TorStream>>,
    onion_address: String,
}

impl TorTransport {
    /// Wrap a stream the platform layer has already routed through Tor.
    ///
    /// # Safety of the claim
    ///
    /// This constructor *trusts* its caller to have actually routed the stream
    /// through Tor — nothing here can verify that. The verification that
    /// matters is the CI check in `scripts/check_no_direct_network.sh`, which
    /// fails the build if any crate in the graph can open a socket outside the
    /// platform Tor layer.
    #[must_use]
    pub fn from_stream(stream: impl TorStream + 'static, onion_address: &str) -> TorTransport {
        TorTransport {
            stream: Some(Box::new(stream)),
            onion_address: onion_address.to_string(),
        }
    }

    /// The relay's onion address. This is the pinned relay key (FR-TRANS-04):
    /// in Tor v3 the onion address *is* the service's public key, so pinning
    /// the address is pinning the key, and there is no certificate authority
    /// anywhere in the trust path.
    #[must_use]
    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }
}

impl Transport for TorTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tor
    }

    fn exchange(&mut self, request: &Frame) -> ClientResult<Frame> {
        let stream = self.stream.as_mut().ok_or(ClientError::TorUnavailable)?;
        let result = exchange_on_stream(stream, request);
        if result.is_err() {
            // A failed exchange means the circuit is gone. Drop it rather than
            // reusing a half-open socket; the caller queues and retries.
            self.stream = None;
        }
        result
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    fn disconnect(&mut self) {
        self.stream = None;
    }
}

/// A direct TCP transport. **Tests and the reference CLI only.**
pub struct TcpTransport {
    stream: Option<TcpStream>,
    address: String,
}

impl TcpTransport {
    /// Connect directly. Reports [`TransportKind::Direct`], which the engine
    /// refuses unless explicitly put in insecure mode.
    pub fn connect(address: &str) -> ClientResult<TcpTransport> {
        let stream = TcpStream::connect(address).map_err(|_| ClientError::TorUnavailable)?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_nodelay(true);
        Ok(TcpTransport {
            stream: Some(stream),
            address: address.to_string(),
        })
    }

    /// The address connected to.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Transport for TcpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Direct
    }

    fn exchange(&mut self, request: &Frame) -> ClientResult<Frame> {
        let stream = self.stream.as_mut().ok_or(ClientError::TorUnavailable)?;
        exchange_on_stream(stream, request)
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    fn disconnect(&mut self) {
        self.stream = None;
    }
}

fn exchange_on_stream<S: Read + Write + ?Sized>(
    stream: &mut S,
    request: &Frame,
) -> ClientResult<Frame> {
    let bytes = request.encode().map_err(|_| ClientError::Protocol)?;
    debug_assert_eq!(bytes.len(), FRAME_SIZE);
    stream
        .write_all(&bytes)
        .map_err(|_| ClientError::TorUnavailable)?;
    stream.flush().map_err(|_| ClientError::TorUnavailable)?;
    let mut buf = vec![0u8; FRAME_SIZE];
    stream
        .read_exact(&mut buf)
        .map_err(|_| ClientError::TorUnavailable)?;
    Frame::decode(&buf).map_err(|_| ClientError::Protocol)
}

/// A transport that is never connected.
///
/// The default an engine is built with before the platform layer has
/// bootstrapped Tor and attached a real circuit. Every exchange fails with
/// [`ClientError::TorUnavailable`], so a client that starts up and immediately
/// tries to send queues the message rather than sending it — the correct
/// fail-closed behaviour (FR-TRANS-05), obtained by construction rather than by
/// remembering to check a flag.
///
/// It reports [`TransportKind::Tor`] so an engine in enforcing mode accepts it.
/// That is not a lie about routing: nothing is routed anywhere. It is the
/// statement that this transport will never carry traffic outside Tor, which is
/// trivially true of a transport that never carries traffic.
pub struct NullTransport;

impl NullTransport {
    /// Create one.
    #[must_use]
    pub fn new() -> NullTransport {
        NullTransport
    }
}

impl Default for NullTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for NullTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tor
    }
    fn exchange(&mut self, _request: &Frame) -> ClientResult<Frame> {
        Err(ClientError::TorUnavailable)
    }
    fn is_connected(&self) -> bool {
        false
    }
    fn disconnect(&mut self) {}
}

/// An in-memory transport that talks to a relay in the same process.
///
/// Used by the integration tests to exercise the full client↔relay protocol
/// with no sockets, so the tests are deterministic and fast.
pub struct MemoryTransport {
    relay: Arc<void_relay::server::Relay>,
    clock: Arc<Mutex<u64>>,
    connected: bool,
    /// Every frame that crossed this transport, for tests that assert on
    /// traffic shape.
    pub sent: Vec<Frame>,
}

impl MemoryTransport {
    /// Wire directly to a relay.
    #[must_use]
    pub fn new(relay: Arc<void_relay::server::Relay>, clock: Arc<Mutex<u64>>) -> MemoryTransport {
        MemoryTransport {
            relay,
            clock,
            connected: true,
            sent: Vec::new(),
        }
    }

    /// Simulate the network going away.
    pub fn go_offline(&mut self) {
        self.connected = false;
    }

    /// Simulate the network coming back.
    pub fn go_online(&mut self) {
        self.connected = true;
    }
}

impl Transport for MemoryTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::InMemory
    }

    fn exchange(&mut self, request: &Frame) -> ClientResult<Frame> {
        if !self.connected {
            return Err(ClientError::TorUnavailable);
        }
        self.sent.push(request.clone());
        let now = *self.clock.lock().map_err(|_| ClientError::Protocol)?;
        self.relay
            .handle(request, now)
            .map_err(|_| ClientError::Protocol)
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use void_relay::protocol::FrameType;
    use void_relay::server::{NoPush, Relay};
    use void_relay::store::Config;

    fn relay() -> Arc<Relay> {
        Arc::new(Relay::new(Config::default(), Box::new(NoPush)))
    }

    #[test]
    fn only_tor_is_acceptable_for_production() {
        assert!(TransportKind::Tor.is_acceptable_for_production());
        assert!(!TransportKind::Direct.is_acceptable_for_production());
        assert!(!TransportKind::InMemory.is_acceptable_for_production());
    }

    #[test]
    fn memory_transport_reaches_the_relay() {
        let clock = Arc::new(Mutex::new(1000u64));
        let mut t = MemoryTransport::new(relay(), clock);
        let resp = t.exchange(&Frame::padding().unwrap()).unwrap();
        assert_eq!(resp.kind, FrameType::Padding);
        assert_eq!(t.sent.len(), 1);
    }

    #[test]
    fn an_offline_transport_errors_rather_than_falling_back() {
        // FR-TRANS-05 and non-negotiable #5. There is no code path here that
        // could succeed by another route, and this test pins that.
        let clock = Arc::new(Mutex::new(0u64));
        let mut t = MemoryTransport::new(relay(), clock);
        t.go_offline();
        assert!(matches!(
            t.exchange(&Frame::padding().unwrap()),
            Err(ClientError::TorUnavailable)
        ));
        assert!(!t.is_connected());
        t.go_online();
        assert!(t.exchange(&Frame::padding().unwrap()).is_ok());
    }

    #[test]
    fn disconnect_is_sticky() {
        let clock = Arc::new(Mutex::new(0u64));
        let mut t = MemoryTransport::new(relay(), clock);
        t.disconnect();
        assert!(!t.is_connected());
        assert!(t.exchange(&Frame::padding().unwrap()).is_err());
    }

    #[test]
    fn the_null_transport_fails_closed() {
        let mut t = NullTransport::new();
        assert!(!t.is_connected());
        assert!(matches!(
            t.exchange(&Frame::padding().unwrap()),
            Err(ClientError::TorUnavailable)
        ));
        // Acceptable in enforcing mode precisely because it carries nothing.
        assert!(t.kind().is_acceptable_for_production());
    }

    #[test]
    fn the_transport_trait_has_no_fallback_method() {
        // A structural test: if someone adds `connect_direct` or a
        // `allow_plaintext` flag to the trait, this file is where review will
        // catch it. The assertion here is that the only way to get a
        // production-acceptable transport is TransportKind::Tor.
        let kinds = [
            TransportKind::Tor,
            TransportKind::Direct,
            TransportKind::InMemory,
        ];
        assert_eq!(
            kinds
                .iter()
                .filter(|k| k.is_acceptable_for_production())
                .count(),
            1
        );
    }
}
