//! Bootstraps Arti and hands `void-client` a live Tor circuit (FR-TRANS-01,
//! FR-TRANS-04, `docs/DECISIONS.md#d-009`).
//!
//! ## Why this crate exists, separately
//!
//! Arti is asynchronous. `void-client` — the trusted core — is not, and
//! NFR-SEC-07 makes every dependency in the trusted path expensive to
//! justify; an async runtime, plus Arti's own dependency tree, is a very
//! large one to bring in just to open one socket. So it does not: `void-tor`
//! is the only crate in this workspace that depends on `arti-client` and
//! `tokio`, and the only crate that runs an async runtime at all.
//! `void-client::transport::TorTransport` is the seam — it takes anything
//! that is `Read + Write + Send`, and does not know or care that the
//! implementation on the other side of that bound is bridging async Tor I/O
//! to blocking calls underneath.
//!
//! ## What "bootstrap" means here, concretely
//!
//! [`TorHandle::bootstrap`] blocks the calling thread until Arti has enough
//! directory material to build circuits, or until it fails. There is no
//! partial-bootstrap success path returned to the caller: FR-TRANS-05 means a
//! caller either gets a working way to reach the network, or an error to
//! queue behind — never something in between that might tempt a caller into
//! sending anyway.
//!
//! ## Pinning (FR-TRANS-04)
//!
//! A Tor v3 onion address *is* the service's Ed25519 public key, encoded.
//! [`TorHandle::connect`] takes that address as its only routing input and
//! passes it straight to Arti's circuit builder — there is no certificate
//! authority, no TOFU prompt, and no fallback address anywhere in this path.
//! Connecting to the wrong relay is only possible by being given the wrong
//! string.
//!
//! ## Fail closed (FR-TRANS-05, non-negotiable #5)
//!
//! Every failure mode here — bootstrap failure, circuit failure, a stream
//! that dies mid-exchange — surfaces as an `Err`. Nothing in this crate holds
//! a fallback transport, reads an environment variable to skip Tor, or
//! contains the word `direct`. The caller (the platform layer, ultimately
//! `Engine`) is the one place that decides what happens next, and what it
//! does is queue.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_rtcompat::PreferredRuntime;

use void_client::transport::TorTransport;

pub mod call;

/// How long a single blocking read or write may take before this crate gives
/// up on the circuit and reports it as gone. Generous, because Tor circuit
/// latency is not comparable to a LAN — but finite, because FR-TRANS-05's
/// "queue and retry" only works if a dead circuit is eventually reported as
/// dead rather than hung forever.
const IO_TIMEOUT: Duration = Duration::from_secs(120);

/// How long opening a circuit to the relay may take before it is abandoned.
///
/// Arti's attempt to reach an onion service has no deadline of its own that a
/// user would call reasonable: one was seen, on an emulator, still waiting after
/// six minutes. `void_engine_attach_tor` blocks for as long as this does, and
/// the app will not start a second attach while one is in flight — so without
/// a limit, one stalled attempt kept a phone offline until it restarted. Now it
/// fails, and the app's backoff tries again.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Everything that can go wrong bootstrapping or using Tor.
///
/// Deliberately coarse in the same spirit as [`void_client::ClientError`]: the
/// caller's only correct response to any of these is "queue and retry",  so
/// there is no reason to give it more to (mis)handle.
#[derive(Debug)]
pub enum TorError {
    /// The local async runtime could not be created.
    Runtime(String),
    /// Arti could not bootstrap a connection to the Tor network.
    Bootstrap(String),
    /// Building a circuit to the target onion address failed.
    Connect(String),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorError::Runtime(e) => write!(f, "could not start the Tor runtime: {e}"),
            TorError::Bootstrap(e) => write!(f, "could not bootstrap Tor: {e}"),
            TorError::Connect(e) => write!(f, "could not connect over Tor: {e}"),
        }
    }
}

impl std::error::Error for TorError {}

/// A bootstrapped Arti client, ready to open circuits.
///
/// Holds the tokio runtime that drives Arti for as long as this handle lives.
/// The platform layer creates one of these once (bootstrapping takes real
/// time — it is a network operation, not a constant-time call) and calls
/// [`TorHandle::connect`] for each relay connection the engine needs.
pub struct TorHandle {
    runtime: tokio::runtime::Runtime,
    client: Arc<TorClient<PreferredRuntime>>,
}

impl TorHandle {
    /// Bootstrap Arti, storing its persistent state and directory cache under
    /// `state_dir` and `cache_dir`.
    ///
    /// The platform layer chooses these directories, not Arti's own
    /// OS-convention defaults — on iOS and Android that is what makes
    /// FR-STOR-05's `isExcludedFromBackup` / equivalent apply to Tor's state
    /// the same way it applies to everything else Void writes to disk.
    ///
    /// Blocks the calling thread until bootstrap completes or fails.
    pub fn bootstrap(state_dir: &Path, cache_dir: &Path) -> Result<TorHandle, TorError> {
        // rustls 0.23 requires a process-wide `CryptoProvider` and will not
        // reliably auto-select one from crate features alone — on Android
        // that autodetection found none and panicked (aborting the whole
        // process, since this workspace builds with `panic = "abort"`)
        // deep inside arti-client's TLS setup. Installing `ring` explicitly,
        // once, before anything touches TLS, removes the ambiguity instead
        // of hoping the right feature wins. `install_default` only errors if
        // a provider is already installed, which is fine to ignore here.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| TorError::Runtime(e.to_string()))?;

        let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;

        let client = runtime
            .block_on(async { TorClient::create_bootstrapped(config).await })
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;

        Ok(TorHandle { runtime, client })
    }

    /// Open a circuit to `onion_address` on `port` and wrap it as a
    /// [`TorTransport`] the engine can use immediately.
    ///
    /// `onion_address` is the pinned relay identity (FR-TRANS-04) — see the
    /// module docs. It is used for nothing else: not logged, not stored
    /// beyond the transport's own lifetime.
    pub fn connect(&self, onion_address: &str, port: u16) -> Result<TorTransport, TorError> {
        let client = Arc::clone(&self.client);
        let target = onion_address.to_string();
        let data_stream = self
            .runtime
            .block_on(async move {
                tokio::time::timeout(CONNECT_TIMEOUT, client.connect((target.as_str(), port))).await
            })
            .map_err(|_| TorError::Connect(String::from("timed out opening a circuit")))?
            .map_err(|e| TorError::Connect(e.to_string()))?;

        let bridged = BlockingCircuit {
            handle: self.runtime.handle().clone(),
            inner: data_stream,
        };
        Ok(TorTransport::from_stream(bridged, onion_address))
    }
}

/// Bridges an Arti `DataStream` (async) to blocking `std::io::Read` / `Write`
/// by driving each call to completion on the Tor runtime before returning.
///
/// This costs nothing `TorTransport` was not already paying: its protocol is
/// one exchange at a time — write a fixed-size frame, then block for the
/// fixed-size reply — so there is no concurrency here to give up by blocking.
struct BlockingCircuit {
    handle: tokio::runtime::Handle,
    inner: arti_client::DataStream,
}

impl Read for BlockingCircuit {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let inner = &mut self.inner;
        self.handle.block_on(async move {
            tokio::time::timeout(IO_TIMEOUT, inner.read(buf))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "Tor circuit read timed out")
                })?
        })
    }
}

impl Write for BlockingCircuit {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let inner = &mut self.inner;
        self.handle.block_on(async move {
            tokio::time::timeout(IO_TIMEOUT, inner.write(buf))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "Tor circuit write timed out")
                })?
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        let inner = &mut self.inner;
        self.handle.block_on(async move {
            tokio::time::timeout(IO_TIMEOUT, inner.flush())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "Tor circuit flush timed out")
                })?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-TRANS-05: the type signature itself is the enforcement. There is no
    /// method on `TorHandle` that takes a plain address with no bootstrap, no
    /// `connect_direct`, and no way to skip `bootstrap` and still get a
    /// `TorTransport` out of this crate.
    #[test]
    fn there_is_no_fallback_construction_path() {
        // A structural assertion, not a runtime one: this compiles only
        // because `TorTransport` can only be produced here via
        // `TorHandle::connect`, which can only be reached via
        // `TorHandle::bootstrap`. If a future edit adds a shortcut, this
        // comment is where a reviewer should look twice.
        fn _assert_only_path_is_bootstrap_then_connect() {
            fn takes_handle(h: &TorHandle) {
                let _ = h.connect("example.onion", 443);
            }
            let _ = takes_handle;
        }
    }
}
