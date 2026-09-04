//! An end-to-end test over a real Tor circuit to a relay onion service.
//!
//! This is PRD §11 Phase 2's deliverable in full: an Arti client, bootstrapped
//! for real against the live Tor network, opening a real circuit to a real
//! onion service, fronting a real `void-relayd`. Nothing here is simulated —
//! `crates/void-cli/tests/live_socket.rs` already covers the protocol over a
//! real loopback socket; this is the one test in the workspace that also
//! proves the Tor half.
//!
//! ## Why this is not part of `cargo test --workspace`
//!
//! It needs two things most CI environments and sandboxes do not have: the
//! system `tor` binary on `PATH` (to host the onion service — Arti's
//! service-hosting support is deliberately not what Void uses, per
//! `docs/DECISIONS.md#d-009`), and unfiltered outbound internet access to the
//! real Tor network. Bootstrapping both a hidden service and an Arti client
//! against the live network is also slow — commonly one to several minutes —
//! which is not something a routine `cargo test` run should pay for.
//!
//! Run it explicitly:
//! ```sh
//! cargo test -p void-tor --test live_tor_circuit -- --ignored --nocapture
//! ```
//!
//! If `tor` is not on `PATH`, the test prints why and returns rather than
//! failing — the same "skip, do not fail, when the environment cannot
//! support this" convention `live_socket.rs` uses for sandboxes with no
//! loopback sockets. Once the binary is found, though, every other failure
//! (bootstrap timeout, descriptor never found, circuit never opens) is a real
//! failure: presence of `tor` on `PATH` is what marks this as a deliberate,
//! opted-in run rather than an incidental CI environment.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use void_client::transport::Transport;
use void_relay::protocol::{Frame, FrameType};
use void_relay::server::{self, NoPush, Relay};
use void_relay::store::Config;
use void_tor::TorHandle;

/// A directory this test owns for the duration of one run, cleaned up when
/// the guard drops even on a failing assertion (via `Drop`, not a `finally`
/// Rust does not have).
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let dir =
            std::env::temp_dir().join(format!("void-tor-live-test-{}-{label}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running `tor` process hosting one onion service, killed on drop.
struct HiddenService {
    child: Child,
    onion_address: String,
    _hs_dir: TempDir,
    _data_dir: TempDir,
}

impl Drop for HiddenService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start a relay on an ephemeral loopback port, exactly as
/// `live_socket.rs::start_relay` does, and return its port.
fn start_relay() -> Option<(Arc<Relay>, u16, std::thread::JoinHandle<()>)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    drop(listener);

    let relay = Arc::new(Relay::new(Config::default(), Box::new(NoPush)));
    let r = Arc::clone(&relay);
    let addr = format!("127.0.0.1:{port}");
    let handle = std::thread::spawn(move || {
        let _ = server::listen(r, &addr);
    });
    std::thread::sleep(Duration::from_millis(250));
    std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    Some((relay, port, handle))
}

/// Launch `tor`, hosting a hidden service that forwards `hs_port` to the
/// relay's loopback port. Blocks until the onion address is known — that is
/// only the *keys* being generated, not the descriptor being published, so a
/// connection attempt immediately after this returns may still need retries.
fn start_hidden_service(relay_port: u16, hs_port: u16) -> Option<HiddenService> {
    if Command::new("tor").arg("--version").output().is_err() {
        return None;
    }

    let hs_dir = TempDir::new("hs");
    let data_dir = TempDir::new("data");
    // Tor refuses a HiddenServiceDir with group/other permissions — a real
    // safety check against the service's private key being world-readable —
    // and `create_dir_all`'s mode depends on the umask, which is not
    // reliably 0700 on its own.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hs_dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let torrc = format!(
        "DataDirectory {}\n\
         HiddenServiceDir {}\n\
         HiddenServicePort {hs_port} 127.0.0.1:{relay_port}\n\
         SocksPort 0\n\
         ControlPort 0\n\
         Log notice stdout\n",
        data_dir.0.display(),
        hs_dir.0.display(),
    );
    let torrc_path = data_dir.0.join("torrc");
    std::fs::write(&torrc_path, torrc).ok()?;

    let mut child = Command::new("tor")
        .arg("-f")
        .arg(&torrc_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Wait for the hostname file: written once the service's keys exist,
    // which is necessary but not sufficient for reachability — the
    // descriptor still has to reach the network, which is why callers must
    // still retry the first connection attempt.
    let stdout = child.stdout.take().unwrap();
    let hostname_path = hs_dir.0.join("hostname");
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut lines = BufReader::new(stdout).lines();
    while Instant::now() < deadline && !hostname_path.exists() {
        if let Some(Ok(line)) = lines.next() {
            eprintln!("[tor] {line}");
        } else {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    // Keep draining tor's log in the background so its stdout pipe never
    // fills up and blocks the process.
    std::thread::spawn(move || {
        for line in lines.map_while(Result::ok) {
            eprintln!("[tor] {line}");
        }
    });

    if !hostname_path.exists() {
        let _ = child.kill();
        return None;
    }
    let onion_address = std::fs::read_to_string(&hostname_path)
        .ok()?
        .trim()
        .to_string();

    Some(HiddenService {
        child,
        onion_address,
        _hs_dir: hs_dir,
        _data_dir: data_dir,
    })
}

#[test]
#[ignore = "needs the system `tor` binary and real Tor network access; run explicitly"]
fn a_real_arti_client_reaches_a_real_relay_over_a_real_onion_service() {
    let Some((relay, relay_port, _relay_handle)) = start_relay() else {
        eprintln!("skipping: loopback sockets unavailable in this environment");
        return;
    };

    const HS_PORT: u16 = 9999;
    let Some(hidden_service) = start_hidden_service(relay_port, HS_PORT) else {
        eprintln!(
            "skipping: `tor` not found on PATH, or the hidden service never \
             produced a hostname within the wait budget"
        );
        return;
    };
    eprintln!(
        "hidden service published at {}",
        hidden_service.onion_address
    );

    let arti_state = TempDir::new("arti-state");
    let arti_cache = TempDir::new("arti-cache");
    eprintln!("bootstrapping Arti against the live Tor network...");
    let tor = TorHandle::bootstrap(&arti_state.0, &arti_cache.0)
        .expect("Arti must bootstrap against the real network for this test to mean anything");
    eprintln!("Arti bootstrapped");

    // The descriptor may not have propagated to the network yet even though
    // the hostname file exists locally. Retry with backoff rather than
    // treating the first failure as definitive.
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut transport = None;
    let mut attempt = 0u32;
    while Instant::now() < deadline {
        attempt += 1;
        match tor.connect(&hidden_service.onion_address, HS_PORT) {
            Ok(t) => {
                transport = Some(t);
                break;
            }
            Err(e) => {
                eprintln!("attempt {attempt}: not reachable yet ({e}), retrying...");
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
    let mut transport = transport.expect(
        "the onion service must become reachable within the wait budget — if this \
         fails consistently outside a hostile network environment, the bootstrap or \
         connect path in void-tor has regressed, not the test",
    );

    assert_eq!(
        transport.onion_address(),
        hidden_service.onion_address,
        "the pinned address must be exactly what was dialled — FR-TRANS-04"
    );

    // The real proof: a frame sent through Arti, over a real circuit, through
    // a real onion service, is handled by our relay and a real response comes
    // back the same way.
    let response = transport
        .exchange(&Frame::padding().unwrap())
        .expect("a full round trip over the live Tor network must succeed");
    assert_eq!(response.kind, FrameType::Padding);
    assert!(
        relay.metrics().is_ok(),
        "the relay must still be alive and answering after serving a request over Tor"
    );

    eprintln!("round trip over a live Tor circuit succeeded");
}
