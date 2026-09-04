//! Does a Tor onion circuit carry a voice packet stream?
//!
//! This answers one question with numbers and is then meant to be deleted. It
//! is not a design, not a prototype of the feature, and nothing here should be
//! copied into `crates/` — the protocol work only starts if the numbers below
//! come back acceptable.
//!
//! ## What it measures, and why that and not "ping"
//!
//! Mean latency is the number everyone quotes and the least useful one for
//! audio. A call is listenable when the *jitter buffer* can absorb the spread
//! between the fastest and slowest packets, and that buffer's depth is added
//! to mouth-to-ear delay on every single packet. A circuit averaging 400 ms
//! with a 1,200 ms tail is worse to listen to than one averaging 700 ms flat.
//!
//! So this sends packets at a real voice cadence — one every 20 ms, the frame
//! size Opus uses — and reports the distribution, not the average.
//!
//! It also matters that Tor is TCP. A dropped segment stalls everything queued
//! behind it (head-of-line blocking), which is exactly the failure mode UDP
//! voice transports exist to avoid. That shows up here as a cluster of packets
//! all arriving late together, which is why the report counts consecutive late
//! arrivals rather than just tallying them.
//!
//! ## Usage
//!
//!   cargo run --release -- listen
//!     → prints an onion address, then echoes packets
//!
//!   cargo run --release -- call <address>.onion
//!     → sends 20 ms packets for 30 seconds and prints the distribution

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::StreamExt;
use safelog::DisplayRedacted as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname};

/// Virtual port the service listens on. Arbitrary; both sides just agree.
const CALL_PORT: u16 = 9999;

/// One packet per 20 ms, matching Opus's default frame duration.
const PACKET_INTERVAL: Duration = Duration::from_millis(20);

/// 40 bytes of payload ≈ Opus at 16 kbit/s, plus 12 bytes of sequence and
/// timestamp so each packet can be matched to its echo.
const PAYLOAD_LEN: usize = 40;
const PACKET_LEN: usize = PAYLOAD_LEN + 12;

/// 30 seconds of call at 50 packets/second.
const PACKET_COUNT: usize = 1500;

fn scratch(kind: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("onion-call-probe/{kind}"));
    p
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    // Same reason void-tor does this: rustls 0.23 wants an explicit provider,
    // and letting it guess has already caused one abort on Android.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("listen") => listen().await,
        Some("call") => {
            let addr = args.get(2).ok_or("usage: call <address>.onion")?;
            call(addr).await
        }
        _ => {
            eprintln!("usage: onion-call-probe [listen | call <address>.onion]");
            std::process::exit(2);
        }
    }
}

/// Bootstrap Arti, publish an ephemeral onion service, echo every packet.
async fn listen() -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    eprintln!("bootstrapping arti (callee)…");
    let config =
        TorClientConfigBuilder::from_directories(scratch("callee-state"), scratch("callee-cache"))
            .build()?;
    let client = TorClient::create_bootstrapped(config).await?;
    eprintln!("  bootstrapped in {:.1}s", started.elapsed().as_secs_f64());

    let publish_started = Instant::now();
    let svc_config = OnionServiceConfigBuilder::default()
        .nickname("probe".parse::<HsNickname>()?)
        .build()?;
    let (service, rend_requests) = client
        .launch_onion_service(svc_config)?
        .ok_or("onion service disabled in config")?;

    let onion = service
        .onion_address()
        .ok_or("service has no onion address yet")?;
    println!("{}", onion.display_unredacted());

    // Accept before waiting. The address exists the moment the key does, but
    // the service is not *reachable* until its descriptor reaches the HSDirs,
    // and that upload is the "ring delay" a real call pays — worth timing on
    // its own. Handling requests concurrently with the wait also means a
    // client that arrives early is not left knocking.
    tokio::spawn(async move {
        let mut streams = Box::pin(handle_rend_requests(rend_requests));
        while let Some(request) = streams.next().await {
            let mut stream = match request.accept(Connected::new_empty()).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("accept failed: {e}");
                    continue;
                }
            };
            eprintln!("call connected");
            tokio::spawn(async move {
                let mut buf = [0u8; PACKET_LEN];
                loop {
                    if stream.read_exact(&mut buf).await.is_err() {
                        break;
                    }
                    if stream.write_all(&buf).await.is_err() {
                        break;
                    }
                    // Without this the echo waits for Tor to accumulate a
                    // fuller cell, which would measure the buffer rather than
                    // the network.
                    if stream.flush().await.is_err() {
                        break;
                    }
                }
                eprintln!("call ended");
            });
        }
    });

    // Deliberately not gated on `status().state() == Running`. A service
    // publishes a descriptor for the current time period *and* the next one,
    // and the aggregate status stays `Bootstrapping` until both land. In this
    // environment the second one retries forever, while the live descriptor
    // went to 8/8 HSDirs in four seconds — so gating on Running reports a
    // reachable service as broken. The caller connecting is the honest test of
    // reachability, so that is the one used.
    eprintln!("accepting. status is logged below but not waited on.");
    let watched = Arc::clone(&service);
    tokio::spawn(async move {
        let mut last = None;
        loop {
            let state = watched.status().state();
            if Some(state) != last {
                eprintln!(
                    "  [{:5.1}s] status: {state:?}",
                    publish_started.elapsed().as_secs_f64()
                );
                last = Some(state);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    futures::future::pending::<()>().await;
    Ok(())
}

/// Bootstrap Arti, connect to the service, and time a voice-rate packet stream.
async fn call(onion: &str) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    eprintln!("bootstrapping arti (caller)…");
    let config =
        TorClientConfigBuilder::from_directories(scratch("caller-state"), scratch("caller-cache"))
            .build()?;
    let client = TorClient::create_bootstrapped(config).await?;
    let bootstrap_secs = started.elapsed().as_secs_f64();
    eprintln!("  bootstrapped in {bootstrap_secs:.1}s");

    let connect_started = Instant::now();
    eprintln!("connecting to {onion}:{CALL_PORT}…");
    let stream = client.connect((onion, CALL_PORT)).await?;
    let connect_secs = connect_started.elapsed().as_secs_f64();
    eprintln!("  connected in {connect_secs:.1}s (this is the ring delay)");

    let (mut reader, mut writer) = stream.split();

    // The echoes are collected on their own task: a call does not stop
    // speaking to wait for the other side, and neither does this.
    let receiver = tokio::spawn(async move {
        let mut rtts = vec![0f64; PACKET_COUNT];
        let mut received = 0usize;
        let mut buf = [0u8; PACKET_LEN];
        for _ in 0..PACKET_COUNT {
            if reader.read_exact(&mut buf).await.is_err() {
                break;
            }
            let seq = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
            let sent_micros = u64::from_be_bytes(buf[4..12].try_into().unwrap());
            let now_micros = MONOTONIC.elapsed().as_micros() as u64;
            if seq < rtts.len() {
                rtts[seq] = (now_micros.saturating_sub(sent_micros)) as f64 / 1000.0;
                received += 1;
            }
        }
        (rtts, received)
    });

    eprintln!("sending {PACKET_COUNT} packets at one per {PACKET_INTERVAL:?}…");
    let send_started = Instant::now();
    let mut ticker = tokio::time::interval(PACKET_INTERVAL);
    for seq in 0..PACKET_COUNT {
        ticker.tick().await;
        let mut packet = [0u8; PACKET_LEN];
        packet[0..4].copy_from_slice(&(seq as u32).to_be_bytes());
        packet[4..12]
            .copy_from_slice(&(MONOTONIC.elapsed().as_micros() as u64).to_be_bytes());
        writer.write_all(&packet).await?;
        writer.flush().await?;
        if seq % 250 == 0 && seq > 0 {
            eprint!("  {seq}…");
            let _ = std::io::stderr().flush();
        }
    }
    eprintln!();
    let send_secs = send_started.elapsed().as_secs_f64();

    let (rtts, received) = tokio::time::timeout(Duration::from_secs(30), receiver)
        .await
        .unwrap_or_else(|_| Ok((vec![], 0)))?;

    report(&rtts, received, bootstrap_secs, connect_secs, send_secs);
    Ok(())
}

/// Process-wide clock. Both timestamps in a packet come from this, and the
/// packet never leaves this process, so no clock sync is involved.
static MONOTONIC: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

fn report(rtts: &[f64], received: usize, bootstrap: f64, connect: f64, send: f64) {
    let mut ok: Vec<f64> = rtts.iter().copied().filter(|r| *r > 0.0).collect();
    if ok.is_empty() {
        println!("\nno packets returned — the circuit never carried anything");
        return;
    }
    ok.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let pct = |p: f64| ok[((ok.len() as f64 - 1.0) * p).round() as usize];
    let p50 = pct(0.50);
    let p95 = pct(0.95);
    let p99 = pct(0.99);

    // A jitter buffer sized to p95 must be at least this deep, and every
    // packet pays that depth in added delay.
    let jitter_depth = p95 - p50;

    // Consecutive late arrivals are the head-of-line signature: TCP stalling
    // means packets arrive in a clump, not scattered.
    let late_threshold = p50 * 2.0;
    let (mut worst_run, mut run) = (0usize, 0usize);
    for r in rtts.iter().copied() {
        if r > late_threshold || r == 0.0 {
            run += 1;
            worst_run = worst_run.max(run);
        } else {
            run = 0;
        }
    }

    println!("\n=== onion-to-onion voice probe ===");
    println!("setup");
    println!("  arti bootstrap      {bootstrap:6.1} s");
    println!("  connect (ring)      {connect:6.1} s");
    println!("send");
    println!(
        "  {} of {PACKET_COUNT} packets echoed ({:.1}% loss), {send:.1} s wall",
        received,
        100.0 * (PACKET_COUNT - received) as f64 / PACKET_COUNT as f64
    );
    println!("round-trip");
    println!("  min                 {:6.0} ms", ok[0]);
    println!("  p50                 {p50:6.0} ms");
    println!("  p95                 {p95:6.0} ms");
    println!("  p99                 {p99:6.0} ms");
    println!("  max                 {:6.0} ms", ok[ok.len() - 1]);
    println!("derived");
    println!("  one-way p50         {:6.0} ms", p50 / 2.0);
    println!("  jitter buffer (p95) {jitter_depth:6.0} ms");
    println!(
        "  mouth-to-ear        {:6.0} ms   (one-way p50 + jitter buffer + 20 ms codec)",
        p50 / 2.0 + jitter_depth + 20.0
    );
    println!("  longest late run    {worst_run:6} packets ({} ms of audio)", worst_run * 20);
    println!("\nITU-T G.114: under 150 ms is good, 150-400 ms degraded, over 400 ms");
    println!("unacceptable for interactive conversation.");
}
