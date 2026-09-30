//! The media path for calls: paired ephemeral onion services (D-024).
//!
//! ## Why this is not the relay
//!
//! Everything else in Void is store-and-forward through an untrusted mailbox,
//! and deliberately so. Audio cannot be. A relay hop plus the retrieval
//! schedule puts mouth-to-ear delay in the tens of seconds, and the schedule
//! is a metadata defence that would have to be dismantled to fix it.
//!
//! So media takes a different path: the caller publishes a short-lived onion
//! service, the callee connects to it, and the audio never reaches the relay
//! at all. What the relay still carries is the *signalling* — offer, answer,
//! end — as ordinary encrypted messages, which is why a call still looks like
//! a handful of records in a queue and nothing more.
//!
//! ## What this costs, measured rather than assumed
//!
//! `experiments/onion-call/RESULTS.md` has the numbers from the live network:
//! round-trip p50 of 376–528 ms, p95 of 635–1112 ms, and zero loss across
//! 4,500 packets. Mouth-to-ear works out at roughly 470–870 ms once a jitter
//! buffer sized to p95 is added.
//!
//! That is a call with real lag — about a second each way, which is fine for
//! taking turns and bad for interrupting. It is a call rather than
//! push-to-talk (D-024): the microphone is open both ways, and the interface
//! says how long the delay is instead of making the user operate around it.
//!
//! ## One stream, two threads, and frames that stay whole
//!
//! A call sends and receives at once, so [`MediaSocket::split`] hands the
//! sending and receiving halves of the stream to two owners that share
//! nothing. Frames are fixed-size and carry no framing of their own, so a frame
//! must only ever be read or written whole: a reader that gave up halfway
//! through one would read every later frame out of alignment, and every one of
//! them would fail to authenticate for the rest of the call. So [`MediaReader`]
//! keeps a partly read frame across calls, and [`MediaWriter`] finishes a
//! partly written one before it starts the next. Tor stalls — runs of late
//! packets of half a second and more are in the measurements — are normal,
//! and a stall must cost audio, never the call.
//!
//! ## Ephemeral, and what that does and does not hide
//!
//! Each call gets a fresh service under its own nickname, and the keys live in
//! a directory the caller deletes when the call ends. A future call to the
//! same contact is a different onion address, so the address is not a stable
//! identifier anyone can follow between calls.
//!
//! What it does not hide: the callee learns the caller is online, and both
//! ends learn the other is present for the duration. That is inherent in a
//! direct connection and is the honest trade against the mailbox model, which
//! hides exactly that.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use safelog::DisplayRedacted as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname, RunningOnionService};
use tor_proto::stream::IncomingStreamRequest;

use void_proto::call::MEDIA_FRAME_LEN;

use crate::{TorError, TorHandle};

/// The virtual port a call's onion service listens on.
///
/// Fixed, and the same for everyone. A per-user or random port would be one
/// more thing that varies between users, and the module docs on
/// `void_proto::record` explain at length why anything that varies per user is
/// an identifier.
pub const CALL_PORT: u16 = 9999;

/// How long to wait for the callee to connect before giving up on a call:
/// exactly as long as the caller's engine waits for an answer
/// (`void_client::engine::CALLER_TIMEOUT_SECONDS`), so the service is not
/// torn down while the call is still ringing, nor kept once it has stopped.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(void_client::engine::CALLER_TIMEOUT_SECONDS);

/// How long a single receive waits for a frame before reporting that none
/// arrived. The call is not over when this passes — the platform decides that
/// from how many pass in a row — it just returns control so silence can be
/// played and a hang-up can be noticed.
const MEDIA_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a send may wait for Tor to take a frame before the next frame is
/// dropped instead. Short: audio twenty milliseconds late is worth sending,
/// audio a second late is not worth delaying everything behind it for.
const SEND_TIMEOUT: Duration = Duration::from_millis(250);

/// How often a blocked wait checks whether it has been cancelled. Bounds how
/// long hanging up can take to reach a thread that is waiting on the network.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// A published onion service waiting for one caller.
///
/// Dropping this stops publishing and deletes the service's key material,
/// which is what makes each call's address ephemeral.
pub struct CallHost {
    onion_address: String,
    #[allow(dead_code)]
    service: Arc<RunningOnionService>,
    incoming: mpsc::Receiver<arti_client::DataStream>,
    handle: tokio::runtime::Handle,
    key_dir: PathBuf,
}

impl Drop for CallHost {
    fn drop(&mut self) {
        // Best effort: the address must not outlive the call. A failure here
        // leaves a key on disk, which is a privacy problem rather than a
        // correctness one, so it is not worth panicking over.
        let _ = std::fs::remove_dir_all(&self.key_dir);
    }
}

impl CallHost {
    /// The address to put in a call offer.
    #[must_use]
    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }

    /// Block until the callee connects, the answer window closes, or
    /// `cancelled` is set — the caller hung up while it rang.
    ///
    /// Called the moment the service is published, not once an answer has
    /// come back through the relay: the callee dials as soon as they answer,
    /// and waiting a mailbox delay for the relayed answer before accepting
    /// left their audio queuing in a stream nobody read.
    pub fn accept(self, cancelled: &AtomicBool) -> Result<MediaSocket, TorError> {
        let deadline = Instant::now() + ANSWER_TIMEOUT;
        loop {
            if cancelled.load(Ordering::SeqCst) {
                return Err(TorError::Connect(String::from("the call was cancelled")));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(TorError::Connect(String::from("nobody answered")));
            }
            match self.incoming.recv_timeout(CANCEL_POLL.min(deadline - now)) {
                Ok(stream) => {
                    return Ok(MediaSocket {
                        handle: self.handle.clone(),
                        inner: stream,
                    })
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(TorError::Connect(String::from("the service stopped")));
                }
            }
        }
    }
}

impl TorHandle {
    /// Publish an ephemeral onion service for one call and return its address.
    ///
    /// `key_dir` is deleted when the returned [`CallHost`] drops, so a caller
    /// should hand this a directory it owns and nothing else lives in.
    ///
    /// Returns as soon as the address exists, which is before the service is
    /// reachable — the descriptor still has to reach the HSDirs, measured at
    /// around four seconds. That is deliberate: the offer can be queued
    /// immediately and the publish finishes while it waits for the peer's next
    /// retrieval slot, so the two delays overlap instead of adding.
    pub fn publish_call_service(&self, key_dir: &Path) -> Result<CallHost, TorError> {
        std::fs::create_dir_all(key_dir)
            .map_err(|e| TorError::Connect(format!("could not create call key dir: {e}")))?;

        // A fresh nickname per call, so arti generates a fresh identity rather
        // than reusing the previous call's address.
        let nickname = format!("call{}", nonce_suffix()?);
        let config = OnionServiceConfigBuilder::default()
            .nickname(
                nickname
                    .parse::<HsNickname>()
                    .map_err(|e| TorError::Connect(format!("bad nickname: {e}")))?,
            )
            .build()
            .map_err(|e| TorError::Connect(e.to_string()))?;

        let client = Arc::clone(&self.client);
        let (tx, rx) = mpsc::channel();

        let (service, onion_address) = self.runtime.block_on(async move {
            let (service, rend_requests) = client
                .launch_onion_service(config)
                .map_err(|e| TorError::Connect(e.to_string()))?
                .ok_or_else(|| TorError::Connect(String::from("onion service disabled")))?;

            let address = service
                .onion_address()
                .ok_or_else(|| TorError::Connect(String::from("service has no address")))?
                .display_unredacted()
                .to_string();

            tokio::spawn(async move {
                let mut streams = Box::pin(handle_rend_requests(rend_requests));
                while let Some(request) = streams.next().await {
                    // Only ever accept a BEGIN for the one port a call uses,
                    // and refuse everything else the way every other onion
                    // service does — an END with reason DONE. Behaving
                    // differently would make this service distinguishable from
                    // every other Void client's, which is a fingerprint.
                    let wanted = matches!(
                        request.request(),
                        IncomingStreamRequest::Begin(begin) if begin.port() == CALL_PORT
                    );
                    if !wanted {
                        let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
                        continue;
                    }
                    if let Ok(stream) = request.accept(Connected::new_empty()).await {
                        if tx.send(stream).is_err() {
                            break;
                        }
                    }
                }
            });

            Ok::<_, TorError>((service, address))
        })?;

        Ok(CallHost {
            onion_address,
            service,
            incoming: rx,
            handle: self.runtime.handle().clone(),
            key_dir: key_dir.to_path_buf(),
        })
    }

    /// Dial a caller's onion service to join a call. Gives up after
    /// [`crate::CONNECT_TIMEOUT`], for the reason given there: the callee would
    /// otherwise sit on "Connecting…" for as long as Arti cared to wait.
    pub fn connect_call(&self, onion_address: &str, port: u16) -> Result<MediaSocket, TorError> {
        let client = Arc::clone(&self.client);
        let target = onion_address.to_string();
        let stream = self
            .runtime
            .block_on(async move {
                tokio::time::timeout(
                    crate::CONNECT_TIMEOUT,
                    client.connect((target.as_str(), port)),
                )
                .await
            })
            .map_err(|_| TorError::Connect(String::from("timed out dialling the caller")))?
            .map_err(|e| TorError::Connect(e.to_string()))?;
        Ok(MediaSocket {
            handle: self.runtime.handle().clone(),
            inner: stream,
        })
    }
}

/// One call's media connection, before it is split for sending and receiving.
///
/// Frames are fixed-size ([`MEDIA_FRAME_LEN`]) and already encrypted by
/// `void_proto::call::MediaSealer` before they reach here — this type moves
/// bytes and knows nothing about what is in them.
pub struct MediaSocket {
    handle: tokio::runtime::Handle,
    inner: arti_client::DataStream,
}

impl MediaSocket {
    /// Separate the halves, for a sending thread and a receiving thread that
    /// must never wait on each other.
    #[must_use]
    pub fn split(self) -> (MediaReader, MediaWriter) {
        let (reader, writer) = self.inner.split();
        (
            MediaReader {
                handle: self.handle.clone(),
                inner: reader,
                buf: [0u8; MEDIA_FRAME_LEN],
                filled: 0,
            },
            MediaWriter {
                handle: self.handle,
                inner: writer,
                pending: Vec::with_capacity(2 * MEDIA_FRAME_LEN),
            },
        )
    }
}

/// The receiving half of a call's media stream. Generic only so the framing can
/// be tested over an in-memory stream; in use it is always Arti's.
pub struct MediaReader<R = arti_client::DataReader> {
    handle: tokio::runtime::Handle,
    inner: R,
    /// The frame being read, kept across calls so a stall mid-frame costs time
    /// and never alignment.
    buf: [u8; MEDIA_FRAME_LEN],
    filled: usize,
}

impl<R: AsyncRead + Unpin> MediaReader<R> {
    /// Wait up to two seconds for the next whole frame.
    ///
    /// `Ok(Some(frame))` is a frame; `Ok(None)` means none finished arriving
    /// in time — any part of one that did is kept for the next call; `Err`
    /// means the stream is closed, or `cancelled` was set.
    pub fn recv_frame(
        &mut self,
        cancelled: &AtomicBool,
    ) -> Result<Option<[u8; MEDIA_FRAME_LEN]>, TorError> {
        self.recv_frame_within(cancelled, MEDIA_TIMEOUT)
    }

    fn recv_frame_within(
        &mut self,
        cancelled: &AtomicBool,
        limit: Duration,
    ) -> Result<Option<[u8; MEDIA_FRAME_LEN]>, TorError> {
        let deadline = Instant::now() + limit;
        while self.filled < MEDIA_FRAME_LEN {
            if cancelled.load(Ordering::SeqCst) {
                return Err(TorError::Connect(String::from("the call was closed")));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let wait = CANCEL_POLL.min(deadline - now);
            let inner = &mut self.inner;
            let target = &mut self.buf[self.filled..];
            // `read` is cancellation-safe: when the timeout wins, nothing was
            // read, so nothing is lost. (`read_exact` is not — the reason this
            // is a loop over `read` rather than one `read_exact`.)
            let read = self
                .handle
                .block_on(async move { tokio::time::timeout(wait, inner.read(target)).await });
            match read {
                Err(_elapsed) => continue,
                Ok(Ok(0)) => {
                    return Err(TorError::Connect(String::from("the call's stream closed")))
                }
                Ok(Ok(n)) => self.filled += n,
                Ok(Err(e)) => return Err(TorError::Connect(e.to_string())),
            }
        }
        self.filled = 0;
        Ok(Some(self.buf))
    }
}

/// The sending half of a call's media stream. Generic only so the framing can
/// be tested over an in-memory stream; in use it is always Arti's.
pub struct MediaWriter<W = arti_client::DataWriter> {
    handle: tokio::runtime::Handle,
    inner: W,
    /// Bytes of an accepted frame that Tor has not yet taken. Always finished
    /// before another frame starts, so frames only ever go out whole.
    pending: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> MediaWriter<W> {
    /// Send one frame of exactly [`MEDIA_FRAME_LEN`] bytes.
    ///
    /// `Ok(true)` means the frame is on its way — possibly with its tail still
    /// waiting, which the next call finishes first. `Ok(false)` means it was
    /// dropped because the previous frame has still not gone: while the
    /// circuit is backed up, new audio is dropped rather than queued, since
    /// queued audio is just delay that never goes away. `Err` means the stream
    /// is closed.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<bool, TorError> {
        self.send_frame_within(frame, SEND_TIMEOUT)
    }

    fn send_frame_within(&mut self, frame: &[u8], limit: Duration) -> Result<bool, TorError> {
        if frame.len() != MEDIA_FRAME_LEN {
            return Err(TorError::Connect(String::from("wrong media frame size")));
        }
        if !self.pending.is_empty() {
            self.write_pending(limit)?;
            if !self.pending.is_empty() {
                return Ok(false);
            }
        }
        self.pending.extend_from_slice(frame);
        self.write_pending(limit)?;
        Ok(true)
    }

    /// Hand Tor as much of `pending` as it takes within `limit`, then flush.
    fn write_pending(&mut self, limit: Duration) -> Result<(), TorError> {
        let deadline = Instant::now() + limit;
        while !self.pending.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                return Ok(());
            }
            let wait = deadline - now;
            let inner = &mut self.inner;
            let data = &self.pending[..];
            // `write` is cancellation-safe: when the timeout wins, nothing was
            // written, and the unwritten bytes stay in `pending`.
            let written = self
                .handle
                .block_on(async move { tokio::time::timeout(wait, inner.write(data)).await });
            match written {
                Err(_elapsed) => return Ok(()),
                Ok(Ok(0)) => {
                    return Err(TorError::Connect(String::from("the call's stream closed")))
                }
                Ok(Ok(n)) => {
                    self.pending.drain(..n);
                }
                Ok(Err(e)) => return Err(TorError::Connect(e.to_string())),
            }
        }
        let inner = &mut self.inner;
        match self
            .handle
            .block_on(async move { tokio::time::timeout(limit, inner.flush()).await })
        {
            Ok(Err(e)) => Err(TorError::Connect(e.to_string())),
            // Flushed, or still flushing: either way the bytes are Tor's now.
            Ok(Ok(())) | Err(_) => Ok(()),
        }
    }
}

/// A short random suffix, so each call's service nickname is distinct.
fn nonce_suffix() -> Result<String, TorError> {
    let bytes =
        void_crypto::rand::bytes16().map_err(|_| TorError::Runtime(String::from("entropy")))?;
    let mut s = String::with_capacity(16);
    for b in bytes.iter().take(8) {
        // Nicknames are restricted to a conservative alphabet; lowercase
        // letters are always safe.
        s.push((b'a' + (b % 26)) as char);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nicknames_are_distinct_and_well_formed() {
        let a = nonce_suffix().unwrap();
        let b = nonce_suffix().unwrap();
        assert_ne!(a, b, "each call needs its own service identity");
        for s in [&a, &b] {
            assert_eq!(s.len(), 8);
            assert!(s.chars().all(|c| c.is_ascii_lowercase()));
            // The full nickname must parse, or publishing fails at runtime
            // rather than here.
            assert!(format!("call{s}").parse::<HsNickname>().is_ok());
        }
    }

    #[test]
    fn the_call_port_is_a_constant_not_a_setting() {
        // FR-MSG-02's reasoning applied to calls: anything that varies per
        // user is a way to tell users apart.
        assert_eq!(CALL_PORT, 9999);
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn frame(fill: u8) -> [u8; MEDIA_FRAME_LEN] {
        [fill; MEDIA_FRAME_LEN]
    }

    #[test]
    fn media_survives_a_stall_mid_frame() {
        // Half a frame arrives, then the circuit stalls for longer than one
        // receive waits. The half must be kept: dropping it put every later
        // frame out of alignment, and a call went silent for good.
        let rt = runtime();
        let (mut far, near) = tokio::io::duplex(4 * MEDIA_FRAME_LEN);
        let mut reader = MediaReader {
            handle: rt.handle().clone(),
            inner: near,
            buf: [0u8; MEDIA_FRAME_LEN],
            filled: 0,
        };
        let never = AtomicBool::new(false);
        let patience = Duration::from_millis(200);

        rt.block_on(far.write_all(&frame(1)[..50])).unwrap();
        assert_eq!(reader.recv_frame_within(&never, patience).unwrap(), None);

        rt.block_on(async {
            far.write_all(&frame(1)[50..]).await?;
            far.write_all(&frame(2)).await
        })
        .unwrap();
        assert_eq!(
            reader.recv_frame_within(&never, patience).unwrap(),
            Some(frame(1)),
            "the half that arrived before the stall is completed, not dropped"
        );
        assert_eq!(
            reader.recv_frame_within(&never, patience).unwrap(),
            Some(frame(2)),
            "and every frame after it is still aligned"
        );

        drop(far);
        assert!(
            reader.recv_frame_within(&never, patience).is_err(),
            "a closed stream is reported as closed, not as silence"
        );
    }

    #[test]
    fn a_cancelled_receive_returns_promptly() {
        let rt = runtime();
        let (_far, near) = tokio::io::duplex(MEDIA_FRAME_LEN);
        let mut reader = MediaReader {
            handle: rt.handle().clone(),
            inner: near,
            buf: [0u8; MEDIA_FRAME_LEN],
            filled: 0,
        };
        let cancelled = AtomicBool::new(true);
        let started = Instant::now();
        assert!(reader.recv_frame(&cancelled).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn a_backed_up_writer_drops_new_frames_but_never_splits_one() {
        // Tor will not take more: the first frame goes partly out and its tail
        // waits; the next frame is dropped rather than queued behind it; and
        // once the circuit drains, what arrives is whole frames, in order.
        let rt = runtime();
        let (mut far, near) = tokio::io::duplex(64);
        let mut writer = MediaWriter {
            handle: rt.handle().clone(),
            inner: near,
            pending: Vec::new(),
        };
        let patience = Duration::from_millis(100);

        assert!(writer.send_frame_within(&frame(1), patience).unwrap());
        assert!(!writer.pending.is_empty(), "its tail is waiting");
        assert!(
            !writer.send_frame_within(&frame(2), patience).unwrap(),
            "backed up: the new frame is dropped, not queued"
        );

        // The far end reads everything; the writer can finish frame 1 and send 3.
        let reader = rt.spawn(async move {
            let mut got = vec![0u8; 2 * MEDIA_FRAME_LEN];
            far.read_exact(&mut got).await.map(|_| got)
        });
        let mut sent_third = false;
        for _ in 0..50 {
            if writer.send_frame_within(&frame(3), patience).unwrap() {
                sent_third = true;
                break;
            }
        }
        assert!(sent_third);
        while !writer.pending.is_empty() {
            writer.write_pending(patience).unwrap();
        }
        let got = rt.block_on(reader).unwrap().unwrap();
        assert_eq!(&got[..MEDIA_FRAME_LEN], &frame(1)[..]);
        assert_eq!(&got[MEDIA_FRAME_LEN..], &frame(3)[..]);
    }

    #[test]
    fn the_service_waits_exactly_as_long_as_the_caller_does() {
        assert_eq!(
            ANSWER_TIMEOUT,
            Duration::from_secs(void_client::engine::CALLER_TIMEOUT_SECONDS)
        );
    }
}
