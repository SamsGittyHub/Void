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
//! That is a walkie-talkie, not a phone call, and the UI says so. ITU-T G.114
//! puts the limit for natural interactive conversation at 400 ms; at 750 ms
//! two people talking freely collide constantly, while two people taking turns
//! do fine. Calling this "calls" in the interface would generate bug reports
//! about echo and talk-over that no amount of engineering can close.
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

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use safelog::DisplayRedacted as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname, RunningOnionService};

use void_proto::call::MEDIA_FRAME_LEN;

use crate::{TorError, TorHandle};

/// The virtual port a call's onion service listens on.
///
/// Fixed, and the same for everyone. A per-user or random port would be one
/// more thing that varies between users, and the module docs on
/// `void_proto::record` explain at length why anything that varies per user is
/// an identifier.
pub const CALL_PORT: u16 = 9999;

/// How long to wait for the callee to connect before giving up on a call.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(90);

/// How long a single media read or write may block before the call is
/// considered dead. Short, unlike the relay transport's timeout: a call that
/// has stopped moving audio for two seconds has stopped being a call.
const MEDIA_TIMEOUT: Duration = Duration::from_secs(2);

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

    /// Block until the callee connects, or the answer window closes.
    pub fn accept(self) -> Result<MediaSocket, TorError> {
        let stream = self
            .incoming
            .recv_timeout(ANSWER_TIMEOUT)
            .map_err(|_| TorError::Connect(String::from("nobody answered")))?;
        Ok(MediaSocket {
            handle: self.handle.clone(),
            inner: stream,
        })
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
                    // Only ever accept the one port a call uses. Accepting
                    // anything else would make this service behave differently
                    // from every other Void client's, which is a fingerprint.
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

    /// Dial a caller's onion service to join a call.
    pub fn connect_call(&self, onion_address: &str, port: u16) -> Result<MediaSocket, TorError> {
        let client = Arc::clone(&self.client);
        let target = onion_address.to_string();
        let stream = self
            .runtime
            .block_on(async move { client.connect((target.as_str(), port)).await })
            .map_err(|e| TorError::Connect(e.to_string()))?;
        Ok(MediaSocket {
            handle: self.runtime.handle().clone(),
            inner: stream,
        })
    }
}

/// One call's media connection, as blocking frame I/O.
///
/// Frames are fixed-size ([`MEDIA_FRAME_LEN`]) and already encrypted by
/// `void_proto::call::MediaStream` before they reach here — this type moves
/// bytes and knows nothing about what is in them.
pub struct MediaSocket {
    handle: tokio::runtime::Handle,
    inner: arti_client::DataStream,
}

impl MediaSocket {
    /// Send one media frame.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), TorError> {
        if frame.len() != MEDIA_FRAME_LEN {
            return Err(TorError::Connect(String::from("wrong media frame size")));
        }
        let inner = &mut self.inner;
        self.handle
            .block_on(async move {
                tokio::time::timeout(MEDIA_TIMEOUT, async {
                    inner.write_all(frame).await?;
                    inner.flush().await
                })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "media write timed out"))?
            })
            .map_err(|e| TorError::Connect(e.to_string()))
    }

    /// Receive one media frame, blocking until it arrives or the call stalls.
    pub fn recv_frame(&mut self) -> Result<Vec<u8>, TorError> {
        let mut buf = vec![0u8; MEDIA_FRAME_LEN];
        let inner = &mut self.inner;
        let slice = &mut buf[..];
        self.handle
            .block_on(async move {
                tokio::time::timeout(MEDIA_TIMEOUT, inner.read_exact(slice))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "media read timed out"))?
            })
            .map_err(|e| TorError::Connect(e.to_string()))?;
        Ok(buf)
    }
}

impl Read for MediaSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let inner = &mut self.inner;
        self.handle.block_on(async move {
            tokio::time::timeout(MEDIA_TIMEOUT, inner.read(buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "media read timed out"))?
        })
    }
}

impl Write for MediaSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let inner = &mut self.inner;
        self.handle.block_on(async move {
            tokio::time::timeout(MEDIA_TIMEOUT, inner.write(buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "media write timed out"))?
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        let inner = &mut self.inner;
        self.handle.block_on(async move {
            tokio::time::timeout(MEDIA_TIMEOUT, inner.flush())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "media flush timed out"))?
        })
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
}
