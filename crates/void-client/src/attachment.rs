//! Moving an attachment's sealed blob to and from the relay (D-032).
//!
//! ## Not through the transport, and why
//!
//! [`crate::transport::Transport`] carries one frame per emission slot over
//! the messaging circuit, and that cadence is the whole of the metadata
//! defence D-015 describes. A file at that cadence takes an hour. So a blob
//! does not go that way at all: the caller hands in a stream of its own — in
//! the apps, a fresh circuit from `void_tor::TorHandle::open_isolated`, which
//! shares nothing with the messaging circuit — and this module keeps it as
//! full as the circuit allows, with up to [`WINDOW`] requests in flight.
//!
//! What that costs is stated in D-032 and in the interface: a transfer is a
//! burst anyone watching the connection can see, sized roughly like the file.
//! Nothing here pretends otherwise; it only makes sure the burst is as short
//! as it can be.
//!
//! ## Pipelining without deadlock
//!
//! The relay answers frames in the order it reads them and never reads ahead.
//! A client that wrote without reading would eventually fill every buffer
//! between itself and the relay with answers nobody had read, and the relay
//! would stop reading in turn. Keeping at most [`WINDOW`] requests unanswered
//! bounds what can pile up to a few dozen frames, far below what those buffers
//! hold.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use void_proto::attachment::SEALED_CHUNK_LEN;
use void_relay::protocol::{BlobGet, BlobPut, Frame, FrameType, FRAME_SIZE};

use crate::{ClientError, ClientResult};

/// Requests in flight at once: about 100 KB, enough to keep a circuit with a
/// half-second round trip moving at a couple of hundred kilobytes a second.
pub const WINDOW: u32 = 48;

/// How far a transfer has got, readable from another thread while it runs, and
/// the switch that stops it.
#[derive(Default)]
pub struct Progress {
    done: AtomicU32,
    total: AtomicU32,
    cancelled: AtomicBool,
}

impl Progress {
    /// A transfer not yet started.
    #[must_use]
    pub fn new() -> Progress {
        Progress::default()
    }

    /// Chunks the relay has confirmed or handed over so far.
    #[must_use]
    pub fn done(&self) -> u32 {
        self.done.load(Ordering::Relaxed)
    }

    /// Chunks in the whole transfer, padding included. Zero until it starts.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.total.load(Ordering::Relaxed)
    }

    /// Stop the transfer at the next chunk.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether [`Progress::cancel`] was called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn start(&self, total: u32) {
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    fn advance(&self, done: u32) {
        self.done.store(done, Ordering::Relaxed);
    }
}

fn write_frame<S: Write>(stream: &mut S, frame: &Frame) -> ClientResult<()> {
    let bytes = frame.encode().map_err(|_| ClientError::Protocol)?;
    stream
        .write_all(&bytes)
        .map_err(|_| ClientError::TorUnavailable)
}

fn read_frame<S: Read>(stream: &mut S) -> ClientResult<Frame> {
    let mut buf = vec![0u8; FRAME_SIZE];
    stream
        .read_exact(&mut buf)
        .map_err(|_| ClientError::TorUnavailable)?;
    Frame::decode(&buf).map_err(|_| ClientError::Protocol)
}

/// Park a blob of `count` sealed chunks on the relay, under `token`.
///
/// `chunk(i)` produces sealed chunk `i` — read from wherever the caller keeps
/// them — and is called in order, each index once. Returns once the relay has
/// acknowledged every chunk. A refusal (the relay is full, or the token names
/// a blob that is not this one) is [`ClientError::AttachmentRefused`]; a
/// broken stream is [`ClientError::TorUnavailable`], and the upload can simply
/// be run again: chunks the relay already holds are acknowledged a second
/// time, not stored twice.
pub fn upload<S, F>(
    stream: &mut S,
    token: &[u8; 32],
    count: u32,
    mut chunk: F,
    progress: &Progress,
) -> ClientResult<()>
where
    S: Read + Write,
    F: FnMut(u32) -> ClientResult<Vec<u8>>,
{
    progress.start(count);
    let mut sent = 0u32;
    let mut acked = 0u32;
    while acked < count {
        if progress.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        while sent < count && sent - acked < WINDOW {
            let sealed = chunk(sent)?;
            if sealed.len() != SEALED_CHUNK_LEN {
                return Err(ClientError::Protocol);
            }
            let put = BlobPut {
                token: *token,
                index: sent,
                count,
                sealed,
            };
            write_frame(stream, &Frame::new(FrameType::BlobPut, put.encode()))?;
            sent += 1;
        }
        stream.flush().map_err(|_| ClientError::TorUnavailable)?;
        let response = read_frame(stream)?;
        if response.kind != FrameType::Ack {
            return Err(ClientError::AttachmentRefused);
        }
        acked += 1;
        progress.advance(acked);
    }
    Ok(())
}

/// Fetch every chunk of a blob of `count` chunks, handing each to
/// `sink(index, sealed)` in order.
///
/// Every chunk is fetched, padding included: fetching only the file's own
/// would tell the relay its real size, which the padding exists to hide. A
/// chunk the relay does not have is [`ClientError::AttachmentUnavailable`] —
/// the blob expired, or was never finished. Whether a chunk *authenticates*
/// is the sink's to decide; it holds the key.
pub fn download<S, F>(
    stream: &mut S,
    token: &[u8; 32],
    count: u32,
    mut sink: F,
    progress: &Progress,
) -> ClientResult<()>
where
    S: Read + Write,
    F: FnMut(u32, &[u8]) -> ClientResult<()>,
{
    progress.start(count);
    let mut requested = 0u32;
    let mut received = 0u32;
    while received < count {
        if progress.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        while requested < count && requested - received < WINDOW {
            let get = BlobGet {
                token: *token,
                index: requested,
            };
            write_frame(stream, &Frame::new(FrameType::BlobGet, get.encode()))?;
            requested += 1;
        }
        stream.flush().map_err(|_| ClientError::TorUnavailable)?;
        let response = read_frame(stream)?;
        if response.kind != FrameType::BlobChunk || response.body.len() != SEALED_CHUNK_LEN {
            return Err(ClientError::AttachmentUnavailable);
        }
        sink(received, &response.body)?;
        received += 1;
        progress.advance(received);
    }
    Ok(())
}

/// Ask the relay to delete a blob. The recipient does this once the file is
/// safely on its phone, so the relay holds it no longer than it must; the
/// relay acknowledges whether or not it held anything.
pub fn delete<S: Read + Write>(stream: &mut S, token: &[u8; 32]) -> ClientResult<()> {
    write_frame(stream, &Frame::new(FrameType::BlobDelete, token.to_vec()))?;
    stream.flush().map_err(|_| ClientError::TorUnavailable)?;
    match read_frame(stream)?.kind {
        FrameType::Ack => Ok(()),
        _ => Err(ClientError::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::Arc;
    use void_proto::attachment::{open_chunk, seal_chunk, AttachmentSecrets};
    use void_relay::server::{serve_stream, NoPush, Relay};
    use void_relay::store::Config;

    /// One end of an in-memory duplex byte stream: no sockets, so nothing
    /// here could reach a network even by mistake.
    struct Pipe {
        rx: Receiver<Vec<u8>>,
        tx: Sender<Vec<u8>>,
        pending: Vec<u8>,
    }

    fn pipe() -> (Pipe, Pipe) {
        let (a_tx, b_rx) = channel();
        let (b_tx, a_rx) = channel();
        (
            Pipe {
                rx: a_rx,
                tx: a_tx,
                pending: Vec::new(),
            },
            Pipe {
                rx: b_rx,
                tx: b_tx,
                pending: Vec::new(),
            },
        )
    }

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pending.is_empty() {
                match self.rx.recv() {
                    Ok(bytes) => self.pending = bytes,
                    Err(_) => return Ok(0),
                }
            }
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.tx
                .send(buf.to_vec())
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A relay serving one connection on its own thread, and the client end.
    fn connect(relay: &Arc<Relay>) -> Pipe {
        let (client, mut server) = pipe();
        let relay = Arc::clone(relay);
        std::thread::spawn(move || {
            let _ = serve_stream(&relay, &mut server);
        });
        client
    }

    fn relay() -> Arc<Relay> {
        Arc::new(Relay::new(Config::default(), Box::new(NoPush)))
    }

    #[test]
    fn a_blob_crosses_the_relay_and_opens_at_the_other_end() {
        let relay = relay();
        let secrets = AttachmentSecrets::generate().unwrap();
        let blob = secrets.blob_id();
        // Larger than one window, so the pipeline has to refill.
        let count = WINDOW * 3 + 5;
        let file: Vec<u8> = (0..(count as usize * 1984 - 77))
            .map(|i| (i % 251) as u8)
            .collect();

        let progress = Progress::new();
        let mut up = connect(&relay);
        upload(
            &mut up,
            &secrets.token,
            count,
            |i| {
                let start = i as usize * 1984;
                let end = (start + 1984).min(file.len());
                seal_chunk(&secrets.key, &blob, i, count, &file[start.min(end)..end])
                    .map_err(|_| ClientError::Protocol)
            },
            &progress,
        )
        .unwrap();
        assert_eq!((progress.done(), progress.total()), (count, count));
        assert_eq!(relay.metrics().unwrap().blobs, 1);

        let mut received = Vec::new();
        let mut down = connect(&relay);
        let fetched = Progress::new();
        download(
            &mut down,
            &secrets.token,
            count,
            |i, sealed| {
                let plain = open_chunk(&secrets.key, &blob, i, count, sealed)
                    .map_err(|_| ClientError::Protocol)?;
                received.extend_from_slice(&plain);
                Ok(())
            },
            &fetched,
        )
        .unwrap();
        received.truncate(file.len());
        assert_eq!(received, file);
        assert_eq!(fetched.done(), count);

        delete(&mut down, &secrets.token).unwrap();
        assert_eq!(
            relay.metrics().unwrap().blobs,
            0,
            "the recipient cleaned up"
        );
    }

    #[test]
    fn an_interrupted_upload_can_simply_run_again() {
        let relay = relay();
        let secrets = AttachmentSecrets::generate().unwrap();
        let blob = secrets.blob_id();
        let count = 20;
        let seal = |i: u32| {
            seal_chunk(&secrets.key, &blob, i, count, &[i as u8; 10])
                .map_err(|_| ClientError::Protocol)
        };

        // First attempt dies after 7 chunks.
        let mut up = connect(&relay);
        let failed = upload(
            &mut up,
            &secrets.token,
            count,
            |i| {
                if i < 7 {
                    seal(i)
                } else {
                    Err(ClientError::TorUnavailable)
                }
            },
            &Progress::new(),
        );
        assert_eq!(failed, Err(ClientError::TorUnavailable));

        // Second attempt sends everything again and succeeds; the chunks that
        // made it the first time are acknowledged, not refused.
        let mut again = connect(&relay);
        upload(&mut again, &secrets.token, count, seal, &Progress::new()).unwrap();
        assert_eq!(
            relay.metrics().unwrap().blob_bytes,
            count as usize * SEALED_CHUNK_LEN
        );
    }

    #[test]
    fn a_missing_blob_is_reported_not_waited_for() {
        let relay = relay();
        let mut down = connect(&relay);
        let result = download(&mut down, &[3u8; 32], 8, |_, _| Ok(()), &Progress::new());
        assert_eq!(result, Err(ClientError::AttachmentUnavailable));
    }

    #[test]
    fn a_full_relay_refuses_and_says_so() {
        let relay = Arc::new(Relay::new(
            Config {
                blobs: void_relay::blobs::BlobConfig {
                    capacity_bytes: 4 * SEALED_CHUNK_LEN,
                    ..void_relay::blobs::BlobConfig::default()
                },
                ..Config::default()
            },
            Box::new(NoPush),
        ));
        let secrets = AttachmentSecrets::generate().unwrap();
        let blob = secrets.blob_id();
        let mut up = connect(&relay);
        let result = upload(
            &mut up,
            &secrets.token,
            8,
            |i| seal_chunk(&secrets.key, &blob, i, 8, &[]).map_err(|_| ClientError::Protocol),
            &Progress::new(),
        );
        assert_eq!(result, Err(ClientError::AttachmentRefused));
    }

    #[test]
    fn a_cancelled_transfer_stops() {
        let relay = relay();
        let progress = Progress::new();
        progress.cancel();
        let mut up = connect(&relay);
        let result = upload(
            &mut up,
            &[1u8; 32],
            8,
            |_| Ok(vec![0u8; SEALED_CHUNK_LEN]),
            &progress,
        );
        assert_eq!(result, Err(ClientError::Cancelled));
    }
}
