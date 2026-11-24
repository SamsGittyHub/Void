//! The relay's blob store: sealed files, parked until collected (D-032).
//!
//! ## The audit surface, again
//!
//! [`crate::store`] holds the list of what a seized relay yields for messages.
//! This is the same list for files, written to the same rule — any addition
//! should be conspicuous. What is held per blob:
//!
//! - its id: sixteen bytes of a hash of the token its uploader presented, so
//!   the table holds addresses and never the capability that names them,
//! - its chunk count, and the sealed chunks themselves, each exactly
//!   [`SEALED_CHUNK_LEN`] bytes and opaque — the key never comes near a relay,
//! - two times: when an unfinished upload is given up on, and when the blob
//!   expires.
//!
//! What is deliberately **not** held, and must never be added:
//!
//! - the token, or anything that would let the table itself be used to fetch,
//! - who uploaded or downloaded a blob, any circuit or connection detail, or
//!   whether and how often it was downloaded,
//! - any link between a blob and a queue. The message that points at a blob
//!   travels in a queue as an ordinary sealed record, and nothing in it is
//!   visible here.
//!
//! ## Who may do what
//!
//! Anyone holding a blob's token may put chunks into it, fetch them, or delete
//! it — the same shape as a queue, where anyone holding the deposit key may
//! deposit. Only the two ends of one conversation hold a given token: the
//! uploader made it, and the only copy that leaves their phone travels inside
//! the ratchet. Chunks are write-once, so the recipient, who holds the token
//! too, cannot replace what was sent; and every chunk is sealed with its index
//! and the blob's chunk count, so the relay cannot either without the
//! recipient noticing.
//!
//! ## What bounds it
//!
//! Uploads are anonymous, so nothing per-user can be limited. What is limited
//! is total bytes actually held ([`BlobConfig::capacity_bytes`]) — counted as
//! chunks arrive rather than reserved when a blob is announced, so claiming a
//! huge blob costs a flooder exactly as much bandwidth as filling one — and
//! time: an upload not finished within [`BlobConfig::upload_window_seconds`]
//! is deleted, and every blob within [`BlobConfig::ttl_seconds`].

use std::collections::HashMap;

use void_proto::attachment::{blob_id, BlobId, MAX_CHUNKS, SEALED_CHUNK_LEN};

use crate::{RelayError, RelayResult};

/// How long a blob is held, by default: seven days. Half a queue record's, on
/// the reasoning that a file is bulkier to hold and its pointer will already
/// have reached a phone that runs at all in that time.
pub const DEFAULT_BLOB_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// How long an upload may stay unfinished, by default: one hour.
pub const DEFAULT_UPLOAD_WINDOW_SECONDS: u64 = 60 * 60;

/// The most blob bytes held at once, by default: one gibibyte.
pub const DEFAULT_BLOB_CAPACITY_BYTES: usize = 1024 * 1024 * 1024;

/// Limits for the blob store.
#[derive(Clone, Copy, Debug)]
pub struct BlobConfig {
    /// How long a blob is held once its upload began.
    pub ttl_seconds: u64,
    /// How long an upload may take before what arrived is deleted.
    pub upload_window_seconds: u64,
    /// The most sealed bytes held across every blob.
    pub capacity_bytes: usize,
    /// The most chunks one blob may have.
    pub max_chunks: u32,
}

impl Default for BlobConfig {
    fn default() -> Self {
        BlobConfig {
            ttl_seconds: DEFAULT_BLOB_TTL_SECONDS,
            upload_window_seconds: DEFAULT_UPLOAD_WINDOW_SECONDS,
            capacity_bytes: DEFAULT_BLOB_CAPACITY_BYTES,
            max_chunks: MAX_CHUNKS,
        }
    }
}

struct Blob {
    chunks: Vec<Option<Box<[u8]>>>,
    present: u32,
    /// When an unfinished upload is given up on.
    finish_by: u64,
    /// When the blob is deleted regardless.
    expires_at: u64,
}

impl Blob {
    fn is_complete(&self) -> bool {
        self.present as usize == self.chunks.len()
    }
}

/// Every blob this relay holds.
pub struct BlobStore {
    blobs: HashMap<BlobId, Blob>,
    held_bytes: usize,
    config: BlobConfig,
}

impl BlobStore {
    /// An empty store.
    #[must_use]
    pub fn new(config: BlobConfig) -> BlobStore {
        BlobStore {
            blobs: HashMap::new(),
            held_bytes: 0,
            config,
        }
    }

    /// Store chunk `index` of the blob `token` names, which has `count` chunks.
    ///
    /// The first put names the count; every later one must agree. Putting the
    /// same bytes twice succeeds — a client resuming after a dropped circuit
    /// cannot know which of its last chunks arrived — but different bytes at
    /// an index already filled are refused.
    pub fn put(
        &mut self,
        token: &[u8; 32],
        index: u32,
        count: u32,
        sealed: &[u8],
        now: u64,
    ) -> RelayResult<()> {
        if sealed.len() != SEALED_CHUNK_LEN
            || count == 0
            || count > self.config.max_chunks
            || index >= count
        {
            return Err(RelayError::Refused);
        }
        let id = blob_id(token);
        let capacity = self.config.capacity_bytes;
        if !self.blobs.contains_key(&id) {
            if self.held_bytes + SEALED_CHUNK_LEN > capacity {
                return Err(RelayError::Refused);
            }
            self.blobs.insert(
                id,
                Blob {
                    chunks: vec![None; count as usize],
                    present: 0,
                    finish_by: now.saturating_add(self.config.upload_window_seconds),
                    expires_at: now.saturating_add(self.config.ttl_seconds),
                },
            );
        }
        let blob = self.blobs.get_mut(&id).ok_or(RelayError::Refused)?;
        if blob.chunks.len() != count as usize || now > blob.expires_at {
            return Err(RelayError::Refused);
        }
        let slot = &mut blob.chunks[index as usize];
        if let Some(existing) = slot {
            return if existing.as_ref() == sealed {
                Ok(())
            } else {
                Err(RelayError::Refused)
            };
        }
        if self.held_bytes + SEALED_CHUNK_LEN > capacity {
            return Err(RelayError::Refused);
        }
        *slot = Some(sealed.to_vec().into_boxed_slice());
        blob.present += 1;
        self.held_bytes += SEALED_CHUNK_LEN;
        Ok(())
    }

    /// Chunk `index` of the blob `token` names, if it is held. Nothing about
    /// the fetch is recorded.
    pub fn get(&self, token: &[u8; 32], index: u32, now: u64) -> RelayResult<Vec<u8>> {
        let blob = self.blobs.get(&blob_id(token)).ok_or(RelayError::Refused)?;
        if now > blob.expires_at {
            return Err(RelayError::Refused);
        }
        blob.chunks
            .get(index as usize)
            .and_then(|c| c.as_ref())
            .map(|c| c.to_vec())
            .ok_or(RelayError::Refused)
    }

    /// Delete the blob `token` names, if there is one. The recipient does this
    /// once it holds the file, so the relay holds it no longer than it must.
    pub fn delete(&mut self, token: &[u8; 32]) {
        if let Some(blob) = self.blobs.remove(&blob_id(token)) {
            self.held_bytes -= blob.present as usize * SEALED_CHUNK_LEN;
        }
    }

    /// Delete expired blobs and abandoned uploads. Returns how many went.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.blobs.len();
        let mut freed = 0usize;
        self.blobs.retain(|_, blob| {
            let keep = now <= blob.expires_at && (blob.is_complete() || now <= blob.finish_by);
            if !keep {
                freed += blob.present as usize * SEALED_CHUNK_LEN;
            }
            keep
        });
        self.held_bytes -= freed;
        before - self.blobs.len()
    }

    /// How many blobs are held. Aggregate only, like every relay metric.
    #[must_use]
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    /// How many sealed bytes are held across every blob.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> BlobStore {
        BlobStore::new(BlobConfig::default())
    }

    fn chunk(fill: u8) -> Vec<u8> {
        vec![fill; SEALED_CHUNK_LEN]
    }

    #[test]
    fn chunks_go_in_and_come_out() {
        let mut s = store();
        let token = [1u8; 32];
        for i in 0..4 {
            s.put(&token, i, 4, &chunk(i as u8), 0).unwrap();
        }
        for i in 0..4 {
            assert_eq!(s.get(&token, i, 0).unwrap(), chunk(i as u8));
        }
        assert_eq!(s.blob_count(), 1);
        assert_eq!(s.held_bytes(), 4 * SEALED_CHUNK_LEN);
    }

    #[test]
    fn a_chunk_cannot_be_replaced_but_can_be_resent() {
        let mut s = store();
        let token = [2u8; 32];
        s.put(&token, 0, 2, &chunk(1), 0).unwrap();
        assert!(
            s.put(&token, 0, 2, &chunk(1), 0).is_ok(),
            "an identical resend"
        );
        assert!(
            s.put(&token, 0, 2, &chunk(9), 0).is_err(),
            "a different chunk"
        );
        assert_eq!(s.get(&token, 0, 0).unwrap(), chunk(1));
        assert_eq!(
            s.held_bytes(),
            SEALED_CHUNK_LEN,
            "the resend was not counted twice"
        );
    }

    #[test]
    fn the_count_is_fixed_by_the_first_chunk() {
        let mut s = store();
        let token = [3u8; 32];
        s.put(&token, 0, 8, &chunk(0), 0).unwrap();
        assert!(s.put(&token, 1, 9, &chunk(0), 0).is_err());
        assert!(
            s.put(&token, 8, 8, &chunk(0), 0).is_err(),
            "index past the count"
        );
        assert!(s.put(&[4u8; 32], 0, MAX_CHUNKS + 1, &chunk(0), 0).is_err());
        assert!(s.put(&[4u8; 32], 0, 0, &chunk(0), 0).is_err());
        assert!(
            s.put(&[4u8; 32], 0, 1, &[0u8; 10], 0).is_err(),
            "wrong size"
        );
    }

    #[test]
    fn the_table_holds_the_id_not_the_token() {
        // A seized relay's table must not double as a list of capabilities.
        let mut s = store();
        let token = [5u8; 32];
        s.put(&token, 0, 1, &chunk(0), 0).unwrap();
        let id = *s.blobs.keys().next().unwrap();
        assert_eq!(id, blob_id(&token));
        assert_ne!(&id[..], &token[..16]);
    }

    #[test]
    fn missing_and_unknown_chunks_are_refused_alike() {
        let mut s = store();
        let token = [6u8; 32];
        s.put(&token, 0, 3, &chunk(0), 0).unwrap();
        assert!(s.get(&token, 1, 0).is_err());
        assert!(s.get(&token, 7, 0).is_err());
        assert!(s.get(&[7u8; 32], 0, 0).is_err());
    }

    #[test]
    fn capacity_counts_bytes_that_arrived_not_bytes_announced() {
        let mut s = BlobStore::new(BlobConfig {
            capacity_bytes: 3 * SEALED_CHUNK_LEN,
            ..BlobConfig::default()
        });
        // Announcing a huge blob costs one chunk of capacity, not its size.
        s.put(&[1u8; 32], 0, 20_000, &chunk(0), 0).unwrap();
        s.put(&[2u8; 32], 0, 2, &chunk(0), 0).unwrap();
        s.put(&[2u8; 32], 1, 2, &chunk(0), 0).unwrap();
        assert!(s.put(&[3u8; 32], 0, 1, &chunk(0), 0).is_err(), "full");
        s.delete(&[2u8; 32]);
        assert_eq!(s.held_bytes(), SEALED_CHUNK_LEN);
        s.put(&[3u8; 32], 0, 1, &chunk(0), 0).unwrap();
    }

    #[test]
    fn unfinished_uploads_and_expired_blobs_are_swept() {
        let cfg = BlobConfig::default();
        let mut s = BlobStore::new(cfg);
        s.put(&[1u8; 32], 0, 2, &chunk(0), 0).unwrap(); // never finished
        s.put(&[2u8; 32], 0, 1, &chunk(0), 0).unwrap(); // complete
        assert_eq!(s.sweep(cfg.upload_window_seconds), 0);
        assert_eq!(
            s.sweep(cfg.upload_window_seconds + 1),
            1,
            "the abandoned upload"
        );
        assert!(s.get(&[2u8; 32], 0, cfg.upload_window_seconds + 1).is_ok());
        assert!(
            s.get(&[2u8; 32], 0, cfg.ttl_seconds + 1).is_err(),
            "expired"
        );
        assert_eq!(s.sweep(cfg.ttl_seconds + 1), 1);
        assert_eq!(s.held_bytes(), 0);
        assert_eq!(s.blob_count(), 0);
    }

    #[test]
    fn deleting_is_silent_about_whether_there_was_anything() {
        let mut s = store();
        s.delete(&[9u8; 32]);
        s.put(&[9u8; 32], 0, 1, &chunk(0), 0).unwrap();
        s.delete(&[9u8; 32]);
        assert!(s.get(&[9u8; 32], 0, 0).is_err());
        assert_eq!(s.held_bytes(), 0);
    }
}
