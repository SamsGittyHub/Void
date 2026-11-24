//! Attachments: files that travel beside a message, not inside it.
//!
//! ## Why a file cannot simply be a long message
//!
//! A message leaves this device one fixed-size record per emission slot —
//! [`crate::record::RECORD_SIZE`] bytes every [`crate::record::PAD_INTERVAL_MS`]
//! — and that rate is the metadata defence: an observer cannot tell a slot that
//! carries a message from one that carries padding (D-015). It is also about
//! 200 bytes a second. A photo would take ten minutes; a document an hour, and
//! [`crate::record::MAX_FRAGMENTS`] caps a message at half a megabyte anyway.
//!
//! So a file is carried the other way round. Its bytes are sealed under a key
//! made for that one file and parked on the relay as a *blob*, over a separate
//! Tor circuit, at whatever speed the circuit allows. What goes through the
//! ratchet is only the [`Attachment`] — the blob's address, its key, its real
//! size, its name — which is one record like any short message. The recipient
//! fetches the blob over a circuit of its own, whenever it next runs.
//!
//! ## What the relay learns, and what it does not
//!
//! It holds ciphertext under a key it never sees, at an address derived from a
//! token only the two ends know (`blob id = KDF(token)`, so the relay's own
//! table holds no capability). It learns roughly how big the file is — the
//! chunk count is padded with Padmé (Nikitin et al., PETS 2019), which leaks
//! O(log log n) bits and costs at most 12% — and when it was uploaded and
//! downloaded. Upload and download each use a fresh isolated circuit, so a
//! blob is not tied to either party's messaging circuit by the circuit itself;
//! timing is another matter, and D-032 says so rather than pretending.
//!
//! Every chunk is sealed with the chunk's index and the blob's chunk count as
//! associated data, so a relay cannot reorder, drop, swap or truncate chunks
//! without the recipient noticing, and cannot splice two blobs together.
//!
//! ## Nonces
//!
//! Chunk `i` is sealed with nonce `i` under a key generated for this attachment
//! alone, and each index is sealed exactly once. A second send of the same
//! file is a new [`AttachmentSecrets`] — a new key — so no (key, nonce) pair
//! repeats.

use alloc::string::String;
use alloc::vec::Vec;

use void_crypto::{aead, blake3, rand, Zeroize};

use crate::wire::{Reader, Writer};
use crate::{ProtoError, Result};

/// Plaintext bytes per chunk. Sized so one sealed chunk, its token, index and
/// count fill one relay frame (`void_relay::protocol::FRAME_BODY_CAPACITY`).
pub const CHUNK_LEN: usize = 1984;

/// Bytes of one sealed chunk: the plaintext plus the AEAD tag.
pub const SEALED_CHUNK_LEN: usize = CHUNK_LEN + aead::TAG_LEN;

/// The largest file Void will send.
///
/// Bounded by what a phone holds comfortably in memory while it seals or
/// opens one, and by what a Tor circuit carries in a few minutes — at a
/// typical 100–300 KB/s, this is two to five.
pub const MAX_ATTACHMENT_BYTES: u64 = 48 * 1024 * 1024;

/// Every blob is at least this many chunks (about 16 KB), so that small files
/// are not told apart by size at all.
pub const MIN_CHUNKS: u32 = 8;

/// Longest file name carried, in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// Longest media type carried, in bytes.
pub const MAX_MIME_LEN: usize = 127;

/// Longest caption carried, in bytes.
pub const MAX_CAPTION_LEN: usize = 4096;

/// The chunk count of the largest file, after padding: the most a relay is
/// ever asked to hold for one blob.
pub const MAX_CHUNKS: u32 = padme(data_chunks(MAX_ATTACHMENT_BYTES));

/// A blob's address on the relay. A hash of the token, so the relay's own table
/// holds addresses and never the capability that names them.
pub type BlobId = [u8; 16];

/// How many chunks carry the file's own bytes.
#[must_use]
pub const fn data_chunks(size: u64) -> u32 {
    let n = size.div_ceil(CHUNK_LEN as u64);
    if n == 0 {
        1
    } else if n > u32::MAX as u64 {
        u32::MAX
    } else {
        n as u32
    }
}

/// Padmé: round `n` up so that only its top few bits survive.
///
/// For `n` with `E = floor(log2 n)`, keeps the top `floor(log2 E) + 1` bits
/// and rounds the rest up. Leaks O(log log n) bits about `n` and costs at most
/// about 12% for large `n`.
#[must_use]
pub const fn padme(n: u32) -> u32 {
    if n <= 2 {
        return n;
    }
    let e = 31 - n.leading_zeros(); // floor(log2 n), at least 1
    let s = (31 - e.leading_zeros()) + 1; // floor(log2 e) + 1
    let last_bits = e - s;
    let mask = (1u32 << last_bits) - 1;
    match n.checked_add(mask) {
        Some(v) => v & !mask,
        None => u32::MAX,
    }
}

/// The chunk count a file of `size` bytes is padded to: Padmé over the data
/// chunks, and never fewer than [`MIN_CHUNKS`].
#[must_use]
pub const fn padded_chunks(size: u64) -> u32 {
    let n = data_chunks(size);
    padme(if n < MIN_CHUNKS { MIN_CHUNKS } else { n })
}

/// The two secrets that make one attachment: the token that addresses its blob
/// on the relay, and the key its chunks are sealed under. Fresh for every send.
pub struct AttachmentSecrets {
    /// Presented to the relay to put, get, or delete the blob.
    pub token: [u8; 32],
    /// Seals the chunks. Never leaves the two ends.
    pub key: [u8; 32],
}

impl Drop for AttachmentSecrets {
    fn drop(&mut self) {
        self.token.zeroize();
        self.key.zeroize();
    }
}

impl AttachmentSecrets {
    /// Fresh secrets for one new attachment.
    pub fn generate() -> Result<AttachmentSecrets> {
        Ok(AttachmentSecrets {
            token: rand::bytes32().map_err(|_| ProtoError::Crypto)?,
            key: rand::bytes32().map_err(|_| ProtoError::Crypto)?,
        })
    }

    /// The blob's address on the relay.
    #[must_use]
    pub fn blob_id(&self) -> BlobId {
        blob_id(&self.token)
    }
}

/// The relay address a token names.
#[must_use]
pub fn blob_id(token: &[u8; 32]) -> BlobId {
    let full = blake3::derive_key_32("void/v1/attachment/blob-id", token);
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

fn chunk_aad(blob: &BlobId, index: u32, count: u32) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..16].copy_from_slice(blob);
    aad[16..20].copy_from_slice(&index.to_be_bytes());
    aad[20..].copy_from_slice(&count.to_be_bytes());
    aad
}

/// Seal chunk `index` of a blob of `count` chunks.
///
/// `data` is at most [`CHUNK_LEN`] bytes; a short one (the file's last chunk,
/// or empty for a padding chunk) is zero-filled, so every sealed chunk is
/// [`SEALED_CHUNK_LEN`] bytes whatever it carries.
pub fn seal_chunk(
    key: &[u8; 32],
    blob: &BlobId,
    index: u32,
    count: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    if data.len() > CHUNK_LEN || index >= count {
        return Err(ProtoError::Malformed);
    }
    let mut buf = Vec::with_capacity(SEALED_CHUNK_LEN);
    buf.extend_from_slice(data);
    buf.resize(CHUNK_LEN, 0);
    aead::seal_in_place(
        key,
        &aead::nonce_from_counter(u64::from(index)),
        &chunk_aad(blob, index, count),
        &mut buf,
    );
    debug_assert_eq!(buf.len(), SEALED_CHUNK_LEN);
    Ok(buf)
}

/// Open chunk `index` of a blob of `count` chunks, returning all
/// [`CHUNK_LEN`] bytes of it — the caller knows from the [`Attachment`] how
/// many of them are the file's.
pub fn open_chunk(
    key: &[u8; 32],
    blob: &BlobId,
    index: u32,
    count: u32,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    if sealed.len() != SEALED_CHUNK_LEN || index >= count {
        return Err(ProtoError::Malformed);
    }
    aead::open(
        key,
        &aead::nonce_from_counter(u64::from(index)),
        &chunk_aad(blob, index, count),
        sealed,
    )
    .map_err(|_| ProtoError::DecryptionFailed)
}

/// Everything the recipient needs to fetch, open and show one file. Travels
/// only inside the ratchet (`Content::Attachment`).
#[derive(Clone, PartialEq, Eq)]
pub struct Attachment {
    /// Addresses the blob on the relay. Confidential.
    pub token: [u8; 32],
    /// Opens the chunks. Confidential.
    pub key: [u8; 32],
    /// The file's real length in bytes.
    pub size: u64,
    /// How many chunks the blob holds, padding included — what the relay sees.
    pub chunks: u32,
    /// The file's name, sanitised: a single path component, no control
    /// characters.
    pub name: String,
    /// Its media type, such as `image/jpeg`.
    pub mime: String,
    /// For an image or video, its width in pixels; zero if unknown.
    pub width: u16,
    /// For an image or video, its height in pixels; zero if unknown.
    pub height: u16,
    /// Text sent with it. May be empty.
    pub caption: String,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.token.zeroize();
        self.key.zeroize();
    }
}

impl core::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attachment")
            .field("blob_id", &self.blob_id())
            .field("size", &self.size)
            .field("chunks", &self.chunks)
            .field("name", &self.name)
            .field("mime", &self.mime)
            .field("token", &"<redacted>")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Attachment {
    /// Describe a file sealed under `secrets`, padding its chunk count.
    ///
    /// The name and media type are sanitised here, and again by whoever
    /// decodes this: a name is something a stranger's phone could have typed.
    pub fn new(
        secrets: &AttachmentSecrets,
        size: u64,
        name: &str,
        mime: &str,
        width: u16,
        height: u16,
        caption: &str,
    ) -> Result<Attachment> {
        if size > MAX_ATTACHMENT_BYTES || caption.len() > MAX_CAPTION_LEN {
            return Err(ProtoError::Malformed);
        }
        Ok(Attachment {
            token: secrets.token,
            key: secrets.key,
            size,
            chunks: padded_chunks(size),
            name: sanitize_name(name),
            mime: sanitize_mime(mime),
            width,
            height,
            caption: String::from(caption),
        })
    }

    /// The blob's address on the relay.
    #[must_use]
    pub fn blob_id(&self) -> BlobId {
        blob_id(&self.token)
    }

    /// How many of the blob's chunks carry the file; the rest are padding.
    #[must_use]
    pub fn data_chunks(&self) -> u32 {
        data_chunks(self.size)
    }

    /// How many of chunk `index`'s bytes are the file's.
    #[must_use]
    pub fn chunk_data_len(&self, index: u32) -> usize {
        let start = u64::from(index) * CHUNK_LEN as u64;
        if start >= self.size {
            return 0;
        }
        core::cmp::min(CHUNK_LEN as u64, self.size - start) as usize
    }

    /// Canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128 + self.name.len() + self.caption.len());
        w.raw(&self.token)
            .raw(&self.key)
            .u64(self.size)
            .u32(self.chunks)
            .bytes16(self.name.as_bytes())
            .bytes16(self.mime.as_bytes())
            .u16(self.width)
            .u16(self.height)
            .bytes16(self.caption.as_bytes());
        w.finish()
    }

    /// Decode, rejecting anything structurally wrong — a size past the limit,
    /// a chunk count that cannot hold the size, an over-long field. The name
    /// and media type come back sanitised whatever the sender put in them.
    pub fn decode(bytes: &[u8]) -> Result<Attachment> {
        let mut r = Reader::new(bytes);
        let token = r.array::<32>()?;
        let key = r.array::<32>()?;
        let size = r.u64()?;
        let chunks = r.u32()?;
        let name = r.bytes16()?;
        let mime = r.bytes16()?;
        let width = r.u16()?;
        let height = r.u16()?;
        let caption = r.bytes16()?;
        r.finish()?;
        if size > MAX_ATTACHMENT_BYTES
            || chunks < data_chunks(size)
            || chunks > MAX_CHUNKS
            || name.len() > MAX_NAME_LEN
            || mime.len() > MAX_MIME_LEN
            || caption.len() > MAX_CAPTION_LEN
        {
            return Err(ProtoError::Malformed);
        }
        let name = core::str::from_utf8(name).map_err(|_| ProtoError::Malformed)?;
        let mime = core::str::from_utf8(mime).map_err(|_| ProtoError::Malformed)?;
        let caption = core::str::from_utf8(caption).map_err(|_| ProtoError::Malformed)?;
        Ok(Attachment {
            token,
            key,
            size,
            chunks,
            name: sanitize_name(name),
            mime: sanitize_mime(mime),
            width,
            height,
            caption: String::from(caption),
        })
    }
}

/// A file name safe to show and to save under: the last path component only,
/// no control or bidirectional-override characters, at most
/// [`MAX_NAME_LEN`] bytes, and never empty or a bare `.` or `..`.
///
/// A name arrives from the other end and may have been chosen to mislead: a
/// right-to-left override turns `exe.jpg` around on screen, and a path
/// separator could reach out of the directory it is saved into.
#[must_use]
pub fn sanitize_name(name: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c))
        .collect();
    let trimmed = cleaned.trim();
    let mut out = String::new();
    for c in trimmed.chars() {
        if out.len() + c.len_utf8() > MAX_NAME_LEN {
            break;
        }
        out.push(c);
    }
    if out.is_empty() || out == "." || out == ".." {
        return String::from("file");
    }
    out
}

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// A media type of the shape `type/subtype`, lower-case ASCII; anything else
/// becomes `application/octet-stream`.
#[must_use]
pub fn sanitize_mime(mime: &str) -> String {
    let lowered = mime.trim().to_ascii_lowercase();
    let valid = !lowered.is_empty()
        && lowered.len() <= MAX_MIME_LEN
        && lowered.matches('/').count() == 1
        && !lowered.starts_with('/')
        && !lowered.ends_with('/')
        && lowered
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-/".contains(&b));
    if valid {
        lowered
    } else {
        String::from("application/octet-stream")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> AttachmentSecrets {
        AttachmentSecrets::generate().unwrap()
    }

    #[test]
    fn padme_matches_the_published_examples() {
        // Small values are exact; larger ones round up within ~12%.
        assert_eq!(padme(1), 1);
        assert_eq!(padme(2), 2);
        assert_eq!(padme(9), 10);
        assert_eq!(padme(100), 104);
        assert_eq!(padme(1000), 1024);
        for n in [3u32, 17, 255, 4097, 33_000, 100_000] {
            let p = padme(n);
            assert!(p >= n);
            assert!(
                u64::from(p - n) * 100 <= u64::from(n) * 12 + 100,
                "{n} -> {p}"
            );
        }
    }

    #[test]
    fn padding_hides_small_files_entirely() {
        // Everything up to MIN_CHUNKS of data looks the same to the relay.
        let tiny = padded_chunks(1);
        assert_eq!(tiny, padded_chunks(10_000));
        assert_eq!(tiny, padded_chunks((MIN_CHUNKS as u64) * CHUNK_LEN as u64));
        assert!(padded_chunks(0) >= MIN_CHUNKS);
    }

    #[test]
    fn padding_never_drops_below_the_data() {
        for size in [0u64, 1, 1984, 1985, 50_000, 1_000_000, MAX_ATTACHMENT_BYTES] {
            assert!(padded_chunks(size) >= data_chunks(size), "{size}");
            assert!(padded_chunks(size) <= MAX_CHUNKS, "{size}");
        }
    }

    #[test]
    fn a_chunk_round_trips_and_every_sealed_chunk_is_one_size() {
        let s = secrets();
        let blob = s.blob_id();
        let full = seal_chunk(&s.key, &blob, 0, 8, &[7u8; CHUNK_LEN]).unwrap();
        let short = seal_chunk(&s.key, &blob, 1, 8, b"tail").unwrap();
        let pad = seal_chunk(&s.key, &blob, 7, 8, &[]).unwrap();
        assert_eq!(full.len(), SEALED_CHUNK_LEN);
        assert_eq!(short.len(), SEALED_CHUNK_LEN);
        assert_eq!(pad.len(), SEALED_CHUNK_LEN);
        assert_eq!(
            open_chunk(&s.key, &blob, 0, 8, &full).unwrap(),
            vec![7u8; CHUNK_LEN]
        );
        let opened = open_chunk(&s.key, &blob, 1, 8, &short).unwrap();
        assert_eq!(&opened[..4], b"tail");
        assert!(opened[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_relay_cannot_reorder_truncate_or_move_chunks() {
        let s = secrets();
        let blob = s.blob_id();
        let chunk = seal_chunk(&s.key, &blob, 3, 16, b"third").unwrap();
        // Presented at another index.
        assert!(open_chunk(&s.key, &blob, 4, 16, &chunk).is_err());
        // As part of a shorter blob — truncation changes the count.
        assert!(open_chunk(&s.key, &blob, 3, 8, &chunk).is_err());
        // As part of another blob.
        let other = secrets().blob_id();
        assert!(open_chunk(&s.key, &other, 3, 16, &chunk).is_err());
        // Tampered.
        let mut bad = chunk.clone();
        bad[100] ^= 1;
        assert!(open_chunk(&s.key, &blob, 3, 16, &bad).is_err());
        // Under another key.
        assert!(open_chunk(&secrets().key, &blob, 3, 16, &chunk).is_err());
    }

    #[test]
    fn out_of_range_chunks_are_refused() {
        let s = secrets();
        let blob = s.blob_id();
        assert!(seal_chunk(&s.key, &blob, 8, 8, b"x").is_err());
        assert!(seal_chunk(&s.key, &blob, 0, 8, &[0u8; CHUNK_LEN + 1]).is_err());
        assert!(open_chunk(&s.key, &blob, 0, 8, &[0u8; 10]).is_err());
    }

    #[test]
    fn the_blob_id_is_not_the_token() {
        // The relay keys its table by the id; the token is the capability.
        let s = secrets();
        assert_ne!(&s.blob_id()[..], &s.token[..16]);
        assert_eq!(s.blob_id(), blob_id(&s.token));
    }

    #[test]
    fn an_attachment_round_trips() {
        let s = secrets();
        let a =
            Attachment::new(&s, 123_456, "holiday.jpg", "image/jpeg", 1600, 1200, "hi").unwrap();
        assert_eq!(a.chunks, padded_chunks(123_456));
        let decoded = Attachment::decode(&a.encode()).unwrap();
        assert_eq!(decoded, a);
        assert_eq!(decoded.data_chunks(), 63);
        assert_eq!(decoded.chunk_data_len(0), CHUNK_LEN);
        assert_eq!(decoded.chunk_data_len(62), 123_456 - 62 * CHUNK_LEN);
        assert_eq!(decoded.chunk_data_len(63), 0);
    }

    #[test]
    fn an_impossible_attachment_is_refused() {
        let s = secrets();
        let a = Attachment::new(&s, 10_000, "a", "text/plain", 0, 0, "").unwrap();

        let mut too_few = a.clone();
        too_few.chunks = 1;
        assert!(Attachment::decode(&too_few.encode()).is_err());

        let mut too_big = a.clone();
        too_big.size = MAX_ATTACHMENT_BYTES + 1;
        too_big.chunks = MAX_CHUNKS;
        assert!(Attachment::decode(&too_big.encode()).is_err());

        let mut extra = a.encode();
        extra.push(0);
        assert!(Attachment::decode(&extra).is_err(), "trailing bytes");
        assert!(Attachment::decode(&a.encode()[..40]).is_err(), "truncated");

        assert!(Attachment::new(&s, MAX_ATTACHMENT_BYTES + 1, "a", "", 0, 0, "").is_err());
    }

    #[test]
    fn names_from_the_other_end_are_made_safe() {
        assert_eq!(sanitize_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_name("C:\\Users\\a\\report.pdf"), "report.pdf");
        assert_eq!(sanitize_name("evil\u{202E}gpj.exe"), "evilgpj.exe");
        assert_eq!(sanitize_name("line\nbreak.txt"), "linebreak.txt");
        assert_eq!(sanitize_name(""), "file");
        assert_eq!(sanitize_name(".."), "file");
        assert_eq!(sanitize_name("dir/"), "file");
        let long = "é".repeat(300);
        let cut = sanitize_name(&long);
        assert!(cut.len() <= MAX_NAME_LEN);
        assert!(cut.chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_decoded_name_is_sanitised_whatever_the_sender_did() {
        let s = secrets();
        let mut a = Attachment::new(&s, 5, "ok.txt", "text/plain", 0, 0, "").unwrap();
        a.name = String::from("../secret\u{202E}txt.exe");
        let decoded = Attachment::decode(&a.encode()).unwrap();
        assert_eq!(decoded.name, "secrettxt.exe");
    }

    #[test]
    fn media_types_are_validated() {
        assert_eq!(sanitize_mime("Image/JPEG"), "image/jpeg");
        assert_eq!(
            sanitize_mime("application/vnd.ms-excel"),
            "application/vnd.ms-excel"
        );
        assert_eq!(
            sanitize_mime("text/html; charset=utf-8"),
            "application/octet-stream"
        );
        assert_eq!(sanitize_mime("nonsense"), "application/octet-stream");
        assert_eq!(sanitize_mime(""), "application/octet-stream");
    }

    #[test]
    fn secrets_are_not_readable_from_debug_output() {
        let s = secrets();
        let a = Attachment::new(&s, 5, "a.txt", "text/plain", 0, 0, "").unwrap();
        let rendered = alloc::format!("{a:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(&alloc::format!("{:?}", a.key)));
    }
}
