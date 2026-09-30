//! The encrypted local database (FR-STOR-01, FR-STOR-04, FR-STOR-05).
//!
//! ## Relationship to SQLCipher
//!
//! The PRD specifies SQLCipher. This crate implements the same *shape* — an
//! encrypted store whose key is Argon2id-derived and hardware-wrapped — as a
//! self-contained encrypted record log, because the build environment for this
//! revision has no package registry and SQLCipher is a C library.
//!
//! The [`Backend`] trait is the seam. `docs/DECISIONS.md#d-007` records the
//! migration: implement `Backend` over `rusqlite` with the `sqlcipher` feature,
//! keep the row-level AEAD as defence in depth, and delete nothing else. No
//! code above this module knows which backend it is talking to.
//!
//! ## Encryption layout
//!
//! Each record is independently sealed with XChaCha20-Poly1305 under a
//! per-record key derived from the DEK and the record id. Per-record keys mean
//! that a single nonce mishap cannot cascade, and that the retention sweep can
//! delete a record by forgetting its key rather than by rewriting the file.
//!
//! ```text
//!   file = header || record*
//!   header = magic(8) || version(2) || argon_params(16) || salt(16) || wrapped_dek(72)
//!   record = id(8) || kind(1) || expires_at(8) || len(4) || nonce(24) || sealed(len+16)
//! ```
//!
//! The header is plaintext and deliberately so: FR-STOR-05 does not ask us to
//! hide that a Void database exists, and PRD §7.4.1 explains at length why
//! pretending otherwise is worse than useless. What the header must not do is
//! reveal anything about *contents*, and it does not — it holds only KDF
//! parameters and a wrapped key.
//!
//! ## What is deliberately absent
//!
//! No plaintext index, no search table, no message-count field, no
//! last-modified per contact. Every one of those is a metadata channel that
//! survives at rest, and FR-STOR-01's protection is only as good as the
//! weakest thing left unencrypted beside it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use void_crypto::{aead, argon2, blake3, kdf, rand, Zeroize};

use crate::vault::KeyVault;
use crate::{StoreError, StoreResult};

/// File magic. Present so a corrupt or truncated file is diagnosed rather than
/// misparsed; it is not a security feature.
pub const MAGIC: &[u8; 8] = b"VOIDDB\x00\x01";

/// On-disk format version.
pub const FORMAT_VERSION: u16 = 1;

/// A record kind. Kept as a small closed set: an open-ended tag would let a
/// future bug write a record type the retention sweep does not know to expire.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Kind {
    /// A conversation message. Subject to retention (FR-STOR-04).
    Message = 1,
    /// A contact record. Not expired by retention.
    Contact = 2,
    /// Serialized ratchet session state. Not expired by retention.
    Session = 3,
    /// A settings key/value pair.
    Setting = 4,
    /// Queue secrets for a contact.
    Queue = 5,
    /// Identity key seeds.
    Identity = 6,
    /// An outbound message awaiting delivery (NFR-REL-04).
    Outbox = 7,
    /// An invitation waiting to be accepted: its intro queue and the prekey
    /// secrets its bundle was signed over. Expires with the invitation.
    Invite = 8,
    /// A fragment collected from the relay whose message has not finished
    /// arriving. The relay deleted it when it handed it over, so this is the
    /// only copy; it expires when the relay would have expired the rest.
    Inbox = 9,
}

impl Kind {
    fn to_byte(self) -> u8 {
        self as u8
    }

    fn from_byte(b: u8) -> StoreResult<Kind> {
        Ok(match b {
            1 => Kind::Message,
            2 => Kind::Contact,
            3 => Kind::Session,
            4 => Kind::Setting,
            5 => Kind::Queue,
            6 => Kind::Identity,
            7 => Kind::Outbox,
            8 => Kind::Invite,
            9 => Kind::Inbox,
            _ => return Err(StoreError::Corrupt),
        })
    }

    /// Does the retention policy expire records of this kind?
    #[must_use]
    pub fn is_expirable(self) -> bool {
        matches!(
            self,
            Kind::Message | Kind::Outbox | Kind::Invite | Kind::Inbox
        )
    }
}

/// One stored record, decrypted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// Monotonic record identifier.
    pub id: u64,
    /// What this record is.
    pub kind: Kind,
    /// Unix seconds after which the retention sweep deletes it. Zero means
    /// "never expires".
    pub expires_at: u64,
    /// The plaintext payload.
    pub payload: Vec<u8>,
}

impl Drop for Record {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

/// Where bytes actually live. Implemented here by a file; implemented on device
/// by SQLCipher (see the module docs).
pub trait Backend: Send {
    /// Replace the whole store with `bytes`.
    fn write_all(&mut self, bytes: &[u8]) -> StoreResult<()>;
    /// Read the whole store.
    fn read_all(&self) -> StoreResult<Vec<u8>>;
    /// Delete the store's bytes entirely.
    fn erase(&mut self) -> StoreResult<()>;
    /// Does the store exist?
    fn exists(&self) -> bool;
}

/// A file-backed store.
pub struct FileBackend {
    path: PathBuf,
}

impl FileBackend {
    /// Point at a path. The file is created on first write.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        FileBackend {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// The path, so the platform layer can apply `isExcludedFromBackup` and
    /// `NSFileProtectionComplete` (FR-STOR-05). Those are OS calls the Rust
    /// core cannot make; `void-ffi` exposes a hook for them.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Backend for FileBackend {
    fn write_all(&mut self, bytes: &[u8]) -> StoreResult<()> {
        // Write to a temporary file and rename, so a crash mid-write leaves the
        // previous database intact rather than a truncated one.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes).map_err(|_| StoreError::Io)?;
        std::fs::rename(&tmp, &self.path).map_err(|_| StoreError::Io)?;
        Ok(())
    }

    fn read_all(&self) -> StoreResult<Vec<u8>> {
        std::fs::read(&self.path).map_err(|_| StoreError::Io)
    }

    fn erase(&mut self) -> StoreResult<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(|_| StoreError::Io)?;
        }
        Ok(())
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }
}

/// An in-memory backend, for tests.
#[derive(Default)]
pub struct MemoryBackend {
    bytes: Option<Vec<u8>>,
}

impl MemoryBackend {
    /// New empty backend.
    #[must_use]
    pub fn new() -> Self {
        MemoryBackend { bytes: None }
    }

    /// The raw bytes as they would sit on disk. Tests use this to assert that
    /// plaintext never appears at rest.
    #[must_use]
    pub fn raw(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
}

impl Backend for MemoryBackend {
    fn write_all(&mut self, bytes: &[u8]) -> StoreResult<()> {
        self.bytes = Some(bytes.to_vec());
        Ok(())
    }
    fn read_all(&self) -> StoreResult<Vec<u8>> {
        self.bytes.clone().ok_or(StoreError::Io)
    }
    fn erase(&mut self) -> StoreResult<()> {
        if let Some(ref mut b) = self.bytes {
            b.zeroize();
        }
        self.bytes = None;
        Ok(())
    }
    fn exists(&self) -> bool {
        self.bytes.is_some()
    }
}

/// The encrypted database.
pub struct Database<B: Backend> {
    backend: B,
    dek: [u8; 32],
    wrapped_dek: Vec<u8>,
    salt: [u8; 16],
    params: argon2::Params,
    records: BTreeMap<u64, Record>,
    next_id: u64,
    locked: bool,
}

impl<B: Backend> Drop for Database<B> {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

impl<B: Backend> Database<B> {
    /// Create a new database, generating a fresh data-encryption key and
    /// wrapping it with `vault`.
    pub fn create(backend: B, vault: &dyn KeyVault, params: argon2::Params) -> StoreResult<Self> {
        let dek = rand::bytes32().map_err(|_| StoreError::Entropy)?;
        let salt = rand::bytes16().map_err(|_| StoreError::Entropy)?;
        let wrapped_dek = vault.wrap(&dek)?;
        let mut db = Database {
            backend,
            dek,
            wrapped_dek,
            salt,
            params,
            records: BTreeMap::new(),
            next_id: 1,
            locked: false,
        };
        db.flush()?;
        Ok(db)
    }

    /// Open an existing database.
    ///
    /// Fails with [`StoreError::VaultDestroyed`] if the vault key is gone —
    /// which is exactly what a duress destruction leaves behind, and what
    /// NFR-REL-03 requires: an unavailable key means the database stays
    /// encrypted and unusable, never partially readable.
    pub fn open(backend: B, vault: &dyn KeyVault) -> StoreResult<Self> {
        let bytes = backend.read_all()?;
        if bytes.len() < 8 + 2 + 16 + 16 + 4 {
            return Err(StoreError::Corrupt);
        }
        if &bytes[..8] != MAGIC {
            return Err(StoreError::Corrupt);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedVersion);
        }
        let m_cost = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let t_cost = u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);
        let lanes = u32::from_be_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
        let _reserved = u32::from_be_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[26..42]);
        let wrapped_len = u32::from_be_bytes([bytes[42], bytes[43], bytes[44], bytes[45]]) as usize;
        if bytes.len() < 46 + wrapped_len {
            return Err(StoreError::Corrupt);
        }
        let wrapped_dek = bytes[46..46 + wrapped_len].to_vec();

        let dek = vault.unwrap_key(&wrapped_dek)?;

        let mut db = Database {
            backend,
            dek,
            wrapped_dek,
            salt,
            params: argon2::Params {
                m_cost,
                t_cost,
                lanes,
                out_len: 32,
            },
            records: BTreeMap::new(),
            next_id: 1,
            locked: false,
        };
        db.load_records(&bytes[46 + wrapped_len..])?;
        Ok(db)
    }

    fn record_key(&self, id: u64) -> [u8; 32] {
        blake3::keyed_hash_parts(&self.dek, &[kdf::LABEL_STORE_ROW, &id.to_be_bytes()])
    }

    /// The plaintext header, byte for byte.
    ///
    /// Every record authenticates this as associated data. Without that, the
    /// header — which holds the KDF parameters and the wrapped key — would be
    /// unauthenticated, and an attacker could rewrite the Argon2 cost
    /// parameters downward or swap in a wrapped key from another database and
    /// see no integrity failure. Binding it in means any edit to the header
    /// makes every record fail to open, which is the correct blast radius.
    fn header_bytes(&self) -> Vec<u8> {
        let mut h = Vec::with_capacity(46 + self.wrapped_dek.len());
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        h.extend_from_slice(&self.params.m_cost.to_be_bytes());
        h.extend_from_slice(&self.params.t_cost.to_be_bytes());
        h.extend_from_slice(&self.params.lanes.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes());
        h.extend_from_slice(&self.salt);
        h.extend_from_slice(&(self.wrapped_dek.len() as u32).to_be_bytes());
        h.extend_from_slice(&self.wrapped_dek);
        h
    }

    fn record_aad(&self, id: u64, kind: Kind, expires_at: u64) -> Vec<u8> {
        let mut aad = self.header_bytes();
        aad.extend_from_slice(&id.to_be_bytes());
        aad.push(kind.to_byte());
        aad.extend_from_slice(&expires_at.to_be_bytes());
        aad
    }

    fn load_records(&mut self, mut body: &[u8]) -> StoreResult<()> {
        while !body.is_empty() {
            if body.len() < 8 + 1 + 8 + 4 + 24 {
                return Err(StoreError::Corrupt);
            }
            let id = u64::from_be_bytes(body[..8].try_into().map_err(|_| StoreError::Corrupt)?);
            let kind = Kind::from_byte(body[8])?;
            let expires_at =
                u64::from_be_bytes(body[9..17].try_into().map_err(|_| StoreError::Corrupt)?);
            let len = u32::from_be_bytes(body[17..21].try_into().map_err(|_| StoreError::Corrupt)?)
                as usize;
            let sealed_len = len + aead::TAG_LEN;
            if body.len() < 21 + 24 + sealed_len {
                return Err(StoreError::Corrupt);
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&body[21..45]);
            let sealed = &body[45..45 + sealed_len];

            let mut key = self.record_key(id);
            let aad = self.record_aad(id, kind, expires_at);
            let payload = aead::xopen(&key, &nonce, &aad, sealed).map_err(|_| StoreError::Corrupt);
            key.zeroize();
            let payload = payload?;

            self.next_id = self.next_id.max(id + 1);
            self.records.insert(
                id,
                Record {
                    id,
                    kind,
                    expires_at,
                    payload,
                },
            );
            body = &body[45 + sealed_len..];
        }
        Ok(())
    }

    /// Write the whole store back out.
    pub fn flush(&mut self) -> StoreResult<()> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        let mut out = self.header_bytes();

        for (id, rec) in &self.records {
            let mut key = self.record_key(*id);
            let nonce = rand::bytes24().map_err(|_| StoreError::Entropy)?;
            let aad = self.record_aad(*id, rec.kind, rec.expires_at);
            let sealed = aead::xseal(&key, &nonce, &aad, &rec.payload);
            key.zeroize();

            out.extend_from_slice(&id.to_be_bytes());
            out.push(rec.kind.to_byte());
            out.extend_from_slice(&rec.expires_at.to_be_bytes());
            out.extend_from_slice(&(rec.payload.len() as u32).to_be_bytes());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&sealed);
        }
        self.backend.write_all(&out)
    }

    /// Insert a record, returning its id.
    pub fn insert(&mut self, kind: Kind, expires_at: u64, payload: &[u8]) -> StoreResult<u64> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.records.insert(
            id,
            Record {
                id,
                kind,
                expires_at,
                payload: payload.to_vec(),
            },
        );
        Ok(id)
    }

    /// Fetch a record by id.
    pub fn get(&self, id: u64) -> StoreResult<Option<&Record>> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        Ok(self.records.get(&id))
    }

    /// All records of a kind, in insertion order.
    pub fn list(&self, kind: Kind) -> StoreResult<Vec<&Record>> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        Ok(self.records.values().filter(|r| r.kind == kind).collect())
    }

    /// Replace a record's payload.
    pub fn update(&mut self, id: u64, payload: &[u8]) -> StoreResult<()> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        let rec = self.records.get_mut(&id).ok_or(StoreError::NotFound)?;
        rec.payload.zeroize();
        rec.payload = payload.to_vec();
        Ok(())
    }

    /// Change a record's expiry.
    ///
    /// Used by the retention policy when the user tightens their setting; see
    /// `retention::apply_policy_change` for why it never loosens.
    pub fn set_expiry(&mut self, id: u64, expires_at: u64) -> StoreResult<()> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        let rec = self.records.get_mut(&id).ok_or(StoreError::NotFound)?;
        rec.expires_at = expires_at;
        Ok(())
    }

    /// Delete a record.
    pub fn delete(&mut self, id: u64) -> StoreResult<()> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        self.records.remove(&id);
        Ok(())
    }

    /// Number of records held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Is the database empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Delete every expired record and rewrite the file (FR-STOR-04's vacuum).
    ///
    /// Rewriting is what makes this a vacuum rather than a logical delete: the
    /// old ciphertext is not left in the file for a forensic tool to find. On
    /// flash storage the previous blocks may still exist physically, which is
    /// why this is defence in depth behind the vault destruction, not a
    /// substitute for it.
    pub fn sweep_expired(&mut self, now: u64) -> StoreResult<usize> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        let doomed: Vec<u64> = self
            .records
            .values()
            .filter(|r| r.expires_at != 0 && r.expires_at <= now)
            .map(|r| r.id)
            .collect();
        for id in &doomed {
            self.records.remove(id);
        }
        if !doomed.is_empty() {
            self.flush()?;
        }
        Ok(doomed.len())
    }

    /// Lock the database in memory: wipe the key and refuse all operations.
    ///
    /// Used by FR-STOR-07's lockdown mode and on app backgrounding.
    pub fn lock(&mut self) {
        self.dek.zeroize();
        for rec in self.records.values_mut() {
            rec.payload.zeroize();
        }
        self.records.clear();
        self.locked = true;
    }

    /// Is the database locked?
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Destroy the database: erase the backing bytes and drop in-memory state.
    ///
    /// This is the *second* half of duress destruction. The first and decisive
    /// half is destroying the vault key, which happens whether or not this
    /// succeeds — a device that loses power mid-erase must still be
    /// unrecoverable.
    pub fn destroy(&mut self) -> StoreResult<()> {
        self.lock();
        self.backend.erase()
    }

    /// Borrow the backend, for tests and for the platform layer.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

/// Object-safe view of [`Database`]'s operations.
///
/// `Database<B>` is generic over [`Backend`], which is the right shape for
/// this crate but the wrong one for a caller like `void-client`'s `Engine`:
/// making `Engine` generic over a storage backend would infect every type
/// that touches it, the way it already deliberately does *not* for
/// `Box<dyn Transport>`. `Store` lets `Engine` hold storage the same way it
/// holds a transport — behind a trait object — while `Database<B>` itself
/// stays concrete for everything inside this crate.
///
/// `get` and `list` return owned [`Record`]s rather than borrowing, because a
/// trait object cannot express the lifetime `Database::get`'s `&Record`
/// depends on. `Record` is already `Clone`, so this costs a copy, not a
/// redesign.
pub trait Store: Send {
    /// Insert a record, returning its id.
    fn insert(&mut self, kind: Kind, expires_at: u64, payload: &[u8]) -> StoreResult<u64>;
    /// Fetch a record by id.
    fn get(&self, id: u64) -> StoreResult<Option<Record>>;
    /// All records of a kind, in insertion order.
    fn list(&self, kind: Kind) -> StoreResult<Vec<Record>>;
    /// Replace a record's payload.
    fn update(&mut self, id: u64, payload: &[u8]) -> StoreResult<()>;
    /// Change a record's expiry.
    fn set_expiry(&mut self, id: u64, expires_at: u64) -> StoreResult<()>;
    /// Delete a record.
    fn delete(&mut self, id: u64) -> StoreResult<()>;
    /// Delete every expired record and rewrite the file (FR-STOR-04's vacuum).
    fn sweep_expired(&mut self, now: u64) -> StoreResult<usize>;
    /// Write the whole store back out.
    fn flush(&mut self) -> StoreResult<()>;
    /// Is the database locked?
    fn is_locked(&self) -> bool;
    /// Lock the database in memory: wipe the key and refuse all operations.
    fn lock(&mut self);
    /// Destroy the database: erase the backing bytes and drop in-memory state.
    fn destroy(&mut self) -> StoreResult<()>;
}

impl<B: Backend> Store for Database<B> {
    fn insert(&mut self, kind: Kind, expires_at: u64, payload: &[u8]) -> StoreResult<u64> {
        Database::insert(self, kind, expires_at, payload)
    }
    fn get(&self, id: u64) -> StoreResult<Option<Record>> {
        Database::get(self, id).map(|r| r.cloned())
    }
    fn list(&self, kind: Kind) -> StoreResult<Vec<Record>> {
        Database::list(self, kind).map(|v| v.into_iter().cloned().collect())
    }
    fn update(&mut self, id: u64, payload: &[u8]) -> StoreResult<()> {
        Database::update(self, id, payload)
    }
    fn set_expiry(&mut self, id: u64, expires_at: u64) -> StoreResult<()> {
        Database::set_expiry(self, id, expires_at)
    }
    fn delete(&mut self, id: u64) -> StoreResult<()> {
        Database::delete(self, id)
    }
    fn sweep_expired(&mut self, now: u64) -> StoreResult<usize> {
        Database::sweep_expired(self, now)
    }
    fn flush(&mut self) -> StoreResult<()> {
        Database::flush(self)
    }
    fn is_locked(&self) -> bool {
        Database::is_locked(self)
    }
    fn lock(&mut self) {
        Database::lock(self)
    }
    fn destroy(&mut self) -> StoreResult<()> {
        Database::destroy(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::SoftwareVault;

    fn db() -> (Database<MemoryBackend>, SoftwareVault) {
        let vault = SoftwareVault::from_raw([1u8; 32]);
        let d =
            Database::create(MemoryBackend::new(), &vault, argon2::Params::TEST_ONLY_WEAK).unwrap();
        (d, vault)
    }

    #[test]
    fn insert_get_update_delete() {
        let (mut d, _v) = db();
        let id = d.insert(Kind::Message, 0, b"hello").unwrap();
        assert_eq!(d.get(id).unwrap().unwrap().payload, b"hello");
        d.update(id, b"goodbye").unwrap();
        assert_eq!(d.get(id).unwrap().unwrap().payload, b"goodbye");
        d.delete(id).unwrap();
        assert!(d.get(id).unwrap().is_none());
        assert!(matches!(d.update(id, b"x"), Err(StoreError::NotFound)));
    }

    #[test]
    fn persistence_roundtrip() {
        let vault = SoftwareVault::from_raw([1u8; 32]);
        let mut backend = MemoryBackend::new();
        {
            let mut d =
                Database::create(MemoryBackend::new(), &vault, argon2::Params::TEST_ONLY_WEAK)
                    .unwrap();
            d.insert(Kind::Message, 0, b"first").unwrap();
            d.insert(Kind::Contact, 0, b"alice").unwrap();
            d.flush().unwrap();
            backend.write_all(d.backend().raw().unwrap()).unwrap();
        }
        let d = Database::open(backend, &vault).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d.list(Kind::Message).unwrap()[0].payload, b"first");
        assert_eq!(d.list(Kind::Contact).unwrap()[0].payload, b"alice");
    }

    #[test]
    fn plaintext_never_appears_at_rest() {
        let (mut d, _v) = db();
        d.insert(Kind::Message, 0, b"THE SECRET MEETING IS AT DAWN")
            .unwrap();
        d.flush().unwrap();
        let raw = d.backend().raw().unwrap();
        assert!(
            raw.windows(6).all(|w| w != b"SECRET"),
            "plaintext leaked into the file"
        );
        assert!(raw.starts_with(MAGIC), "header is intentionally plaintext");
    }

    #[test]
    fn header_reveals_nothing_about_contents() {
        // Two databases with wildly different contents must have identical
        // header structure — only the salt and wrapped key differ.
        let v = SoftwareVault::from_raw([1u8; 32]);
        let mut a =
            Database::create(MemoryBackend::new(), &v, argon2::Params::TEST_ONLY_WEAK).unwrap();
        let mut b =
            Database::create(MemoryBackend::new(), &v, argon2::Params::TEST_ONLY_WEAK).unwrap();
        for i in 0..50 {
            a.insert(Kind::Message, 0, &[i as u8; 200]).unwrap();
        }
        a.flush().unwrap();
        b.flush().unwrap();
        assert_eq!(
            &a.backend().raw().unwrap()[..26],
            &b.backend().raw().unwrap()[..26]
        );
    }

    #[test]
    fn a_destroyed_vault_makes_the_database_unopenable() {
        // NFR-REL-03 and FR-STOR-02 together: no key, no partial read.
        let vault = SoftwareVault::from_raw([1u8; 32]);
        let mut backend = MemoryBackend::new();
        {
            let mut d =
                Database::create(MemoryBackend::new(), &vault, argon2::Params::TEST_ONLY_WEAK)
                    .unwrap();
            d.insert(Kind::Message, 0, b"irrecoverable").unwrap();
            d.flush().unwrap();
            backend.write_all(d.backend().raw().unwrap()).unwrap();
        }
        vault.destroy().unwrap();
        assert!(matches!(
            Database::open(backend, &vault),
            Err(StoreError::VaultDestroyed)
        ));
    }

    #[test]
    fn a_different_vault_cannot_open() {
        let a = SoftwareVault::from_raw([1u8; 32]);
        let b = SoftwareVault::from_raw([2u8; 32]);
        let mut backend = MemoryBackend::new();
        {
            let mut d =
                Database::create(MemoryBackend::new(), &a, argon2::Params::TEST_ONLY_WEAK).unwrap();
            d.flush().unwrap();
            backend.write_all(d.backend().raw().unwrap()).unwrap();
        }
        assert!(Database::open(backend, &b).is_err());
    }

    #[test]
    fn corruption_is_detected_not_ignored() {
        let vault = SoftwareVault::from_raw([1u8; 32]);
        let mut d =
            Database::create(MemoryBackend::new(), &vault, argon2::Params::TEST_ONLY_WEAK).unwrap();
        d.insert(Kind::Message, 0, b"payload").unwrap();
        d.flush().unwrap();
        let good = d.backend().raw().unwrap().to_vec();

        // Every byte of the header is covered, because the header is
        // authenticated as associated data by every record.
        for i in [0usize, 8, 12, 30, 45, 60, good.len() - 1] {
            let mut bad = good.clone();
            bad[i] ^= 0xFF;
            let mut backend = MemoryBackend::new();
            backend.write_all(&bad).unwrap();
            assert!(
                Database::open(backend, &vault).is_err(),
                "corruption at byte {i} was not detected"
            );
        }

        // Truncation too.
        for n in [0usize, 10, 45, good.len() - 1] {
            let mut backend = MemoryBackend::new();
            backend.write_all(&good[..n]).unwrap();
            assert!(
                Database::open(backend, &vault).is_err(),
                "truncation to {n}"
            );
        }
    }

    #[test]
    fn retention_sweep_removes_only_expired_records() {
        let (mut d, _v) = db();
        let keep = d.insert(Kind::Message, 0, b"forever").unwrap();
        let alive = d.insert(Kind::Message, 2000, b"not yet").unwrap();
        let dead = d.insert(Kind::Message, 1000, b"expired").unwrap();
        let contact = d.insert(Kind::Contact, 0, b"alice").unwrap();
        d.flush().unwrap();

        assert_eq!(d.sweep_expired(1500).unwrap(), 1);
        assert!(d.get(dead).unwrap().is_none());
        assert!(d.get(alive).unwrap().is_some());
        assert!(d.get(keep).unwrap().is_some());
        assert!(d.get(contact).unwrap().is_some());
    }

    #[test]
    fn sweeping_actually_removes_the_ciphertext_from_the_file() {
        let (mut d, _v) = db();
        d.insert(Kind::Message, 1000, &[0xAB; 300]).unwrap();
        d.flush().unwrap();
        let before = d.backend().raw().unwrap().len();
        d.sweep_expired(2000).unwrap();
        let after = d.backend().raw().unwrap().len();
        assert!(
            after < before,
            "vacuum must shrink the file: {before} -> {after}"
        );
    }

    #[test]
    fn locking_wipes_state_and_refuses_operations() {
        let (mut d, _v) = db();
        d.insert(Kind::Message, 0, b"secret").unwrap();
        d.lock();
        assert!(d.is_locked());
        assert!(matches!(d.get(1), Err(StoreError::Locked)));
        assert!(matches!(
            d.insert(Kind::Message, 0, b"x"),
            Err(StoreError::Locked)
        ));
        assert!(matches!(d.flush(), Err(StoreError::Locked)));
        assert!(d.is_empty());
    }

    #[test]
    fn destroy_erases_the_backing_store() {
        let (mut d, _v) = db();
        d.insert(Kind::Message, 0, b"x").unwrap();
        d.flush().unwrap();
        assert!(d.backend().exists());
        d.destroy().unwrap();
        assert!(!d.backend().exists());
        assert!(d.is_locked());
    }

    #[test]
    fn record_kinds_roundtrip_and_reject_unknown() {
        for k in [
            Kind::Message,
            Kind::Contact,
            Kind::Session,
            Kind::Setting,
            Kind::Queue,
            Kind::Identity,
            Kind::Outbox,
            Kind::Invite,
            Kind::Inbox,
        ] {
            assert_eq!(Kind::from_byte(k.to_byte()).unwrap(), k);
        }
        assert!(Kind::from_byte(0).is_err());
        assert!(Kind::from_byte(99).is_err());
        assert!(Kind::Message.is_expirable());
        assert!(Kind::Invite.is_expirable());
        assert!(Kind::Inbox.is_expirable());
        assert!(!Kind::Identity.is_expirable());
    }

    #[test]
    fn database_is_usable_behind_a_store_trait_object() {
        let vault = SoftwareVault::from_raw([1u8; 32]);
        let db =
            Database::create(MemoryBackend::new(), &vault, argon2::Params::TEST_ONLY_WEAK).unwrap();
        let mut store: Box<dyn Store> = Box::new(db);
        let id = store.insert(Kind::Message, 0, b"hello").unwrap();
        assert_eq!(store.get(id).unwrap().unwrap().payload, b"hello");
        store.update(id, b"goodbye").unwrap();
        assert_eq!(store.list(Kind::Message).unwrap()[0].payload, b"goodbye");
        store.flush().unwrap();
        store.delete(id).unwrap();
        assert!(store.get(id).unwrap().is_none());
    }

    #[test]
    fn file_backend_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("void-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.voiddb");
        let vault = SoftwareVault::from_raw([3u8; 32]);
        {
            let mut d = Database::create(
                FileBackend::new(&path),
                &vault,
                argon2::Params::TEST_ONLY_WEAK,
            )
            .unwrap();
            d.insert(Kind::Message, 0, b"durable").unwrap();
            d.flush().unwrap();
        }
        let d = Database::open(FileBackend::new(&path), &vault).unwrap();
        assert_eq!(d.list(Kind::Message).unwrap()[0].payload, b"durable");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
