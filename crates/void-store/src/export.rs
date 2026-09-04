//! Encrypted export and recovery (FR-REC-01 … FR-REC-04).
//!
//! ## The tension this resolves
//!
//! PRD §7.7 states it exactly: binding the identity key to one device's Secure
//! Enclave means **losing the device loses every conversation, permanently,
//! with no recovery path.** For Persona A that may be precisely right. For
//! Persona C it is a product-ending experience — and Persona C is the anonymity
//! set that protects everyone else (§5).
//!
//! So export is **optional**, **local**, and **honest**:
//!
//! - Optional: Void never creates one on its own.
//! - Local: the archive is handed to the platform share sheet. Void never
//!   transmits or stores it, and there is no server-side backup, no cloud key
//!   escrow, and no HSM recovery scheme (§7.7's design note).
//! - Honest: [`STORAGE_WARNING`] is shown before the share sheet opens, and it
//!   names iCloud and Google Drive specifically, because "store it safely" is
//!   advice nobody acts on and "putting this in iCloud puts it within reach of
//!   a legal request to Apple" is advice people act on.
//!
//! ## Why the identity is exported as seeds
//!
//! An ML-DSA-87 secret key is 4,896 bytes; its seed is 32. The export stores
//! three 32-byte seeds and re-derives the keys on import
//! ([`Identity::from_seeds`](void_proto::identity::Identity::from_seeds)). The
//! archive is smaller, and — more usefully — the thing the user is asked to
//! protect is small enough to be printed or written down if they choose.

use void_crypto::{aead, argon2, rand, Zeroize};
use void_proto::identity::Identity;
use void_proto::wire::{Reader, Writer};

use crate::{StoreError, StoreResult};

/// Magic bytes for an export archive.
pub const EXPORT_MAGIC: &[u8; 8] = b"VOIDEXP\x01";

/// Archive format version.
pub const EXPORT_VERSION: u16 = 1;

/// The warning FR-REC-03 requires before the share sheet opens.
pub const STORAGE_WARNING: &str = "This file is only as safe as the place you put it. If you save \
it to iCloud or Google Drive, its contents are within reach of a legal request to Apple or Google. \
Anyone who has this file and your passphrase can read your messages and act as you.";

/// The acknowledgement FR-REC-01 requires during onboarding.
pub const DEVICE_LOSS_WARNING: &str = "If you lose this device, you lose your messages and your \
identity, permanently. Nobody can recover them for you — not your contacts, not Void. Set up a \
recovery file if that is not acceptable to you.";

/// What an export archive carries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportPayload {
    /// Ed25519 identity seed.
    pub ed_seed: [u8; 32],
    /// ML-DSA identity seed.
    pub mldsa_seed: [u8; 32],
    /// X25519 identity seed.
    pub x_seed: [u8; 32],
    /// Serialized contacts.
    pub contacts: Vec<Vec<u8>>,
    /// Serialized messages. May be empty if the user chose identity-only.
    pub messages: Vec<Vec<u8>>,
    /// Serialized settings.
    pub settings: Vec<u8>,
}

impl Drop for ExportPayload {
    fn drop(&mut self) {
        self.ed_seed.zeroize();
        self.mldsa_seed.zeroize();
        self.x_seed.zeroize();
        for c in self.contacts.iter_mut() {
            c.zeroize();
        }
        for m in self.messages.iter_mut() {
            m.zeroize();
        }
        self.settings.zeroize();
    }
}

impl ExportPayload {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.ed_seed).raw(&self.mldsa_seed).raw(&self.x_seed);
        w.u32(self.contacts.len() as u32);
        for c in &self.contacts {
            w.bytes32(c);
        }
        w.u32(self.messages.len() as u32);
        for m in &self.messages {
            w.bytes32(m);
        }
        w.bytes32(&self.settings);
        w.finish()
    }

    fn decode(bytes: &[u8]) -> StoreResult<ExportPayload> {
        let mut r = Reader::new(bytes);
        let ed_seed = r.array::<32>().map_err(|_| StoreError::Corrupt)?;
        let mldsa_seed = r.array::<32>().map_err(|_| StoreError::Corrupt)?;
        let x_seed = r.array::<32>().map_err(|_| StoreError::Corrupt)?;

        let n = r.u32().map_err(|_| StoreError::Corrupt)? as usize;
        if n > 100_000 {
            return Err(StoreError::Corrupt);
        }
        let mut contacts = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            contacts.push(
                r.bytes32_max(1024 * 1024)
                    .map_err(|_| StoreError::Corrupt)?
                    .to_vec(),
            );
        }
        let n = r.u32().map_err(|_| StoreError::Corrupt)? as usize;
        if n > 10_000_000 {
            return Err(StoreError::Corrupt);
        }
        let mut messages = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            messages.push(
                r.bytes32_max(16 * 1024 * 1024)
                    .map_err(|_| StoreError::Corrupt)?
                    .to_vec(),
            );
        }
        let settings = r
            .bytes32_max(64 * 1024)
            .map_err(|_| StoreError::Corrupt)?
            .to_vec();
        r.finish().map_err(|_| StoreError::Corrupt)?;

        Ok(ExportPayload {
            ed_seed,
            mldsa_seed,
            x_seed,
            contacts,
            messages,
            settings,
        })
    }

    /// Reconstruct the identity from the exported seeds.
    #[must_use]
    pub fn identity(&self) -> Identity {
        Identity::from_seeds(&self.ed_seed, &self.mldsa_seed, &self.x_seed)
    }
}

/// Produce an encrypted archive.
///
/// Uses [`argon2::Params::EXPORT`] — 256 MiB, four passes — rather than the
/// database parameters. The archive may sit in a cloud folder for years, so the
/// per-guess cost for an offline attacker should be as high as a one-off
/// operation can tolerate. The user waits a second; an attacker waits a second
/// per candidate passphrase.
pub fn create(payload: &ExportPayload, passphrase: &[u8]) -> StoreResult<Vec<u8>> {
    create_with_params(payload, passphrase, argon2::Params::EXPORT)
}

/// The minimum Argon2 memory cost an archive may claim, in KiB.
///
/// Enforced on open so that an attacker who can edit the file cannot downgrade
/// the work factor and brute-force the passphrase cheaply.
pub const MIN_EXPORT_M_COST: u32 = 8 * 1024;

/// Produce an archive with explicit cost parameters.
///
/// Public so that tests and a future "low-power device" path can use a cheaper
/// profile. The parameters are stored in the authenticated header, so an
/// archive always records the cost it was actually created with.
pub fn create_with_params(
    payload: &ExportPayload,
    passphrase: &[u8],
    params: argon2::Params,
) -> StoreResult<Vec<u8>> {
    if passphrase.len() < 8 {
        return Err(StoreError::InvalidConfiguration);
    }
    if params.m_cost < MIN_EXPORT_M_COST {
        return Err(StoreError::InvalidConfiguration);
    }
    let salt = rand::bytes16().map_err(|_| StoreError::Entropy)?;
    let nonce = rand::bytes24().map_err(|_| StoreError::Entropy)?;
    let mut key =
        argon2::derive_key32(passphrase, &salt, params).map_err(|_| StoreError::KeyDerivation)?;

    let mut header = Vec::with_capacity(8 + 2 + 12 + 16 + 24);
    header.extend_from_slice(EXPORT_MAGIC);
    header.extend_from_slice(&EXPORT_VERSION.to_be_bytes());
    header.extend_from_slice(&params.m_cost.to_be_bytes());
    header.extend_from_slice(&params.t_cost.to_be_bytes());
    header.extend_from_slice(&params.lanes.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    // The header is authenticated, so the KDF parameters cannot be downgraded
    // by an attacker who wants to make a brute-force cheaper.
    let mut plaintext = payload.encode();
    let sealed = aead::xseal(&key, &nonce, &header, &plaintext);
    key.zeroize();
    plaintext.zeroize();

    let mut out = header;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open an encrypted archive.
pub fn open(archive: &[u8], passphrase: &[u8]) -> StoreResult<ExportPayload> {
    const HEADER_LEN: usize = 8 + 2 + 12 + 16 + 24;
    if archive.len() < HEADER_LEN + aead::TAG_LEN {
        return Err(StoreError::Corrupt);
    }
    if &archive[..8] != EXPORT_MAGIC {
        return Err(StoreError::Corrupt);
    }
    let version = u16::from_be_bytes([archive[8], archive[9]]);
    if version != EXPORT_VERSION {
        return Err(StoreError::UnsupportedVersion);
    }
    let m_cost = u32::from_be_bytes(
        archive[10..14]
            .try_into()
            .map_err(|_| StoreError::Corrupt)?,
    );
    let t_cost = u32::from_be_bytes(
        archive[14..18]
            .try_into()
            .map_err(|_| StoreError::Corrupt)?,
    );
    let lanes = u32::from_be_bytes(
        archive[18..22]
            .try_into()
            .map_err(|_| StoreError::Corrupt)?,
    );

    // Refuse an archive that claims parameters far below what we ever write.
    // Without this, an attacker who can modify the file makes the passphrase
    // trivially brute-forceable and the user never notices.
    if m_cost < MIN_EXPORT_M_COST || t_cost == 0 || lanes == 0 || lanes > 64 {
        return Err(StoreError::Corrupt);
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&archive[22..38]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&archive[38..62]);

    let params = argon2::Params {
        m_cost,
        t_cost,
        lanes,
        out_len: 32,
    };
    let mut key =
        argon2::derive_key32(passphrase, &salt, params).map_err(|_| StoreError::KeyDerivation)?;
    let plaintext = aead::xopen(&key, &nonce, &archive[..HEADER_LEN], &archive[HEADER_LEN..]);
    key.zeroize();
    let mut plaintext = plaintext.map_err(|_| StoreError::Corrupt)?;
    let payload = ExportPayload::decode(&plaintext);
    plaintext.zeroize();
    payload
}

/// Estimate the archive size before writing it, so the UI can warn about a
/// large export before the share sheet appears.
#[must_use]
pub fn estimated_size(payload: &ExportPayload) -> usize {
    let body: usize = 96
        + 8
        + payload.contacts.iter().map(|c| c.len() + 4).sum::<usize>()
        + payload.messages.iter().map(|m| m.len() + 4).sum::<usize>()
        + payload.settings.len()
        + 4;
    body + 62 + aead::TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> ExportPayload {
        ExportPayload {
            ed_seed: [1u8; 32],
            mldsa_seed: [2u8; 32],
            x_seed: [3u8; 32],
            contacts: vec![b"contact-a".to_vec(), b"contact-b".to_vec()],
            messages: vec![b"message-1".to_vec()],
            settings: b"settings".to_vec(),
        }
    }

    /// The production profile is 256 MiB and four passes, which is correct for
    /// a file that may sit in a cloud folder for years and wrong for a test
    /// suite that runs on every commit. These tests use the cheapest profile
    /// the format will accept, which still exercises every code path.
    fn test_params() -> argon2::Params {
        argon2::Params {
            m_cost: MIN_EXPORT_M_COST,
            t_cost: 1,
            lanes: 1,
            out_len: 32,
        }
    }

    fn mk(p: &ExportPayload, pass: &[u8]) -> Vec<u8> {
        create_with_params(p, pass, test_params()).unwrap()
    }
    #[test]
    fn create_and_open_roundtrip() {
        let p = payload();
        let archive = mk(&p, b"a good long passphrase");
        let opened = open(&archive, b"a good long passphrase").unwrap();
        assert_eq!(opened.ed_seed, p.ed_seed);
        assert_eq!(opened.contacts, p.contacts);
        assert_eq!(opened.messages, p.messages);
        assert_eq!(opened.settings, p.settings);
    }

    #[test]
    fn the_identity_survives_a_round_trip() {
        // FR-REC-04: migrating to a new device must reproduce the same
        // identity, or every contact sees a key change.
        let p = payload();
        let before = p.identity().public.clone();
        let archive = mk(&p, b"passphrase123");
        let after = open(&archive, b"passphrase123").unwrap().identity();
        assert_eq!(before, after.public);
        assert_eq!(before.fingerprint(), after.public.fingerprint());
    }

    #[test]
    fn a_wrong_passphrase_fails_cleanly() {
        let archive = mk(&payload(), b"correct passphrase");
        assert!(matches!(
            open(&archive, b"wrong passphrase!"),
            Err(StoreError::Corrupt)
        ));
    }

    #[test]
    fn short_passphrases_are_refused_at_creation() {
        assert!(matches!(
            create(&payload(), b"short"),
            Err(StoreError::InvalidConfiguration)
        ));
    }

    #[test]
    fn seeds_never_appear_in_the_archive() {
        let p = payload();
        let archive = mk(&p, b"a good long passphrase");
        for seed in [&p.ed_seed, &p.mldsa_seed, &p.x_seed] {
            assert!(
                !archive.windows(32).any(|w| w == &seed[..]),
                "a seed leaked into the archive"
            );
        }
        assert!(
            !archive.windows(9).any(|w| w == b"contact-a"),
            "contact data leaked"
        );
    }

    #[test]
    fn kdf_parameters_cannot_be_downgraded() {
        // An attacker who can edit the file must not be able to make the
        // passphrase cheap to brute force.
        let archive = mk(&payload(), b"a good long passphrase");
        let mut weakened = archive.clone();
        weakened[10..14].copy_from_slice(&64u32.to_be_bytes());
        assert!(matches!(
            open(&weakened, b"anything"),
            Err(StoreError::Corrupt)
        ));

        // Even an *increase* to a plausible value fails, because the header is
        // authenticated: the parameters are not a hint the reader may follow,
        // they are part of what the tag covers.
        let mut tweaked = archive.clone();
        tweaked[14..18].copy_from_slice(&2u32.to_be_bytes());
        assert!(open(&tweaked, b"a good long passphrase").is_err());
    }

    #[test]
    fn tampering_and_truncation_are_detected() {
        let archive = mk(&payload(), b"a good long passphrase");
        for i in [0usize, 8, 30, 62, archive.len() - 1] {
            let mut bad = archive.clone();
            bad[i] ^= 1;
            assert!(
                open(&bad, b"a good long passphrase").is_err(),
                "tamper at {i}"
            );
        }
        for n in [0usize, 10, 61, archive.len() - 1] {
            assert!(
                open(&archive[..n], b"a good long passphrase").is_err(),
                "trunc {n}"
            );
        }
    }

    #[test]
    fn hostile_lengths_do_not_drive_allocation() {
        // A payload claiming four billion contacts must be rejected before any
        // allocation proportional to that number.
        let mut w = Writer::new();
        w.raw(&[0u8; 96]).u32(u32::MAX);
        assert!(ExportPayload::decode(&w.finish()).is_err());
    }

    #[test]
    fn identity_only_export_is_valid() {
        let p = ExportPayload {
            ed_seed: [1u8; 32],
            mldsa_seed: [2u8; 32],
            x_seed: [3u8; 32],
            contacts: vec![],
            messages: vec![],
            settings: vec![],
        };
        let archive = mk(&p, b"a good long passphrase");
        let opened = open(&archive, b"a good long passphrase").unwrap();
        assert!(opened.messages.is_empty());
        assert_eq!(opened.ed_seed, [1u8; 32]);
    }

    #[test]
    fn size_estimate_is_close_to_reality() {
        let p = payload();
        let actual = mk(&p, b"a good long passphrase").len();
        let estimate = estimated_size(&p);
        assert!(
            estimate.abs_diff(actual) < 32,
            "estimate {estimate} vs actual {actual}"
        );
    }

    #[test]
    fn the_required_warnings_name_the_real_risks() {
        // FR-REC-03 requires naming the cloud providers specifically.
        assert!(STORAGE_WARNING.contains("iCloud"));
        assert!(STORAGE_WARNING.contains("Google Drive"));
        assert!(STORAGE_WARNING.contains("legal request"));
        // FR-REC-01 requires the loss to be stated as permanent.
        assert!(DEVICE_LOSS_WARNING.contains("permanently"));
        assert!(DEVICE_LOSS_WARNING.contains("Nobody can recover"));
    }
}
