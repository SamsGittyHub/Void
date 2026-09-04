//! Hardware key wrapping and duress destruction (FR-ID-02, FR-STOR-02).
//!
//! ## What the Secure Enclave can and cannot do
//!
//! FR-ID-02a exists because PRD v1.0 claimed key material never enters
//! application memory. On iOS that claim is false and would not survive audit.
//! The Secure Enclave supports **P-256 only**. It cannot generate, hold, or
//! operate on Ed25519, X25519, ML-KEM, or ML-DSA keys. What it can do is hold a
//! non-exportable P-256 key and perform ECDH with it, which is enough to wrap a
//! symmetric data-encryption key.
//!
//! So the real architecture is:
//!
//! ```text
//!   Secure Enclave P-256 key  (non-exportable, biometric-gated)
//!            │  ECDH
//!            ▼
//!   Key-encryption key (KEK)  ──unwraps──▶  Data-encryption key (DEK)
//!                                                   │
//!                                                   ▼
//!                                          the encrypted database
//! ```
//!
//! The guarantee this delivers is **"not extractable from a locked device"**.
//! It is not "never present in application memory": the DEK, and every PQC
//! private key it protects, is in process memory for the duration of an
//! operation and is zeroized after. Saying otherwise would be the exact kind of
//! claim non-negotiable #10 forbids.
//!
//! ## Duress destruction
//!
//! FR-STOR-02 requires that entering a duress PIN destroys the key in under
//! 500 ms, irreversibly, and uninterruptibly. Destroying the *Secure Enclave
//! key* — not the database — is what makes this fast and total: the database
//! is a few hundred megabytes that would take minutes to overwrite, while the
//! Enclave key is one `SecItemDelete` and its loss makes every byte of that
//! database permanently undecryptable. There is no key escrow and no recovery
//! path, by design.
//!
//! The honest sentence FR-STOR-04's setup flow must show the user is in
//! [`DURESS_DISCLOSURE`], and it is in this file so it cannot drift from the
//! behaviour it describes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use void_crypto::{aead, argon2, ct, rand, Zeroize};

use crate::{StoreError, StoreResult};

/// The text FR-STOR-04 and FR-UI-04 require in the duress-PIN setup flow.
///
/// PRD §7.4.1: *"That sentence must appear in the duress-PIN setup flow, in
/// those words or close to them."* It lives next to the implementation so a
/// change to one is visible as a change to the other.
pub const DURESS_DISCLOSURE: &str = "This deletes your messages. It does not hide that Void was \
installed, and it does not give you something to show instead.";

/// The phrase a user must type to confirm duress-PIN setup (FR-UI-04).
pub const DURESS_CONFIRMATION_PHRASE: &str = "I understand this cannot be undone";

/// A holder of a non-exportable key-encryption key.
///
/// On iOS this is backed by a Secure Enclave P-256 key with
/// `kSecAttrTokenIDSecureEnclave`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
/// and an access control requiring user presence. On Android it is a StrongBox
/// or TEE key (NFR-COMP-02 requires the difference be surfaced in the UI, not
/// hidden). The `Software` implementation below is for tests and the CLI, and
/// says so loudly.
pub trait KeyVault: Send + Sync {
    /// Wrap a data-encryption key. The returned blob is safe to store on disk.
    fn wrap(&self, dek: &[u8; 32]) -> StoreResult<Vec<u8>>;

    /// Unwrap a previously wrapped data-encryption key.
    fn unwrap_key(&self, wrapped: &[u8]) -> StoreResult<[u8; 32]>;

    /// Destroy the wrapping key irreversibly.
    ///
    /// After this returns, `unwrap_key` must fail for every blob ever produced
    /// by this vault, on this device, forever.
    fn destroy(&self) -> StoreResult<()>;

    /// Has the wrapping key been destroyed?
    fn is_destroyed(&self) -> bool;

    /// A human-readable description of the backing, for the UI.
    ///
    /// NFR-COMP-02: a user on a device that fell back to a software-backed TEE
    /// is entitled to know that.
    fn backing(&self) -> VaultBacking;
}

/// What is actually protecting the key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VaultBacking {
    /// iOS Secure Enclave.
    SecureEnclave,
    /// Android StrongBox (discrete secure element).
    StrongBox,
    /// Android TEE without StrongBox. Weaker; must be surfaced in the UI.
    TrustedExecutionEnvironment,
    /// Software only. Not acceptable for a shipped client.
    Software,
}

impl VaultBacking {
    /// Plain-language description for the UI (FR-UI-03: no jargon).
    #[must_use]
    pub fn user_description(self) -> &'static str {
        match self {
            VaultBacking::SecureEnclave => {
                "Your keys are held in this iPhone's security chip and cannot be copied off it."
            }
            VaultBacking::StrongBox => {
                "Your keys are held in this phone's dedicated security chip and cannot be copied off it."
            }
            VaultBacking::TrustedExecutionEnvironment => {
                "Your keys are held in this phone's secure area. This phone does not have a \
                 separate security chip, so the protection is weaker than on devices that do."
            }
            VaultBacking::Software => {
                "Your keys are protected by your passphrase only. This device has no hardware \
                 key storage."
            }
        }
    }

    /// Is this backing acceptable for a production client?
    #[must_use]
    pub fn is_hardware_backed(self) -> bool {
        !matches!(self, VaultBacking::Software)
    }
}

/// A software-backed vault, for tests and the reference CLI.
///
/// The KEK is derived from a passphrase with Argon2id. This provides no
/// hardware binding at all: an attacker with the disk image can attack the
/// passphrase offline. It exists so the core can be exercised without a device,
/// and `backing()` reports [`VaultBacking::Software`] so that a UI built on it
/// tells the truth.
pub struct SoftwareVault {
    kek: Mutex<Option<[u8; 32]>>,
    destroyed: AtomicBool,
}

impl SoftwareVault {
    /// Derive a vault from a passphrase and salt.
    pub fn from_passphrase(
        passphrase: &[u8],
        salt: &[u8],
        params: argon2::Params,
    ) -> StoreResult<Self> {
        let kek = argon2::derive_key32(passphrase, salt, params)
            .map_err(|_| StoreError::KeyDerivation)?;
        Ok(SoftwareVault {
            kek: Mutex::new(Some(kek)),
            destroyed: AtomicBool::new(false),
        })
    }

    /// Build from raw key material. Tests only.
    #[must_use]
    pub fn from_raw(kek: [u8; 32]) -> Self {
        SoftwareVault {
            kek: Mutex::new(Some(kek)),
            destroyed: AtomicBool::new(false),
        }
    }
}

impl KeyVault for SoftwareVault {
    fn wrap(&self, dek: &[u8; 32]) -> StoreResult<Vec<u8>> {
        if self.is_destroyed() {
            return Err(StoreError::VaultDestroyed);
        }
        let guard = self.kek.lock().map_err(|_| StoreError::VaultDestroyed)?;
        let kek = guard.as_ref().ok_or(StoreError::VaultDestroyed)?;
        let nonce = rand::bytes24().map_err(|_| StoreError::Entropy)?;
        let mut out = Vec::with_capacity(24 + 32 + 16);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&aead::xseal(kek, &nonce, b"void/v1/vault/wrap", dek));
        Ok(out)
    }

    fn unwrap_key(&self, wrapped: &[u8]) -> StoreResult<[u8; 32]> {
        if self.is_destroyed() {
            return Err(StoreError::VaultDestroyed);
        }
        if wrapped.len() != 24 + 32 + 16 {
            return Err(StoreError::Corrupt);
        }
        let guard = self.kek.lock().map_err(|_| StoreError::VaultDestroyed)?;
        let kek = guard.as_ref().ok_or(StoreError::VaultDestroyed)?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&wrapped[..24]);
        let pt = aead::xopen(kek, &nonce, b"void/v1/vault/wrap", &wrapped[24..])
            .map_err(|_| StoreError::VaultDestroyed)?;
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&pt);
        Ok(dek)
    }

    fn destroy(&self) -> StoreResult<()> {
        // Order matters: set the flag first so that a concurrent unwrap racing
        // us fails rather than succeeding on the way down. FR-STOR-02 requires
        // destruction be uninterruptible; on a real device the equivalent is
        // that `SecItemDelete` is a single kernel transition.
        self.destroyed.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.kek.lock() {
            if let Some(ref mut k) = *guard {
                k.zeroize();
            }
            *guard = None;
        }
        Ok(())
    }

    fn is_destroyed(&self) -> bool {
        self.destroyed.load(Ordering::SeqCst)
    }

    fn backing(&self) -> VaultBacking {
        VaultBacking::Software
    }
}

/// How the app should react to a PIN entered at the lock screen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinOutcome {
    /// The normal unlock PIN. Proceed.
    Unlock,
    /// The duress PIN. Destroy everything and show a first-run screen.
    Duress,
    /// Neither. Count a failed attempt.
    Wrong,
}

/// Verifier for the unlock and duress PINs.
///
/// ## Why both PINs are checked the same way
///
/// Both are stored as Argon2id hashes with the same parameters, and both are
/// compared in constant time, and the *duress check runs first*. If the duress
/// check were cheaper, or ran second, or short-circuited, the time to reject a
/// wrong PIN would differ measurably from the time to trigger destruction — and
/// an examiner watching the screen with a stopwatch could learn that a duress
/// PIN exists on this device. That would defeat the feature, which is the same
/// reason PRD §7.4.1 cut the decoy database.
pub struct PinVerifier {
    unlock_hash: Vec<u8>,
    duress_hash: Option<Vec<u8>>,
    salt: Vec<u8>,
    params: argon2::Params,
    failed_attempts: AtomicBool,
}

impl PinVerifier {
    /// Create a verifier. `duress_pin` is optional (FR-STOR-02 makes the
    /// feature opt-in).
    pub fn new(
        unlock_pin: &[u8],
        duress_pin: Option<&[u8]>,
        salt: &[u8],
        params: argon2::Params,
    ) -> StoreResult<PinVerifier> {
        if let Some(d) = duress_pin {
            if ct::eq(unlock_pin, d) {
                // A duress PIN identical to the unlock PIN would destroy the
                // database on every normal unlock.
                return Err(StoreError::InvalidConfiguration);
            }
        }
        let unlock_hash = argon2::hash(unlock_pin, salt, params, b"unlock", &[])
            .map_err(|_| StoreError::KeyDerivation)?;
        let duress_hash = match duress_pin {
            Some(d) => Some(
                argon2::hash(d, salt, params, b"duress", &[])
                    .map_err(|_| StoreError::KeyDerivation)?,
            ),
            None => None,
        };
        Ok(PinVerifier {
            unlock_hash,
            duress_hash,
            salt: salt.to_vec(),
            params,
            failed_attempts: AtomicBool::new(false),
        })
    }

    /// Classify an entered PIN.
    ///
    /// Both hashes are always computed, in the same order, regardless of which
    /// (if either) matches. When no duress PIN is configured a dummy hash is
    /// computed anyway, so that the presence or absence of the feature is not
    /// observable in the response time.
    pub fn check(&self, pin: &[u8]) -> StoreResult<PinOutcome> {
        let unlock_attempt = argon2::hash(pin, &self.salt, self.params, b"unlock", &[])
            .map_err(|_| StoreError::KeyDerivation)?;
        let duress_attempt = argon2::hash(pin, &self.salt, self.params, b"duress", &[])
            .map_err(|_| StoreError::KeyDerivation)?;

        let unlock_ok = ct::eq(&unlock_attempt, &self.unlock_hash);
        let duress_ok = match &self.duress_hash {
            Some(h) => ct::eq(&duress_attempt, h),
            // Compare against the unlock hash so the work is identical; the
            // result is discarded.
            None => {
                let _ = ct::eq(&duress_attempt, &self.unlock_hash);
                false
            }
        };

        // Duress wins if somehow both matched, which the constructor prevents
        // but which we do not want to depend on here.
        if duress_ok {
            Ok(PinOutcome::Duress)
        } else if unlock_ok {
            Ok(PinOutcome::Unlock)
        } else {
            self.failed_attempts.store(true, Ordering::Relaxed);
            Ok(PinOutcome::Wrong)
        }
    }

    /// Whether a duress PIN is configured. For the settings screen only —
    /// never expose this over any interface an examiner could reach.
    #[must_use]
    pub fn has_duress_pin(&self) -> bool {
        self.duress_hash.is_some()
    }

    /// Has any wrong PIN been entered in this process lifetime?
    #[must_use]
    pub fn saw_failed_attempt(&self) -> bool {
        self.failed_attempts.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weak() -> argon2::Params {
        argon2::Params::TEST_ONLY_WEAK
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let v = SoftwareVault::from_raw([1u8; 32]);
        let dek = [9u8; 32];
        let wrapped = v.wrap(&dek).unwrap();
        assert_ne!(
            &wrapped[24..56],
            &dek[..],
            "the dek must not appear in clear"
        );
        assert_eq!(v.unwrap_key(&wrapped).unwrap(), dek);
    }

    #[test]
    fn destruction_is_irreversible_and_total() {
        let v = SoftwareVault::from_raw([1u8; 32]);
        let a = v.wrap(&[1u8; 32]).unwrap();
        let b = v.wrap(&[2u8; 32]).unwrap();
        assert!(!v.is_destroyed());

        v.destroy().unwrap();

        assert!(v.is_destroyed());
        // Every blob ever produced must now be undecryptable, not just the
        // most recent one.
        assert!(matches!(v.unwrap_key(&a), Err(StoreError::VaultDestroyed)));
        assert!(matches!(v.unwrap_key(&b), Err(StoreError::VaultDestroyed)));
        assert!(matches!(
            v.wrap(&[3u8; 32]),
            Err(StoreError::VaultDestroyed)
        ));
        // And destroying twice is not an error.
        assert!(v.destroy().is_ok());
    }

    #[test]
    fn destruction_is_fast_enough_for_fr_stor_02() {
        // FR-STOR-02: under 500 ms. The point of destroying the key rather than
        // the data is that this is essentially instant.
        let v = SoftwareVault::from_raw([1u8; 32]);
        let start = std::time::Instant::now();
        v.destroy().unwrap();
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "duress destruction took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_different_vault_cannot_unwrap() {
        let a = SoftwareVault::from_raw([1u8; 32]);
        let b = SoftwareVault::from_raw([2u8; 32]);
        let w = a.wrap(&[7u8; 32]).unwrap();
        assert!(b.unwrap_key(&w).is_err());
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let v = SoftwareVault::from_raw([1u8; 32]);
        let w = v.wrap(&[7u8; 32]).unwrap();
        for i in [0usize, 23, 24, w.len() - 1] {
            let mut bad = w.clone();
            bad[i] ^= 1;
            assert!(v.unwrap_key(&bad).is_err(), "tamper at {i}");
        }
        assert!(v.unwrap_key(&w[..10]).is_err());
    }

    #[test]
    fn passphrase_vault_is_deterministic() {
        let a = SoftwareVault::from_passphrase(b"correct horse", b"saltsaltsalt", weak()).unwrap();
        let b = SoftwareVault::from_passphrase(b"correct horse", b"saltsaltsalt", weak()).unwrap();
        let w = a.wrap(&[5u8; 32]).unwrap();
        assert_eq!(b.unwrap_key(&w).unwrap(), [5u8; 32]);

        let c = SoftwareVault::from_passphrase(b"wrong horse", b"saltsaltsalt", weak()).unwrap();
        assert!(c.unwrap_key(&w).is_err());
    }

    #[test]
    fn pin_classification() {
        let v = PinVerifier::new(b"1234", Some(b"9999"), b"saltsaltsalt", weak()).unwrap();
        assert_eq!(v.check(b"1234").unwrap(), PinOutcome::Unlock);
        assert_eq!(v.check(b"9999").unwrap(), PinOutcome::Duress);
        assert_eq!(v.check(b"0000").unwrap(), PinOutcome::Wrong);
        assert!(v.has_duress_pin());
        assert!(v.saw_failed_attempt());
    }

    #[test]
    fn duress_pin_may_not_equal_unlock_pin() {
        assert!(matches!(
            PinVerifier::new(b"1234", Some(b"1234"), b"saltsaltsalt", weak()),
            Err(StoreError::InvalidConfiguration)
        ));
    }

    #[test]
    fn without_a_duress_pin_nothing_triggers_duress() {
        let v = PinVerifier::new(b"1234", None, b"saltsaltsalt", weak()).unwrap();
        assert!(!v.has_duress_pin());
        for candidate in [&b"1234"[..], b"0000", b"9999", b""] {
            assert_ne!(v.check(candidate).unwrap(), PinOutcome::Duress);
        }
    }

    #[test]
    fn duress_check_does_not_short_circuit() {
        // Both configurations must do the same amount of work, or the presence
        // of a duress PIN is observable from response time alone. This test is
        // a smoke check, not a real timing analysis — the CI `dudect` job is
        // what actually measures it.
        let with = PinVerifier::new(b"1234", Some(b"9999"), b"saltsaltsalt", weak()).unwrap();
        let without = PinVerifier::new(b"1234", None, b"saltsaltsalt", weak()).unwrap();

        let t0 = std::time::Instant::now();
        for _ in 0..20 {
            let _ = with.check(b"0000").unwrap();
        }
        let with_time = t0.elapsed();

        let t1 = std::time::Instant::now();
        for _ in 0..20 {
            let _ = without.check(b"0000").unwrap();
        }
        let without_time = t1.elapsed();

        let ratio = with_time.as_secs_f64() / without_time.as_secs_f64().max(1e-9);
        assert!(
            (0.5..2.0).contains(&ratio),
            "duress presence changed timing by {ratio}x"
        );
    }

    #[test]
    fn the_required_disclosure_text_is_present_and_honest() {
        // PRD §7.4.1 requires these three admissions verbatim or close to it.
        let d = DURESS_DISCLOSURE;
        assert!(d.contains("deletes your messages"));
        assert!(d.contains("does not hide that Void was installed"));
        assert!(d.contains("does not give you something to show instead"));
        assert!(!DURESS_CONFIRMATION_PHRASE.is_empty());
    }

    #[test]
    fn backing_is_reported_honestly() {
        let v = SoftwareVault::from_raw([1u8; 32]);
        assert_eq!(v.backing(), VaultBacking::Software);
        assert!(!v.backing().is_hardware_backed());
        // NFR-COMP-02: the TEE fallback must be described as weaker.
        assert!(VaultBacking::TrustedExecutionEnvironment
            .user_description()
            .contains("weaker"));
        assert!(VaultBacking::SecureEnclave.is_hardware_backed());
    }
}
