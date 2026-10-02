//! # void-ffi
//!
//! The C ABI the Swift and Kotlin clients call.
//!
//! ## Why this is hand-written and not UniFFI
//!
//! PRD §11 Phase 3 says "UniFFI bindings". UniFFI is the right tool and
//! `docs/DECISIONS.md#d-010` records the intent to adopt it. This crate is a
//! hand-written C ABI because the build environment for this revision has no
//! package registry, and because writing it out once makes the FFI surface
//! explicit — which for the *one* place the memory-safe core meets
//! platform-managed memory is worth doing deliberately.
//!
//! NFR-SEC-02 permits `unsafe` only at "a small, explicitly enumerated and
//! separately reviewed FFI boundary". This crate is that boundary and it is the
//! only crate in the workspace without `#![forbid(unsafe_code)]`. Everything
//! `unsafe` in Void is in this file, and it is all of one shape: converting a
//! caller-supplied pointer and length into a slice.
//!
//! ## The rules this boundary follows
//!
//! 1. **No panics cross the boundary.** Every entry point wraps its body in
//!    `catch_unwind`. A panic unwinding into Swift or Kotlin is undefined
//!    behaviour, and a crash in a messaging app under duress is worse than an
//!    error code.
//! 2. **No secrets in returned strings.** Buffers the platform allocates are
//!    outside our zeroization discipline, so nothing secret is ever returned by
//!    value — the platform gets handles and opaque bytes, never key material.
//! 3. **Every buffer is freed by the side that allocated it.** `void_free_bytes`
//!    is the only way to release something this crate returned.
//! 4. **Null and zero-length inputs are valid and produce errors, not crashes.**
//!    The platform layer is not trusted to be correct; it is another attack
//!    surface.

#![deny(missing_docs)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use void_client::engine::{Engine, SecurityMode, TickOutcome};
use void_proto::fingerprint;
use void_proto::identity::Identity;
use void_proto::queue::QueueId;
use void_store::model::Settings;
use void_store::vault::{DURESS_CONFIRMATION_PHRASE, DURESS_DISCLOSURE};

/// Status codes returned across the boundary.
///
/// Deliberately coarse, matching `ProtoError`'s reasoning: a caller — and
/// therefore anything an attacker can observe through the UI — must not be able
/// to distinguish a bad MAC from a bad key.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VoidStatus {
    /// Success.
    Ok = 0,
    /// A pointer was null or a length was zero where that is not allowed.
    BadArgument = 1,
    /// The operation failed.
    Failed = 2,
    /// The network is unreachable; messages are queued (FR-TRANS-05).
    Offline = 3,
    /// The contact's identity key changed; sending is blocked (FR-DISC-05).
    KeyChanged = 4,
    /// The database is locked or its key has been destroyed.
    Locked = 5,
    /// An internal invariant failed. Reported rather than panicking.
    Internal = 6,
    /// The invitation has expired. The person who made it needs to make a new
    /// one.
    Expired = 7,
    /// A conversation with this person already exists (see
    /// `void_client::ClientError::AlreadyConnected` for why this refuses).
    AlreadyConnected = 8,
    /// The invitation is the user's own.
    OwnInvite = 9,
    /// The invitation is parked on a different relay from the one this app
    /// uses.
    WrongRelay = 10,
    /// A file is larger than one message carries ([`void_file_max_bytes`]),
    /// or its name or type is too long. Nothing was queued and no ratchet
    /// state was spent.
    TooLarge = 11,
}

/// The largest `now` this boundary accepts: 3000-01-01T00:00:00Z, in Unix
/// seconds.
///
/// Every `now` crossing the boundary is in **seconds** (`now_ms` parameters
/// say so in their name). A millisecond value passed by mistake is about a
/// thousand times larger than any plausible time in seconds, so it lands far
/// past this bound and is refused as [`VoidStatus::BadArgument`]. That mix-up
/// is not hypothetical: the Android app made it, and its invitations expired
/// 3.6 seconds after they were created.
const MAX_PLAUSIBLE_UNIX_SECONDS: u64 = 32_503_680_000;

/// Whether `now` can be a time in seconds. See [`MAX_PLAUSIBLE_UNIX_SECONDS`].
fn plausible_seconds(now: u64) -> bool {
    now <= MAX_PLAUSIBLE_UNIX_SECONDS
}

/// An owned byte buffer handed to the platform.
///
/// The platform must return it to [`void_free_bytes`]. It never contains key
/// material — see rule 2 in the crate documentation.
#[repr(C)]
pub struct VoidBytes {
    /// Pointer to the data, or null.
    pub data: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

impl VoidBytes {
    fn empty() -> VoidBytes {
        VoidBytes {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }

    fn from_vec(mut v: Vec<u8>) -> VoidBytes {
        v.shrink_to_fit();
        let len = v.len();
        let data = v.as_mut_ptr();
        std::mem::forget(v);
        VoidBytes { data, len }
    }
}

/// An opaque handle to an engine.
pub struct VoidEngine {
    inner: Mutex<Engine>,
}

/// Convert a caller pointer and length into a slice.
///
/// # Safety
/// `ptr` must be valid for `len` bytes, or null with `len == 0`.
unsafe fn slice_from<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return if len == 0 { Some(&[]) } else { None };
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

/// Run `f`, converting any panic into [`VoidStatus::Internal`].
fn guard<F: FnOnce() -> VoidStatus>(f: F) -> VoidStatus {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(VoidStatus::Internal)
}

fn guard_bytes<F: FnOnce() -> VoidBytes>(f: F) -> VoidBytes {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| VoidBytes::empty())
}

// --- lifecycle ---------------------------------------------------------------

/// Create an engine with a freshly generated identity, held in memory only.
///
/// Generation is entirely offline (FR-ID-04): no network round trip, no server
/// state, nothing to register. Nothing it holds outlives the process, so this
/// is for tests; the apps use [`void_engine_open`].
///
/// # Safety
/// `out` must be a valid pointer to a `*mut VoidEngine`.
#[no_mangle]
pub unsafe extern "C" fn void_engine_new(out: *mut *mut VoidEngine) -> VoidStatus {
    if out.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(identity) = Identity::generate() else {
            return VoidStatus::Failed;
        };
        // The platform layer supplies a Tor-routed transport through
        // `void_engine_attach_tor`; until then the engine has none and every
        // send queues, which is the correct fail-closed default.
        let Ok(engine) = Engine::new(
            identity,
            Settings::default(),
            Box::new(void_client::transport::NullTransport::new()),
            SecurityMode::Enforcing,
            0,
        ) else {
            return VoidStatus::Failed;
        };
        let boxed = Box::new(VoidEngine {
            inner: Mutex::new(engine),
        });
        *out = Box::into_raw(boxed);
        VoidStatus::Ok
    })
}

/// The database file inside the data directory [`void_engine_open`] is given.
const DATABASE_FILE: &str = "void.db";

/// Open this device's engine: restore it if it has run here before, otherwise
/// create it with a freshly generated identity. The apps call this, not
/// [`void_engine_new`], which keeps nothing past the process.
///
/// `kek` is the 32-byte key-encryption key the platform's hardware keystore
/// released for this launch (Secure Enclave on iOS, Keystore on Android), and
/// `backing` says truthfully what protects it at rest on this device
/// (NFR-COMP-02). This crate copies it into a vault used only to unwrap the
/// database key, and zeroizes every copy it made before returning. Deleting
/// the hardware key — duress destruction's irreversible step — stays the
/// platform's job (D-017).
///
/// `data_dir` must be app-private and excluded from backup (FR-STOR-05); it is
/// created if missing. The engine starts on a transport that carries nothing,
/// so every send queues until [`void_engine_attach_tor`] (FR-TRANS-05).
///
/// Returns `Locked` if the key does not open the existing database — a wrong
/// key, or one destroyed by a duress PIN. Never falls back to creating a new
/// database in its place: that would silently replace the user's identity,
/// which every contact would then see as a key change.
///
/// # Safety
/// `data_dir` must be a valid, NUL-terminated UTF-8 string. `kek` must point
/// to 32 readable bytes. `out` must be a valid pointer to a `*mut VoidEngine`.
#[no_mangle]
pub unsafe extern "C" fn void_engine_open(
    data_dir: *const c_char,
    kek: *const u8,
    backing: VoidVaultBacking,
    now_ms: u64,
    out: *mut *mut VoidEngine,
) -> VoidStatus {
    if data_dir.is_null() || kek.is_null() || out.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(dir) = CStr::from_ptr(data_dir).to_str() else {
            return VoidStatus::BadArgument;
        };
        let dir = std::path::Path::new(dir);
        if std::fs::create_dir_all(dir).is_err() {
            return VoidStatus::Failed;
        }
        let mut key = [0u8; 32];
        std::ptr::copy_nonoverlapping(kek, key.as_mut_ptr(), 32);
        // The vault takes its own copy (and zeroizes it when dropped at the end
        // of this call); this one is wiped immediately.
        let vault = void_store::vault::PlatformVault::new(key, backing.to_store());
        void_crypto::Zeroize::zeroize(&mut key);

        let backend = void_store::db::FileBackend::new(dir.join(DATABASE_FILE));
        let transport = Box::new(void_client::transport::NullTransport::new());
        let engine = if void_store::db::Backend::exists(&backend) {
            let db = match void_store::db::Database::open(backend, &vault) {
                Ok(db) => db,
                Err(void_store::StoreError::VaultDestroyed) => return VoidStatus::Locked,
                Err(_) => return VoidStatus::Failed,
            };
            Engine::restore(Box::new(db), transport, SecurityMode::Enforcing, now_ms)
        } else {
            let Ok((identity, seeds)) = Identity::generate_with_seeds() else {
                return VoidStatus::Failed;
            };
            let Ok(db) = void_store::db::Database::create(
                backend,
                &vault,
                void_crypto::argon2::Params::DEFAULT,
            ) else {
                return VoidStatus::Failed;
            };
            Engine::new_persisted(
                identity,
                &seeds,
                Settings::default(),
                transport,
                SecurityMode::Enforcing,
                now_ms,
                Box::new(db),
            )
        };
        let Ok(engine) = engine else {
            return VoidStatus::Failed;
        };
        *out = Box::into_raw(Box::new(VoidEngine {
            inner: Mutex::new(engine),
        }));
        VoidStatus::Ok
    })
}

/// The stored history with one contact, oldest first — what a conversation
/// screen shows when it reopens after a restart.
///
/// Layout, repeated per message:
///
/// ```text
///   u64 LE(id)           names this message to void_engine_attachment
///   u8(direction)        1 = sent by us, 2 = received
///   u8(delivery)         0 queued, 1 sent, 2 delivered, 3 failed, 4 received
///   u64 LE(timestamp)    Unix seconds, local clock
///   u16 LE(remaining)    records of it still waiting to leave; 0 once sent
///   u32 LE(text_len) || raw(text)
///   u8(has_file)         0 or 1; the rest only when 1:
///   u16 LE(name_len) || raw(name)
///   u16 LE(mime_len) || raw(mime)
///   u32 LE(size)         the file's size in bytes
/// ```
///
/// A file's bytes are not here; [`void_engine_attachment`] fetches them by
/// `id` when that message is on screen, so listing a conversation with a
/// hundred photos in it copies none of them. `remaining` times
/// [`void_pad_interval_ms`] is how long a file still has to go.
///
/// Empty for an engine with no store attached.
///
/// # Safety
/// `engine` must be valid and `fingerprint` must point to 32 readable bytes.
/// Free the result with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_engine_messages(
    engine: *const VoidEngine,
    fingerprint: *const u8,
) -> VoidBytes {
    if engine.is_null() || fingerprint.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let mut fp = [0u8; 32];
        std::ptr::copy_nonoverlapping(fingerprint, fp.as_mut_ptr(), 32);
        let Ok(guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        let Ok(history) = guard.history(&fp) else {
            return VoidBytes::empty();
        };
        VoidBytes::from_vec(encode_history(&history))
    })
}

fn encode_history(entries: &[void_client::engine::HistoryEntry]) -> Vec<u8> {
    use void_store::model::{DeliveryState, Direction};
    let mut out = Vec::new();
    for e in entries {
        let m = &e.message;
        out.extend_from_slice(&e.id.to_le_bytes());
        out.push(match m.direction {
            Direction::Outgoing => 1u8,
            Direction::Incoming => 2u8,
        });
        out.push(match m.delivery {
            DeliveryState::Queued => 0u8,
            DeliveryState::Deposited => 1,
            DeliveryState::Collected => 2,
            DeliveryState::Failed => 3,
            DeliveryState::Received => 4,
        });
        out.extend_from_slice(&m.timestamp.to_le_bytes());
        out.extend_from_slice(&e.fragments_remaining.to_le_bytes());
        out.extend_from_slice(&(m.body.len() as u32).to_le_bytes());
        out.extend_from_slice(m.body.as_bytes());
        match &m.attachment {
            None => out.push(0),
            Some(file) => {
                out.push(1);
                let name = &file.name.as_bytes()[..file.name.len().min(u16::MAX as usize)];
                out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                out.extend_from_slice(name);
                let mime = &file.mime.as_bytes()[..file.mime.len().min(u16::MAX as usize)];
                out.extend_from_slice(&(mime.len() as u16).to_le_bytes());
                out.extend_from_slice(mime);
                out.extend_from_slice(&file.len.to_le_bytes());
            }
        }
    }
    out
}

/// The bytes of the file a stored message carries, by the `id`
/// [`void_engine_messages`] gave it. Empty for a message that is not a file,
/// one retention has since deleted, or an id that is not a message's.
///
/// # Safety
/// `engine` must be valid. Free the result with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_engine_attachment(engine: *const VoidEngine, id: u64) -> VoidBytes {
    if engine.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let Ok(guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        match guard.attachment(id) {
            Ok(Some(file)) => VoidBytes::from_vec(file.data.clone()),
            _ => VoidBytes::empty(),
        }
    })
}

/// Destroy an engine, zeroizing its secrets.
///
/// # Safety
/// `engine` must have come from [`void_engine_new`] or [`void_engine_open`]
/// and must not be used after.
#[no_mangle]
pub unsafe extern "C" fn void_engine_free(engine: *mut VoidEngine) {
    if engine.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(engine));
    }));
}

/// Free a buffer this crate returned.
///
/// # Safety
/// `bytes` must have come from this crate and must not be used after.
#[no_mangle]
pub unsafe extern "C" fn void_free_bytes(bytes: VoidBytes) {
    if bytes.data.is_null() || bytes.len == 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Vec::from_raw_parts(bytes.data, bytes.len, bytes.len));
    }));
}

// --- duress and the lock screen ----------------------------------------------
//
// FR-STOR-02's destruction has two halves, split across the boundary on
// purpose. Destroying the hardware vault key is a platform API call —
// `SecItemDelete` on iOS, `KeyStore.deleteEntry` on Android — that this crate
// has no reason to wrap, since void-ffi has no platform code of its own (see
// the module docs) and the call has nothing to do with anything Rust holds.
// What crosses this boundary is the two things that *are* the core's job:
// classifying the PIN the user typed, and erasing what this process holds
// once the platform has already destroyed the key.
//
// The lock screen's flow is therefore:
//   1. `void_pin_check` — classify the entered PIN.
//   2. On `Duress`, the platform calls `SecItemDelete` (or equivalent) itself.
//   3. `void_engine_duress_destroy` — erase the local store and RAM.
//   4. The platform navigates to a first-run screen. Also pure UI.

/// An opaque handle to a PIN verifier.
pub struct VoidPinVerifier {
    inner: void_store::vault::PinVerifier,
}

/// How an entered PIN classified.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VoidPinOutcome {
    /// The normal unlock PIN.
    Unlock = 0,
    /// The duress PIN. The platform must destroy the vault key, call
    /// [`void_engine_duress_destroy`], and show a first-run screen.
    Duress = 1,
    /// Neither PIN. Count a failed attempt.
    Wrong = 2,
    /// The check itself failed (e.g. entropy unavailable). Treat as neither
    /// PIN — never as a reason to skip counting a failed attempt.
    Error = 3,
}

/// Build a PIN verifier from an unlock PIN and an optional duress PIN.
///
/// `duress_pin` may be null (with `duress_pin_len == 0`) — FR-STOR-02 makes
/// the duress PIN opt-in. Uses [`void_crypto::argon2::Params::DEFAULT`], the
/// same cost as the database's own key derivation.
///
/// # Safety
/// `out` must be a valid pointer to a `*mut VoidPinVerifier`. `unlock_pin` and
/// `salt` must be valid for their lengths; `duress_pin` likewise, or null with
/// length zero.
#[no_mangle]
pub unsafe extern "C" fn void_pin_verifier_new(
    unlock_pin: *const u8,
    unlock_pin_len: usize,
    duress_pin: *const u8,
    duress_pin_len: usize,
    salt: *const u8,
    salt_len: usize,
    out: *mut *mut VoidPinVerifier,
) -> VoidStatus {
    if out.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let (Some(unlock), Some(salt)) = (
            slice_from(unlock_pin, unlock_pin_len),
            slice_from(salt, salt_len),
        ) else {
            return VoidStatus::BadArgument;
        };
        let duress = if duress_pin_len == 0 {
            None
        } else {
            match slice_from(duress_pin, duress_pin_len) {
                Some(d) => Some(d),
                None => return VoidStatus::BadArgument,
            }
        };
        let Ok(inner) = void_store::vault::PinVerifier::new(
            unlock,
            duress,
            salt,
            void_crypto::argon2::Params::DEFAULT,
        ) else {
            return VoidStatus::Failed;
        };
        *out = Box::into_raw(Box::new(VoidPinVerifier { inner }));
        VoidStatus::Ok
    })
}

/// Free a PIN verifier.
///
/// # Safety
/// `verifier` must have come from [`void_pin_verifier_new`] and must not be
/// used after.
#[no_mangle]
pub unsafe extern "C" fn void_pin_verifier_free(verifier: *mut VoidPinVerifier) {
    if verifier.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(verifier));
    }));
}

/// Classify an entered PIN.
///
/// Always does the same work regardless of which PIN (if either) matches —
/// see [`void_store::vault::PinVerifier::check`] for why that matters.
///
/// # Safety
/// `verifier` must be valid. `pin` must be valid for `pin_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn void_pin_check(
    verifier: *const VoidPinVerifier,
    pin: *const u8,
    pin_len: usize,
) -> VoidPinOutcome {
    if verifier.is_null() {
        return VoidPinOutcome::Error;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let Some(pin) = slice_from(pin, pin_len) else {
            return VoidPinOutcome::Error;
        };
        match (*verifier).inner.check(pin) {
            Ok(void_store::vault::PinOutcome::Unlock) => VoidPinOutcome::Unlock,
            Ok(void_store::vault::PinOutcome::Duress) => VoidPinOutcome::Duress,
            Ok(void_store::vault::PinOutcome::Wrong) => VoidPinOutcome::Wrong,
            Err(_) => VoidPinOutcome::Error,
        }
    }))
    .unwrap_or(VoidPinOutcome::Error)
}

/// The second half of duress destruction (FR-STOR-02): erase the local store
/// and every session, contact, and queued message this process holds.
///
/// Call this only after the platform has already destroyed the hardware
/// vault key — that destruction, not this call, is what makes the data
/// unrecoverable. This method still runs, and still wipes what it can, even
/// on an engine with no store attached, so that a caller cannot skip the RAM
/// wipe by forgetting to check first.
///
/// # Safety
/// `engine` must be valid.
#[no_mangle]
pub unsafe extern "C" fn void_engine_duress_destroy(engine: *mut VoidEngine) -> VoidStatus {
    if engine.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.duress_destroy() {
            Ok(()) => VoidStatus::Ok,
            Err(_) => VoidStatus::Failed,
        }
    })
}

// --- Tor -----------------------------------------------------------------
//
// void-ffi is the only place in the workspace that links both void-client
// and void-tor — the platform-facing static/dynamic library the app embeds
// necessarily contains both halves of the seam D-009 describes, even though
// void-client itself never depends on void-tor and knows nothing about it.
// These two functions are the entire surface: bootstrap once, then attach
// the resulting circuit to an engine with `void_engine_attach_tor`. There is
// no third function that skips either step.

/// An opaque handle to a bootstrapped Arti client.
pub struct VoidTorHandle {
    inner: void_tor::TorHandle,
}

/// Bootstrap Arti, storing its state and cache under the given directories.
///
/// **Blocks the calling thread** until bootstrap succeeds or fails — this is
/// a network operation, commonly tens of seconds, and the platform layer
/// must call it off the main/UI thread.
///
/// # Safety
/// `out` must be a valid pointer to a `*mut VoidTorHandle`. `state_dir` and
/// `cache_dir` must be valid, NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn void_tor_bootstrap(
    state_dir: *const c_char,
    cache_dir: *const c_char,
    out: *mut *mut VoidTorHandle,
) -> VoidStatus {
    if out.is_null() || state_dir.is_null() || cache_dir.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let (Ok(state_dir), Ok(cache_dir)) = (
            CStr::from_ptr(state_dir).to_str(),
            CStr::from_ptr(cache_dir).to_str(),
        ) else {
            return VoidStatus::BadArgument;
        };
        match void_tor::TorHandle::bootstrap(
            std::path::Path::new(state_dir),
            std::path::Path::new(cache_dir),
        ) {
            Ok(inner) => {
                *out = Box::into_raw(Box::new(VoidTorHandle { inner }));
                VoidStatus::Ok
            }
            // FR-TRANS-05: bootstrap failure is not partial success. The
            // caller gets `Offline` and queues, exactly as if a circuit it
            // already had had died.
            Err(_) => VoidStatus::Offline,
        }
    })
}

/// Free a Tor handle.
///
/// # Safety
/// `handle` must have come from [`void_tor_bootstrap`] and must not be used
/// after, including by any [`VoidEngine`] still holding a transport built
/// from it — see [`void_engine_attach_tor`].
#[no_mangle]
pub unsafe extern "C" fn void_tor_free(handle: *mut VoidTorHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(handle));
    }));
}

/// Open a circuit to `onion_address` on `port` and make it `engine`'s
/// transport.
///
/// This is the whole of FR-TRANS-04's pinning: `onion_address` is the
/// relay's Tor v3 public key, encoded, and it is used for nothing but
/// dialling — there is no certificate authority anywhere in this path, and
/// nothing here could fall back to reaching `onion_address` any other way.
///
/// # Safety
/// `engine` and `tor` must be valid. `onion_address` must be a valid,
/// NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn void_engine_attach_tor(
    engine: *mut VoidEngine,
    tor: *const VoidTorHandle,
    onion_address: *const c_char,
    port: u16,
) -> VoidStatus {
    if engine.is_null() || tor.is_null() || onion_address.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(onion_address) = CStr::from_ptr(onion_address).to_str() else {
            return VoidStatus::BadArgument;
        };
        let transport = match (*tor).inner.connect(onion_address, port) {
            Ok(t) => t,
            Err(_) => return VoidStatus::Offline,
        };
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.set_transport(Box::new(transport)) {
            Ok(()) => {
                // What short invitations made here name, and what ones opened
                // here must name.
                guard.set_relay(&format!("{onion_address}:{port}"));
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Failed,
        }
    })
}

// --- conversations -------------------------------------------------------
//
// The shapes here are deliberately simple, fixed-layout byte encodings —
// `(fingerprint: 32 bytes) || (u32 LE length) || (UTF-8 text)`, repeated —
// rather than a serialization framework, for the same reason `void-proto`'s
// own wire format is hand-written: this is the most attacker-exposed code
// in the system, and an explicit reader the platform team can audit in ten
// minutes is worth more than a dependency. Each function's doc comment
// states its exact layout.

/// Publish an invitation (FR-DISC-01, FR-DISC-02) and return its link.
///
/// `out_link` receives the `void://` link — render it as a QR code or share
/// sheet text; both are the same string. `out_invite_id` receives 16 bytes
/// naming this invitation in [`void_engine_take_contact_events`] and
/// [`void_engine_cancel_invite`].
///
/// `relay_hint` is where the invitation is parked; empty (null with length 0)
/// means the relay [`void_engine_attach_tor`] attached. `my_label` travels
/// inside the encrypted invitation and is shown to whoever opens it.
/// `contact_label` never leaves the device: it becomes the name of whoever
/// accepts. Either may be empty.
///
/// The link is short — one QR code — because the invitation itself is parked
/// on the relay; see [`void_engine_invite_status`] for how far along that is.
///
/// The engine keeps the invitation and watches for its acceptance on its own
/// schedule; the platform does nothing but tick and drain contact events. Any
/// number of invitations can be outstanding at once.
///
/// `now` and `ttl_seconds` are in **seconds**. A millisecond `now` is refused
/// as `BadArgument` rather than misread.
///
/// # Safety
/// `engine` must be valid. Each pointer/length pair must be valid for its
/// length. `out_link` must be a valid output pointer and `out_invite_id` must
/// be valid for 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_create_invite(
    engine: *mut VoidEngine,
    relay_hint: *const u8,
    relay_hint_len: usize,
    my_label: *const u8,
    my_label_len: usize,
    contact_label: *const u8,
    contact_label_len: usize,
    now: u64,
    ttl_seconds: u64,
    out_link: *mut VoidBytes,
    out_invite_id: *mut u8,
) -> VoidStatus {
    if engine.is_null() || out_link.is_null() || out_invite_id.is_null() {
        return VoidStatus::BadArgument;
    }
    if !plausible_seconds(now) {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let (Some(hint), Some(my_label), Some(contact_label)) = (
            slice_from(relay_hint, relay_hint_len),
            slice_from(my_label, my_label_len),
            slice_from(contact_label, contact_label_len),
        ) else {
            return VoidStatus::BadArgument;
        };
        let (Ok(my_label), Ok(contact_label)) = (
            std::str::from_utf8(my_label),
            std::str::from_utf8(contact_label),
        ) else {
            return VoidStatus::BadArgument;
        };
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.create_invite(hint, my_label, contact_label, now, ttl_seconds) {
            Ok(created) => {
                *out_link = VoidBytes::from_vec(created.link.into_bytes());
                std::ptr::copy_nonoverlapping(created.id.as_ptr(), out_invite_id, 16);
                VoidStatus::Ok
            }
            Err(e) => client_status(e),
        }
    })
}

/// Withdraw an invitation. A handshake sent against it afterwards is never
/// answered. Returns `Failed` if it was not outstanding (already accepted,
/// expired, or cancelled).
///
/// # Safety
/// `engine` must be valid and `invite_id` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_cancel_invite(
    engine: *mut VoidEngine,
    invite_id: *const u8,
) -> VoidStatus {
    if engine.is_null() || invite_id.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let mut id: QueueId = [0u8; 16];
        std::ptr::copy_nonoverlapping(invite_id, id.as_mut_ptr(), 16);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        if guard.cancel_invite(&id) {
            VoidStatus::Ok
        } else {
            VoidStatus::Failed
        }
    })
}

/// Drain everything that has happened to contacts and invitations since the
/// last drain. Call it after every [`void_engine_tick`].
///
/// Layout, repeated per event:
///
/// ```text
///   u8(kind)              1 = someone accepted one of our invitations
///                         2 = one of our invitations expired unaccepted
///                         3 = an invitation the user opened is ready to confirm
///                         4 / 5 / 6 = one the user opened could not be used:
///                                     expired / invalid / never arrived
///   raw(id : 16)          our invitation's id (1, 2) or the fetch id (3–6)
///   raw(fingerprint : 32) kind 1: the new contact; kind 3: who made the
///                         invitation; otherwise zero
///   u16 LE(name_len)      || raw(name)      kind 1: the contact's local name;
///                                           kind 3: the name the invitation
///                                           carried; otherwise empty
///   u32 LE(message_len)   || raw(message)   kind 1: their first message, which
///                                           may be empty; otherwise empty
/// ```
///
/// # Safety
/// `engine` must be valid. Free the result with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_engine_take_contact_events(engine: *mut VoidEngine) -> VoidBytes {
    if engine.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        VoidBytes::from_vec(encode_contact_events(&guard.take_contact_events()))
    })
}

fn encode_contact_events(events: &[void_client::engine::ContactEvent]) -> Vec<u8> {
    use void_client::engine::ContactEvent;
    let mut out = Vec::new();
    for event in events {
        match event {
            ContactEvent::Added {
                invite_id,
                contact_fingerprint,
                name,
                first_message,
            } => {
                out.push(1u8);
                out.extend_from_slice(invite_id);
                out.extend_from_slice(contact_fingerprint);
                // Contact names are bounded far below this; the clamp is so a
                // pathological one cannot make the length field lie.
                let name = &name.as_bytes()[..name.len().min(u16::MAX as usize)];
                out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                out.extend_from_slice(name);
                out.extend_from_slice(&(first_message.len() as u32).to_le_bytes());
                out.extend_from_slice(first_message.as_bytes());
            }
            ContactEvent::InviteExpired { invite_id } => {
                out.push(2u8);
                out.extend_from_slice(invite_id);
                out.extend_from_slice(&[0u8; 32]);
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
            }
            ContactEvent::InviteReady {
                fetch_id,
                inviter_label,
                inviter_fingerprint,
            } => {
                out.push(3u8);
                out.extend_from_slice(fetch_id);
                out.extend_from_slice(inviter_fingerprint);
                // Bounded by `MAX_LABEL_LEN` already; the clamp keeps the
                // length field honest regardless.
                let label = &inviter_label.as_bytes()[..inviter_label.len().min(u16::MAX as usize)];
                out.extend_from_slice(&(label.len() as u16).to_le_bytes());
                out.extend_from_slice(label);
                out.extend_from_slice(&0u32.to_le_bytes());
            }
            ContactEvent::InviteFailed { fetch_id, reason } => {
                out.push(match reason {
                    void_client::engine::InviteFailure::Expired => 4u8,
                    void_client::engine::InviteFailure::Invalid => 5u8,
                    void_client::engine::InviteFailure::TimedOut => 6u8,
                });
                out.extend_from_slice(fetch_id);
                out.extend_from_slice(&[0u8; 32]);
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
    }
    out
}

/// Open an invitation someone gave the user — scanned or pasted — and start
/// collecting it (FR-DISC-01). Nothing about the contact list changes yet.
///
/// Writes a 16-byte id to `out_fetch_id`. Watch [`void_engine_take_contact_events`]
/// for kind 3 (ready: show who it is from, then [`void_engine_confirm_invite`])
/// or kinds 4–6 (it could not be used). A full `void://c/` link is ready at
/// once; a short `void://i/` one is collected from the relay, normally within
/// one emission slot.
///
/// Returns `BadArgument` for something that is not a Void invitation,
/// `Expired`, `WrongRelay` for one parked on another relay, and `OwnInvite`
/// for the user's own. `now` is in seconds.
///
/// # Safety
/// `engine` must be valid, `link` a valid NUL-terminated UTF-8 string, and
/// `out_fetch_id` valid for 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_open_invite(
    engine: *mut VoidEngine,
    link: *const c_char,
    now: u64,
    out_fetch_id: *mut u8,
) -> VoidStatus {
    if engine.is_null() || link.is_null() || out_fetch_id.is_null() {
        return VoidStatus::BadArgument;
    }
    if !plausible_seconds(now) {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(link) = CStr::from_ptr(link).to_str() else {
            return VoidStatus::BadArgument;
        };
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.open_invite(link, now) {
            Ok(id) => {
                std::ptr::copy_nonoverlapping(id.as_ptr(), out_fetch_id, 16);
                VoidStatus::Ok
            }
            Err(e) => client_status(e),
        }
    })
}

/// Connect using an invitation reported ready. Writes the new contact's
/// fingerprint to `out_fingerprint`.
///
/// `local_name` may be empty, to use the name the invitation carried.
/// `first_message` may be empty, to connect without saying anything yet —
/// the other side shows nothing for it. `now` is in seconds.
///
/// Returns `AlreadyConnected` if this person is already a contact, `OwnInvite`
/// for the user's own invitation, and `Expired` if it expired while the user
/// was deciding.
///
/// # Safety
/// `engine` must be valid, `fetch_id` must point to 16 readable bytes,
/// `local_name` and `first_message` must be valid NUL-terminated UTF-8
/// strings, and `out_fingerprint` must be valid for 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_confirm_invite(
    engine: *mut VoidEngine,
    fetch_id: *const u8,
    local_name: *const c_char,
    first_message: *const c_char,
    now: u64,
    out_fingerprint: *mut u8,
) -> VoidStatus {
    if engine.is_null()
        || fetch_id.is_null()
        || local_name.is_null()
        || first_message.is_null()
        || out_fingerprint.is_null()
    {
        return VoidStatus::BadArgument;
    }
    if !plausible_seconds(now) {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let (Ok(local_name), Ok(first_message)) = (
            CStr::from_ptr(local_name).to_str(),
            CStr::from_ptr(first_message).to_str(),
        ) else {
            return VoidStatus::BadArgument;
        };
        let mut id: QueueId = [0u8; 16];
        std::ptr::copy_nonoverlapping(fetch_id, id.as_mut_ptr(), 16);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.confirm_invite(&id, local_name, first_message, now) {
            Ok(fingerprint) => {
                std::ptr::copy_nonoverlapping(fingerprint.as_ptr(), out_fingerprint, 32);
                VoidStatus::Ok
            }
            Err(e) => client_status(e),
        }
    })
}

/// Stop waiting for an invitation the user opened.
///
/// # Safety
/// `engine` must be valid and `fetch_id` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_cancel_fetch(
    engine: *mut VoidEngine,
    fetch_id: *const u8,
) -> VoidStatus {
    if engine.is_null() || fetch_id.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let mut id: QueueId = [0u8; 16];
        std::ptr::copy_nonoverlapping(fetch_id, id.as_mut_ptr(), 16);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        if guard.cancel_fetch(&id) {
            VoidStatus::Ok
        } else {
            VoidStatus::Failed
        }
    })
}

/// Where one of the user's own outstanding invitations stands: how many of
/// its records are still waiting to be parked on the relay (0 means whoever
/// opens it can collect it now), or -1 once it has been accepted, has
/// expired, or was cancelled.
///
/// # Safety
/// `engine` must be valid and `invite_id` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_invite_status(
    engine: *const VoidEngine,
    invite_id: *const u8,
) -> i32 {
    if engine.is_null() || invite_id.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let mut id: QueueId = [0u8; 16];
        std::ptr::copy_nonoverlapping(invite_id, id.as_mut_ptr(), 16);
        let Ok(guard) = (*engine).inner.lock() else {
            return -1;
        };
        match guard.invite_upload_remaining(&id) {
            Some(remaining) => i32::try_from(remaining).unwrap_or(i32::MAX),
            None => -1,
        }
    }))
    .unwrap_or(-1)
}

/// The link of one of the user's own outstanding invitations, so the app can
/// show its code again. Empty once it is no longer outstanding.
///
/// # Safety
/// `engine` must be valid and `invite_id` must point to 16 readable bytes.
/// Free the result with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_engine_invite_link(
    engine: *const VoidEngine,
    invite_id: *const u8,
) -> VoidBytes {
    if engine.is_null() || invite_id.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let mut id: QueueId = [0u8; 16];
        std::ptr::copy_nonoverlapping(invite_id, id.as_mut_ptr(), 16);
        let Ok(guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        match guard.invite_link(&id) {
            Some(link) => VoidBytes::from_vec(link.as_bytes().to_vec()),
            None => VoidBytes::empty(),
        }
    })
}

/// Change the name this device shows for a contact. Never transmitted.
///
/// # Safety
/// `engine` must be valid, `fingerprint` must point to 32 readable bytes, and
/// `name` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn void_engine_rename_contact(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
    name: *const c_char,
) -> VoidStatus {
    if engine.is_null() || fingerprint.is_null() || name.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(name) = CStr::from_ptr(name).to_str() else {
            return VoidStatus::BadArgument;
        };
        let mut fp = [0u8; 32];
        std::ptr::copy_nonoverlapping(fingerprint, fp.as_mut_ptr(), 32);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.rename_contact(&fp, name) {
            Ok(()) => VoidStatus::Ok,
            Err(e) => client_status(e),
        }
    })
}

/// The name the user puts on invitations they make (empty until they choose
/// one). Stored in the encrypted database, not the platform's preferences.
///
/// # Safety
/// `engine` must be valid. Free the result with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_engine_invite_name(engine: *const VoidEngine) -> VoidBytes {
    if engine.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let Ok(guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        VoidBytes::from_vec(guard.settings().invite_name.as_bytes().to_vec())
    })
}

/// Set the name the user puts on invitations they make.
///
/// # Safety
/// `engine` must be valid and `name` a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn void_engine_set_invite_name(
    engine: *mut VoidEngine,
    name: *const c_char,
) -> VoidStatus {
    if engine.is_null() || name.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(name) = CStr::from_ptr(name).to_str() else {
            return VoidStatus::BadArgument;
        };
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        guard.set_invite_name(name);
        VoidStatus::Ok
    })
}

/// Whether the user has been through the "what Void does and does not
/// protect" screen (FR-UI-05) on this device. Persisted, so onboarding is not
/// repeated at every launch.
///
/// # Safety
/// `engine` must be valid.
#[no_mangle]
pub unsafe extern "C" fn void_engine_protection_acknowledged(engine: *const VoidEngine) -> bool {
    if engine.is_null() {
        return false;
    }
    catch_unwind(AssertUnwindSafe(|| {
        (*engine)
            .inner
            .lock()
            .map(|g| g.settings().protection_screen_acknowledged)
            .unwrap_or(false)
    }))
    .unwrap_or(false)
}

/// Record that the user has been through the protection screen.
///
/// # Safety
/// `engine` must be valid.
#[no_mangle]
pub unsafe extern "C" fn void_engine_acknowledge_protection(engine: *mut VoidEngine) -> VoidStatus {
    if engine.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        let mut settings = guard.settings().clone();
        settings.protection_screen_acknowledged = true;
        guard.set_settings(settings);
        VoidStatus::Ok
    })
}

/// The status a failed engine call reports across the boundary.
fn client_status(e: void_client::ClientError) -> VoidStatus {
    use void_client::ClientError as E;
    match e {
        E::TorUnavailable => VoidStatus::Offline,
        E::ContactKeyChanged => VoidStatus::KeyChanged,
        E::Storage => VoidStatus::Locked,
        E::InviteExpired => VoidStatus::Expired,
        E::AlreadyConnected => VoidStatus::AlreadyConnected,
        E::OwnInvite => VoidStatus::OwnInvite,
        E::WrongRelay => VoidStatus::WrongRelay,
        E::InvalidInvite => VoidStatus::BadArgument,
        E::TooLarge => VoidStatus::TooLarge,
        _ => VoidStatus::Failed,
    }
}

/// Send a message. Queues it; transmission happens on the scheduler's own
/// timing (FR-MSG-06) via [`void_engine_tick`].
///
/// # Safety
/// `engine` must be valid. `fingerprint` must be valid for 32 bytes. `text`
/// must be a valid, NUL-terminated UTF-8 string. `out_message_id` must be a
/// valid output pointer.
#[no_mangle]
pub unsafe extern "C" fn void_engine_send(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
    text: *const c_char,
    now: u64,
    out_message_id: *mut u64,
) -> VoidStatus {
    if engine.is_null() || fingerprint.is_null() || text.is_null() || out_message_id.is_null() {
        return VoidStatus::BadArgument;
    }
    if !plausible_seconds(now) {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(text) = CStr::from_ptr(text).to_str() else {
            return VoidStatus::BadArgument;
        };
        let mut fp = [0u8; 32];
        std::ptr::copy_nonoverlapping(fingerprint, fp.as_mut_ptr(), 32);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.send(&fp, text, now) {
            Ok(id) => {
                *out_message_id = id;
                VoidStatus::Ok
            }
            Err(void_client::ClientError::ContactKeyChanged) => VoidStatus::KeyChanged,
            Err(void_client::ClientError::TorUnavailable) => VoidStatus::Offline,
            Err(_) => VoidStatus::Failed,
        }
    })
}

/// Send a file: a photo, a document, anything up to [`void_file_max_bytes`].
///
/// A file is a message (see `void_proto::content`): the same ratchet, the
/// same fixed-size records, one per emission slot, so the relay cannot tell a
/// photo from the same number of text messages. What it costs is time —
/// [`void_file_record_count`] records at [`void_pad_interval_ms`] each — and
/// the interface says so before sending. Its records go out behind every
/// queued message, so a reply typed while it leaves does not wait for it.
///
/// `name` and `mime` are UTF-8 and may be empty; at most 255 and 127 bytes.
/// A file over any bound is refused as [`VoidStatus::TooLarge`] before any
/// ratchet state is spent on it.
///
/// # Safety
/// `engine` must be valid. `fingerprint` must be valid for 32 bytes. `name`,
/// `mime` and `data` must each be valid for their length, or null with length
/// zero. `out_message_id` must be a valid output pointer.
#[no_mangle]
pub unsafe extern "C" fn void_engine_send_file(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
    name: *const u8,
    name_len: usize,
    mime: *const u8,
    mime_len: usize,
    data: *const u8,
    data_len: usize,
    now: u64,
    out_message_id: *mut u64,
) -> VoidStatus {
    if engine.is_null() || fingerprint.is_null() || out_message_id.is_null() {
        return VoidStatus::BadArgument;
    }
    if !plausible_seconds(now) {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let (Some(name), Some(mime), Some(data)) = (
            slice_from(name, name_len),
            slice_from(mime, mime_len),
            slice_from(data, data_len),
        ) else {
            return VoidStatus::BadArgument;
        };
        let (Ok(name), Ok(mime)) = (std::str::from_utf8(name), std::str::from_utf8(mime)) else {
            return VoidStatus::BadArgument;
        };
        // Bounded before it is copied, so a hostile length cannot ask for an
        // allocation the protocol would refuse anyway.
        if data.len() > void_proto::content::MAX_FILE_BYTES {
            return VoidStatus::TooLarge;
        }
        let mut fp = [0u8; 32];
        std::ptr::copy_nonoverlapping(fingerprint, fp.as_mut_ptr(), 32);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.send_file(&fp, name, mime, data.to_vec(), now) {
            Ok(id) => {
                *out_message_id = id;
                VoidStatus::Ok
            }
            Err(e) => client_status(e),
        }
    })
}

/// The largest file [`void_engine_send_file`] accepts, in bytes
/// (`void_proto::content::MAX_FILE_BYTES`).
#[no_mangle]
pub extern "C" fn void_file_max_bytes() -> usize {
    void_proto::content::MAX_FILE_BYTES
}

/// How many records a file of `data_len` bytes takes to send, at most. Times
/// [`void_pad_interval_ms`], that is the time to quote before sending.
#[no_mangle]
pub extern "C" fn void_file_record_count(data_len: usize) -> u16 {
    void_proto::content::file_record_count(data_len)
}

/// How often a connected client emits one record, in milliseconds
/// (`PAD_INTERVAL_MS`, FR-MSG-06). A protocol constant, the same for everyone.
#[no_mangle]
pub extern "C" fn void_pad_interval_ms() -> u64 {
    void_proto::record::PAD_INTERVAL_MS
}

/// What one [`void_engine_tick`] call did. Mirrors `void_client::engine::TickOutcome`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VoidTickOutcome {
    /// Nothing due yet.
    Waiting = 0,
    /// Cover traffic emitted.
    SentPadding = 1,
    /// A real record was deposited.
    Deposited = 2,
    /// The relay refused the deposit; it stays queued.
    Refused = 3,
    /// Records were collected — see `out_messages`.
    Retrieved = 4,
    /// The transport is unavailable (FR-TRANS-05: queued, not dropped).
    Offline = 5,
}

fn encode_received_messages(messages: &[void_client::engine::ReceivedMessage]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in messages {
        out.extend_from_slice(&m.contact_fingerprint);
        match &m.attachment {
            None => {
                out.push(1);
                out.extend_from_slice(&0u32.to_le_bytes());
                let text_bytes = m.text.as_bytes();
                out.extend_from_slice(&(text_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(text_bytes);
            }
            Some(file) => {
                out.push(3);
                out.extend_from_slice(&file.len.to_le_bytes());
                let name = file.name.as_bytes();
                out.extend_from_slice(&(name.len() as u32).to_le_bytes());
                out.extend_from_slice(name);
            }
        }
    }
    out
}

/// Advance the scheduler by one tick (FR-MSG-06). Call this on a regular
/// timer — every [`void_record_size`]-scale interval the platform's
/// background-execution budget allows — while the app can run.
///
/// `out_messages` is populated only when the returned outcome is `Retrieved`:
/// repeated `(fingerprint: 32 bytes, u8 kind, u32 LE size, u32 LE length,
/// bytes)`, where kind 1 is text — `size` is 0 and the bytes are the UTF-8
/// text — and kind 3 is a file: `size` is its size and the bytes are its
/// name. A file's bytes are in the history ([`void_engine_messages`],
/// [`void_engine_attachment`]). Otherwise it is left empty.
///
/// # Safety
/// `engine` must be valid. `out_outcome` and `out_messages` must be valid
/// output pointers.
#[no_mangle]
pub unsafe extern "C" fn void_engine_tick(
    engine: *mut VoidEngine,
    now_ms: u64,
    out_outcome: *mut VoidTickOutcome,
    out_messages: *mut VoidBytes,
) -> VoidStatus {
    if engine.is_null() || out_outcome.is_null() || out_messages.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        *out_messages = VoidBytes::empty();
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.tick(now_ms) {
            Ok(TickOutcome::Waiting(_)) => {
                *out_outcome = VoidTickOutcome::Waiting;
                VoidStatus::Ok
            }
            Ok(TickOutcome::SentPadding) => {
                *out_outcome = VoidTickOutcome::SentPadding;
                VoidStatus::Ok
            }
            Ok(TickOutcome::Deposited(_)) => {
                *out_outcome = VoidTickOutcome::Deposited;
                VoidStatus::Ok
            }
            Ok(TickOutcome::Refused(_)) => {
                *out_outcome = VoidTickOutcome::Refused;
                VoidStatus::Ok
            }
            Ok(TickOutcome::Retrieved(messages)) => {
                *out_outcome = VoidTickOutcome::Retrieved;
                *out_messages = VoidBytes::from_vec(encode_received_messages(&messages));
                VoidStatus::Ok
            }
            Ok(TickOutcome::Offline) => {
                *out_outcome = VoidTickOutcome::Offline;
                VoidStatus::Ok
            }
            Err(_) => {
                *out_outcome = VoidTickOutcome::Offline;
                VoidStatus::Offline
            }
        }
    })
}

/// The contact list, for the conversation list screen.
///
/// Encoding: repeated `(fingerprint: 32 bytes, trust: u8 — 0 unverified,
/// 1 verified, 2 key-changed, u16 LE name length, UTF-8 name)`.
///
/// # Safety
/// `engine` must be valid.
#[no_mangle]
pub unsafe extern "C" fn void_engine_contacts(engine: *const VoidEngine) -> VoidBytes {
    if engine.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let Ok(guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        let mut out = Vec::new();
        for c in guard.contacts() {
            out.extend_from_slice(&c.fingerprint());
            let trust_byte = match c.trust {
                void_store::model::TrustState::Unverified => 0u8,
                void_store::model::TrustState::Verified => 1u8,
                void_store::model::TrustState::KeyChanged => 2u8,
            };
            out.push(trust_byte);
            let name_bytes = c.local_name.as_bytes();
            out.extend_from_slice(&(name_bytes.len().min(u16::MAX as usize) as u16).to_le_bytes());
            out.extend_from_slice(&name_bytes[..name_bytes.len().min(u16::MAX as usize)]);
        }
        VoidBytes::from_vec(out)
    })
}

/// Mark a contact verified after comparing security codes (FR-DISC-04).
///
/// # Safety
/// `engine` must be valid. `fingerprint` must be valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_mark_verified(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
) -> VoidStatus {
    if engine.is_null() || fingerprint.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let mut fp = [0u8; 32];
        std::ptr::copy_nonoverlapping(fingerprint, fp.as_mut_ptr(), 32);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.mark_verified(&fp) {
            Ok(()) => VoidStatus::Ok,
            Err(_) => VoidStatus::Failed,
        }
    })
}

/// Acknowledge a contact's identity key change (FR-DISC-05). Unblocks
/// sending; drops back to unverified, never straight to verified.
///
/// # Safety
/// `engine` must be valid. `fingerprint` must be valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_acknowledge_key_change(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
) -> VoidStatus {
    if engine.is_null() || fingerprint.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let mut fp = [0u8; 32];
        std::ptr::copy_nonoverlapping(fingerprint, fp.as_mut_ptr(), 32);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.acknowledge_key_change(&fp) {
            Ok(()) => VoidStatus::Ok,
            Err(_) => VoidStatus::Failed,
        }
    })
}

/// Revoke a contact (FR-ABUSE-02).
///
/// # Safety
/// `engine` must be valid. `fingerprint` must be valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_revoke_contact(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
) -> VoidStatus {
    if engine.is_null() || fingerprint.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let mut fp = [0u8; 32];
        std::ptr::copy_nonoverlapping(fingerprint, fp.as_mut_ptr(), 32);
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.revoke_contact(&fp) {
            Ok(()) => VoidStatus::Ok,
            Err(_) => VoidStatus::Failed,
        }
    })
}

// --- identity and verification ----------------------------------------------

/// The local identity fingerprint, rendered as proquint words (FR-ID-03).
///
/// # Safety
/// `engine` must be valid.
#[no_mangle]
pub unsafe extern "C" fn void_fingerprint_words(engine: *const VoidEngine) -> VoidBytes {
    if engine.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let Ok(guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        VoidBytes::from_vec(fingerprint::to_words(&guard.fingerprint()).into_bytes())
    })
}

/// The local identity fingerprint, rendered as decimal groups.
///
/// # Safety
/// `engine` must be valid.
#[no_mangle]
pub unsafe extern "C" fn void_fingerprint_numbers(engine: *const VoidEngine) -> VoidBytes {
    if engine.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let Ok(guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        VoidBytes::from_vec(fingerprint::to_numbers(&guard.fingerprint()).into_bytes())
    })
}

/// Render an arbitrary 32-byte fingerprint as proquint words.
///
/// [`void_fingerprint_words`] only renders the local engine's own — this is
/// for a contact's, which the caller already holds as raw bytes from
/// [`void_engine_confirm_invite`], [`void_engine_take_contact_events`], or
/// [`void_engine_contacts`].
///
/// # Safety
/// `fingerprint` must be valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn void_fingerprint_render_words(fingerprint: *const u8) -> VoidBytes {
    if fingerprint.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let mut fp = [0u8; 32];
        std::ptr::copy_nonoverlapping(fingerprint, fp.as_mut_ptr(), 32);
        VoidBytes::from_vec(fingerprint::to_words(&fp).into_bytes())
    })
}

/// Compare a fingerprint the user typed or read aloud against a contact's.
///
/// Returns 1 on match, 0 on mismatch, negative on error. Comparison is constant
/// time and tolerant of formatting.
///
/// # Safety
/// Pointers must be valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn void_fingerprint_matches(
    expected: *const u8,
    expected_len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    let (Some(exp), Some(inp)) = (
        slice_from(expected, expected_len),
        slice_from(input, input_len),
    ) else {
        return -1;
    };
    if exp.len() != 32 {
        return -1;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(exp);
    let Ok(text) = std::str::from_utf8(inp) else {
        return -1;
    };
    catch_unwind(AssertUnwindSafe(|| {
        i32::from(fingerprint::verify_match(&fp, text))
    }))
    .unwrap_or(-1)
}

// --- required user-facing text ----------------------------------------------
//
// These strings are exported rather than duplicated in Swift and Kotlin so that
// the wording the PRD requires cannot drift between platforms. FR-STOR-04,
// FR-UI-04, FR-REC-01, and FR-REC-03 all specify text; a copy in three places
// is three chances for one of them to be softened.

/// The duress-destruction disclosure required by PRD §7.4.1.
#[no_mangle]
pub extern "C" fn void_text_duress_disclosure() -> VoidBytes {
    guard_bytes(|| VoidBytes::from_vec(DURESS_DISCLOSURE.as_bytes().to_vec()))
}

/// The confirmation phrase required by FR-UI-04.
#[no_mangle]
pub extern "C" fn void_text_duress_confirmation() -> VoidBytes {
    guard_bytes(|| VoidBytes::from_vec(DURESS_CONFIRMATION_PHRASE.as_bytes().to_vec()))
}

/// The device-loss warning required by FR-REC-01.
#[no_mangle]
pub extern "C" fn void_text_device_loss_warning() -> VoidBytes {
    guard_bytes(|| VoidBytes::from_vec(void_store::export::DEVICE_LOSS_WARNING.as_bytes().to_vec()))
}

/// The export storage warning required by FR-REC-03.
#[no_mangle]
pub extern "C" fn void_text_export_storage_warning() -> VoidBytes {
    guard_bytes(|| VoidBytes::from_vec(void_store::export::STORAGE_WARNING.as_bytes().to_vec()))
}

// --- platform hooks ----------------------------------------------------------

/// The platform's answer to "is this device's key storage hardware-backed?"
///
/// NFR-COMP-02 requires the difference between StrongBox and a software TEE be
/// surfaced in the UI rather than hidden, so the platform reports it here and
/// the UI renders `void_vault_backing_description`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VoidVaultBacking {
    /// iOS Secure Enclave.
    SecureEnclave = 0,
    /// Android StrongBox.
    StrongBox = 1,
    /// Android TEE without StrongBox. Weaker.
    Tee = 2,
    /// Software only. Not acceptable for a shipped client.
    Software = 3,
}

impl VoidVaultBacking {
    fn to_store(self) -> void_store::vault::VaultBacking {
        match self {
            VoidVaultBacking::SecureEnclave => void_store::vault::VaultBacking::SecureEnclave,
            VoidVaultBacking::StrongBox => void_store::vault::VaultBacking::StrongBox,
            VoidVaultBacking::Tee => void_store::vault::VaultBacking::TrustedExecutionEnvironment,
            VoidVaultBacking::Software => void_store::vault::VaultBacking::Software,
        }
    }
}

/// Plain-language description of what is protecting the keys.
#[no_mangle]
pub extern "C" fn void_vault_backing_description(backing: VoidVaultBacking) -> VoidBytes {
    guard_bytes(|| VoidBytes::from_vec(backing.to_store().user_description().as_bytes().to_vec()))
}

/// Byte-slice equality usable in a `const` assertion.
const fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The protocol version this build speaks.
#[no_mangle]
pub extern "C" fn void_protocol_version() -> u16 {
    void_proto::PROTOCOL_VERSION
}

/// The fixed record size, so the platform layer can size its buffers.
#[no_mangle]
pub extern "C" fn void_record_size() -> usize {
    void_proto::record::RECORD_SIZE
}

/// A C string naming this build's protocol identifier, for the about screen.
///
/// # Safety
/// The returned pointer is static and must not be freed.
#[no_mangle]
pub extern "C" fn void_protocol_id() -> *const c_char {
    // A static, NUL-terminated string checked at compile time. Nothing is
    // allocated and there is nothing for the caller to free.
    const ID: &CStr = c"void/v4/pqxdh/x25519+mlkem1024/ed25519+mldsa87";
    // A literal, because a static C string needs its NUL; checked against the
    // core's constant at compile time, so this copy cannot drift the way
    // PROTOCOL.md's and `PROTOCOL_VERSION` had.
    const _: () = assert!(bytes_equal(
        ID.to_bytes(),
        void_proto::handshake::PROTOCOL_ID
    ));
    ID.as_ptr()
}

// --- calls ---------------------------------------------------------------
//
// A call has two halves that cross this boundary separately, because they
// have nothing to do with each other. Signalling — place, answer, end, and
// the event queue — goes through the engine like any message. Media is a
// direct onion connection, and the platform pushes and pulls opaque audio
// frames through `VoidCallMedia`, which owns the encryption.
//
// The platform never sees a media key. It hands over encoded audio and gets
// encoded audio back; everything between those two points is this crate's
// problem. See `void_proto::call` and `void_tor::call` (D-024).
//
// ## Threads, and why these handles are reference-counted
//
// A call is used from several threads at once: one sends, one receives, and
// the UI thread hangs up. An earlier version gave both `send` and `recv` a
// `&mut` to the same struct with no lock — a data race — and freed it from the
// UI thread while the receiving thread could still be inside `recv`. Now:
//
// - the sending and receiving halves are separate, each behind its own lock,
//   so a receive blocked on the network never delays a send;
// - `void_call_media_close` and `void_call_host_cancel` wake a blocked
//   receive or accept within about a tenth of a second;
// - the handles are `Arc`s, and every call takes its own reference for its
//   duration, so a free racing an in-flight call leaves that call a live
//   object to finish with.
//
// The contract for the platform is still: close (or cancel), join the threads
// that use the handle, then free — and never start a call on a handle after
// freeing it.

/// A published onion service waiting for the callee to connect.
pub struct VoidCallHost {
    host: Mutex<Option<void_tor::call::CallHost>>,
    address: String,
    cancelled: std::sync::atomic::AtomicBool,
}

/// One call's media connection, with its encryption attached.
pub struct VoidCallMedia {
    sending: Mutex<(void_tor::call::MediaWriter, void_proto::call::MediaSealer)>,
    receiving: Mutex<(void_tor::call::MediaReader, void_proto::call::MediaOpener)>,
    closed: std::sync::atomic::AtomicBool,
}

impl VoidCallMedia {
    fn new(
        socket: void_tor::call::MediaSocket,
        secret: &[u8; 32],
        role: void_proto::call::Role,
        call_id: [u8; 16],
    ) -> VoidCallMedia {
        let (reader, writer) = socket.split();
        let (sealer, opener) = void_proto::call::MediaStream::new(secret, role, call_id).split();
        VoidCallMedia {
            sending: Mutex::new((writer, sealer)),
            receiving: Mutex::new((reader, opener)),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Take a counted reference to a handle the platform holds, so the object
/// outlives this call even if the platform frees its handle meanwhile.
///
/// # Safety
/// `ptr` must have come from `Arc::into_raw` and not yet have been freed.
unsafe fn retain<T>(ptr: *const T) -> std::sync::Arc<T> {
    std::sync::Arc::increment_strong_count(ptr);
    std::sync::Arc::from_raw(ptr)
}

/// Why a call ended, matching `void_proto::call::EndReason`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VoidCallEndReason {
    /// The user hung up.
    HungUp = 1,
    /// The user declined an incoming call.
    Declined = 2,
    /// Nobody answered in time.
    Missed = 3,
    /// The media connection failed or was lost.
    Failed = 4,
    /// The other end was already on a call.
    Busy = 5,
}

impl VoidCallEndReason {
    fn to_proto(self) -> void_proto::call::EndReason {
        use void_proto::call::EndReason as E;
        match self {
            VoidCallEndReason::HungUp => E::HungUp,
            VoidCallEndReason::Declined => E::Declined,
            VoidCallEndReason::Missed => E::Missed,
            VoidCallEndReason::Failed => E::Failed,
            VoidCallEndReason::Busy => E::Busy,
        }
    }

    fn from_proto(r: void_proto::call::EndReason) -> u8 {
        use void_proto::call::EndReason as E;
        match r {
            E::HungUp => 1,
            E::Declined => 2,
            E::Missed => 3,
            E::Failed => 4,
            E::Busy => 5,
        }
    }
}

/// What one [`void_call_media_recv`] produced.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VoidMediaRecv {
    /// An authenticated frame of audio, in the output buffer. Play it.
    Audio = 0,
    /// An authenticated frame of silence. Nothing to play — but it proves the
    /// other end is there, which is how the caller learns the call connected.
    Silence = 1,
    /// Nothing usable arrived: a two-second wait with no whole frame, or a
    /// frame that did not authenticate, or a replay. Play nothing. Many in a
    /// row mean the connection has stalled.
    Nothing = 2,
    /// The connection is gone, or the handle was closed. End the call.
    Closed = 3,
}

/// Publish an ephemeral onion service for an outgoing call.
///
/// Returns immediately, before the service is reachable — the descriptor
/// upload takes a few seconds and overlaps the peer's polling delay. Call
/// [`void_engine_place_call`] with the address as soon as this returns, and
/// [`void_call_host_accept`] on a background thread straight after that.
///
/// # Safety
/// `tor` must be valid. `key_dir` must be a valid, NUL-terminated UTF-8
/// string naming a directory this call may delete when it ends.
#[no_mangle]
pub unsafe extern "C" fn void_call_host_publish(
    tor: *const VoidTorHandle,
    key_dir: *const c_char,
    out: *mut *mut VoidCallHost,
) -> VoidStatus {
    if tor.is_null() || key_dir.is_null() || out.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(key_dir) = CStr::from_ptr(key_dir).to_str() else {
            return VoidStatus::BadArgument;
        };
        match (*tor)
            .inner
            .publish_call_service(std::path::Path::new(key_dir))
        {
            Ok(host) => {
                let address = String::from(host.onion_address());
                let handle = std::sync::Arc::new(VoidCallHost {
                    host: Mutex::new(Some(host)),
                    address,
                    cancelled: std::sync::atomic::AtomicBool::new(false),
                });
                *out = std::sync::Arc::into_raw(handle) as *mut VoidCallHost;
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Offline,
        }
    })
}

/// The onion address of a published call service, as UTF-8 bytes.
///
/// # Safety
/// `host` must be valid. Free the result with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_call_host_address(host: *const VoidCallHost) -> VoidBytes {
    if host.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let host = retain(host);
        VoidBytes::from_vec(host.address.as_bytes().to_vec())
    })
}

/// Block until the callee connects, then hand back the media connection.
///
/// Call it on a background thread as soon as the call is placed — not once an
/// answer has come back through the relay. The callee dials the moment they
/// answer, and their first authenticated frame is the answer (see
/// [`void_engine_mark_call_connected`]). Blocks for up to the caller's answer
/// window, or until [`void_call_host_cancel`]. Can succeed once per host.
///
/// # Safety
/// `host`, `media_secret` (32 bytes), `call_id` (16 bytes), and `out` must be
/// valid.
#[no_mangle]
pub unsafe extern "C" fn void_call_host_accept(
    host: *mut VoidCallHost,
    media_secret: *const u8,
    call_id: *const u8,
    out: *mut *mut VoidCallMedia,
) -> VoidStatus {
    if host.is_null() || media_secret.is_null() || call_id.is_null() || out.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let handle = retain(host as *const VoidCallHost);
        let Some(h) = handle.host.lock().ok().and_then(|mut slot| slot.take()) else {
            return VoidStatus::BadArgument;
        };
        let mut secret = [0u8; 32];
        secret.copy_from_slice(std::slice::from_raw_parts(media_secret, 32));
        let mut id = [0u8; 16];
        id.copy_from_slice(std::slice::from_raw_parts(call_id, 16));

        let status = match h.accept(&handle.cancelled) {
            Ok(socket) => {
                let media = VoidCallMedia::new(socket, &secret, void_proto::call::Role::Caller, id);
                *out = std::sync::Arc::into_raw(std::sync::Arc::new(media)) as *mut VoidCallMedia;
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Offline,
        };
        void_crypto::Zeroize::zeroize(&mut secret);
        status
    })
}

/// Stop waiting for the callee: a blocked [`void_call_host_accept`] returns
/// `Offline` within about a tenth of a second. The caller hung up while it
/// rang.
///
/// # Safety
/// `host` must be valid.
#[no_mangle]
pub unsafe extern "C" fn void_call_host_cancel(host: *const VoidCallHost) {
    if host.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        retain(host)
            .cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }));
}

/// Release a call host. Cancels a pending accept; the service is unpublished
/// and its keys deleted once nothing is using it.
///
/// # Safety
/// `host` must have come from [`void_call_host_publish`] and must not be used
/// after.
#[no_mangle]
pub unsafe extern "C" fn void_call_host_free(host: *mut VoidCallHost) {
    if host.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let handle = std::sync::Arc::from_raw(host as *const VoidCallHost);
        handle
            .cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        drop(handle);
    }));
}

/// Dial the caller's onion service to join a call (the callee side).
///
/// # Safety
/// `tor` must be valid. `onion_address` must be a valid, NUL-terminated UTF-8
/// string. `media_secret` is 32 bytes and `call_id` is 16.
#[no_mangle]
pub unsafe extern "C" fn void_call_media_connect(
    tor: *const VoidTorHandle,
    onion_address: *const c_char,
    port: u16,
    media_secret: *const u8,
    call_id: *const u8,
    out: *mut *mut VoidCallMedia,
) -> VoidStatus {
    if tor.is_null()
        || onion_address.is_null()
        || media_secret.is_null()
        || call_id.is_null()
        || out.is_null()
    {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(address) = CStr::from_ptr(onion_address).to_str() else {
            return VoidStatus::BadArgument;
        };
        let mut secret = [0u8; 32];
        secret.copy_from_slice(std::slice::from_raw_parts(media_secret, 32));
        let mut id = [0u8; 16];
        id.copy_from_slice(std::slice::from_raw_parts(call_id, 16));

        let status = match (*tor).inner.connect_call(address, port) {
            Ok(socket) => {
                let media = VoidCallMedia::new(socket, &secret, void_proto::call::Role::Callee, id);
                *out = std::sync::Arc::into_raw(std::sync::Arc::new(media)) as *mut VoidCallMedia;
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Offline,
        };
        void_crypto::Zeroize::zeroize(&mut secret);
        status
    })
}

/// Encrypt and send one encoded audio frame.
///
/// `audio` is whatever the platform's codec produced, at most
/// [`void_call_media_payload_len`] bytes. Passing a null pointer with zero
/// length sends a silence frame, which is what keeps the cadence constant
/// while nobody is speaking — see `void_proto::call` on why that matters.
///
/// `Ok` also covers a frame dropped because the circuit is backed up: queued
/// audio is only delay. `Offline` means the connection is gone.
///
/// Call it from one sending thread. It never waits on a receive.
///
/// # Safety
/// `media` must be valid. `audio` must point to `audio_len` readable bytes, or
/// be null when `audio_len` is zero.
#[no_mangle]
pub unsafe extern "C" fn void_call_media_send(
    media: *mut VoidCallMedia,
    audio: *const u8,
    audio_len: usize,
) -> VoidStatus {
    if media.is_null() || (audio.is_null() && audio_len != 0) {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let media = retain(media as *const VoidCallMedia);
        if media.is_closed() {
            return VoidStatus::Offline;
        }
        let frame_audio: &[u8] = if audio_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(audio, audio_len)
        };
        let Ok(mut sending) = media.sending.lock() else {
            return VoidStatus::Internal;
        };
        let (writer, sealer) = &mut *sending;
        let Ok(frame) = sealer.seal(frame_audio) else {
            return VoidStatus::BadArgument;
        };
        match writer.send_frame(&frame) {
            Ok(_sent_or_dropped) => VoidStatus::Ok,
            Err(_) => {
                media.close();
                VoidStatus::Offline
            }
        }
    })
}

/// Receive and decrypt one audio frame, waiting up to two seconds.
///
/// Writes audio to `out_audio` only for [`VoidMediaRecv::Audio`]; free it with
/// [`void_free_bytes`]. Returns [`VoidMediaRecv::Closed`] once the connection
/// is gone or [`void_call_media_close`] was called — end the call then.
///
/// Call it from one receiving thread. It never waits on a send.
///
/// # Safety
/// `media` must be valid and `out_audio` a valid output pointer.
#[no_mangle]
pub unsafe extern "C" fn void_call_media_recv(
    media: *mut VoidCallMedia,
    out_audio: *mut VoidBytes,
) -> VoidMediaRecv {
    if media.is_null() || out_audio.is_null() {
        return VoidMediaRecv::Closed;
    }
    *out_audio = VoidBytes::empty();
    catch_unwind(AssertUnwindSafe(|| {
        let media = retain(media as *const VoidCallMedia);
        let Ok(mut receiving) = media.receiving.lock() else {
            return VoidMediaRecv::Closed;
        };
        let (reader, opener) = &mut *receiving;
        match reader.recv_frame(&media.closed) {
            Ok(Some(frame)) => match opener.open(&frame) {
                Ok(audio) if audio.is_empty() => VoidMediaRecv::Silence,
                Ok(audio) => {
                    *out_audio = VoidBytes::from_vec(audio);
                    VoidMediaRecv::Audio
                }
                // A frame that does not authenticate, or a replay: play
                // nothing, keep listening.
                Err(_) => VoidMediaRecv::Nothing,
            },
            Ok(None) => VoidMediaRecv::Nothing,
            Err(_) => {
                media.close();
                VoidMediaRecv::Closed
            }
        }
    }))
    .unwrap_or(VoidMediaRecv::Closed)
}

/// Close a call's media connection: a blocked [`void_call_media_recv`] returns
/// `Closed` within about a tenth of a second, and later sends are refused.
/// Hang up with this, join the audio threads, then free.
///
/// # Safety
/// `media` must be valid.
#[no_mangle]
pub unsafe extern "C" fn void_call_media_close(media: *const VoidCallMedia) {
    if media.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        retain(media).close();
    }));
}

/// Release a call's media connection. Closes it first; the connection and its
/// keys are dropped once nothing is using them.
///
/// # Safety
/// `media` must have come from [`void_call_host_accept`] or
/// [`void_call_media_connect`] and must not be used after.
#[no_mangle]
pub unsafe extern "C" fn void_call_media_free(media: *mut VoidCallMedia) {
    if media.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let media = std::sync::Arc::from_raw(media as *const VoidCallMedia);
        media.close();
        drop(media);
    }));
}

/// Largest encoded audio frame one media frame can carry.
#[no_mangle]
pub extern "C" fn void_call_media_payload_len() -> usize {
    void_proto::call::MEDIA_PAYLOAD_LEN
}

/// How often the platform should emit a media frame, in milliseconds.
#[no_mangle]
pub extern "C" fn void_call_media_frame_ms() -> u64 {
    void_proto::call::MEDIA_FRAME_MS
}

/// The virtual port a call's onion service listens on.
#[no_mangle]
pub extern "C" fn void_call_port() -> u16 {
    void_tor::call::CALL_PORT
}

/// What the user must be told before a call connects, as UTF-8 bytes.
///
/// Comes from the core rather than being retyped in Swift and Kotlin, for the
/// same reason [`void_text_duress_disclosure`] does: two copies are two
/// chances for someone to soften it. See `void_proto::call::CALL_DISCLOSURE`,
/// including why it does not claim location exposure.
///
/// # Safety
/// Free the result with [`void_free_bytes`].
#[no_mangle]
pub extern "C" fn void_call_disclosure() -> VoidBytes {
    guard_bytes(|| VoidBytes::from_vec(void_proto::call::CALL_DISCLOSURE.as_bytes().to_vec()))
}

/// Place a call to a contact whose onion service is already publishing.
///
/// Writes the call id (16 bytes) and media secret (32 bytes) the platform
/// needs for [`void_call_host_accept`]. `now` is in seconds: the offer carries
/// it, so an offer that reaches the callee too late to be live is shown as
/// missed instead of ringing.
///
/// # Safety
/// `engine` must be valid. `fingerprint` must point to 32 readable bytes,
/// `onion_address` must be NUL-terminated UTF-8, and `out_call_id` /
/// `out_media_secret` must point to 16 and 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_place_call(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
    onion_address: *const c_char,
    port: u16,
    now: u64,
    out_call_id: *mut u8,
    out_media_secret: *mut u8,
) -> VoidStatus {
    if engine.is_null()
        || fingerprint.is_null()
        || onion_address.is_null()
        || out_call_id.is_null()
        || out_media_secret.is_null()
    {
        return VoidStatus::BadArgument;
    }
    if !plausible_seconds(now) {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(address) = CStr::from_ptr(onion_address).to_str() else {
            return VoidStatus::BadArgument;
        };
        let mut fp = [0u8; 32];
        fp.copy_from_slice(std::slice::from_raw_parts(fingerprint, 32));
        let Ok(mut engine_guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match engine_guard.place_call(&fp, address, port, now) {
            Ok(call) => {
                std::ptr::copy_nonoverlapping(call.call_id.as_ptr(), out_call_id, 16);
                std::ptr::copy_nonoverlapping(call.media_secret.as_ptr(), out_media_secret, 32);
                VoidStatus::Ok
            }
            Err(e) => client_status(e),
        }
    })
}

/// The caller's side has seen the callee's first authenticated media frame
/// ([`VoidMediaRecv::Audio`] or [`VoidMediaRecv::Silence`]): the call is
/// answered. Stops the ring timer without waiting for the relayed answer.
///
/// # Safety
/// `engine` must be valid and `fingerprint` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_mark_call_connected(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
) -> VoidStatus {
    if engine.is_null() || fingerprint.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let mut fp = [0u8; 32];
        fp.copy_from_slice(std::slice::from_raw_parts(fingerprint, 32));
        let Ok(mut engine_guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        if engine_guard.mark_call_connected(&fp) {
            VoidStatus::Ok
        } else {
            VoidStatus::Failed
        }
    })
}

/// Answer an incoming call, writing back what the media connection needs.
///
/// # Safety
/// As [`void_engine_place_call`], plus `out_address` receives the caller's
/// onion address as UTF-8 bytes to be freed with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_engine_answer_call(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
    out_call_id: *mut u8,
    out_media_secret: *mut u8,
    out_address: *mut VoidBytes,
    out_port: *mut u16,
) -> VoidStatus {
    if engine.is_null()
        || fingerprint.is_null()
        || out_call_id.is_null()
        || out_media_secret.is_null()
        || out_address.is_null()
        || out_port.is_null()
    {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let mut fp = [0u8; 32];
        fp.copy_from_slice(std::slice::from_raw_parts(fingerprint, 32));
        let Ok(mut engine_guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match engine_guard.answer_call(&fp) {
            Ok(call) => {
                std::ptr::copy_nonoverlapping(call.call_id.as_ptr(), out_call_id, 16);
                std::ptr::copy_nonoverlapping(call.media_secret.as_ptr(), out_media_secret, 32);
                *out_address = VoidBytes::from_vec(call.onion_address.as_bytes().to_vec());
                *out_port = call.port;
                VoidStatus::Ok
            }
            Err(e) => client_status(e),
        }
    })
}

/// End a call — hang up, decline, or report failure.
///
/// # Safety
/// `engine` must be valid and `fingerprint` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_end_call(
    engine: *mut VoidEngine,
    fingerprint: *const u8,
    reason: VoidCallEndReason,
) -> VoidStatus {
    if engine.is_null() || fingerprint.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let mut fp = [0u8; 32];
        fp.copy_from_slice(std::slice::from_raw_parts(fingerprint, 32));
        let Ok(mut engine_guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match engine_guard.end_call(&fp, reason.to_proto()) {
            Ok(()) => VoidStatus::Ok,
            Err(e) => client_status(e),
        }
    })
}

/// Drain everything that has happened to calls since the last drain.
///
/// Layout, repeated per event:
///
/// ```text
///   u8(kind)              1 = incoming, 2 = answered, 3 = ended, 4 = missed
///   raw(fingerprint : 32)
///   raw(call_id : 16)
///   u8(end_reason)        0 unless kind == 3
///   u32 LE(address_len)
///   raw(address)          empty unless kind == 1
///   u16 LE(port)          0 unless kind == 1
/// ```
///
/// "Missed" is a call that never rang here: it arrived too late to be live,
/// or this device was already on a call. Show it in the conversation.
///
/// The media secret is deliberately **not** in this encoding. It is fetched
/// separately by answering, so that a routine event poll never copies key
/// material into a platform-allocated buffer this crate cannot zeroize.
///
/// # Safety
/// `engine` must be valid. Free the result with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_engine_take_call_events(engine: *mut VoidEngine) -> VoidBytes {
    if engine.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let Ok(mut engine_guard) = (*engine).inner.lock() else {
            return VoidBytes::empty();
        };
        VoidBytes::from_vec(encode_call_events(&engine_guard.take_call_events()))
    })
}

fn encode_call_events(events: &[void_client::engine::CallEvent]) -> Vec<u8> {
    use void_client::engine::CallEvent;
    let mut out = Vec::new();
    for event in events {
        let (kind, peer, call_id, reason, address, port): (
            u8,
            &[u8; 32],
            &[u8; 16],
            u8,
            &[u8],
            u16,
        ) = match event {
            CallEvent::Incoming(call) => (
                1,
                &call.peer,
                &call.call_id,
                0,
                call.onion_address.as_bytes(),
                call.port,
            ),
            CallEvent::Answered(call) => (2, &call.peer, &call.call_id, 0, &[], 0),
            CallEvent::Ended {
                contact_fingerprint,
                call_id,
                reason,
            } => (
                3,
                contact_fingerprint,
                call_id,
                VoidCallEndReason::from_proto(*reason),
                &[],
                0,
            ),
            CallEvent::Missed {
                contact_fingerprint,
                call_id,
            } => (4, contact_fingerprint, call_id, 0, &[], 0),
        };
        out.push(kind);
        out.extend_from_slice(peer);
        out.extend_from_slice(call_id);
        out.push(reason);
        out.extend_from_slice(&(address.len() as u32).to_le_bytes());
        out.extend_from_slice(address);
        out.extend_from_slice(&port.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_lifecycle_does_not_leak_or_crash() {
        let mut engine: *mut VoidEngine = std::ptr::null_mut();
        unsafe {
            assert_eq!(void_engine_new(&mut engine), VoidStatus::Ok);
            assert!(!engine.is_null());
            void_engine_free(engine);
            // Freeing null must be a no-op, not a crash.
            void_engine_free(std::ptr::null_mut());
        }
    }

    /// A fresh data directory for one test, removed by the caller.
    fn temp_data_dir(label: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("void-ffi-open-test-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    unsafe fn open(dir: &std::path::Path, kek: &[u8; 32]) -> (VoidStatus, *mut VoidEngine) {
        let dir_c = std::ffi::CString::new(dir.to_str().unwrap()).unwrap();
        let mut engine: *mut VoidEngine = std::ptr::null_mut();
        let status = void_engine_open(
            dir_c.as_ptr(),
            kek.as_ptr(),
            VoidVaultBacking::Software,
            0,
            &mut engine,
        );
        (status, engine)
    }

    #[test]
    fn an_engine_opened_twice_with_the_same_key_keeps_its_identity() {
        // The apps used to call void_engine_new at every launch, so every
        // launch was a new identity and every contact was gone.
        let dir = temp_data_dir("same-key");
        let kek = [42u8; 32];
        unsafe {
            let (status, first) = open(&dir, &kek);
            assert_eq!(status, VoidStatus::Ok);
            let fingerprint = (*first).inner.lock().unwrap().fingerprint();
            assert!((*first).inner.lock().unwrap().is_persisted());
            void_engine_free(first);

            let (status, second) = open(&dir, &kek);
            assert_eq!(status, VoidStatus::Ok);
            assert_eq!(
                (*second).inner.lock().unwrap().fingerprint(),
                fingerprint,
                "reopening must restore the same identity, not generate a new one"
            );
            void_engine_free(second);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_key_reports_locked_and_replaces_nothing() {
        let dir = temp_data_dir("wrong-key");
        unsafe {
            let (status, first) = open(&dir, &[1u8; 32]);
            assert_eq!(status, VoidStatus::Ok);
            let fingerprint = (*first).inner.lock().unwrap().fingerprint();
            void_engine_free(first);

            let (status, engine) = open(&dir, &[2u8; 32]);
            assert_eq!(status, VoidStatus::Locked);
            assert!(engine.is_null());

            // Nothing was overwritten: the right key still opens the original.
            let (status, again) = open(&dir, &[1u8; 32]);
            assert_eq!(status, VoidStatus::Ok);
            assert_eq!((*again).inner.lock().unwrap().fingerprint(), fingerprint);
            void_engine_free(again);

            let mut out: *mut VoidEngine = std::ptr::null_mut();
            assert_eq!(
                void_engine_open(
                    std::ptr::null(),
                    [0u8; 32].as_ptr(),
                    VoidVaultBacking::Software,
                    0,
                    &mut out
                ),
                VoidStatus::BadArgument
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_message_encoding_matches_its_documented_layout() {
        use void_client::engine::HistoryEntry;
        use void_store::model::{Attachment, DeliveryState, Direction, StoredMessage};
        let encoded = encode_history(&[
            HistoryEntry {
                id: 11,
                message: StoredMessage::text(
                    [1u8; 32],
                    Direction::Outgoing,
                    1_700_000_000,
                    "sent",
                    DeliveryState::Deposited,
                ),
                fragments_remaining: 0,
            },
            HistoryEntry {
                id: 12,
                message: StoredMessage::text(
                    [1u8; 32],
                    Direction::Incoming,
                    1_700_000_060,
                    "got",
                    DeliveryState::Received,
                ),
                fragments_remaining: 0,
            },
            HistoryEntry {
                id: 13,
                message: StoredMessage {
                    contact_fingerprint: [1u8; 32],
                    direction: Direction::Outgoing,
                    timestamp: 1_700_000_120,
                    body: String::new(),
                    delivery: DeliveryState::Queued,
                    attachment: Some(Attachment {
                        name: "photo.jpg".to_string(),
                        mime: "image/jpeg".to_string(),
                        len: 123_456,
                        data: Vec::new(),
                    }),
                },
                fragments_remaining: 97,
            },
        ]);
        // Decode the way Swift and Kotlin do.
        let mut pos = 0;
        let mut decoded = Vec::new();
        while pos < encoded.len() {
            let id = u64::from_le_bytes(encoded[pos..pos + 8].try_into().unwrap());
            let direction = encoded[pos + 8];
            let delivery = encoded[pos + 9];
            let timestamp = u64::from_le_bytes(encoded[pos + 10..pos + 18].try_into().unwrap());
            let remaining = u16::from_le_bytes(encoded[pos + 18..pos + 20].try_into().unwrap());
            let len = u32::from_le_bytes(encoded[pos + 20..pos + 24].try_into().unwrap()) as usize;
            let text = std::str::from_utf8(&encoded[pos + 24..pos + 24 + len]).unwrap();
            pos += 24 + len;
            let has_file = encoded[pos];
            pos += 1;
            let file = if has_file == 1 {
                let n = u16::from_le_bytes(encoded[pos..pos + 2].try_into().unwrap()) as usize;
                let name = std::str::from_utf8(&encoded[pos + 2..pos + 2 + n]).unwrap();
                pos += 2 + n;
                let m = u16::from_le_bytes(encoded[pos..pos + 2].try_into().unwrap()) as usize;
                let mime = std::str::from_utf8(&encoded[pos + 2..pos + 2 + m]).unwrap();
                pos += 2 + m;
                let size = u32::from_le_bytes(encoded[pos..pos + 4].try_into().unwrap());
                pos += 4;
                Some((name.to_string(), mime.to_string(), size))
            } else {
                None
            };
            decoded.push((
                id,
                direction,
                delivery,
                timestamp,
                remaining,
                text.to_string(),
                file,
            ));
        }
        assert_eq!(
            decoded,
            vec![
                (11, 1, 1, 1_700_000_000, 0, "sent".to_string(), None),
                (12, 2, 4, 1_700_000_060, 0, "got".to_string(), None),
                (
                    13,
                    1,
                    0,
                    1_700_000_120,
                    97,
                    String::new(),
                    Some(("photo.jpg".to_string(), "image/jpeg".to_string(), 123_456)),
                ),
            ]
        );
    }

    #[test]
    fn a_file_sent_through_the_boundary_is_listed_and_fetched_by_id() {
        // Two in-memory engines cannot talk without a relay, so this checks
        // the boundary on the sender alone: a persisted engine sends a file,
        // its history lists the file without its bytes, and the bytes come
        // back by id. The core's end-to-end tests cover arrival.
        let dir = temp_data_dir("send-file");
        let kek = [77u8; 32];
        unsafe {
            let (status, engine) = open(&dir, &kek);
            assert_eq!(status, VoidStatus::Ok);
            // A contact to send to: a second, in-memory engine's bundle.
            let mut peer: *mut VoidEngine = std::ptr::null_mut();
            assert_eq!(void_engine_new(&mut peer), VoidStatus::Ok);
            let (bundle, _) = (*peer)
                .inner
                .lock()
                .unwrap()
                .create_bundle(b"relay.onion")
                .unwrap();
            let fp = (*engine)
                .inner
                .lock()
                .unwrap()
                .start_conversation(&bundle, "Peer", "", 1_700_000_000)
                .unwrap();

            let data = vec![5u8; 2_500];
            let mut id = 0u64;
            assert_eq!(
                void_engine_send_file(
                    engine,
                    fp.as_ptr(),
                    b"a.bin".as_ptr(),
                    5,
                    std::ptr::null(),
                    0,
                    data.as_ptr(),
                    data.len(),
                    1_700_000_000,
                    &mut id,
                ),
                VoidStatus::Ok
            );
            assert_ne!(id, 0);

            // Too large is refused at the boundary, with its own status.
            let huge = vec![0u8; void_file_max_bytes() + 1];
            assert_eq!(
                void_engine_send_file(
                    engine,
                    fp.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    huge.as_ptr(),
                    huge.len(),
                    1_700_000_000,
                    &mut id,
                ),
                VoidStatus::TooLarge
            );
            assert_eq!(
                void_file_record_count(huge.len()),
                void_proto::record::MAX_FRAGMENTS
            );
            assert_eq!(void_pad_interval_ms(), void_proto::record::PAD_INTERVAL_MS);

            let listed = void_engine_messages(engine, fp.as_ptr());
            let bytes = std::slice::from_raw_parts(listed.data, listed.len).to_vec();
            void_free_bytes(listed);
            // One message: the file. Its id is the first eight bytes.
            let record_id = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            assert_eq!(bytes[8], 1, "sent by us");
            assert_eq!(bytes[9], 0, "still queued");
            let remaining = u16::from_le_bytes(bytes[18..20].try_into().unwrap());
            assert!(
                remaining >= 3,
                "{remaining} records of a 2.5 KB file still to go"
            );
            assert_eq!(&bytes[20..24], &[0, 0, 0, 0], "no text");
            assert_eq!(bytes[24], 1, "has a file");
            assert_eq!(
                bytes.len(),
                25 + 2 + 5 + 2 + 4,
                "name, empty type, size, nothing else"
            );

            let fetched = void_engine_attachment(engine, record_id);
            assert_eq!(fetched.len, data.len());
            assert_eq!(
                std::slice::from_raw_parts(fetched.data, fetched.len),
                &data[..]
            );
            void_free_bytes(fetched);

            // The wrong id, or a null engine, gives nothing — not a crash.
            let none = void_engine_attachment(engine, record_id + 1_000);
            assert!(none.data.is_null() && none.len == 0);
            let none = void_engine_attachment(std::ptr::null(), record_id);
            assert!(none.data.is_null());

            void_engine_free(peer);
            void_engine_free(engine);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pin_verifier_classifies_unlock_duress_and_wrong() {
        let salt = b"a fixed test salt";
        let mut verifier: *mut VoidPinVerifier = std::ptr::null_mut();
        unsafe {
            assert_eq!(
                void_pin_verifier_new(
                    b"1234".as_ptr(),
                    4,
                    b"0000".as_ptr(),
                    4,
                    salt.as_ptr(),
                    salt.len(),
                    &mut verifier,
                ),
                VoidStatus::Ok
            );
            assert!(!verifier.is_null());

            assert_eq!(
                void_pin_check(verifier, b"1234".as_ptr(), 4),
                VoidPinOutcome::Unlock
            );
            assert_eq!(
                void_pin_check(verifier, b"0000".as_ptr(), 4),
                VoidPinOutcome::Duress
            );
            assert_eq!(
                void_pin_check(verifier, b"9999".as_ptr(), 4),
                VoidPinOutcome::Wrong
            );

            void_pin_verifier_free(verifier);
            void_pin_verifier_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn pin_verifier_without_a_duress_pin_never_reports_duress() {
        let salt = b"another test salt";
        let mut verifier: *mut VoidPinVerifier = std::ptr::null_mut();
        unsafe {
            assert_eq!(
                void_pin_verifier_new(
                    b"1234".as_ptr(),
                    4,
                    std::ptr::null(),
                    0,
                    salt.as_ptr(),
                    salt.len(),
                    &mut verifier,
                ),
                VoidStatus::Ok
            );
            assert_eq!(
                void_pin_check(verifier, b"anything".as_ptr(), 8),
                VoidPinOutcome::Wrong
            );
            void_pin_verifier_free(verifier);
        }
    }

    #[test]
    fn duress_destroy_wipes_the_engine_across_the_boundary() {
        let mut engine: *mut VoidEngine = std::ptr::null_mut();
        unsafe {
            assert_eq!(void_engine_new(&mut engine), VoidStatus::Ok);
            assert_eq!(void_engine_duress_destroy(engine), VoidStatus::Ok);
            assert!((*engine).inner.lock().unwrap().contacts().is_empty());
            // Safe to call again — idempotent, not a use-after-free trap.
            assert_eq!(void_engine_duress_destroy(engine), VoidStatus::Ok);
            void_engine_free(engine);

            assert_eq!(
                void_engine_duress_destroy(std::ptr::null_mut()),
                VoidStatus::BadArgument
            );
        }
    }

    #[test]
    fn null_arguments_produce_errors_not_crashes() {
        unsafe {
            assert_eq!(
                void_engine_new(std::ptr::null_mut()),
                VoidStatus::BadArgument
            );
            let b = void_fingerprint_words(std::ptr::null());
            assert!(b.data.is_null());
            assert_eq!(
                void_fingerprint_matches(std::ptr::null(), 5, std::ptr::null(), 5),
                -1
            );
            assert_eq!(
                void_tor_bootstrap(std::ptr::null(), std::ptr::null(), std::ptr::null_mut()),
                VoidStatus::BadArgument
            );
            assert_eq!(
                void_engine_attach_tor(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    443
                ),
                VoidStatus::BadArgument
            );
            // Freeing null must be a no-op, not a crash, same as every other
            // free function at this boundary.
            void_tor_free(std::ptr::null_mut());

            assert_eq!(
                void_engine_create_invite(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                VoidStatus::BadArgument
            );
            assert_eq!(
                void_engine_cancel_invite(std::ptr::null_mut(), std::ptr::null()),
                VoidStatus::BadArgument
            );
            assert!(void_engine_take_contact_events(std::ptr::null_mut())
                .data
                .is_null());
            assert_eq!(
                void_engine_send(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                ),
                VoidStatus::BadArgument
            );
            assert!(void_engine_contacts(std::ptr::null()).data.is_null());
            assert_eq!(
                void_engine_mark_verified(std::ptr::null_mut(), std::ptr::null()),
                VoidStatus::BadArgument
            );
        }
    }

    #[test]
    fn received_message_encoding_roundtrips() {
        use void_client::engine::{ReceivedAttachment, ReceivedMessage};
        let a = ReceivedMessage {
            contact_fingerprint: [7u8; 32],
            text: "hello".to_string(),
            attachment: None,
        };
        let b = ReceivedMessage {
            contact_fingerprint: [9u8; 32],
            text: "".to_string(),
            attachment: None,
        };
        let c = ReceivedMessage {
            contact_fingerprint: [11u8; 32],
            text: String::new(),
            attachment: Some(ReceivedAttachment {
                name: "photo.jpg".to_string(),
                mime: "image/jpeg".to_string(),
                len: 40_000,
            }),
        };
        let encoded = encode_received_messages(&[a, b, c]);

        // Manually decode, the way Swift will: fingerprint(32) || kind(u8)
        // || size(u32 LE) || len(u32 LE) || bytes.
        let mut pos = 0;
        let mut decoded = Vec::new();
        while pos < encoded.len() {
            let fp = &encoded[pos..pos + 32];
            pos += 32;
            let kind = encoded[pos];
            pos += 1;
            let size = u32::from_le_bytes(encoded[pos..pos + 4].try_into().unwrap());
            pos += 4;
            let len = u32::from_le_bytes(encoded[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let text = std::str::from_utf8(&encoded[pos..pos + len])
                .unwrap()
                .to_string();
            pos += len;
            decoded.push((fp.to_vec(), kind, size, text));
        }
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], (vec![7u8; 32], 1, 0, "hello".to_string()));
        assert_eq!(decoded[1], (vec![9u8; 32], 1, 0, String::new()));
        assert_eq!(
            decoded[2],
            (vec![11u8; 32], 3, 40_000, "photo.jpg".to_string())
        );
    }

    /// One decoded contact event: (kind, invite id, fingerprint, name, first
    /// message).
    type DecodedContactEvent = (u8, [u8; 16], [u8; 32], String, String);

    /// Decode [`void_engine_take_contact_events`]'s layout the way Swift and
    /// Kotlin do.
    fn decode_contact_events(b: &[u8]) -> Vec<DecodedContactEvent> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 1 + 16 + 32 + 2 <= b.len() {
            let kind = b[pos];
            let mut id = [0u8; 16];
            id.copy_from_slice(&b[pos + 1..pos + 17]);
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&b[pos + 17..pos + 49]);
            pos += 49;
            let name_len = u16::from_le_bytes([b[pos], b[pos + 1]]) as usize;
            pos += 2;
            let name = String::from_utf8(b[pos..pos + name_len].to_vec()).unwrap();
            pos += name_len;
            let msg_len = u32::from_le_bytes(b[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let msg = String::from_utf8(b[pos..pos + msg_len].to_vec()).unwrap();
            pos += msg_len;
            out.push((kind, id, fp, name, msg));
        }
        assert_eq!(pos, b.len(), "the layout must account for every byte");
        out
    }

    #[test]
    fn contact_event_encoding_matches_its_documented_layout() {
        use void_client::engine::ContactEvent;
        let encoded = encode_contact_events(&[
            ContactEvent::Added {
                invite_id: [1u8; 16],
                contact_fingerprint: [2u8; 32],
                name: "Ada".to_string(),
                first_message: "hi".to_string(),
            },
            ContactEvent::InviteExpired {
                invite_id: [3u8; 16],
            },
        ]);
        let decoded = decode_contact_events(&encoded);
        assert_eq!(
            decoded,
            vec![
                (1, [1u8; 16], [2u8; 32], "Ada".to_string(), "hi".to_string()),
                (2, [3u8; 16], [0u8; 32], String::new(), String::new()),
            ]
        );
    }

    #[test]
    fn a_full_conversation_works_end_to_end_across_the_ffi_boundary() {
        // Two real engines, wired to each other's transport by a shared
        // in-process relay — the same MemoryTransport void-client's own
        // integration tests use, attached directly to the private engine
        // field since void-ffi has no public "attach a test transport" hook
        // (only void_engine_attach_tor, which needs real Tor). Everything
        // from here on goes through the C ABI, exactly as Swift would call
        // it: invite creation, ticking both sides, draining contact events.
        //
        // Both engines tick on the same schedule throughout, as two phones
        // would, so the inviter is collecting while the handshake is still
        // arriving — the order the apps actually produce.
        use std::sync::{Arc, Mutex};
        use void_client::engine::{Engine, SecurityMode};
        use void_client::transport::MemoryTransport;
        use void_proto::identity::Identity;
        use void_relay::server::{NoPush, Relay};
        use void_relay::store::Config;

        let relay = Arc::new(Relay::new(Config::default(), Box::new(NoPush)));
        let clock = Arc::new(Mutex::new(1_000_000u64));

        // Built directly rather than through `void_engine_new`, which always
        // runs in `SecurityMode::Enforcing` and would refuse the in-memory
        // test transport below — the same reason void-client's own tests use
        // `InsecureForTesting`. Everything downstream of this still goes
        // through the real `unsafe extern "C" fn`s the boundary exposes.
        let alice_engine = Engine::new(
            Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[3u8; 32]),
            Settings::default(),
            Box::new(MemoryTransport::new(Arc::clone(&relay), Arc::clone(&clock))),
            SecurityMode::InsecureForTesting,
            0,
        )
        .unwrap();
        let bob_engine = Engine::new(
            Identity::from_seeds(&[4u8; 32], &[5u8; 32], &[6u8; 32]),
            Settings::default(),
            Box::new(MemoryTransport::new(Arc::clone(&relay), clock)),
            SecurityMode::InsecureForTesting,
            0,
        )
        .unwrap();
        let alice: *mut VoidEngine = Box::into_raw(Box::new(VoidEngine {
            inner: Mutex::new(alice_engine),
        }));
        let bob: *mut VoidEngine = Box::into_raw(Box::new(VoidEngine {
            inner: Mutex::new(bob_engine),
        }));

        unsafe {
            let now_secs = 1_000_000u64;
            let relay_hint = b"relay.onion";
            let my_label = b"Bob";
            let contact_label = b"Alice";
            let mut link = VoidBytes::empty();
            let mut invite_id = [0u8; 16];
            assert_eq!(
                void_engine_create_invite(
                    bob,
                    relay_hint.as_ptr(),
                    relay_hint.len(),
                    my_label.as_ptr(),
                    my_label.len(),
                    contact_label.as_ptr(),
                    contact_label.len(),
                    now_secs,
                    3600,
                    &mut link,
                    invite_id.as_mut_ptr(),
                ),
                VoidStatus::Ok
            );
            let link_str = std::str::from_utf8(std::slice::from_raw_parts(link.data, link.len))
                .unwrap()
                .to_string();
            void_free_bytes(link);

            assert!(link_str.len() < 150, "one QR code: {link_str}");
            let link_c = std::ffi::CString::new(link_str).unwrap();
            let mut fetch_id = [0u8; 16];
            assert_eq!(
                void_engine_open_invite(alice, link_c.as_ptr(), now_secs, fetch_id.as_mut_ptr()),
                VoidStatus::Ok
            );

            // Both phones tick: Bob parks the invitation, Alice collects it.
            let tick_both = |t_ms: u64| {
                for engine in [alice, bob] {
                    let mut outcome = VoidTickOutcome::Waiting;
                    let mut msgs = VoidBytes::empty();
                    assert_eq!(
                        void_engine_tick(engine, t_ms, &mut outcome, &mut msgs),
                        VoidStatus::Ok
                    );
                    void_free_bytes(msgs);
                }
            };
            let mut t_ms = now_secs * 1000;
            let mut ready = Vec::new();
            for _ in 0..200u64 {
                tick_both(t_ms);
                let events = void_engine_take_contact_events(alice);
                if events.len > 0 {
                    ready =
                        decode_contact_events(std::slice::from_raw_parts(events.data, events.len));
                }
                void_free_bytes(events);
                if !ready.is_empty() {
                    break;
                }
                t_ms += 5000;
            }
            assert_eq!(ready.len(), 1, "alice must be told the invitation is ready");
            let (kind, id, inviter_fp, inviter_label, _) = ready.remove(0);
            assert_eq!(kind, 3);
            assert_eq!(id, fetch_id);
            assert_eq!(inviter_label, "Bob");
            assert_eq!(inviter_fp, (*bob).inner.lock().unwrap().fingerprint());

            let empty_name = std::ffi::CString::new("").unwrap();
            let msg_c = std::ffi::CString::new("hello across the boundary").unwrap();
            let mut bob_fp = [0u8; 32];
            assert_eq!(
                void_engine_confirm_invite(
                    alice,
                    fetch_id.as_ptr(),
                    empty_name.as_ptr(),
                    msg_c.as_ptr(),
                    t_ms / 1000,
                    bob_fp.as_mut_ptr(),
                ),
                VoidStatus::Ok
            );
            // Confirming it a second time finds nothing: it was used.
            let mut again = [0u8; 32];
            assert_eq!(
                void_engine_confirm_invite(
                    alice,
                    fetch_id.as_ptr(),
                    empty_name.as_ptr(),
                    msg_c.as_ptr(),
                    t_ms / 1000,
                    again.as_mut_ptr(),
                ),
                VoidStatus::Failed
            );

            let mut added = Vec::new();
            for _ in 0..400u64 {
                for engine in [alice, bob] {
                    let mut outcome = VoidTickOutcome::Waiting;
                    let mut msgs = VoidBytes::empty();
                    assert_eq!(
                        void_engine_tick(engine, t_ms, &mut outcome, &mut msgs),
                        VoidStatus::Ok
                    );
                    void_free_bytes(msgs);
                }
                let events = void_engine_take_contact_events(bob);
                if events.len > 0 {
                    added =
                        decode_contact_events(std::slice::from_raw_parts(events.data, events.len));
                }
                void_free_bytes(events);
                if !added.is_empty() {
                    break;
                }
                t_ms += 5000;
            }
            assert_eq!(added.len(), 1, "bob must report exactly one new contact");
            let (kind, id, alice_fp, name, first) = added.remove(0);
            assert_eq!(kind, 1);
            assert_eq!(id, invite_id);
            assert_eq!(alice_fp, (*alice).inner.lock().unwrap().fingerprint());
            assert_eq!(bob_fp, inviter_fp);
            assert_eq!(name, "Alice");
            assert_eq!(first, "hello across the boundary");

            let contacts = void_engine_contacts(bob);
            assert!(contacts.len > 0, "bob must now have alice as a contact");
            void_free_bytes(contacts);

            // Consumed: cancelling it now finds nothing.
            assert_eq!(
                void_engine_cancel_invite(bob, invite_id.as_ptr()),
                VoidStatus::Failed
            );

            void_engine_free(alice);
            void_engine_free(bob);
        }
    }

    #[test]
    fn an_invitations_status_and_link_cross_the_boundary() {
        let relay = b"relay.onion:9443";
        let mut engine: *mut VoidEngine = std::ptr::null_mut();
        unsafe {
            assert_eq!(void_engine_new(&mut engine), VoidStatus::Ok);
            let mut link = VoidBytes::empty();
            let mut id = [0u8; 16];
            assert_eq!(
                void_engine_create_invite(
                    engine,
                    relay.as_ptr(),
                    relay.len(),
                    b"Bob".as_ptr(),
                    3,
                    std::ptr::null(),
                    0,
                    1_000,
                    86_400,
                    &mut link,
                    id.as_mut_ptr(),
                ),
                VoidStatus::Ok
            );
            let made = std::slice::from_raw_parts(link.data, link.len).to_vec();
            void_free_bytes(link);
            // Nothing is parked yet: this engine has no transport, so every
            // record of the invitation is still waiting to go out.
            assert!(void_engine_invite_status(engine, id.as_ptr()) > 0);
            let shown = void_engine_invite_link(engine, id.as_ptr());
            assert_eq!(std::slice::from_raw_parts(shown.data, shown.len), &made[..]);
            void_free_bytes(shown);

            assert_eq!(
                void_engine_cancel_invite(engine, id.as_ptr()),
                VoidStatus::Ok
            );
            assert_eq!(void_engine_invite_status(engine, id.as_ptr()), -1);
            assert!(void_engine_invite_link(engine, id.as_ptr()).data.is_null());

            // The name on invitations is stored with the rest of the settings.
            let name = std::ffi::CString::new("Bob").unwrap();
            assert_eq!(
                void_engine_set_invite_name(engine, name.as_ptr()),
                VoidStatus::Ok
            );
            let got = void_engine_invite_name(engine);
            assert_eq!(std::slice::from_raw_parts(got.data, got.len), b"Bob");
            void_free_bytes(got);
            assert!(!void_engine_protection_acknowledged(engine));
            assert_eq!(void_engine_acknowledge_protection(engine), VoidStatus::Ok);
            assert!(void_engine_protection_acknowledged(engine));
            void_engine_free(engine);
        }
    }

    #[test]
    fn call_handles_survive_being_freed_mid_call_and_refuse_null() {
        unsafe {
            // Null handles produce errors, never crashes, on every call entry.
            let mut out = VoidBytes::empty();
            assert_eq!(
                void_call_media_recv(std::ptr::null_mut(), &mut out),
                VoidMediaRecv::Closed
            );
            assert_eq!(
                void_call_media_send(std::ptr::null_mut(), std::ptr::null(), 0),
                VoidStatus::BadArgument
            );
            void_call_media_close(std::ptr::null());
            void_call_media_free(std::ptr::null_mut());
            void_call_host_cancel(std::ptr::null());
            void_call_host_free(std::ptr::null_mut());
            let mut media: *mut VoidCallMedia = std::ptr::null_mut();
            assert_eq!(
                void_call_host_accept(
                    std::ptr::null_mut(),
                    [0u8; 32].as_ptr(),
                    [0u8; 16].as_ptr(),
                    &mut media
                ),
                VoidStatus::BadArgument
            );
            assert_eq!(
                void_engine_mark_call_connected(std::ptr::null_mut(), [0u8; 32].as_ptr()),
                VoidStatus::BadArgument
            );
        }

        // The reference-counting contract, without a network: a handle freed
        // by one thread while another still holds a reference keeps the object
        // alive for the holder. `retain` is what every media entry point does
        // first.
        let host = std::sync::Arc::new(VoidCallHost {
            host: Mutex::new(None),
            address: String::from("x.onion"),
            cancelled: std::sync::atomic::AtomicBool::new(false),
        });
        let raw = std::sync::Arc::into_raw(host) as *mut VoidCallHost;
        unsafe {
            let held = retain(raw as *const VoidCallHost);
            void_call_host_cancel(raw);
            assert!(held.cancelled.load(std::sync::atomic::Ordering::SeqCst));
            void_call_host_free(raw);
            // Freed by the platform — still alive for the call in flight.
            assert_eq!(held.address, "x.onion");
            assert_eq!(std::sync::Arc::strong_count(&held), 1);
        }
    }

    #[test]
    fn a_call_handle_freed_while_many_threads_use_it_lives_until_the_last_one_is_done() {
        // What a call does to its handles: a sending thread, a receiving
        // thread, and the UI thread hanging up and freeing, all at once. Each
        // entry point takes its own reference first (`retain`), so the
        // platform's free must leave every in-flight use a live object, and the
        // object must be released exactly once, after the last of them.
        // Fewer under Miri, which checks every access and runs far slower.
        const THREADS: usize = if cfg!(miri) { 4 } else { 16 };
        const ROUNDS: usize = if cfg!(miri) { 10 } else { 2_000 };
        let host = std::sync::Arc::new(VoidCallHost {
            host: Mutex::new(None),
            address: String::from("x.onion"),
            cancelled: std::sync::atomic::AtomicBool::new(false),
        });
        let watch = std::sync::Arc::downgrade(&host);
        /// The handle as the platform holds it, carried to other threads the
        /// way a platform does — as a pointer, not an integer, so Miri can
        /// follow it.
        #[derive(Clone, Copy)]
        struct Handle(*const VoidCallHost);
        // Safety: the object behind it is shared by reference counting, which
        // is exactly what this test checks.
        unsafe impl Send for Handle {}
        let raw = Handle(std::sync::Arc::into_raw(host));
        let ready = std::sync::Arc::new(std::sync::Barrier::new(THREADS + 1));

        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let ready = std::sync::Arc::clone(&ready);
                std::thread::spawn(move || {
                    let raw = raw;
                    // In flight before the platform frees: this is the
                    // reference the entry point it is inside of would hold.
                    let held = unsafe { retain(raw.0) };
                    ready.wait();
                    for _ in 0..ROUNDS {
                        let again = std::sync::Arc::clone(&held);
                        assert_eq!(again.address, "x.onion");
                        again
                            .cancelled
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        // An accept on a host whose service is already taken
                        // refuses, and never blocks.
                        assert!(again.host.lock().unwrap().is_none());
                    }
                })
            })
            .collect();

        ready.wait();
        // The UI thread hangs up while every worker is mid-call.
        unsafe { void_call_host_free(raw.0.cast_mut()) };
        assert!(
            watch.upgrade().is_some() || workers.iter().all(|w| w.is_finished()),
            "freed while in use"
        );
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(
            watch.upgrade().is_none(),
            "released once the last user was done, and not leaked"
        );
    }

    #[test]
    fn call_events_encode_to_their_documented_layout() {
        use void_client::engine::CallEvent;
        let encoded = encode_call_events(&[
            CallEvent::Missed {
                contact_fingerprint: [7u8; 32],
                call_id: [9u8; 16],
            },
            CallEvent::Ended {
                contact_fingerprint: [1u8; 32],
                call_id: [2u8; 16],
                reason: void_proto::call::EndReason::Busy,
            },
        ]);
        // Every event without an address is exactly the fixed 56 bytes Swift
        // and Kotlin parse: kind, fingerprint, call id, reason, u32 address
        // length, u16 port.
        assert_eq!(encoded.len(), 2 * 56);
        let (missed, ended) = encoded.split_at(56);
        assert_eq!(missed[0], 4);
        assert_eq!(&missed[1..33], &[7u8; 32]);
        assert_eq!(&missed[33..49], &[9u8; 16]);
        assert_eq!(missed[49], 0);
        assert_eq!(ended[0], 3);
        assert_eq!(ended[49], 5, "busy");
        assert_eq!(&ended[50..56], &[0u8; 6]);
    }

    #[test]
    fn a_millisecond_timestamp_is_rejected_not_misread() {
        // The Android app passed milliseconds where seconds belong, and its
        // invitations expired 3.6 seconds after they were made. A value that
        // large is now refused at the boundary instead of misread.
        let now_ms = 1_759_000_000_000u64;
        let relay = b"relay.onion:9443";
        let mut engine: *mut VoidEngine = std::ptr::null_mut();
        unsafe {
            assert_eq!(void_engine_new(&mut engine), VoidStatus::Ok);
            let mut link = VoidBytes::empty();
            let mut id = [0u8; 16];
            assert_eq!(
                void_engine_create_invite(
                    engine,
                    relay.as_ptr(),
                    relay.len(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    now_ms,
                    86_400,
                    &mut link,
                    id.as_mut_ptr(),
                ),
                VoidStatus::BadArgument
            );
            assert!(link.data.is_null());

            // The same instant in seconds is fine.
            assert_eq!(
                void_engine_create_invite(
                    engine,
                    relay.as_ptr(),
                    relay.len(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    now_ms / 1000,
                    86_400,
                    &mut link,
                    id.as_mut_ptr(),
                ),
                VoidStatus::Ok
            );
            void_free_bytes(link);

            let fp = [0u8; 32];
            let text = std::ffi::CString::new("x").unwrap();
            let mut message_id = 0u64;
            assert_eq!(
                void_engine_send(engine, fp.as_ptr(), text.as_ptr(), now_ms, &mut message_id),
                VoidStatus::BadArgument
            );
            void_engine_free(engine);
        }
    }

    #[test]
    fn fingerprint_rendering_roundtrips_across_the_boundary() {
        let mut engine: *mut VoidEngine = std::ptr::null_mut();
        unsafe {
            assert_eq!(void_engine_new(&mut engine), VoidStatus::Ok);
            let words = void_fingerprint_words(engine);
            assert!(words.len > 0);
            let text = std::slice::from_raw_parts(words.data, words.len);
            let fp = (*engine).inner.lock().unwrap().fingerprint();

            assert_eq!(
                void_fingerprint_matches(fp.as_ptr(), 32, text.as_ptr(), text.len()),
                1
            );
            let wrong = b"lusab-babad-gutih-tugad";
            assert_eq!(
                void_fingerprint_matches(fp.as_ptr(), 32, wrong.as_ptr(), wrong.len()),
                0
            );

            void_free_bytes(words);
            void_engine_free(engine);
        }
    }

    #[test]
    fn required_text_crosses_the_boundary_intact() {
        // The reason these are exported at all: the wording must not drift
        // between Swift and Kotlin.
        unsafe {
            let cases: [(extern "C" fn() -> VoidBytes, &str); 3] = [
                (
                    void_text_duress_disclosure,
                    "does not give you something to show instead",
                ),
                (void_text_device_loss_warning, "permanently"),
                (void_text_export_storage_warning, "iCloud"),
            ];
            for (get, needle) in cases {
                let b = get();
                let s = std::str::from_utf8(std::slice::from_raw_parts(b.data, b.len)).unwrap();
                assert!(s.contains(needle), "missing {needle} in {s}");
                void_free_bytes(b);
            }
        }
    }

    #[test]
    fn vault_backing_descriptions_are_honest() {
        unsafe {
            let b = void_vault_backing_description(VoidVaultBacking::Tee);
            let s = std::str::from_utf8(std::slice::from_raw_parts(b.data, b.len)).unwrap();
            assert!(
                s.contains("weaker"),
                "the TEE fallback must be described as weaker"
            );
            void_free_bytes(b);
        }
    }

    #[test]
    fn constants_match_the_core() {
        assert_eq!(void_protocol_version(), void_proto::PROTOCOL_VERSION);
        assert_eq!(void_record_size(), void_proto::record::RECORD_SIZE);
    }

    #[test]
    fn freeing_an_empty_buffer_is_safe() {
        unsafe {
            void_free_bytes(VoidBytes::empty());
        }
    }
}
