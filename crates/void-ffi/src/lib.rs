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
use void_proto::handshake::PrekeyBundle;
use void_proto::identity::Identity;
use void_proto::invite::{self, Invite};
use void_proto::queue::QueueSecret;
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

/// Create an engine with a freshly generated identity.
///
/// Generation is entirely offline (FR-ID-04): no network round trip, no server
/// state, nothing to register.
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
        // `void_engine_attach_transport`; until then the engine has none and
        // every send queues, which is the correct fail-closed default.
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

/// Destroy an engine, zeroizing its secrets.
///
/// # Safety
/// `engine` must have come from [`void_engine_new`] and must not be used after.
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
            Ok(()) => VoidStatus::Ok,
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

/// An opaque handle to an introduction queue secret — what
/// [`void_engine_create_invite`] hands back alongside the invite link, and
/// what [`void_engine_poll_intro_queue`] and [`void_engine_accept_conversation`]
/// need to detect and accept whoever scans that invite.
pub struct VoidQueueSecret {
    inner: QueueSecret,
}

/// Free a queue secret handle.
///
/// # Safety
/// `queue` must have come from [`void_engine_create_invite`] and must not be
/// used after.
#[no_mangle]
pub unsafe extern "C" fn void_queue_secret_free(queue: *mut VoidQueueSecret) {
    if queue.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(queue));
    }));
}

/// Publish a prekey bundle as a shareable invite link (FR-DISC-01), and
/// return the queue handle needed to detect when someone accepts it.
///
/// `out_link` receives the `void://c/...` link — render it as a QR code or
/// share sheet text, both are the same string (FR-DISC-01's QR and link
/// paths are one code path, not two). `out_queue` receives the handle for
/// [`void_engine_poll_intro_queue`].
///
/// # Safety
/// `engine` must be valid. `relay_hint`/`label` must be valid for their
/// lengths (label may be null with length 0). `out_link` and `out_queue`
/// must be valid output pointers.
#[no_mangle]
pub unsafe extern "C" fn void_engine_create_invite(
    engine: *mut VoidEngine,
    relay_hint: *const u8,
    relay_hint_len: usize,
    label: *const u8,
    label_len: usize,
    now: u64,
    ttl_seconds: u64,
    out_link: *mut VoidBytes,
    out_queue: *mut *mut VoidQueueSecret,
) -> VoidStatus {
    if engine.is_null() || out_link.is_null() || out_queue.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let (Some(hint), Some(label_bytes)) = (
            slice_from(relay_hint, relay_hint_len),
            slice_from(label, label_len),
        ) else {
            return VoidStatus::BadArgument;
        };
        let Ok(label) = std::str::from_utf8(label_bytes) else {
            return VoidStatus::BadArgument;
        };
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        let Ok((bundle, queue)) = guard.create_bundle(hint) else {
            return VoidStatus::Failed;
        };
        let Ok(invite) = invite::create(&bundle, now, ttl_seconds, label) else {
            return VoidStatus::Failed;
        };
        *out_link = VoidBytes::from_vec(invite.to_link().into_bytes());
        *out_queue = Box::into_raw(Box::new(VoidQueueSecret { inner: queue }));
        VoidStatus::Ok
    })
}

/// Poll an introduction queue published via [`void_engine_create_invite`].
///
/// `out` is empty (`data` null, `len` 0) if nothing has arrived yet — that
/// is success, not failure; keep polling. When something has arrived, `out`
/// holds the raw bytes to pass to [`void_engine_accept_conversation`].
///
/// # Safety
/// `engine` and `queue` must be valid. `out` must be a valid output pointer.
#[no_mangle]
pub unsafe extern "C" fn void_engine_poll_intro_queue(
    engine: *mut VoidEngine,
    queue: *const VoidQueueSecret,
    out: *mut VoidBytes,
) -> VoidStatus {
    if engine.is_null() || queue.is_null() || out.is_null() {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.poll_intro_queue(&(*queue).inner) {
            Ok(Some(bytes)) => {
                *out = VoidBytes::from_vec(bytes);
                VoidStatus::Ok
            }
            Ok(None) => {
                *out = VoidBytes::empty();
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Offline,
        }
    })
}

/// Accept a conversation from bytes [`void_engine_poll_intro_queue`] returned
/// (the responder side).
///
/// `out_fingerprint` must point to a 32-byte buffer; `out_first_message`
/// receives the sender's first plaintext.
///
/// # Safety
/// `engine`, `queue`, and `initial` must be valid for their lengths.
/// `out_fingerprint` must be valid for 32 bytes. `out_first_message` must be
/// a valid output pointer.
#[no_mangle]
pub unsafe extern "C" fn void_engine_accept_conversation(
    engine: *mut VoidEngine,
    queue: *const VoidQueueSecret,
    initial: *const u8,
    initial_len: usize,
    now: u64,
    out_fingerprint: *mut u8,
    out_first_message: *mut VoidBytes,
) -> VoidStatus {
    if engine.is_null()
        || queue.is_null()
        || out_fingerprint.is_null()
        || out_first_message.is_null()
    {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let Some(initial_bytes) = slice_from(initial, initial_len) else {
            return VoidStatus::BadArgument;
        };
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        let queue_id = (*queue).inner.queue_id();
        match guard.accept_conversation(queue_id, initial_bytes, now) {
            Ok((fingerprint, text)) => {
                std::ptr::copy_nonoverlapping(fingerprint.as_ptr(), out_fingerprint, 32);
                *out_first_message = VoidBytes::from_vec(text.into_bytes());
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Failed,
        }
    })
}

/// Start a conversation from a scanned or pasted invite link (the initiator
/// side, FR-DISC-01).
///
/// `out_fingerprint` must point to a 32-byte buffer.
///
/// # Safety
/// `engine` must be valid. `link`, `local_name`, and `first_message` must be
/// valid, NUL-terminated UTF-8 strings. `out_fingerprint` must be valid for
/// 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn void_engine_start_conversation(
    engine: *mut VoidEngine,
    link: *const c_char,
    local_name: *const c_char,
    first_message: *const c_char,
    now: u64,
    out_fingerprint: *mut u8,
) -> VoidStatus {
    if engine.is_null()
        || link.is_null()
        || local_name.is_null()
        || first_message.is_null()
        || out_fingerprint.is_null()
    {
        return VoidStatus::BadArgument;
    }
    guard(|| {
        let (Ok(link), Ok(local_name), Ok(first_message)) = (
            CStr::from_ptr(link).to_str(),
            CStr::from_ptr(local_name).to_str(),
            CStr::from_ptr(first_message).to_str(),
        ) else {
            return VoidStatus::BadArgument;
        };
        let Ok(parsed) = Invite::from_link(link) else {
            return VoidStatus::BadArgument;
        };
        let Ok(body) = invite::open(&parsed, now) else {
            return VoidStatus::Failed;
        };
        let bundle: PrekeyBundle = body.bundle;
        let Ok(mut guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match guard.start_conversation(&bundle, local_name, first_message, now) {
            Ok(fingerprint) => {
                std::ptr::copy_nonoverlapping(fingerprint.as_ptr(), out_fingerprint, 32);
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Failed,
        }
    })
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
        let text_bytes = m.text.as_bytes();
        out.extend_from_slice(&(text_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(text_bytes);
    }
    out
}

/// Advance the scheduler by one tick (FR-MSG-06). Call this on a regular
/// timer — every [`void_record_size`]-scale interval the platform's
/// background-execution budget allows — while the app can run.
///
/// `out_messages` is populated only when the returned outcome is `Retrieved`:
/// repeated `(fingerprint: 32 bytes, u32 LE text length, UTF-8 text)`.
/// Otherwise it is left empty.
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
/// [`void_engine_start_conversation`], [`void_engine_accept_conversation`],
/// or [`void_engine_contacts`].
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

/// Plain-language description of what is protecting the keys.
#[no_mangle]
pub extern "C" fn void_vault_backing_description(backing: VoidVaultBacking) -> VoidBytes {
    guard_bytes(|| {
        let b = match backing {
            VoidVaultBacking::SecureEnclave => void_store::vault::VaultBacking::SecureEnclave,
            VoidVaultBacking::StrongBox => void_store::vault::VaultBacking::StrongBox,
            VoidVaultBacking::Tee => void_store::vault::VaultBacking::TrustedExecutionEnvironment,
            VoidVaultBacking::Software => void_store::vault::VaultBacking::Software,
        };
        VoidBytes::from_vec(b.user_description().as_bytes().to_vec())
    })
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
    const ID: &CStr = c"void/v2/pqxdh/x25519+mlkem1024/ed25519+mldsa87";
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

/// A published onion service waiting for the callee to connect.
pub struct VoidCallHost {
    inner: Option<void_tor::call::CallHost>,
}

/// One call's media connection, with its encryption attached.
pub struct VoidCallMedia {
    socket: void_tor::call::MediaSocket,
    stream: void_proto::call::MediaStream,
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
}

impl VoidCallEndReason {
    fn to_proto(self) -> void_proto::call::EndReason {
        use void_proto::call::EndReason as E;
        match self {
            VoidCallEndReason::HungUp => E::HungUp,
            VoidCallEndReason::Declined => E::Declined,
            VoidCallEndReason::Missed => E::Missed,
            VoidCallEndReason::Failed => E::Failed,
        }
    }

    fn from_proto(r: void_proto::call::EndReason) -> u8 {
        use void_proto::call::EndReason as E;
        match r {
            E::HungUp => 1,
            E::Declined => 2,
            E::Missed => 3,
            E::Failed => 4,
        }
    }
}

/// Publish an ephemeral onion service for an outgoing call.
///
/// Returns immediately, before the service is reachable — the descriptor
/// upload takes a few seconds and overlaps the peer's polling delay. Call
/// [`void_engine_place_call`] with the address as soon as this returns.
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
                *out = Box::into_raw(Box::new(VoidCallHost { inner: Some(host) }));
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
    guard_bytes(|| match (*host).inner.as_ref() {
        Some(h) => VoidBytes::from_vec(h.onion_address().as_bytes().to_vec()),
        None => VoidBytes::empty(),
    })
}

/// Block until the callee connects, then hand back the media connection.
///
/// Consumes the host: after this returns `Ok`, free the host handle. The
/// platform should call this on a background thread, because it blocks for up
/// to ninety seconds waiting for an answer.
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
        let Some(h) = (*host).inner.take() else {
            return VoidStatus::BadArgument;
        };
        let mut secret = [0u8; 32];
        secret.copy_from_slice(std::slice::from_raw_parts(media_secret, 32));
        let mut id = [0u8; 16];
        id.copy_from_slice(std::slice::from_raw_parts(call_id, 16));

        match h.accept() {
            Ok(socket) => {
                let stream =
                    void_proto::call::MediaStream::new(&secret, void_proto::call::Role::Caller, id);
                *out = Box::into_raw(Box::new(VoidCallMedia { socket, stream }));
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Offline,
        }
    })
}

/// Free a call host, unpublishing its service and deleting its keys.
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
        drop(Box::from_raw(host));
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

        match (*tor).inner.connect_call(address, port) {
            Ok(socket) => {
                let stream =
                    void_proto::call::MediaStream::new(&secret, void_proto::call::Role::Callee, id);
                *out = Box::into_raw(Box::new(VoidCallMedia { socket, stream }));
                VoidStatus::Ok
            }
            Err(_) => VoidStatus::Offline,
        }
    })
}

/// Encrypt and send one encoded audio frame.
///
/// `audio` is whatever the platform's codec produced, at most
/// [`void_call_media_payload_len`] bytes. Passing a null pointer with zero
/// length sends a silence frame, which is what keeps the cadence constant
/// while nobody is speaking — see `void_proto::call` on why that matters.
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
        let frame_audio: &[u8] = if audio_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(audio, audio_len)
        };
        let m = &mut *media;
        let Ok(frame) = m.stream.seal(frame_audio) else {
            return VoidStatus::BadArgument;
        };
        match m.socket.send_frame(&frame) {
            Ok(()) => VoidStatus::Ok,
            Err(_) => VoidStatus::Offline,
        }
    })
}

/// Receive and decrypt one audio frame.
///
/// Returns an empty buffer when the frame did not authenticate, was a replay,
/// or arrived out of order — all of which the caller should treat identically,
/// by playing nothing and moving on. An empty buffer is also what a silence
/// frame produces, which is the same thing to a speaker.
///
/// Blocks until a frame arrives or the call stalls, so call it on the audio
/// thread and not the UI thread.
///
/// # Safety
/// `media` must be valid. Free the result with [`void_free_bytes`].
#[no_mangle]
pub unsafe extern "C" fn void_call_media_recv(media: *mut VoidCallMedia) -> VoidBytes {
    if media.is_null() {
        return VoidBytes::empty();
    }
    guard_bytes(|| {
        let m = &mut *media;
        let Ok(frame) = m.socket.recv_frame() else {
            return VoidBytes::empty();
        };
        match m.stream.open(&frame) {
            Ok(audio) => VoidBytes::from_vec(audio),
            Err(_) => VoidBytes::empty(),
        }
    })
}

/// Close a call's media connection.
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
        drop(Box::from_raw(media));
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
/// needs to open the media connection once the peer answers.
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
    guard(|| {
        let Ok(address) = CStr::from_ptr(onion_address).to_str() else {
            return VoidStatus::BadArgument;
        };
        let mut fp = [0u8; 32];
        fp.copy_from_slice(std::slice::from_raw_parts(fingerprint, 32));
        let Ok(mut engine_guard) = (*engine).inner.lock() else {
            return VoidStatus::Internal;
        };
        match engine_guard.place_call(&fp, address, port) {
            Ok(call) => {
                std::ptr::copy_nonoverlapping(call.call_id.as_ptr(), out_call_id, 16);
                std::ptr::copy_nonoverlapping(call.media_secret.as_ptr(), out_media_secret, 32);
                VoidStatus::Ok
            }
            Err(void_client::ClientError::ContactKeyChanged) => VoidStatus::KeyChanged,
            Err(_) => VoidStatus::Failed,
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
            Err(void_client::ClientError::ContactKeyChanged) => VoidStatus::KeyChanged,
            Err(_) => VoidStatus::Failed,
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
            Err(_) => VoidStatus::Failed,
        }
    })
}

/// Drain everything that has happened to calls since the last drain.
///
/// Layout, repeated per event:
///
/// ```text
///   u8(kind)              1 = incoming, 2 = answered, 3 = ended
///   raw(fingerprint : 32)
///   raw(call_id : 16)
///   u8(end_reason)        0 unless kind == 3
///   u32 LE(address_len)
///   raw(address)          empty unless kind == 1
///   u16 LE(port)          0 unless kind == 1
/// ```
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
        let events = engine_guard.take_call_events();
        let mut out = Vec::new();
        for event in events {
            match event {
                void_client::engine::CallEvent::Incoming(call) => {
                    out.push(1u8);
                    out.extend_from_slice(&call.peer);
                    out.extend_from_slice(&call.call_id);
                    out.push(0);
                    let addr = call.onion_address.as_bytes();
                    out.extend_from_slice(&(addr.len() as u32).to_le_bytes());
                    out.extend_from_slice(addr);
                    out.extend_from_slice(&call.port.to_le_bytes());
                }
                void_client::engine::CallEvent::Answered(call) => {
                    out.push(2u8);
                    out.extend_from_slice(&call.peer);
                    out.extend_from_slice(&call.call_id);
                    out.push(0);
                    out.extend_from_slice(&0u32.to_le_bytes());
                    out.extend_from_slice(&0u16.to_le_bytes());
                }
                void_client::engine::CallEvent::Ended {
                    contact_fingerprint,
                    call_id,
                    reason,
                } => {
                    out.push(3u8);
                    out.extend_from_slice(&contact_fingerprint);
                    out.extend_from_slice(&call_id);
                    out.push(VoidCallEndReason::from_proto(reason));
                    out.extend_from_slice(&0u32.to_le_bytes());
                    out.extend_from_slice(&0u16.to_le_bytes());
                }
            }
        }
        VoidBytes::from_vec(out)
    })
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
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                VoidStatus::BadArgument
            );
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
            void_queue_secret_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn received_message_encoding_roundtrips() {
        let a = void_client::engine::ReceivedMessage {
            contact_fingerprint: [7u8; 32],
            text: "hello".to_string(),
        };
        let b = void_client::engine::ReceivedMessage {
            contact_fingerprint: [9u8; 32],
            text: "".to_string(),
        };
        let encoded = encode_received_messages(&[a, b]);

        // Manually decode, the way Swift will: fingerprint(32) || len(u32 LE) || text.
        let mut pos = 0;
        let mut decoded = Vec::new();
        while pos < encoded.len() {
            let fp = &encoded[pos..pos + 32];
            pos += 32;
            let len = u32::from_le_bytes(encoded[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let text = std::str::from_utf8(&encoded[pos..pos + len])
                .unwrap()
                .to_string();
            pos += len;
            decoded.push((fp.to_vec(), text));
        }
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], (vec![7u8; 32], "hello".to_string()));
        assert_eq!(decoded[1], (vec![9u8; 32], String::new()));
    }

    #[test]
    fn a_full_conversation_works_end_to_end_across_the_ffi_boundary() {
        // Two real engines, wired to each other's transport by a shared
        // in-process relay — the same MemoryTransport void-client's own
        // integration tests use, attached directly to the private engine
        // field since void-ffi has no public "attach a test transport" hook
        // (only void_engine_attach_tor, which needs real Tor). Everything
        // from here on goes through the C ABI, exactly as Swift would call
        // it: invite creation, polling, acceptance, sending, and ticking.
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
            let relay_hint = b"relay.onion";
            let mut link = VoidBytes::empty();
            let mut queue: *mut VoidQueueSecret = std::ptr::null_mut();
            assert_eq!(
                void_engine_create_invite(
                    bob,
                    relay_hint.as_ptr(),
                    relay_hint.len(),
                    std::ptr::null(),
                    0,
                    1_000_000,
                    3600,
                    &mut link,
                    &mut queue,
                ),
                VoidStatus::Ok
            );
            assert!(!queue.is_null());
            let link_str = std::str::from_utf8(std::slice::from_raw_parts(link.data, link.len))
                .unwrap()
                .to_string();
            void_free_bytes(link);

            let link_c = std::ffi::CString::new(link_str).unwrap();
            let name_c = std::ffi::CString::new("Bob").unwrap();
            let msg_c = std::ffi::CString::new("hello across the boundary").unwrap();
            let mut alice_fp = [0u8; 32];
            assert_eq!(
                void_engine_start_conversation(
                    alice,
                    link_c.as_ptr(),
                    name_c.as_ptr(),
                    msg_c.as_ptr(),
                    1_000_000,
                    alice_fp.as_mut_ptr(),
                ),
                VoidStatus::Ok
            );

            // Drain alice's outbox so the handshake actually reaches the relay.
            let mut t = 1_000_000u64;
            for _ in 0..40u64 {
                let mut outcome = VoidTickOutcome::Waiting;
                let mut msgs = VoidBytes::empty();
                void_engine_tick(alice, t, &mut outcome, &mut msgs);
                t += 5000;
                if (*alice).inner.lock().unwrap().outbox_len() == 0 {
                    break;
                }
            }
            // A few more ticks so the deposit definitely lands.
            for _ in 0..3u64 {
                let mut outcome = VoidTickOutcome::Waiting;
                let mut msgs = VoidBytes::empty();
                void_engine_tick(alice, t, &mut outcome, &mut msgs);
                t += 5000;
            }

            let mut initial = VoidBytes::empty();
            let mut got_it = false;
            for _ in 0..10 {
                assert_eq!(
                    void_engine_poll_intro_queue(bob, queue, &mut initial),
                    VoidStatus::Ok
                );
                if initial.len > 0 {
                    got_it = true;
                    break;
                }
            }
            assert!(got_it, "bob must receive the handshake");

            let mut bob_alice_fp = [0u8; 32];
            let mut first_message = VoidBytes::empty();
            assert_eq!(
                void_engine_accept_conversation(
                    bob,
                    queue,
                    initial.data,
                    initial.len,
                    1_000_000,
                    bob_alice_fp.as_mut_ptr(),
                    &mut first_message,
                ),
                VoidStatus::Ok
            );
            // `alice_fp` (from start_conversation) is bob's fingerprint as
            // alice sees it; `bob_alice_fp` (from accept_conversation) is
            // alice's fingerprint as bob sees it — two different identities.
            // What must actually match is bob's view of alice against
            // alice's own engine.
            assert_eq!(bob_alice_fp, (*alice).inner.lock().unwrap().fingerprint());
            let first_text = std::str::from_utf8(std::slice::from_raw_parts(
                first_message.data,
                first_message.len,
            ))
            .unwrap();
            assert_eq!(first_text, "hello across the boundary");
            void_free_bytes(first_message);
            void_free_bytes(initial);

            let contacts = void_engine_contacts(bob);
            assert!(contacts.len > 0, "bob must now have alice as a contact");
            void_free_bytes(contacts);

            void_queue_secret_free(queue);
            void_engine_free(alice);
            void_engine_free(bob);
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
