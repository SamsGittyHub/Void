//! # void-jni
//!
//! The JNI ABI the Kotlin client calls, mirroring `void-ffi`'s C ABI rather
//! than reimplementing it: every function here does JNI type conversion
//! (`jbyteArray`/`jstring`/`jlong` in, Kotlin objects out) and then calls
//! straight into a `void_ffi::void_*` function. The engine logic, error
//! mapping, and the `catch_unwind` discipline all already live at that layer
//! (see `void-ffi`'s module docs) — duplicating it here for JNI's sake would
//! be a second copy of the one thing NFR-SEC-02 asks to keep small and
//! reviewable.
//!
//! ## Why a second unsafe crate instead of extending void-ffi
//!
//! `void-ffi` is unsafe in exactly one shape: a caller pointer and a length.
//! JNI's unsafety is a different shape — `JNIEnv`, `jobject`, exceptions —
//! and mixing the two ABIs in one file would make neither boundary the "one
//! shape" NFR-SEC-02 asks for. `void-jni` depends on `void-ffi` as an
//! ordinary Rust library and never touches a `VoidEngine`'s fields directly;
//! it only ever holds the opaque pointers `void-ffi` hands back. See
//! `docs/DECISIONS.md`'s entry on this split.
//!
//! ## The rules this boundary follows
//!
//! Same three as void-ffi's: no panic crosses into the JVM (every entry
//! point is wrapped in `catch_unwind`), no secret is ever returned as a JVM
//! object title or log-visible value, and null/empty inputs produce a
//! sentinel result (0, an empty array, a null object) rather than a crash.

#![allow(clippy::missing_safety_doc)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::objects::{JByteArray, JClass, JIntArray, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use void_ffi::{
    VoidBytes, VoidEngine, VoidPinOutcome, VoidPinVerifier, VoidStatus, VoidTickOutcome,
    VoidTorHandle, VoidVaultBacking,
};

// --- small conversion helpers ------------------------------------------------

fn empty_bytes() -> VoidBytes {
    VoidBytes {
        data: std::ptr::null_mut(),
        len: 0,
    }
}

fn read_bytes(env: &mut JNIEnv, arr: &JByteArray) -> Vec<u8> {
    env.convert_byte_array(arr).unwrap_or_default()
}

fn read_string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s)
        .map(|j| j.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn new_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|j| j.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Converts and frees a `VoidBytes` the platform must treat as UTF-8 text.
unsafe fn bytes_to_jstring(env: &mut JNIEnv, bytes: VoidBytes) -> jstring {
    let text = if bytes.data.is_null() || bytes.len == 0 {
        String::new()
    } else {
        let slice = std::slice::from_raw_parts(bytes.data, bytes.len);
        String::from_utf8_lossy(slice).into_owned()
    };
    void_ffi::void_free_bytes(bytes);
    new_jstring(env, &text)
}

/// Converts and frees a `VoidBytes` the platform must treat as an opaque
/// buffer (a fingerprint, an encoded contact list, a wire record).
unsafe fn bytes_to_jbytearray(env: &mut JNIEnv, bytes: VoidBytes) -> jbyteArray {
    let slice: &[u8] = if bytes.data.is_null() || bytes.len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(bytes.data, bytes.len)
    };
    let out = env
        .byte_array_from_slice(slice)
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut());
    void_ffi::void_free_bytes(bytes);
    out
}

/// Runs `f`, converting any panic into `default`. Deliberately takes no
/// `JNIEnv` of its own — callers close over a `&mut JNIEnv` they already
/// hold, so this stays a plain `FnOnce() -> R` with no lifetime to thread
/// through, unlike an earlier version of this file that tried to pass `env`
/// through `guard` itself and fought the borrow checker for it.
fn guard<R>(default: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

fn find_and_new_object<'a>(
    env: &mut JNIEnv<'a>,
    class_name: &str,
    sig: &str,
    args: &[JValue],
) -> JObject<'a> {
    match env.find_class(class_name) {
        Ok(class) => env
            .new_object(class, sig, args)
            .unwrap_or_else(|_| JObject::null()),
        Err(_) => JObject::null(),
    }
}

// --- lifecycle ----------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineNew(_env: JNIEnv, _class: JClass) -> jlong {
    guard(0, || unsafe {
        let mut out: *mut VoidEngine = std::ptr::null_mut();
        if void_ffi::void_engine_new(&mut out) == VoidStatus::Ok {
            out as jlong
        } else {
            0
        }
    })
}

/// Opens this device's engine — restoring it, or creating it on first launch.
/// Returns the handle, or 0 on failure; `outStatus[0]` receives the
/// `VoidStatus` so Kotlin can tell `LOCKED` (wrong or destroyed key) from any
/// other failure. See `void_ffi::void_engine_open`.
///
/// The KEK is copied out of the JVM array and zeroized on this side after the
/// call; the Kotlin caller zeroizes its own array too (`ByteArray.fill(0)`).
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineOpen(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
    kek: JByteArray,
    backing: jint,
    now_ms: jlong,
    out_status: JIntArray,
) -> jlong {
    let env = &mut env;
    guard(0, || {
        let dir = read_string(env, &data_dir);
        let mut key = read_bytes(env, &kek);
        let status = if key.len() != 32 {
            (VoidStatus::BadArgument, 0)
        } else if let Ok(dir_c) = std::ffi::CString::new(dir) {
            let backing = match backing {
                0 => VoidVaultBacking::SecureEnclave,
                1 => VoidVaultBacking::StrongBox,
                2 => VoidVaultBacking::Tee,
                _ => VoidVaultBacking::Software,
            };
            let mut out: *mut VoidEngine = std::ptr::null_mut();
            let status = unsafe {
                void_ffi::void_engine_open(
                    dir_c.as_ptr(),
                    key.as_ptr(),
                    backing,
                    now_ms as u64,
                    &mut out,
                )
            };
            (
                status,
                if status == VoidStatus::Ok {
                    out as jlong
                } else {
                    0
                },
            )
        } else {
            (VoidStatus::BadArgument, 0)
        };
        for b in key.iter_mut() {
            *b = 0;
        }
        std::hint::black_box(&key);
        let _ = env.set_int_array_region(&out_status, 0, &[status.0 as jint]);
        status.1
    })
}

/// The stored history with one contact. Layout is documented on
/// `void_ffi::void_engine_messages`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_messages(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    fingerprint: JByteArray,
) -> jbyteArray {
    let env = &mut env;
    guard(std::ptr::null_mut(), || {
        let fp = read_bytes(env, &fingerprint);
        if engine_handle == 0 || fp.len() != 32 {
            return unsafe { bytes_to_jbytearray(env, empty_bytes()) };
        }
        unsafe {
            bytes_to_jbytearray(
                env,
                void_ffi::void_engine_messages(engine_handle as *const VoidEngine, fp.as_ptr()),
            )
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    guard((), || unsafe {
        void_ffi::void_engine_free(handle as *mut VoidEngine);
    })
}

// --- identity -------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_fingerprintWords(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        let bytes = void_ffi::void_fingerprint_words(handle as *const VoidEngine);
        bytes_to_jstring(env, bytes)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_fingerprintNumbers(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        let bytes = void_ffi::void_fingerprint_numbers(handle as *const VoidEngine);
        bytes_to_jstring(env, bytes)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_fingerprintRenderWords(
    mut env: JNIEnv,
    _class: JClass,
    fingerprint: JByteArray,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || {
        let fp = read_bytes(env, &fingerprint);
        if fp.len() != 32 {
            return std::ptr::null_mut();
        }
        unsafe {
            let bytes = void_ffi::void_fingerprint_render_words(fp.as_ptr());
            bytes_to_jstring(env, bytes)
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_fingerprintMatches(
    mut env: JNIEnv,
    _class: JClass,
    expected: JByteArray,
    input: JString,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let expected = read_bytes(env, &expected);
        let input = read_string(env, &input);
        let result = unsafe {
            void_ffi::void_fingerprint_matches(
                expected.as_ptr(),
                expected.len(),
                input.as_ptr(),
                input.len(),
            )
        };
        if result == 1 {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    })
}

// --- required user-facing text ---------------------------------------------

macro_rules! text_getter {
    ($jni_name:ident, $ffi_fn:path) => {
        #[no_mangle]
        pub extern "system" fn $jni_name(mut env: JNIEnv, _class: JClass) -> jstring {
            let env = &mut env;
            guard(std::ptr::null_mut(), || unsafe {
                bytes_to_jstring(env, $ffi_fn())
            })
        }
    };
}

text_getter!(
    Java_app_void_VoidCore_textDuressDisclosure,
    void_ffi::void_text_duress_disclosure
);
text_getter!(
    Java_app_void_VoidCore_textDuressConfirmation,
    void_ffi::void_text_duress_confirmation
);
text_getter!(
    Java_app_void_VoidCore_textDeviceLossWarning,
    void_ffi::void_text_device_loss_warning
);
text_getter!(
    Java_app_void_VoidCore_textCallDisclosure,
    void_ffi::void_call_disclosure
);
text_getter!(
    Java_app_void_VoidCore_textExportStorageWarning,
    void_ffi::void_text_export_storage_warning
);

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_vaultBackingDescription(
    mut env: JNIEnv,
    _class: JClass,
    backing: jint,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || {
        let backing = match backing {
            0 => VoidVaultBacking::SecureEnclave,
            1 => VoidVaultBacking::StrongBox,
            2 => VoidVaultBacking::Tee,
            _ => VoidVaultBacking::Software,
        };
        unsafe { bytes_to_jstring(env, void_ffi::void_vault_backing_description(backing)) }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_protocolId(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        let cstr = std::ffi::CStr::from_ptr(void_ffi::void_protocol_id());
        new_jstring(env, &cstr.to_string_lossy())
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_recordSize(_env: JNIEnv, _class: JClass) -> jint {
    void_ffi::void_record_size() as jint
}

// --- duress and the lock screen ---------------------------------------------

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_pinVerifierNew(
    mut env: JNIEnv,
    _class: JClass,
    unlock_pin: JByteArray,
    duress_pin: JByteArray,
    salt: JByteArray,
) -> jlong {
    let env = &mut env;
    guard(0, || {
        let unlock = read_bytes(env, &unlock_pin);
        let duress = read_bytes(env, &duress_pin);
        let salt = read_bytes(env, &salt);
        unsafe {
            let mut out: *mut VoidPinVerifier = std::ptr::null_mut();
            let (duress_ptr, duress_len) = if duress.is_empty() {
                (std::ptr::null(), 0)
            } else {
                (duress.as_ptr(), duress.len())
            };
            let status = void_ffi::void_pin_verifier_new(
                unlock.as_ptr(),
                unlock.len(),
                duress_ptr,
                duress_len,
                salt.as_ptr(),
                salt.len(),
                &mut out,
            );
            if status == VoidStatus::Ok {
                out as jlong
            } else {
                0
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_pinVerifierFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    guard((), || unsafe {
        void_ffi::void_pin_verifier_free(handle as *mut VoidPinVerifier);
    })
}

/// Matches `void_ffi::VoidPinOutcome`'s discriminants: 0 unlock, 1 duress, 2
/// wrong, 3 error. Kotlin's `PinOutcome` enum (added alongside this) mirrors
/// them the same way `VoidTickOutcome`/`TickResult` do.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_pinCheck(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pin: JByteArray,
) -> jint {
    let env = &mut env;
    guard(VoidPinOutcome::Error as jint, || {
        let pin = read_bytes(env, &pin);
        let outcome = unsafe {
            void_ffi::void_pin_check(handle as *const VoidPinVerifier, pin.as_ptr(), pin.len())
        };
        outcome as jint
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineDuressDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    guard(JNI_FALSE, || unsafe {
        if void_ffi::void_engine_duress_destroy(handle as *mut VoidEngine) == VoidStatus::Ok {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    })
}

// --- Tor ---------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_torBootstrap(
    mut env: JNIEnv,
    _class: JClass,
    state_dir: JString,
    cache_dir: JString,
) -> jlong {
    let env = &mut env;
    guard(0, || {
        let state_dir = read_string(env, &state_dir);
        let cache_dir = read_string(env, &cache_dir);
        let (Ok(state_c), Ok(cache_c)) = (
            std::ffi::CString::new(state_dir),
            std::ffi::CString::new(cache_dir),
        ) else {
            return 0;
        };
        unsafe {
            let mut out: *mut VoidTorHandle = std::ptr::null_mut();
            let status = void_ffi::void_tor_bootstrap(state_c.as_ptr(), cache_c.as_ptr(), &mut out);
            if status == VoidStatus::Ok {
                out as jlong
            } else {
                0
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_torFree(_env: JNIEnv, _class: JClass, handle: jlong) {
    guard((), || unsafe {
        void_ffi::void_tor_free(handle as *mut VoidTorHandle);
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineAttachTor(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    tor_handle: jlong,
    onion_address: JString,
    port: jint,
) -> jint {
    let env = &mut env;
    guard(VoidStatus::Internal as jint, || {
        let onion_address = read_string(env, &onion_address);
        let Ok(onion_c) = std::ffi::CString::new(onion_address) else {
            return VoidStatus::BadArgument as jint;
        };
        unsafe {
            void_ffi::void_engine_attach_tor(
                engine_handle as *mut VoidEngine,
                tor_handle as *const VoidTorHandle,
                onion_c.as_ptr(),
                port as u16,
            ) as jint
        }
    })
}

// --- conversations -------------------------------------------------------

/// `app.void.NativeInviteResult(link: String, inviteId: ByteArray)`.
///
/// `now` and `ttlSeconds` are in seconds. A millisecond value is refused by
/// void-ffi rather than misread — see `void_ffi`'s `MAX_PLAUSIBLE_UNIX_SECONDS`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_void_VoidCore_createInvite<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    engine_handle: jlong,
    relay_hint: JByteArray<'a>,
    my_label: JString<'a>,
    contact_label: JString<'a>,
    now: jlong,
    ttl_seconds: jlong,
) -> JObject<'a> {
    let env = &mut env;
    guard(JObject::null(), || {
        let hint = read_bytes(env, &relay_hint);
        let my_label = read_string(env, &my_label);
        let contact_label = read_string(env, &contact_label);
        unsafe {
            let mut out_link = empty_bytes();
            let mut out_id = [0u8; 16];
            let status = void_ffi::void_engine_create_invite(
                engine_handle as *mut VoidEngine,
                hint.as_ptr(),
                hint.len(),
                my_label.as_ptr(),
                my_label.len(),
                contact_label.as_ptr(),
                contact_label.len(),
                now as u64,
                ttl_seconds as u64,
                &mut out_link,
                out_id.as_mut_ptr(),
            );
            if status != VoidStatus::Ok {
                return JObject::null();
            }
            let link_jstring = bytes_to_jstring(env, out_link);
            let link_jobject = JObject::from_raw(link_jstring);
            let id_raw = env
                .byte_array_from_slice(&out_id)
                .map(|a| a.into_raw())
                .unwrap_or(std::ptr::null_mut());
            let id_jobject = JObject::from_raw(id_raw);
            find_and_new_object(
                env,
                "app/void/NativeInviteResult",
                "(Ljava/lang/String;[B)V",
                &[JValue::Object(&link_jobject), JValue::Object(&id_jobject)],
            )
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_cancelInvite(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    invite_id: JByteArray,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let id = read_bytes(env, &invite_id);
        if engine_handle == 0 || id.len() != 16 {
            return JNI_FALSE;
        }
        unsafe {
            if void_ffi::void_engine_cancel_invite(engine_handle as *mut VoidEngine, id.as_ptr())
                == VoidStatus::Ok
            {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }
    })
}

/// Drains contact events. Layout is documented on
/// `void_ffi::void_engine_take_contact_events`; Kotlin parses it in
/// `ContactEvent.parseAll`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_takeContactEvents(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
) -> jbyteArray {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        if engine_handle == 0 {
            return bytes_to_jbytearray(env, empty_bytes());
        }
        bytes_to_jbytearray(
            env,
            void_ffi::void_engine_take_contact_events(engine_handle as *mut VoidEngine),
        )
    })
}

/// `app.void.NativeOpenResult(status: Int, fetchId: ByteArray)`.
///
/// `fetchId` is empty unless `status` is `VoidStatus::Ok`. See
/// `void_ffi::void_engine_open_invite`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_openInvite<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    engine_handle: jlong,
    link: JString<'a>,
    now: jlong,
) -> JObject<'a> {
    let env = &mut env;
    guard(JObject::null(), || {
        let link = read_string(env, &link);
        let Ok(link_c) = std::ffi::CString::new(link) else {
            return status_with_bytes(
                env,
                "app/void/NativeOpenResult",
                VoidStatus::BadArgument,
                &[],
            );
        };
        let mut out_id = [0u8; 16];
        let status = unsafe {
            void_ffi::void_engine_open_invite(
                engine_handle as *mut VoidEngine,
                link_c.as_ptr(),
                now as u64,
                out_id.as_mut_ptr(),
            )
        };
        let id: &[u8] = if status == VoidStatus::Ok {
            &out_id
        } else {
            &[]
        };
        status_with_bytes(env, "app/void/NativeOpenResult", status, id)
    })
}

/// `app.void.NativeStartResult(status: Int, fingerprint: ByteArray)`.
///
/// The status is passed through rather than collapsed to null, so Kotlin can
/// say the invitation expired, or that they are already connected, instead of
/// "something went wrong". See `void_ffi::void_engine_confirm_invite`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_confirmInvite<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    engine_handle: jlong,
    fetch_id: JByteArray<'a>,
    local_name: JString<'a>,
    first_message: JString<'a>,
    now: jlong,
) -> JObject<'a> {
    let env = &mut env;
    guard(JObject::null(), || {
        let id = read_bytes(env, &fetch_id);
        let local_name = read_string(env, &local_name);
        let first_message = read_string(env, &first_message);
        let (Ok(name_c), Ok(msg_c)) = (
            std::ffi::CString::new(local_name),
            std::ffi::CString::new(first_message),
        ) else {
            return status_with_bytes(
                env,
                "app/void/NativeStartResult",
                VoidStatus::BadArgument,
                &[],
            );
        };
        if id.len() != 16 {
            return status_with_bytes(
                env,
                "app/void/NativeStartResult",
                VoidStatus::BadArgument,
                &[],
            );
        }
        let mut out_fp = [0u8; 32];
        let status = unsafe {
            void_ffi::void_engine_confirm_invite(
                engine_handle as *mut VoidEngine,
                id.as_ptr(),
                name_c.as_ptr(),
                msg_c.as_ptr(),
                now as u64,
                out_fp.as_mut_ptr(),
            )
        };
        let fingerprint: &[u8] = if status == VoidStatus::Ok {
            &out_fp
        } else {
            &[]
        };
        status_with_bytes(env, "app/void/NativeStartResult", status, fingerprint)
    })
}

/// Builds one of the `(status: Int, bytes: ByteArray)` result classes.
fn status_with_bytes<'a>(
    env: &mut JNIEnv<'a>,
    class: &str,
    status: VoidStatus,
    bytes: &[u8],
) -> JObject<'a> {
    let raw = env
        .byte_array_from_slice(bytes)
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut());
    // Safety: `raw` is either null or a local reference just created above.
    let array = unsafe { JObject::from_raw(raw) };
    find_and_new_object(
        env,
        class,
        "(I[B)V",
        &[JValue::Int(status as jint), JValue::Object(&array)],
    )
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_cancelFetch(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    fetch_id: JByteArray,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let id = read_bytes(env, &fetch_id);
        if engine_handle == 0 || id.len() != 16 {
            return JNI_FALSE;
        }
        let status = unsafe {
            void_ffi::void_engine_cancel_fetch(engine_handle as *mut VoidEngine, id.as_ptr())
        };
        if status == VoidStatus::Ok {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    })
}

/// Records still to upload for one of our invitations, or -1 once it is no
/// longer outstanding. See `void_ffi::void_engine_invite_status`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_inviteStatus(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    invite_id: JByteArray,
) -> jint {
    let env = &mut env;
    guard(-1, || {
        let id = read_bytes(env, &invite_id);
        if engine_handle == 0 || id.len() != 16 {
            return -1;
        }
        unsafe {
            void_ffi::void_engine_invite_status(engine_handle as *const VoidEngine, id.as_ptr())
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_inviteLink(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    invite_id: JByteArray,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || {
        let id = read_bytes(env, &invite_id);
        if engine_handle == 0 || id.len() != 16 {
            return new_jstring(env, "");
        }
        unsafe {
            let bytes =
                void_ffi::void_engine_invite_link(engine_handle as *const VoidEngine, id.as_ptr());
            bytes_to_jstring(env, bytes)
        }
    })
}

/// Returns the `VoidStatus` ordinal.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_renameContact(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    fingerprint: JByteArray,
    name: JString,
) -> jint {
    let env = &mut env;
    guard(VoidStatus::Internal as jint, || {
        let fp = read_bytes(env, &fingerprint);
        let name = read_string(env, &name);
        if engine_handle == 0 || fp.len() != 32 {
            return VoidStatus::BadArgument as jint;
        }
        let Ok(name_c) = std::ffi::CString::new(name) else {
            return VoidStatus::BadArgument as jint;
        };
        unsafe {
            void_ffi::void_engine_rename_contact(
                engine_handle as *mut VoidEngine,
                fp.as_ptr(),
                name_c.as_ptr(),
            ) as jint
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_inviteName(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        if engine_handle == 0 {
            return new_jstring(env, "");
        }
        bytes_to_jstring(
            env,
            void_ffi::void_engine_invite_name(engine_handle as *const VoidEngine),
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_setInviteName(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    name: JString,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let name = read_string(env, &name);
        let Ok(name_c) = std::ffi::CString::new(name) else {
            return JNI_FALSE;
        };
        if engine_handle == 0 {
            return JNI_FALSE;
        }
        let status = unsafe {
            void_ffi::void_engine_set_invite_name(engine_handle as *mut VoidEngine, name_c.as_ptr())
        };
        if status == VoidStatus::Ok {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_protectionAcknowledged(
    _env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
) -> jboolean {
    guard(JNI_FALSE, || unsafe {
        if engine_handle != 0
            && void_ffi::void_engine_protection_acknowledged(engine_handle as *const VoidEngine)
        {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_acknowledgeProtection(
    _env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
) -> jboolean {
    guard(JNI_FALSE, || unsafe {
        if engine_handle != 0
            && void_ffi::void_engine_acknowledge_protection(engine_handle as *mut VoidEngine)
                == VoidStatus::Ok
        {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    })
}

/// `app.void.NativeSendResult(status: Int, messageId: Long)`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_send<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    engine_handle: jlong,
    fingerprint: JByteArray<'a>,
    text: JString<'a>,
    now: jlong,
) -> JObject<'a> {
    let env = &mut env;
    guard(JObject::null(), || {
        let fp = read_bytes(env, &fingerprint);
        let text = read_string(env, &text);
        if fp.len() != 32 {
            return find_and_new_object(
                env,
                "app/void/NativeSendResult",
                "(IJ)V",
                &[
                    JValue::Int(VoidStatus::BadArgument as jint),
                    JValue::Long(0),
                ],
            );
        }
        let Ok(text_c) = std::ffi::CString::new(text) else {
            return find_and_new_object(
                env,
                "app/void/NativeSendResult",
                "(IJ)V",
                &[
                    JValue::Int(VoidStatus::BadArgument as jint),
                    JValue::Long(0),
                ],
            );
        };
        let mut out_id: u64 = 0;
        let status = unsafe {
            void_ffi::void_engine_send(
                engine_handle as *mut VoidEngine,
                fp.as_ptr(),
                text_c.as_ptr(),
                now as u64,
                &mut out_id,
            )
        };
        find_and_new_object(
            env,
            "app/void/NativeSendResult",
            "(IJ)V",
            &[JValue::Int(status as jint), JValue::Long(out_id as jlong)],
        )
    })
}

/// `app.void.NativeTickResult(outcome: Int, messages: ByteArray)`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_tick<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    engine_handle: jlong,
    now_ms: jlong,
) -> JObject<'a> {
    let env = &mut env;
    guard(JObject::null(), || unsafe {
        let mut outcome = VoidTickOutcome::Waiting;
        let mut messages = empty_bytes();
        void_ffi::void_engine_tick(
            engine_handle as *mut VoidEngine,
            now_ms as u64,
            &mut outcome,
            &mut messages,
        );
        let msgs_raw = bytes_to_jbytearray(env, messages);
        let msgs_jobject = JObject::from_raw(msgs_raw);
        find_and_new_object(
            env,
            "app/void/NativeTickResult",
            "(I[B)V",
            &[JValue::Int(outcome as jint), JValue::Object(&msgs_jobject)],
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_contacts(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
) -> jbyteArray {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        let bytes = void_ffi::void_engine_contacts(engine_handle as *const VoidEngine);
        bytes_to_jbytearray(env, bytes)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_markVerified(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    fingerprint: JByteArray,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let fp = read_bytes(env, &fingerprint);
        if fp.len() != 32 {
            return JNI_FALSE;
        }
        unsafe {
            if void_ffi::void_engine_mark_verified(engine_handle as *mut VoidEngine, fp.as_ptr())
                == VoidStatus::Ok
            {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_acknowledgeKeyChange(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    fingerprint: JByteArray,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let fp = read_bytes(env, &fingerprint);
        if fp.len() != 32 {
            return JNI_FALSE;
        }
        unsafe {
            if void_ffi::void_engine_acknowledge_key_change(
                engine_handle as *mut VoidEngine,
                fp.as_ptr(),
            ) == VoidStatus::Ok
            {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_revokeContact(
    mut env: JNIEnv,
    _class: JClass,
    engine_handle: jlong,
    fingerprint: JByteArray,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let fp = read_bytes(env, &fingerprint);
        if fp.len() != 32 {
            return JNI_FALSE;
        }
        unsafe {
            if void_ffi::void_engine_revoke_contact(engine_handle as *mut VoidEngine, fp.as_ptr())
                == VoidStatus::Ok
            {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }
    })
}

// --- calls --------------------------------------------------------------------
//
// Mirrors void-ffi's call surface one-for-one. The two halves stay separate
// here for the same reason they are separate there: signalling goes through
// the engine, media goes through a direct onion connection, and the only
// thing crossing this boundary for media is opaque encoded audio.
//
// Media keys never become JVM objects. `answerCall` writes the secret into a
// byte array the Kotlin side passes straight back into `mediaConnect` and
// otherwise never reads — a JVM byte array cannot be zeroized on demand, so
// the less time key material spends in one, the better.

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callHostPublish(
    mut env: JNIEnv,
    _class: JClass,
    tor: jlong,
    key_dir: JString,
) -> jlong {
    let env = &mut env;
    guard(0, || {
        if tor == 0 {
            return 0;
        }
        let key_dir = read_string(env, &key_dir);
        let Ok(key_c) = std::ffi::CString::new(key_dir) else {
            return 0;
        };
        unsafe {
            let mut out: *mut void_ffi::VoidCallHost = std::ptr::null_mut();
            if void_ffi::void_call_host_publish(
                tor as *const VoidTorHandle,
                key_c.as_ptr(),
                &mut out,
            ) == VoidStatus::Ok
            {
                out as jlong
            } else {
                0
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callHostAddress(
    mut env: JNIEnv,
    _class: JClass,
    host: jlong,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        if host == 0 {
            return new_jstring(env, "");
        }
        bytes_to_jstring(
            env,
            void_ffi::void_call_host_address(host as *const void_ffi::VoidCallHost),
        )
    })
}

/// Blocks until the callee connects, the answer window closes, or
/// `callHostCancel`. Kotlin must call this off the main thread, straight after
/// placing the call.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callHostAccept(
    mut env: JNIEnv,
    _class: JClass,
    host: jlong,
    media_secret: JByteArray,
    call_id: JByteArray,
) -> jlong {
    let env = &mut env;
    guard(0, || {
        let secret = read_bytes(env, &media_secret);
        let id = read_bytes(env, &call_id);
        if host == 0 || secret.len() != 32 || id.len() != 16 {
            return 0;
        }
        unsafe {
            let mut out: *mut void_ffi::VoidCallMedia = std::ptr::null_mut();
            if void_ffi::void_call_host_accept(
                host as *mut void_ffi::VoidCallHost,
                secret.as_ptr(),
                id.as_ptr(),
                &mut out,
            ) == VoidStatus::Ok
            {
                out as jlong
            } else {
                0
            }
        }
    })
}

/// Wakes a blocked `callHostAccept` (it returns 0). The caller hung up while it
/// rang.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callHostCancel(
    _env: JNIEnv,
    _class: JClass,
    host: jlong,
) {
    guard((), || unsafe {
        if host != 0 {
            void_ffi::void_call_host_cancel(host as *const void_ffi::VoidCallHost);
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callHostFree(
    _env: JNIEnv,
    _class: JClass,
    host: jlong,
) {
    guard((), || unsafe {
        if host != 0 {
            void_ffi::void_call_host_free(host as *mut void_ffi::VoidCallHost);
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callMediaConnect(
    mut env: JNIEnv,
    _class: JClass,
    tor: jlong,
    onion_address: JString,
    port: jint,
    media_secret: JByteArray,
    call_id: JByteArray,
) -> jlong {
    let env = &mut env;
    guard(0, || {
        let address = read_string(env, &onion_address);
        let secret = read_bytes(env, &media_secret);
        let id = read_bytes(env, &call_id);
        if tor == 0 || secret.len() != 32 || id.len() != 16 {
            return 0;
        }
        let Ok(addr_c) = std::ffi::CString::new(address) else {
            return 0;
        };
        unsafe {
            let mut out: *mut void_ffi::VoidCallMedia = std::ptr::null_mut();
            if void_ffi::void_call_media_connect(
                tor as *const VoidTorHandle,
                addr_c.as_ptr(),
                port as u16,
                secret.as_ptr(),
                id.as_ptr(),
                &mut out,
            ) == VoidStatus::Ok
            {
                out as jlong
            } else {
                0
            }
        }
    })
}

/// Sends one encoded audio frame. An empty array sends silence, which is what
/// holds the cadence constant while nobody is talking.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callMediaSend(
    mut env: JNIEnv,
    _class: JClass,
    media: jlong,
    audio: JByteArray,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        if media == 0 {
            return JNI_FALSE;
        }
        let frame = read_bytes(env, &audio);
        unsafe {
            let ptr = if frame.is_empty() {
                std::ptr::null()
            } else {
                frame.as_ptr()
            };
            if void_ffi::void_call_media_send(
                media as *mut void_ffi::VoidCallMedia,
                ptr,
                frame.len(),
            ) == VoidStatus::Ok
            {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }
    })
}

/// Receives one frame, waiting up to two seconds. The first byte is the
/// `VoidMediaRecv` status — 0 audio, 1 authenticated silence, 2 nothing, 3
/// closed — and the rest is the audio, present only for 0. One array rather
/// than a result object, because this runs fifty times a second.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callMediaRecv(
    mut env: JNIEnv,
    _class: JClass,
    media: jlong,
) -> jbyteArray {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        let closed = void_ffi::VoidMediaRecv::Closed as u8;
        if media == 0 {
            return env
                .byte_array_from_slice(&[closed])
                .map(|a| a.into_raw())
                .unwrap_or(std::ptr::null_mut());
        }
        let mut audio = empty_bytes();
        let status =
            void_ffi::void_call_media_recv(media as *mut void_ffi::VoidCallMedia, &mut audio);
        let mut framed = Vec::with_capacity(1 + audio.len);
        framed.push(status as u8);
        if !audio.data.is_null() && audio.len > 0 {
            framed.extend_from_slice(std::slice::from_raw_parts(audio.data, audio.len));
        }
        void_ffi::void_free_bytes(audio);
        env.byte_array_from_slice(&framed)
            .map(|a| a.into_raw())
            .unwrap_or(std::ptr::null_mut())
    })
}

/// Closes a call's media: a blocked `callMediaRecv` returns closed within
/// about a tenth of a second. Hang up with this, join the audio threads, then
/// `callMediaFree`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callMediaClose(
    _env: JNIEnv,
    _class: JClass,
    media: jlong,
) {
    guard((), || unsafe {
        if media != 0 {
            void_ffi::void_call_media_close(media as *const void_ffi::VoidCallMedia);
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callMediaFree(
    _env: JNIEnv,
    _class: JClass,
    media: jlong,
) {
    guard((), || unsafe {
        if media != 0 {
            void_ffi::void_call_media_free(media as *mut void_ffi::VoidCallMedia);
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callPort(_env: JNIEnv, _class: JClass) -> jint {
    guard(0, || void_ffi::void_call_port() as jint)
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callFrameMs(_env: JNIEnv, _class: JClass) -> jlong {
    guard(0, || void_ffi::void_call_media_frame_ms() as jlong)
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_callPayloadLen(_env: JNIEnv, _class: JClass) -> jint {
    guard(0, || void_ffi::void_call_media_payload_len() as jint)
}

/// Places a call. Writes the 16-byte call id and 32-byte media secret into the
/// caller-supplied arrays and returns true on success. `now` is in seconds.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_void_VoidCore_enginePlaceCall(
    mut env: JNIEnv,
    _class: JClass,
    engine: jlong,
    fingerprint: JByteArray,
    onion_address: JString,
    port: jint,
    now: jlong,
    out_call_id: JByteArray,
    out_media_secret: JByteArray,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let fp = read_bytes(env, &fingerprint);
        let address = read_string(env, &onion_address);
        if engine == 0 || fp.len() != 32 {
            return JNI_FALSE;
        }
        let Ok(addr_c) = std::ffi::CString::new(address) else {
            return JNI_FALSE;
        };
        let mut call_id = [0u8; 16];
        let mut secret = [0u8; 32];
        let ok = unsafe {
            void_ffi::void_engine_place_call(
                engine as *mut VoidEngine,
                fp.as_ptr(),
                addr_c.as_ptr(),
                port as u16,
                now as u64,
                call_id.as_mut_ptr(),
                secret.as_mut_ptr(),
            ) == VoidStatus::Ok
        };
        if !ok {
            return JNI_FALSE;
        }
        if env
            .set_byte_array_region(&out_call_id, 0, &to_jbytes(&call_id))
            .is_err()
            || env
                .set_byte_array_region(&out_media_secret, 0, &to_jbytes(&secret))
                .is_err()
        {
            return JNI_FALSE;
        }
        JNI_TRUE
    })
}

/// Answers a call. Writes the call id and media secret as `enginePlaceCall`
/// does, and returns the caller's onion address, or an empty string on failure.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineAnswerCall(
    mut env: JNIEnv,
    _class: JClass,
    engine: jlong,
    fingerprint: JByteArray,
    out_call_id: JByteArray,
    out_media_secret: JByteArray,
) -> jstring {
    let env = &mut env;
    guard(std::ptr::null_mut(), || {
        let fp = read_bytes(env, &fingerprint);
        if engine == 0 || fp.len() != 32 {
            return new_jstring(env, "");
        }
        let mut call_id = [0u8; 16];
        let mut secret = [0u8; 32];
        let mut address = empty_bytes();
        let mut port: u16 = 0;
        let ok = unsafe {
            void_ffi::void_engine_answer_call(
                engine as *mut VoidEngine,
                fp.as_ptr(),
                call_id.as_mut_ptr(),
                secret.as_mut_ptr(),
                &mut address,
                &mut port,
            ) == VoidStatus::Ok
        };
        if !ok {
            return new_jstring(env, "");
        }
        if env
            .set_byte_array_region(&out_call_id, 0, &to_jbytes(&call_id))
            .is_err()
            || env
                .set_byte_array_region(&out_media_secret, 0, &to_jbytes(&secret))
                .is_err()
        {
            unsafe { void_ffi::void_free_bytes(address) };
            return new_jstring(env, "");
        }
        unsafe { bytes_to_jstring(env, address) }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineEndCall(
    mut env: JNIEnv,
    _class: JClass,
    engine: jlong,
    fingerprint: JByteArray,
    reason: jint,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let fp = read_bytes(env, &fingerprint);
        if engine == 0 || fp.len() != 32 {
            return JNI_FALSE;
        }
        let reason = match reason {
            1 => void_ffi::VoidCallEndReason::HungUp,
            2 => void_ffi::VoidCallEndReason::Declined,
            3 => void_ffi::VoidCallEndReason::Missed,
            5 => void_ffi::VoidCallEndReason::Busy,
            _ => void_ffi::VoidCallEndReason::Failed,
        };
        unsafe {
            if void_ffi::void_engine_end_call(engine as *mut VoidEngine, fp.as_ptr(), reason)
                == VoidStatus::Ok
            {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }
    })
}

/// The caller has seen the callee's first authenticated media frame: the call
/// is answered. See `void_ffi::void_engine_mark_call_connected`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineMarkCallConnected(
    mut env: JNIEnv,
    _class: JClass,
    engine: jlong,
    fingerprint: JByteArray,
) -> jboolean {
    let env = &mut env;
    guard(JNI_FALSE, || {
        let fp = read_bytes(env, &fingerprint);
        if engine == 0 || fp.len() != 32 {
            return JNI_FALSE;
        }
        unsafe {
            if void_ffi::void_engine_mark_call_connected(engine as *mut VoidEngine, fp.as_ptr())
                == VoidStatus::Ok
            {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }
    })
}

/// Drains call events. Layout is documented on
/// `void_ffi::void_engine_take_call_events`; Kotlin parses it in `Engine.kt`.
#[no_mangle]
pub extern "system" fn Java_app_void_VoidCore_engineTakeCallEvents(
    mut env: JNIEnv,
    _class: JClass,
    engine: jlong,
) -> jbyteArray {
    let env = &mut env;
    guard(std::ptr::null_mut(), || unsafe {
        if engine == 0 {
            return bytes_to_jbytearray(env, empty_bytes());
        }
        bytes_to_jbytearray(
            env,
            void_ffi::void_engine_take_call_events(engine as *mut VoidEngine),
        )
    })
}

/// `set_byte_array_region` wants `i8`, and every buffer here is `u8`.
fn to_jbytes(bytes: &[u8]) -> Vec<i8> {
    bytes.iter().map(|b| *b as i8).collect()
}
