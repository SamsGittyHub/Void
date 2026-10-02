package app.void

/**
 * The Kotlin side of the FFI boundary.
 *
 * FR-UI-01 requires native Kotlin with no cross-platform runtime in the trusted
 * path. This file is the entire seam between the Android UI and the Rust core.
 *
 * ## Why the security-critical text comes from Rust
 *
 * PRD §7.4.1, FR-UI-04, FR-REC-01 and FR-REC-03 specify wording the user must
 * see. Those strings live in the core and are fetched through JNI rather than
 * being retyped here — a copy in Swift and another in Kotlin is two chances for
 * someone to soften "this cannot be undone".
 *
 * ## Threads
 *
 * Engine calls can block — the engine holds its lock for a whole tick, and a
 * tick can wait on the network — so none of these may run on the main thread.
 * [AppState] runs every engine call on one dedicated thread.
 */
object VoidCore {

    init {
        // void_jni, not void_ffi: void-ffi exports a C ABI for iOS.
        // void-jni is the JNI-convention (Java_app_void_VoidCore_*) wrapper
        // around it that this file's `external fun`s actually resolve
        // against — see crates/void-jni/src/lib.rs and docs/DECISIONS.md's
        // D-023.
        System.loadLibrary("void_jni")
    }

    // --- lifecycle -----------------------------------------------------------

    /** An engine with a fresh identity, held in memory only — for tests. 0 on failure. */
    @JvmStatic external fun engineNew(): Long

    /**
     * Open this device's engine, restoring it or creating it on first launch
     * (D-026). Returns the handle, or 0; `outStatus[0]` receives the
     * [VoidStatus] ordinal, so [VoidStatus.LOCKED] — a key that does not open
     * the existing database — can be told apart. `nowMs` is in milliseconds.
     */
    @JvmStatic external fun engineOpen(
        dataDir: String,
        kek: ByteArray,
        backing: Int,
        nowMs: Long,
        outStatus: IntArray,
    ): Long

    /** Destroy an engine and zeroize its secrets. */
    @JvmStatic external fun engineFree(handle: Long)

    /** The stored history with one contact; parse with [StoredMessage.parseAll]. */
    @JvmStatic external fun messages(engineHandle: Long, fingerprint: ByteArray): ByteArray

    // --- identity ------------------------------------------------------------

    /** The local security code as pronounceable syllables (FR-ID-03). */
    @JvmStatic external fun fingerprintWords(handle: Long): String

    /** The local security code as decimal groups, for reading aloud. */
    @JvmStatic external fun fingerprintNumbers(handle: Long): String

    /** Render an arbitrary 32-byte fingerprint as proquint words. */
    @JvmStatic external fun fingerprintRenderWords(fingerprint: ByteArray): String

    /**
     * Compare a code the user typed or heard against a contact's (FR-DISC-04).
     *
     * Constant-time and formatting-tolerant on the Rust side. A comparison that
     * failed on whitespace would train users to ignore mismatches.
     */
    @JvmStatic external fun fingerprintMatches(expected: ByteArray, input: String): Boolean

    // --- required user-facing text -------------------------------------------

    /** PRD §7.4.1's required duress disclosure. */
    @JvmStatic external fun textDuressDisclosure(): String

    /** FR-UI-04's confirmation phrase. */
    @JvmStatic external fun textDuressConfirmation(): String

    /** FR-REC-01's device-loss warning. */
    @JvmStatic external fun textDeviceLossWarning(): String

    /** FR-REC-03's export storage warning. */
    @JvmStatic external fun textExportStorageWarning(): String

    /**
     * What the user must be told before a call connects.
     *
     * From the core, not retyped here — see `void_proto::call::CALL_DISCLOSURE`,
     * including why it does not claim location exposure.
     */
    @JvmStatic external fun textCallDisclosure(): String

    /** Plain-language description of what protects the keys (NFR-COMP-02). */
    @JvmStatic external fun vaultBackingDescription(backing: Int): String

    /** The protocol identifier, for the about screen. */
    @JvmStatic external fun protocolId(): String

    /** The fixed record size (FR-MSG-02). */
    @JvmStatic external fun recordSize(): Int

    /** The largest file [sendFile] accepts, in bytes (`MAX_FILE_BYTES`). */
    @JvmStatic external fun fileMaxBytes(): Int

    /** How many records a file of this many bytes takes to send, at most. */
    @JvmStatic external fun fileRecordCount(dataLen: Int): Int

    /** How often one record leaves, in milliseconds. A protocol constant. */
    @JvmStatic external fun padIntervalMs(): Long

    // --- duress and the lock screen -------------------------------------------

    /** Opaque handle to a PIN verifier, or 0 on failure. `duressPin` may be empty. */
    @JvmStatic external fun pinVerifierNew(unlockPin: ByteArray, duressPin: ByteArray, salt: ByteArray): Long

    @JvmStatic external fun pinVerifierFree(handle: Long)

    /** Matches [PinOutcome]'s ordinals: 0 unlock, 1 duress, 2 wrong, 3 error. */
    @JvmStatic external fun pinCheck(handle: Long, pin: ByteArray): Int

    /** The RAM/store half of duress destruction (FR-STOR-02). */
    @JvmStatic external fun engineDuressDestroy(handle: Long): Boolean

    // --- Tor -------------------------------------------------------------------

    /** Blocks the calling thread until bootstrap succeeds or fails. Call off the UI thread. */
    @JvmStatic external fun torBootstrap(stateDir: String, cacheDir: String): Long

    @JvmStatic external fun torFree(handle: Long)

    /** Matches [VoidStatus]'s ordinals (see void-ffi). Blocks on the network. */
    @JvmStatic external fun engineAttachTor(engineHandle: Long, torHandle: Long, onionAddress: String, port: Int): Int

    // --- invitations (FR-DISC-01, FR-DISC-02) ------------------------------

    /**
     * Make an invitation. `null` on failure. `now` and `ttlSeconds` are in
     * **seconds** — a millisecond value is refused, not misread.
     */
    @JvmStatic external fun createInvite(
        engineHandle: Long,
        relayHint: ByteArray,
        myLabel: String,
        contactLabel: String,
        now: Long,
        ttlSeconds: Long,
    ): NativeInviteResult?

    @JvmStatic external fun cancelInvite(engineHandle: Long, inviteId: ByteArray): Boolean

    /** Parse with [ContactEvent.parseAll]. */
    @JvmStatic external fun takeContactEvents(engineHandle: Long): ByteArray

    @JvmStatic external fun openInvite(engineHandle: Long, link: String, now: Long): NativeOpenResult?

    @JvmStatic external fun confirmInvite(
        engineHandle: Long,
        fetchId: ByteArray,
        localName: String,
        firstMessage: String,
        now: Long,
    ): NativeStartResult?

    @JvmStatic external fun cancelFetch(engineHandle: Long, fetchId: ByteArray): Boolean

    /** Records still to park on the relay, or -1 once the invitation is no longer outstanding. */
    @JvmStatic external fun inviteStatus(engineHandle: Long, inviteId: ByteArray): Int

    @JvmStatic external fun inviteLink(engineHandle: Long, inviteId: ByteArray): String

    // --- settings and names ------------------------------------------------------

    /** Returns the [VoidStatus] ordinal. */
    @JvmStatic external fun renameContact(engineHandle: Long, fingerprint: ByteArray, name: String): Int

    @JvmStatic external fun inviteName(engineHandle: Long): String

    @JvmStatic external fun setInviteName(engineHandle: Long, name: String): Boolean

    @JvmStatic external fun protectionAcknowledged(engineHandle: Long): Boolean

    @JvmStatic external fun acknowledgeProtection(engineHandle: Long): Boolean

    // --- messages and contacts -------------------------------------------------

    @JvmStatic external fun send(engineHandle: Long, fingerprint: ByteArray, text: String, now: Long): NativeSendResult?

    /**
     * Queue a file. A file is a message — same ratchet, same fixed-size
     * records, one per slot — so it costs time, not shape; [fileRecordCount]
     * times [padIntervalMs] is the estimate to show first. Refused as
     * [VoidStatus.TOO_LARGE] before any ratchet state is spent on one over
     * [fileMaxBytes].
     */
    @JvmStatic external fun sendFile(
        engineHandle: Long,
        fingerprint: ByteArray,
        name: String,
        mime: String,
        data: ByteArray,
        now: Long,
    ): NativeSendResult?

    /** The bytes of a stored file, by the id [messages] listed it under; empty if there is none. */
    @JvmStatic external fun attachment(engineHandle: Long, id: Long): ByteArray

    @JvmStatic external fun tick(engineHandle: Long, nowMs: Long): NativeTickResult?

    /** Encoding: repeated `(fingerprint: 32 bytes, trust: u8, u16 LE name length, UTF-8 name)`. */
    @JvmStatic external fun contacts(engineHandle: Long): ByteArray

    @JvmStatic external fun markVerified(engineHandle: Long, fingerprint: ByteArray): Boolean

    @JvmStatic external fun acknowledgeKeyChange(engineHandle: Long, fingerprint: ByteArray): Boolean

    @JvmStatic external fun revokeContact(engineHandle: Long, fingerprint: ByteArray): Boolean

    // --- calls ---------------------------------------------------------------
    //
    // Two halves that have nothing to do with each other. Signalling — place,
    // answer, end, drain events — goes through the engine exactly as a message
    // does. Media is a direct onion connection and carries opaque encoded
    // audio; no media key ever becomes a Kotlin object beyond the byte array
    // that is handed straight back into `callMediaConnect`.
    //
    // See docs/DECISIONS.md D-024 and D-028, and
    // experiments/onion-call/RESULTS.md for the latency this costs.

    /** Publish an ephemeral onion service for an outgoing call. 0 on failure. */
    @JvmStatic external fun callHostPublish(torHandle: Long, keyDir: String): Long

    /** The address to put in the offer. */
    @JvmStatic external fun callHostAddress(hostHandle: Long): String

    /**
     * Blocks until the callee connects, the answer window closes, or
     * [callHostCancel]. Never call on the main thread. 0 on failure.
     */
    @JvmStatic external fun callHostAccept(hostHandle: Long, mediaSecret: ByteArray, callId: ByteArray): Long

    /** Wake a blocked [callHostAccept]. */
    @JvmStatic external fun callHostCancel(hostHandle: Long)

    /** Unpublish the service and delete its keys once nothing is using it. */
    @JvmStatic external fun callHostFree(hostHandle: Long)

    /** Dial the caller's service (the callee side). Blocks. 0 on failure. */
    @JvmStatic external fun callMediaConnect(
        torHandle: Long,
        onionAddress: String,
        port: Int,
        mediaSecret: ByteArray,
        callId: ByteArray,
    ): Long

    /** Encrypt and send one encoded audio frame. Empty means silence. False once the connection is gone. */
    @JvmStatic external fun callMediaSend(mediaHandle: Long, audio: ByteArray): Boolean

    /**
     * Receive one frame, waiting up to two seconds. The first byte is the
     * status — 0 audio, 1 authenticated silence, 2 nothing, 3 closed — and the
     * rest is the audio, present only for 0.
     */
    @JvmStatic external fun callMediaRecv(mediaHandle: Long): ByteArray

    /** Wake a blocked [callMediaRecv] and refuse later sends. */
    @JvmStatic external fun callMediaClose(mediaHandle: Long)

    @JvmStatic external fun callMediaFree(mediaHandle: Long)

    /** The virtual port every call's service listens on. Fixed for everyone. */
    @JvmStatic external fun callPort(): Int

    /** How often to emit a media frame, in milliseconds. */
    @JvmStatic external fun callFrameMs(): Long

    /** Largest encoded audio frame one media frame can carry. */
    @JvmStatic external fun callPayloadLen(): Int

    /** Places a call, filling the 16-byte id and 32-byte secret arrays. `now` is in seconds. */
    @JvmStatic external fun enginePlaceCall(
        engineHandle: Long,
        fingerprint: ByteArray,
        onionAddress: String,
        port: Int,
        now: Long,
        outCallId: ByteArray,
        outMediaSecret: ByteArray,
    ): Boolean

    /** Answers a call, returning the caller's address, or "" on failure. */
    @JvmStatic external fun engineAnswerCall(
        engineHandle: Long,
        fingerprint: ByteArray,
        outCallId: ByteArray,
        outMediaSecret: ByteArray,
    ): String

    /** Ends a call. `reason` matches [CallEndReason.code]. */
    @JvmStatic external fun engineEndCall(engineHandle: Long, fingerprint: ByteArray, reason: Int): Boolean

    /** The caller saw the callee's first authenticated frame: the call is answered. */
    @JvmStatic external fun engineMarkCallConnected(engineHandle: Long, fingerprint: ByteArray): Boolean

    /** Drains call events; parse with [CallEvent.parseAll]. */
    @JvmStatic external fun engineTakeCallEvents(engineHandle: Long): ByteArray
}

// --- parsing -----------------------------------------------------------------

/**
 * Reads the fixed-layout encodings `void-ffi` documents on each function.
 *
 * Every read is bounds-checked and returns `null` past the end, so a short or
 * malformed buffer stops parsing rather than throwing: this is the most
 * attacker-adjacent parsing on this side of the boundary, and dropping the tail
 * is always safe where an exception on the UI thread is not.
 */
class ByteReader(private val bytes: ByteArray) {
    private var position = 0

    val isAtEnd: Boolean get() = position >= bytes.size

    fun u8(): Int? = take(1)?.let { bytes[it].toInt() and 0xff }

    fun u16(): Int? = take(2)?.let { le(it, 2).toInt() }

    fun u32(): Long? = take(4)?.let { le(it, 4) }

    fun u64(): Long? = take(8)?.let { le(it, 8) }

    fun bytes(count: Int): ByteArray? = take(count)?.let { bytes.copyOfRange(it, it + count) }

    fun string(count: Int): String? = take(count)?.let { String(bytes, it, count, Charsets.UTF_8) }

    /** Advance past `count` bytes, returning where they started, or null if they are not all there. */
    private fun take(count: Int): Int? {
        if (count < 0 || count > bytes.size - position) return null
        val start = position
        position += count
        return start
    }

    private fun le(start: Int, count: Int): Long {
        var value = 0L
        for (i in count - 1 downTo 0) {
            value = (value shl 8) or (bytes[start + i].toLong() and 0xff)
        }
        return value
    }
}

/** A u32 length as an Int, refusing one too large to be real. */
private fun Long.asLength(): Int? = if (this in 0..Int.MAX_VALUE) toInt() else null

// --- contacts and invitations ------------------------------------------------

/** Why an invitation the user opened could not be used. */
enum class InviteFailure {
    EXPIRED, INVALID, TIMED_OUT;

    /** FR-UI-03: plain language, and a next step. */
    val explanation: String
        get() = when (this) {
            EXPIRED -> "This invitation has expired. Ask them for a new one."
            INVALID -> "This invitation couldn't be read. Ask them to send it again."
            TIMED_OUT ->
                "Their invitation never arrived. They may be offline, or someone else already " +
                    "used it. Ask them for a new one."
        }
}

/** Something that happened to a contact or an invitation. */
sealed class ContactEvent {
    /** Someone accepted one of our invitations. They are a contact now. */
    class Added(val inviteId: ByteArray, val fingerprint: ByteArray, val name: String, val firstMessage: String) :
        ContactEvent()

    /** One of our invitations expired unaccepted. */
    class InviteExpired(val inviteId: ByteArray) : ContactEvent()

    /** An invitation the user opened arrived and verified. Show who it is from, then confirm. */
    class InviteReady(val fetchId: ByteArray, val fingerprint: ByteArray, val inviterName: String) : ContactEvent()

    /** An invitation the user opened could not be used. */
    class InviteFailed(val fetchId: ByteArray, val reason: InviteFailure) : ContactEvent()

    companion object {
        /** Layout documented on `void_ffi::void_engine_take_contact_events`. */
        fun parseAll(buf: ByteArray): List<ContactEvent> {
            val reader = ByteReader(buf)
            val out = mutableListOf<ContactEvent>()
            while (!reader.isAtEnd) {
                val kind = reader.u8() ?: break
                val id = reader.bytes(16) ?: break
                val fingerprint = reader.bytes(32) ?: break
                val name = reader.u16()?.let { reader.string(it) } ?: break
                val message = reader.u32()?.asLength()?.let { reader.string(it) } ?: break
                out.add(
                    when (kind) {
                        1 -> Added(id, fingerprint, name, message)
                        2 -> InviteExpired(id)
                        3 -> InviteReady(id, fingerprint, name)
                        4 -> InviteFailed(id, InviteFailure.EXPIRED)
                        5 -> InviteFailed(id, InviteFailure.INVALID)
                        6 -> InviteFailed(id, InviteFailure.TIMED_OUT)
                        else -> return out
                    },
                )
            }
            return out
        }
    }
}

/** What a file in a conversation is, without its bytes. */
data class AttachmentInfo(val name: String, val mime: String, val size: Int) {
    /** Whether to show it as a picture rather than a file card. */
    val isImage: Boolean get() = mime.lowercase().startsWith("image/")

    /** What the conversation list shows for it. */
    val summary: String get() = if (isImage) "Photo" else name.ifBlank { "File" }
}

/** One message from the stored history. */
data class StoredMessage(
    /** The store record that holds it; what [Engine.attachment] takes. */
    val id: Long,
    val isOutgoing: Boolean,
    val delivery: DeliveryState,
    val timestampSeconds: Long,
    /** Empty for a file. */
    val text: String,
    /** The file it is, if it is one, without its bytes. */
    val attachment: AttachmentInfo? = null,
    /** Records of it still to leave. Zero once sent, and for anything received. */
    val fragmentsRemaining: Int = 0,
) {
    companion object {
        /** Layout documented on `void_ffi::void_engine_messages`. */
        fun parseAll(buf: ByteArray): List<StoredMessage> {
            val reader = ByteReader(buf)
            val out = mutableListOf<StoredMessage>()
            while (!reader.isAtEnd) {
                val id = reader.u64() ?: break
                val direction = reader.u8() ?: break
                val delivery = reader.u8() ?: break
                val timestamp = reader.u64() ?: break
                val remaining = reader.u16() ?: break
                val text = reader.u32()?.asLength()?.let { reader.string(it) } ?: break
                val hasFile = reader.u8() ?: break
                var attachment: AttachmentInfo? = null
                if (hasFile == 1) {
                    val name = reader.u16()?.let { reader.string(it) } ?: break
                    val mime = reader.u16()?.let { reader.string(it) } ?: break
                    val size = reader.u32()?.asLength() ?: break
                    attachment = AttachmentInfo(name, mime, size)
                }
                out.add(StoredMessage(id, direction == 1, DeliveryState.fromCode(delivery), timestamp, text, attachment, remaining))
            }
            return out
        }
    }
}

// --- calls -------------------------------------------------------------------

/** Why a call ended. Mirrors `void_proto::call::EndReason`. */
enum class CallEndReason(val code: Int) {
    HUNG_UP(1),
    DECLINED(2),
    MISSED(3),
    FAILED(4),
    BUSY(5);

    /** Plain language for the UI, per FR-UI-03. No codes shown to a person. */
    val plainLanguage: String
        get() = when (this) {
            HUNG_UP -> "Call ended."
            DECLINED -> "They declined."
            MISSED -> "No answer."
            FAILED -> "The connection didn't hold."
            BUSY -> "They're on another call."
        }

    companion object {
        fun from(code: Int): CallEndReason =
            entries.firstOrNull { it.code == code } ?: FAILED
    }
}

/** Something that happened to a call. */
sealed class CallEvent {
    abstract val fingerprint: ByteArray
    abstract val callId: ByteArray

    class Incoming(
        override val fingerprint: ByteArray,
        override val callId: ByteArray,
        val address: String,
        val port: Int,
    ) : CallEvent()

    class Answered(override val fingerprint: ByteArray, override val callId: ByteArray) : CallEvent()

    class Ended(
        override val fingerprint: ByteArray,
        override val callId: ByteArray,
        val reason: CallEndReason,
    ) : CallEvent()

    /**
     * A call that never rang here: it arrived too late to be live, or this
     * device was already on a call. Worth showing in the conversation.
     */
    class Missed(override val fingerprint: ByteArray, override val callId: ByteArray) : CallEvent()

    companion object {
        /**
         * Parse what [VoidCore.engineTakeCallEvents] returned. Layout, per
         * event, matching `void_ffi::void_engine_take_call_events`:
         *
         *   u8(kind) | 32 fingerprint | 16 call_id | u8(reason)
         *   | u32 LE(address_len) | address | u16 LE(port)
         */
        fun parseAll(buf: ByteArray): List<CallEvent> {
            val reader = ByteReader(buf)
            val out = mutableListOf<CallEvent>()
            while (!reader.isAtEnd) {
                val kind = reader.u8() ?: break
                val fingerprint = reader.bytes(32) ?: break
                val callId = reader.bytes(16) ?: break
                val reason = reader.u8() ?: break
                val address = reader.u32()?.asLength()?.let { reader.string(it) } ?: break
                val port = reader.u16() ?: break
                out.add(
                    when (kind) {
                        1 -> Incoming(fingerprint, callId, address, port)
                        2 -> Answered(fingerprint, callId)
                        3 -> Ended(fingerprint, callId, CallEndReason.from(reason))
                        4 -> Missed(fingerprint, callId)
                        else -> return out
                    },
                )
            }
            return out
        }
    }
}

/** What one media receive produced. Mirrors `VoidMediaRecv`. */
sealed class MediaReceive {
    /** Authenticated audio. Play it. */
    class Audio(val frame: ByteArray) : MediaReceive()

    /** An authenticated frame of silence: nothing to play, but proof the other end is there. */
    data object Silence : MediaReceive()

    /** Nothing usable within two seconds. Many in a row mean a stall. */
    data object Nothing : MediaReceive()

    /** The connection is gone, or was closed. End the call. */
    data object Closed : MediaReceive()
}

// --- native result shapes ----------------------------------------------------
//
// JNI returns compound results by constructing one of these directly (see
// void-jni's `find_and_new_object`) rather than through multiple out
// parameters. Their constructors are called only from native code, which is
// why proguard-rules.pro keeps them.

class NativeInviteResult(val link: String, val inviteId: ByteArray)

/** `status` matches [VoidStatus]'s ordinals; `fetchId` is empty unless OK. */
class NativeOpenResult(val status: Int, val fetchId: ByteArray)

/** `status` matches [VoidStatus]'s ordinals; `fingerprint` is empty unless OK. */
class NativeStartResult(val status: Int, val fingerprint: ByteArray)

/** `status` matches [VoidStatus]'s ordinals. */
class NativeSendResult(val status: Int, val messageId: Long)

/** `outcome` matches `VoidTickOutcome`'s ordinals; `messages` is populated only when retrieved. */
class NativeTickResult(val outcome: Int, val messages: ByteArray)

/** Mirrors `void_ffi::VoidStatus`. */
enum class VoidStatus {
    OK, BAD_ARGUMENT, FAILED, OFFLINE, KEY_CHANGED, LOCKED, INTERNAL, EXPIRED, ALREADY_CONNECTED, OWN_INVITE,
    WRONG_RELAY, TOO_LARGE;

    companion object {
        fun from(ordinal: Int): VoidStatus = entries.getOrElse(ordinal) { FAILED }
    }
}

/** Mirrors `void_ffi::VoidPinOutcome`. */
enum class PinOutcome {
    UNLOCK, DURESS, WRONG, ERROR;

    companion object {
        fun from(ordinal: Int): PinOutcome = entries.getOrElse(ordinal) { ERROR }
    }
}

/**
 * What is actually protecting the keys on this device.
 *
 * NFR-COMP-02: "StrongBox preferred with a documented TEE fallback and the
 * difference surfaced in the UI." A device that fell back to a software-backed
 * TEE is weaker, and the user is entitled to know that rather than seeing the
 * same reassuring padlock either way. [KeyVault] reports which one the key
 * actually landed in.
 */
enum class VaultBacking(val raw: Int) {
    STRONG_BOX(1),
    TEE(2),
    SOFTWARE(3);

    val userDescription: String
        get() = VoidCore.vaultBackingDescription(raw)

    val isHardwareBacked: Boolean
        get() = this != SOFTWARE
}

/**
 * How verified a contact is (FR-DISC-04, FR-DISC-05).
 *
 * Three states with no "probably fine" middle. A changed key blocks messaging
 * rather than warning about it, and that is enforced in the Rust engine — this
 * enum only decides how to say so.
 */
enum class TrustState {
    UNVERIFIED,
    VERIFIED,
    KEY_CHANGED;

    val canSend: Boolean get() = this != KEY_CHANGED

    /** FR-UI-03: plain language, no jargon the user must learn. */
    val statusLine: String
        get() = when (this) {
            UNVERIFIED -> "Not verified yet"
            VERIFIED -> "Verified in person"
            KEY_CHANGED -> "Their security code changed"
        }

    val guidance: String
        get() = when (this) {
            UNVERIFIED ->
                "Anyone could be at the other end of this conversation. Compare security " +
                    "codes with them in person or on a call you trust."
            VERIFIED ->
                "You compared security codes with this person. Messages are for them alone."
            KEY_CHANGED ->
                "This can happen if they reinstalled Void or switched devices. It can also " +
                    "mean someone is intercepting this conversation. Messaging is paused " +
                    "until you check with them through another channel."
        }
}

/** Per-message delivery state (NFR-REL-04). */
enum class DeliveryState {
    QUEUED, DEPOSITED, COLLECTED, FAILED, RECEIVED;

    /**
     * FR-UI-03: plain language, and never "sent" for something that is only
     * queued. A user deciding whether their message got out needs the
     * difference.
     */
    val label: String
        get() = when (this) {
            QUEUED -> "Waiting to send"
            DEPOSITED -> "Sent"
            COLLECTED -> "Delivered"
            FAILED -> "Could not send"
            RECEIVED -> ""
        }

    companion object {
        /** The byte `void_engine_messages` encodes. */
        fun fromCode(code: Int): DeliveryState = when (code) {
            0 -> QUEUED
            1 -> DEPOSITED
            2 -> COLLECTED
            3 -> FAILED
            else -> RECEIVED
        }
    }
}

/** Retention policy (FR-STOR-04). */
enum class RetentionPolicy {
    ONE_DAY, ONE_WEEK, THIRTY_DAYS, ONE_YEAR, FOREVER;

    val label: String
        get() = when (this) {
            ONE_DAY -> "24 hours"
            ONE_WEEK -> "7 days"
            THIRTY_DAYS -> "30 days"
            ONE_YEAR -> "1 year"
            FOREVER -> "Keep until I delete them"
        }

    /** Non-negotiable #8: every option states its cost, not just its benefit. */
    val consequence: String
        get() = when (this) {
            FOREVER ->
                "Messages stay on this phone until you delete them. If your phone is taken " +
                    "while unlocked, everything is there."
            else ->
                "Messages are deleted from this phone automatically. Once deleted they cannot " +
                    "be recovered, by you or by anyone else."
        }

    companion object {
        /**
         * FR-STOR-04: "with the shortest options presented first".
         *
         * The ordering is the requirement, so it lives here rather than in a
         * layout file that could be reordered during a redesign.
         */
        val ordered: List<RetentionPolicy> =
            listOf(ONE_DAY, ONE_WEEK, THIRTY_DAYS, ONE_YEAR, FOREVER)

        /** FR-STOR-04's default. */
        val default: RetentionPolicy = THIRTY_DAYS
    }
}
