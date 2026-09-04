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
 */
object VoidCore {

    init {
        // void_jni, not void_ffi: void-ffi exports a C ABI for iOS.
        // void-jni is the JNI-convention (Java_app_void_VoidCore_*) wrapper
        // around it that this file's `external fun`s actually resolve
        // against — see crates/void-jni/src/lib.rs and docs/DECISIONS.md's
        // D-021.
        System.loadLibrary("void_jni")
    }

    // --- lifecycle -----------------------------------------------------------

    /** Opaque handle to the Rust engine, or 0 on failure. */
    @JvmStatic external fun engineNew(): Long

    /** Destroy an engine and zeroize its secrets. */
    @JvmStatic external fun engineFree(handle: Long)

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

    /** Matches [VoidStatus]'s ordinals (see void-ffi). */
    @JvmStatic external fun engineAttachTor(engineHandle: Long, torHandle: Long, onionAddress: String, port: Int): Int

    // --- conversations -----------------------------------------------------

    /** `null` if the engine is invalid or the relay refuses the bundle. */
    @JvmStatic external fun createInvite(
        engineHandle: Long,
        relayHint: ByteArray,
        label: String,
        now: Long,
        ttlSeconds: Long,
    ): NativeInviteResult?

    @JvmStatic external fun queueSecretFree(handle: Long)

    @JvmStatic external fun pollIntroQueue(engineHandle: Long, queueHandle: Long): NativePollResult?

    @JvmStatic external fun acceptConversation(
        engineHandle: Long,
        queueHandle: Long,
        initial: ByteArray,
        now: Long,
    ): NativeAcceptResult?

    /** The 32-byte fingerprint of the new contact, or `null` on failure. */
    @JvmStatic external fun startConversation(
        engineHandle: Long,
        link: String,
        localName: String,
        firstMessage: String,
        now: Long,
    ): ByteArray?

    @JvmStatic external fun send(engineHandle: Long, fingerprint: ByteArray, text: String, now: Long): NativeSendResult?

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
    // See docs/DECISIONS.md D-024 for why media bypasses the relay, and
    // experiments/onion-call/RESULTS.md for the latency this costs.

    /** Publish an ephemeral onion service for an outgoing call. 0 on failure. */
    @JvmStatic external fun callHostPublish(torHandle: Long, keyDir: String): Long

    /** The address to put in the offer. */
    @JvmStatic external fun callHostAddress(hostHandle: Long): String

    /** Blocks up to 90s waiting for the callee. Never call on the main thread. */
    @JvmStatic external fun callHostAccept(
        hostHandle: Long,
        mediaSecret: ByteArray,
        callId: ByteArray,
    ): Long

    /** Unpublish the service and delete its keys. */
    @JvmStatic external fun callHostFree(hostHandle: Long)

    /** Dial the caller's service (the callee side). 0 on failure. */
    @JvmStatic external fun callMediaConnect(
        torHandle: Long,
        onionAddress: String,
        port: Int,
        mediaSecret: ByteArray,
        callId: ByteArray,
    ): Long

    /** Encrypt and send one encoded audio frame. Empty means silence. */
    @JvmStatic external fun callMediaSend(mediaHandle: Long, audio: ByteArray): Boolean

    /**
     * Receive one frame. Empty means play nothing — silence, a replay, and a
     * frame that failed to authenticate all arrive empty on purpose, because
     * the right response to all three is identical.
     */
    @JvmStatic external fun callMediaRecv(mediaHandle: Long): ByteArray

    @JvmStatic external fun callMediaFree(mediaHandle: Long)

    /** The virtual port every call's service listens on. Fixed for everyone. */
    @JvmStatic external fun callPort(): Int

    /** How often to emit a media frame, in milliseconds. */
    @JvmStatic external fun callFrameMs(): Long

    /** Largest encoded audio frame one media frame can carry. */
    @JvmStatic external fun callPayloadLen(): Int

    /** Places a call, filling the 16-byte id and 32-byte secret arrays. */
    @JvmStatic external fun enginePlaceCall(
        engineHandle: Long,
        fingerprint: ByteArray,
        onionAddress: String,
        port: Int,
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
    @JvmStatic external fun engineEndCall(
        engineHandle: Long,
        fingerprint: ByteArray,
        reason: Int,
    ): Boolean

    /** Drains call events; parse with [CallEvent.parseAll]. */
    @JvmStatic external fun engineTakeCallEvents(engineHandle: Long): ByteArray
}

// --- calls -------------------------------------------------------------------

/** Why a call ended. Mirrors `void_proto::call::EndReason`. */
enum class CallEndReason(val code: Int) {
    HUNG_UP(1),
    DECLINED(2),
    MISSED(3),
    FAILED(4);

    /** Plain language for the UI, per FR-UI-03. No codes shown to a person. */
    val plainLanguage: String
        get() = when (this) {
            HUNG_UP -> "Call ended."
            DECLINED -> "They declined."
            MISSED -> "No answer."
            FAILED -> "The connection didn't hold."
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

    data class Incoming(
        override val fingerprint: ByteArray,
        override val callId: ByteArray,
        val address: String,
        val port: Int,
    ) : CallEvent()

    data class Answered(
        override val fingerprint: ByteArray,
        override val callId: ByteArray,
    ) : CallEvent()

    data class Ended(
        override val fingerprint: ByteArray,
        override val callId: ByteArray,
        val reason: CallEndReason,
    ) : CallEvent()

    companion object {
        /**
         * Parse what [VoidCore.engineTakeCallEvents] returned.
         *
         * Layout, per event, matching the doc comment on
         * `void_ffi::void_engine_take_call_events`:
         *
         *   u8(kind) | 32 fingerprint | 16 call_id | u8(reason)
         *   | u32 LE(address_len) | address | u16 LE(port)
         *
         * A short or malformed buffer stops parsing rather than throwing:
         * this is the most attacker-adjacent parsing on this side of the
         * boundary, and dropping the tail is always safe where an exception
         * on the UI thread is not.
         */
        fun parseAll(buf: ByteArray): List<CallEvent> {
            val out = mutableListOf<CallEvent>()
            var pos = 0
            val fixed = 56 // 1 + 32 + 16 + 1 + 4 + 2
            while (pos + fixed <= buf.size) {
                val kind = buf[pos].toInt() and 0xff
                val fingerprint = buf.copyOfRange(pos + 1, pos + 33)
                val callId = buf.copyOfRange(pos + 33, pos + 49)
                val reason = buf[pos + 49].toInt() and 0xff
                val lenBase = pos + 50
                val len = (buf[lenBase].toInt() and 0xff) or
                    ((buf[lenBase + 1].toInt() and 0xff) shl 8) or
                    ((buf[lenBase + 2].toInt() and 0xff) shl 16) or
                    ((buf[lenBase + 3].toInt() and 0xff) shl 24)
                var cursor = lenBase + 4
                if (len < 0 || cursor + len + 2 > buf.size) break
                val address = String(buf, cursor, len, Charsets.UTF_8)
                cursor += len
                val port = (buf[cursor].toInt() and 0xff) or
                    ((buf[cursor + 1].toInt() and 0xff) shl 8)
                cursor += 2
                pos = cursor

                when (kind) {
                    1 -> out.add(Incoming(fingerprint, callId, address, port))
                    2 -> out.add(Answered(fingerprint, callId))
                    3 -> out.add(Ended(fingerprint, callId, CallEndReason.from(reason)))
                    else -> return out
                }
            }
            return out
        }
    }
}

// --- native result shapes ----------------------------------------------------
//
// JNI returns compound results by constructing one of these directly (see
// void-jni's `find_and_new_object`) rather than through multiple out
// parameters — the natural shape on this side of the boundary, where Swift's
// equivalent uses tuples.

class NativeInviteResult(val link: String, val queueHandle: Long)

/** `status` matches [VoidStatus]'s ordinals; `data` is empty until something arrives. */
class NativePollResult(val status: Int, val data: ByteArray)

class NativeAcceptResult(val fingerprint: ByteArray, val firstMessage: String)

/** `status` matches [VoidStatus]'s ordinals. */
class NativeSendResult(val status: Int, val messageId: Long)

/** `outcome` matches `VoidTickOutcome`'s ordinals; `messages` is populated only when retrieved. */
class NativeTickResult(val outcome: Int, val messages: ByteArray)

/** Mirrors `void_ffi::VoidStatus`. */
enum class VoidStatus {
    OK, BAD_ARGUMENT, FAILED, OFFLINE, KEY_CHANGED, LOCKED, INTERNAL;

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
 * same reassuring padlock either way.
 */
enum class VaultBacking(val raw: Int) {
    STRONG_BOX(1),
    TEE(2),
    SOFTWARE(3);

    val userDescription: String
        get() = VoidCore.vaultBackingDescription(raw)

    val isHardwareBacked: Boolean
        get() = this != SOFTWARE

    companion object {
        /**
         * Detect what this device actually offers.
         *
         * Reports the truth rather than the best case: a device without
         * StrongBox gets [TEE] and the UI says so.
         */
        fun detect(hasStrongBox: Boolean, hasTee: Boolean): VaultBacking = when {
            hasStrongBox -> STRONG_BOX
            hasTee -> TEE
            else -> SOFTWARE
        }
    }
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
