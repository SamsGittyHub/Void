package app.void

import java.io.File

/**
 * The instance-level wrapper around [VoidCore]'s raw JNI handles — the
 * Kotlin analogue of `ios/Void/VoidCore.swift`'s `VoidCore` class. [VoidCore]
 * itself stays the thin `external fun` surface (and the home for the
 * identity/text functions that need no handle); this is where a live engine
 * handle becomes an idiomatic Kotlin API.
 *
 * Every method can block, so none may run on the main thread; [AppState] runs
 * them all on one dedicated thread.
 */
class Engine private constructor(private var handle: Long) {

    val fingerprintWords: String get() = VoidCore.fingerprintWords(handle)
    val fingerprintNumbers: String get() = VoidCore.fingerprintNumbers(handle)

    /** The Tor client this engine's transport was built from, kept alive as long as the engine. */
    private var attachedTor: TorHandle? = null

    fun close() {
        if (handle != 0L) {
            VoidCore.engineFree(handle)
            handle = 0L
        }
    }

    // --- invitations (FR-DISC-01, FR-DISC-02) ------------------------------

    data class CreatedInvite(val link: String, val id: ByteArray)

    /**
     * Make an invitation and return its short `void://i/` link — one QR code —
     * with the id that names it in [takeContactEvents].
     *
     * The engine parks the invitation on [relay] through its outbox and
     * watches for its acceptance on its own schedule; there is nothing to
     * poll. [myLabel] travels inside the encrypted invitation and is shown to
     * whoever opens it. [contactLabel] never leaves this device: it becomes the
     * name of whoever accepts. `now` and `ttlSeconds` are in seconds.
     */
    fun createInvite(relay: String, myLabel: String, contactLabel: String, now: Long, ttlSeconds: Long): CreatedInvite {
        val result = VoidCore.createInvite(handle, relay.toByteArray(Charsets.UTF_8), myLabel, contactLabel, now, ttlSeconds)
            ?: throw VoidException(VoidStatus.FAILED)
        return CreatedInvite(result.link, result.inviteId)
    }

    /** Withdraw an invitation. A handshake sent against it is never answered. */
    fun cancelInvite(id: ByteArray): Boolean = VoidCore.cancelInvite(handle, id)

    /**
     * Records of an outstanding invitation still to be parked on the relay:
     * 0 means whoever opens it can collect it now; `null` once it has been
     * accepted, has expired, or was cancelled.
     */
    fun inviteUploadRemaining(id: ByteArray): Int? = VoidCore.inviteStatus(handle, id).takeIf { it >= 0 }

    /**
     * Open an invitation someone gave the user — scanned or pasted — and start
     * collecting it. Returns the id its ready or failed event will carry.
     */
    fun openInvite(link: String, now: Long): ByteArray {
        val result = VoidCore.openInvite(handle, link, now) ?: throw VoidException(VoidStatus.FAILED)
        val status = VoidStatus.from(result.status)
        if (status != VoidStatus.OK) throw VoidException(status)
        return result.fetchId
    }

    /**
     * Connect using an invitation reported ready. [localName] may be empty to
     * keep the name it carried; [firstMessage] may be empty. Returns the new
     * contact's fingerprint.
     */
    fun confirmInvite(fetchId: ByteArray, localName: String, firstMessage: String, now: Long): ByteArray {
        val result = VoidCore.confirmInvite(handle, fetchId, localName, firstMessage, now)
            ?: throw VoidException(VoidStatus.FAILED)
        val status = VoidStatus.from(result.status)
        if (status != VoidStatus.OK) throw VoidException(status)
        return result.fingerprint
    }

    /** Stop waiting for an invitation the user opened. */
    fun cancelFetch(fetchId: ByteArray) {
        VoidCore.cancelFetch(handle, fetchId)
    }

    /** Everything that happened to contacts and invitations since the last drain. */
    fun takeContactEvents(): List<ContactEvent> = ContactEvent.parseAll(VoidCore.takeContactEvents(handle))

    // --- settings and names ------------------------------------------------------

    /** The name the user puts on invitations. Stored in the encrypted database. */
    val inviteName: String get() = VoidCore.inviteName(handle)

    fun setInviteName(name: String) {
        if (!VoidCore.setInviteName(handle, name)) throw VoidException(VoidStatus.FAILED)
    }

    /** Whether the user has been through the protection screen on this device (FR-UI-05). */
    val protectionAcknowledged: Boolean get() = VoidCore.protectionAcknowledged(handle)

    fun acknowledgeProtection() {
        if (!VoidCore.acknowledgeProtection(handle)) throw VoidException(VoidStatus.FAILED)
    }

    /** Change the name this device shows for a contact. Never transmitted. */
    fun renameContact(fingerprint: ByteArray, name: String) {
        val status = VoidStatus.from(VoidCore.renameContact(handle, fingerprint, name))
        if (status != VoidStatus.OK) throw VoidException(status)
    }

    // --- sending and receiving -----------------------------------------------

    /** Queues a message. Transmission happens on the scheduler's own timing (FR-MSG-06) via [tick]. */
    fun send(fingerprint: ByteArray, text: String, now: Long): Long {
        val result = VoidCore.send(handle, fingerprint, text, now) ?: throw VoidException(VoidStatus.FAILED)
        val status = VoidStatus.from(result.status)
        if (status != VoidStatus.OK) throw VoidException(status)
        return result.messageId
    }

    sealed class TickResult {
        data object Waiting : TickResult()
        data object SentPadding : TickResult()
        data object Deposited : TickResult()
        data object Refused : TickResult()
        class Retrieved(val messages: List<Pair<ByteArray, String>>) : TickResult()
        data object Offline : TickResult()
    }

    /**
     * Advances the scheduler by one tick (FR-MSG-06). Call on a repeating
     * timer; every call takes the same observable time regardless of
     * whether it carries real traffic.
     */
    fun tick(nowMs: Long): TickResult {
        val result = VoidCore.tick(handle, nowMs) ?: return TickResult.Offline
        return when (result.outcome) {
            0 -> TickResult.Waiting
            1 -> TickResult.SentPadding
            2 -> TickResult.Deposited
            3 -> TickResult.Refused
            4 -> TickResult.Retrieved(decodeReceivedMessages(result.messages))
            else -> TickResult.Offline
        }
    }

    private fun decodeReceivedMessages(bytes: ByteArray): List<Pair<ByteArray, String>> {
        val reader = ByteReader(bytes)
        val out = mutableListOf<Pair<ByteArray, String>>()
        while (!reader.isAtEnd) {
            val fp = reader.bytes(32) ?: break
            val length = reader.u32() ?: break
            if (length > Int.MAX_VALUE) break
            val text = reader.string(length.toInt()) ?: break
            out.add(fp to text)
        }
        return out
    }

    /** The stored history with one contact, oldest first. */
    fun messages(fingerprint: ByteArray): List<StoredMessage> =
        StoredMessage.parseAll(VoidCore.messages(handle, fingerprint))

    // --- contacts --------------------------------------------------------------

    class ContactSummary(val fingerprint: ByteArray, val trust: TrustState, val name: String) {
        /** Hex of the fingerprint: a stable map key, since arrays compare by identity. */
        val key: String get() = fingerprint.toHex()
    }

    /** The contact list, for the conversation list screen. */
    fun contacts(): List<ContactSummary> {
        val reader = ByteReader(VoidCore.contacts(handle))
        val out = mutableListOf<ContactSummary>()
        while (!reader.isAtEnd) {
            val fp = reader.bytes(32) ?: break
            val trust = when (reader.u8() ?: break) {
                1 -> TrustState.VERIFIED
                2 -> TrustState.KEY_CHANGED
                else -> TrustState.UNVERIFIED
            }
            val name = reader.u16()?.let { reader.string(it) } ?: break
            out.add(ContactSummary(fp, trust, name))
        }
        return out
    }

    fun markVerified(fingerprint: ByteArray) {
        if (!VoidCore.markVerified(handle, fingerprint)) throw VoidException(VoidStatus.FAILED)
    }

    fun acknowledgeKeyChange(fingerprint: ByteArray) {
        if (!VoidCore.acknowledgeKeyChange(handle, fingerprint)) throw VoidException(VoidStatus.FAILED)
    }

    fun revokeContact(fingerprint: ByteArray) {
        if (!VoidCore.revokeContact(handle, fingerprint)) throw VoidException(VoidStatus.FAILED)
    }

    // --- Tor -----------------------------------------------------------------

    /**
     * Opens a circuit to `onionAddress:port` and makes it this engine's
     * transport (FR-TRANS-04's pinning: the onion address *is* the relay's
     * public key, so there is no certificate authority anywhere in this
     * path). Blocks on the network, and does not hold the engine's lock while
     * it connects.
     */
    fun attachTor(tor: TorHandle, onionAddress: String, port: Int) {
        val status = VoidStatus.from(VoidCore.engineAttachTor(handle, tor.handle, onionAddress, port))
        if (status != VoidStatus.OK) throw VoidException(status)
        attachedTor = tor
    }

    // --- calls ---------------------------------------------------------------

    /** What a call needs to open its media connection. Never rendered, never logged. */
    class CallCredentials(
        val callId: ByteArray,
        val mediaSecret: ByteArray,
        val address: String,
        val port: Int,
    )

    /**
     * Place a call to a contact whose onion service is already publishing.
     * `now` is in seconds: the offer carries it, so one that reaches the
     * callee too late to be live shows as missed instead of ringing.
     */
    fun placeCall(fingerprint: ByteArray, onionAddress: String, port: Int, now: Long): CallCredentials {
        val callId = ByteArray(16)
        val secret = ByteArray(32)
        if (!VoidCore.enginePlaceCall(handle, fingerprint, onionAddress, port, now, callId, secret)) {
            throw VoidException(VoidStatus.FAILED)
        }
        return CallCredentials(callId, secret, onionAddress, port)
    }

    /** Answer an incoming call, returning what the media connection needs. */
    fun answerCall(fingerprint: ByteArray): CallCredentials {
        val callId = ByteArray(16)
        val secret = ByteArray(32)
        val address = VoidCore.engineAnswerCall(handle, fingerprint, callId, secret)
        if (address.isEmpty()) throw VoidException(VoidStatus.FAILED)
        // Every call's service listens on the one fixed port.
        return CallCredentials(callId, secret, address, VoidCore.callPort())
    }

    /**
     * The caller saw the callee's first authenticated media frame: the call is
     * answered, without waiting a mailbox delay for the relayed answer.
     */
    fun markCallConnected(fingerprint: ByteArray): Boolean = VoidCore.engineMarkCallConnected(handle, fingerprint)

    /** End a call. Local state clears whether or not the signal gets out. */
    fun endCall(fingerprint: ByteArray, reason: CallEndReason) {
        VoidCore.engineEndCall(handle, fingerprint, reason.code)
    }

    /** Everything that has happened to calls since the last drain. */
    fun takeCallEvents(): List<CallEvent> =
        CallEvent.parseAll(VoidCore.engineTakeCallEvents(handle))

    companion object {
        /** An engine held in memory only, with a fresh identity — for tests. */
        fun inMemory(): Engine {
            val handle = VoidCore.engineNew()
            if (handle == 0L) throw VoidException(VoidStatus.FAILED)
            return Engine(handle)
        }

        /**
         * Open this device's engine: restore it, or create it with a fresh
         * identity on first launch (D-026). [kek] is the key [KeyVault]
         * released; it is zeroed before this returns. Throws
         * [VoidStatus.LOCKED] if it does not open the existing database, and
         * replaces nothing in that case.
         */
        fun open(dataDir: File, kek: ByteArray, backing: VaultBacking, nowMs: Long): Engine {
            val status = IntArray(1)
            val handle = try {
                VoidCore.engineOpen(dataDir.absolutePath, kek, backing.raw, nowMs, status)
            } finally {
                kek.fill(0)
            }
            if (handle == 0L) {
                throw VoidException(VoidStatus.from(status[0]).takeIf { it != VoidStatus.OK } ?: VoidStatus.FAILED)
            }
            return Engine(handle)
        }
    }
}

/** Hex rendering of a byte array, for map keys. */
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

/**
 * An ephemeral onion service published for one outgoing call.
 *
 * Freeing it unpublishes the service and deletes its keys, which is what makes
 * each call's address unlinkable from the last one's.
 */
class CallHost private constructor(private val handle: Long) {
    /** The address to put in the offer. */
    val address: String = VoidCore.callHostAddress(handle)

    private val lock = Any()
    private var accepting = false
    private var releaseRequested = false
    private var freed = false

    /**
     * Block until the callee connects, the answer window closes, or
     * [release]. Call it straight after placing the call — not once the
     * relayed answer arrives: the callee dials the moment they answer, and
     * their first authenticated frame is the answer (D-028). Never on the main
     * thread.
     */
    fun accept(credentials: Engine.CallCredentials): CallMedia? {
        synchronized(lock) {
            if (freed || releaseRequested) return null
            accepting = true
        }
        val media = VoidCore.callHostAccept(handle, credentials.mediaSecret, credentials.callId)
        synchronized(lock) {
            accepting = false
            if (releaseRequested && !freed) {
                freed = true
                VoidCore.callHostFree(handle)
            }
        }
        return if (media != 0L) CallMedia(media) else null
    }

    /**
     * Stop waiting and let the handle go: at once if nothing is using it,
     * otherwise as soon as a blocked [accept] — woken here — returns. Freeing
     * it while [accept] was still on its way into native code would free a
     * handle about to be used. Safe to call more than once.
     */
    fun release() {
        synchronized(lock) {
            if (freed) return
            if (accepting) {
                releaseRequested = true
                VoidCore.callHostCancel(handle)
            } else {
                freed = true
                VoidCore.callHostFree(handle)
            }
        }
    }

    companion object {
        fun publish(tor: TorHandle, keyDir: String): CallHost {
            val handle = VoidCore.callHostPublish(tor.handle, keyDir)
            if (handle == 0L) throw VoidException(VoidStatus.OFFLINE)
            return CallHost(handle)
        }
    }
}

/**
 * One call's live media connection.
 *
 * Used from a sending thread and a receiving thread while the main thread may
 * hang up. The core's handle is safe for that; the rule on this side is only
 * the order of teardown: [close], join the threads that use it, then [free].
 * [CallAudio.stop] does exactly that.
 */
class CallMedia internal constructor(private val handle: Long) {
    /** Encrypt and send one encoded frame; empty is silence. False once the connection is gone. */
    fun send(audio: ByteArray): Boolean = VoidCore.callMediaSend(handle, audio)

    /** Receive one frame, waiting up to two seconds. */
    fun receive(): MediaReceive {
        val framed = VoidCore.callMediaRecv(handle)
        if (framed.isEmpty()) return MediaReceive.Closed
        return when (framed[0].toInt()) {
            0 -> MediaReceive.Audio(framed.copyOfRange(1, framed.size))
            1 -> MediaReceive.Silence
            2 -> MediaReceive.Nothing
            else -> MediaReceive.Closed
        }
    }

    /** Wake a blocked [receive] within about a tenth of a second, and refuse later sends. */
    fun close() = VoidCore.callMediaClose(handle)

    /** Release the handle. Only after every thread using it has finished. */
    fun free() = VoidCore.callMediaFree(handle)

    companion object {
        /** Dial the caller's service (the callee side). Blocks. */
        fun connect(tor: TorHandle, credentials: Engine.CallCredentials): CallMedia? {
            val media = VoidCore.callMediaConnect(
                tor.handle,
                credentials.address,
                credentials.port,
                credentials.mediaSecret,
                credentials.callId,
            )
            return if (media != 0L) CallMedia(media) else null
        }
    }
}

/**
 * A bootstrapped Arti client (D-009: the async runtime lives here, never in
 * [Engine]'s own dependency graph). [bootstrap] blocks the calling thread
 * until the circuit is up or bootstrap fails — commonly tens of seconds —
 * so call it from a background dispatcher, never from the main thread.
 */
class TorHandle private constructor(internal val handle: Long) {
    fun close() = VoidCore.torFree(handle)

    companion object {
        fun bootstrap(stateDir: String, cacheDir: String): TorHandle {
            val handle = VoidCore.torBootstrap(stateDir, cacheDir)
            if (handle == 0L) throw VoidException(VoidStatus.OFFLINE)
            return TorHandle(handle)
        }
    }
}

/** Thrown by [Engine]'s methods on a non-OK [VoidStatus]. */
class VoidException(val status: VoidStatus) : Exception() {
    /** Plain language, per FR-UI-03. No jargon, and no reassurance we cannot back up. */
    override val message: String
        get() = when (status) {
            VoidStatus.OFFLINE ->
                "Void can't reach the network right now. Your message is saved on this " +
                    "device and will send when it can. It has not been sent any other way."
            VoidStatus.KEY_CHANGED ->
                "This contact's security code changed. Messaging is paused until you check " +
                    "with them through another channel."
            VoidStatus.LOCKED -> "Void is locked."
            VoidStatus.EXPIRED -> "This invitation has expired. Ask them for a new one."
            VoidStatus.ALREADY_CONNECTED -> "You're already connected with this person."
            VoidStatus.OWN_INVITE ->
                "That's your own invitation. Send it to the person you want to talk to."
            VoidStatus.WRONG_RELAY ->
                "This invitation uses a different Void server from this app, so it can't be " +
                    "opened here."
            else -> "Something went wrong. Nothing was sent."
        }
}
