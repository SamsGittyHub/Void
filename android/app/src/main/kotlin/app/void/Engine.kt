package app.void

/**
 * The instance-level wrapper around [VoidCore]'s raw JNI handles — the
 * Kotlin analogue of `ios/Void/VoidCore.swift`'s `VoidCore` class. [VoidCore]
 * itself stays the thin `external fun` surface (and the home for the
 * identity/text functions that need no handle); this is where a live engine
 * handle becomes an idiomatic Kotlin API.
 */
class Engine private constructor(private var handle: Long) {

    val fingerprintWords: String get() = VoidCore.fingerprintWords(handle)
    val fingerprintNumbers: String get() = VoidCore.fingerprintNumbers(handle)

    fun close() {
        if (handle != 0L) {
            VoidCore.engineFree(handle)
            handle = 0L
        }
    }

    // --- establishing a conversation (FR-DISC-01, FR-DISC-02) --------------

    /** Publishes an invite and returns it with the queue needed to detect acceptance. */
    fun createInvite(relayHint: String, label: String, now: Long, ttlSeconds: Long): Pair<String, IntroQueue> {
        val result = VoidCore.createInvite(handle, relayHint.toByteArray(Charsets.UTF_8), label, now, ttlSeconds)
            ?: throw VoidException(VoidStatus.FAILED)
        return result.link to IntroQueue(result.queueHandle)
    }

    /**
     * Polls a queue from [createInvite] for a delivered handshake. `null`
     * until someone has scanned the invite — that is normal, not an error,
     * and this is safe to call on a repeating timer.
     */
    fun pollIntroQueue(queue: IntroQueue): ByteArray? {
        val result = VoidCore.pollIntroQueue(handle, queue.handle) ?: throw VoidException(VoidStatus.OFFLINE)
        val status = VoidStatus.from(result.status)
        if (status != VoidStatus.OK) throw VoidException(status)
        return result.data.takeIf { it.isNotEmpty() }
    }

    /** Accepts a conversation from bytes [pollIntroQueue] returned. */
    fun acceptConversation(queue: IntroQueue, initial: ByteArray, now: Long): Pair<ByteArray, String> {
        val result = VoidCore.acceptConversation(handle, queue.handle, initial, now)
            ?: throw VoidException(VoidStatus.FAILED)
        return result.fingerprint to result.firstMessage
    }

    /** Starts a conversation from a scanned or pasted invite link (the initiator side). */
    fun startConversation(link: String, localName: String, firstMessage: String, now: Long): ByteArray =
        VoidCore.startConversation(handle, link, localName, firstMessage, now)
            ?: throw VoidException(VoidStatus.FAILED)

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
        data class Retrieved(val messages: List<Pair<ByteArray, String>>) : TickResult()
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
        val out = mutableListOf<Pair<ByteArray, String>>()
        var pos = 0
        while (pos + 36 <= bytes.size) {
            val fp = bytes.copyOfRange(pos, pos + 32)
            pos += 32
            val len = (bytes[pos].toInt() and 0xFF) or
                ((bytes[pos + 1].toInt() and 0xFF) shl 8) or
                ((bytes[pos + 2].toInt() and 0xFF) shl 16) or
                ((bytes[pos + 3].toInt() and 0xFF) shl 24)
            pos += 4
            if (pos + len > bytes.size) break
            val text = String(bytes, pos, len, Charsets.UTF_8)
            pos += len
            out.add(fp to text)
        }
        return out
    }

    // --- contacts --------------------------------------------------------------

    data class ContactSummary(val fingerprint: ByteArray, val trust: TrustState, val name: String)

    /** The contact list, for the conversation list screen. */
    fun contacts(): List<ContactSummary> {
        val bytes = VoidCore.contacts(handle)
        val out = mutableListOf<ContactSummary>()
        var pos = 0
        while (pos + 35 <= bytes.size) {
            val fp = bytes.copyOfRange(pos, pos + 32)
            pos += 32
            val trust = when (bytes[pos].toInt()) {
                1 -> TrustState.VERIFIED
                2 -> TrustState.KEY_CHANGED
                else -> TrustState.UNVERIFIED
            }
            pos += 1
            val nameLen = (bytes[pos].toInt() and 0xFF) or ((bytes[pos + 1].toInt() and 0xFF) shl 8)
            pos += 2
            if (pos + nameLen > bytes.size) break
            val name = String(bytes, pos, nameLen, Charsets.UTF_8)
            pos += nameLen
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
     * path). Call after [TorHandle.bootstrap] has returned.
     */
    fun attachTor(tor: TorHandle, onionAddress: String, port: Int) {
        val status = VoidStatus.from(VoidCore.engineAttachTor(handle, tor.handle, onionAddress, port))
        if (status != VoidStatus.OK) throw VoidException(status)
    }

    // --- calls ---------------------------------------------------------------

    /** What a call needs to open its media connection. */
    data class CallCredentials(
        val callId: ByteArray,
        val mediaSecret: ByteArray,
        val address: String,
        val port: Int,
    )

    /**
     * Place a call to a contact whose onion service is already publishing.
     *
     * Publish first ([CallHost.publish]) and pass that address in: the
     * descriptor upload then finishes while this offer waits for the peer's
     * next retrieval slot, so the two delays overlap rather than add.
     */
    fun placeCall(fingerprint: ByteArray, onionAddress: String, port: Int): CallCredentials {
        val callId = ByteArray(16)
        val secret = ByteArray(32)
        val ok = VoidCore.enginePlaceCall(handle, fingerprint, onionAddress, port, callId, secret)
        if (!ok) throw VoidException(VoidStatus.FAILED)
        return CallCredentials(callId, secret, onionAddress, port)
    }

    /** Answer an incoming call, returning what the media connection needs. */
    fun answerCall(fingerprint: ByteArray): CallCredentials {
        val callId = ByteArray(16)
        val secret = ByteArray(32)
        val address = VoidCore.engineAnswerCall(handle, fingerprint, callId, secret)
        if (address.isEmpty()) throw VoidException(VoidStatus.FAILED)
        return CallCredentials(callId, secret, address, VoidCore.callPort())
    }

    /** End a call. Local state clears whether or not the signal gets out. */
    fun endCall(fingerprint: ByteArray, reason: CallEndReason) {
        VoidCore.engineEndCall(handle, fingerprint, reason.code)
    }

    /** Everything that has happened to calls since the last drain. */
    fun takeCallEvents(): List<CallEvent> =
        CallEvent.parseAll(VoidCore.engineTakeCallEvents(handle))

    /** Dial the caller's service. Blocks; call from [Dispatchers.IO]. */
    fun connectCallMedia(tor: TorHandle, credentials: CallCredentials): Long =
        VoidCore.callMediaConnect(
            tor.handle,
            credentials.address,
            credentials.port,
            credentials.mediaSecret,
            credentials.callId,
        )

    companion object {
        fun create(): Engine {
            val handle = VoidCore.engineNew()
            if (handle == 0L) throw VoidException(VoidStatus.FAILED)
            return Engine(handle)
        }
    }
}

/** A handle to an introduction queue, from [Engine.createInvite]. */
class IntroQueue internal constructor(internal val handle: Long) {
    fun close() = VoidCore.queueSecretFree(handle)
}

/**
 * A bootstrapped Arti client (D-009: the async runtime lives here, never in
 * [Engine]'s own dependency graph). [bootstrap] blocks the calling thread
 * until the circuit is up or bootstrap fails — commonly tens of seconds —
 * so call it from a background dispatcher, never from the main thread.
 */
/**
 * An ephemeral onion service published for one outgoing call.
 *
 * Closing it unpublishes the service and deletes its keys, which is what makes
 * each call's address unlinkable from the last one's.
 */
class CallHost private constructor(private var handle: Long) {
    /** The address to put in the offer. */
    val address: String get() = VoidCore.callHostAddress(handle)

    /**
     * Block until the callee connects, then return a media handle.
     *
     * Waits up to ninety seconds and consumes the host either way. Never call
     * this on the main thread.
     */
    fun accept(credentials: Engine.CallCredentials): Long {
        val media = VoidCore.callHostAccept(handle, credentials.mediaSecret, credentials.callId)
        handle = 0
        return media
    }

    fun close() {
        if (handle != 0L) {
            VoidCore.callHostFree(handle)
            handle = 0
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
            else -> "Something went wrong. Nothing was sent."
        }
}
