package app.void

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Bootstrap progress for the Tor circuit [AppState.connectTor] opens. */
enum class TorStatus { NOT_STARTED, BOOTSTRAPPING, CONNECTED, FAILED }

/**
 * A relay for local/dev testing, not a production endpoint — there is no
 * deployed Void relay yet. This one runs as `void-relayd` on a developer
 * machine, reachable only through the onion service address below, and it
 * will go away the moment that process stops. A real release needs this to
 * come from configuration, not a compiled-in constant.
 */
object DevRelay {
    const val ONION_ADDRESS = "hxxfawyq3xymghgqkalw4ut6emtt5nhaimquyrvi7ngyeecrri4qy5qd.onion"
    const val PORT = 9443
}

/**
 * The one place [Engine] meets Compose state — the Kotlin mirror of
 * `ios/Void/AppState.swift`. Every screen reads from or writes through here;
 * nothing above reimplements protocol logic.
 *
 * ## What this does not yet do
 *
 * Same gaps as the iOS increment this mirrors: no `void-store` wiring
 * (conversations live in memory for the process's lifetime) and no
 * StrongBox-backed vault. Tor *is* wired ([connectTor]) — that gap iOS's own
 * header still lists is closed here. See `ios/Void/AppState.swift`'s header
 * for why the remaining ones are increments, not a redesign.
 */
class AppState(private val scope: CoroutineScope) {
    val engine: Engine = Engine.create()

    var conversations by mutableStateOf<List<Engine.ContactSummary>>(emptyList())
        private set
    var messagesByFingerprint by mutableStateOf<Map<String, List<MessageItem>>>(emptyMap())
        private set
    var isOffline by mutableStateOf(true)
        private set
    var torStatus by mutableStateOf(TorStatus.NOT_STARTED)
        private set
    var protectionAcknowledged by mutableStateOf(false)
    var lastError by mutableStateOf<String?>(null)

    /** The call in progress, if any. At most one. */
    var activeCall by mutableStateOf<CallSession?>(null)

    /** Why the last call ended, in plain language, for the conversation view. */
    var lastCallSummary by mutableStateOf<String?>(null)

    /** A call waiting on the user reading the disclosure. */
    var pendingDisclosure by mutableStateOf<PendingCall?>(null)

    val fingerprintWords: String get() = engine.fingerprintWords

    private var pendingInvite: Pair<String, IntroQueue>? = null
    private var tickJob: Job? = null
    private var torHandle: TorHandle? = null

    /**
     * Bootstraps Arti and attaches the resulting circuit to [engine].
     * `stateDir`/`cacheDir` must be app-private storage (typically
     * `context.filesDir`/`context.cacheDir` subdirectories) — Arti's own
     * consensus/state database lives there, distinct from anything
     * `void-store` writes. Bootstrap runs on [Dispatchers.IO]: it blocks for
     * commonly tens of seconds, and [TorHandle.bootstrap] would freeze the
     * UI thread otherwise.
     *
     * Safe to call more than once (e.g. from an `onCreate` that can rerun) —
     * a bootstrap already in flight or complete is left alone rather than
     * opening a second circuit.
     */
    fun connectTor(stateDir: File, cacheDir: File, onionAddress: String, port: Int) {
        if (torStatus == TorStatus.BOOTSTRAPPING || torStatus == TorStatus.CONNECTED) return
        torStatus = TorStatus.BOOTSTRAPPING
        scope.launch(Dispatchers.IO) {
            stateDir.mkdirs()
            cacheDir.mkdirs()

            // The two stages fail for unrelated reasons and are caught
            // separately. Collapsing them into one "Tor unavailable" — which
            // this did — leaves a user unable to tell "this phone cannot reach
            // Tor" from "Tor is fine, the relay is down", and leaves a
            // developer with nothing to go on but a boolean. FR-TRANS-05 says
            // both outcomes queue rather than fall back, and that is unchanged;
            // what changes is that the app can now say which happened.
            val tor = try {
                TorHandle.bootstrap(stateDir.absolutePath, cacheDir.absolutePath)
            } catch (e: VoidException) {
                torStatus = TorStatus.FAILED
                lastError = "Couldn't connect to the Tor network. Messages stay on this phone."
                return@launch
            }
            torHandle = tor

            try {
                engine.attachTor(tor, onionAddress, port)
                torStatus = TorStatus.CONNECTED
                lastError = null
            } catch (e: VoidException) {
                torStatus = TorStatus.FAILED
                lastError = "Tor is working, but the relay didn't answer. Messages stay on " +
                    "this phone until it does."
            }
        }
    }

    data class MessageItem(val text: String, val isMine: Boolean, val timestampMs: Long)

    private fun nowMs(): Long = System.currentTimeMillis()

    fun startTicking() {
        tickJob?.cancel()
        tickJob = scope.launch {
            while (true) {
                tick()
                delay(2000)
            }
        }
    }

    private fun tick() {
        pendingInvite?.let { (_, queue) ->
            try {
                val data = engine.pollIntroQueue(queue)
                if (data != null) {
                    val (fp, firstMessage) = engine.acceptConversation(queue, data, nowMs())
                    appendMessage(fp, firstMessage, isMine = false)
                    pendingInvite = null
                    refreshContacts()
                }
            } catch (e: VoidException) {
                // Offline while polling is normal — keep the invite pending.
            }
        }

        when (val outcome = engine.tick(nowMs())) {
            is Engine.TickResult.Retrieved -> {
                isOffline = false
                for ((fp, text) in outcome.messages) appendMessage(fp, text, isMine = false)
            }
            Engine.TickResult.Offline -> isOffline = true
            Engine.TickResult.Deposited, Engine.TickResult.SentPadding -> isOffline = false
            else -> {}
        }

        pollCallEvents()
    }

    // --- calls ---------------------------------------------------------------
    //
    // Drained on the same tick as everything else. Polling rather than a
    // callback keeps the JNI boundary one-directional: nothing in Rust ever
    // calls into the JVM, so no thread's ownership has to be reasoned about
    // across it.

    private var callHost: CallHost? = null
    private var callAudio: CallAudio? = null

    private fun pollCallEvents() {
        for (event in engine.takeCallEvents()) {
            when (event) {
                is CallEvent.Incoming -> {
                    // The engine already refuses a second concurrent offer;
                    // this is the UI's own guard on the same rule.
                    if (activeCall != null) continue
                    activeCall = CallSession(
                        fingerprint = event.fingerprint,
                        address = event.address,
                        port = event.port,
                        phase = CallPhase.INCOMING,
                    )
                }
                is CallEvent.Answered -> {
                    val call = activeCall ?: continue
                    if (!call.fingerprint.contentEquals(event.fingerprint)) continue
                    activeCall = call.copy(phase = CallPhase.CONNECTING)
                    openMediaAsCaller()
                }
                is CallEvent.Ended -> {
                    val call = activeCall ?: continue
                    if (!call.fingerprint.contentEquals(event.fingerprint)) continue
                    finishCall(event.reason.plainLanguage)
                }
            }
        }
    }

    /**
     * Ask for the disclosure before a call connects, in either direction.
     *
     * Gating both placing *and* answering is deliberate. The costs the
     * disclosure names — that the other person learns you are online, and that
     * a call's traffic shape is nothing like messaging's — land on whoever is
     * on the call, not whoever started it. Warning only the caller would leave
     * the person answering uninformed about their own exposure.
     */
    fun requestCall(fingerprint: ByteArray, callKeyDir: File) {
        if (activeCall != null) return
        pendingDisclosure = PendingCall(fingerprint, isAnswering = false, keyDir = callKeyDir)
    }

    /** Ask for the disclosure before answering. See [requestCall]. */
    fun requestAnswer() {
        val call = activeCall ?: return
        if (call.phase != CallPhase.INCOMING) return
        pendingDisclosure = PendingCall(call.fingerprint, isAnswering = true, keyDir = null)
    }

    /** The user read the disclosure and chose to go ahead. */
    fun confirmDisclosure() {
        val pending = pendingDisclosure ?: return
        pendingDisclosure = null
        if (pending.isAnswering) {
            answerCall()
        } else {
            pending.keyDir?.let { placeCall(pending.fingerprint, it) }
        }
    }

    /**
     * The user read it and backed out. Backing out of an incoming call is a
     * decline, not a silent dismissal — the caller is told.
     */
    fun cancelDisclosure() {
        val pending = pendingDisclosure ?: return
        pendingDisclosure = null
        if (pending.isAnswering) endCall()
    }

    /**
     * Start an outgoing call: publish a service, then offer it.
     *
     * Publishing touches the network, so it runs on [Dispatchers.IO]; the
     * offer is queued the instant the address exists.
     */
    private fun placeCall(fingerprint: ByteArray, callKeyDir: File) {
        if (activeCall != null) return
        val tor = torHandle ?: run {
            lastError = "Void isn't connected yet."
            return
        }
        activeCall = CallSession(fingerprint, "", 0, CallPhase.PUBLISHING)
        scope.launch(Dispatchers.IO) {
            try {
                val dir = File(callKeyDir, "call-${System.nanoTime()}")
                val host = CallHost.publish(tor, dir.absolutePath)
                val credentials = engine.placeCall(fingerprint, host.address, VoidCore.callPort())
                callHost = host
                activeCall = activeCall?.copy(
                    credentials = credentials,
                    address = host.address,
                    phase = CallPhase.RINGING,
                )
            } catch (e: VoidException) {
                finishCall("Couldn't set up the connection.")
            }
        }
    }

    /** The callee side: answer, then dial the caller's service. */
    private fun answerCall() {
        val call = activeCall ?: return
        if (call.phase != CallPhase.INCOMING) return
        val tor = torHandle ?: return
        activeCall = call.copy(phase = CallPhase.CONNECTING)
        scope.launch(Dispatchers.IO) {
            try {
                val credentials = engine.answerCall(call.fingerprint)
                val media = engine.connectCallMedia(tor, credentials)
                if (media == 0L) {
                    finishCall("Couldn't connect.")
                    return@launch
                }
                startAudio(media)
            } catch (e: VoidException) {
                finishCall("Couldn't connect.")
            }
        }
    }

    /** The caller side, once answered: wait for them on the published service. */
    private fun openMediaAsCaller() {
        val host = callHost ?: return
        val credentials = activeCall?.credentials ?: return
        callHost = null
        scope.launch(Dispatchers.IO) {
            val media = host.accept(credentials)
            if (media == 0L) {
                finishCall("They didn't arrive.")
                return@launch
            }
            startAudio(media)
        }
    }

    private fun startAudio(mediaHandle: Long) {
        val audio = CallAudio(mediaHandle)
        // The microphone opens with the call. This is a call; muting is an
        // action the user takes, not a state they hold a button to leave.
        audio.transmitting = true
        try {
            audio.start()
        } catch (e: Exception) {
            VoidCore.callMediaFree(mediaHandle)
            finishCall("The microphone isn't available.")
            return
        }
        callAudio = audio
        activeCall = activeCall?.copy(phase = CallPhase.ACTIVE)
    }

    /** Hang up, decline, or cancel — one action from here. */
    fun endCall() {
        val call = activeCall ?: return
        val reason =
            if (call.phase == CallPhase.INCOMING) CallEndReason.DECLINED else CallEndReason.HUNG_UP
        engine.endCall(call.fingerprint, reason)
        finishCall(reason.plainLanguage)
    }

    /** Tear down local call state. Always safe to call twice. */
    private fun finishCall(summary: String) {
        callAudio?.stop()
        callAudio = null
        callHost?.close()
        callHost = null
        activeCall = null
        lastCallSummary = summary
    }

    /**
     * Whether the microphone is muted.
     *
     * Muting stops the microphone, not the emission: silence frames go out on
     * the same cadence, so a muted call and a talking one are the same shape
     * on the wire.
     */
    var isMuted: Boolean
        get() = !(callAudio?.transmitting ?: false)
        set(value) {
            callAudio?.transmitting = !value
        }

    private fun keyFor(fingerprint: ByteArray): String = fingerprint.joinToString("") { "%02x".format(it) }

    private fun appendMessage(fingerprint: ByteArray, text: String, isMine: Boolean) {
        val key = keyFor(fingerprint)
        val existing = messagesByFingerprint[key].orEmpty()
        messagesByFingerprint = messagesByFingerprint + (key to (existing + MessageItem(text, isMine, nowMs())))
    }

    private fun refreshContacts() {
        conversations = engine.contacts()
    }

    fun createInvite(): String {
        val (link, queue) = engine.createInvite(
            relayHint = "${DevRelay.ONION_ADDRESS}:${DevRelay.PORT}",
            label = "",
            now = nowMs(),
            ttlSeconds = 3600,
        )
        pendingInvite?.second?.close()
        pendingInvite = link to queue
        return link
    }

    fun startConversation(link: String, localName: String, firstMessage: String) {
        try {
            val fp = engine.startConversation(link, localName, firstMessage, nowMs())
            appendMessage(fp, firstMessage, isMine = true)
            refreshContacts()
        } catch (e: VoidException) {
            lastError = e.message
        }
    }

    fun send(fingerprint: ByteArray, text: String) {
        try {
            engine.send(fingerprint, text, nowMs())
            appendMessage(fingerprint, text, isMine = true)
        } catch (e: VoidException) {
            lastError = e.message
        }
    }

    fun handleVerificationResult(fingerprint: ByteArray, matched: Boolean) {
        try {
            if (matched) engine.markVerified(fingerprint) else engine.acknowledgeKeyChange(fingerprint)
            refreshContacts()
        } catch (e: VoidException) {
            lastError = e.message
        }
    }

    fun close() {
        tickJob?.cancel()
        pendingInvite?.second?.close()
        torHandle?.close()
        engine.close()
    }
}
