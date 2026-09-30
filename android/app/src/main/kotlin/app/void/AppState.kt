package app.void

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Bootstrap progress for the Tor circuit. */
enum class TorStatus { NOT_STARTED, BOOTSTRAPPING, CONNECTED, FAILED }

/** Where the app is: one of the screens, never more than one at a time. */
sealed class Screen {
    data object List : Screen()
    data class Conversation(val key: String) : Screen()
    data class Verification(val key: String) : Screen()
    data object NewContact : Screen()
    data object Security : Screen()
}

/** An invitation made on this device, as the "show my code" screen needs it. */
data class ShownInvite(
    val id: ByteArray,
    val link: String,
    val contactLabel: String,
    /** Records still being parked on the relay: 0 means it can be collected now. Null until known. */
    val uploadRemaining: Int? = null,
    /** Set once someone accepts it, to the name they now have here. */
    val joinedName: String? = null,
    val expired: Boolean = false,
)

/** An invitation the user opened, while it is collected and confirmed. */
data class OpenedInvite(val fetchId: ByteArray, val stage: Stage) {
    sealed class Stage {
        data object Fetching : Stage()
        class Ready(val inviterName: String, val fingerprint: ByteArray) : Stage()
        class Failed(val message: String) : Stage()
    }
}

/** One message in a conversation, as the screen renders it. */
data class MessageItem(val text: String, val isMine: Boolean, val delivery: DeliveryState, val timestampSeconds: Long)

/**
 * The one place [Engine] meets Compose state — the Kotlin mirror of
 * `ios/Void/AppState.swift`. Every screen reads from or writes through here;
 * nothing above reimplements protocol logic.
 *
 * Owned by [VoidApplication], not an activity, so rotating the screen no
 * longer destroys the engine (and, before persistence, the identity with it).
 *
 * ## The engine is the source of truth
 *
 * Contacts, their names and trust, and every message's history and delivery
 * state come from the engine's encrypted database (D-026). What is published
 * here is a copy, refreshed after each tick that changed something.
 *
 * ## Threads
 *
 * Every engine call runs on [engineDispatcher], one thread: a tick holds the
 * engine's lock while it waits on the network, so a call from the main thread
 * could freeze the app into "not responding". Compose state is written on the
 * main thread. Tor bootstrap, the relay circuit and call media run on their
 * own threads, because none of them needs the engine's lock while it waits.
 */
class AppState(
    private val context: Context,
    private val engine: Engine,
    val backing: VaultBacking,
    val fingerprintWords: String,
    private val scope: CoroutineScope,
    private val engineDispatcher: CoroutineDispatcher,
) {
    var screen by mutableStateOf<Screen>(Screen.List)

    var conversations by mutableStateOf<List<Engine.ContactSummary>>(emptyList())
        private set
    var messagesByFingerprint by mutableStateOf<Map<String, List<MessageItem>>>(emptyMap())
        private set
    var unread by mutableStateOf<Map<String, Int>>(emptyMap())
        private set
    var isOffline by mutableStateOf(true)
        private set
    var torStatus by mutableStateOf(TorStatus.NOT_STARTED)
        private set
    var protectionAcknowledged by mutableStateOf(false)
        private set
    var lastError by mutableStateOf<String?>(null)

    /** A short-lived line at the top of the screen: an invitation accepted, a call ended or missed. */
    var notice by mutableStateOf<String?>(null)
        private set

    /** The invitation the "show my code" screen is showing, if any. */
    var shownInvite by mutableStateOf<ShownInvite?>(null)
        private set

    /** The name put on invitations this user makes. Stored encrypted by the engine. */
    var inviteName by mutableStateOf("")

    /** The invitation the user is opening, if any. */
    var openedInvite by mutableStateOf<OpenedInvite?>(null)
        private set

    /** The call in progress, if any. At most one: the engine answers a second offer "busy". */
    var activeCall by mutableStateOf<CallSession?>(null)
        private set

    /** A call waiting on the user reading the disclosure. */
    var pendingDisclosure by mutableStateOf<PendingCall?>(null)
        private set

    private var tickJob: Job? = null
    private var tor: TorHandle? = null
    private var attaching = false
    private var reconnectPending = false
    private var reconnectDelayMs = 5_000L
    private var callHost: CallHost? = null
    private var callAudio: CallAudio? = null
    private var noticeJob: Job? = null

    /** Invitations whose upload progress the tick reports. Touched only on the engine thread. */
    private val watchedInvites = mutableMapOf<String, ByteArray>()

    /**
     * Contacts the user found did not match when comparing codes. The engine
     * has no state for a user's verdict — its key-changed state is for a key it
     * saw rotate — so messaging to them is paused here, for this session.
     */
    private val mismatched = mutableSetOf<String>()

    /** The conversation on screen, whose new messages are read as they arrive. */
    private var visibleConversation: String? = null

    init {
        scope.launch { loadStoredState() }
        connectTor()
        startTicking()
    }

    private suspend fun <T> onEngine(block: (Engine) -> T): T = withContext(engineDispatcher) { block(engine) }

    private suspend fun loadStoredState() {
        val contacts = onEngine { it.contacts() }
        val histories = onEngine { e -> contacts.associate { it.key to e.messages(it.fingerprint) } }
        val (acknowledged, name) = onEngine { it.protectionAcknowledged to it.inviteName }
        for ((key, history) in histories) applyHistory(key, history)
        applyContacts(contacts)
        if (acknowledged) protectionAcknowledged = true
        inviteName = name
    }

    fun finishOnboarding() {
        protectionAcknowledged = true
        scope.launch { runCatching { onEngine { it.acknowledgeProtection() } } }
    }

    fun contact(key: String): Engine.ContactSummary? = conversations.firstOrNull { it.key == key }

    fun name(key: String): String = contact(key)?.name?.ifBlank { null } ?: "Unnamed contact"

    // --- ticking (FR-MSG-06) ------------------------------------------------------

    private class TickUpdate(
        val outcome: Engine.TickResult,
        val contactEvents: List<ContactEvent>,
        val callEvents: List<CallEvent>,
        val contacts: List<Engine.ContactSummary>?,
        val histories: Map<String, List<StoredMessage>>,
        val inviteUploads: Map<String, Int?>,
    )

    /**
     * Once a second, on the engine thread. The scheduler decides what, if
     * anything, each tick sends — one frame per emission slot, whatever the
     * app does — so ticking more often only lands each slot closer to its
     * time. Invitations are collected inside the scheduler's own retrieval
     * slots (D-025); there is no separate timer for them.
     */
    private fun startTicking() {
        tickJob?.cancel()
        tickJob = scope.launch(engineDispatcher) {
            while (isActive) {
                val update = runTick()
                withContext(Dispatchers.Main) { apply(update) }
                delay(1_000)
            }
        }
    }

    /** On the engine thread. */
    private fun runTick(): TickUpdate {
        val outcome = engine.tick(System.currentTimeMillis())
        val contactEvents = engine.takeContactEvents()
        val callEvents = engine.takeCallEvents()

        val changed = mutableMapOf<String, ByteArray>()
        when (outcome) {
            is Engine.TickResult.Retrieved -> outcome.messages.forEach { (fp, _) -> changed[fp.toHex()] = fp }
            // A message may just have moved to "Sent".
            Engine.TickResult.Deposited -> engine.contacts().forEach { changed[it.key] = it.fingerprint }
            else -> {}
        }
        var contacts: List<Engine.ContactSummary>? = null
        if (contactEvents.isNotEmpty()) {
            contacts = engine.contacts()
            for (event in contactEvents) {
                when (event) {
                    is ContactEvent.Added -> {
                        changed[event.fingerprint.toHex()] = event.fingerprint
                        watchedInvites.remove(event.inviteId.toHex())
                    }
                    is ContactEvent.InviteExpired -> watchedInvites.remove(event.inviteId.toHex())
                    else -> {}
                }
            }
        }
        val histories = changed.mapValues { (_, fp) -> engine.messages(fp) }
        val uploads = watchedInvites.mapValues { (_, id) -> engine.inviteUploadRemaining(id) }
        return TickUpdate(outcome, contactEvents, callEvents, contacts, histories, uploads)
    }

    private fun apply(update: TickUpdate) {
        isOffline = update.outcome == Engine.TickResult.Offline
        if (isOffline) scheduleReconnect() else reconnectDelayMs = 5_000
        for ((key, history) in update.histories) applyHistory(key, history)
        update.contacts?.let { applyContacts(it) }
        (update.outcome as? Engine.TickResult.Retrieved)?.let { retrieved ->
            val counts = unread.toMutableMap()
            for ((fp, _) in retrieved.messages) {
                val key = fp.toHex()
                if (key != visibleConversation) counts[key] = (counts[key] ?: 0) + 1
            }
            unread = counts
        }
        shownInvite?.let { shown ->
            val key = shown.id.toHex()
            if (update.inviteUploads.containsKey(key)) {
                shownInvite = shown.copy(uploadRemaining = update.inviteUploads[key])
            }
        }
        update.contactEvents.forEach { handle(it) }
        update.callEvents.forEach { handle(it) }
    }

    private fun applyContacts(contacts: List<Engine.ContactSummary>) {
        conversations = contacts.map { c ->
            if (c.key in mismatched) Engine.ContactSummary(c.fingerprint, TrustState.KEY_CHANGED, c.name) else c
        }
    }

    private fun applyHistory(key: String, history: List<StoredMessage>) {
        messagesByFingerprint = messagesByFingerprint + (
            key to history.map { MessageItem(it.text, it.isOutgoing, it.delivery, it.timestampSeconds) }
            )
    }

    fun lastMessage(key: String): String = messagesByFingerprint[key]?.lastOrNull()?.text.orEmpty()

    fun openConversation(key: String) {
        visibleConversation = key
        unread = unread - key
        screen = Screen.Conversation(key)
    }

    fun closeConversation() {
        visibleConversation = null
        screen = Screen.List
    }

    private fun showNotice(text: String) {
        notice = text
        noticeJob?.cancel()
        noticeJob = scope.launch {
            delay(5_000)
            notice = null
        }
    }

    fun dismissNotice() {
        notice = null
    }

    // --- Tor and the relay ------------------------------------------------------------

    private fun torDirs(): Pair<File, File> =
        File(context.noBackupFilesDir, "tor-state") to File(context.cacheDir, "tor-cache")

    /** Bootstrap Arti off the main thread, then attach the relay. */
    private fun connectTor() {
        if (tor != null || torStatus == TorStatus.BOOTSTRAPPING) return
        torStatus = TorStatus.BOOTSTRAPPING
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val (state, cache) = torDirs()
                    state.mkdirs()
                    cache.mkdirs()
                    TorHandle.bootstrap(state.absolutePath, cache.absolutePath)
                }
            }
            result.onSuccess {
                tor = it
                attachRelay()
            }.onFailure {
                torStatus = TorStatus.FAILED
                scheduleReconnect()
            }
        }
    }

    /**
     * Open a circuit to the relay and give it to the engine. Not on the engine
     * thread: connecting takes seconds to minutes, and the engine's lock is
     * taken only once the circuit exists.
     */
    private fun attachRelay() {
        val tor = tor ?: return
        if (attaching) return
        attaching = true
        scope.launch {
            val attached = withContext(Dispatchers.IO) {
                runCatching { engine.attachTor(tor, RelayConfig.ONION_ADDRESS, RelayConfig.PORT) }.isSuccess
            }
            attaching = false
            if (attached) {
                torStatus = TorStatus.CONNECTED
                reconnectDelayMs = 5_000
            } else {
                torStatus = TorStatus.FAILED
                scheduleReconnect()
            }
        }
    }

    /**
     * Offline with a way back: try again, waiting twice as long each time,
     * from five seconds up to five minutes. Nothing is ever sent any other way
     * meanwhile (FR-TRANS-05); messages wait in the outbox.
     */
    private fun scheduleReconnect() {
        if (reconnectPending || attaching || torStatus == TorStatus.BOOTSTRAPPING) return
        reconnectPending = true
        val wait = reconnectDelayMs
        reconnectDelayMs = (reconnectDelayMs * 2).coerceAtMost(300_000)
        scope.launch {
            delay(wait)
            reconnectPending = false
            if (tor == null) connectTor() else if (isOffline) attachRelay()
        }
    }

    // --- invitations made here (FR-DISC-01) --------------------------------------------

    /**
     * Make an invitation for one person and show its code. [contactLabel] is
     * what they will be called here once they accept; it never leaves this
     * device. Works offline: the invitation waits in the outbox.
     */
    fun createInvite(contactLabel: String) {
        val myLabel = inviteName.trim()
        val label = contactLabel.trim()
        scope.launch {
            try {
                val created = onEngine { e ->
                    if (e.inviteName != myLabel) e.setInviteName(myLabel)
                    val created = e.createInvite(
                        relay = RelayConfig.ADDRESS,
                        myLabel = myLabel,
                        contactLabel = label,
                        now = System.currentTimeMillis() / 1000,
                        ttlSeconds = 24 * 60 * 60,
                    )
                    shownInvite?.let { watchedInvites.remove(it.id.toHex()) }
                    watchedInvites[created.id.toHex()] = created.id
                    created
                }
                shownInvite = ShownInvite(created.id, created.link, label)
            } catch (e: VoidException) {
                lastError = e.message
            }
        }
    }

    /** Stop showing the code. The invitation stays open until it expires. */
    fun dismissShownInvite() {
        val id = shownInvite?.id ?: return
        shownInvite = null
        scope.launch { onEngine { watchedInvites.remove(id.toHex()) } }
    }

    /** Withdraw the shown invitation entirely. */
    fun cancelShownInvite() {
        val id = shownInvite?.id ?: return
        shownInvite = null
        scope.launch {
            onEngine { e ->
                watchedInvites.remove(id.toHex())
                e.cancelInvite(id)
            }
        }
    }

    // --- invitations opened here ------------------------------------------------------

    /** Open a scanned or pasted link and start collecting the invitation. */
    fun openInvite(link: String) {
        val trimmed = link.trim()
        if (trimmed.isEmpty()) return
        openedInvite?.let { previous -> scope.launch { onEngine { it.cancelFetch(previous.fetchId) } } }
        scope.launch {
            try {
                val fetchId = onEngine { it.openInvite(trimmed, System.currentTimeMillis() / 1000) }
                // A full link is ready at once, and its event may already be queued.
                if (openedInvite?.fetchId?.contentEquals(fetchId) != true) {
                    openedInvite = OpenedInvite(fetchId, OpenedInvite.Stage.Fetching)
                }
            } catch (e: VoidException) {
                lastError = if (e.status == VoidStatus.BAD_ARGUMENT) "That isn't a Void invitation link." else e.message
            }
        }
    }

    /** Connect using the invitation that arrived. [name] may be empty to keep the one it carried. */
    fun confirmOpenedInvite(name: String, firstMessage: String) {
        val opened = openedInvite ?: return
        if (opened.stage !is OpenedInvite.Stage.Ready) return
        scope.launch {
            try {
                val (key, contacts, history) = onEngine { e ->
                    val fp = e.confirmInvite(opened.fetchId, name.trim(), firstMessage.trim(), System.currentTimeMillis() / 1000)
                    Triple(fp.toHex(), e.contacts(), e.messages(fp))
                }
                openedInvite = null
                applyHistory(key, history)
                applyContacts(contacts)
                screen = Screen.List
            } catch (e: VoidException) {
                openedInvite = null
                lastError = e.message
            }
        }
    }

    fun cancelOpenedInvite() {
        val opened = openedInvite ?: return
        openedInvite = null
        scope.launch { onEngine { it.cancelFetch(opened.fetchId) } }
    }

    private fun handle(event: ContactEvent) {
        when (event) {
            is ContactEvent.Added -> {
                val who = event.name.ifBlank { "Someone" }
                shownInvite?.let { if (it.id.contentEquals(event.inviteId)) shownInvite = it.copy(joinedName = who) }
                showNotice("$who accepted your invitation.")
            }
            is ContactEvent.InviteExpired -> {
                shownInvite?.let { if (it.id.contentEquals(event.inviteId)) shownInvite = it.copy(expired = true) }
            }
            is ContactEvent.InviteReady -> {
                val current = openedInvite
                if (current == null || current.fetchId.contentEquals(event.fetchId)) {
                    openedInvite = OpenedInvite(event.fetchId, OpenedInvite.Stage.Ready(event.inviterName, event.fingerprint))
                }
            }
            is ContactEvent.InviteFailed -> {
                val current = openedInvite
                if (current != null && current.fetchId.contentEquals(event.fetchId)) {
                    openedInvite = current.copy(stage = OpenedInvite.Stage.Failed(event.reason.explanation))
                }
            }
        }
    }

    // --- sending, names, verification -------------------------------------------------

    fun send(fingerprint: ByteArray, text: String) {
        val key = fingerprint.toHex()
        // Shown at once as "Waiting to send", then replaced by the stored copy.
        messagesByFingerprint = messagesByFingerprint + (
            key to (messagesByFingerprint[key].orEmpty() + MessageItem(text, true, DeliveryState.QUEUED, System.currentTimeMillis() / 1000))
            )
        scope.launch {
            try {
                val history = onEngine { e ->
                    e.send(fingerprint, text, System.currentTimeMillis() / 1000)
                    e.messages(fingerprint)
                }
                applyHistory(key, history)
            } catch (e: VoidException) {
                lastError = e.message
                applyHistory(key, onEngine { it.messages(fingerprint) })
            }
        }
    }

    /** Change the name this device shows for a contact. Never transmitted. */
    fun renameContact(fingerprint: ByteArray, name: String) {
        scope.launch {
            try {
                applyContacts(onEngine { e -> e.renameContact(fingerprint, name.trim()); e.contacts() })
            } catch (e: VoidException) {
                lastError = e.message
            }
        }
    }

    fun handleVerificationResult(fingerprint: ByteArray, matched: Boolean) {
        val key = fingerprint.toHex()
        if (!matched) {
            // See `mismatched`: the pause lasts for this session.
            mismatched.add(key)
            applyContacts(conversations)
            return
        }
        mismatched.remove(key)
        scope.launch {
            try {
                applyContacts(onEngine { e -> e.markVerified(fingerprint); e.contacts() })
            } catch (e: VoidException) {
                lastError = e.message
            }
        }
    }

    /** The user checked a changed code another way and chose to continue: "not verified", never "verified". */
    fun acknowledgeKeyChange(fingerprint: ByteArray) {
        val key = fingerprint.toHex()
        mismatched.remove(key)
        scope.launch {
            try {
                applyContacts(
                    onEngine { e ->
                        if (e.contacts().firstOrNull { it.key == key }?.trust == TrustState.KEY_CHANGED) {
                            e.acknowledgeKeyChange(fingerprint)
                        }
                        e.contacts()
                    },
                )
            } catch (e: VoidException) {
                lastError = e.message
            }
        }
    }

    // --- calls (D-024, D-028) --------------------------------------------------------
    //
    // Drained on the same tick as everything else. Polling rather than a
    // callback keeps the JNI boundary one-directional: nothing in Rust ever
    // calls into the JVM, so no thread's ownership has to be reasoned about
    // across it.

    /**
     * Ask for the disclosure before a call connects, in either direction.
     *
     * Gating both placing *and* answering is deliberate. The costs the
     * disclosure names — that the other person learns you are online, and that
     * a call's traffic shape is nothing like messaging's — land on whoever is
     * on the call, not whoever started it. Warning only the caller would leave
     * the person answering uninformed about their own exposure.
     */
    fun requestCall(fingerprint: ByteArray) {
        if (activeCall != null) return
        pendingDisclosure = PendingCall(fingerprint, isAnswering = false)
    }

    /** Ask for the disclosure before answering. See [requestCall]. */
    fun requestAnswer() {
        val call = activeCall ?: return
        if (call.phase != CallPhase.INCOMING) return
        pendingDisclosure = PendingCall(call.fingerprint, isAnswering = true)
    }

    /**
     * The user read the disclosure, chose to go ahead, and the microphone
     * permission was settled — asked for at that moment, never at launch.
     */
    fun confirmDisclosure(microphoneGranted: Boolean) {
        val pending = pendingDisclosure ?: return
        pendingDisclosure = null
        if (!microphoneGranted) {
            lastError = "Void needs the microphone for calls. You can allow it in Settings."
            if (pending.isAnswering) hangUp()
            return
        }
        if (pending.isAnswering) answerCall() else placeCall(pending.fingerprint)
    }

    /** Backing out of an incoming call is a decline, not a silent dismissal — the caller is told. */
    fun cancelDisclosure() {
        val pending = pendingDisclosure ?: return
        pendingDisclosure = null
        if (pending.isAnswering) hangUp()
    }

    /**
     * Start an outgoing call: publish a service, offer it, and wait on it.
     * Publishing touches the network, so it runs off the main thread; the
     * offer is queued the instant the address exists.
     */
    private fun placeCall(fingerprint: ByteArray) {
        if (activeCall != null) return
        val tor = tor ?: run {
            lastError = "Void isn't connected yet. Calls need the network."
            return
        }
        activeCall = CallSession(fingerprint, ByteArray(0), CallRole.CALLER, CallPhase.PUBLISHING)
        scope.launch {
            val host = withContext(Dispatchers.IO) {
                runCatching { CallHost.publish(tor, File(context.cacheDir, "call-${System.nanoTime()}").absolutePath) }
                    .getOrNull()
            }
            if (activeCall?.fingerprint?.contentEquals(fingerprint) != true) {
                host?.release()
                return@launch
            }
            if (host == null) {
                endCall(CallEndReason.FAILED, "Couldn't set up a private connection for the call.")
                return@launch
            }
            callHost = host
            try {
                val credentials = onEngine {
                    it.placeCall(fingerprint, host.address, VoidCore.callPort(), System.currentTimeMillis() / 1000)
                }
                val call = activeCall
                if (call == null || !call.fingerprint.contentEquals(fingerprint)) {
                    // Hung up while the offer was being queued. The hang-up
                    // reached the engine first and found no call, so withdraw
                    // the offer now, or they ring for nobody.
                    onEngine { it.endCall(fingerprint, CallEndReason.HUNG_UP) }
                    return@launch
                }
                activeCall = call.copy(callId = credentials.callId, phase = CallPhase.RINGING)
                waitForCallee(host, credentials, fingerprint)
            } catch (e: VoidException) {
                finishCall("Couldn't call them. ${e.message}")
            }
        }
    }

    /**
     * Accept on our service from the moment the offer is queued, not once the
     * relayed answer arrives (D-028): the callee dials the moment they answer,
     * and their first authenticated frame is the answer.
     */
    private fun waitForCallee(host: CallHost, credentials: Engine.CallCredentials, fingerprint: ByteArray) {
        scope.launch {
            val media = withContext(Dispatchers.IO) { host.accept(credentials) }
            if (activeCall?.callId?.contentEquals(credentials.callId) != true) {
                media?.let { it.close(); it.free() }
                return@launch
            }
            if (media == null) {
                // Nobody came within the answer window, or the network failed.
                // A hang-up would already have cleared the call.
                endCall(CallEndReason.FAILED, "The call couldn't connect.")
                return@launch
            }
            activeCall = activeCall?.copy(phase = CallPhase.CONNECTING)
            startAudio(media, fingerprint, credentials.callId, CallRole.CALLER)
        }
    }

    /** The callee side: answer, then dial the caller's service. */
    private fun answerCall() {
        val call = activeCall ?: return
        if (call.phase != CallPhase.INCOMING) return
        val tor = tor ?: run {
            endCall(CallEndReason.FAILED, "Void isn't connected, so it couldn't answer.")
            return
        }
        activeCall = call.copy(phase = CallPhase.CONNECTING)
        scope.launch {
            try {
                val credentials = onEngine { it.answerCall(call.fingerprint) }
                val media = withContext(Dispatchers.IO) { CallMedia.connect(tor, credentials) }
                if (activeCall?.callId?.contentEquals(credentials.callId) != true) {
                    media?.let { it.close(); it.free() }
                    return@launch
                }
                if (media == null) {
                    endCall(CallEndReason.FAILED, "Couldn't connect to them.")
                    return@launch
                }
                startAudio(media, call.fingerprint, credentials.callId, CallRole.CALLEE)
            } catch (e: VoidException) {
                endCall(CallEndReason.FAILED, "Couldn't answer. ${e.message}")
            }
        }
    }

    private fun startAudio(media: CallMedia, fingerprint: ByteArray, callId: ByteArray, role: CallRole) {
        val audio = CallAudio(context, media)
        audio.onConnected = { scope.launch { mediaConnected(callId, fingerprint, role) } }
        audio.onDropped = { connectionClosed -> scope.launch { mediaDropped(callId, connectionClosed) } }
        try {
            audio.start()
        } catch (e: Exception) {
            audio.stop()
            endCall(CallEndReason.FAILED, "The microphone isn't available.")
            return
        }
        callAudio = audio
        // Keeps the microphone working when the screen locks or the user
        // switches apps, as a phone call does.
        CallService.start(context)
    }

    /** The first authenticated frame arrived. For the caller that is the answer. */
    private fun mediaConnected(callId: ByteArray, fingerprint: ByteArray, role: CallRole) {
        val call = activeCall ?: return
        if (!call.callId.contentEquals(callId)) return
        activeCall = call.copy(phase = CallPhase.ACTIVE)
        if (role == CallRole.CALLER) scope.launch { onEngine { it.markCallConnected(fingerprint) } }
    }

    /**
     * The media connection is over. A closed connection is almost always the
     * other end hanging up — theirs reaches the relay seconds later — so it
     * reads as one. A stall is what "dropped" means.
     */
    private fun mediaDropped(callId: ByteArray, connectionClosed: Boolean) {
        if (activeCall?.callId?.contentEquals(callId) != true) return
        if (connectionClosed) {
            endCall(CallEndReason.HUNG_UP, "Call ended.")
        } else {
            endCall(CallEndReason.FAILED, "The connection dropped.")
        }
    }

    private fun handle(event: CallEvent) {
        when (event) {
            is CallEvent.Incoming -> {
                // The engine already answers a second offer "busy"; this is
                // the UI's own guard on the same rule.
                if (activeCall != null) return
                activeCall = CallSession(event.fingerprint, event.callId, CallRole.CALLEE, CallPhase.INCOMING)
            }
            is CallEvent.Answered -> {
                // Usually the callee's media got here first and the call is
                // already active; the relayed answer then changes nothing.
                val call = activeCall ?: return
                if (call.callId.contentEquals(event.callId) && call.phase == CallPhase.RINGING) {
                    activeCall = call.copy(phase = CallPhase.CONNECTING)
                }
            }
            is CallEvent.Ended -> {
                if (activeCall?.callId?.contentEquals(event.callId) == true) finishCall(event.reason.plainLanguage)
            }
            is CallEvent.Missed -> showNotice("Missed call from ${name(event.fingerprint.toHex())}.")
        }
    }

    /** Hang up, decline, or cancel — the one button the call screens have. */
    fun hangUp() {
        val call = activeCall ?: return
        val reason = if (call.phase == CallPhase.INCOMING) CallEndReason.DECLINED else CallEndReason.HUNG_UP
        endCall(reason, if (reason == CallEndReason.DECLINED) "Declined." else "Call ended.")
    }

    /** Tell the engine, then tear down. The engine clears its own state whether or not the signal gets out. */
    private fun endCall(reason: CallEndReason, summary: String) {
        val call = activeCall ?: return
        scope.launch { onEngine { it.endCall(call.fingerprint, reason) } }
        finishCall(summary)
    }

    /** Tear down local call state. Always safe to call twice. */
    private fun finishCall(summary: String) {
        callAudio?.stop()
        callAudio = null
        callHost?.release()
        callHost = null
        activeCall = null
        isMuted = false
        CallService.stop(context)
        showNotice(summary)
    }

    /**
     * Whether the microphone is muted.
     *
     * Muting stops the microphone, not the emission: silence frames go out on
     * the same cadence, so a muted call and a talking one are the same shape
     * on the wire.
     */
    var isMuted by mutableStateOf(false)
        private set

    fun mute(muted: Boolean) {
        isMuted = muted
        callAudio?.muted = muted
    }
}
