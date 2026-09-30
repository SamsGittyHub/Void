//  AppState.swift
//
//  The one place `VoidCore` meets SwiftUI state. Every screen in this app
//  reads from or writes through here — nothing below reimplements protocol
//  logic, and nothing above reaches into `VoidCore` directly except this
//  file, so there is exactly one place that has to get the FFI calling
//  convention right.
//
//  ## The engine is the source of truth
//
//  Contacts, their names and trust, and every message's history and delivery
//  state come from the engine's encrypted database (D-026), which survives
//  restarts. What is published here is a copy for the screens, refreshed after
//  each tick that changed something.
//
//  ## Threads
//
//  Engine calls go through `CoreQueue`, never the main thread: a tick holds
//  the engine's lock while it waits on the network. Tor bootstrap, the relay
//  circuit, and call media run on their own threads, because none of them
//  needs the engine's lock while it waits.
//
//  ## What this does not yet do
//
//  - There is no lock screen, so the duress PIN (`KeyVault.destroy` followed
//    by `VoidCore.duressDestroy`) is not reachable from the interface yet.
//  - Ticks run only while the app is in the foreground; iOS suspends it
//    otherwise (see D-015 on what that means for cover traffic).

import Foundation
import SwiftUI

/// Bootstrap progress for the Tor circuit.
enum TorStatus {
    case notStarted
    case bootstrapping
    case connected
    case failed
}

/// An invitation made on this device, as the "show my code" screen needs it.
struct ShownInvite: Equatable {
    let id: Data
    let link: String
    let contactLabel: String
    /// Records still being parked on the relay: 0 means whoever opens the link
    /// can collect it now. `nil` until the first tick reports.
    var uploadRemaining: Int?
    /// Set once someone accepts it, to the name they now have here.
    var joinedName: String?
    var expired = false
}

/// An invitation the user opened, while it is collected and confirmed.
struct OpenedInvite: Equatable {
    enum Stage: Equatable {
        case fetching
        case ready(inviterName: String, fingerprint: Data)
        case failed(String)
    }

    let fetchId: Data
    var stage: Stage
}

@MainActor
final class AppState: ObservableObject {
    @Published var conversations: [ConversationSummary] = []
    @Published var messagesByFingerprint: [Data: [MessageItem]] = [:]
    @Published private(set) var isOffline = true
    @Published private(set) var torStatus: TorStatus = .notStarted
    @Published private(set) var protectionAcknowledged = false
    @Published var lastError: String?
    /// A short-lived line at the top of the screen: someone accepted an
    /// invitation, a call ended, a call was missed.
    @Published var notice: String?
    @Published var showingNewContact = false

    /// The invitation the "show my code" screen is showing, if any.
    @Published private(set) var shownInvite: ShownInvite?
    /// The name put on invitations this user makes. Stored encrypted by the
    /// engine; empty until they choose one.
    @Published var inviteName = ""
    /// The invitation the user is opening, if any.
    @Published private(set) var openedInvite: OpenedInvite?

    /// The call in progress, if any. At most one: the engine answers a second
    /// offer with "busy".
    @Published private(set) var activeCall: CallSession?
    /// A call waiting on the user reading the disclosure.
    @Published var pendingDisclosure: PendingCall?

    /// Which direction the pending call goes, so the disclosure can say so.
    enum PendingCall: Equatable {
        case placing(Data)
        case answering(Data)

        var isAnswering: Bool {
            if case .answering = self { return true }
            return false
        }

        var fingerprint: Data {
            switch self {
            case .placing(let fp), .answering(let fp): return fp
            }
        }
    }

    let backing: VaultBacking
    let fingerprintWords: String

    private let worker: CoreQueue
    private var tickTimer: DispatchSourceTimer?
    private let watchedInvites = WatchedInvites()

    private var tor: TorClient?
    private var attaching = false
    private var reconnectPending = false
    private var reconnectDelay: TimeInterval = 5

    private var callHost: CallHost?
    private var callAudio: CallAudio?

    /// Contacts the user found did not match when comparing codes. The engine
    /// has no state for a user's verdict — its key-changed state is for a key
    /// it saw rotate — so messaging to them is paused here, for this session.
    private var mismatched: Set<Data> = []

    private var noticeTask: Task<Void, Never>?

    /// The conversation on screen, whose new messages are read as they arrive.
    private var visibleConversation: Data?

    init(core: VoidCore, backing: VaultBacking, fingerprintWords: String) {
        worker = CoreQueue(core: core)
        self.backing = backing
        self.fingerprintWords = fingerprintWords
        // UI tests need to reach the screen under test without re-proving the
        // onboarding flow's own scroll/toggle gating on every run — that
        // gating is ProtectionScreen/DeviceLossScreen's job to get right, not
        // every test's job to fight through.
        if ProcessInfo.processInfo.arguments.contains("-uiTestsSkipOnboarding") {
            protectionAcknowledged = true
        }
        Task { await loadStoredState() }
        connectTor()
        startTicking()
    }

    deinit {
        tickTimer?.cancel()
    }

    private func loadStoredState() async {
        let stored = await worker.run { core -> ([VoidCore.ContactSummary], [Data: [StoredMessage]], Bool, String) in
            let contacts = core.contacts
            var histories: [Data: [StoredMessage]] = [:]
            for contact in contacts {
                histories[contact.fingerprint] = core.messages(with: contact.fingerprint)
            }
            return (contacts, histories, core.protectionAcknowledged, core.inviteName)
        }
        for (fingerprint, history) in stored.1 {
            applyHistory(history, for: fingerprint)
        }
        applyContacts(stored.0)
        if stored.2 {
            protectionAcknowledged = true
        }
        inviteName = stored.3
    }

    func finishOnboarding() {
        protectionAcknowledged = true
        Task { _ = try? await worker.attempt { try $0.acknowledgeProtection() } }
    }

    // MARK: Ticking (FR-MSG-06)

    /// Once a second, on the core queue. The scheduler decides what, if
    /// anything, each tick sends — one frame per emission slot, whatever the
    /// app does — so ticking more often only lands each slot closer to its
    /// time. Invitations are collected inside the scheduler's own retrieval
    /// slots (D-025); there is no separate timer for them.
    private func startTicking() {
        let watched = watchedInvites
        tickTimer = worker.makeTimer(every: .seconds(1)) { [weak self] core in
            let outcome = core.tick(nowMs: Clock.nowMs)
            let contactEvents = core.takeContactEvents()
            let callEvents = core.takeCallEvents()

            var changed = Set<Data>()
            switch outcome {
            case .retrieved(let messages):
                changed.formUnion(messages.map(\.fingerprint))
            case .deposited:
                // A message may just have moved to "Sent".
                changed.formUnion(core.contacts.map(\.fingerprint))
            default:
                break
            }
            var contacts: [VoidCore.ContactSummary]?
            if !contactEvents.isEmpty {
                contacts = core.contacts
                for case .added(_, let fingerprint, _, _) in contactEvents {
                    changed.insert(fingerprint)
                }
            }
            var histories: [Data: [StoredMessage]] = [:]
            for fingerprint in changed {
                histories[fingerprint] = core.messages(with: fingerprint)
            }
            var uploads: [Data: Int?] = [:]
            for id in watched.ids {
                uploads[id] = core.inviteUploadRemaining(id)
            }
            let update = TickUpdate(
                outcome: outcome,
                contactEvents: contactEvents,
                callEvents: callEvents,
                contacts: contacts,
                histories: histories,
                inviteUploads: uploads
            )
            Task { @MainActor in self?.apply(update) }
        }
    }

    private struct TickUpdate {
        let outcome: VoidCore.TickResult
        let contactEvents: [ContactEvent]
        let callEvents: [CallEvent]
        let contacts: [VoidCore.ContactSummary]?
        let histories: [Data: [StoredMessage]]
        let inviteUploads: [Data: Int?]
    }

    private func apply(_ update: TickUpdate) {
        isOffline = update.outcome == .offline
        if isOffline {
            scheduleReconnect()
        } else {
            reconnectDelay = 5
        }
        for (fingerprint, history) in update.histories {
            applyHistory(history, for: fingerprint)
        }
        if let contacts = update.contacts {
            applyContacts(contacts)
        }
        if case .retrieved(let messages) = update.outcome {
            for message in messages where message.fingerprint != visibleConversation {
                if let index = conversations.firstIndex(where: { $0.id == message.fingerprint }) {
                    conversations[index].unread += 1
                }
            }
        }
        for (id, remaining) in update.inviteUploads where shownInvite?.id == id {
            shownInvite?.uploadRemaining = remaining
        }
        for event in update.contactEvents {
            handle(event)
        }
        for event in update.callEvents {
            handle(event)
        }
    }

    private func applyContacts(_ contacts: [VoidCore.ContactSummary]) {
        conversations = contacts.map { contact in
            let existing = conversations.first { $0.id == contact.fingerprint }
            return ConversationSummary(
                id: contact.fingerprint,
                name: contact.name,
                trust: mismatched.contains(contact.fingerprint) ? .keyChanged : contact.trust,
                lastMessage: messagesByFingerprint[contact.fingerprint]?.last?.text
                    ?? existing?.lastMessage ?? "",
                unread: existing?.unread ?? 0
            )
        }
    }

    private func applyHistory(_ history: [StoredMessage], for fingerprint: Data) {
        messagesByFingerprint[fingerprint] = history.enumerated().map { index, message in
            MessageItem(
                id: UInt64(index),
                text: message.text,
                isOutgoing: message.isOutgoing,
                delivery: message.delivery,
                timestamp: message.timestamp
            )
        }
        if let index = conversations.firstIndex(where: { $0.id == fingerprint }),
            let last = history.last
        {
            conversations[index].lastMessage = last.text
        }
    }

    private func refreshContacts() async {
        applyContacts(await worker.run { $0.contacts })
    }

    func openConversation(_ fingerprint: Data) {
        visibleConversation = fingerprint
        if let index = conversations.firstIndex(where: { $0.id == fingerprint }) {
            conversations[index].unread = 0
        }
    }

    func closeConversation(_ fingerprint: Data) {
        if visibleConversation == fingerprint {
            visibleConversation = nil
        }
    }

    private func show(notice text: String) {
        notice = text
        noticeTask?.cancel()
        noticeTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            guard !Task.isCancelled else { return }
            self?.notice = nil
        }
    }

    private func name(of fingerprint: Data) -> String {
        let name = conversations.first { $0.id == fingerprint }?.name ?? ""
        return name.isEmpty ? "Unnamed contact" : name
    }

    // MARK: Tor and the relay

    /// Bootstrap Arti off the main thread, then attach the relay.
    private func connectTor() {
        guard tor == nil, torStatus != .bootstrapping else { return }
        torStatus = .bootstrapping
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result = Result {
                try TorClient(
                    stateDirectory: AppDirectories.torState(),
                    cacheDirectory: AppDirectories.torCache()
                )
            }
            Task { @MainActor in self?.torBootstrapped(result) }
        }
    }

    private func torBootstrapped(_ result: Result<TorClient, Error>) {
        switch result {
        case .success(let client):
            tor = client
            attachRelay()
        case .failure:
            torStatus = .failed
            scheduleReconnect()
        }
    }

    /// Open a circuit to the relay and give it to the engine. Not on the core
    /// queue: connecting takes seconds to minutes, and the engine's lock is
    /// taken only once the circuit exists.
    private func attachRelay() {
        guard let tor, !attaching else { return }
        attaching = true
        let core = worker.core
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let attached =
                (try? core.attachTor(tor, onionAddress: RelayConfig.onionAddress, port: RelayConfig.port))
                != nil
            Task { @MainActor in self?.relayAttached(attached) }
        }
    }

    private func relayAttached(_ attached: Bool) {
        attaching = false
        if attached {
            torStatus = .connected
            reconnectDelay = 5
        } else {
            torStatus = .failed
            scheduleReconnect()
        }
    }

    /// Offline with a way back: try again, waiting twice as long each time,
    /// from five seconds up to five minutes. Nothing is ever sent any other way
    /// meanwhile (FR-TRANS-05); messages wait in the outbox.
    private func scheduleReconnect() {
        guard !reconnectPending, !attaching, torStatus != .bootstrapping else { return }
        reconnectPending = true
        let delay = reconnectDelay
        reconnectDelay = min(reconnectDelay * 2, 300)
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard let self else { return }
            self.reconnectPending = false
            if self.tor == nil {
                self.connectTor()
            } else if self.isOffline {
                self.attachRelay()
            }
        }
    }

    // MARK: Invitations made here (FR-DISC-01)

    /// Make an invitation for one person and show its code. `contactLabel` is
    /// what they will be called here once they accept; it never leaves this
    /// device. Works offline: the invitation waits in the outbox until the
    /// relay is reachable, and the screen says so.
    func createInvite(for contactLabel: String) {
        let myLabel = inviteName.trimmingCharacters(in: .whitespacesAndNewlines)
        let label = contactLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            do {
                let created = try await worker.attempt { core -> (link: String, id: Data) in
                    if core.inviteName != myLabel {
                        try core.setInviteName(myLabel)
                    }
                    return try core.createInvite(
                        relay: RelayConfig.address,
                        myLabel: myLabel,
                        contactLabel: label,
                        now: Clock.nowSeconds,
                        ttlSeconds: 24 * 60 * 60
                    )
                }
                if let previous = shownInvite?.id {
                    watchedInvites.remove(previous)
                }
                watchedInvites.insert(created.id)
                shownInvite = ShownInvite(id: created.id, link: created.link, contactLabel: label)
            } catch {
                lastError = error.localizedDescription
            }
        }
    }

    /// Stop showing the code. The invitation stays open: whoever it was given
    /// to can still accept it until it expires.
    func dismissShownInvite() {
        if let id = shownInvite?.id {
            watchedInvites.remove(id)
        }
        shownInvite = nil
    }

    /// Withdraw the shown invitation entirely.
    func cancelShownInvite() {
        guard let id = shownInvite?.id else { return }
        dismissShownInvite()
        Task { _ = await worker.run { $0.cancelInvite(id) } }
    }

    // MARK: Invitations opened here

    /// Open a scanned or pasted link and start collecting the invitation.
    func openInvite(_ link: String) {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if let previous = openedInvite?.fetchId {
            Task { _ = await worker.run { $0.cancelFetch(previous) } }
        }
        Task {
            do {
                let fetchId = try await worker.attempt {
                    try $0.openInvite(link: trimmed, now: Clock.nowSeconds)
                }
                // A full link is ready at once; its ready event may already be
                // queued, so do not overwrite a stage it has set.
                if openedInvite?.fetchId != fetchId {
                    openedInvite = OpenedInvite(fetchId: fetchId, stage: .fetching)
                }
            } catch VoidError.badArgument {
                lastError = "That isn't a Void invitation link."
            } catch {
                lastError = error.localizedDescription
            }
        }
    }

    /// Connect using the invitation that arrived. `name` may be empty to keep
    /// the one it carried; `firstMessage` may be empty.
    func confirmOpenedInvite(name: String, firstMessage: String) {
        guard let opened = openedInvite, case .ready = opened.stage else { return }
        let localName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let message = firstMessage.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            do {
                let (fingerprint, contacts, history) = try await worker.attempt {
                    core -> (Data, [VoidCore.ContactSummary], [StoredMessage]) in
                    let fingerprint = try core.confirmInvite(
                        fetchId: opened.fetchId,
                        localName: localName,
                        firstMessage: message,
                        now: Clock.nowSeconds
                    )
                    return (fingerprint, core.contacts, core.messages(with: fingerprint))
                }
                openedInvite = nil
                applyHistory(history, for: fingerprint)
                applyContacts(contacts)
                showingNewContact = false
            } catch {
                openedInvite = nil
                lastError = error.localizedDescription
            }
        }
    }

    func cancelOpenedInvite() {
        guard let id = openedInvite?.fetchId else { return }
        openedInvite = nil
        Task { _ = await worker.run { $0.cancelFetch(id) } }
    }

    private func handle(_ event: ContactEvent) {
        switch event {
        case .added(let inviteId, _, let name, _):
            watchedInvites.remove(inviteId)
            let who = name.isEmpty ? "Someone" : name
            if shownInvite?.id == inviteId {
                shownInvite?.joinedName = who
            }
            show(notice: "\(who) accepted your invitation.")
        case .inviteExpired(let inviteId):
            watchedInvites.remove(inviteId)
            if shownInvite?.id == inviteId {
                shownInvite?.expired = true
            }
        case .inviteReady(let fetchId, let fingerprint, let inviterName):
            if openedInvite?.fetchId == fetchId || openedInvite == nil {
                openedInvite = OpenedInvite(
                    fetchId: fetchId, stage: .ready(inviterName: inviterName, fingerprint: fingerprint))
            }
        case .inviteFailed(let fetchId, let reason):
            if openedInvite?.fetchId == fetchId {
                openedInvite?.stage = .failed(reason.explanation)
            }
        }
    }

    // MARK: Sending

    func send(to fingerprint: Data, text: String) {
        // Shown at once as "Waiting to send", then replaced by the stored copy.
        var items = messagesByFingerprint[fingerprint] ?? []
        items.append(
            MessageItem(
                id: UInt64.max - UInt64(items.count),
                text: text,
                isOutgoing: true,
                delivery: .queued,
                timestamp: Date()
            ))
        messagesByFingerprint[fingerprint] = items
        Task {
            do {
                let history = try await worker.attempt { core -> [StoredMessage] in
                    try core.send(to: fingerprint, text: text, now: Clock.nowSeconds)
                    return core.messages(with: fingerprint)
                }
                applyHistory(history, for: fingerprint)
            } catch {
                lastError = error.localizedDescription
                applyHistory(await worker.run { $0.messages(with: fingerprint) }, for: fingerprint)
            }
        }
    }

    // MARK: Contacts

    /// Change the name this device shows for a contact. Never transmitted.
    func renameContact(_ fingerprint: Data, to name: String) {
        Task {
            do {
                let contacts = try await worker.attempt { core -> [VoidCore.ContactSummary] in
                    try core.renameContact(fingerprint, to: name)
                    return core.contacts
                }
                applyContacts(contacts)
            } catch {
                lastError = error.localizedDescription
            }
        }
    }

    // MARK: Verification (FR-DISC-04, FR-DISC-05)

    func handleVerificationResult(fingerprint: Data, matched: Bool) {
        guard matched else {
            // See `mismatched`: the pause lasts for this session.
            mismatched.insert(fingerprint)
            if let index = conversations.firstIndex(where: { $0.id == fingerprint }) {
                conversations[index].trust = .keyChanged
            }
            return
        }
        mismatched.remove(fingerprint)
        Task {
            do {
                let contacts = try await worker.attempt { core -> [VoidCore.ContactSummary] in
                    try core.markVerified(fingerprint)
                    return core.contacts
                }
                applyContacts(contacts)
            } catch {
                lastError = error.localizedDescription
            }
        }
    }

    /// The user checked a changed code another way and chose to continue. Drops
    /// to "not verified", never straight to "verified".
    func acknowledgeKeyChange(fingerprint: Data) {
        mismatched.remove(fingerprint)
        Task {
            do {
                let contacts = try await worker.attempt { core -> [VoidCore.ContactSummary] in
                    if core.contacts.first(where: { $0.fingerprint == fingerprint })?.trust == .keyChanged {
                        try core.acknowledgeKeyChange(fingerprint)
                    }
                    return core.contacts
                }
                applyContacts(contacts)
            } catch {
                lastError = error.localizedDescription
            }
        }
    }

    // MARK: Calls (D-024, D-028)

    /// Ask for the disclosure before a call connects, in either direction.
    ///
    /// Gating both placing *and* answering is deliberate. The costs the
    /// disclosure names — that the other person learns you are online, and that
    /// a call's traffic shape is nothing like messaging's — land on whoever is
    /// on the call, not on whoever started it. Warning only the caller would
    /// leave the person who answers uninformed about their own exposure.
    func requestCall(to fingerprint: Data) {
        guard activeCall == nil else { return }
        pendingDisclosure = .placing(fingerprint)
    }

    /// Ask for the disclosure before answering. See `requestCall`.
    func requestAnswer() {
        guard let call = activeCall, call.phase == .incoming else { return }
        pendingDisclosure = .answering(call.fingerprint)
    }

    /// The user read the disclosure and chose to go ahead. The microphone is
    /// asked for here — the moment they chose to talk — and not at launch.
    func confirmDisclosure() {
        guard let pending = pendingDisclosure else { return }
        pendingDisclosure = nil
        CallAudio.requestMicrophone { [weak self] granted in
            guard let self else { return }
            guard granted else {
                self.lastError = "Void needs the microphone for calls. You can allow it in Settings."
                if pending.isAnswering {
                    self.hangUp()
                }
                return
            }
            switch pending {
            case .placing(let fingerprint): self.placeCall(to: fingerprint)
            case .answering: self.answerCall()
            }
        }
    }

    /// The user read it and backed out. Declining an incoming call here is a
    /// decline, not a silent dismissal — the caller is told.
    func cancelDisclosure() {
        guard let pending = pendingDisclosure else { return }
        pendingDisclosure = nil
        if pending.isAnswering {
            hangUp()
        }
    }

    /// Start an outgoing call: publish a service, offer it, and wait on it.
    ///
    /// The service is published off the main thread because it talks to the
    /// network, and the offer is queued the moment the address exists — the
    /// descriptor finishes uploading while the offer travels.
    private func placeCall(to fingerprint: Data) {
        guard activeCall == nil else { return }
        guard let tor else {
            lastError = "Void isn't connected yet. Calls need the network."
            return
        }
        activeCall = CallSession(fingerprint: fingerprint, callId: Data(), role: .caller, phase: .publishing)
        let worker = self.worker
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let host = CallHost(tor: tor, keyDirectory: AppDirectories.callKeys())
            Task { @MainActor in
                guard let self, self.activeCall?.fingerprint == fingerprint else { return }
                guard let host else {
                    self.endCall(reason: .failed, summary: "Couldn't set up a private connection for the call.")
                    return
                }
                self.callHost = host
                do {
                    let placed = try await worker.attempt {
                        try $0.placeCall(
                            to: fingerprint, address: host.address, port: VoidCore.callPort,
                            now: Clock.nowSeconds)
                    }
                    guard var call = self.activeCall, call.fingerprint == fingerprint else {
                        // Hung up while the offer was being queued. The hang-up
                        // reached the engine first and found no call, so
                        // withdraw the offer now, or they ring for nobody.
                        _ = try? await worker.attempt { try $0.endCall(with: fingerprint, reason: .hungUp) }
                        return
                    }
                    call.callId = placed.callId
                    call.phase = .ringing
                    self.activeCall = call
                    self.waitForCallee(host: host, placed: placed, fingerprint: fingerprint)
                } catch {
                    self.finishCall(summary: "Couldn't call them. \(error.localizedDescription)")
                }
            }
        }
    }

    /// Accept on our service from the moment the offer is queued, not once the
    /// relayed answer arrives (D-028): the callee dials the moment they
    /// answer, and their first authenticated frame is the answer.
    private func waitForCallee(host: CallHost, placed: (callId: Data, mediaSecret: Data), fingerprint: Data) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let media = host.accept(mediaSecret: placed.mediaSecret, callId: placed.callId)
            Task { @MainActor in
                guard let self, self.activeCall?.callId == placed.callId else {
                    media?.close()
                    return
                }
                guard let media else {
                    // Nobody came within the answer window, or the network
                    // failed. A hang-up would already have cleared the call.
                    self.endCall(reason: .failed, summary: "The call couldn't connect.")
                    return
                }
                self.activeCall?.phase = .connecting
                self.startAudio(media, fingerprint: fingerprint, callId: placed.callId, role: .caller)
            }
        }
    }

    /// The callee side: answer, then dial the caller's service.
    private func answerCall() {
        guard var call = activeCall, call.phase == .incoming else { return }
        guard let tor else {
            endCall(reason: .failed, summary: "Void isn't connected, so it couldn't answer.")
            return
        }
        call.phase = .connecting
        activeCall = call
        let fingerprint = call.fingerprint
        Task { [weak self, worker] in
            do {
                let answered = try await worker.attempt { try $0.answerCall(from: fingerprint) }
                DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                    let media = CallMedia.connect(
                        tor: tor,
                        address: answered.address,
                        port: answered.port,
                        mediaSecret: answered.mediaSecret,
                        callId: answered.callId
                    )
                    Task { @MainActor in
                        guard let self, self.activeCall?.callId == answered.callId else {
                            media?.close()
                            return
                        }
                        guard let media else {
                            self.endCall(reason: .failed, summary: "Couldn't connect to them.")
                            return
                        }
                        self.startAudio(media, fingerprint: fingerprint, callId: answered.callId, role: .callee)
                    }
                }
            } catch {
                self?.endCall(reason: .failed, summary: "Couldn't answer. \(error.localizedDescription)")
            }
        }
    }

    private func startAudio(_ media: CallMedia, fingerprint: Data, callId: Data, role: CallRole) {
        let audio: CallAudio
        do {
            audio = try CallAudio(media: media)
        } catch {
            media.close()
            endCall(reason: .failed, summary: "Audio couldn't start.")
            return
        }
        audio.onConnected = { [weak self] in
            Task { @MainActor in self?.mediaConnected(callId: callId, fingerprint: fingerprint, role: role) }
        }
        audio.onDropped = { [weak self] connectionClosed in
            Task { @MainActor in self?.mediaDropped(callId: callId, connectionClosed: connectionClosed) }
        }
        do {
            try audio.start()
        } catch {
            audio.stop()
            endCall(reason: .failed, summary: "The microphone isn't available.")
            return
        }
        callAudio = audio
    }

    /// The first authenticated frame arrived. For the caller that is the
    /// answer: the ring stops now, not a mailbox delay later.
    private func mediaConnected(callId: Data, fingerprint: Data, role: CallRole) {
        guard var call = activeCall, call.callId == callId else { return }
        call.phase = .active
        activeCall = call
        if role == .caller {
            Task { _ = await worker.run { $0.markCallConnected(fingerprint) } }
        }
    }

    /// The media connection is over. A closed connection is almost always the
    /// other end hanging up — theirs reaches the relay seconds later — so it
    /// reads as one. A stall is what "dropped" means.
    private func mediaDropped(callId: Data, connectionClosed: Bool) {
        guard activeCall?.callId == callId else { return }
        if connectionClosed {
            endCall(reason: .hungUp, summary: "Call ended.")
        } else {
            endCall(reason: .failed, summary: "The connection dropped.")
        }
    }

    private func handle(_ event: CallEvent) {
        switch event {
        case .incoming(let fingerprint, let callId, _, _):
            // The engine already answers a second offer "busy"; this is the
            // UI's own guard on the same rule.
            guard activeCall == nil else { break }
            activeCall = CallSession(fingerprint: fingerprint, callId: callId, role: .callee, phase: .incoming)
        case .answered(_, let callId):
            // Usually the callee's media got here first and the call is already
            // active; the relayed answer then changes nothing.
            guard var call = activeCall, call.callId == callId, call.phase == .ringing else { break }
            call.phase = .connecting
            activeCall = call
        case .ended(_, let callId, let reason):
            guard activeCall?.callId == callId else { break }
            finishCall(summary: Self.plainLanguage(for: reason))
        case .missed(let fingerprint, _):
            show(notice: "Missed call from \(name(of: fingerprint)).")
        }
    }

    /// Plain language, per FR-UI-03. No status codes shown to a person.
    private static func plainLanguage(for reason: CallEndReason) -> String {
        switch reason {
        case .hungUp: return "Call ended."
        case .declined: return "They declined."
        case .missed: return "No answer."
        case .failed: return "The connection didn't hold."
        case .busy: return "They're on another call."
        }
    }

    /// Hang up, decline, or cancel — the one button the call screens have.
    func hangUp() {
        guard let call = activeCall else { return }
        let reason: CallEndReason = call.phase == .incoming ? .declined : .hungUp
        endCall(reason: reason, summary: reason == .declined ? "Declined." : "Call ended.")
    }

    /// Tell the engine, then tear down. The engine clears its own call state
    /// whether or not the signal gets out.
    private func endCall(reason: CallEndReason, summary: String) {
        guard let call = activeCall else { return }
        let fingerprint = call.fingerprint
        Task { _ = try? await worker.attempt { try $0.endCall(with: fingerprint, reason: reason) } }
        finishCall(summary: summary)
    }

    /// Tear down local call state. Always safe to call twice.
    private func finishCall(summary: String) {
        callAudio?.stop()
        callAudio = nil
        callHost?.cancel()
        callHost = nil
        activeCall = nil
        show(notice: summary)
    }

    /// Whether the microphone is muted.
    ///
    /// Muting stops the microphone, not the emission: silence frames go out on
    /// the same cadence, so a muted call and a talking one are the same shape
    /// on the wire.
    var isMuted: Bool {
        get { callAudio?.isMuted ?? false }
        set {
            objectWillChange.send()
            callAudio?.isMuted = newValue
        }
    }
}

/// The ids of invitations whose upload progress the tick should report. Read
/// on the core queue, written on the main thread.
private final class WatchedInvites: @unchecked Sendable {
    private let lock = NSLock()
    private var set: Set<Data> = []

    var ids: Set<Data> {
        lock.lock()
        defer { lock.unlock() }
        return set
    }

    func insert(_ id: Data) {
        lock.lock()
        set.insert(id)
        lock.unlock()
    }

    func remove(_ id: Data) {
        lock.lock()
        set.remove(id)
        lock.unlock()
    }
}
