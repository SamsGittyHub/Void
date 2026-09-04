//  AppState.swift
//
//  The one place `VoidCore` meets SwiftUI state. Every screen in this app
//  reads from or writes through here — nothing below reimplements protocol
//  logic, and nothing above reaches into `VoidCore` directly except this
//  file, so there is exactly one place that has to get the FFI calling
//  convention right.
//
//  ## What this does not yet do
//
//  - No `void-store` wiring: conversations live in memory for the process's
//    lifetime, not across relaunches. `Engine::new_persisted` exists on the
//    Rust side; giving this app a data directory and calling it is the next
//    increment, not a redesign.
//  - No Tor: `VoidCore` starts on the engine's default `NullTransport`
//    (reports Tor-acceptable, carries nothing — see `void_engine_new`'s
//    docs), so every send queues until `void_engine_attach_tor` is called
//    with a bootstrapped `TorHandle`. Wiring that in is a background-thread
//    bootstrap call away, not a protocol change.
//  - No Secure Enclave `KeyVault`: nothing here calls `SecItemAdd`/
//    `SecItemDelete` yet, so duress destruction has no hardware key to
//    destroy. `void_engine_duress_destroy` (the RAM/store half) is wired to
//    `DuressSetupView`'s intent but not yet reachable from the lock screen,
//    because there is no lock screen here yet.

import Foundation
import SwiftUI

@MainActor
final class AppState: ObservableObject {
    @Published var conversations: [ConversationSummary] = []
    @Published var messagesByFingerprint: [Data: [MessageItem]] = [:]
    @Published var isOffline = true
    @Published var protectionAcknowledged = false
    @Published var deviceLossAcknowledged = false
    @Published var lastError: String?
    @Published var showingNewContact = false

    /// The call in progress, if any. At most one — a second incoming offer is
    /// refused by the engine rather than replacing this.
    @Published var activeCall: CallSession?
    /// Why the last call ended, in plain language, for the conversation view.
    @Published var lastCallSummary: String?

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

    /// The published onion service, held only between placing a call and the
    /// peer arriving on it.
    private var callHost: CallHost?
    private var callAudio: CallAudio?

    let core: VoidCore
    var fingerprintWords: String { core.fingerprintWords }

    private var pendingInvite: (link: String, queue: IntroQueue)?
    private var tickTimer: Timer?

    init() throws {
        core = try VoidCore()
        startTicking()
        // UI tests need to reach the screen under test without re-proving the
        // onboarding flow's own scroll/toggle gating on every run — that
        // gating is ProtectionScreen/DeviceLossScreen's job to get right, not
        // every test's job to fight through.
        if ProcessInfo.processInfo.arguments.contains("-uiTestsSkipOnboarding") {
            protectionAcknowledged = true
        }
    }

    deinit {
        tickTimer?.invalidate()
    }

    private func nowMs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }

    private func nowSecs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970)
    }

    // MARK: Ticking (FR-MSG-06)

    /// Every 2 seconds while the app is foregrounded. A background-execution
    /// budget on iOS would drive the same `tick` call from a BGTask instead —
    /// the scheduler itself doesn't care who calls it, only that the calls
    /// keep coming at roughly a constant rate.
    private func startTicking() {
        tickTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
    }

    private func tick() {
        let result = core.tick(nowMs: nowMs())
        switch result {
        case .offline:
            isOffline = true
        case .retrieved(let messages):
            isOffline = false
            for (fingerprint, text) in messages {
                receiveMessage(from: fingerprint, text: text)
            }
        default:
            isOffline = false
        }
        pollPendingInvite()
        pollCallEvents()
    }

    // MARK: - Calls

    /// Drain call events on the same timer as everything else.
    ///
    /// Polling rather than a callback keeps the FFI one-directional: nothing
    /// in Rust ever calls into Swift, so there is no thread whose ownership
    /// has to be reasoned about across the boundary.
    private func pollCallEvents() {
        for event in core.takeCallEvents() {
            switch event {
            case .incoming(let fingerprint, let callId, let address, let port):
                // Only ring if we are not already busy. A second call arriving
                // mid-call is refused by the engine, so this is belt and
                // braces for the UI's own state.
                guard activeCall == nil else { break }
                activeCall = CallSession(
                    fingerprint: fingerprint,
                    callId: callId,
                    address: address,
                    port: port,
                    phase: .incoming
                )
            case .answered(let fingerprint, _):
                guard var call = activeCall, call.fingerprint == fingerprint else { break }
                call.phase = .connecting
                activeCall = call
                openMediaAsCaller()
            case .ended(let fingerprint, _, let reason):
                guard let call = activeCall, call.fingerprint == fingerprint else { break }
                finishCall(reason: Self.plainLanguage(for: reason))
            }
        }
    }

    /// Plain language, per FR-UI-03. No status codes shown to a person.
    private static func plainLanguage(for reason: CallEndReason) -> String {
        switch reason {
        case .hungUp: return "Call ended."
        case .declined: return "They declined."
        case .missed: return "No answer."
        case .failed: return "The connection didn't hold."
        }
    }

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

    /// The user read the disclosure and chose to go ahead.
    func confirmDisclosure() {
        guard let pending = pendingDisclosure else { return }
        pendingDisclosure = nil
        switch pending {
        case .placing(let fingerprint):
            placeCall(to: fingerprint)
        case .answering:
            answerCall()
        }
    }

    /// The user read it and backed out. Declining an incoming call here is a
    /// decline, not a silent dismissal — the caller is told.
    func cancelDisclosure() {
        guard let pending = pendingDisclosure else { return }
        pendingDisclosure = nil
        if case .answering = pending {
            endCall()
        }
    }

    /// Start an outgoing call: publish a service, then offer it.
    ///
    /// Publishing happens off the main thread because it talks to the network,
    /// and the offer is queued the moment the address exists — the descriptor
    /// finishes uploading while the offer waits for the peer's next retrieval
    /// slot, so the two delays overlap.
    private func placeCall(to fingerprint: Data) {
        guard activeCall == nil else { return }
        activeCall = CallSession(
            fingerprint: fingerprint, callId: Data(), address: "", port: 0, phase: .publishing
        )
        let core = self.core
        Task.detached { [weak self] in
            let keyDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("void-call-\(UUID().uuidString)")
            guard let host = core.publishCallService(keyDirectory: keyDir) else {
                await MainActor.run { self?.finishCall(reason: "Couldn't set up the connection.") }
                return
            }
            do {
                let (callId, secret) = try core.placeCall(
                    to: fingerprint, address: host.address, port: VoidCore.callPort
                )
                await MainActor.run {
                    guard var call = self?.activeCall else { return }
                    call.callId = callId
                    call.mediaSecret = secret
                    call.phase = .ringing
                    self?.activeCall = call
                    self?.callHost = host
                }
            } catch {
                host.cancel()
                await MainActor.run { self?.finishCall(reason: "Couldn't reach them.") }
            }
        }
    }

    /// Ask for the disclosure before answering. See `requestCall`.
    func requestAnswer() {
        guard let call = activeCall, call.phase == .incoming else { return }
        pendingDisclosure = .answering(call.fingerprint)
    }

    /// The callee side: answer, then dial the caller's service.
    private func answerCall() {
        guard let call = activeCall, call.phase == .incoming else { return }
        let core = self.core
        let fingerprint = call.fingerprint
        Task.detached { [weak self] in
            do {
                let (callId, secret, address, port) = try core.answerCall(from: fingerprint)
                guard let media = core.connectCall(
                    address: address, port: port, mediaSecret: secret, callId: callId
                ) else {
                    await MainActor.run { self?.finishCall(reason: "Couldn't connect.") }
                    return
                }
                await MainActor.run { self?.startAudio(media: media) }
            } catch {
                await MainActor.run { self?.finishCall(reason: "Couldn't connect.") }
            }
        }
    }

    /// The caller side, once the offer has been answered: wait for them to
    /// arrive on the service we published.
    private func openMediaAsCaller() {
        guard let host = callHost, let call = activeCall else { return }
        callHost = nil
        let secret = call.mediaSecret
        let callId = call.callId
        Task.detached { [weak self] in
            guard let media = host.accept(mediaSecret: secret, callId: callId) else {
                await MainActor.run { self?.finishCall(reason: "They didn't arrive.") }
                return
            }
            await MainActor.run { self?.startAudio(media: media) }
        }
    }

    private func startAudio(media: CallMedia) {
        guard var call = activeCall else {
            media.close()
            return
        }
        let audio = CallAudio()
        // The microphone opens with the call. This is a call, not a
        // walkie-talkie; muting is an action the user takes, not a state they
        // have to hold down to leave.
        audio.transmitting = true
        do {
            try audio.start(media: media) { _ in }
        } catch {
            media.close()
            finishCall(reason: "The microphone isn't available.")
            return
        }
        callAudio = audio
        call.phase = .active
        activeCall = call
    }

    /// Hang up, decline, or cancel — all the same action from here.
    func endCall() {
        guard let call = activeCall else { return }
        let reason: CallEndReason = call.phase == .incoming ? .declined : .hungUp
        try? core.endCall(with: call.fingerprint, reason: reason)
        finishCall(reason: reason == .declined ? "Declined." : "Call ended.")
    }

    /// Tear down local call state. Always safe to call twice.
    private func finishCall(reason: String) {
        callAudio?.stop()
        callAudio = nil
        callHost?.cancel()
        callHost = nil
        activeCall = nil
        lastCallSummary = reason
    }

    /// Whether the microphone is muted.
    ///
    /// Muting stops the microphone, not the emission: silence frames go out on
    /// the same cadence, so a muted call and a talking one are the same shape
    /// on the wire.
    var isMuted: Bool {
        get { !(callAudio?.transmitting ?? false) }
        set { callAudio?.transmitting = !newValue }
    }

    private func pollPendingInvite() {
        guard let pending = pendingInvite else { return }
        // `try?` on a `throws -> Data?` function already flattens to `Data?`
        // (SE-0230) — nil here covers both "not arrived yet" and "the poll
        // itself failed", and the right response to either is the same:
        // try again next tick.
        guard let initial = try? core.pollIntroQueue(pending.queue) else { return }
        pendingInvite = nil
        guard let (fingerprint, firstMessage) = try? core.acceptConversation(
            queue: pending.queue, initial: initial, now: nowSecs()
        ) else { return }
        upsertConversation(fingerprint: fingerprint, name: "")
        receiveMessage(from: fingerprint, text: firstMessage)
    }

    private func receiveMessage(from fingerprint: Data, text: String) {
        messagesByFingerprint[fingerprint, default: []].append(
            MessageItem(
                id: UInt64(messagesByFingerprint[fingerprint]?.count ?? 0) + 1,
                text: text,
                isOutgoing: false,
                delivery: .received,
                timestamp: Date()
            )
        )
        if let index = conversations.firstIndex(where: { $0.id == fingerprint }) {
            conversations[index].lastMessage = text
            conversations[index].unread += 1
        } else {
            upsertConversation(fingerprint: fingerprint, name: "", lastMessage: text)
        }
    }

    private func upsertConversation(fingerprint: Data, name: String, lastMessage: String = "") {
        guard !conversations.contains(where: { $0.id == fingerprint }) else { return }
        let trust: TrustState = core.contacts.first(where: { $0.fingerprint == fingerprint })?.trust ?? .unverified
        conversations.append(
            ConversationSummary(
                id: fingerprint, name: name, trust: trust, lastMessage: lastMessage, unread: 0
            )
        )
    }

    // MARK: Establishing a conversation

    /// Publish an invite and start polling for its acceptance on every tick.
    /// Returns the link to render as a QR code / share sheet text.
    func createInvite(relayHint: String = "relay.example.onion", label: String = "") -> String? {
        do {
            let (link, queue) = try core.createInvite(
                relayHint: relayHint, label: label, now: nowSecs(), ttlSeconds: 24 * 3600
            )
            pendingInvite = (link, queue)
            return link
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    /// Start a conversation from a scanned or pasted invite link.
    func startConversation(link: String, localName: String, firstMessage: String) {
        do {
            let fingerprint = try core.startConversation(
                link: link, localName: localName, firstMessage: firstMessage, now: nowSecs()
            )
            upsertConversation(fingerprint: fingerprint, name: localName)
            messagesByFingerprint[fingerprint, default: []].append(
                MessageItem(id: 1, text: firstMessage, isOutgoing: true, delivery: .queued, timestamp: Date())
            )
        } catch {
            lastError = error.localizedDescription
        }
    }

    // MARK: Sending

    func send(to fingerprint: Data, text: String) {
        do {
            try core.send(to: fingerprint, text: text, now: nowSecs())
        } catch {
            lastError = error.localizedDescription
        }
    }

    // MARK: Verification (FR-DISC-04, FR-DISC-05)

    func handleVerificationResult(fingerprint: Data, matched: Bool) {
        do {
            if matched {
                try core.markVerified(fingerprint)
            } else {
                // See ConversationViews.swift's VerificationView: a rejected
                // comparison has no direct engine-side equivalent (that
                // state is for a *detected* key rotation, not a user
                // decision), so this only updates local UI state today.
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    func acknowledgeKeyChange(fingerprint: Data) {
        do {
            try core.acknowledgeKeyChange(fingerprint)
            if let index = conversations.firstIndex(where: { $0.id == fingerprint }) {
                conversations[index].trust = .unverified
            }
        } catch {
            lastError = error.localizedDescription
        }
    }
}
