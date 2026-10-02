//  VoidApp.swift
//
//  The app entry point. Unlocks this device's key, opens its engine, and
//  decides between onboarding (FR-UI-05, FR-REC-01) and the main app.

import SwiftUI

@main
struct VoidApp: App {
    @StateObject private var appState = AppStateBox()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView(box: appState)
                // FR-STOR-06: the app switcher's snapshot is a screenshot
                // iOS takes and caches to disk. Covering the content
                // whenever the scene is not `.active` — not just
                // `.background` — is what keeps a message from sitting in
                // that snapshot the instant the user swipes to another app.
                .privacyCover(scenePhase != .active)
        }
    }
}

private extension View {
    func privacyCover(_ isCovered: Bool) -> some View {
        overlay {
            if isCovered {
                ZStack {
                    Color(.systemBackground).ignoresSafeArea()
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 44))
                        .foregroundStyle(.secondary)
                }
                .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.15), value: isCovered)
    }
}

/// Opens the engine before anything else can run.
///
/// Opening needs the key-encryption key, and releasing that key can mean a
/// Face ID or passcode prompt (`KeyVault`), which must not block the main
/// thread. Until it is released there is no identity and no contacts to show.
@MainActor
final class AppStateBox: ObservableObject {
    enum Phase {
        case unlocking
        case ready(AppState)
        /// The user dismissed the prompt. Nothing is wrong; offer it again.
        case locked(String)
        case failed(String)
    }

    @Published private(set) var phase: Phase = .unlocking

    init() {
        unlock()
    }

    func unlock() {
        phase = .unlocking
        // Opening an engine for the first time generates its identity, which
        // needs `CoreThread`'s stack, not a dispatch queue's.
        CoreThread.detach(name: "app.void.unlock", qos: .userInitiated) { [weak self] in
            let result = Result { () throws -> (VoidCore, VaultBacking, String) in
                var opened = try KeyVault.openOrCreate(reason: "Unlock Void")
                let core = try VoidCore(
                    dataDirectory: AppDirectories.database(),
                    kek: &opened.kek,
                    backing: opened.backing,
                    nowMs: Clock.nowMs
                )
                return (core, opened.backing, core.fingerprintWords)
            }
            Task { @MainActor in self?.opened(result) }
        }
    }

    private func opened(_ result: Result<(VoidCore, VaultBacking, String), Error>) {
        switch result {
        case .success(let (core, backing, words)):
            phase = .ready(AppState(core: core, backing: backing, fingerprintWords: words))
        case .failure(KeyVault.Failure.cancelled):
            phase = .locked(KeyVault.Failure.cancelled.localizedDescription)
        case .failure(VoidError.locked):
            // Never papered over by making a new identity: that would silently
            // replace the user's, and every contact would see a stranger.
            phase = .failed(
                "This phone's key no longer opens Void's data. Nothing has been changed or replaced.")
        case .failure(let error):
            phase = .failed(error.localizedDescription)
        }
    }
}

private struct RootView: View {
    @ObservedObject var box: AppStateBox

    var body: some View {
        switch box.phase {
        case .ready(let state):
            MainView().environmentObject(state)
        case .unlocking:
            VStack(spacing: 12) {
                ProgressView()
                Text("Unlocking…")
                    .foregroundStyle(.secondary)
            }
        case .locked(let message):
            VStack(spacing: 16) {
                Image(systemName: "lock.fill")
                    .font(.largeTitle)
                    .foregroundStyle(.secondary)
                Text(message)
                    .multilineTextAlignment(.center)
                Button("Unlock") { box.unlock() }
                    .buttonStyle(.borderedProminent)
            }
            .padding(32)
        case .failed(let message):
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.largeTitle)
                    .foregroundStyle(.orange)
                Text("Void could not start")
                    .font(.headline)
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
        }
    }
}

private struct MainView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        if !state.protectionAcknowledged {
            OnboardingFlow {
                state.finishOnboarding()
            }
        } else {
            TabView {
                ConversationListView(
                    conversations: $state.conversations,
                    messagesByFingerprint: $state.messagesByFingerprint,
                    isOffline: state.isOffline,
                    myWords: state.fingerprintWords,
                    onNewContact: { state.showingNewContact = true },
                    onSend: { fingerprint, text in state.send(to: fingerprint, text: text) },
                    onSendFile: { fingerprint, pending in state.sendFile(to: fingerprint, pending) },
                    loadAttachment: { recordId in await state.attachmentData(recordId: recordId) },
                    onVerificationResult: { fingerprint, matched in
                        state.handleVerificationResult(fingerprint: fingerprint, matched: matched)
                    },
                    onAcknowledgeKeyChange: { state.acknowledgeKeyChange(fingerprint: $0) },
                    onRename: { fingerprint, name in state.renameContact(fingerprint, to: name) },
                    onCall: { state.requestCall(to: $0) },
                    onOpen: { state.openConversation($0) },
                    onClose: { state.closeConversation($0) }
                )
                .tabItem { Label("Conversations", systemImage: "bubble.left.and.bubble.right") }

                NavigationStack {
                    KeyStorageView(backing: state.backing)
                }
                .tabItem { Label("Security", systemImage: "lock.shield") }
            }
            .overlay(alignment: .top) {
                NoticeBanner(text: state.notice) { state.notice = nil }
            }
            .sheet(
                isPresented: $state.showingNewContact,
                onDismiss: {
                    state.dismissShownInvite()
                    state.cancelOpenedInvite()
                }
            ) {
                NewContactView().environmentObject(state)
            }
            // One presentation for everything about a call, disclosure
            // included. A sheet for the disclosure followed by a cover for the
            // call meant dismissing one and presenting the other in the same
            // moment, which UIKit can refuse — leaving a call with no screen.
            .fullScreenCover(
                isPresented: Binding(
                    get: { state.activeCall != nil || state.pendingDisclosure != nil },
                    set: { _ in }
                )
            ) {
                CallContainer().environmentObject(state)
            }
            .alert(
                "Something went wrong",
                isPresented: Binding(
                    get: { state.lastError != nil },
                    set: { if !$0 { state.lastError = nil } }
                )
            ) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(state.lastError ?? "")
            }
        }
    }

}

/// The disclosure, the incoming-call screen, and the ringing and in-call
/// screen, one at a time. The disclosure comes first, in either direction.
private struct CallContainer: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        Group {
            if let pending = state.pendingDisclosure {
                CallDisclosureView(
                    contactName: disclosureName(pending.fingerprint),
                    isAnswering: pending.isAnswering,
                    onContinue: { state.confirmDisclosure() },
                    onCancel: { state.cancelDisclosure() }
                )
            } else if let call = state.activeCall {
                if call.phase == .incoming {
                    IncomingCallView(
                        contactName: name(call.fingerprint),
                        isVerified: trust(call.fingerprint) == .verified,
                        onAnswer: { state.requestAnswer() },
                        onDecline: { state.hangUp() }
                    )
                } else {
                    CallView(
                        contactName: name(call.fingerprint),
                        phase: call.phase,
                        isMuted: $state.isMuted,
                        onHangUp: { state.hangUp() }
                    )
                }
            }
        }
    }

    private func disclosureName(_ fingerprint: Data) -> String {
        let name = state.conversations.first { $0.id == fingerprint }?.name ?? ""
        return name.isEmpty ? "them" : name
    }

    private func name(_ fingerprint: Data?) -> String {
        let name = state.conversations.first { $0.id == fingerprint }?.name ?? ""
        return name.isEmpty ? "Unnamed contact" : name
    }

    private func trust(_ fingerprint: Data) -> TrustState {
        state.conversations.first { $0.id == fingerprint }?.trust ?? .unverified
    }
}

/// A short line at the top of the screen that goes away on its own.
private struct NoticeBanner: View {
    let text: String?
    var onDismiss: () -> Void

    var body: some View {
        Group {
            if let text {
                Text(text)
                    .font(.subheadline)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(.thinMaterial, in: Capsule())
                    .padding(.top, 8)
                    .padding(.horizontal, 16)
                    .onTapGesture(perform: onDismiss)
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .accessibilityAddTraits(.isStaticText)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: text)
    }
}

/// Adding a contact (FR-DISC-01), both ways round: show my code to someone,
/// or scan or paste theirs. Each invitation is for one person and is one QR
/// code (D-027).
private struct NewContactView: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss

    private enum Mode: Hashable {
        case showCode
        case scan
    }

    @State private var mode: Mode = .showCode
    @State private var contactLabel = ""
    @State private var pastedLink = ""
    @State private var showingScanner = false
    @State private var confirmName = ""
    @State private var confirmMessage = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("How", selection: $mode) {
                        Text("Show my code").tag(Mode.showCode)
                        Text("Scan or paste").tag(Mode.scan)
                    }
                    .pickerStyle(.segmented)
                }
                .listRowBackground(Color.clear)

                switch mode {
                case .showCode: showCode
                case .scan: scanOrPaste
                }
            }
            .navigationTitle("Add a contact")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .sheet(isPresented: $showingScanner) {
                InviteScanSheet { link in state.openInvite(link) }
            }
            .onChange(of: state.openedInvite) { opened in
                guard let opened else { return }
                mode = .scan
                if case .ready(let inviterName, _) = opened.stage, confirmName.isEmpty {
                    confirmName = inviterName
                }
            }
        }
    }

    // MARK: Show my code

    @ViewBuilder private var showCode: some View {
        if let invite = state.shownInvite {
            Section {
                QRCodeImage(content: invite.link)
                    .frame(maxWidth: .infinity)
                    .frame(height: 240)
                    .accessibilityIdentifier("inviteQRCode")
                Text(status(of: invite))
                    .font(.subheadline)
                    .foregroundStyle(invite.joinedName == nil ? .secondary : .primary)
                ShareLink(item: invite.link) {
                    Label("Share link", systemImage: "square.and.arrow.up")
                }
                Button("Copy link") {
                    UIPasteboard.general.string = invite.link
                }
            } footer: {
                Text("One code is for one person, and it works for 24 hours. Anyone who has it can use it, so send the link only to them.")
            }

            Section {
                if invite.joinedName != nil {
                    Button("Done") { dismiss() }
                } else {
                    Button("Make a code for someone else") {
                        contactLabel = ""
                        state.dismissShownInvite()
                    }
                    Button("Cancel this invitation", role: .destructive) {
                        state.cancelShownInvite()
                    }
                }
            }
        } else {
            Section {
                TextField("Their name (optional)", text: $contactLabel)
            } header: {
                Text("Who's this for?")
            } footer: {
                Text("Only you see this. They'll appear under this name when they connect.")
            }

            Section {
                TextField("Your name (optional)", text: $state.inviteName)
            } header: {
                Text("Your name on invitations")
            } footer: {
                Text("Shown to whoever opens your invitation, so they know it's from you. Anyone can type any name, which is why you compare security codes.")
            }

            Section {
                Button("Create a code") {
                    state.createInvite(for: contactLabel)
                }
                .accessibilityIdentifier("createInviteButton")
            }
        }
    }

    private func status(of invite: ShownInvite) -> String {
        let who = invite.contactLabel.isEmpty ? "them" : invite.contactLabel
        if let joined = invite.joinedName {
            return "\(joined) joined. You can message them now."
        }
        if invite.expired {
            return "This code expired. Make a new one."
        }
        switch invite.uploadRemaining {
        case .none:
            return "Getting it ready…"
        case .some(0):
            return "Ready. Show this code to \(who), or send them the link."
        case .some(let remaining):
            if state.isOffline {
                return "Waiting for the network. The code will work once Void is online."
            }
            // One record leaves per five-second slot.
            let seconds = max(5, remaining * 5)
            return "Getting it ready — about \(seconds) seconds. They can scan it now and wait."
        }
    }

    // MARK: Scan or paste

    @ViewBuilder private var scanOrPaste: some View {
        if let opened = state.openedInvite {
            switch opened.stage {
            case .fetching:
                Section {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Getting their invitation…")
                    }
                    Button("Cancel", role: .cancel) { state.cancelOpenedInvite() }
                } footer: {
                    Text("This usually takes a few seconds, and up to a minute if they have only just made it.")
                }
            case .ready(let inviterName, let fingerprint):
                Section {
                    TextField("Their name", text: $confirmName)
                    TextField("First message (optional)", text: $confirmMessage, axis: .vertical)
                        .lineLimit(1...4)
                } header: {
                    Text(inviterName.isEmpty ? "Connect with this person?" : "Connect with \(inviterName)?")
                } footer: {
                    Text(
                        "Their security code is \(VoidCore.fingerprintWords(for: fingerprint)). Compare it with them in person to be sure it's really them."
                    )
                }
                Section {
                    Button("Connect") {
                        state.confirmOpenedInvite(name: confirmName, firstMessage: confirmMessage)
                    }
                    .accessibilityIdentifier("confirmInviteButton")
                    Button("Cancel", role: .cancel) {
                        confirmName = ""
                        confirmMessage = ""
                        state.cancelOpenedInvite()
                    }
                }
            case .failed(let message):
                Section {
                    Text(message)
                    Button("Try another invitation") {
                        state.cancelOpenedInvite()
                    }
                }
            }
        } else {
            Section {
                Button {
                    showingScanner = true
                } label: {
                    Label("Scan their code", systemImage: "qrcode.viewfinder")
                }
            }
            Section {
                TextField("void://…", text: $pastedLink)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Open") {
                    state.openInvite(pastedLink)
                    pastedLink = ""
                }
                .disabled(pastedLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            } header: {
                Text("Or paste their link")
            }
        }
    }
}
