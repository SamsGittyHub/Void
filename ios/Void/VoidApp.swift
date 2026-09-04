//  VoidApp.swift
//
//  The app entry point. Builds the one `AppState` the whole UI shares and
//  decides between onboarding (FR-UI-05, FR-REC-01) and the main app.

import SwiftUI

@main
struct VoidApp: App {
    @StateObject private var appState: AppStateBox
    @Environment(\.scenePhase) private var scenePhase

    init() {
        _appState = StateObject(wrappedValue: AppStateBox())
    }

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

/// `AppState`'s `init` can throw (identity generation is fallible — FR-ID-04
/// requires it happen offline from system entropy, and entropy failure is a
/// real, if rare, condition to handle rather than force-unwrap past). This
/// box lets SwiftUI hold a `StateObject` either way and show a failure
/// screen instead of crashing at launch.
@MainActor
final class AppStateBox: ObservableObject {
    @Published private(set) var state: AppState?
    @Published private(set) var launchError: String?

    init() {
        do {
            state = try AppState()
        } catch {
            launchError = error.localizedDescription
        }
    }
}

private struct RootView: View {
    @ObservedObject var box: AppStateBox

    var body: some View {
        if let state = box.state {
            MainView().environmentObject(state)
        } else {
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.largeTitle)
                    .foregroundStyle(.orange)
                Text("Void could not start")
                    .font(.headline)
                Text(box.launchError ?? "Unknown error")
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
                state.protectionAcknowledged = true
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
                    onVerificationResult: { fingerprint, matched in
                        state.handleVerificationResult(fingerprint: fingerprint, matched: matched)
                    }
                )
                .tabItem { Label("Conversations", systemImage: "bubble.left.and.bubble.right") }

                NavigationStack {
                    KeyStorageView(backing: .secureEnclave)
                }
                .tabItem { Label("Security", systemImage: "lock.shield") }
            }
            .sheet(isPresented: $state.showingNewContact) {
                NewContactView().environmentObject(state)
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

/// The "add a contact" sheet (FR-DISC-01): shows my invite as a QR code, or
/// accepts a pasted link. Camera-based scanning is not implemented yet — the
/// paste path exercises the identical `startConversation` call a scanner
/// would.
private struct NewContactView: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var myInviteLink: String?
    @State private var pastedLink = ""
    @State private var contactName = ""
    @State private var firstMessage = ""
    @State private var showingScanner = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Your invite") {
                    if let link = myInviteLink {
                        InviteQRCodeCarousel(link: link)
                        Text(link)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                        Button("Copy link") {
                            UIPasteboard.general.string = link
                        }
                    } else {
                        Button("Generate an invite") {
                            myInviteLink = state.createInvite()
                        }
                    }
                }

                Section("Accept an invite") {
                    Button {
                        showingScanner = true
                    } label: {
                        Label("Scan a QR code", systemImage: "qrcode.viewfinder")
                    }
                    TextField("Paste a void:// link", text: $pastedLink)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Their name (just for you)", text: $contactName)
                    TextField("First message", text: $firstMessage)
                    Button("Start conversation") {
                        state.startConversation(
                            link: pastedLink, localName: contactName, firstMessage: firstMessage
                        )
                        dismiss()
                    }
                    .disabled(pastedLink.isEmpty || firstMessage.isEmpty)
                }
            }
            .navigationTitle("Add a contact")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .sheet(isPresented: $showingScanner) {
                InviteScanSheet { link in
                    pastedLink = link
                }
            }
        }
    }
}
