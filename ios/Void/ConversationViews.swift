//  ConversationViews.swift
//
//  The conversation list, the conversation itself, and verification.
//
//  Two requirements drive almost every decision here:
//
//  - FR-UI-03: "Security state is shown as plain-language conversation status
//    (verified / unverified / key changed), not as jargon or iconography the
//    user must learn."
//  - FR-DISC-05: a changed identity key **blocks** messaging until the user
//    acknowledges it. Blocks, not warns. The composer is replaced, not disabled
//    with a tooltip.

import SwiftUI

// MARK: - Conversation list

struct ConversationListView: View {
    @Binding var conversations: [ConversationSummary]
    @Binding var messagesByFingerprint: [Data: [MessageItem]]
    var isOffline: Bool
    var myWords: String = ""
    var onNewContact: () -> Void
    var onSend: (Data, String) -> Void = { _, _ in }
    /// A file the user picked and confirmed, to send to that contact.
    var onSendFile: (Data, PendingAttachment) -> Void = { _, _ in }
    /// The bytes of a file in the history, by its record id, for the bubble
    /// that shows it. Async: the engine reads it on its own thread.
    var loadAttachment: (UInt64) async -> Data? = { _ in nil }
    var onVerificationResult: (Data, Bool) -> Void = { _, _ in }
    var onAcknowledgeKeyChange: (Data) -> Void = { _ in }
    var onRename: (Data, String) -> Void = { _, _ in }
    var onCall: (Data) -> Void = { _ in }
    var onOpen: (Data) -> Void = { _ in }
    var onClose: (Data) -> Void = { _ in }

    /// On an iPad, or an iPhone in landscape with room for it, the list and
    /// the open conversation sit side by side; otherwise one at a time.
    @Environment(\.horizontalSizeClass) private var sizeClass
    /// The conversation open in the side-by-side layout.
    @State private var selected: Data?

    private var emptyStateDescription: String {
        "Void has no directory and no way to look people up. You start a conversation by "
            + "scanning someone's code in person, or by sending them a one-time link through "
            + "another app."
    }

    var body: some View {
        if sizeClass == .regular {
            splitLayout
        } else {
            stackLayout
        }
    }

    // MARK: Compact: one screen at a time

    private var stackLayout: some View {
        NavigationStack {
            list
                .navigationDestination(for: Data.self) { id in
                    conversation(id)
                }
        }
    }

    // MARK: Regular: list beside conversation (D-034)

    private var splitLayout: some View {
        NavigationSplitView {
            list
        } detail: {
            if let id = selected, conversations.contains(where: { $0.id == id }) {
                NavigationStack {
                    conversation(id)
                }
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "bubble.left.and.bubble.right")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("Choose a conversation")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: The pieces both layouts share

    /// The list itself. `selection` is read only by the split layout; in a
    /// navigation stack the links push instead.
    private var list: some View {
        List(selection: $selected) {
            if isOffline {
                // NFR-REL-04 and FR-TRANS-05: the user is told plainly that
                // nothing is being sent, and told *why that is deliberate*.
                // A generic "no connection" banner would invite them to
                // look for a workaround; there isn't one, by design.
                Section {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Not connected").font(.subheadline.bold())
                            Text(
                                "Messages are saved on this phone and will send when Void "
                                    + "can reach the network. Nothing is sent any other way."
                            )
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "wifi.slash").foregroundStyle(.orange)
                    }
                }
            }

            ForEach($conversations) { $conversation in
                NavigationLink(value: conversation.id) {
                    ConversationRow(conversation: conversation)
                }
            }
        }
        .navigationTitle("Void")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: onNewContact) {
                    Label("Add contact", systemImage: "qrcode")
                }
            }
        }
        .overlay {
            // ContentUnavailableView is iOS 17+; NFR-COMP-01 sets the
            // floor at iOS 16, so this needs a plain fallback rather
            // than raising the deployment target for one empty state.
            if conversations.isEmpty {
                if #available(iOS 17.0, *) {
                    ContentUnavailableView {
                        Label("No conversations", systemImage: "qrcode.viewfinder")
                    } description: {
                        Text(emptyStateDescription)
                    } actions: {
                        Button("Add a contact", action: onNewContact)
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    VStack(spacing: 12) {
                        Image(systemName: "qrcode.viewfinder")
                            .font(.system(size: 40))
                            .foregroundStyle(.secondary)
                        Text("No conversations").font(.headline)
                        Text(emptyStateDescription)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.horizontal, 32)
                        Button("Add a contact", action: onNewContact)
                            .buttonStyle(.borderedProminent)
                    }
                }
            }
        }
    }

    /// One conversation, wired to the callbacks. Its appearing and
    /// disappearing is what tells `AppState` which conversation is on screen,
    /// in either layout.
    @ViewBuilder private func conversation(_ id: Data) -> some View {
        if let index = conversations.firstIndex(where: { $0.id == id }) {
            ConversationView(
                conversation: $conversations[index],
                messages: messagesByFingerprint[id] ?? [],
                onSend: { text in onSend(id, text) },
                onSendFile: { pending in onSendFile(id, pending) },
                loadAttachment: loadAttachment,
                myWords: myWords,
                onVerificationResult: { matched in onVerificationResult(id, matched) },
                onAcknowledgeKeyChange: { onAcknowledgeKeyChange(id) },
                onRename: { name in onRename(id, name) },
                onCall: { onCall(id) }
            )
            .onAppear { onOpen(id) }
            .onDisappear { onClose(id) }
        }
    }
}

private struct ConversationRow: View {
    let conversation: ConversationSummary

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(conversation.name.isEmpty ? "Unnamed contact" : conversation.name)
                        .font(.headline)
                    trustBadge
                }
                Text(conversation.lastMessage)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if conversation.unread > 0 {
                Text("\(conversation.unread)")
                    .font(.caption.bold())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Capsule().fill(Color.accentColor))
                    .foregroundStyle(.white)
            }
        }
        .padding(.vertical, 4)
        // NFR-COMP-04: the security state must be conveyed non-visually. A
        // VoiceOver user hears "Not verified yet" as part of the row, not as a
        // decorative image they have to hunt for.
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "\(conversation.name). \(conversation.trust.statusLine). \(conversation.lastMessage)"
        )
    }

    /// FR-UI-03: words, not icons the user must learn. The symbol is decorative
    /// and is hidden from accessibility; the text carries the meaning.
    @ViewBuilder private var trustBadge: some View {
        switch conversation.trust {
        case .verified:
            Text("Verified")
                .font(.caption2.bold())
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Capsule().fill(Color.green.opacity(0.18)))
                .foregroundStyle(.green)
        case .unverified:
            Text("Not verified")
                .font(.caption2)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Capsule().fill(Color.secondary.opacity(0.15)))
                .foregroundStyle(.secondary)
        case .keyChanged:
            Text("Code changed")
                .font(.caption2.bold())
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Capsule().fill(Color.orange.opacity(0.22)))
                .foregroundStyle(.orange)
        }
    }
}

// MARK: - A conversation

struct ConversationView: View {
    @Binding var conversation: ConversationSummary
    /// The stored history, oldest first, refreshed from the engine.
    var messages: [MessageItem]
    /// Called with the drafted text when the user taps send. The engine
    /// queues it — see `VoidCore.send` — it does not transmit immediately
    /// (FR-MSG-06): the message shows as "Waiting to send" until the scheduler
    /// has actually deposited it.
    var onSend: (String) -> Void = { _ in }
    /// Called with a file the user picked and, having seen its size and how
    /// long it will take, chose to send. Queued like a message: a file *is* a
    /// message, in records that leave one per slot behind every queued text.
    var onSendFile: (PendingAttachment) -> Void = { _ in }
    /// The bytes of a file in this history, for the bubble showing it.
    var loadAttachment: (UInt64) async -> Data? = { _ in nil }
    /// My own security code, for the verification sheet. The engine only
    /// exposes this via an instance call (`VoidCore.fingerprintWords`), so
    /// unlike the contact's code below it cannot be computed inline here.
    var myWords = ""
    var onVerificationResult: (Bool) -> Void = { _ in }
    var onAcknowledgeKeyChange: () -> Void = {}
    var onRename: (String) -> Void = { _ in }
    var onCall: () -> Void = {}
    @State private var draft = ""
    @State private var showingVerification = false
    @State private var renaming = false
    @State private var newName = ""
    /// A file picked and not yet confirmed: the confirmation sheet shows its
    /// size and how long it will take, and sends it or not.
    @State private var pendingAttachment: PendingAttachment?

    var body: some View {
        VStack(spacing: 0) {
            if conversation.trust != .verified {
                trustBanner
            }

            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(messages) { message in
                        MessageBubble(message: message, loadAttachment: loadAttachment)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 16)
            }

            Divider()

            // FR-DISC-05: a changed key blocks messaging. The composer is
            // *replaced*, not disabled — a greyed-out text field invites the
            // user to look for a way around it, and there must not be one.
            if conversation.trust.canSend {
                composer
            } else {
                blockedComposer
            }
        }
        .navigationTitle(conversation.name.isEmpty ? "Unnamed contact" : conversation.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(action: onCall) {
                    Label("Call", systemImage: "phone")
                }
                .disabled(!conversation.trust.canSend)
                .accessibilityIdentifier("callButton")
                Menu {
                    Button("Compare security codes") { showingVerification = true }
                    Button("Rename") {
                        newName = conversation.name
                        renaming = true
                    }
                } label: {
                    Label("More", systemImage: "ellipsis.circle")
                }
            }
        }
        // The name is only ever this device's: renaming tells nobody.
        .alert("Rename", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Save") { onRename(newName) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Only you see this name.")
        }
        .sheet(isPresented: $showingVerification) {
            NavigationStack {
                VerificationView(
                    contactName: conversation.name,
                    trust: $conversation.trust,
                    myCode: myWords,
                    theirCode: VoidCore.fingerprintWords(for: conversation.id),
                    onResult: onVerificationResult
                )
            }
        }
        .sheet(
            isPresented: Binding(
                get: { pendingAttachment != nil },
                set: { if !$0 { pendingAttachment = nil } }
            )
        ) {
            if let pending = pendingAttachment {
                AttachmentConfirmView(
                    pending: pending,
                    contactName: conversation.name.isEmpty ? "them" : conversation.name,
                    onSend: {
                        pendingAttachment = nil
                        onSendFile(pending)
                    },
                    onCancel: { pendingAttachment = nil }
                )
            }
        }
    }

    private var trustBanner: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(conversation.trust.statusLine).font(.subheadline.bold())
            Text(conversation.trust.guidance)
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
            if conversation.trust == .keyChanged {
                HStack {
                    Button("Check their code") { showingVerification = true }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    // Acknowledging drops to "not verified", never straight to
                    // "verified" — dismissing a banner is not the same as
                    // comparing codes with a person. It goes to the engine,
                    // which is what actually blocks sending.
                    Button("I've checked, continue") {
                        onAcknowledgeKeyChange()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(
            conversation.trust == .keyChanged
                ? Color.orange.opacity(0.15) : Color.secondary.opacity(0.10)
        )
        .accessibilityElement(children: .combine)
    }

    private var composer: some View {
        HStack(spacing: 8) {
            // A photo or any file. Picked here, confirmed on a sheet that
            // states its size and the time it will take, then queued.
            AttachmentPicker { picked in pendingAttachment = picked }
            TextField("Message", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...5)
            Button {
                let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !text.isEmpty else { return }
                // Queued, not sent: the engine holds it until the next
                // scheduled slot so that send timing does not reveal typing
                // timing (FR-MSG-06).
                onSend(text)
                draft = ""
            } label: {
                Image(systemName: "arrow.up.circle.fill").font(.title2)
            }
            .accessibilityLabel("Send")
            .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(12)
    }

    private var blockedComposer: some View {
        VStack(spacing: 8) {
            Label("Messaging is paused", systemImage: "hand.raised.fill")
                .font(.subheadline.bold())
                .foregroundStyle(.orange)
            Text(
                "Void will not send to this contact until you have checked their new security "
                    + "code through another channel."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(16)
        .accessibilityElement(children: .combine)
    }
}

private struct MessageBubble: View {
    let message: MessageItem
    var loadAttachment: (UInt64) async -> Data? = { _ in nil }

    /// A bubble never grows past this, so a short message on an iPad is a
    /// bubble and not a banner.
    private static let maxBubbleWidth: CGFloat = 560

    var body: some View {
        HStack {
            if message.isOutgoing { Spacer(minLength: 48) }
            VStack(alignment: message.isOutgoing ? .trailing : .leading, spacing: 3) {
                if let attachment = message.attachment {
                    AttachmentBubble(
                        message: message, attachment: attachment, loadAttachment: loadAttachment
                    )
                    .background(
                        RoundedRectangle(cornerRadius: 16)
                            .fill(
                                message.isOutgoing
                                    ? Color.accentColor.opacity(0.20)
                                    : Color.secondary.opacity(0.14)
                            )
                    )
                } else {
                    Text(message.text)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(
                            RoundedRectangle(cornerRadius: 16)
                                .fill(
                                    message.isOutgoing
                                        ? Color.accentColor.opacity(0.20)
                                        : Color.secondary.opacity(0.14)
                                )
                        )
                }
                if message.isOutgoing && !statusLine.isEmpty {
                    Text(statusLine)
                        .font(.caption2)
                        .foregroundStyle(
                            message.delivery == .failed ? Color.orange : Color.secondary
                        )
                }
            }
            .frame(maxWidth: Self.maxBubbleWidth, alignment: message.isOutgoing ? .trailing : .leading)
            if !message.isOutgoing { Spacer(minLength: 48) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            (message.isOutgoing ? "You sent: " : "They sent: ")
                + (message.attachment.map { $0.isImage ? "a photo" : "a file, \($0.name)" } ?? message.text)
                + (statusLine.isEmpty ? "" : ". \(statusLine)")
        )
    }

    /// The delivery label, or, for a file still leaving, how much longer. A
    /// photo is hundreds of records at one per slot, so "Waiting to send" on
    /// its own would look stuck for twenty minutes.
    private var statusLine: String {
        if message.delivery == .queued, message.fragmentsRemaining > 0, message.attachment != nil {
            let seconds = message.fragmentsRemaining * Int(VoidCore.padIntervalMs / 1000)
            return "Sending — about \(AttachmentFormat.duration(seconds: seconds)) left"
        }
        return message.delivery.label
    }
}

// MARK: - Verification (FR-DISC-04)

struct VerificationView: View {
    let contactName: String
    @Binding var trust: TrustState
    /// Both codes, rendered from the real fingerprints by the caller —
    /// `VoidCore.fingerprintWords` for mine, `VoidCore.fingerprintWords(for:)`
    /// for theirs. Defaulted only so this view still compiles in a preview.
    var myCode = "tinas-dofil-lusab-babad\ngutih-tugad-kabad-lusab"
    var theirCode = "lusab-babad-gutih-tugad\nkabad-lusab-tinas-dofil"
    /// Called once the user confirms a match or mismatch, so the caller can
    /// tell the engine (`VoidCore.markVerified` / `acknowledgeKeyChange`) —
    /// this view only knows what the user said, not how to record it.
    var onResult: (Bool) -> Void = { _ in }

    @State private var typedCode = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                Text(
                    "Compare these codes with \(contactName.isEmpty ? "them" : contactName) in "
                        + "person, or on a call where you recognise their voice. Do not compare "
                        + "them inside Void — if someone is intercepting this conversation, they "
                        + "would be showing you their own codes."
                )
                .font(.subheadline)
                .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("How to do this")
            }

            Section("Their code") {
                Text(theirCode)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                    .accessibilityLabel(spelledOut(theirCode))
            }

            Section("Your code") {
                Text(myCode)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                    .accessibilityLabel(spelledOut(myCode))
            }

            Section {
                Button {
                    trust = .verified
                    onResult(true)
                    dismiss()
                } label: {
                    Label("The codes match", systemImage: "checkmark.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)

                Button(role: .destructive) {
                    trust = .keyChanged
                    onResult(false)
                    dismiss()
                } label: {
                    Label("They don't match", systemImage: "exclamationmark.triangle")
                        .frame(maxWidth: .infinity)
                }
            } footer: {
                Text(
                    "If the codes don't match, stop using this conversation and reach the person "
                        + "another way. Void will pause messaging."
                )
            }
        }
        .navigationTitle("Compare codes")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Not now") { dismiss() }
            }
        }
    }

    /// NFR-COMP-04: a VoiceOver user comparing codes needs them spelled, not
    /// read as invented words. "lusab" pronounced by a screen reader is not
    /// something two people can reliably match.
    private func spelledOut(_ code: String) -> String {
        code
            .replacingOccurrences(of: "\n", with: ", ")
            .split(separator: "-")
            .map { $0.map(String.init).joined(separator: " ") }
            .joined(separator: ", then ")
    }
}
