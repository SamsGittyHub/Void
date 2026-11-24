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

import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Conversation list

struct ConversationListView: View {
    @EnvironmentObject var state: AppState
    @State private var search = ""
    @State private var path: [Data] = []

    private var emptyStateDescription: String {
        "Void has no directory and no way to look people up. You start a conversation by "
            + "scanning someone's code in person, or by sending them a one-time link through "
            + "another app."
    }

    private var shown: [ConversationSummary] {
        let query = search.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return state.conversations }
        return state.conversations.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                if state.isOffline {
                    OfflineCard(bootstrapping: state.torStatus == .bootstrapping || state.torStatus == .notStarted)
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 8, trailing: 16))
                } else {
                    ConnectionIndicator()
                        .frame(maxWidth: .infinity)
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 6, trailing: 16))
                }
                ForEach(shown) { conversation in
                    NavigationLink(value: conversation.id) {
                        ConversationRow(conversation: conversation)
                    }
                    .listRowInsets(EdgeInsets(top: 10, leading: 16, bottom: 10, trailing: 16))
                }
            }
            .listStyle(.plain)
            .searchable(text: $search, prompt: "Search contacts")
            .navigationTitle("Chats")
            .navigationDestination(for: Data.self) { id in
                ConversationView(fingerprint: id)
            }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        state.showingNewContact = true
                    } label: {
                        Image(systemName: "square.and.pencil")
                            .fontWeight(.semibold)
                    }
                    .accessibilityLabel("Add contact")
                    .accessibilityIdentifier("addContactButton")
                }
            }
            .overlay {
                if state.conversations.isEmpty {
                    EmptyChats(description: emptyStateDescription) {
                        state.showingNewContact = true
                    }
                }
            }
        }
    }
}

/// A quiet line at the top of the list while everything is working: the one
/// way Void ever reaches the network, and that it is up.
private struct ConnectionIndicator: View {
    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(Theme.verified)
                .frame(width: 7, height: 7)
            Text("Connected over Tor")
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Connected over Tor")
        .accessibilityIdentifier("connectionIndicator")
    }
}

private struct OfflineCard: View {
    let bootstrapping: Bool

    var body: some View {
        // NFR-REL-04 and FR-TRANS-05: the user is told plainly that nothing is
        // being sent, and told *why that is deliberate*. A generic "no
        // connection" banner would invite them to look for a workaround;
        // there isn't one, by design.
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: bootstrapping ? "network" : "wifi.slash")
                .font(.title3)
                .foregroundStyle(Theme.warning)
            VStack(alignment: .leading, spacing: 3) {
                Text(bootstrapping ? "Connecting to Tor…" : "Not connected")
                    .font(.subheadline.weight(.semibold))
                Text(
                    "Messages are saved on this phone and will send when Void can reach the "
                        + "network. Nothing is sent any other way."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(Theme.warning.opacity(0.10)))
        .accessibilityElement(children: .combine)
    }
}

private struct EmptyChats: View {
    let description: String
    var onAdd: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            ZStack {
                Circle().fill(Theme.accent.opacity(0.12)).frame(width: 120, height: 120)
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 50, weight: .light))
                    .foregroundStyle(Theme.accent)
            }
            .accessibilityHidden(true)
            Text("No conversations yet")
                .font(.title3.weight(.semibold))
            Text(description)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 36)
            Button("Add a contact", action: onAdd)
                .buttonStyle(PrimaryButtonStyle())
                .frame(maxWidth: 240)
                .accessibilityIdentifier("emptyAddContact")
        }
    }
}

private struct ConversationRow: View {
    let conversation: ConversationSummary

    var body: some View {
        HStack(spacing: 14) {
            Avatar(name: conversation.name, fingerprint: conversation.id, size: 52)
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(conversation.name.isEmpty ? "Unnamed contact" : conversation.name)
                        .font(.headline)
                        .lineLimit(1)
                    TrustBadge(trust: conversation.trust)
                    Spacer(minLength: 4)
                    if let last = conversation.lastActivity {
                        Text(Format.listTime(last))
                            .font(.caption)
                            .foregroundStyle(conversation.unread > 0 ? Theme.accent : .secondary)
                    }
                }
                HStack(spacing: 6) {
                    Text(conversation.lastMessage.isEmpty ? "No messages yet" : conversation.lastMessage)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                    Spacer(minLength: 4)
                    if conversation.unread > 0 {
                        Text("\(conversation.unread)")
                            .font(.caption2.bold())
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(Capsule().fill(Theme.accent))
                            .foregroundStyle(.white)
                    }
                }
            }
        }
        // NFR-COMP-04: the security state must be conveyed non-visually. A
        // VoiceOver user hears "Not verified yet" as part of the row, not as a
        // decorative image they have to hunt for.
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "\(conversation.name). \(conversation.trust.statusLine). \(conversation.lastMessage)"
                + (conversation.unread > 0 ? ". \(conversation.unread) unread" : "")
        )
    }
}

// MARK: - A conversation

struct ConversationView: View {
    @EnvironmentObject var state: AppState
    let fingerprint: Data

    @State private var draft = ""
    @State private var showingVerification = false
    @State private var showingDetails = false
    @State private var renaming = false
    @State private var newName = ""
    @State private var photoItem: PhotosPickerItem?
    @State private var showingPhotos = false
    @State private var showingFiles = false
    @State private var outgoing: OutgoingChoice?
    @State private var viewingImage: ViewedImage?
    @State private var viewingFile: AttachmentInfo?
    @FocusState private var composing: Bool

    private struct OutgoingChoice: Identifiable {
        let id = UUID()
        let file: AppState.OutgoingFile
        let isPhoto: Bool
    }

    private struct ViewedImage: Identifiable {
        var id: Data { attachment.id }
        let attachment: AttachmentInfo
        let image: UIImage
    }

    private var conversation: ConversationSummary? {
        state.conversations.first { $0.id == fingerprint }
    }

    private var name: String {
        let name = conversation?.name ?? ""
        return name.isEmpty ? "Unnamed contact" : name
    }

    private var trust: TrustState { conversation?.trust ?? .unverified }

    var body: some View {
        VStack(spacing: 0) {
            if trust != .verified {
                trustBanner
            }
            MessageList(
                fingerprint: fingerprint,
                messages: state.items(for: fingerprint),
                onOpenImage: { viewingImage = ViewedImage(attachment: $0, image: $1) },
                onOpenFile: { viewingFile = $0 }
            )
            // FR-DISC-05: a changed key blocks messaging. The composer is
            // *replaced*, not disabled — a greyed-out text field invites the
            // user to look for a way around it, and there must not be one.
            if trust.canSend {
                composer
            } else {
                blockedComposer
            }
        }
        .background(Color(.systemBackground))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Button {
                    showingDetails = true
                } label: {
                    HStack(spacing: 10) {
                        Avatar(name: name, fingerprint: fingerprint, size: 32)
                        VStack(alignment: .leading, spacing: 0) {
                            Text(name).font(.subheadline.weight(.semibold)).foregroundStyle(.primary)
                            Text(trust.statusLine)
                                .font(.caption2)
                                .foregroundStyle(trust == .keyChanged ? Theme.warning : .secondary)
                        }
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(name). \(trust.statusLine). Contact details")
            }
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    state.requestCall(to: fingerprint, video: true)
                } label: {
                    Image(systemName: "video")
                }
                .disabled(!trust.canSend)
                .accessibilityLabel("Video call")
                .accessibilityIdentifier("videoCallButton")
                Button {
                    state.requestCall(to: fingerprint)
                } label: {
                    Image(systemName: "phone")
                }
                .disabled(!trust.canSend)
                .accessibilityLabel("Call")
                .accessibilityIdentifier("callButton")
            }
        }
        .onAppear { state.openConversation(fingerprint) }
        .onDisappear { state.closeConversation(fingerprint) }
        // The name is only ever this device's: renaming tells nobody.
        .alert("Rename", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Save") { state.renameContact(fingerprint, to: newName) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Only you see this name.")
        }
        .sheet(isPresented: $showingVerification) {
            NavigationStack {
                VerificationView(
                    contactName: conversation?.name ?? "",
                    fingerprint: fingerprint,
                    myCode: state.fingerprintWords,
                    theirCode: VoidCore.fingerprintWords(for: fingerprint),
                    onResult: { state.handleVerificationResult(fingerprint: fingerprint, matched: $0) }
                )
            }
        }
        .sheet(isPresented: $showingDetails) {
            ContactDetails(
                name: name, fingerprint: fingerprint, trust: trust,
                onCompare: {
                    showingDetails = false
                    showingVerification = true
                },
                onRename: {
                    showingDetails = false
                    newName = conversation?.name ?? ""
                    renaming = true
                }
            )
            .presentationDetents([.medium, .large])
        }
        .photosPicker(isPresented: $showingPhotos, selection: $photoItem, matching: .images)
        .onChange(of: photoItem) { item in
            guard let item else { return }
            photoItem = nil
            Task {
                guard let data = try? await item.loadTransferable(type: Data.self),
                    let file = OutgoingMedia.preparePhoto(data)
                else {
                    state.lastError = "That photo couldn't be read."
                    return
                }
                outgoing = OutgoingChoice(file: file, isPhoto: true)
            }
        }
        .fileImporter(isPresented: $showingFiles, allowedContentTypes: [.item]) { result in
            guard case .success(let url) = result else { return }
            guard let file = OutgoingMedia.prepareFile(url) else {
                state.lastError = "That file couldn't be read."
                return
            }
            outgoing = OutgoingChoice(file: file, isPhoto: false)
        }
        .sheet(item: $outgoing) { choice in
            SendAttachmentSheet(
                file: choice.file, isPhoto: choice.isPhoto, contactName: name,
                onSend: { state.sendFile($0, to: fingerprint) },
                onCancel: { TempFiles.remove(choice.file.url) }
            )
            .presentationDetents([.medium, .large])
        }
        .fullScreenCover(item: $viewingImage) { viewed in
            ImageViewer(attachment: viewed.attachment, image: viewed.image)
        }
        .sheet(item: Binding(
            get: { viewingFile.map { IdentifiedAttachment(info: $0) } },
            set: { viewingFile = $0?.info }
        )) { item in
            FileViewer(attachment: item.info)
        }
    }

    private struct IdentifiedAttachment: Identifiable {
        let info: AttachmentInfo
        var id: Data { info.id }
    }

    private var trustBanner: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: trust == .keyChanged ? "exclamationmark.triangle.fill" : "person.badge.shield.checkmark")
                .font(.title3)
                .foregroundStyle(trust == .keyChanged ? Theme.warning : Theme.accent)
            VStack(alignment: .leading, spacing: 6) {
                Text(trust.statusLine).font(.subheadline.weight(.semibold))
                Text(trust.guidance)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Button(trust == .keyChanged ? "Check their code" : "Compare codes") {
                        showingVerification = true
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(trust == .keyChanged ? Theme.warning : Theme.accent)
                    .controlSize(.small)
                    if trust == .keyChanged {
                        // Acknowledging drops to "not verified", never straight
                        // to "verified" — dismissing a banner is not the same
                        // as comparing codes with a person. It goes to the
                        // engine, which is what actually blocks sending.
                        Button("I've checked, continue") {
                            state.acknowledgeKeyChange(fingerprint: fingerprint)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
                .padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(
            (trust == .keyChanged ? Theme.warning : Theme.accent).opacity(0.08)
        )
        .accessibilityElement(children: .contain)
    }

    private var composer: some View {
        HStack(alignment: .bottom, spacing: 10) {
            Menu {
                Button {
                    showingPhotos = true
                } label: {
                    Label("Photo", systemImage: "photo.on.rectangle")
                }
                Button {
                    showingFiles = true
                } label: {
                    Label("File", systemImage: "doc")
                }
                #if DEBUG
                    if ProcessInfo.processInfo.arguments.contains("-uiTestsAttachmentFixture") {
                        Button {
                            sendFixture()
                        } label: {
                            Label("Test picture", systemImage: "testtube.2")
                        }
                        .accessibilityIdentifier("attachTestPicture")
                    }
                #endif
            } label: {
                Image(systemName: "plus")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 36, height: 36)
                    .background(Circle().fill(Theme.accent.opacity(0.12)))
            }
            .accessibilityLabel("Attach")
            .accessibilityIdentifier("attachButton")

            TextField("Message", text: $draft, axis: .vertical)
                .lineLimit(1...6)
                .focused($composing)
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                .background(
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .fill(Color(.secondarySystemBackground)))

            let empty = draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            Button {
                let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !text.isEmpty else { return }
                // Queued, not sent: the engine holds it until the next
                // scheduled slot so that send timing does not reveal typing
                // timing (FR-MSG-06).
                state.send(to: fingerprint, text: text)
                draft = ""
            } label: {
                Image(systemName: "arrow.up")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(width: 36, height: 36)
                    .background(Circle().fill(empty ? AnyShapeStyle(Color.secondary.opacity(0.35)) : AnyShapeStyle(Theme.outgoing)))
            }
            .disabled(empty)
            .accessibilityLabel("Send")
            .accessibilityIdentifier("sendButton")
            .animation(.easeOut(duration: 0.15), value: empty)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }

    #if DEBUG
        /// A picture made here, for UI tests: the Simulator's photo library
        /// cannot be driven reliably from a test, and what is being tested is
        /// everything after the picker.
        private func sendFixture() {
            let size = CGSize(width: 1200, height: 900)
            let image = UIGraphicsImageRenderer(size: size).image { context in
                let colors = [UIColor.systemIndigo.cgColor, UIColor.systemPink.cgColor] as CFArray
                if let gradient = CGGradient(
                    colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0, 1])
                {
                    context.cgContext.drawLinearGradient(
                        gradient, start: .zero, end: CGPoint(x: size.width, y: size.height), options: [])
                }
                ("Void test picture" as NSString).draw(
                    at: CGPoint(x: 80, y: 400),
                    withAttributes: [.font: UIFont.boldSystemFont(ofSize: 90), .foregroundColor: UIColor.white])
            }
            guard let data = image.jpegData(compressionQuality: 0.9),
                let file = OutgoingMedia.preparePhoto(data)
            else { return }
            let named = AppState.OutgoingFile(
                url: file.url, name: "Test picture.jpg", mime: file.mime, width: file.width,
                height: file.height, caption: "A test picture")
            state.sendFile(named, to: fingerprint)
        }
    #endif

    private var blockedComposer: some View {
        VStack(spacing: 8) {
            Label("Messaging is paused", systemImage: "hand.raised.fill")
                .font(.subheadline.bold())
                .foregroundStyle(Theme.warning)
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
        .background(.bar)
        .accessibilityElement(children: .combine)
    }
}

/// The messages, grouped by day and by sender, kept scrolled to the newest.
private struct MessageList: View {
    let fingerprint: Data
    let messages: [MessageItem]
    var onOpenImage: (AttachmentInfo, UIImage) -> Void
    var onOpenFile: (AttachmentInfo) -> Void

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 2) {
                    ForEach(Array(messages.enumerated()), id: \.element.id) { index, message in
                        let previous = index > 0 ? messages[index - 1] : nil
                        let next = index + 1 < messages.count ? messages[index + 1] : nil
                        if previous.map({ !Calendar.current.isDate($0.timestamp, inSameDayAs: message.timestamp) }) ?? true {
                            Text(Format.dayHeading(message.timestamp))
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .padding(.vertical, 12)
                                .frame(maxWidth: .infinity)
                        }
                        let continues = next.map { $0.isOutgoing == message.isOutgoing
                            && $0.timestamp.timeIntervalSince(message.timestamp) < 120 } ?? false
                        MessageBubble(
                            message: message,
                            fingerprint: fingerprint,
                            showsFooter: !continues,
                            onOpenImage: onOpenImage,
                            onOpenFile: onOpenFile
                        )
                        .padding(.top, previous.map { $0.isOutgoing != message.isOutgoing } ?? false ? 10 : 0)
                        .id(message.id)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 12)
                .animation(.spring(response: 0.35, dampingFraction: 0.85), value: messages.map(\.id))
            }
            .scrollDismissesKeyboard(.interactively)
            .onAppear {
                if let last = messages.last { proxy.scrollTo(last.id, anchor: .bottom) }
            }
            .onChange(of: messages.last?.id) { id in
                guard let id else { return }
                withAnimation(.easeOut(duration: 0.25)) { proxy.scrollTo(id, anchor: .bottom) }
            }
        }
    }
}

private struct MessageBubble: View {
    let message: MessageItem
    let fingerprint: Data
    let showsFooter: Bool
    var onOpenImage: (AttachmentInfo, UIImage) -> Void
    var onOpenFile: (AttachmentInfo) -> Void

    private var shape: BubbleShape {
        BubbleShape(outgoing: message.isOutgoing, tail: showsFooter)
    }

    var body: some View {
        HStack(alignment: .bottom) {
            if message.isOutgoing { Spacer(minLength: 56) }
            VStack(alignment: message.isOutgoing ? .trailing : .leading, spacing: 3) {
                content
                if showsFooter {
                    footer
                }
            }
            if !message.isOutgoing { Spacer(minLength: 56) }
        }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder private var content: some View {
        if let attachment = message.attachment {
            VStack(alignment: .leading, spacing: 0) {
                if attachment.isImage {
                    AttachmentImageBubble(
                        message: message, attachment: attachment, fingerprint: fingerprint,
                        onOpen: onOpenImage)
                } else {
                    AttachmentFileBubble(
                        message: message, attachment: attachment, fingerprint: fingerprint,
                        onOpen: onOpenFile)
                }
                if !message.text.isEmpty {
                    Text(message.text)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .frame(maxWidth: 250, alignment: .leading)
                }
            }
            .foregroundStyle(message.isOutgoing ? Color.white : Color.primary)
            .background(background)
            .clipShape(shape)
        } else {
            Text(message.text)
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                .foregroundStyle(message.isOutgoing ? Color.white : Color.primary)
                .background(background)
                .clipShape(shape)
                .textSelection(.enabled)
                .accessibilityLabel(
                    (message.isOutgoing ? "You said: " : "They said: ") + message.text
                        + (message.delivery.label.isEmpty ? "" : ". \(message.delivery.label)"))
        }
    }

    @ViewBuilder private var background: some View {
        if message.isOutgoing {
            Theme.outgoing
        } else {
            Theme.incoming
        }
    }

    private var footer: some View {
        HStack(spacing: 4) {
            Text(message.timestamp.formatted(date: .omitted, time: .shortened))
            if message.isOutgoing {
                if message.transfer?.direction == .upload, message.transfer?.failure == nil {
                    Text("· Sending file…")
                } else if !message.delivery.label.isEmpty {
                    Text("· \(message.delivery.label)")
                        .foregroundStyle(message.delivery == .failed ? Theme.warning : .secondary)
                }
                Image(systemName: deliveryIcon)
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(message.delivery == .deposited || message.delivery == .collected ? Theme.accent : .secondary)
                    .accessibilityHidden(true)
            }
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 6)
        .padding(.bottom, 4)
    }

    private var deliveryIcon: String {
        switch message.delivery {
        case .queued: return "clock"
        case .deposited: return "checkmark"
        case .collected: return "checkmark.circle"
        case .failed: return "exclamationmark.circle"
        case .received: return ""
        }
    }
}

/// A bubble: rounded, with a tighter corner on the speaker's side for the last
/// message of a run.
private struct BubbleShape: Shape {
    let outgoing: Bool
    let tail: Bool

    func path(in rect: CGRect) -> Path {
        let big: CGFloat = 20
        let small: CGFloat = tail ? 6 : 20
        let tl = big
        let tr = outgoing ? big : big
        let br = outgoing ? small : big
        let bl = outgoing ? big : small
        var path = Path()
        path.move(to: CGPoint(x: rect.minX + tl, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX - tr, y: rect.minY))
        path.addArc(
            tangent1End: CGPoint(x: rect.maxX, y: rect.minY), tangent2End: CGPoint(x: rect.maxX, y: rect.minY + tr),
            radius: tr)
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - br))
        path.addArc(
            tangent1End: CGPoint(x: rect.maxX, y: rect.maxY), tangent2End: CGPoint(x: rect.maxX - br, y: rect.maxY),
            radius: br)
        path.addLine(to: CGPoint(x: rect.minX + bl, y: rect.maxY))
        path.addArc(
            tangent1End: CGPoint(x: rect.minX, y: rect.maxY), tangent2End: CGPoint(x: rect.minX, y: rect.maxY - bl),
            radius: bl)
        path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + tl))
        path.addArc(
            tangent1End: CGPoint(x: rect.minX, y: rect.minY), tangent2End: CGPoint(x: rect.minX + tl, y: rect.minY),
            radius: tl)
        path.closeSubpath()
        return path
    }
}

/// Who this is, how sure you are of it, and what to do about that.
private struct ContactDetails: View {
    let name: String
    let fingerprint: Data
    let trust: TrustState
    var onCompare: () -> Void
    var onRename: () -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                Avatar(name: name, fingerprint: fingerprint, size: 84)
                    .padding(.top, 28)
                VStack(spacing: 6) {
                    Text(name).font(.title2.weight(.semibold))
                    TrustBadge(trust: trust, compact: false)
                }
                Text(trust.guidance)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 28)
                VStack(spacing: 10) {
                    Button(action: onCompare) {
                        Label("Compare security codes", systemImage: "checkmark.shield")
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    Button(action: onRename) {
                        Label("Rename", systemImage: "pencil")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                    }
                    .buttonStyle(.bordered)
                    .tint(Theme.accent)
                }
                .padding(.horizontal, 24)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Their security code")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(VoidCore.fingerprintWords(for: fingerprint))
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
                .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemBackground)))
                .padding(.horizontal, 24)
            }
            .padding(.bottom, 24)
        }
    }
}

// MARK: - Verification (FR-DISC-04)

struct VerificationView: View {
    let contactName: String
    var fingerprint = Data()
    /// Both codes, rendered from the real fingerprints by the caller —
    /// `VoidCore.fingerprintWords` for mine, `VoidCore.fingerprintWords(for:)`
    /// for theirs. Defaulted only so this view still compiles in a preview.
    var myCode = "tinas-dofil-lusab-babad\ngutih-tugad-kabad-lusab"
    var theirCode = "lusab-babad-gutih-tugad\nkabad-lusab-tinas-dofil"
    /// Called once the user confirms a match or mismatch, so the caller can
    /// tell the engine (`VoidCore.markVerified` / `acknowledgeKeyChange`) —
    /// this view only knows what the user said, not how to record it.
    var onResult: (Bool) -> Void = { _ in }

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text(
                    "Compare these codes with \(contactName.isEmpty ? "them" : contactName) in "
                        + "person, or on a call where you recognise their voice. Do not compare "
                        + "them inside Void — if someone is intercepting this conversation, they "
                        + "would be showing you their own codes."
                )
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                codeCard(title: "Their code", code: theirCode, highlight: true)
                codeCard(title: "Your code", code: myCode, highlight: false)

                VStack(spacing: 10) {
                    Button {
                        onResult(true)
                        dismiss()
                    } label: {
                        Label("The codes match", systemImage: "checkmark.circle.fill")
                    }
                    .buttonStyle(PrimaryButtonStyle(tint: Theme.verified))

                    Button(role: .destructive) {
                        onResult(false)
                        dismiss()
                    } label: {
                        Label("They don't match", systemImage: "exclamationmark.triangle")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                    }
                    .buttonStyle(.bordered)
                }
                Text(
                    "If the codes don't match, stop using this conversation and reach the person "
                        + "another way. Void will pause messaging."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
            .padding(20)
        }
        .navigationTitle("Compare codes")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Not now") { dismiss() }
            }
        }
    }

    private func codeCard(title: String, code: String, highlight: Bool) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Text(code)
                .font(.title3.monospaced().weight(.medium))
                .textSelection(.enabled)
                .accessibilityLabel(spelledOut(code))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(highlight ? Theme.accent.opacity(0.10) : Color(.secondarySystemBackground)))
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
