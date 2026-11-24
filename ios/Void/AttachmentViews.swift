//  AttachmentViews.swift
//
//  Files in a conversation: the bubbles that show them, the viewer that opens
//  them, and the sheet that sends them (D-032).
//
//  ## What a photo loses on the way out
//
//  A photo from the library carries its metadata — where it was taken, often
//  to a few metres, and on what. Void re-encodes every photo it sends from its
//  pixels alone, so none of that leaves the phone, and the send sheet says so.
//  A file sent as a file is sent as it is: Void cannot know what a PDF or a
//  document keeps inside itself, and the sheet says that too.

import PhotosUI
import QuickLook
import SwiftUI
import UIKit
import UniformTypeIdentifiers

// MARK: - Images, decoded once

/// Decoded images by attachment id. In memory only: the sealed copy on disk
/// is the only copy that persists.
@MainActor
final class AttachmentImages {
    static let shared = AttachmentImages()
    private let cache = NSCache<NSData, UIImage>()

    init() {
        cache.countLimit = 60
    }

    func cached(_ id: Data) -> UIImage? {
        cache.object(forKey: id as NSData)
    }

    func load(_ attachment: AttachmentInfo, from state: AppState) async -> UIImage? {
        if let image = cached(attachment.id) { return image }
        guard let data = await state.attachmentData(attachment) else { return nil }
        let image = await Task.detached(priority: .userInitiated) { () -> UIImage? in
            guard let image = UIImage(data: data) else { return nil }
            return image.preparingForDisplay() ?? image
        }.value
        if let image {
            cache.setObject(image, forKey: attachment.id as NSData)
        }
        return image
    }
}

// MARK: - Preparing what is sent

enum OutgoingMedia {
    /// The longest side a sent photo keeps. Enough for any phone screen, and a
    /// photo of a few hundred kilobytes rather than several megabytes — which
    /// over Tor is the difference between seconds and a minute.
    static let maxPixels: CGFloat = 2048

    /// Re-encode a photo from its pixels alone, so none of its metadata —
    /// location, time, camera — leaves the phone. Returns Void's own copy.
    static func preparePhoto(_ data: Data) -> AppState.OutgoingFile? {
        guard let source = UIImage(data: data) else { return nil }
        let size = source.size
        let scale = min(1, maxPixels / max(size.width, size.height))
        let target = CGSize(width: (size.width * scale).rounded(), height: (size.height * scale).rounded())
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        format.opaque = true
        let image = UIGraphicsImageRenderer(size: target, format: format).image { _ in
            source.draw(in: CGRect(origin: .zero, size: target))
        }
        guard let jpeg = image.jpegData(compressionQuality: 0.82) else { return nil }
        let url = TempFiles.path(named: "photo.jpg")
        guard (try? jpeg.write(to: url, options: [.completeFileProtection])) != nil else { return nil }
        let stamp = Date().formatted(.iso8601.year().month().day().time(includingFractionalSeconds: false))
            .replacingOccurrences(of: ":", with: "-")
        return AppState.OutgoingFile(
            url: url, name: "Photo \(stamp).jpg", mime: "image/jpeg",
            width: Int(target.width), height: Int(target.height))
    }

    /// A copy of a file the user picked, made while access to it is granted.
    static func prepareFile(_ picked: URL) -> AppState.OutgoingFile? {
        let scoped = picked.startAccessingSecurityScopedResource()
        defer {
            if scoped { picked.stopAccessingSecurityScopedResource() }
        }
        let name = picked.lastPathComponent
        let copy = TempFiles.path(named: name)
        guard (try? FileManager.default.copyItem(at: picked, to: copy)) != nil else { return nil }
        let type = UTType(filenameExtension: picked.pathExtension)
        var file = AppState.OutgoingFile(
            url: copy, name: name, mime: type?.preferredMIMEType ?? "application/octet-stream")
        if type?.conforms(to: .image) == true, let image = UIImage(contentsOfFile: copy.path) {
            file.width = Int(image.size.width * image.scale)
            file.height = Int(image.size.height * image.scale)
        }
        return file
    }
}

// MARK: - In a bubble

/// A photo in a conversation: the picture once it is here, its progress while
/// it moves, and a way to fetch it if it was too large to fetch unasked.
struct AttachmentImageBubble: View {
    @EnvironmentObject var state: AppState
    let message: MessageItem
    let attachment: AttachmentInfo
    let fingerprint: Data
    var onOpen: (AttachmentInfo, UIImage) -> Void

    @State private var image: UIImage?

    private var width: CGFloat {
        attachment.aspectRatio >= 1 ? 250 : 200
    }

    var body: some View {
        ZStack {
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
            } else {
                LinearGradient(
                    colors: Theme.avatarColors(for: attachment.id.isEmpty ? fingerprint : attachment.id)
                        .map { $0.opacity(0.35) },
                    startPoint: .topLeading, endPoint: .bottomTrailing)
                Image(systemName: "photo")
                    .font(.system(size: 30, weight: .light))
                    .foregroundStyle(.white.opacity(0.8))
            }
            TransferOverlay(
                message: message, attachment: attachment, fingerprint: fingerprint, onMedia: true)
        }
        .frame(width: width, height: width / max(0.5, min(attachment.aspectRatio, 2)))
        .clipped()
        .contentShape(Rectangle())
        .onTapGesture {
            if let image { onOpen(attachment, image) }
        }
        .task(id: attachment.isLocal) {
            guard attachment.isLocal, image == nil else { return }
            image = await AttachmentImages.shared.load(attachment, from: state)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(message.isOutgoing ? "Photo you sent" : "Photo")
        .accessibilityHint(image == nil ? "" : "Opens the photo")
        .accessibilityValue(accessibilityState)
        .accessibilityIdentifier("attachmentPhoto")
    }

    /// Where the photo is, in words: for VoiceOver, and for the end-to-end
    /// tests, which wait on it.
    private var accessibilityState: String {
        let shown: String
        if let transfer = message.transfer {
            if transfer.failure != nil {
                shown = "failed"
            } else {
                let percent = Int(transfer.fraction * 100)
                shown = transfer.direction == .upload ? "sending \(percent) percent" : "downloading \(percent) percent"
            }
        } else {
            shown = image == nil ? "not loaded" : "loaded"
        }
        let delivery = message.isOutgoing && message.transfer == nil ? message.delivery.label : ""
        return delivery.isEmpty ? shown : "\(shown), \(delivery)"
    }
}

/// Any other file: an icon, its name and size, and its progress.
struct AttachmentFileBubble: View {
    let message: MessageItem
    let attachment: AttachmentInfo
    let fingerprint: Data
    var onOpen: (AttachmentInfo) -> Void

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(message.isOutgoing ? Color.white.opacity(0.22) : Theme.accent.opacity(0.14))
                Image(systemName: Self.icon(for: attachment))
                    .font(.system(size: 20, weight: .medium))
                    .foregroundStyle(message.isOutgoing ? .white : Theme.accent)
            }
            .frame(width: 44, height: 44)
            VStack(alignment: .leading, spacing: 3) {
                Text(attachment.name)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(2)
                    .truncationMode(.middle)
                Text("\(attachment.sizeDescription) · \(attachment.typeLabel)")
                    .font(.caption)
                    .opacity(0.75)
            }
            Spacer(minLength: 0)
            TransferOverlay(
                message: message, attachment: attachment, fingerprint: fingerprint, onMedia: false)
        }
        .foregroundStyle(message.isOutgoing ? Color.white : Color.primary)
        .padding(12)
        .frame(width: 250)
        .contentShape(Rectangle())
        .onTapGesture {
            if attachment.isLocal, message.transfer == nil { onOpen(attachment) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("File \(attachment.name), \(attachment.sizeDescription)")
    }

    static func icon(for attachment: AttachmentInfo) -> String {
        let type = UTType(mimeType: attachment.mime)
        if attachment.isVideo { return "film" }
        if attachment.isAudio { return "waveform" }
        if type?.conforms(to: .pdf) == true { return "doc.richtext" }
        if type?.conforms(to: .archive) == true { return "archivebox" }
        if type?.conforms(to: .spreadsheet) == true { return "tablecells" }
        if type?.conforms(to: .presentation) == true { return "rectangle.on.rectangle" }
        if type?.conforms(to: .text) == true { return "doc.text" }
        return "doc"
    }
}

/// Progress, failure, or the button that fetches a file — whatever a bubble
/// needs to show over or beside its file.
private struct TransferOverlay: View {
    @EnvironmentObject var state: AppState
    let message: MessageItem
    let attachment: AttachmentInfo
    let fingerprint: Data
    let onMedia: Bool

    var body: some View {
        if let transfer = message.transfer {
            if let failure = transfer.failure {
                failed(failure, transfer: transfer)
            } else {
                ProgressRing(
                    fraction: transfer.fraction, direction: transfer.direction,
                    tint: onMedia || message.isOutgoing ? .white : Theme.accent, backdrop: onMedia)
                    .accessibilityLabel(
                        transfer.direction == .upload
                            ? "Sending, \(Int(transfer.fraction * 100)) percent"
                            : "Downloading, \(Int(transfer.fraction * 100)) percent")
            }
        } else if !attachment.isLocal, !message.isOutgoing {
            Button {
                state.download(attachment, from: fingerprint)
            } label: {
                Label(onMedia ? attachment.sizeDescription : "Download", systemImage: "arrow.down.circle.fill")
                    .font(.footnote.weight(.semibold))
                    .padding(.horizontal, onMedia ? 12 : 0)
                    .padding(.vertical, onMedia ? 8 : 0)
                    .background {
                        if onMedia { Capsule().fill(.ultraThinMaterial) }
                    }
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Download, \(attachment.sizeDescription)")
        }
    }

    @ViewBuilder
    private func failed(_ failure: String, transfer: TransferProgress) -> some View {
        VStack(spacing: 6) {
            Image(systemName: "exclamationmark.circle.fill")
                .font(.title3)
                .foregroundStyle(Theme.warning)
            if onMedia {
                Text(failure)
                    .font(.caption2)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.white)
                    .padding(.horizontal, 10)
            }
            HStack(spacing: 8) {
                Button("Retry") {
                    if transfer.direction == .upload {
                        state.retryUpload(message.id)
                    } else {
                        state.download(attachment, from: fingerprint)
                    }
                }
                if transfer.direction == .upload {
                    Button("Discard", role: .destructive) { state.discardUpload(message.id) }
                }
            }
            .font(.caption.weight(.semibold))
            .buttonStyle(.bordered)
            .controlSize(.mini)
        }
        .padding(8)
        .background {
            if onMedia { RoundedRectangle(cornerRadius: 12).fill(.black.opacity(0.45)) }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(failure)
    }
}

/// A ring that fills as a file moves, with its direction in the middle.
struct ProgressRing: View {
    let fraction: Double
    let direction: TransferProgress.Direction
    var tint: Color = .white
    var backdrop = true

    var body: some View {
        ZStack {
            Circle()
                .fill(backdrop ? Color.black.opacity(0.35) : Color.clear)
            Circle()
                .stroke(tint.opacity(0.25), lineWidth: 3)
            Circle()
                .trim(from: 0, to: max(0.03, fraction))
                .stroke(tint, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.easeOut(duration: 0.25), value: fraction)
            Image(systemName: direction == .upload ? "arrow.up" : "arrow.down")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(tint)
        }
        .frame(width: 40, height: 40)
    }
}

// MARK: - Opening

/// A photo, full screen: pinch to zoom, share, done.
struct ImageViewer: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    let attachment: AttachmentInfo
    let image: UIImage

    @State private var scale: CGFloat = 1
    @State private var settledScale: CGFloat = 1
    @State private var shared: URL?

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .scaleEffect(scale)
                    .gesture(
                        MagnificationGesture()
                            .onChanged { scale = max(1, settledScale * $0) }
                            .onEnded { _ in settledScale = scale }
                    )
                    .onTapGesture(count: 2) {
                        withAnimation(.spring()) {
                            scale = scale > 1 ? 1 : 2.5
                            settledScale = scale
                        }
                    }
                    .accessibilityLabel("Photo")
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    if let shared {
                        ShareLink(item: shared) {
                            Label("Share", systemImage: "square.and.arrow.up")
                        }
                    }
                }
            }
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbarColorScheme(.dark, for: .navigationBar)
        }
        .task { shared = await state.exportAttachment(attachment) }
        .onDisappear {
            if let shared { TempFiles.remove(shared) }
        }
    }
}

/// Any other file, in QuickLook, from a plaintext copy Void removes again when
/// the viewer closes.
struct FileViewer: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    let attachment: AttachmentInfo
    @State private var url: URL?
    @State private var failed = false

    var body: some View {
        NavigationStack {
            Group {
                if let url {
                    QuickLookPreview(url: url)
                        .ignoresSafeArea(edges: .bottom)
                } else if failed {
                    VStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.largeTitle)
                            .foregroundStyle(Theme.warning)
                        Text("This file couldn't be opened.")
                    }
                } else {
                    ProgressView("Opening…")
                }
            }
            .navigationTitle(attachment.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    if let url {
                        ShareLink(item: url) {
                            Label("Share", systemImage: "square.and.arrow.up")
                        }
                    }
                }
            }
        }
        .task {
            url = await state.exportAttachment(attachment)
            failed = url == nil
        }
        .onDisappear {
            if let url { TempFiles.remove(url) }
        }
    }
}

private struct QuickLookPreview: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> QLPreviewController {
        let controller = QLPreviewController()
        controller.dataSource = context.coordinator
        return controller
    }

    func updateUIViewController(_ controller: QLPreviewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(url: url) }

    final class Coordinator: NSObject, QLPreviewControllerDataSource {
        let url: URL
        init(url: URL) { self.url = url }
        func numberOfPreviewItems(in controller: QLPreviewController) -> Int { 1 }
        func previewController(_ controller: QLPreviewController, previewItemAt index: Int) -> QLPreviewItem {
            url as NSURL
        }
    }
}

// MARK: - Sending

/// What the user is about to send: a preview, an optional caption, and what
/// sending it reveals — said before they send, not after.
struct SendAttachmentSheet: View {
    @Environment(\.dismiss) private var dismiss
    let file: AppState.OutgoingFile
    let isPhoto: Bool
    let contactName: String
    var onSend: (AppState.OutgoingFile) -> Void
    var onCancel: () -> Void

    @State private var caption = ""
    @State private var image: UIImage?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    preview
                    TextField("Add a caption (optional)", text: $caption, axis: .vertical)
                        .lineLimit(1...4)
                        .padding(12)
                        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.secondarySystemBackground)))
                    Label {
                        Text(
                            isPhoto
                                ? "Void sends the picture only: where and when it was taken, and on what, are removed first."
                                : "Void sends this file exactly as it is. Anything the file keeps inside itself — an author's name, edits, location — goes with it."
                        )
                    } icon: {
                        Image(systemName: isPhoto ? "location.slash" : "info.circle")
                    }
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    Label {
                        Text(
                            "Files travel to the relay encrypted, over a connection of their own. Someone watching your connection can see that you sent something about this size."
                        )
                    } icon: {
                        Image(systemName: "lock.shield")
                    }
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
                .padding(20)
            }
            .navigationTitle(isPhoto ? "Send photo" : "Send file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        onCancel()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Send") {
                        var outgoing = file
                        outgoing.caption = caption.trimmingCharacters(in: .whitespacesAndNewlines)
                        onSend(outgoing)
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .accessibilityIdentifier("sendAttachmentButton")
                }
            }
        }
        .task {
            if isPhoto { image = UIImage(contentsOfFile: file.url.path) }
        }
    }

    @ViewBuilder private var preview: some View {
        if let image {
            Image(uiImage: image)
                .resizable()
                .scaledToFit()
                .frame(maxHeight: 340)
                .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
                .accessibilityLabel("The photo you are sending")
        } else {
            let info = AttachmentInfo(
                id: Data(), size: (try? file.url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
                    .map(UInt64.init) ?? 0,
                width: 0, height: 0, name: file.name, mime: file.mime, isLocal: true)
            HStack(spacing: 14) {
                Image(systemName: AttachmentFileBubble.icon(for: info))
                    .font(.system(size: 28))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 56, height: 56)
                    .background(RoundedRectangle(cornerRadius: 14).fill(Theme.accent.opacity(0.12)))
                VStack(alignment: .leading, spacing: 4) {
                    Text(file.name).font(.headline).lineLimit(2)
                    Text("\(info.sizeDescription) · to \(contactName)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(16)
            .background(RoundedRectangle(cornerRadius: 18).fill(Color(.secondarySystemBackground)))
        }
    }
}
