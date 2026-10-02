//  Attachments.swift
//
//  Picking, confirming, showing and saving files in a conversation.
//
//  ## A file is a message
//
//  Nothing about sending a file is different on the wire from sending text
//  (`void_proto::content`, D-032): the same ratchet, the same fixed-size
//  records, one per emission slot. The relay cannot tell a photo from the
//  same number of texts. What a file costs is time — a photo is hundreds of
//  records at one every five seconds — and this file's job is to say so, in
//  numbers, before the user commits to it (non-negotiable #8: every option
//  states its cost).
//
//  ## Photos are shrunk, on purpose
//
//  A phone camera's photo is several megabytes; the protocol carries 500 KiB
//  in one message. Pictures are re-encoded here at a size that reads well on
//  a phone screen and sends in minutes rather than the better part of an
//  hour. That also strips the camera's metadata — location, device, time —
//  which a messenger built around not leaking who and where should not be
//  forwarding by accident.
//
//  ## Nothing here reaches the core
//
//  Everything below is platform work: pickers, image codecs, the share sheet.
//  Bytes go to `AppState.sendFile`, and come back from
//  `AppState.attachmentData`, and that is the whole interface.

import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Sizes and durations

enum AttachmentFormat {
    /// "240 KB", "1.2 MB".
    static func size(bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    /// "40 seconds", "about 4 minutes", "about 43 minutes". Rounded up: a
    /// promise of time is better kept short than broken.
    static func duration(seconds: Int) -> String {
        if seconds < 60 {
            return "\(max(seconds, 5)) seconds"
        }
        let minutes = (seconds + 59) / 60
        return minutes == 1 ? "1 minute" : "\(minutes) minutes"
    }
}

// MARK: - Picking

/// The two ways to attach: a photo from the library, or any file.
///
/// Two buttons rather than one menu, because `PhotosPicker` is a view of its
/// own on iOS 16 (NFR-COMP-01's floor; the `.photosPicker` modifier that
/// would let it sit inside a menu is iOS 17).
struct AttachmentPicker: View {
    /// Called with the file once it has been read and, for a picture,
    /// shrunk. Confirmation is the caller's.
    var onPicked: (PendingAttachment) -> Void

    @State private var photoItem: PhotosPickerItem?
    @State private var showingFiles = false
    @State private var failure: String?

    var body: some View {
        HStack(spacing: 4) {
            PhotosPicker(selection: $photoItem, matching: .images) {
                Image(systemName: "photo").font(.title3)
            }
            .accessibilityLabel("Attach a photo")
            Button {
                showingFiles = true
            } label: {
                Image(systemName: "paperclip").font(.title3)
            }
            .accessibilityLabel("Attach a file")
        }
        .onChange(of: photoItem) { item in
            guard let item else { return }
            photoItem = nil
            Task {
                if let picked = await AttachmentImport.fromPhoto(item) {
                    onPicked(picked)
                } else {
                    failure = "That photo couldn't be read."
                }
            }
        }
        .fileImporter(isPresented: $showingFiles, allowedContentTypes: [.item]) { result in
            switch result {
            case .success(let url):
                switch AttachmentImport.fromFile(url) {
                case .success(let picked): onPicked(picked)
                case .failure(let error): failure = error.localizedDescription
                }
            case .failure:
                failure = "That file couldn't be read."
            }
        }
        .alert(
            "Can't attach that",
            isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(failure ?? "")
        }
    }
}

/// Turns what the pickers hand back into bytes the protocol can carry.
enum AttachmentImport {
    /// Longest side of a sent picture, in pixels. Reads well on a phone and
    /// lands around 100–250 KB as JPEG: a few minutes to send.
    static let maxImageSide: CGFloat = 1280

    /// A file the picker named but that could not be read.
    struct Unreadable: LocalizedError {
        var errorDescription: String? { "That file couldn't be read." }
    }

    /// A file that cannot be made to fit.
    struct TooLarge: LocalizedError {
        let size: Int
        var errorDescription: String? {
            "This file is \(AttachmentFormat.size(bytes: size)). Void sends files of up to "
                + "\(AttachmentFormat.size(bytes: VoidCore.fileMaxBytes)) in one message; "
                + "photos are shrunk to fit, other files are not."
        }
    }

    /// A photo from the library, re-encoded to fit. `nil` if it cannot be read.
    static func fromPhoto(_ item: PhotosPickerItem) async -> PendingAttachment? {
        guard let data = try? await item.loadTransferable(type: Data.self) else { return nil }
        return shrink(imageData: data, name: "photo-\(Self.stamp()).jpg")
    }

    /// A file from the Files picker. Pictures are shrunk like photos; anything
    /// else is sent as it is, or refused if it is over the bound.
    static func fromFile(_ url: URL) -> Result<PendingAttachment, Error> {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
        }
        guard let data = try? Data(contentsOf: url) else {
            return .failure(Unreadable())
        }
        let type = UTType(filenameExtension: url.pathExtension)
        let mime = type?.preferredMIMEType ?? ""
        if type?.conforms(to: .image) == true, let shrunk = shrink(imageData: data, name: url.lastPathComponent) {
            return .success(shrunk)
        }
        guard data.count <= VoidCore.fileMaxBytes else {
            return .failure(TooLarge(size: data.count))
        }
        return .success(PendingAttachment(name: url.lastPathComponent, mime: mime, data: data))
    }

    /// Re-encode a picture as JPEG under the bound: first by size, then by
    /// quality, then smaller again. Always a fresh encoding, even for a small
    /// JPEG that would have fit as it was, because the fresh encoding is what
    /// drops the camera's metadata.
    static func shrink(imageData: Data, name: String) -> PendingAttachment? {
        guard var image = UIImage(data: imageData) else { return nil }
        let limit = VoidCore.fileMaxBytes
        var side = min(maxImageSide, max(image.size.width, image.size.height))
        var quality: CGFloat = 0.7
        for _ in 0..<8 {
            image = resized(image, longestSide: side)
            if let jpeg = image.jpegData(compressionQuality: quality), jpeg.count <= limit {
                let base = (name as NSString).deletingPathExtension
                return PendingAttachment(name: "\(base).jpg", mime: "image/jpeg", data: jpeg)
            }
            if quality > 0.4 {
                quality -= 0.15
            } else {
                side *= 0.7
                quality = 0.7
            }
        }
        return nil
    }

    private static func resized(_ image: UIImage, longestSide: CGFloat) -> UIImage {
        let longest = max(image.size.width, image.size.height)
        guard longest > longestSide, longest > 0 else { return image }
        let scale = longestSide / longest
        let target = CGSize(width: image.size.width * scale, height: image.size.height * scale)
        let format = UIGraphicsImageRendererFormat.default()
        format.scale = 1
        return UIGraphicsImageRenderer(size: target, format: format).image { _ in
            image.draw(in: CGRect(origin: .zero, size: target))
        }
    }

    private static func stamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }
}

// MARK: - Confirming

/// Before a file is queued: what it is, how big, and how long it will take —
/// because a photo takes minutes, not the instant a text takes, and someone
/// who is not told that concludes the app is broken.
struct AttachmentConfirmView: View {
    let pending: PendingAttachment
    let contactName: String
    var onSend: () -> Void
    var onCancel: () -> Void

    private var seconds: Int { VoidCore.fileSendSeconds(bytes: pending.data.count) }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                if pending.mime.hasPrefix("image/"), let image = UIImage(data: pending.data) {
                    Image(uiImage: image)
                        .resizable()
                        .scaledToFit()
                        .frame(maxHeight: 220)
                        .frame(maxWidth: .infinity)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                } else {
                    Label(pending.name.isEmpty ? "File" : pending.name, systemImage: "doc")
                        .font(.headline)
                }

                Text("\(AttachmentFormat.size(bytes: pending.data.count)) — about \(AttachmentFormat.duration(seconds: seconds)) to send.")
                    .font(.body.weight(.semibold))
                    .accessibilityIdentifier("attachmentEstimate")

                // Non-negotiable #8: the cost, and why it is the cost. Not an
                // apology; the slowness is the privacy.
                Text(
                    "Void sends everything at one fixed pace, in pieces that all look the same, so "
                        + "nobody watching can tell a photo from a few messages. That is why a file "
                        + "takes longer. You can keep using Void while it sends, and anything you "
                        + "write to \(contactName) meanwhile goes out first."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                Spacer()

                HStack(spacing: 16) {
                    Button(action: onCancel) {
                        Text("Cancel").frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .buttonStyle(.bordered)
                    Button(action: onSend) {
                        Text("Send").frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("sendAttachmentButton")
                }
            }
            .padding(24)
            .navigationTitle("Send this file?")
            .navigationBarTitleDisplayMode(.inline)
        }
        .presentationDetents([.medium, .large])
    }
}

// MARK: - Showing

/// A file in the conversation: the picture itself, or a card with its name
/// and size. The bytes are fetched when the bubble appears and kept by
/// `AppState` while the conversation is open.
struct AttachmentBubble: View {
    let message: MessageItem
    let attachment: AttachmentInfo
    var loadAttachment: (UInt64) async -> Data?

    @State private var data: Data?
    @State private var shareURL: URL?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if attachment.isImage, let data, let image = UIImage(data: data) {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 260, maxHeight: 260)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .accessibilityLabel("Photo")
            } else {
                HStack(spacing: 10) {
                    Image(systemName: attachment.isImage ? "photo" : "doc.fill")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(attachment.name.isEmpty ? (attachment.isImage ? "Photo" : "File") : attachment.name)
                            .font(.subheadline.weight(.medium))
                            .lineLimit(2)
                        Text(AttachmentFormat.size(bytes: attachment.size))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            if let data {
                // Written to a protected temporary file only when asked for,
                // and only for the share sheet: a photo on disk under its own
                // name is the plaintext column the database promises not to
                // keep. Saving to Photos or Files is the user's choice from
                // that sheet.
                Button {
                    shareURL = AttachmentShare.temporaryFile(name: attachment.name, mime: attachment.mime, data: data)
                } label: {
                    Label("Save or share", systemImage: "square.and.arrow.up").font(.caption)
                }
                .buttonStyle(.borderless)
                .sheet(
                    isPresented: Binding(get: { shareURL != nil }, set: { if !$0 { shareURL = nil } }),
                    onDismiss: { AttachmentShare.remove(shareURL); shareURL = nil }
                ) {
                    if let shareURL {
                        ShareSheet(items: [shareURL])
                    }
                }
            }
        }
        .padding(10)
        .task(id: message.recordId) {
            guard message.recordId != 0, data == nil else { return }
            data = await loadAttachment(message.recordId)
        }
    }
}

enum AttachmentShare {
    /// Write the bytes to a temporary file under the attachment's own name,
    /// with complete file protection, for the share sheet to hand on. The
    /// caller removes it once the sheet is dismissed.
    static func temporaryFile(name: String, mime: String, data: Data) -> URL? {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("void-share-\(UUID().uuidString)", isDirectory: true)
        let safeName = name.split(separator: "/").last.map(String.init).flatMap { $0.isEmpty ? nil : $0 }
            ?? (mime.hasPrefix("image/") ? "photo.jpg" : "file")
        let url = directory.appendingPathComponent(safeName)
        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            return url
        } catch {
            return nil
        }
    }

    static func remove(_ url: URL?) {
        guard let url else { return }
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }
}

/// UIKit's share sheet. `ShareLink` would do for a URL on iOS 16, but it
/// cannot be told when it was dismissed, and the temporary file must go then.
private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
