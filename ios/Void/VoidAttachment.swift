//  VoidAttachment.swift
//
//  Files: the Swift half of `void_proto::attachment`, `void_client::attachment`
//  and void-ffi's attachment surface. See docs/DECISIONS.md D-032.
//
//  ## What crosses the FFI
//
//  A path in, an opaque handle and a 16-byte id out. The file is sealed by the
//  core under a key made for it alone, into the core's own attachments
//  directory, and the key never becomes a Swift value: it lives in the handle
//  and, once sent, in the encrypted database beside the message. That is what
//  makes duress destruction reach files too — the database's key goes, and
//  every sealed copy on this phone is noise.
//
//  The only plaintext this file ever writes is what the user asked to look at
//  or share (`export`), in the app's temporary directory, and `TempFiles`
//  removes it again.
//
//  ## Threads
//
//  Upload and download block for as long as the transfer takes, so they run
//  on a `CoreThread`, never the core queue: a transfer uses a circuit of its
//  own and does not need the engine at all. `progress` can be read from any
//  thread while one runs.

import Foundation

/// A file in the history, as `void_engine_messages` describes it. Never its
/// key: only what a screen needs.
struct AttachmentInfo: Equatable, Hashable {
    /// Its relay address, which is how the core names it.
    let id: Data
    let size: UInt64
    let width: Int
    let height: Int
    let name: String
    let mime: String
    /// Whether this phone holds the sealed copy, so it can be opened now.
    var isLocal: Bool

    var isImage: Bool { mime.hasPrefix("image/") }
    var isVideo: Bool { mime.hasPrefix("video/") }
    var isAudio: Bool { mime.hasPrefix("audio/") }

    /// Width over height, when the sender said; images default to 4:3.
    var aspectRatio: CGFloat {
        guard width > 0, height > 0 else { return 4.0 / 3.0 }
        return CGFloat(width) / CGFloat(height)
    }

    var sizeDescription: String {
        ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
    }

    /// The file's extension, upper-cased, for a file card — "PDF", "ZIP".
    var typeLabel: String {
        let ext = (name as NSString).pathExtension
        return ext.isEmpty ? "FILE" : ext.uppercased()
    }
}

/// One file being sent or fetched. Frees its handle exactly once.
final class AttachmentTransfer: @unchecked Sendable {
    fileprivate let handle: OpaquePointer
    /// Its relay address.
    let id: Data

    fileprivate init(handle: OpaquePointer) {
        self.handle = handle
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = void_attachment_id(handle, &bytes)
        id = Data(bytes)
    }

    /// Chunks done and chunks in all, padding included. Any thread.
    var progress: (done: UInt32, total: UInt32) {
        var done: UInt32 = 0
        var total: UInt32 = 0
        _ = void_attachment_progress(handle, &done, &total)
        return (done, total)
    }

    /// How far along, from 0 to 1.
    var fraction: Double {
        let p = progress
        return p.total == 0 ? 0 : Double(p.done) / Double(p.total)
    }

    /// Stop at the next chunk; the transfer throws `.cancelled`.
    func cancel() {
        void_attachment_cancel(handle)
    }

    /// Park the sealed file on the relay over a circuit of its own. **Blocks**
    /// for the whole upload; safe to run again after a failure.
    func upload(tor: TorClient) throws {
        let status = RelayConfig.onionAddress.withCString { onion in
            void_attachment_upload(tor.handle, onion, RelayConfig.port, handle)
        }
        guard status.rawValue == 0 else { throw VoidError(status) }
    }

    /// Fetch a received file from the relay over a circuit of its own, every
    /// chunk checked on arrival, then ask the relay to forget it. **Blocks**.
    /// Throws `.expired` if the relay no longer has it.
    func download(tor: TorClient) throws {
        let status = RelayConfig.onionAddress.withCString { onion in
            void_attachment_download(tor.handle, onion, RelayConfig.port, handle)
        }
        guard status.rawValue == 0 else { throw VoidError(status) }
    }

    deinit {
        void_attachment_free(handle)
    }
}

extension VoidCore {
    /// The largest file Void sends, in bytes.
    static var maxAttachmentBytes: UInt64 { void_attachment_max_bytes() }

    /// Seal the file at `url` for sending. The core reads it once; delete it
    /// afterwards. Does not wait on the engine, so it is safe off the core
    /// queue, on a `CoreThread`.
    func prepareAttachment(
        fileAt url: URL, name: String, mime: String, width: Int, height: Int, caption: String
    ) throws -> AttachmentTransfer {
        let nameBytes = Array(name.utf8)
        let mimeBytes = Array(mime.utf8)
        let captionBytes = Array(caption.utf8)
        var out: OpaquePointer?
        let status = url.path.withCString { path in
            nameBytes.withUnsafeBufferPointer { n in
                mimeBytes.withUnsafeBufferPointer { m in
                    captionBytes.withUnsafeBufferPointer { c in
                        void_engine_prepare_attachment(
                            handle, path,
                            n.baseAddress, UInt(n.count),
                            m.baseAddress, UInt(m.count),
                            UInt16(clamping: width), UInt16(clamping: height),
                            c.baseAddress, UInt(c.count),
                            &out
                        )
                    }
                }
            }
        }
        guard status.rawValue == 0, let out else { throw VoidError(status) }
        return AttachmentTransfer(handle: out)
    }

    /// Send an uploaded file: its pointer goes through the ratchet like any
    /// message, on the scheduler's timing. Upload first.
    @discardableResult
    func sendAttachment(_ transfer: AttachmentTransfer, to fingerprint: Data, now: UInt64) throws
        -> UInt64
    {
        var messageId: UInt64 = 0
        let status = fingerprint.withUnsafeBytes { fp in
            void_engine_send_attachment(
                handle, fp.bindMemory(to: UInt8.self).baseAddress, transfer.handle, now, &messageId)
        }
        guard status.rawValue == 0 else { throw VoidError(status) }
        return messageId
    }

    /// A handle to a file in the history, to fetch it. Nil if no message here
    /// points at it.
    func openAttachment(id: Data) -> AttachmentTransfer? {
        var out: OpaquePointer?
        let status = id.withUnsafeBytes {
            void_engine_attachment_open(handle, $0.bindMemory(to: UInt8.self).baseAddress, &out)
        }
        guard status.rawValue == 0, let out else { return nil }
        return AttachmentTransfer(handle: out)
    }

    /// Open a file this phone holds, into memory — for showing an image. Nil if
    /// it is not here yet, or its sealed copy does not authenticate.
    func readAttachment(id: Data) -> Data? {
        var out = VoidBytes()
        let status = id.withUnsafeBytes {
            void_engine_attachment_read(handle, $0.bindMemory(to: UInt8.self).baseAddress, &out)
        }
        let buffer = CoreBuffer(out)
        guard status.rawValue == 0 else { return nil }
        return Data(buffer.array)
    }

    /// Write a file out in the clear, for a viewer or the share sheet. The
    /// caller owns `url` from then on — see `TempFiles`.
    func exportAttachment(id: Data, to url: URL) throws {
        let status = id.withUnsafeBytes { idBytes in
            url.path.withCString { dest in
                void_engine_attachment_export(handle, idBytes.bindMemory(to: UInt8.self).baseAddress, dest)
            }
        }
        guard status.rawValue == 0 else { throw VoidError(status) }
    }
}

/// Plaintext files Void wrote because the user asked to see or share one.
///
/// They live in their own folder under the temporary directory — excluded from
/// backup, complete file protection like everything else — and are removed
/// when the viewer closes, and on every launch in case one was not.
enum TempFiles {
    static func directory() -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(
            "void-open", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir
    }

    /// A fresh path for a file called `name`, in a folder of its own so the
    /// name can be kept exactly as sent.
    static func path(named name: String) -> URL {
        let folder = directory().appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(
            at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return folder.appendingPathComponent(name.isEmpty ? "file" : name)
    }

    static func remove(_ url: URL) {
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }

    static func removeAll() {
        try? FileManager.default.removeItem(at: directory())
    }
}
