//  VoidCore.swift
//  The Swift side of the FFI boundary.
//
//  FR-UI-01 requires native Swift with no cross-platform runtime in the trusted
//  path. This file is the entire seam between SwiftUI and the Rust core: every
//  cryptographic operation, every protocol decision, and every piece of
//  security-critical text comes from `void-ffi`. Nothing below this line
//  reimplements anything.
//
//  ## Why the required text comes from Rust
//
//  PRD §7.4.1, FR-UI-04, FR-REC-01 and FR-REC-03 all specify wording the user
//  must see. Those strings live in the Rust core and are fetched through the FFI
//  rather than being retyped here, because a copy in Swift and another in Kotlin
//  is two chances for someone to soften "this cannot be undone" into "this
//  cannot easily be undone". `VoidText` below is the only way the UI gets them.
//
//  ## Threads
//
//  Every engine call can block: the engine holds its lock for a whole tick,
//  and a tick can wait on the network. So nothing here may be called from the
//  main thread. `CoreQueue` is how the app calls in.

import Foundation

// MARK: - Byte buffer bridging

/// Wraps a `VoidBytes` returned by the core and frees it exactly once.
///
/// Every buffer the core hands us must go back to `void_free_bytes`. Doing that
/// in `deinit` rather than at each call site means there is no path where an
/// early return leaks.
final class CoreBuffer {
    private var bytes: VoidBytes

    init(_ bytes: VoidBytes) {
        self.bytes = bytes
    }

    var array: [UInt8] {
        guard let data = bytes.data, bytes.len > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: data, count: Int(bytes.len)))
    }

    var string: String {
        String(decoding: array, as: UTF8.self)
    }

    deinit {
        void_free_bytes(bytes)
    }
}

/// Reads the fixed-layout encodings `void-ffi` documents on each function.
///
/// Every read is bounds-checked and returns `nil` past the end, so a short or
/// malformed buffer stops parsing instead of trapping. This is the most
/// attacker-adjacent parsing on this side of the boundary: dropping the tail
/// is always safe, and a crash is not.
struct ByteReader {
    private let bytes: [UInt8]
    private var position = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var isAtEnd: Bool { position >= bytes.count }

    mutating func u8() -> UInt8? {
        guard position < bytes.count else { return nil }
        defer { position += 1 }
        return bytes[position]
    }

    // Folded rather than indexed: a slice keeps its parent's indices, so
    // `raw[0]` would read the wrong byte, or trap, anywhere past the start.
    mutating func u16() -> UInt16? {
        guard let raw = take(2) else { return nil }
        return raw.reversed().reduce(0) { $0 << 8 | UInt16($1) }
    }

    mutating func u32() -> UInt32? {
        guard let raw = take(4) else { return nil }
        return raw.reversed().reduce(0) { $0 << 8 | UInt32($1) }
    }

    mutating func u64() -> UInt64? {
        guard let raw = take(8) else { return nil }
        return raw.reversed().reduce(0) { $0 << 8 | UInt64($1) }
    }

    mutating func data(_ count: Int) -> Data? {
        take(count).map { Data($0) }
    }

    mutating func string(_ count: Int) -> String? {
        take(count).map { String(decoding: $0, as: UTF8.self) }
    }

    private mutating func take(_ count: Int) -> ArraySlice<UInt8>? {
        guard count >= 0, count <= bytes.count - position else { return nil }
        defer { position += count }
        return bytes[position..<position + count]
    }
}

// MARK: - Errors

enum VoidError: Error, LocalizedError, Equatable {
    case badArgument
    case failed
    case offline
    case keyChanged
    case locked
    case internalError
    case expired
    case alreadyConnected
    case ownInvite
    case wrongRelay
    case tooLarge

    init(_ status: VoidStatus) {
        switch status.rawValue {
        case 1: self = .badArgument
        case 3: self = .offline
        case 4: self = .keyChanged
        case 5: self = .locked
        case 6: self = .internalError
        case 7: self = .expired
        case 8: self = .alreadyConnected
        case 9: self = .ownInvite
        case 10: self = .wrongRelay
        case 11: self = .tooLarge
        default: self = .failed
        }
    }

    /// Plain language, per FR-UI-03. No jargon, and no reassurance we cannot
    /// back up.
    var errorDescription: String? {
        switch self {
        case .offline:
            return "Void can't reach the network right now. Your message is saved on this "
                + "device and will send when it can. It has not been sent any other way."
        case .keyChanged:
            return "This contact's security code changed. Messaging is paused until you check "
                + "with them through another channel."
        case .locked:
            return "Void is locked."
        case .expired:
            return "This invitation has expired. Ask them for a new one."
        case .alreadyConnected:
            return "You're already connected with this person."
        case .ownInvite:
            return "That's your own invitation. Send it to the person you want to talk to."
        case .wrongRelay:
            return "This invitation uses a different Void server from this app, so it can't be "
                + "opened here."
        case .tooLarge:
            return "This file is too large to send. Void sends files of up to "
                + "\(VoidCore.fileMaxBytes / 1024) KB; photos are shrunk to fit."
        case .badArgument, .failed, .internalError:
            return "Something went wrong. Nothing was sent."
        }
    }
}

private let statusOk = VoidStatus(rawValue: 0)

/// Throw unless `status` is `Ok`.
private func check(_ status: VoidStatus) throws {
    guard status == statusOk else { throw VoidError(status) }
}

// MARK: - Security-critical text

/// The strings the PRD requires the user to see, fetched from the core.
///
/// Deliberately not `String` constants in Swift. See the file header.
enum VoidText {
    /// PRD §7.4.1's required duress disclosure.
    static var duressDisclosure: String { CoreBuffer(void_text_duress_disclosure()).string }
    /// FR-UI-04's confirmation phrase.
    static var duressConfirmation: String { CoreBuffer(void_text_duress_confirmation()).string }
    /// FR-REC-01's device-loss warning.
    static var deviceLossWarning: String { CoreBuffer(void_text_device_loss_warning()).string }
    /// FR-REC-03's export storage warning.
    static var exportStorageWarning: String { CoreBuffer(void_text_export_storage_warning()).string }
}

// MARK: - Key storage backing

/// What is actually protecting the keys on this device (NFR-COMP-02).
enum VaultBacking {
    case secureEnclave
    case software

    fileprivate var raw: VoidVaultBacking {
        switch self {
        case .secureEnclave: return VoidVaultBacking(rawValue: 0)
        case .software: return VoidVaultBacking(rawValue: 3)
        }
    }

    /// Plain-language description, from the core.
    var userDescription: String {
        CoreBuffer(void_vault_backing_description(raw)).string
    }

    var isHardwareBacked: Bool { self != .software }
}

// MARK: - Tor

/// A bootstrapped Arti client. Frees it exactly once.
///
/// An engine attached through `VoidCore.attachTor` keeps a reference to this,
/// so the Tor client always outlives the transport built from it — the order
/// `void_tor_free`'s contract requires.
final class TorClient: @unchecked Sendable {
    let handle: OpaquePointer

    /// Bootstrap Arti. **Blocks**, commonly for tens of seconds; never call it
    /// on the main thread.
    ///
    /// FR-TRANS-05: failure here is not partial success. Either this returns
    /// and the app has a way to reach the network, or it throws and every send
    /// stays queued — there is no third state and no fallback path.
    init(stateDirectory: URL, cacheDirectory: URL) throws {
        var out: OpaquePointer?
        let status = stateDirectory.path.withCString { state in
            cacheDirectory.path.withCString { cache in
                void_tor_bootstrap(state, cache, &out)
            }
        }
        try check(status)
        guard let out else { throw VoidError.offline }
        handle = out
    }

    deinit {
        void_tor_free(handle)
    }
}

// MARK: - The core handle

/// The engine.
///
/// `@unchecked Sendable` because the Rust side guards its state with a mutex;
/// the one mutable property here is guarded by `lock`.
final class VoidCore: @unchecked Sendable {
    // Internal rather than private: `VoidCall.swift` extends this type with
    // the call surface and needs the same handle. Still not public — nothing
    // outside this module ever sees a raw pointer.
    let handle: OpaquePointer

    private let lock = NSLock()
    private var attachedTor: TorClient?

    /// An engine with a fresh identity, held in memory only. For tests: the app
    /// opens its persistent one with `init(dataDirectory:kek:backing:nowMs:)`.
    init() throws {
        var raw: OpaquePointer?
        try check(void_engine_new(&raw))
        guard let raw else { throw VoidError.failed }
        handle = raw
    }

    /// Open this device's engine: restore it if it has run here before,
    /// otherwise create it with a freshly generated identity (D-026).
    ///
    /// `kek` is the key-encryption key `KeyVault` released for this launch. It
    /// is overwritten with zeros before this returns, and the core zeroizes
    /// every copy it made. Throws `.locked` if the key does not open the
    /// existing database; nothing is replaced in that case.
    init(dataDirectory: URL, kek: inout [UInt8], backing: VaultBacking, nowMs: UInt64) throws {
        defer {
            for i in kek.indices { kek[i] = 0 }
        }
        guard kek.count == 32 else { throw VoidError.badArgument }
        var raw: OpaquePointer?
        let status = dataDirectory.path.withCString { dir in
            kek.withUnsafeBufferPointer { key in
                void_engine_open(dir, key.baseAddress, backing.raw, nowMs, &raw)
            }
        }
        try check(status)
        guard let raw else { throw VoidError.failed }
        handle = raw
    }

    deinit {
        // The engine's transport may be built from the Tor client, so the
        // engine goes first; `attachedTor` is released after this body.
        void_engine_free(handle)
    }

    /// Open a circuit to the relay and make it this engine's transport.
    /// `onionAddress` is the relay's pinned identity (FR-TRANS-04) and is used
    /// for nothing else. Blocks on the network.
    func attachTor(_ tor: TorClient, onionAddress: String, port: UInt16) throws {
        let status = onionAddress.withCString { addr in
            void_engine_attach_tor(handle, tor.handle, addr, port)
        }
        try check(status)
        lock.lock()
        attachedTor = tor
        lock.unlock()
    }

    /// The protocol this build speaks, for the about screen.
    static var protocolIdentifier: String {
        String(cString: void_protocol_id())
    }

    static var protocolVersion: UInt16 { void_protocol_version() }

    /// The fixed record size (FR-MSG-02), shown on the about screen so a
    /// curious user can check it against the published specification.
    static var recordSize: Int { Int(void_record_size()) }

    // MARK: Identity

    /// The local security code as pronounceable syllables (FR-ID-03).
    var fingerprintWords: String {
        CoreBuffer(void_fingerprint_words(handle)).string
    }

    /// The local security code as decimal groups, for reading aloud.
    var fingerprintNumbers: String {
        CoreBuffer(void_fingerprint_numbers(handle)).string
    }

    /// Compare a code the user typed or heard against `expected` (FR-DISC-04).
    ///
    /// Constant-time and formatting-tolerant on the Rust side. A comparison
    /// that failed on whitespace would train users to ignore mismatches, which
    /// is the opposite of what verification is for.
    static func fingerprintMatches(expected: Data, input: String) -> Bool {
        let inputBytes = Array(input.utf8)
        return expected.withUnsafeBytes { exp -> Bool in
            inputBytes.withUnsafeBufferPointer { inp -> Bool in
                void_fingerprint_matches(
                    exp.bindMemory(to: UInt8.self).baseAddress,
                    UInt(exp.count),
                    inp.baseAddress,
                    UInt(inp.count)
                ) == 1
            }
        }
    }

    /// Render an arbitrary contact's fingerprint as proquint words — the
    /// engine's own is `fingerprintWords`; this is for someone else's, kept
    /// as raw bytes from `contacts` and the contact events.
    static func fingerprintWords(for fingerprint: Data) -> String {
        fingerprint.withUnsafeBytes { buf -> String in
            CoreBuffer(
                void_fingerprint_render_words(buf.bindMemory(to: UInt8.self).baseAddress)
            ).string
        }
    }

    // MARK: Invitations (FR-DISC-01, FR-DISC-02)

    /// Make an invitation and return its short `void://i/` link — one QR code —
    /// and the id that names it in `takeContactEvents`.
    ///
    /// The engine parks the invitation on `relay` through its outbox and
    /// watches for its acceptance on its own schedule; there is nothing to poll.
    /// `myLabel` travels inside the encrypted invitation and is shown to
    /// whoever opens it. `contactLabel` never leaves this device: it becomes
    /// the name of whoever accepts. Any number can be outstanding.
    func createInvite(
        relay: String, myLabel: String, contactLabel: String, now: UInt64, ttlSeconds: UInt64
    ) throws -> (link: String, id: Data) {
        let relayBytes = Array(relay.utf8)
        let mine = Array(myLabel.utf8)
        let theirs = Array(contactLabel.utf8)
        var link = VoidBytes()
        var id = [UInt8](repeating: 0, count: 16)
        let status = relayBytes.withUnsafeBufferPointer { r in
            mine.withUnsafeBufferPointer { m in
                theirs.withUnsafeBufferPointer { t in
                    void_engine_create_invite(
                        handle,
                        r.baseAddress, UInt(r.count),
                        m.baseAddress, UInt(m.count),
                        t.baseAddress, UInt(t.count),
                        now, ttlSeconds,
                        &link, &id
                    )
                }
            }
        }
        let linkBuffer = CoreBuffer(link)
        try check(status)
        return (linkBuffer.string, Data(id))
    }

    /// Withdraw an invitation. A handshake sent against it is never answered.
    @discardableResult
    func cancelInvite(_ id: Data) -> Bool {
        id.withUnsafeBytes { void_engine_cancel_invite(handle, $0.bindMemory(to: UInt8.self).baseAddress) }
            == statusOk
    }

    /// How many of an outstanding invitation's records still have to reach the
    /// relay before whoever opens it can collect it; `nil` once it has been
    /// accepted, has expired, or was cancelled.
    func inviteUploadRemaining(_ id: Data) -> Int? {
        let remaining = id.withUnsafeBytes {
            void_engine_invite_status(handle, $0.bindMemory(to: UInt8.self).baseAddress)
        }
        return remaining < 0 ? nil : Int(remaining)
    }

    /// Open an invitation someone gave the user — scanned or pasted — and start
    /// collecting it. Returns the id its `inviteReady` or `inviteFailed` event
    /// will carry. Nothing about the contact list changes yet.
    func openInvite(link: String, now: UInt64) throws -> Data {
        var id = [UInt8](repeating: 0, count: 16)
        let status = link.withCString { void_engine_open_invite(handle, $0, now, &id) }
        try check(status)
        return Data(id)
    }

    /// Connect using an invitation reported ready. `localName` may be empty to
    /// keep the name the invitation carried; `firstMessage` may be empty to
    /// connect without saying anything yet. Returns the new contact's
    /// fingerprint.
    func confirmInvite(fetchId: Data, localName: String, firstMessage: String, now: UInt64) throws
        -> Data
    {
        var fingerprint = [UInt8](repeating: 0, count: 32)
        let status = fetchId.withUnsafeBytes { id in
            localName.withCString { name in
                firstMessage.withCString { message in
                    void_engine_confirm_invite(
                        handle, id.bindMemory(to: UInt8.self).baseAddress, name, message, now,
                        &fingerprint
                    )
                }
            }
        }
        try check(status)
        return Data(fingerprint)
    }

    /// Stop waiting for an invitation the user opened.
    func cancelFetch(_ id: Data) {
        _ = id.withUnsafeBytes { void_engine_cancel_fetch(handle, $0.bindMemory(to: UInt8.self).baseAddress) }
    }

    /// Everything that happened to contacts and invitations since the last
    /// drain. Layout is documented on `void_engine_take_contact_events`.
    func takeContactEvents() -> [ContactEvent] {
        var reader = ByteReader(CoreBuffer(void_engine_take_contact_events(handle)).array)
        var events: [ContactEvent] = []
        while !reader.isAtEnd {
            guard let kind = reader.u8(),
                let id = reader.data(16),
                let fingerprint = reader.data(32),
                let nameLength = reader.u16(),
                let name = reader.string(Int(nameLength)),
                let messageLength = reader.u32(),
                let message = reader.string(Int(messageLength))
            else { break }
            switch kind {
            case 1:
                events.append(
                    .added(inviteId: id, fingerprint: fingerprint, name: name, firstMessage: message)
                )
            case 2: events.append(.inviteExpired(inviteId: id))
            case 3: events.append(.inviteReady(fetchId: id, fingerprint: fingerprint, inviterName: name))
            case 4: events.append(.inviteFailed(fetchId: id, reason: .expired))
            case 5: events.append(.inviteFailed(fetchId: id, reason: .invalid))
            case 6: events.append(.inviteFailed(fetchId: id, reason: .timedOut))
            default: return events
            }
        }
        return events
    }

    /// The name the user puts on invitations they make. Stored in the
    /// encrypted database, not in `UserDefaults`.
    var inviteName: String {
        CoreBuffer(void_engine_invite_name(handle)).string
    }

    func setInviteName(_ name: String) throws {
        try check(name.withCString { void_engine_set_invite_name(handle, $0) })
    }

    // MARK: Settings

    /// Whether the user has been through the "what Void does and does not
    /// protect" screen on this device (FR-UI-05). Persisted, so onboarding is
    /// not repeated at every launch.
    var protectionAcknowledged: Bool {
        void_engine_protection_acknowledged(handle)
    }

    func acknowledgeProtection() throws {
        try check(void_engine_acknowledge_protection(handle))
    }

    // MARK: Sending and receiving

    /// Queue a message. Transmission happens on the scheduler's own timing
    /// (FR-MSG-06) via `tick`, not immediately.
    @discardableResult
    func send(to fingerprint: Data, text: String, now: UInt64) throws -> UInt64 {
        var messageId: UInt64 = 0
        let status = fingerprint.withUnsafeBytes { fp in
            text.withCString { textC in
                void_engine_send(
                    handle, fp.bindMemory(to: UInt8.self).baseAddress, textC, now, &messageId
                )
            }
        }
        try check(status)
        return messageId
    }

    /// Queue a file: a photo, a document, anything up to `fileMaxBytes`. A
    /// file is a message — same ratchet, same fixed-size records, one per
    /// emission slot — so what it costs is time, not shape; `fileRecordCount`
    /// times `padIntervalMs` is the estimate to show before sending. Its
    /// records go out behind every queued message, so a reply typed while a
    /// photo is leaving does not wait for it. Throws `.tooLarge` before any
    /// ratchet state is spent on a file that cannot travel.
    @discardableResult
    func sendFile(to fingerprint: Data, name: String, mime: String, data: Data, now: UInt64) throws
        -> UInt64
    {
        var messageId: UInt64 = 0
        let nameBytes = Array(name.utf8)
        let mimeBytes = Array(mime.utf8)
        let status = fingerprint.withUnsafeBytes { fp in
            nameBytes.withUnsafeBufferPointer { n in
                mimeBytes.withUnsafeBufferPointer { m in
                    data.withUnsafeBytes { d in
                        void_engine_send_file(
                            handle,
                            fp.bindMemory(to: UInt8.self).baseAddress,
                            n.baseAddress, UInt(n.count),
                            m.baseAddress, UInt(m.count),
                            d.bindMemory(to: UInt8.self).baseAddress, UInt(d.count),
                            now,
                            &messageId
                        )
                    }
                }
            }
        }
        try check(status)
        return messageId
    }

    /// The largest file `sendFile` accepts, in bytes.
    static var fileMaxBytes: Int { Int(void_file_max_bytes()) }

    /// How many records a file of `bytes` takes to send, at most.
    static func fileRecordCount(bytes: Int) -> Int {
        Int(void_file_record_count(UInt(max(bytes, 0))))
    }

    /// How often one record leaves, in milliseconds. A protocol constant.
    static var padIntervalMs: UInt64 { void_pad_interval_ms() }

    /// How long a file of `bytes` takes to send, in seconds, at most.
    static func fileSendSeconds(bytes: Int) -> Int {
        fileRecordCount(bytes: bytes) * Int(padIntervalMs / 1000)
    }

    /// The bytes of a stored file, by the id `messages` listed it under.
    /// `nil` if that message is not a file, or is gone.
    func attachment(id: UInt64) -> Data? {
        let bytes = CoreBuffer(void_engine_attachment(handle, id)).array
        return bytes.isEmpty ? nil : Data(bytes)
    }

    /// What one `tick` did, and any messages it collected.
    enum TickResult: Equatable {
        case waiting
        case sentPadding
        case deposited
        case refused
        case retrieved([ReceivedMessage])
        case offline
    }

    struct ReceivedMessage: Equatable {
        let fingerprint: Data
        /// The text; empty for a file.
        let text: String
        /// The file it was, if it was one — name, type and size. Its bytes
        /// are in the history.
        let attachment: AttachmentInfo?
    }

    /// Advance the scheduler by one tick (FR-MSG-06). Call on a repeating
    /// timer; every call takes the same observable time regardless of
    /// whether it carries real traffic.
    func tick(nowMs: UInt64) -> TickResult {
        var outcome = VoidTickOutcome(rawValue: 0)
        var messages = VoidBytes()
        let status = void_engine_tick(handle, nowMs, &outcome, &messages)
        let buffer = CoreBuffer(messages)
        guard status == statusOk else { return .offline }
        switch outcome.rawValue {
        case 0: return .waiting
        case 1: return .sentPadding
        case 2: return .deposited
        case 3: return .refused
        case 4:
            var reader = ByteReader(buffer.array)
            var out: [ReceivedMessage] = []
            while !reader.isAtEnd {
                guard let fingerprint = reader.data(32),
                    let kind = reader.u8(),
                    let size = reader.u32(),
                    let length = reader.u32(),
                    let text = reader.string(Int(length))
                else { break }
                if kind == 3 {
                    out.append(
                        ReceivedMessage(
                            fingerprint: fingerprint, text: "",
                            attachment: AttachmentInfo(name: text, mime: "", size: Int(size))))
                } else {
                    out.append(ReceivedMessage(fingerprint: fingerprint, text: text, attachment: nil))
                }
            }
            return .retrieved(out)
        default: return .offline
        }
    }

    /// The stored history with one contact, oldest first — what a conversation
    /// shows after a restart. Layout is documented on `void_engine_messages`.
    func messages(with fingerprint: Data) -> [StoredMessage] {
        let bytes = fingerprint.withUnsafeBytes {
            void_engine_messages(handle, $0.bindMemory(to: UInt8.self).baseAddress)
        }
        var reader = ByteReader(CoreBuffer(bytes).array)
        var out: [StoredMessage] = []
        while !reader.isAtEnd {
            guard let id = reader.u64(),
                let direction = reader.u8(),
                let delivery = reader.u8(),
                let timestamp = reader.u64(),
                let remaining = reader.u16(),
                let length = reader.u32(),
                let text = reader.string(Int(length)),
                let hasFile = reader.u8()
            else { break }
            var attachment: AttachmentInfo?
            if hasFile == 1 {
                guard let nameLength = reader.u16(),
                    let name = reader.string(Int(nameLength)),
                    let mimeLength = reader.u16(),
                    let mime = reader.string(Int(mimeLength)),
                    let size = reader.u32()
                else { break }
                attachment = AttachmentInfo(name: name, mime: mime, size: Int(size))
            }
            out.append(
                StoredMessage(
                    id: id,
                    isOutgoing: direction == 1,
                    delivery: DeliveryState(code: delivery),
                    timestamp: Date(timeIntervalSince1970: TimeInterval(timestamp)),
                    text: text,
                    attachment: attachment,
                    fragmentsRemaining: Int(remaining)
                )
            )
        }
        return out
    }

    // MARK: Contacts

    struct ContactSummary: Equatable {
        let fingerprint: Data
        let trust: TrustState
        let name: String
    }

    /// The contact list, for the conversation list screen.
    var contacts: [ContactSummary] {
        var reader = ByteReader(CoreBuffer(void_engine_contacts(handle)).array)
        var out: [ContactSummary] = []
        while !reader.isAtEnd {
            guard let fingerprint = reader.data(32),
                let trust = reader.u8(),
                let nameLength = reader.u16(),
                let name = reader.string(Int(nameLength))
            else { break }
            let state: TrustState =
                switch trust {
                case 1: .verified
                case 2: .keyChanged
                default: .unverified
                }
            out.append(ContactSummary(fingerprint: fingerprint, trust: state, name: name))
        }
        return out
    }

    func markVerified(_ fingerprint: Data) throws {
        try check(
            fingerprint.withUnsafeBytes {
                void_engine_mark_verified(handle, $0.bindMemory(to: UInt8.self).baseAddress)
            })
    }

    func acknowledgeKeyChange(_ fingerprint: Data) throws {
        try check(
            fingerprint.withUnsafeBytes {
                void_engine_acknowledge_key_change(handle, $0.bindMemory(to: UInt8.self).baseAddress)
            })
    }

    func revokeContact(_ fingerprint: Data) throws {
        try check(
            fingerprint.withUnsafeBytes {
                void_engine_revoke_contact(handle, $0.bindMemory(to: UInt8.self).baseAddress)
            })
    }

    /// Change the name this device shows for a contact. Never transmitted.
    func renameContact(_ fingerprint: Data, to name: String) throws {
        try check(
            fingerprint.withUnsafeBytes { fp in
                name.withCString { void_engine_rename_contact(handle, fp.bindMemory(to: UInt8.self).baseAddress, $0) }
            })
    }

    // MARK: Duress

    /// The RAM and store half of duress destruction (FR-STOR-02). The hardware
    /// half — deleting the key the database is wrapped under — is
    /// `KeyVault.destroy`, and must happen first (D-017).
    func duressDestroy() throws {
        try check(void_engine_duress_destroy(handle))
    }
}

// MARK: - Contact events

/// Something that happened to a contact or an invitation.
enum ContactEvent: Equatable {
    /// Someone accepted one of our invitations. They are a contact now.
    case added(inviteId: Data, fingerprint: Data, name: String, firstMessage: String)
    /// One of our invitations expired unaccepted and was forgotten.
    case inviteExpired(inviteId: Data)
    /// An invitation the user opened has arrived and verified. Show who it is
    /// from, then connect with `confirmInvite`.
    case inviteReady(fetchId: Data, fingerprint: Data, inviterName: String)
    /// An invitation the user opened could not be used.
    case inviteFailed(fetchId: Data, reason: InviteFailure)
}

/// Why an invitation the user opened could not be used.
enum InviteFailure: Equatable {
    case expired
    case invalid
    case timedOut

    /// FR-UI-03: plain language, and a next step.
    var explanation: String {
        switch self {
        case .expired:
            return "This invitation has expired. Ask them for a new one."
        case .invalid:
            return "This invitation couldn't be read. Ask them to send it again."
        case .timedOut:
            return "Their invitation never arrived. They may be offline, or someone else already "
                + "used it. Ask them for a new one."
        }
    }
}

// MARK: - Stored messages

/// What a file in a conversation is, without its bytes. Lives here rather
/// than in `Models.swift` because the core wrapper parses it off the
/// boundary, and the Linux bindings check type-checks this file without the
/// models.
struct AttachmentInfo: Equatable {
    let name: String
    let mime: String
    /// Size in bytes.
    let size: Int

    /// Whether to show it as a picture rather than a file card.
    var isImage: Bool { mime.lowercased().hasPrefix("image/") }

    /// What the conversation list shows for it.
    var summary: String {
        if isImage { return "Photo" }
        return name.isEmpty ? "File" : name
    }
}

/// One message from the stored history.
struct StoredMessage: Equatable {
    /// The store record that holds it; what `VoidCore.attachment(id:)` takes.
    let id: UInt64
    let isOutgoing: Bool
    let delivery: DeliveryState
    let timestamp: Date
    /// Empty for a file.
    let text: String
    /// The file it is, if it is one, without its bytes.
    let attachment: AttachmentInfo?
    /// Records of it still to leave. Zero once sent, and for anything received.
    let fragmentsRemaining: Int
}

// MARK: - Trust state

/// How verified a contact is (FR-DISC-04, FR-DISC-05).
///
/// Three states with no "probably fine" middle: a changed key blocks messaging
/// rather than warning about it, and that is enforced in the Rust engine, not
/// here. This enum only decides how to say so.
enum TrustState {
    case unverified
    case verified
    case keyChanged

    var canSend: Bool { self != .keyChanged }

    var statusLine: String {
        switch self {
        case .unverified: return "Not verified yet"
        case .verified: return "Verified in person"
        case .keyChanged: return "Their security code changed"
        }
    }

    var guidance: String {
        switch self {
        case .unverified:
            return "Anyone could be at the other end of this conversation. Compare security "
                + "codes with them in person or on a call you trust."
        case .verified:
            return "You compared security codes with this person. Messages are for them alone."
        case .keyChanged:
            return "This can happen if they reinstalled Void or switched devices. It can also "
                + "mean someone is intercepting this conversation. Messaging is paused until "
                + "you check with them through another channel."
        }
    }
}

// MARK: - Delivery state

/// Per-message delivery state (NFR-REL-04).
enum DeliveryState {
    case queued
    case deposited
    case collected
    case failed
    case received

    /// The byte `void_engine_messages` encodes.
    init(code: UInt8) {
        switch code {
        case 0: self = .queued
        case 1: self = .deposited
        case 2: self = .collected
        case 3: self = .failed
        default: self = .received
        }
    }

    /// FR-UI-03: plain language. "Waiting to send" and not a clock icon the
    /// user has to learn, and never "sent" for something that is only queued.
    var label: String {
        switch self {
        case .queued: return "Waiting to send"
        case .deposited: return "Sent"
        case .collected: return "Delivered"
        case .failed: return "Could not send"
        case .received: return ""
        }
    }
}
