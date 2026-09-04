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

import Foundation

// MARK: - Byte buffer bridging

/// Wraps a `VoidBytes` returned by the core and frees it exactly once.
///
/// Every buffer the core hands us must go back to `void_free_bytes`. Doing that
/// in `deinit` rather than at each call site means there is no path where an
/// early return leaks.
private final class CoreBuffer {
    private var bytes: VoidBytes

    init(_ bytes: VoidBytes) {
        self.bytes = bytes
    }

    var string: String {
        guard bytes.data != nil, bytes.len > 0 else { return "" }
        let data = Data(bytes: bytes.data, count: Int(bytes.len))
        return String(data: data, encoding: .utf8) ?? ""
    }

    deinit {
        void_free_bytes(bytes)
    }
}

// MARK: - Errors

enum VoidError: Error, LocalizedError {
    case badArgument
    case failed
    case offline
    case keyChanged
    case locked
    case internalError

    init(_ status: VoidStatus) {
        switch status {
        case VoidStatus(rawValue: 1): self = .badArgument
        case VoidStatus(rawValue: 3): self = .offline
        case VoidStatus(rawValue: 4): self = .keyChanged
        case VoidStatus(rawValue: 5): self = .locked
        case VoidStatus(rawValue: 6): self = .internalError
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
        case .badArgument, .failed, .internalError:
            return "Something went wrong. Nothing was sent."
        }
    }
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

// MARK: - The core handle

/// The engine.
///
/// `@unchecked Sendable` because the Rust side guards its state with a mutex;
/// the pointer itself is immutable after `init`.
final class VoidCore: @unchecked Sendable {
    // Internal rather than private: `VoidCall.swift` extends this type with
    // the call surface and needs the same handle. Still not public — nothing
    // outside this module ever sees a raw pointer.
    let handle: OpaquePointer

    /// The bootstrapped Tor handle, once `bootstrapTor` has succeeded.
    ///
    /// Calls need this for their own reason beyond the relay: the media path
    /// publishes and dials onion services directly (D-024), so a call is
    /// impossible without it even if the relay were somehow reachable.
    private(set) var torHandle: OpaquePointer?

    init() throws {
        var raw: OpaquePointer?
        let status = void_engine_new(&raw)
        guard status == VoidStatus(rawValue: 0), let raw else {
            throw VoidError(status)
        }
        self.handle = raw
    }

    deinit {
        // Order matters: the engine may hold a transport built from the Tor
        // handle, so it goes first.
        void_engine_free(handle)
        if let torHandle {
            void_tor_free(torHandle)
        }
    }

    // MARK: Tor

    /// Bootstrap Arti. Blocks; call from a background thread.
    ///
    /// FR-TRANS-05: failure here is not partial success. Either this returns
    /// and the app has a way to reach the network, or it throws and every send
    /// stays queued — there is no third state and no fallback path.
    func bootstrapTor(stateDirectory: URL, cacheDirectory: URL) throws {
        var out: OpaquePointer?
        let status = stateDirectory.path.withCString { state in
            cacheDirectory.path.withCString { cache in
                void_tor_bootstrap(state, cache, &out)
            }
        }
        guard status == VoidStatus(rawValue: 0), let out else { throw VoidError(status) }
        torHandle = out
    }

    /// Point the engine at a relay over Tor. `onionAddress` is the relay's
    /// pinned identity (FR-TRANS-04) and is used for nothing else.
    func attachTor(relayOnionAddress: String, port: UInt16) throws {
        guard let torHandle else { throw VoidError.offline }
        let status = relayOnionAddress.withCString { addr in
            void_engine_attach_tor(handle, torHandle, addr, port)
        }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
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
    /// as raw bytes since `startConversation`/`acceptConversation`/`contacts`.
    static func fingerprintWords(for fingerprint: Data) -> String {
        fingerprint.withUnsafeBytes { buf -> String in
            CoreBuffer(
                void_fingerprint_render_words(buf.bindMemory(to: UInt8.self).baseAddress)
            ).string
        }
    }

    // MARK: Establishing a conversation (FR-DISC-01, FR-DISC-02)

    /// Publish an invite (a `void://c/...` link, also the QR payload) and
    /// return it alongside the queue handle needed to detect acceptance.
    func createInvite(relayHint: String, label: String, now: UInt64, ttlSeconds: UInt64) throws -> (
        link: String, queue: IntroQueue
    ) {
        let hintBytes = Array(relayHint.utf8)
        let labelBytes = Array(label.utf8)
        var linkBytes = VoidBytes()
        var queuePtr: OpaquePointer?
        let status = hintBytes.withUnsafeBufferPointer { hint in
            labelBytes.withUnsafeBufferPointer { lbl in
                void_engine_create_invite(
                    handle,
                    hint.baseAddress, UInt(hint.count),
                    lbl.baseAddress, UInt(lbl.count),
                    now, ttlSeconds,
                    &linkBytes, &queuePtr
                )
            }
        }
        guard status == VoidStatus(rawValue: 0), let queuePtr else { throw VoidError(status) }
        return (CoreBuffer(linkBytes).string, IntroQueue(queuePtr))
    }

    /// Poll a queue from `createInvite` for a delivered handshake. Returns
    /// `nil` until someone has scanned the invite — that is normal, not an
    /// error, and this is safe to call on a repeating timer.
    func pollIntroQueue(_ queue: IntroQueue) throws -> Data? {
        var out = VoidBytes()
        let status = void_engine_poll_intro_queue(handle, queue.handle, &out)
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
        guard out.data != nil, out.len > 0 else { return nil }
        defer { void_free_bytes(out) }
        return Data(bytes: out.data, count: Int(out.len))
    }

    /// Accept a conversation from bytes `pollIntroQueue` returned.
    func acceptConversation(queue: IntroQueue, initial: Data, now: UInt64) throws -> (
        fingerprint: Data, firstMessage: String
    ) {
        var fingerprint = Data(count: 32)
        var firstMessage = VoidBytes()
        let status = initial.withUnsafeBytes { buf -> VoidStatus in
            fingerprint.withUnsafeMutableBytes { fp -> VoidStatus in
                void_engine_accept_conversation(
                    handle, queue.handle,
                    buf.bindMemory(to: UInt8.self).baseAddress, UInt(buf.count),
                    now,
                    fp.bindMemory(to: UInt8.self).baseAddress,
                    &firstMessage
                )
            }
        }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
        return (fingerprint, CoreBuffer(firstMessage).string)
    }

    /// Start a conversation from a scanned or pasted invite link (the
    /// initiator side).
    func startConversation(link: String, localName: String, firstMessage: String, now: UInt64)
        throws -> Data
    {
        var fingerprint = Data(count: 32)
        let status = link.withCString { linkC in
            localName.withCString { nameC in
                firstMessage.withCString { msgC in
                    fingerprint.withUnsafeMutableBytes { fp in
                        void_engine_start_conversation(
                            handle, linkC, nameC, msgC, now,
                            fp.bindMemory(to: UInt8.self).baseAddress
                        )
                    }
                }
            }
        }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
        return fingerprint
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
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
        return messageId
    }

    /// What one `tick` did, and any messages it collected.
    enum TickResult {
        case waiting
        case sentPadding
        case deposited
        case refused
        case retrieved([(fingerprint: Data, text: String)])
        case offline
    }

    /// Advance the scheduler by one tick (FR-MSG-06). Call on a repeating
    /// timer; every call takes the same observable time regardless of
    /// whether it carries real traffic.
    func tick(nowMs: UInt64) -> TickResult {
        var outcome = VoidTickOutcome(rawValue: 0)
        var messages = VoidBytes()
        let status = void_engine_tick(handle, nowMs, &outcome, &messages)
        guard status == VoidStatus(rawValue: 0) else { return .offline }
        switch outcome {
        case VoidTickOutcome(rawValue: 0): return .waiting
        case VoidTickOutcome(rawValue: 1): return .sentPadding
        case VoidTickOutcome(rawValue: 2): return .deposited
        case VoidTickOutcome(rawValue: 3): return .refused
        case VoidTickOutcome(rawValue: 5): return .offline
        case VoidTickOutcome(rawValue: 4):
            defer { void_free_bytes(messages) }
            guard let data = messages.data else { return .retrieved([]) }
            var out: [(Data, String)] = []
            var pos = 0
            let buf = UnsafeBufferPointer(start: data, count: Int(messages.len))
            while pos + 36 <= buf.count {
                let fp = Data(bytes: buf.baseAddress! + pos, count: 32)
                pos += 32
                let lenParts: (UInt32, UInt32, UInt32, UInt32) = (
                    UInt32(buf[pos]), UInt32(buf[pos + 1]), UInt32(buf[pos + 2]), UInt32(buf[pos + 3])
                )
                let len = Int(lenParts.0 | (lenParts.1 << 8) | (lenParts.2 << 16) | (lenParts.3 << 24))
                pos += 4
                guard pos + len <= buf.count else { break }
                let textBytes = Array(buf[pos..<pos + len])
                pos += len
                let text = String(decoding: textBytes, as: UTF8.self)
                out.append((fp, text))
            }
            return .retrieved(out)
        default: return .offline
        }
    }

    // MARK: Contacts

    struct ContactSummary {
        let fingerprint: Data
        let trust: TrustState
        let name: String
    }

    /// The contact list, for the conversation list screen.
    var contacts: [ContactSummary] {
        let bytes = void_engine_contacts(handle)
        guard let data = bytes.data else { return [] }
        defer { void_free_bytes(bytes) }
        var out: [ContactSummary] = []
        var pos = 0
        let buf = UnsafeBufferPointer(start: data, count: Int(bytes.len))
        while pos + 35 <= buf.count {
            let fp = Data(bytes: buf.baseAddress! + pos, count: 32)
            pos += 32
            let trust: TrustState =
                switch buf[pos] {
                case 1: .verified
                case 2: .keyChanged
                default: .unverified
                }
            pos += 1
            let nameLen = Int(buf[pos]) | (Int(buf[pos + 1]) << 8)
            pos += 2
            guard pos + nameLen <= buf.count else { break }
            let name = String(decoding: Array(buf[pos..<pos + nameLen]), as: UTF8.self)
            pos += nameLen
            out.append(ContactSummary(fingerprint: fp, trust: trust, name: name))
        }
        return out
    }

    func markVerified(_ fingerprint: Data) throws {
        let status = fingerprint.withUnsafeBytes {
            void_engine_mark_verified(handle, $0.bindMemory(to: UInt8.self).baseAddress)
        }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
    }

    func acknowledgeKeyChange(_ fingerprint: Data) throws {
        let status = fingerprint.withUnsafeBytes {
            void_engine_acknowledge_key_change(handle, $0.bindMemory(to: UInt8.self).baseAddress)
        }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
    }

    func revokeContact(_ fingerprint: Data) throws {
        let status = fingerprint.withUnsafeBytes {
            void_engine_revoke_contact(handle, $0.bindMemory(to: UInt8.self).baseAddress)
        }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
    }
}

/// A handle to an introduction queue, from `VoidCore.createInvite`. Frees the
/// underlying secret on deinit — hold one of these per outstanding invite,
/// not the raw pointer.
final class IntroQueue {
    fileprivate let handle: OpaquePointer

    fileprivate init(_ handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        void_queue_secret_free(handle)
    }
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
