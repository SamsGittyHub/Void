//  VoidCall.swift
//
//  Calls: the Swift half of `void_proto::call` and `void_tor::call`.
//  See docs/DECISIONS.md D-024 and D-028.
//
//  ## The latency, stated rather than designed around
//
//  Measured on the live Tor network (experiments/onion-call/RESULTS.md),
//  mouth-to-ear delay over paired onion services is 470-870 ms. ITU-T G.114
//  puts the limit for natural interactive conversation at 400 ms, so this is
//  a call with real lag: interrupting does not work, and two people who both
//  start talking will collide.
//
//  The microphone is open both ways regardless, because that is what a call
//  is. What the app does about the lag is tell the user about it, once before
//  the call and once on the call screen, rather than hide it behind a
//  hold-to-talk button that would make the limitation the user's problem to
//  operate.
//
//  ## What crosses the FFI
//
//  Encoded Opus frames, and nothing else. The core encrypts and decrypts
//  them; this file never sees a media key. `answerCall` returns the secret
//  only to hand straight back to `CallMedia.connect`, because Swift `Data` is
//  outside the core's zeroization discipline.
//
//  ## Threads and lifetimes
//
//  A call's media is used from a sending thread and a receiving thread while
//  the main thread may hang up. The core's handles are reference counted and
//  safe for that; the rule on this side is only that a handle is freed after
//  the last thread using it has finished. Each class below frees its handle in
//  `deinit`, and each audio thread holds a strong reference while it runs, so
//  ARC enforces the order. Hanging up is `close` (or `cancel`), which wakes a
//  thread blocked in the network within about a tenth of a second.

import Foundation

// MARK: - Call state

/// Which end of a call this device is.
enum CallRole {
    case caller
    case callee
}

/// Why a call ended. Mirrors `void_proto::call::EndReason`.
enum CallEndReason: UInt32 {
    case hungUp = 1
    case declined = 2
    case missed = 3
    case failed = 4
    case busy = 5
}

/// What the engine reported about a call.
enum CallEvent: Equatable {
    case incoming(fingerprint: Data, callId: Data, address: String, port: UInt16)
    case answered(fingerprint: Data, callId: Data)
    case ended(fingerprint: Data, callId: Data, reason: CallEndReason)
    /// A call that never rang here: it arrived too late to be live, or this
    /// device was already on a call. Worth showing in the conversation.
    case missed(fingerprint: Data, callId: Data)
}

/// What one receive produced. Mirrors `VoidMediaRecv`.
enum MediaReceive: Equatable {
    /// Authenticated audio. Play it.
    case audio(Data)
    /// An authenticated frame of silence: nothing to play, but proof the other
    /// end is there.
    case silence
    /// Nothing usable within two seconds. Many in a row mean a stall.
    case nothing
    /// The connection is gone, or was closed. End the call.
    case closed
}

private let statusOk = VoidStatus(rawValue: 0)

/// A live media connection.
final class CallMedia: @unchecked Sendable {
    private let handle: OpaquePointer

    fileprivate init(_ handle: OpaquePointer) {
        self.handle = handle
    }

    /// Dial the caller's service (the callee side). Blocks on the network.
    static func connect(
        tor: TorClient, address: String, port: UInt16, mediaSecret: Data, callId: Data
    ) -> CallMedia? {
        var out: OpaquePointer?
        let status = address.withCString { addr in
            mediaSecret.withUnsafeBytes { secret in
                callId.withUnsafeBytes { id in
                    void_call_media_connect(
                        tor.handle,
                        addr,
                        port,
                        secret.bindMemory(to: UInt8.self).baseAddress,
                        id.bindMemory(to: UInt8.self).baseAddress,
                        &out
                    )
                }
            }
        }
        guard status == statusOk, let out else { return nil }
        return CallMedia(out)
    }

    /// Encrypt and send one encoded audio frame; an empty one is silence, which
    /// keeps the cadence constant while nobody talks. Returns false once the
    /// connection is gone. A frame dropped because the circuit is backed up
    /// still returns true: late audio is only delay.
    @discardableResult
    func send(_ audio: Data) -> Bool {
        if audio.isEmpty {
            return void_call_media_send(handle, nil, 0) == statusOk
        }
        return audio.withUnsafeBytes { buf in
            void_call_media_send(
                handle, buf.bindMemory(to: UInt8.self).baseAddress, UInt(audio.count)
            ) == statusOk
        }
    }

    /// Receive one frame, waiting up to two seconds.
    func receive() -> MediaReceive {
        var audio = VoidBytes()
        let result = void_call_media_recv(handle, &audio)
        let buffer = CoreBuffer(audio)
        switch result.rawValue {
        case 0: return .audio(Data(buffer.array))
        case 1: return .silence
        case 2: return .nothing
        default: return .closed
        }
    }

    /// Wake a blocked receive, and refuse later sends. Safe to call any number
    /// of times, from any thread.
    func close() {
        void_call_media_close(handle)
    }

    deinit {
        void_call_media_free(handle)
    }
}

/// A published onion service waiting for the callee to connect.
final class CallHost: @unchecked Sendable {
    private let handle: OpaquePointer

    /// The address to put in the offer.
    let address: String

    /// Publish an ephemeral service for an outgoing call.
    ///
    /// Returns before the service is reachable; the descriptor upload (about
    /// four seconds, measured) overlaps the peer's retrieval delay rather than
    /// adding to it, so place the call immediately after this returns.
    init?(tor: TorClient, keyDirectory: URL) {
        var out: OpaquePointer?
        let status = keyDirectory.path.withCString { dir in
            void_call_host_publish(tor.handle, dir, &out)
        }
        guard status == statusOk, let out else { return nil }
        let address = CoreBuffer(void_call_host_address(out)).string
        guard !address.isEmpty else {
            void_call_host_free(out)
            return nil
        }
        self.handle = out
        self.address = address
    }

    /// Block until the callee connects, the answer window closes, or `cancel`.
    /// Call it off the main thread straight after placing the call — not once
    /// the relayed answer arrives: the callee dials the moment they answer, and
    /// their first authenticated frame is the answer (D-028).
    func accept(mediaSecret: Data, callId: Data) -> CallMedia? {
        var out: OpaquePointer?
        let status = mediaSecret.withUnsafeBytes { secret in
            callId.withUnsafeBytes { id in
                void_call_host_accept(
                    handle,
                    secret.bindMemory(to: UInt8.self).baseAddress,
                    id.bindMemory(to: UInt8.self).baseAddress,
                    &out
                )
            }
        }
        guard status == statusOk, let out else { return nil }
        return CallMedia(out)
    }

    /// Stop waiting: a blocked `accept` returns nil within about a tenth of a
    /// second. The caller hung up while it rang.
    func cancel() {
        void_call_host_cancel(handle)
    }

    deinit {
        // Unpublishes the service and deletes its keys once nothing is using it.
        void_call_host_free(handle)
    }
}

// MARK: - VoidCore call surface

extension VoidCore {
    /// How often the audio loop must send a frame, in milliseconds.
    static var frameDurationMs: UInt64 { void_call_media_frame_ms() }

    /// Largest encoded frame one media frame can carry.
    static var maxPayloadLength: Int { Int(void_call_media_payload_len()) }

    /// The virtual port a call's onion service listens on.
    static var callPort: UInt16 { void_call_port() }

    /// What the user must be told before a call connects.
    ///
    /// From the core, not retyped here — see `void_proto::call::CALL_DISCLOSURE`,
    /// including why it does not claim location exposure.
    static var callDisclosure: String {
        CoreBuffer(void_call_disclosure()).string
    }

    /// Place a call to a contact whose onion service is already publishing.
    /// Returns the call id and the media secret to key it with. `now` is in
    /// seconds: the offer carries it, so one that reaches the callee too late
    /// to be live shows as missed instead of ringing.
    func placeCall(to fingerprint: Data, address: String, port: UInt16, now: UInt64) throws -> (
        callId: Data, mediaSecret: Data
    ) {
        var callId = [UInt8](repeating: 0, count: 16)
        var secret = [UInt8](repeating: 0, count: 32)
        defer {
            for i in secret.indices { secret[i] = 0 }
        }
        let status = fingerprint.withUnsafeBytes { fp in
            address.withCString { addr in
                void_engine_place_call(
                    handle,
                    fp.bindMemory(to: UInt8.self).baseAddress,
                    addr,
                    port,
                    now,
                    &callId,
                    &secret
                )
            }
        }
        guard status == statusOk else { throw VoidError(status) }
        return (Data(callId), Data(secret))
    }

    /// Answer an incoming call, returning what the media connection needs.
    func answerCall(from fingerprint: Data) throws -> (
        callId: Data, mediaSecret: Data, address: String, port: UInt16
    ) {
        var callId = [UInt8](repeating: 0, count: 16)
        var secret = [UInt8](repeating: 0, count: 32)
        defer {
            for i in secret.indices { secret[i] = 0 }
        }
        var addressBytes = VoidBytes()
        var port: UInt16 = 0
        let status = fingerprint.withUnsafeBytes { fp in
            void_engine_answer_call(
                handle,
                fp.bindMemory(to: UInt8.self).baseAddress,
                &callId,
                &secret,
                &addressBytes,
                &port
            )
        }
        let address = CoreBuffer(addressBytes).string
        guard status == statusOk else { throw VoidError(status) }
        return (Data(callId), Data(secret), address, port)
    }

    /// The caller has seen the callee's first authenticated media frame: the
    /// call is answered, without waiting a mailbox delay for the relayed answer.
    @discardableResult
    func markCallConnected(_ fingerprint: Data) -> Bool {
        fingerprint.withUnsafeBytes {
            void_engine_mark_call_connected(handle, $0.bindMemory(to: UInt8.self).baseAddress)
        } == statusOk
    }

    /// End a call — hang up, decline, or report failure. Local call state
    /// clears whether or not the signal gets out.
    func endCall(with fingerprint: Data, reason: CallEndReason) throws {
        let status = fingerprint.withUnsafeBytes { fp in
            void_engine_end_call(
                handle,
                fp.bindMemory(to: UInt8.self).baseAddress,
                VoidCallEndReason(rawValue: reason.rawValue)
            )
        }
        guard status == statusOk else { throw VoidError(status) }
    }

    /// Drain call events. Layout is documented on
    /// `void_ffi::void_engine_take_call_events`.
    func takeCallEvents() -> [CallEvent] {
        var reader = ByteReader(CoreBuffer(void_engine_take_call_events(handle)).array)
        var events: [CallEvent] = []
        while !reader.isAtEnd {
            guard let kind = reader.u8(),
                let fingerprint = reader.data(32),
                let callId = reader.data(16),
                let reason = reader.u8(),
                let addressLength = reader.u32(),
                let address = reader.string(Int(addressLength)),
                let port = reader.u16()
            else { break }
            switch kind {
            case 1:
                events.append(
                    .incoming(fingerprint: fingerprint, callId: callId, address: address, port: port))
            case 2:
                events.append(.answered(fingerprint: fingerprint, callId: callId))
            case 3:
                events.append(
                    .ended(
                        fingerprint: fingerprint,
                        callId: callId,
                        reason: CallEndReason(rawValue: UInt32(reason)) ?? .failed
                    ))
            case 4:
                events.append(.missed(fingerprint: fingerprint, callId: callId))
            default:
                return events
            }
        }
        return events
    }
}
