//  VoidCall.swift
//
//  Calls: the Swift half of `void_proto::call` and `void_tor::call`.
//  See docs/DECISIONS.md D-024.
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
//  them; this file never sees a media key. `answerCall` writes the secret
//  into a buffer that is handed straight back to `connect` and zeroed after,
//  because Swift `Data` is outside the core's zeroization discipline.

import AVFoundation
import Foundation

// MARK: - Call state

/// Which end of a call this device is.
enum CallRole {
    case caller
    case callee
}

/// Why a call ended. Mirrors `void_proto::call::EndReason`.
enum CallEndReason: Int32 {
    case hungUp = 1
    case declined = 2
    case missed = 3
    case failed = 4
}

/// What the engine reported about a call.
enum CallEvent {
    case incoming(fingerprint: Data, callId: Data, address: String, port: UInt16)
    case answered(fingerprint: Data, callId: Data)
    case ended(fingerprint: Data, callId: Data, reason: CallEndReason)
}

/// A live media connection. Owns the C handle and frees it exactly once.
final class CallMedia {
    private var handle: OpaquePointer?

    fileprivate init(_ handle: OpaquePointer) {
        self.handle = handle
    }

    /// Encrypt and send one encoded audio frame. An empty frame is silence,
    /// which is what keeps the emission cadence constant while nobody talks.
    @discardableResult
    func send(_ audio: Data) -> Bool {
        guard let handle else { return false }
        if audio.isEmpty {
            return void_call_media_send(handle, nil, 0) == VoidStatus(rawValue: 0)
        }
        return audio.withUnsafeBytes { buf in
            void_call_media_send(
                handle, buf.bindMemory(to: UInt8.self).baseAddress, UInt(audio.count)
            ) == VoidStatus(rawValue: 0)
        }
    }

    /// Receive one frame. Empty means play nothing — silence, a replay, and a
    /// frame that failed to authenticate all arrive as empty on purpose,
    /// because the right response to all three is the same.
    func receive() -> Data {
        guard let handle else { return Data() }
        let bytes = void_call_media_recv(handle)
        defer { void_free_bytes(bytes) }
        guard let data = bytes.data, bytes.len > 0 else { return Data() }
        return Data(bytes: data, count: Int(bytes.len))
    }

    func close() {
        guard let handle else { return }
        void_call_media_free(handle)
        self.handle = nil
    }

    deinit { close() }
}

/// A published onion service waiting for the other side to connect.
final class CallHost {
    private var handle: OpaquePointer?

    /// The address to put in the offer.
    let address: String

    fileprivate init?(tor: OpaquePointer, keyDirectory: URL) {
        var out: OpaquePointer?
        let status = keyDirectory.path.withCString { dir in
            void_call_host_publish(tor, dir, &out)
        }
        guard status == VoidStatus(rawValue: 0), let handle = out else { return nil }
        self.handle = handle

        let bytes = void_call_host_address(handle)
        defer { void_free_bytes(bytes) }
        guard let data = bytes.data, bytes.len > 0 else { return nil }
        address = String(decoding: Data(bytes: data, count: Int(bytes.len)), as: UTF8.self)
    }

    /// Blocks up to ninety seconds waiting for the callee. Call off the main
    /// thread.
    func accept(mediaSecret: Data, callId: Data) -> CallMedia? {
        guard let handle else { return nil }
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
        // `accept` consumes the host on the Rust side either way.
        self.handle = nil
        void_call_host_free(handle)
        guard status == VoidStatus(rawValue: 0), let media = out else { return nil }
        return CallMedia(media)
    }

    func cancel() {
        guard let handle else { return }
        void_call_host_free(handle)
        self.handle = nil
    }

    deinit { cancel() }
}

// MARK: - VoidCore call surface

extension VoidCore {
    /// Frames per second the audio loop must maintain.
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
        let bytes = void_call_disclosure()
        defer { void_free_bytes(bytes) }
        guard let data = bytes.data, bytes.len > 0 else { return "" }
        return String(decoding: Data(bytes: data, count: Int(bytes.len)), as: UTF8.self)
    }

    /// Publish an ephemeral service for an outgoing call.
    ///
    /// Returns before the service is reachable; the descriptor upload (about
    /// four seconds, measured) overlaps the peer's polling delay rather than
    /// adding to it, so place the call immediately after this returns.
    func publishCallService(keyDirectory: URL) -> CallHost? {
        guard let tor = torHandle else { return nil }
        return CallHost(tor: tor, keyDirectory: keyDirectory)
    }

    /// Place a call. Returns the call id and the media secret to key it with.
    func placeCall(to fingerprint: Data, address: String, port: UInt16) throws -> (
        callId: Data, mediaSecret: Data
    ) {
        var callId = [UInt8](repeating: 0, count: 16)
        var secret = [UInt8](repeating: 0, count: 32)
        let status = fingerprint.withUnsafeBytes { fp in
            address.withCString { addr in
                void_engine_place_call(
                    handle,
                    fp.bindMemory(to: UInt8.self).baseAddress,
                    addr,
                    port,
                    &callId,
                    &secret
                )
            }
        }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
        return (Data(callId), Data(secret))
    }

    /// Answer an incoming call, returning what the media connection needs.
    func answerCall(from fingerprint: Data) throws -> (
        callId: Data, mediaSecret: Data, address: String, port: UInt16
    ) {
        var callId = [UInt8](repeating: 0, count: 16)
        var secret = [UInt8](repeating: 0, count: 32)
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
        defer { void_free_bytes(addressBytes) }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
        let address: String
        if let data = addressBytes.data, addressBytes.len > 0 {
            address = String(decoding: Data(bytes: data, count: Int(addressBytes.len)), as: UTF8.self)
        } else {
            address = ""
        }
        return (Data(callId), Data(secret), address, port)
    }

    /// Dial the caller's service (the callee side).
    func connectCall(address: String, port: UInt16, mediaSecret: Data, callId: Data) -> CallMedia? {
        guard let tor = torHandle else { return nil }
        var out: OpaquePointer?
        let status = address.withCString { addr in
            mediaSecret.withUnsafeBytes { secret in
                callId.withUnsafeBytes { id in
                    void_call_media_connect(
                        tor,
                        addr,
                        port,
                        secret.bindMemory(to: UInt8.self).baseAddress,
                        id.bindMemory(to: UInt8.self).baseAddress,
                        &out
                    )
                }
            }
        }
        guard status == VoidStatus(rawValue: 0), let media = out else { return nil }
        return CallMedia(media)
    }

    /// End a call.
    func endCall(with fingerprint: Data, reason: CallEndReason) throws {
        let status = fingerprint.withUnsafeBytes { fp in
            void_engine_end_call(
                handle,
                fp.bindMemory(to: UInt8.self).baseAddress,
                VoidCallEndReason(rawValue: UInt32(reason.rawValue))
            )
        }
        guard status == VoidStatus(rawValue: 0) else { throw VoidError(status) }
    }

    /// Drain call events. Layout is documented on
    /// `void_ffi::void_engine_take_call_events`.
    func takeCallEvents() -> [CallEvent] {
        let bytes = void_engine_take_call_events(handle)
        defer { void_free_bytes(bytes) }
        guard let data = bytes.data, bytes.len > 0 else { return [] }
        let buf = UnsafeBufferPointer(start: data, count: Int(bytes.len))

        var events: [CallEvent] = []
        var pos = 0
        // kind(1) + fingerprint(32) + call_id(16) + reason(1) + len(4) + port(2)
        let fixed = 56
        while pos + fixed <= buf.count {
            let kind = buf[pos]
            let fingerprint = Data(bytes: buf.baseAddress! + pos + 1, count: 32)
            let callId = Data(bytes: buf.baseAddress! + pos + 33, count: 16)
            let reasonByte = buf[pos + 49]
            let lenBase = pos + 50
            let len =
                Int(buf[lenBase]) | (Int(buf[lenBase + 1]) << 8) | (Int(buf[lenBase + 2]) << 16)
                | (Int(buf[lenBase + 3]) << 24)
            var cursor = lenBase + 4
            guard cursor + len + 2 <= buf.count else { break }
            let address = String(decoding: Array(buf[cursor..<cursor + len]), as: UTF8.self)
            cursor += len
            let port = UInt16(buf[cursor]) | (UInt16(buf[cursor + 1]) << 8)
            cursor += 2
            pos = cursor

            switch kind {
            case 1:
                events.append(
                    .incoming(fingerprint: fingerprint, callId: callId, address: address, port: port)
                )
            case 2:
                events.append(.answered(fingerprint: fingerprint, callId: callId))
            case 3:
                events.append(
                    .ended(
                        fingerprint: fingerprint,
                        callId: callId,
                        reason: CallEndReason(rawValue: Int32(reasonByte)) ?? .failed
                    )
                )
            default:
                return events
            }
        }
        return events
    }
}

// MARK: - Audio

/// Captures and plays Opus frames for one call.
///
/// ## Why the codec is here and not in Rust
///
/// `void-crypto` has two third-party dependencies and a CI check that fails
/// the build on a third (NFR-SEC-07). Linking libopus would mean C in the
/// workspace, `unsafe` outside `void-ffi`, and a `check_deps.sh` exemption —
/// for a codec that both platforms already ship. iOS has had Opus in
/// AudioToolbox since iOS 11, so the core stays codec-agnostic and moves
/// opaque bytes, and this file is the only place that knows what those bytes
/// are.
///
/// ## Constant bitrate, deliberately
///
/// The encoder runs CBR with no voice-activity detection. A variable-rate
/// codec makes packet sizes track the shape of speech, which leaks phonetics
/// to anyone counting bytes — a published attack, not a hypothetical. The
/// core pads every frame to one size anyway; configuring the encoder to match
/// means that padding is not also wasting bandwidth on a slow circuit.
final class CallAudio {
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private var converter: AVAudioConverter?
    private var decoder: AVAudioConverter?
    private var media: CallMedia?
    private var receiveThread: Thread?
    private var running = false

    /// 20 ms frames at 16 kHz mono — wideband speech, which is what a circuit
    /// this slow can carry without the buffer growing further.
    private let sampleRate: Double = 16000

    /// Whether the microphone is currently open. Muting sets this false;
    /// silence frames still go out either way, so muting changes what the
    /// other person hears and nothing about what the network sees.
    var transmitting = true

    func start(media: CallMedia, onFrameReceived: @escaping (Data) -> Void) throws {
        self.media = media

        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetooth])
        try session.setPreferredIOBufferDuration(Double(VoidCore.frameDurationMs) / 1000.0)
        try session.setActive(true)

        let input = engine.inputNode
        let inputFormat = input.inputFormat(forBus: 0)
        guard
            let opusFormat = AVAudioFormat(
                settings: [
                    AVFormatIDKey: kAudioFormatOpus,
                    AVSampleRateKey: sampleRate,
                    AVNumberOfChannelsKey: 1,
                    AVEncoderBitRateKey: 16000,
                ]
            )
        else { throw VoidError.failed }

        converter = AVAudioConverter(from: inputFormat, to: opusFormat)
        decoder = AVAudioConverter(from: opusFormat, to: input.outputFormat(forBus: 0))

        engine.attach(player)
        engine.connect(player, to: engine.mainMixerNode, format: nil)

        let framesPerBuffer = AVAudioFrameCount(sampleRate * Double(VoidCore.frameDurationMs) / 1000.0)
        input.installTap(onBus: 0, bufferSize: framesPerBuffer, format: inputFormat) {
            [weak self] buffer, _ in
            guard let self, let media = self.media else { return }
            // Silence still goes out when not transmitting: the cadence is
            // constant whether or not anyone is speaking.
            let payload = self.transmitting ? self.encode(buffer) : Data()
            media.send(payload)
        }

        try engine.start()
        player.play()

        running = true
        let thread = Thread { [weak self] in
            guard let self else { return }
            while self.running, let media = self.media {
                let frame = media.receive()
                if !frame.isEmpty {
                    onFrameReceived(frame)
                    self.play(frame)
                }
            }
        }
        thread.qualityOfService = .userInteractive
        thread.start()
        receiveThread = thread
    }

    func stop() {
        running = false
        player.stop()
        engine.inputNode.removeTap(onBus: 0)
        engine.stop()
        media?.close()
        media = nil
        try? AVAudioSession.sharedInstance().setActive(false)
    }

    private func encode(_ buffer: AVAudioPCMBuffer) -> Data {
        guard let converter, let format = converter.outputFormat as AVAudioFormat? else {
            return Data()
        }
        let out = AVAudioCompressedBuffer(
            format: format,
            packetCapacity: 1,
            maximumPacketSize: VoidCore.maxPayloadLength
        )

        var supplied = false
        var error: NSError?
        converter.convert(to: out, error: &error) { _, status in
            if supplied {
                status.pointee = .noDataNow
                return nil
            }
            supplied = true
            status.pointee = .haveData
            return buffer
        }
        guard error == nil, out.byteLength > 0 else { return Data() }
        return Data(bytes: out.data, count: Int(out.byteLength))
    }

    private func play(_ frame: Data) {
        // Decoding and scheduling happen on the receive thread; AVAudioPlayerNode
        // is documented as safe to schedule from a background thread, and the
        // jitter buffer is the node's own queue.
        guard let decoder, let inFormat = decoder.inputFormat as AVAudioFormat? else { return }
        let compressed = AVAudioCompressedBuffer(
            format: inFormat,
            packetCapacity: 1,
            maximumPacketSize: max(frame.count, 1)
        )
        frame.withUnsafeBytes { src in
            guard let base = src.baseAddress else { return }
            compressed.data.copyMemory(from: base, byteCount: frame.count)
        }
        compressed.byteLength = UInt32(frame.count)
        compressed.packetCount = 1

        guard
            let pcm = AVAudioPCMBuffer(
                pcmFormat: decoder.outputFormat,
                frameCapacity: AVAudioFrameCount(
                    decoder.outputFormat.sampleRate * Double(VoidCore.frameDurationMs) / 1000.0
                )
            )
        else { return }

        var supplied = false
        var error: NSError?
        decoder.convert(to: pcm, error: &error) { _, status in
            if supplied {
                status.pointee = .noDataNow
                return nil
            }
            supplied = true
            status.pointee = .haveData
            return compressed
        }
        guard error == nil else { return }
        player.scheduleBuffer(pcm, completionHandler: nil)
    }
}
