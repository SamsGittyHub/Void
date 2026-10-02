//  CallAudio.swift
//
//  Captures, encodes, sends, receives, decodes and plays one call's audio.
//
//  ## Why the codec is here and not in Rust
//
//  `void-crypto` has two third-party dependencies and a CI check that fails
//  the build on a third (NFR-SEC-07). Linking libopus would mean C in the
//  workspace, `unsafe` outside the FFI crates, and a `check_deps.sh`
//  exemption — for a codec both platforms already ship. iOS has had Opus in
//  AudioToolbox since iOS 11, so the core stays codec-agnostic and moves
//  opaque bytes, and this file is the only place that knows what those bytes
//  are.
//
//  ## Constant bitrate, deliberately
//
//  The encoder runs CBR with no voice-activity detection. A variable-rate
//  codec makes packet sizes track the shape of speech, which leaks phonetics
//  to anyone counting bytes — a published attack, not a hypothetical. The core
//  pads every frame to one size anyway; configuring the encoder to match means
//  that padding is not also wasting bandwidth on a slow circuit.
//
//  ## Three threads, none of them the audio thread
//
//  - The input tap converts whatever the microphone produces to 16 kHz mono
//    and appends it to a short queue. It never touches the network: an audio
//    callback that blocks on Tor stalls the whole audio engine.
//  - A paced sender takes exactly one 20 ms frame from that queue every 20 ms,
//    encodes it and sends it — or sends silence if there is none or the
//    microphone is muted, so the cadence never varies.
//  - A receiver blocks on the network, decodes, and schedules playback. It
//    also decides when the call has dropped: the connection closed, or ten
//    seconds passed with nothing authenticated arriving.

import AVFoundation
import Foundation

/// Apple's Opus codec, through `AVAudioConverter`, at the one configuration
/// a call uses: 16 kHz mono, one 20 ms packet per frame, constant bitrate.
///
/// Separate from `CallAudio` so that it can be exercised without a
/// microphone, a call, or Tor: `OpusCodecTests` runs it on the Simulator in
/// CI, which is the only place the assumption that iOS can encode and decode
/// Opus at this configuration has ever been checked — no call has yet been
/// made between two iPhones (D-024, D-031).
final class OpusCodec {
    /// 16 kHz mono float: what the encoder takes and the decoder produces.
    /// Wideband speech is what a circuit this slow carries without the delay
    /// growing further.
    let pcmFormat: AVAudioFormat
    let opusFormat: AVAudioFormat
    /// Samples in one frame: 320 at 16 kHz and 20 ms.
    let samplesPerFrame: Int
    private let encoder: AVAudioConverter
    private let decoder: AVAudioConverter

    /// Constant bitrate, deliberately (see `CallAudio`): 16 kbit/s is 40
    /// bytes a packet, a third of what a media frame carries.
    static let bitRate = 16_000

    init(sampleRate: Double = 16_000, frameMs: Int = Int(VoidCore.frameDurationMs)) throws {
        let perFrame = Int(sampleRate) * frameMs / 1000
        samplesPerFrame = perFrame
        guard
            let pcm = AVAudioFormat(
                commonFormat: .pcmFormatFloat32, sampleRate: sampleRate, channels: 1,
                interleaved: false)
        else { throw VoidError.failed }
        var description = AudioStreamBasicDescription(
            mSampleRate: sampleRate,
            mFormatID: kAudioFormatOpus,
            mFormatFlags: 0,
            mBytesPerPacket: 0,
            mFramesPerPacket: UInt32(perFrame),
            mBytesPerFrame: 0,
            mChannelsPerFrame: 1,
            mBitsPerChannel: 0,
            mReserved: 0
        )
        guard let opus = AVAudioFormat(streamDescription: &description),
            let encoder = AVAudioConverter(from: pcm, to: opus),
            let decoder = AVAudioConverter(from: opus, to: pcm)
        else { throw VoidError.failed }
        encoder.bitRate = Self.bitRate
        encoder.bitRateStrategy = AVAudioBitRateStrategy_Constant
        pcmFormat = pcm
        opusFormat = opus
        self.encoder = encoder
        self.decoder = decoder
    }

    /// Encode one frame of exactly `samplesPerFrame` samples. `nil` if the
    /// encoder produced nothing usable, in which case the caller sends
    /// silence instead. A packet larger than a media frame carries is dropped
    /// rather than cut: half an Opus packet is noise, not quieter speech.
    func encode(_ samples: [Float]) -> Data? {
        guard samples.count == samplesPerFrame,
            let pcm = AVAudioPCMBuffer(pcmFormat: pcmFormat, frameCapacity: AVAudioFrameCount(samplesPerFrame)),
            let channel = pcm.floatChannelData?[0]
        else { return nil }
        pcm.frameLength = AVAudioFrameCount(samplesPerFrame)
        samples.withUnsafeBufferPointer { src in
            if let base = src.baseAddress {
                channel.update(from: base, count: samplesPerFrame)
            }
        }
        let out = AVAudioCompressedBuffer(
            format: opusFormat,
            packetCapacity: 1,
            maximumPacketSize: max(encoder.maximumOutputPacketSize, VoidCore.maxPayloadLength)
        )
        var supplied = false
        var error: NSError?
        let status = encoder.convert(to: out, error: &error) { _, inputStatus in
            if supplied {
                inputStatus.pointee = .noDataNow
                return nil
            }
            supplied = true
            inputStatus.pointee = .haveData
            return pcm
        }
        guard status != .error, error == nil, out.packetCount > 0, out.byteLength > 0 else {
            return nil
        }
        let offset = Int(out.packetDescriptions?.pointee.mStartOffset ?? 0)
        let size = Int(out.packetDescriptions?.pointee.mDataByteSize ?? out.byteLength)
        guard size > 0, size <= VoidCore.maxPayloadLength else { return nil }
        return Data(bytes: out.data.advanced(by: offset), count: size)
    }

    /// Decode one packet to PCM. `nil` if it does not decode.
    func decode(_ frame: Data) -> AVAudioPCMBuffer? {
        guard !frame.isEmpty else { return nil }
        let compressed = AVAudioCompressedBuffer(
            format: opusFormat, packetCapacity: 1, maximumPacketSize: max(frame.count, 1))
        frame.withUnsafeBytes { src in
            if let base = src.baseAddress {
                compressed.data.copyMemory(from: base, byteCount: frame.count)
            }
        }
        compressed.byteLength = UInt32(frame.count)
        compressed.packetCount = 1
        compressed.packetDescriptions?.pointee = AudioStreamPacketDescription(
            mStartOffset: 0, mVariableFramesInPacket: 0, mDataByteSize: UInt32(frame.count))

        // Room for a whole Opus frame at 48 kHz, whatever the encoder chose.
        guard let pcm = AVAudioPCMBuffer(pcmFormat: pcmFormat, frameCapacity: 2_880) else { return nil }
        var supplied = false
        var error: NSError?
        let status = decoder.convert(to: pcm, error: &error) { _, inputStatus in
            if supplied {
                inputStatus.pointee = .noDataNow
                return nil
            }
            supplied = true
            inputStatus.pointee = .haveData
            return compressed
        }
        guard status != .error, error == nil, pcm.frameLength > 0 else { return nil }
        return pcm
    }
}

final class CallAudio: @unchecked Sendable {
    private let media: CallMedia
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()

    private let codec: OpusCodec
    private var pcmFormat: AVAudioFormat { codec.pcmFormat }
    private var captureConverter: AVAudioConverter?

    private let samplesPerFrame: Int
    private let frameNanos: UInt64

    private let lock = NSLock()
    private var captured: [Float] = []
    private var scheduledFrames = 0
    private var muted = false
    private var running = false
    private var heardFrom = false
    private var interruptionObserver: NSObjectProtocol?
    private let threads = DispatchGroup()

    /// Called once, on the receiving thread, when the first authenticated
    /// frame arrives — audio or silence. For the caller, that is the answer.
    /// Set before `start`.
    var onConnected: (@Sendable () -> Void)?
    /// Called once, from an audio thread, when the call is over from this
    /// end's point of view: `true` if the connection closed — nearly always the
    /// other end hanging up, whose relayed "ended" arrives seconds later —
    /// `false` if it stalled, open but carrying nothing authenticated for ten
    /// seconds. Set before `start`.
    var onDropped: (@Sendable (_ connectionClosed: Bool) -> Void)?

    /// At most this much received audio waits to be played. Tor delivers late
    /// packets in clumps (runs of half a second and more are in the
    /// measurements); playing a clump in full would add its length to every
    /// word that followed, for the rest of the call.
    private static let maxQueuedPlaybackMs = 400
    /// How long without an authenticated frame before the call counts as
    /// dropped.
    private static let dropAfterSeconds: TimeInterval = 10
    /// The most captured audio held for the sender, so a stalled sender cannot
    /// grow the queue without bound.
    private static let maxCapturedMs = 200

    init(media: CallMedia) throws {
        self.media = media
        let frameMs = Int(VoidCore.frameDurationMs)
        codec = try OpusCodec(sampleRate: 16_000, frameMs: frameMs)
        samplesPerFrame = codec.samplesPerFrame
        frameNanos = UInt64(frameMs) * 1_000_000
    }

    /// Ask for the microphone, once, at the moment the user chooses to call or
    /// answer — not mid-call, and not at launch for a feature they may never
    /// use.
    @MainActor
    static func requestMicrophone(_ completion: @escaping @MainActor (Bool) -> Void) {
        let session = AVAudioSession.sharedInstance()
        switch session.recordPermission {
        case .granted:
            completion(true)
        case .denied:
            completion(false)
        default:
            session.requestRecordPermission { granted in
                Task { @MainActor in completion(granted) }
            }
        }
    }

    /// Whether the microphone is muted. Muting stops the microphone, not the
    /// emission: silence goes out on the same cadence, so muting changes what
    /// the other person hears and nothing about what the network sees.
    var isMuted: Bool {
        get { lock.withLock { muted } }
        set { lock.withLock { muted = newValue } }
    }

    /// Start capture, playback, and the two network threads. The microphone
    /// permission must already be granted — asking mid-call is the wrong moment.
    func start() throws {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetooth])
        try session.setActive(true)

        // Echo cancellation: without it the other person hears themselves a
        // second later, which on a line with this much delay is unusable.
        try engine.inputNode.setVoiceProcessingEnabled(true)

        let input = engine.inputNode
        let inputFormat = input.outputFormat(forBus: 0)
        guard inputFormat.sampleRate > 0, inputFormat.channelCount > 0,
            let converter = AVAudioConverter(from: inputFormat, to: pcmFormat)
        else { throw VoidError.failed }
        captureConverter = converter
        input.installTap(onBus: 0, bufferSize: 1024, format: inputFormat) { [weak self] buffer, _ in
            self?.capture(buffer)
        }

        engine.attach(player)
        // Connected in the decoder's own format; the mixer converts to the
        // hardware's. Connecting with `format: nil` left the player expecting
        // one format and receiving another.
        engine.connect(player, to: engine.mainMixerNode, format: pcmFormat)
        engine.prepare()
        try engine.start()
        player.play()

        interruptionObserver = NotificationCenter.default.addObserver(
            forName: AVAudioSession.interruptionNotification, object: session, queue: nil
        ) { [weak self] note in
            self?.handleInterruption(note)
        }

        lock.withLock { running = true }
        spawn("void-call-send") { [self] in sendLoop() }
        spawn("void-call-receive") { [self] in receiveLoop() }
    }

    /// Hang up the audio: close the media connection, let both threads finish,
    /// then release the audio hardware. Returns at once; the teardown finishes
    /// in the background.
    func stop() {
        let wasRunning = lock.withLock { () -> Bool in
            let was = running
            running = false
            return was
        }
        media.close()
        if let observer = interruptionObserver {
            NotificationCenter.default.removeObserver(observer)
            interruptionObserver = nil
        }
        guard wasRunning else { return }
        let group = threads
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            // A blocked receive wakes within about a tenth of a second of
            // `close`, and the sender within one frame.
            _ = group.wait(timeout: .now() + 3)
            engine.inputNode.removeTap(onBus: 0)
            player.stop()
            engine.stop()
            try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        }
    }

    private var isRunning: Bool { lock.withLock { running } }

    private func spawn(_ name: String, _ body: @escaping () -> Void) {
        threads.enter()
        let thread = Thread { [threads] in
            body()
            threads.leave()
        }
        thread.name = name
        // Both loops call into the core; see `CoreThread`.
        thread.stackSize = CoreThread.stackSize
        thread.qualityOfService = .userInteractive
        thread.start()
    }

    // MARK: Capture

    /// On the tap's thread: convert to 16 kHz mono and queue it for the sender.
    private func capture(_ buffer: AVAudioPCMBuffer) {
        guard let converter = captureConverter, buffer.frameLength > 0 else { return }
        let ratio = pcmFormat.sampleRate / buffer.format.sampleRate
        let capacity = AVAudioFrameCount(Double(buffer.frameLength) * ratio) + 32
        guard let out = AVAudioPCMBuffer(pcmFormat: pcmFormat, frameCapacity: capacity) else {
            return
        }
        var supplied = false
        var error: NSError?
        _ = converter.convert(to: out, error: &error) { _, status in
            if supplied {
                status.pointee = .noDataNow
                return nil
            }
            supplied = true
            status.pointee = .haveData
            return buffer
        }
        guard error == nil, out.frameLength > 0, let channel = out.floatChannelData?[0] else {
            return
        }
        let samples = UnsafeBufferPointer(start: channel, count: Int(out.frameLength))
        let limit = samplesPerFrame * Self.maxCapturedMs / Int(VoidCore.frameDurationMs)
        lock.withLock {
            captured.append(contentsOf: samples)
            if captured.count > limit {
                captured.removeFirst(captured.count - limit)
            }
        }
    }

    // MARK: Sending

    /// One frame every 20 ms, on a clock that does not drift: each deadline is
    /// the previous one plus a frame, not "now plus a frame".
    private func sendLoop() {
        var deadline = DispatchTime.now().uptimeNanoseconds
        while isRunning {
            let frame: [Float]? = lock.withLock {
                if muted {
                    // Dropped, not kept: unmuting must not send what was said
                    // while muted.
                    captured.removeAll(keepingCapacity: true)
                    return nil
                }
                guard captured.count >= samplesPerFrame else { return nil }
                let next = Array(captured.prefix(samplesPerFrame))
                captured.removeFirst(samplesPerFrame)
                return next
            }
            let payload = frame.flatMap(codec.encode) ?? Data()
            if !media.send(payload) {
                // Refused because the connection is gone: whichever of the two
                // threads notices first, a closed connection means the same.
                dropped(connectionClosed: true)
                return
            }
            deadline += frameNanos
            let now = DispatchTime.now().uptimeNanoseconds
            if deadline > now {
                Thread.sleep(forTimeInterval: Double(deadline - now) / 1_000_000_000)
            } else if now - deadline > 10 * frameNanos {
                // Far behind — the app was suspended. Resynchronise instead of
                // sending a burst to catch up.
                deadline = now
            }
        }
    }

    // MARK: Receiving

    private func receiveLoop() {
        var lastHeard = Date()
        while isRunning {
            switch media.receive() {
            case .audio(let frame):
                lastHeard = Date()
                announceConnected()
                play(frame)
            case .silence:
                lastHeard = Date()
                announceConnected()
            case .nothing:
                if Date().timeIntervalSince(lastHeard) > Self.dropAfterSeconds {
                    dropped(connectionClosed: false)
                    return
                }
            case .closed:
                if isRunning { dropped(connectionClosed: true) }
                return
            }
        }
    }

    private func announceConnected() {
        let first = lock.withLock { () -> Bool in
            defer { heardFrom = true }
            return !heardFrom
        }
        if first { onConnected?() }
    }

    private func dropped(connectionClosed: Bool) {
        let wasRunning = lock.withLock { () -> Bool in
            let was = running
            running = false
            return was
        }
        media.close()
        if wasRunning { onDropped?(connectionClosed) }
    }

    private func play(_ frame: Data) {
        guard let pcm = codec.decode(frame) else { return }

        let maxQueued = Self.maxQueuedPlaybackMs / Int(VoidCore.frameDurationMs)
        let behind = lock.withLock { scheduledFrames >= maxQueued }
        if behind {
            // Drop the oldest audio rather than fall further behind. `stop`
            // discards everything scheduled; each dropped buffer's completion
            // handler still runs and keeps the count honest.
            player.stop()
            player.play()
        }
        lock.withLock { scheduledFrames += 1 }
        player.scheduleBuffer(pcm) { [weak self] in
            guard let self else { return }
            self.lock.withLock { self.scheduledFrames = max(0, self.scheduledFrames - 1) }
        }
    }

    // MARK: Interruptions

    /// A phone call or Siri takes the audio hardware. Frames keep going out as
    /// silence meanwhile — the cadence never varies — and audio resumes when the
    /// interruption ends.
    private func handleInterruption(_ note: Notification) {
        guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
            let type = AVAudioSession.InterruptionType(rawValue: raw)
        else { return }
        switch type {
        case .began:
            lock.withLock { captured.removeAll() }
        case .ended:
            guard isRunning else { return }
            try? AVAudioSession.sharedInstance().setActive(true)
            try? engine.start()
            player.play()
        @unknown default:
            break
        }
    }
}
