//  CallVideo.swift
//
//  Captures, encodes, sends, receives, decodes and shows one video call's
//  pictures. The audio is `CallAudio`'s, unchanged: a video call is a voice
//  call whose frames also carry a slice of video (D-033).
//
//  ## Why the codec is here and not in Rust
//
//  For the reason `CallAudio` gives for Opus: both platforms ship H.264, in
//  hardware, and linking a codec into the core would mean C in the workspace
//  and `unsafe` outside the FFI crates for something the phone already does.
//  The core moves opaque units. The two apps agree between themselves on what
//  is in them — H.264 Annex B, Constrained Baseline, parameter sets in front of
//  every keyframe — and this file is the only Swift that knows.
//
//  ## Sized for the lane, not the camera
//
//  The lane is 224 kbit/s and constant (`void_proto::call::VIDEO_SLICE_LEN`).
//  The encoder is asked for about two thirds of that on average, capped at
//  four fifths, at 360×480 and 15 frames a second: enough for a face, and
//  leaving room for a keyframe to drain in well under a second. What the
//  encoder produces beyond the lane is dropped by the core and answered with a
//  keyframe, never queued — queued video is delay that never goes away.
//
//  ## The Simulator has no camera
//
//  On the Simulator, and only there, the picture is a generated test pattern —
//  a moving gradient with the time on it — so that everything from the encoder
//  to the other phone's screen can still be exercised. A phone whose camera
//  the user has not allowed sends no picture at all: the camera is off.

import AVFoundation
import CoreMedia
import UIKit
import VideoToolbox

/// What the other end's video is doing, for the call screen.
struct RemoteVideoState: Equatable {
    /// At least one frame has been shown.
    var started = false
    /// They turned their camera off.
    var cameraOff = false
}

/// One video call's pictures, both ways.
final class CallVideo: NSObject, @unchecked Sendable {
    private let media: CallMedia
    /// The other end's picture. Hosted by `RemoteVideoView`.
    let remoteLayer = AVSampleBufferDisplayLayer()
    /// This end's own picture: the camera's preview, or the test pattern.
    let localView: UIView

    /// Called on the main thread when the other end's video changes state.
    var onRemoteState: (@MainActor (RemoteVideoState) -> Void)?
    /// Called on the main thread with the rotation the other end's frames ask
    /// for, in quarter turns, when it changes.
    var onRemoteRotation: (@MainActor (Int) -> Void)?

    private let lock = NSLock()
    private let captureQueue = DispatchQueue(label: "app.void.video.capture")
    private let decodeQueue = DispatchQueue(label: "app.void.video.decode")
    private var session: AVCaptureSession?
    private var synthetic: SyntheticCamera?
    private var encoder: H264Encoder?
    private let receiver = H264Receiver()
    private var cameraOn = true
    private var front = true
    private var forceKeyframe = true
    private var lastCapture: CMTime = .invalid
    private var remote = RemoteVideoState()
    private var remoteRotation = 0
    private let started = DispatchTime.now()
    private var counts = VideoStats()

    /// Frames the camera produced that went to the encoder; units sent and
    /// dropped; units received and shown.
    struct VideoStats: Equatable {
        var encoded = 0
        var sent = 0
        var dropped = 0
        var received = 0
        var shown = 0
    }

    var stats: VideoStats { lock.withLock { counts } }

    /// The camera frame rate the lane is sized for.
    static let framesPerSecond: Int32 = 15
    /// The encoded picture, portrait.
    static let width: Int32 = 360
    static let height: Int32 = 480

    init(media: CallMedia) {
        self.media = media
        #if targetEnvironment(simulator)
            localView = SampleBufferView()
        #else
            localView = PreviewView()
        #endif
        super.init()
        remoteLayer.videoGravity = .resizeAspectFill
        remoteLayer.backgroundColor = UIColor.black.cgColor
    }

    /// Ask for the camera, once, when the user chooses a video call — never at
    /// launch. A refusal means the call goes ahead with the camera off.
    @MainActor
    static func requestCamera(_ completion: @escaping @MainActor (Bool) -> Void) {
        #if targetEnvironment(simulator)
            completion(true)
        #else
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .authorized: completion(true)
            case .notDetermined:
                AVCaptureDevice.requestAccess(for: .video) { granted in
                    Task { @MainActor in completion(granted) }
                }
            default: completion(false)
            }
        #endif
    }

    /// Start the encoder and, if `cameraAllowed`, the camera.
    func start(cameraAllowed: Bool) {
        do {
            let encoder = try H264Encoder(width: Self.width, height: Self.height)
            encoder.onUnit = { [weak self] data, keyframe in self?.sendUnit(data, keyframe: keyframe) }
            lock.withLock { self.encoder = encoder }
        } catch {
            lock.withLock { cameraOn = false }
        }
        setCamera(on: cameraAllowed && lock.withLock { self.encoder != nil })
    }

    /// Stop everything. Safe to call twice.
    func stop() {
        let (session, synthetic, encoder) = lock.withLock { () -> (AVCaptureSession?, SyntheticCamera?, H264Encoder?) in
            defer {
                self.session = nil
                self.synthetic = nil
                self.encoder = nil
            }
            return (self.session, self.synthetic, self.encoder)
        }
        synthetic?.stop()
        captureQueue.async {
            session?.stopRunning()
            encoder?.invalidate()
        }
        decodeQueue.async { [remoteLayer] in remoteLayer.flushAndRemoveImage() }
    }

    // MARK: The camera

    var isCameraOn: Bool { lock.withLock { cameraOn } }
    var isFrontCamera: Bool { lock.withLock { front } }

    /// Turn the camera on or off. Off, nothing is captured and the other end is
    /// told so; the frames on the wire are the same size either way.
    func setCamera(on: Bool) {
        lock.withLock {
            cameraOn = on
            if on { forceKeyframe = true }
        }
        media.setCamera(on: on)
        if on {
            startCapture()
        } else {
            stopCapture()
        }
    }

    /// Switch between the front and back cameras.
    func flipCamera() {
        lock.withLock {
            front.toggle()
            forceKeyframe = true
        }
        guard isCameraOn else { return }
        stopCapture()
        startCapture()
    }

    private func startCapture() {
        #if targetEnvironment(simulator)
            let camera = SyntheticCamera(width: Int(Self.width), height: Int(Self.height))
            lock.withLock { synthetic = camera }
            let preview = localView as? SampleBufferView
            camera.start(framesPerSecond: Int(Self.framesPerSecond)) { [weak self] pixels, time in
                preview?.show(pixels)
                self?.encode(pixels, at: time)
            }
        #else
            let useFront = isFrontCamera
            captureQueue.async { [weak self] in
                guard let self, let session = self.makeSession(front: useFront) else { return }
                session.startRunning()
                self.lock.withLock { self.session = session }
                DispatchQueue.main.async {
                    (self.localView as? PreviewView)?.previewLayer.session = session
                }
            }
        #endif
    }

    private func stopCapture() {
        let (session, synthetic) = lock.withLock { () -> (AVCaptureSession?, SyntheticCamera?) in
            defer {
                self.session = nil
                self.synthetic = nil
            }
            return (self.session, self.synthetic)
        }
        synthetic?.stop()
        captureQueue.async { session?.stopRunning() }
    }

    private func makeSession(front: Bool) -> AVCaptureSession? {
        let position: AVCaptureDevice.Position = front ? .front : .back
        guard
            let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: position),
            let input = try? AVCaptureDeviceInput(device: device)
        else { return nil }
        let session = AVCaptureSession()
        session.beginConfiguration()
        if session.canSetSessionPreset(.vga640x480) {
            session.sessionPreset = .vga640x480
        }
        guard session.canAddInput(input) else { return nil }
        session.addInput(input)
        let output = AVCaptureVideoDataOutput()
        output.videoSettings = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange
        ]
        output.alwaysDiscardsLateVideoFrames = true
        output.setSampleBufferDelegate(self, queue: captureQueue)
        guard session.canAddOutput(output) else { return nil }
        session.addOutput(output)
        if let connection = output.connection(with: .video) {
            // Upright and unmirrored: the other person sees what anyone
            // standing opposite would. Only the local preview is a mirror.
            if #available(iOS 17.0, *) {
                if connection.isVideoRotationAngleSupported(90) {
                    connection.videoRotationAngle = 90
                }
            } else if connection.isVideoOrientationSupported {
                connection.videoOrientation = .portrait
            }
            if connection.isVideoMirroringSupported {
                connection.automaticallyAdjustsVideoMirroring = false
                connection.isVideoMirrored = false
            }
        }
        session.commitConfiguration()
        return session
    }

    // MARK: Sending

    /// Encode one captured frame, at most `framesPerSecond` of them a second.
    fileprivate func encode(_ pixels: CVPixelBuffer, at time: CMTime) {
        let (active, keyframe) = lock.withLock { () -> (H264Encoder?, Bool) in
            guard cameraOn, let current = self.encoder else { return (nil, false) }
            if lastCapture.isValid,
                CMTimeGetSeconds(CMTimeSubtract(time, lastCapture)) < 0.9 / Double(Self.framesPerSecond)
            {
                return (nil, false)
            }
            lastCapture = time
            let force = forceKeyframe
            forceKeyframe = false
            counts.encoded += 1
            return (current, force)
        }
        guard let active else { return }
        active.encode(pixels, at: time, keyframe: keyframe || media.videoNeedsKeyframe)
    }

    private func sendUnit(_ data: Data, keyframe: Bool) {
        let elapsed = (DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000
        let sent = media.pushVideo(
            VideoUnit(data: data, keyframe: keyframe, rotation: 0, timestampMs: UInt32(truncatingIfNeeded: elapsed)))
        lock.withLock {
            if sent {
                counts.sent += 1
            } else {
                counts.dropped += 1
                // The other end is missing a frame its successors refer to.
                forceKeyframe = true
            }
        }
    }

    // MARK: Receiving

    /// Take every frame that arrived with the last receive and show them. Runs
    /// on `CallAudio`'s receiving thread, so it must never block.
    func drainRemote() {
        var units: [VideoUnit] = []
        while let unit = media.takeVideo() {
            units.append(unit)
        }
        let cameraOff = media.peerCameraOff
        lock.withLock { counts.received += units.count }
        if !units.isEmpty {
            decodeQueue.async { [weak self] in self?.show(units) }
        }
        updateRemote { $0.cameraOff = cameraOff }
    }

    private func show(_ units: [VideoUnit]) {
        for unit in units {
            guard let sample = receiver.sampleBuffer(for: unit) else { continue }
            if remoteLayer.status == .failed {
                remoteLayer.flush()
            }
            remoteLayer.enqueue(sample)
            lock.withLock { counts.shown += 1 }
            updateRemote { $0.started = true }
            let rotation = unit.rotation
            let changed = lock.withLock { () -> Bool in
                defer { remoteRotation = rotation }
                return remoteRotation != rotation
            }
            if changed, let callback = onRemoteRotation {
                Task { @MainActor in callback(rotation) }
            }
        }
    }

    private func updateRemote(_ change: (inout RemoteVideoState) -> Void) {
        let (changed, state) = lock.withLock { () -> (Bool, RemoteVideoState) in
            var next = remote
            change(&next)
            defer { remote = next }
            return (next != remote, next)
        }
        if changed, let callback = onRemoteState {
            Task { @MainActor in callback(state) }
        }
    }
}

extension CallVideo: AVCaptureVideoDataOutputSampleBufferDelegate {
    func captureOutput(
        _ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection
    ) {
        guard let pixels = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        encode(pixels, at: CMSampleBufferGetPresentationTimeStamp(sampleBuffer))
    }
}

// MARK: - H.264, out

/// A real-time H.264 encoder producing Annex B access units.
final class H264Encoder: @unchecked Sendable {
    private var session: VTCompressionSession?
    /// Called with each encoded frame, Annex B, parameter sets in front of
    /// every keyframe.
    var onUnit: ((Data, Bool) -> Void)?

    init(width: Int32, height: Int32) throws {
        var created: VTCompressionSession?
        let status = VTCompressionSessionCreate(
            allocator: kCFAllocatorDefault, width: width, height: height,
            codecType: kCMVideoCodecType_H264, encoderSpecification: nil,
            imageBufferAttributes: nil, compressedDataAllocator: nil,
            outputCallback: nil, refcon: nil, compressionSessionOut: &created)
        guard status == noErr, let session = created else { throw VoidError.failed }
        let set = { (key: CFString, value: CFTypeRef) in
            _ = VTSessionSetProperty(session, key: key, value: value)
        }
        set(kVTCompressionPropertyKey_RealTime, kCFBooleanTrue)
        set(kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_Baseline_AutoLevel)
        set(kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse)
        // About two thirds of the lane on average, four fifths at most: a
        // keyframe still drains in well under a second.
        set(kVTCompressionPropertyKey_AverageBitRate, 150_000 as CFNumber)
        set(kVTCompressionPropertyKey_DataRateLimits, [22_000, 1] as CFArray)
        set(kVTCompressionPropertyKey_ExpectedFrameRate, CallVideo.framesPerSecond as CFNumber)
        set(kVTCompressionPropertyKey_MaxKeyFrameInterval, 60 as CFNumber)
        set(kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration, 4 as CFNumber)
        VTCompressionSessionPrepareToEncodeFrames(session)
        self.session = session
    }

    func encode(_ pixels: CVPixelBuffer, at time: CMTime, keyframe: Bool) {
        guard let session else { return }
        let properties: CFDictionary? =
            keyframe ? [kVTEncodeFrameOptionKey_ForceKeyFrame: kCFBooleanTrue] as CFDictionary : nil
        VTCompressionSessionEncodeFrame(
            session, imageBuffer: pixels, presentationTimeStamp: time, duration: .invalid,
            frameProperties: properties, infoFlagsOut: nil
        ) { [weak self] status, _, sample in
            guard status == noErr, let sample, let unit = H264Encoder.annexB(from: sample) else { return }
            self?.onUnit?(unit.data, unit.keyframe)
        }
    }

    func invalidate() {
        if let session {
            VTCompressionSessionCompleteFrames(session, untilPresentationTimeStamp: .invalid)
            VTCompressionSessionInvalidate(session)
        }
        session = nil
    }

    deinit {
        invalidate()
    }

    private static let startCode: [UInt8] = [0, 0, 0, 1]

    /// VideoToolbox's length-prefixed NAL units as Annex B, with the SPS and
    /// PPS in front of a keyframe so a decoder can start from any keyframe.
    static func annexB(from sample: CMSampleBuffer) -> (data: Data, keyframe: Bool)? {
        guard let block = CMSampleBufferGetDataBuffer(sample) else { return nil }
        var keyframe = true
        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: false)
            as? [[CFString: Any]], let first = attachments.first,
            let notSync = first[kCMSampleAttachmentKey_NotSync] as? Bool
        {
            keyframe = !notSync
        }
        var out = Data()
        var headerLength: Int32 = 4
        if let format = CMSampleBufferGetFormatDescription(sample) {
            var count = 0
            CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                format, parameterSetIndex: 0, parameterSetPointerOut: nil, parameterSetSizeOut: nil,
                parameterSetCountOut: &count, nalUnitHeaderLengthOut: &headerLength)
            if keyframe {
                for index in 0..<count {
                    var pointer: UnsafePointer<UInt8>?
                    var size = 0
                    let status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                        format, parameterSetIndex: index, parameterSetPointerOut: &pointer,
                        parameterSetSizeOut: &size, parameterSetCountOut: nil, nalUnitHeaderLengthOut: nil)
                    guard status == noErr, let pointer else { continue }
                    out.append(contentsOf: startCode)
                    out.append(pointer, count: size)
                }
            }
        }
        let length = CMBlockBufferGetDataLength(block)
        var bytes = [UInt8](repeating: 0, count: length)
        guard CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: length, destination: &bytes) == noErr
        else { return nil }
        let prefix = Int(headerLength)
        var offset = 0
        while offset + prefix <= length {
            var nalLength = 0
            for i in 0..<prefix {
                nalLength = nalLength << 8 | Int(bytes[offset + i])
            }
            offset += prefix
            guard nalLength > 0, offset + nalLength <= length else { break }
            out.append(contentsOf: startCode)
            out.append(contentsOf: bytes[offset..<offset + nalLength])
            offset += nalLength
        }
        return out.isEmpty ? nil : (out, keyframe)
    }
}

// MARK: - H.264, in

/// Turns Annex B units into sample buffers a display layer can show.
final class H264Receiver: @unchecked Sendable {
    private var format: CMVideoFormatDescription?
    private var sps = Data()
    private var pps = Data()

    /// Split an Annex B stream at its start codes.
    static func nalUnits(_ data: Data) -> [Data] {
        let bytes = [UInt8](data)
        var units: [Data] = []
        var start: Int?
        var i = 0
        while i + 3 <= bytes.count {
            let three = bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1
            let four = i + 4 <= bytes.count && bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 0
                && bytes[i + 3] == 1
            if three || four {
                if let s = start, s < i {
                    units.append(Data(bytes[s..<i]))
                }
                i += four ? 4 : 3
                start = i
            } else {
                i += 1
            }
        }
        if let s = start, s < bytes.count {
            units.append(Data(bytes[s..<bytes.count]))
        }
        return units
    }

    func sampleBuffer(for unit: VideoUnit) -> CMSampleBuffer? {
        var slices: [Data] = []
        var newSPS: Data?
        var newPPS: Data?
        for nal in Self.nalUnits(unit.data) {
            guard let header = nal.first else { continue }
            switch header & 0x1F {
            case 7: newSPS = nal
            case 8: newPPS = nal
            case 1, 5: slices.append(nal)
            default: continue  // SEI, delimiters: nothing a display needs.
            }
        }
        if let newSPS, let newPPS, newSPS != sps || newPPS != pps || format == nil {
            sps = newSPS
            pps = newPPS
            format = Self.makeFormat(sps: newSPS, pps: newPPS)
        }
        guard let format, !slices.isEmpty else { return nil }

        var avcc = Data()
        for nal in slices {
            var length = UInt32(nal.count).bigEndian
            withUnsafeBytes(of: &length) { avcc.append(contentsOf: $0) }
            avcc.append(nal)
        }
        var block: CMBlockBuffer?
        guard
            CMBlockBufferCreateWithMemoryBlock(
                allocator: kCFAllocatorDefault, memoryBlock: nil, blockLength: avcc.count,
                blockAllocator: kCFAllocatorDefault, customBlockSource: nil, offsetToData: 0,
                dataLength: avcc.count, flags: 0, blockBufferOut: &block) == noErr,
            let block
        else { return nil }
        let copied = avcc.withUnsafeBytes { raw -> OSStatus in
            guard let base = raw.baseAddress else { return -1 }
            return CMBlockBufferReplaceDataBytes(
                with: base, blockBuffer: block, offsetIntoDestination: 0, dataLength: avcc.count)
        }
        guard copied == noErr else { return nil }
        var sample: CMSampleBuffer?
        var size = avcc.count
        guard
            CMSampleBufferCreateReady(
                allocator: kCFAllocatorDefault, dataBuffer: block, formatDescription: format,
                sampleCount: 1, sampleTimingEntryCount: 0, sampleTimingArray: nil,
                sampleSizeEntryCount: 1, sampleSizeArray: &size, sampleBufferOut: &sample) == noErr,
            let sample
        else { return nil }
        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: true),
            CFArrayGetCount(attachments) > 0
        {
            let dictionary = unsafeBitCast(CFArrayGetValueAtIndex(attachments, 0), to: CFMutableDictionary.self)
            CFDictionarySetValue(
                dictionary,
                Unmanaged.passUnretained(kCMSampleAttachmentKey_DisplayImmediately).toOpaque(),
                Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
        }
        return sample
    }

    private static func makeFormat(sps: Data, pps: Data) -> CMVideoFormatDescription? {
        var format: CMVideoFormatDescription?
        let status = sps.withUnsafeBytes { spsRaw -> OSStatus in
            pps.withUnsafeBytes { ppsRaw -> OSStatus in
                guard let spsBase = spsRaw.bindMemory(to: UInt8.self).baseAddress,
                    let ppsBase = ppsRaw.bindMemory(to: UInt8.self).baseAddress
                else { return -1 }
                let pointers: [UnsafePointer<UInt8>] = [spsBase, ppsBase]
                let sizes = [sps.count, pps.count]
                return CMVideoFormatDescriptionCreateFromH264ParameterSets(
                    allocator: kCFAllocatorDefault, parameterSetCount: 2,
                    parameterSetPointers: pointers, parameterSetSizes: sizes,
                    nalUnitHeaderLength: 4, formatDescriptionOut: &format)
            }
        }
        return status == noErr ? format : nil
    }
}

// MARK: - The Simulator's camera

/// A moving test pattern, for the Simulator, which has no camera.
final class SyntheticCamera: @unchecked Sendable {
    private let width: Int
    private let height: Int
    private let queue = DispatchQueue(label: "app.void.video.synthetic")
    private var timer: DispatchSourceTimer?
    private var frame = 0

    init(width: Int, height: Int) {
        self.width = width
        self.height = height
    }

    func start(framesPerSecond: Int, handler: @escaping (CVPixelBuffer, CMTime) -> Void) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(1000 / framesPerSecond))
        timer.setEventHandler { [weak self] in
            guard let self, let pixels = self.render() else { return }
            self.frame += 1
            handler(pixels, CMTime(value: CMTimeValue(self.frame), timescale: CMTimeScale(framesPerSecond)))
        }
        self.timer = timer
        timer.resume()
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    private func render() -> CVPixelBuffer? {
        var pixels: CVPixelBuffer?
        let attributes = [kCVPixelBufferIOSurfacePropertiesKey: [:]] as CFDictionary
        guard
            CVPixelBufferCreate(
                kCFAllocatorDefault, width, height, kCVPixelFormatType_32BGRA, attributes, &pixels)
                == kCVReturnSuccess, let pixels
        else { return nil }
        CVPixelBufferLockBaseAddress(pixels, [])
        defer { CVPixelBufferUnlockBaseAddress(pixels, []) }
        guard
            let context = CGContext(
                data: CVPixelBufferGetBaseAddress(pixels), width: width, height: height,
                bitsPerComponent: 8, bytesPerRow: CVPixelBufferGetBytesPerRow(pixels),
                space: CGColorSpaceCreateDeviceRGB(),
                bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue
                    | CGBitmapInfo.byteOrder32Little.rawValue)
        else { return nil }
        let t = Double(frame) / Double(CallVideo.framesPerSecond)
        let hue = CGFloat((t * 0.04).truncatingRemainder(dividingBy: 1))
        let top = UIColor(hue: hue, saturation: 0.65, brightness: 0.55, alpha: 1).cgColor
        let bottom = UIColor(hue: (hue + 0.18).truncatingRemainder(dividingBy: 1), saturation: 0.8,
            brightness: 0.25, alpha: 1).cgColor
        if let gradient = CGGradient(
            colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: [top, bottom] as CFArray, locations: [0, 1])
        {
            context.drawLinearGradient(
                gradient, start: CGPoint(x: 0, y: height), end: CGPoint(x: width, y: 0), options: [])
        }
        // A disc that moves, so motion — and a frozen picture — is obvious.
        let r = CGFloat(width) * 0.16
        let x = CGFloat(width) / 2 + CGFloat(sin(t * 1.3)) * CGFloat(width) * 0.28
        let y = CGFloat(height) / 2 + CGFloat(cos(t * 0.9)) * CGFloat(height) * 0.22
        context.setFillColor(UIColor(white: 1, alpha: 0.85).cgColor)
        context.fillEllipse(in: CGRect(x: x - r, y: y - r, width: 2 * r, height: 2 * r))

        UIGraphicsPushContext(context)
        context.saveGState()
        context.translateBy(x: 0, y: CGFloat(height))
        context.scaleBy(x: 1, y: -1)
        let clock = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let label = "Simulator camera\n\(clock)" as NSString
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .center
        label.draw(
            in: CGRect(x: 0, y: CGFloat(height) - 70, width: CGFloat(width), height: 60),
            withAttributes: [
                .font: UIFont.monospacedDigitSystemFont(ofSize: 18, weight: .semibold),
                .foregroundColor: UIColor.white,
                .paragraphStyle: paragraph,
            ])
        context.restoreGState()
        UIGraphicsPopContext()
        return pixels
    }
}

// MARK: - Views that host the layers

/// Shows the camera's own preview, mirrored as a mirror is.
final class PreviewView: UIView {
    override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
    var previewLayer: AVCaptureVideoPreviewLayer {
        // The layer class above guarantees the type.
        layer as! AVCaptureVideoPreviewLayer  // swiftlint:disable:this force_cast
    }

    override init(frame: CGRect) {
        super.init(frame: frame)
        previewLayer.videoGravity = .resizeAspectFill
        backgroundColor = .black
    }

    required init?(coder: NSCoder) { nil }
}

/// Shows raw frames — the Simulator's test pattern — as a local preview.
final class SampleBufferView: UIView {
    private let display = AVSampleBufferDisplayLayer()
    private var format: CMVideoFormatDescription?

    override init(frame: CGRect) {
        super.init(frame: frame)
        display.videoGravity = .resizeAspectFill
        layer.addSublayer(display)
        backgroundColor = .black
    }

    required init?(coder: NSCoder) { nil }

    override func layoutSubviews() {
        super.layoutSubviews()
        display.frame = bounds
    }

    func show(_ pixels: CVPixelBuffer) {
        if format == nil {
            CMVideoFormatDescriptionCreateForImageBuffer(
                allocator: kCFAllocatorDefault, imageBuffer: pixels, formatDescriptionOut: &format)
        }
        guard let format else { return }
        var timing = CMSampleTimingInfo(
            duration: .invalid, presentationTimeStamp: .zero, decodeTimeStamp: .invalid)
        var sample: CMSampleBuffer?
        CMSampleBufferCreateReadyWithImageBuffer(
            allocator: kCFAllocatorDefault, imageBuffer: pixels, formatDescription: format,
            sampleTiming: &timing, sampleBufferOut: &sample)
        guard let sample else { return }
        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: true),
            CFArrayGetCount(attachments) > 0
        {
            let dictionary = unsafeBitCast(CFArrayGetValueAtIndex(attachments, 0), to: CFMutableDictionary.self)
            CFDictionarySetValue(
                dictionary,
                Unmanaged.passUnretained(kCMSampleAttachmentKey_DisplayImmediately).toOpaque(),
                Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
        }
        display.enqueue(sample)
    }
}

/// Shows the other end's picture, turned upright.
final class RemoteVideoUIView: UIView {
    let display: AVSampleBufferDisplayLayer
    var quarterTurns = 0 {
        didSet { setNeedsLayout() }
    }

    init(layer display: AVSampleBufferDisplayLayer) {
        self.display = display
        super.init(frame: .zero)
        layer.addSublayer(display)
        backgroundColor = .black
        clipsToBounds = true
    }

    required init?(coder: NSCoder) { nil }

    override func layoutSubviews() {
        super.layoutSubviews()
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        let sideways = quarterTurns % 2 == 1
        display.bounds = CGRect(
            x: 0, y: 0, width: sideways ? bounds.height : bounds.width,
            height: sideways ? bounds.width : bounds.height)
        display.position = CGPoint(x: bounds.midX, y: bounds.midY)
        display.setAffineTransform(CGAffineTransform(rotationAngle: CGFloat(quarterTurns) * .pi / 2))
        CATransaction.commit()
    }
}
