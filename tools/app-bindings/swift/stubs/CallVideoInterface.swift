// The surface of ios/Void/CallVideo.swift that AppState.swift uses, so that
// AppState can be type-checked on Linux without AVFoundation, VideoToolbox or
// UIKit. Keep in step with that file. CallVideo.swift itself needs Apple's
// SDKs and is only built by CI's macOS job.
struct RemoteVideoState: Equatable {
    var started = false
    var cameraOff = false
}

final class CallVideo: @unchecked Sendable {
    struct VideoStats: Equatable {
        var encoded = 0
        var sent = 0
        var dropped = 0
        var received = 0
        var shown = 0
    }

    init(media: CallMedia) {}
    var onRemoteState: (@MainActor (RemoteVideoState) -> Void)?
    var onRemoteRotation: (@MainActor (Int) -> Void)?
    var stats: VideoStats { VideoStats() }
    var isCameraOn: Bool { false }
    var isFrontCamera: Bool { true }
    func start(cameraAllowed: Bool) {}
    func stop() {}
    func setCamera(on: Bool) {}
    func flipCamera() {}
    func drainRemote() {}
    @MainActor static func requestCamera(_ completion: @escaping @MainActor (Bool) -> Void) {}
}
