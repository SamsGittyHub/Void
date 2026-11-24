// The surface of ios/Void/CallAudio.swift that AppState.swift uses, so that
// AppState can be type-checked on Linux without AVFoundation. Keep in step
// with that file; scripts/check_ios_bindings.sh type-checks CallAudio.swift
// itself separately, against stubs/AVFoundation.swift.
struct CallStats: Equatable {
    var sentAudio = 0
    var sentSilence = 0
    var receivedAudio = 0
    var receivedSilence = 0
    var played = 0
    var echoCancellation = false
}

final class CallAudio: @unchecked Sendable {
    init(media: CallMedia) throws {}
    var currentStats: CallStats { CallStats() }
    var afterReceive: (@Sendable () -> Void)?
    var onConnected: (@Sendable () -> Void)?
    var onDropped: (@Sendable (_ connectionClosed: Bool) -> Void)?
    var isMuted: Bool {
        get { false }
        set {}
    }
    func start() throws {}
    func stop() {}
    @MainActor static func requestMicrophone(_ completion: @escaping @MainActor (Bool) -> Void) {}
}
