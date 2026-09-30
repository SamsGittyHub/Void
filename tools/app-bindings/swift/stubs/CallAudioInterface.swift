// The surface of ios/Void/CallAudio.swift that AppState.swift uses, so that
// AppState can be type-checked on Linux without AVFoundation. Keep in step
// with that file; scripts/check_ios_bindings.sh type-checks CallAudio.swift
// itself separately, against stubs/AVFoundation.swift.
final class CallAudio: @unchecked Sendable {
    init(media: CallMedia) throws {}
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
