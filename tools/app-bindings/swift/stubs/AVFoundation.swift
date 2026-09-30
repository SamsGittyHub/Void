// Linux stand-in for the AVFoundation/AudioToolbox members CallAudio.swift
// uses, transcribed from the iOS SDK's Swift interface. Type-checking only.
@_exported import Foundation

public typealias AVAudioFrameCount = UInt32
public typealias AVAudioPacketCount = UInt32
public typealias AVAudioChannelCount = UInt32
public typealias AVAudioNodeBus = Int
public typealias AudioFormatID = UInt32
public typealias AudioFormatFlags = UInt32
// On Apple platforms this is an AutoreleasingUnsafeMutablePointer; call sites
// pass `&error` either way.
public typealias NSErrorPointer = UnsafeMutablePointer<NSError?>?

public let kAudioFormatOpus: AudioFormatID = 0x6F70_7573
public let AVAudioBitRateStrategy_Constant: String = "AVAudioBitRateStrategy_Constant"
public let AVAudioSessionInterruptionTypeKey: String = "AVAudioSessionInterruptionTypeKey"

public struct AudioStreamBasicDescription {
    public var mSampleRate: Double
    public var mFormatID: AudioFormatID
    public var mFormatFlags: AudioFormatFlags
    public var mBytesPerPacket: UInt32
    public var mFramesPerPacket: UInt32
    public var mBytesPerFrame: UInt32
    public var mChannelsPerFrame: UInt32
    public var mBitsPerChannel: UInt32
    public var mReserved: UInt32
    public init(
        mSampleRate: Double, mFormatID: AudioFormatID, mFormatFlags: AudioFormatFlags,
        mBytesPerPacket: UInt32, mFramesPerPacket: UInt32, mBytesPerFrame: UInt32,
        mChannelsPerFrame: UInt32, mBitsPerChannel: UInt32, mReserved: UInt32
    ) {
        self.mSampleRate = mSampleRate
        self.mFormatID = mFormatID
        self.mFormatFlags = mFormatFlags
        self.mBytesPerPacket = mBytesPerPacket
        self.mFramesPerPacket = mFramesPerPacket
        self.mBytesPerFrame = mBytesPerFrame
        self.mChannelsPerFrame = mChannelsPerFrame
        self.mBitsPerChannel = mBitsPerChannel
        self.mReserved = mReserved
    }
}

public struct AudioStreamPacketDescription {
    public var mStartOffset: Int64
    public var mVariableFramesInPacket: UInt32
    public var mDataByteSize: UInt32
    public init(mStartOffset: Int64, mVariableFramesInPacket: UInt32, mDataByteSize: UInt32) {
        self.mStartOffset = mStartOffset
        self.mVariableFramesInPacket = mVariableFramesInPacket
        self.mDataByteSize = mDataByteSize
    }
}

public enum AVAudioCommonFormat: UInt {
    case otherFormat = 0, pcmFormatFloat32 = 1, pcmFormatFloat64 = 2, pcmFormatInt16 = 3, pcmFormatInt32 = 4
}

open class AVAudioFormat: NSObject {
    public init?(commonFormat format: AVAudioCommonFormat, sampleRate: Double, channels: AVAudioChannelCount, interleaved: Bool) { nil }
    public init?(streamDescription asbd: UnsafePointer<AudioStreamBasicDescription>) { nil }
    open var sampleRate: Double { 0 }
    open var channelCount: AVAudioChannelCount { 0 }
}

open class AVAudioBuffer: NSObject {
    open var format: AVAudioFormat { fatalError() }
}

open class AVAudioPCMBuffer: AVAudioBuffer {
    public init?(pcmFormat format: AVAudioFormat, frameCapacity: AVAudioFrameCount) { nil }
    open var frameLength: AVAudioFrameCount = 0
    open var floatChannelData: UnsafePointer<UnsafeMutablePointer<Float>>? { nil }
}

open class AVAudioCompressedBuffer: AVAudioBuffer {
    public init(format: AVAudioFormat, packetCapacity: AVAudioPacketCount, maximumPacketSize: Int) {}
    open var data: UnsafeMutableRawPointer { fatalError() }
    open var byteLength: UInt32 = 0
    open var packetCount: AVAudioPacketCount = 0
    open var packetDescriptions: UnsafeMutablePointer<AudioStreamPacketDescription>? { nil }
}

public enum AVAudioConverterInputStatus: Int { case haveData = 0, noDataNow = 1, endOfStream = 2 }
public enum AVAudioConverterOutputStatus: Int { case haveData = 0, inputRanDry = 1, endOfStream = 2, error = 3 }
public typealias AVAudioConverterInputBlock = (AVAudioPacketCount, UnsafeMutablePointer<AVAudioConverterInputStatus>) -> AVAudioBuffer?

open class AVAudioConverter: NSObject {
    public init?(from fromFormat: AVAudioFormat, to toFormat: AVAudioFormat) { nil }
    open var bitRate: Int = 0
    open var bitRateStrategy: String?
    open var maximumOutputPacketSize: Int { 0 }
    open func convert(to outputBuffer: AVAudioBuffer, error outError: NSErrorPointer, withInputFrom inputBlock: AVAudioConverterInputBlock) -> AVAudioConverterOutputStatus { .error }
}

open class AVAudioTime: NSObject {}
public typealias AVAudioNodeTapBlock = (AVAudioPCMBuffer, AVAudioTime) -> Void
public typealias AVAudioNodeCompletionHandler = () -> Void

open class AVAudioNode: NSObject {
    open func installTap(onBus bus: AVAudioNodeBus, bufferSize: AVAudioFrameCount, format: AVAudioFormat?, block tapBlock: @escaping AVAudioNodeTapBlock) {}
    open func removeTap(onBus bus: AVAudioNodeBus) {}
    open func outputFormat(forBus bus: AVAudioNodeBus) -> AVAudioFormat { fatalError() }
}
open class AVAudioIONode: AVAudioNode {
    open func setVoiceProcessingEnabled(_ enabled: Bool) throws {}
}
open class AVAudioInputNode: AVAudioIONode {}
open class AVAudioMixerNode: AVAudioNode {}
open class AVAudioPlayerNode: AVAudioNode {
    public override init() {}
    open func play() {}
    open func stop() {}
    open func scheduleBuffer(_ buffer: AVAudioPCMBuffer, completionHandler: AVAudioNodeCompletionHandler? = nil) {}
}

open class AVAudioEngine: NSObject {
    public override init() {}
    open var inputNode: AVAudioInputNode { fatalError() }
    open var mainMixerNode: AVAudioMixerNode { fatalError() }
    open func attach(_ node: AVAudioNode) {}
    open func connect(_ node1: AVAudioNode, to node2: AVAudioNode, format: AVAudioFormat?) {}
    open func prepare() {}
    open func start() throws {}
    open func stop() {}
}

open class AVAudioSession: NSObject {
    public struct Category: Hashable { public static let playAndRecord = Category() }
    public struct Mode: Hashable { public static let voiceChat = Mode() }
    public struct CategoryOptions: OptionSet {
        public let rawValue: UInt
        public init(rawValue: UInt) { self.rawValue = rawValue }
        public static let allowBluetooth = CategoryOptions(rawValue: 4)
    }
    public struct SetActiveOptions: OptionSet {
        public let rawValue: UInt
        public init(rawValue: UInt) { self.rawValue = rawValue }
        public static let notifyOthersOnDeactivation = SetActiveOptions(rawValue: 1)
    }
    public enum RecordPermission: UInt { case undetermined = 1970168948, denied = 1684369017, granted = 1735552628 }
    public enum InterruptionType: UInt { case began = 1, ended = 0 }
    public static let interruptionNotification = Notification.Name("AVAudioSessionInterruptionNotification")

    open class func sharedInstance() -> AVAudioSession { fatalError() }
    open func setCategory(_ category: Category, mode: Mode, options: CategoryOptions = []) throws {}
    open func setActive(_ active: Bool, options: SetActiveOptions = []) throws {}
    open var recordPermission: RecordPermission { .undetermined }
    open func requestRecordPermission(_ response: @escaping (Bool) -> Void) {}
}
