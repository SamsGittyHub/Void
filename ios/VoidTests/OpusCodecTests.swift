//  OpusCodecTests.swift
//
//  Runs the call's codec path — Apple's Opus encoder and decoder through
//  `AVAudioConverter`, at 16 kHz mono in 20 ms packets at a constant 16 kbit/s
//  — on the Simulator, in CI. No call has been placed between two iPhones
//  (D-024, D-031), so until one is, this is the only check that the one piece
//  of the iOS call path that is Apple's and not Void's behaves as the audio
//  loop assumes: that a frame of PCM comes out as one packet that fits a
//  media frame, and that the packet decodes back to audio.

import AVFoundation
import XCTest

@testable import Void

final class OpusCodecTests: XCTestCase {
    /// One second of a 440 Hz tone at half scale, in 20 ms frames.
    private func toneFrames(_ codec: OpusCodec, seconds: Int = 1) -> [[Float]] {
        let rate = codec.pcmFormat.sampleRate
        let perFrame = codec.samplesPerFrame
        let count = Int(rate) * seconds / perFrame
        return (0..<count).map { frame in
            (0..<perFrame).map { i in
                let t = Double(frame * perFrame + i) / rate
                return Float(0.5 * sin(2 * .pi * 440 * t))
            }
        }
    }

    func testTheCodecExistsAtTheCallsConfiguration() throws {
        let codec = try OpusCodec()
        XCTAssertEqual(codec.samplesPerFrame, 320, "16 kHz at 20 ms")
        XCTAssertEqual(codec.pcmFormat.sampleRate, 16_000)
        XCTAssertEqual(codec.pcmFormat.channelCount, 1)
    }

    func testAFrameEncodesToOnePacketThatFitsAMediaFrame() throws {
        let codec = try OpusCodec()
        let frames = toneFrames(codec)
        var packets = 0
        var largest = 0
        for frame in frames {
            if let packet = codec.encode(frame) {
                packets += 1
                largest = max(largest, packet.count)
                XCTAssertLessThanOrEqual(
                    packet.count, VoidCore.maxPayloadLength,
                    "a packet must fit the \(VoidCore.maxPayloadLength)-byte media payload")
                XCTAssertGreaterThan(packet.count, 0)
            }
        }
        // The encoder may hold the first frame or two for lookahead; after
        // that every frame must come out as a packet, or the call is silent.
        XCTAssertGreaterThanOrEqual(packets, frames.count - 2, "\(packets) packets from \(frames.count) frames")
        // Constant 16 kbit/s at 20 ms is 40 bytes; allow the codec its
        // framing, but it must not be anywhere near variable-rate sizes.
        XCTAssertLessThanOrEqual(largest, 80, "largest packet \(largest) bytes at a constant 16 kbit/s")
    }

    func testPacketsDecodeBackToAudio() throws {
        let codec = try OpusCodec()
        var energy: Float = 0
        var decodedFrames = 0
        var samples = 0
        for (index, frame) in toneFrames(codec).enumerated() {
            guard let packet = codec.encode(frame) else { continue }
            guard let pcm = codec.decode(packet) else {
                XCTFail("packet \(index) did not decode")
                continue
            }
            decodedFrames += 1
            XCTAssertEqual(pcm.format.sampleRate, codec.pcmFormat.sampleRate)
            // Opus has a pre-skip: the encoder's lookahead, which the decoder
            // trims from the start of the stream. Apple's decoder applies it
            // to the first packet (observed in CI: 280 samples out of 320),
            // so the first packets may come up short; after that one packet
            // is exactly one frame, or the player's cadence would drift.
            XCTAssertGreaterThan(pcm.frameLength, 0)
            XCTAssertLessThanOrEqual(Int(pcm.frameLength), codec.samplesPerFrame)
            if index >= 5 {
                XCTAssertEqual(Int(pcm.frameLength), codec.samplesPerFrame, "one packet is one frame")
            }
            // Skip the first frames: the decoder's pre-skip is silence.
            if index >= 5, let channel = pcm.floatChannelData?[0] {
                for i in 0..<Int(pcm.frameLength) {
                    energy += channel[i] * channel[i]
                }
                samples += Int(pcm.frameLength)
            }
        }
        XCTAssertGreaterThan(decodedFrames, 40)
        let rms = (energy / Float(max(samples, 1))).squareRoot()
        // A sine with a peak of 0.5 has an RMS of about 0.35; anything near that
        // means audio came through, and near zero means the decoder produced
        // silence.
        XCTAssertGreaterThan(rms, 0.15, "decoded audio must carry the tone, rms \(rms)")
    }

    func testJunkDoesNotDecodeAndSilenceIsNotEncoded() throws {
        let codec = try OpusCodec()
        XCTAssertNil(codec.decode(Data()))
        XCTAssertNil(codec.encode([Float](repeating: 0, count: 7)), "a short frame is refused")
    }
}
