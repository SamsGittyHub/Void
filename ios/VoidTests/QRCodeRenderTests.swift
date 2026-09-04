//  QRCodeRenderTests.swift
//
//  Renders the real invite QR carousel off-screen against a real, full-size
//  invite link (the same shape `AppState.createInvite` produces) and writes
//  it to disk — a way to actually look at what the multi-part QR carousel
//  produces without needing full UI automation.

import SwiftUI
import XCTest

@testable import Void

final class QRCodeRenderTests: XCTestCase {
    /// A stand-in for a real `void://c/...` link, sized like the real thing
    /// (~14,600 characters — see QRCode.swift's module docs for why).
    private var sampleLink: String {
        "void://c/" + String(repeating: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", count: 440) + "#"
            + String(repeating: "A", count: 52)
    }

    @MainActor
    func testCarouselRendersMultipleFramesForARealSizedLink() {
        let chunks = QRChunker.chunks(for: sampleLink)
        XCTAssertGreaterThan(chunks.count, 1, "a real invite link must need more than one frame")
        for chunk in chunks {
            XCTAssertLessThanOrEqual(chunk.count, QRChunker.chunkSize + 20)
        }

        let view = InviteQRCodeCarousel(link: sampleLink)
            .frame(width: 400, height: 400)
            .background(Color.white)
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2.0

        guard let uiImage = renderer.uiImage, let png = uiImage.pngData() else {
            XCTFail("carousel failed to render")
            return
        }
        XCTAssertGreaterThan(png.count, 0)

        let outPath = "/tmp/void_qr_carousel_render.png"
        try? png.write(to: URL(fileURLWithPath: outPath))
        print("Wrote carousel render to \(outPath)")
    }

    @MainActor
    func testSingleFrameForAShortPayload() {
        let short = "void://c/SHORT#KEY"
        let chunks = QRChunker.chunks(for: short)
        XCTAssertEqual(chunks.count, 1, "a short payload must not be split")

        let view = InviteQRCodeCarousel(link: short)
            .frame(width: 300, height: 300)
            .background(Color.white)
        let renderer = ImageRenderer(content: view)
        guard let uiImage = renderer.uiImage, let png = uiImage.pngData() else {
            XCTFail("single-frame carousel failed to render")
            return
        }
        try? png.write(to: URL(fileURLWithPath: "/tmp/void_qr_single_render.png"))
    }
}
