//  QRCodeRenderTests.swift
//
//  An invitation is one QR code (D-027). This renders a real short link made
//  by the real core and reads it back with CoreImage's own detector — the round
//  trip a person's camera makes, without needing a camera. It replaces a test
//  of the thirteen-frame carousel, which only checked that a PNG was non-empty
//  and so passed on a placeholder image.

import CoreImage
import UIKit
import XCTest

@testable import Void

final class QRCodeRenderTests: XCTestCase {
    func testAnInvitationFromTheCoreRendersAsOneCodeThatReadsBack() throws {
        let core = try VoidCore()
        let (link, _) = try core.createInvite(
            relay: RelayConfig.address,
            myLabel: "Sam",
            contactLabel: "",
            now: UInt64(Date().timeIntervalSince1970),
            ttlSeconds: 3600
        )
        XCTAssertTrue(link.hasPrefix("void://i/"))
        XCTAssertLessThanOrEqual(link.count, 150, "one small code, easy to scan at arm's length")

        let image = try XCTUnwrap(QRCodeImage.render(link))
        let ciImage = try XCTUnwrap(CIImage(image: image))
        let detector = try XCTUnwrap(
            CIDetector(
                ofType: CIDetectorTypeQRCode, context: nil,
                options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        let decoded = detector.features(in: ciImage).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
        XCTAssertEqual(decoded, [link], "the code must read back as exactly the link")
    }
}
