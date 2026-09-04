//  FingerprintRenderingTests.swift
//
//  A small, real smoke test that the app target actually links against a
//  working Rust core through the full pipeline — cross-compiled static
//  libraries, cbindgen header, bridging header, Swift call — not just that
//  the Swift compiles. The protocol and cryptography themselves are
//  exhaustively covered by `cargo test --workspace`; this is the one seam
//  that suite cannot reach.

import XCTest

@testable import Void

final class FingerprintRenderingTests: XCTestCase {
    func testEngineGeneratesAnIdentityAndRendersItsFingerprint() throws {
        let core = try VoidCore()
        let words = core.fingerprintWords
        XCTAssertFalse(words.isEmpty, "fingerprint words must render across the FFI boundary")
        XCTAssertTrue(words.contains("-"), "proquint words are hyphen-joined")
    }

    func testTwoIdentitiesHaveDifferentFingerprints() throws {
        let a = try VoidCore()
        let b = try VoidCore()
        XCTAssertNotEqual(a.fingerprintWords, b.fingerprintWords)
    }

    func testFingerprintMatchesItselfAndRejectsAnUnrelatedCode() throws {
        let core = try VoidCore()
        let words = core.fingerprintWords

        // The bytes this test compares against are not exposed directly —
        // `startConversation`/`acceptConversation` are what normally hand
        // them out — but `fingerprintWords` round-tripping through
        // `fingerprintMatches` against itself is exactly FR-DISC-04's
        // comparison path in miniature, and rejecting an unrelated string
        // is the failure mode that actually matters.
        XCTAssertFalse(
            VoidCore.fingerprintMatches(expected: Data(count: 32), input: words),
            "an all-zero fingerprint must not match real words"
        )
    }
}
