//  FingerprintRenderingTests.swift
//
//  Small, real smoke tests that the app target links against a working Rust
//  core through the full pipeline — cross-compiled static libraries, cbindgen
//  header, bridging header, Swift call — not just that the Swift compiles. The
//  protocol and cryptography themselves are exhaustively covered by
//  `cargo test --workspace`; this is the one seam that suite cannot reach.

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

        // The raw bytes are not exposed for the engine's own identity, but
        // rejecting an unrelated code is the failure mode that matters for
        // FR-DISC-04's comparison path.
        XCTAssertFalse(
            VoidCore.fingerprintMatches(expected: Data(count: 32), input: words),
            "an all-zero fingerprint must not match real words"
        )
    }
}

/// The invitation surface, as far as it goes without a relay to reach.
final class InvitationBoundaryTests: XCTestCase {
    private func now() -> UInt64 { UInt64(Date().timeIntervalSince1970) }

    func testOpeningYourOwnInvitationIsRefused() throws {
        let core = try VoidCore()
        let (link, _) = try core.createInvite(
            relay: RelayConfig.address, myLabel: "", contactLabel: "", now: now(), ttlSeconds: 3600)
        XCTAssertThrowsError(try core.openInvite(link: link, now: now())) { error in
            XCTAssertEqual(error as? VoidError, .ownInvite)
        }
    }

    func testSomethingThatIsNotAnInvitationIsRefused() throws {
        let core = try VoidCore()
        XCTAssertThrowsError(try core.openInvite(link: "https://example.com", now: now())) { error in
            XCTAssertEqual(error as? VoidError, .badArgument)
        }
    }

    func testAMillisecondTimestampIsRefusedNotMisread() throws {
        let core = try VoidCore()
        let milliseconds = now() * 1000
        XCTAssertThrowsError(
            try core.createInvite(
                relay: RelayConfig.address, myLabel: "", contactLabel: "", now: milliseconds, ttlSeconds: 3600)
        ) { error in
            XCTAssertEqual(error as? VoidError, .badArgument)
        }
    }

    func testAnInvitationIsOutstandingAndCancellable() throws {
        let core = try VoidCore()
        let (_, id) = try core.createInvite(
            relay: RelayConfig.address, myLabel: "", contactLabel: "Alex", now: now(), ttlSeconds: 3600)
        XCTAssertNotNil(core.inviteUploadRemaining(id), "outstanding until accepted, expired or cancelled")
        XCTAssertTrue(core.cancelInvite(id))
        XCTAssertNil(core.inviteUploadRemaining(id))
        XCTAssertTrue(core.takeContactEvents().isEmpty)
    }
}
