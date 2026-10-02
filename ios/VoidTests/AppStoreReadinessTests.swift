//  AppStoreReadinessTests.swift
//
//  The things App Store Connect checks before a human ever sees the build,
//  pinned so a project regeneration or a plist edit cannot quietly undo them.
//  Each one is a rejection in practice, not in theory: an upload with no icon
//  is refused outright, and so is an iPad-capable app that supports
//  multitasking without declaring all four orientations. These tests run in
//  the built app, so they see the Info.plist Xcode actually produced, icon
//  entries included.
//
//  What they cannot check: the App Store listing, screenshots, the export
//  compliance questionnaire (FR-DIST-03 says why it is triggered), and that a
//  release build points at a production relay rather than the development one
//  in RelayConfig.swift. Those are submission-time steps for a person.

import XCTest

@testable import Void

final class AppStoreReadinessTests: XCTestCase {
    /// The Info.plist as the running device resolves it: device-specific
    /// keys (`~ipad`, `~iphone`) are folded in for this device and the other
    /// device's are dropped. Right for everything that is the same on both.
    private var info: [String: Any] {
        Bundle.main.infoDictionary ?? [:]
    }

    /// The Info.plist as written into the bundle, every key as App Store
    /// Connect sees it. On an iPhone Simulator the resolved dictionary has no
    /// `UISupportedInterfaceOrientations~ipad` at all (CI found this), so the
    /// iPad check reads the file.
    private var rawInfo: [String: Any] {
        guard let url = Bundle.main.url(forResource: "Info", withExtension: "plist"),
            let data = try? Data(contentsOf: url),
            let plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
        else { return info }
        return plist as? [String: Any] ?? info
    }

    func testTheAppHasAnIcon() throws {
        // Xcode writes CFBundleIcons from the asset catalog's AppIcon set.
        // Without it App Store Connect refuses the upload before review.
        let icons = try XCTUnwrap(info["CFBundleIcons"] as? [String: Any], "no icon in the built app")
        let primary = try XCTUnwrap(icons["CFBundlePrimaryIcon"] as? [String: Any])
        XCTAssertEqual(primary["CFBundleIconName"] as? String, "AppIcon")
    }

    func testIPadDeclaresEveryOrientationOrOptsOutOfMultitasking() throws {
        let fullScreen = rawInfo["UIRequiresFullScreen"] as? Bool ?? false
        if fullScreen { return }
        let ipad = try XCTUnwrap(
            rawInfo["UISupportedInterfaceOrientations~ipad"] as? [String],
            "an iPad app that multitasks must list its orientations")
        XCTAssertEqual(
            Set(ipad),
            [
                "UIInterfaceOrientationPortrait",
                "UIInterfaceOrientationPortraitUpsideDown",
                "UIInterfaceOrientationLandscapeLeft",
                "UIInterfaceOrientationLandscapeRight",
            ],
            "all four, or the upload is refused")
    }

    func testEveryPermissionTheAppAsksForHasAReason() {
        // iOS kills the app on first use of a capability without one, and
        // review rejects a vague one. Each should say what Void does and
        // does not do with it.
        for key in ["NSCameraUsageDescription", "NSMicrophoneUsageDescription", "NSFaceIDUsageDescription"] {
            let text = info[key] as? String ?? ""
            XCTAssertGreaterThan(text.count, 40, "\(key) must explain itself")
        }
    }

    func testExportComplianceIsDeclaredHonestly() {
        // FR-DIST-03: this app implements its own cryptography and is not
        // exempt. `false` here would be a false statement on submission.
        XCTAssertEqual(info["ITSAppUsesNonExemptEncryption"] as? Bool, true)
    }

    func testVersionAndBuildArePresent() {
        XCTAssertFalse((info["CFBundleShortVersionString"] as? String ?? "").isEmpty)
        XCTAssertFalse((info["CFBundleVersion"] as? String ?? "").isEmpty)
        XCTAssertEqual(info["CFBundleIdentifier"] as? String, "app.void.Void")
    }
}
