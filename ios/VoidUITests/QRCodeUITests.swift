//  QRCodeUITests.swift
//
//  `QRCodeRenderTests` (the unit test) proved the wrong thing: ImageRenderer
//  can't flatten `TabView(.page)` off-screen (see the "Invalid Configuration
//  ... UIKitPagingView" warning it logs), so its PNG for the multi-frame case
//  was a system placeholder, not a QR code — a false pass, since the assertion
//  only checked `png.count > 0`. This drives the real on-screen app through
//  Simulator and captures what `XCUIScreen` actually shows, which does not
//  go through ImageRenderer at all.

import XCTest

final class QRCodeUITests: XCTestCase {
    func testGeneratingAnInviteShowsAScannableQRCode() {
        let app = XCUIApplication()
        app.launchArguments += ["-uiTestsSkipOnboarding"]
        app.launch()

        let addContact = app.buttons["Add contact"]
        XCTAssertTrue(addContact.waitForExistence(timeout: 5))
        addContact.tap()

        let generate = app.buttons["Generate an invite"]
        XCTAssertTrue(generate.waitForExistence(timeout: 5))
        generate.tap()

        // Real invite generation (identity + prekey bundle) runs synchronously
        // on tap; give the carousel a beat to lay out before capturing.
        Thread.sleep(forTimeInterval: 1.5)

        let screenshot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.lifetime = .keepAlways
        attachment.name = "invite-qr-carousel"
        add(attachment)

        try? screenshot.pngRepresentation.write(to: URL(fileURLWithPath: "/tmp/void_qr_live_screenshot.png"))
    }
}
