//  QRCodeUITests.swift
//
//  Drives the real app in the Simulator: open "Add a contact", make an
//  invitation, and check that its one QR code is on screen. The screenshot is
//  attached so a person can see what was shown; `QRCodeRenderTests` is what
//  checks that the code reads back as the link.

import XCTest

final class QRCodeUITests: XCTestCase {
    func testCreatingAnInvitationShowsItsCode() {
        let app = XCUIApplication()
        app.launchArguments += ["-uiTestsSkipOnboarding"]
        app.launch()

        // Launch unlocks the key and opens the database before anything shows.
        let addContact = app.buttons["Add contact"]
        XCTAssertTrue(addContact.waitForExistence(timeout: 20))
        addContact.tap()

        let create = app.buttons["createInviteButton"]
        XCTAssertTrue(create.waitForExistence(timeout: 5))
        create.tap()

        // Made offline if need be: the invitation waits in the outbox, and the
        // code is shown straight away.
        let code = app.descendants(matching: .any)["inviteQRCode"]
        XCTAssertTrue(code.waitForExistence(timeout: 10))

        let screenshot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.lifetime = .keepAlways
        attachment.name = "invite-qr-code"
        add(attachment)
    }
}
