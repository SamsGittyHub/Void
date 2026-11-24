//  EndToEndUITests.swift
//
//  Two phones, one relay, the live Tor network: everything a person would do,
//  driven through the real interface on two Simulators at once. One test plays
//  Ada, who makes an invitation; the other plays Bea, who accepts it. Then:
//  messages both ways, a photo, a voice call, and a video call.
//
//  The two runs meet through files in a shared directory on the host — the
//  only thing they share. `scripts/run_ios_e2e.sh` starts a relay behind a
//  Tor onion service, launches both runs, and passes the directory and the
//  relay's address in the runner's environment:
//
//      E2E_DIR     the shared directory
//      E2E_RELAY   the relay's onion address
//      E2E_RUN     a name for this run, so each starts from a new identity
//
//  Without those, both tests skip: CI's `xcodebuild test` has no relay.
//
//  The Simulator has no camera, so the video either side sends is the app's
//  own test pattern (see CallVideo.swift). Its microphone is the Mac's. What
//  this checks for media is what the call screen's details count: frames
//  sent, received, decoded and shown — it cannot listen.

import CoreImage
import XCTest

final class EndToEndUITests: XCTestCase {
    private var shared: URL!
    private var relay = ""
    private var run = "e2e"
    private var role = ""

    override func setUpWithError() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let dir = environment["E2E_DIR"], let relay = environment["E2E_RELAY"] else {
            throw XCTSkip("Two-phone run: start it with scripts/run_ios_e2e.sh")
        }
        shared = URL(fileURLWithPath: dir)
        self.relay = relay
        run = environment["E2E_RUN"] ?? "e2e"
        continueAfterFailure = false
        addUIInterruptionMonitor(withDescription: "Permission") { alert in
            for label in ["Allow", "OK", "Allow While Using App"] where alert.buttons[label].exists {
                alert.buttons[label].tap()
                return true
            }
            return false
        }
    }

    // MARK: Ada

    func testAda() throws {
        role = "ada"
        let app = launch(as: "Ada")
        waitConnected(app)

        // An invitation, with our name on it and theirs for us.
        app.buttons["Add contact"].tap()
        type("Bea", into: field(app, "Their name (optional)"))
        type("Ada", into: field(app, "Your name (optional)"))
        app.buttons["createInviteButton"].tap()
        let code = app.descendants(matching: .any)["inviteQRCode"]
        XCTAssertTrue(code.waitForExistence(timeout: 20))
        let link = try XCTUnwrap(readQRCode(code), "the code on screen must read back as a link")
        XCTAssertTrue(link.hasPrefix("void://i/"), link)
        note("invitation made: \(link.prefix(24))…")
        snapshot(app, "01-ada-invitation")
        post("link", link)

        // Bea collects it, confirms, and her handshake arrives. The sheet
        // says so — and if something swiped it away meanwhile, the contact
        // appearing in the list says the same thing.
        let status = app.staticTexts["inviteStatus"]
        let row = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Bea'")).firstMatch
        XCTAssertTrue(
            waitUntil(timeout: 600) { (status.exists && status.label.contains("joined")) || row.exists },
            "Bea never joined")
        note("Bea joined")
        snapshot(app, "02-ada-bea-joined")
        if app.buttons["Close"].exists {
            app.buttons["Close"].tap()
        }

        openConversation(app, "Bea")
        XCTAssertTrue(message(app, "Hi Ada, it's Bea").waitForExistence(timeout: 300), "Bea's first message")
        note("Bea's first message arrived")

        send(app, "Hello Bea, this is Ada over Tor")
        XCTAssertTrue(waitUntil(timeout: 180) { self.footer(app, "Sent").exists }, "never sent")
        note("message sent")
        post("ada-sent")

        // Bea sends a photo; it is fetched and opens.
        XCTAssertNotNil(wait(for: "bea-sent-photo", timeout: 600))
        let photo = app.descendants(matching: .any).matching(identifier: "attachmentPhoto").firstMatch
        XCTAssertTrue(photo.waitForExistence(timeout: 300), "the photo's pointer never arrived")
        XCTAssertTrue(
            waitUntil(timeout: 300) { (photo.value as? String)?.hasPrefix("loaded") == true },
            "the photo never downloaded")
        snapshot(app, "05-ada-photo-received")
        photo.tap()
        XCTAssertTrue(app.buttons["Share"].waitForExistence(timeout: 30), "the photo never opened")
        snapshot(app, "06-ada-photo-viewer")
        app.buttons["Done"].tap()
        note("photo received and opened")
        post("ada-got-photo")

        // A voice call, from Ada.
        app.buttons["callButton"].tap()
        tapWhenReady(app.buttons["callDisclosureContinue"], timeout: 15)
        XCTAssertTrue(
            app.staticTexts["callTimer"].waitForExistence(timeout: 300), "the voice call never connected")
        note("voice call connected")
        sleep(12)
        let voice = readStats(app, video: false)
        note("voice call stats: \(voice)")
        snapshot(app, "07-ada-voice-call")
        XCTAssertGreaterThan(voice.audioReceived + voice.silenceReceived, 50, "no media arrived")
        app.buttons["endCallButton"].tap()
        note("voice call ended")
        post("ada-voice-done")

        // A video call, from Bea.
        let answer = app.buttons["answerCallButton"]
        XCTAssertTrue(answer.waitForExistence(timeout: 400), "Bea's video call never rang")
        snapshot(app, "10-ada-incoming-video")
        answer.tap()
        tapWhenReady(app.buttons["callDisclosureContinue"], timeout: 15)
        XCTAssertTrue(app.staticTexts["callTimer"].waitForExistence(timeout: 180), "never connected")
        XCTAssertTrue(
            waitUntil(timeout: 120) { self.readStats(app, video: true).videoShown > 10 },
            "no video was shown")
        sleep(6)
        let video = readStats(app, video: true)
        note("video call stats: \(video)")
        snapshot(app, "11-ada-video-call")
        XCTAssertNotNil(wait(for: "bea-video-done", timeout: 300))
        note("done")
    }

    // MARK: Bea

    func testBea() throws {
        role = "bea"
        let app = launch(as: "Bea")
        waitConnected(app)

        let link = try XCTUnwrap(wait(for: "link", timeout: 900), "Ada never made an invitation")
        app.buttons["Add contact"].tap()
        app.buttons["Scan or paste"].tap()
        type(link, into: field(app, "void://…"))
        app.buttons["openLinkButton"].tap()
        note("opened the invitation")

        let connect = app.buttons["confirmInviteButton"]
        XCTAssertTrue(connect.waitForExistence(timeout: 600), "the invitation never arrived")
        snapshot(app, "03-bea-connect")
        type("Hi Ada, it's Bea", into: field(app, "First message (optional)"))
        connect.tap()
        note("connected")

        openConversation(app, "Ada")
        XCTAssertTrue(
            message(app, "Hello Bea, this is Ada over Tor").waitForExistence(timeout: 400),
            "Ada's message never arrived")
        note("Ada's message arrived")
        snapshot(app, "04-bea-conversation")

        // A photo, made in the app (the Simulator's library cannot be driven).
        XCTAssertNotNil(wait(for: "ada-sent", timeout: 60))
        app.buttons["attachButton"].tap()
        tapWhenReady(app.buttons["attachTestPicture"], timeout: 10)
        let sent = app.descendants(matching: .any).matching(identifier: "attachmentPhoto").firstMatch
        XCTAssertTrue(sent.waitForExistence(timeout: 30))
        XCTAssertTrue(
            waitUntil(timeout: 400) { (sent.value as? String)?.contains("Sent") == true },
            "the photo never finished sending")
        note("photo sent")
        snapshot(app, "05-bea-photo-sent")
        post("bea-sent-photo")

        // Ada's voice call.
        let answer = app.buttons["answerCallButton"]
        XCTAssertTrue(answer.waitForExistence(timeout: 600), "Ada's call never rang")
        snapshot(app, "07-bea-incoming-voice")
        answer.tap()
        tapWhenReady(app.buttons["callDisclosureContinue"], timeout: 15)
        XCTAssertTrue(app.staticTexts["callTimer"].waitForExistence(timeout: 180), "never connected")
        note("voice call connected")
        XCTAssertNotNil(wait(for: "ada-voice-done", timeout: 300))
        XCTAssertTrue(waitUntil(timeout: 60) { !app.staticTexts["callTimer"].exists }, "the call never ended")
        note("voice call ended")

        // A video call, to Ada.
        sleep(5)
        app.buttons["videoCallButton"].tap()
        snapshot(app, "09-bea-video-disclosure")
        tapWhenReady(app.buttons["callDisclosureContinue"], timeout: 15)
        XCTAssertTrue(app.staticTexts["callTimer"].waitForExistence(timeout: 400), "the video call never connected")
        XCTAssertTrue(
            waitUntil(timeout: 120) { self.readStats(app, video: true).videoShown > 10 },
            "no video was shown")
        sleep(10)
        let video = readStats(app, video: true)
        note("video call stats: \(video)")
        snapshot(app, "11-bea-video-call")
        app.buttons["cameraButton"].tap()
        sleep(3)
        snapshot(app, "12-bea-camera-off")
        app.buttons["endCallButton"].tap()
        post("bea-video-done")
        note("done")
    }

    // MARK: Driving the app

    private func launch(as name: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += [
            "-uiTestsSkipOnboarding", "-uiTestsAttachmentFixture",
            "-uiTestsDataSuffix", "\(run)\(name)", "-uiTestsRelay", relay,
        ]
        app.launch()
        return app
    }

    private func waitConnected(_ app: XCUIApplication) {
        let connected = app.descendants(matching: .any)["connectionIndicator"]
        XCTAssertTrue(connected.waitForExistence(timeout: 420), "never connected over Tor")
        note("connected over Tor")
    }

    private func openConversation(_ app: XCUIApplication, _ name: String) {
        let row = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", name)).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 60), "no conversation with \(name)")
        row.tap()
    }

    private func send(_ app: XCUIApplication, _ text: String) {
        type(text, into: field(app, "Message"))
        app.buttons["sendButton"].tap()
    }

    /// A text field by its placeholder. SwiftUI's vertical text fields do not
    /// answer to their label, but they do to this.
    private func field(_ app: XCUIApplication, _ placeholder: String) -> XCUIElement {
        let byPlaceholder = app.textFields.matching(NSPredicate(format: "placeholderValue == %@", placeholder))
        let views = app.textViews.matching(NSPredicate(format: "placeholderValue == %@", placeholder))
        return byPlaceholder.count > 0 ? byPlaceholder.firstMatch : views.firstMatch
    }

    private func message(_ app: XCUIApplication, _ text: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch
    }

    private func footer(_ app: XCUIApplication, _ text: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch
    }

    private func type(_ text: String, into field: XCUIElement) {
        XCTAssertTrue(field.waitForExistence(timeout: 20), "no field for \(text.prefix(12))")
        field.tap()
        field.typeText(text)
    }

    private func tapWhenReady(_ element: XCUIElement, timeout: TimeInterval) {
        XCTAssertTrue(element.waitForExistence(timeout: timeout), "\(element) never appeared")
        element.tap()
    }

    private struct Stats: CustomStringConvertible {
        var audioReceived = 0
        var silenceReceived = 0
        var audioSent = 0
        var videoSent = 0
        var videoShown = 0
        var description: String {
            "audio sent \(audioSent), received \(audioReceived) (+\(silenceReceived) silent); "
                + "video sent \(videoSent), shown \(videoShown)"
        }
    }

    /// Open the call's details, read what it has carried, close them again.
    private func readStats(_ app: XCUIApplication, video: Bool) -> Stats {
        let details = app.buttons["callDetailsButton"]
        guard details.waitForExistence(timeout: 10) else { return Stats() }
        details.tap()
        var stats = Stats()
        let numbers = { (id: String) -> [Int] in
            let element = app.staticTexts[id]
            guard element.waitForExistence(timeout: 5) else { return [] }
            return element.label.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        }
        let received = numbers("statsAudioReceived")
        if received.count >= 2 {
            stats.audioReceived = received[0]
            stats.silenceReceived = received[1]
        }
        stats.audioSent = numbers("statsAudioSent").first ?? 0
        if video {
            stats.videoSent = numbers("statsVideoSent").first ?? 0
            let shown = numbers("statsVideoReceived")
            stats.videoShown = shown.count >= 2 ? shown[1] : 0
        }
        snapshot(app, "stats-\(Int(Date().timeIntervalSince1970))")
        app.buttons["callDetailsDone"].tap()
        return stats
    }

    // MARK: Between the two runs

    private func post(_ name: String, _ value: String = "") {
        try? value.write(to: shared.appendingPathComponent(name), atomically: true, encoding: .utf8)
    }

    private func wait(for name: String, timeout: TimeInterval) -> String? {
        let url = shared.appendingPathComponent(name)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let value = try? String(contentsOf: url, encoding: .utf8) { return value }
            Thread.sleep(forTimeInterval: 1)
        }
        return nil
    }

    private func waitUntil(timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            Thread.sleep(forTimeInterval: 1)
        }
        return condition()
    }

    private func note(_ line: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        let url = shared.appendingPathComponent("log-\(role).txt")
        let entry = "\(stamp) \(line)\n"
        if let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile()
            handle.write(Data(entry.utf8))
            try? handle.close()
        } else {
            try? entry.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private func snapshot(_ app: XCUIApplication, _ name: String) {
        let shot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: shot)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
        try? shot.pngRepresentation.write(to: shared.appendingPathComponent("\(name).png"))
    }

    private func readQRCode(_ element: XCUIElement) -> String? {
        guard let image = CIImage(image: element.screenshot().image),
            let detector = CIDetector(
                ofType: CIDetectorTypeQRCode, context: nil,
                options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        else { return nil }
        return detector.features(in: image).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.first
    }
}
