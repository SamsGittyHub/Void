// Runs the iOS app's FFI wrapper (VoidCore.swift, VoidCall.swift,
// CoreQueue.swift) against the real Rust core, built as a shared library, on
// Linux. Compiled as main.swift by scripts/check_ios_bindings.sh (D-029).
import Foundation
import VoidFFI

setvbuf(stdout, nil, _IOLBF, 0)

var failures = 0
func check(_ condition: @autoclosure () -> Bool, _ message: String, line: Int = #line) {
    if condition() { print("  ok   \(message)") } else { failures += 1; print("  FAIL \(message) (line \(line))") }
}
func expectError(_ expected: VoidError, _ message: String, _ body: () throws -> Void) {
    do { try body(); check(false, "\(message): no error thrown") }
    catch let e as VoidError { check(e == expected, "\(message): \(e)") }
    catch { check(false, "\(message): unexpected \(error)") }
}
let now = UInt64(Date().timeIntervalSince1970)

print("in-memory engine")
let core = try VoidCore()
check(core.fingerprintWords.contains("-"), "fingerprint words render")
check(core.contacts.isEmpty, "no contacts")
check(core.takeContactEvents().isEmpty, "no contact events")
check(core.takeCallEvents().isEmpty, "no call events")
check(core.tick(nowMs: now * 1000) == .offline, "tick without a transport reports offline")
check(!core.protectionAcknowledged, "protection screen not yet acknowledged")

print("invitations")
let (link, id) = try core.createInvite(relay: RelayConfig.address, myLabel: "Sam", contactLabel: "Alex", now: now, ttlSeconds: 3600)
check(link.hasPrefix("void://i/"), "short link: \(link)")
check(link.count <= 150, "fits one QR code (\(link.count) chars)")
check(id.count == 16, "16-byte invite id")
check((core.inviteUploadRemaining(id) ?? 0) > 0, "upload queued: \(String(describing: core.inviteUploadRemaining(id))) records")
expectError(.ownInvite, "own invitation refused") { _ = try core.openInvite(link: link, now: now) }
expectError(.badArgument, "not an invitation") { _ = try core.openInvite(link: "https://example.com", now: now) }
expectError(.badArgument, "milliseconds refused") {
    _ = try core.createInvite(relay: RelayConfig.address, myLabel: "", contactLabel: "", now: now * 1000, ttlSeconds: 3600)
}
expectError(.badArgument, "no relay named, none attached") {
    _ = try core.createInvite(relay: "", myLabel: "", contactLabel: "", now: now, ttlSeconds: 3600)
}
check(core.cancelInvite(id), "cancel succeeds")
check(core.inviteUploadRemaining(id) == nil, "cancelled invite is no longer outstanding")
check(!core.cancelInvite(id), "second cancel reports nothing to cancel")
let other = try VoidCore()
let otherInvite = try other.createInvite(relay: RelayConfig.address, myLabel: "Sam", contactLabel: "", now: now, ttlSeconds: 3600)
let fetchId = try core.openInvite(link: otherInvite.link, now: now)
check(fetchId.count == 16, "someone else's short link opens and starts collecting")
check(core.takeContactEvents().isEmpty, "nothing ready before it is collected")
core.cancelFetch(fetchId)
expectError(.failed, "confirming a fetch that never arrived fails") {
    _ = try core.confirmInvite(fetchId: fetchId, localName: "", firstMessage: "", now: now)
}

print("settings")
try core.setInviteName("Sam Ü")
check(core.inviteName == "Sam Ü", "invite name round-trips UTF-8: \(core.inviteName)")
try core.acknowledgeProtection()
check(core.protectionAcknowledged, "protection acknowledged")

print("persistence")
let dir = FileManager.default.temporaryDirectory.appendingPathComponent("void-swift-\(UUID().uuidString)")
var kek = (0..<32).map { _ in UInt8.random(in: 0...255) }
let original = kek
var words = ""
do {
    let persisted = try VoidCore(dataDirectory: dir, kek: &kek, backing: .software, nowMs: now * 1000)
    words = persisted.fingerprintWords
    try persisted.setInviteName("Robin")
    try persisted.acknowledgeProtection()
    _ = try persisted.createInvite(relay: RelayConfig.address, myLabel: "Robin", contactLabel: "Kim", now: now, ttlSeconds: 3600)
}
check(kek.allSatisfy { $0 == 0 }, "caller's KEK copy is zeroed")
var again = original
do {
    let reopened = try VoidCore(dataDirectory: dir, kek: &again, backing: .software, nowMs: now * 1000)
    check(reopened.fingerprintWords == words, "same identity after reopening")
    check(reopened.inviteName == "Robin", "invite name persisted")
    check(reopened.protectionAcknowledged, "acknowledgement persisted")
}
var wrong = (0..<32).map { _ in UInt8.random(in: 0...255) }
expectError(.locked, "a wrong key reports locked") {
    _ = try VoidCore(dataDirectory: dir, kek: &wrong, backing: .software, nowMs: now * 1000)
}
var short: [UInt8] = [1, 2, 3]
expectError(.badArgument, "a short key is refused") {
    _ = try VoidCore(dataDirectory: dir, kek: &short, backing: .software, nowMs: now * 1000)
}
var third = original
do {
    let reopened = try VoidCore(dataDirectory: dir, kek: &third, backing: .software, nowMs: now * 1000)
    check(reopened.fingerprintWords == words, "the wrong key replaced nothing")
}

print("core queue")
let queue = CoreQueue(core: core)
let semaphore = DispatchSemaphore(value: 0)
Task { () async -> Void in
    let viaQueue = await queue.run { $0.fingerprintWords }
    check(viaQueue == core.fingerprintWords, "run returns the engine's value")
    do {
        _ = try await queue.attempt { try $0.openInvite(link: "nope", now: now) }
        check(false, "attempt should rethrow")
    } catch let e as VoidError {
        check(e == .badArgument, "attempt rethrows the engine's error")
    } catch {
        check(false, "unexpected \(error)")
    }
    semaphore.signal()
}
semaphore.wait()
var ticks = 0
let tickDone = DispatchSemaphore(value: 0)
let timer = queue.makeTimer(every: .milliseconds(50)) { core in
    _ = core.tick(nowMs: UInt64(Date().timeIntervalSince1970 * 1000))
    ticks += 1
    if ticks == 3 { tickDone.signal() }
}
check(tickDone.wait(timeout: .now() + 5) == .success, "timer ticks on the core queue")
timer.cancel()

print("byte reader")
var reader = ByteReader([1, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0xff])
check(reader.u8() == 1, "u8")
check(reader.u16() == 0x1234, "u16 little-endian")
check(reader.u32() == 0x1234_5678, "u32 little-endian")
check(reader.u16() == nil, "a read past the end is nil, not a trap")
var lengths = ByteReader([5, 0, 0, 0, 0x68, 0x69])
if let n = lengths.u32() { check(lengths.string(Int(n)) == nil, "a length longer than the buffer is refused") }

print(failures == 0 ? "ALL PASSED" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
