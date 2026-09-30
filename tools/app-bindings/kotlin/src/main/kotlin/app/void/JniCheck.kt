package app.void

import java.io.File
import java.nio.file.Files
import kotlin.random.Random
import kotlin.system.exitProcess

// Runs the Android app's JNI wrapper against the real Rust core on a desktop
// JVM (scripts/check_android_bindings.sh, D-029). Every call here crosses the
// real JNI shim: a wrong `external fun` signature is an UnsatisfiedLinkError,
// a wrong result-class constructor is a null result.

private var failures = 0

private fun check(condition: Boolean, message: String) {
    if (condition) println("  ok   $message") else { failures++; println("  FAIL $message") }
}

private fun expectStatus(expected: VoidStatus, message: String, block: () -> Unit) {
    try {
        block()
        check(false, "$message: nothing thrown")
    } catch (e: VoidException) {
        check(e.status == expected, "$message: ${e.status}")
    }
}

fun main() {
    val now = System.currentTimeMillis() / 1000

    println("in-memory engine")
    val engine = Engine.inMemory()
    check(engine.fingerprintWords.contains("-"), "fingerprint words render")
    check(engine.contacts().isEmpty(), "no contacts")
    check(engine.takeContactEvents().isEmpty(), "no contact events")
    check(engine.takeCallEvents().isEmpty(), "no call events")
    check(engine.tick(now * 1000) == Engine.TickResult.Offline, "tick without a transport reports offline")
    check(!engine.protectionAcknowledged, "protection not yet acknowledged")
    check(VoidCore.protocolId().startsWith("void/v3/"), "protocol id: ${VoidCore.protocolId()}")
    check(VoidCore.callPort() == 9999 && VoidCore.callFrameMs() == 20L, "call constants")
    check(VoidCore.textCallDisclosure().isNotEmpty(), "call disclosure text")

    println("invitations")
    val created = engine.createInvite(RelayConfig.ADDRESS, "Sam", "Alex", now, 3600)
    check(created.link.startsWith("void://i/"), "short link: ${created.link}")
    check(created.link.length <= 150, "fits one QR code (${created.link.length} chars)")
    check(created.id.size == 16, "16-byte invite id")
    check((engine.inviteUploadRemaining(created.id) ?: 0) > 0, "upload queued: ${engine.inviteUploadRemaining(created.id)}")
    check(VoidCore.inviteLink(0, created.id).isEmpty(), "a null engine handle gives nothing, not a crash")
    expectStatus(VoidStatus.OWN_INVITE, "own invitation refused") { engine.openInvite(created.link, now) }
    expectStatus(VoidStatus.BAD_ARGUMENT, "not an invitation") { engine.openInvite("https://example.com", now) }
    try {
        engine.createInvite(RelayConfig.ADDRESS, "", "", now * 1000, 3600)
        check(false, "milliseconds should be refused")
    } catch (e: VoidException) {
        check(true, "milliseconds refused (${e.status})")
    }
    check(engine.cancelInvite(created.id), "cancel succeeds")
    check(engine.inviteUploadRemaining(created.id) == null, "cancelled invite no longer outstanding")
    val other = Engine.inMemory()
    val theirs = other.createInvite(RelayConfig.ADDRESS, "Kim", "", now, 3600)
    val fetchId = engine.openInvite(theirs.link, now)
    check(fetchId.size == 16, "someone else's link opens and starts collecting")
    engine.cancelFetch(fetchId)
    expectStatus(VoidStatus.FAILED, "confirming a fetch that never arrived fails") {
        engine.confirmInvite(fetchId, "", "", now)
    }

    println("settings")
    engine.setInviteName("Sam Ü")
    check(engine.inviteName == "Sam Ü", "invite name round-trips UTF-8")
    engine.acknowledgeProtection()
    check(engine.protectionAcknowledged, "protection acknowledged")
    expectStatus(VoidStatus.FAILED, "renaming someone who isn't a contact fails") {
        engine.renameContact(ByteArray(32), "Nobody")
    }

    println("persistence")
    val dir = Files.createTempDirectory("void-kotlin").toFile()
    val key = Random.nextBytes(32)
    var words: String
    run {
        val kek = key.copyOf()
        val persisted = Engine.open(File(dir, "data"), kek, VaultBacking.TEE, System.currentTimeMillis())
        check(kek.all { it == 0.toByte() }, "caller's KEK copy is zeroed")
        words = persisted.fingerprintWords
        persisted.setInviteName("Robin")
        persisted.close()
    }
    run {
        val reopened = Engine.open(File(dir, "data"), key.copyOf(), VaultBacking.TEE, System.currentTimeMillis())
        check(reopened.fingerprintWords == words, "same identity after reopening")
        check(reopened.inviteName == "Robin", "invite name persisted")
        check(reopened.messages(ByteArray(32)).isEmpty(), "no history with a stranger")
        reopened.close()
    }
    expectStatus(VoidStatus.LOCKED, "a wrong key reports locked") {
        Engine.open(File(dir, "data"), Random.nextBytes(32), VaultBacking.TEE, System.currentTimeMillis())
    }
    run {
        val reopened = Engine.open(File(dir, "data"), key.copyOf(), VaultBacking.TEE, System.currentTimeMillis())
        check(reopened.fingerprintWords == words, "the wrong key replaced nothing")
        reopened.close()
    }

    println("parsers")
    val reader = ByteReader(byteArrayOf(1, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0xff.toByte()))
    check(reader.u8() == 1, "u8")
    check(reader.u16() == 0x1234, "u16 little-endian")
    check(reader.u32() == 0x12345678L, "u32 little-endian")
    check(reader.u16() == null, "a read past the end is null, not an exception")
    val lying = ByteReader(byteArrayOf(0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0x7f, 0x68))
    check(lying.u32()?.let { lying.string(it.toInt()) } == null, "a length longer than the buffer is refused")
    check(CallEvent.parseAll(byteArrayOf(1, 2, 3)).isEmpty(), "a truncated call event parses to nothing")
    check(ContactEvent.parseAll(ByteArray(10)).isEmpty(), "a truncated contact event parses to nothing")

    println(if (failures == 0) "ALL PASSED" else "$failures FAILED")
    exitProcess(if (failures == 0) 0 else 1)
}
