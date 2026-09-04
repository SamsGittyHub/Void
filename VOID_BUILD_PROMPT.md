# Prompt for Claude Code — finish Void and ship both apps

Paste everything below the line into Claude Code, with the `void/` repo as the
working directory.

---

You are continuing work on **Void**, a post-quantum, metadata-minimizing secure
messenger. The Rust core, the mailbox relay, the client engine, and the FFI
boundary already exist and pass 337 tests. Your job is to close the remaining
integration gaps and build shippable iOS and Android apps.

## Read these first, before writing any code

1. `README.md` — current status and the four known gaps
2. `docs/DECISIONS.md` — 15 decisions with reasoning, cost, and reversal cost
3. `docs/PROTOCOL.md` — the wire specification
4. `Void_PRD_v2.md` — the product requirements, if present in the repo

`docs/DECISIONS.md` is the important one. Several decisions there look
arbitrary and are not — D-005, D-011, and D-014 each exist because the obvious
approach was tried and failed for a reason that is documented. **Do not
"simplify" them without reading why they are the way they are.**

## Environment

You need network access for `cargo`. The original build had none, which is why
every cryptographic primitive is hand-implemented and the workspace has zero
third-party dependencies. That constraint is lifted for you, but see
"Dependency policy" below — it does not mean add dependencies freely.

---

## Work, in priority order

### 1. Persistence — the largest gap

The engine holds everything in RAM. `void-store` is complete and tested but
nothing calls it. A restart loses every conversation.

**1a. Ratchet state serialization.** `void_proto::ratchet::Ratchet` has no way
to save itself. Add `serialize()` / `deserialize()` covering: root key, both
chain keys, the X25519 keypair, both ML-KEM keypairs plus the retained previous
generation, all epoch counters, message numbers, `previous_chain_len`, the
skipped-key map, and `dh_steps_since_kem`.

Requirements:
- Hand-written encoding via `void_proto::wire`, matching the style of
  `Header::encode`. No serde — see the reasoning at the top of `wire.rs`.
- Round-trip tests, including mid-conversation: serialize a ratchet after a
  partial exchange, restore it, and confirm the conversation continues.
- A test that a deserialized ratchet still rejects replays — the skipped-key
  map must survive, or forward secrecy silently weakens on every restart.
- Extend `docs/PROTOCOL.md` with the serialized layout.

**1b. Wire the engine to the store.** Give `Engine` a `Database<B>` and persist
sessions, contacts, messages, queue secrets, settings, and the outbox. The
`Kind` enum in `void-store/src/db.rs` already has variants for all of these.

Requirements:
- Restart-survival test: build an engine, exchange messages, drop it, rebuild
  from the same store, and confirm the conversation continues and history is
  intact.
- Messages must be stored with the expiry from `Engine::message_expiry` so the
  retention sweep (FR-STOR-04) actually applies to them.
- The retention sweep must run — on launch and periodically.

**1c. Duress destruction must work end to end.** `void-store` can destroy a
vault key; nothing triggers it. Wire the lock screen path: PIN entry →
`PinVerifier::check` → on `Duress`, destroy the vault, wipe in-memory state, and
present a first-run screen. Test that the database is unopenable afterward.

### 2. Tor

`void_client::transport::TorTransport::from_stream` takes a stream the platform
has already routed. Nothing produces one.

- Add Arti behind a feature flag, in a **separate crate** (`void-tor`), so the
  async runtime stays out of `void-client`'s dependency graph. `docs/DECISIONS.md#d-009`
  explains why that separation matters.
- Bootstrap Arti, connect to the relay's `.onion`, hand the stream to
  `TorTransport::from_stream`.
- FR-TRANS-04: the onion address *is* the relay's public key. Pin it. No
  certificate authority anywhere.
- FR-TRANS-05, non-negotiable #5: **fail closed.** If Tor is unavailable,
  messages queue. Do not add a retry path that falls back to direct TCP. There
  must be no code path that can send outside Tor.
- `scripts/check_no_direct_network.sh` must still pass. Add `void-tor` to its
  allow-list with a comment saying why.

### 3. Replace the post-quantum implementations

`void-crypto`'s `mlkem` and `mldsa` are clean-room implementations that have
**not** been validated against NIST ACVP vectors. See `docs/DECISIONS.md#d-006`.

- Swap in the RustCrypto `ml-kem` and `ml-dsa` crates behind the existing `Kem`
  and `SignatureScheme` traits. Nothing above the traits should change.
- Keep the current implementations as a differential-test oracle: a test that
  runs both and asserts identical outputs is the cheapest way to find out that
  one of them is wrong.
- If the differential test fails, **the hand-written one is wrong** — treat that
  as the expected outcome and fix or delete it, do not "fix" the audited crate.
- Update the warning in `void-crypto/src/lib.rs` and the D-006 entry once this
  lands. That warning currently says these are not fit for production; it must
  stop saying that only when it stops being true.

### 4. iOS app

`ios/Void/` has real SwiftUI screens implementing the PRD's UI requirements, but
no Xcode project and nothing calls the FFI.

Build a complete app:
- Xcode project, `xcodebuild`-able from CI, iOS 16 minimum (NFR-COMP-01)
- Build the Rust core as a static library for `arm64` device and simulator; XCFramework
- Generate a C header for `void-ffi` (cbindgen) and a bridging header
- **Secure Enclave key wrapping.** Implement `KeyVault` per FR-ID-02: a P-256
  key with `kSecAttrTokenIDSecureEnclave`,
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, access control requiring user
  presence. It wraps a DEK — it does not hold the PQC keys, and FR-ID-02a
  requires the whitepaper and UI to say so.
- Duress destruction = `SecItemDelete` on that key. Must complete in under
  500 ms and be uninterruptible (FR-STOR-02).
- `isExcludedFromBackup` on the data directory, `NSFileProtectionComplete` on
  all files (FR-STOR-05)
- Disable the app-switcher snapshot for conversation views (FR-STOR-06)
- APNs registration against a **rotating wake identifier**, not a user identity
  (FR-NOTIF-03). Push is **off by default** (FR-NOTIF-04).
- Wire up the existing screens: `OnboardingViews`, `ConversationViews`,
  `SecuritySettingsViews`. They are written against the FFI shape; connect them
  to a real `VoidCore`.
- QR scanning and generation for contact establishment (FR-DISC-01)
- Full VoiceOver support. Security-critical states — verification, key change,
  duress setup — must be conveyed non-visually (NFR-COMP-04). The fingerprint
  comparison view already spells syllables letter by letter for this reason.
- `ITSAppUsesNonExemptEncryption` set correctly in `Info.plist` (FR-DIST-03)
- Privacy nutrition label: "Data Not Collected" in every category (FR-DIST-04).
  This must be *true*, which it is only if nothing you add phones home.

### 5. Android app

`android/app/src/main/kotlin/app/void/` has Compose screens. Same job.

- Gradle project, `assembleRelease`-able from CI, API 30 minimum (NFR-COMP-02)
- Rust core as a `cdylib` for `arm64-v8a` and `x86_64`; JNI bindings for
  `void-ffi`
- **StrongBox preferred, TEE fallback, and the difference surfaced in the UI**
  (NFR-COMP-02). `VaultBacking.detect()` and `KeyStorageScreen` already exist
  for this — a user on a device without StrongBox must be told it is weaker,
  not shown the same padlock.
- `FLAG_SECURE` on conversation activities (FR-STOR-06)
- FCM against a rotating wake identifier; off by default
- Direct-APK build with published signing keys and reproducible core hashes
  (FR-DIST-06)

---

## Non-negotiables — do not weaken these

From the PRD. Each is already enforced by a CI script in `scripts/`. If a check
starts failing, fix the code, not the check.

1. **No relay ever holds plaintext.**
2. **No phone numbers, emails, or real-world identifiers.** Ever, in any flow.
3. **No network traffic outside Tor.** No exceptions for analytics, crash
   reporting, or update checks. Adding Sentry or Crashlytics breaks the
   "Data Not Collected" label, which is a lie in an App Store listing.
4. **WebRTC, ICE, STUN, TURN are banned.** They leak the real IP by design.
5. **Fail closed.** If Tor is unavailable, messages queue. There is never a
   fallback path.
6. **The Rust core is reproducibly built and transparency-logged**, and the
   store-delivered binary is not — say so, do not claim otherwise.
7. **No cross-platform runtime in the trusted path.** Native Swift and Kotlin.
8. **No dark patterns on security choices.** Push, retention, and duress
   settings state the cost of each option. The existing screens do this; keep it
   when you restyle them.
9. **Residual risks are documented in the product**, not only in a whitepaper.
10. **Do not claim guarantees you cannot demonstrate.** If a property is not
    verifiable by an external auditor, it does not go in marketing copy, the App
    Store listing, or the UI.

Item 10 governs everything else. When you finish, the README's status table and
gap list must still be accurate — update them as things land, and do not delete
a gap until it is genuinely closed.

## Dependency policy

NFR-SEC-07: every crate in the trusted path is pinned, vendored, and reviewed.
`scripts/check_deps.sh` currently fails the build if `void-crypto` gains *any*
dependency. When you swap in the PQC crates, update that check deliberately and
narrowly — allow exactly `ml-kem` and `ml-dsa`, pinned, and say so in the
script's comment.

`unsafe` stays confined to `void-ffi`. Every other crate has
`#![forbid(unsafe_code)]` and the check enforces it. JNI glue goes in
`void-ffi`, not in a new crate that quietly permits `unsafe`.

## Traps that already cost time

- **KEM material must repeat in every header of a chain.** If only the first
  message carries it, losing that message kills the session. This is why
  `KEM_RATCHET_INTERVAL` exists (D-005). Do not set it to 1 to "improve
  security" — read the bandwidth arithmetic first.
- **Retrieval jitter must stay quantised to the emission grid** (D-014). An
  off-grid frame tells an observer the client just checked its queue.
- **Do not add a queue-key registry to the relay** (D-011). Retrieval auth is a
  signature precisely so the relay holds nothing.
- **A prekey bundle publishes a `DepositKey`, never a `QueueSecret`** (D-012).
  The type split is the enforcement.
- **The engine's key-change check is in exactly one place** — `Engine::send`.
  Keep it there. A UI that forgets to grey out the send button must still be
  unable to send.

## Verification — required before you call anything done

```sh
cargo test --workspace                 # all tests
cargo test --workspace --release       # overflow checks on; the ratchet counter matters
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
./scripts/check_banned_symbols.sh
./scripts/check_no_direct_network.sh
./scripts/check_deps.sh
./scripts/check_reproducible.sh
```

Plus, new:
- A restart-survival integration test
- A differential test between the old and new PQC implementations
- An end-to-end test over a **real Tor circuit** to a relay onion service
- `xcodebuild test` and `./gradlew test` wired into `.github/workflows/ci.yml`
- The `dudect` constant-time job in CI is currently a stub that prints a TODO.
  Implement it over `ct::eq`, `Poly1305::verify`, `mlkem::decaps`, and
  `PinVerifier::check`. NFR-SEC-03 requires measurement on the built artifact;
  source review cannot establish it.

## How to work

- Work in priority order. Persistence first — it is what makes everything else
  testable as an application rather than a protocol.
- Every new security property gets a test whose name states the property, in the
  style of the existing suite (`the_relay_cannot_link_two_queues_of_one_user`,
  `a_client_that_loses_the_relay_queues_rather_than_failing_open`).
- When you make a decision that departs from the PRD or resolves something it
  left open, add an entry to `docs/DECISIONS.md` in the existing format: what,
  why, what it costs, how to reverse it.
- When you change the wire format, update `docs/PROTOCOL.md` in the same commit.
- If you find that something in `docs/` is wrong, fix the document. A
  specification that has drifted from the code is worse than none.

## What "done" means

A user can install Void from TestFlight or an APK, generate an identity offline,
scan a contact's QR code, exchange messages over Tor through a relay, close the
app, reopen it a week later and find the conversation still there, set a duress
PIN and have it destroy everything in under half a second.

And the README's gap list is empty except for "no external audit" — because that
is the one thing you cannot do yourself.
