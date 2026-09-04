# Void

A post-quantum, metadata-minimizing secure messenger.

This repository implements PRD v2.0. It is a **working implementation of the
protocol and infrastructure**, not a shippable product — see
[Status](#status) for exactly what that means.

---

## Status

| Layer | State |
|---|---|
| `void-crypto` — primitives | Working. Classical primitives validated against published test vectors. PQC is now RustCrypto's `ml-kem`/`ml-dsa` — D-006 |
| `void-proto` — protocol | Working: identity, PQXDH handshake, hybrid ratchet, records, sealed deposits, queues, invitations, wake IDs |
| `void-store` — storage | Working: encrypted store, key wrapping, duress destruction, retention, encrypted export |
| `void-relay` — mailbox relay | Working: queues, TTL, rate limiting, stateless retrieval auth, content-free push |
| `void-client` — engine | Working: transport abstraction, constant-rate scheduler, sessions, contacts, restart-survival persistence, duress destruction wired end to end |
| `void-tor` — Tor bootstrap | Working: bootstraps Arti, opens circuits, hands `TorTransport` a live stream. Also publishes and dials the ephemeral onion services calls use. Proven against the real Tor network — see below |
| Calls | Protocol, engine, FFI, JNI, and both platform layers built; transport latency measured on the live network. **Never run between two real devices** — D-024 |
| `void-cli` — reference client | Working. Plain TCP, loudly insecure, development only |
| `void-ffi` — C ABI | Working, including conversations end to end (invite, accept, send, tick, contacts), Tor bootstrap/attach, and duress |
| `ios/` | **Real.** Builds, links, launches, and passes `xcodebuild test` on Simulator, running the actual cross-compiled core — D-019 |
| `void-jni` — JNI ABI | Compiles, for the host. Never cross-compiled for an Android target, never run in a JVM — D-023 |
| `android/` | Gradle-scaffolded, and the JNI shim its Kotlin calls now exists. Still no NDK in this environment, so nothing here has been built or run — D-020 |

### Known gaps — read these before believing the table above

Two things are **not** done:

1. **No external audit.** PRD §11 puts an audited release twelve months out.
   Nothing below substitutes for it, including the differential tests
   mentioned next — those catch disagreement between two implementations,
   not a flaw both share, and they are not an ACVP run.
2. **Android has no working build.** See D-020 and D-023. The Gradle project,
   the Kotlin, and now the JNI shim (`crates/void-jni`) are all structurally
   real, and the shim compiles — for macOS, which is not where it runs.
   `cargo check -p void-jni --target aarch64-linux-android` still fails for
   want of an NDK, so nothing in `android/` has been compiled or run, unlike
   every other row in the table above.

**Closed since the table above was last wrong:**

- **The engine now persists.** `Ratchet::serialize`/`deserialize`
  (`docs/PROTOCOL.md#66-serialized-state-persistence`) covers the full ratchet
  including the skipped-key map; `Engine::new_persisted` and `Engine::restore`
  wire sessions, contacts, messages, queue secrets, settings, and the outbox to
  `void-store`, with the retention sweep running on launch and periodically;
  and `Engine::duress_destroy` plus `void-ffi`'s `void_pin_check` /
  `void_engine_duress_destroy` wire duress destruction from PIN entry through
  to an unopenable database. Restart-survival and duress integration tests
  live in `crates/void-client/tests/persistence.rs` and
  `crates/void-client/tests/duress.rs`.
- **Tor is real.** `void-tor` bootstraps Arti and opens circuits to onion
  addresses; `void-client::transport::TorTransport` now takes any
  `Read + Write + Send` stream rather than a literal `TcpStream`, because an
  Arti circuit is not one. `void-ffi` exposes `void_tor_bootstrap` and
  `void_engine_attach_tor` as the two calls a platform layer needs.
  `crates/void-tor/tests/live_tor_circuit.rs` is a real, not simulated,
  end-to-end test: it hosts an actual onion service (via the system `tor`
  binary) fronting a real `void-relayd`, bootstraps Arti against the live Tor
  network, and drives a full frame exchange over that circuit. It is
  `#[ignore]`d by default — see the test file for why and how to run it —
  but it has been run and it passes.
- **The PQC crate swap landed.** `mlkem` and `mldsa` are thin wrappers over
  RustCrypto's `ml-kem` and `ml-dsa` — no protocol code above the `Kem` /
  `SignatureScheme` traits changed. The clean-room implementations they
  replaced are kept as `mlkem_reference` / `mldsa_reference`, test-only, as a
  differential-test oracle (`void-crypto/src/differential.rs`): same seeds
  in, byte-identical public keys, ciphertexts, shared secrets, and
  (deterministic) signatures out, across both implementations. It passes.
  `scripts/check_deps.sh` now allows exactly these two dependencies,
  exact-version-pinned. See D-006 and D-018.
- **The iOS app is real, not scaffolding.** `scripts/build_ios.sh`
  cross-compiles `void-ffi` for device and simulator, generates its C header
  with `cbindgen`, and packages both into `Void.xcframework`; `ios/project.yml`
  (via `xcodegen`) produces a real `.xcodeproj` linking it. The engine's
  conversation surface (`void_engine_create_invite`, `_poll_intro_queue`,
  `_accept_conversation`, `_start_conversation`, `_send`, `_tick`,
  `_contacts`) is wired into `AppState.swift`, which drives the existing
  `ConversationViews`/`OnboardingViews`/`SecuritySettingsViews` — not mock
  data. `xcodebuild build` and `xcodebuild test` both succeed for
  `iphonesimulator`, and the app has been installed and launched on a booted
  Simulator, reaching the onboarding screen on a live, cross-compiled
  identity. See D-019 for the pipeline and the two build-time gotchas it
  needed. What it does *not* yet do: persist across launches, use Tor, or
  hold keys in the Secure Enclave — `AppState.swift`'s header comment lists
  exactly what's left.

**What "Tor is real" does not yet mean.** Nothing in `ios/` or `android/`
calls `void_tor_bootstrap` yet (that lands with the app work below), and the
onion service in the test above is host-side C-tor for the test's own
convenience, not a deployed relay — standing up the *production* relay as a
long-running onion service is a deployment task, not a code gap.

**Do not use this to protect anyone.** Not because it is sloppy — the security
properties listed below are real and tested — but because "the cryptography is
right" and "this is safe for a journalist's source" are very different claims,
and only the first one is defensible today.

---

## What is actually true here

Claims are cheap. Each of these is enforced by a test whose name is given, and
`cargo test --workspace` runs all of them.

- **A relay cannot read messages** — `the_relay_never_sees_plaintext`
- **A relay cannot tell who sent one** — there is no sender field in the wire
  format at all: `the_deposit_contains_no_sender_field`
- **A relay cannot link two of your queues** —
  `the_relay_cannot_link_two_queues_of_one_user`
- **A relay cannot move a message between queues** —
  `a_relay_that_moves_a_deposit_between_queues_is_detected`
- **A relay cannot kill a conversation by redelivering an old record** —
  `a_relay_redelivering_an_old_record_cannot_kill_a_conversation`
- **A message that does not authenticate changes no state at all** —
  `a_failed_decrypt_leaves_no_trace_in_the_state`
- **A relay cannot tell a call from a message** —
  `call_signalling_is_indistinguishable_from_a_message_to_the_relay`
- **Both directions of call audio use different keys** —
  `the_two_directions_use_different_keys`
- **A relay holds no key material, even for retrieval auth** —
  `a_key_that_does_not_address_the_queue_is_refused`
- **Every deposit is the same size** —
  `every_deposit_the_relay_sees_is_the_same_size`
- **Send timing does not depend on whether you are sending** —
  `emission_is_constant_rate_regardless_of_traffic`
- **Losing the network queues messages rather than falling back** —
  `a_client_that_loses_the_relay_queues_rather_than_failing_open`
- **A changed identity key blocks messaging** —
  `sending_to_a_contact_whose_key_changed_is_blocked`
- **Duress destruction is total and irreversible** —
  `a_destroyed_vault_makes_the_database_unopenable`
- **A forged prekey bundle is refused before any secret is computed** —
  `tampered_bundle_is_rejected_before_any_secret_is_computed`

And two things that are *not* true, stated here rather than buried:

- Void does not protect a compromised device.
- Void does not hide that it is installed, and gives you nothing to show
  instead. See PRD §7.4.1 for why that is deliberate.

---

## Layout

```
crates/
  void-crypto   primitives — zero third-party dependencies, CI-enforced
  void-proto    the protocol — no I/O, no sockets, pure logic
  void-store    encrypted storage, key wrapping, duress, retention, export
  void-relay    the untrusted mailbox relay
  void-client   engine: transport, scheduler, sessions
  void-tor      bootstraps Arti; the only crate with an async runtime
  void-ffi      the C ABI — the only crate permitted `unsafe`
  void-cli      reference client and relay daemon
docs/
  PROTOCOL.md   the wire specification
  DECISIONS.md  every decision, why, what it cost, how to reverse it
ios/, android/  native clients
scripts/        the CI checks that enforce the non-negotiables
```

---

## Building

```sh
cargo test --workspace          # 350+ tests
cargo build --release
```

The core has **no third-party dependencies at all**. This started as a
constraint — the build environment had no package registry — and turned out to
be worth keeping for `void-crypto`, where NFR-SEC-07 makes every dependency
expensive to justify. `scripts/check_deps.sh` fails the build if that changes.

### Trying it end to end

```sh
# terminal 1
cargo run --bin void-relayd -- --listen 127.0.0.1:9443

# terminal 2 — prints an invitation link
cargo run --bin void -- invite 127.0.0.1:9443

# terminal 3 — paste the link
cargo run --bin void -- accept 127.0.0.1:9443 'void://c/...#...'
```

The CLI prints a warning on every invocation because it uses plain TCP and gives
you no anonymity whatsoever. That is deliberate: a tool that is *quietly*
insecure is how a bypass ends up in a release.

---

## The CI checks are the point

PRD non-negotiables #3 and #4 say "enforced by CI, not by policy". A policy is
something someone forgets; a failing build is not.

```sh
./scripts/check_banned_symbols.sh    # FR-TRANS-02: no WebRTC/ICE/STUN/TURN
./scripts/check_no_direct_network.sh # FR-TRANS-03: no network outside Tor
./scripts/check_deps.sh              # NFR-SEC-07 + NFR-SEC-02
./scripts/check_reproducible.sh      # NFR-SEC-04: bit-identical core
```

The reproducibility check covers the **Rust core only**. The App Store re-signs
and re-encrypts the app binary, so a locally built copy provably will not match.
PRD §8.1 says so; pretending otherwise would be a promise broken on day one.

One more check exists but does not run in CI, by design:

```sh
cargo test -p void-tor --test live_tor_circuit -- --ignored --nocapture
```

A real end-to-end test over the live Tor network — see
`crates/void-tor/tests/live_tor_circuit.rs` for why it needs the system `tor`
binary and unfiltered internet access, neither of which a routine CI run
should require to pass.

---

## What was decided while building this

[`docs/DECISIONS.md`](docs/DECISIONS.md) has all twenty entries. The ones worth
knowing about before reading the code:

- **D-005** — the ML-KEM ratchet runs every 4 DH steps, not every step. Doing it
  every step costs 3.2 KB *per message* because the KEM material must repeat
  across a chain for loss tolerance, and NFR-PERF-03's bandwidth budget does not
  survive that. Harvest-now-decrypt-later resistance is unaffected.
- **D-011** — queue retrieval is an Ed25519 signature over a relay challenge,
  not a MAC. A MAC needs the relay to hold verification keys, which creates a
  first-registration race and puts key material on the machine §9.1 assumes will
  be seized. The queue id *is* a hash of the public key, so verification is
  intrinsic and the relay stores nothing.
- **D-014** — retrieval jitter is quantised to the emission grid. Unquantised
  jitter produces a frame at a moment no other frame would appear, which tells
  an observer the client just checked its queue.
- **D-006** — the PQC modules are now RustCrypto's `ml-kem`/`ml-dsa`, with the
  original clean-room code kept only as a differential-test oracle.
- **D-009** — Arti lives in its own crate (`void-tor`), so the async runtime
  never enters `void-client`'s dependency graph. `TorTransport` takes any
  `Read + Write + Send` stream, not a `TcpStream`, because that is what makes
  bridging an Arti circuit to it possible at all.
- **D-016** — a `Store` trait, not a generic `Engine<B: Backend>`, for the same
  reason `Engine` already holds its transport as `Box<dyn Transport>`.
- **D-017** — duress destruction splits at the FFI boundary: the platform
  destroys its own hardware vault key directly (a `SecItemDelete` call has no
  reason to round-trip through Rust), and `Engine::duress_destroy` erases the
  local store and RAM.
- **D-019** — the iOS project is generated (`xcodegen` from `project.yml`),
  never hand-edited, and two build-time gotchas are recorded there: C enums
  share one namespace unlike Rust's, and Arti's `rusqlite` dependency needs
  `libsqlite3.tbd` linked explicitly.
- **D-020** — the Android app is Gradle-scaffolded but not JNI-wired, and
  says so specifically rather than looking finished: there was no NDK
  available to write or test the JNI shim `void-ffi` needs against.
- **D-021** — the ratchet's receive path stages every state change and commits
  only after the AEAD tag verifies. Without that, a relay could permanently
  kill a conversation by handing back one sealed record it had already
  delivered — the stale ratchet key in it looks exactly like a new chain, so
  the receiver stepped its root key somewhere the peer would never follow.
- **D-022** — a full reassembly buffer evicts its stalest partial message
  rather than erroring, because fragments go missing for ordinary reasons
  (TTL expiry, a queue rotation) and the old behaviour turned sixty-four of
  those into a contact that never received again.
- **D-024** — calls run over paired ephemeral onion services, so media never
  touches the relay. Signal/Discord-style calling is WebRTC over UDP, and Tor
  carries no UDP at all; running it outside Tor would put both IP addresses on
  the wire. Measured mouth-to-ear on the live network is 470–870 ms, which the
  UI states rather than hides. A disclosure is shown before every call, in
  both directions — and it does **not** claim calls reveal your location,
  because media is Tor both ways and that would be false. It names what is
  actually true: the other person learns you are online, and a call's traffic
  shape is nothing like messaging's constant-rate padding.

---

## Licence

AGPL-3.0-or-later, including the relay server (NFR-SEC-06).
