# Void — Decisions Log

Every decision here was open in PRD v2.0 and had to be closed to write code.
Each entry states what was decided, why, what it costs, and what it would take
to reverse. Entries that resolve a numbered PRD open question say so.

The point of this file is that a future reader — an auditor, a funder, or the
person who picks this up in two years — can tell the difference between a
decision that was reasoned about and one that was defaulted into.

---

## D-001 — ML-KEM-1024, not ML-KEM-768

**Resolves:** PRD §13.1 (partially)

ML-KEM-1024 throughout. Signal's PQXDH chose Kyber-1024 and matching a widely
reviewed deployment has real value: it means our parameter choice is not a novel
one an auditor has to reason about independently.

**Cost.** 1,568-byte encapsulation keys and ciphertexts, against 1,184/1,088 for
ML-KEM-768. At the ratchet's KEM step that is ~3.2 KB versus ~2.3 KB — four
records instead of three at the current record size.

**Reversal.** One constant in `void-crypto/src/mlkem.rs` (`K`) plus the derived
size constants. The protocol identifier in `void-proto::handshake::PROTOCOL_ID`
must change with it, so old and new clients cannot silently interoperate.

---

## D-002 — ML-DSA-87, confined to the handshake

**Resolves:** PRD §13.1's sharper question, in the affirmative

PRD §13.1 asks: *"can the protocol authenticate per-message from ratchet state
alone, restricting ML-DSA to handshake and re-keying? If yes, ML-DSA-87 costs
little and should stay."*

Yes, and it does. Per-message authentication comes from the ratchet's AEAD tag:
possession of the message key proves membership in the chain, and the chain is
rooted in a handshake both parties signed. An identity signature per message
would add nothing that the ratchet does not already provide, and would put a
4,627-byte floor under every "ok".

So ML-DSA-87 signatures appear in exactly two places: the prekey bundle, and the
initiator's transcript signature. Both are once per conversation.

**Cost.** A hybrid signature is 4,693 bytes encoded. A prekey bundle is
therefore about 9 KB — far more than one QR code carries, which is why an
invitation is a short link with the bundle parked on the relay (D-027).

**Reversal.** Dropping to ML-DSA-65 saves 1.3 KB per signature. The parameter
lives in `void-crypto/src/mldsa.rs`.

---

## D-003 — Three identity keys, not XEdDSA

Void's identity is Ed25519 + ML-DSA-87 + a **separate** X25519 key. Signal
derives its DH key from its Ed25519 key using XEdDSA, avoiding the third key at
the cost of a birational map between Edwards and Montgomery forms plus sign
handling that has historically been a source of subtle bugs.

**Cost.** 32 extra bytes in every identity encoding, and a third seed to back
up.

**Why it is worth it.** The bug class XEdDSA introduces is precisely the kind
that passes tests and fails audits. Thirty-two bytes is a cheap price for
deleting it.

---

## D-004 — Proquints for fingerprints, not BIP-39

**Relates to:** FR-ID-03, which says "BIP-39-style"

BIP-39's English wordlist is the obvious choice and Void does not use it.
Proquints — consonant-vowel-consonant-vowel-consonant syllables from a
20-character alphabet — are generated from ten lines of code, so there is no
2,048-word data file whose integrity has to be established and pinned, and the
syllables are pronounceable by most readers of Latin script rather than only by
English speakers.

**Cost.** `lusab-babad` is less memorable than `abandon-ability`. Void does not
ask users to *recall* a fingerprint, only to *compare* one, and for comparison
the difference is small.

**Mitigation.** Both renderings are offered: syllables, and Signal-style decimal
groups for reading aloud. The accessibility path spells syllables letter by
letter, because a screen reader pronouncing an invented word is not something
two people can reliably match.

---

## D-005 — The ML-KEM ratchet runs on a schedule

**The decision that took the most thought.**

The Diffie-Hellman half of the ratchet steps on every direction change, as in
the original Double Ratchet. The ML-KEM half steps every
`KEM_RATCHET_INTERVAL` = 4 DH steps.

**Why not every step.** A KEM step must carry a 1,568-byte encapsulation key and
a 1,568-byte ciphertext, and — the part that is easy to miss — it must repeat
them in *every* header of that sending chain. If only the first message of a
chain carried the KEM material, losing that message would leave the peer unable
to take the matching step, and the session would be dead. That repetition is
what makes per-step KEM unaffordable: a 50-message unidirectional burst would
carry 3.2 KB fifty times, which is 200 records where 50 would do, and
NFR-PERF-03's 50 MB/month budget does not survive it.

**What this costs, precisely.** Post-compromise security against a *quantum*
adversary is restored within four ratchet steps of an intrusion rather than one.
Post-compromise security against a *classical* adversary is unchanged — that is
the DH half, which still runs every step.

**What it does not cost.** G1 — harvest-now-decrypt-later resistance — is
unaffected and holds unconditionally from the first message, because the initial
handshake is fully hybrid. An adversary recording traffic today cannot decrypt
it with a future quantum computer regardless of the schedule.

This is the same structural choice Apple's PQ3 and Signal's SPQR make, for the
same reason.

**Reversal.** One constant. Setting it to 1 restores per-step KEM at the
bandwidth cost above; the code path is identical.

---

## D-006 — The PQC implementations are not production-ready — migration landed

`void-crypto`'s `mlkem` and `mldsa` were clean-room implementations written
from FIPS 203 and FIPS 204. They passed round-trip, cross-key, tamper,
determinism, and structural tests, and their NTTs were checked against
schoolbook multiplication — but they had never been validated against the
NIST ACVP vector set, because the original build environment had no network
access to fetch it.

**The migration this entry originally proposed has landed.** `mlkem` and
`mldsa` are now thin wrappers over the RustCrypto `ml-kem` and `ml-dsa`
crates — network access to fetch and pin them was available by the time
this migration was done, closing the reason the original implementation
existed at all. `scripts/check_deps.sh` allows exactly these two
dependencies, exact-version-pinned, and nothing else. The clean-room
implementations are kept as `mlkem_reference` / `mldsa_reference`, compiled
only for tests, and `void-crypto/src/differential.rs` runs both
implementations against the same deterministic inputs and asserts
agreement — the tests pass, which is the closest thing to independent
confirmation this codebase can produce without ACVP access of its own.

Everything above the `Kem` and `SignatureScheme` traits — `void-proto` and
everything built on it — is written against `mlkem` and `mldsa`'s function
*signatures*, not their internal types, so the swap touched no protocol
code. It changed two things worth knowing about, both covered in their own
module docs and in D-018: the ML-KEM decapsulation key and ML-DSA secret key
are now stored as seeds rather than expanded forms (smaller, and it's what
the audited crates prefer; neither ever crossed the wire, so nothing
interoperability-relevant changed), and ML-DSA signing is now deterministic
rather than hedged.

**What this migration does not close.** RustCrypto's `ml-kem`/`ml-dsa` are
widely reviewed, but this codebase has not independently run NIST's ACVP
vectors against them either — that claim belongs to upstream, and repeating
it here without having done so would be exactly the kind of claim
non-negotiable #10 forbids. What changed is *whose* implementation Void now
trusts for this: a maintained, widely-depended-on crate instead of a
from-scratch one nobody but this codebase had ever exercised.

---

## D-018 — ML-DSA signing is deterministic, not hedged, after the RustCrypto swap

**Deviates from:** the pre-migration implementation's choice

FIPS 204 permits two signing variants: *deterministic* (the randomizer `rnd`
is fixed at all-zero) and *hedged* (`rnd` is fresh random bytes mixed into
every signature). The clean-room implementation D-006 replaced used hedged
signing in its public `sign()` — defence in depth against fault-injection
attacks, where an attacker who can induce a hardware glitch during signing
tries to recover the secret key from a corrupted signature.

The RustCrypto `ml-dsa` crate's ergonomic `Signer` trait implementation uses
the deterministic variant, and does not expose hedged signing without
reaching into `ExpandedSigningKey`'s lower-level randomized-signing API and
bridging Void's own RNG into `rand_core`'s traits to use it.

**The choice: take the deterministic variant as-is.** Fault injection is a
threat model for smartcards, HSMs, and other hardware under an attacker's
physical control during the signing operation — not a phone running Void as
an ordinary app under the OS's normal process isolation. Bridging a custom
RNG adapter into a lower-level API to preserve a defence against a threat
outside Void's model was judged not worth the additional code in the trusted
crypto path (NFR-SEC-07 makes every line there expensive to justify).

**What is unaffected.** Signature *unforgeability* — the property that
actually protects the handshake and key-change events D-002 confines ML-DSA
signatures to — does not depend on which variant produced the signature;
both are secure signing procedures under FIPS 204. `void-crypto/src/differential.rs`
pins the deterministic variant specifically, comparing `mldsa::sign` against
the reference implementation's `sign_with_rnd(..., &[0u8; 32])`.

**Reversal.** If Void's threat model ever needs to account for physical
fault-injection (for example, a hardware wallet-style deployment), bridging
`ExpandedSigningKey`'s `RandomizedSigner` into `crate::rand` is a contained
change inside `mldsa.rs` — nothing in `void-proto` or above would need to
change, for the same reason the original swap didn't touch it.

---

## D-007 — An encrypted record log, not SQLCipher

**Deviates from:** FR-STOR-01, which names SQLCipher

Same shape — a database encrypted under an Argon2id-derived, hardware-wrapped
key — implemented as a self-contained encrypted record log because this build
environment has no package registry and SQLCipher is a C library.

The `Backend` trait is the seam. The migration is: implement `Backend` over
`rusqlite` with the `sqlcipher` feature, keep the per-record AEAD as defence in
depth, change nothing above it.

**What the current implementation does that SQLCipher would not.** Per-record
keys derived from the DEK and the record id, and a header authenticated as
associated data by every record — so a header edit invalidates the whole file
rather than being silently accepted. Both are worth keeping after the migration.

---

## D-008 — Thread-per-connection, no async runtime

The relay uses standard-library sockets and one thread per connection. This is
not performance-optimal and it is deliberate: NFR-SEC-07 makes every dependency
in the trusted path expensive to justify, and an async runtime is a very large
one.

A relay serves fixed-size frames over Tor, where circuit latency dominates by
orders of magnitude. Thread-per-connection is comfortably sufficient at any
plausible scale for this product.

**Reversal.** If a relay ever needs tens of thousands of concurrent circuits,
`serve_connection` is a pure function of (frame, store, clock) and can be driven
by anything.

---

## D-009 — Arti, via a platform-supplied stream

**Resolves:** PRD §13.2

Arti, for the reason NFR-SEC-02 gives for everything else: Rust, memory-safe,
matching the posture of the rest of the core. Void needs only the *client* side
of onion services — connecting outward to a relay's onion address — which is the
mature half of Arti's onion support, not the service-hosting half.

**How it is integrated.** `void-tor` bootstraps Arti and hands the core a
connected stream through `TorTransport::from_stream`. The async Tor runtime
therefore never enters `void-client`'s dependency graph — `void-tor` is the
only crate in the workspace depending on `arti-client` or `tokio`, and
`scripts/check_deps.sh`'s per-crate `#![forbid(unsafe_code)]` check still
applies to it like every other crate outside `void-ffi`.

**What `TorTransport::from_stream` actually takes.** Not a `TcpStream` — a
`DataStream` from an Arti circuit is not one; it is a layered, encrypted
stream with no OS socket of its own to hand out. The signature is generic
over anything `Read + Write + Send` (the `TorStream` marker trait in
`transport.rs`), and `void-tor` bridges Arti's async `DataStream` to that
blocking contract itself, one call at a time, on the runtime it owns. Nothing
about `void-client`'s side of the seam changed: it still just reads and
writes bytes.

**What this means for the claim.** `TorTransport::from_stream` *trusts* its
caller to have actually routed the stream. Nothing in the core can verify that.
The verification that matters is the CI check in
`scripts/check_no_direct_network.sh`, which fails the build if any crate outside
`void-tor` and the documented seam can open a socket.

**Bootstrap has no partial-success path.** `TorHandle::bootstrap` blocks until
Arti has enough directory material to build circuits, or returns `Err`. A
caller gets a working way to reach the network or a reason to queue and
retry — never a client in some third, in-between state that might tempt a
caller into sending through it anyway (FR-TRANS-05).

---

## D-010 — A hand-written C ABI, not UniFFI

**Deviates from:** PRD §11 Phase 3, which says "UniFFI bindings"

UniFFI is the right tool and should be adopted. This crate is a hand-written C
ABI because no package registry was reachable, and because writing the boundary
out once makes it explicit — which for the one place a memory-safe core meets
platform-managed memory is worth doing deliberately.

`void-ffi` is the only crate in the workspace without `#![forbid(unsafe_code)]`,
which is exactly the "small, explicitly enumerated and separately reviewed FFI
boundary" NFR-SEC-02 permits.

---

## D-011 — Queue retrieval is a signature, not a MAC

**Not an open question in the PRD. It became one while building.**

The obvious construction for "prove you may collect from this queue" is a MAC
over a relay-issued challenge. It does not work, and the reason is worth
recording because it is not obvious until you try to deploy it.

A MAC is checkable only by someone holding the key. So the relay needs a
registry mapping queue id to verification key. That registry has two problems it
cannot solve:

1. **A first-registration race.** Whoever registers a queue id first owns it. A
   contact who knows your queue id — and they must, to deposit — could claim it.
2. **Key material on the relay.** §9.1 assumes a relay will eventually be
   seized. A pile of per-queue verification keys is exactly the "user record to
   produce" the design promises does not exist.

**What Void does instead.** The queue identifier *is* a hash of an Ed25519
public key:

```
retrieval seed = KDF(queue secret, "queue/auth", generation)
signing key    = Ed25519(retrieval seed)
queue_id       = KDF("queue/address", public key)[0..16]
```

A collector presents the public key and a signature over the challenge. The
relay recomputes the identifier from the key, checks it addresses the queue
being requested, and verifies the signature. **It holds nothing and registers
nothing.** There is no race, because only a party who can derive the queue
secret can produce a key that hashes to that identifier.

**Cost.** A `Retrieve` frame grows from 80 to 144 bytes, which disappears
entirely into the fixed 2,048-byte frame.

**Bonus property.** Publishing a `DepositKey` — which an invitation must do —
stays safe, because it carries a *hash* of the public key, never the key.

---

## D-012 — Deposit and retrieval capabilities are separate types

`DepositKey` carries a queue id and an envelope key. `QueueSecret` carries the
seed from which both that and the retrieval signing key derive.

This exists because a prekey bundle must be publishable. The initiator of a
handshake holds only what the bundle gave them and has no shared secret with the
responder yet — so they cannot derive an envelope key, and the bundle must
publish one. Publishing the whole `QueueSecret` would also hand out collection
authority.

Making it a distinct type rather than a documented convention means the compiler
enforces it: `envelope::seal` takes a `DepositKey`, and there is no function
anywhere that turns one back into a `QueueSecret`.

---

## D-013 — Post-handshake queues are derived, not negotiated

An earlier draft had each party choose a queue and send it to the other. That
works, but it puts a party-chosen value in the transcript and creates a
question — what if they choose badly, or maliciously?

Instead the handshake's KDF produces 64 bytes: 32 seed the ratchet root, 32 seed
a pair of per-direction queues. Both parties derive both queues; neither chooses
anything. The bundle's published queue is used for the first message only and
then abandoned.

**Consequence worth stating.** Both parties can derive both queues, so either
could collect from the other's. That is not a weakness: they are the two
endpoints of the conversation and already share the full ratchet state. The
trust boundary that matters is the relay, and the relay has neither.

---

## D-014 — Retrieval jitter is quantised to the emission grid

**Refines:** FR-MSG-07

FR-MSG-07 asks for randomised retrieval timing so a relay cannot pair a deposit
with the collection that followed it. The first implementation drew a random
delay and retrieved whenever it elapsed.

That is wrong in a way that took a failing test to notice: a retrieval landing
off the constant-rate emission grid produces a frame at a moment no other frame
would have appeared. The *contents* are hidden, but the *event* is not — an
observer learns "this client just checked its queue", which is close to learning
"this client is expecting something".

So a retrieval now occupies a scheduled slot rather than creating one. Every
frame is on the grid; the jitter only decides which of three
identically-sized frames fills a given slot.

**Cost.** The effective delay is quantised to multiples of the pad interval, so
the jitter range was widened to span six slots to keep the distribution useful.

---

## D-015 — Cover traffic flows only while connected, and we say so

**Confirms:** the PRD §2.3 downgrade, and refuses to soften it

Void does **not** claim continuous cover traffic. On iOS the app is suspended
within seconds of backgrounding, so cover traffic that stops when the app closes
is a direct signal of when the user has the app open — worse than none.

The claim Void makes instead is narrower and true: *while a connection is open,
the traffic on it is constant-rate and uniform-size, so an observer cannot tell
whether any given emission carries a message.*

The scheduler enforces the part of that which is enforceable: emission timing
does not depend on outbox contents, and there is no API to change the rate,
because a user-configurable rate is a per-user fingerprint — which is exactly
the flaw §2.3 identifies in PRD v1.0.

---

## D-016 — A `Store` trait, not a generic `Engine<B: Backend>`

Wiring `void-client::Engine` to `void-store::Database<B>` (FR-STOR-01) needed
`Engine` to hold storage somehow. `Database<B>` is generic over `Backend`,
which is the right shape inside `void-store` but the wrong one for `Engine`:
making `Engine` generic over a storage backend would infect every type that
touches it — `VoidEngine` in `void-ffi`, every test helper, everything.

`Engine` already solved the equivalent problem for networking: it holds its
transport as `Box<dyn Transport>`, not `Engine<T: Transport>`. `Store`
(`void-store/src/db.rs`) is the same move applied to storage — an object-safe
trait covering `Database`'s operations, with a blanket `impl<B: Backend> Store
for Database<B>`. `Engine::new_persisted` and `Engine::restore` take `Box<dyn
Store>`, and a caller that does not want persistence (most of this crate's own
tests) never has to name a backend at all.

The one place this costs something: `Store::get` and `Store::list` return
owned `Record`s rather than `&Record`, because a trait object cannot express
the lifetime `Database::get`'s borrow depends on. `Record` was already
`Clone`, so this is a copy, not a redesign.

**Reversal.** If `Engine` ever needs `Database`-specific operations `Store`
does not expose, widening the trait is the fix; nothing about this shape
prevents it.

---

## D-017 — Duress destruction splits at the FFI boundary by who can act

FR-STOR-02's destruction is two calls, not one, and they cross the FFI
boundary in different directions:

1. **Destroying the hardware vault key** is a platform API call —
   `SecItemDelete` on iOS, `KeyStore.deleteEntry` on Android. `void-ffi` does
   not wrap it, because `void-ffi` has no platform code of its own (see its
   module docs) and the call has nothing to do with anything Rust holds — a
   `KeyVault` trait object bridged over the FFI boundary through C callbacks
   was considered and rejected as complexity with no corresponding benefit:
   the platform can call its own Keychain/KeyStore API directly, faster and
   with fewer moving parts than round-tripping through Rust.
2. **Erasing the local store and RAM** is `Engine::duress_destroy`, exposed as
   `void_engine_duress_destroy`. This is Rust's job because the store and the
   sessions it holds are Rust's state.

The lock screen's flow is therefore: classify the PIN with `void_pin_check`
(wraps `PinVerifier::check`, which never touches `KeyVault` at all); on
`Duress`, the platform destroys its own vault key directly, then calls
`void_engine_duress_destroy`; then the platform shows a first-run screen —
pure UI navigation, nothing left for the core to do.

What makes destruction *irreversible* is step 1, not step 2 — losing the vault
key makes every byte of the database permanently undecryptable whether or not
the erase in step 2 completes. Step 2 is defence in depth: it means a forensic
tool does not find intact ciphertext sitting next to an unrecoverable key, and
it clears sessions and contacts out of the running process's memory.

**Reversal.** If a platform ever wants Rust to own vault destruction too (for
example, a desktop build with a software-only vault and no separate Keychain
API to call), a `KeyVault`-backed `Engine::duress_destroy` variant can be added
alongside this one without changing the FFI functions that already exist.

---

## D-019 — xcodegen, cbindgen, and an XCFramework, not a hand-edited `.xcodeproj`

Building a real iOS app needed an Xcode project, and a `project.pbxproj` is
not a format meant to be hand-written or reviewed as a diff — it is a
serialization of Xcode's own object graph, and two edits to the same file
routinely produce spurious conflicts even when they touch unrelated targets.

**The pipeline `scripts/build_ios.sh` implements:**

1. `cbindgen` generates `VoidFFI.h` from `void-ffi`'s actual source
   (`crates/void-ffi/cbindgen.toml`), so the header cannot drift from the
   functions it describes the way a hand-maintained one could.
2. `void-ffi` is cross-compiled for `aarch64-apple-ios` (device) and both
   `aarch64-apple-ios-sim` / `x86_64-apple-ios` (simulator, `lipo`'d into one
   fat library).
3. `xcodebuild -create-xcframework` packages both slices, with the header, as
   `Void.xcframework`.
4. `xcodegen` (a `project.yml` → `.xcodeproj` generator) produces the actual
   project from a declarative, diffable spec (`ios/project.yml`), rather than
   the pbxproj itself being the source of truth.

Everything `xcodegen` and `build_ios.sh` produce is gitignored — the
`.xcodeproj`, the XCFramework, the generated header — because all of it is a
deterministic function of the Rust source and `project.yml`; committing it
would just be a second copy that could go stale.

**Two build-time issues worth recording, because they will recur if anyone
changes the FFI surface without knowing why:**

- **C enum variants are not namespaced by their enum, unlike Rust's.**
  `VoidStatus::Offline` and `VoidTickOutcome::Offline` compiled fine as Rust
  and then failed as a C redefinition the moment cbindgen emitted both as
  bare `Offline`. `cbindgen.toml`'s `[enum] prefix_with_name = true` fixes
  this for every current and future `#[repr(C)]` enum in one place, rather
  than requiring every new enum's variants to be manually kept globally
  unique.
- **`arti-client`'s `rusqlite` dependency links against the system
  SQLite.** `void-tor` (bundled into `void-ffi`) needs `libsqlite3.tbd`
  linked into the app target explicitly (`ios/project.yml`'s
  `dependencies:`) or the link fails with undefined `sqlite3_*` symbols —
  this is Arti's own state storage, unrelated to `void-store`, which has no
  SQLite dependency at all.

**Verified, not just built.** `xcodebuild build` and `xcodebuild test` both
succeed for `iphonesimulator`, and the app was installed and launched on a
booted Simulator — `AppState.init()` throws unless `VoidCore.init()`
succeeds, and `VoidCore.init()` calls `void_engine_new`, so reaching the
onboarding screen at all is a live Rust identity generated through the full
cross-compiled pipeline, not a mock.

**Reversal.** None of this is load-bearing for anything above it: `xcodegen`
could be swapped for a hand-maintained project, or for Swift Package
Manager's newer executable-target support, without `void-ffi` or the header
it generates changing at all.

## D-020 — The Android app is Gradle-scaffolded, not JNI-wired, and says so

Item 5's Android work needed the same three things iOS got: a build that
actually produces an app, native libraries cross-compiled from `void-ffi`,
and a bridge from the platform language to the C ABI. Only the first was
achievable here: this build environment has no Android SDK, no NDK, and no
`adb` — `android/`'s Gradle project, `AndroidManifest.xml`, and Kotlin files
were written without ever running `./gradlew` or `cargo build --target
aarch64-linux-android` against them, unlike everything in `crates/` and
`ios/`, all of which is proven working in this same revision.

**What is real.** The Gradle project structure (`settings.gradle.kts`,
`build.gradle.kts`, `app/build.gradle.kts` with `minSdk = 30` per
NFR-COMP-02), `AndroidManifest.xml` (`allowBackup="false"` for FR-STOR-05,
`FLAG_SECURE` in `MainActivity` for FR-STOR-06 — the OS-level equivalent of
iOS's manual snapshot-cover overlay), and `scripts/build_android.sh`
documenting the NDK cross-compilation steps.

**What is missing, specifically.** `android/.../VoidCore.kt`'s `external
fun` declarations (`engineNew`, `fingerprintWords`, and the rest) expect JNI
symbols named `Java_app_void_VoidCore_engineNew` and so on — standard JNI
calling convention, which is *not* what `void-ffi`'s C ABI exports (`void_engine_new`
et al., callable directly from Swift via a bridging header, but not from
Kotlin without a shim in between). Per the build prompt's own instruction —
"JNI glue goes in `void-ffi`, not in a new crate that quietly permits
`unsafe`" — the missing piece is a `#[cfg(target_os = "android")]` module
inside `void-ffi` using the `jni` crate, exposing exactly the JNI-convention
names `VoidCore.kt` already calls, each one a thin `unsafe` wrapper around
the same `Engine`/`VoidEngine` this crate already has. Writing that module
blind, with no NDK to compile it against and no emulator to run it on, would
have produced code that *looked* finished while being exactly the kind of
unverified claim non-negotiable #10 exists to prevent — so it was left
undone and documented here instead of guessed at.

**Reversal — this is closer to "next task" than "decision".** Once an NDK is
available: `cargo build -p void-ffi --release --target aarch64-linux-android`
(and `x86_64-linux-android`) needs to succeed, the JNI shim module needs
writing and testing against `VoidCore.kt`'s exact declarations, and
`scripts/build_android.sh` needs an actual run to confirm it does what its
comments claim.

**Superseded in part by D-023.** The shim described above as missing has since
been written, as its own crate rather than a module inside `void-ffi`. What
remains true is everything about the *build*: no NDK, no cross-compilation, no
emulator, nothing in `android/` run even once.

**Closed by D-029.** `scripts/build_android.sh` has run, cross-compiling
`void-jni` for arm64-v8a and x86_64, and the app has run end to end on two
emulators over the live Tor network. CI's `android` job cross-compiles, builds
and lints it on every push. No physical device has run it.

---

## D-023 — The JNI shim is its own crate, and it is unverified on Android

D-020 said the missing piece was a `#[cfg(target_os = "android")]` module
inside `void-ffi`, per the build prompt's "JNI glue goes in `void-ffi`, not in
a new crate that quietly permits `unsafe`". It was written as
`crates/void-jni` instead. The instruction's concern was a crate that *quietly*
permits `unsafe`; the answer is a crate that does so loudly —
`scripts/check_deps.sh` names both `void-ffi` and `void-jni` explicitly, so
adding a third is a failing build, which is what the instruction was protecting.

**Why the split.** `void-ffi` is unsafe in exactly one shape: a caller pointer
and a length. JNI's unsafety is a different shape — `JNIEnv`, `jobject`,
exceptions, a garbage collector — and holding both ABIs in one file makes
neither boundary the single reviewable shape NFR-SEC-02 asks for. `void-jni`
depends on `void-ffi` as an ordinary library, holds only the opaque pointers
that crate hands back, and every entry point is a type conversion around a
`void_*` call. No engine logic is duplicated.

**What is not true about it.** It compiles for the host and nothing more. There
is no NDK here, so `cargo check -p void-jni --target aarch64-linux-android`
fails in `cc-rs` before reaching any Rust of ours, and no JNI symbol has ever
been called from a JVM. Every symbol name matching `VoidCore.kt`'s `external
fun` declarations is a claim checked by reading, which is exactly the kind of
claim non-negotiable #10 exists to distrust.

**What would close it.** An NDK, then in order: the cross-compile succeeds;
`scripts/build_android.sh` runs rather than merely documenting; the app
launches on an emulator against a real cross-compiled core, as `ios/` already
does under D-019. Until the third one happens, this row stays honest by saying
so.

**Closed by D-029.** All three have happened: the cross-compile succeeded with
NDK r30, the script ran, and the app ran end to end on two emulators against
the core it produced. Every symbol has also been called from a desktop JVM, by
`scripts/check_android_bindings.sh` in CI's `app-bindings` job, so a mismatched
`external fun` now fails a build rather than a phone.

## D-021 — The receive path stages its state changes and commits after the tag

A `Ratchet::decrypt` that mutated as it went had a flaw worth naming plainly,
because the fix is cheap and the failure was not: **a relay could permanently
kill a conversation by handing back one sealed record it had already
delivered.**

The mechanism. Deposits are deliberately unauthenticated — that asymmetry is
what keeps senders anonymous to the relay (`void-proto::queue`), so anyone who
can reach a queue can put bytes into it, and the relay holds every record it
ever accepted. A record from a chain the receiver has since left carries a
ratchet public key the receiver no longer holds, which is indistinguishable
from a chain *starting*. The old receive path therefore performed the
asymmetric step — overwriting the root key and the receiving chain — and only
then discovered the AEAD tag did not verify. The root key had already moved
somewhere the peer would never follow. Every subsequent message failed, and the
next send persisted the wreckage to disk.

Two smaller versions of the same mistake sat beside it: a stored skipped key
was removed from the map *before* the message claiming it was opened, so one
flipped bit in a copied record permanently silenced the real message; and up to
`MAX_SKIP` derived keys were inserted on the strength of an unverified header.

**Decided.** The receive path computes into a `Staged` value that owns its
copies and zeroizes them on drop, and writes to the `Ratchet` only in `commit`,
reached only after `try_open` returns. `stage` takes `&self`, so the invariant
is enforced by the borrow checker rather than by a comment. This is the
discipline the Double Ratchet specification calls for and libsignal implements
by cloning session state; staging is the same guarantee without copying the
skipped-key map on every message.

Sending is deliberately not staged. Nothing an attacker controls reaches it.

**Cost.** One `Vec` allocation per received message carrying skipped keys, and
a receive path that is longer to read than the in-place version was. The
serialized state format is unchanged — `RATCHET_STATE_VERSION` stays at 1,
because what changed is *when* fields are written, not which fields exist.

**Reversal.** None wanted, but the shape of the fix is worth keeping legible:
`decrypt` is three lines, and any future field added to the receive path has to
be added to `Staged` and `commit` or it will not persist — which is the failure
mode you want, since a field that never commits is visible in the first test,
where a field that commits early is visible only to an attacker.

**Enforced by.** `a_relay_replaying_an_old_chain_cannot_kill_the_session`,
`a_forgery_cannot_destroy_a_stored_skipped_key`, and
`a_failed_decrypt_leaves_no_trace_in_the_state` in `void-proto`, plus
`a_relay_redelivering_an_old_record_cannot_kill_a_conversation` in
`void-client/tests/end_to_end.rs`, which runs the attack through the real
stack: a relay that hoards every deposit, replays the lot, and must not cost
the conversation a single message.

---

## D-022 — A full reassembly buffer evicts its stalest message rather than failing

`Reassembler` bounded itself at `max_messages` partial messages and returned an
error on the one that would exceed it. The engine turned that error into an
aborted collection — and the buffer had no eviction, so the partials that
caused it were there for good.

That makes an ordinary event fatal. A multi-fragment message loses fragments
for entirely mundane reasons: records expire off the relay after
`DEFAULT_TTL_SECONDS`, a queue rotates mid-message, a client is destroyed and
restored between fragments. Each one leaves a partial that will never complete.
Sixty-four of them, hostile or not, and the contact goes silent permanently —
a ratchet step spans four to five records, so a relay that wants to cause this
has plenty of material and needs no key to use it.

**Decided.** The bound evicts the least recently touched partial instead of
erroring, tracked by a monotonic tick rather than a clock — this type has no
business knowing the time, and relative order is all an eviction policy needs.
Last-touched, not first-seen, so a message still actively arriving outranks one
that stalled. Both engine call sites now discard a record that will not
reassemble and keep collecting, on the same terms as one that will not open:
corruption or an attacker probing, and neither earns a distinguishable
response. `poll_intro_queue` needed this most — its deposit key is published in
every copy of the invite link, so strangers depositing into it is the expected
case, not the exceptional one.

**Cost.** A message whose fragments arrive spread across more than
`max_messages` other in-flight messages can now be evicted mid-reassembly and
lost, where before it would have errored. Both outcomes lose the message; only
one of them also loses every message after it.

**Enforced by.** `a_flood_of_stalled_messages_does_not_block_a_real_one` and
`eviction_takes_the_stalest_message_not_an_arriving_one`.

---

## D-024 — Calls run over paired onion services, and say what they cost

**New scope.** Voice appears nowhere in PRD v2.0. This entry is the whole
argument.

### What was ruled out first

"Calls like Signal or Discord" means WebRTC: media as RTP over UDP, with ICE
for connectivity. **Tor carries TCP streams only** — it has no UDP transport at
all — so that construction cannot run over Tor at any effort level. Running it
*outside* Tor means putting both endpoints' IP addresses on the wire, which is
the single thing FR-TRANS-03 exists to prevent, and `check_banned_symbols.sh`
and `check_no_direct_network.sh` fail the build on both halves of it.

Signal is instructive rather than a counter-example: its 1:1 calls ship with
"Always Relay Calls" **off**, so by default a Signal call hands your IP to the
person you called. That is a reasonable trade for a product whose threat model
is content confidentiality attached to a phone number. It is the opposite trade
from Void's.

Carrying media over the relay was also ruled out, for a different reason: a
relay hop plus the retrieval schedule (FR-MSG-07) puts mouth-to-ear delay in
the tens of seconds, and the schedule is a metadata defence, not an
inefficiency to optimise away.

### What was built, and what it measures

The caller publishes an ephemeral onion service; the callee dials it; media
never touches the relay. Signalling — offer, answer, end — is an ordinary
ratchet-encrypted message in the peer's mailbox queue, so a call costs the
relay's view exactly what a few text messages cost it.

Before writing any of it, `experiments/onion-call/` measured the real network:
1,500 packets at Opus cadence, three runs, three fresh circuits.

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| loss | 0.0% | 0.0% | 0.0% |
| RTT p50 | 528 ms | 376 ms | 497 ms |
| RTT p95 | 1112 ms | 635 ms | 983 ms |
| mouth-to-ear | 868 ms | 467 ms | 755 ms |

Zero loss across 4,500 packets. Latency alone would almost pass — the minimum
round-trip was 228–313 ms — but p95 runs two to four times the minimum, and
that spread forces a 259–584 ms jitter buffer that every packet then pays.
Head-of-line blocking is visible as runs of 23–45 consecutive late packets:
460–900 ms of audio arriving in a clump, which is the failure UDP voice
transports exist to avoid and TCP-only Tor cannot.

### The decision that follows from the numbers

ITU-T G.114 puts the limit for natural interactive conversation at 400 ms. At
~750 ms, two people speaking freely collide constantly; two people taking turns
do fine.

The first cut of this shipped as push-to-talk for that reason. It now ships as
**calls** — microphone open both ways, a mute button rather than a hold-to-talk
one — because a hold-to-talk button does not remove the latency, it just makes
the user operate around it. The latency is handled by saying so instead: one
line on the call screen (*"About a second of delay each way — leave a beat
before you reply"*) and the disclosure below before the call connects. Users who
are told about lag adapt to it; users who are not conclude the app is broken.

Muting stops the microphone, not the emission. Silence frames go out on the
same cadence either way, so a muted call and a talking one are identical on the
wire — the same reasoning as `Record::dummy`.

### The disclosure, and why it does not say "location"

`void_proto::call::CALL_DISCLOSURE` is shown before a call connects, in **both
directions** — placing and answering. The costs it names land on whoever is on
the call, not whoever started it, so warning only the caller would leave the
person answering uninformed about their own exposure. It lives in the core, like
`DURESS_DISCLOSURE`, so Swift and Kotlin cannot soften it or drift apart.

It deliberately does **not** say a call reveals your location. That would be
false here: media runs over paired onion services, Tor in both directions, so
neither end learns the other's IP and neither does the relay. A false security
warning is worse than none — a user told their location is exposed reaches for a
VPN, concludes they are covered, and never learns what a call actually costs.

What it says instead is the two things that are true:

- **Presence.** A direct connection only works if both people are online at
  once, so a call tells your contact you are there right now. The mailbox model
  hides exactly that, and this is the one feature that trades it away.
- **Traffic shape.** Messaging emits one fixed-size record every
  `PAD_INTERVAL_MS` whether or not you are saying anything. A call cannot: it is
  a sustained bidirectional stream for minutes. Anyone watching your connection
  can tell you are on a call, and anyone watching both ends has a far easier
  correlation problem than messaging has ever given them. This is the closest
  real thing to "a call exposes me", and it is worth stating plainly.

`the_call_disclosure_says_what_is_true_and_not_what_is_not` asserts both claims
are present and that the location claim is absent — so if media ever stops going
over Tor, that test is where the now-wrong disclosure surfaces.

**Cost, stated plainly.** A direct connection tells each end the other is
online, for the call's duration. The mailbox model hides exactly that, so this
is the one feature in Void that trades away presence. It is why calls are
per-call opt-in rather than a background capability: nothing publishes a
service until the user presses the button.

**Metadata that is preserved.** Media is constant-bitrate with no
voice-activity detection, and every frame is padded to one size
(`MEDIA_PAYLOAD_LEN`), because packet sizes that track speech leak phonetics —
a published attack. The service is fresh per call and its keys are deleted on
hang-up, so the address is not a stable identifier across calls. The signalling
kind byte lives *inside* the ratchet ciphertext, so the relay cannot tell a
call offer from a greeting.

**The codec is on the platform, not in Rust.** iOS and Android both ship Opus.
Linking libopus would mean C in the workspace, `unsafe` outside the two FFI
crates, and a `check_deps.sh` exemption, for a codec both platforms already
have. The core moves opaque bytes and never learns what codec produced them.

**Wire format.** Plaintexts now carry a one-byte kind (`void_proto::content`),
because "assume the plaintext is text" stops being true the moment anything
else shares the channel. `PROTOCOL_ID` moved to `v2` with it: a v1 client and a
v2 client would otherwise decrypt each other successfully and then misread
every message, and a failed handshake is the correct outcome there.

**Reversal.** Delete `void_proto::call`, `void_tor::call`, and the platform
call files; drop `onion-service-service` from `void-tor`'s arti features. The
`content` framing should stay regardless — it is right on its own merits.

**Enforced by.** `a_call_rings_answers_and_ends_through_the_relay`,
`a_declined_call_leaves_no_message_and_no_state`,
`call_signalling_is_indistinguishable_from_a_message_to_the_relay`, and
`a_second_offer_from_the_same_contact_is_refused_not_silently_swapped` in
`void-client/tests/end_to_end.rs`, plus the media-layer tests in
`void-proto/src/call.rs` — of which the one that matters most is
`the_two_directions_use_different_keys`, since both ends start their sequence
numbers at zero and a shared key would be an immediate nonce collision.

### What is not done

The media path has never run between two real devices. `experiments/onion-call`
proved the transport carries a packet stream at this rate, and the protocol and
platform layers are built and compile — iOS builds, links, and passes
`xcodebuild test` against the real cross-compiled core — but no call has been
placed end to end, because that needs two devices with microphones and this
environment has none. Android additionally cannot be built at all (D-020,
D-023). Treat "calls work" as unproven until someone has held a conversation.

---

## D-025 — Invitations belong to the engine, and only a verified handshake consumes one

**Found, not planned.** Adding a contact failed in practice for four
independent reasons. The tests exercised none of them, because each flushed the
whole handshake to the relay before the inviter looked once.

1. The apps polled the intro queue every 2 s through `poll_intro_queue`, which
   built a new, empty `Reassembler` on every call. The relay deletes each
   record as it hands it over, and a handshake is about thirteen records
   uploaded one per 5 s slot, so nearly every poll landed mid-upload and threw
   away what it had collected. The contact never appeared.
2. `accept_conversation` removed the invitation's prekey secrets *before*
   decoding or verifying anything. The intro queue's deposit key is in every
   copy of the link, so one junk deposit from anyone holding it destroyed the
   invitation for the person it was meant for — D-021's mistake, one layer up.
3. The apps held a single pending invitation; making a second freed the first.
4. The Android app passed milliseconds where the boundary expects seconds. Its
   invitations expired 3.6 s after creation for another Android phone, every
   iOS invitation read as expired on Android, and Android's never expired on
   iOS.

**Decided.**

- The engine owns invitations (`Engine::create_invite`, `cancel_invite`,
  `take_contact_events`). It polls every outstanding intro queue inside the
  retrieval slot, after the session queues, and keeps each invitation's
  reassembler between polls. There is no platform timer — and so no
  off-grid retrieval, which the old 2 s timer was (D-014).
- `accept_conversation` verifies everything first — decoding, the transcript
  signature, decryption of the first message, that it is text — and consumes
  the invitation only after all of it passes.
- Any number of invitations can be outstanding. Each is forgotten
  `INVITE_ACCEPT_GRACE_SECONDS` (24 hours) after its link expires, because a
  handshake started in time can still be uploading and the initial message
  carries no timestamp to judge it by.
- Every `now` crossing the FFI is in seconds, and one later than the year 3000
  is refused as `BadArgument`. A millisecond value lands far past that, so the
  Android mistake now fails loudly instead of silently.
- Message ids are random, not a counter. A counter restarted at 1 whenever the
  outbox was empty at launch, so a stalled partial in the peer's reassembler
  could absorb a new message's fragments; and on an intro queue it was
  predictable, so a stranger holding the link could aim junk fragments at a
  handshake still arriving.
- Starting a conversation with an identity already in the contacts is refused
  (`AlreadyConnected`). Replacing the session on one side only leaves the two
  ends on different queues and every later message silently vanishes — and
  users retry exactly when adding a contact seems not to have worked. An
  accepted re-handshake from a known identity keeps that contact's
  verification and name, since its fingerprint is the same.

**Cost.** Intro queues are collected in the same retrieval burst as session
queues, so the burst grows by two frames per outstanding invitation. It already
grows with the number of contacts; see "Retrieval shape" under *Open* below.

**Enforced by.** `an_invite_polled_while_it_is_still_arriving_completes`,
`a_stranger_depositing_junk_cannot_spend_an_invite`,
`two_outstanding_invites_both_complete`, `an_expired_invite_is_forgotten`,
`rescanning_a_known_contact_is_refused_not_a_silent_session_swap`,
`a_new_handshake_from_a_known_identity_keeps_trust_and_name`,
`a_cancelled_invite_is_never_answered`, and `scanning_your_own_invite_is_refused`
in `void-client/tests/end_to_end.rs`; `a_millisecond_timestamp_is_rejected_not_misread`
and `a_full_conversation_works_end_to_end_across_the_ffi_boundary` in `void-ffi`.
The first was checked against the old behaviour: with a per-poll reassembler it
fails.

---

## D-026 — Persistence reaches the apps, behind a key the platform holds

**Found, not planned.** The README said the engine persists. That was true in
Rust and nowhere else: no FFI function called `Engine::new_persisted` or
`Engine::restore`, and `void_engine_new` generated a fresh identity at every
launch — so every launch lost every contact, and every contact then saw a
stranger. On Android, rotating the screen did the same.

**Decided.**

- `void_engine_open(data_dir, kek, backing, now_ms)` restores this device's
  engine, or creates it on first launch. A key that does not open the existing
  database — wrong, or destroyed by a duress PIN — is `Locked`, and it never
  falls back to creating a new database in its place: that would silently
  replace the user's identity.
- **The key.** The platform generates a random 32-byte key-encryption key once,
  keeps it wrapped by its hardware keystore — the Secure Enclave on iOS, behind
  user presence per FR-ID-02; the Android Keystore, in StrongBox where the device
  has one — and passes it in at launch. `PlatformVault` wraps the database key
  under it with exactly `SoftwareVault`'s construction and reports the backing
  the platform stated (NFR-COMP-02). Every copy the core makes is zeroized
  before `void_engine_open` returns. Duress destruction is unchanged (D-017):
  the platform deletes its hardware key, which makes the database permanently
  undecryptable, then calls `void_engine_duress_destroy`.
- **Invitations persist** (`Kind::Invite`), written before the link exists, so
  there is no moment when someone could accept an invitation this device would
  not remember after a restart.
- **Fragments persist** (`Kind::Inbox`). The relay deletes each record as it
  hands it over, so a fragment of a message still arriving existed only in RAM,
  and a restart between two retrievals lost every multi-record message in
  flight — including a handshake, which is thirteen records long and so almost
  always spans several retrievals. Stored fragments are re-fed on restore and
  deleted once their message completes.
- **Outbox records carry the id of the message they deliver**, so a message
  queued before a restart moves to "Sent" after one.
- **`void_engine_messages`** gives the apps the stored history to show after a
  restart.
- **The app libraries unwind on panic.** They are built with a `mobile` profile
  (`panic = "unwind"`) instead of `release` (`panic = "abort"`). Under
  `release`, every `catch_unwind` in `void-ffi` and `void-jni` compiled to
  nothing and any panic in the core killed the app. `check_reproducible.sh` now
  checks the mobile artifacts too, since those are what ship.

**Why not a `KeyVault` across the FFI.** D-017 already rejected bridging a vault
through C callbacks, for good reason: it makes the boundary two-directional.
Passing the key in once keeps it one-directional.

**What it costs.** The key-encryption key is in application memory for the
duration of `void_engine_open`, as the database key already is for as long as
the database is open. `vault.rs`'s module docs already make the only claim this
supports — *not extractable from a locked device*, never *never in memory*.
Android does not yet gate the key behind user presence; iOS does. The
difference is stated here rather than hidden.

**Enforced by.** `a_pending_invite_survives_a_restart`,
`a_handshake_half_received_before_a_restart_still_completes` (checked against
the old behaviour: without stored fragments it fails),
`a_message_queued_before_a_restart_is_marked_sent_after_it` in
`void-client/tests/persistence.rs`; `an_engine_opened_twice_with_the_same_key_keeps_its_identity`
and `a_wrong_key_reports_locked_and_replaces_nothing` in `void-ffi`;
`a_platform_vault_reports_the_backing_it_was_given` in `void-store`.

---

## D-027 — Invitations are short links, with the invitation parked on the relay

**Relates to:** FR-DISC-01; replaces the multi-QR workaround in `QRCode.swift`

A full invitation carries the signed prekey bundle — an ML-DSA-87 identity key
and signature and an ML-KEM-1024 prekey, about 9 KB — so its link was about
14,600 characters and took thirteen QR codes to show. The apps split it into
`VOID1/i/n/` frames for the user to swipe through, and the scanners
reassembled them by frame count; every invitation had the same count, so frames
from two invitations mixed silently.

**Decided.** The apps hand out a short link, `void://i/<relay>#<secret>`, about
130 characters: one small QR code, and short enough to paste anywhere. From the
32-byte secret both sides derive the key the full invitation is encrypted under
and a queue on the relay (PROTOCOL.md §5.6). The inviter parks the encrypted
invitation in that queue through its ordinary outbox; whoever opens the link
collects it, opens it exactly as a full link, and sees who it is from before
choosing to connect (`Engine::open_invite`, then `Engine::confirm_invite`).
Full `void://c/` links still open.

- The name on an invitation comes from an encrypted setting (`invite_name`,
  empty by default) and is shown to whoever opens it. The inviter also names
  the invitation for its recipient, locally; whoever accepts takes that name.
  Contacts can be renamed. A first message is optional.
- Opening a short link expedites the next retrieval: the next emission slot
  collects instead of waiting out the jitter. It is still a slot — nothing
  leaves the grid (D-014) — and the jitter hides the link between a deposit and
  its collection, which does not exist here: the deposit was someone else's,
  made earlier, and the collection follows the user's own tap.
- An invitation that never arrives — its maker offline, or it was already
  collected — is reported after `INVITE_FETCH_TIMEOUT_SECONDS` rather than
  waited on forever. One opened on a different relay from this client's is
  refused at once (`WrongRelay`).
- The engine refuses to collect its own parked invitation: the relay deletes as
  it hands over, so collecting it would destroy it for the person it was made
  for.

**What it costs.**

- Opening a short link needs the relay reachable, where a full link opened
  offline. The handshake that follows needed the relay anyway.
- The inviter's outbox carries about ten extra records per invitation, at one
  per slot — so an invitation shown the moment it is made is collectable
  about fifty seconds later, and the person scanning it waits for that.
  `Engine::invite_upload_remaining` lets the app say so.
- The relay sees one more queue per invitation receive about ten records and
  later be emptied — the same shape an intro queue already has.
- An opened invitation is held in memory only while it is collected and
  confirmed. A restart in that minute costs a new invitation, because the relay
  has already handed the parked copy over.

**Reversal.** The full-link path is intact; making `create_invite` return
`invite::create(...).to_link()` again is one change.

**Enforced by.** `a_short_invite_link_fits_one_qr_code`,
`a_short_invite_opens_the_invitation_it_parked`,
`a_short_invite_derives_independent_key_and_queue`,
`malformed_short_links_are_rejected`, and
`a_multibyte_label_truncates_without_panicking` in `void-proto`;
`an_invite_polled_while_it_is_still_arriving_completes` (which opens the link
before the inviter has finished parking it), `scanning_your_own_invite_is_refused`,
`an_invite_on_another_relay_is_refused_clearly`, and
`a_cancelled_invite_is_never_answered` in `void-client`;
`an_expedited_retrieval_still_lands_on_the_grid` in the scheduler.

---

## D-028 — A call connects when its media arrives, and neither end rings forever

**Relates to:** D-024. **Found, not planned.** No call had been placed between
two devices (D-024, *What is not done*), and reading the path end to end showed
it could not have worked:

1. `void_call_media_send` and `_recv` each took `&mut` to the same struct with
   no lock, and both apps call them from two threads at once — a data race.
   Hanging up freed the handle while the receiving thread could still be inside
   `recv` (Android waited 500 ms for a receive that blocks for two seconds; iOS
   freed it from the main thread).
2. A receive that timed out partway through a frame threw away the bytes it had
   read, and every later frame was misaligned and failed to authenticate: any
   pause of two seconds made the rest of the call silent. A closed connection
   looked the same as silence, so a dropped call spun at full CPU still showing
   "Connected".
3. The caller only started accepting on its service once the relayed answer
   arrived — a second mailbox delay, about half a minute, during which the
   callee's audio was already queuing in a stream nobody read. That audio was
   then played, adding a delay the call never recovered from.
4. An offer carried no timestamp, so one that waited in the mailbox rang hours
   later. Nothing timed out: the caller rang forever. An offer arriving during
   another call was ignored by the apps while the engine kept it, refusing that
   contact's calls until restart.

**Decided.**

- **Separate halves.** The media stream splits into a sealer and an opener
  (`void_proto::call`), and the Tor stream into a reader and a writer
  (`void_tor::call`), each behind its own lock. The FFI handles are reference
  counted, so a free racing a call in flight leaves that call a live object.
  `void_call_media_close` wakes a blocked receive within about a tenth of a
  second; the platforms close, join their audio threads, then free.
- **Frames stay whole.** The reader keeps a partial frame across timeouts; the
  writer finishes a partial frame before the next, and drops new frames while
  the circuit is backed up rather than queue audio that is only delay.
- **Receive says what happened:** audio, authenticated silence, nothing, or
  closed. The apps end the call on closed, or after ten seconds of nothing.
- **The first authenticated frame is the answer.** The caller accepts on its
  service from the moment the offer is queued, and the callee's first frame —
  which only the holder of the offer's media secret can produce — marks the call
  connected (`mark_call_connected`). The relayed answer still goes out, and is
  ignored if the media got there first. The service accepts streams only for
  `CALL_PORT`, as its comment always claimed.
- **Timing.** An offer carries `sent_at`; one older than
  `OFFER_MAX_AGE_SECONDS` on arrival is a missed call and does not ring. The
  callee rings for `RING_TIMEOUT_SECONDS` and then tells the caller; the caller
  gives up on its own after `CALLER_TIMEOUT_SECONDS`. An offer arriving during
  any call is declined with the new `EndReason::Busy` and shown as missed.
- **Signals jump the queue.** Call signals go ahead of queued message fragments
  in the outbox and are never written to disk — one record per slot as before,
  but a ring no longer waits behind a long message or a parked invitation.
- **`PROTOCOL_ID` is `v3`**: the offer gained a field, and a v2 client would
  misread it. `void_protocol_id` is checked against the core's constant at
  compile time, and `PROTOCOL.md`'s header and `PROTOCOL_VERSION` now agree
  with it.

**The offer's age allowance is two minutes, not one.** It was first set to a
minute, from the reasoning that an offer takes one slot to leave and then
the callee's jittered retrieval. But an offer is four records whenever its
ratchet chain carries an ML-KEM step (D-005), and the caller's own retrievals
take some of its slots. Simulated, offers arrived after 15–60 seconds with a
tail beyond, and about one call in 300 was reported missed without ringing —
which showed up as two intermittently failing tests. Two minutes covers the
delay with room for the clocks of two phones to disagree. The cost is a caller
who waits up to three minutes when the callee's phone is off; when it is on,
the callee's own timeout reaches the caller sooner.

**What it costs.** A caller's service is reachable for the whole ring rather
than only after an answer, so the window in which it can be probed is longer.
Anyone who can reach it still has to produce a frame under the media secret,
which travels only in the ratchet-encrypted offer. A clock more than two
minutes behind the other phone's makes every call from it arrive as missed;
nothing detects that yet.

**What is still not done.** Everything D-024 says under *What is not done* is
still true: no call has been placed between two devices, and the platform
audio code cannot be exercised here.

**Enforced by.** `a_stale_offer_is_missed_not_ringing`,
`an_unanswered_call_times_out_as_missed_at_both_ends`,
`a_callee_that_stops_ringing_tells_the_caller`,
`an_offer_during_a_call_is_declined_busy`,
`call_signals_go_ahead_of_queued_messages`, and
`media_that_connects_first_is_the_answer` in `void-client/tests/end_to_end.rs`;
`media_survives_a_stall_mid_frame`,
`a_backed_up_writer_drops_new_frames_but_never_splits_one`,
`a_cancelled_receive_returns_promptly`, and
`the_service_waits_exactly_as_long_as_the_caller_does` in `void-tor`;
`the_split_halves_talk_to_the_other_end_independently` in `void-proto`;
`call_handles_survive_being_freed_mid_call_and_refuse_null` and
`call_events_encode_to_their_documented_layout` in `void-ffi`.

---

## D-029 — The apps run the engine on one thread, and can place a call

**Relates to:** D-025 to D-028, which changed the core's surface; the apps had
not followed. **Found, not planned,** while moving them onto it:

1. Neither app could place or answer a call. Both had the call screen, the
   incoming-call screen, and the disclosure, but nothing presented them, and no
   conversation had a call button.
2. "I've checked, continue", on a contact whose code changed, changed only the
   screen. The engine still blocked sending, so every send after it failed.
3. An Android release build would have broken every JNI call that returns an
   object. `void-jni` constructs `NativeTickResult` and its siblings by class
   name, which R8 cannot see, so it would rename or strip them — and every tick
   would read as offline.
4. From Android 12, `allowBackup="false"` no longer covers device-to-device
   transfer.
5. Android silences the microphone of an app in the background, so a call
   would have gone mute the moment the screen locked.
6. On Android the back button left the app from any screen, and the key
   storage screen was unreachable.

**Decided.**

- **One engine thread.** Every engine call runs on one serial queue: iOS's
  `CoreQueue` (a dispatch queue, not an actor, because the calls block and an
  actor would park a thread of Swift's small cooperative pool), and on Android
  a single-thread dispatcher. A tick holds the engine's lock while it waits on
  the network, up to two minutes over a stalled circuit; the interface never
  waits on it. Tor bootstrap and the relay attach run on their own threads,
  since neither holds the lock while it waits.
- **Launch opens the persistent engine** (D-026) with the key `KeyVault`
  releases. iOS: a P-256 key generated in the Secure Enclave, usable only after
  Face ID, Touch ID or the passcode, with the KEK sealed to it by ECIES in
  Application Support (excluded from backup, complete file protection); where
  no such key can be made — the Simulator, or no passcode set — a
  `ThisDeviceOnly` Keychain item, reported as Software. Android: a Keystore
  AES-GCM key in StrongBox, else the TEE, with the backing read back from
  `KeyInfo` rather than assumed, and the KEK sealed under it in
  `noBackupFilesDir`. A key that does not open the database is reported, and
  nothing is replaced.
- **The engine is the source of truth.** Contacts, names, trust, history, and
  delivery state are read back from it after each tick that changed something.
  A sent message shows "Waiting to send" until the scheduler has deposited it.
- **Tor at launch, and back after a drop.** Bootstrap, then attach the relay;
  when a tick reports offline, attach again, waiting from five seconds up to
  five minutes between tries.
- **Adding a contact, both ways round.** Show my code: one QR code, share and
  copy, and how long until it can be collected (from
  `invite_upload_remaining`), then "Sam joined". Scan or paste: "Getting their
  invitation…", then "Connect with Alex?" with the name it carried, editable,
  and an optional first message. Several invitations can be outstanding.
- **Calls are reachable.** A call button, the incoming-call screen, and the
  disclosure before connecting in either direction, with the microphone asked
  for at that moment and never at launch. The caller accepts from the moment
  the offer is queued and takes the first authenticated frame as the answer
  (D-028). A call ends when its connection closes or ten seconds pass with
  nothing authenticated. Hanging up while the offer is still being queued
  withdraws it; before, the hang-up reached the engine first, found no call,
  and the offer went out anyway. iOS declares background audio; Android runs a
  foreground service of type microphone while a call's audio runs, whose
  notification says a call is in progress and not with whom.
- **Audio, as planned.** iOS: voice processing for echo cancellation, 16 kHz
  mono cut into exact 20 ms frames, a paced sender thread instead of network
  sends from the audio tap, the player connected in the decoder's format, Opus
  packet descriptions set, playback capped at about 400 ms, interruptions
  handled. Android: the encoder's setup buffers are no longer sent as audio,
  every ready packet is drained, the decoder is given the Opus identification
  header and delays it never had, capture feeds a bounded queue that a paced
  sender drains, playback never blocks and is capped at about 400 ms, echo
  cancellation and communication mode are on, and teardown is close, join,
  release, free — in that order.
- **R8 keeps the JNI result classes**, and `dataExtractionRules` excludes
  everything from cloud backup and device transfer. The database and the
  sealed key are in `noBackupFilesDir` regardless.

**How this was checked, and what was not.** No Mac and no Android device were
available.

- *Swift.* The files that call the core — `VoidCore.swift`, `VoidCall.swift`,
  `CoreQueue.swift` — were type-checked on Linux with Swift 6.4 against the
  header cbindgen generates from the current source, then compiled and run
  against the real core: in-memory and persisted engines, invitations, error
  mapping, the milliseconds guard, the right key and a wrong one. That found a
  crash before it shipped: the byte reader indexed an array slice from zero,
  and would have trapped on every contact list. `AppState.swift` and
  `CallAudio.swift` were type-checked against minimal stand-ins for Combine
  and AVFoundation. The SwiftUI views and `KeyVault.swift` were only
  syntax-checked. Nothing has been built with Xcode.
- *Kotlin.* The app compiles against SDK 34 and assembles
  (`./gradlew assembleDebug`), and lint reports no errors — it found one, a
  missing microphone permission check, now fixed. `VoidCore.kt` and
  `Engine.kt` were run on a desktop JVM against the real core through
  `void-jni` built for Linux, so D-023's "never run in a JVM" no longer holds
  for the shim itself.
- *Android, running.* `scripts/build_android.sh` cross-compiled `void-jni`
  for arm64-v8a and x86_64 with NDK r30 — the first time it was built for
  Android at all — and the app ran on two emulated phones (API 34, x86_64),
  with a local `void-relayd` published as an onion service by C-tor, over the
  live Tor network. Every item on the plan's device list passed except the QR
  camera (the emulators have none; the link was pasted instead): launch and
  onboarding; the Keystore key and persistent engine, surviving a restart and
  a rotation; Arti bootstrapping inside the app; an invitation made offline;
  adding a contact both ways round, the invitation carrying its maker's name;
  messages both ways, "Waiting to send" becoming "Sent", history surviving a
  restart; a call placed, rung in eight seconds, answered, connected in six,
  muted, and hung up from either end; the call held for over a minute with the
  callee's screen locked; killing the callee ended the call on the caller at
  once; airplane mode, with backoff, reconnection, and a message held by the
  relay delivered after it. The audio was a silent virtual device, so the media
  path is proven and what a voice sounds like is not.
- *What running found, fixed:* an attach that hung for over six minutes
  inside Arti's onion-service connect, keeping the phone offline with no retry
  (both `void-tor` connects now give up after `CONNECT_TIMEOUT`, and the app's
  backoff retries); Android's Opus decoder always producing 48 kHz, played into
  a 16 kHz track (playback now follows the decoder's output format); a hang-up
  shown to the other end as "The connection dropped" (a closed connection now
  reads "Call ended", and "dropped" means ten seconds of nothing on an open
  one); and the key-storage screen promising "your passphrase" on a phone
  with software-only key storage, where the app never asks for one (the core's
  description is now true of every software case).
- *Seen once: a stalled circuit.* One call ended itself after about 40
  seconds. Its logs show both phones' decoders receiving their last frame at
  the same moment, and both phones' ten-second stall timers ending the call
  ten seconds later, a tenth of a second apart. The circuit carrying the call
  stalled in both directions; neither app hung up. The logs do not say why.
  The callee's screen had locked seven seconds earlier, but the next call held
  for over a minute with it locked, and a circuit on the live network can
  stall with no help. Nothing reconnects a call whose circuit stalls: it ends,
  and the user calls again.
- The iOS app has not run, and no build of either app has run on physical
  hardware. D-024's rule — treat calls as unproven until someone has held a
  conversation — stands for iOS, and for real audio on both. *(The iOS app
  has since run on the Simulator: D-031.)*

**Enforced by.** `QRCodeRenderTests` (a real short link from the core renders
as a code that CoreImage's detector reads back as the same link),
`InvitationBoundaryTests`, and `QRCodeUITests`, in CI's macOS job; the
bindings checks in CI's `app-bindings` job (`scripts/check_ios_bindings.sh`,
`scripts/check_android_bindings.sh`); and the Android build, lint, and
cross-compile in CI's `android` job.

---

## D-030 — A deposit the relay refuses waits its turn, and duress leaves no identity behind

Two items the review that produced D-025 to D-028 deferred.

**A refused deposit held up every contact.** The outbox sends one record per
slot, always the one at its head, and a refused record stayed at the head. A
refusal carries no reason — one would be an oracle — and its causes (one
queue's deposit rate, its capacity) pass, so the record is kept. But every slot
went to retrying it, and every other contact's messages waited behind one
queue's limit. Now a refused record moves to the back of its class (a call
signal behind the other signals, a message fragment behind everything) and is
retried in turn. Retrying costs nothing a relay or observer can see: the slot
carries a frame either way. Nothing is ever given up on.

**Duress left the identity in memory.** `Engine::duress_destroy` cleared
sessions, invitations and calls, and destroyed the store, but the identity's
secret keys stayed in the process until the platform freed the engine. Now it
replaces them with a stand-in derived from fixed zero seeds, which belongs to
nobody — dropping the real keys, which wipe themselves — resets the settings
(the name the user went by) and the relay address, and drops the store once it
is destroyed, so nothing writes to it afterwards. D-017's split is unchanged:
the platform still destroys its hardware key first.

**Enforced by.** `a_queue_the_relay_keeps_refusing_does_not_hold_up_other_contacts`
(checked against the old behaviour: the other contact never received) in
`void-client/tests/end_to_end.rs`; `duress_destroy_wipes_memory_and_leaves_the_database_unopenable`,
which now also requires the identity and the name to be gone, in
`void-client/tests/duress.rs`.

---

## D-031 — The iOS app runs: the core gets the stack it needs, and Tor a private directory

**Found, not planned,** the first time the iOS app was built with Xcode since
D-029, on a Mac with Xcode 26.6 and the iOS 26.5 Simulator. CI's iOS job had
failed on every run since D-029 because of the first of these.

1. **It crashed at launch, before any screen.** SIGBUS, "Thread stack size
   exceeded", inside `ml_dsa::VerifyingKey::new`: opening the engine generates
   the identity, and that ran on a dispatch queue, whose threads have 512 KiB
   of stack on iOS. The core's own end-to-end tests, built with the profile
   the app links, overflow at 512 KiB and pass at 576. In CI the unit tests'
   host app crashed the same way before a test began ("Early unexpected exit,
   operation never finished bootstrapping"). Android is spared by margin, not
   by design: its threads default to about 1 MiB.
2. **Once it launched, it was offline for good.** Arti refused to bootstrap,
   "problem with filesystem permissions", in well under a second, and the app
   retried with backoff indefinitely with nothing on screen to say why.
   `FileManager` creates directories 0755, and Arti wants its state and cache
   readable by their owner only.

**Decided.**

- **Every thread that calls the core is the app's own, with 8 MiB of stack.**
  `CoreQueue` is now a thread rather than a dispatch queue, with its own
  repeating timer, and keeps D-029's rules: an engine call never overlaps
  another, and a slow tick delays the next rather than piling up. Unlocking,
  Tor bootstrap, the relay attach, and call setup run on `CoreThread.detach`;
  the call audio threads set the same stack size. The stack is address space
  reserved up front; only the pages a call touches are ever backed.
- **Every directory the app makes is 0700,** and one an earlier build left
  0755 is closed again at the next launch.

**How this was checked.** `xcodebuild test` on the Simulator: the unit tests
and the QR code UI test pass. Then the app ran on two Simulators over the live
Tor network, against a local `void-relayd` published as an onion service by
C-tor, driven by a UI test on each phone. In order: Tor bootstrapped and the
relay attached inside the app; an invitation was made, its link read back off
the screen's QR code with CoreImage's detector, and parked on the relay in
about a minute; the other phone pasted the link, collected the invitation in
ten seconds, showed "Connect with Ada?" with the name it carried, and
connected; the inviter showed "Bea joined" ninety seconds later. Both apps
were then relaunched: each contact came back from the encrypted database, a
message went from the inviter ("Sent" ten seconds after sending) and arrived
thirty-four seconds after it was sent, and was still there after the
receiver's own restart; and the reply was "Sent" eight seconds after sending
and arrived sixteen seconds after it was sent.

What this did not check: the Secure Enclave key (the Simulator has none, so
the app used the Keychain and said Software), the QR camera, calls, and any
physical device. D-024's rule on calls stands for iOS.

**Enforced by.** `AppDirectoriesTests` (both fail against the old code, which
left the directories 0755); the bindings check, which now requires the core
queue's thread to have `CoreThread.stackSize` of stack, a cancelled timer to
stop, and an identity to be made on it; and CI's iOS job, whose host app no
longer crashes.

---

## Open, and deliberately so

**PRD §13.3 — who runs the relays.** Not resolved. The code supports any
deployment model: relays are interchangeable, hold no keys, and a client can
point at any onion address. The decision is operational and political rather
than technical, and making it in code would be pretending otherwise.

**PRD §13.4 — push on or off by default.** Implemented as off (FR-NOTIF-04),
with the anonymity-set argument for on-by-default recorded but not acted on.
Changing it is one field in `Settings::default()`. The UI is built so that
either default is presented honestly (FR-UI-06).

**PRD §13.5 — Path A versus Path B.** The PRD recommends Path B and this
codebase implements it. §2.3's own caveat stands: if the product's purpose is
specifically to resist an adversary with visibility into both endpoints, Path A
is correct and the honest move is to contribute to Briar.

**PRD §13.6 — build versus contribute to SimpleX.** Unanswered here, because
it is not a question code can answer. The PRD is right that it deserves a
written answer before this goes further.

**Retrieval shape, and what a hostile relay can link.** Found while fixing
D-025, not resolved by it. A client carries every deposit and every retrieval
over one Tor stream, and a retrieval slot collects *all* of its queues in one
burst: two frames per session queue, two per intro queue, and two more per
record collected. So a relay that chose to log could group every queue one
client retrieves as belonging to one pseudonymous circuit, and could pair the
circuit that deposits into a queue with the circuit that collects from it —
which is a contact edge. That is weaker than "a relay cannot link two of your
queues", which holds for the queue identifiers themselves
(`the_relay_cannot_link_two_queues_of_one_user`) but not for how they are
collected. The burst's length also tells a network observer roughly how many
contacts a client has. The usual remedies — a stream per queue through Arti's
isolation tokens, spreading retrievals across slots, or separate relays for
sending and receiving — each cost latency or bandwidth, and choosing between
them is a threat-model decision this entry records rather than makes.
