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
therefore ~12 KB, which is at the upper end of what a QR code can carry — see
D-011.

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

## D-024 — Calls are push-to-talk over paired onion services, and are labelled as such

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
