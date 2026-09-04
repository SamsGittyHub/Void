# Void Protocol Specification v1

**Status:** Draft, for review before implementation freeze (PRD §11 Phase 1
deliverable)
**Protocol identifier:** `void/v1/pqxdh/x25519+mlkem1024/ed25519+mldsa87`

This document specifies the bytes on the wire. It is written so that an
independent implementation could be built from it, and so that a reviewer can
check the code against it line for line. Where the implementation and this
document disagree, that is a bug in one of them and the tests named at the end
of each section are what settle it.

---

## 1. Notation

- All integers are **big-endian**.
- `u8`, `u16`, `u32`, `u64` are unsigned integers of that width.
- `bytes16(x)` is a `u16` length followed by that many bytes.
- `bytes32(x)` is a `u32` length followed by that many bytes.
- `raw(x)` is a fixed-size field with no length prefix.
- `||` is concatenation.

**Encoding is unambiguous by construction.** There are no optional fields
encoded by absence: an absent value is an explicit presence byte plus a
zero-filled placeholder. This matters because the handshake transcript is a hash
over encoded values, and encoding ambiguity there is a signature-substitution
vulnerability.

---

## 2. Primitives

| Role | Algorithm | Standard |
|---|---|---|
| Hash | BLAKE3 | BLAKE3 spec |
| KDF (chains) | HKDF-SHA-256 | RFC 5869 |
| KDF (labelled) | BLAKE3 `derive_key` | BLAKE3 spec |
| AEAD (counter nonce) | ChaCha20-Poly1305 | RFC 8439 |
| AEAD (random nonce) | XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha |
| Classical KEX | X25519 | RFC 7748 |
| PQ KEM | ML-KEM-1024 | FIPS 203 |
| Classical signature | Ed25519 | RFC 8032 |
| PQ signature | ML-DSA-87 | FIPS 204 |
| Password KDF | Argon2id | RFC 9106 |

### 2.1 KDF labels

Every derived key has a label that appears exactly once in the codebase
(`void_crypto::kdf::ALL_LABELS`, with a test that fails on collision). Labels
are versioned; a change in meaning bumps the label rather than reusing it.

```
void/v1/handshake/root          void/v1/ratchet/root
void/v1/handshake/chain         void/v1/ratchet/chain
void/v1/ratchet/message         void/v1/ratchet/header
void/v1/sealed-sender/envelope  void/v1/record/pad
void/v1/identity/fingerprint    void/v1/store/database
void/v1/store/row               void/v1/export/archive
void/v1/queue/address           void/v1/queue/auth
void/v1/push/wake-id            void/v1/invite/link
```

### 2.2 Hybrid combination

Secrets are **length-prefixed before concatenation**, then fed to HKDF-Extract
with the transcript as salt:

```
concat_labeled(parts) = u16(count) || bytes32(part_0) || ... || bytes32(part_n)
PRK  = HKDF-Extract(salt = transcript, ikm = concat_labeled(secrets))
out  = HKDF-Expand(PRK, label, len)
```

Length prefixing is required: without it `["ab","c"]` and `["a","bc"]` hash
identically. `void_proto::wire::tests::labeled_concat_is_injective` pins this.

The result is secure if **either** input secret is secure. That is the whole
point of the hybrid: a break of X25519 or a break of ML-KEM alone yields
nothing.

---

## 3. Identity

An identity is three keypairs, generated on device, never transmitted to any
Void infrastructure (FR-ID-01, FR-ID-05).

```
IdentityPublic = raw(ed25519_public : 32)
              || bytes16(mldsa_public : 2592)
              || raw(x25519_public : 32)
```

A **hybrid signature** is both components, and verification requires **both** to
pass, evaluated without short-circuiting:

```
Signature = raw(ed25519_sig : 64) || bytes16(mldsa_sig : 4627)
```

Total encoded: 4,693 bytes. This is why signatures appear only at handshake and
key-change (D-002).

**Fingerprint** (FR-ID-03):

```
fingerprint = BLAKE3-derive_key("void/v1/identity/fingerprint", IdentityPublic)
```

Rendered as 16 proquint syllables, or 12 groups of 5 decimal digits.

*Tests:* `identity::tests::both_components_are_required` demonstrates that a
signature spliced from two identities verifies under neither.

---

## 4. Queues

A queue is a per-contact mailbox address. §2.4 of the PRD: *"No relay ever holds
an identifier that maps to Alice — only a set of unlinked queue IDs."*

```
retrieval_seed  = BLAKE3-keyed(secret, "void/v1/queue/auth"  || u32(generation))
signing_key     = Ed25519-from-seed(retrieval_seed)
queue_id        = BLAKE3-derive_key("void/v1/queue/address", signing_public)[0..16]
envelope_key    = BLAKE3-keyed(secret, "void/v1/sealed-sender/envelope" || u32(generation))
```

### 4.1 The two capabilities

| Capability | What it is | Who may hold it |
|---|---|---|
| Deposit | `(queue_id, envelope_key)` | anyone; published in prekey bundles |
| Retrieve | `signing_key` | the queue owner only |

They derive independently from the queue secret, so holding one yields nothing
about the other. `DepositKey` is a distinct type so the compiler enforces the
split.

### 4.2 Retrieval proof

Stateless and registry-free (D-011):

```
proof = Ed25519-Sign(signing_key, "void/v1/queue/retrieve" || challenge)
```

A relay verifies by recomputing `queue_id` from the presented public key,
checking it matches the queue addressed, and verifying the signature. **The
relay stores nothing.**

### 4.3 Rotation

```
next_secret = BLAKE3-derive_key("void/v1/queue/rotate", secret || u32(generation))
```

Both parties derive the same next queue without negotiation. The old id is not
computable from the new one, so a relay that has seen both cannot link them.

---

## 5. Handshake

PQXDH-shaped. The responder publishes a bundle out of band; the initiator sends
one message and can send immediately after.

### 5.1 Prekey bundle

```
PrekeyBundle = bytes32(IdentityPublic)
            || raw(signed_prekey : 32)
            || u8(has_one_time) || raw(one_time_prekey : 32)   // zeroed if absent
            || bytes16(kem_prekey : 1568)
            || bytes32(Signature)
            || raw(queue_id : 16)
            || raw(queue_envelope_key : 32)
            || bytes16(relay_hint)
```

Signed body (context-separated):

```
body = bytes16("void/v1/prekey-bundle")
    || bytes16(PROTOCOL_ID)
    || bytes32(IdentityPublic)
    || raw(signed_prekey)
    || u8(has_one_time) || raw(one_time_prekey)
    || bytes16(kem_prekey)
    || raw(queue_id) || raw(queue_envelope_key)
    || bytes16(relay_hint)
```

**The envelope key is inside the signature.** Without that, an attacker who
substituted only the envelope key could read the first message while every other
field still verified.

`PrekeyBundle::verify` must be called before any secret is derived from a
bundle.

### 5.2 Secrets

```
DH1 = DH(IK_A_x, SPK_B)
DH2 = DH(EK_A,   IK_B_x)
DH3 = DH(EK_A,   SPK_B)
DH4 = DH(EK_A,   OPK_B)          // zeroes if no one-time prekey
(CT, SS) = ML-KEM-1024.Encaps(PQSPK_B)
```

### 5.3 Transcript

```
transcript = BLAKE3(
      bytes16(PROTOCOL_ID)
   || bytes32(IdentityPublic_initiator)
   || bytes32(IdentityPublic_responder)
   || raw(EK_A) || raw(SPK_B)
   || u8(has_one_time) || raw(OPK_B)
   || bytes16(PQSPK_B) || bytes16(CT))
```

### 5.4 Key derivation

```
material   = HKDF(salt = transcript,
                  ikm  = concat_labeled([DH1, DH2, DH3, DH4, SS]),
                  info = "void/v1/handshake/root",
                  len  = 64)
root_key   = material[0..32]
queue_seed = material[32..64]

queue_a2b  = BLAKE3-derive_key("void/v1/queue/initiator-to-responder", queue_seed)
queue_b2a  = BLAKE3-derive_key("void/v1/queue/responder-to-initiator", queue_seed)
```

Both parties derive both queues. Neither chooses one (D-013).

### 5.5 Initial message

```
InitialMessage = bytes32(IdentityPublic_initiator)
              || raw(ephemeral : 32)
              || bytes16(kem_ciphertext : 1568)
              || u8(used_one_time)
              || bytes32(Signature over "void/v1/initial-message" || transcript)
              || bytes32(first ratchet message)
```

Deposited into the bundle's published queue. Every subsequent message goes to
the derived steady-state queue.

The responder verifies the transcript signature **before** using the derived key
for anything.

---

## 6. Ratchet

Signal's Double Ratchet with the asymmetric step performed by both X25519 and
ML-KEM-1024.

### 6.1 Header

```
Header = raw(dh_public : 32)
      || u32(kem_epoch)
      || u32(kem_target_epoch)
      || bytes16(kem_encaps_key)     // empty, or exactly 1568
      || bytes16(kem_ciphertext)     // empty, or exactly 1568
      || u32(previous_chain_len)
      || u32(message_number)
```

The two KEM fields are either both absent or both present at their exact sizes.
A header with one but not the other is malformed.

Header size: **56 bytes** without a KEM step, **3,192 bytes** with one.

### 6.2 Symmetric step (every message)

```
next_chain_key = BLAKE3-keyed(chain_key, "void/v1/ratchet/chain")
message_key    = BLAKE3-keyed(chain_key, "void/v1/ratchet/message")
```

Forward secrecy comes from here: the old chain key is overwritten and the
function is one-way.

### 6.3 Asymmetric step

On a direction change. With a KEM step every `KEM_RATCHET_INTERVAL` = 4 steps
(D-005):

```
dh_secret = DH(new_dh_self, dh_remote)

with KEM:     combined = concat_labeled([dh_secret, kem_secret])
without KEM:  combined = concat_labeled([dh_secret])

(root_key, chain_key) = HKDF-Expand(
    HKDF-Extract(salt = root_key, ikm = combined),
    "void/v1/ratchet/root", 64)
```

KEM material is repeated in **every header of the chain in which the step
occurred**, so losing any one message of that chain does not kill the session.
`kem_target_epoch` names which of the recipient's KEM generations was
encapsulated to; one previous generation is retained.

### 6.4 Encryption

```
aad        = Header (encoded)
nonce      = 4 zero bytes || u64(message_number)
ciphertext = ChaCha20-Poly1305(message_key, nonce, aad, plaintext)
```

Nonce uniqueness follows from the chain key never being reused.

### 6.5 Bounds

`MAX_SKIP` = 1000 keys derivable from one header; `MAX_SKIPPED_STORED` = 2000
retained overall. Exceeding either is an error, never a silent truncation. Both
bounds are checked against what is already stored *plus* what the message being
processed has derived so far, so one header cannot exceed the total by
splitting its demand across the two skips a receive performs.

### 6.5.1 Receive is atomic

A message that does not authenticate changes **nothing**: not the root key, not
either chain key, not a counter, not one entry of the skipped-key map. A
receiver computes the whole step — skipped keys, the asymmetric step, the
message key — and commits it only after the AEAD tag verifies.

This is not an optimisation, and it is the requirement most easily missed by an
implementation that mutates as it parses. Deposits are unauthenticated by
design (§8), so anyone who can reach a queue can present a header, and a relay
holds every record it ever accepted. A record from a chain the receiver has
already left carries a ratchet public key the receiver no longer holds — which
is indistinguishable from a chain beginning. A receiver that steps before it
verifies will therefore ratchet its root key to a value the peer will never
derive, on demand, at zero cost to the attacker, and the session is dead
permanently. The same applies in miniature to a stored skipped key: it must be
removed when its message opens, never when a message merely claims it.

`Ratchet::stage` takes `&self` and `Ratchet::commit` is unreachable except
through a successful open, which is this rule expressed in the type system
rather than in a comment (D-021).

*Tests:* `ratchet::tests::a_kem_step_survives_losing_the_first_message_of_its_chain`,
`ratchet::tests::replay_is_rejected`,
`ratchet::tests::tampering_is_detected_everywhere`,
`ratchet::tests::a_failed_decrypt_leaves_no_trace_in_the_state`,
`ratchet::tests::a_relay_replaying_an_old_chain_cannot_kill_the_session`,
`ratchet::tests::a_forgery_cannot_destroy_a_stored_skipped_key`.

### 6.6 Serialized state (persistence)

`Ratchet::serialize` / `Ratchet::deserialize` (FR-STOR-01) cover everything
needed to resume a session, including the skipped-key map — losing it on
restart would silently reopen a forward-secrecy gap the ratchet had already
closed. This is raw key material with no encryption of its own; the caller
(`void-client`'s engine, via `void-store`) is responsible for writing it only
inside an already-encrypted-at-rest record.

```
RatchetState = u8(version)                    // = 1
            || raw(root_key : 32)
            || raw(dh_self_secret : 32)        // public is re-derived on load
            || Optional32(dh_remote)

            || KemSelf(kem_self)
            || u8(has_kem_self_prev) || KemSelf(kem_self_prev)?

            || u8(has_kem_remote_encaps) || bytes16(kem_remote_encaps)?
            || u32(kem_remote_epoch)

            || u8(has_kem_pending)
            || ( u32(epoch) || u32(target_epoch)
                 || bytes16(encaps) || bytes16(ciphertext) )?

            || u32(dh_steps_since_kem)
            || Optional32(chain_send)
            || Optional32(chain_recv)

            || u32(n_send)
            || u32(n_recv)
            || u32(previous_chain_len)
            || u8(pending_step)

            || u32(skipped_count)
            || ( raw(ratchet_public : 32) || u32(message_number) || raw(message_key : 32) ){skipped_count}

KemSelf     = u32(epoch) || bytes16(encaps_key) || bytes16(decaps_key)
Optional32  = u8(present) || raw(value : 32)?
```

The skipped-entry list is written in the `BTreeMap` iteration order of
`(ratchet_public, message_number)`, which is deterministic, so re-serializing
a freshly deserialized ratchet is byte-for-byte identical to the original —
the round trip is exact, not merely equivalent.

`version` is checked on load; a mismatch is treated as malformed rather than
partially parsed. `skipped_count` is bounded by `MAX_SKIPPED_STORED` before
any allocation, for the same reason every other length-prefixed field in this
protocol is bounded before use.

*Tests:* `ratchet::tests::serialize_deserialize_is_byte_stable`,
`ratchet::tests::ratchet_state_roundtrips_and_conversation_continues_after_restore`,
`ratchet::tests::a_restored_ratchet_still_rejects_replays_and_keeps_its_skipped_keys`,
`ratchet::tests::deserialize_rejects_truncated_or_wrong_version_state`.

---

## 7. Records

Fixed size, always (FR-MSG-02).

```
RECORD_SIZE = 1024
Record = u8(kind) || u64(message_id) || u16(index) || u16(count)
      || u16(body_len) || raw(body) || raw(random padding)
```

`kind`: 1 = payload, 2 = dummy. Body capacity is 1,009 bytes.

**Padding is random, not zero.** Zero padding is compressible and
distinguishable after any transform that leaks entropy.

The size follows from NFR-PERF-03's 50 MB/month budget at one record per
`PAD_INTERVAL_MS` = 5,000 ms while connected. A 4 KB record would be four times
that and would not fit the budget, which is why ratchet steps fragment instead.

**Reassembly is bounded and evicts.** A receiver holds at most `max_messages`
incomplete messages and drops the least recently touched one to make room. It
must not treat a full buffer as an error: fragments go missing for ordinary
reasons — a record expiring off the relay, a queue rotating mid-message — and a
receiver that fails instead of evicting can be stopped permanently by anything
that strands enough partial messages, including a relay redelivering one
fragment of an old one (D-022). A record that will not reassemble is discarded
on the same terms as one that will not open.

*Tests:* `record::tests::cover_traffic_budget_matches_the_prd`,
`record::tests::padding_is_not_constant`,
`record::tests::a_flood_of_stalled_messages_does_not_block_a_real_one`,
`record::tests::eviction_takes_the_stalest_message_not_an_arriving_one`.

---

## 8. Sealed deposits

```
sealed  = raw(nonce : 24) || XChaCha20-Poly1305(envelope_key, nonce, aad = queue_id, Record)
Deposit = raw(queue_id : 16) || bytes32(sealed : 1064)
```

**There is no sender field.** Void's delivery address is per-contact-pair, so
the recipient already knows who owns the queue and there is nothing to encode.
The cheapest way to not leak a sender is to never have a field for one.

The queue id is authenticated as associated data, so a relay cannot move a
sealed record from one queue to another and have it open.

---

## 9. Client ↔ relay

Every frame is exactly **2,048 bytes**, padded with random bytes.

```
Frame = u8(type) || u8(0) || u16(0) || u32(body_len) || raw(body) || raw(padding)
```

| Type | Direction | Body |
|---|---|---|
| 1 Deposit | C→R | `Deposit` |
| 2 Challenge | C→R | `raw(queue_id : 16)` |
| 3 ChallengeReply | R→C | `raw(challenge : 32)` |
| 4 Retrieve | C→R | `queue_id \|\| challenge \|\| retrieval_public \|\| proof` |
| 5 Delivery | R→C | `bytes32(sealed) \|\| u32(remaining)` |
| 6 Ack | R→C | empty |
| 7 Refuse | R→C | empty |
| 8 Padding | both | random |
| 9 WakeRegister | C→R | `WakeRegistration` |

**Refusals carry no reason.** A relay distinguishing "bad proof" from "unknown
queue" from "rate limited" is an oracle for probing which queues exist.

**An empty queue returns a Delivery with an empty body**, not a Refuse — same
type, same size, so "nothing waiting" is not observable.

---

## 10. Push wake

```
wake_id = BLAKE3-keyed(wake_secret, "void/v1/push/wake-id" || u64(epoch))[0..16]
epoch   = unix_seconds / 21600        // 6 hours
```

The relay's queue→wake mapping is dropped when the epoch changes, so it never
becomes a durable device identifier. A push carries a wake identifier and
nothing else — the `PushSender` trait has no parameter that could hold a sender,
preview, or queue.

Relays add up to 30 seconds of randomised delay before pushing (§9.3.1's
mitigation).

**This does not solve §9.3.1.** Apple and Google still see that a device was
pinged and when, because they operate the delivery network. Push is off by
default and the UI says so.

---

## 11. Signature semantics

Ed25519 verification here is **cofactorless** — the re-derived `R` encoding is
compared against the supplied one — and a non-canonically-reduced `s` is
rejected. That combination matches ref10 and the majority of deployed verifiers.

Void relies on neither signature uniqueness nor batch-verification equivalence,
so the known divergences between verifier definitions do not affect any Void
security property.

---

## 12. Storage

```
file   = header || record*
header = magic(8) || u16(version) || u32(m_cost) || u32(t_cost) || u32(lanes)
      || u32(0) || raw(salt : 16) || bytes32(wrapped_dek)
record = u64(id) || u8(kind) || u64(expires_at) || u32(len)
      || raw(nonce : 24) || sealed(len + 16)
```

Per-record key: `BLAKE3-keyed(dek, "void/v1/store/row" || u64(id))`.

Record AAD: **the full header** `|| u64(id) || u8(kind) || u64(expires_at)`.
Binding the header in means any edit to the KDF parameters or the wrapped key
invalidates every record, rather than being silently accepted.

The header is plaintext by design. FR-STOR-05 does not ask us to hide that a
Void database exists, and PRD §7.4.1 explains at length why pretending otherwise
is worse than useless.

---

## 13. Export archive

```
header  = "VOIDEXP\x01" || u16(version) || u32(m_cost) || u32(t_cost)
       || u32(lanes) || raw(salt : 16) || raw(nonce : 24)
archive = header || XChaCha20-Poly1305(key, nonce, aad = header, payload)
```

Key: Argon2id at 256 MiB / 4 passes / 4 lanes.

The header is authenticated, so the cost parameters cannot be downgraded by an
attacker who can edit the file — and an archive claiming less than 8 MiB is
refused outright.

The payload stores identity **seeds** (3 × 32 bytes), not expanded keys: an
ML-DSA secret key is 4,896 bytes and its seed is 32.

---

## 13a. Message content framing

Every ratchet plaintext carries a kind byte before its body:

```
plaintext = u8(kind) || body
kind 1 = Text   body = UTF-8
kind 2 = Call   body = CallSignal (§13b)
```

An unknown kind is an error, never a silent drop — a message a client cannot
read must not look to the sender like delivery.

The kind is **inside** the ratchet ciphertext, not in the record header. Putting
a content type where fragmentation could see it would tell the relay which of
your messages are calls; here, a call offer and a greeting are identical on the
wire in size and in every observable field.

This framing is why `PROTOCOL_ID` is `v2`. It changes no key derivation, but a
v1 and a v2 client would decrypt each other successfully and then misread every
message, so the handshake must fail instead.

---

## 13b. Calls (D-024)

Two channels with opposite requirements, carried differently.

**Signalling** is an ordinary encrypted message (§13a, kind 2):

```
CallSignal = u8(1) || raw(call_id : 16) || bytes16(onion_address)
           || u16(port) || raw(media_secret : 32)      -- Offer
           = u8(2) || raw(call_id : 16) || u8(accepted) -- Answer
           = u8(3) || raw(call_id : 16) || u8(reason)   -- End
```

**Media** is a direct connection over paired ephemeral onion services and never
touches the relay. The caller publishes; the callee dials. That direction is
chosen so the descriptor upload overlaps the peer's retrieval delay rather than
adding to it, and so declining a call leaves nothing published anywhere.

```
k_c2e   = KDF("void/v1/call/media/c2e", media_secret)
k_e2c   = KDF("void/v1/call/media/e2c", media_secret)
frame   = u32(seq) || AEAD(k_dir, nonce = seq, aad = call_id,
                           u16(len) || audio || padding)
MEDIA_PAYLOAD_LEN = 120, fixed
```

Directional keys are required, not stylistic: both ends begin at sequence zero,
so one shared key would collide nonces on the first frame.

`media_secret` travels only inside a ratchet-encrypted offer. The onion address
authenticates the *service* (a v3 address is an Ed25519 public key) but says
nothing about whose service it is; that comes from the offer having arrived
through a channel only the contact can write to. A compromised onion service
therefore carries media it cannot read.

**Constant bitrate, no voice-activity detection.** Every frame is padded to one
size and emitted on a fixed cadence whether or not anyone is speaking. Packet
sizes that track speech leak phonetics, which is a published attack rather than
a theoretical one.

**Replay and reordering.** A frame at or below the highest sequence already
opened is refused. Voice tolerates loss but not reordering into the past: a
late frame played anyway is a syllable out of order, and a replayed one is a
repeated syllable.

*Tests:* `call::tests::*` in `void-proto`, and the four call tests in
`void-client/tests/end_to_end.rs`.

**Measured cost.** `experiments/onion-call/RESULTS.md`: 0% loss over 4,500
packets, round-trip p50 376–528 ms, p95 635–1112 ms, mouth-to-ear 470–870 ms.
ITU-T G.114 puts interactive conversation's limit at 400 ms, so a call works for
turn-taking and not for interruption. The interface states the delay rather than
designing around it.

**What a call costs the user, and what it does not.** Media is Tor in both
directions, so neither end learns the other's IP address and neither does the
relay. Two things do change relative to messaging, and `CALL_DISCLOSURE`
(shown before connecting, in both directions) names both: the peer learns you
are online *now*, which the mailbox model otherwise hides; and a call is a
sustained stream where messaging is one fixed-size record every
`PAD_INTERVAL_MS` regardless of activity, which is a materially better
correlation target. Any claim that a call exposes location would be false and is
asserted against in `the_call_disclosure_says_what_is_true_and_not_what_is_not`.

---

## 14. Constants

| Constant | Value |
|---|---|
| `RECORD_SIZE` | 1,024 |
| `RECORD_BODY_CAPACITY` | 1,009 |
| `SEALED_RECORD_SIZE` | 1,064 |
| `FRAME_SIZE` | 2,048 |
| `PAD_INTERVAL_MS` | 5,000 |
| `RETRIEVAL_JITTER_MS` | 30,000 |
| `KEM_RATCHET_INTERVAL` | 4 |
| `MAX_SKIP` | 1,000 |
| `MAX_SKIPPED_STORED` | 2,000 |
| `MAX_FRAGMENTS` | 512 |
| Queue TTL | 14 days |
| Deposit rate limit | 600/queue/hour |
| Wake epoch | 6 hours |
| Invitation TTL | 24 hours |

---

## 15. Security properties, and where each is enforced

| Property | Enforced by | Test |
|---|---|---|
| Confidentiality against a quantum adversary | hybrid handshake + ratchet | `full_handshake_and_conversation` |
| Forward secrecy | one-way chain step | `replay_is_rejected` |
| Post-compromise security (classical) | DH step per direction change | `ratchet_actually_steps` |
| Post-compromise security (PQ) | KEM step per 4 DH steps | `kem_ratchet_runs_on_schedule` |
| Relay cannot read | sealed deposits | `the_relay_never_sees_plaintext` |
| Relay cannot identify sender | no sender field exists | `the_deposit_contains_no_sender_field` |
| Relay cannot link queues | independent per-pair derivation | `the_relay_cannot_link_two_queues_of_one_user` |
| Relay cannot move records | queue id is AEAD associated data | `a_relay_that_moves_a_deposit_between_queues_is_detected` |
| Relay cannot forge messages | ratchet authentication | `a_relay_returning_forged_records_cannot_inject_messages` |
| Relay cannot destroy a session by replay | receive commits after the tag (§6.5.1) | `a_relay_redelivering_an_old_record_cannot_kill_a_conversation` |
| Relay cannot tell a call from a message | content kind is inside the ciphertext | `call_signalling_is_indistinguishable_from_a_message_to_the_relay` |
| Call media is confidential to the two ends | keys derive from a secret sent inside the ratchet | `the_two_directions_use_different_keys` |
| Relay cannot stall delivery with partial messages | reassembly evicts, never fails | `a_flood_of_stalled_messages_does_not_block_a_real_one` |
| Relay holds no key material | intrinsic proof verification | `a_key_that_does_not_address_the_queue_is_refused` |
| No message-length leak | fixed record size | `every_deposit_the_relay_sees_is_the_same_size` |
| Send timing independent of typing | constant-rate scheduler | `emission_is_constant_rate_regardless_of_traffic` |
| Fail closed without Tor | no fallback path exists | `a_client_that_loses_the_relay_queues_rather_than_failing_open` |
| MITM at first contact | signed bundle + out-of-band verification | `tampered_bundle_is_rejected_before_any_secret_is_computed` |
| Silent key change | blocked in the engine, one place | `sending_to_a_contact_whose_key_changed_is_blocked` |
| Duress destruction total | vault key destroyed | `a_destroyed_vault_makes_the_database_unopenable` |

---

## 16. What this protocol does not do

Restated from PRD §9.3, because a specification that lists only its guarantees
is misleading:

- It does not protect a compromised device. Spyware reads plaintext at the UI
  layer regardless of anything here.
- It does not hide that Void is installed.
- It does not prevent Apple or Google from observing push delivery timing.
- It does not defeat an adversary who can watch both endpoints over a long
  period and correlate.
- It provides no plausible deniability. It provides fast, verifiable destruction
  instead.
