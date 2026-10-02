//! The hybrid post-quantum handshake (PQXDH-style).
//!
//! Void's handshake follows the shape of Signal's PQXDH: an X3DH-style
//! multi-DH agreement, with an ML-KEM encapsulation to a signed post-quantum
//! prekey folded into the same KDF.
//!
//! ## What is exchanged, and how
//!
//! There is no key server (FR-DISC-01). A responder's [`PrekeyBundle`] travels
//! out of band — inside a QR code or a one-time invitation link — so the only
//! party that ever holds it is the person the responder handed it to.
//!
//! ```text
//!   Bob (responder)                         Alice (initiator)
//!   ---------------                         -----------------
//!   generates IK_B, SPK_B, PQSPK_B, OPK_B
//!   signs the prekeys with IK_B
//!   encodes a PrekeyBundle       ---QR--->  verifies both signatures
//!                                           generates EK_A
//!                                           DH1 = DH(IK_A, SPK_B)
//!                                           DH2 = DH(EK_A, IK_B)
//!                                           DH3 = DH(EK_A, SPK_B)
//!                                           DH4 = DH(EK_A, OPK_B)
//!                                           (CT, SS) = Encaps(PQSPK_B)
//!                                           RK = KDF(DH1..DH4, SS; transcript)
//!                              <--Initial-- signs the transcript with IK_A
//! ```
//!
//! ## Why the responder's signature is checked before anything else
//!
//! An unauthenticated prekey bundle is a machine-in-the-middle waiting to
//! happen: an attacker who substitutes their own prekeys reads everything. The
//! bundle carries a hybrid signature over its own contents, and
//! [`PrekeyBundle::verify`] is called before any secret is computed. FR-DISC-04
//! then requires the user to compare fingerprints out of band, which is what
//! actually binds the bundle to a person rather than to a key.
//!
//! ## Why the transcript is bound in
//!
//! The root key is derived with the transcript hash as HKDF salt, and the
//! initiator signs that same transcript. This makes the handshake
//! *contributive*: neither party can steer the resulting key, and a replayed
//! or spliced bundle produces a different transcript and therefore a different
//! root key that the peer will not derive.

use alloc::vec::Vec;

use void_crypto::{blake3, kdf, mlkem, x25519, Zeroize};

use crate::identity::{Identity, IdentityPublic, Signature};
use crate::queue::{DepositKey, QueueSecret};
use crate::ratchet::Ratchet;
use crate::wire::{concat_labeled, Reader, Writer};
use crate::{ProtoError, Result};

/// Protocol identifier bound into every transcript. Changing the protocol in a
/// way that alters key derivation must change this string.
///
/// Bumped to `v2` when [`crate::content`] put a kind byte in front of every
/// ratchet plaintext. That change alters no key derivation, but it does change
/// how a plaintext is read, and a v1 client talking to a v2 client would
/// decrypt successfully and then misinterpret every message it received. A
/// handshake that fails is the correct outcome there, so the identifier moved
/// with the framing.
///
/// Bumped to `v3` when call offers gained the time they were sent and calls
/// gained a busy signal (`crate::call`). A v2 client would fail to decode a v3
/// offer and silently never ring — the same reasoning again.
///
/// Bumped to `v4` when files joined the content kinds (`crate::content`). A
/// v3 client cannot read a file: it would drop the message as malformed and
/// the sender would still see "Sent". Failing the handshake instead is what
/// the content framing's own documentation promises for an unknown kind.
pub const PROTOCOL_ID: &[u8] = b"void/v4/pqxdh/x25519+mlkem1024/ed25519+mldsa87";

/// Domain separator for the prekey signature.
const PREKEY_SIG_CONTEXT: &[u8] = b"void/v1/prekey-bundle";
/// Domain separator for the initiator's transcript signature.
const INITIAL_SIG_CONTEXT: &[u8] = b"void/v1/initial-message";

/// The responder's secret half of a published bundle.
///
/// Held on the responder's device only. `one_time` is consumed on first use,
/// which is what makes an invitation single-use (FR-DISC-02).
pub struct PrekeySecrets {
    /// Signed prekey pair.
    pub signed: x25519::KeyPair,
    /// One-time prekey pair, if this bundle carries one.
    pub one_time: Option<x25519::KeyPair>,
    /// ML-KEM prekey encapsulation key.
    pub kem_encaps: Vec<u8>,
    /// ML-KEM prekey decapsulation key.
    pub kem_decaps: Vec<u8>,
}

impl Drop for PrekeySecrets {
    fn drop(&mut self) {
        self.kem_decaps.zeroize();
    }
}

/// Version byte of [`PrekeySecrets::serialize`]'s layout.
const PREKEY_SECRETS_VERSION: u8 = 1;

impl PrekeySecrets {
    /// Serialize for storage, so an invitation outlives the process that made
    /// it.
    ///
    /// This is raw secret key material with no encryption of its own — the
    /// same contract as `Ratchet::serialize` (`docs/PROTOCOL.md` §6.6): the
    /// caller writes it only inside an already-encrypted-at-rest record, and
    /// zeroizes the returned buffer after.
    ///
    /// ```text
    /// PrekeySecrets = u8(version)                          // = 1
    ///              || raw(signed_secret : 32)
    ///              || u8(has_one_time) || raw(one_time_secret : 32)   // zeroed if absent
    ///              || bytes16(kem_encaps : 1568)
    ///              || bytes16(kem_decaps : 64)
    /// ```
    ///
    /// The X25519 public halves are re-derived on load rather than stored, so
    /// a corrupted record cannot pair one key's secret with another's public.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(PREKEY_SECRETS_VERSION).raw(&self.signed.secret);
        match &self.one_time {
            Some(k) => {
                w.u8(1).raw(&k.secret);
            }
            None => {
                w.u8(0).raw(&[0u8; 32]);
            }
        }
        w.bytes16(&self.kem_encaps).bytes16(&self.kem_decaps);
        w.finish()
    }

    /// Restore from [`serialize`](Self::serialize)'s output. A wrong version or
    /// a wrong key length is malformed, never partially parsed.
    pub fn deserialize(bytes: &[u8]) -> Result<PrekeySecrets> {
        let mut r = Reader::new(bytes);
        if r.u8()? != PREKEY_SECRETS_VERSION {
            return Err(ProtoError::Malformed);
        }
        let signed = x25519::KeyPair::from_secret(r.array::<32>()?);
        let has_one_time = r.u8()?;
        let mut one_time_secret = r.array::<32>()?;
        let one_time = match has_one_time {
            0 => None,
            1 => Some(x25519::KeyPair::from_secret(one_time_secret)),
            _ => {
                one_time_secret.zeroize();
                return Err(ProtoError::Malformed);
            }
        };
        one_time_secret.zeroize();
        let kem_encaps = r.bytes16()?.to_vec();
        // Owned by the struct from here on, so its Drop zeroizes the
        // decapsulation key on every early return below.
        let secrets = PrekeySecrets {
            signed,
            one_time,
            kem_encaps,
            kem_decaps: r.bytes16()?.to_vec(),
        };
        r.finish()?;
        if secrets.kem_encaps.len() != mlkem::ENCAPS_KEY_LEN
            || secrets.kem_decaps.len() != mlkem::DECAPS_KEY_LEN
        {
            return Err(ProtoError::Malformed);
        }
        Ok(secrets)
    }
}

/// A responder's published prekey bundle.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrekeyBundle {
    /// Responder's identity.
    pub identity: IdentityPublic,
    /// Signed X25519 prekey.
    pub signed_prekey: [u8; 32],
    /// One-time X25519 prekey, if present.
    pub one_time_prekey: Option<[u8; 32]>,
    /// ML-KEM-1024 encapsulation prekey.
    pub kem_prekey: Vec<u8>,
    /// Hybrid signature by `identity` over the bundle body.
    pub signature: Signature,
    /// The mailbox queue the initiator should deposit into, together with the
    /// key that seals records for it (FR-DISC-03).
    ///
    /// Publishing the *deposit* capability — never the retrieval capability —
    /// is what lets a stranger send the first message without either party
    /// having a shared secret yet. See [`DepositKey`].
    pub queue: DepositKey,
    /// Relay address hint, as an onion service name. Not authenticated as a
    /// trust anchor — a wrong relay costs availability, never confidentiality.
    pub relay_hint: Vec<u8>,
}

impl PrekeyBundle {
    /// The bytes covered by `signature`.
    fn signed_body(
        identity: &IdentityPublic,
        signed_prekey: &[u8; 32],
        one_time_prekey: &Option<[u8; 32]>,
        kem_prekey: &[u8],
        queue: &DepositKey,
        relay_hint: &[u8],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes16(PREKEY_SIG_CONTEXT)
            .bytes16(PROTOCOL_ID)
            .bytes32(&identity.encode())
            .raw(signed_prekey);
        // Presence is encoded explicitly, never by absence: a bundle with no
        // one-time prekey and a bundle with an all-zero one must not produce
        // the same signed bytes.
        match one_time_prekey {
            Some(k) => {
                w.u8(1).raw(k);
            }
            None => {
                w.u8(0).raw(&[0u8; 32]);
            }
        }
        w.bytes16(kem_prekey)
            .raw(&queue.queue_id)
            .raw(&queue.envelope_key)
            .bytes16(relay_hint);
        w.finish()
    }

    /// Build and sign a bundle, returning it with the secrets to retain.
    pub fn create(
        identity: &Identity,
        queue: &QueueSecret,
        relay_hint: &[u8],
        with_one_time: bool,
    ) -> Result<(PrekeyBundle, PrekeySecrets)> {
        let signed = x25519::KeyPair::generate().map_err(|_| ProtoError::Crypto)?;
        let one_time = if with_one_time {
            Some(x25519::KeyPair::generate().map_err(|_| ProtoError::Crypto)?)
        } else {
            None
        };
        let kem = mlkem::keygen().map_err(|_| ProtoError::Crypto)?;

        let one_time_public = one_time.as_ref().map(|k| k.public);
        let deposit_key = queue.deposit_key();
        let body = Self::signed_body(
            &identity.public,
            &signed.public,
            &one_time_public,
            &kem.encaps_key,
            &deposit_key,
            relay_hint,
        );
        let signature = identity.sign(&body)?;

        let bundle = PrekeyBundle {
            identity: identity.public.clone(),
            signed_prekey: signed.public,
            one_time_prekey: one_time_public,
            kem_prekey: kem.encaps_key.clone(),
            signature,
            queue: deposit_key,
            relay_hint: relay_hint.to_vec(),
        };
        let secrets = PrekeySecrets {
            signed,
            one_time,
            kem_encaps: kem.encaps_key.clone(),
            kem_decaps: kem.decaps_key.clone(),
        };
        Ok((bundle, secrets))
    }

    /// Verify the bundle's self-signature and the well-formedness of its keys.
    ///
    /// This must be called before any secret is derived from the bundle.
    #[must_use]
    pub fn verify(&self) -> bool {
        if mlkem::validate_encaps_key(&self.kem_prekey).is_err() {
            return false;
        }
        let body = Self::signed_body(
            &self.identity,
            &self.signed_prekey,
            &self.one_time_prekey,
            &self.kem_prekey,
            &self.queue,
            &self.relay_hint,
        );
        self.identity.verify(&body, &self.signature)
    }

    /// Canonical encoding, for QR codes and invitation links.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes32(&self.identity.encode()).raw(&self.signed_prekey);
        match self.one_time_prekey {
            Some(k) => {
                w.u8(1).raw(&k);
            }
            None => {
                w.u8(0).raw(&[0u8; 32]);
            }
        }
        w.bytes16(&self.kem_prekey)
            .bytes32(&self.signature.encode())
            .raw(&self.queue.queue_id)
            .raw(&self.queue.envelope_key)
            .bytes16(&self.relay_hint);
        w.finish()
    }

    /// Decode a bundle. Does **not** verify it; call [`verify`](Self::verify).
    pub fn decode(bytes: &[u8]) -> Result<PrekeyBundle> {
        let mut r = Reader::new(bytes);
        let identity = IdentityPublic::decode(r.bytes32_max(8 * 1024)?)?;
        let signed_prekey = r.array::<32>()?;
        let has_otp = r.u8()?;
        let otp_bytes = r.array::<32>()?;
        let one_time_prekey = match has_otp {
            0 => None,
            1 => Some(otp_bytes),
            _ => return Err(ProtoError::Malformed),
        };
        let kem_prekey = r.bytes16()?.to_vec();
        let signature = Signature::decode(r.bytes32_max(16 * 1024)?)?;
        let queue_id = r.array::<16>()?;
        let envelope_key = r.array::<32>()?;
        let relay_hint = r.bytes16()?.to_vec();
        r.finish()?;
        if kem_prekey.len() != mlkem::ENCAPS_KEY_LEN {
            return Err(ProtoError::Malformed);
        }
        Ok(PrekeyBundle {
            identity,
            signed_prekey,
            one_time_prekey,
            kem_prekey,
            signature,
            queue: DepositKey {
                queue_id,
                envelope_key,
            },
            relay_hint,
        })
    }
}

/// The initiator's first message, deposited into the responder's queue.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InitialMessage {
    /// Initiator's identity.
    pub identity: IdentityPublic,
    /// Initiator's ephemeral X25519 public key.
    pub ephemeral: [u8; 32],
    /// ML-KEM ciphertext encapsulated to the responder's KEM prekey.
    pub kem_ciphertext: Vec<u8>,
    /// Which one-time prekey was consumed, echoed so the responder can find it.
    pub used_one_time: bool,
    /// Initiator's signature over the handshake transcript.
    pub signature: Signature,
    /// The first ratchet message, encrypted under the derived root key.
    pub first_message: Vec<u8>,
}

impl InitialMessage {
    /// Canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes32(&self.identity.encode())
            .raw(&self.ephemeral)
            .bytes16(&self.kem_ciphertext)
            .u8(u8::from(self.used_one_time))
            .bytes32(&self.signature.encode())
            .bytes32(&self.first_message);
        w.finish()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<InitialMessage> {
        let mut r = Reader::new(bytes);
        let identity = IdentityPublic::decode(r.bytes32_max(8 * 1024)?)?;
        let ephemeral = r.array::<32>()?;
        let kem_ciphertext = r.bytes16()?.to_vec();
        let used_one_time = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ProtoError::Malformed),
        };
        let signature = Signature::decode(r.bytes32_max(16 * 1024)?)?;
        let first_message = r.bytes32_max(1024 * 1024)?.to_vec();
        r.finish()?;
        if kem_ciphertext.len() != mlkem::CIPHERTEXT_LEN {
            return Err(ProtoError::Malformed);
        }
        Ok(InitialMessage {
            identity,
            ephemeral,
            kem_ciphertext,
            used_one_time,
            signature,
            first_message,
        })
    }
}

/// Compute the handshake transcript hash.
///
/// Everything that identifies the session goes in, length-prefixed, in a fixed
/// order. Both parties compute this independently; if they disagree about any
/// field the root keys differ and nothing decrypts.
#[allow(clippy::too_many_arguments)]
fn transcript(
    initiator: &IdentityPublic,
    responder: &IdentityPublic,
    ephemeral: &[u8; 32],
    signed_prekey: &[u8; 32],
    one_time_prekey: &Option<[u8; 32]>,
    kem_prekey: &[u8],
    kem_ciphertext: &[u8],
) -> [u8; 32] {
    let mut w = Writer::new();
    w.bytes16(PROTOCOL_ID)
        .bytes32(&initiator.encode())
        .bytes32(&responder.encode())
        .raw(ephemeral)
        .raw(signed_prekey);
    match one_time_prekey {
        Some(k) => {
            w.u8(1).raw(k);
        }
        None => {
            w.u8(0).raw(&[0u8; 32]);
        }
    }
    w.bytes16(kem_prekey).bytes16(kem_ciphertext);
    blake3::hash(w.as_slice())
}

/// The result of a completed handshake on either side.
pub struct Established {
    /// The ratchet, ready to use.
    pub ratchet: Ratchet,
    /// The peer's verified identity.
    pub peer: IdentityPublic,
    /// The queue we deposit into for this contact.
    pub send_queue: QueueSecret,
    /// The queue we collect from for this contact.
    pub recv_queue: QueueSecret,
}

/// Derive the two per-direction steady-state queues from the handshake output.
///
/// ## Why not keep using the bundle's queue
///
/// The bundle's queue is a *published* address: anyone holding the invitation
/// can deposit into it, which is exactly right for a first contact and exactly
/// wrong for an ongoing conversation. So the handshake output — which only the
/// two parties can compute — seeds a fresh pair of queues, one per direction,
/// and the bundle queue is abandoned after the first message.
///
/// Both parties derive both queues. That is deliberate: they are the two
/// endpoints of the conversation and already share the ratchet state, so
/// splitting retrieval authority between them would add mechanism without
/// adding a trust boundary. The boundary that matters is the relay, and the
/// relay has neither.
fn derive_pair_queues(queue_seed: &[u8; 32]) -> (QueueSecret, QueueSecret) {
    let a2b = blake3::derive_key_32("void/v1/queue/initiator-to-responder", queue_seed);
    let b2a = blake3::derive_key_32("void/v1/queue/responder-to-initiator", queue_seed);
    (
        QueueSecret::from_parts(a2b, 0),
        QueueSecret::from_parts(b2a, 0),
    )
}

/// Run the initiator side.
///
/// Returns the [`InitialMessage`] to deposit and an [`Established`] session.
/// `reply_queue_id` is the queue we have allocated for the peer to answer on.
pub fn initiate(
    identity: &Identity,
    bundle: &PrekeyBundle,
    first_plaintext: &[u8],
) -> Result<(InitialMessage, Established, DepositKey)> {
    if !bundle.verify() {
        return Err(ProtoError::BadSignature);
    }

    let ephemeral = x25519::KeyPair::generate().map_err(|_| ProtoError::Crypto)?;

    // Four Diffie-Hellmans, exactly as X3DH.
    let dh1 = identity
        .dh(&bundle.signed_prekey)
        .map_err(|_| ProtoError::InvalidKey)?;
    let dh2 = ephemeral
        .dh(&bundle.identity.x25519)
        .map_err(|_| ProtoError::InvalidKey)?;
    let dh3 = ephemeral
        .dh(&bundle.signed_prekey)
        .map_err(|_| ProtoError::InvalidKey)?;
    let dh4 = match bundle.one_time_prekey {
        Some(otp) => Some(ephemeral.dh(&otp).map_err(|_| ProtoError::InvalidKey)?),
        None => None,
    };

    let (kem_ciphertext, kem_secret) =
        mlkem::encaps(&bundle.kem_prekey).map_err(|_| ProtoError::InvalidKey)?;

    // The reply queue is derived from the handshake itself, so it does not need
    // to be chosen in advance or transmitted — the responder computes the same
    // value. What *is* transmitted is nothing: the transcript binds the
    // ephemeral key, which is what makes the derived queues unique per session.
    let tr = transcript(
        &identity.public,
        &bundle.identity,
        &ephemeral.public,
        &bundle.signed_prekey,
        &bundle.one_time_prekey,
        &bundle.kem_prekey,
        &kem_ciphertext,
    );

    let (root, queue_seed) = derive_root(&dh1, &dh2, &dh3, dh4.as_ref(), &kem_secret, &tr);
    let (a2b, b2a) = derive_pair_queues(&queue_seed);

    // The initiator signs the transcript. This is the only place a per-session
    // identity signature appears (D-002): everything after is authenticated by
    // the ratchet.
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(INITIAL_SIG_CONTEXT);
    sig_input.extend_from_slice(&tr);
    let signature = identity.sign(&sig_input)?;

    let mut ratchet =
        Ratchet::init_initiator(root, bundle.signed_prekey, bundle.kem_prekey.clone())?;
    let first = ratchet.encrypt(first_plaintext)?;

    let initial = InitialMessage {
        identity: identity.public.clone(),
        ephemeral: ephemeral.public,
        kem_ciphertext,
        used_one_time: bundle.one_time_prekey.is_some(),
        signature,
        first_message: first.encode(),
    };

    Ok((
        initial,
        Established {
            ratchet,
            peer: bundle.identity.clone(),
            send_queue: a2b,
            recv_queue: b2a,
        },
        bundle.queue.clone(),
    ))
}

/// Run the responder side against a received [`InitialMessage`].
///
/// Returns the established session and the decrypted first plaintext.
pub fn respond(
    identity: &Identity,
    secrets: &PrekeySecrets,
    initial: &InitialMessage,
) -> Result<(Established, Vec<u8>)> {
    // Each term is the mirror of the initiator's: DH1 = DH(IK_A, SPK_B) is
    // computed here as DH(SPK_B, IK_A), and so on. Getting one of these pairs
    // backwards yields a root key mismatch rather than a silent weakness,
    // which is why the round-trip test in this module is the real check.
    let dh1 = secrets
        .signed
        .dh(&initial.identity.x25519)
        .map_err(|_| ProtoError::InvalidKey)?;
    let dh2 = identity
        .dh(&initial.ephemeral)
        .map_err(|_| ProtoError::InvalidKey)?;
    let dh3 = secrets
        .signed
        .dh(&initial.ephemeral)
        .map_err(|_| ProtoError::InvalidKey)?;
    let dh4 = if initial.used_one_time {
        let otp = secrets.one_time.as_ref().ok_or(ProtoError::NotReady)?;
        Some(
            otp.dh(&initial.ephemeral)
                .map_err(|_| ProtoError::InvalidKey)?,
        )
    } else {
        None
    };

    let kem_secret = mlkem::decaps(&secrets.kem_decaps, &initial.kem_ciphertext)
        .map_err(|_| ProtoError::InvalidKey)?;

    let one_time_public = secrets.one_time.as_ref().map(|k| k.public);
    let tr = transcript(
        &initial.identity,
        &identity.public,
        &initial.ephemeral,
        &secrets.signed.public,
        &if initial.used_one_time {
            one_time_public
        } else {
            None
        },
        &secrets.kem_encaps,
        &initial.kem_ciphertext,
    );

    // Verify the initiator's signature over the transcript *before* using the
    // derived key for anything.
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(INITIAL_SIG_CONTEXT);
    sig_input.extend_from_slice(&tr);
    if !initial.identity.verify(&sig_input, &initial.signature) {
        return Err(ProtoError::BadSignature);
    }

    let (root, queue_seed) = derive_root(&dh1, &dh2, &dh3, dh4.as_ref(), &kem_secret, &tr);
    let (a2b, b2a) = derive_pair_queues(&queue_seed);

    let prekey_copy = x25519::KeyPair::from_secret(secrets.signed.secret);
    let mut ratchet = Ratchet::init_responder(
        root,
        prekey_copy,
        secrets.kem_encaps.clone(),
        secrets.kem_decaps.clone(),
    );
    let first = crate::ratchet::Message::decode(&initial.first_message)?;
    let plaintext = ratchet.decrypt(&first)?;

    Ok((
        Established {
            ratchet,
            peer: initial.identity.clone(),
            // Mirrored: the responder sends on b2a and collects from a2b.
            send_queue: b2a,
            recv_queue: a2b,
        },
        plaintext,
    ))
}

/// Derive the root key and the queue seed from the handshake secrets.
///
/// One KDF invocation produces 64 bytes: the first 32 seed the ratchet, the
/// second 32 seed the per-direction queues. Deriving both from the same call
/// with distinct offsets keeps them independent while making it obvious in
/// review that no other material influences either.
fn derive_root(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
    kem_secret: &[u8; 32],
    tr: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    // Length-prefix every secret so no two different tuples collide.
    let empty: [u8; 32] = [0u8; 32];
    let parts: [&[u8]; 5] = [
        dh1,
        dh2,
        dh3,
        match dh4 {
            Some(d) => d,
            None => &empty,
        },
        kem_secret,
    ];
    let mut combined = concat_labeled(&parts);
    let mut out = kdf::derive_hybrid(&[&combined], tr, kdf::LABEL_HANDSHAKE_ROOT, 64);
    combined.zeroize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&out[..32]);
    let mut queue_seed = [0u8; 32];
    queue_seed.copy_from_slice(&out[32..]);
    out.zeroize();
    (root, queue_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Identity {
        Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[3u8; 32])
    }
    fn bob() -> Identity {
        Identity::from_seeds(&[4u8; 32], &[5u8; 32], &[6u8; 32])
    }
    fn queue(seed: u8) -> QueueSecret {
        QueueSecret::from_parts([seed; 32], 0)
    }

    #[test]
    fn full_handshake_and_conversation() {
        let (a, b) = (alice(), bob());
        let bq = queue(9);
        let (bundle, secrets) = PrekeyBundle::create(&b, &bq, b"relay.onion", true).unwrap();
        assert!(bundle.verify());

        let (initial, mut a_sess, first_deposit) = initiate(&a, &bundle, b"hello bob").unwrap();
        // The first message goes to the bundle's published queue.
        assert_eq!(first_deposit.queue_id, bq.queue_id());

        let (mut b_sess, first) = respond(&b, &secrets, &initial).unwrap();
        assert_eq!(first, b"hello bob");
        assert_eq!(a_sess.peer, b.public);
        assert_eq!(b_sess.peer, a.public);

        // Both sides must agree on the two steady-state queues, mirrored.
        assert_eq!(a_sess.send_queue.queue_id(), b_sess.recv_queue.queue_id());
        assert_eq!(a_sess.recv_queue.queue_id(), b_sess.send_queue.queue_id());
        assert_ne!(a_sess.send_queue.queue_id(), a_sess.recv_queue.queue_id());
        // And neither is the bundle's published queue: that one is abandoned.
        assert_ne!(a_sess.send_queue.queue_id(), bq.queue_id());
        assert_ne!(a_sess.recv_queue.queue_id(), bq.queue_id());

        for i in 0..5u8 {
            let m = b_sess.ratchet.encrypt(&[i]).unwrap();
            assert_eq!(a_sess.ratchet.decrypt(&m).unwrap(), alloc::vec![i]);
            let m = a_sess.ratchet.encrypt(&[i, i]).unwrap();
            assert_eq!(b_sess.ratchet.decrypt(&m).unwrap(), alloc::vec![i, i]);
        }
    }

    #[test]
    fn handshake_without_one_time_prekey() {
        let (a, b) = (alice(), bob());
        let bq = queue(10);
        let (bundle, secrets) = PrekeyBundle::create(&b, &bq, b"r", false).unwrap();
        assert!(bundle.one_time_prekey.is_none());
        let (initial, _, _) = initiate(&a, &bundle, b"hi").unwrap();
        let (_, first) = respond(&b, &secrets, &initial).unwrap();
        assert_eq!(first, b"hi");
    }

    #[test]
    fn the_bundle_publishes_deposit_authority_only() {
        // A holder of the bundle can seal to the queue but cannot collect from
        // it. That asymmetry is what makes an open invitation safe to hand out.
        let b = bob();
        let bq = queue(11);
        let (bundle, _) = PrekeyBundle::create(&b, &bq, b"r", true).unwrap();
        assert_eq!(bundle.queue.queue_id, bq.queue_id());
        assert_eq!(bundle.queue.envelope_key, bq.envelope_key());
        // Nothing in the bundle lets a holder prove retrieval.
        assert!(!bq.verify_retrieval(b"challenge", &bundle.queue.envelope_key));
    }

    #[test]
    fn tampered_bundle_is_rejected_before_any_secret_is_computed() {
        let (a, b) = (alice(), bob());
        let bq = queue(12);
        let (bundle, _) = PrekeyBundle::create(&b, &bq, b"r", true).unwrap();

        // Substituting the signed prekey — the classic MITM move.
        let mut evil = bundle.clone();
        evil.signed_prekey = x25519::KeyPair::from_secret([99u8; 32]).public;
        assert!(!evil.verify());
        assert!(matches!(
            initiate(&a, &evil, b"x"),
            Err(ProtoError::BadSignature)
        ));

        // Substituting the KEM prekey.
        let mut evil = bundle.clone();
        let other_kem = mlkem::keygen_derand(&[77u8; 32], &[78u8; 32]);
        evil.kem_prekey = other_kem.encaps_key.clone();
        assert!(!evil.verify());

        // Substituting the queue, which would redirect the first message.
        let mut evil = bundle.clone();
        evil.queue.queue_id = [0xFF; 16];
        assert!(!evil.verify());

        // Substituting only the envelope key, which would let an eavesdropper
        // read the first message. This is why the key is inside the signature.
        let mut evil = bundle.clone();
        evil.queue.envelope_key = [0xAA; 32];
        assert!(!evil.verify());

        // Substituting the whole identity.
        let mut evil = bundle.clone();
        evil.identity = a.public.clone();
        assert!(!evil.verify());
    }

    #[test]
    fn forged_initial_signature_is_rejected() {
        let (a, b) = (alice(), bob());
        let mallory = Identity::from_seeds(&[7u8; 32], &[8u8; 32], &[9u8; 32]);
        let bq = queue(13);
        let (bundle, secrets) = PrekeyBundle::create(&b, &bq, b"r", true).unwrap();
        let (mut initial, _, _) = initiate(&a, &bundle, b"x").unwrap();

        // Claim to be Mallory while presenting Alice's transcript signature.
        initial.identity = mallory.public.clone();
        assert!(respond(&b, &secrets, &initial).is_err());
    }

    #[test]
    fn wrong_responder_cannot_complete() {
        let (a, b) = (alice(), bob());
        let carol = Identity::from_seeds(&[10u8; 32], &[11u8; 32], &[12u8; 32]);
        let (bundle, _) = PrekeyBundle::create(&b, &queue(14), b"r", true).unwrap();
        let (_, carol_secrets) = PrekeyBundle::create(&carol, &queue(15), b"r", true).unwrap();
        let (initial, _, _) = initiate(&a, &bundle, b"x").unwrap();
        assert!(respond(&carol, &carol_secrets, &initial).is_err());
    }

    #[test]
    fn encodings_roundtrip() {
        let (a, b) = (alice(), bob());
        let bq = queue(16);
        let (bundle, secrets) = PrekeyBundle::create(&b, &bq, b"relay.onion", true).unwrap();
        let enc = bundle.encode();
        let decoded = PrekeyBundle::decode(&enc).unwrap();
        assert_eq!(decoded, bundle);
        assert!(decoded.verify());

        let (initial, _, _) = initiate(&a, &bundle, b"payload").unwrap();
        let enc = initial.encode();
        assert_eq!(InitialMessage::decode(&enc).unwrap(), initial);
        let (_, first) = respond(&b, &secrets, &InitialMessage::decode(&enc).unwrap()).unwrap();
        assert_eq!(first, b"payload");
    }

    #[test]
    fn truncated_encodings_are_rejected() {
        let b = bob();
        let (bundle, _) = PrekeyBundle::create(&b, &queue(17), b"r", true).unwrap();
        let enc = bundle.encode();
        for n in [0usize, 1, 100, enc.len() - 1] {
            assert!(PrekeyBundle::decode(&enc[..n]).is_err(), "len {n}");
        }
        let mut extra = enc.clone();
        extra.push(0);
        assert!(PrekeyBundle::decode(&extra).is_err());
    }

    #[test]
    fn two_initiators_to_one_bundle_derive_different_queues_and_roots() {
        // Two people who received the same invitation must not end up sharing a
        // queue or a key. The ephemeral key is in the transcript, so they do not.
        let b = bob();
        let a1 = alice();
        let a2 = Identity::from_seeds(&[20u8; 32], &[21u8; 32], &[22u8; 32]);
        let bq = queue(18);
        let (bundle, secrets) = PrekeyBundle::create(&b, &bq, b"r", true).unwrap();

        let (i1, s1, _) = initiate(&a1, &bundle, b"from a1").unwrap();
        let (i2, s2, _) = initiate(&a2, &bundle, b"from a2").unwrap();
        assert_ne!(i1.kem_ciphertext, i2.kem_ciphertext);
        assert_ne!(s1.send_queue.queue_id(), s2.send_queue.queue_id());
        assert_ne!(s1.recv_queue.queue_id(), s2.recv_queue.queue_id());

        let (b1, p1) = respond(&b, &secrets, &i1).unwrap();
        let (b2, p2) = respond(&b, &secrets, &i2).unwrap();
        assert_eq!(p1, b"from a1");
        assert_eq!(p2, b"from a2");
        assert_eq!(b1.recv_queue.queue_id(), s1.send_queue.queue_id());
        assert_eq!(b2.recv_queue.queue_id(), s2.send_queue.queue_id());
    }

    #[test]
    fn a_replayed_initial_message_derives_the_same_session() {
        // Replay protection is the one-time prekey's job, enforced above this
        // layer. What must hold here is that the derivation is deterministic:
        // a replay does not produce a *different* session that could be used to
        // confuse the responder.
        let (a, b) = (alice(), bob());
        let (bundle, secrets) = PrekeyBundle::create(&b, &queue(19), b"r", true).unwrap();
        let (initial, _, _) = initiate(&a, &bundle, b"x").unwrap();
        let (s1, _) = respond(&b, &secrets, &initial).unwrap();
        let (s2, _) = respond(&b, &secrets, &initial).unwrap();
        assert_eq!(s1.send_queue.queue_id(), s2.send_queue.queue_id());
    }

    #[test]
    fn restored_prekey_secrets_still_complete_the_handshake() {
        // An invitation must outlive the process that made it: the person it
        // was sent to may accept it hours later, after the app was killed.
        let (a, b) = (alice(), bob());
        for with_one_time in [true, false] {
            let (bundle, secrets) =
                PrekeyBundle::create(&b, &queue(20), b"r", with_one_time).unwrap();
            let bytes = secrets.serialize();
            let restored = PrekeySecrets::deserialize(&bytes).unwrap();
            assert_eq!(restored.serialize(), bytes, "the round trip is exact");
            assert_eq!(restored.signed.public, secrets.signed.public);

            let (initial, _, _) = initiate(&a, &bundle, b"after a restart").unwrap();
            let (_, first) = respond(&b, &restored, &initial).unwrap();
            assert_eq!(first, b"after a restart");
        }
    }

    #[test]
    fn malformed_prekey_secrets_are_refused() {
        let (_, secrets) = PrekeyBundle::create(&bob(), &queue(21), b"r", true).unwrap();
        let bytes = secrets.serialize();
        for n in [0usize, 1, 33, bytes.len() - 1] {
            assert!(PrekeySecrets::deserialize(&bytes[..n]).is_err(), "len {n}");
        }
        let mut wrong_version = bytes.clone();
        wrong_version[0] = 2;
        assert!(PrekeySecrets::deserialize(&wrong_version).is_err());
        let mut bad_flag = bytes.clone();
        bad_flag[33] = 7;
        assert!(PrekeySecrets::deserialize(&bad_flag).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PrekeySecrets::deserialize(&trailing).is_err());
    }

    #[test]
    fn queue_seed_and_root_are_independent() {
        // Both come from one KDF call at different offsets. Compromise of the
        // queue seed must reveal nothing about the ratchet root.
        let dh = [1u8; 32];
        let kem = [2u8; 32];
        let tr = [3u8; 32];
        let (root, seed) = derive_root(&dh, &dh, &dh, None, &kem, &tr);
        assert_ne!(root, seed);
        let (root2, seed2) = derive_root(&dh, &dh, &dh, None, &kem, &[4u8; 32]);
        assert_ne!(root, root2);
        assert_ne!(seed, seed2);
    }
}
