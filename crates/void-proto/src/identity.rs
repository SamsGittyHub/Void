//! Identity keys (FR-ID-01, FR-ID-05).
//!
//! A Void identity is three keys, generated on device, never transmitted to any
//! Void infrastructure:
//!
//! | Key | Purpose |
//! |---|---|
//! | Ed25519 | classical signature |
//! | ML-DSA-87 | post-quantum signature |
//! | X25519 | long-term Diffie-Hellman in the handshake |
//!
//! ## Why three keys and not two
//!
//! Signal derives its DH key from its Ed25519 identity key using XEdDSA, which
//! avoids carrying a separate key at the cost of a birational map between the
//! Edwards and Montgomery forms and some subtle sign handling. Void carries a
//! separate X25519 key instead. It costs 32 bytes in the prekey bundle and
//! removes an entire class of implementation error. `docs/DECISIONS.md#d-003`.
//!
//! ## Why both signatures must verify
//!
//! `verify` requires Ed25519 **and** ML-DSA to accept. An attacker who breaks
//! one — a future quantum computer against Ed25519, or a lattice break against
//! ML-DSA — still cannot forge an identity assertion. This is the whole point
//! of a hybrid: the composite is as strong as the stronger component, not the
//! weaker one.

use alloc::vec::Vec;

use void_crypto::{ed25519, mldsa, rand, x25519, Zeroize};

use crate::wire::{Reader, Writer};
use crate::{ProtoError, Result};

/// A public identity: what a contact knows about you.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityPublic {
    /// Ed25519 verification key.
    pub ed25519: [u8; 32],
    /// ML-DSA-87 verification key.
    pub mldsa: Vec<u8>,
    /// Long-term X25519 public key.
    pub x25519: [u8; 32],
}

impl IdentityPublic {
    /// Canonical encoding. This is what the fingerprint hashes and what the
    /// handshake transcript binds.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(32 + 2 + self.mldsa.len() + 32);
        w.raw(&self.ed25519).bytes16(&self.mldsa).raw(&self.x25519);
        w.finish()
    }

    /// Decode a canonical encoding, validating the ML-DSA key length.
    pub fn decode(bytes: &[u8]) -> Result<IdentityPublic> {
        let mut r = Reader::new(bytes);
        let ed = r.array::<32>()?;
        let mldsa = r.bytes16()?.to_vec();
        let x = r.array::<32>()?;
        r.finish()?;
        if mldsa.len() != mldsa::PUBLIC_KEY_LEN {
            return Err(ProtoError::Malformed);
        }
        Ok(IdentityPublic {
            ed25519: ed,
            mldsa,
            x25519: x,
        })
    }

    /// Verify a hybrid signature over `message`.
    ///
    /// Both component signatures must verify. There is no "one is enough"
    /// path, and no algorithm-agility negotiation that an attacker could
    /// downgrade.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let ed_ok = ed25519::verify(&self.ed25519, message, &signature.ed25519);
        let pq_ok = mldsa::verify(&self.mldsa, message, &signature.mldsa);
        // Evaluate both before combining: no short-circuit, so verification
        // time does not reveal which component failed.
        ed_ok & pq_ok
    }

    /// The 32-byte identity fingerprint (FR-ID-03).
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        void_crypto::blake3::derive_key_32(
            core::str::from_utf8(void_crypto::kdf::LABEL_FINGERPRINT).unwrap_or("void/v1/fp"),
            &self.encode(),
        )
    }
}

/// A hybrid signature: Ed25519 plus ML-DSA-87.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    /// Ed25519 component.
    pub ed25519: [u8; 64],
    /// ML-DSA-87 component.
    pub mldsa: Vec<u8>,
}

impl Signature {
    /// Total encoded length: 64 + 2 + 4627 = 4,693 bytes.
    ///
    /// This is why `docs/DECISIONS.md#d-002` confines identity signatures to
    /// the handshake and to key-change events. Carrying one per message would
    /// set a 4.7 KB floor on the record size, which NFR-PERF-03's 50 MB/month
    /// budget cannot absorb.
    pub const ENCODED_LEN: usize = 64 + 2 + mldsa::SIGNATURE_LEN;

    /// Canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::ENCODED_LEN);
        w.raw(&self.ed25519).bytes16(&self.mldsa);
        w.finish()
    }

    /// Decode, validating the ML-DSA signature length.
    pub fn decode(bytes: &[u8]) -> Result<Signature> {
        let mut r = Reader::new(bytes);
        let ed = r.array::<64>()?;
        let pq = r.bytes16()?.to_vec();
        r.finish()?;
        if pq.len() != mldsa::SIGNATURE_LEN {
            return Err(ProtoError::Malformed);
        }
        Ok(Signature {
            ed25519: ed,
            mldsa: pq,
        })
    }
}

/// The three seeds [`Identity::from_seeds`] derives an identity from.
///
/// An expanded ML-DSA-87 secret key is 4,896 bytes; its seed is 32. Storing
/// and exporting the seeds rather than the expanded keys is what keeps
/// FR-STOR-01's persisted identity record and FR-REC-02's export archive both
/// small enough to be practical — and, for export, small enough that a user
/// could write the seeds down by hand if they chose to.
pub struct IdentitySeeds {
    /// Ed25519 identity seed.
    pub ed_seed: [u8; 32],
    /// ML-DSA identity seed.
    pub mldsa_seed: [u8; 32],
    /// X25519 identity seed.
    pub x_seed: [u8; 32],
}

impl Drop for IdentitySeeds {
    fn drop(&mut self) {
        self.ed_seed.zeroize();
        self.mldsa_seed.zeroize();
        self.x_seed.zeroize();
    }
}

impl IdentitySeeds {
    /// Canonical encoding: the three seeds, concatenated. Fixed-size, so no
    /// length prefixes are needed.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(96);
        w.raw(&self.ed_seed).raw(&self.mldsa_seed).raw(&self.x_seed);
        w.finish()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<IdentitySeeds> {
        let mut r = Reader::new(bytes);
        let ed_seed = r.array::<32>()?;
        let mldsa_seed = r.array::<32>()?;
        let x_seed = r.array::<32>()?;
        r.finish()?;
        Ok(IdentitySeeds {
            ed_seed,
            mldsa_seed,
            x_seed,
        })
    }

    /// Reconstruct the identity these seeds describe.
    #[must_use]
    pub fn identity(&self) -> Identity {
        Identity::from_seeds(&self.ed_seed, &self.mldsa_seed, &self.x_seed)
    }
}

/// A full identity key pair. Secret material; never leaves the device.
pub struct Identity {
    ed: ed25519::SigningKey,
    mldsa_secret: Vec<u8>,
    mldsa_public: Vec<u8>,
    x: x25519::KeyPair,
    /// The public half.
    pub public: IdentityPublic,
}

impl Identity {
    /// Generate a new identity entirely offline (FR-ID-04): no network round
    /// trip, no server state, no registration.
    ///
    /// The seeds are generated and discarded immediately. Use
    /// [`Identity::generate_with_seeds`] if the caller needs to persist or
    /// export the identity afterwards — storage and export both work from the
    /// 96-byte seed triple, not the expanded keys (see `export` in
    /// `void-store` and `docs/PROTOCOL.md#13-export-archive`).
    pub fn generate() -> Result<Identity> {
        let (identity, _seeds) = Identity::generate_with_seeds()?;
        Ok(identity)
    }

    /// Generate a new identity, returning the seeds alongside it.
    pub fn generate_with_seeds() -> Result<(Identity, IdentitySeeds)> {
        let ed_seed = rand::bytes32()?;
        let mldsa_seed = rand::bytes32()?;
        let x_seed = rand::bytes32()?;
        let identity = Identity::from_seeds(&ed_seed, &mldsa_seed, &x_seed);
        Ok((
            identity,
            IdentitySeeds {
                ed_seed,
                mldsa_seed,
                x_seed,
            },
        ))
    }

    /// Deterministically reconstruct an identity from its three seeds.
    ///
    /// This is what the encrypted export (FR-REC-02) stores: 96 bytes rather
    /// than the 4,896-byte expanded ML-DSA secret key.
    #[must_use]
    pub fn from_seeds(ed_seed: &[u8; 32], mldsa_seed: &[u8; 32], x_seed: &[u8; 32]) -> Identity {
        let ed = ed25519::SigningKey::from_seed(*ed_seed);
        let pq = mldsa::keygen_derand(mldsa_seed);
        let x = x25519::KeyPair::from_secret(*x_seed);
        let public = IdentityPublic {
            ed25519: ed.public,
            mldsa: pq.public.clone(),
            x25519: x.public,
        };
        Identity {
            ed,
            mldsa_secret: pq.secret.clone(),
            mldsa_public: pq.public.clone(),
            x,
            public,
        }
    }

    /// Produce a hybrid signature.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(Signature {
            ed25519: self.ed.sign(message),
            mldsa: mldsa::sign(&self.mldsa_secret, message)?,
        })
    }

    /// Diffie-Hellman with a peer public key, using the long-term X25519 key.
    pub fn dh(&self, peer: &[u8; 32]) -> Result<[u8; 32]> {
        self.x.dh(peer).map_err(|_| ProtoError::InvalidKey)
    }

    /// The ML-DSA public key.
    #[must_use]
    pub fn mldsa_public(&self) -> &[u8] {
        &self.mldsa_public
    }

    /// The fingerprint of this identity.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.public.fingerprint()
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.mldsa_secret.zeroize();
        // `ed` and `x` wipe themselves in their own Drop impls.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Identity {
        Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[3u8; 32])
    }

    #[test]
    fn generation_is_deterministic_in_its_seeds() {
        let a = id();
        let b = id();
        assert_eq!(a.public, b.public);
        let c = Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[4u8; 32]);
        assert_ne!(a.public, c.public);
    }

    #[test]
    fn public_encoding_roundtrips() {
        let a = id();
        let enc = a.public.encode();
        assert_eq!(IdentityPublic::decode(&enc).unwrap(), a.public);
        // Truncation and trailing bytes must fail.
        assert!(IdentityPublic::decode(&enc[..enc.len() - 1]).is_err());
        let mut extra = enc.clone();
        extra.push(0);
        assert!(IdentityPublic::decode(&extra).is_err());
    }

    #[test]
    fn hybrid_signature_roundtrips() {
        let a = id();
        let sig = a.sign(b"attest").unwrap();
        assert!(a.public.verify(b"attest", &sig));
        assert!(!a.public.verify(b"attesu", &sig));

        let enc = sig.encode();
        assert_eq!(enc.len(), Signature::ENCODED_LEN);
        assert_eq!(Signature::decode(&enc).unwrap(), sig);
    }

    #[test]
    fn both_components_are_required() {
        let a = id();
        let b = Identity::from_seeds(&[9u8; 32], &[8u8; 32], &[7u8; 32]);
        let sig_a = a.sign(b"m").unwrap();
        let sig_b = b.sign(b"m").unwrap();

        // Splice: valid Ed25519 from A, valid ML-DSA from B. Neither identity
        // may accept it. This is the property that makes the hybrid worth its
        // 4.7 KB.
        let spliced = Signature {
            ed25519: sig_a.ed25519,
            mldsa: sig_b.mldsa.clone(),
        };
        assert!(!a.public.verify(b"m", &spliced));
        assert!(!b.public.verify(b"m", &spliced));

        // Corrupting only the PQ half must still fail.
        let mut pq_broken = sig_a.clone();
        pq_broken.mldsa[0] ^= 1;
        assert!(!a.public.verify(b"m", &pq_broken));

        // Corrupting only the classical half must still fail.
        let mut ed_broken = sig_a.clone();
        ed_broken.ed25519[0] ^= 1;
        assert!(!a.public.verify(b"m", &ed_broken));
    }

    #[test]
    fn identities_agree_on_dh() {
        let a = id();
        let b = Identity::from_seeds(&[4u8; 32], &[5u8; 32], &[6u8; 32]);
        assert_eq!(
            a.dh(&b.public.x25519).unwrap(),
            b.dh(&a.public.x25519).unwrap()
        );
    }

    #[test]
    fn fingerprint_is_stable_and_key_dependent() {
        let a = id();
        assert_eq!(a.fingerprint(), id().fingerprint());
        let b = Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[99u8; 32]);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn malformed_mldsa_key_length_is_rejected() {
        let a = id();
        let mut pubk = a.public.clone();
        pubk.mldsa.truncate(100);
        assert!(IdentityPublic::decode(&pubk.encode()).is_err());
    }

    #[test]
    fn generate_with_seeds_reconstructs_the_same_identity() {
        let (identity, seeds) = Identity::generate_with_seeds().unwrap();
        assert_eq!(identity.public, seeds.identity().public);
    }

    #[test]
    fn identity_seeds_roundtrip() {
        let seeds = IdentitySeeds {
            ed_seed: [1u8; 32],
            mldsa_seed: [2u8; 32],
            x_seed: [3u8; 32],
        };
        let enc = seeds.encode();
        assert_eq!(enc.len(), 96);
        let decoded = IdentitySeeds::decode(&enc).unwrap();
        assert_eq!(decoded.identity().public, seeds.identity().public);
        assert!(IdentitySeeds::decode(&enc[..enc.len() - 1]).is_err());
    }
}
