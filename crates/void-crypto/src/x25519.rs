//! X25519 (RFC 7748) and the shared GF(2^255 - 19) field arithmetic that
//! Ed25519 also uses.
//!
//! The field is represented as five 51-bit limbs in a `u64` array, with `u128`
//! intermediates — the standard "radix 2^51" layout. Every operation is
//! branch-free and data-independent, which is what NFR-SEC-03 requires for
//! secret-dependent code.
//!
//! ## Contributory behaviour
//!
//! `x25519` returns `Err(Invalid)` when the computed shared secret is all
//! zero, which is what happens for the small-order input points. RFC 7748
//! makes this check optional; Void makes it mandatory, because the handshake
//! in `void-proto` binds identity to the shared secret and an all-zero secret
//! would let a peer force a known key.

use crate::{CryptoError, Result};

/// Field element: 5 limbs of 51 bits, little-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fe(pub [u64; 5]);

const MASK51: u64 = (1u64 << 51) - 1;

impl Fe {
    /// Additive identity.
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    /// Multiplicative identity.
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Decode 32 little-endian bytes. The top bit is ignored, per RFC 7748.
    #[must_use]
    pub fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| -> u64 {
            let mut v = [0u8; 8];
            v.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(v)
        };
        let mut h = [0u64; 5];
        h[0] = load(0) & MASK51;
        h[1] = (load(6) >> 3) & MASK51;
        h[2] = (load(12) >> 6) & MASK51;
        h[3] = (load(19) >> 1) & MASK51;
        h[4] = (load(24) >> 12) & MASK51;
        Fe(h)
    }

    /// Encode to 32 little-endian bytes, fully reduced.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = self.0;
        // Carry propagate.
        carry(&mut h);
        // Compute h + 19 and check whether it carries past 2^255, which tells
        // us whether h >= p.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        h[1] += h[0] >> 51;
        h[0] &= MASK51;
        h[2] += h[1] >> 51;
        h[1] &= MASK51;
        h[3] += h[2] >> 51;
        h[2] &= MASK51;
        h[4] += h[3] >> 51;
        h[3] &= MASK51;
        h[4] &= MASK51;

        let mut out = [0u8; 32];
        let packed: [u64; 4] = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        for i in 0..4 {
            out[8 * i..8 * i + 8].copy_from_slice(&packed[i].to_le_bytes());
        }
        out
    }

    /// Field addition.
    #[must_use]
    pub fn add(self, other: Fe) -> Fe {
        let mut h = [0u64; 5];
        for i in 0..5 {
            h[i] = self.0[i] + other.0[i];
        }
        carry(&mut h);
        Fe(h)
    }

    /// Field subtraction.
    #[must_use]
    pub fn sub(self, other: Fe) -> Fe {
        // Add 2p before subtracting so limbs never go negative.
        let mut h = [0u64; 5];
        h[0] = self.0[0] + 0x000f_ffff_ffff_ffda - other.0[0];
        h[1] = self.0[1] + 0x000f_ffff_ffff_fffe - other.0[1];
        h[2] = self.0[2] + 0x000f_ffff_ffff_fffe - other.0[2];
        h[3] = self.0[3] + 0x000f_ffff_ffff_fffe - other.0[3];
        h[4] = self.0[4] + 0x000f_ffff_ffff_fffe - other.0[4];
        carry(&mut h);
        Fe(h)
    }

    /// Field negation.
    #[must_use]
    pub fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// Field multiplication.
    #[must_use]
    pub fn mul(self, other: Fe) -> Fe {
        let a = self.0;
        let b = other.0;
        let b1_19 = (b[1] as u128) * 19;
        let b2_19 = (b[2] as u128) * 19;
        let b3_19 = (b[3] as u128) * 19;
        let b4_19 = (b[4] as u128) * 19;

        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;
        let b0 = b[0] as u128;
        let b1 = b[1] as u128;
        let b2 = b[2] as u128;
        let b3 = b[3] as u128;
        let b4 = b[4] as u128;

        let t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        reduce128([t0, t1, t2, t3, t4])
    }

    /// Field squaring.
    #[must_use]
    pub fn sq(self) -> Fe {
        self.mul(self)
    }

    /// Multiply by the Montgomery constant a24 = 121665.
    #[must_use]
    pub fn mul121666(self) -> Fe {
        let mut t = [0u128; 5];
        for i in 0..5 {
            t[i] = (self.0[i] as u128) * 121666;
        }
        reduce128(t)
    }

    /// Repeated squaring, `n` times.
    #[must_use]
    pub fn sq_n(self, n: usize) -> Fe {
        let mut r = self;
        for _ in 0..n {
            r = r.sq();
        }
        r
    }

    /// Multiplicative inverse via Fermat: `self^(p-2)`.
    ///
    /// Returns zero for a zero input, which is what every reference
    /// implementation does; callers must not rely on invert to detect zero.
    #[must_use]
    pub fn invert(self) -> Fe {
        // Addition chain from ref10.
        let z2 = self.sq();
        let z8 = z2.sq_n(2);
        let z9 = self.mul(z8);
        let z11 = z2.mul(z9);
        let z22 = z11.sq();
        let z_5_0 = z9.mul(z22);
        let z_10_5 = z_5_0.sq_n(5);
        let z_10_0 = z_10_5.mul(z_5_0);
        let z_20_10 = z_10_0.sq_n(10);
        let z_20_0 = z_20_10.mul(z_10_0);
        let z_40_20 = z_20_0.sq_n(20);
        let z_40_0 = z_40_20.mul(z_20_0);
        let z_50_10 = z_40_0.sq_n(10);
        let z_50_0 = z_50_10.mul(z_10_0);
        let z_100_50 = z_50_0.sq_n(50);
        let z_100_0 = z_100_50.mul(z_50_0);
        let z_200_100 = z_100_0.sq_n(100);
        let z_200_0 = z_200_100.mul(z_100_0);
        let z_250_50 = z_200_0.sq_n(50);
        let z_250_0 = z_250_50.mul(z_50_0);
        let z_255_5 = z_250_0.sq_n(5);
        z_255_5.mul(z11)
    }

    /// `self^((p-5)/8)`, used for square roots in Ed25519 decompression.
    #[must_use]
    pub fn pow_p58(self) -> Fe {
        let z2 = self.sq();
        let z8 = z2.sq_n(2);
        let z9 = self.mul(z8);
        let z11 = z2.mul(z9);
        let z22 = z11.sq();
        let z_5_0 = z9.mul(z22);
        let z_10_5 = z_5_0.sq_n(5);
        let z_10_0 = z_10_5.mul(z_5_0);
        let z_20_10 = z_10_0.sq_n(10);
        let z_20_0 = z_20_10.mul(z_10_0);
        let z_40_20 = z_20_0.sq_n(20);
        let z_40_0 = z_40_20.mul(z_20_0);
        let z_50_10 = z_40_0.sq_n(10);
        let z_50_0 = z_50_10.mul(z_10_0);
        let z_100_50 = z_50_0.sq_n(50);
        let z_100_0 = z_100_50.mul(z_50_0);
        let z_200_100 = z_100_0.sq_n(100);
        let z_200_0 = z_200_100.mul(z_100_0);
        let z_250_50 = z_200_0.sq_n(50);
        let z_250_0 = z_250_50.mul(z_50_0);
        let z_252_2 = z_250_0.sq_n(2);
        z_252_2.mul(self)
    }

    /// Constant-time conditional swap.
    pub fn cswap(a: &mut Fe, b: &mut Fe, choice: u8) {
        let mask = (choice as u64).wrapping_neg();
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// Constant-time conditional move: `a = b` if `choice == 1`.
    pub fn cmov(a: &mut Fe, b: &Fe, choice: u8) {
        let mask = (choice as u64).wrapping_neg();
        for i in 0..5 {
            a.0[i] ^= mask & (a.0[i] ^ b.0[i]);
        }
    }

    /// Constant-time test for zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        crate::ct::is_zero(&self.to_bytes())
    }

    /// Low bit of the canonical encoding (the "sign" in Ed25519).
    #[must_use]
    pub fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }
}

fn carry(h: &mut [u64; 5]) {
    h[1] += h[0] >> 51;
    h[0] &= MASK51;
    h[2] += h[1] >> 51;
    h[1] &= MASK51;
    h[3] += h[2] >> 51;
    h[2] &= MASK51;
    h[4] += h[3] >> 51;
    h[3] &= MASK51;
    h[0] += 19 * (h[4] >> 51);
    h[4] &= MASK51;
    h[1] += h[0] >> 51;
    h[0] &= MASK51;
}

fn reduce128(t: [u128; 5]) -> Fe {
    let mut h = [0u64; 5];
    let mut c: u128;

    c = t[0] >> 51;
    h[0] = (t[0] as u64) & MASK51;
    let t1 = t[1] + c;
    c = t1 >> 51;
    h[1] = (t1 as u64) & MASK51;
    let t2 = t[2] + c;
    c = t2 >> 51;
    h[2] = (t2 as u64) & MASK51;
    let t3 = t[3] + c;
    c = t3 >> 51;
    h[3] = (t3 as u64) & MASK51;
    let t4 = t[4] + c;
    c = t4 >> 51;
    h[4] = (t4 as u64) & MASK51;
    h[0] += (c as u64) * 19;
    h[1] += h[0] >> 51;
    h[0] &= MASK51;
    Fe(h)
}

/// Length of an X25519 public key or shared secret.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an X25519 secret key.
pub const SECRET_KEY_LEN: usize = 32;

/// Clamp a scalar per RFC 7748 §5.
#[must_use]
pub fn clamp(mut s: [u8; 32]) -> [u8; 32] {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
}

/// The X25519 function: scalar multiplication on Curve25519.
///
/// Returns `Err(Invalid)` if the result is the all-zero value, which indicates
/// a small-order (or otherwise degenerate) peer public key.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> Result<[u8; 32]> {
    let k = clamp(*scalar);
    let u = Fe::from_bytes(point);

    let x1 = u;
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = u;
    let mut z3 = Fe::ONE;
    let mut swap: u8 = 0;

    for t in (0..255).rev() {
        let bit = (k[t >> 3] >> (t & 7)) & 1;
        swap ^= bit;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(z2);
        let aa = a.sq();
        let b = x2.sub(z2);
        let bb = b.sq();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).sq();
        z3 = x1.mul(da.sub(cb).sq());
        x2 = aa.mul(bb);
        // z2 = E * (BB + a24*E) with a24 = 121665. We compute the algebraically
        // identical BB + 121666*E, which is the ref10 arrangement and lets us
        // keep a single multiply-by-small-constant helper.
        z2 = e.mul(bb.add(e.mul121666()));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);

    let out = x2.mul(z2.invert()).to_bytes();
    // Mandatory contributory-behaviour check.
    if crate::ct::is_zero(&out) {
        // Wipe the (zero) buffer anyway to keep the code path uniform.
        return Err(CryptoError::Invalid);
    }
    Ok(out)
}

/// Derive the public key for a secret key: `X25519(sk, 9)`.
#[must_use]
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    // The basepoint has large order, so this cannot fail; if the field
    // arithmetic were broken it would, and returning zeros would be worse than
    // a panic in a test build.
    x25519(secret, &basepoint).expect("x25519 basepoint multiplication cannot yield zero")
}

/// An X25519 key pair.
#[derive(Clone)]
pub struct KeyPair {
    /// Secret scalar (unclamped as stored; clamped on use).
    pub secret: [u8; 32],
    /// Public key.
    pub public: [u8; 32],
}

impl KeyPair {
    /// Generate from the system CSPRNG.
    pub fn generate() -> Result<KeyPair> {
        let mut secret = [0u8; 32];
        crate::rand::fill(&mut secret)?;
        Ok(KeyPair::from_secret(secret))
    }

    /// Construct from an existing secret.
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> KeyPair {
        let public = public_key(&secret);
        KeyPair { secret, public }
    }

    /// Diffie-Hellman with a peer's public key.
    pub fn dh(&self, peer: &[u8; 32]) -> Result<[u8; 32]> {
        x25519(&self.secret, peer)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::{hex, unhex};

    fn arr(s: &str) -> [u8; 32] {
        let v = unhex(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn field_roundtrip() {
        for seed in 0u8..32 {
            let mut b = [seed; 32];
            b[31] &= 0x7f;
            assert_eq!(Fe::from_bytes(&b).to_bytes(), b);
        }
    }

    #[test]
    fn field_arithmetic_identities() {
        let a = Fe::from_bytes(&[3u8; 32]);
        let b = Fe::from_bytes(&[7u8; 32]);
        assert_eq!(a.add(b).sub(b).to_bytes(), a.to_bytes());
        assert_eq!(a.mul(Fe::ONE).to_bytes(), a.to_bytes());
        assert_eq!(a.mul(a.invert()).to_bytes(), Fe::ONE.to_bytes());
        assert_eq!(a.sub(a).to_bytes(), Fe::ZERO.to_bytes());
        assert_eq!(a.mul(b).to_bytes(), b.mul(a).to_bytes());
        assert_eq!(a.neg().add(a).to_bytes(), Fe::ZERO.to_bytes());
    }

    #[test]
    fn rfc7748_scalar_mult_vector_1() {
        let s = arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = arr("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            hex(&x25519(&s, &u).unwrap()),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    #[test]
    fn rfc7748_scalar_mult_vector_2() {
        let s = arr("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = arr("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(
            hex(&x25519(&s, &u).unwrap()),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        let a_sk = arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b_sk = arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assert_eq!(
            hex(&public_key(&a_sk)),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex(&public_key(&b_sk)),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let ab = x25519(&a_sk, &public_key(&b_sk)).unwrap();
        let ba = x25519(&b_sk, &public_key(&a_sk)).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(
            hex(&ab),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[test]
    fn small_order_points_are_rejected() {
        // The canonical small-order inputs from the "May the Fourth" test set.
        let bad = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        let sk = [0x77u8; 32];
        for b in bad {
            assert!(
                x25519(&sk, &arr(b)).is_err(),
                "small-order point {b} must be rejected"
            );
        }
    }

    #[test]
    fn keypair_agreement() {
        let a = KeyPair::from_secret([1u8; 32]);
        let b = KeyPair::from_secret([2u8; 32]);
        assert_eq!(a.dh(&b.public).unwrap(), b.dh(&a.public).unwrap());
        let c = KeyPair::from_secret([3u8; 32]);
        assert_ne!(a.dh(&b.public).unwrap(), a.dh(&c.public).unwrap());
    }
}
