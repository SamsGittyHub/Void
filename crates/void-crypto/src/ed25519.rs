//! Ed25519 signatures (RFC 8032).
//!
//! Used for the classical half of Void's hybrid identity (FR-ID-01). The
//! post-quantum half is ML-DSA-87; `void-proto::identity` requires **both**
//! signatures to verify, so a break of either primitive alone does not forge
//! an identity.
//!
//! ## Verification semantics
//!
//! This implementation performs cofactorless verification (compare the
//! re-derived `R` encoding against the supplied one) and rejects a scalar `s`
//! that is not canonically reduced mod L. That combination is what ref10 and
//! the majority of deployed verifiers do. Void never relies on signature
//! uniqueness or on strict "ZIP-215"-style batch equivalence, so the known
//! divergences between verifier definitions do not affect any Void security
//! property — see `docs/PROTOCOL.md#signature-semantics`.

use alloc::vec::Vec;

use crate::sha2::Sha512;
use crate::x25519::Fe;
use crate::{CryptoError, Result};

/// Length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 secret seed.
pub const SECRET_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

fn fe_const(hex_le: [u8; 32]) -> Fe {
    Fe::from_bytes(&hex_le)
}

/// The curve constant `d = -121665/121666`.
fn d_const() -> Fe {
    fe_const([
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70,
        0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c,
        0x03, 0x52,
    ])
}

/// `sqrt(-1)` in GF(p).
fn sqrt_m1() -> Fe {
    fe_const([
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43,
        0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24,
        0x83, 0x2b,
    ])
}

/// A point in extended twisted-Edwards coordinates: `x = X/Z`, `y = Y/Z`,
/// `xy = T/Z`.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    /// The neutral element (0, 1).
    #[must_use]
    pub fn identity() -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    /// The standard base point B.
    #[must_use]
    pub fn basepoint() -> Point {
        let bx = fe_const([
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
            0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
            0xd3, 0x36, 0x69, 0x21,
        ]);
        let by = fe_const([
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]);
        Point {
            x: bx,
            y: by,
            z: Fe::ONE,
            t: bx.mul(by),
        }
    }

    /// Point addition (add-2008-hwcd-3, for a = -1).
    #[must_use]
    pub fn add(self, other: Point) -> Point {
        let a = self.y.sub(self.x).mul(other.y.sub(other.x));
        let b = self.y.add(self.x).mul(other.y.add(other.x));
        let c = self.t.mul(other.t).mul(d_const()).mul(Fe([2, 0, 0, 0, 0]));
        let dd = self.z.mul(other.z).mul(Fe([2, 0, 0, 0, 0]));
        let e = b.sub(a);
        let f = dd.sub(c);
        let g = dd.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// Point doubling (dbl-2008-hwcd).
    #[must_use]
    pub fn double(self) -> Point {
        let a = self.x.sq();
        let b = self.y.sq();
        let c = self.z.sq().mul(Fe([2, 0, 0, 0, 0]));
        let d = a.neg();
        let e = self.x.add(self.y).sq().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// Point negation.
    #[must_use]
    pub fn neg(self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    fn cmov(&mut self, other: &Point, choice: u8) {
        Fe::cmov(&mut self.x, &other.x, choice);
        Fe::cmov(&mut self.y, &other.y, choice);
        Fe::cmov(&mut self.z, &other.z, choice);
        Fe::cmov(&mut self.t, &other.t, choice);
    }

    /// Constant-time scalar multiplication.
    ///
    /// Uses a fixed 255-iteration double-and-conditional-add ladder: the same
    /// sequence of field operations runs regardless of the scalar's bits, and
    /// the only scalar-dependent step is a branch-free `cmov`.
    #[must_use]
    pub fn mul_scalar(self, scalar: &[u8; 32]) -> Point {
        let mut acc = Point::identity();
        for i in (0..255).rev() {
            acc = acc.double();
            let bit = (scalar[i >> 3] >> (i & 7)) & 1;
            let sum = acc.add(self);
            acc.cmov(&sum, bit);
        }
        acc
    }

    /// Compress to the 32-byte encoding: little-endian `y` with the sign of
    /// `x` in the top bit.
    #[must_use]
    pub fn compress(self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(zinv);
        let y = self.y.mul(zinv);
        let mut out = y.to_bytes();
        out[31] |= (x.to_bytes()[0] & 1) << 7;
        out
    }

    /// Decompress from the 32-byte encoding.
    ///
    /// Returns `Err(Invalid)` if the encoding does not correspond to a curve
    /// point. Non-canonical `y` values (>= p) are also rejected, since they
    /// would give two encodings for one point.
    pub fn decompress(bytes: &[u8; 32]) -> Result<Point> {
        let sign = bytes[31] >> 7;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;

        let y = Fe::from_bytes(&y_bytes);
        // Canonicality: re-encoding must reproduce the input.
        if y.to_bytes() != y_bytes {
            return Err(CryptoError::Invalid);
        }

        let y2 = y.sq();
        let u = y2.sub(Fe::ONE);
        let v = y2.mul(d_const()).add(Fe::ONE);

        // x = u*v^3 * (u*v^7)^((p-5)/8)
        let v3 = v.sq().mul(v);
        let v7 = v3.sq().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v7).pow_p58());

        let vxx = x.sq().mul(v);
        if vxx.sub(u).is_zero() {
            // correct root already
        } else if vxx.add(u).is_zero() {
            x = x.mul(sqrt_m1());
        } else {
            return Err(CryptoError::Invalid);
        }

        if x.is_zero() && sign == 1 {
            // x = 0 has only one valid sign encoding.
            return Err(CryptoError::Invalid);
        }
        if (x.to_bytes()[0] & 1) != sign {
            x = x.neg();
        }

        Ok(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    /// Compare two points by their canonical encodings.
    #[must_use]
    pub fn ct_eq(self, other: Point) -> bool {
        crate::ct::eq(&self.compress(), &other.compress())
    }
}

// ---------------------------------------------------------------------------
// Scalar arithmetic mod L = 2^252 + 27742317777372353535851937790883648493
// ---------------------------------------------------------------------------

const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// Constant-time `r -= L` if `r >= L`.
fn cond_sub_l(r: &mut [u64; 4]) {
    let mut diff = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = r[i].overflowing_sub(L[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    // borrow == 1 means r < L, so keep r; else take diff.
    let mask = borrow.wrapping_sub(1); // 0xFFFF.. if borrow == 0
    for i in 0..4 {
        r[i] = (r[i] & !mask) | (diff[i] & mask);
    }
}

/// Reduce an arbitrary little-endian integer mod L.
///
/// Implemented as bitwise long division: 8 bits per input byte, each a shift
/// and one constant-time conditional subtraction. This is slower than the
/// hand-unrolled Barrett reduction in ref10 but it is short enough to audit by
/// reading, which for a signature scheme is the better trade. At 512 bits the
/// cost is a few microseconds — irrelevant next to the scalar multiplication.
#[must_use]
pub fn scalar_mod_l(x_le: &[u8]) -> [u8; 32] {
    let mut r = [0u64; 4];
    let nbits = x_le.len() * 8;
    for i in (0..nbits).rev() {
        let bit = ((x_le[i >> 3] >> (i & 7)) & 1) as u64;
        // r = (r << 1) | bit. Since r < L < 2^253, this never overflows 4 limbs.
        let mut carry = bit;
        for limb in r.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        cond_sub_l(&mut r);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&r[i].to_le_bytes());
    }
    out
}

/// `(a * b + c) mod L`, with all inputs 32-byte little-endian scalars.
#[must_use]
pub fn scalar_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    // 256x256 -> 512 bit schoolbook multiply over 32-bit limbs.
    let al: Vec<u64> = (0..8)
        .map(|i| u32::from_le_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]) as u64)
        .collect();
    let bl: Vec<u64> = (0..8)
        .map(|i| u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]) as u64)
        .collect();
    let mut prod = [0u64; 17]; // 16 limbs of product + 1 for the addition carry
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let t = prod[i + j] + al[i] * bl[j] + carry;
            prod[i + j] = t & 0xFFFF_FFFF;
            carry = t >> 32;
        }
        let mut k = i + 8;
        while carry > 0 {
            let t = prod[k] + carry;
            prod[k] = t & 0xFFFF_FFFF;
            carry = t >> 32;
            k += 1;
        }
    }
    // Add c.
    let mut carry = 0u64;
    for i in 0..8 {
        let ci = u32::from_le_bytes([c[4 * i], c[4 * i + 1], c[4 * i + 2], c[4 * i + 3]]) as u64;
        let t = prod[i] + ci + carry;
        prod[i] = t & 0xFFFF_FFFF;
        carry = t >> 32;
    }
    let mut k = 8;
    while carry > 0 {
        let t = prod[k] + carry;
        prod[k] = t & 0xFFFF_FFFF;
        carry = t >> 32;
        k += 1;
    }

    let mut bytes = Vec::with_capacity(17 * 4);
    for limb in prod.iter() {
        bytes.extend_from_slice(&(*limb as u32).to_le_bytes());
    }
    scalar_mod_l(&bytes)
}

/// Is a 32-byte scalar canonically reduced (i.e. `< L`)?
#[must_use]
pub fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&s[8 * i..8 * i + 8]);
        r[i] = u64::from_le_bytes(b);
    }
    // r < L ?
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = r[i].overflowing_sub(L[i]);
        let (_, b2) = d1.overflowing_sub(borrow);
        borrow = (b1 as u64) | (b2 as u64);
    }
    borrow == 1
}

// ---------------------------------------------------------------------------
// Signature scheme
// ---------------------------------------------------------------------------

/// An Ed25519 signing key (the 32-byte seed plus the derived material).
#[derive(Clone)]
pub struct SigningKey {
    seed: [u8; 32],
    scalar: [u8; 32],
    prefix: [u8; 32],
    /// The corresponding public key.
    pub public: [u8; 32],
}

impl SigningKey {
    /// Derive a signing key from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> SigningKey {
        let h = Sha512::digest(&seed);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&h[..32]);
        scalar[0] &= 248;
        scalar[31] &= 63;
        scalar[31] |= 64;
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        let public = Point::basepoint().mul_scalar(&scalar).compress();
        SigningKey {
            seed,
            scalar,
            prefix,
            public,
        }
    }

    /// Generate a fresh key from system entropy.
    pub fn generate() -> Result<SigningKey> {
        Ok(SigningKey::from_seed(crate::rand::bytes32()?))
    }

    /// The 32-byte seed. Handle as top secret; this is the identity.
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Sign a message. Deterministic, per RFC 8032.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let r_hash = Sha512::digest_parts(&[&self.prefix, message]);
        let r = scalar_mod_l(&r_hash);
        let r_point = Point::basepoint().mul_scalar(&r);
        let r_bytes = r_point.compress();

        let k_hash = Sha512::digest_parts(&[&r_bytes, &self.public, message]);
        let k = scalar_mod_l(&k_hash);

        let s = scalar_muladd(&k, &self.scalar, &r);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s);
        sig
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        use crate::zeroize::Zeroize;
        self.seed.zeroize();
        self.scalar.zeroize();
        self.prefix.zeroize();
    }
}

/// Verify an Ed25519 signature.
#[must_use]
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature[32..]);

    // Reject non-canonical s: otherwise a signature is malleable by adding L.
    if !scalar_is_canonical(&s) {
        return false;
    }

    let a_point = match Point::decompress(public) {
        Ok(p) => p.neg(),
        Err(_) => return false,
    };
    // R must be a valid point encoding too.
    if Point::decompress(&r_bytes).is_err() {
        return false;
    }

    let k_hash = Sha512::digest_parts(&[&r_bytes, public, message]);
    let k = scalar_mod_l(&k_hash);

    // R' = sB - kA
    let sb = Point::basepoint().mul_scalar(&s);
    let ka = a_point.mul_scalar(&k);
    let check = sb.add(ka);

    crate::ct::eq(&check.compress(), &r_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::{hex, unhex};

    fn arr32(s: &str) -> [u8; 32] {
        let v = unhex(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn basepoint_compresses_correctly() {
        assert_eq!(
            hex(&Point::basepoint().compress()),
            // y = 4/5 little-endian, sign bit of x is 0.
            "5866666666666666666666666666666666666666666666666666666666666666"
        );
    }

    #[test]
    fn group_law_identities() {
        let b = Point::basepoint();
        let id = Point::identity();
        assert!(b.add(id).ct_eq(b));
        assert!(b.add(b.neg()).ct_eq(id));
        assert!(b.double().ct_eq(b.add(b)));
        let mut two = [0u8; 32];
        two[0] = 2;
        assert!(b.mul_scalar(&two).ct_eq(b.double()));
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let mut p = Point::basepoint();
        for _ in 0..16 {
            let c = p.compress();
            let q = Point::decompress(&c).unwrap();
            assert!(q.ct_eq(p));
            p = p.double();
        }
    }

    #[test]
    fn rfc8032_test_vector_1_empty_message() {
        let seed = arr32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let sk = SigningKey::from_seed(seed);
        assert_eq!(
            hex(&sk.public),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sk.sign(b"");
        assert_eq!(
            hex(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                .replace(['\n', ' '], "")
        );
        assert!(verify(&sk.public, b"", &sig));
    }

    #[test]
    fn rfc8032_test_vector_2_one_byte() {
        let seed = arr32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let sk = SigningKey::from_seed(seed);
        assert_eq!(
            hex(&sk.public),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        let sig = sk.sign(&[0x72]);
        assert_eq!(
            hex(&sig),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
                .replace(['\n', ' '], "")
        );
        assert!(verify(&sk.public, &[0x72], &sig));
    }

    #[test]
    fn rfc8032_test_vector_3_two_bytes() {
        let seed = arr32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let sk = SigningKey::from_seed(seed);
        assert_eq!(
            hex(&sk.public),
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        );
        let sig = sk.sign(&[0xaf, 0x82]);
        assert_eq!(
            hex(&sig),
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
                .replace(['\n', ' '], "")
        );
        assert!(verify(&sk.public, &[0xaf, 0x82], &sig));
    }

    #[test]
    fn rejects_tampering() {
        let sk = SigningKey::from_seed([42u8; 32]);
        let msg = b"transfer authority";
        let sig = sk.sign(msg);
        assert!(verify(&sk.public, msg, &sig));

        // Wrong message.
        assert!(!verify(&sk.public, b"transfer authorityx", &sig));
        // Wrong key.
        let other = SigningKey::from_seed([43u8; 32]);
        assert!(!verify(&other.public, msg, &sig));
        // Every single-bit flip in the signature.
        for i in 0..64 {
            for bit in [1u8, 0x80] {
                let mut bad = sig;
                bad[i] ^= bit;
                assert!(!verify(&sk.public, msg, &bad), "sig byte {i} bit {bit:#x}");
            }
        }
    }

    #[test]
    fn rejects_non_canonical_s() {
        let sk = SigningKey::from_seed([7u8; 32]);
        let sig = sk.sign(b"m");
        // s + L is a different encoding of the same scalar; it must not verify.
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        let mut carry = 0u64;
        let mut s_plus_l = [0u8; 32];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&s[8 * i..8 * i + 8]);
            let (t, c1) = u64::from_le_bytes(b).overflowing_add(L[i]);
            let (t2, c2) = t.overflowing_add(carry);
            carry = (c1 as u64) | (c2 as u64);
            s_plus_l[8 * i..8 * i + 8].copy_from_slice(&t2.to_le_bytes());
        }
        let mut bad = sig;
        bad[32..].copy_from_slice(&s_plus_l);
        assert!(!scalar_is_canonical(&s_plus_l));
        assert!(!verify(&sk.public, b"m", &bad));
    }

    #[test]
    fn scalar_reduction_basics() {
        // 0 and L reduce to 0; L-1 stays.
        let zero = [0u8; 32];
        assert_eq!(scalar_mod_l(&zero), zero);
        let mut l_bytes = [0u8; 32];
        for i in 0..4 {
            l_bytes[8 * i..8 * i + 8].copy_from_slice(&L[i].to_le_bytes());
        }
        assert_eq!(scalar_mod_l(&l_bytes), zero);
        assert!(!scalar_is_canonical(&l_bytes));

        // muladd(a, 0, c) == c mod L
        let a = [3u8; 32];
        let c = [5u8; 32];
        assert_eq!(scalar_muladd(&a, &zero, &c), scalar_mod_l(&c));
        // muladd(1, b, 0) == b mod L
        let mut one = [0u8; 32];
        one[0] = 1;
        let b = [9u8; 32];
        assert_eq!(scalar_muladd(&one, &b, &zero), scalar_mod_l(&b));
    }

    #[test]
    fn decompress_rejects_garbage() {
        // A y value with no corresponding x.
        let mut bad = [0xffu8; 32];
        bad[31] = 0x7f;
        assert!(Point::decompress(&bad).is_err());
    }
}
