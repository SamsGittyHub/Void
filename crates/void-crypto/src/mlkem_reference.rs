//! ML-KEM-1024 (FIPS 203).
//!
//! The post-quantum half of Void's hybrid key agreement (FR-MSG-01). Parameter
//! selection is ML-KEM-1024, per `docs/DECISIONS.md#d-001`: it matches Signal's
//! PQXDH choice of Kyber-1024, and the 1,568-byte ciphertext fits Void's record
//! budget once ML-DSA signatures are confined to the handshake (§13.1 of the
//! PRD, resolved in D-002).
//!
//! ## Implementation notes
//!
//! Coefficients are held as `u16` in `[0, q)` with an explicit Barrett
//! reduction after every multiply. This is slower than the Montgomery-domain
//! arrangement the reference implementation uses, and it is deliberate: the
//! representation invariant is "always canonically reduced", which a reviewer
//! can check locally at every line instead of tracking a domain factor through
//! the whole file.
//!
//! Every reduction is branch-free. The only data-dependent control flow in the
//! module is rejection sampling in `sample_ntt`, which operates on the public
//! matrix seed `rho` and never on secret data.
//!
//! ## ⚠️ Not yet ACVP-validated
//!
//! See the crate-level warning. This implementation is not cleared for
//! production until it passes the NIST ACVP vectors.

use alloc::vec;
use alloc::vec::Vec;

use crate::sha3::{sha3_256, sha3_512_parts, Shake128, Shake256};
use crate::{CryptoError, Result};

const Q: u32 = 3329;
const N: usize = 256;

/// Module rank for ML-KEM-1024.
pub const K: usize = 4;
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: usize = 11;
const DV: usize = 5;

/// Encapsulation key length in bytes.
pub const ENCAPS_KEY_LEN: usize = 384 * K + 32; // 1568
/// Decapsulation key length in bytes.
pub const DECAPS_KEY_LEN: usize = 768 * K + 96; // 3168
/// Ciphertext length in bytes.
pub const CIPHERTEXT_LEN: usize = 32 * (DU * K + DV); // 1568
/// Shared secret length in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

type Poly = [u16; N];
type PolyVec = [Poly; K];

const ZERO_POLY: Poly = [0u16; N];

// --- modular arithmetic -----------------------------------------------------

/// Barrett reduction of a value `< 2^32` to `[0, q)`. Branch-free.
#[inline(always)]
const fn barrett(a: u32) -> u16 {
    // floor(2^32 / q) = 1290167
    let m = ((a as u64) * 1_290_167) >> 32;
    let r = a - (m as u32) * Q;
    // r < 2q, so one conditional subtraction suffices.
    csub(r)
}

/// Constant-time `r - q if r >= q`.
#[inline(always)]
const fn csub(r: u32) -> u16 {
    let t = r.wrapping_sub(Q);
    // mask = 0xFFFFFFFF when t underflowed (i.e. r < q)
    let mask = ((t as i32) >> 31) as u32;
    ((t.wrapping_add(mask & Q)) & 0xFFFF) as u16
}

#[inline(always)]
const fn addq(a: u16, b: u16) -> u16 {
    csub(a as u32 + b as u32)
}

#[inline(always)]
const fn subq(a: u16, b: u16) -> u16 {
    csub(a as u32 + Q - b as u32)
}

#[inline(always)]
const fn mulq(a: u16, b: u16) -> u16 {
    barrett(a as u32 * b as u32)
}

const fn pow_mod(mut base: u32, mut exp: u32) -> u32 {
    let mut acc: u32 = 1;
    base %= Q;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = (acc * base) % Q;
        }
        base = (base * base) % Q;
        exp >>= 1;
    }
    acc
}

/// `zetas[i] = 17^bitrev7(i) mod q`, computed at compile time so the table
/// cannot drift from its definition.
const ZETAS: [u16; 128] = {
    let mut z = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        let mut r = 0u32;
        let mut b = 0;
        while b < 7 {
            r = (r << 1) | ((i as u32 >> b) & 1);
            b += 1;
        }
        z[i] = pow_mod(17, r) as u16;
        i += 1;
    }
    z
};

/// `128^-1 mod q`, the scaling factor the seven inverse-NTT layers leave behind.
const INV128: u16 = 3303;

// --- NTT --------------------------------------------------------------------

fn ntt(p: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = mulq(zeta, p[j + len]);
                p[j + len] = subq(p[j], t);
                p[j] = addq(p[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn inv_ntt(p: &mut Poly) {
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            for j in start..start + len {
                let t = p[j];
                p[j] = addq(t, p[j + len]);
                p[j + len] = subq(p[j + len], t);
                p[j + len] = mulq(zeta, p[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in p.iter_mut() {
        *c = mulq(*c, INV128);
    }
}

/// Multiplication in the NTT domain: 128 independent degree-1 products.
fn basemul(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO_POLY;
    for i in 0..64 {
        let zeta = ZETAS[64 + i];
        // (a0 + a1 X)(b0 + b1 X) mod (X^2 - zeta)
        let (a0, a1, b0, b1) = (a[4 * i], a[4 * i + 1], b[4 * i], b[4 * i + 1]);
        r[4 * i] = addq(mulq(mulq(a1, b1), zeta), mulq(a0, b0));
        r[4 * i + 1] = addq(mulq(a0, b1), mulq(a1, b0));

        // The paired block uses -zeta.
        let nzeta = subq(0, zeta);
        let (a0, a1, b0, b1) = (a[4 * i + 2], a[4 * i + 3], b[4 * i + 2], b[4 * i + 3]);
        r[4 * i + 2] = addq(mulq(mulq(a1, b1), nzeta), mulq(a0, b0));
        r[4 * i + 3] = addq(mulq(a0, b1), mulq(a1, b0));
    }
    r
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO_POLY;
    for i in 0..N {
        r[i] = addq(a[i], b[i]);
    }
    r
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO_POLY;
    for i in 0..N {
        r[i] = subq(a[i], b[i]);
    }
    r
}

// --- encode / decode / compress ---------------------------------------------

fn compress(x: u16, d: usize) -> u16 {
    // round(2^d / q * x) mod 2^d. The divisor is a compile-time constant, so
    // this lowers to a multiply-and-shift, not a division instruction.
    let t = (((x as u32) << d) + Q / 2) / Q;
    (t & ((1u32 << d) - 1)) as u16
}

fn decompress(y: u16, d: usize) -> u16 {
    (((y as u32) * Q + (1 << (d - 1))) >> d) as u16
}

/// Pack `n` values of `d` bits each, little-endian bit order.
fn bit_pack(vals: &[u16], d: usize, out: &mut Vec<u8>) {
    let mut acc: u32 = 0;
    let mut acc_bits = 0usize;
    for &v in vals {
        acc |= ((v as u32) & ((1u32 << d) - 1)) << acc_bits;
        acc_bits += d;
        while acc_bits >= 8 {
            out.push((acc & 0xFF) as u8);
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    if acc_bits > 0 {
        out.push((acc & 0xFF) as u8);
    }
}

fn bit_unpack(bytes: &[u8], d: usize, count: usize) -> Vec<u16> {
    let mut out = Vec::with_capacity(count);
    let mut acc: u32 = 0;
    let mut acc_bits = 0usize;
    let mut idx = 0usize;
    for _ in 0..count {
        while acc_bits < d {
            let b = if idx < bytes.len() { bytes[idx] } else { 0 };
            idx += 1;
            acc |= (b as u32) << acc_bits;
            acc_bits += 8;
        }
        out.push((acc & ((1u32 << d) - 1)) as u16);
        acc >>= d;
        acc_bits -= d;
    }
    out
}

fn encode_poly(p: &Poly, d: usize, out: &mut Vec<u8>) {
    bit_pack(p, d, out);
}

fn decode_poly(bytes: &[u8], d: usize) -> Poly {
    let v = bit_unpack(bytes, d, N);
    let mut p = ZERO_POLY;
    p.copy_from_slice(&v);
    p
}

// --- sampling ---------------------------------------------------------------

/// Rejection-sample a polynomial in the NTT domain from the public seed.
///
/// The loop is data-dependent, but only on `rho`, `i`, `j` — all public.
fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(rho);
    xof.update(&[j, i]);
    let mut p = ZERO_POLY;
    let mut count = 0usize;
    let mut buf = [0u8; 3];
    while count < N {
        xof.squeeze(&mut buf);
        let d1 = (buf[0] as u32) | (((buf[1] as u32) & 0x0F) << 8);
        let d2 = ((buf[1] as u32) >> 4) | ((buf[2] as u32) << 4);
        if d1 < Q {
            p[count] = d1 as u16;
            count += 1;
        }
        if d2 < Q && count < N {
            p[count] = d2 as u16;
            count += 1;
        }
    }
    p
}

fn prf(eta: usize, seed: &[u8; 32], nonce: u8) -> Vec<u8> {
    let mut x = Shake256::new();
    x.update(seed);
    x.update(&[nonce]);
    let mut out = vec![0u8; 64 * eta];
    x.squeeze(&mut out);
    out
}

/// Centered binomial distribution sampler.
fn sample_cbd(bytes: &[u8], eta: usize) -> Poly {
    let bits = bit_unpack(bytes, 1, N * 2 * eta);
    let mut p = ZERO_POLY;
    for i in 0..N {
        let mut a = 0u16;
        let mut b = 0u16;
        for j in 0..eta {
            a += bits[2 * i * eta + j];
            b += bits[2 * i * eta + eta + j];
        }
        p[i] = subq(a, b);
    }
    p
}

// --- K-PKE ------------------------------------------------------------------

fn expand_matrix(rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    let mut a = Vec::with_capacity(K);
    for i in 0..K {
        let mut row = Vec::with_capacity(K);
        for j in 0..K {
            row.push(sample_ntt(rho, i as u8, j as u8));
        }
        a.push(row);
    }
    a
}

fn kpke_keygen(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let g = sha3_512_parts(&[d, &[K as u8]]);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(&g[32..]);

    let a = expand_matrix(&rho);

    let mut s: PolyVec = [ZERO_POLY; K];
    let mut e: PolyVec = [ZERO_POLY; K];
    let mut nonce = 0u8;
    for item in s.iter_mut() {
        *item = sample_cbd(&prf(ETA1, &sigma, nonce), ETA1);
        nonce += 1;
    }
    for item in e.iter_mut() {
        *item = sample_cbd(&prf(ETA1, &sigma, nonce), ETA1);
        nonce += 1;
    }
    for item in s.iter_mut() {
        ntt(item);
    }
    for item in e.iter_mut() {
        ntt(item);
    }

    // t_hat = A_hat . s_hat + e_hat
    let mut t: PolyVec = [ZERO_POLY; K];
    for i in 0..K {
        let mut acc = ZERO_POLY;
        for j in 0..K {
            acc = poly_add(&acc, &basemul(&a[i][j], &s[j]));
        }
        t[i] = poly_add(&acc, &e[i]);
    }

    let mut ek = Vec::with_capacity(ENCAPS_KEY_LEN);
    for item in t.iter() {
        encode_poly(item, 12, &mut ek);
    }
    ek.extend_from_slice(&rho);

    let mut dk = Vec::with_capacity(384 * K);
    for item in s.iter() {
        encode_poly(item, 12, &mut dk);
    }
    (ek, dk)
}

fn kpke_encrypt(ek: &[u8], msg: &[u8; 32], rand: &[u8; 32]) -> Vec<u8> {
    let mut t: PolyVec = [ZERO_POLY; K];
    for (i, item) in t.iter_mut().enumerate() {
        *item = decode_poly(&ek[384 * i..384 * (i + 1)], 12);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..384 * K + 32]);

    let a = expand_matrix(&rho);

    let mut y: PolyVec = [ZERO_POLY; K];
    let mut e1: PolyVec = [ZERO_POLY; K];
    let mut nonce = 0u8;
    for item in y.iter_mut() {
        *item = sample_cbd(&prf(ETA1, rand, nonce), ETA1);
        nonce += 1;
    }
    for item in e1.iter_mut() {
        *item = sample_cbd(&prf(ETA2, rand, nonce), ETA2);
        nonce += 1;
    }
    let e2 = sample_cbd(&prf(ETA2, rand, nonce), ETA2);

    for item in y.iter_mut() {
        ntt(item);
    }

    // u = NTT^-1(A_hat^T . y_hat) + e1
    let mut u: PolyVec = [ZERO_POLY; K];
    for i in 0..K {
        let mut acc = ZERO_POLY;
        for j in 0..K {
            acc = poly_add(&acc, &basemul(&a[j][i], &y[j]));
        }
        inv_ntt(&mut acc);
        u[i] = poly_add(&acc, &e1[i]);
    }

    // v = NTT^-1(t_hat^T . y_hat) + e2 + Decompress_1(m)
    let mut acc = ZERO_POLY;
    for j in 0..K {
        acc = poly_add(&acc, &basemul(&t[j], &y[j]));
    }
    inv_ntt(&mut acc);
    let mut mu = ZERO_POLY;
    let bits = bit_unpack(msg, 1, N);
    for i in 0..N {
        mu[i] = decompress(bits[i], 1);
    }
    let v = poly_add(&poly_add(&acc, &e2), &mu);

    let mut ct = Vec::with_capacity(CIPHERTEXT_LEN);
    for item in u.iter() {
        let mut c = ZERO_POLY;
        for i in 0..N {
            c[i] = compress(item[i], DU);
        }
        encode_poly(&c, DU, &mut ct);
    }
    let mut c = ZERO_POLY;
    for i in 0..N {
        c[i] = compress(v[i], DV);
    }
    encode_poly(&c, DV, &mut ct);
    ct
}

fn kpke_decrypt(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let u_len = 32 * DU;
    let mut u: PolyVec = [ZERO_POLY; K];
    for (i, item) in u.iter_mut().enumerate() {
        let packed = decode_poly(&ct[u_len * i..u_len * (i + 1)], DU);
        let mut p = ZERO_POLY;
        for j in 0..N {
            p[j] = decompress(packed[j], DU);
        }
        *item = p;
    }
    let packed_v = decode_poly(&ct[u_len * K..], DV);
    let mut v = ZERO_POLY;
    for j in 0..N {
        v[j] = decompress(packed_v[j], DV);
    }

    let mut s: PolyVec = [ZERO_POLY; K];
    for (i, item) in s.iter_mut().enumerate() {
        *item = decode_poly(&dk[384 * i..384 * (i + 1)], 12);
    }

    let mut acc = ZERO_POLY;
    for j in 0..K {
        let mut uj = u[j];
        ntt(&mut uj);
        acc = poly_add(&acc, &basemul(&s[j], &uj));
    }
    inv_ntt(&mut acc);
    let w = poly_sub(&v, &acc);

    let mut bits = [0u16; N];
    for i in 0..N {
        bits[i] = compress(w[i], 1);
    }
    let mut out = Vec::with_capacity(32);
    bit_pack(&bits, 1, &mut out);
    let mut m = [0u8; 32];
    m.copy_from_slice(&out[..32]);
    m
}

// --- ML-KEM -----------------------------------------------------------------

/// An ML-KEM-1024 key pair.
pub struct KeyPair {
    /// Encapsulation (public) key.
    pub encaps_key: Vec<u8>,
    /// Decapsulation (secret) key.
    pub decaps_key: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.decaps_key);
    }
}

/// Deterministic key generation from the two 32-byte seeds `d` and `z`.
///
/// Exposed so that the handshake can regenerate a key pair from stored seed
/// material without keeping the expanded 3,168-byte secret key resident.
#[must_use]
pub fn keygen_derand(d: &[u8; 32], z: &[u8; 32]) -> KeyPair {
    let (ek, dk_pke) = kpke_keygen(d);
    let h = sha3_256(&ek);
    let mut dk = Vec::with_capacity(DECAPS_KEY_LEN);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h);
    dk.extend_from_slice(z);
    KeyPair {
        encaps_key: ek,
        decaps_key: dk,
    }
}

/// Generate a key pair from system entropy.
pub fn keygen() -> Result<KeyPair> {
    let d = crate::rand::bytes32()?;
    let z = crate::rand::bytes32()?;
    Ok(keygen_derand(&d, &z))
}

/// Validate an encapsulation key per FIPS 203 §7.2.
///
/// Two checks: the length, and that every packed 12-bit coefficient is `< q`.
/// Skipping the second check is the classic way an implementation accepts a
/// malformed key and produces a shared secret the peer can predict.
pub fn validate_encaps_key(ek: &[u8]) -> Result<()> {
    if ek.len() != ENCAPS_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    for i in 0..K {
        let p = decode_poly(&ek[384 * i..384 * (i + 1)], 12);
        // Re-encode and compare: equality holds iff every coefficient was < q.
        let mut re = Vec::with_capacity(384);
        encode_poly(&p, 12, &mut re);
        if re != ek[384 * i..384 * (i + 1)] {
            return Err(CryptoError::Invalid);
        }
        for c in p.iter() {
            if *c as u32 >= Q {
                return Err(CryptoError::Invalid);
            }
        }
    }
    Ok(())
}

/// Deterministic encapsulation, given the 32-byte message `m`.
pub fn encaps_derand(ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    validate_encaps_key(ek)?;
    let h = sha3_256(ek);
    let g = sha3_512_parts(&[m, &h]);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(&g[..32]);
    let mut r = [0u8; 32];
    r.copy_from_slice(&g[32..]);
    let ct = kpke_encrypt(ek, m, &r);
    Ok((ct, shared))
}

/// Encapsulate to a peer's encapsulation key.
pub fn encaps(ek: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    let m = crate::rand::bytes32()?;
    encaps_derand(ek, &m)
}

/// Decapsulate a ciphertext.
///
/// On any failure — wrong ciphertext, tampered ciphertext, mismatched key —
/// this returns a pseudorandom shared secret derived from the implicit
/// rejection value `z`, *not* an error. That is deliberate and required: an
/// error here would be a decryption oracle. The caller learns that something
/// is wrong only when the resulting session fails to authenticate.
pub fn decaps(dk: &[u8], ct: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
    if dk.len() != DECAPS_KEY_LEN || ct.len() != CIPHERTEXT_LEN {
        return Err(CryptoError::BadLength);
    }
    let dk_pke = &dk[..384 * K];
    let ek = &dk[384 * K..768 * K + 32];
    let h = &dk[768 * K + 32..768 * K + 64];
    let z = &dk[768 * K + 64..768 * K + 96];

    let m = kpke_decrypt(dk_pke, ct);
    let g = sha3_512_parts(&[&m, h]);
    let mut k_prime = [0u8; 32];
    k_prime.copy_from_slice(&g[..32]);
    let mut r = [0u8; 32];
    r.copy_from_slice(&g[32..]);

    // Implicit rejection value.
    let mut x = Shake256::new();
    x.update(z);
    x.update(ct);
    let mut k_bar = [0u8; 32];
    x.squeeze(&mut k_bar);

    let ct_prime = kpke_encrypt(ek, &m, &r);

    // Constant-time select: no branch on whether re-encryption matched.
    let matched = crate::ct::eq(&ct_prime, ct) as u8;
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = crate::ct::select_u8(matched, k_prime[i], k_bar[i]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modular_arithmetic_is_correct() {
        for a in [0u32, 1, 3328, 3329, 6657, 11_075_584, 4_294_967_295] {
            assert_eq!(barrett(a) as u32, a % Q, "barrett({a})");
        }
        assert_eq!(addq(3328, 1), 0);
        assert_eq!(subq(0, 1), 3328);
        assert_eq!(mulq(3328, 3328), 1);
    }

    #[test]
    fn zetas_table_is_well_formed() {
        assert_eq!(ZETAS[0], 1);
        // 17 is a primitive 256th root of unity mod q.
        assert_eq!(pow_mod(17, 256), 1);
        assert_ne!(pow_mod(17, 128), 1);
        assert_eq!((INV128 as u32 * 128) % Q, 1);
    }

    #[test]
    fn ntt_roundtrips() {
        let mut p = ZERO_POLY;
        for (i, c) in p.iter_mut().enumerate() {
            *c = ((i * 7 + 13) % Q as usize) as u16;
        }
        let orig = p;
        ntt(&mut p);
        assert_ne!(p, orig, "NTT must actually transform");
        inv_ntt(&mut p);
        assert_eq!(p, orig, "inverse NTT must recover the input");
    }

    #[test]
    fn ntt_multiplication_matches_schoolbook() {
        // Multiply two polynomials in Z_q[X]/(X^256+1) both ways.
        let mut a = ZERO_POLY;
        let mut b = ZERO_POLY;
        for i in 0..N {
            a[i] = ((i * 31 + 5) % Q as usize) as u16;
            b[i] = ((i * 17 + 91) % Q as usize) as u16;
        }
        let mut school = ZERO_POLY;
        for i in 0..N {
            for j in 0..N {
                let prod = mulq(a[i], b[j]);
                let k = i + j;
                if k < N {
                    school[k] = addq(school[k], prod);
                } else {
                    // X^256 = -1
                    school[k - N] = subq(school[k - N], prod);
                }
            }
        }
        let (mut na, mut nb) = (a, b);
        ntt(&mut na);
        ntt(&mut nb);
        let mut prod = basemul(&na, &nb);
        inv_ntt(&mut prod);
        assert_eq!(prod, school, "NTT product must equal schoolbook product");
    }

    #[test]
    fn compress_decompress_is_close() {
        for d in [1usize, 4, 5, 10, 11] {
            for x in [0u16, 1, 100, 1664, 3328] {
                let y = decompress(compress(x, d), d);
                let err = (x as i32 - y as i32).unsigned_abs();
                let bound = Q / (1 << d) + 1;
                assert!(err <= bound || (Q - err) <= bound, "d={d} x={x} y={y}");
            }
        }
    }

    #[test]
    fn bit_packing_roundtrips() {
        for d in [1usize, 4, 5, 10, 11, 12] {
            let vals: Vec<u16> = (0..N).map(|i| (i as u16) & ((1 << d) - 1)).collect();
            let mut buf = Vec::new();
            bit_pack(&vals, d, &mut buf);
            assert_eq!(buf.len(), N * d / 8);
            assert_eq!(bit_unpack(&buf, d, N), vals);
        }
    }

    #[test]
    fn key_and_ciphertext_sizes_match_fips203() {
        let kp = keygen_derand(&[1u8; 32], &[2u8; 32]);
        assert_eq!(kp.encaps_key.len(), 1568);
        assert_eq!(kp.decaps_key.len(), 3168);
        let (ct, _) = encaps(&kp.encaps_key).unwrap();
        assert_eq!(ct.len(), 1568);
    }

    #[test]
    fn encaps_decaps_roundtrip() {
        let kp = keygen().unwrap();
        for _ in 0..8 {
            let (ct, ss1) = encaps(&kp.encaps_key).unwrap();
            let ss2 = decaps(&kp.decaps_key, &ct).unwrap();
            assert_eq!(ss1, ss2, "shared secrets must agree");
            assert!(!crate::ct::is_zero(&ss1));
        }
    }

    #[test]
    fn keygen_is_deterministic_in_its_seeds() {
        let a = keygen_derand(&[7u8; 32], &[8u8; 32]);
        let b = keygen_derand(&[7u8; 32], &[8u8; 32]);
        assert_eq!(a.encaps_key, b.encaps_key);
        assert_eq!(a.decaps_key, b.decaps_key);
        let c = keygen_derand(&[7u8; 32], &[9u8; 32]);
        assert_eq!(
            a.encaps_key, c.encaps_key,
            "z must not affect the public key"
        );
        assert_ne!(a.decaps_key, c.decaps_key);
    }

    #[test]
    fn wrong_key_yields_a_different_secret_not_an_error() {
        let a = keygen().unwrap();
        let b = keygen().unwrap();
        let (ct, ss) = encaps(&a.encaps_key).unwrap();
        // Implicit rejection: decapsulation succeeds but returns garbage.
        let wrong = decaps(&b.decaps_key, &ct).unwrap();
        assert_ne!(ss, wrong);
    }

    #[test]
    fn tampered_ciphertext_triggers_implicit_rejection() {
        let kp = keygen().unwrap();
        let (ct, ss) = encaps(&kp.encaps_key).unwrap();
        for i in [0usize, 1, 700, 1567] {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            let got = decaps(&kp.decaps_key, &bad).unwrap();
            assert_ne!(got, ss, "tamper at byte {i} must change the secret");
        }
    }

    #[test]
    fn implicit_rejection_is_deterministic() {
        let kp = keygen().unwrap();
        let (ct, _) = encaps(&kp.encaps_key).unwrap();
        let mut bad = ct.clone();
        bad[10] ^= 0xFF;
        assert_eq!(
            decaps(&kp.decaps_key, &bad).unwrap(),
            decaps(&kp.decaps_key, &bad).unwrap()
        );
    }

    #[test]
    fn malformed_keys_and_ciphertexts_are_rejected() {
        let kp = keygen().unwrap();
        assert!(validate_encaps_key(&kp.encaps_key).is_ok());
        assert!(validate_encaps_key(&kp.encaps_key[..100]).is_err());

        // Coefficient >= q must be caught.
        let mut bad = kp.encaps_key.clone();
        bad[0] = 0xFF;
        bad[1] = 0xFF;
        assert!(validate_encaps_key(&bad).is_err());
        assert!(encaps(&bad).is_err());

        assert!(decaps(&kp.decaps_key, &[0u8; 10]).is_err());
        assert!(decaps(&[0u8; 10], &[0u8; CIPHERTEXT_LEN]).is_err());
    }

    #[test]
    fn encaps_is_deterministic_in_its_message() {
        let kp = keygen_derand(&[1u8; 32], &[2u8; 32]);
        let (c1, s1) = encaps_derand(&kp.encaps_key, &[3u8; 32]).unwrap();
        let (c2, s2) = encaps_derand(&kp.encaps_key, &[3u8; 32]).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(s1, s2);
        let (c3, s3) = encaps_derand(&kp.encaps_key, &[4u8; 32]).unwrap();
        assert_ne!(c1, c3);
        assert_ne!(s1, s3);
        assert_eq!(decaps(&kp.decaps_key, &c1).unwrap(), s1);
    }
}
