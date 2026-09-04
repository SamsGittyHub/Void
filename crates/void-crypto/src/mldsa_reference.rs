//! ML-DSA-87 (FIPS 204).
//!
//! The post-quantum half of Void's identity signature (FR-ID-01). ML-DSA-87 is
//! kept at the highest parameter set — despite its 4,627-byte signature —
//! because `docs/DECISIONS.md#d-002` resolves PRD §13.1 in favour of confining
//! identity signatures to the handshake and to key-change events. Per-message
//! authentication comes from the ratchet's AEAD, so the signature size does not
//! set the record size.
//!
//! ## Implementation notes
//!
//! Coefficients are `u32` in `[0, q)` with `q = 8380417`. Reductions use `%`
//! against a compile-time constant, which LLVM lowers to a multiply-and-shift,
//! not a division instruction — so the reduction is constant time despite
//! looking like a modulo.
//!
//! Signing is a rejection loop. The number of iterations is secret-dependent
//! but leaks nothing useful: it is a function of the per-signature mask `y`,
//! which is freshly derived each attempt. This is the same behaviour as every
//! Fiat-Shamir-with-aborts signature scheme, including the reference
//! implementation.
//!
//! ## ⚠️ Not yet ACVP-validated
//!
//! See the crate-level warning. Not cleared for production until it passes the
//! NIST ACVP vectors.

use alloc::vec;
use alloc::vec::Vec;

use crate::sha3::{Shake128, Shake256};
use crate::{CryptoError, Result};

const Q: u32 = 8_380_417;
const N: usize = 256;
const D: usize = 13;

/// Rows of the matrix A (ML-DSA-87).
pub const K: usize = 8;
/// Columns of the matrix A (ML-DSA-87).
pub const L: usize = 7;
const ETA: u32 = 2;
const TAU: usize = 60;
const BETA: u32 = (TAU as u32) * ETA; // 120
const GAMMA1: u32 = 1 << 19; // 524288
const GAMMA2: u32 = (Q - 1) / 32; // 261888
const OMEGA: usize = 75;
const LAMBDA_BYTES: usize = 64; // lambda/4 with lambda = 256

/// Public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32 + 32 * K * (23 - D); // 2592
/// Secret key length in bytes.
pub const SECRET_KEY_LEN: usize = 32 + 32 + LAMBDA_BYTES + 32 * (L * 3 + K * 3 + K * D); // 4896
/// Signature length in bytes.
pub const SIGNATURE_LEN: usize = LAMBDA_BYTES + L * 32 * 20 + OMEGA + K; // 4627

type Poly = [u32; N];
const ZERO: Poly = [0u32; N];

// --- arithmetic -------------------------------------------------------------

#[inline(always)]
fn addq(a: u32, b: u32) -> u32 {
    let s = a + b;
    let t = s.wrapping_sub(Q);
    let mask = ((t as i32) >> 31) as u32;
    t.wrapping_add(mask & Q)
}

#[inline(always)]
fn subq(a: u32, b: u32) -> u32 {
    let t = a.wrapping_sub(b);
    let mask = ((t as i32) >> 31) as u32;
    t.wrapping_add(mask & Q)
}

#[inline(always)]
fn mulq(a: u32, b: u32) -> u32 {
    (((a as u64) * (b as u64)) % (Q as u64)) as u32
}

/// Centered representative: the unique value in `(-q/2, q/2]`.
#[inline(always)]
fn centered(a: u32) -> i32 {
    let a = a as i32;
    if a > (Q as i32) / 2 {
        a - Q as i32
    } else {
        a
    }
}

#[inline(always)]
fn from_centered(a: i32) -> u32 {
    if a < 0 {
        (a + Q as i32) as u32
    } else {
        a as u32
    }
}

const fn pow_mod(mut base: u64, mut exp: u64) -> u64 {
    let mut acc: u64 = 1;
    base %= Q as u64;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = (acc * base) % (Q as u64);
        }
        base = (base * base) % (Q as u64);
        exp >>= 1;
    }
    acc
}

/// `zetas[i] = 1753^bitrev8(i) mod q`, computed at compile time.
const ZETAS: [u32; 256] = {
    let mut z = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut r = 0u64;
        let mut b = 0;
        while b < 8 {
            r = (r << 1) | ((i as u64 >> b) & 1);
            b += 1;
        }
        z[i] = pow_mod(1753, r) as u32;
        i += 1;
    }
    z
};

/// `256^-1 mod q`.
const INV256: u32 = 8_347_681;

fn ntt(p: &mut Poly) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            for j in start..start + len {
                let t = mulq(zeta, p[j + len]);
                p[j + len] = subq(p[j], t);
                p[j] = addq(p[j], t);
            }
            start += 2 * len;
        }
        if len == 1 {
            break;
        }
        len >>= 1;
    }
}

fn inv_ntt(p: &mut Poly) {
    let mut k = 256usize;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = subq(0, ZETAS[k]);
            for j in start..start + len {
                let t = p[j];
                p[j] = addq(t, p[j + len]);
                p[j + len] = subq(t, p[j + len]);
                p[j + len] = mulq(zeta, p[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in p.iter_mut() {
        *c = mulq(*c, INV256);
    }
}

fn poly_pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO;
    for i in 0..N {
        r[i] = mulq(a[i], b[i]);
    }
    r
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO;
    for i in 0..N {
        r[i] = addq(a[i], b[i]);
    }
    r
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO;
    for i in 0..N {
        r[i] = subq(a[i], b[i]);
    }
    r
}

fn inf_norm(p: &Poly) -> u32 {
    let mut m = 0u32;
    for &c in p.iter() {
        let v = centered(c).unsigned_abs();
        if v > m {
            m = v;
        }
    }
    m
}

fn vec_inf_norm(v: &[Poly]) -> u32 {
    v.iter().map(inf_norm).max().unwrap_or(0)
}

// --- rounding ---------------------------------------------------------------

/// `r mod± alpha` for even `alpha`: the unique value in `(-alpha/2, alpha/2]`.
fn centered_mod(r: u32, alpha: u32) -> i32 {
    let mut r0 = (r % alpha) as i32;
    if r0 > (alpha / 2) as i32 {
        r0 -= alpha as i32;
    }
    r0
}

fn power2round(r: u32) -> (u32, i32) {
    let r0 = centered_mod(r, 1 << D);
    let r1 = ((r as i32 - r0) >> D) as u32;
    (r1, r0)
}

fn decompose(r: u32) -> (u32, i32) {
    let alpha = 2 * GAMMA2;
    let mut r0 = centered_mod(r, alpha);
    let r1;
    if (r as i32 - r0) == (Q - 1) as i32 {
        r1 = 0;
        r0 -= 1;
    } else {
        r1 = ((r as i32 - r0) / alpha as i32) as u32;
    }
    (r1, r0)
}

fn high_bits(r: u32) -> u32 {
    decompose(r).0
}

fn low_bits(r: u32) -> i32 {
    decompose(r).1
}

fn make_hint(z: u32, r: u32) -> u8 {
    let r1 = high_bits(r);
    let v1 = high_bits(addq(r, z));
    u8::from(r1 != v1)
}

fn use_hint(h: u8, r: u32) -> u32 {
    let m = (Q - 1) / (2 * GAMMA2); // 16
    let (r1, r0) = decompose(r);
    if h == 1 {
        if r0 > 0 {
            (r1 + 1) % m
        } else {
            (r1 + m - 1) % m
        }
    } else {
        r1
    }
}

// --- bit packing ------------------------------------------------------------

fn bitlen(x: u32) -> usize {
    (32 - x.leading_zeros()) as usize
}

fn pack_bits(vals: &[u32], bits: usize, out: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut acc_bits = 0usize;
    for &v in vals {
        acc |= ((v as u64) & ((1u64 << bits) - 1)) << acc_bits;
        acc_bits += bits;
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

fn unpack_bits(bytes: &[u8], bits: usize, count: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(count);
    let mut acc: u64 = 0;
    let mut acc_bits = 0usize;
    let mut idx = 0usize;
    for _ in 0..count {
        while acc_bits < bits {
            let b = if idx < bytes.len() { bytes[idx] } else { 0 };
            idx += 1;
            acc |= (b as u64) << acc_bits;
            acc_bits += 8;
        }
        out.push((acc & ((1u64 << bits) - 1)) as u32);
        acc >>= bits;
        acc_bits -= bits;
    }
    out
}

/// `SimpleBitPack(w, b)` — coefficients are already in `[0, b]`.
fn simple_bit_pack(p: &Poly, b: u32, out: &mut Vec<u8>) {
    pack_bits(p, bitlen(b), out);
}

fn simple_bit_unpack(bytes: &[u8], b: u32) -> Poly {
    let v = unpack_bits(bytes, bitlen(b), N);
    let mut p = ZERO;
    p.copy_from_slice(&v);
    p
}

/// `BitPack(w, a, b)` — coefficients are centered in `[-a, b]`.
fn bit_pack(p: &Poly, a: u32, b: u32, out: &mut Vec<u8>) {
    let bits = bitlen(a + b);
    let vals: Vec<u32> = p.iter().map(|&c| (b as i32 - centered(c)) as u32).collect();
    pack_bits(&vals, bits, out);
}

fn bit_unpack(bytes: &[u8], a: u32, b: u32) -> Poly {
    let bits = bitlen(a + b);
    let v = unpack_bits(bytes, bits, N);
    let mut p = ZERO;
    for i in 0..N {
        p[i] = from_centered(b as i32 - v[i] as i32);
    }
    p
}

fn hint_bit_pack(h: &[[u8; N]; K], out: &mut Vec<u8>) {
    let mut y = vec![0u8; OMEGA + K];
    let mut index = 0usize;
    for i in 0..K {
        for j in 0..N {
            if h[i][j] == 1 {
                y[index] = j as u8;
                index += 1;
            }
        }
        y[OMEGA + i] = index as u8;
    }
    out.extend_from_slice(&y);
}

fn hint_bit_unpack(y: &[u8]) -> Option<[[u8; N]; K]> {
    let mut h = [[0u8; N]; K];
    let mut index = 0usize;
    for i in 0..K {
        let end = y[OMEGA + i] as usize;
        if end < index || end > OMEGA {
            return None;
        }
        let first = index;
        while index < end {
            if index > first && y[index - 1] >= y[index] {
                return None;
            }
            h[i][y[index] as usize] = 1;
            index += 1;
        }
    }
    for &b in y.iter().take(OMEGA).skip(index) {
        if b != 0 {
            return None;
        }
    }
    Some(h)
}

// --- sampling ---------------------------------------------------------------

fn rej_ntt_poly(rho: &[u8], s: u8, r: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(rho);
    xof.update(&[s, r]);
    let mut p = ZERO;
    let mut count = 0usize;
    let mut buf = [0u8; 3];
    while count < N {
        xof.squeeze(&mut buf);
        let z = (buf[0] as u32) | ((buf[1] as u32) << 8) | (((buf[2] as u32) & 0x7F) << 16);
        if z < Q {
            p[count] = z;
            count += 1;
        }
    }
    p
}

fn rej_bounded_poly(rho: &[u8], nonce: u16) -> Poly {
    let mut xof = Shake256::new();
    xof.update(rho);
    xof.update(&nonce.to_le_bytes());
    let mut p = ZERO;
    let mut count = 0usize;
    let mut buf = [0u8; 1];
    while count < N {
        xof.squeeze(&mut buf);
        for half in [buf[0] & 0x0F, buf[0] >> 4] {
            if count >= N {
                break;
            }
            // eta = 2: accept b < 15, coefficient = 2 - (b mod 5)
            if half < 15 {
                let c = 2i32 - (half % 5) as i32;
                p[count] = from_centered(c);
                count += 1;
            }
        }
    }
    p
}

fn sample_in_ball(seed: &[u8]) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed);
    let mut sign_bytes = [0u8; 8];
    xof.squeeze(&mut sign_bytes);
    let mut signs = u64::from_le_bytes(sign_bytes);

    let mut c = ZERO;
    let mut byte = [0u8; 1];
    for i in (N - TAU)..N {
        let mut j: usize;
        loop {
            xof.squeeze(&mut byte);
            j = byte[0] as usize;
            if j <= i {
                break;
            }
        }
        c[i] = c[j];
        c[j] = if signs & 1 == 1 { Q - 1 } else { 1 };
        signs >>= 1;
    }
    c
}

fn expand_a(rho: &[u8]) -> Vec<Vec<Poly>> {
    let mut a = Vec::with_capacity(K);
    for r in 0..K {
        let mut row = Vec::with_capacity(L);
        for s in 0..L {
            row.push(rej_ntt_poly(rho, s as u8, r as u8));
        }
        a.push(row);
    }
    a
}

fn expand_s(rho: &[u8]) -> (Vec<Poly>, Vec<Poly>) {
    let s1: Vec<Poly> = (0..L).map(|i| rej_bounded_poly(rho, i as u16)).collect();
    let s2: Vec<Poly> = (0..K)
        .map(|i| rej_bounded_poly(rho, (i + L) as u16))
        .collect();
    (s1, s2)
}

fn expand_mask(rho: &[u8], kappa: u16) -> Vec<Poly> {
    let c = 1 + bitlen(GAMMA1 - 1); // 20
    (0..L)
        .map(|r| {
            let mut x = Shake256::new();
            x.update(rho);
            x.update(&(kappa + r as u16).to_le_bytes());
            let mut v = vec![0u8; 32 * c];
            x.squeeze(&mut v);
            bit_unpack(&v, GAMMA1 - 1, GAMMA1)
        })
        .collect()
}

fn shake256_of(parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    crate::sha3::shake256_parts(parts, out_len)
}

fn w1_encode(w1: &[Poly]) -> Vec<u8> {
    let b = (Q - 1) / (2 * GAMMA2) - 1; // 15
    let mut out = Vec::new();
    for p in w1 {
        simple_bit_pack(p, b, &mut out);
    }
    out
}

// --- key encoding -----------------------------------------------------------

fn pk_encode(rho: &[u8; 32], t1: &[Poly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_KEY_LEN);
    out.extend_from_slice(rho);
    let b = (1u32 << (23 - D)) - 1; // 1023
    for p in t1 {
        simple_bit_pack(p, b, &mut out);
    }
    out
}

fn pk_decode(pk: &[u8]) -> Option<([u8; 32], Vec<Poly>)> {
    if pk.len() != PUBLIC_KEY_LEN {
        return None;
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);
    let b = (1u32 << (23 - D)) - 1;
    let chunk = 32 * (23 - D);
    let t1 = (0..K)
        .map(|i| simple_bit_unpack(&pk[32 + chunk * i..32 + chunk * (i + 1)], b))
        .collect();
    Some((rho, t1))
}

#[allow(clippy::type_complexity)]
fn sk_encode(
    rho: &[u8; 32],
    key: &[u8; 32],
    tr: &[u8],
    s1: &[Poly],
    s2: &[Poly],
    t0: &[Poly],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SECRET_KEY_LEN);
    out.extend_from_slice(rho);
    out.extend_from_slice(key);
    out.extend_from_slice(tr);
    for p in s1 {
        bit_pack(p, ETA, ETA, &mut out);
    }
    for p in s2 {
        bit_pack(p, ETA, ETA, &mut out);
    }
    let a = 1u32 << (D - 1);
    for p in t0 {
        bit_pack(p, a - 1, a, &mut out);
    }
    out
}

#[allow(clippy::type_complexity)]
fn sk_decode(sk: &[u8]) -> Option<([u8; 32], [u8; 32], Vec<u8>, Vec<Poly>, Vec<Poly>, Vec<Poly>)> {
    if sk.len() != SECRET_KEY_LEN {
        return None;
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk[..32]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&sk[32..64]);
    let tr = sk[64..64 + LAMBDA_BYTES].to_vec();
    let mut off = 64 + LAMBDA_BYTES;

    let eta_bytes = 32 * bitlen(2 * ETA); // 96
    let s1 = (0..L)
        .map(|i| {
            bit_unpack(
                &sk[off + eta_bytes * i..off + eta_bytes * (i + 1)],
                ETA,
                ETA,
            )
        })
        .collect::<Vec<_>>();
    off += eta_bytes * L;
    let s2 = (0..K)
        .map(|i| {
            bit_unpack(
                &sk[off + eta_bytes * i..off + eta_bytes * (i + 1)],
                ETA,
                ETA,
            )
        })
        .collect::<Vec<_>>();
    off += eta_bytes * K;
    let a = 1u32 << (D - 1);
    let t0_bytes = 32 * D;
    let t0 = (0..K)
        .map(|i| bit_unpack(&sk[off + t0_bytes * i..off + t0_bytes * (i + 1)], a - 1, a))
        .collect::<Vec<_>>();
    Some((rho, key, tr, s1, s2, t0))
}

fn sig_encode(c_tilde: &[u8], z: &[Poly], h: &[[u8; N]; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNATURE_LEN);
    out.extend_from_slice(c_tilde);
    for p in z {
        bit_pack(p, GAMMA1 - 1, GAMMA1, &mut out);
    }
    hint_bit_pack(h, &mut out);
    out
}

#[allow(clippy::type_complexity)]
fn sig_decode(sig: &[u8]) -> Option<(Vec<u8>, Vec<Poly>, [[u8; N]; K])> {
    if sig.len() != SIGNATURE_LEN {
        return None;
    }
    let c_tilde = sig[..LAMBDA_BYTES].to_vec();
    let zbytes = 32 * (1 + bitlen(GAMMA1 - 1));
    let mut off = LAMBDA_BYTES;
    let z = (0..L)
        .map(|i| {
            bit_unpack(
                &sig[off + zbytes * i..off + zbytes * (i + 1)],
                GAMMA1 - 1,
                GAMMA1,
            )
        })
        .collect::<Vec<_>>();
    off += zbytes * L;
    let h = hint_bit_unpack(&sig[off..])?;
    Some((c_tilde, z, h))
}

// --- public API -------------------------------------------------------------

/// An ML-DSA-87 key pair.
pub struct KeyPair {
    /// Public verification key.
    pub public: Vec<u8>,
    /// Secret signing key.
    pub secret: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

/// Deterministic key generation from a 32-byte seed.
#[must_use]
pub fn keygen_derand(xi: &[u8; 32]) -> KeyPair {
    let expanded = shake256_of(&[xi, &[K as u8], &[L as u8]], 128);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&expanded[..32]);
    let rho_prime = &expanded[32..96];
    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded[96..128]);

    let a = expand_a(&rho);
    let (s1, s2) = expand_s(rho_prime);

    let s1_hat: Vec<Poly> = s1
        .iter()
        .map(|p| {
            let mut q = *p;
            ntt(&mut q);
            q
        })
        .collect();

    let mut t = Vec::with_capacity(K);
    for i in 0..K {
        let mut acc = ZERO;
        for j in 0..L {
            acc = poly_add(&acc, &poly_pointwise(&a[i][j], &s1_hat[j]));
        }
        inv_ntt(&mut acc);
        t.push(poly_add(&acc, &s2[i]));
    }

    let mut t1 = Vec::with_capacity(K);
    let mut t0 = Vec::with_capacity(K);
    for p in &t {
        let mut a1 = ZERO;
        let mut a0 = ZERO;
        for j in 0..N {
            let (hi, lo) = power2round(p[j]);
            a1[j] = hi;
            a0[j] = from_centered(lo);
        }
        t1.push(a1);
        t0.push(a0);
    }

    let pk = pk_encode(&rho, &t1);
    let tr = shake256_of(&[&pk], LAMBDA_BYTES);
    let sk = sk_encode(&rho, &key, &tr, &s1, &s2, &t0);
    KeyPair {
        public: pk,
        secret: sk,
    }
}

/// Generate a key pair from system entropy.
pub fn keygen() -> Result<KeyPair> {
    Ok(keygen_derand(&crate::rand::bytes32()?))
}

/// Sign `message` with an empty context string, per ML-DSA.Sign.
///
/// `rnd` is the 32-byte randomizer. Passing all zeros gives the deterministic
/// ("hedged off") variant, which FIPS 204 permits and which Void uses in tests
/// so that signatures are reproducible.
pub fn sign_with_rnd(sk: &[u8], message: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>> {
    // M' = IntegerToBytes(0,1) || IntegerToBytes(|ctx|,1) || ctx || M, ctx = ""
    let mut m_prime = Vec::with_capacity(message.len() + 2);
    m_prime.push(0u8);
    m_prime.push(0u8);
    m_prime.extend_from_slice(message);
    sign_internal(sk, &m_prime, rnd)
}

/// Sign with a fresh randomizer from system entropy (the hedged variant).
pub fn sign(sk: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let rnd = crate::rand::bytes32()?;
    sign_with_rnd(sk, message, &rnd)
}

fn sign_internal(sk: &[u8], m_prime: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>> {
    let (rho, key, tr, s1, s2, t0) = sk_decode(sk).ok_or(CryptoError::BadLength)?;

    let a = expand_a(&rho);
    let to_ntt = |v: &[Poly]| -> Vec<Poly> {
        v.iter()
            .map(|p| {
                let mut q = *p;
                ntt(&mut q);
                q
            })
            .collect()
    };
    let s1_hat = to_ntt(&s1);
    let s2_hat = to_ntt(&s2);
    let t0_hat = to_ntt(&t0);

    let mu = shake256_of(&[&tr, m_prime], 64);
    let rho_dprime = shake256_of(&[&key, rnd, &mu], 64);

    let mut kappa: u16 = 0;
    // The loop is bounded so a pathological key cannot hang the caller; the
    // expected number of iterations for ML-DSA-87 is about 4.3.
    for _ in 0..1000 {
        let y = expand_mask(&rho_dprime, kappa);
        kappa += L as u16;

        let y_hat = to_ntt(&y);
        let mut w = Vec::with_capacity(K);
        for i in 0..K {
            let mut acc = ZERO;
            for j in 0..L {
                acc = poly_add(&acc, &poly_pointwise(&a[i][j], &y_hat[j]));
            }
            inv_ntt(&mut acc);
            w.push(acc);
        }

        let w1: Vec<Poly> = w
            .iter()
            .map(|p| {
                let mut o = ZERO;
                for j in 0..N {
                    o[j] = high_bits(p[j]);
                }
                o
            })
            .collect();

        let c_tilde = shake256_of(&[&mu, &w1_encode(&w1)], LAMBDA_BYTES);
        let c = sample_in_ball(&c_tilde);
        let mut c_hat = c;
        ntt(&mut c_hat);

        let cs1: Vec<Poly> = (0..L)
            .map(|i| {
                let mut p = poly_pointwise(&c_hat, &s1_hat[i]);
                inv_ntt(&mut p);
                p
            })
            .collect();
        let cs2: Vec<Poly> = (0..K)
            .map(|i| {
                let mut p = poly_pointwise(&c_hat, &s2_hat[i]);
                inv_ntt(&mut p);
                p
            })
            .collect();

        let z: Vec<Poly> = (0..L).map(|i| poly_add(&y[i], &cs1[i])).collect();
        let w_minus_cs2: Vec<Poly> = (0..K).map(|i| poly_sub(&w[i], &cs2[i])).collect();
        let r0: Vec<Poly> = w_minus_cs2
            .iter()
            .map(|p| {
                let mut o = ZERO;
                for j in 0..N {
                    o[j] = from_centered(low_bits(p[j]));
                }
                o
            })
            .collect();

        if vec_inf_norm(&z) >= GAMMA1 - BETA || vec_inf_norm(&r0) >= GAMMA2 - BETA {
            continue;
        }

        let ct0: Vec<Poly> = (0..K)
            .map(|i| {
                let mut p = poly_pointwise(&c_hat, &t0_hat[i]);
                inv_ntt(&mut p);
                p
            })
            .collect();

        let mut h = [[0u8; N]; K];
        let mut ones = 0usize;
        for i in 0..K {
            for j in 0..N {
                let neg_ct0 = subq(0, ct0[i][j]);
                let r = addq(w_minus_cs2[i][j], ct0[i][j]);
                h[i][j] = make_hint(neg_ct0, r);
                ones += h[i][j] as usize;
            }
        }

        if vec_inf_norm(&ct0) >= GAMMA2 || ones > OMEGA {
            continue;
        }

        return Ok(sig_encode(&c_tilde, &z, &h));
    }
    Err(CryptoError::Invalid)
}

/// Verify a signature produced by `sign` / `sign_with_rnd`.
#[must_use]
pub fn verify(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let mut m_prime = Vec::with_capacity(message.len() + 2);
    m_prime.push(0u8);
    m_prime.push(0u8);
    m_prime.extend_from_slice(message);
    verify_internal(pk, &m_prime, sig)
}

fn verify_internal(pk: &[u8], m_prime: &[u8], sig: &[u8]) -> bool {
    let (rho, t1) = match pk_decode(pk) {
        Some(v) => v,
        None => return false,
    };
    let (c_tilde, z, h) = match sig_decode(sig) {
        Some(v) => v,
        None => return false,
    };

    if vec_inf_norm(&z) >= GAMMA1 - BETA {
        return false;
    }

    let a = expand_a(&rho);
    let tr = shake256_of(&[pk], LAMBDA_BYTES);
    let mu = shake256_of(&[&tr, m_prime], 64);
    let c = sample_in_ball(&c_tilde);
    let mut c_hat = c;
    ntt(&mut c_hat);

    let z_hat: Vec<Poly> = z
        .iter()
        .map(|p| {
            let mut q = *p;
            ntt(&mut q);
            q
        })
        .collect();

    // w'_approx = A.z - c.t1.2^d
    let mut w_approx = Vec::with_capacity(K);
    for i in 0..K {
        let mut acc = ZERO;
        for j in 0..L {
            acc = poly_add(&acc, &poly_pointwise(&a[i][j], &z_hat[j]));
        }
        let mut t1_shift = ZERO;
        for j in 0..N {
            t1_shift[j] = mulq(t1[i][j], 1 << D);
        }
        ntt(&mut t1_shift);
        let ct1 = poly_pointwise(&c_hat, &t1_shift);
        let mut diff = poly_sub(&acc, &ct1);
        inv_ntt(&mut diff);
        w_approx.push(diff);
    }

    let w1: Vec<Poly> = (0..K)
        .map(|i| {
            let mut o = ZERO;
            for j in 0..N {
                o[j] = use_hint(h[i][j], w_approx[i][j]);
            }
            o
        })
        .collect();

    let c_tilde_prime = shake256_of(&[&mu, &w1_encode(&w1)], LAMBDA_BYTES);
    crate::ct::eq(&c_tilde, &c_tilde_prime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_and_constants() {
        assert_eq!(Q, 8_380_417);
        assert_eq!(GAMMA2, 261_888);
        assert_eq!((INV256 as u64 * 256) % Q as u64, 1);
        assert_eq!(pow_mod(1753, 512), 1);
        assert_ne!(pow_mod(1753, 256), 1);
        assert_eq!(addq(Q - 1, 1), 0);
        assert_eq!(subq(0, 1), Q - 1);
        assert_eq!(mulq(Q - 1, Q - 1), 1);
        assert_eq!(centered(Q - 1), -1);
        assert_eq!(from_centered(-1), Q - 1);
    }

    #[test]
    fn sizes_match_fips204_table() {
        assert_eq!(PUBLIC_KEY_LEN, 2592);
        assert_eq!(SECRET_KEY_LEN, 4896);
        assert_eq!(SIGNATURE_LEN, 4627);
    }

    #[test]
    fn ntt_roundtrips_and_multiplies() {
        let mut p = ZERO;
        for (i, c) in p.iter_mut().enumerate() {
            *c = (i as u32 * 7919 + 13) % Q;
        }
        let orig = p;
        ntt(&mut p);
        assert_ne!(p, orig);
        inv_ntt(&mut p);
        assert_eq!(p, orig);

        // Compare NTT product against schoolbook in Z_q[X]/(X^256+1).
        let mut a = ZERO;
        let mut b = ZERO;
        for i in 0..N {
            a[i] = (i as u32 * 31 + 5) % Q;
            b[i] = (i as u32 * 17 + 91) % Q;
        }
        let mut school = ZERO;
        for i in 0..N {
            for j in 0..N {
                let prod = mulq(a[i], b[j]);
                let k = i + j;
                if k < N {
                    school[k] = addq(school[k], prod);
                } else {
                    school[k - N] = subq(school[k - N], prod);
                }
            }
        }
        let (mut na, mut nb) = (a, b);
        ntt(&mut na);
        ntt(&mut nb);
        let mut prod = poly_pointwise(&na, &nb);
        inv_ntt(&mut prod);
        assert_eq!(prod, school);
    }

    #[test]
    fn rounding_identities() {
        for r in [0u32, 1, 8191, 8192, 261_888, 4_190_208, Q - 1] {
            let (r1, r0) = power2round(r);
            assert_eq!(
                from_centered((r1 as i32) * (1 << D) + r0),
                r,
                "power2round({r})"
            );
            assert!(r0 > -(1 << (D - 1)) && r0 <= (1 << (D - 1)));

            let (h, l) = decompose(r);
            assert!(h < 16, "high bits out of range for {r}");
            assert!(l > -(GAMMA2 as i32) && l <= GAMMA2 as i32);
        }
    }

    #[test]
    fn hint_recovers_high_bits() {
        // UseHint(MakeHint(z, r), r + z) must recover HighBits(r + z).
        for r in [0u32, 1000, 300_000, 4_000_000, Q - 5] {
            for z in [0u32, 1, 100, Q - 1] {
                let rz = addq(r, z);
                let hint = make_hint(subq(0, z), rz);
                assert_eq!(use_hint(hint, rz), high_bits(r), "r={r} z={z}");
            }
        }
    }

    #[test]
    fn bit_packing_roundtrips() {
        let mut p = ZERO;
        for i in 0..N {
            p[i] = from_centered((i as i32 % 5) - 2);
        }
        let mut buf = Vec::new();
        bit_pack(&p, ETA, ETA, &mut buf);
        assert_eq!(buf.len(), 32 * bitlen(2 * ETA));
        assert_eq!(bit_unpack(&buf, ETA, ETA), p);

        let mut q = ZERO;
        for i in 0..N {
            q[i] = (i as u32) % 1024;
        }
        let mut buf2 = Vec::new();
        simple_bit_pack(&q, 1023, &mut buf2);
        assert_eq!(buf2.len(), 32 * 10);
        assert_eq!(simple_bit_unpack(&buf2, 1023), q);
    }

    #[test]
    fn hint_packing_roundtrips_and_validates() {
        let mut h = [[0u8; N]; K];
        h[0][5] = 1;
        h[0][200] = 1;
        h[3][17] = 1;
        let mut buf = Vec::new();
        hint_bit_pack(&h, &mut buf);
        assert_eq!(buf.len(), OMEGA + K);
        assert_eq!(hint_bit_unpack(&buf).unwrap(), h);

        // Out-of-order indices must be rejected.
        let mut bad = buf.clone();
        bad[0] = 200;
        bad[1] = 5;
        assert!(hint_bit_unpack(&bad).is_none());
        // Count exceeding omega must be rejected.
        let mut bad2 = buf.clone();
        bad2[OMEGA] = (OMEGA + 1) as u8;
        assert!(hint_bit_unpack(&bad2).is_none());
    }

    #[test]
    fn sample_in_ball_has_exactly_tau_nonzero() {
        for seed in 0u8..8 {
            let c = sample_in_ball(&[seed; 64]);
            let nonzero = c.iter().filter(|&&x| x != 0).count();
            assert_eq!(nonzero, TAU, "seed {seed}");
            for &x in c.iter() {
                assert!(x == 0 || x == 1 || x == Q - 1);
            }
        }
    }

    #[test]
    fn expand_s_respects_eta_bound() {
        let (s1, s2) = expand_s(&[9u8; 64]);
        assert_eq!(s1.len(), L);
        assert_eq!(s2.len(), K);
        for p in s1.iter().chain(s2.iter()) {
            assert!(inf_norm(p) <= ETA);
        }
    }

    #[test]
    fn keygen_sizes_and_determinism() {
        let a = keygen_derand(&[1u8; 32]);
        assert_eq!(a.public.len(), PUBLIC_KEY_LEN);
        assert_eq!(a.secret.len(), SECRET_KEY_LEN);
        let b = keygen_derand(&[1u8; 32]);
        assert_eq!(a.public, b.public);
        assert_eq!(a.secret, b.secret);
        let c = keygen_derand(&[2u8; 32]);
        assert_ne!(a.public, c.public);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = keygen_derand(&[42u8; 32]);
        for msg in [
            &b""[..],
            &b"a"[..],
            &b"the quick brown fox jumps over the lazy dog"[..],
            &[0xFFu8; 1000][..],
        ] {
            let sig = sign_with_rnd(&kp.secret, msg, &[0u8; 32]).unwrap();
            assert_eq!(sig.len(), SIGNATURE_LEN);
            assert!(
                verify(&kp.public, msg, &sig),
                "verify failed for {} bytes",
                msg.len()
            );
        }
    }

    #[test]
    fn hedged_signing_produces_valid_but_distinct_signatures() {
        let kp = keygen_derand(&[5u8; 32]);
        let a = sign_with_rnd(&kp.secret, b"m", &[1u8; 32]).unwrap();
        let b = sign_with_rnd(&kp.secret, b"m", &[2u8; 32]).unwrap();
        assert_ne!(a, b, "different randomizers must give different signatures");
        assert!(verify(&kp.public, b"m", &a));
        assert!(verify(&kp.public, b"m", &b));
    }

    #[test]
    fn deterministic_signing_is_reproducible() {
        let kp = keygen_derand(&[6u8; 32]);
        let a = sign_with_rnd(&kp.secret, b"m", &[0u8; 32]).unwrap();
        let b = sign_with_rnd(&kp.secret, b"m", &[0u8; 32]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_wrong_message_key_and_tampering() {
        let kp = keygen_derand(&[7u8; 32]);
        let other = keygen_derand(&[8u8; 32]);
        let msg = b"authorize";
        let sig = sign_with_rnd(&kp.secret, msg, &[0u8; 32]).unwrap();

        assert!(verify(&kp.public, msg, &sig));
        assert!(!verify(&kp.public, b"authorizf", &sig));
        assert!(!verify(&other.public, msg, &sig));
        assert!(!verify(&kp.public, msg, &sig[..SIGNATURE_LEN - 1]));

        // Tamper across the three signature regions: c_tilde, z, hints.
        for i in [0usize, 63, 64, 2000, SIGNATURE_LEN - 1] {
            let mut bad = sig.clone();
            bad[i] ^= 0x01;
            assert!(!verify(&kp.public, msg, &bad), "tamper at {i} not detected");
        }
    }

    #[test]
    fn rejects_malformed_public_key() {
        let kp = keygen_derand(&[9u8; 32]);
        let sig = sign_with_rnd(&kp.secret, b"m", &[0u8; 32]).unwrap();
        assert!(!verify(&kp.public[..10], b"m", &sig));
        let mut bad = kp.public.clone();
        bad[0] ^= 0xFF;
        assert!(!verify(&bad, b"m", &sig));
    }
}
