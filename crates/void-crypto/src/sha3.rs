//! Keccak / SHA-3 and the SHAKE XOFs (FIPS 202).
//!
//! Void does not use SHA-3 for its own KDF chains — those are HKDF-SHA-256 and
//! BLAKE3, chosen in NFR-SEC-01 for reviewability and speed. SHA-3 is here
//! because FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) *mandate* it: their
//! sampling, hashing, and expansion steps are defined in terms of SHA3-256,
//! SHA3-512, SHAKE128, and SHAKE256. Substituting anything else would be
//! novel cryptography, which NFR-SEC-01 forbids.

use alloc::vec::Vec;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// The Keccak-f\[1600\] permutation.
fn keccak_f1600(a: &mut [u64; 25]) {
    for round in 0..24 {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }

        // rho and pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let idx = x + 5 * y;
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[idx].rotate_left(RHO_OFFSETS[idx]);
            }
        }

        // chi
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // iota
        a[0] ^= ROUND_CONSTANTS[round];
    }
}

/// A Keccak sponge, generic over rate and domain-separation byte.
///
/// `RATE` is in bytes: 136 for SHA3-256/SHAKE128 is not right — see the
/// concrete constructors below, which set it per FIPS 202 Table 3.
#[derive(Clone)]
pub struct Keccak {
    state: [u64; 25],
    rate: usize,
    pad: u8,
    offset: usize,
    squeezing: bool,
}

impl Keccak {
    fn new(rate: usize, pad: u8) -> Self {
        Keccak {
            state: [0u64; 25],
            rate,
            pad,
            offset: 0,
            squeezing: false,
        }
    }

    fn xor_byte_at(&mut self, pos: usize, byte: u8) {
        let lane = pos / 8;
        let shift = 8 * (pos % 8);
        self.state[lane] ^= (byte as u64) << shift;
    }

    fn byte_at(&self, pos: usize) -> u8 {
        let lane = pos / 8;
        let shift = 8 * (pos % 8);
        ((self.state[lane] >> shift) & 0xFF) as u8
    }

    /// Absorb input. Panics if called after squeezing has begun; that would be
    /// a programming error, not an attacker-controlled condition.
    pub fn update(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "Keccak: absorb after squeeze");
        for &byte in data {
            self.xor_byte_at(self.offset, byte);
            self.offset += 1;
            if self.offset == self.rate {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
        }
    }

    fn pad_and_switch(&mut self) {
        self.xor_byte_at(self.offset, self.pad);
        self.xor_byte_at(self.rate - 1, 0x80);
        keccak_f1600(&mut self.state);
        self.offset = 0;
        self.squeezing = true;
    }

    /// Squeeze output. May be called repeatedly for XOF use.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.pad_and_switch();
        }
        for slot in out.iter_mut() {
            if self.offset == self.rate {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
            *slot = self.byte_at(self.offset);
            self.offset += 1;
        }
    }
}

macro_rules! fixed_hash {
    ($name:ident, $rate:expr, $outlen:expr, $doc:expr) => {
        #[doc = $doc]
        #[must_use]
        pub fn $name(data: &[u8]) -> [u8; $outlen] {
            let mut k = Keccak::new($rate, 0x06);
            k.update(data);
            let mut out = [0u8; $outlen];
            k.squeeze(&mut out);
            out
        }
    };
}

fixed_hash!(sha3_256, 136, 32, "SHA3-256 (FIPS 202).");
fixed_hash!(sha3_512, 72, 64, "SHA3-512 (FIPS 202).");

/// SHA3-256 over several parts without an intermediate concatenation.
#[must_use]
pub fn sha3_256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::new(136, 0x06);
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.squeeze(&mut out);
    out
}

/// SHA3-512 over several parts.
#[must_use]
pub fn sha3_512_parts(parts: &[&[u8]]) -> [u8; 64] {
    let mut k = Keccak::new(72, 0x06);
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 64];
    k.squeeze(&mut out);
    out
}

/// SHAKE128 as an incremental XOF. Used by ML-KEM's matrix expansion, which
/// needs an unbounded stream per (i, j) cell.
#[derive(Clone)]
pub struct Shake128(Keccak);

impl Shake128 {
    /// Create a new SHAKE128 XOF.
    #[must_use]
    pub fn new() -> Self {
        Shake128(Keccak::new(168, 0x1F))
    }
    /// Absorb input.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    /// Squeeze arbitrary output; may be called repeatedly.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.0.squeeze(out);
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHAKE256 as an incremental XOF. Used by ML-KEM and ML-DSA.
#[derive(Clone)]
pub struct Shake256(Keccak);

impl Shake256 {
    /// Create a new SHAKE256 XOF.
    #[must_use]
    pub fn new() -> Self {
        Shake256(Keccak::new(136, 0x1F))
    }
    /// Absorb input.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    /// Squeeze arbitrary output; may be called repeatedly.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.0.squeeze(out);
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHAKE256 with a chosen output length.
#[must_use]
pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut x = Shake256::new();
    x.update(data);
    let mut out = alloc::vec![0u8; out_len];
    x.squeeze(&mut out);
    out
}

/// One-shot SHAKE256 over several parts.
#[must_use]
pub fn shake256_parts(parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut x = Shake256::new();
    for p in parts {
        x.update(p);
    }
    let mut out = alloc::vec![0u8; out_len];
    x.squeeze(&mut out);
    out
}

/// One-shot SHAKE128 with a chosen output length.
#[must_use]
pub fn shake128(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut x = Shake128::new();
    x.update(data);
    let mut out = alloc::vec![0u8; out_len];
    x.squeeze(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::hex;

    #[test]
    fn sha3_published_vectors() {
        assert_eq!(
            hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex(&sha3_512(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
                .replace(['\n', ' '], "")
        );
        assert_eq!(
            hex(&sha3_512(b"abc")),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn shake_published_vectors() {
        // SHAKE128("") first 32 bytes
        assert_eq!(
            hex(&shake128(b"", 32)),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        // SHAKE256("") first 32 bytes
        assert_eq!(
            hex(&shake256(b"", 32)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn xof_incremental_matches_oneshot() {
        let mut x = Shake128::new();
        x.update(b"void");
        let mut a = [0u8; 100];
        x.squeeze(&mut a[..40]);
        x.squeeze(&mut a[40..]);
        assert_eq!(&a[..], &shake128(b"void", 100)[..]);
    }

    #[test]
    fn absorb_across_block_boundary() {
        let data: Vec<u8> = (0u8..=255).cycle().take(500).collect();
        for split in [0usize, 1, 135, 136, 137, 167, 168, 169, 499] {
            let mut k = Shake256::new();
            k.update(&data[..split]);
            k.update(&data[split..]);
            let mut out = [0u8; 64];
            k.squeeze(&mut out);
            assert_eq!(&out[..], &shake256(&data, 64)[..], "split {split}");
        }
    }
}
