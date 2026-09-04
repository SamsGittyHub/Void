//! BLAKE2b (RFC 7693).
//!
//! Present because Argon2id (RFC 9106) is defined in terms of BLAKE2b. Void
//! does not use BLAKE2b directly anywhere else; general-purpose hashing is
//! BLAKE3 and the KDF is HKDF-SHA-256.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Streaming BLAKE2b with a configurable digest length (1..=64 bytes) and
/// optional key.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    counter: u128,
    out_len: usize,
}

impl Blake2b {
    /// Create an unkeyed hasher with the given output length (1..=64).
    #[must_use]
    pub fn new(out_len: usize) -> Self {
        Self::with_key(out_len, &[])
    }

    /// Create a keyed hasher. `key` may be up to 64 bytes.
    #[must_use]
    pub fn with_key(out_len: usize, key: &[u8]) -> Self {
        assert!((1..=64).contains(&out_len), "blake2b: bad output length");
        assert!(key.len() <= 64, "blake2b: key too long");
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ (out_len as u64);
        let mut s = Blake2b {
            h,
            buf: [0u8; 128],
            buf_len: 0,
            counter: 0,
            out_len,
        };
        if !key.is_empty() {
            let mut block = [0u8; 128];
            block[..key.len()].copy_from_slice(key);
            s.update(&block);
        }
        s
    }

    fn compress(&mut self, block: &[u8; 128], last: bool) {
        let mut m = [0u64; 16];
        for i in 0..16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[8 * i..8 * i + 8]);
            m[i] = u64::from_le_bytes(b);
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.counter as u64;
        v[13] ^= (self.counter >> 64) as u64;
        if last {
            v[14] = !v[14];
        }

        #[inline(always)]
        fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        }

        for round in 0..12 {
            let s = &SIGMA[round];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// Absorb input.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buf_len == 128 {
                // Only compress a full buffer once we know more data follows,
                // because the final block must be flagged.
                self.counter = self.counter.wrapping_add(128);
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
            }
            let take = core::cmp::min(128 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
        }
    }

    /// Finish and write the digest into `out`, which must be `out_len` bytes.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.out_len);
        self.counter = self.counter.wrapping_add(self.buf_len as u128);
        for b in self.buf[self.buf_len..].iter_mut() {
            *b = 0;
        }
        let block = self.buf;
        self.compress(&block, true);
        let mut full = [0u8; 64];
        for i in 0..8 {
            full[8 * i..8 * i + 8].copy_from_slice(&self.h[i].to_le_bytes());
        }
        out.copy_from_slice(&full[..self.out_len]);
    }

    /// One-shot unkeyed BLAKE2b-512.
    #[must_use]
    pub fn digest512(data: &[u8]) -> [u8; 64] {
        let mut h = Blake2b::new(64);
        h.update(data);
        let mut out = [0u8; 64];
        h.finalize_into(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::hex;

    #[test]
    fn blake2b512_published_vectors() {
        assert_eq!(
            hex(&Blake2b::digest512(b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
                .replace(['\n', ' '], "")
        );
        assert_eq!(
            hex(&Blake2b::digest512(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data: alloc::vec::Vec<u8> = (0u8..=255).cycle().take(400).collect();
        for split in [0usize, 1, 127, 128, 129, 255, 256, 399] {
            let mut h = Blake2b::new(64);
            h.update(&data[..split]);
            h.update(&data[split..]);
            let mut out = [0u8; 64];
            h.finalize_into(&mut out);
            assert_eq!(out, Blake2b::digest512(&data), "split {split}");
        }
    }

    #[test]
    fn exact_block_multiple() {
        // The "compress only when more data follows" rule is the classic
        // BLAKE2 off-by-one; pin it.
        let data = [0x42u8; 128];
        let mut h = Blake2b::new(64);
        h.update(&data);
        let mut a = [0u8; 64];
        h.finalize_into(&mut a);
        assert_eq!(a, Blake2b::digest512(&data));
    }
}
