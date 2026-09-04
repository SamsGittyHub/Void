//! Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Used only as part of ChaCha20-Poly1305. A Poly1305 key must never be reused
//! across two messages; the AEAD construction in `chacha` guarantees this by
//! deriving the key from the (key, nonce) pair via the ChaCha20 block function.

use crate::ct;

/// Poly1305 state.
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    /// Create from a 32-byte one-time key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        // Clamp r per RFC 8439.
        let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);

        let r = [
            t0 & 0x3ff_ffff,
            ((t0 >> 26) | (t1 << 6)) & 0x3ff_ff03,
            ((t1 >> 20) | (t2 << 12)) & 0x3ff_c0ff,
            ((t2 >> 14) | (t3 << 18)) & 0x3f0_3fff,
            (t3 >> 8) & 0x000f_ffff,
        ];
        let pad = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];
        Poly1305 {
            r,
            h: [0u32; 5],
            pad,
            buf: [0u8; 16],
            buf_len: 0,
        }
    }

    fn block(&mut self, m: &[u8; 16], final_block: bool) {
        let hibit: u32 = if final_block { 0 } else { 1 << 24 };

        let t0 = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
        let t1 = u32::from_le_bytes([m[4], m[5], m[6], m[7]]);
        let t2 = u32::from_le_bytes([m[8], m[9], m[10], m[11]]);
        let t3 = u32::from_le_bytes([m[12], m[13], m[14], m[15]]);

        self.h[0] += t0 & 0x3ff_ffff;
        self.h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ff_ffff;
        self.h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ff_ffff;
        self.h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ff_ffff;
        self.h[4] += (t3 >> 8) | hibit;

        let r = self.r;
        let s: [u32; 4] = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];

        let h = self.h;
        let d0 = (h[0] as u64) * (r[0] as u64)
            + (h[1] as u64) * (s[3] as u64)
            + (h[2] as u64) * (s[2] as u64)
            + (h[3] as u64) * (s[1] as u64)
            + (h[4] as u64) * (s[0] as u64);
        let d1 = (h[0] as u64) * (r[1] as u64)
            + (h[1] as u64) * (r[0] as u64)
            + (h[2] as u64) * (s[3] as u64)
            + (h[3] as u64) * (s[2] as u64)
            + (h[4] as u64) * (s[1] as u64);
        let d2 = (h[0] as u64) * (r[2] as u64)
            + (h[1] as u64) * (r[1] as u64)
            + (h[2] as u64) * (r[0] as u64)
            + (h[3] as u64) * (s[3] as u64)
            + (h[4] as u64) * (s[2] as u64);
        let d3 = (h[0] as u64) * (r[3] as u64)
            + (h[1] as u64) * (r[2] as u64)
            + (h[2] as u64) * (r[1] as u64)
            + (h[3] as u64) * (r[0] as u64)
            + (h[4] as u64) * (s[3] as u64);
        let d4 = (h[0] as u64) * (r[4] as u64)
            + (h[1] as u64) * (r[3] as u64)
            + (h[2] as u64) * (r[2] as u64)
            + (h[3] as u64) * (r[1] as u64)
            + (h[4] as u64) * (r[0] as u64);

        // Partial reduction mod 2^130 - 5
        let mut c: u64;
        c = d0 >> 26;
        self.h[0] = (d0 as u32) & 0x3ff_ffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        self.h[1] = (d1 as u32) & 0x3ff_ffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        self.h[2] = (d2 as u32) & 0x3ff_ffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        self.h[3] = (d3 as u32) & 0x3ff_ffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        self.h[4] = (d4 as u32) & 0x3ff_ffff;
        self.h[0] += (c as u32) * 5;
        c = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x3ff_ffff;
        self.h[1] += c as u32;
    }

    /// Absorb message bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = core::cmp::min(16 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let b = self.buf;
                self.block(&b, false);
                self.buf_len = 0;
            }
        }
        while data.len() >= 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[..16]);
            self.block(&b, false);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Produce the 16-byte tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let n = self.buf_len;
            self.buf[n] = 1;
            for b in self.buf[n + 1..].iter_mut() {
                *b = 0;
            }
            let b = self.buf;
            self.block(&b, true);
        }

        // Full carry
        let mut c = self.h[1] >> 26;
        self.h[1] &= 0x3ff_ffff;
        self.h[2] += c;
        c = self.h[2] >> 26;
        self.h[2] &= 0x3ff_ffff;
        self.h[3] += c;
        c = self.h[3] >> 26;
        self.h[3] &= 0x3ff_ffff;
        self.h[4] += c;
        c = self.h[4] >> 26;
        self.h[4] &= 0x3ff_ffff;
        self.h[0] += c * 5;
        c = self.h[0] >> 26;
        self.h[0] &= 0x3ff_ffff;
        self.h[1] += c;

        // Compute h + -p
        let mut g = [0u32; 5];
        let mut c2 = self.h[0].wrapping_add(5);
        g[0] = c2 & 0x3ff_ffff;
        c2 >>= 26;
        for i in 1..4 {
            c2 = self.h[i].wrapping_add(c2);
            g[i] = c2 & 0x3ff_ffff;
            c2 >>= 26;
        }
        g[4] = self.h[4].wrapping_add(c2).wrapping_sub(1 << 26);

        // Select h if h < p, or h + -p if h >= p, in constant time.
        let mask = (g[4] >> 31).wrapping_sub(1); // 0xffffffff if g[4] >= 0
        for i in 0..5 {
            self.h[i] = (self.h[i] & !mask) | (g[i] & mask);
        }

        // h = h % 2^128
        let h0 = (self.h[0] | (self.h[1] << 26)) as u64;
        let h1 = ((self.h[1] >> 6) | (self.h[2] << 20)) as u64;
        let h2 = ((self.h[2] >> 12) | (self.h[3] << 14)) as u64;
        let h3 = ((self.h[3] >> 18) | (self.h[4] << 8)) as u64;

        // h += pad
        let mut f = h0 + self.pad[0] as u64;
        let r0 = f as u32;
        f = h1 + self.pad[1] as u64 + (f >> 32);
        let r1 = f as u32;
        f = h2 + self.pad[2] as u64 + (f >> 32);
        let r2 = f as u32;
        f = h3 + self.pad[3] as u64 + (f >> 32);
        let r3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&r0.to_le_bytes());
        tag[4..8].copy_from_slice(&r1.to_le_bytes());
        tag[8..12].copy_from_slice(&r2.to_le_bytes());
        tag[12..16].copy_from_slice(&r3.to_le_bytes());
        tag
    }

    /// One-shot MAC.
    #[must_use]
    pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
        let mut p = Poly1305::new(key);
        p.update(data);
        p.finalize()
    }

    /// Constant-time verify.
    #[must_use]
    pub fn verify(key: &[u8; 32], data: &[u8], tag: &[u8]) -> bool {
        ct::eq(&Poly1305::mac(key, data), tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::{hex, unhex};

    #[test]
    fn rfc8439_section_2_5_2() {
        let key =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let msg = b"Cryptographic Forum Research Group";
        assert_eq!(
            hex(&Poly1305::mac(&k, msg)),
            "a8061dc1305136c6c22b8baf0c0127a9"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let k = [0x2Au8; 32];
        let data: alloc::vec::Vec<u8> = (0u8..=255).cycle().take(300).collect();
        for split in [0usize, 1, 15, 16, 17, 299] {
            let mut p = Poly1305::new(&k);
            p.update(&data[..split]);
            p.update(&data[split..]);
            assert_eq!(p.finalize(), Poly1305::mac(&k, &data), "split {split}");
        }
    }

    #[test]
    fn verify_rejects_tampering() {
        let k = [1u8; 32];
        let mut t = Poly1305::mac(&k, b"hello");
        assert!(Poly1305::verify(&k, b"hello", &t));
        t[15] ^= 0x80;
        assert!(!Poly1305::verify(&k, b"hello", &t));
    }
}
