//! ChaCha20 and HChaCha20 (RFC 8439, and the XChaCha draft for HChaCha20).

/// ChaCha20 quarter round.
#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn rounds(s: &mut [u32; 16]) {
    for _ in 0..10 {
        qr(s, 0, 4, 8, 12);
        qr(s, 1, 5, 9, 13);
        qr(s, 2, 6, 10, 14);
        qr(s, 3, 7, 11, 15);
        qr(s, 0, 5, 10, 15);
        qr(s, 1, 6, 11, 12);
        qr(s, 2, 7, 8, 13);
        qr(s, 3, 4, 9, 14);
    }
}

fn init_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }
    s
}

/// The ChaCha20 block function: produces 64 bytes of keystream.
#[must_use]
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let initial = init_state(key, counter, nonce);
    let mut s = initial;
    rounds(&mut s);
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = s[i].wrapping_add(initial[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// XOR `data` in place with the ChaCha20 keystream starting at `counter`.
///
/// # Panics
/// Panics if the data would overflow the 32-bit block counter (256 GiB under
/// one nonce). Void's fixed record size makes this unreachable, but a panic is
/// the right response to a keystream-reuse condition.
pub fn apply_keystream(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let blocks_needed = data.len().div_ceil(64) as u64;
    assert!(
        (counter as u64) + blocks_needed <= u64::from(u32::MAX) + 1,
        "chacha20: block counter would overflow; keystream reuse refused"
    );
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let ks = block(key, ctr, nonce);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
        ctr = ctr.wrapping_add(1);
    }
}

/// HChaCha20: the key-derivation half of XChaCha20.
#[must_use]
pub fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in 0..4 {
        s[12 + i] = u32::from_le_bytes([
            nonce16[4 * i],
            nonce16[4 * i + 1],
            nonce16[4 * i + 2],
            nonce16[4 * i + 3],
        ]);
    }
    rounds(&mut s);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].to_le_bytes());
    }
    for i in 0..4 {
        out[16 + 4 * i..16 + 4 * i + 4].copy_from_slice(&s[12 + i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::{hex, unhex};

    #[test]
    fn rfc8439_block_function_vector() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let out = block(&key, 1, &nonce);
        assert_eq!(
            hex(&out[..32]),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        );
    }

    #[test]
    fn rfc8439_encryption_vector() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let plaintext =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut buf = plaintext.to_vec();
        apply_keystream(&key, 1, &nonce, &mut buf);
        assert_eq!(hex(&buf[..16]), "6e2e359a2568f98041ba0728dd0d6981");
        // Round-trip
        apply_keystream(&key, 1, &nonce, &mut buf);
        assert_eq!(&buf[..], &plaintext[..]);
    }

    #[test]
    fn hchacha20_reference_vector() {
        let key =
            unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let nonce = unhex("000000090000004a0000000031415927").unwrap();
        let mut n = [0u8; 16];
        n.copy_from_slice(&nonce);
        assert_eq!(
            hex(&hchacha20(&k, &n)),
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
        );
    }

    #[test]
    fn keystream_is_chunk_size_independent() {
        let key = [5u8; 32];
        let nonce = [7u8; 12];
        let mut a = alloc::vec![0u8; 200];
        let mut b = a.clone();
        apply_keystream(&key, 0, &nonce, &mut a);
        // Same keystream applied in two passes over disjoint block-aligned ranges.
        apply_keystream(&key, 0, &nonce, &mut b[..128]);
        apply_keystream(&key, 2, &nonce, &mut b[128..]);
        assert_eq!(a, b);
    }
}
