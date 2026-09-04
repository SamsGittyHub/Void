//! BLAKE3, including keyed hashing and `derive_key`.
//!
//! NFR-SEC-01 selects BLAKE3 for general-purpose and keyed hashing. Void uses
//! it for:
//!
//! - the transcript hash in the PQXDH-style handshake (`void-proto::handshake`),
//! - fingerprint derivation for FR-ID-03,
//! - the record-key stream in `void-proto::record`,
//! - domain-separated subkey derivation via `derive_key`, which gives us
//!   labelled key separation without inventing a KDF.
//!
//! HKDF-SHA-256 is kept alongside it for the ratchet chains, because that is
//! the construction the Double Ratchet specification and every reviewer of it
//! expect to see (NFR-SEC-01: no novel cryptography includes not making
//! gratuitous substitutions in a well-analysed protocol).

use alloc::vec::Vec;

const OUT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    *m = permuted;
}

fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;
    for r in 0..7 {
        round(&mut state, &block);
        if r < 6 {
            permute(&mut block);
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn words_from_le_bytes(bytes: &[u8; 64]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for i in 0..16 {
        out[i] = u32::from_le_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
    }
    out
}

#[derive(Clone, Copy)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let full = compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&full[..8]);
        cv
    }

    fn root_output_bytes(&self, out: &mut [u8]) {
        // The counter is the XOF output-block index, which the BLAKE3
        // specification defines as the enumeration position of the block.
        for (counter, chunk) in out.chunks_mut(2 * OUT_LEN).enumerate() {
            let words = compress(
                &self.input_chaining_value,
                &self.block_words,
                counter as u64,
                self.block_len,
                self.flags | ROOT,
            );
            for (word, dest) in words.iter().zip(chunk.chunks_mut(4)) {
                dest.copy_from_slice(&word.to_le_bytes()[..dest.len()]);
            }
        }
    }
}

#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        ChunkState {
            chaining_value: key_words,
            chunk_counter,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * (self.blocks_compressed as usize) + (self.block_len as usize)
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let block_words = words_from_le_bytes(&self.block);
                let full = compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                );
                self.chaining_value.copy_from_slice(&full[..8]);
                self.blocks_compressed += 1;
                self.block = [0u8; BLOCK_LEN];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - self.block_len as usize;
            let take = core::cmp::min(want, input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_chaining_value: self.chaining_value,
            block_words: words_from_le_bytes(&self.block),
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(left: [u32; 8], right: [u32; 8], key_words: [u32; 8], flags: u32) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left);
    block_words[8..].copy_from_slice(&right);
    Output {
        input_chaining_value: key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

/// Streaming BLAKE3 hasher.
#[derive(Clone)]
pub struct Hasher {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: u8,
    flags: u32,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Hasher {
            chunk_state: ChunkState::new(key_words, 0, flags),
            key_words,
            cv_stack: [[0u32; 8]; 54],
            cv_stack_len: 0,
            flags,
        }
    }

    /// Unkeyed BLAKE3.
    #[must_use]
    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    /// Keyed BLAKE3 with a 32-byte key. This is a PRF; use it wherever a MAC
    /// over non-secret-length data is needed.
    #[must_use]
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] =
                u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        Self::new_internal(key_words, KEYED_HASH)
    }

    /// BLAKE3 `derive_key` mode. `context` must be a hardcoded, globally
    /// unique, application-specific string — never attacker-influenced.
    #[must_use]
    pub fn new_derive_key(context: &str) -> Self {
        let mut context_hasher = Self::new_internal(IV, DERIVE_KEY_CONTEXT);
        context_hasher.update(context.as_bytes());
        let mut context_key = [0u8; KEY_LEN];
        context_hasher.finalize_xof(&mut context_key);
        let mut context_key_words = [0u32; 8];
        for i in 0..8 {
            context_key_words[i] = u32::from_le_bytes([
                context_key[4 * i],
                context_key[4 * i + 1],
                context_key[4 * i + 2],
                context_key[4 * i + 3],
            ]);
        }
        Self::new_internal(context_key_words, DERIVE_KEY_MATERIAL)
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            new_cv = parent_output(self.pop_stack(), new_cv, self.key_words, self.flags)
                .chaining_value();
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    /// Absorb input.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(self.key_words, total_chunks, self.flags);
            }
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = core::cmp::min(want, input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Write output of any length (XOF mode).
    pub fn finalize_xof(&self, out: &mut [u8]) {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len as usize;
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            );
        }
        output.root_output_bytes(out);
    }

    /// Standard 32-byte output.
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.finalize_xof(&mut out);
        out
    }
}

/// One-shot unkeyed BLAKE3.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

/// One-shot unkeyed BLAKE3 over several parts.
#[must_use]
pub fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// One-shot keyed BLAKE3 (a PRF / MAC).
#[must_use]
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(key);
    h.update(data);
    h.finalize()
}

/// One-shot keyed BLAKE3 over several parts.
#[must_use]
pub fn keyed_hash_parts(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(key);
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// BLAKE3 `derive_key`: domain-separated subkey derivation.
#[must_use]
pub fn derive_key(context: &str, key_material: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Hasher::new_derive_key(context);
    h.update(key_material);
    let mut out = alloc::vec![0u8; out_len];
    h.finalize_xof(&mut out);
    out
}

/// BLAKE3 `derive_key` producing exactly 32 bytes.
#[must_use]
pub fn derive_key_32(context: &str, key_material: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_derive_key(context);
    h.update(key_material);
    h.finalize()
}

/// BLAKE3 XOF over arbitrary data.
#[must_use]
pub fn hash_xof(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Hasher::new();
    h.update(data);
    let mut out = alloc::vec![0u8; out_len];
    h.finalize_xof(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::hex;

    #[test]
    fn published_vectors_empty_and_short() {
        assert_eq!(
            hex(&hash(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hex(&hash(b"abc")),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        assert_eq!(
            hex(&hash(b"IETF")),
            "83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2"
        );
    }

    #[test]
    fn multi_chunk_input() {
        // Exercises the chunk tree: > 1 KiB forces parent nodes.
        let data: Vec<u8> = (0..251u32).map(|i| i as u8).cycle().take(3072).collect();
        let one = hash(&data);
        let mut h = Hasher::new();
        for c in data.chunks(97) {
            h.update(c);
        }
        assert_eq!(h.finalize(), one, "streaming must match one-shot");
    }

    #[test]
    fn xof_is_prefix_consistent() {
        let long = hash_xof(b"void", 131);
        assert_eq!(&long[..32], &hash(b"void")[..]);
    }

    #[test]
    fn keyed_and_derive_are_domain_separated() {
        let key = [7u8; 32];
        let a = keyed_hash(&key, b"m");
        let b = hash(b"m");
        assert_ne!(a, b);
        let d1 = derive_key("void 2026 test one", b"m", 32);
        let d2 = derive_key("void 2026 test two", b"m", 32);
        assert_ne!(d1, d2, "different contexts must give different keys");
    }

    #[test]
    fn exact_chunk_boundary() {
        for n in [1023usize, 1024, 1025, 2048, 2049] {
            let data = alloc::vec![0xABu8; n];
            let mut h = Hasher::new();
            h.update(&data[..n / 2]);
            h.update(&data[n / 2..]);
            assert_eq!(h.finalize(), hash(&data), "n = {n}");
        }
    }
}
