//! Argon2id (RFC 9106).
//!
//! Two call sites, both from FR-STOR-01 and FR-REC-02:
//!
//! 1. Deriving the database encryption key from a user passphrase.
//! 2. Deriving the encrypted-export key from an export passphrase.
//!
//! The default parameters below follow RFC 9106's first recommended option
//! scaled for a phone: 64 MiB, 3 passes, 4 lanes. On a 2022-era device this is
//! roughly 100-200 ms, which is a tolerable unlock delay and a painful
//! per-guess cost for an offline attacker holding a seized device.

use alloc::vec;
use alloc::vec::Vec;

use crate::blake2b::Blake2b;
use crate::{CryptoError, Result};

const BLOCK_SIZE: usize = 1024;
const SYNC_POINTS: u32 = 4;
const ARGON2_ID: u32 = 2;
const VERSION: u32 = 0x13;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Memory cost in kibibytes.
    pub m_cost: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub lanes: u32,
    /// Output length in bytes.
    pub out_len: usize,
}

impl Params {
    /// Void's production defaults: 64 MiB, 3 passes, 4 lanes, 32-byte output.
    ///
    /// These are recorded in the storage header so that a future increase does
    /// not lock users out of an existing database.
    pub const DEFAULT: Params = Params {
        m_cost: 65536,
        t_cost: 3,
        lanes: 4,
        out_len: 32,
    };

    /// Higher-cost profile for the encrypted export (FR-REC-02), where the
    /// archive may sit in cloud storage indefinitely and the one-off delay is
    /// acceptable: 256 MiB, 4 passes.
    pub const EXPORT: Params = Params {
        m_cost: 262_144,
        t_cost: 4,
        lanes: 4,
        out_len: 32,
    };

    /// Deliberately weak parameters, for tests only.
    pub const TEST_ONLY_WEAK: Params = Params {
        m_cost: 64,
        t_cost: 1,
        lanes: 1,
        out_len: 32,
    };
}

type Block = [u64; 128];

fn blake2b_long(out: &mut [u8], input: &[&[u8]]) {
    let out_len = out.len();
    if out_len <= 64 {
        let mut h = Blake2b::new(out_len);
        h.update(&(out_len as u32).to_le_bytes());
        for p in input {
            h.update(p);
        }
        h.finalize_into(out);
        return;
    }
    let mut buf = [0u8; 64];
    let mut h = Blake2b::new(64);
    h.update(&(out_len as u32).to_le_bytes());
    for p in input {
        h.update(p);
    }
    h.finalize_into(&mut buf);
    out[..32].copy_from_slice(&buf[..32]);
    let mut produced = 32;
    while out_len - produced > 64 {
        let mut h = Blake2b::new(64);
        h.update(&buf);
        h.finalize_into(&mut buf);
        out[produced..produced + 32].copy_from_slice(&buf[..32]);
        produced += 32;
    }
    let remaining = out_len - produced;
    let mut h = Blake2b::new(remaining);
    h.update(&buf);
    h.finalize_into(&mut out[produced..]);
}

#[inline(always)]
fn fbla_mka(x: u64, y: u64) -> u64 {
    x.wrapping_add(y)
        .wrapping_add(2u64.wrapping_mul((x & 0xFFFF_FFFF).wrapping_mul(y & 0xFFFF_FFFF)))
}

#[inline(always)]
fn g_arg(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = fbla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = fbla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = fbla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = fbla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn permute(v: &mut [u64; 16]) {
    g_arg(v, 0, 4, 8, 12);
    g_arg(v, 1, 5, 9, 13);
    g_arg(v, 2, 6, 10, 14);
    g_arg(v, 3, 7, 11, 15);
    g_arg(v, 0, 5, 10, 15);
    g_arg(v, 1, 6, 11, 12);
    g_arg(v, 2, 7, 8, 13);
    g_arg(v, 3, 4, 9, 14);
}

fn compress_block(dst: &mut Block, prev: &Block, refb: &Block, with_xor: bool) {
    let mut r = [0u64; 128];
    for i in 0..128 {
        r[i] = prev[i] ^ refb[i];
    }
    let mut q = r;

    // Row rounds
    for i in 0..8 {
        let mut v = [0u64; 16];
        v.copy_from_slice(&q[16 * i..16 * i + 16]);
        permute(&mut v);
        q[16 * i..16 * i + 16].copy_from_slice(&v);
    }
    // Column rounds
    for i in 0..8 {
        let idx = [
            2 * i,
            2 * i + 1,
            2 * i + 16,
            2 * i + 17,
            2 * i + 32,
            2 * i + 33,
            2 * i + 48,
            2 * i + 49,
            2 * i + 64,
            2 * i + 65,
            2 * i + 80,
            2 * i + 81,
            2 * i + 96,
            2 * i + 97,
            2 * i + 112,
            2 * i + 113,
        ];
        let mut v = [0u64; 16];
        for (k, &j) in idx.iter().enumerate() {
            v[k] = q[j];
        }
        permute(&mut v);
        for (k, &j) in idx.iter().enumerate() {
            q[j] = v[k];
        }
    }

    for i in 0..128 {
        let val = q[i] ^ r[i];
        if with_xor {
            dst[i] ^= val;
        } else {
            dst[i] = val;
        }
    }
}

fn block_to_bytes(b: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLOCK_SIZE);
    for w in b.iter() {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn bytes_to_block(bytes: &[u8]) -> Block {
    let mut b = [0u64; 128];
    for i in 0..128 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        b[i] = u64::from_le_bytes(w);
    }
    b
}

/// Derive a key with Argon2id.
///
/// Returns `BadLength` for parameters outside RFC 9106's allowed ranges rather
/// than silently clamping them.
pub fn hash(
    password: &[u8],
    salt: &[u8],
    params: Params,
    secret: &[u8],
    associated: &[u8],
) -> Result<Vec<u8>> {
    if params.lanes == 0 || params.t_cost == 0 || salt.len() < 8 || params.out_len < 4 {
        return Err(CryptoError::BadLength);
    }
    let lanes = params.lanes;
    let min_memory = 8 * lanes;
    let m_cost = core::cmp::max(params.m_cost, min_memory);
    let memory_blocks = (m_cost / (SYNC_POINTS * lanes)) * (SYNC_POINTS * lanes);
    let lane_length = memory_blocks / lanes;
    let segment_length = lane_length / SYNC_POINTS;

    // H_0
    let mut h0 = [0u8; 64];
    {
        let mut h = Blake2b::new(64);
        h.update(&lanes.to_le_bytes());
        h.update(&(params.out_len as u32).to_le_bytes());
        h.update(&m_cost.to_le_bytes());
        h.update(&params.t_cost.to_le_bytes());
        h.update(&VERSION.to_le_bytes());
        h.update(&ARGON2_ID.to_le_bytes());
        h.update(&(password.len() as u32).to_le_bytes());
        h.update(password);
        h.update(&(salt.len() as u32).to_le_bytes());
        h.update(salt);
        h.update(&(secret.len() as u32).to_le_bytes());
        h.update(secret);
        h.update(&(associated.len() as u32).to_le_bytes());
        h.update(associated);
        h.finalize_into(&mut h0);
    }

    let mut memory: Vec<Block> = vec![[0u64; 128]; memory_blocks as usize];

    // First two blocks of each lane.
    for lane in 0..lanes {
        for idx in 0..2u32 {
            let mut buf = vec![0u8; BLOCK_SIZE];
            blake2b_long(&mut buf, &[&h0, &idx.to_le_bytes(), &lane.to_le_bytes()]);
            memory[(lane * lane_length + idx) as usize] = bytes_to_block(&buf);
        }
    }

    for pass in 0..params.t_cost {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                // Argon2id: first pass, first two slices use data-independent
                // addressing; everything else is data-dependent.
                let data_independent = pass == 0 && slice < 2;
                let mut address_block: Block = [0u64; 128];
                let mut input_block: Block = [0u64; 128];
                let mut zero_block: Block = [0u64; 128];
                if data_independent {
                    input_block[0] = pass as u64;
                    input_block[1] = lane as u64;
                    input_block[2] = slice as u64;
                    input_block[3] = memory_blocks as u64;
                    input_block[4] = params.t_cost as u64;
                    input_block[5] = ARGON2_ID as u64;
                }

                let start = if pass == 0 && slice == 0 { 2 } else { 0 };
                for index in start..segment_length {
                    let cur_offset = lane * lane_length + slice * segment_length + index;
                    let prev_offset = if cur_offset % lane_length == 0 {
                        cur_offset + lane_length - 1
                    } else {
                        cur_offset - 1
                    };

                    let (pseudo_rand_lo, pseudo_rand_hi) = if data_independent {
                        let i_in_seg = index % 128;
                        if i_in_seg == 0 {
                            input_block[6] += 1;
                            let ib = input_block;
                            compress_block(&mut address_block, &zero_block, &ib, false);
                            let ab = address_block;
                            compress_block(&mut address_block, &zero_block, &ab, false);
                            zero_block = [0u64; 128];
                        }
                        let w = address_block[i_in_seg as usize];
                        ((w & 0xFFFF_FFFF) as u32, (w >> 32) as u32)
                    } else {
                        let w = memory[prev_offset as usize][0];
                        ((w & 0xFFFF_FFFF) as u32, (w >> 32) as u32)
                    };

                    let ref_lane = if pass == 0 && slice == 0 {
                        lane
                    } else {
                        pseudo_rand_hi % lanes
                    };

                    let ref_index = index_alpha(
                        pass,
                        slice,
                        index,
                        pseudo_rand_lo,
                        ref_lane == lane,
                        lane_length,
                        segment_length,
                    );

                    let ref_offset = ref_lane * lane_length + ref_index;
                    let prev = memory[prev_offset as usize];
                    let refb = memory[ref_offset as usize];
                    let mut cur = memory[cur_offset as usize];
                    compress_block(&mut cur, &prev, &refb, pass > 0);
                    memory[cur_offset as usize] = cur;
                }
            }
        }
    }

    // XOR the last block of every lane.
    let mut final_block = memory[(lane_length - 1) as usize];
    for lane in 1..lanes {
        let b = memory[(lane * lane_length + lane_length - 1) as usize];
        for i in 0..128 {
            final_block[i] ^= b[i];
        }
    }

    let mut out = vec![0u8; params.out_len];
    blake2b_long(&mut out, &[&block_to_bytes(&final_block)]);

    // Wipe the memory array: it is full of password-derived material.
    for b in memory.iter_mut() {
        for w in b.iter_mut() {
            *w = 0;
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn index_alpha(
    pass: u32,
    slice: u32,
    index: u32,
    pseudo_rand: u32,
    same_lane: bool,
    lane_length: u32,
    segment_length: u32,
) -> u32 {
    let reference_area_size: u32 = if pass == 0 {
        if slice == 0 {
            index - 1
        } else if same_lane {
            slice * segment_length + index - 1
        } else {
            slice * segment_length - if index == 0 { 1 } else { 0 }
        }
    } else if same_lane {
        lane_length - segment_length + index - 1
    } else {
        lane_length - segment_length - if index == 0 { 1 } else { 0 }
    };

    let mut relative_position = pseudo_rand as u64;
    relative_position = (relative_position * relative_position) >> 32;
    relative_position = (reference_area_size as u64)
        - 1
        - (((reference_area_size as u64) * relative_position) >> 32);

    let start_position: u32 = if pass != 0 && slice != SYNC_POINTS - 1 {
        (slice + 1) * segment_length
    } else {
        0
    };

    (((start_position as u64) + relative_position) % (lane_length as u64)) as u32
}

/// Convenience: derive a 32-byte key with Void's default parameters.
pub fn derive_key32(password: &[u8], salt: &[u8], params: Params) -> Result<[u8; 32]> {
    let v = hash(password, salt, params, &[], &[])?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::hex;

    #[test]
    fn rfc9106_argon2id_test_vector() {
        // RFC 9106 §5.3: Argon2id, t=3, m=32, p=4, 32-byte tag.
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let associated = [0x04u8; 12];
        let params = Params {
            m_cost: 32,
            t_cost: 3,
            lanes: 4,
            out_len: 32,
        };
        let out = hash(&password, &salt, params, &secret, &associated).unwrap();
        assert_eq!(
            hex(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn distinct_inputs_give_distinct_keys() {
        let p = Params::TEST_ONLY_WEAK;
        let a = derive_key32(b"password", b"saltsaltsalt", p).unwrap();
        let b = derive_key32(b"passwore", b"saltsaltsalt", p).unwrap();
        let c = derive_key32(b"password", b"saltsaltsalu", p).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        // Deterministic for the same inputs.
        assert_eq!(a, derive_key32(b"password", b"saltsaltsalt", p).unwrap());
    }

    #[test]
    fn parameters_are_validated() {
        let p = Params {
            m_cost: 64,
            t_cost: 0,
            lanes: 1,
            out_len: 32,
        };
        assert!(hash(b"pw", b"saltsalt", p, &[], &[]).is_err());
        assert!(hash(b"pw", b"short", Params::TEST_ONLY_WEAK, &[], &[]).is_err());
    }

    #[test]
    fn cost_parameters_change_the_output() {
        let a = derive_key32(b"pw", b"saltsaltsalt", Params::TEST_ONLY_WEAK).unwrap();
        let b = derive_key32(
            b"pw",
            b"saltsaltsalt",
            Params {
                t_cost: 2,
                ..Params::TEST_ONLY_WEAK
            },
        )
        .unwrap();
        assert_ne!(a, b);
    }
}
