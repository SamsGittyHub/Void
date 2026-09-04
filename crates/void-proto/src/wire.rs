//! Wire encoding.
//!
//! Void hand-writes its serialization rather than using a derive-based
//! framework. Three reasons, all from the PRD:
//!
//! 1. NFR-SEC-07 makes every dependency in the trusted path expensive, and a
//!    serialization framework is a large one.
//! 2. Parsing untrusted bytes is the most attacker-exposed code in the system.
//!    A reader that is 200 lines of explicit bounds checks is auditable; a
//!    derive macro's expansion is not.
//! 3. `docs/PROTOCOL.md` has to specify the exact byte layout anyway. Writing
//!    it by hand keeps the code and the specification in one-to-one
//!    correspondence.
//!
//! Everything is big-endian and length-prefixed. There are no optional fields
//! encoded by absence — an absent value is an explicit zero-length field — so
//! that two different byte strings can never decode to the same structure.
//! That property matters: the handshake transcript is a hash over encoded
//! values, and encoding ambiguity there would be a signature-substitution bug.

use alloc::vec::Vec;

use crate::ProtoError;

/// Result alias for wire operations.
pub type Result<T> = core::result::Result<T, ProtoError>;

/// Incremental encoder.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// New empty writer.
    #[must_use]
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    /// New writer with reserved capacity.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    /// Append a single byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Append a big-endian `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a big-endian `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a big-endian `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append raw bytes with no length prefix. Only for fixed-size fields.
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Append bytes with a `u16` length prefix.
    ///
    /// # Panics
    /// Panics if `v` exceeds 65,535 bytes. Every call site in Void writes a
    /// value whose maximum length is a protocol constant, so this is a
    /// programming error rather than an input-driven condition.
    pub fn bytes16(&mut self, v: &[u8]) -> &mut Self {
        assert!(
            v.len() <= u16::MAX as usize,
            "wire: field too long for u16 prefix"
        );
        self.u16(v.len() as u16);
        self.buf.extend_from_slice(v);
        self
    }

    /// Append bytes with a `u32` length prefix.
    pub fn bytes32(&mut self, v: &[u8]) -> &mut Self {
        assert!(v.len() <= u32::MAX as usize);
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
        self
    }

    /// Current length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Is the buffer empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow the encoded bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consume and return the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Incremental decoder with explicit bounds checking on every read.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(ProtoError::Malformed);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.raw(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.raw(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.raw(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// Read exactly `n` raw bytes.
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(ProtoError::Malformed);
        }
        let v = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(v)
    }

    /// Read a fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let b = self.raw(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }

    /// Read a `u16`-length-prefixed byte string.
    pub fn bytes16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.raw(n)
    }

    /// Read a `u32`-length-prefixed byte string, refusing anything above
    /// `max` so a hostile length cannot drive an allocation.
    pub fn bytes32_max(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(ProtoError::Malformed);
        }
        self.raw(n)
    }

    /// Require that the input is fully consumed.
    ///
    /// Call this at the end of every top-level decode. Trailing bytes are how
    /// a parser and a hash function end up disagreeing about what was signed.
    pub fn finish(self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(ProtoError::Malformed)
        }
    }
}

/// Length-prefix a sequence of secrets before feeding them to a KDF.
///
/// Without this, `["ab", "c"]` and `["a", "bc"]` hash identically — see the
/// note in `void_crypto::kdf`. Every hybrid combination in Void goes through
/// here.
#[must_use]
pub fn concat_labeled(parts: &[&[u8]]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(parts.len() as u16);
    for p in parts {
        w.bytes32(p);
    }
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_primitives() {
        let mut w = Writer::new();
        w.u8(0xAB)
            .u16(0x1234)
            .u32(0xDEAD_BEEF)
            .u64(0x0102_0304_0506_0708)
            .raw(&[9, 9, 9])
            .bytes16(b"hello")
            .bytes32(b"world");
        let buf = w.finish();

        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 0xAB);
        assert_eq!(r.u16().unwrap(), 0x1234);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(r.raw(3).unwrap(), &[9, 9, 9]);
        assert_eq!(r.bytes16().unwrap(), b"hello");
        assert_eq!(r.bytes32_max(100).unwrap(), b"world");
        assert!(r.finish().is_ok());
    }

    #[test]
    fn truncation_is_always_an_error() {
        let mut w = Writer::new();
        w.u32(7).bytes16(b"abc");
        let buf = w.finish();
        for n in 0..buf.len() {
            let mut r = Reader::new(&buf[..n]);
            let ok = r.u32().is_ok() && r.bytes16().is_ok();
            assert!(!ok, "truncation to {n} bytes must not decode");
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let buf = [0u8; 8];
        let mut r = Reader::new(&buf);
        let _ = r.u32().unwrap();
        assert!(r.finish().is_err());
    }

    #[test]
    fn oversized_length_is_refused_before_allocation() {
        let mut w = Writer::new();
        w.u32(0xFFFF_FFFF);
        let buf = w.finish();
        let mut r = Reader::new(&buf);
        assert!(r.bytes32_max(1024).is_err());
    }

    #[test]
    fn labeled_concat_is_injective() {
        assert_ne!(
            concat_labeled(&[b"ab", b"c"]),
            concat_labeled(&[b"a", b"bc"]),
            "length prefixing must disambiguate the split"
        );
        assert_ne!(concat_labeled(&[b"abc"]), concat_labeled(&[b"abc", b""]));
    }
}
