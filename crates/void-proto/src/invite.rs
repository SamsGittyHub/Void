//! Out-of-band contact establishment (FR-DISC-01, FR-DISC-02).
//!
//! There is no directory, no lookup, and no server that could be asked who
//! knows whom. A contact begins as a [`PrekeyBundle`](crate::handshake::PrekeyBundle)
//! that travelled through a channel Void does not control: a QR code held up in
//! a room, a link sent over another medium, or a fingerprint read aloud.
//!
//! ## Single use and expiry
//!
//! FR-DISC-02 requires invitations to be single-use and to expire (24h by
//! default), and requires that a used or expired link reveal nothing about
//! either party. Two mechanisms:
//!
//! - The link body is **encrypted** under a key carried in the link's own
//!   fragment. Someone who obtains the stored ciphertext without the fragment —
//!   a relay operator, a server log, a phone backup — learns nothing at all.
//! - The bundle inside carries a one-time prekey. Consuming it is what makes
//!   the invitation single-use, and that enforcement lives on the responder's
//!   device, not in the link.
//!
//! The expiry is advisory in the sense that it is checked by the recipient's
//! client; a link that has expired is refused before any secret is derived. An
//! attacker who ignores the check still cannot complete a handshake once the
//! one-time prekey is gone.
//!
//! ## Link format
//!
//! ```text
//!   void://c/<base32(ciphertext)>#<base32(key)>
//! ```
//!
//! The key lives after `#`. In every URL-handling system that matters, the
//! fragment is not sent to a server, is not written to most access logs, and is
//! not included in a `Referer` header. If the link is pasted somewhere it
//! should not have been, the part that leaks is the part that is useless alone.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use void_crypto::{aead, rand, Zeroize};

use crate::handshake::PrekeyBundle;
use crate::wire::{Reader, Writer};
use crate::{ProtoError, Result};

/// Default invitation lifetime: 24 hours (FR-DISC-02).
pub const DEFAULT_INVITE_TTL_SECONDS: u64 = 24 * 60 * 60;

/// URL scheme prefix for invitation links.
pub const LINK_PREFIX: &str = "void://c/";

/// An invitation ready to be rendered as a QR code or a link.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Invite {
    /// The encrypted bundle.
    pub ciphertext: Vec<u8>,
    /// The key that decrypts it. Travels in the URL fragment.
    pub key: [u8; 32],
}

/// The plaintext an invitation carries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InviteBody {
    /// The responder's signed prekey bundle.
    pub bundle: PrekeyBundle,
    /// Unix seconds after which this invitation must be refused.
    pub expires_at: u64,
    /// Optional display label chosen by the inviter, shown before the user
    /// accepts. Never trusted as an identity — that is what the fingerprint is
    /// for — and truncated to bound abuse.
    pub label: String,
}

/// Maximum label length in bytes. A long label in a QR code is a place to hide
/// a phishing message.
pub const MAX_LABEL_LEN: usize = 64;

impl InviteBody {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let label = if self.label.len() > MAX_LABEL_LEN {
            &self.label[..MAX_LABEL_LEN]
        } else {
            &self.label[..]
        };
        w.bytes32(&self.bundle.encode())
            .u64(self.expires_at)
            .bytes16(label.as_bytes());
        w.finish()
    }

    fn decode(bytes: &[u8]) -> Result<InviteBody> {
        let mut r = Reader::new(bytes);
        let bundle = PrekeyBundle::decode(r.bytes32_max(64 * 1024)?)?;
        let expires_at = r.u64()?;
        let label_bytes = r.bytes16()?;
        r.finish()?;
        if label_bytes.len() > MAX_LABEL_LEN {
            return Err(ProtoError::Malformed);
        }
        let label = core::str::from_utf8(label_bytes)
            .map_err(|_| ProtoError::Malformed)?
            .to_string();
        Ok(InviteBody {
            bundle,
            expires_at,
            label,
        })
    }
}

/// Create an invitation.
pub fn create(bundle: &PrekeyBundle, now: u64, ttl_seconds: u64, label: &str) -> Result<Invite> {
    let body = InviteBody {
        bundle: bundle.clone(),
        expires_at: now.saturating_add(ttl_seconds),
        label: label.to_string(),
    };
    let plaintext = body.encode();
    let key = rand::bytes32().map_err(|_| ProtoError::Crypto)?;
    let nonce = rand::bytes24().map_err(|_| ProtoError::Crypto)?;

    let mut ciphertext = Vec::with_capacity(aead::XNONCE_LEN + plaintext.len() + aead::TAG_LEN);
    ciphertext.extend_from_slice(&nonce);
    ciphertext.extend_from_slice(&aead::xseal(
        &key,
        &nonce,
        LINK_PREFIX.as_bytes(),
        &plaintext,
    ));

    Ok(Invite { ciphertext, key })
}

/// Open an invitation and validate it.
///
/// Checks, in order: decryption, decoding, the bundle's own signature, and
/// expiry. Nothing is returned to the caller unless all four pass, so a caller
/// cannot accidentally act on a bundle whose signature failed.
pub fn open(invite: &Invite, now: u64) -> Result<InviteBody> {
    if invite.ciphertext.len() < aead::XNONCE_LEN + aead::TAG_LEN {
        return Err(ProtoError::Malformed);
    }
    let mut nonce = [0u8; aead::XNONCE_LEN];
    nonce.copy_from_slice(&invite.ciphertext[..aead::XNONCE_LEN]);
    let plaintext = aead::xopen(
        &invite.key,
        &nonce,
        LINK_PREFIX.as_bytes(),
        &invite.ciphertext[aead::XNONCE_LEN..],
    )
    .map_err(|_| ProtoError::DecryptionFailed)?;

    let body = InviteBody::decode(&plaintext)?;
    if !body.bundle.verify() {
        return Err(ProtoError::BadSignature);
    }
    if now > body.expires_at {
        return Err(ProtoError::Expired);
    }
    Ok(body)
}

// --- Base32 (RFC 4648, no padding, uppercase) --------------------------------
//
// Base32 rather than base64 because invitation links get read aloud, typed on
// phone keyboards, and rendered as QR codes. Base32's alphabet has no
// case-sensitivity trap and no characters that URL-encode.

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode bytes as unpadded RFC 4648 base32.
#[must_use]
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

/// Decode unpadded RFC 4648 base32. Case-insensitive.
#[must_use]
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let u = c.to_ascii_uppercase() as u8;
        let v = B32.iter().position(|&x| x == u)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

impl Invite {
    /// Render as a `void://` link with the key in the fragment.
    #[must_use]
    pub fn to_link(&self) -> String {
        alloc::format!(
            "{}{}#{}",
            LINK_PREFIX,
            base32_encode(&self.ciphertext),
            base32_encode(&self.key)
        )
    }

    /// Parse a `void://` link.
    pub fn from_link(link: &str) -> Result<Invite> {
        let trimmed = link.trim();
        let rest = trimmed
            .strip_prefix(LINK_PREFIX)
            .ok_or(ProtoError::Malformed)?;
        let (ct_part, key_part) = rest.split_once('#').ok_or(ProtoError::Malformed)?;
        let ciphertext = base32_decode(ct_part).ok_or(ProtoError::Malformed)?;
        let key_bytes = base32_decode(key_part).ok_or(ProtoError::Malformed)?;
        if key_bytes.len() != 32 {
            return Err(ProtoError::Malformed);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(Invite { ciphertext, key })
    }

    /// The QR payload. Identical to the link — a QR code that encodes something
    /// different from what the link encodes is a second format to get wrong.
    #[must_use]
    pub fn to_qr_payload(&self) -> String {
        self.to_link()
    }
}

impl Drop for Invite {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn bundle() -> PrekeyBundle {
        let id = Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let queue = crate::queue::QueueSecret::from_parts([4u8; 32], 0);
        PrekeyBundle::create(&id, &queue, b"relay.onion", true)
            .unwrap()
            .0
    }

    #[test]
    fn create_and_open_roundtrip() {
        let b = bundle();
        let inv = create(&b, 1000, DEFAULT_INVITE_TTL_SECONDS, "Alice").unwrap();
        let body = open(&inv, 1001).unwrap();
        assert_eq!(body.bundle, b);
        assert_eq!(body.label, "Alice");
        assert_eq!(body.expires_at, 1000 + DEFAULT_INVITE_TTL_SECONDS);
    }

    #[test]
    fn expired_invitations_are_refused() {
        let inv = create(&bundle(), 1000, 60, "x").unwrap();
        assert!(open(&inv, 1050).is_ok());
        assert!(matches!(open(&inv, 1061), Err(ProtoError::Expired)));
    }

    #[test]
    fn ciphertext_alone_reveals_nothing() {
        // FR-DISC-02: a used or expired link reveals nothing about either
        // party. Without the fragment key the stored ciphertext is opaque.
        let b = bundle();
        let inv = create(&b, 0, 60, "Alice").unwrap();
        let wrong = Invite {
            ciphertext: inv.ciphertext.clone(),
            key: [0u8; 32],
        };
        assert!(matches!(open(&wrong, 1), Err(ProtoError::DecryptionFailed)));

        // And the ciphertext does not contain the identity key in the clear.
        let idbytes = b.identity.encode();
        assert!(
            !inv.ciphertext
                .windows(idbytes.len())
                .any(|w| w == idbytes.as_slice()),
            "identity must not appear in the ciphertext"
        );
    }

    #[test]
    fn link_roundtrips() {
        let inv = create(&bundle(), 0, 3600, "Bob").unwrap();
        let link = inv.to_link();
        assert!(link.starts_with(LINK_PREFIX));
        assert!(link.contains('#'));
        let parsed = Invite::from_link(&link).unwrap();
        assert_eq!(parsed.ciphertext, inv.ciphertext);
        assert_eq!(parsed.key, inv.key);
        assert_eq!(open(&parsed, 1).unwrap().label, "Bob");
    }

    #[test]
    fn link_key_lives_in_the_fragment() {
        let inv = create(&bundle(), 0, 3600, "x").unwrap();
        let link = inv.to_link();
        let (before, after) = link.split_once('#').unwrap();
        assert_eq!(base32_decode(after).unwrap(), inv.key.to_vec());
        // The part a server would see must not decrypt anything.
        assert!(!before.contains(&base32_encode(&inv.key)));
    }

    #[test]
    fn malformed_links_are_rejected() {
        assert!(Invite::from_link("https://example.com").is_err());
        assert!(Invite::from_link("void://c/ABC").is_err()); // no fragment
        assert!(Invite::from_link("void://c/ABC#AB").is_err()); // short key
        assert!(Invite::from_link("void://c/!!!#AAAA").is_err()); // bad base32
    }

    #[test]
    fn base32_roundtrips_at_every_residue() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let enc = base32_encode(&data);
            assert_eq!(base32_decode(&enc).unwrap(), data, "len {len}");
            // Case-insensitive and whitespace-tolerant.
            assert_eq!(base32_decode(&enc.to_lowercase()).unwrap(), data);
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let inv = create(&bundle(), 0, 3600, "x").unwrap();
        for i in [0usize, 23, 24, inv.ciphertext.len() - 1] {
            let mut bad = Invite {
                ciphertext: inv.ciphertext.clone(),
                key: inv.key,
            };
            bad.ciphertext[i] ^= 1;
            assert!(open(&bad, 1).is_err(), "tamper at {i}");
        }
    }

    #[test]
    fn oversized_label_is_truncated_not_rejected() {
        let long = "x".repeat(500);
        let inv = create(&bundle(), 0, 3600, &long).unwrap();
        let body = open(&inv, 1).unwrap();
        assert_eq!(body.label.len(), MAX_LABEL_LEN);
    }
}

