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
//!
//! That link is about 14,600 characters, because it carries the whole signed
//! bundle. [`ShortInvite`] is the form the apps hand out: about 130 characters
//! and one QR code, with the same encrypted body parked on the relay instead.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use void_crypto::{aead, kdf, rand, Zeroize};

use crate::handshake::PrekeyBundle;
use crate::queue::QueueSecret;
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

/// The longest prefix of `label` that fits [`MAX_LABEL_LEN`] bytes and ends on
/// a character boundary.
///
/// Slicing at byte 64 unconditionally panicked whenever that byte fell inside
/// a multi-byte character — a name in most of the world's scripts — and the
/// app libraries used to abort on panic, so creating an invitation with such a
/// name crashed the app.
#[must_use]
pub fn truncate_label(label: &str) -> &str {
    if label.len() <= MAX_LABEL_LEN {
        return label;
    }
    let mut end = MAX_LABEL_LEN;
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    &label[..end]
}

impl InviteBody {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let label = truncate_label(&self.label);
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

/// Create an invitation under a fresh random key.
pub fn create(bundle: &PrekeyBundle, now: u64, ttl_seconds: u64, label: &str) -> Result<Invite> {
    let key = rand::bytes32().map_err(|_| ProtoError::Crypto)?;
    create_with_key(bundle, now, ttl_seconds, label, key)
}

/// Create an invitation encrypted under `key` — for a short invitation, the
/// key its link's secret derives ([`ShortInvite::link_key`]).
pub fn create_with_key(
    bundle: &PrekeyBundle,
    now: u64,
    ttl_seconds: u64,
    label: &str,
    key: [u8; 32],
) -> Result<Invite> {
    let body = InviteBody {
        bundle: bundle.clone(),
        expires_at: now.saturating_add(ttl_seconds),
        label: label.to_string(),
    };
    let plaintext = body.encode();
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

// --- Short invitations ---------------------------------------------------------

/// URL scheme prefix for short invitation links.
pub const SHORT_LINK_PREFIX: &str = "void://i/";

/// Longest relay address a short link carries.
pub const MAX_RELAY_LEN: usize = 255;

/// A short invitation: where the full invitation is parked, and the one secret
/// that finds it and opens it.
///
/// ## Why this exists
///
/// A full invitation carries the whole signed prekey bundle — an ML-DSA-87
/// identity key and signature and an ML-KEM-1024 prekey, about 9 KB — so its
/// link is about 14,600 characters and it takes thirteen QR codes to show. A
/// short invitation carries a 32-byte secret instead. From it both sides
/// derive the key the full invitation is encrypted under
/// ([`kdf::LABEL_INVITE`]) and a queue on the relay
/// ([`kdf::LABEL_INVITE_DROP`]). The inviter parks the encrypted invitation in
/// that queue; whoever opens the link collects it and opens it exactly as they
/// would a full one. The link is about 130 characters: one small QR code, and
/// short enough to paste anywhere.
///
/// ```text
///   void://i/<relay>#<base32(secret)>
/// ```
///
/// ## What the relay learns
///
/// Nothing it can read. It holds the same ciphertext a full link carries, and
/// the key comes from the part of the link after `#`, which never reaches a
/// server. Anyone holding the link can collect that ciphertext, and the relay
/// deletes it as it hands it over, so a short invitation is fetched once —
/// which is no new exposure, since anyone holding a full link could already
/// use it. What the relay does see is a queue receiving about ten records and
/// later being emptied: the same shape an intro queue already has.
pub struct ShortInvite {
    /// The relay the invitation is parked on, as the inviter's app addresses it.
    pub relay: String,
    /// The link's secret. Travels in the URL fragment.
    pub secret: [u8; 32],
}

impl Drop for ShortInvite {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl core::fmt::Debug for ShortInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShortInvite")
            .field("relay", &self.relay)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Whether `relay` is an address a short link may carry: lowercase letters,
/// digits, `.`, `:`, and `-` — enough for an onion address and a port, and
/// nothing that changes how the link parses.
fn valid_relay(relay: &str) -> bool {
    !relay.is_empty()
        && relay.len() <= MAX_RELAY_LEN
        && relay.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b':' | b'-')
        })
}

impl ShortInvite {
    /// A fresh short invitation parked on `relay`.
    pub fn generate(relay: &str) -> Result<ShortInvite> {
        if !valid_relay(relay) {
            return Err(ProtoError::Malformed);
        }
        Ok(ShortInvite {
            relay: relay.to_string(),
            secret: rand::bytes32().map_err(|_| ProtoError::Crypto)?,
        })
    }

    /// The key the full invitation is encrypted under.
    #[must_use]
    pub fn link_key(&self) -> [u8; 32] {
        kdf::derive32(&self.secret, &[], kdf::LABEL_INVITE)
    }

    /// The relay queue the full invitation is parked in.
    ///
    /// Both sides derive it; neither sends it. The inviter deposits into it and
    /// whoever holds the link collects from it — the retrieval key derives from
    /// the same secret, so holding the link is what authorises collecting.
    #[must_use]
    pub fn drop_queue(&self) -> QueueSecret {
        QueueSecret::from_parts(kdf::derive32(&self.secret, &[], kdf::LABEL_INVITE_DROP), 0)
    }

    /// Open the full invitation this link parked, once collected.
    ///
    /// Checks exactly what [`open`] checks — decryption, decoding, the bundle's
    /// signature, and expiry — because it is [`open`].
    pub fn open_parked(&self, ciphertext: &[u8], now: u64) -> Result<InviteBody> {
        let invite = Invite {
            ciphertext: ciphertext.to_vec(),
            key: self.link_key(),
        };
        open(&invite, now)
    }

    /// Render as a link, secret in the fragment.
    #[must_use]
    pub fn to_link(&self) -> String {
        alloc::format!(
            "{}{}#{}",
            SHORT_LINK_PREFIX,
            self.relay,
            base32_encode(&self.secret)
        )
    }

    /// Parse a short link. The relay part is case-folded, since a QR reader or
    /// a keyboard may have uppercased it.
    pub fn from_link(link: &str) -> Result<ShortInvite> {
        let rest = link
            .trim()
            .strip_prefix(SHORT_LINK_PREFIX)
            .ok_or(ProtoError::Malformed)?;
        let (relay, secret_part) = rest.split_once('#').ok_or(ProtoError::Malformed)?;
        let relay = relay.to_ascii_lowercase();
        if !valid_relay(&relay) {
            return Err(ProtoError::Malformed);
        }
        let mut secret_bytes = base32_decode(secret_part).ok_or(ProtoError::Malformed)?;
        if secret_bytes.len() != 32 {
            secret_bytes.zeroize();
            return Err(ProtoError::Malformed);
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        secret_bytes.zeroize();
        Ok(ShortInvite { relay, secret })
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

    #[test]
    fn a_multibyte_label_truncates_without_panicking() {
        // Twenty-two three-byte characters: byte 64 falls inside the last one,
        // which is exactly where slicing at a fixed byte offset panicked.
        let name = "日".repeat(22);
        assert_eq!(name.len(), 66);
        let inv = create(&bundle(), 0, 3600, &name).unwrap();
        let body = open(&inv, 1).unwrap();
        assert_eq!(body.label, "日".repeat(21));
        assert_eq!(truncate_label("Ada"), "Ada");
    }

    fn onion_relay() -> &'static str {
        "hxxfawyq3xymghgqkalw4ut6emtt5nhaimquyrvi7ngyeecrri4qy5qd.onion:9443"
    }

    #[test]
    fn a_short_invite_link_fits_one_qr_code() {
        // The full link, for scale: about 14,600 characters and thirteen QR
        // codes. The short one must fit one small, easily scanned code.
        let full = create(&bundle(), 0, 3600, "Alice").unwrap().to_link();
        assert!(full.len() > 10_000, "{}", full.len());

        let short = ShortInvite::generate(onion_relay()).unwrap().to_link();
        assert!(short.len() <= 150, "{} chars: {short}", short.len());
        assert!(short.starts_with(SHORT_LINK_PREFIX));
    }

    #[test]
    fn a_short_link_roundtrips_and_keeps_its_secret_in_the_fragment() {
        let short = ShortInvite::generate(onion_relay()).unwrap();
        let link = short.to_link();
        let (before, after) = link.split_once('#').unwrap();
        assert!(!before.contains(&base32_encode(&short.secret)));
        assert_eq!(base32_decode(after).unwrap(), short.secret.to_vec());

        let parsed = ShortInvite::from_link(&link.to_uppercase().replacen(
            "VOID://I/",
            SHORT_LINK_PREFIX,
            1,
        ))
        .unwrap();
        assert_eq!(parsed.relay, short.relay, "the relay part is case-folded");
        assert_eq!(parsed.secret, short.secret);
        assert_eq!(
            parsed.drop_queue().queue_id(),
            short.drop_queue().queue_id()
        );
    }

    #[test]
    fn a_short_invite_opens_the_invitation_it_parked() {
        let b = bundle();
        let short = ShortInvite::generate("relay.onion").unwrap();
        let parked = create_with_key(&b, 1_000, 3600, "Alice", short.link_key()).unwrap();

        let opened = ShortInvite::from_link(&short.to_link())
            .unwrap()
            .open_parked(&parked.ciphertext, 1_001)
            .unwrap();
        assert_eq!(opened.bundle, b);
        assert_eq!(opened.label, "Alice");

        // Another link's secret opens nothing, and expiry still applies.
        let other = ShortInvite::generate("relay.onion").unwrap();
        assert!(other.open_parked(&parked.ciphertext, 1_001).is_err());
        assert!(matches!(
            short.open_parked(&parked.ciphertext, 1_000 + 3601),
            Err(ProtoError::Expired)
        ));
    }

    #[test]
    fn a_short_invite_derives_independent_key_and_queue() {
        let short = ShortInvite::generate("relay.onion").unwrap();
        let key = short.link_key();
        let queue = short.drop_queue();
        assert_ne!(
            &key,
            queue.secret(),
            "the two derivations must not coincide"
        );
        assert_ne!(key, short.secret);
        // Holding the link is what authorises collecting: the retrieval key
        // comes from the same secret.
        let challenge = b"challenge";
        assert!(short
            .drop_queue()
            .verify_retrieval(challenge, &queue.prove_retrieval(challenge)));
    }

    #[test]
    fn malformed_short_links_are_rejected() {
        let good = ShortInvite::generate("relay.onion").unwrap().to_link();
        assert!(ShortInvite::from_link(&good).is_ok());
        assert!(
            ShortInvite::from_link("void://c/ABC#DEF").is_err(),
            "a full link is not a short one"
        );
        assert!(
            ShortInvite::from_link("void://i/relay.onion").is_err(),
            "no fragment"
        );
        assert!(
            ShortInvite::from_link("void://i/relay.onion#AAAA").is_err(),
            "short secret"
        );
        assert!(
            ShortInvite::from_link("void://i/#AAAA").is_err(),
            "no relay"
        );
        let (_, secret) = good.split_once('#').unwrap();
        for relay in ["re lay", "relay/x", "relay?x=1", "relay@host"] {
            assert!(
                ShortInvite::from_link(&alloc::format!("void://i/{relay}#{secret}")).is_err(),
                "{relay}"
            );
            assert!(ShortInvite::generate(relay).is_err(), "{relay}");
        }
        assert!(ShortInvite::generate(&"a".repeat(MAX_RELAY_LEN + 1)).is_err());
    }
}
