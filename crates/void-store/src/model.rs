//! Stored record types.
//!
//! Every type here encodes to bytes that go straight into an encrypted record.
//! There is no plaintext column anywhere — not a contact name, not a timestamp
//! index, not a conversation id. The database's sort order is by opaque record
//! id, and that is all a forensic tool gets from the file structure.
//!
//! ## Contact trust states (FR-DISC-04, FR-DISC-05)
//!
//! [`TrustState`] is deliberately a three-value enum with no "probably fine"
//! middle. FR-DISC-05 requires that a changed identity key *blocks* messaging
//! until the user explicitly acknowledges it — not warns, blocks. Encoding that
//! as a state rather than a boolean flag is what makes
//! [`Contact::can_send`] able to enforce it in one place.

use void_crypto::Zeroize;
use void_proto::identity::IdentityPublic;
use void_proto::wire::{Reader, Writer};

use crate::retention::DisappearingTimer;
use crate::{StoreError, StoreResult};

/// How much a contact's identity has been verified.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrustState {
    /// Key exchanged out of band but fingerprints never compared.
    Unverified,
    /// Fingerprints compared in person or over another channel (FR-DISC-04).
    Verified,
    /// The identity key changed. Messaging is blocked (FR-DISC-05).
    KeyChanged,
}

impl TrustState {
    fn to_byte(self) -> u8 {
        match self {
            TrustState::Unverified => 1,
            TrustState::Verified => 2,
            TrustState::KeyChanged => 3,
        }
    }

    fn from_byte(b: u8) -> StoreResult<TrustState> {
        Ok(match b {
            1 => TrustState::Unverified,
            2 => TrustState::Verified,
            // Anything unrecognised is treated as a key change: fail towards
            // blocking, never towards sending.
            _ => TrustState::KeyChanged,
        })
    }

    /// Plain-language status for the conversation header (FR-UI-03).
    #[must_use]
    pub fn user_status(self) -> &'static str {
        match self {
            TrustState::Unverified => "Not verified yet",
            TrustState::Verified => "Verified in person",
            TrustState::KeyChanged => "Their security code changed",
        }
    }

    /// What the user should do about it, in plain language.
    #[must_use]
    pub fn user_guidance(self) -> &'static str {
        match self {
            TrustState::Unverified => {
                "Anyone could be at the other end of this conversation. Compare security codes \
                 with them in person or on a call you trust."
            }
            TrustState::Verified => {
                "You compared security codes with this person. Messages are for them alone."
            }
            TrustState::KeyChanged => {
                "This can happen if they reinstalled Void or switched devices. It can also mean \
                 someone is intercepting this conversation. Messaging is paused until you check \
                 with them through another channel."
            }
        }
    }
}

/// A contact.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Contact {
    /// Their identity.
    pub identity: IdentityPublic,
    /// A local name the user chose. Never transmitted.
    pub local_name: String,
    /// Verification state.
    pub trust: TrustState,
    /// Unix seconds when this contact was created.
    pub created_at: u64,
    /// Per-conversation disappearing timer (FR-MSG-09).
    pub timer: DisappearingTimer,
    /// Read receipts for this conversation. Off by default (FR-MSG-10).
    pub read_receipts: bool,
    /// Typing indicators for this conversation. Off by default (FR-MSG-10).
    pub typing_indicators: bool,
}

impl Contact {
    /// A new, unverified contact with the safe defaults.
    #[must_use]
    pub fn new(identity: IdentityPublic, local_name: &str, created_at: u64) -> Contact {
        Contact {
            identity,
            local_name: local_name.to_string(),
            trust: TrustState::Unverified,
            created_at,
            timer: DisappearingTimer::default(),
            // FR-MSG-10: both default to off. These are real-time side channels
            // that reveal when a user is physically at their device.
            read_receipts: false,
            typing_indicators: false,
        }
    }

    /// May we send to this contact?
    ///
    /// FR-DISC-05: a key change blocks messaging until explicitly
    /// acknowledged. This is the single place that decision is made.
    #[must_use]
    pub fn can_send(&self) -> bool {
        !matches!(self.trust, TrustState::KeyChanged)
    }

    /// Record that the contact's identity key changed.
    ///
    /// Never silently accepts the new key: it stores it but moves to
    /// [`TrustState::KeyChanged`], which blocks sending.
    pub fn note_key_change(&mut self, new_identity: IdentityPublic) {
        self.identity = new_identity;
        self.trust = TrustState::KeyChanged;
    }

    /// The user acknowledged a key change and wishes to continue.
    ///
    /// Drops back to `Unverified`, never straight to `Verified` — the user
    /// dismissing a dialog is not the same as comparing fingerprints.
    pub fn acknowledge_key_change(&mut self) {
        if self.trust == TrustState::KeyChanged {
            self.trust = TrustState::Unverified;
        }
    }

    /// Mark verified after an out-of-band fingerprint comparison.
    pub fn mark_verified(&mut self) {
        self.trust = TrustState::Verified;
    }

    /// The fingerprint to display for comparison.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.identity.fingerprint()
    }

    /// Encode for storage.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes32(&self.identity.encode())
            .bytes16(self.local_name.as_bytes())
            .u8(self.trust.to_byte())
            .u64(self.created_at)
            .u8(timer_to_byte(self.timer))
            .u8(u8::from(self.read_receipts))
            .u8(u8::from(self.typing_indicators));
        w.finish()
    }

    /// Decode from storage.
    pub fn decode(bytes: &[u8]) -> StoreResult<Contact> {
        let mut r = Reader::new(bytes);
        let identity =
            IdentityPublic::decode(r.bytes32_max(64 * 1024).map_err(|_| StoreError::Corrupt)?)
                .map_err(|_| StoreError::Corrupt)?;
        let name = r.bytes16().map_err(|_| StoreError::Corrupt)?;
        let trust = TrustState::from_byte(r.u8().map_err(|_| StoreError::Corrupt)?)?;
        let created_at = r.u64().map_err(|_| StoreError::Corrupt)?;
        let timer = timer_from_byte(r.u8().map_err(|_| StoreError::Corrupt)?);
        let read_receipts = r.u8().map_err(|_| StoreError::Corrupt)? != 0;
        let typing_indicators = r.u8().map_err(|_| StoreError::Corrupt)? != 0;
        r.finish().map_err(|_| StoreError::Corrupt)?;
        Ok(Contact {
            identity,
            local_name: String::from_utf8(name.to_vec()).map_err(|_| StoreError::Corrupt)?,
            trust,
            created_at,
            timer,
            read_receipts,
            typing_indicators,
        })
    }
}

fn timer_to_byte(t: DisappearingTimer) -> u8 {
    match t {
        DisappearingTimer::Off => 0,
        DisappearingTimer::OneHour => 1,
        DisappearingTimer::OneDay => 2,
        DisappearingTimer::SevenDays => 3,
        DisappearingTimer::ThirtyDays => 4,
    }
}

fn timer_from_byte(b: u8) -> DisappearingTimer {
    match b {
        1 => DisappearingTimer::OneHour,
        2 => DisappearingTimer::OneDay,
        3 => DisappearingTimer::SevenDays,
        4 => DisappearingTimer::ThirtyDays,
        _ => DisappearingTimer::Off,
    }
}

/// Which way a message went.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// We sent it.
    Outgoing,
    /// We received it.
    Incoming,
}

/// Delivery state, surfaced per message (NFR-REL-04).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeliveryState {
    /// Queued locally because Tor or the relay is unreachable. Void never
    /// falls back to a direct connection (FR-TRANS-05), so this state can
    /// persist and the UI must say so honestly.
    Queued,
    /// Accepted by a relay.
    Deposited,
    /// The recipient collected it from the queue.
    Collected,
    /// Permanently failed.
    Failed,
    /// Not applicable — an incoming message.
    Received,
}

impl DeliveryState {
    fn to_byte(self) -> u8 {
        match self {
            DeliveryState::Queued => 1,
            DeliveryState::Deposited => 2,
            DeliveryState::Collected => 3,
            DeliveryState::Failed => 4,
            DeliveryState::Received => 5,
        }
    }
    fn from_byte(b: u8) -> DeliveryState {
        match b {
            2 => DeliveryState::Deposited,
            3 => DeliveryState::Collected,
            4 => DeliveryState::Failed,
            5 => DeliveryState::Received,
            _ => DeliveryState::Queued,
        }
    }

    /// Plain-language label (FR-UI-03).
    #[must_use]
    pub fn user_label(self) -> &'static str {
        match self {
            DeliveryState::Queued => "Waiting to send",
            DeliveryState::Deposited => "Sent",
            DeliveryState::Collected => "Delivered",
            DeliveryState::Failed => "Could not send",
            DeliveryState::Received => "",
        }
    }
}

/// A stored message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoredMessage {
    /// Fingerprint of the contact this belongs to.
    pub contact_fingerprint: [u8; 32],
    /// Direction.
    pub direction: Direction,
    /// Unix seconds. Local clock only; never taken from the peer, because a
    /// peer-supplied timestamp is a channel we would have to trust.
    pub timestamp: u64,
    /// The message body.
    pub body: String,
    /// Delivery state.
    pub delivery: DeliveryState,
}

impl Drop for StoredMessage {
    fn drop(&mut self) {
        // Overwrite the body in place before releasing it. `String` is UTF-8,
        // so we cannot simply zero its bytes without `unsafe`; writing an
        // equal-length run of NULs is valid UTF-8 and does not reallocate,
        // because the length is unchanged.
        //
        // Honest limitation, per FR-ID-02a's spirit: this narrows the window in
        // which a message body is recoverable from a live process. It does not
        // reach a copy the allocator, the OS, or a prior `String` growth
        // already made elsewhere. The authoritative protection is the vault
        // (see the crate docs), not this.
        let len = self.body.len();
        if len > 0 {
            self.body.replace_range(.., &"\0".repeat(len));
        }
        self.body.clear();
        self.contact_fingerprint.zeroize();
    }
}

impl StoredMessage {
    /// Encode for storage.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.contact_fingerprint)
            .u8(match self.direction {
                Direction::Outgoing => 1,
                Direction::Incoming => 2,
            })
            .u64(self.timestamp)
            .u8(self.delivery.to_byte())
            .bytes32(self.body.as_bytes());
        w.finish()
    }

    /// Decode from storage.
    pub fn decode(bytes: &[u8]) -> StoreResult<StoredMessage> {
        let mut r = Reader::new(bytes);
        let contact_fingerprint = r.array::<32>().map_err(|_| StoreError::Corrupt)?;
        let direction = match r.u8().map_err(|_| StoreError::Corrupt)? {
            1 => Direction::Outgoing,
            2 => Direction::Incoming,
            _ => return Err(StoreError::Corrupt),
        };
        let timestamp = r.u64().map_err(|_| StoreError::Corrupt)?;
        let delivery = DeliveryState::from_byte(r.u8().map_err(|_| StoreError::Corrupt)?);
        let body = r
            .bytes32_max(1024 * 1024)
            .map_err(|_| StoreError::Corrupt)?;
        r.finish().map_err(|_| StoreError::Corrupt)?;
        Ok(StoredMessage {
            contact_fingerprint,
            direction,
            timestamp,
            body: String::from_utf8(body.to_vec()).map_err(|_| StoreError::Corrupt)?,
            delivery,
        })
    }
}

/// Device-wide settings.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Settings {
    /// Retention policy.
    pub retention: crate::retention::RetentionPolicy,
    /// Push notifications. **Off by default** (FR-NOTIF-04).
    pub push_enabled: bool,
    /// What a notification shows on the lock screen (FR-NOTIF-06).
    pub notification_detail: NotificationDetail,
    /// Whether a duress PIN is configured.
    pub duress_pin_configured: bool,
    /// Failed unlock attempts before automatic destruction. Zero means the
    /// feature is disabled, which FR-STOR-03 makes the default.
    pub destroy_after_failed_attempts: u8,
    /// Whether the onboarding "what Void does and does not protect" screen has
    /// been shown (FR-UI-05).
    pub protection_screen_acknowledged: bool,
    /// Whether the device-loss warning has been acknowledged (FR-REC-01).
    pub device_loss_acknowledged: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            retention: crate::retention::RetentionPolicy::ThirtyDays,
            push_enabled: false,
            notification_detail: NotificationDetail::Generic,
            duress_pin_configured: false,
            destroy_after_failed_attempts: 0,
            protection_screen_acknowledged: false,
            device_loss_acknowledged: false,
        }
    }
}

/// How much a notification reveals on the lock screen (FR-NOTIF-06).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotificationDetail {
    /// "Message received". The default: reveals nothing.
    Generic,
    /// The sender's local name.
    SenderName,
    /// A preview of the message body.
    Preview,
}

impl NotificationDetail {
    fn to_byte(self) -> u8 {
        match self {
            NotificationDetail::Generic => 1,
            NotificationDetail::SenderName => 2,
            NotificationDetail::Preview => 3,
        }
    }
    fn from_byte(b: u8) -> NotificationDetail {
        match b {
            2 => NotificationDetail::SenderName,
            3 => NotificationDetail::Preview,
            // Fail towards revealing less.
            _ => NotificationDetail::Generic,
        }
    }

    /// The text actually shown on the lock screen.
    #[must_use]
    pub fn render(self, sender: &str, body: &str) -> String {
        match self {
            NotificationDetail::Generic => "Message received".to_string(),
            NotificationDetail::SenderName => format!("Message from {sender}"),
            NotificationDetail::Preview => {
                let truncated: String = body.chars().take(100).collect();
                format!("{sender}: {truncated}")
            }
        }
    }
}

impl Settings {
    /// Encode for storage.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.retention.to_byte())
            .u8(u8::from(self.push_enabled))
            .u8(self.notification_detail.to_byte())
            .u8(u8::from(self.duress_pin_configured))
            .u8(self.destroy_after_failed_attempts)
            .u8(u8::from(self.protection_screen_acknowledged))
            .u8(u8::from(self.device_loss_acknowledged));
        w.finish()
    }

    /// Decode from storage.
    pub fn decode(bytes: &[u8]) -> StoreResult<Settings> {
        let mut r = Reader::new(bytes);
        let retention =
            crate::retention::RetentionPolicy::from_byte(r.u8().map_err(|_| StoreError::Corrupt)?);
        let push_enabled = r.u8().map_err(|_| StoreError::Corrupt)? != 0;
        let notification_detail =
            NotificationDetail::from_byte(r.u8().map_err(|_| StoreError::Corrupt)?);
        let duress_pin_configured = r.u8().map_err(|_| StoreError::Corrupt)? != 0;
        let destroy_after_failed_attempts = r.u8().map_err(|_| StoreError::Corrupt)?;
        let protection_screen_acknowledged = r.u8().map_err(|_| StoreError::Corrupt)? != 0;
        let device_loss_acknowledged = r.u8().map_err(|_| StoreError::Corrupt)? != 0;
        r.finish().map_err(|_| StoreError::Corrupt)?;
        Ok(Settings {
            retention,
            push_enabled,
            notification_detail,
            duress_pin_configured,
            destroy_after_failed_attempts,
            protection_screen_acknowledged,
            device_loss_acknowledged,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use void_proto::identity::Identity;

    fn ident() -> IdentityPublic {
        Identity::from_seeds(&[1u8; 32], &[2u8; 32], &[3u8; 32])
            .public
            .clone()
    }

    #[test]
    fn new_contacts_start_unverified_with_side_channels_off() {
        let c = Contact::new(ident(), "Alice", 1000);
        assert_eq!(c.trust, TrustState::Unverified);
        // FR-MSG-10: both off by default.
        assert!(!c.read_receipts);
        assert!(!c.typing_indicators);
        assert_eq!(c.timer, DisappearingTimer::Off);
        assert!(c.can_send());
    }

    #[test]
    fn key_change_blocks_sending_until_acknowledged() {
        // FR-DISC-05: blocked, not warned.
        let mut c = Contact::new(ident(), "Alice", 1000);
        c.mark_verified();
        assert!(c.can_send());

        let other = Identity::from_seeds(&[9u8; 32], &[8u8; 32], &[7u8; 32])
            .public
            .clone();
        c.note_key_change(other.clone());
        assert_eq!(c.trust, TrustState::KeyChanged);
        assert!(
            !c.can_send(),
            "messaging must be blocked after a key change"
        );
        assert_eq!(
            c.identity, other,
            "the new key is stored, not silently accepted"
        );

        c.acknowledge_key_change();
        assert!(c.can_send());
        assert_eq!(
            c.trust,
            TrustState::Unverified,
            "acknowledging must not restore verified status"
        );
    }

    #[test]
    fn unknown_trust_bytes_fail_towards_blocking() {
        assert_eq!(TrustState::from_byte(99).unwrap(), TrustState::KeyChanged);
        assert!(!Contact {
            trust: TrustState::from_byte(99).unwrap(),
            ..Contact::new(ident(), "x", 0)
        }
        .can_send());
    }

    #[test]
    fn contact_encoding_roundtrips() {
        let mut c = Contact::new(ident(), "Alice \u{2713}", 1234);
        c.mark_verified();
        c.timer = DisappearingTimer::SevenDays;
        c.read_receipts = true;
        let enc = c.encode();
        assert_eq!(Contact::decode(&enc).unwrap(), c);
        assert!(Contact::decode(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn message_encoding_roundtrips() {
        let m = StoredMessage {
            contact_fingerprint: [7u8; 32],
            direction: Direction::Outgoing,
            timestamp: 999,
            body: "hello \u{1F600}".to_string(),
            delivery: DeliveryState::Queued,
        };
        let enc = m.encode();
        let decoded = StoredMessage::decode(&enc).unwrap();
        assert_eq!(decoded.body, m.body);
        assert_eq!(decoded.delivery, DeliveryState::Queued);
        assert!(StoredMessage::decode(&enc[..10]).is_err());
    }

    #[test]
    fn settings_default_to_the_safe_choices() {
        let s = Settings::default();
        // FR-NOTIF-04: push off by default.
        assert!(!s.push_enabled);
        // FR-NOTIF-06: default reveals nothing on the lock screen.
        assert_eq!(s.notification_detail, NotificationDetail::Generic);
        // FR-STOR-04: 30 days.
        assert_eq!(s.retention, crate::retention::RetentionPolicy::ThirtyDays);
        // FR-STOR-03: destroy-after-failed-attempts defaults to disabled.
        assert_eq!(s.destroy_after_failed_attempts, 0);
    }

    #[test]
    fn settings_encoding_roundtrips_and_fails_safe() {
        let s = Settings {
            push_enabled: true,
            notification_detail: NotificationDetail::Preview,
            destroy_after_failed_attempts: 10,
            ..Settings::default()
        };
        let enc = s.encode();
        assert_eq!(Settings::decode(&enc).unwrap(), s);

        // A corrupt notification byte must fall back to Generic, never Preview.
        let mut bad = enc.clone();
        bad[2] = 200;
        assert_eq!(
            Settings::decode(&bad).unwrap().notification_detail,
            NotificationDetail::Generic
        );
    }

    #[test]
    fn notification_rendering_respects_the_setting() {
        assert_eq!(
            NotificationDetail::Generic.render("Alice", "the meeting is at dawn"),
            "Message received"
        );
        assert!(!NotificationDetail::Generic
            .render("Alice", "the meeting is at dawn")
            .contains("Alice"));
        assert_eq!(
            NotificationDetail::SenderName.render("Alice", "secret"),
            "Message from Alice"
        );
        assert!(!NotificationDetail::SenderName
            .render("Alice", "secret")
            .contains("secret"));
        let long = "x".repeat(500);
        assert!(NotificationDetail::Preview.render("A", &long).len() < 200);
    }

    #[test]
    fn every_trust_state_has_plain_language_guidance() {
        for t in [
            TrustState::Unverified,
            TrustState::Verified,
            TrustState::KeyChanged,
        ] {
            assert!(!t.user_status().is_empty());
            assert!(t.user_guidance().len() > 40, "{t:?} needs real guidance");
            // FR-UI-03: no jargon.
            for jargon in ["fingerprint", "public key", "MITM", "cryptograph"] {
                assert!(
                    !t.user_guidance().to_lowercase().contains(jargon),
                    "{t:?} guidance uses jargon: {jargon}"
                );
            }
        }
        // The key-change guidance must name both innocent and hostile causes.
        let g = TrustState::KeyChanged.user_guidance();
        assert!(g.contains("reinstalled"));
        assert!(g.contains("intercepting"));
    }

    #[test]
    fn delivery_states_have_honest_labels() {
        assert_eq!(DeliveryState::Queued.user_label(), "Waiting to send");
        assert_eq!(DeliveryState::Failed.user_label(), "Could not send");
        assert_eq!(DeliveryState::from_byte(200), DeliveryState::Queued);
    }
}
