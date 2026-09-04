//! Retention policy (FR-STOR-04).
//!
//! PRD §7.4.1: *"the strongest defense against coercion is not having the
//! data."* Retention is therefore a security control, not a housekeeping
//! feature, and the defaults are chosen accordingly:
//!
//! - The default is **30 days**, not "forever".
//! - The options are presented **shortest first**, so the safe choice is the
//!   one the thumb reaches. FR-STOR-04 says this explicitly and
//!   [`RetentionPolicy::ordered_options`] encodes it, with a test.
//! - "Forever" exists, because a journalist may need a record and lying to
//!   them about whether it is kept would be worse. It is last in the list.

use crate::db::{Backend, Database, Kind};
use crate::StoreResult;

/// How long messages are kept.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RetentionPolicy {
    /// 24 hours.
    OneDay,
    /// 7 days.
    OneWeek,
    /// 30 days. FR-STOR-04's default, marked here so the default cannot drift
    /// from the requirement by someone reordering the variants.
    #[default]
    ThirtyDays,
    /// 365 days.
    OneYear,
    /// No automatic expiry.
    Forever,
}

impl RetentionPolicy {
    /// Lifetime in seconds. `None` means no expiry.
    #[must_use]
    pub fn seconds(self) -> Option<u64> {
        match self {
            RetentionPolicy::OneDay => Some(24 * 60 * 60),
            RetentionPolicy::OneWeek => Some(7 * 24 * 60 * 60),
            RetentionPolicy::ThirtyDays => Some(30 * 24 * 60 * 60),
            RetentionPolicy::OneYear => Some(365 * 24 * 60 * 60),
            RetentionPolicy::Forever => None,
        }
    }

    /// The expiry timestamp for a message stored at `now`. Zero means never.
    #[must_use]
    pub fn expires_at(self, now: u64) -> u64 {
        match self.seconds() {
            Some(s) => now.saturating_add(s),
            None => 0,
        }
    }

    /// The options in the order the UI must present them: **shortest first**.
    ///
    /// FR-STOR-04 requires this ordering. It is a dark-pattern question in
    /// reverse — the ordering that serves the user is the one that puts the
    /// most protective option where it will be picked by default.
    #[must_use]
    pub fn ordered_options() -> [RetentionPolicy; 5] {
        [
            RetentionPolicy::OneDay,
            RetentionPolicy::OneWeek,
            RetentionPolicy::ThirtyDays,
            RetentionPolicy::OneYear,
            RetentionPolicy::Forever,
        ]
    }

    /// Plain-language label (FR-UI-03).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            RetentionPolicy::OneDay => "24 hours",
            RetentionPolicy::OneWeek => "7 days",
            RetentionPolicy::ThirtyDays => "30 days",
            RetentionPolicy::OneYear => "1 year",
            RetentionPolicy::Forever => "Keep until I delete them",
        }
    }

    /// The consequence, stated honestly (non-negotiable #8: no dark patterns —
    /// the cost of each option is stated).
    #[must_use]
    pub fn consequence(self) -> &'static str {
        match self {
            RetentionPolicy::Forever => {
                "Messages stay on this device until you delete them. If your device is seized \
                 while unlocked, everything is there."
            }
            _ => {
                "Messages are deleted from this device automatically. Once deleted they cannot \
                 be recovered, by you or by anyone else."
            }
        }
    }

    /// Encode for storage.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            RetentionPolicy::OneDay => 1,
            RetentionPolicy::OneWeek => 2,
            RetentionPolicy::ThirtyDays => 3,
            RetentionPolicy::OneYear => 4,
            RetentionPolicy::Forever => 5,
        }
    }

    /// Decode from storage. Unknown values fall back to the default rather
    /// than to "forever": a corrupt byte must not silently disable expiry.
    #[must_use]
    pub fn from_byte(b: u8) -> RetentionPolicy {
        match b {
            1 => RetentionPolicy::OneDay,
            2 => RetentionPolicy::OneWeek,
            4 => RetentionPolicy::OneYear,
            5 => RetentionPolicy::Forever,
            _ => RetentionPolicy::ThirtyDays,
        }
    }
}

/// Per-conversation disappearing-message timer (FR-MSG-09).
///
/// Distinct from [`RetentionPolicy`], which is a device-wide floor. The
/// effective lifetime of a message is the shorter of the two — a conversation
/// timer can tighten the device policy but never loosen it, so a user who set
/// 24-hour retention does not get 30-day messages because a contact chose a
/// longer timer.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DisappearingTimer {
    /// No per-conversation timer.
    #[default]
    Off,
    /// One hour.
    OneHour,
    /// One day.
    OneDay,
    /// Seven days.
    SevenDays,
    /// Thirty days.
    ThirtyDays,
}

impl DisappearingTimer {
    /// Lifetime in seconds, if set.
    #[must_use]
    pub fn seconds(self) -> Option<u64> {
        match self {
            DisappearingTimer::Off => None,
            DisappearingTimer::OneHour => Some(60 * 60),
            DisappearingTimer::OneDay => Some(24 * 60 * 60),
            DisappearingTimer::SevenDays => Some(7 * 24 * 60 * 60),
            DisappearingTimer::ThirtyDays => Some(30 * 24 * 60 * 60),
        }
    }

    /// The options FR-MSG-09 specifies, shortest first.
    #[must_use]
    pub fn ordered_options() -> [DisappearingTimer; 5] {
        [
            DisappearingTimer::OneHour,
            DisappearingTimer::OneDay,
            DisappearingTimer::SevenDays,
            DisappearingTimer::ThirtyDays,
            DisappearingTimer::Off,
        ]
    }
}

/// Compute a message's expiry from both policies. Zero means never.
#[must_use]
pub fn effective_expiry(policy: RetentionPolicy, timer: DisappearingTimer, now: u64) -> u64 {
    match (policy.seconds(), timer.seconds()) {
        (None, None) => 0,
        (Some(a), None) => now.saturating_add(a),
        (None, Some(b)) => now.saturating_add(b),
        (Some(a), Some(b)) => now.saturating_add(a.min(b)),
    }
}

/// Run the retention sweep.
pub fn sweep<B: Backend>(db: &mut Database<B>, now: u64) -> StoreResult<usize> {
    db.sweep_expired(now)
}

/// Apply a policy change to records already stored.
///
/// Shortening retention must take effect on existing messages immediately —
/// otherwise a user who tightens the setting because they are about to cross a
/// border is not actually protected. Lengthening it does **not** revive
/// already-deleted messages, and does not extend existing ones, because a
/// message the user believed would expire at time T must expire at time T.
pub fn apply_policy_change<B: Backend>(
    db: &mut Database<B>,
    new_policy: RetentionPolicy,
    now: u64,
) -> StoreResult<usize> {
    let new_expiry = new_policy.expires_at(now);
    let ids: Vec<(u64, u64)> = db
        .list(Kind::Message)?
        .iter()
        .map(|r| (r.id, r.expires_at))
        .collect();

    let mut tightened = 0usize;
    for (id, current) in ids {
        let should = match (current, new_expiry) {
            // Currently never expires; the new policy gives it an expiry.
            (0, e) if e != 0 => Some(e),
            // New expiry is sooner than the current one.
            (c, e) if e != 0 && e < c => Some(e),
            _ => None,
        };
        if let Some(e) = should {
            db.set_expiry(id, e)?;
            tightened += 1;
        }
    }
    if tightened > 0 {
        db.flush()?;
    }
    Ok(tightened)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::MemoryBackend;
    use crate::vault::SoftwareVault;
    use void_crypto::argon2;

    fn db() -> Database<MemoryBackend> {
        let vault = SoftwareVault::from_raw([1u8; 32]);
        Database::create(MemoryBackend::new(), &vault, argon2::Params::TEST_ONLY_WEAK).unwrap()
    }

    #[test]
    fn default_is_thirty_days() {
        assert_eq!(RetentionPolicy::default(), RetentionPolicy::ThirtyDays);
        assert_eq!(
            RetentionPolicy::ThirtyDays.seconds().unwrap(),
            30 * 24 * 60 * 60
        );
    }

    #[test]
    fn options_are_ordered_shortest_first() {
        // FR-STOR-04 requires this, and it is the kind of requirement that
        // silently regresses in a UI refactor. Hence a test.
        let opts = RetentionPolicy::ordered_options();
        let mut last = 0u64;
        for o in opts.iter().take(4) {
            let s = o.seconds().unwrap();
            assert!(s > last, "options must increase: {o:?}");
            last = s;
        }
        assert_eq!(opts[0], RetentionPolicy::OneDay);
        assert_eq!(*opts.last().unwrap(), RetentionPolicy::Forever);

        let timers = DisappearingTimer::ordered_options();
        assert_eq!(timers[0], DisappearingTimer::OneHour);
        assert_eq!(*timers.last().unwrap(), DisappearingTimer::Off);
    }

    #[test]
    fn encoding_roundtrips_and_fails_safe() {
        for p in RetentionPolicy::ordered_options() {
            assert_eq!(RetentionPolicy::from_byte(p.to_byte()), p);
        }
        // A corrupt byte must fall back to the default, never to Forever.
        assert_eq!(RetentionPolicy::from_byte(0), RetentionPolicy::ThirtyDays);
        assert_eq!(RetentionPolicy::from_byte(200), RetentionPolicy::ThirtyDays);
        assert_ne!(RetentionPolicy::from_byte(200), RetentionPolicy::Forever);
    }

    #[test]
    fn effective_expiry_takes_the_shorter_of_the_two() {
        let now = 1000;
        assert_eq!(
            effective_expiry(RetentionPolicy::ThirtyDays, DisappearingTimer::OneHour, now),
            now + 3600
        );
        assert_eq!(
            effective_expiry(RetentionPolicy::OneDay, DisappearingTimer::SevenDays, now),
            now + 24 * 3600
        );
        assert_eq!(
            effective_expiry(RetentionPolicy::Forever, DisappearingTimer::OneHour, now),
            now + 3600
        );
        assert_eq!(
            effective_expiry(RetentionPolicy::Forever, DisappearingTimer::Off, now),
            0
        );
    }

    #[test]
    fn sweep_deletes_expired_messages() {
        let mut d = db();
        d.insert(crate::db::Kind::Message, 100, b"old").unwrap();
        d.insert(crate::db::Kind::Message, 10_000, b"new").unwrap();
        d.flush().unwrap();
        assert_eq!(sweep(&mut d, 500).unwrap(), 1);
        assert_eq!(d.list(crate::db::Kind::Message).unwrap().len(), 1);
    }

    #[test]
    fn tightening_the_policy_applies_to_existing_messages() {
        let mut d = db();
        let now = 1_000_000u64;
        let far = d
            .insert(crate::db::Kind::Message, now + 30 * 86400, b"a")
            .unwrap();
        let never = d.insert(crate::db::Kind::Message, 0, b"b").unwrap();
        d.flush().unwrap();

        let changed = apply_policy_change(&mut d, RetentionPolicy::OneDay, now).unwrap();
        assert_eq!(changed, 2);
        assert_eq!(d.get(far).unwrap().unwrap().expires_at, now + 86400);
        assert_eq!(d.get(never).unwrap().unwrap().expires_at, now + 86400);
    }

    #[test]
    fn loosening_the_policy_does_not_extend_existing_messages() {
        // A message the user believed would expire tomorrow must still expire
        // tomorrow, even if they later choose a longer retention.
        let mut d = db();
        let now = 1_000_000u64;
        let id = d
            .insert(crate::db::Kind::Message, now + 86400, b"a")
            .unwrap();
        d.flush().unwrap();

        let changed = apply_policy_change(&mut d, RetentionPolicy::OneYear, now).unwrap();
        assert_eq!(changed, 0);
        assert_eq!(d.get(id).unwrap().unwrap().expires_at, now + 86400);

        let changed = apply_policy_change(&mut d, RetentionPolicy::Forever, now).unwrap();
        assert_eq!(changed, 0);
        assert_eq!(d.get(id).unwrap().unwrap().expires_at, now + 86400);
    }

    #[test]
    fn every_option_states_its_consequence() {
        for p in RetentionPolicy::ordered_options() {
            assert!(!p.label().is_empty());
            assert!(p.consequence().len() > 40, "{p:?} needs a real explanation");
        }
        assert!(RetentionPolicy::Forever.consequence().contains("seized"));
    }
}
