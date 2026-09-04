//! The send scheduler: constant-rate padding and jittered retrieval
//! (FR-MSG-06, FR-MSG-07).
//!
//! ## What v1.0 got wrong, and what this does instead
//!
//! PRD v1.0 specified 24/7 chaffing at a **user-configurable** 1–10 KB/s. §2.3
//! dismantles that on two grounds, and both are encoded here as invariants:
//!
//! 1. *A configurable rate is a per-user fingerprint.* It partitions users into
//!    buckets an observer can tell apart, which is the opposite of an anonymity
//!    set. So [`PAD_INTERVAL_MS`](void_proto::record::PAD_INTERVAL_MS) is a
//!    protocol constant and this module exposes no way to change it.
//! 2. *Foreground-only chaff is worse than none.* On iOS the app is suspended
//!    within seconds of backgrounding, so cover traffic that stops when the app
//!    closes is a direct signal of when the user has the app open. Void
//!    therefore does not claim continuous cover traffic at all. It claims
//!    something narrower and true: **while a connection is open, the traffic on
//!    it is constant-rate and uniform-size, so an observer cannot tell whether
//!    any given emission carries a message.**
//!
//! That is the honest version of the claim, and it is what §9.2 says the threat
//! model was downgraded to.
//!
//! ## Jitter, and why it is quantised
//!
//! Retrieval is scheduled with randomised delay (FR-MSG-07) so that a relay
//! cannot tie a deposit at time T to a collection at time T+ε. The jitter is
//! drawn without modulo bias — see `void_crypto::rand::below` — because a
//! biased delay distribution is itself a weak fingerprint.
//!
//! The drawn delay is then **quantised to the emission grid**: a retrieval
//! occupies a scheduled slot rather than creating one. This is a deliberate
//! second-order decision. Unquantised jitter would mean a retrieval frame
//! appears at a moment no other frame would have, which makes the retrieval
//! itself visible in the timing even though its *contents* are not — the
//! observer learns "this client just checked its queue", which is close to
//! learning "this client is expecting something". Quantising costs granularity
//! and buys the property that every frame is on the grid, indistinguishable
//! from every other frame.
//!
//! The consequence is that the effective delay is a multiple of
//! [`PAD_INTERVAL_MS`], so [`RETRIEVAL_JITTER_MS`] is sized to span several
//! slots rather than a fraction of one.
//!
//! A push wake (FR-NOTIF-02) bypasses this schedule: the client builds a
//! circuit and retrieves immediately. That is the trade the user accepted when
//! they enabled push, and §9.3.1 states it.

use std::time::Duration;

use void_crypto::rand;
use void_proto::record::PAD_INTERVAL_MS;

use crate::{ClientError, ClientResult};

/// Minimum delay before a scheduled retrieval, in milliseconds.
pub const RETRIEVAL_MIN_DELAY_MS: u64 = 500;

/// Maximum additional randomised delay before a retrieval, in milliseconds.
///
/// Spans six emission slots at the current [`PAD_INTERVAL_MS`], giving a
/// retrieval delay uniform over roughly {0, 5, 10, 15, 20, 25, 30} seconds once
/// quantised. Wide enough that a relay cannot pair a deposit with the
/// collection that followed it; short enough that a conversation still feels
/// live to Persona C, whose continued use is what gives Personas A and B an
/// anonymity set (§5).
pub const RETRIEVAL_JITTER_MS: u64 = 30_000;

/// How many emission slots the retrieval jitter can span.
pub const RETRIEVAL_JITTER_SLOTS: u64 = RETRIEVAL_JITTER_MS / PAD_INTERVAL_MS;

// Quantisation (D-014) means the jitter is only useful if it spans several
// slots. A compile-time assertion rather than a test, because a future change
// to either constant that collapses the jitter should not build at all.
const _: () = assert!(
    RETRIEVAL_JITTER_SLOTS >= 4,
    "retrieval jitter must span at least four emission slots to decorrelate \
     deposit from collection; see docs/DECISIONS.md#d-014"
);

/// What the scheduler wants done next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Emit a real payload record from the outbox.
    SendPayload,
    /// Emit a dummy record. Indistinguishable on the wire from a payload.
    SendPadding,
    /// Poll the queues for incoming records.
    Retrieve,
    /// Nothing is due yet; sleep for this long.
    Wait(Duration),
}

/// Drives the constant-rate emission and jittered retrieval schedule.
///
/// The scheduler is a pure state machine over a caller-supplied clock, so tests
/// can run a simulated month in milliseconds and assert on the resulting
/// traffic shape.
pub struct Scheduler {
    /// Milliseconds since some fixed origin, supplied by the caller.
    next_emit_ms: u64,
    next_retrieve_ms: u64,
    connected: bool,
    emitted_payload: u64,
    emitted_padding: u64,
}

impl Scheduler {
    /// New scheduler, starting at `now_ms`.
    pub fn new(now_ms: u64) -> ClientResult<Scheduler> {
        Ok(Scheduler {
            next_emit_ms: now_ms,
            next_retrieve_ms: now_ms.saturating_add(Self::draw_jitter()?),
            connected: false,
            emitted_payload: 0,
            emitted_padding: 0,
        })
    }

    fn draw_jitter() -> ClientResult<u64> {
        let extra = rand::below(RETRIEVAL_JITTER_MS + 1).map_err(|_| ClientError::Entropy)?;
        Ok(RETRIEVAL_MIN_DELAY_MS + extra)
    }

    /// Tell the scheduler whether a connection is open.
    ///
    /// Cover traffic only flows while connected — see the module docs for why
    /// Void does not pretend otherwise.
    pub fn set_connected(&mut self, connected: bool, now_ms: u64) {
        if connected && !self.connected {
            // Starting a connection resets the emission phase, so the first
            // emission is not at a predictable offset from the last session.
            self.next_emit_ms = now_ms;
        }
        self.connected = connected;
    }

    /// Is a connection open?
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// What should happen at `now_ms`?
    ///
    /// ## The invariant
    ///
    /// The schedule produces **exactly one frame per
    /// [`PAD_INTERVAL_MS`]**, always, while connected. What varies is the
    /// frame's *type*, never its *timing*:
    ///
    /// 1. a retrieval, if one is due (the jittered schedule),
    /// 2. otherwise a payload, if the outbox has work,
    /// 3. otherwise a dummy record.
    ///
    /// Modelling retrieval as a *choice within* a slot rather than an extra
    /// event is the whole point. An earlier version let a due retrieval preempt
    /// an emission, which meant the emission grid shifted whenever a retrieval
    /// landed — and since retrieval timing is jittered, that shift was
    /// observable. Now the grid is fixed and the jitter only decides which of
    /// three identically-sized frames occupies a slot.
    ///
    /// `outbox_has_work` influences *what* is emitted and never *when*. That is
    /// the property FR-MSG-06 asks for: a user with a full outbox and a user
    /// with an empty one emit at exactly the same times.
    pub fn poll(&mut self, now_ms: u64, outbox_has_work: bool) -> ClientResult<Action> {
        if !self.connected {
            // Disconnected: nothing is emitted, and the caller should attempt
            // to reconnect rather than fall back to another path.
            return Ok(Action::Wait(Duration::from_millis(PAD_INTERVAL_MS)));
        }

        if now_ms < self.next_emit_ms {
            let until = self.next_emit_ms.saturating_sub(now_ms);
            return Ok(Action::Wait(Duration::from_millis(until.max(1))));
        }

        // Advance the grid. If we have fallen far behind — the app was
        // suspended, which on iOS is the normal case — resynchronise to the
        // present rather than emitting the backlog. A catch-up burst would
        // announce exactly when the user reopened the app.
        self.next_emit_ms = self.next_emit_ms.saturating_add(PAD_INTERVAL_MS);
        if self.next_emit_ms <= now_ms {
            self.next_emit_ms = now_ms.saturating_add(PAD_INTERVAL_MS);
        }

        if now_ms >= self.next_retrieve_ms {
            self.next_retrieve_ms = now_ms.saturating_add(Self::draw_jitter()?);
            return Ok(Action::Retrieve);
        }

        if outbox_has_work {
            self.emitted_payload += 1;
            Ok(Action::SendPayload)
        } else {
            self.emitted_padding += 1;
            Ok(Action::SendPadding)
        }
    }

    /// How many payload records have been emitted.
    #[must_use]
    pub fn payload_count(&self) -> u64 {
        self.emitted_payload
    }

    /// How many dummy records have been emitted.
    #[must_use]
    pub fn padding_count(&self) -> u64 {
        self.emitted_padding
    }

    /// Bytes of cover traffic emitted so far, for the opt-in aggregate metric
    /// in PRD §12. Counted locally and never reported without consent.
    #[must_use]
    pub fn padding_bytes(&self) -> u64 {
        self.emitted_padding * (void_proto::record::RECORD_SIZE as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_emitted_while_disconnected() {
        let mut s = Scheduler::new(0).unwrap();
        for t in (0..100_000).step_by(1000) {
            assert!(matches!(s.poll(t, true).unwrap(), Action::Wait(_)));
        }
        assert_eq!(s.payload_count(), 0);
        assert_eq!(s.padding_count(), 0);
    }

    #[test]
    fn emission_is_constant_rate_regardless_of_traffic() {
        // The core property: the emission schedule does not depend on whether
        // the user is actually sending anything.
        let run = |has_work: bool| -> Vec<u64> {
            let mut s = Scheduler::new(0).unwrap();
            s.set_connected(true, 0);
            let mut times = Vec::new();
            let mut t = 0u64;
            while t < 60_000 {
                // Every non-Wait action is one frame on the wire, and the
                // grid must be identical whether or not there is work.
                match s.poll(t, has_work).unwrap() {
                    Action::SendPayload | Action::SendPadding | Action::Retrieve => times.push(t),
                    Action::Wait(_) => {}
                }
                t += 100;
            }
            times
        };
        let busy = run(true);
        let idle = run(false);
        assert_eq!(
            busy, idle,
            "emission times must not depend on outbox contents"
        );
        assert!(
            busy.len() >= 11,
            "expected ~12 frames in 60s, got {}",
            busy.len()
        );
    }

    #[test]
    fn emissions_are_spaced_by_the_pad_interval() {
        let mut s = Scheduler::new(0).unwrap();
        s.set_connected(true, 0);
        let mut times = Vec::new();
        let mut t = 0u64;
        while t < 60_000 {
            if !matches!(s.poll(t, false).unwrap(), Action::Wait(_)) {
                times.push(t);
            }
            t += 50;
        }
        for w in times.windows(2) {
            let gap = w[1] - w[0];
            assert!(
                gap.abs_diff(PAD_INTERVAL_MS) <= 50,
                "gap {gap} is not the pad interval"
            );
        }
    }

    #[test]
    fn payload_is_emitted_when_the_outbox_has_work() {
        let mut s = Scheduler::new(0).unwrap();
        s.set_connected(true, 0);
        // A slot may be claimed by the jittered retrieval; drive several.
        let mut t = 0u64;
        while s.payload_count() == 0 && t < 200_000 {
            let _ = s.poll(t, true).unwrap();
            t += PAD_INTERVAL_MS;
        }
        assert!(s.payload_count() > 0, "a full outbox must eventually send");

        let before = s.padding_count();
        let mut t2 = t;
        while s.padding_count() == before && t2 < t + 200_000 {
            let _ = s.poll(t2, false).unwrap();
            t2 += PAD_INTERVAL_MS;
        }
        assert!(
            s.padding_count() > before,
            "an empty outbox must emit cover traffic"
        );
    }

    #[test]
    fn retrieval_is_jittered_across_several_slots() {
        // Quantised to the emission grid (see the module docs), so the
        // observable values are multiples of PAD_INTERVAL_MS. What must hold is
        // that several distinct slots occur, not that the raw delay is
        // continuous.
        let mut slots = std::collections::BTreeSet::new();
        for _ in 0..60 {
            let mut s = Scheduler::new(0).unwrap();
            s.set_connected(true, 0);
            let mut t = 0u64;
            while t <= 120_000 {
                if matches!(s.poll(t, false).unwrap(), Action::Retrieve) {
                    slots.insert(t);
                    break;
                }
                t += 100;
            }
        }
        assert!(
            slots.len() >= 4,
            "retrieval must land in several distinct slots; saw {slots:?}"
        );
        for slot in &slots {
            assert_eq!(
                slot % PAD_INTERVAL_MS,
                0,
                "a retrieval must occupy a scheduled slot, never its own"
            );
        }
    }

    #[test]
    fn retrieval_never_creates_an_off_grid_frame() {
        // The property that quantisation buys: no frame ever appears at a time
        // the constant-rate grid would not have produced one.
        let mut s = Scheduler::new(0).unwrap();
        s.set_connected(true, 0);
        let mut t = 0u64;
        while t < 300_000 {
            if !matches!(s.poll(t, false).unwrap(), Action::Wait(_)) {
                assert_eq!(t % PAD_INTERVAL_MS, 0, "off-grid frame at {t}");
            }
            t += 100;
        }
    }

    #[test]
    fn a_suspended_app_does_not_emit_a_catch_up_burst() {
        // On iOS the app is suspended for minutes at a time. Emitting the
        // backlog on resume would announce exactly when the user opened it.
        let mut s = Scheduler::new(0).unwrap();
        s.set_connected(true, 0);
        let _ = s.poll(0, false).unwrap();

        // Jump forward ten minutes, as if suspended.
        let resume = 600_000u64;
        let mut emissions = 0;
        for t in (resume..resume + 6000).step_by(100) {
            if !matches!(s.poll(t, false).unwrap(), Action::Wait(_)) {
                emissions += 1;
            }
        }
        assert!(
            emissions <= 2,
            "resume produced a burst of {emissions} emissions"
        );
    }

    #[test]
    fn reconnecting_resets_the_emission_phase() {
        let mut s = Scheduler::new(0).unwrap();
        s.set_connected(true, 0);
        s.poll(0, false).unwrap();
        s.set_connected(false, 1000);
        s.set_connected(true, 50_000);
        // The first frame after reconnecting is immediate, not at an offset
        // that would leak how long the app was away. Which *kind* of frame it
        // is depends on the jittered retrieval schedule and does not matter.
        assert!(!matches!(s.poll(50_000, false).unwrap(), Action::Wait(_)));
    }

    #[test]
    fn cover_traffic_stays_within_the_monthly_budget() {
        // NFR-PERF-03: under 50 MB/month. Two hours connected per day.
        let mut s = Scheduler::new(0).unwrap();
        s.set_connected(true, 0);
        let two_hours_ms = 2 * 60 * 60 * 1000u64;
        let mut t = 0u64;
        while t < two_hours_ms {
            let _ = s.poll(t, false).unwrap();
            t += 250;
        }
        let monthly = s.padding_bytes() * 30;
        assert!(
            monthly < 50 * 1024 * 1024,
            "cover traffic would be {} MB/month",
            monthly / 1024 / 1024
        );
    }

    #[test]
    fn wait_durations_are_never_zero() {
        let mut s = Scheduler::new(0).unwrap();
        s.set_connected(true, 0);
        s.poll(0, false).unwrap();
        if let Action::Wait(d) = s.poll(1, false).unwrap() {
            assert!(d.as_millis() > 0, "a zero wait would spin the CPU");
        }
    }
}
