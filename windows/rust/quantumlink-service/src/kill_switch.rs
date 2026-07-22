//! Strict-mode kill-switch watchdog — Rust port of
//! `QuantumLinkKit/KillSwitchWatchdog.swift`.
//!
//! The pump's per-batch kill switch already drops protected-prefix
//! packets while the transport is unhealthy, but it does not by itself
//! bring the tunnel down — a strict deployment that loses connectivity
//! would stay "up but dropping" indefinitely. The watchdog closes that
//! gap: once the transport has been unhealthy for at least `deadline`,
//! [`KillSwitchWatchdog::evaluate`] reports `Fire` exactly once (until a
//! recovery re-arms it) and the engine tears the tunnel down while the
//! WFP filters keep protected prefixes blocked.
//!
//! `FailClosed` is a no-op for this type — drop behavior is the only
//! contract that policy makes.

use quantumlink_proto::models::KillSwitchPolicy;
use std::time::{Duration, Instant};

pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogVerdict {
    /// Nothing to do (healthy, policy is fail-closed, or already fired).
    Idle,
    /// Unhealthy but still inside the deadline window.
    Armed,
    /// Deadline expired — caller must tear the tunnel down now.
    Fire,
}

pub struct KillSwitchWatchdog {
    policy: KillSwitchPolicy,
    deadline: Duration,
    clock: Box<dyn Fn() -> Instant + Send>,
    not_ready_since: Option<Instant>,
    has_fired: bool,
}

impl KillSwitchWatchdog {
    pub fn new(policy: KillSwitchPolicy, deadline: Duration) -> Self {
        Self::with_clock(policy, deadline, Box::new(Instant::now))
    }

    /// Clock-injectable constructor so tests can drive the watchdog
    /// deterministically without sleeping.
    pub fn with_clock(
        policy: KillSwitchPolicy,
        deadline: Duration,
        clock: Box<dyn Fn() -> Instant + Send>,
    ) -> Self {
        Self {
            policy,
            deadline,
            clock,
            not_ready_since: None,
            has_fired: false,
        }
    }

    /// Re-evaluates the strict-mode deadline against the supplied
    /// transport-health bit. Idempotent; safe to call on any cadence.
    pub fn evaluate(&mut self, transport_ready: bool) -> WatchdogVerdict {
        if self.policy != KillSwitchPolicy::Strict {
            return WatchdogVerdict::Idle;
        }
        if transport_ready {
            self.not_ready_since = None;
            self.has_fired = false;
            return WatchdogVerdict::Idle;
        }
        let now = (self.clock)();
        let first_seen = *self.not_ready_since.get_or_insert(now);
        if self.has_fired {
            return WatchdogVerdict::Idle;
        }
        if now.duration_since(first_seen) >= self.deadline {
            self.has_fired = true;
            WatchdogVerdict::Fire
        } else {
            WatchdogVerdict::Armed
        }
    }

    pub fn is_armed(&self) -> bool {
        self.not_ready_since.is_some()
    }

    pub fn has_fired(&self) -> bool {
        self.has_fired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn manual_clock() -> (Arc<Mutex<Instant>>, Box<dyn Fn() -> Instant + Send>) {
        let now = Arc::new(Mutex::new(Instant::now()));
        let clock_now = Arc::clone(&now);
        (now, Box::new(move || *clock_now.lock().unwrap()))
    }

    #[test]
    fn fail_closed_never_fires() {
        let (now, clock) = manual_clock();
        let mut watchdog = KillSwitchWatchdog::with_clock(
            KillSwitchPolicy::FailClosed,
            Duration::from_secs(30),
            clock,
        );
        assert_eq!(watchdog.evaluate(false), WatchdogVerdict::Idle);
        *now.lock().unwrap() += Duration::from_secs(3600);
        assert_eq!(watchdog.evaluate(false), WatchdogVerdict::Idle);
        assert!(!watchdog.is_armed());
    }

    #[test]
    fn strict_fires_once_after_deadline_and_rearms_on_recovery() {
        let (now, clock) = manual_clock();
        let mut watchdog = KillSwitchWatchdog::with_clock(
            KillSwitchPolicy::Strict,
            Duration::from_secs(30),
            clock,
        );

        assert_eq!(watchdog.evaluate(false), WatchdogVerdict::Armed);
        *now.lock().unwrap() += Duration::from_secs(29);
        assert_eq!(watchdog.evaluate(false), WatchdogVerdict::Armed);
        *now.lock().unwrap() += Duration::from_secs(2);
        assert_eq!(watchdog.evaluate(false), WatchdogVerdict::Fire);
        // Fires exactly once.
        assert_eq!(watchdog.evaluate(false), WatchdogVerdict::Idle);
        assert!(watchdog.has_fired());

        // Recovery disarms and re-arms for the next failure.
        assert_eq!(watchdog.evaluate(true), WatchdogVerdict::Idle);
        assert!(!watchdog.has_fired());
        assert_eq!(watchdog.evaluate(false), WatchdogVerdict::Armed);
        *now.lock().unwrap() += Duration::from_secs(31);
        assert_eq!(watchdog.evaluate(false), WatchdogVerdict::Fire);
    }
}
