//! Decoy connections + client identity rotation — incremental
//! anonymity polish on top of the layered defenses.
//!
//! ## Decoy connections
//!
//! Even with onion routing and cover traffic, an observer with
//! enough vantage can profile a user's interests by watching the
//! domains their tunnel reaches over time. If the user only ever
//! visits, say, three obscure activist forums, that pattern
//! eventually becomes recognizable across sessions.
//!
//! Decoy connections muddy this signal by mixing real traffic
//! with periodic, randomized fetches to popular destinations the
//! user doesn't actually care about. From an interest-profiling
//! standpoint the user's traffic now looks indistinguishable from
//! "anyone using the internet."
//!
//! Defaults aim to be cheap (~1 fetch per 5-30 minutes, only
//! when the tunnel is otherwise idle) and benign (popular sites
//! that handle bot traffic gracefully).
//!
//! ## Identity rotation
//!
//! QuantumLink peer identity is bound to the device keypair. Long-
//! lived keys mean an exit peer (or anyone with subpoena power
//! over one) can tell that "the same user came back" across
//! sessions, even if individual sessions are perfectly anonymous.
//!
//! Rotation regenerates the device's hybrid X25519+ML-KEM keypair
//! on a schedule — daily by default for users in adversarial
//! environments, monthly for normal users. Each rotation produces
//! a new fingerprint that peers must re-verify, so it's not free
//! UX-wise; the GUI prompts before each rotation in the default
//! "monthly" mode and just does it silently in "daily" mode.
//!
//! Rotation does NOT delete past traffic — anything captured
//! before rotation remains decryptable with the captured-at-
//! rotation-time keys (forward secrecy from the per-session key
//! schedule already protects there). What it DOES do is sever
//! cross-session linkability going forward.

use std::time::Duration;

/// Curated list of decoy targets. Picked for three traits:
///
/// 1. **Universally popular**: most ISPs see them in nearly every
///    user's traffic, so visiting them adds zero distinguishability.
/// 2. **Bot-friendly**: handle automated/repeated requests gracefully.
///    No CAPTCHAs, no rate-limit bans, no "are you a robot" interstitials.
/// 3. **Stable**: unlikely to disappear or change behavior in a way
///    that would make the decoy traffic conspicuous.
///
/// We keep this list small (10 entries) so it ships compiled-in
/// without bloat. Operators can override with their own pool via
/// [`DecoyPool::custom`].
const DEFAULT_DECOY_TARGETS: &[&str] = &[
    "https://www.google.com/",
    "https://www.wikipedia.org/",
    "https://www.youtube.com/",
    "https://github.com/",
    "https://www.cloudflare.com/",
    "https://www.amazon.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://duckduckgo.com/",
    "https://en.wikipedia.org/wiki/Special:Random",
];

/// Pool of decoy targets the scheduler picks from.
#[derive(Debug, Clone)]
pub struct DecoyPool {
    targets: Vec<String>,
}

impl DecoyPool {
    /// Use the built-in popular-sites list.
    pub fn default_pool() -> Self {
        Self {
            targets: DEFAULT_DECOY_TARGETS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Use an operator-provided list. Useful for managed
    /// deployments where IT wants to pin exactly which decoys are
    /// fetched (e.g. only the company's own public homepage).
    pub fn custom(targets: Vec<String>) -> Self {
        Self { targets }
    }

    /// Pick one target at "random" — we use the supplied counter
    /// to keep the function pure and testable. Production
    /// integration drives the counter from the same RNG that
    /// powers session nonces.
    pub fn pick(&self, counter: u64) -> Option<&str> {
        if self.targets.is_empty() {
            return None;
        }
        Some(&self.targets[counter as usize % self.targets.len()])
    }

    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

/// Cadence preset for decoy fetches. The scheduler waits a random
/// interval bounded by the preset's min/max before each fetch so
/// observers can't rely on regular timing to identify decoys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyCadence {
    Off,
    /// One decoy every 30–120 seconds. For users in active
    /// surveillance environments where coarse timing matters.
    Aggressive,
    /// One decoy every 5–30 minutes. Default for users who care
    /// about interest-profiling defense without burning bandwidth.
    Steady,
    /// One decoy every 1–6 hours. Light pattern coverage with
    /// minimal bandwidth cost.
    Light,
    /// Operator-defined min/max in seconds.
    Custom { min_secs: u64, max_secs: u64 },
}

impl DecoyCadence {
    /// Returns (min, max) interval bounds. Off returns (0, 0)
    /// signaling the scheduler to stay silent.
    pub fn bounds(&self) -> (Duration, Duration) {
        match self {
            Self::Off => (Duration::ZERO, Duration::ZERO),
            Self::Aggressive => (Duration::from_secs(30), Duration::from_secs(120)),
            Self::Steady => (Duration::from_secs(5 * 60), Duration::from_secs(30 * 60)),
            Self::Light => (Duration::from_secs(60 * 60), Duration::from_secs(6 * 60 * 60)),
            Self::Custom { min_secs, max_secs } => (
                Duration::from_secs(*min_secs),
                Duration::from_secs(*max_secs),
            ),
        }
    }

    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Pick the next interval given the cadence and a counter that
/// substitutes for an RNG. Range is inclusive of min, exclusive
/// of max, so a (30, 120) bound never sleeps less than 30s.
pub fn next_interval(cadence: DecoyCadence, counter: u64) -> Duration {
    let (lo, hi) = cadence.bounds();
    if hi == Duration::ZERO {
        return Duration::ZERO;
    }
    let span_secs = (hi.as_secs().saturating_sub(lo.as_secs())).max(1);
    let pick = counter % span_secs;
    lo + Duration::from_secs(pick)
}

// ---------------------------------------------------------------------------
// Identity rotation policy
// ---------------------------------------------------------------------------

/// How frequently the device keypair rotates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPolicy {
    /// Don't rotate automatically. Manual via Configuration → Security.
    Manual,
    /// Rotate weekly. Default for casual users; still gets new
    /// fingerprints often enough to defeat long-window linkability.
    Weekly,
    /// Rotate daily. For users in adversarial environments. UX
    /// cost: peers must re-verify the new fingerprint daily; we
    /// streamline by auto-publishing the new fingerprint to the
    /// rendezvous service signed by the old key for a one-day
    /// transition window.
    Daily,
    /// Custom cadence in seconds.
    CustomSeconds(u64),
}

impl RotationPolicy {
    pub fn interval(&self) -> Option<Duration> {
        match self {
            Self::Manual => None,
            Self::Weekly => Some(Duration::from_secs(7 * 86400)),
            Self::Daily => Some(Duration::from_secs(86400)),
            Self::CustomSeconds(s) => Some(Duration::from_secs(*s)),
        }
    }
}

/// Decision returned by [`should_rotate_now`] — used by the GUI's
/// background timer to know whether to kick off rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationDecision {
    DueNow,
    NotYet { remaining: Duration },
    PolicyDisabled,
}

/// Given the rotation policy, the time the current key was created,
/// and "now," return whether to rotate.
pub fn should_rotate_now(
    policy: RotationPolicy,
    key_created_secs_ago: Duration,
) -> RotationDecision {
    let interval = match policy.interval() {
        Some(i) => i,
        None => return RotationDecision::PolicyDisabled,
    };
    if key_created_secs_ago >= interval {
        RotationDecision::DueNow
    } else {
        RotationDecision::NotYet {
            remaining: interval - key_created_secs_ago,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_is_nonempty() {
        let pool = DecoyPool::default_pool();
        assert!(!pool.is_empty());
        assert!(pool.len() >= 5, "default pool should have ≥5 decoys");
    }

    #[test]
    fn pick_cycles_through_pool() {
        let pool = DecoyPool::default_pool();
        let picks: Vec<&str> = (0..pool.len() as u64).map(|i| pool.pick(i).unwrap()).collect();
        let unique: std::collections::HashSet<_> = picks.iter().collect();
        assert_eq!(unique.len(), pool.len(), "every counter picks a distinct target across one full cycle");
    }

    #[test]
    fn cadence_off_yields_zero_interval() {
        assert_eq!(next_interval(DecoyCadence::Off, 0), Duration::ZERO);
        assert!(!DecoyCadence::Off.is_active());
    }

    #[test]
    fn cadence_aggressive_within_bounds() {
        let (lo, hi) = DecoyCadence::Aggressive.bounds();
        for i in 0..1000 {
            let pick = next_interval(DecoyCadence::Aggressive, i);
            assert!(pick >= lo && pick <= hi, "pick {pick:?} outside [{lo:?}, {hi:?}]");
        }
    }

    #[test]
    fn rotation_manual_disables() {
        let decision = should_rotate_now(RotationPolicy::Manual, Duration::from_secs(86400 * 365));
        assert_eq!(decision, RotationDecision::PolicyDisabled);
    }

    #[test]
    fn rotation_due_when_past_interval() {
        let decision = should_rotate_now(RotationPolicy::Daily, Duration::from_secs(86400 + 1));
        assert_eq!(decision, RotationDecision::DueNow);
    }

    #[test]
    fn rotation_not_due_when_within_interval() {
        let decision = should_rotate_now(RotationPolicy::Daily, Duration::from_secs(3600));
        match decision {
            RotationDecision::NotYet { remaining } => {
                assert!(remaining.as_secs() <= 86400);
                assert!(remaining.as_secs() > 80000);
            }
            other => panic!("expected NotYet, got {other:?}"),
        }
    }
}
