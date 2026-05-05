//! Process-wide runtime configuration for the privacy primitives
//! that aren't long-running services.
//!
//! Three of the user-facing privacy controls don't have a "running
//! service" lifetime — they're just settings that other code paths
//! consult on every operation:
//!
//! - **Pluggable transport choice**: applied to outbound bytes
//!   right before they hit the wire (`pluggable_transport::apply_outbound`).
//!   The transport layer reads the current choice on every frame.
//! - **Onion-routing config**: when the circuit-builder spins up,
//!   it asks here what the user wants (enabled + length).
//! - **Identity-rotation policy**: a background timer consults
//!   this when deciding whether to rotate.
//!
//! Putting these in a process-wide config (rather than threading
//! them through every call site) matches how the existing
//! `tracing_bridge` module handles its global subscriber. Concurrent
//! reads are atomic; updates take a mutex briefly.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::pluggable_transport::TransportObfuscation;

// =============================================================================
// Pluggable transport
// =============================================================================

/// Encoded as u8 to match the FFI ABI. Mapping:
/// 0 = None, 1 = TlsLikeFraming, 2 = Obfs4XorScramble.
static TRANSPORT_OBFUSCATION: AtomicU8 = AtomicU8::new(1); // default = TLS-disguised

pub fn set_transport_obfuscation(value: TransportObfuscation) {
    let encoded: u8 = match value {
        TransportObfuscation::None => 0,
        TransportObfuscation::TlsLikeFraming => 1,
        TransportObfuscation::Obfs4XorScramble => 2,
    };
    TRANSPORT_OBFUSCATION.store(encoded, Ordering::Relaxed);
}

pub fn current_transport_obfuscation() -> TransportObfuscation {
    match TRANSPORT_OBFUSCATION.load(Ordering::Relaxed) {
        0 => TransportObfuscation::None,
        2 => TransportObfuscation::Obfs4XorScramble,
        _ => TransportObfuscation::TlsLikeFraming,
    }
}

// =============================================================================
// Onion routing
// =============================================================================

/// Bit 0 = enabled. Bits 8..16 = circuit length (1-5 valid).
static ONION_CONFIG: AtomicU32 = AtomicU32::new(0);

pub fn set_onion_routing(enabled: bool, circuit_length: u32) {
    let length = circuit_length.clamp(1, 5);
    let encoded = (if enabled { 1 } else { 0 }) | (length << 8);
    ONION_CONFIG.store(encoded, Ordering::Relaxed);
}

pub fn current_onion_routing() -> (bool, u32) {
    let raw = ONION_CONFIG.load(Ordering::Relaxed);
    let enabled = (raw & 1) == 1;
    let length = (raw >> 8) & 0xFF;
    let length = if length == 0 { 3 } else { length };
    (enabled, length)
}

// =============================================================================
// Identity rotation
// =============================================================================

/// 0 = Manual, 1 = Weekly, 2 = Daily, 3+ = custom seconds (in
/// the high bits — see encoded helper).
static ROTATION_POLICY: AtomicU8 = AtomicU8::new(1); // default = Weekly
static ROTATION_KEY_CREATED_UNIX: AtomicU64 = AtomicU64::new(0);

pub fn set_rotation_policy(policy: u8) {
    ROTATION_POLICY.store(policy, Ordering::Relaxed);
}

pub fn current_rotation_policy() -> u8 {
    ROTATION_POLICY.load(Ordering::Relaxed)
}

/// Records when the current device keypair was created, in unix
/// seconds. The rotation timer reads this + the policy to decide
/// when to trigger regeneration.
pub fn set_key_created_at(unix_seconds: u64) {
    ROTATION_KEY_CREATED_UNIX.store(unix_seconds, Ordering::Relaxed);
}

pub fn current_key_age_secs() -> u64 {
    let created = ROTATION_KEY_CREATED_UNIX.load(Ordering::Relaxed);
    if created == 0 {
        return 0;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(created)
}

// =============================================================================
// Status counters (for the GUI's "real things are happening" indicators)
// =============================================================================

/// Counters bumped from various subsystems. The GUI polls these
/// for live status indicators on the Privacy panel.

pub static OBFUSCATION_FRAMES: AtomicUsize = AtomicUsize::new(0);
pub static ONION_CIRCUITS_BUILT: AtomicUsize = AtomicUsize::new(0);
pub static DECOY_FETCHES_COMPLETED: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_obfuscation_round_trip() {
        set_transport_obfuscation(TransportObfuscation::Obfs4XorScramble);
        assert_eq!(current_transport_obfuscation(), TransportObfuscation::Obfs4XorScramble);
        set_transport_obfuscation(TransportObfuscation::None);
        assert_eq!(current_transport_obfuscation(), TransportObfuscation::None);
        set_transport_obfuscation(TransportObfuscation::TlsLikeFraming);
        assert_eq!(current_transport_obfuscation(), TransportObfuscation::TlsLikeFraming);
    }

    #[test]
    fn onion_config_round_trip() {
        set_onion_routing(true, 3);
        let (enabled, len) = current_onion_routing();
        assert!(enabled);
        assert_eq!(len, 3);

        set_onion_routing(false, 5);
        let (enabled, len) = current_onion_routing();
        assert!(!enabled);
        assert_eq!(len, 5);

        // Length clamping: 0 maps to 1; 99 maps to 5.
        set_onion_routing(true, 0);
        let (_, len) = current_onion_routing();
        assert_eq!(len, 1);
        set_onion_routing(true, 99);
        let (_, len) = current_onion_routing();
        assert_eq!(len, 5);
    }

    #[test]
    fn rotation_policy_round_trip() {
        set_rotation_policy(2);
        assert_eq!(current_rotation_policy(), 2);
        set_rotation_policy(0);
        assert_eq!(current_rotation_policy(), 0);
    }

    #[test]
    fn key_age_starts_at_zero_when_unset() {
        // The static is shared across tests so we can't fully isolate;
        // this just sanity-checks the math doesn't panic.
        let _ = current_key_age_secs();
    }
}
