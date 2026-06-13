//! Local data-plane smoke test — the Windows analog of the macOS
//! `TransportSmokeRunner` and the `qlinkctl quic-loopback` check.
//!
//! Runs the full engine (loopback adapter + local echo transport on dev
//! hosts, or the same code paths under Wintun on Windows when invoked
//! with a platform), pushes synthetic protected and unprotected packets
//! through, and asserts the fail-closed invariants:
//!
//! - protected packets round-trip encode -> decode and come back out
//! - unprotected packets are dropped by core route policy
//! - counters account for every packet observed
//!
//! Exits non-zero on any violation so CI and the pre-release runbook can
//! gate on it.

use crate::adapter::LoopbackAdapter;
use crate::engine::{EngineError, PlatformNetwork, TunnelEngine};
use crate::secret_store::InMemorySecretStore;
use quantumlink_proto::models::TunnelConfiguration;
use quantumlink_proto::privacy;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CLI_SMOKE_STACK_SIZE: usize = 8 * 1024 * 1024;

pub struct SmokeReport {
    pub passed: bool,
    pub summary: serde_json::Value,
}

struct SmokePlatform {
    adapter: Mutex<Option<Arc<LoopbackAdapter>>>,
}

impl PlatformNetwork for SmokePlatform {
    fn create_adapter(
        &self,
        _config: &TunnelConfiguration,
    ) -> Result<Arc<dyn crate::adapter::TunnelAdapter>, EngineError> {
        let adapter = Arc::new(LoopbackAdapter::default());
        *self.adapter.lock().unwrap() = Some(Arc::clone(&adapter));
        Ok(adapter)
    }
    fn apply_network_config(
        &self,
        _adapter: &Arc<dyn crate::adapter::TunnelAdapter>,
        _config: &TunnelConfiguration,
    ) -> Result<(), EngineError> {
        Ok(())
    }
    fn engage_kill_switch(&self, _config: &TunnelConfiguration) -> Result<(), EngineError> {
        Ok(())
    }
    fn disengage_kill_switch(&self) -> Result<(), EngineError> {
        Ok(())
    }
    fn kill_switch_engaged(&self) -> bool {
        true
    }
    fn teardown(
        &self,
        adapter: &Arc<dyn crate::adapter::TunnelAdapter>,
        _config: &TunnelConfiguration,
    ) -> Result<(), EngineError> {
        adapter.shutdown();
        Ok(())
    }
}

fn ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[3] = 20;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[100, 127, 0, 2]);
    packet[16..20].copy_from_slice(&destination);
    packet
}

pub fn run_loopback_smoke() -> SmokeReport {
    let platform = Arc::new(SmokePlatform {
        adapter: Mutex::new(None),
    });
    let engine = TunnelEngine::new(
        Arc::new(InMemorySecretStore::default()),
        Arc::clone(&platform) as Arc<dyn PlatformNetwork>,
        std::env::temp_dir(),
    );

    let mut config = privacy::default_tunnel_configuration();
    config.protected_routes = vec!["100.127.0.0/16".to_string()];

    if let Err(error) = engine.connect(config) {
        return SmokeReport {
            passed: false,
            summary: serde_json::json!({ "error": error.to_string() }),
        };
    }
    let adapter = platform.adapter.lock().unwrap().clone().expect("adapter");

    const PROTECTED_COUNT: usize = 32;
    for index in 0..PROTECTED_COUNT {
        adapter.inject_inbound(ipv4_packet([100, 127, 1, index as u8]));
    }
    adapter.inject_inbound(ipv4_packet([8, 8, 8, 8])); // must be dropped

    let mut round_tripped = 0usize;
    let deadline = Instant::now() + Duration::from_secs(10);
    while round_tripped < PROTECTED_COUNT && Instant::now() < deadline {
        round_tripped += adapter.drain_outbound().len();
        std::thread::sleep(Duration::from_millis(10));
    }
    // Give the unprotected packet a chance to (incorrectly) appear.
    std::thread::sleep(Duration::from_millis(100));
    let stragglers = adapter.drain_outbound().len();

    let status = engine.status();
    let pump = status.pump.clone().unwrap_or_default();
    engine.disconnect();

    let passed = round_tripped == PROTECTED_COUNT
        && stragglers == 0
        && pump.dropped_unprotected == 1
        && pump.queued_for_transport == PROTECTED_COUNT as u64
        && pump.tunnel_packets_emitted == PROTECTED_COUNT as u64
        && pump.failed_submissions == 0;

    SmokeReport {
        passed,
        summary: serde_json::json!({
            "passed": passed,
            "protectedInjected": PROTECTED_COUNT,
            "roundTripped": round_tripped,
            "unexpectedExtraPackets": stragglers,
            "pump": pump,
        }),
    }
}

pub fn run_loopback_smoke_on_cli_stack() -> Result<SmokeReport, String> {
    std::thread::Builder::new()
        .name("quantumlink-service-smoke".to_string())
        .stack_size(CLI_SMOKE_STACK_SIZE)
        .spawn(run_loopback_smoke)
        .map_err(|error| error.to_string())?
        .join()
        .map_err(|panic| {
            if let Some(message) = panic.downcast_ref::<&str>() {
                (*message).to_string()
            } else if let Some(message) = panic.downcast_ref::<String>() {
                message.clone()
            } else {
                "smoke thread panicked".to_string()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_smoke_passes() {
        let report = run_loopback_smoke();
        assert!(report.passed, "smoke failed: {}", report.summary);
    }

    #[test]
    fn loopback_smoke_passes_on_cli_stack() {
        let report = run_loopback_smoke_on_cli_stack().expect("smoke thread joins");
        assert!(report.passed, "smoke failed: {}", report.summary);
    }
}
