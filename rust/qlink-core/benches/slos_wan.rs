//! SLO scenarios re-run through the synthetic WAN harness.
//!
//! Where `slos.rs` measures product targets at loopback latency (the
//! floor; if we can't meet the SLO at zero RTT, no real network will
//! help), this file injects realistic delay / loss / jitter via
//! [`qlink_core::synthetic_wan::WanProxy`] and reports the resulting
//! percentiles per profile.
//!
//! Unlike `slos.rs`, we deliberately do NOT assert SLO targets at WAN
//! profiles — degraded networks may legitimately fail the spec's
//! loopback-anchored numbers, and pretending otherwise would just
//! produce flaky CI failures. The point is honest measurement.
//!
//! Output: one line per (scenario × profile), e.g.
//!   slo.direct_warm.cable: n=15 p50=85.4ms p90=92.1ms p99=130.5ms max=130.5ms
//!
//! These lines are surfaced in the perf CI workflow's job summary and
//! committed numbers live in `docs/perf-baseline.md`.

mod common;

use criterion::{criterion_group, criterion_main, Criterion};
use qlink_core::{
    mesh_connection::{NetworkEvent, PathKind},
    synthetic_wan::WanProfile,
};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

const SAMPLE_COUNT: usize = 15;

fn run_direct_warm_through_wan(profile: WanProfile) {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        // Probe and overall budgets sized to absorb the profile's
        // round-trip time plus QUIC handshake (~3 RTTs) plus headroom.
        let rtt_ms = (profile.one_way_delay.as_millis() as u64) * 2;
        let probe_ms = 750 + rtt_ms * 4;
        let deadline_ms = 3_000 + rtt_ms * 6;
        let env = common::build_direct_env_via_wan(probe_ms, deadline_ms, profile).await;

        // Warm-up: prime the cache so subsequent connects are "warm".
        let (warmup, _outcome) = env.connector.connect(&env.remote_peer_id).await.unwrap();
        drop(warmup);

        let mut samples: Vec<Duration> = Vec::with_capacity(SAMPLE_COUNT);
        let mut direct_count = 0_usize;
        let mut relay_count = 0_usize;
        for _ in 0..SAMPLE_COUNT {
            let started = Instant::now();
            let result = env.connector.connect(&env.remote_peer_id).await;
            let elapsed = started.elapsed();
            match result {
                Ok((link, outcome)) => {
                    samples.push(elapsed);
                    match outcome.path_kind {
                        PathKind::Direct => direct_count += 1,
                        PathKind::Relay => relay_count += 1,
                    }
                    drop(link);
                }
                Err(_) => samples.push(Duration::from_millis(deadline_ms)),
            }
        }
        let pct = common::percentiles(samples);
        pct.print(&format!(
            "slo.direct_warm.{} (direct={direct_count} relay={relay_count})",
            profile.name
        ));
    });
}

fn run_post_event_recovery_through_wan(profile: WanProfile) {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        let rtt_ms = (profile.one_way_delay.as_millis() as u64) * 2;
        let probe_ms = 750 + rtt_ms * 4;
        let deadline_ms = 3_000 + rtt_ms * 6;
        let env = common::build_direct_env_via_wan(probe_ms, deadline_ms, profile).await;

        let (warmup, _) = env.connector.connect(&env.remote_peer_id).await.unwrap();
        drop(warmup);

        let mut samples: Vec<Duration> = Vec::with_capacity(SAMPLE_COUNT);
        let mut direct_count = 0_usize;
        let mut relay_count = 0_usize;
        for _ in 0..SAMPLE_COUNT {
            env.connector
                .handle_network_event(NetworkEvent::PathChanged);
            let started = Instant::now();
            match env.connector.connect(&env.remote_peer_id).await {
                Ok((link, outcome)) => {
                    samples.push(started.elapsed());
                    match outcome.path_kind {
                        PathKind::Direct => direct_count += 1,
                        PathKind::Relay => relay_count += 1,
                    }
                    drop(link);
                }
                Err(_) => samples.push(Duration::from_millis(deadline_ms)),
            }
        }
        let pct = common::percentiles(samples);
        pct.print(&format!(
            "slo.post_event_recovery.{} (direct={direct_count} relay={relay_count})",
            profile.name
        ));
    });
}

fn run_relay_fallback_through_wan(profile: WanProfile) {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        // Direct probe budget tied to the profile's RTT — a too-short
        // budget produces immediate-fallback behavior that doesn't
        // reflect what the connector would do on a real network.
        let rtt_ms = (profile.one_way_delay.as_millis() as u64) * 2;
        let probe_ms = (rtt_ms.saturating_mul(2)).max(200);
        let deadline_ms = 2_000 + rtt_ms * 4;
        let env = common::build_relay_only_env_via_wan(probe_ms, deadline_ms, profile).await;

        let mut samples: Vec<Duration> = Vec::with_capacity(SAMPLE_COUNT);
        for _ in 0..SAMPLE_COUNT {
            let started = Instant::now();
            match env.connector.connect(&env.remote_peer_id).await {
                Ok((link, outcome)) => {
                    samples.push(started.elapsed());
                    assert_eq!(outcome.path_kind, PathKind::Relay);
                    drop(link);
                }
                Err(_) => samples.push(Duration::from_millis(deadline_ms)),
            }
        }
        let pct = common::percentiles(samples);
        pct.print(&format!("slo.relay_fallback.{}", profile.name));
    });
}

fn bench_slos_wan(_c: &mut Criterion) {
    println!("# QuantumLink SLO scenarios — synthetic WAN profiles");

    for profile in [WanProfile::LAN, WanProfile::CABLE, WanProfile::MOBILE_3G] {
        run_direct_warm_through_wan(profile);
        run_post_event_recovery_through_wan(profile);
        run_relay_fallback_through_wan(profile);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_millis(100));
    targets = bench_slos_wan
}
criterion_main!(benches);
