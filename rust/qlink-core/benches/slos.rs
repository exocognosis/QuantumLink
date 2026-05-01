//! SLO scenario benchmarks: assert the three product.md targets and emit a
//! line of percentile data per scenario for the perf-baseline doc.
//!
//! Targets (from product.md "Performance, failure modes, and open questions"):
//!   - <300ms median direct connect (warm discovery)
//!   - <1s median post-event recovery (PathChanged → ready)
//!   - <2s median relay fallback activation
//!
//! Loopback is the floor: real-world numbers will be higher because of WAN
//! RTT, but if the loopback baseline ever exceeds the SLO, no real network
//! will save us.
//!
//! Runs as a `bench` (so `cargo bench` picks it up) but uses its own
//! sampling loop because each iteration is high-cost and high-setup —
//! criterion's per-bench overhead is poorly amortized here. The output is
//! plain `println!` lines that the perf-baseline workflow parses.

mod common;

use criterion::{criterion_group, criterion_main, Criterion};
use qlink_core::mesh_connection::{NetworkEvent, PathKind};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

const SLO_DIRECT_WARM_MS: u64 = 300;
const SLO_POST_EVENT_MS: u64 = 1_000;
const SLO_RELAY_FALLBACK_MS: u64 = 2_000;

const SAMPLE_COUNT: usize = 30;

fn run_direct_warm_scenario() {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        let env = common::build_direct_env(750, 3_000).await;
        // Prime the cache so subsequent connects are "warm" by the
        // product.md definition.
        let (warmup, _) = env.connector.connect(&env.remote_peer_id).await.unwrap();
        drop(warmup);

        let mut samples: Vec<Duration> = Vec::with_capacity(SAMPLE_COUNT);
        for _ in 0..SAMPLE_COUNT {
            let started = Instant::now();
            let (link, outcome) = env
                .connector
                .connect(&env.remote_peer_id)
                .await
                .expect("warm direct connect must succeed");
            samples.push(started.elapsed());
            assert!(outcome.used_cached_path);
            assert_eq!(outcome.path_kind, PathKind::Direct);
            drop(link);
        }
        let pct = common::percentiles(samples);
        pct.print("slo.direct_warm");
        assert!(
            pct.p50 < Duration::from_millis(SLO_DIRECT_WARM_MS),
            "direct-warm p50 {:?} exceeds SLO {SLO_DIRECT_WARM_MS}ms",
            pct.p50
        );
    });
}

fn run_post_event_recovery_scenario() {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        let env = common::build_direct_env(750, 3_000).await;
        // Establish the initial path so the cache is warm before the
        // simulated network event.
        let (warmup, _) = env.connector.connect(&env.remote_peer_id).await.unwrap();
        drop(warmup);

        let mut samples: Vec<Duration> = Vec::with_capacity(SAMPLE_COUNT);
        for _ in 0..SAMPLE_COUNT {
            // Simulate a network change: connector clears its cache; SLO
            // measures from "event arrives" to "we're ready again".
            env.connector
                .handle_network_event(NetworkEvent::PathChanged);
            let started = Instant::now();
            let (link, outcome) = env
                .connector
                .connect(&env.remote_peer_id)
                .await
                .expect("post-event reconnect must succeed");
            samples.push(started.elapsed());
            assert_eq!(outcome.path_kind, PathKind::Direct);
            drop(link);
        }
        let pct = common::percentiles(samples);
        pct.print("slo.post_event_recovery");
        assert!(
            pct.p50 < Duration::from_millis(SLO_POST_EVENT_MS),
            "post-event-recovery p50 {:?} exceeds SLO {SLO_POST_EVENT_MS}ms",
            pct.p50
        );
    });
}

fn run_relay_fallback_scenario() {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        // Direct probe budget = 200ms; fallback to relay must follow.
        let env = common::build_relay_only_env(200, 2_000).await;

        let mut samples: Vec<Duration> = Vec::with_capacity(SAMPLE_COUNT);
        for _ in 0..SAMPLE_COUNT {
            let started = Instant::now();
            let (link, outcome) = env
                .connector
                .connect(&env.remote_peer_id)
                .await
                .expect("relay fallback must succeed when no direct path works");
            samples.push(started.elapsed());
            assert_eq!(outcome.path_kind, PathKind::Relay);
            drop(link);
        }
        let pct = common::percentiles(samples);
        pct.print("slo.relay_fallback");
        assert!(
            pct.p50 < Duration::from_millis(SLO_RELAY_FALLBACK_MS),
            "relay-fallback p50 {:?} exceeds SLO {SLO_RELAY_FALLBACK_MS}ms",
            pct.p50
        );
    });
}

fn bench_slos(_c: &mut Criterion) {
    println!("# QuantumLink SLO scenarios — product.md targets");
    run_direct_warm_scenario();
    run_post_event_recovery_scenario();
    run_relay_fallback_scenario();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_millis(100));
    targets = bench_slos
}
criterion_main!(benches);
