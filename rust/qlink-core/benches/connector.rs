//! Micro-benchmarks for `MeshConnector` hot paths: cold and warm direct
//! connect, plus reconnect after cache invalidation.
//!
//! Each iteration drops the returned `MeshLink` (and therefore tears down
//! the QUIC session). That's intentional — it measures the realistic cost
//! of bringing up a fresh end-to-end path, which is what the SLOs are
//! about. A v2 of these benches could add session pooling for "steady
//! state throughput after warm-up".

mod common;

use criterion::{criterion_group, criterion_main, Criterion};
use std::{hint::black_box, time::Duration};
use tokio::runtime::Runtime;

fn bench_cold_connect(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let env = runtime.block_on(common::build_direct_env(750, 3_000));
    let mut group = c.benchmark_group("connector");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8))
        .warm_up_time(Duration::from_secs(2));
    group.bench_function("cold_direct_connect", |b| {
        b.to_async(&runtime).iter(|| async {
            // Invalidate cache so each iteration is "cold" (no last-good
            // entry). The remote record is still cached in rendezvous, so
            // this measures: rendezvous lookup + paced probes + QUIC
            // handshake.
            env.connector.cache().clear();
            let (link, outcome) = env
                .connector
                .connect(&env.remote_peer_id)
                .await
                .expect("cold connect must succeed");
            black_box(outcome.total_elapsed);
            drop(link);
        });
    });
    group.finish();
}

fn bench_warm_connect(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let env = runtime.block_on(common::build_direct_env(750, 3_000));
    // Warm up the cache once.
    runtime.block_on(async {
        let (link, _) = env.connector.connect(&env.remote_peer_id).await.unwrap();
        drop(link);
    });

    let mut group = c.benchmark_group("connector");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8))
        .warm_up_time(Duration::from_secs(2));
    group.bench_function("warm_direct_connect", |b| {
        b.to_async(&runtime).iter(|| async {
            // Cache is preserved; the connector reorders the cached
            // candidate first and probes it immediately at offset=0.
            let (link, outcome) = env
                .connector
                .connect(&env.remote_peer_id)
                .await
                .expect("warm connect must succeed");
            assert!(outcome.used_cached_path, "warm path must hit cache");
            black_box(outcome.total_elapsed);
            drop(link);
        });
    });
    group.finish();
}

fn bench_reconnect_after_event(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let env = runtime.block_on(common::build_direct_env(750, 3_000));
    runtime.block_on(async {
        let (link, _) = env.connector.connect(&env.remote_peer_id).await.unwrap();
        drop(link);
    });

    let mut group = c.benchmark_group("connector");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8))
        .warm_up_time(Duration::from_secs(2));
    group.bench_function("reconnect_post_event", |b| {
        b.to_async(&runtime).iter(|| async {
            // Mirror what happens after a system PathChanged: the cache is
            // dropped, then the caller re-runs the full connect.
            env.connector
                .handle_network_event(qlink_core::mesh_connection::NetworkEvent::PathChanged);
            let (link, outcome) = env.connector.connect(&env.remote_peer_id).await.unwrap();
            black_box(outcome.total_elapsed);
            drop(link);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_cold_connect,
    bench_warm_connect,
    bench_reconnect_after_event
);
criterion_main!(benches);
