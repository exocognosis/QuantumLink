//! Lower-bound microbench for the ICE STUN binding-request round-trip.
//! Measures the cost of: build authenticated request → send → wait for
//! response → verify FINGERPRINT + MESSAGE-INTEGRITY. Loopback only —
//! provides the floor for what an ICE check costs in this codebase, which
//! the connector benches add on top of.

mod common;

use criterion::{criterion_group, criterion_main, Criterion};
use qlink_core::ice::{perform_ice_check, spawn_dev_ice_responder, IceCheckRequest};
use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, runtime::Runtime};

fn bench_ice_check_loopback(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let remote_credentials = common::fresh_ice_credentials();
    let local_credentials = common::fresh_ice_credentials();

    let responder = runtime
        .block_on(spawn_dev_ice_responder(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            remote_credentials.clone(),
        ))
        .expect("dev ICE responder");
    let responder_addr = responder.local_addr();
    let socket = runtime
        .block_on(async { UdpSocket::bind("127.0.0.1:0").await })
        .unwrap();

    let mut group = c.benchmark_group("ice");
    group
        .sample_size(50)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1));
    group.bench_function("authenticated_check_round_trip", |b| {
        b.to_async(&runtime).iter(|| async {
            let request = IceCheckRequest {
                remote_credentials: remote_credentials.clone(),
                local_ufrag: local_credentials.ufrag.clone(),
                local_priority: 0x7eff_ffff,
                controlling_tiebreaker: 0xdead_beef_cafe_d00d,
                use_candidate: true,
            };
            let result =
                perform_ice_check(&socket, responder_addr, request, Duration::from_secs(1))
                    .await
                    .expect("ICE check must succeed on loopback");
            black_box(result.round_trip);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_ice_check_loopback);
criterion_main!(benches);
