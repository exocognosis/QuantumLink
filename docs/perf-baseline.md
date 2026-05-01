# Performance Baseline

This file records the first-run baseline for QuantumLink's performance
harness. Subsequent runs in CI compare against these numbers; a regression
of more than 20% on any p50 should block release until investigated.

## Methodology

- **Hardware**: Apple Silicon developer workstation (M-series). CI runs on
  `macos-15` runners; expect higher variance there.
- **Surface**: loopback only. Real WAN numbers will be higher because of
  network RTT, but if the loopback baseline ever exceeds an SLO, no real
  network will save us.
- **Crypto**: hybrid X25519 + ML-KEM-768 KEM + ML-DSA-65 signatures
  (FIPS 203 / 204 suites). ICE checks use HMAC-SHA1 short-term credentials
  per RFC 8445.
- **Tools**:
  - `cargo bench -p qlink-core --bench connector` — Criterion micro-benches
    for warm/cold/reconnect direct-connect.
  - `cargo bench -p qlink-core --bench ice` — Criterion micro-bench for one
    authenticated STUN binding-request round-trip.
  - `cargo bench -p qlink-core --bench slos` — scenario harness that
    captures p50/p90/p99/max for each product SLO and asserts the target.
  - `swift test --filter RustMeshTransportPerformanceTests` — XCTClockMetric
    coverage of the Swift FFI path (gated on `QLINK_CORE_DYLIB`).

The bench helpers live in `rust/qlink-core/benches/common/mod.rs`.

## Product SLO targets

From `product.md` § "Performance, failure modes, and open questions":

| SLO | Target |
|---|---|
| Median direct connect (warm discovery) | < 300 ms |
| Median post-event recovery (PathChanged → ready) | < 1 s |
| Median relay-fallback activation | < 2 s |

## Initial baseline (loopback, dev workstation)

### SLO scenarios — `cargo bench --bench slos`

| Scenario | n | p50 | p90 | p99 | max | SLO | Margin |
|---|---:|---:|---:|---:|---:|---:|---:|
| `slo.direct_warm` | 30 | **1.9 ms** | 2.1 ms | 2.7 ms | 2.7 ms | 300 ms | 158× |
| `slo.post_event_recovery` | 30 | **2.0 ms** | 2.0 ms | 2.3 ms | 2.3 ms | 1000 ms | 500× |
| `slo.relay_fallback` | 30 | **204.9 ms** | 206.5 ms | 208.6 ms | 208.6 ms | 2000 ms | 9.8× |

The relay-fallback p50 is dominated by the configured 200 ms direct probe
timeout: the connector waits the full probe budget on the unreachable
TEST-NET-1 candidate before opening the relay. To bring real-world fallback
under 200 ms the probe budget needs to drop, which trades against false
fallbacks on slow-but-working networks. v1 chose 750 ms direct / 200 ms in
the relay-fallback scenario; production may want to tune this per
deployment policy.

### Connector micro-benches — `cargo bench --bench connector`

Numbers below are `[lower bound, estimate, upper bound]` from criterion's
20-sample collection.

| Bench | Lower | Estimate | Upper |
|---|---:|---:|---:|
| `cold_direct_connect` | 2.86 ms | **2.98 ms** | 3.06 ms |
| `warm_direct_connect` | 3.03 ms | **3.07 ms** | 3.11 ms |
| `reconnect_post_event` | 2.67 ms | **2.83 ms** | 2.95 ms |

Cold and warm connect look almost identical at this scale because the
loopback path's dominant cost is the QUIC + ML-KEM handshake, not the
rendezvous lookup. The cache hit reorders candidates but doesn't shorten
the handshake. WAN numbers will diverge — the cached candidate will skip
discovery RTT entirely.

### ICE round-trip — `cargo bench --bench ice`

| Bench | Lower | Estimate | Upper |
|---|---:|---:|---:|
| `authenticated_check_round_trip` | 26.75 µs | **28.00 µs** | 29.33 µs |

This is the authenticated STUN binding-request floor: send → wait → verify
FINGERPRINT + MESSAGE-INTEGRITY. Real ICE checks add network RTT and
retransmission policy (RFC 8445 §6.1.4); the connector adds 50 ms paced
offsets between candidates by default.

### Swift FFI — `swift test --filter RustMeshTransportPerformanceTests`

| Test | Median |
|---|---:|
| `testStartToFailedTransitionWhenRendezvousIsUnreachable` | ~119 µs |
| `testRustMeshTransportFFISymbolsLoadWithinReasonableTime` | ~178 ms |

The first test measures the synchronous-failure path (bogus cert → start()
throws). The 178 ms library load is dominated by `dlopen` of the ~50 MB
release dylib + 23 `dlsym` calls; expect this to grow if the public FFI
surface expands.

## How to regenerate locally

```sh
# All three Rust suites (~30s each).
cargo bench -p qlink-core --bench slos
cargo bench -p qlink-core --bench connector
cargo bench -p qlink-core --bench ice

# Swift perf tests need the release dylib on disk.
cargo build -p qlink-core --release
QLINK_CORE_DYLIB="$PWD/target/release/libqlink_core.dylib" \
  swift test --filter RustMeshTransportPerformanceTests
```

## Known limitations

- Loopback only. The next-iteration harness should add a "synthetic WAN"
  fixture (`tc qdisc` on Linux, `dummynet` on macOS) so we can observe how
  the SLOs degrade under realistic latency / loss / reordering.
- Sample sizes are deliberately modest (n=30 for SLOs, n=20 for criterion)
  so the suite finishes in well under a minute. Tightening regression
  gating will require larger samples plus per-runner variance baselines.
- Swift perf tests do not yet exercise a successful end-to-end mesh
  transport path because building one in XCTest requires hosting a Rust
  rendezvous server inside the Swift test process. Tracked as a follow-up.
- The 20% regression-gate threshold in `.github/workflows/perf.yml` is
  documented but not yet enforced. Variance characterization on shared
  runners has to come first.
