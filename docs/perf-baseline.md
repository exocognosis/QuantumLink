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

## SLO scenarios under synthetic WAN — `cargo bench --bench slos_wan`

Loopback measurements answer "is the floor low enough?" The synthetic WAN
harness answers "what should operators actually expect?" The harness wraps
the connector's QUIC traffic in a forwarding proxy (in-process Rust,
[`synthetic_wan::WanProxy`](../rust/qlink-core/src/synthetic_wan.rs)) that
injects per-direction delay, jitter, and loss.

### Profiles

| Name | One-way delay | Jitter | Loss | Models |
|---|---:|---:|---:|---|
| `lan` | 0.5 ms | 200 µs | 0% | Quiet office Ethernet |
| `cable` | 15 ms | 5 ms | 0.1% | Typical home broadband (cable / fiber) |
| `mobile-3g` | 125 ms | 40 ms | 1% | Degraded mobile, weak signal |

### Direct-warm connect (SLO target: < 300 ms p50)

| Profile | Direct success rate | p50 | p90 | p99 | SLO |
|---|---:|---:|---:|---:|---:|
| `lan` | 15/15 | **16.0 ms** | 17.2 ms | 18.1 ms | ✓ |
| `cable` | 15/15 | **160.4 ms** | 189.5 ms | 199.9 ms | ✓ |
| `mobile-3g` | 10/15 | **1.6 s** | 1.8 s | 1.8 s | ✗ |

The 3G profile blows the SLO and falls back to relay 5 of 15 attempts.
That's expected: 1% packet loss + 250 ms RTT means QUIC handshake
retransmits push past the configured 1.75-second probe budget on a
substantial fraction of attempts. Operators on degraded mobile should
expect either relay fallback or noticeably higher direct-connect
latency. The product.md SLO is anchored at "warm discovery" implying
better network conditions — degraded-mobile is the wrong baseline for
the spec target, but the measurement is what it is.

### Post-event recovery (SLO target: < 1 s p50)

| Profile | Direct success rate | p50 | p90 | p99 | SLO |
|---|---:|---:|---:|---:|---:|
| `lan` | 15/15 | **15.2 ms** | 18.6 ms | 21.3 ms | ✓ |
| `cable` | 15/15 | **171.4 ms** | 183.0 ms | 193.9 ms | ✓ |
| `mobile-3g` | 5/15 | **1.8 s** | 1.8 s | 1.8 s | ✗ |

Same shape as direct-warm. Recovery on cable is ~170 ms, well within
the SLO. 3G fails the SLO for the same retransmission-budget reason.

### Relay-fallback activation (SLO target: < 2 s p50)

| Profile | p50 | p90 | p99 | SLO |
|---|---:|---:|---:|---:|
| `lan` | **205.7 ms** | 208.5 ms | 208.8 ms | ✓ |
| `cable` | **206.5 ms** | 207.2 ms | 207.2 ms | ✓ |
| `mobile-3g` | **506.3 ms** | 507.7 ms | 508.0 ms | ✓ |

Relay fallback comfortably beats the SLO across all profiles. The p50
tracks the configured direct-probe timeout (200 ms for `lan`/`cable`,
500 ms for `mobile-3g`) plus the TCP relay handshake. **Caveat**: the
WAN proxy impairs UDP only; the relay path itself runs over loopback
TCP, so the relay-side timing is a *lower bound* on real-world relay
latency. A v2 harness that impairs the relay's TCP socket would push
these numbers up.

## How to regenerate locally

```sh
# All four Rust bench suites (~60s combined).
cargo bench -p qlink-core --bench slos       # loopback SLOs
cargo bench -p qlink-core --bench slos_wan   # WAN-impaired SLOs
cargo bench -p qlink-core --bench connector  # micro-benches
cargo bench -p qlink-core --bench ice        # ICE round-trip floor

# Swift perf tests need the release dylib on disk.
cargo build -p qlink-core --release
QLINK_CORE_DYLIB="$PWD/target/release/libqlink_core.dylib" \
  swift test --filter RustMeshTransportPerformanceTests
```

## Known limitations

- The WAN harness impairs **UDP only**. Relay (TCP) timing on the WAN
  benches is a lower bound; a follow-up could add TCP impairment.
- Sample sizes are deliberately modest (n=30 for loopback SLOs, n=15
  for WAN SLOs, n=20 for criterion micro-benches) so the suite finishes
  in well under a minute. Tightening regression gating will require
  larger samples plus per-runner variance baselines.
- Swift perf tests do not yet exercise a successful end-to-end mesh
  transport path because building one in XCTest requires hosting a Rust
  rendezvous server inside the Swift test process. Tracked as a follow-up.
- The 20% regression-gate threshold in `.github/workflows/perf.yml` is
  documented but not yet enforced. Variance characterization on shared
  runners has to come first.
- The mobile-3g profile fails the direct-connect SLOs by design: 1%
  loss × 250 ms RTT × 3-RTT QUIC handshake exceeds the probe budget.
  This isn't a bug in the protocol layer; it's an honest measurement
  saying "on a network this bad, expect relay fallback, not direct."
