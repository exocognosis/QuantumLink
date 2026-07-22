# Performance Baseline

This file records the human-readable perf baseline for QuantumLink. The
machine-readable copy at [`perf-baseline.json`](./perf-baseline.json)
drives CI's regression gate (see "Regression gating" below); keep the
two in sync when refreshing.

## Methodology

- **Hardware**: The CI regression gate uses a GitHub Actions `macos-15`
  hosted-runner baseline captured on 2026-07-20 from workflow run
  `29775985217` on commit `ece070139949612fa7e6e6e9b7962cc14163a198`.
  The refresh followed a benchmark-fixture upgrade that now runs signed
  inbound identity plus app-layer PQC responder handshakes.
- **Surface**: loopback SLO assertions plus synthetic WAN measurement rows.
  Real public-network numbers will vary by RTT, loss, and relay placement,
  but if the loopback baseline ever exceeds an SLO, no real network will
  save us.
- **Crypto**: ML-KEM-768 KEM + ML-DSA-65 signatures
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

The bench helpers live in `qlink-core/benches/common/mod.rs`.

## Product SLO targets

From `product.md` § "Performance, failure modes, and open questions":

| SLO | Target |
|---|---|
| Median direct connect (warm discovery) | < 300 ms |
| Median post-event recovery (PathChanged → ready) | < 1 s |
| Median relay-fallback activation | < 2 s |

## CI gate baseline (macos-15 hosted runner)

### SLO scenarios — `cargo bench --bench slos`

| Scenario | n | p50 | p90 | p99 | max | SLO | Margin |
|---|---:|---:|---:|---:|---:|---:|---:|
| `slo.direct_warm` | 30 | **6.9 ms** | 7.7 ms | 9.2 ms | 9.2 ms | 300 ms | 43× |
| `slo.post_event_recovery` | 30 | **7.0 ms** | 7.9 ms | 8.4 ms | 8.4 ms | 1000 ms | 143× |
| `slo.relay_fallback` | 30 | **223.7 ms** | 231.4 ms | 241.0 ms | 241.0 ms | 2000 ms | 8.9× |

The relay-fallback p50 is dominated by the configured 200 ms direct probe
timeout: the connector waits the full probe budget on the unreachable
loopback candidate before opening the relay. The fixture uses a fast local
refusal (`127.0.0.1:1`) so the SLO measures relay activation and the
end-to-end PQC relay session rather than route-level timeout behavior for
unroutable documentation IPs. To bring real-world fallback under 200 ms the
probe budget needs to drop, which trades against false fallbacks on
slow-but-working networks. v1 chose 750 ms direct / 200 ms in the
relay-fallback scenario; production may want to tune this per deployment
policy.

### Connector micro-benches — `cargo bench --bench connector`

The CI gate stores the single Criterion estimate value that `perfgate`
reads from Criterion's JSON output. Lower/upper bounds are useful in the
HTML report artifact, but they are not part of the committed gate baseline.

| Bench | Lower | Estimate | Upper |
|---|---:|---:|---:|
| `cold_direct_connect` | n/a | **7.101 ms** | n/a |
| `warm_direct_connect` | n/a | **7.078 ms** | n/a |
| `reconnect_post_event` | n/a | **7.047 ms** | n/a |

Cold and warm connect look almost identical at this scale because the
loopback path's dominant cost is the QUIC + ML-KEM handshake, not the
rendezvous lookup. The cache hit reorders candidates but doesn't shorten
the handshake. WAN numbers will diverge — the cached candidate will skip
discovery RTT entirely.

### ICE round-trip — `cargo bench --bench ice`

| Bench | Lower | Estimate | Upper |
|---|---:|---:|---:|
| `authenticated_check_round_trip` | n/a | **42.00 µs** | n/a |

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
[`synthetic_wan::WanProxy`](../qlink-core/src/synthetic_wan.rs)) that
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
| `lan` | 15/15 | **193.5 ms** | 212.3 ms | 223.2 ms | ✓ |
| `cable` | 15/15 | **1.6 s** | 1.6 s | 1.6 s | ✗ |
| `mobile-3g` | 0/15 | **3.0 s** | 3.0 s | 3.0 s | ✗ |

These rows now exercise the same signed inbound identity and app-layer
PQC responder setup used by live links. Cable succeeds directly but misses
the loopback-anchored product SLO; mobile-3g falls back to relay after the
wider measurement probe budget. Operators should treat relay fallback as
normal on degraded mobile and should tune direct-probe policy per deployment
before promising sub-300 ms WAN direct setup.

### Post-event recovery (SLO target: < 1 s p50)

| Profile | Direct success rate | p50 | p90 | p99 | SLO |
|---|---:|---:|---:|---:|---:|
| `lan` | 15/15 | **195.6 ms** | 234.1 ms | 247.4 ms | ✓ |
| `cable` | 15/15 | **1.5 s** | 1.6 s | 1.6 s | ✗ |
| `mobile-3g` | 0/15 | **3.0 s** | 3.0 s | 3.0 s | ✗ |

Same shape as direct-warm. LAN recovery stays inside the SLO after a
network event; cable and degraded mobile are honest WAN measurements, not
loopback-SLO proofs.

### Relay-fallback activation (SLO target: < 2 s p50)

| Profile | p50 | p90 | p99 | SLO |
|---|---:|---:|---:|---:|
| `lan` | **224.8 ms** | 231.4 ms | 235.2 ms | ✓ |
| `cable` | **224.0 ms** | 235.4 ms | 235.6 ms | ✓ |
| `mobile-3g` | **525.3 ms** | 532.5 ms | 545.0 ms | ✓ |

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
cargo bench -p qlink-core --bench slos --no-default-features --features dev-quic-carrier       # loopback SLOs
cargo bench -p qlink-core --bench slos_wan --no-default-features --features dev-quic-carrier   # WAN-impaired SLOs
cargo bench -p qlink-core --bench connector --no-default-features --features dev-quic-carrier  # micro-benches
cargo bench -p qlink-core --bench ice --no-default-features --features dev-quic-carrier        # ICE round-trip floor

# Swift perf tests need the release dylib on disk.
cargo build -p qlink-core --release
QLINK_CORE_DYLIB="$PWD/target/release/libqlink_core.dylib" \
  swift test --filter RustMeshTransportPerformanceTests
```

## Regression gating

CI runs the same suites on a `macos-15` runner and then runs
`perfgate` (the binary at `qlink-core/src/bin/perfgate.rs`) to
diff observed values against `perf-baseline.json`. Any metric that
regresses past the baseline's `regression_threshold_pct` (currently
`20.0`) fails the `Performance` workflow. Baseline rows may also
declare `regression_noise_floor_ms`; when present, a metric must exceed
both the percentage threshold and that absolute millisecond floor before
the row is treated as regressed. The current CI baseline uses a 5 ms
floor for the two small loopback SLO rows, a 2 ms floor for connector
microbench rows, and a 0.1 ms floor for the sub-millisecond ICE
micro-benchmark, where hosted-runner jitter is larger than the protocol
signal being measured.

```sh
# Locally, after running the bench suites:
cargo build -p qlink-core --bin perfgate --release
target/release/perfgate \
  --baseline docs/perf-baseline.json \
  --slo-log build/perf-slos.log \
  --slo-log build/perf-slos-wan.log \
  --criterion-dir target/criterion
```

The flags are independent: pass only `--slo-log` if you only ran the
SLO scenarios; pass only `--criterion-dir` if you only ran the
micro-benches. Baseline metrics without a corresponding data source are
silently skipped. Add `--dry-run` to print the report without exiting
non-zero.

### Refreshing the baseline

When an intentional perf change moves a metric past the threshold:

1. Prefer a GitHub Actions `macos-15` run or downloaded CI artifact. A local
   workstation refresh is acceptable only during a fixture transition and
   should be replaced with hosted-runner numbers after the next green run.
2. Update the corresponding row in `perf-baseline.json`.
3. Update the matching numbers in the tables below so humans reading
   the doc and the machine reading the JSON agree.
4. Commit both files in the same change.

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
- The 20% regression gate is enforced by `perfgate` against the
  metrics in `perf-baseline.json`. The gate baseline is intentionally
  CI-runner-specific; workstation numbers are useful for diagnosis but
  should not drive hosted-runner pass/fail decisions.
- The `mobile-3g` direct-connect + post-event rows are *not*
  baselined: their p50 is dominated by the configured probe-budget
  timeout (the protocol falls back to relay almost every iteration),
  so gating on them would assert "did we time out exactly the same
  way" rather than meaningful protocol latency. The mobile-3g
  *relay* row is baselined since the relay path actually completes.
- The mobile-3g profile fails the direct-connect SLOs by design: 1%
  loss × 250 ms RTT × 3-RTT QUIC handshake exceeds the probe budget.
  This isn't a bug in the protocol layer; it's an honest measurement
  saying "on a network this bad, expect relay fallback, not direct."
