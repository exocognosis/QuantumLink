# Performance Baseline

This file records the human-readable perf baseline for QuantumLink. The
machine-readable copy at [`perf-baseline.json`](./perf-baseline.json)
drives CI's regression gate (see "Regression gating" below); keep the
two in sync when refreshing.

## Methodology

- **Hardware**: The CI regression gate uses a GitHub Actions `macos-15`
  hosted-runner baseline captured on 2026-06-22 from `main` commit
  `e13448c51e4d5180d24e25c906b8b08f3d99ba15`. Earlier Apple Silicon
  developer-workstation numbers are preserved in git history, but this
  file now records the hosted-runner values that drive CI pass/fail
  decisions. Compare CI output to CI baselines; compare local workstation
  output to local history.
- **Surface**: loopback only. Real WAN numbers will be higher because of
  network RTT, but if the loopback baseline ever exceeds an SLO, no real
  network will save us.
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
| `slo.direct_warm` | 30 | **3.3 ms** | 4.1 ms | 4.2 ms | 4.2 ms | 300 ms | 91× |
| `slo.post_event_recovery` | 30 | **3.3 ms** | 3.7 ms | 3.9 ms | 3.9 ms | 1000 ms | 303× |
| `slo.relay_fallback` | 30 | **210.8 ms** | 216.6 ms | 218.3 ms | 218.3 ms | 2000 ms | 9.5× |

The relay-fallback p50 is dominated by the configured 200 ms direct probe
timeout: the connector waits the full probe budget on the unreachable
TEST-NET-1 candidate before opening the relay. To bring real-world fallback
under 200 ms the probe budget needs to drop, which trades against false
fallbacks on slow-but-working networks. v1 chose 750 ms direct / 200 ms in
the relay-fallback scenario; production may want to tune this per
deployment policy.

### Connector micro-benches — `cargo bench --bench connector`

The CI gate stores the single Criterion estimate value that `perfgate`
reads from Criterion's JSON output. Lower/upper bounds are useful in the
HTML report artifact, but they are not part of the committed gate baseline.

| Bench | Lower | Estimate | Upper |
|---|---:|---:|---:|
| `cold_direct_connect` | n/a | **4.577 ms** | n/a |
| `warm_direct_connect` | n/a | **5.552 ms** | n/a |
| `reconnect_post_event` | n/a | **5.504 ms** | n/a |

Cold and warm connect look almost identical at this scale because the
loopback path's dominant cost is the QUIC + ML-KEM handshake, not the
rendezvous lookup. The cache hit reorders candidates but doesn't shorten
the handshake. WAN numbers will diverge — the cached candidate will skip
discovery RTT entirely.

### ICE round-trip — `cargo bench --bench ice`

| Bench | Lower | Estimate | Upper |
|---|---:|---:|---:|
| `authenticated_check_round_trip` | n/a | **49.00 µs** | n/a |

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
| `lan` | 15/15 | **25.1 ms** | 30.3 ms | 33.2 ms | ✓ |
| `cable` | 15/15 | **236.8 ms** | 256.8 ms | 272.2 ms | ✓ |
| `mobile-3g` | 1/15 | **1.8 s** | 1.8 s | 1.8 s | ✗ |

The 3G profile blows the SLO and falls back to relay 14 of 15 attempts.
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
| `lan` | 15/15 | **25.6 ms** | 29.3 ms | 29.7 ms | ✓ |
| `cable` | 15/15 | **218.8 ms** | 235.3 ms | 253.7 ms | ✓ |
| `mobile-3g` | 1/15 | **1.8 s** | 1.8 s | 1.8 s | ✗ |

Same shape as direct-warm. Recovery on cable is ~219 ms, well within
the SLO. 3G fails the SLO for the same retransmission-budget reason.

### Relay-fallback activation (SLO target: < 2 s p50)

| Profile | p50 | p90 | p99 | SLO |
|---|---:|---:|---:|---:|
| `lan` | **210.9 ms** | 215.1 ms | 216.7 ms | ✓ |
| `cable` | **210.4 ms** | 216.6 ms | 217.5 ms | ✓ |
| `mobile-3g` | **511.0 ms** | 517.5 ms | 518.5 ms | ✓ |

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

## Regression gating

CI runs the same suites on a `macos-15` runner and then runs
`perfgate` (the binary at `qlink-core/src/bin/perfgate.rs`) to
diff observed values against `perf-baseline.json`. Any metric that
regresses past the baseline's `regression_threshold_pct` (currently
`20.0`) fails the `Performance` workflow.

```sh
# Locally, after running the bench suites:
cargo build -p qlink-core --bin perfgate --release
target/release/perfgate \
  --baseline docs/perf-baseline.json \
  --slo-log build/perf-slos.log \
  --criterion-dir target/criterion
```

The flags are independent: pass only `--slo-log` if you only ran the
SLO scenarios; pass only `--criterion-dir` if you only ran the
micro-benches. Baseline metrics without a corresponding data source are
silently skipped. Add `--dry-run` to print the report without exiting
non-zero.

### Refreshing the baseline

When an intentional perf change moves a metric past the threshold:

1. Re-run the affected bench suite in GitHub Actions, or download the
   artifact from the CI run. Use local workstation runs only for local
   workstation trend analysis, not for the CI gate baseline.
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
