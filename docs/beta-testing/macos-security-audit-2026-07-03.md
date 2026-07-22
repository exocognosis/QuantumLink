# QuantumLink macOS Security Test Execution Report - 2026-07-03

## Scope

This report executes the local, pre-Apple portion of
`docs/security-test-plan-macos.md` against the live checkout.

- Checkout: `/Users/rickglenn/Desktop/QuantumLink/QuantumLinkOS`
- Branch: `main`
- Base commit: `2039105`
- Host: macOS 26.5.2 build 25F84, arm64
- Swift: 6.2.3
- Rust/Cargo: 1.88.0
- Xcode state: Command Line Tools only at `/Library/Developer/CommandLineTools`

The host cannot run full XCTest or Xcode release packaging because `xctest`
and `xcodebuild` are unavailable under the active Command Line Tools developer
directory. All Network Extension install, signed app, notarization, stapling,
Gatekeeper, real `utun`, and MDM-managed Mac tests remain Apple-gated.

## Executive Result

Local Rust crypto, packet-core, loopback transport, config validation, MDM plist
lint, development packaging, and Swift build gates passed after two cleanup
fixes:

- `qlinkctl quic-loopback` now asserts semantic IPv4 packet round-trip success
  instead of comparing pre-normalized bytes to normalized packet bytes.
- `SupportBundleExporter` no longer emits the Swift 6.2 `@Sendable` default
  closure warning.
- The non-test `qlinkctl` release build no longer includes the test-only
  direct-send wrapper helper.

This run did not find a locally demonstrated protected-route plaintext leak.
That is not a production VPN proof: route leak testing against a live packet
tunnel is blocked until the Apple Network Extension, signing, provisioning,
and managed-device path is available.

Release posture: do not claim a production-ready macOS VPN bundle from this
checkout yet. The local baseline is improving, but production macOS release is
blocked by Apple-gated validation and open hardening findings below.

## Command Evidence

| Gate | Result | Evidence |
| --- | --- | --- |
| Toolchain | Partial | Swift 6.2.3, Rust/Cargo 1.88.0, XcodeGen 2.45.4. `xcode-select -p` returns `/Library/Developer/CommandLineTools`; `xcrun --find xctest` fails. |
| Host identity | Pass | `sw_vers` reports macOS 26.5.2 build 25F84; `uname -m` reports arm64. |
| `swift test --filter ...` | Blocked | Compile fails with `no such module 'XCTest'` on this CLT-only host. |
| `swift build` | Pass | Build completed after the `SupportBundleExporter` warning fix. |
| `cargo fmt --all -- --check` | Pass | No formatting drift. |
| `cargo test --workspace` | Pass | 158 `qlink-core` library tests, 5 `perfgate` tests, 2 `qlinkctl` tests, and doc-tests passed. |
| `cargo build --workspace --release` | Pass | Release build completed after gating the test-only `run_direct_send` helper behind `#[cfg(test)]`. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Fail | Fails on pre-existing lint debt, including missing `# Safety` docs on unsafe FFI exports, large enum variants, loop style, and test assertions on constants. |
| `swift run QuantumLinkSmoke validate-config --config config/mesh.example.json` | Pass | `config_valid=true`, `protected_route_count=2`, `rendezvous_count=1`, `relay_count=1`, `warning_count=0`. |
| `swift run QuantumLinkSmoke preflight --transport --mode dev-quic-loopback` | Pass | `preflight_transport_state=ready`, `preflight_packet_round_trip=true`. |
| `target/release/qlinkctl simulate-handshake` | Pass | Suite `QLINK-FIPS203-MLKEM768-HKDFSHA256-v1`; initiator/responder directional keys match. |
| `target/release/qlinkctl quic-loopback` | Pass | `packet_round_trip=true` after the semantic packet-roundtrip fix. |
| `target/release/qlinkctl mesh-loopback` | Pass | `packet_round_trip=true`; selected path was `Relay`, so this run is relay-path evidence, not direct-path evidence. |
| `target/release/qlinkctl relay-loopback` | Pass | `packet_round_trip=true`. |
| `plutil -lint macos/mdm/*.mobileconfig.template macos/entitlements/*.entitlements` | Pass | All MDM templates and entitlement plists lint cleanly. |
| `swift run QuantumLinkMDM --help` | Pass | CLI builds and prints `build-perapp` and `build-ondemand` usage. SwiftPM emits a non-security warning that `Sources/QuantumLinkApp/Assets.xcassets` is unhandled. |
| `./scripts/package-dev-artifacts.sh` | Pass | Created `build/dist/QuantumLink-dev.tar.gz`. |
| `./scripts/package-macos.sh --skip-sign --pkg` | Blocked | Rust Darwin targets build, then `xcodebuild -create-xcframework` fails because active developer directory is Command Line Tools, not full Xcode. |

## Phase Results

### Phase 1 - Architecture And Design Review

Result: partial pass, with Apple-gated production proof blocked.

Evidence reviewed:

- `docs/security.md` keeps production claims bounded and explicitly lists
  missing production transport, notarized app/extension bundles, update
  signing, MDA/SSO, and relay abuse controls.
- `docs/pre-apple-development.md` correctly separates local validation from
  Apple-blocked entitlement, signing, notarization, and real extension tests.
- App and tunnel entitlements include sandboxing, network client access, shared
  app group, and `packet-tunnel-provider`.
- The packet tunnel code uses `NEPacketTunnelNetworkSettings` included and
  excluded routes from `TunnelConfiguration`.

Security conclusion: the architecture is framed conservatively. The main local
architectural risk is not a hidden kext/pf dependency; it is that route, kill
switch, and MDM enforcement cannot be proven without a real signed packet tunnel
install.

### Phase 2 - Cryptography And Key Management

Result: Rust crypto and packet-core tests pass; inbound assertion anti-replay
needs hardening.

Evidence reviewed:

- `cargo test --workspace` passed all current Rust tests.
- `qlinkctl simulate-handshake` proves the current ML-KEM/HKDF suite path
  produces matching directional keys.
- `inbound_identity.rs` verifies peer ID derivation, mesh ID, timestamp age,
  future timestamp rejection, and signature validity.
- Keychain-backed Swift stores use the Data Protection Keychain and
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for local secret material.
- Device seed and peer-store encryption key material are kept in Keychain-backed
  helpers, not plain config files.

Security conclusion: the core cryptographic baseline is testable locally and
passing, but the inbound identity assertion still has a timestamp-only replay
window and no nonce cache.

### Phase 3 - App, Extension, And IPC Boundary

Result: partial pass by code review; XCTest fuzz coverage blocked on this host.

Evidence reviewed:

- `handleAppMessage` rejects malformed JSON by returning nil.
- `status`, `exportDiagnostics`, and `disconnect` are narrow local extension
  commands.
- `reloadConfiguration` currently returns "Configuration reload queued." but
  does not apply the supplied configuration.

Security conclusion: no local IPC privilege escalation was demonstrated, but
`reloadConfiguration` is misleading and should either apply a validated config
or report unsupported behavior.

### Phase 4 - Packet Tunnel, Routing, And Kill Switch

Result: local code and unit-level evidence support fail-closed behavior; real
route leak proof is blocked.

Evidence reviewed:

- `TunnelPacketPump` drops all observed packets when the Rust core is nil.
- The kill-switch transport readiness gate drops packets before submitting them
  to the core when the transport is not ready.
- Encrypted transport frames use pop-then-send semantics; send failure drops the
  frame and does not route plaintext.
- `PacketTunnelProvider.startTunnel` refuses startup under strict kill-switch
  mode if the transport fails.

Security conclusion: local code review supports fail-closed semantics, but the
release gate remains live testing with `NEPacketTunnelProvider`, route tables,
DNS, sleep/wake, network roam, and transport outage scenarios on a signed Mac.

### Phase 5 - Rust FFI Boundary

Result: functionally tested by Rust and Swift smoke paths; lint gate fails.

Evidence reviewed:

- Rust tests and Swift smoke calls exercise the FFI-backed packet core.
- FFI helpers perform null checks, pointer/length checks, owned-buffer returns,
  and explicit free functions.
- `cargo clippy --workspace --all-targets -- -D warnings` fails because unsafe
  exported FFI functions do not document their `# Safety` contracts.

Security conclusion: no memory corruption was demonstrated in local tests, but
the FFI boundary is security-critical and should not fail a strict lint gate
before release.

### Phase 6 - Mesh, Rendezvous, Relay, And Transport

Result: local smokes pass; production mesh claims remain limited.

Evidence reviewed:

- `quic-loopback`, `mesh-loopback`, and `relay-loopback` all report
  `packet_round_trip=true`.
- The observed `mesh-loopback` selected `Relay`, so that run proves relay
  packet delivery, not a direct peer-to-peer path.
- `PacketTunnelProvider.makeTransport` uses production mesh transport when
  available, but honors `QLINK_TRANSPORT_MODE` as a dev override and falls back
  to the default factory when production transport construction fails.

Security conclusion: local transport smokes are healthy. Production release
should explicitly prevent dev transport overrides in signed release context and
require fail-closed behavior if production transport construction fails.

### Phase 7 - Diagnostics, Logs, And Support Bundles

Result: pass with one policy decision to keep visible.

Evidence reviewed:

- `PrivacyDefaults.redactForLog` redacts both network identifiers and
  QuantumLink peer IDs for public log strings.
- `SupportBundleExporter` redacts raw network identifiers by default and reports
  counts rather than full route, DNS, rendezvous, or relay lists.
- Support bundles intentionally retain pseudonymous peer IDs for operational
  debugging.
- Rust tracing is redacted through `PrivacyDefaults.redactForLog` before OS
  logging.

Security conclusion: default logging and support-bundle behavior are reasonable
for local beta evidence. The decision to retain peer IDs in support bundles
should remain explicit in product/privacy documentation.

### Phase 8 - Packaging, Signing, Notarization, And Updates

Result: development package passes; release packaging is blocked on full Xcode
and Apple credentials.

Evidence reviewed:

- `package-dev-artifacts.sh` produced `build/dist/QuantumLink-dev.tar.gz`.
- `package-macos.sh --skip-sign --pkg` reached the XCFramework creation step
  and failed because `xcodebuild` requires full Xcode.
- Signed app, PKG, notarization, stapling, Gatekeeper, and Sparkle update
  verification were not run.

Security conclusion: the development artifact is useful for protocol smokes.
It is not a trusted install artifact and must not be presented as a production
macOS release.

### Phase 9 - Fuzzing And Abuse Testing

Result: not complete.

Evidence reviewed:

- Existing Rust tests cover malformed packets, replay behavior, bad signatures,
  stale records, and local loopback flows.
- No dedicated fuzz harness was run in this pass.

Security conclusion: fuzzing remains a release-hardening task, especially for
FFI inputs, packet/frame parsers, identity assertions, rendezvous records, MDM
payload construction, and provider message decoding.

### Phase 10 - Reporting And Release Decision

Result: this report and the updated test-plan snapshot are the local evidence
artifacts for this pass.

Release decision: local pre-Apple evidence is not sufficient to ship a
production macOS VPN. Continue to harden the open findings, then rerun on a host
with full Xcode and Apple credentials.

## Findings

### QL-MAC-001 - Inbound Identity Assertions Lack A Nonce Replay Cache

- Severity: Medium
- Status: Open
- Area: Rust inbound identity, peer authentication
- Evidence: `rust/qlink-core/src/inbound_identity.rs` documents that v1 uses a
  timestamp window only and no `(peer_id, nonce)` cache.
- Impact: A valid assertion captured within the freshness window could be
  replayed during that window if surrounding transport/session controls do not
  reject it first.
- Mitigations already present: ML-DSA signature verification, peer ID derivation
  check, mesh ID binding, timestamp max-age, future timestamp rejection, and
  inbound ACL evaluation.
- Required fix: add a bounded LRU replay cache keyed by `(peer_id, nonce)` at
  the inbound connection decision point, with tests for duplicate assertion
  rejection inside the freshness window.

### QL-MAC-002 - FFI Boundary Fails Strict Clippy Safety Documentation Gate

- Severity: Medium
- Status: Open
- Area: Rust FFI, Swift bridge
- Evidence: `cargo clippy --workspace --all-targets -- -D warnings` fails on
  missing `# Safety` docs for unsafe exported functions in
  `rust/qlink-core/src/ffi.rs`.
- Impact: Missing safety contracts make the C ABI harder to audit and increase
  the chance of Swift caller misuse around pointer lifetime, nullability,
  ownership, buffer length, and free semantics.
- Mitigations already present: local null/pointer helpers, owned-buffer free
  APIs, and current Rust/Swift smoke coverage.
- Required fix: document every unsafe export with caller obligations and add or
  retain tests for null pointers, zero lengths, oversized lengths, double-free
  resistance expectations, and invalid handle behavior.

### QL-MAC-003 - Full macOS Security Validation Is Blocked On Full Xcode And Apple Gates

- Severity: Release blocker
- Status: Open
- Area: macOS release, packet tunnel, signing, managed deployment
- Evidence: `xcrun --find xctest` fails; `package-macos.sh --skip-sign --pkg`
  fails when `xcodebuild -create-xcframework` is required.
- Impact: The team cannot honestly claim production packet-tunnel behavior,
  leak-free route enforcement, notarized distribution, Gatekeeper acceptance, or
  MDM installation from this host.
- Required fix: rerun the full plan on a Mac with full Xcode, Apple-granted
  Network Extension entitlement, provisioning profiles, Developer ID signing,
  notary credentials, and managed/unmanaged validation machines.

### QL-MAC-004 - Provider Reload Command Is Acknowledged But Not Applied

- Severity: Low
- Status: Open
- Area: Packet tunnel provider IPC
- Evidence: `PacketTunnelProvider.handleAppMessage` returns "Configuration
  reload queued." for `.reloadConfiguration` but does not apply the envelope's
  configuration.
- Impact: Operators and tests can receive a success-like message when route,
  DNS, kill-switch, or transport settings were not actually changed.
- Required fix: either implement validated in-place reload with route/settings
  replacement and transport restart semantics, or return an explicit unsupported
  response until reload is implemented.

### QL-MAC-005 - Release Builds Need An Explicit Dev-Transport Override Policy

- Severity: Medium
- Status: Open
- Area: Packet tunnel provider transport selection
- Evidence: `PacketTunnelProvider.makeTransport` honors `QLINK_TRANSPORT_MODE`
  as a development override and falls back to the default transport factory if
  production mesh construction fails.
- Impact: A signed production build should never accidentally run a permissive
  development transport mode or silently degrade away from production mesh
  security.
- Mitigations already present: strict kill switch refuses startup on transport
  start failure; default/drop paths are designed fail-closed for protected
  packets.
- Required fix: add a release-build guard that ignores or rejects dev transport
  environment overrides, and define whether production mesh construction failure
  is always fatal in release.

## Blocked Production Gates

These were not and cannot be completed from the current host state:

- Full Swift XCTest run.
- Real packet tunnel installation and `NEPacketTunnelProvider` startup.
- Protected-route plaintext leak tests under live route tables.
- DNS leak tests with tunnel DNS settings.
- Sleep/wake, network roam, and transport outage tests against a live tunnel.
- Apple Network Extension entitlement validation.
- Developer ID app and installer signing.
- Notarization, stapling, and Gatekeeper validation.
- MDM extension pre-approval and per-app VPN install tests.
- Clean managed and unmanaged Mac install tests.
- Sparkle update signature and rollback tests.

## Next Batch

1. Fix `QL-MAC-001` by adding inbound assertion nonce replay caching and tests.
2. Fix `QL-MAC-002` enough for `cargo clippy --workspace --all-targets -- -D warnings`
   to pass or narrow the enforced lint scope with explicit rationale.
3. Implement or explicitly reject `reloadConfiguration`.
4. Add release-build assertions around `QLINK_TRANSPORT_MODE` and production
   mesh fallback behavior.
5. Move validation to a full-Xcode Mac and rerun the full XCTest, XCFramework,
   unsigned packaging, signed packaging, and Network Extension leak-test gates.
