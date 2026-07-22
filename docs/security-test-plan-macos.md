# QuantumLink macOS Security Testing Plan

## Project Overview

- **Type**: Post-quantum encrypted mesh VPN for macOS.
- **Architecture**: SwiftUI app plus `QuantumLinkKit`, `NEPacketTunnelProvider` packet-tunnel extension, Rust `qlink-core` transport/crypto engine, Keychain-backed local secret helpers, MDM profile templates, and Developer ID release scripts.
- **Crypto**: ML-KEM-768 session establishment, ML-DSA-65 device credentials, SLH-DSA-SHA2-128S suite support, transcript-bound HKDF-SHA-256, and ChaCha20-Poly1305 packet-frame protection.
- **Key Components**: Network Extension `utun` packet tunnel, protected-route packet pump, fail-closed kill-switch policy, Rust FFI bridge, QUIC/native transport smokes, rendezvous/relay scaffolding, Keychain secret stores, support-bundle redaction, MDM payload generation, Developer ID/notarization/Sparkle release pipeline.
- **Current Maturity**: Implemented local baseline. Production VPN claims remain blocked until Apple Network Extension entitlement, provisioning, Developer ID signing, notarization, stapling, Gatekeeper validation, and real Mac tunnel validation are complete.

## Scope

- **Full macOS surface**: Swift app, `QuantumLinkKit`, packet tunnel extension, Rust core, FFI boundary, config files, MDM payloads, scripts, release workflows, and diagnostics.
- **Threat Models**: Local unprivileged process, malicious local admin, stolen Mac, malicious peer, active on-path attacker, compromised rendezvous/relay operator, update-channel attacker, MDM/operator misconfiguration, and privacy-sensitive support workflow.
- **Testing Types**: Code review, Swift/Rust tests, crypto verification, packet/frame fuzzing, config mutation, Network Extension route validation, kill-switch leak tests, Keychain review, diagnostics privacy review, packaging/signing verification, update verification, and real-hardware integration testing.
- **Goals**: Find vulnerabilities, verify fail-closed design, validate crypto and key handling, prove privacy defaults, verify app/extension trust boundaries, and produce release-blocking evidence before any production macOS claim.

## Evidence Rules

- Treat pre-Apple local tests as development evidence only.
- Treat Apple-gated tests as blocked until the exact credential, entitlement, signed artifact, or managed Mac requirement exists.
- Every pass/fail claim must include command output, artifact hash, machine class, OS version, and the tested git commit.
- Production release is blocked if protected-route plaintext can leave outside the tunnel, support exports leak raw network identifiers by default, signing/notarization fails, update signatures fail, or public meshes accept missing/stale/revoked identity.

## Local Validation Snapshot - 2026-07-03

**Checkout:** `/Users/rickglenn/Desktop/QuantumLink/QuantumLinkOS`, branch `main`, base commit `2039105` plus local changes in this plan, the 2026-07-03 audit report, and the local smoke/warning cleanup fixes.

| Gate | Result | Evidence |
| --- | --- | --- |
| Toolchain | Partial | Swift 6.2.3, Rust/Cargo 1.88.0, XcodeGen 2.45.4. `xcode-select -p` points to `/Library/Developer/CommandLineTools`; `xcrun --find xctest` fails. |
| `swift build` | Pass | Debug build completed. The prior `SupportBundleExporter.swift` Swift 6.2 sendability warning was fixed. |
| Targeted Swift security tests | Blocked | `swift test --filter ...` fails at compile time with `no such module 'XCTest'` because this host lacks full Xcode/XCTest. |
| `./scripts/preapple-check.sh` | Blocked | Stops at first `swift test` step with the same `no such module 'XCTest'` error. |
| `cargo fmt --all -- --check` | Pass | No formatting drift. |
| `cargo test --workspace` | Pass | 158 `qlink-core` library tests, 5 `perfgate` tests, 2 `qlinkctl` tests, and doc-tests passed. |
| `cargo build --workspace --release` | Pass | Optimized release build completed after gating the test-only `run_direct_send` helper behind `#[cfg(test)]`. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Fail | Fails on strict lint debt, including missing `# Safety` docs on unsafe FFI exports, large enum variants, loop style, and test assertions on constants. |
| `swift run QuantumLinkSmoke validate-config --config config/mesh.example.json` | Pass | `config_valid=true`, `protected_route_count=2`, `rendezvous_count=1`, `relay_count=1`, `warning_count=0`. |
| `swift run QuantumLinkSmoke preflight --transport --mode dev-quic-loopback` | Pass | `preflight_transport_state=ready`, `preflight_packet_round_trip=true`. |
| `target/release/qlinkctl simulate-handshake` | Pass | Suite `QLINK-FIPS203-MLKEM768-HKDFSHA256-v1`; initiator/responder directional keys match. |
| `target/release/qlinkctl quic-loopback` | Pass after fix | Initial run exited 0 but printed `packet_round_trip=false` because the CLI compared pre-normalized and normalized IPv4 bytes. The smoke now checks semantic round trip and prints `packet_round_trip=true`. |
| `target/release/qlinkctl mesh-loopback` | Pass | `packet_round_trip=true`; selected path was `Relay`, so this run is relay-path evidence, not direct-path evidence. |
| `target/release/qlinkctl relay-loopback` | Pass | `packet_round_trip=true`. |
| `plutil -lint macos/mdm/*.mobileconfig.template macos/entitlements/*.entitlements` | Pass | All MDM templates and entitlement plists lint cleanly. |
| `swift run QuantumLinkMDM --help` | Pass | CLI builds and prints `build-perapp` and `build-ondemand` usage. SwiftPM emits a non-security warning that `macos/Sources/QuantumLinkApp/Assets.xcassets` is unhandled. |
| `./scripts/package-dev-artifacts.sh` | Pass | Created `build/dist/QuantumLink-dev.tar.gz`; the prior `SupportBundleExporter.swift` sendability warning is fixed. |
| `./scripts/build-rust-xcframework.sh` | Blocked after Rust builds | Both Apple Darwin Rust targets compiled, then `xcodebuild -create-xcframework` failed because active developer directory is CommandLineTools, not full Xcode. |
| `./scripts/package-macos.sh --skip-sign --pkg` | Blocked | Reached the same `xcodebuild -create-xcframework` full-Xcode boundary after Rust Darwin target builds. |
| Audit report | Complete | See `docs/beta-testing/macos-security-audit-2026-07-03.md`. |

**Not run locally:** signed `./scripts/package-macos.sh --pkg`, `codesign`, `spctl`, `notarytool`, `stapler`, real packet-tunnel install, MDM extension pre-approval, per-app VPN validation, sleep/wake leak tests, and managed/unmanaged clean Mac install tests. These require full Xcode and/or Apple signing, Network Extension entitlement, notarization credentials, and real Mac validation hosts.

---

## PHASE 1: Architecture & Design Review (Week 1)

**Goal**: Validate the macOS threat model, trust boundaries, and Apple-specific production blockers.

### 1.1 Threat Model Validation

- [ ] Review `docs/security.md`, `docs/pre-apple-development.md`, `product.md`, and this plan for consistent threat assumptions.
- [ ] Map trust boundaries: SwiftUI app to `QuantumLinkKit`, app to packet-tunnel provider messages, packet tunnel to Rust FFI, packet tunnel to `NEPacketTunnelNetworkSettings`, Rust core to rendezvous/relay, and app/extension to Keychain.
- [ ] Confirm the macOS surface has no kernel extension, no TAP/kext dependency, and no pf-based core security model.
- [ ] Document failure modes for app crash, extension crash, Rust core unavailable, transport unavailable, Keychain error, config parse failure, and network roam.

### 1.2 Control Architecture Review

- [ ] Verify fail-closed layering: Network Extension route settings, packet-pump transport readiness gate, protected-route policy, Rust packet core, and authenticated frame encryption.
- [ ] Verify split-tunnel versus protected-prefix-only behavior is explicit and not implied by UI state alone.
- [ ] Review `TunnelConfiguration`, `DeploymentMode`, `VPNOnDemandRules`, and MDM templates for routes that could unintentionally leak protected traffic.
- [ ] Confirm app-visible controls cannot bypass packet-tunnel policy or turn protected routes into best-effort routing.

### 1.3 Platform-Readiness Boundary

- [ ] Separate local proof from Apple-gated proof in every report.
- [ ] Confirm `docs/pre-apple-development.md` remains the source of truth for local validation before credentials.
- [ ] Confirm release docs do not claim a production VPN bundle before Network Extension entitlement, provisioning, signing, notarization, stapling, and Gatekeeper pass.

---

## PHASE 2: Cryptography & Key Management (Week 2-3)

**Goal**: Verify post-quantum crypto usage, frame key handling, nonce/replay safety, and macOS secret storage.

### 2.1 PQC Implementation Verification

- [ ] **ML-KEM-768**
  - [ ] Verify `qlink-core` suite identifiers match the FIPS 203 path documented in `README.md`.
  - [ ] Check encapsulation/decapsulation error handling and transcript binding.
  - [ ] Run unit tests covering handshake success, tampered transcripts, and rejected legacy suite identifiers.
  - [ ] Compare against available vendor or NIST KATs when crate support exposes stable vectors.
- [ ] **ML-DSA-65 and SLH-DSA**
  - [ ] Verify device credential generation, signature verification, wrong-key rejection, and stale/expired record handling.
  - [ ] Confirm SLH-DSA is treated as high-assurance suite support, not the default live-device credential unless product requirements change.
- [ ] **ChaCha20-Poly1305**
  - [ ] Verify nonce derivation never repeats for the same key and packet number.
  - [ ] Test corrupted ciphertext, truncated tag, wrong key, malformed frame, and replayed packet rejection.
  - [ ] Confirm packet metadata normalization occurs before frame encryption.

### 2.2 Keychain And Local Secret Handling

- [ ] Review `KeychainSecretStore`, `DeviceKeypairStore`, and `PeerStoreKey` for service names, access controls, overwrite behavior, duplicate-item handling, and delete/recreate behavior.
- [ ] Verify tests isolate Keychain accounts and clean up after themselves.
- [ ] Confirm long-term seeds and peer-store keys are never stored in plain config files or support bundles.
- [ ] Review crash/log paths for accidental key, seed, nonce, or bearer-token exposure.

### 2.3 Cryptographic Attack Scenarios

- [ ] **Nonce Reuse**: Try to force repeated packet numbers, session resets, or peer confusion under the same frame key.
- [ ] **Replay**: Re-send prior accepted packets, stale packets outside the replay window, and cross-peer packets.
- [ ] **Downgrade**: Submit legacy or unsupported suite identifiers and require rejection.
- [ ] **Fault Injection**: Flip bits in ciphertext, signatures, peer records, and config material.

---

## PHASE 3: App, Extension, And IPC Boundary (Week 2)

**Goal**: Find privilege, configuration, and state-corruption bugs across the Swift app, `QuantumLinkKit`, and packet-tunnel provider boundary.

### 3.1 Provider Message Protocol

- [ ] Fuzz `TunnelMessages` decoding with malformed JSON, oversized messages, unknown commands, nulls, type confusion, and version skew.
- [ ] Verify `status`, `disconnect`, `reloadConfiguration`, and diagnostics commands cannot alter protected routes without validated configuration.
- [ ] Test app crash during command, extension crash during command, and stale response handling.

### 3.2 Configuration Validation

- [ ] Mutate `config/mesh.example.json` and managed settings for invalid routes, duplicate routes, invalid MTU, malicious mesh IDs, bad DNS mode, and unsupported crypto suite.
- [ ] Verify invalid config fails before tunnel activation.
- [ ] Verify protected routes and excluded routes cannot create a silent full-route leak.
- [ ] Confirm route-mode decisions from `DeploymentMode` are covered by tests for direct, rendezvous, managed, and private-LAN modes.

### 3.3 App/Extension Trust Boundary

- [ ] Verify app UI state is advisory only and packet routing decisions remain inside the tunnel/core path.
- [ ] Review App Group, Keychain access group, and entitlements for least privilege once Apple profiles are available.
- [ ] Confirm debug/development transport modes cannot be selected by production builds unless an explicit development flag is present.

---

## PHASE 4: Network Extension Route Policy & Kill Switch (Week 3-4)

**Goal**: Verify protected-route enforcement and fail-closed behavior through startup, runtime, crash, sleep/wake, and teardown.

### 4.1 Network Extension Settings

- [ ] Review `PacketTunnelProvider` route creation for included routes, excluded routes, DNS settings, MTU, and remote address.
- [ ] Test invalid CIDR parsing and route normalization.
- [ ] Validate `NEPacketTunnelNetworkSettings` on a real Mac with signed entitlement and provisioning.
- [ ] Verify managed per-app VPN and on-demand rules apply only to intended bundle IDs and route sets.

### 4.2 Fail-Closed Verification

- [ ] Run `TunnelPacketPumpTests` and verify packets drop when the Rust core is unavailable.
- [ ] Run kill-switch tests and verify transport-not-ready packets never enter the core or transport sink.
- [ ] Test transport transition from ready to not-ready and confirm protected packets are dropped.
- [ ] Kill the packet-tunnel extension on a real Mac and capture whether protected traffic leaks, blocks, or reconnects.

### 4.3 Edge Cases

- [ ] Startup race before route settings apply.
- [ ] Configuration reload while packets are flowing.
- [ ] Wi-Fi to Ethernet transition.
- [ ] Sleep/wake and network roam.
- [ ] Captive portal, tethering, and offline recovery.
- [ ] Tunnel stop, uninstall, reinstall, and stale state cleanup.

---

## PHASE 5: Packet Core, Rust FFI, And Frame Encoding (Week 4)

**Goal**: Find memory-safety, parser, route-policy, and frame-handling bugs at the Swift/Rust boundary.

### 5.1 Rust FFI Boundary

- [ ] Review pointer lifetimes, buffer lengths, ownership transfer, and null handling in the Rust FFI surface.
- [ ] Test Swift bridge behavior when the dylib is missing, has incompatible symbols, or returns malformed status.
- [ ] Run `RustCoreBridgeTests` with and without `QLINK_CORE_DYLIB`.
- [ ] Confirm production code fails closed when the Rust bridge cannot initialize.

### 5.2 Packet And Frame Parsing

- [ ] Fuzz IPv4 packets with truncated headers, invalid header lengths, bad checksums, fragments, oversized MTU, unsupported protocols, and outside-protected-route destinations.
- [ ] Fuzz transport frames with undersized frames, oversized frames, corrupted tags, repeated nonces, wrong peer IDs, and stale packet numbers.
- [ ] Verify every malformed input is rejected or counted without plaintext fallback.

### 5.3 Policy Enforcement

- [ ] Verify protected routes are enforced before frame emission.
- [ ] Verify unprotected packets are counted and dropped.
- [ ] Verify failed transport sends drop encrypted frames rather than retrying as plaintext.

---

## PHASE 6: Peer Discovery, Rendezvous, Relay, And Identity (Week 4-5)

**Goal**: Verify peer identity, discovery, relay fallback, and compromised-control-plane assumptions.

### 6.1 Peer Records And Dytallix Trust

- [ ] Verify signed peer records bind peer ID, device public key, routes, endpoints, expiration, sequence number, and crypto suite.
- [ ] Test missing, stale, revoked, mismatched, and unavailable Dytallix registry state for public meshes.
- [ ] Confirm private/development meshes clearly label any warn/allow policy and cannot be confused with public production trust.

### 6.2 Rendezvous And Relay

- [ ] Test rendezvous publication with expired records, replayed records, wrong signatures, duplicate sequence numbers, and malicious endpoint candidates.
- [ ] Verify relay operators cannot read or modify end-to-end encrypted frames.
- [ ] Document relay metadata leakage: peer timing, connection attempts, packet sizes, and failure modes.
- [ ] Add rate-limit, abuse, TLS, authentication, and retention controls before exposing development services publicly.

### 6.3 Transport State Machine

- [ ] Run direct, relay fallback, mesh-loopback, and transport-loopback smokes.
- [ ] Test wrong mesh ID, unauthorized peer, peer removal during active session, reconnect backoff, and simultaneous peer sessions.
- [ ] Verify macOS transport status reports direct, relay, degraded, and fail-closed states distinctly.

---

## PHASE 7: macOS Secrets, Diagnostics, And Privacy (Week 5)

**Goal**: Prevent support, logging, analytics, and crash workflows from leaking sensitive network or identity data.

### 7.1 Diagnostics And Support Bundles

- [ ] Run `SupportBundleExporterTests` and verify default exports redact IP literals, ports, routes, DNS servers, rendezvous servers, relay servers, and overlay addresses.
- [ ] Verify raw diagnostics require an explicit operator action and are clearly labeled.
- [ ] Review `PacketTunnelProvider.diagnosticSummary()` for raw peer, endpoint, route, or token leakage.
- [ ] Confirm support bundles include counts and states rather than full lists where possible.

### 7.2 Logging

- [ ] Review `RustTracingForwarder` and `PrivacyDefaults.redactForLog`.
- [ ] Search OSLog messages for raw network identifiers, keys, endpoints, and peer secrets.
- [ ] Verify malformed Rust tracing events are redacted before logging.

### 7.3 Local Privacy Defaults

- [ ] Verify pseudonymous labels and overlay addresses are generated without exposing hostnames or LAN endpoints.
- [ ] Verify no DNS search-domain default is emitted.
- [ ] Verify private-LAN and managed-enterprise profiles document what metadata is collected and why.

---

## PHASE 8: Packaging, Signing, Updates, And MDM (Week 6)

**Goal**: Validate macOS distribution security and managed deployment controls.

### 8.1 Unsigned Development Packaging

- [ ] Run `scripts/build-rust-xcframework.sh`.
- [ ] Run `scripts/package-dev-artifacts.sh`.
- [ ] If XcodeGen is installed, run `scripts/package-macos.sh --skip-sign --pkg` and treat artifacts as untrusted development output only.
- [ ] Verify unsigned artifacts are never described as production installables.

### 8.2 Developer ID And Notarization

- [ ] Run `scripts/package-macos.sh --pkg` with Developer ID Application and Installer identities.
- [ ] Verify `codesign --verify --deep --strict` on app, extension, helpers, and frameworks.
- [ ] Verify `spctl -a -vv` accepts the app and `spctl -a -vv -t install` accepts the PKG.
- [ ] Verify `xcrun notarytool` success, `xcrun stapler validate`, and offline Gatekeeper behavior.
- [ ] Confirm entitlements contain the production app group and packet-tunnel Network Extension capability.

### 8.3 Updates And Release Manifest

- [ ] Verify Sparkle appcast EdDSA signature and Apple code-signing checks.
- [ ] Verify update from previous signed build to current signed build.
- [ ] Verify downgrade, replayed appcast, tampered archive, and mismatched checksum rejection.
- [ ] Pair update signing with the product-level post-quantum release manifest before production claims.

### 8.4 MDM

- [ ] Validate extension pre-approval, managed defaults, strict kill switch, on-demand, and per-app VPN mobileconfig payloads.
- [ ] Test clean MDM-managed Mac enrollment, policy apply, policy removal, and uninstall.
- [ ] Confirm code requirement extraction for per-app VPN payloads matches signed production binaries.

---

## PHASE 9: Fuzzing & Automated Stress Testing (Week 7)

**Goal**: Find crashes, hangs, parser bugs, state-machine bugs, and data leaks through automation.

### 9.1 Protocol And Packet Fuzzing

- [ ] Add or run fuzz targets for Rust packet core frames, IPv4 parsing, peer records, STUN parsing, rendezvous records, and provider messages.
- [ ] Generate malformed QUIC/native transport frames and verify graceful rejection.
- [ ] Track crashes, panics, memory growth, hangs, and rejected-input counters.

### 9.2 Configuration And MDM Fuzzing

- [ ] Mutate mesh JSON, managed preferences, mobileconfig payloads, and on-demand rules.
- [ ] Confirm invalid values fail before activation.
- [ ] Confirm malformed profile material cannot create permissive routing defaults.

### 9.3 Runtime Stress

- [ ] Run private-LAN harnesses with packet loss, latency, network switches, relay-only mode, and peer churn.
- [ ] Exercise app launch/quit, extension restart, system sleep/wake, and rapid connect/disconnect loops.
- [ ] Record memory, file descriptor, socket, and packet-drop behavior.

---

## PHASE 10: Compliance, Reporting, And Release Decision (Week 8)

**Goal**: Convert testing evidence into a decision-ready audit trail.

### 10.1 Cryptographic Standards

- [ ] Document FIPS 203, FIPS 204, FIPS 205, HKDF-SHA-256, and RFC 8439 ChaCha20-Poly1305 coverage.
- [ ] Record crate versions, KAT status, and any non-validated cryptographic module limitations.
- [ ] Document why Apple notarization and Gatekeeper are distribution controls, not protocol-security proof.

### 10.2 Security Best Practices

- [ ] Verify least privilege for app, extension, Keychain, App Group, MDM payloads, release scripts, and CI secrets.
- [ ] Verify defense-in-depth across route policy, packet pump, Rust core, transport encryption, identity, diagnostics, signing, and update verification.
- [ ] Verify privacy-by-default behavior against support bundles, logs, profile generation, and relay metadata.

### 10.3 Audit Trail

- [ ] Create a vulnerability report with severity, exploitability, affected files, reproduction steps, and remediation.
- [ ] Create a macOS release-blocker ledger with owner, evidence path, and closure criteria for every failed or blocked gate.
- [ ] Create an executive summary that separates implemented local baseline, Apple-gated blockers, real-hardware blockers, and production-ready scope.

---

## Local Verification Commands

Run from `/Users/rickglenn/Desktop/QuantumLink/QuantumLinkOS` unless stated otherwise.

### Environment

```sh
swift --version
rustc --version
cargo --version
xcode-select -p
xcrun --find xctest
command -v xcodegen || true
```

### Baseline

```sh
swift test
cargo fmt --all -- --check
cargo test --workspace
cargo build --workspace --release
```

### macOS Security-Focused Swift Tests

```sh
swift test --filter ConfigurationValidationTests
swift test --filter DeviceKeypairStoreTests
swift test --filter PeerStoreKeyTests
swift test --filter TunnelPacketPumpTests
swift test --filter KillSwitchWatchdogTests
swift test --filter SupportBundleExporterTests
swift test --filter PrivacyDefaultsTests
swift test --filter PerAppVPNPayloadTests
swift test --filter VPNOnDemandRulesTests
swift test --filter MobileConfigSignerTests
swift test --filter RustCoreBridgeTests
swift test --filter TunnelTransportTests
swift test --filter ProductionMeshTransportTests
```

### Transport And Config Smokes

```sh
cargo build --workspace --release
swift run QuantumLinkSmoke validate-config --config config/mesh.example.json
swift run QuantumLinkSmoke preflight \
  --config config/mesh.example.json \
  --transport \
  --mode dev-quic-loopback \
  --dylib "$PWD/target/release/libqlink_core.dylib"
target/release/qlinkctl simulate-handshake
target/release/qlinkctl quic-loopback
target/release/qlinkctl mesh-loopback
target/release/qlinkctl relay-loopback
```

### Pre-Apple Aggregate Gate

```sh
./scripts/preapple-check.sh
```

Expected: Swift tests, Rust formatting, Rust tests, release build, dylib-backed Swift integration tests, config validation, transport preflight, Rust loopback smokes, XCFramework generation, and development artifact packaging pass. Unsigned release package dry run runs only when XcodeGen is installed.

### Apple-Gated Release Gate

```sh
./scripts/package-macos.sh --pkg
codesign --verify --deep --strict --verbose=4 build/release/QuantumLink.app
codesign -dvvv --entitlements :- build/release/QuantumLink.app
spctl -a -vv build/release/QuantumLink.app
spctl -a -vv -t install build/release/QuantumLink.pkg
xcrun stapler validate build/release/QuantumLink.app
xcrun stapler validate build/release/QuantumLink.pkg
```

Expected: Developer ID signature, production App Group, packet-tunnel Network Extension entitlement, notarization success, valid stapling, accepted Gatekeeper assessment, and installable PKG.

---

## Testing Tools & Resources

### Code Review

- [ ] SwiftPM XCTest.
- [ ] Rust unit/integration tests.
- [ ] `cargo fmt --all -- --check`.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` when dependency and target state allow it.
- [ ] Manual review of `macos/Sources/QuantumLinkKit`, `macos/Sources/QuantumLinkTunnel`, `qlink-core/src`, `macos/entitlements`, `macos/mdm`, and release scripts.

### Cryptography

- [ ] FIPS 203, FIPS 204, and FIPS 205 references.
- [ ] RFC 8439 ChaCha20-Poly1305 test vectors.
- [ ] Library KATs or crate-provided deterministic vectors.
- [ ] Side-channel and fault-injection review for signing, decapsulation, and frame authentication.

### macOS Platform

- [ ] Full Xcode with XCTest runtime.
- [ ] Apple Developer account with Packet Tunnel Provider entitlement.
- [ ] Developer ID Application and Installer identities.
- [ ] Notary credentials.
- [ ] Clean unmanaged Mac.
- [ ] Existing-user Mac with prior state.
- [ ] MDM-managed Mac.
- [ ] Apple Silicon Mac and Intel Mac if universal distribution remains supported.

### Network And Runtime

- [ ] `tcpdump`, `nettop`, `scutil --nwi`, `route -n get`, and `ifconfig` for leak and route verification.
- [ ] Network Link Conditioner or equivalent packet loss/latency tooling.
- [ ] Private-LAN harness and `qlinkctl` loopback smokes.
- [ ] OSLog and crash report review.

---

## Deliverables

1. **macOS Security Architecture Review** covering app, extension, Rust core, Keychain, Network Extension, MDM, release, and update boundaries.
2. **Cryptographic Assessment Report** covering PQC, frame keys, nonce/replay handling, KAT status, and non-validated-module caveats.
3. **Packet Tunnel Fail-Closed Report** covering route settings, packet pump, transport outage, crash, sleep/wake, teardown, and leak tests.
4. **Swift/Rust FFI And Packet Fuzzing Report** covering malformed packets, frames, provider messages, and config inputs.
5. **Diagnostics Privacy Report** covering support bundles, OSLog, crash paths, relay metadata, and raw-mode disclosure.
6. **macOS Packaging And Update Security Report** covering Developer ID, notarization, stapling, Gatekeeper, Sparkle, and post-quantum release manifest.
7. **MDM Deployment Report** covering extension pre-approval, per-app VPN, on-demand rules, strict kill switch, managed defaults, and policy removal.
8. **Consolidated Vulnerability Report** with CVSS 3.1 scores and reproduction steps.
9. **Release Blocker Ledger** with evidence paths and closure criteria.
10. **Remediation Roadmap** prioritized by exploitability, release impact, and Apple-gated dependency.

---

## Timeline

- **Week 1**: Architecture, threat model, and platform-readiness boundary.
- **Weeks 2-3**: Cryptography, Keychain, provider message protocol, and config validation.
- **Weeks 3-4**: Network Extension route policy, kill switch, packet core, and Rust FFI.
- **Weeks 4-5**: Peer discovery, rendezvous, relay, Dytallix trust, and transport state machine.
- **Week 5**: Diagnostics, privacy, logging, and local secret exposure.
- **Week 6**: Packaging, signing, notarization, updates, and MDM.
- **Week 7**: Fuzzing, state-machine stress, and runtime leak tests.
- **Week 8**: Compliance mapping, reports, release-blocker ledger, and remediation roadmap.

**Total**: 8 weeks, full-time macOS security audit, with Apple-gated work scheduled only after the required account, entitlement, certificates, profiles, and hardware are available.
