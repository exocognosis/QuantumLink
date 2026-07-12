# QuantumLink macOS — Full Feature & Functional Execution Plan

> Created 2026-07-12. Goal: take the macOS build from ~55% to a fully featured, functional, production-grade release: all connection types (LAN, direct, mesh/relay) live, with the Dytallix on-chain identity protocol integrated and enforced.

## Where we are (baseline, 2026-07-12)

Grounded in code inspection, not doc claims:

- **Crypto core ~88%** — ML-KEM-768, ML-DSA-65, SLH-DSA-128s, anti-downgrade suite binding, replay window, ChaCha20-Poly1305 frames all implemented in `rust/qlink-core/src/crypto.rs` + `packet_core.rs` + `replay.rs`.
- **Mesh state machine ~60%** — elaborate connector in `rust/qlink-core/src/mesh_connection.rs` (2,588 ln) + `mesh_transport.rs` (2,578 ln): rendezvous lookup, direct probe, relay fallback, last-good caching. Dev-grade, not hardened.
- **Live data plane ~35%** — `quic_transport.rs` binds real UDP sockets but the shipped FFI path is `qlink_dev_quic_transport_*` (loopback, self-signed). Production session-key install into packet frames is listed *not complete* in `FEATURES.md`.
- **Connection types ~55%** — mDNS (`mdns_discovery.rs`), ICE (`ice.rs`, 1,034 ln), STUN (`stun.rs`) exist; **full ICE/STUN/TURN nomination incomplete; no TURN client**.
- **On-chain Dytallix identity ~18% (on this branch)** — NOT on `main`. Real 1,392-line `dytallix_identity.rs` + `dytallix/quantumlink-node-registry` crate + Swift UX exist in silo worktrees, reconciled against the `qlink-core/`+`macos/Sources/` **silo layout**, which differs from this repo's `rust/qlink-core/`+`Sources/` layout. On `main`, identity = app-layer ML-DSA assertions (`inbound_identity.rs`), not on-chain.
- **App/UX shell ~80%** — `Sources/QuantumLinkApp/QuantumLinkApp.swift` (2,617 ln), all views present, bound to simulated/dev state.
- **Packet tunnel ~55%** — `Sources/QuantumLinkTunnel/PacketTunnelProvider.swift` + kill-switch + fail-closed pump coded; cannot run without Apple entitlements/signing.
- **Enterprise/MDM ~70%**, **Signing/notarization ~25%**, **Real-hardware validation ~10%**.

Test culture is strong: **147 Rust tests**, **25 Swift test files** — plan is TDD-first to match.

## Strategic update (2026-07-12) — the silo branch is ahead of `main`

Discovered while executing the Phase 3 spike: the cross-platform **silo** branch's `qlink-core` (in `.worktrees/*/qlink-core/`) is materially ahead of this repo's `main` and already contains, with tests, much of what this plan framed as net-new:

- **Phase 1 modules exist in silo, missing from main:** `carrier_transport` (1,117 ln, 12 tests — the native UDP carrier), `session_crypto` (751 ln, 7 tests), `pqc_frame` (242 ln, 3 tests — session-keys-into-frames), `pqc_session_wire` (221 ln, 2 tests).
- **Phase 3 connection wiring exists in silo:** `mesh_connection.rs` already wires `IdentityRegistryLookup` + `verify_registry_binding` to gate dialing.
- Silo `qlink-core` has **252 test fns vs main's 192**.

**Revised strategy for Phases 1 & 3:** treat them as a **structured module-by-module reconcile-port from silo → this repo's `rust/qlink-core/` layout, gated by the test suite** (as done successfully for `dytallix_identity` + `quantumlink-node-registry` on 2026-07-12), NOT as net-new implementation. Risk to manage: silo uses the `qlink-core/`+`macos/Sources/` layout and other modules (`mesh_connection` +130, `mesh_transport` +295) have diverged — reconcile per-module with tests green, do not wholesale-copy.

### Landed on branch `feat/macos-full-feature` (2026-07-12, uncommitted)
- Dytallix SDK deps (`dytallix-core`/`dytallix-sdk` @ `657d0db`) + `hex`/`reqwest` added to `rust/qlink-core/Cargo.toml`; builds clean.
- `quantumlink-node-registry` contract crate ported to `dytallix/quantumlink-node-registry/`, workspace member; **native 23 tests pass**, WASM deploy artifact built + validated (388 KB).
- `dytallix_identity.rs` (2,122 ln) ported to `rust/qlink-core/src/`; **45 module tests pass**; full suite **203 pass, 0 fail** (no regressions). — commit `292fb19`
- **Phase 1 foundation ported** from silo: `carrier_transport` (12 tests), `session_crypto` (7), `pqc_frame` (3), `pqc_session_wire` (1); added `sha3` + declared `dev-quic-carrier` feature (off). qlink-core suite **226 pass, 0 fail**. — commit `7f23e5a`
- **Registry contract deployed + live-verified** at `0xbcb5cf5abb50333ee4bfde91f21bbcc24828673d`; `config/dytallix-testnet.json` + `tests/dytallix_live.rs`. — commits `ce2729a`, `7257f73`
- **SHAKE256 stack adopted** (decision over legacy HKDF): `crypto.rs` migrated (suites `…-SHAKE256-v1`); `packet_core.rs` gains production peer-session key installation (`install_peer_session` + `require_peer_session`); suite strings synced across ffi/config/Swift. **232 pass / 0 fail.** — commit `1ba142d`
- **Mesh reconcile DONE — Phase 1 + Phase 3 converge on the live dial path:** `mesh_transport`/`mesh_connection` ported; `MeshTransportConfig` now carries `mesh_trust_policy` + `dytallix_identity`, and the connector gates dialing on `verify_registry_binding` while driving `CarrierSession` + PQC session install. `inbound_identity`/`quic_transport`/`qlinkctl` reconciled. **Default (production) build 213 pass / 0 fail; dev-quic 256 pass serially** (2–4 flaky only under high parallelism — tight in-process QUIC timeouts). — commits `d800db0`, `1901324`
- **Live enforcement ACTIVATED** (commits `8d56eff`, `28f6390`): shipped `config/mesh-transport.public.example.json` (`meshTrustPolicy=public_required` + `dytallixIdentity` → deployed contract); the core auto-builds the live registry and gates connector + responder. Proven end-to-end against the DEPLOYED contract in `tests/dytallix_live.rs`: an unregistered peer is rejected by a public mesh (fail closed), accepted by dev. A non-network CI guard asserts the shipped config stays enforcing.
- **(c) SHAKE256 core is macOS-ready** (2026-07-12): `cargo build -p qlink-core --release` succeeds for `aarch64-apple-darwin` + `x86_64-apple-darwin`; `scripts/build-rust-xcframework.sh` produced the universal lib `macos/build/qlink-core-universal/libqlink_core.a` (verified to embed `QLINK-FIPS203-MLKEM768-SHAKE256-v1`, not HKDF). `swift build` compiles.
- **⛔ ENVIRONMENT BLOCKER:** this machine has only Command Line Tools, **not full Xcode**. So `xcodebuild -create-xcframework` (final `.xcframework` packaging) and `swift test` (no `XCTest` module) **cannot run here**. FFI ABI is unchanged, so the existing `.xcframework` structure/header stays valid — only its lib slice needs refreshing on an Xcode machine.
- **Next up (needs full Xcode to verify):** (b) Swift enrollment + discovery-identity UX — port `DytallixEnrollmentSettings` / `DiscoveryIdentityPresentation` / `DytallixEnrollmentCommandOutput` + `TunnelProviderConfigurationCodec`, and inject `meshTrustPolicy`/`dytallixIdentity` into the FFI `MeshTransportConfig` JSON (silo composes this above `MeshTransportConfiguration`, not as struct fields). This is a large multi-file reconcile (`TunnelTransport.swift` also diverged — silo disables the dev-quic loopback) that is only compile-checkable here, not test-verifiable. Then (d) Phase 2 ICE/STUN/TURN; (e) dev-quic test-timeout polish; Phase 5/6 (Apple signing + hardware validation). NB: prior `qlinkctl` WIP preserved in `git stash`.

## Critical external dependencies (gate completion, not code)

1. **Dytallix chain reachability — RESOLVED / CLOSED 2026-07-12.** SDK builds + coexists with qlink-core (zero conflicts). Registry contract **deployed** to the public testnet at `0xbcb5cf5abb50333ee4bfde91f21bbcc24828673d` (owner `dytallix13duzmpz…dpvgg`, tx `0x05d828c9…a3dc`) and **live-verified** from qlink-core via `tests/dytallix_live.rs` (a `get_node` lookup returns a well-formed `Ok(None)` for an unregistered peer). Captured in `config/dytallix-testnet.json`. Gateway `https://dytallix.com`. No remaining external inputs — the only work left for live *enforcement* is internal (the mesh dial-path reconcile). NB: publishing the CLI-side fix required fixing DytallixHQ/dytallix-sdk PR #17 (gas fee checked against DRT not DGT).
2. **Apple credentials** — Developer ID cert, Network Extension entitlement, provisioning profiles, notary API key gate Phase 5. Nothing runs as a real tunnel or ships signed until these exist.
3. **TURN infrastructure** — completing the relay path needs either a stood-up `coturn` (recommended) or a bespoke QUIC relay.

## Architecture of the plan

Six phases. **Phase 0 first.** Phases 1–3 are independent subsystems (transport / traversal / identity) and run in parallel. Phase 4 depends on Phase 1. Phase 5 is Apple-gated and preps in parallel. Phase 6 is final validation. Start the Phase-3 chain-reachability spike on day one — it is the longest-lead risk.

```
P0 hygiene ─┬─ P1 live carrier ───┬─ P4 tunnel/privacy ─┐
            ├─ P2 ICE/STUN/TURN ──┘                      ├─ P6 validation & release
            └─ P3 Dytallix on-chain identity ────────────┤
                                     P5 Apple signing ────┘  (parallel, credential-gated)
```

---

## Phase 0 — Integration branch, source-of-truth, green baseline

**Goal:** one canonical layout, a clean branch, and a recorded green baseline so every later phase measures against truth.

**Files:** `Cargo.toml` (workspace), `Package.swift`, `docs/` status docs. Remove/needs-decision: `Package.swift.blocked-read-20260521`, `.build.codex-stale-*`.

- [ ] Confirm canonical layout is this repo's `rust/qlink-core/` + `Sources/` (decision: do **not** adopt the silo `qlink-core/`+`macos/Sources/` layout; port into this one).
- [ ] Create branch `feat/macos-full-feature` off `main`.
- [ ] Run and record baseline: `cargo test` (expect ~147 passing) and `swift test` (25 suites). Capture pass/fail list.
- [ ] Triage stale artifacts (`.build.codex-stale-*`, `Package.swift.blocked-read-*`, extra `QuantumLink N.xcodeproj` copies) — archive or delete after confirming they are not referenced.

**Done when:** clean branch, documented green baseline, no ambiguity about which layout/xcodeproj is canonical.

---

## Phase 1 — Live production data-plane carrier

**Goal:** two real peers carry encrypted traffic over the network (not loopback), with negotiated ML-KEM session keys installed into packet-frame encryption, no `dev-quic-carrier`.

**Files:** `rust/qlink-core/src/mesh_connection.rs`, `mesh_transport.rs`, `quic_transport.rs`, `rendezvous.rs`, `packet_core.rs`, `ffi.rs`, `src/bin/qlinkctl.rs`; `Sources/QuantumLinkKit/RustCoreBridge.swift`, `TransportSmokeRunner.swift`, `TunnelTransport.swift`; tests `Tests/QuantumLinkKitTests/RustMeshTransportTests.swift`, `ProductionMeshTransportTests.swift`.

- [ ] **Failing test first:** two peer records with real UDP endpoint candidates; assert direct probe returns an established production session, not the dev-loopback path.
- [ ] Promote `quic_transport` production path: real bind addresses from rendezvous candidates, production certificate/trust handling (not the loopback self-signed test cert), behind a `production-carrier` feature; keep dev-quic loopback for tests only.
- [ ] Install negotiated ML-KEM-derived session keys into `packet_core` frame encryption with mandatory time+byte rekey thresholds (closes `FEATURES.md` "Not Production-Complete" #1).
- [ ] Real rendezvous publish/lookup over the network in `rendezvous.rs` (replace loopback-only smoke path).
- [ ] `qlinkctl` direct-send/mesh-connect report `selected_path=native-udp-direct | relay | fail-closed`; preserve fail-closed when no protected path.
- [ ] macOS smoke bridge distinguishes: direct established / relay established / fail-closed.

**Verify:** `cargo test -p qlink-core production_carrier`, `... synthetic_wan`, `... --no-default-features --features production-carrier`; `swift test --filter RustMeshTransportTests`, `--filter ProductionMeshTransportTests`.

**Done when:** default live mesh uses production carrier direct-probe or hardened relay fallback with no `dev-quic-carrier`, and session keys are installed into frame crypto end-to-end.

---

## Phase 2 — Connection types: complete ICE / STUN / TURN nomination

**Goal:** LAN, server-reflexive, and relay candidates gathered, prioritized, and nominated deterministically; TURN relay client real; mDNS opt-in.

**Files:** `rust/qlink-core/src/ice.rs`, `stun.rs`, `traversal.rs`, `relay.rs`, `mdns_discovery.rs`, `mesh_transport.rs`; `Sources/QuantumLinkKit/TunnelTransport.swift`, `ConnectionProfile.swift`, `ManagedConfiguration.swift`; tests `DirectConnectionRoutingTests.swift`, `TunnelTransportTests.swift`, `rust/qlink-core` synthetic_wan.

- [ ] Deterministic candidate priority: (1) local/private LAN, (2) server-reflexive STUN, (3) TURN/relay, (4) fail-closed for protected routes.
- [ ] Complete ICE connectivity-check pacing + nomination (currently "optional helper paths").
- [ ] **TURN client** in the relay path (no TURN today). Decide `coturn` deployment vs bespoke QUIC relay (see external dep #3).
- [ ] mDNS LAN discovery hardened and **off by default on untrusted LANs** (privacy per `product.md`).
- [ ] Managed-profile fields: allowed relay endpoints, relay TLS policy, max candidate age, fail-closed behavior.
- [ ] Tests: LAN beats relay; STUN wins when LAN absent; relay when direct fails; protected route fails closed; captive-portal/offline never leak outside the tunnel.

**Verify:** `cargo test -p qlink-core synthetic_wan`; `swift test --filter DirectConnectionRoutingTests`, `--filter TunnelTransportTests`.

**Done when:** all three connection types (LAN direct, direct-via-STUN, relay) demonstrably nominate correctly under the synthetic-WAN matrix, with fail-closed guarantees.

---

## Phase 3 — Dytallix on-chain identity integration (headline requirement)

**Goal:** port the real Dytallix identity registry into this repo's layout and enforce chain-backed trust for public meshes. References: `docs/superpowers/specs/2026-06-01-dytallix-identity-registry-design.md`, `docs/superpowers/plans/2026-06-01-dytallix-identity-registry.md`, `docs/dytallix-upstream-sources.md`.

**Source to port (silo layout → this layout):** `.worktrees/*/qlink-core/src/dytallix_identity.rs` (reconciled 1,392-ln version), `.worktrees/*/dytallix/quantumlink-node-registry/` crate, Swift enrollment/UX deltas.

**Files (target):** new `rust/qlink-core/src/dytallix_identity.rs`; new workspace member `dytallix/quantumlink-node-registry/`; `Cargo.toml` (add members + `dytallix-core`/`dytallix-sdk` pinned git deps); `rust/qlink-core/src/mesh_connection.rs`, `inbound_identity.rs`, `discovery.rs`, `lib.rs`, `src/bin/qlinkctl.rs`; `Sources/QuantumLinkKit/` new `DytallixEnrollmentSettings.swift`, plus `Models.swift`, `ConfigurationValidation.swift`, `ManagedConfiguration.swift`, `TunnelTransport.swift`; `Sources/QuantumLinkApp/QuantumLinkApp.swift` (enrollment + discovery-identity UX); `scripts/dytallix-live-validation.sh`, `scripts/dytallix-identity-e2e.sh`; tests.

- [x] **Day-one spike (longest lead) — DONE 2026-07-12:** pinned `dytallix-core`/`dytallix-sdk` deps added to `rust/qlink-core/Cargo.toml`; SDK builds standalone and coexists with qlink-core's graph (no conflicts); testnet gateway live with `/contracts/call` + `/contracts/deploy`. Still needed for live enforcement: deployed registry contract address + funded testnet wallet.
- [ ] Port `IdentityRegistry` trait + `DytallixIdentityRegistry` (lookup / register / verify_binding) near discovery, **not** in packet crypto.
- [ ] Registry data model + decision states per spec (`accepted`, `rejected_missing_registry`, `rejected_revoked`, `rejected_key_mismatch`, `rejected_record_hash_mismatch`, `registry_unavailable`, …).
- [ ] Enforce mesh trust policy in connection decisions: **public = required/fail-closed**, private = preferred/warn, dev = optional. Wire into outbound (`PeerRecord`) and inbound (`InboundIdentityAssertion`) verification.
- [ ] Registration / update / revoke flows (device key signs binding statement; wallet submits contract call).
- [ ] Swift UX: wallet present/missing, registry status, discovery-identity mode **Off / Verified / Public Wallet** (public meshes may not select Off), last verification result, **wallet-address redaction** outside Public Wallet mode. Tunnel receives validated policy only — never wallet secrets.
- [ ] Rust tests per spec (public rejects missing/revoked/mismatch; private warns+accepts; dev bypass; register/update/revoke/lookup against real contract state machine). Swift tests (policy mapping, redaction, config encoding).

**Verify:** `cargo test -p qlink-core dytallix`; `scripts/dytallix-live-validation.sh`; `scripts/dytallix-identity-e2e.sh`; `swift test --filter DytallixEnrollmentSettingsTests --filter DytallixPeerTrustModelTests`.

**Done when:** public meshes enforce pinned Dytallix production trust and fail closed on registry errors; enrollment + discovery-identity UX ships; no mocks/stubs in the identity path.

---

## Phase 4 — macOS packet tunnel + privacy production hardening

**Goal:** the running tunnel preserves fail-closed protected routes across the real data plane and leaks nothing in default diagnostics. Depends on Phase 1.

**Files:** `Sources/QuantumLinkTunnel/PacketTunnelProvider.swift`, `Sources/QuantumLinkKit/TunnelPacketPump.swift`, `KillSwitchWatchdog.swift`, `SupportBundleExporter.swift`, `PrivacyDefaults.swift`, `PerAppVPNPayload.swift`; tests for each.

- [ ] Prove protected routes stay blocked when the data plane is unavailable, the provider stops unexpectedly, or route re-application fails after sleep/wake.
- [ ] Support bundles redact raw peer IDs, **wallet addresses**, endpoint candidates, routes, DNS, and packet captures unless an elevated raw-export action is taken.
- [ ] MDM + per-app VPN payloads use production bundle IDs, app group, NE payload keys, per-app rules — no kext/pf assumptions. Reconcile `macos/mdm/*.template`, `macos/entitlements/*`, `macos/config/*.xcconfig`.
- [ ] macOS recovery: on wake/interface change, mark candidate pairs suspect, probe last-good, race fresh candidates.

**Verify:** `swift test --filter TunnelPacketPumpTests --filter KillSwitchWatchdogTests --filter SupportBundleExporterTests --filter PrivacyDefaultsTests --filter PerAppVPNPayloadTests`; `./scripts/preapple-check.sh`.

**Done when:** fail-closed proven across churn, and default exports are clean.

---

## Phase 5 — Apple signing, notarization, updates (credential-gated)

**Status:** Apple-dependent. Prep scripts/CI now; execute when credentials land.

**Files:** `macos/project.yml`, `macos/config/*.xcconfig`, `macos/entitlements/*`, `macos/scripts/macos-release-readiness.sh`, `package-macos.sh`, `sparkle-build-appcast.sh`, `.github/workflows/release.yml`, `Sources/QuantumLinkApp/UpdateController.swift`.

- [ ] Configure Apple inputs (Developer ID cert, NE entitlement, provisioning profiles, notary API key, Sparkle EdDSA key, bundle IDs, app group, team) as CI secrets/vars.
- [ ] Produce signed `QuantumLink.app` + `.pkg` + `.dmg`, notarize, staple, `SHA256SUMS.txt`.
- [ ] Validate `codesign`/`spctl`/`stapler`; Gatekeeper accepts app + installer.
- [ ] Signed Sparkle appcast **plus post-quantum release manifest layer** (Sparkle signing is classical).

**Done when:** app + extension are Developer ID signed with production entitlements, notarized, stapled, Gatekeeper-accepted, and the update channel is signed.

---

## Phase 6 — Real-hardware validation & release decision

**Files:** `docs/beta-testing/macos-production-validation.md`, `docs/release-operator-checklist.md`, `product.md`, `FEATURES.md`.

- [ ] Two-Mac live mesh: LAN direct path, mesh via real rendezvous, relay fallback.
- [ ] Dytallix enrollment + public-mesh verification against the live registry.
- [ ] Adverse transitions: sleep, wake, Wi-Fi roam, captive portal, offline, tethering, relay-only.
- [ ] Signed update: previous build → RC via signed appcast; verify signature + state preservation.
- [ ] Clean-install, existing-user, and MDM-managed Macs; Apple Silicon (+ Intel if targeted).
- [ ] Record artifact SHA256s, machine classes, pass/fail, limitations, release decision. Update `product.md`/`FEATURES.md` from "not production-complete" to a precise status only after gates pass.

**Done when:** validation passes on all machine classes and the release decision is recorded with evidence.

---

## Sequencing & ownership (suggested subagent batches)

1. **Transport agent** — Phase 1.
2. **Traversal agent** — Phase 2.
3. **Identity agent** — Phase 3 (start chain-reachability spike immediately).
4. **Tunnel/privacy agent** — Phase 4 (after Phase 1 lands).
5. **Release-eng agent** — Phase 5 (after Apple credentials).
6. **Validation agent** — Phase 6 (after 1–5).

## Overall done definition

macOS is full-feature/functional when: default live mesh uses the production carrier (no dev-quic); LAN/direct/relay nominate correctly with fail-closed guarantees; public meshes enforce pinned Dytallix on-chain identity; the packet tunnel preserves fail-closed protected routes; the app+extension are signed, notarized, stapled, Gatekeeper-accepted; updates are signed + PQ-manifest-paired; and real-hardware validation passes on clean, existing-user, and MDM-managed Macs.
