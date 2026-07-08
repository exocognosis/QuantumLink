# QuantumLink SteamOS Security Testing Plan

## Project Overview

- **Type**: Post-quantum encrypted mesh VPN runtime for SteamOS / Steam Deck
- **Architecture**: Privileged Rust `qlinkd` systemd daemon + local `qlinkctl` CLI + Linux TUN interface + route and nftables ownership
- **Crypto**: Shared `qlink-core` post-quantum stack, including ML-KEM-768, ML-DSA-65, SLH-DSA, HKDF-SHA-256, and ChaCha20-Poly1305 packet framing
- **Key Components**: `qlinkd`, `qlinkctl`, `qlink-linux`, `qlink-proto`, `qlink-game`, `qlink-core`, systemd unit, installer, package verifier, Deck validation harness
- **Current Readiness**: Pre-production daemon scaffold. Local Rust, shell, installer, support-bundle, and dev-package gates can be tested now. Production publication remains blocked until signed release artifacts, active rendezvous/relay evidence, public Dytallix registry evidence, and real two-Deck validation are linked from `production-readiness.md`.

## Scope

- **SteamOS silo**: `steam/steamos/**`
- **Shared protocol core**: `qlink-core/**` where SteamOS data-plane, peer-session, crypto, routing, discovery, relay, rendezvous, replay, and identity behavior depends on it
- **Release automation**: `steam/steamos/scripts/**`, `steam/steamos/tests/**`, `.github/workflows/steamos-release.yml`
- **Threat Models**: Local unprivileged user, local admin/root, malicious peer, network attacker, relay/rendezvous operator, Dytallix registry/RPC adversary, supply-chain attacker, diagnostics recipient
- **Testing Types**: Code review, crypto verification, protocol testing, TUN/route/nftables testing, local-control testing, fuzzing, package validation, Deck hardware validation, game compatibility testing, release-signing validation
- **Goals**: Find vulnerabilities, validate fail-closed behavior, prove Steam-safe routing, verify package and install safety, bound privacy leakage, and maintain a clear pre-production vs production-ready evidence line

## Evidence Boundaries

- **Local proof can validate**: parsing, config validation, peer-store permissions, invite lifecycle, local-control ACL contracts, TUN packet pump behavior with fake transports, packet-session fail-closed behavior, nftables rollback planning, installer staging safety, package shape, shell syntax, support-bundle redaction, clippy/static checks.
- **Local proof cannot validate**: real Steam Deck behavior, real route-leak resistance under SteamOS NetworkManager/systemd conditions, anti-cheat compatibility, real voice/game behavior, production signing-key custody, active public Dytallix accept/reject evidence, hardened public rendezvous/relay operations.
- **Production rule**: A dev package can be structurally valid while still reporting `"notProductionReady":true`; that is a blocking publication result, not a warning to waive.

---

## PHASE 1: Architecture & Design Review (Week 1)
**Goal**: Understand the SteamOS trust model, verify the daemon and package boundaries, and identify production-control gaps.

### 1.1 Threat Model Validation
- [ ] Review `THREAT_MODEL.md`, `SECURITY.md`, `steam/steamos/docs/architecture.md`, and `steam/steamos/docs/production-readiness.md`.
- [ ] Map trust boundaries: `qlinkctl` to `qlinkd`, `qlinkd` to Linux TUN, `qlinkd` to nftables/routes, `qlinkd` to shared `qlink-core`, `qlinkd` to rendezvous/relay, and package verifier to release artifacts.
- [ ] Identify attacker-controlled inputs: config JSON, Unix socket requests, invite codes, peer-store records, game profile TOML, TUN packets, transport frames, rendezvous/relay records, support-bundle contents, package sidecars.
- [ ] Document failure modes: daemon crash, packet I/O failure after network activation, network apply failure, nftables apply failure, partial install, failed package verification, stale peer session, expired invite, missing Dytallix registry record.

### 1.2 Control Architecture Review
- [ ] Verify default service mode is dry-run planning, not network activation.
- [ ] Verify `--activate-network` is explicit and mutually exclusive with `--check` and `--deactivate-network`.
- [ ] Verify `--deactivate-network` removes only QuantumLink-owned state from the ownership record.
- [ ] Verify full-tunnel activation fails closed until underlay exemptions exist.
- [ ] Verify package verification treats dev signatures as not production-ready.
- [ ] Verify the production-readiness ledger lists every blocked publication gate.

### 1.3 SteamOS-Specific Data Flow
- [ ] Map game traffic selection: profile TOML -> route mode -> protected CIDR -> Linux policy routing -> `qlink0` -> packet pump -> peer transport.
- [ ] Map Steam bypass decisions for account, store, wallet, checkout, inventory, marketplace, launcher, embedded browser, updates, and login categories.
- [ ] Map diagnostics flow: daemon status -> `qlinkctl doctor` / support bundle -> redaction report.
- [ ] Map release flow: Rust build -> package payload -> sidecars -> checksums -> manifest -> signature -> verifier report -> production-readiness ledger.

---

## PHASE 2: Cryptography & Key Management (Week 2-3)
**Goal**: Verify shared PQC usage remains correct when driven by the SteamOS daemon and packet pump.

### 2.1 PQC Implementation Verification
- [ ] **ML-KEM-768 session establishment**
  - [ ] Verify SteamOS uses the same `qlink-core` session-establishment implementation as other platforms.
  - [ ] Check encapsulation/decapsulation failure handling propagates to fail-closed packet behavior.
  - [ ] Validate test vectors or known-answer fixtures where available.
- [ ] **ML-DSA-65 and SLH-DSA identity**
  - [ ] Verify peer records and inbound identity assertions bind peer ID, mesh ID, endpoint candidates, routes, sequence, expiration, and device key material.
  - [ ] Confirm public mesh mode rejects missing, revoked, suspended, stale, mismatched, or expired Dytallix records.
  - [ ] Confirm private-friends mode does not accidentally accept public-mode records as authoritative without policy.
- [ ] **ChaCha20-Poly1305 packet framing**
  - [ ] Verify nonce uniqueness for each installed peer session.
  - [ ] Verify stale, missing, or revoked packet sessions do not emit transport frames.
  - [ ] Verify corrupted frames, truncated tags, unsupported suites, and malformed IPv4/IPv6 packets are rejected.

### 2.2 SteamOS Secret Storage
- [ ] **Peer store**
  - [ ] Verify `peers.json` is created under the daemon state directory with mode `0600`.
  - [ ] Confirm invite import/revoke/remove paths preserve file permissions.
  - [ ] Test malformed peer-store JSON and oversize peer entries.
- [ ] **Dytallix and wallet material**
  - [ ] Verify no Dytallix private key, wallet seed, entitlement token, or private endpoint is copied into daemon config, support bundles, release packages, or validation evidence.
  - [ ] Verify public-registry proof artifacts are redacted before linking.
- [ ] **Release keys**
  - [ ] Verify production signing keys are not present in the repository, package payload, sidecars, SBOM, or validation directories.
  - [ ] Verify dev signatures cannot pass `QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1`.

### 2.3 Cryptographic Attack Scenarios
- [ ] **Nonce reuse**: Can packet sessions or rekey behavior repeat a nonce for the same key?
- [ ] **Missing peer session**: Can protected packets leave the TUN path before authenticated peer session keys are installed?
- [ ] **Stale session**: Are expired or revoked sessions rejected before frame emission?
- [ ] **Replay**: Does shared replay protection reject duplicate or out-of-window frames per peer/session?
- [ ] **Downgrade**: Can an attacker select a legacy, classical-only, or unsupported crypto suite?
- [ ] **Fault injection**: Do bit flips in frames, peer records, or signatures fail closed?

---

## PHASE 3: Local Control & Privilege Boundary (Week 2)
**Goal**: Find privilege escalation, unsafe local-control behavior, and daemon state corruption.

### 3.1 Unix Socket Protocol Analysis
- [ ] Verify socket path is `/run/quantumlink/qlinkd.sock`.
- [ ] Verify owner/group/mode contract: root owner, `quantumlink` group, `0660` socket mode, systemd runtime directory hardening.
- [ ] Verify local group users can only request status and doctor-style diagnostics.
- [ ] Verify activation, deactivation, peer revoke, peer remove, profile mutation, package install, and support-bundle privileged operations cannot be triggered through read-only status access.
- [ ] Fuzz control requests with malformed JSON, invalid UTF-8, missing newline, oversize payloads above `MAX_CONTROL_REQUEST_BYTES`, slowloris reads beyond timeout, repeated connections, and unsupported command strings.

### 3.2 Privilege Boundary Testing
- [ ] **Unprivileged user -> privileged daemon**
  - [ ] Test whether an unprivileged local user can mutate `/etc/quantumlink`, `/var/lib/quantumlink`, systemd units, activation drop-ins, or ownership records.
  - [ ] Test whether a `quantumlink` group member can escalate from diagnostics to network mutation.
  - [ ] Test TOCTOU behavior around socket replacement, runtime directory recreation, and daemon restart.
- [ ] **Daemon crash and restart**
  - [ ] Verify ownership record survives crash and cleanup retries remove only QuantumLink-owned state.
  - [ ] Verify stale socket files do not widen permissions.
  - [ ] Verify daemon restart does not auto-enable network activation.

### 3.3 Configuration Injection
- [ ] Validate `interfaceName` rejects empty, overlong, path-like, non-ASCII, shell-metacharacter, and `.` / `..` names.
- [ ] Validate `overlayCidr` canonicalization and overlay address membership.
- [ ] Validate rendezvous and relay server entries reject empty entries and are not rendered into shell strings.
- [ ] Confirm typed `Command` argv execution is used for privileged route/nft operations, not shell concatenation.
- [ ] Test symlink and hardlink attacks against config, state, peer-store, ownership-record, and support-bundle paths.

---

## PHASE 4: Network Protocol & Control Plane (Week 3-4)
**Goal**: Find protocol-state, rendezvous, relay, peer-discovery, and registry trust bugs.

### 4.1 Rendezvous And Relay
- [ ] Verify production endpoints require TLS for publish, lookup, relay allocation, control, health, and revocation.
- [ ] Verify publish/lookup requires Dytallix identity, device binding, entitlement status, and caller policy context.
- [ ] Verify peer records are signed, short-lived, sequence-checked, and rejected when expired, malformed, replayed, or signed by revoked keys.
- [ ] Test relay operator MITM assumptions: relay must not read plaintext, forge frames, or modify authenticated frames.
- [ ] Measure metadata exposure: peer timing, source/destination, packet sizes, relay path use, and game profile identifiers.

### 4.2 Public Dytallix Policy
- [ ] Build an accept/reject matrix for missing, active, revoked, suspended, stale, mismatched, expired, wrong-chain, wrong-peer, and endpoint-substitution records.
- [ ] Verify registry lookup configuration pins network ID, chain ID, and allowed RPC endpoints.
- [ ] Verify event-log fallback behavior is intentional and cannot accept unrelated events.
- [ ] Verify public mesh mode fails closed when registry proof is unavailable.

### 4.3 Peer Discovery And Traversal
- [ ] Review signed peer-record validation in `qlink-core`.
- [ ] Fuzz STUN and ICE parsing paths where SteamOS depends on them.
- [ ] Test direct path first, relay fallback, relay-disallowed profiles, and NAT path changes.
- [ ] Validate QUIC certificate binding to signed peer records.
- [ ] Validate mDNS or LAN discovery cannot spoof peer identity or force route-policy changes.

---

## PHASE 5: Packet Core, TUN, And Encoding (Week 4)
**Goal**: Find packet parsing bugs, MTU issues, fail-open paths, and unsafe packet emission.

### 5.1 TUN Packet I/O
- [ ] Verify Linux TUN open uses `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`.
- [ ] Verify TUN interface name is bounded by Linux `IFNAMSIZ` expectations.
- [ ] Verify read buffer handling rejects oversized packets and handles `WouldBlock` without error.
- [ ] Verify writes reject packets above configured MTU.
- [ ] Verify IPv4 and IPv6 protocol-family detection is explicit and malformed packets are rejected.

### 5.2 Packet Pump
- [ ] Verify protected packets are dropped when transport is unavailable.
- [ ] Verify protected packets are dropped when peer session keys are unavailable.
- [ ] Verify stale or revoked peer sessions do not emit frames.
- [ ] Verify inbound frames are authenticated before tunnel packets are written.
- [ ] Verify outbound and inbound counters distinguish observed, queued, dropped, emitted, accepted, rejected, and transport-error states.
- [ ] Fuzz packet bytes: empty packets, first-byte mutations, truncated IPv4 headers, max-MTU packets, over-MTU packets, corrupted encrypted frames, duplicate frames.

### 5.3 Route Policy Enforcement
- [ ] Verify game-only and protected-prefix modes protect only intended overlay/game routes.
- [ ] Verify full tunnel cannot activate until explicit underlay exemptions exist.
- [ ] Verify Steam account/store/wallet/update/login categories bypass by default.
- [ ] Verify no code path silently replaces the SteamOS default route.

---

## PHASE 6: Kill Switch, nftables, And Route Ownership (Week 5)
**Goal**: Verify fail-closed networking, rollback behavior, and state ownership on SteamOS.

### 6.1 nftables Rule Coverage
- [ ] Review generated nftables family, table, route-output chain, filter-output chain, fwmark, and protected CIDR rules.
- [ ] Verify protected destinations cannot leave through the wrong interface.
- [ ] Verify DHCP, DNS, Steam login/store/wallet/update, local LAN, rendezvous, and relay exemptions are explicit and documented before full-tunnel activation.
- [ ] Verify activation creates TUN, address, MTU, rule, route, and nftables state in a deterministic order.
- [ ] Verify apply failure rolls back completed network and nftables operations.

### 6.2 Ownership Record And Teardown
- [ ] Verify `/var/lib/quantumlink/network-ownership.json` is written only after successful activation.
- [ ] Verify teardown reconstructs and removes only owned QuantumLink state.
- [ ] Verify cleanup failures preserve the ownership record for retry.
- [ ] Verify `ExecStop` and `ExecStopPost` call `qlinkd --deactivate-network`.
- [ ] Verify dry-run service starts have no ownership record and no teardown side effects.

### 6.3 Edge Cases
- [ ] **Startup race**: protected route appears before nftables fail-closed policy.
- [ ] **Partial activation**: nftables failure after routes are applied.
- [ ] **TUN failure after activation**: data-plane startup fails and cleanup runs.
- [ ] **System sleep/wake**: routes and nftables state survive or are safely rebuilt.
- [ ] **SteamOS update**: `/usr/local` binaries or unit files disappear and reinstall is safe.
- [ ] **NetworkManager changes**: default route changes while `qlinkd` is active.

---

## PHASE 7: Privilege Escalation & Unsafe Code (Week 5-6)
**Goal**: Find unsafe Rust, FFI, command execution, package install, and local privesc bugs.

### 7.1 Unsafe Code Audit
- [ ] Audit `steam/steamos/rust/qlink-linux/src/tun.rs` for `ioctl` structure layout, interface-name copy, null termination, file descriptor lifetime, and raw constant correctness.
- [ ] Audit any `unsafe` in shared `qlink-core` paths reached by SteamOS packet, crypto, FFI, transport, or replay code.
- [ ] Verify `cargo geiger` or equivalent unsafe-code inventory is clean or justified.

### 7.2 Command Execution And Path Safety
- [ ] Verify privileged network commands call trusted absolute binaries (`/usr/bin/ip`, `/usr/bin/nft`) with typed argv.
- [ ] Verify no untrusted config value can inject extra command arguments or shell metacharacters.
- [ ] Verify installer rejects `DESTDIR=/`, `DESTDIR=/./`, `DESTDIR=//`, and symlinked staging roots.
- [ ] Verify installer protects against symlink swaps in target directories after directory creation.
- [ ] Verify custom `BINDIR`, `SYSD_UNIT_DIR`, `CONFIG_DIR`, and `STATE_DIR` values cannot escape the staging root in package tests.

### 7.3 Information Disclosure
- [ ] Verify support bundles redact private keys, wallet seed material, entitlement tokens, exact peer endpoints, and raw packet payload markers.
- [ ] Verify daemon logs and `journalctl -u qlinkd` do not contain secrets, private endpoints, wallet material, raw packet payloads, or unredacted invite codes.
- [ ] Verify release manifests, SBOMs, checksums, and package payloads do not expose local build paths, private keys, signing-key paths, endpoint credentials, or wallet data.
- [ ] Verify Deck validation evidence excludes raw pcaps and raw support bundles.

---

## PHASE 8: Integration, Package, And Deck Testing (Week 6)
**Goal**: Validate real-world SteamOS behavior, install safety, package integrity, and game compatibility.

### 8.1 Installation & Setup
- [ ] Run staged installer tests with non-root `DESTDIR`.
- [ ] Run live install on Steam Deck A and B.
- [ ] Verify default install does not create live `10-activate-network.conf`.
- [ ] Verify binaries, systemd unit, config directory, state directory, runtime directory, and sample activation drop-in permissions.
- [ ] Verify reinstall is idempotent after a SteamOS update.
- [ ] Verify uninstall/rollback removes owned state and leaves unrelated routes/nftables rules intact.

### 8.2 Release Package Validation
- [ ] Run `package-steamos.sh` and inspect archive payload.
- [ ] Verify `SHA256SUMS.txt`, `SBOM.spdx.json`, `release-manifest.json`, and `verify-report.json`.
- [ ] Verify dev package reports `valid:true` and `notProductionReady:true`.
- [ ] Verify `QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1` rejects dev packages.
- [ ] Verify production package requires a production signature and public-key validation.
- [ ] Verify production signing keys are never committed or packaged.

### 8.3 Steam Deck Hardware Scenarios
- [ ] Preflight dry-run status on Deck A and Deck B.
- [ ] Activated network lifecycle on Deck A and Deck B.
- [ ] Two-Deck protected roundtrip.
- [ ] Steam-safe bypass for account/store/wallet/update/login categories.
- [ ] Factorio dedicated UDP profile.
- [ ] Minecraft LAN-discovery-heavy profile.
- [ ] Peer-hosted world reconnect and suspend/resume.
- [ ] Steam Remote Play style traffic.
- [ ] Voice-chat-safe profile.
- [ ] Relay-disallowed low-latency profile.
- [ ] Support-bundle redaction on real hardware.
- [ ] Uninstall and rollback.

### 8.4 Game Compatibility And Anti-Cheat
- [ ] Test games with LAN discovery, dedicated servers, peer-hosted worlds, Steam matchmaking, voice chat, and streaming traffic.
- [ ] Verify no anti-cheat false-positive or blocked networking behavior caused by TUN/nftables state.
- [ ] Verify route policy keeps Steam commerce, login, account, and launcher traffic outside QuantumLink by default.
- [ ] Verify latency SLOs from `deck-validation.md` under reasonable LAN/WAN conditions.

---

## PHASE 9: Fuzzing & Automated Testing (Week 7)
**Goal**: Use automated mutation to find crash-causing bugs, parser defects, and fail-open states.

### 9.1 Protocol And Packet Fuzzing
- [ ] Fuzz packet-core frame parsing and AEAD rejection paths.
- [ ] Fuzz TUN packet input for IPv4/IPv6/truncated/over-MTU cases.
- [ ] Fuzz signed peer records, inbound identity assertions, rendezvous records, relay frames, STUN messages, and ICE candidates.
- [ ] Fuzz packet-session rekey and replay windows.

### 9.2 Local Control Fuzzing
- [ ] Generate random Unix socket requests within and above `MAX_CONTROL_REQUEST_BYTES`.
- [ ] Test missing newline, multiple JSON lines, invalid UTF-8, large strings, nulls, arrays, nested objects, and slow reads.
- [ ] Monitor daemon for crash, hang, memory growth, state mutation, or widened privileges.

### 9.3 Configuration And Profile Fuzzing
- [ ] Mutate `config.json` route modes, interface names, overlay CIDRs, server lists, and booleans.
- [ ] Mutate game profile TOML names, executables, ports, booleans, duplicate fields, and invalid types.
- [ ] Mutate Steam bypass policy categories and default actions.
- [ ] Verify all invalid inputs fail closed and produce non-secret diagnostics.

### 9.4 Automation Gates
- [ ] `cargo fmt --all --check`
- [ ] `cargo test -p qlink-core -p qlink-proto -p qlink-linux -p qlink-game -p qlinkd -p qlinkctl --locked`
- [ ] `cargo clippy --no-deps -p qlink-game -p qlink-proto -p qlink-linux -p qlinkd -p qlinkctl --all-targets --locked -- -D warnings`
- [ ] `bash steam/steamos/tests/install-steamos-test.sh`
- [ ] `bash -n steam/steamos/scripts/install-steamos.sh`
- [ ] `bash -n steam/steamos/scripts/package-steamos.sh`
- [ ] `bash -n steam/steamos/scripts/verify-steamos-release.sh`
- [ ] `bash -n steam/steamos/tests/deck-validation.sh`
- [ ] Package and verifier roundtrip with `QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=0`
- [ ] Negative package verifier run with `QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1` on a dev package

---

## PHASE 10: Compliance & Documentation (Week 8)
**Goal**: Produce the audit trail, classify findings, and keep release claims evidence-bound.

### 10.1 Cryptographic Standards Compliance
- [ ] **NIST FIPS 203**: ML-KEM usage, test vectors, error handling, downgrade rejection.
- [ ] **NIST FIPS 204**: ML-DSA usage, signature verification, key-generation assumptions.
- [ ] **NIST FIPS 205**: SLH-DSA suite support and interoperability assumptions.
- [ ] **RFC 8439 / ChaCha20-Poly1305**: nonce uniqueness, tag validation, frame authentication.
- [ ] **HKDF-SHA-256**: domain separation, peer/session binding, rekey behavior.

### 10.2 Security Best Practices
- [ ] Least privilege: justify root daemon, group-readable diagnostics, and no default network activation.
- [ ] Defense in depth: packet session keys, route policy, nftables, TUN I/O, release verifier, diagnostics redaction.
- [ ] Fail closed: no protected packet emission without peer session, no full tunnel without underlay exemptions, no production publication without production signature and evidence links.
- [ ] Input validation: config JSON, TOML, Unix socket commands, invite codes, peer records, package sidecars.
- [ ] Output safety: support bundles, logs, release reports, validation evidence, status output.

### 10.3 Audit Trail
- [ ] Document all findings with severity, affected file/line, exploitability, reproduction, and remediation.
- [ ] Categorize findings as Critical, High, Medium, Low, Informational, or Production Gate.
- [ ] Keep separate sections for local validated results, hardware-blocked gates, infrastructure-blocked gates, and deferred future work.
- [ ] Update `production-readiness.md` only when evidence paths exist.
- [ ] Do not claim production-ready until every blocking gate is `Passed`.

---

## Local Verification Bundle

Run from the repository root of the SteamOS branch:

```sh
cargo fmt --all --check
cargo test -p qlink-core -p qlink-proto -p qlink-linux -p qlink-game -p qlinkd -p qlinkctl --locked
cargo clippy --no-deps -p qlink-game -p qlink-proto -p qlink-linux -p qlinkd -p qlinkctl --all-targets --locked -- -D warnings
bash steam/steamos/tests/install-steamos-test.sh
bash -n steam/steamos/scripts/install-steamos.sh
bash -n steam/steamos/scripts/package-steamos.sh
bash -n steam/steamos/scripts/verify-steamos-release.sh
bash -n steam/steamos/tests/deck-validation.sh
bash steam/steamos/scripts/package-steamos.sh
bash steam/steamos/scripts/verify-steamos-release.sh dist/steamos/quantumlink-steamos-0.1.0.tar.zst
QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1 bash steam/steamos/scripts/verify-steamos-release.sh dist/steamos/quantumlink-steamos-0.1.0.tar.zst
```

Expected local result:

- The first eight commands should pass on a correctly provisioned local development host.
- The normal verifier should report a structurally valid development package.
- The production-required verifier command should fail until a production signature and public-key validation are available.
- Passing this bundle does not close the Deck hardware, public Dytallix, rendezvous/relay, or production-signing gates.

## Testing Tools & Resources

### Code Review
- [ ] `cargo fmt`
- [ ] `cargo clippy`
- [ ] `cargo test --locked`
- [ ] `cargo audit`
- [ ] `cargo deny`
- [ ] `cargo geiger`
- [ ] Manual review of `qlinkd`, `qlinkctl`, `qlink-linux`, `qlink-proto`, `qlink-game`, and SteamOS-reached `qlink-core` paths

### Cryptography
- [ ] NIST known-answer tests for ML-KEM, ML-DSA, and SLH-DSA where available
- [ ] ChaCha20-Poly1305 known-answer tests
- [ ] Replay and rekey tests
- [ ] Fault injection fixtures for frame and signature corruption

### Network And Protocol Testing
- [ ] `ip route`, `ip rule`, `ip addr`
- [ ] `nft list ruleset`
- [ ] `journalctl -u qlinkd`
- [ ] `tcpdump` or Wireshark on non-committed local evidence only
- [ ] STUN/ICE/QUIC fuzzers and loopback harnesses

### Steam Deck Testing
- [ ] `steam/steamos/tests/deck-validation.sh`
- [ ] Two Steam Decks on current stable SteamOS
- [ ] LAN controller for route-leak checks
- [ ] Hardened staging rendezvous/relay endpoint
- [ ] Redacted validation evidence under `steam/steamos/validation/deck/<timestamp>/`

### Package And Release
- [ ] `steam/steamos/scripts/package-steamos.sh`
- [ ] `steam/steamos/scripts/verify-steamos-release.sh`
- [ ] `zstd`, `tar`, `sha256sum` or `shasum`, `python3`, `openssl`
- [ ] Production Ed25519 signing key kept outside the repository

---

## Deliverables

1. **SteamOS Security Architecture Review** (Phase 1)
2. **SteamOS Cryptographic Assessment** (Phase 2)
3. **Local Control And Privilege Boundary Report** (Phase 3)
4. **Rendezvous, Relay, And Dytallix Policy Report** (Phase 4)
5. **Packet Core, TUN, And Route Policy Report** (Phase 5)
6. **nftables Kill Switch And Rollback Report** (Phase 6)
7. **Unsafe Code And Installer Privesc Audit** (Phase 7)
8. **Deck Hardware Validation Report** (Phase 8)
9. **Fuzzing And Automated Test Report** (Phase 9)
10. **Compliance Checklist And Remediation Roadmap** (Phase 10)
11. **Consolidated Vulnerability Report**
12. **Production Go / No-Go Decision Update**

---

## Timeline

- **Week 1**: Architecture, threat model, control inventory
- **Weeks 2-3**: Crypto, key/session handling, local control boundary
- **Weeks 3-4**: Network protocol, rendezvous, relay, Dytallix policy
- **Week 4**: Packet core, TUN I/O, route policy
- **Weeks 5-6**: nftables, rollback, privilege escalation, unsafe code
- **Week 6**: Install, packaging, release verifier, Deck setup
- **Week 7**: Fuzzing and automation hardening
- **Week 8**: Compliance, reports, remediation roadmap, go/no-go evidence

**Total**: 8 weeks, full-time security audit, plus any blocked time required for real Steam Deck hardware, production signing, public registry evidence, and hardened rendezvous/relay staging.
