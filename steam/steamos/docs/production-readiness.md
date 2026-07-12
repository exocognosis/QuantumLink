# SteamOS Production Readiness

## Release Target

- Product: QuantumLink for SteamOS
- Channel: production candidate
- Distribution: direct Steam Deck / SteamOS installer
- Runtime: `qlinkd` systemd daemon plus `qlinkctl`
- Shared core: `qlink-core`
- Default mesh: private friends mesh with invite-based trusted peers

## Blocking Gates

| Gate | Status | Evidence |
|---|---|---|
| Live TUN to peer transport | Blocked | The resident daemon now builds a live `DaemonMeshTransport` (shared `qlink-core` `MeshTransportHandle`, or a local-echo dev transport when no rendezvous is configured) from a persistent device identity and drives the bidirectional pump in `pump_and_serve_once`. On-device local-echo roundtrip proven 2026-07-12 (`cargo test -p qlinkd pump_and_serve_once_round_trips_protected_packet_through_local_echo -- --nocapture`); earlier bridge tests still pass (`cargo test -p qlinkd live_mesh_transport`). Production still requires a two-Deck packet roundtrip evidence directory under `../validation/deck/<timestamp>/`, and peer-session-key installation into packet-frame encryption over the real transport remains the shared cross-platform gap (the mesh variant fails closed, matching macOS/Windows) |
| Production packet-session keys | Passed | Codex local automation on 2026-06-30: `cargo test -p qlink-core packet` and `cargo test -p qlinkd packet_session_keys -- --nocapture`; fail-closed missing/stale session coverage passed |
| Steam-safe bypass | Blocked | The `qlink-game` policy is no longer orphaned: `qlinkd` loads it into `SteamBypassSummary` at startup, validates the protected overlay CIDR against the policy, and logs the posture; `qlinkctl`'s operator guide derives its Steam-safe disclosure from the same policy so enforcement and disclosure share one source. Verified 2026-07-12 (`cargo test -p qlinkd game::`, `cargo test -p qlinkctl steam_safe_disclosure`). Local profile tests still pass (`cargo test -p qlink-game steam_bypass`). Real Deck route-leak evidence for Steam account/store/wallet/update/login categories is still required |
| nftables rollback | Passed | Codex local automation on 2026-06-30: `cargo test -p qlink-linux network_lifecycle -- --nocapture`; fake-executor rollback and owned-record retry paths passed |
| Private invite peer lifecycle | Passed | Codex local automation on 2026-06-30: `cargo test -p qlinkd peer_lifecycle -- --nocapture` and `cargo test -p qlinkctl`; invite import, revoke, expiry, peer trust output, and 0600 peer-store checks passed |
| Public Dytallix policy | Blocked | Shared-core status policy tests pass locally, but live public registry accept/reject evidence for missing, revoked, suspended, mismatched, stale, unavailable, and active records is not linked; sidecar schema/verifier: [`production-evidence.md`](production-evidence.md), [`../scripts/verify-production-evidence.sh`](../scripts/verify-production-evidence.sh) |
| Rendezvous/relay production profile | Blocked | Requirements/runbook: [`rendezvous-relay-production.md`](rendezvous-relay-production.md); active TLS/auth/rate-limit/retention/rotation endpoint evidence is not linked; sidecar schema/verifier: [`production-evidence.md`](production-evidence.md), [`../scripts/verify-production-evidence.sh`](../scripts/verify-production-evidence.sh) |
| Non-root local control | Passed | Codex local automation on 2026-06-30: `cargo test -p qlinkd local_control_acl -- --nocapture`, `cargo test -p qlinkctl support_bundle -- --nocapture`, and `bash steam/steamos/tests/install-steamos-test.sh` |
| Signed release artifacts | Blocked | Dev package verified on 2026-06-30 at `dist/steamos/quantumlink-steamos-0.1.0.tar.zst`; 2026-07-02 verifier hardening keeps readiness in `verify-report.json` and requires public-key signature validation plus non-hardware production evidence validation for production publication, but production signing key/signature evidence is still absent |
| Deck validation | Blocked | Hardware runbook: [`deck-validation.md`](deck-validation.md), harness: [`../tests/deck-validation.sh`](../tests/deck-validation.sh), evidence verifier: [`../tests/verify-deck-evidence.sh`](../tests/verify-deck-evidence.sh); no real two-Deck evidence directory is linked |
| Game compatibility | Blocked | Matrix placeholder: [`deck-validation.md`](deck-validation.md), profiles: `../config/games/factorio.toml`, `../config/games/minecraft.toml`, `../config/games/steam-remote-play.toml`; no real game-session evidence is linked |
| Diagnostics redaction | Passed | Codex local automation on 2026-06-30: [`support-bundle-redaction.md`](support-bundle-redaction.md) plus `cargo test -p qlinkctl support_bundle -- --nocapture`; no raw bundle evidence committed |

## 2026-06-30 Local Verification

- Host class: local macOS development host with fake TUN/network executors; no Steam Deck hardware was attached.
- Operator/job: Codex local automation on branch `codex/steamos-production-gap-closeout`.
- Passed: `cargo fmt --all --check`.
- Passed: `cargo test -p qlink-core -p qlink-proto -p qlink-linux -p qlink-game -p qlinkd -p qlinkctl --locked`.
- Passed: `cargo clippy --no-deps -p qlink-game -p qlink-proto -p qlink-linux -p qlinkd -p qlinkctl --all-targets --locked -- -D warnings`.
- Passed: shell syntax for installer, package, verifier, and Deck-validation scripts.
- Passed: `bash steam/steamos/tests/install-steamos-test.sh`.
- Package verification: `steam/steamos/scripts/package-steamos.sh` produced `dist/steamos/quantumlink-steamos-0.1.0.tar.zst`; `steam/steamos/scripts/verify-steamos-release.sh` reported `"valid":true` and `"notProductionReady":true`.
- Decision: No-Go for production publication until production signing, active rendezvous/relay evidence, public Dytallix registry evidence, and real Steam Deck validation evidence are linked.

## 2026-07-02 Evidence Gate Hardening

- Host class: local macOS development host with fixture-based Deck/SteamOS evidence simulation; no Steam Deck hardware was attached.
- Operator/job: Codex local automation on branch `codex/steamos-production-evidence-gates`.
- Added Deck evidence host classification so `hardwareClaimed` is true only when the evidence host identifies as SteamOS and Steam Deck hardware.
- Added `steam/steamos/tests/verify-deck-evidence.sh` to validate required evidence files, redaction booleans, forbidden raw artifact names, and optional hardware-required proof.
- Added `steam/steamos/tests/verify-steamos-release-test.sh` to cover release verifier schema, production-readiness failure for dev packages, missing public-key failure for production-mode packages, and workflow publication guards.
- Tightened release packaging so `release-manifest.json` records signing mode and signature coverage, while production readiness is decided only by `verify-report.json` after verifier checks.
- Tightened SteamOS release workflow so manual production signing dispatch requires production-ready verification and upload uses the final verification report instead of a stale package-time report.
- Added `steam/steamos/scripts/verify-production-evidence.sh` and `steam/steamos/docs/production-evidence.md` so public Dytallix and rendezvous/relay non-hardware proof travel as a signed sidecar gate instead of prose-only readiness.
- Extended package, release verification, and the SteamOS release workflow so `production-evidence-manifest.json` is included in sidecar artifacts when provided and `verify-report.json` exposes `nonHardwareProductionEvidenceValidated` plus `nonHardwareProductionReady` without asserting full `productionReady`.
- Decision: No-Go remains unchanged until production signing, active rendezvous/relay evidence, public Dytallix registry evidence, and real Steam Deck validation evidence are linked.

## 2026-07-12 Resident Data Plane + Game Layer Wiring

Brings the SteamOS silo to the same wiring maturity as the macOS and Windows
silos: the resident daemon runs a live packet pump against a real mesh transport
(not just in tests), the daemon owns a persistent device identity, and the
Steam-safe game layer is wired into the daemon and CLI instead of shipping as an
orphaned crate.

- Host class: local macOS development host with fake TUN (`LoopbackTunDevice`),
  the local-echo dev transport, and fake network executors; no Steam Deck
  hardware was attached and no real rendezvous/relay network was contacted.
- Added `qlinkd::identity`: a persistent `0600` ML-DSA device keypair + peer
  store key under the state directory (the SteamOS analogue of the Windows DPAPI
  secret store and the macOS Keychain), which the mesh transport requires.
- Added `qlinkd::mesh_runtime::DaemonMeshTransport`: the SteamOS counterpart of
  the Windows `ActiveTransport`, wrapping the shared `qlink-core`
  `MeshTransportHandle` behind the existing `MeshFrameTransport` contract, with a
  local-echo development transport when no rendezvous server is configured.
- Rewrote `run_resident` so the daemon builds the transport and drives the
  bidirectional packet pump (`pump_and_serve_once`) concurrently with the control
  socket, with SIGTERM/SIGINT-driven clean shutdown. Previously the resident loop
  only served status and never moved packets.
- Set the production Linux TUN non-blocking so the single-threaded resident pump
  cannot stall on an idle interface (`qlink-linux`).
- Wired `qlink-game` into `qlinkd` (Steam-safe bypass policy validation, host
  selection) and `qlinkctl` (policy-derived disclosure); installer now places
  `steam-bypass.toml` and `games/*.toml` under `/etc/quantumlink`.
- Passed: `cargo test -p qlinkd -p qlink-game -p qlink-linux -p qlinkctl -p qlink-proto`
  (all green; adds device-identity, mesh-transport, resident-pump, and
  game-wiring coverage).
- Passed: `bash steam/steamos/tests/install-steamos-test.sh` (now also asserts
  the bypass policy and game profiles are installed).
- Decision: No-Go is unchanged. This work raises local/code maturity to parity
  with the other silos; it does not provide two-Deck hardware evidence, live
  rendezvous/relay evidence, public Dytallix registry evidence, production
  signing, or peer-session-key installation over the real transport.

## Go / No-Go Rule

Do not label SteamOS production-ready until every blocking gate is `Passed`
and the evidence path is linked from this file.
