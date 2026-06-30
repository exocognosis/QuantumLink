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
| Live TUN to peer transport | Blocked | Local bridge tests pass on 2026-06-30 (`cargo test -p qlinkd live_mesh_transport -- --nocapture`), but production still requires a two-Deck packet roundtrip evidence directory under `../validation/deck/<timestamp>/` |
| Production packet-session keys | Passed | Codex local automation on 2026-06-30: `cargo test -p qlink-core packet` and `cargo test -p qlinkd packet_session_keys -- --nocapture`; fail-closed missing/stale session coverage passed |
| Steam-safe bypass | Blocked | Local profile tests pass on 2026-06-30 (`cargo test -p qlink-game steam_bypass -- --nocapture`), but real Deck route-leak evidence for Steam account/store/wallet/update/login categories is still required |
| nftables rollback | Passed | Codex local automation on 2026-06-30: `cargo test -p qlink-linux network_lifecycle -- --nocapture`; fake-executor rollback and owned-record retry paths passed |
| Private invite peer lifecycle | Passed | Codex local automation on 2026-06-30: `cargo test -p qlinkd peer_lifecycle -- --nocapture` and `cargo test -p qlinkctl`; invite import, revoke, expiry, peer trust output, and 0600 peer-store checks passed |
| Public Dytallix policy | Blocked | Shared-core status policy tests pass locally, but live public registry accept/reject evidence for missing, revoked, suspended, mismatched, stale, and active records is not linked |
| Rendezvous/relay production profile | Blocked | Requirements/runbook: [`rendezvous-relay-production.md`](rendezvous-relay-production.md); active TLS/auth/rate-limit/retention/rotation endpoint evidence is not linked |
| Non-root local control | Passed | Codex local automation on 2026-06-30: `cargo test -p qlinkd local_control_acl -- --nocapture`, `cargo test -p qlinkctl support_bundle -- --nocapture`, and `bash steam/steamos/tests/install-steamos-test.sh` |
| Signed release artifacts | Blocked | Dev package verified on 2026-06-30 at `dist/steamos/quantumlink-steamos-0.1.0.tar.zst`; verifier report is valid but `"notProductionReady":true` because production signing key/signature evidence is absent |
| Deck validation | Blocked | Hardware runbook: [`deck-validation.md`](deck-validation.md), harness: [`../tests/deck-validation.sh`](../tests/deck-validation.sh); no real two-Deck evidence directory is linked |
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

## Go / No-Go Rule

Do not label SteamOS production-ready until every blocking gate is `Passed`
and the evidence path is linked from this file.
