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
| Live TUN to peer transport | Blocked | The resident mesh now selects one eligible trusted peer, installs exact authenticated outbound and inbound session leases, and drains generation-aware rekey/clear events. Local integration tests pass, but production still requires a two-Deck packet roundtrip evidence directory under `../validation/deck/<timestamp>/` |
| Production packet-session keys | Passed | Shared `MeshTransportHandle` leases now reach the SteamOS packet core without synthetic production material; rekey, expiry, disconnect, inbound attribution, stale generation, and fail-closed paths are covered by shared-core and `qlinkd` tests |
| Steam-safe bypass | Blocked | The `qlink-game` policy is no longer orphaned: `qlinkd` loads it into `SteamBypassSummary` at startup, validates the protected overlay CIDR against the policy, and logs the posture; `qlinkctl`'s operator guide derives its Steam-safe disclosure from the same policy so enforcement and disclosure share one source. Verified 2026-07-12 (`cargo test -p qlinkd game::`, `cargo test -p qlinkctl steam_safe_disclosure`). Local profile tests still pass (`cargo test -p qlink-game steam_bypass`). Real Deck route-leak evidence for Steam account/store/wallet/update/login categories is still required |
| nftables rollback | Passed | Codex local automation on 2026-06-30: `cargo test -p qlink-linux network_lifecycle -- --nocapture`; fake-executor rollback and owned-record retry paths passed |
| Private invite peer lifecycle | Passed | Invite import, explicit `peer select`, revoke, expiry, exact inbound ACL, owner-only peer storage, unambiguous targeting, and bounded resident revalidation are covered; removing, revoking, expiring, or replacing the selected peer drops the full transport |
| Public Dytallix policy | Blocked | Stable identity v2 contract and shared verifier code now bind wallet/device identity independently from ephemeral signed reachability; public SteamOS refuses v1 downgrade and reports local enrollment separately from remote trust. Live deployed-chain finality/readback and accept/reject evidence are still required |
| Rendezvous/relay production profile | Blocked | Fixture-tested bridge logic can translate verified TLS, auth, limits, revocation, relay denial, and an explicit ML-DSA signed-record publication/expiry/refresh verifier report. No off-host public-edge run is linked; abuse-log samples, deployed retention, key rotation, endpoint rotation, and incident shutdown also remain blocked |
| Non-root local control | Passed | Codex local automation on 2026-06-30: `cargo test -p qlinkd local_control_acl -- --nocapture`, `cargo test -p qlinkctl support_bundle -- --nocapture`, and `bash steam/steamos/tests/install-steamos-test.sh` |
| Signed release artifacts | Blocked | Compatible Linux CI implements the ephemeral Ed25519 signed-RC positive path and asserts `productionReady=false`; no protected production-key signature evidence or linked passing production release run exists |
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

## 2026-07-10 Non-Hardware Evidence Collection Slice

- Host class: local development host with fixture-based evidence bundles; no Steam Deck hardware was attached and no live endpoint evidence is claimed.
- Added `steam/steamos/scripts/collect-production-evidence.sh` to generate the non-hardware production evidence manifest from a redacted operator evidence bundle with referenced evidence-file SHA-256 digests.
- Added `steam/steamos/scripts/steamos-rc-dry-run.sh` to run a signed SteamOS RC package dry run that requires production signing material, a release public key, and non-hardware evidence before asserting `nonHardwareProductionReady`.
- Added focused tests for collector failures, forbidden evidence markers, blocked-but-valid evidence, and signed RC dry-run behavior where local OpenSSL supports Ed25519 key generation.
- Decision: No-Go remains unchanged until real public Dytallix evidence, active rendezvous/relay evidence, production signing material, and real Steam Deck validation evidence are linked.

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

## 2026-07-27 Real Mesh Production Closure

- Host class: local macOS development host with fixture and loopback network
  paths; no Steam Deck hardware or live production endpoint is claimed.
- Replaced synthetic SteamOS packet-session material with exact directional
  leases and generation-aware ready/clear events from the shared
  `qlink-core` mesh transport.
- Added deterministic trusted-peer targeting with `qlinkctl peer select`,
  separated the trusted invite store from the shared record cache, enforced an
  exact inbound ACL, and added bounded resident revalidation that drops the
  complete transport after peer removal, revocation, expiry, or replacement.
- Added owner-only credential-file loading for rendezvous and relay
  authentication plus pinned Dytallix lookup configuration in the SteamOS
  daemon contract.
- Added `bridge-public-edge-evidence.py` to verify a supplied shared public-edge
  manifest before translating supported controls into the SteamOS evidence
  sidecar. Only fixtures were exercised; no off-host live proof is claimed.
- Added a compatible-Linux CI proof that creates ephemeral Ed25519 keys, builds
  and verifies a signed RC with fixture non-hardware evidence, and asserts that
  the result does not claim full production readiness.
- Decision: No-Go remains. Production still requires complete live Dytallix and
  public-edge evidence, a protected production signing key, two-Deck packet and
  route-leak evidence, and the game compatibility matrix.

## 2026-07-27 Signed Record Evidence Contract

- Host class: local development host with synthetic, redacted evidence
  fixtures; no live rendezvous endpoint or Steam Deck hardware is claimed.
- Extended the public-edge bridge with an optional, confined
  `signedExpiringRecords` verifier report.
- The control passes only when the report identifies the repository-owned
  `qlink-core` verifier, matches the public-edge revision and rendezvous
  endpoint hash, records valid ML-DSA-65 signatures and identity bindings, and
  proves lookup after publication, rejection after expiry, and a
  higher-sequence pre-expiry refresh.
- Missing or inconsistent lifecycle proof remains blocked. Secret markers,
  escaped paths, and symlinked evidence are rejected; the generated sidecar
  contains only whitelisted hashes, times, decisions, and verifier outcomes.
- Focused fixture tests and workflow wiring validate the contract mechanics.
  They do not satisfy the live rendezvous/relay gate.
- Decision: No-Go remains unchanged.

## 2026-07-27 Resident Discovery Lifecycle

- Host class: local macOS development host plus an in-process shared
  rendezvous server; the Linux netlink module was cross-checked for
  `x86_64-unknown-linux-gnu`. No public endpoint or Deck hardware is claimed.
- Added a non-blocking resident publication worker using the shared
  `qlink-core` signing and rendezvous APIs.
- Added owner-only, atomic sequence reservation and current-record outbox
  files, TTL/2 refresh, bounded retry, initial/expired fail-closure, and
  systemd-restart behavior after expiry.
- Added monotonic sequence enforcement to the shared rendezvous store so equal
  and lower live replacements are rejected across every platform.
- Added Linux route/link/address monitoring that triggers shared transport
  reconnection and immediate republication.
- Added backward-compatible daemon status plus `qlinkctl` status, doctor, and
  onboarding output for publication and Dytallix trust health.
- Added bounded shared-core peer trust revalidation for public identities.
- Local tests prove a live initial publication and higher-sequence TTL refresh.
- Decision at this stage: private-mesh discovery lifecycle code was closed
  locally. Public production still required a stable Dytallix binding design,
  live public-edge evidence, protected production signing, and Deck validation.

## 2026-07-27 Stable Dytallix Identity V2

- Host class: local macOS development host with native Rust tests and a
  `wasm32-unknown-unknown` contract build; no live Dytallix deployment, public
  endpoint, production signing key, or Steam Deck hardware is claimed.
- Added the versioned `quantumlink-node-registry-v2` contract with wallet and
  device authorization, exact identity revisions, owner-only emergency
  suspension, terminal revocation, stable device binding, authorization
  expiry, optional mesh scope, and peer-record TTL policy.
- Added the shared `qlink-core` v2 verifier and explicit versioned lookup
  dispatch for outbound, inbound, relay, and trust-revalidation paths.
- Signed peer records now carry issuance time, and rendezvous/peer-store
  replacement rejects equal or lower live sequence numbers while permitting a
  new sequence epoch after expiry.
- Public SteamOS mode requires `bindingVersion=stableIdentityV2` and refuses
  silent v1 downgrade. `qlinkd` validates local enrollment separately from
  selected remote-peer trust and exposes typed, redacted status for both.
- Passed locally: v2 contract native tests, v2 WASM release build, all 257
  `qlink-core` tests, all 78 `qlinkd` tests, all 32 `qlinkctl` tests, and all 31
  SteamOS protocol tests.
- Decision: Public Dytallix remains No-Go until the evidence schema and
  collector require v2, offline provisioning is shipped, and finalized live
  chain register/readback/update/suspend/reactivate/revoke plus negative-policy
  evidence is linked.

## Go / No-Go Rule

Do not label SteamOS production-ready until every blocking gate is `Passed`
and the evidence path is linked from this file.
