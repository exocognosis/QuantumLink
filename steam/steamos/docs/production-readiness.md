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
| Public Dytallix policy | Blocked | The schema-v2 evidence contract now requires `stableIdentityV2`, contract schema 2, `liveChain` evidence, pinned network/chain/contract/code hash, independently verified finality, the complete register/update/suspend/reactivate/revoke lifecycle, rejected post-revocation reactivation, TTL refresh preserving identity revision, the negative-policy matrix, and contained SHA-256-matched sidecars. No qualifying live evidence is linked |
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
- Passed locally: v2 contract native tests, v2 WASM release build, 265
  `qlink-core` package tests, 94 `qlinkd` package tests, all 32 `qlinkctl` tests, and all 31
  SteamOS protocol tests.
- Decision: Public Dytallix remains No-Go until the evidence schema and
  collector require v2, offline provisioning is shipped, and finalized live
  chain register/readback/update/suspend/reactivate/revoke plus negative-policy
  evidence is linked.

## 2026-07-27 Offline Dytallix Provisioning

- Added daemon-independent `qlinkctl dytallix` status, register, update,
  suspend, reactivate, and terminal revoke commands backed by shared-core v2
  transaction and readback logic.
- Mutations require an explicit owner-only regular keystore file. Device-bound
  operations load only the existing owner-only SteamOS device seed; emergency
  suspend/revoke can use an explicit peer ID without device-key access.
- Configuration supplies the HTTPS endpoint, RPC allowlist, chain ID, network
  ID, and deployed contract pin. Public operations require
  `bindingVersion=stableIdentityV2` and cannot silently select v1.
- Lifecycle checks reject duplicate registration, update preserves suspended
  state, reactivate requires suspension, and revoke requires exact peer-ID
  confirmation.
- JSON receipts distinguish confirmed transaction plus exact readback from
  finalized-chain proof. The pinned SDK does not yet expose trustworthy
  finalized-block metadata, so production readiness remains No-Go.
- The production-evidence schema, collector, verifier, bridge, packager, and
  tests now enforce live-chain v2 lifecycle and negative-policy evidence,
  independently verified finality, content-bound sidecars, and signed-archive
  binding.
- Next blocker: run the live Dytallix lifecycle and policy harness against the
  deployed chain using an independent finality source, then link the resulting
  passing bundle. The current pinned SDK cannot supply that finality proof.

## 2026-07-28 Production-Evidence Schema V2 Enforcement

- Defined schema v2 as the only production-eligible non-hardware evidence
  contract.
- Schema v1 remains parseable for historical inspection and gap analysis, but
  it is always production-blocked and must never set
  `nonHardwareProductionReady=true`.
- The Dytallix gate now requires `bindingVersion=stableIdentityV2`,
  `contractSchemaVersion=2`, `evidenceClass=liveChain`, and pinned network,
  chain, deployed contract address, and deployed code hash.
- Required lifecycle proof covers finalized register, update, suspend,
  reactivate, and revoke transactions plus rejected post-revocation
  reactivation and TTL refresh that preserves the stable identity revision.
- Required negative-policy proof covers v1 downgrade, expired authorization,
  device mismatch, signing-key mismatch, wrong mesh scope, TTL excess,
  non-monotonic revision, missing/suspended/revoked identities, and registry
  outage fail-closure.
- Every finality proof, readback, lifecycle case, negative case, and
  rendezvous/relay control requires a contained regular-file sidecar with a
  matching SHA-256 digest.
- Dytallix sidecar JSON must match the manifest's pinned chain, contract,
  transaction, lifecycle/readback, identity revision, and policy decision.
  The independently finalized checkpoint must cover every claimed transaction.
- The finality report must carry a valid ECDSA P-256/SHA-256 signature from an
  independently configured, pinned verifier public key. Bundle-supplied trust
  alone cannot set readiness. Its signed transaction inventory binds each
  lifecycle operation to the observed result, identity revision, and exact
  readback digest.
- The packager embeds an identical evidence manifest and sidecar tree in the
  signed application archive. Release verification rejects detached or
  substituted external evidence.
- SDK transaction confirmation and exact readback are explicitly not
  finalized-chain proof. Finality must be independently verified against the
  pinned chain and transaction.
- The collector, verifier, bridge, packager, fixtures, and tests enforce the
  complete v2 contract. Schema-v1 evidence is rejected for production signing.
- Decision: No-Go remains unchanged. No schema-v2 live-chain bundle is linked,
  independently verified, and recorded as passing evidence.

## 2026-08-17 Production Activation And Gaming Requirements

- Host class: local macOS development host and clean temporary worktree. No
  Steam Deck hardware, live Dytallix deployment, or public relay is claimed.
- The packaged systemd service now starts `qlinkd --activate-network` and uses
  record-backed stop cleanup. Packaging includes a planning-only recovery
  sample instead of an opt-in activation sample.
- Full-tunnel configuration now requires explicit canonical IPv4 underlay
  exemptions. The nftables plan returns exempt traffic before mark and drop
  rules. Invalid, duplicate, default-route, and overlay-overlapping exemptions
  fail configuration validation.
- Added SteamOS gaming VPN requirements for direct-first path selection,
  per-flow path affinity, jitter and loss inputs, path-change hysteresis,
  datagram MTU discovery, Steam-safe routing, recovery, voice traffic, and a
  controller-accessible Desktop Mode control surface.
- Defined the Dytallix boundary. `qlink-core` owns stable identity v2 binding,
  signed records, policy, and verification. The Steam silo owns device-key
  storage, provisioning commands, status, and Desktop Mode controls.
- Passed in the clean worktree: `cargo fmt --all --check`.
- Passed: 234 tests across `qlink-proto`, `qlink-linux`, `qlink-game`,
  `qlinkd`, and `qlinkctl`.
- Passed: 270 `qlink-core` library, tool, and direct-send tests, including the
  Dytallix v1 and stable identity v2 policy suites.
- Passed: strict Clippy for all SteamOS crates with `-D warnings`.
- Passed: staged installer and release-verifier tests. The local OpenSSL build
  did not support the Ed25519 production-signature positive fixture.
- A repository-wide strict Clippy run that included `qlink-core` found existing
  warnings in shared-core FFI documentation and enum sizing. This batch does
  not change those shared-core files.
- Decision: No-Go remains unchanged. Real Deck network and game evidence, a
  schema-v2 live-chain Dytallix lifecycle bundle with independent finality,
  public rendezvous and relay evidence, and protected production signing are
  still required.

## 2026-08-17 Desktop Mode Control Application

- Host class: local macOS development host and clean temporary worktree. The
  application used a fixture `qlinkctl` backend for visual checks. No Steam
  Deck hardware or live-chain result is claimed.
- Added the native `qlink-desktop` application with Overview, Peers, Dytallix
  Identity, and Diagnostics views.
- The application runs as the desktop user. It sends all control requests to
  `qlinkctl` and does not implement a second daemon, protocol, peer store, or
  Dytallix client.
- Added typed `qlinkctl` commands for peer state, peer selection cleanup, and
  fixed service start, stop, and restart operations. Service operations use a
  fixed `pkexec systemctl` argument vector and cannot select another unit.
- Dytallix controls use the existing shared-core v2 commands. Wallet secrets
  do not enter the application process. The application supplies only the
  keystore path, wallet name, public operation data, and exact revoke
  confirmation.
- Added package assets for the application binary, FreeDesktop launcher, and
  256-pixel icon. The installer and release verifier check all three assets.
- Passed: 78 focused tests across `qlink-desktop`, `qlink-proto`, and
  `qlinkctl`.
- Passed: locked release builds for `qlinkd`, `qlinkctl`, and
  `qlink-desktop`; workspace format checks; strict scoped Clippy with
  `-D warnings`; staged installer tests; and release-verifier tests.
- Passed: a release package made from the optimized binaries. The verifier
  reported `valid=true`, `productionReady=false`, and
  `notProductionReady=true` because the package used the development signing
  mode and did not contain production evidence.
- Visual check passed for the native fixture-backed application. The checked
  desktop view had no visible overlap, clipping, or blank content.
- Decision: No-Go remains unchanged. Steam Deck Desktop Mode and Game Mode
  input tests, profile selection, live service authorization, live Dytallix
  finality, public edge evidence, and protected production signing remain
  open.

## 2026-08-17 Game Profile And Game Mode Controls

- Host class: local macOS development host and clean temporary worktree. The
  application used a fixture `qlinkctl` backend. No Steam Deck or Steam Input
  result is claimed.
- `qlink-game` now validates profile IDs, display names, executable basenames,
  and UDP ports. It stores the selected profile in a schema-versioned,
  owner-only state file with atomic replacement.
- `qlinkd` owns profile selection state. It accepts typed select and clear
  requests only for validated installed profiles. Daemon status returns the
  selected profile and the available profile catalog.
- `qlinkctl` now provides `profile list`, `profile status`, `profile select`,
  and `profile clear` commands.
- `qlink-desktop` now shows explicit profile controls. The `--game-mode` option
  requests full screen and adds keyboard or controller navigation for pages
  and profile selection.
- Packaging now contains separate Desktop Mode and Game Mode launchers. The
  installer and release verifier check both launchers.
- Passed: 188 focused tests across `qlink-desktop`, `qlink-game`,
  `qlink-proto`, `qlinkctl`, and `qlinkd`.
- Passed: workspace format checks and strict scoped Clippy with `-D warnings`.
- Passed: shell syntax checks, staged installer tests, and release-verifier
  tests. The local OpenSSL build did not support the Ed25519 production
  signature positive fixture.
- Passed: optimized builds for `qlinkd`, `qlinkctl`, and `qlink-desktop`.
- Passed: a development package that contains both launchers. The verifier
  reported `valid=true`, `productionReady=false`, and
  `notProductionReady=true`.
- Visual check passed for the fixture-backed full-screen Game Profiles view.
  The view showed three profiles, selected state, controller focus, and no
  visible overlap or clipping.
- Decision: No-Go remains unchanged. The selected profile does not yet drive
  live process, port, route, or nftables flow classification. Real Steam Deck
  and Steam Input validation, live Dytallix finality, public edge evidence, and
  protected production signing also remain open.

## 2026-08-17 Selected Profile Port Enforcement

- Host class: local macOS development host and clean temporary worktree. No
  Steam Deck nftables result is claimed.
- `qlink-linux` now accepts a validated game UDP port selector for `gameOnly`
  plans. It sorts and removes duplicate ports and rejects port zero.
- The route chain marks only UDP source or destination ports from the selected
  profile when the destination is inside the protected overlay CIDR.
- The filter chain drops unmarked overlay traffic and then enforces the
  existing output-interface leak rule. No selected profile produces a
  fail-closed plan with no game port marks.
- Protected-prefix and full-tunnel modes keep their existing route behavior.
- Daemon status reports the profile represented by the current runtime plan,
  the enforced UDP ports, the enforcement state, and whether a restart is
  required.
- Active profile changes preserve the immutable applied plan and set
  `restartRequired=true`. The desktop application uses the fixed
  `qlinkctl service restart` path to run owned teardown before replacement.
- Passed: 242 focused tests across `qlink-linux`, `qlink-proto`, `qlinkd`,
  `qlinkctl`, and `qlink-desktop`.
- Passed: format checks, strict scoped Clippy with `-D warnings`, shell syntax,
  staged installer tests, release-verifier tests, and optimized builds.
- Passed: a development package made from the optimized binaries. The verifier
  reported `valid=true`, `productionReady=false`, and
  `notProductionReady=true`.
- Visual check passed for the full-screen profile view. The applied profile and
  enforced UDP ports were visible with no overlap or clipping.
- Decision: No-Go remains unchanged. Executable-aware process classification,
  real Deck nftables and route-leak evidence, live Dytallix finality, public
  edge evidence, and protected production signing remain open.

## 2026-08-17 Launch-Bound Process Classification

- Host class: local macOS development host with Linux behavior covered by
  typed plans and injected executors. No Steam Deck kernel result is claimed.
- `qlinkctl game launch -- <command> [args...]` validates the selected profile
  and builds a fixed `systemd-run --user --scope` command. It does not use a
  shell.
- The scope runs inside `quantumlink-game.slice`. The inner control request
  reaches `qlinkd` before the game executable starts.
- On Linux, `qlinkd` reads `SO_PEERCRED` and `/proc/<pid>/cgroup`. It validates
  the caller UID, exact cgroup v2 scope, session ID, selected profile, applied
  network plan, and executable basename.
- The game-only startup plan contains no unscoped UDP mark. It remains
  fail-closed until the daemon adds rules that match the exact cgroup path and
  profile UDP source or destination port.
- The daemon records each nftables handle. The outer launcher removes all
  recorded rules after the scoped game exits. Partial rule application rolls
  back the rules that were already added.
- Status, `qlinkctl doctor`, and the Desktop Mode profile view expose
  `failClosed`, `armed`, `active`, and `applyFailed` classification states.
- Passed: 260 focused Rust tests across `qlink-game`, `qlink-linux`,
  `qlink-proto`, `qlinkd`, `qlinkctl`, and `qlink-desktop`.
- Passed: strict scoped Clippy with `-D warnings`.
- Passed: optimized `qlinkd`, `qlinkctl`, and `qlink-desktop` builds, staged
  installer tests, shell syntax, and release-verifier tests.
- Passed: the development package verifier reported `valid=true` and
  `notProductionReady=true`. Production signing remains absent by design.
- Visual check passed for the full-screen profile view. `Process active`, the
  classified executable, applied profile, and UDP port fit without overlap.
- Decision: No-Go remains unchanged. Real Steam Deck cgroup v2, nftables,
  Proton, route-leak, suspend/resume, and anti-cheat proof remains open. Live
  Dytallix finality, public edge evidence, and protected production signing
  also remain open.

## 2026-08-18 Desktop Control Wiring

- Audited each visible Desktop Mode action against the `qlinkctl` command
  boundary.
- Added fixed service start and restart controls. Existing connect and stop
  controls continue to use fixed peer-selection and service commands.
- Added peer-selection clear controls. Revocation remains irreversible because
  `qlinkctl peer trust` reports trust state and does not restore a revoked peer.
- Added an in-application `qlinkctl doctor` report with selectable output.
- Backend peer state now clears stale UI selection after peer removal,
  revocation, or external selection changes.
- Game launch remains a Steam launch-option action. The desktop application
  does not bypass the cgroup-qualified launcher contract.
- Passed: 7 focused `qlink-desktop` tests, scoped formatting, and strict Clippy
  with `-D warnings`.
- Visual validation passed for the Diagnostics view at 1180 by 792 points. The
  four service controls and support-bundle controls have no clipping or
  overlap.
- Decision: No-Go remains unchanged. This batch connects local controls but
  does not provide Steam Deck, public edge, live Dytallix, or signing evidence.

## 2026-08-18 Compatible Linux Desktop Control Integration

- Host class: privileged Debian systemd container in the Docker Desktop Linux
  VM. The host used cgroup v2 and systemd 252. It was not Steam Deck hardware.
- Added a repeatable isolated runner for the Desktop Mode control boundary.
  The runner stages the current SteamOS crates and assets in a clean clone.
- Passed: `qlinkctl service start`, `restart`, and `stop` through `pkexec` and
  the packaged systemd service in planning mode.
- Passed: daemon status, doctor, profile list/select/clear, invite import, peer
  select/clear/revoke/remove, read-only peer trust state, restart recovery, and
  control-socket removal after service stop.
- The machine-readable report is
  `/tmp/quantumlink-steamos-desktop-control-linux.json`. It sets
  `notProductionReady=true`.
- All SteamOS crate manifests now declare Rust 1.88. This version supports the
  locked dependency graph and the shared-core FFI implementation.
- Decision: No-Go remains unchanged. This run does not apply TUN, route, or
  nftables state. Root execution does not prove an interactive PolicyKit
  prompt. Steam Deck rendering, Steam Input, and real game launch behavior
  remain open.

## 2026-08-18 Active Linux Network And Authorization Integration

- Host class: privileged Debian systemd container in the Docker Desktop Linux
  VM. The host used LinuxKit 6.10.14, cgroup v2, and systemd 252. It was not
  Steam Deck hardware.
- Replaced direct privileged `systemctl` calls with the fixed root-owned
  `/usr/local/libexec/quantumlink-service-control` helper. The helper accepts
  only `start`, `stop`, or `restart` for `qlinkd.service`.
- Added a production PolicyKit rule. It limits the helper to members of the
  `quantumlink` group and requests administrator authentication. The installer
  installs both files and adds the desktop user to the group.
- Passed: non-member denial and group-authorized start, restart, and stop. A
  test-only rule removed the interactive prompt because Docker has no logind
  session. The production `AUTH_ADMIN_KEEP` prompt remains blocked.
- Passed: active `qlink0` creation, `100.64.10.2/32` assignment, fwmark policy
  rule, table 51820 route, fail-closed nftables table, daemon packet I/O status,
  and record-backed teardown.
- Added controlled `/usr/bin` and `/usr/sbin` resolution for `ip` and `nft`.
  The daemon does not search `PATH`.
- Removed the invalid `systemd-run --scope --wait` combination. Scope launch
  plans use the supported synchronous scope path.
- Added nft string-literal encoding for cgroup paths and rule comments.
- The Docker Desktop kernel rejected the nftables `socket cgroupv2` expression.
  The harness now probes this kernel feature. It records native and
  Proton-shaped classification as blocked when the feature is absent.
- The machine-readable active-network report is
  `/tmp/quantumlink-steamos-network-game-linux.json`. It sets
  `notProductionReady=true` and preserves each blocked check.
- Passed: 266 tests across the six SteamOS crates, Steam-only strict Clippy,
  staged installer tests, release-verifier tests, shell syntax, ShellCheck, and
  PolicyKit JavaScript syntax checks.
- The release-verifier test skipped its Ed25519 positive fixture because the
  local OpenSSL build cannot generate that key type. Negative signing and
  release-gate tests passed.
- Decision: No-Go remains unchanged. Run the same harness on a compatible
  SteamOS kernel to close native and Proton classification. A real Steam Deck
  must also prove interactive PolicyKit, Steam Input, route leaks,
  suspend/resume, voice traffic, anti-cheat behavior, and game compatibility.

## 2026-08-18 Runtime Capability And Launch Recovery Gate

- `qlinkd` now detects and reports cgroup v2, nftables cgroup matching, TUN,
  systemd user scopes, PolicyKit, and logind session support.
- The capability schema has backward-compatible defaults. Older status payloads
  deserialize as `notChecked`.
- `qlinkctl doctor` reports required game-path capability failures as `FAIL`.
  Missing PolicyKit or logind support produces `WARN` because these capabilities
  affect desktop authorization but do not change the packet path.
- `qlinkctl game launch` now stops before `systemd-run` unless cgroup v2,
  nftables cgroup matching, TUN, and systemd user scopes report `supported`.
- The desktop Diagnostics view shows the same typed capability state and the
  first detected issue.
- Concurrent launch, wrong-session cleanup, active-profile mutation, partial
  cleanup retry, and legacy protocol behavior have focused Rust tests.
- The launcher catches `SIGINT` and `SIGTERM`. It stops the transient scope
  before it removes nftables classification. If scope stop fails, it keeps the
  classification active.
- The compatible Linux harness records the capability object in evidence schema
  version 2. On an unsupported kernel, it proves that launch fails before game
  rules are installed. On a compatible kernel, it also tests game crash,
  concurrent launch, launcher interruption, daemon restart, native launch, and
  Proton-shaped descendant cleanup.
- Decision: No-Go remains unchanged. The Docker Desktop kernel can prove the
  unsupported fail-closed path. A compatible SteamOS kernel must execute the
  native, Proton-shaped, and recovery paths. Steam Deck hardware evidence is
  still required for production.

## 2026-08-18 Deck Runtime Qualification Tooling

- No Steam Deck or remote SteamOS target was configured for this run. No new
  hardware result is claimed.
- Added a device-local preflight that rejects non-SteamOS and non-Steam Deck
  hosts before it changes network state.
- Added an explicit mutation gate for runtime qualification. Run mode requires
  the signed-in desktop user and `QLINK_DECK_CONFIRM_NETWORK_MUTATION=YES`.
- The runtime qualification requires all six reported capabilities to be
  `supported`. It tests PolicyKit service restart, native game scope
  classification, descendant inheritance, crash cleanup, concurrent launch
  rejection, signal cleanup, and daemon restart cleanup.
- The evidence schema marks all executable tests as synthetic fixtures. It
  explicitly sets real-game compatibility and two-Deck packet proof to false.
- Added a strict verifier. Complete evidence requires a physical Deck claim,
  `mode=run`, `status=pass`, all runtime checks passed, all capabilities
  supported, contained required files, and no forbidden private artifacts.
- Added both runtime scripts to the SteamOS package and release verifier.
- Decision: No-Go remains unchanged. Run the packaged qualification on a Deck,
  then complete real Proton, game matrix, two-Deck packet, suspend, voice,
  anti-cheat, and route-leak evidence.

## Go / No-Go Rule

Do not label SteamOS production-ready until every blocking gate is `Passed`
and the evidence path is linked from this file.
