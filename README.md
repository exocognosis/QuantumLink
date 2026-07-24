# QuantumLink

[![CI](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml)
[![Windows CI](https://github.com/exocognosis/QuantumLink/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/windows-ci.yml)
[![Release](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml)

QuantumLink is a cross-platform, post-quantum mesh VPN product built
around a shared Rust protocol core and native platform silos for macOS,
Windows, and the Steam/SteamOS gamer track, plus a separate
QuantumLink Agent silo for agent-assisted mesh operations. It is
designed to minimize central infrastructure: peers discover each other
through short-lived signed records, connect directly when possible,
fall back to relay when necessary, and preserve a fail-closed L3
overlay on each supported OS.

The product promise is: **identity on-chain, traffic off-chain, access
accountless, transport server-minimized.** Peer identity is verified
against the [Dytallix](https://github.com/DytallixHQ) blockchain
registry before public mesh peers are dialed or accepted, while packet
data, routes, DNS, endpoints, and session keys never touch the chain.

The repository is not a macOS-only proof of concept. It is a product monorepo:
`qlink-core` owns the mesh protocol, cryptography, packet framing,
rendezvous, relay, ICE/STUN helpers, peer stores, identity assertions,
metrics, tracing, and smoke tooling; each platform silo wraps that core
with the OS-specific tunnel, UI, privilege boundary, packaging, and
release mechanics.

## Product Pillars

- **Post-quantum data plane** - ML-KEM-768 session establishment,
  ML-DSA-65 and SLH-DSA-SHAKE device credentials, SHAKE256 transcript
  binding and directional key derivation, app-layer PQC frame
  protection, replay windows, and protocol downgrade rejection.
- **Server-minimized mesh control plane** - signed and expiring peer
  records, rendezvous discovery, relay fallback, peer-store caching,
  mDNS/local discovery support, and synthetic WAN test harnesses.
- **On-chain identity and trust** - [Dytallix](https://github.com/DytallixHQ)-backed registry flows,
  wallet/contract-aware enrollment settings, registry lookup policy,
  verified peer decisions, identity assertions, ACL/denylist handling,
  blocked-peer history, and support-bundle diagnostics that explain
  trust failures without leaking raw peer identifiers by default.
- **Native platform silos** - macOS uses SwiftUI, Network Extension,
  Keychain, XcodeGen, MDM payloads, and Apple packaging; Windows uses a
  privileged Rust service, Wintun, WFP kill switch, DPAPI, named-pipe
  IPC, WinUI 3, and WiX packaging; Steam/SteamOS is tracked as a gamer
  edition with Steam-safe routing policy and low-latency game traffic
  goals.
- **QuantumLink Agent** - a product silo for agent runtime
  orchestration, policy guardrails, mesh diagnostics interpretation,
  Dytallix identity explanation, route and relay recommendations,
  typed remediation plans, approval gates, audit records, and UI/CLI
  adapter contracts.
- **Fail-closed posture** - protected-route filtering, kill-switch
  watchdogs, packet-pump drop accounting, route/DNS policy, diagnostics
  redaction, and explicit production gates for signing, notarization,
  certificates, and real-hardware validation.

## Platform Silos

| Silo | Path | Status | What it contains |
|------|------|--------|------------------|
| **Shared core** | [`qlink-core/`](qlink-core) | Active | Rust mesh engine, PQC crypto, signed peer records, packet core, QUIC transport, rendezvous, relay, ICE/STUN, peer store, metrics, tracing bridge, FFI, and `qlinkctl` loopback/smoke tooling. |
| **On-chain identity** | [`dytallix/`](dytallix) | Active model layer | `quantumlink-node-registry`: Dytallix node registry records (peer ID, owner wallet, device/transport key hashes, status, reputation, stake), wallet and device-binding authorizations, and registry events, built against the pinned Dytallix SDK with native and WASM contract targets. |
| **macOS** | [`macos/`](macos) | Implemented baseline | SwiftUI app, `NEPacketTunnelProvider`, `QuantumLinkKit`, Rust FFI bridge, transport smoke runner, Dytallix enrollment UI/models, MDM payload templates, XcodeGen project, entitlements, Sparkle/appcast scripts, and unsigned/package build flows. |
| **Windows** | [`windows/`](windows) | Alpha implementation | Privileged Rust tunnel service, Wintun adapter path, WFP kill switch, DPAPI secret storage, named-pipe IPC schema, WinUI 3 dashboard, WiX MSI packaging, beta runbook, and Windows CI smoke coverage. |
| **Steam / SteamOS** | [`steam/`](steam) | Product track / planning baseline | Steam-safe gamer edition notes for desktop and companion surfaces: game-aware routing, SDR awareness, account/store traffic bypass policy, latency-sensitive mode, streamer/privacy modes, and future SteamOS packaging direction. |
| **QuantumLink Agent** | [`QuantumLinkAgent/`](QuantumLinkAgent) | Build-neutral scaffold | Agentic VPN product silo for runtime orchestration, policy guardrails, approval-gated remediation, redacted diagnostics, Dytallix identity explanation, mesh adapter contracts, prompt templates, and Agent-specific test fixtures. |

All platform work is built around the same `qlink-core` crate. There is
no separate macOS protocol, Windows protocol, or Steam protocol. The
root Cargo workspace ties together the shared core and Windows Rust
crates; the macOS silo consumes the same core through a generated
XCFramework; the Steam track is expected to depend on the same service
and policy layers rather than fork the mesh engine.

QuantumLink Agent is separate from the platform clients. It depends on
shared `qlink-core` mesh, cryptography, identity, and transport
primitives, but it does not own macOS Network Extension packaging,
Windows service packaging, SteamOS daemon packaging, or the shared
cryptographic protocol.

## Repository Layout

```text
qlink-core/                         Shared Rust mesh protocol core
  src/crypto.rs                     ML-KEM/ML-DSA/SLH-DSA orchestration
  src/packet_core.rs                Protected-route packet framing
  src/mesh_transport.rs             Multi-peer transport/session manager
  src/rendezvous.rs, relay.rs       Development control-plane services
  src/inbound_identity.rs           Authenticated inbound identity checks
  src/peer_acl.rs                   Peer allow/deny policy
  include/qlink_core.h              Swift/C FFI surface

dytallix/
  quantumlink-node-registry/        On-chain identity registry models
                                    (Dytallix SDK, native + WASM targets)

macos/
  Package.swift, Sources/, Tests/   SwiftPM app, QuantumLinkKit, tunnel
  project.yml                       XcodeGen spec; generate project locally
  entitlements/, Info/, mdm/        Apple signing and managed deployment
  scripts/                          XCFramework, Xcode, package, release

windows/
  rust/quantumlink-proto            Shared models and IPC schema
  rust/quantumlink-service          Privileged tunnel service
  ui/QuantumLink.Windows            WinUI 3 app
  installer/                        WiX MSI packaging
  docs/                             Architecture, porting notes, beta runbook

steam/
  README.md, version.md             Steam gamer edition product direction
  steamos/                          SteamOS/Linux daemon runtime (qlinkd, qlinkctl)
  mobile/                           Steam Mobile companion silo (planning scaffold)

QuantumLinkAgent/
  README.md                         Agent silo overview and ownership boundary
  feature.md                        Agent product feature specification
  docs/                             Runtime architecture, development plan, permissions
  src/runtime/                      Agent orchestration boundary
  src/identity/                     Dytallix identity adapter boundary
  src/mesh/                         qlink-core mesh adapter boundary
  src/policy/                       Policy engine and patch model
  src/diagnostics/                  Redacted evidence model
  src/ui/                           Agent-facing UI contract
  config/                           Example policy and prompt templates
  scripts/                          Future Agent development scripts
  tests/                            Agent test strategy and safe fixtures

config/                             Shared example mesh configuration
docs/                               Architecture, security, beta, perf notes
Cargo.toml                          Root Cargo workspace
```

## Identity And Trust

QuantumLink treats peer identity as part of the mesh, not as an
afterthought bolted onto transport setup.

- Device credentials are post-quantum signing keys, with ML-DSA-65 as
  the default and SLH-DSA-SHAKE-128S support for the FIPS 205 path.
- Peer records are signed, expiring, sequence-numbered documents that
  bind peer ID, device public key, routes, endpoint candidates, ICE
  credentials, QUIC certificate material, and discovery metadata.
- The mesh transport records registry failures and ACL rejections so a
  peer can surface "why this connection was blocked" without requiring
  payload traffic from that peer first.
- Diagnostics redact raw `qlink_*` peer identifiers and network
  addresses by default; raw support-bundle export is an explicit opt-in.

### On-Chain Identity Via The Dytallix Blockchain

On-chain identity verification is a first-class product feature. It
binds a QuantumLink peer identity to a
[Dytallix](https://github.com/DytallixHQ) blockchain registry entry:
the registry proves that a Dytallix wallet owns or authorizes a
QuantumLink device identity, and peers use that registry state as a
connection policy input before dialing, accepting, or publishing into
public mesh infrastructure. Unregistered, revoked, suspended, or
mismatched identities are rejected before transport setup.

The [`dytallix/quantumlink-node-registry`](dytallix) workspace crate
implements the registry model layer: node records keyed by `peer_id`
with owner wallet address, device/transport public-key hashes, latest
peer-record hash binding, `active`/`revoked`/`suspended` status,
reputation score, and stake status, plus wallet and device-binding
authorizations and registry events. It builds against the pinned
Dytallix SDK for native targets and compiles as a WASM contract
artifact.

Identity modes:

| Mode | Meaning | Intended use |
|---|---|---|
| `Off` | No Dytallix identity for discovery or peer policy. | Development and fully private meshes; not allowed for public meshes. |
| `Verified` | Verify active registry status without publishing the wallet address in rendezvous records. | Default for public meshes. |
| `Public Wallet` | Publish the Dytallix wallet address in the discovery record. | Operators who intentionally want visible identity, reputation, or staking. |

Mesh trust policy:

| Mesh type | Registry behavior | Connection behavior |
|---|---|---|
| Public | Required | Fail closed: reject peers without an active, matching Dytallix registry entry. |
| Private | Preferred | Accept valid QuantumLink peers; warn when registry status is missing, stale, or unavailable. |
| Development | Optional | Registry enforcement can be disabled entirely. |

The identity layer is discovery-adjacent, not packet-path
infrastructure. The registry stores identity, status, and policy data
only; it does not store raw peer endpoints, hostnames, routes, DNS
activity, packet data or timing, relay paths, or session keys, and
packet encryption never depends on the chain. Enrollment binds both
ownerships: the device key signs a binding statement and the Dytallix
wallet submits the registry contract call. Wallet secrets stay in the
Dytallix keystore, device private keys stay in the platform secret
store, and the tunnel runtime receives only validated policy and
registry configuration.

Rejected peers produce operator-readable reasons such as
`rejected_missing_registry`, `rejected_revoked`, `rejected_suspended`,
`rejected_key_mismatch`, and `registry_unavailable`, surfaced in the
app and redacted support bundles.

Registry configuration supports lookup-only trust decisions,
contract/network allowlists, wallet-aware enrollment outputs, and
operator-visible trust status. The external Dytallix project publishes
the public SDK/CLI, PQC primitive crate, documentation, node, faucet,
explorer surface map, and on-chain WASM contract repositories under
[`DytallixHQ`](https://github.com/DytallixHQ). Live public-registry
enforcement evidence against hosted Dytallix infrastructure remains an
open production gate; see the platform readiness ledgers.

## Cryptographic Core

The protocol lives once in [`qlink-core`](qlink-core) and is shared
across platform silos.

Supported suite identifiers:

- `QLINK-FIPS203-MLKEM768-SHAKE256-v1`
- `QLINK-FIPS204-MLDSA65-SHAKE256-v1`
- `QLINK-FIPS205-SLHDSA-SHAKE128S-SHAKE256-v1`

Implemented behavior includes ML-KEM-768 session establishment,
SHAKE256 transcript binding, SHAKE256 directional derivation, signed
peer records, app-layer PQC frame protection with replay rejection,
protected IPv4 route enforcement, selected metadata normalization,
native UDP carrier session-wire coverage, optional dev-only QUIC
DATAGRAM carrier transport behind `dev-quic-carrier`, fail-closed raw
relay fallback, rendezvous lookup/publish, QuantumLink-only SHAKE-based
ICE helpers, SHAKE256 v3 peer-store protection, tracing export, and
metrics surfaces.

The legacy hybrid X25519/ML-KEM app-layer suite identifier is
intentionally rejected. QuantumLink's v1 app-layer cryptographic
direction is post-quantum session establishment without a classical
key-exchange fallback.

Known blockers for a strict "zero classical in the full stack" profile:

- The default `qlink-core` build excludes the dev Quinn/rustls/rcgen
  carrier dependencies. The legacy Quinn/rustls carrier is still present
  only behind `--features dev-quic-carrier`, where it configures the
  hybrid `X25519MLKEM768` group for development comparison smokes.
  Default live mesh dialing now fails closed until rendezvous publication
  and direct probing are wired to the native UDP carrier.
- macOS and Windows privacy-redaction helpers still use SHA-256-derived
  stable aliases outside the packet/session boundary.
- macOS CMS/profile signing still requests platform SHA-256, and tests
  document platform AES behavior. That is OS distribution/signing
  plumbing, not the mesh transport boundary, but it is not a zero-
  classical stack.
- Optional dev-carrier builds still pull transitive rustls/aws-lc/ring
  classical algorithms through Quinn. The default core graph should not,
  but lockfile contents and dev tooling are not a full zero-classical
  stack claim.

## Build And Validate

Shared Rust workspace:

```sh
cargo test --workspace
cargo run -p qlink-core --bin qlinkctl -- rendezvous
```

`quic-loopback`, `mesh-loopback`, `relay-loopback`, and `relay-smoke`
are disabled in the strict PQC profile because they bypass or lack the
app-layer PQC frame session.

Legacy dev-carrier mesh publication is explicit opt-in:

```sh
cargo run -p qlink-core --no-default-features --features dev-quic-carrier --bin qlinkctl -- publish-self --once
```

macOS:

```sh
cd macos
swift test
./scripts/build-rust-xcframework.sh
./scripts/generate-xcode-project.sh
```

The macOS source tree is source-first. `macos/project.yml` is the
tracked XcodeGen source of truth; `QuantumLink.xcodeproj` is generated
locally and is not part of the public source boundary.

Windows:

```powershell
cargo test --workspace
cargo run -p quantumlink-service -- smoke
windows\scripts\build-windows.ps1
```

Steam / SteamOS:

- The SteamOS/Linux runtime (`steam/steamos`) is a compiling pre-production
  daemon scaffold; the Steam Mobile silo (`steam/mobile`) is a planning-stage
  companion scaffold.
- See [`steam/README.md`](steam/README.md), [`steam/version.md`](steam/version.md),
  [`steam/steamos/README.md`](steam/steamos/README.md), and
  [`steam/mobile/README.md`](steam/mobile/README.md).

## Open Source Status

QuantumLink is published as a full-source product monorepo for the
shared Rust core, the native macOS client, the native Windows client,
and the Steam/SteamOS product track. The repository is licensed under
Apache-2.0; see [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), and
[`docs/open-source-boundaries.md`](docs/open-source-boundaries.md).

Official macOS and Windows production binaries are signed release
artifacts. Local source builds, unsigned packages, and CI uploads are
development or validation artifacts only and should not be treated as
production distributions.

The public repository includes:

- source code for `qlink-core`, macOS, Windows, and Steam/SteamOS
  planning surfaces
- reproducible local build and validation scripts
- public documentation, examples, tests, and CI definitions
- release packaging source for macOS and Windows

The public repository does not include production signing keys,
certificates, app-store accounts, hosted rendezvous or relay operations,
telemetry infrastructure, support data, customer data, production
environment secrets, or private release infrastructure.

CI covers the Rust workspace, Rust formatting, QUIC/mesh/relay smokes,
Swift tests, Swift transport smoke, XCFramework generation, unsigned
Xcode generation/build checks, Windows Rust tests, Windows service
smoke, and WinUI build checks.

## Production Boundaries

- No mandatory centralized VPN concentrator in the steady-state data
  plane; rendezvous, STUN/ICE, and relay exist for discovery,
  reachability, and fallback.
- L3 overlay per platform: macOS `NEPacketTunnelProvider`/`utun`,
  Windows Wintun/WFP, and a Steam/SteamOS track intended to layer
  game-aware policy over the same core.
- No kernel extension or custom driver in v1 beyond platform-approved
  tunnel mechanisms.
- Public relay and rendezvous services in this repo are development
  tools until hardened for internet exposure.
- Local-first diagnostics are redacted by default; raw export is
  operator-controlled.

## More Detail

- Product feature inventory: [`FEATURES.md`](FEATURES.md)
- Protocol and runtime spec: [`SPEC.md`](SPEC.md)
- Security notes: [`docs/security.md`](docs/security.md)
- macOS pre-Apple checklist: [`docs/pre-apple-development.md`](docs/pre-apple-development.md)
- Windows architecture: [`windows/docs/architecture-windows.md`](windows/docs/architecture-windows.md)
- Windows beta runbook: [`windows/docs/beta-runbook-windows.md`](windows/docs/beta-runbook-windows.md)
- Steam product track: [`steam/README.md`](steam/README.md)
- Dytallix organization: [`DytallixHQ`](https://github.com/DytallixHQ)
- Dytallix SDK/CLI: [`DytallixHQ/dytallix-sdk`](https://github.com/DytallixHQ/dytallix-sdk)
- Dytallix PQC primitives: [`DytallixHQ/dytallix-pqc`](https://github.com/DytallixHQ/dytallix-pqc)
- Dytallix node: [`DytallixHQ/dytallix-node`](https://github.com/DytallixHQ/dytallix-node)
- Dytallix faucet: [`DytallixHQ/dytallix-faucet`](https://github.com/DytallixHQ/dytallix-faucet)
- Dytallix explorer surface: [`DytallixHQ/dytallix-explorer`](https://github.com/DytallixHQ/dytallix-explorer)
- Dytallix contracts: [`DytallixHQ/dytallix-contracts`](https://github.com/DytallixHQ/dytallix-contracts)
- Dytallix docs: [`DytallixHQ/dytallix-docs`](https://github.com/DytallixHQ/dytallix-docs)

## Contributing And Support

- Contribution workflow: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security reporting: [`SECURITY.md`](SECURITY.md)
- Support expectations: [`SUPPORT.md`](SUPPORT.md)
- Community expectations: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Release notes: [`CHANGELOG.md`](CHANGELOG.md)
