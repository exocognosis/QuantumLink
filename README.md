# QuantumLink

[![CI](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml)
[![Windows CI](https://github.com/exocognosis/QuantumLink/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/windows-ci.yml)
[![Release](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml)

QuantumLink is a cross-platform, post-quantum mesh VPN product built
around a shared Rust protocol core and native platform silos for macOS,
Windows, and the Steam/SteamOS gamer track. It is designed to minimize
central infrastructure: peers discover each other through short-lived
signed records, connect directly when possible, fall back to relay when
necessary, and preserve a fail-closed L3 overlay on each supported OS.

The repository is not a macOS-only proof of concept. It is a product monorepo:
`qlink-core` owns the mesh protocol, cryptography, packet framing,
rendezvous, relay, ICE/STUN helpers, peer stores, identity assertions,
metrics, tracing, and smoke tooling; each platform silo wraps that core
with the OS-specific tunnel, UI, privilege boundary, packaging, and
release mechanics.

## Product Pillars

- **Post-quantum data plane** - ML-KEM-768 session establishment,
  ML-DSA-65 and SLH-DSA device credentials, suite-bound HKDF keys,
  ChaCha20-Poly1305 packet-frame protection, replay windows, and
  protocol downgrade rejection.
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
- **Fail-closed posture** - protected-route filtering, kill-switch
  watchdogs, packet-pump drop accounting, route/DNS policy, diagnostics
  redaction, and explicit production gates for signing, notarization,
  certificates, and real-hardware validation.

## Platform Silos

| Silo | Path | Status | What it contains |
|------|------|--------|------------------|
| **Shared core** | [`qlink-core/`](qlink-core) | Active | Rust mesh engine, PQC crypto, signed peer records, packet core, QUIC transport, rendezvous, relay, ICE/STUN, peer store, metrics, tracing bridge, FFI, and `qlinkctl` loopback/smoke tooling. |
| **macOS** | [`macos/`](macos) | Implemented baseline | SwiftUI app, `NEPacketTunnelProvider`, `QuantumLinkKit`, Rust FFI bridge, transport smoke runner, Dytallix enrollment UI/models, MDM payload templates, XcodeGen project, entitlements, Sparkle/appcast scripts, and unsigned/package build flows. |
| **Windows** | [`windows/`](windows) | Alpha implementation | Privileged Rust tunnel service, Wintun adapter path, WFP kill switch, DPAPI secret storage, named-pipe IPC schema, WinUI 3 dashboard, WiX MSI packaging, beta runbook, and Windows CI smoke coverage. |
| **Steam / SteamOS** | [`steam/`](steam) | Product track / planning baseline | Steam-safe gamer edition notes for desktop and companion surfaces: game-aware routing, SDR awareness, account/store traffic bypass policy, latency-sensitive mode, streamer/privacy modes, and future SteamOS packaging direction. |

All platform work is built around the same `qlink-core` crate. There is
no separate macOS protocol, Windows protocol, or Steam protocol. The
root Cargo workspace ties together the shared core and Windows Rust
crates; the macOS silo consumes the same core through a generated
XCFramework; the Steam track is expected to depend on the same service
and policy layers rather than fork the mesh engine.

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
  docs/version-mobile.md            Mobile companion direction

config/                             Shared example mesh configuration
docs/                               Architecture, security, beta, perf notes
Cargo.toml                          Root Cargo workspace
```

## Identity And Trust

QuantumLink treats peer identity as part of the mesh, not as an
afterthought bolted onto transport setup.

- Device credentials are post-quantum signing keys, with ML-DSA-65 as
  the default and SLH-DSA-SHA2-128S support for the FIPS 205 path.
- Peer records are signed, expiring, sequence-numbered documents that
  bind peer ID, device public key, routes, endpoint candidates, ICE
  credentials, QUIC certificate material, and discovery metadata.
- Dytallix registry configuration supports lookup-only trust decisions,
  contract/network allowlists, wallet-aware enrollment outputs, and
  operator-visible trust status in the app and support bundles. The
  external Dytallix project publishes the public SDK/CLI, PQC primitive
  crate, documentation, node, faucet, explorer surface map, and on-chain
  WASM contract repositories under
  [`DytallixHQ`](https://github.com/DytallixHQ).
- The mesh transport records registry failures and ACL rejections so a
  peer can surface "why this connection was blocked" without requiring
  payload traffic from that peer first.
- Diagnostics redact raw `qlink_*` peer identifiers and network
  addresses by default; raw support-bundle export is an explicit opt-in.

## Cryptographic Core

The protocol lives once in [`qlink-core`](qlink-core) and is shared
across platform silos.

Supported suite identifiers:

- `QLINK-FIPS203-MLKEM768-HKDFSHA256-v1`
- `QLINK-FIPS204-MLDSA65-HKDFSHA256-v1`
- `QLINK-FIPS205-SLHDSA-SHA2-128S-HKDFSHA256-v1`

Implemented behavior includes ML-KEM-768 session establishment,
SHA-256 transcript binding, HKDF-SHA-256 directional derivation,
signed peer records, suite-bound packet-frame encryption, protected
IPv4 route enforcement, selected metadata normalization, monotonic
packet-number replay protection, QUIC DATAGRAM transport, relay
fallback, rendezvous lookup/publish, STUN/ICE helpers, peer-store
persistence, tracing export, and metrics surfaces.

The legacy hybrid X25519/ML-KEM suite identifier is intentionally
rejected. QuantumLink's v1 cryptographic direction is post-quantum
session establishment without a classical key-exchange fallback.

## Build And Validate

Shared Rust workspace:

```sh
cargo test --workspace
cargo run -p qlink-core --bin qlinkctl -- quic-loopback
cargo run -p qlink-core --bin qlinkctl -- mesh-loopback
cargo run -p qlink-core --bin qlinkctl -- relay-loopback
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

- Current source is product and policy planning, not a compiled client.
- See [`steam/README.md`](steam/README.md), [`steam/version.md`](steam/version.md),
  and [`steam/docs/version-mobile.md`](steam/docs/version-mobile.md).

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
