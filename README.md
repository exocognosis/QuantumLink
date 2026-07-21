# QuantumLink

[![CI](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml)
[![Release](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml)

QuantumLink is a cross-platform peer-to-peer mesh VPN product with a server-minimized control plane, a shared post-quantum cryptographic core, native client silos for macOS, Windows, and Steam/SteamOS, and a dedicated QuantumLink Agent silo for agent-assisted mesh operations. The repository contains:

- A SwiftUI macOS app surface for mesh status, enrollment, and operator controls.
- A `NEPacketTunnelProvider` implementation scaffold for the packet tunnel extension.
- A Rust `qlink-core` crate with ML-KEM-768 session establishment, ML-DSA-65 and SLH-DSA device credentials, signed peer records, suite-bound packet-frame encryption, routing helpers, replay protection, QUIC/ICE traversal scaffolding, and development rendezvous/relay services.
- Native platform silos for macOS, Windows, and Steam/SteamOS development.
- A `QuantumLinkAgent` silo for agent runtime orchestration, trust-policy guardrails, diagnostics interpretation, Dytallix identity explanation, and guarded automation.
- macOS entitlement examples, deployment notes, and build scripts.

This is a v1 implementation baseline, not a signed/notarized production bundle. Apple signing, Network Extension entitlements, MDM pre-approval, and notarization must be completed in an Apple Developer account before installing the tunnel extension on managed or unmanaged Macs.

## Status

This repository is ready for local protocol, app, and packaging development. It is not yet ready for production VPN use.

Tracked GitHub automation includes:

- CI for Swift tests, Rust tests, formatting, local transport smokes, XCFramework generation, and unsigned Xcode project builds.
- Performance workflows for Rust criterion benches and Swift XCTest performance coverage.
- Release workflow scaffolding for unsigned builds and optional Developer ID signing/notarization when secrets are configured.

## Product Silos

QuantumLink is organized around a shared core plus product-specific silos:

- `rust/qlink-core`: shared post-quantum mesh, identity, peer-record, packet-protection, routing, replay, rendezvous, relay, and development CLI assets.
- `Sources/QuantumLinkApp`, `Sources/QuantumLinkKit`, `Sources/QuantumLinkTunnel`, and `macos/`: macOS app, shared Swift models, packet tunnel provider, Apple entitlement, packaging, and release support.
- `windows/`: Windows client architecture, beta runbooks, and Windows-specific product planning.
- `steam/`: Steam/SteamOS client planning, Linux-oriented daemon/CLI expectations, and release-readiness material.
- `QuantumLinkAgent/`: agentic VPN product silo that uses shared `qlink-core` primitives to explain, recommend, and safely apply mesh operations without owning the platform VPN implementations or cryptographic protocol.

QuantumLink Agent is intentionally separate from the macOS, Windows, and Steam/SteamOS client silos. Platform clients own native packaging and tunnel integration. `qlink-core` owns cryptography, transport, identity primitives, peer records, and packet protection. QuantumLink Agent owns the agent runtime, policy guardrails, diagnostics interpretation, Dytallix identity explanation, route and relay recommendations, Agent-specific prompts, workflows, audit records, and UI/CLI adapter contracts.

## Cryptographic Implementation

The active protocol implementation lives in `rust/qlink-core`. Its current cryptographic design combines post-quantum key establishment and signatures with conventional transcript hashing, HKDF, and AEAD packet framing:

- Protocol version: `1`.
- Supported suite identifiers:
  - `QLINK-FIPS203-MLKEM768-HKDFSHA256-v1`
  - `QLINK-FIPS204-MLDSA65-HKDFSHA256-v1`
  - `QLINK-FIPS205-SLHDSA-SHA2-128S-HKDFSHA256-v1`
- Session establishment uses ML-KEM-768. The initiator/responder transcript is hashed with SHA-256 and bound into HKDF-SHA-256 directional key derivation.
- Device credentials use ML-DSA-65 by default. SLH-DSA-SHA2-128S is implemented for the FIPS 205 suite, but v1 persistence is ML-DSA-seed based.
- Signed peer records bind peer ID, device public key, routes, short-lived endpoint candidates, ICE credentials, QUIC certificate material, expiration, and sequence number.
- `PacketTunnelCore` accepts only protected IPv4 routes, normalizes selected IPv4 metadata, and wraps transport frames with ChaCha20-Poly1305 using suite-bound HKDF-derived frame keys.
- Replay protection is implemented with a monotonic packet-number window.

The Rust core intentionally rejects the legacy `QLINK-HYBRID-X25519-MLKEM768-HKDFSHA256-v1` identifier. There is no X25519 fallback in the current handshake. Production peer sessions still need to wire negotiated session secrets into packet-frame encryption; the current packet-frame keys are development suite-bound keys.

For the repo-level specification and feature inventory, see `SPEC.md` and `FEATURES.md`.

## Requirements

- macOS 14 or newer
- Swift 6 toolchain
- Rust stable toolchain
- Xcode command line tools
- XcodeGen for unsigned Xcode project generation

## Repository Layout

```text
Sources/QuantumLinkApp       SwiftUI macOS app surface
Sources/QuantumLinkKit       Shared Swift models, keychain, profile management
Sources/QuantumLinkTunnel    macOS packet tunnel provider scaffold
rust/qlink-core              Shared Rust PQC mesh core and qlinkctl development CLI
macos                        macOS project, entitlement, packaging, and release assets
windows                      Windows architecture, planning, and beta materials
steam                        Steam/SteamOS planning and release-readiness materials
QuantumLinkAgent             Agentic VPN silo for policy, diagnostics, identity, and automation
config                       Example mesh configuration
docs                         Architecture, security, and operations notes
scripts                      Build and packaging helpers
```

The `QuantumLinkAgent` silo currently contains:

```text
QuantumLinkAgent/README.md                       Silo overview and ownership boundary
QuantumLinkAgent/feature.md                      Agent product feature specification
QuantumLinkAgent/docs/architecture.md            Agent runtime architecture
QuantumLinkAgent/docs/development-plan.md        Implementation roadmap
QuantumLinkAgent/docs/policy-and-permissions.md  Guardrails and approval model
QuantumLinkAgent/src/runtime                     Agent runtime orchestration boundary
QuantumLinkAgent/src/identity                    Dytallix identity adapter boundary
QuantumLinkAgent/src/mesh                        qlink-core mesh adapter boundary
QuantumLinkAgent/src/policy                      Policy engine and patch model
QuantumLinkAgent/src/diagnostics                 Redacted evidence model
QuantumLinkAgent/src/ui                          Agent-facing UI contract
QuantumLinkAgent/config                          Example policy and prompt templates
QuantumLinkAgent/scripts                         Future Agent development scripts
QuantumLinkAgent/tests                           Agent test strategy and safe fixtures
```

## Build

```sh
./scripts/build.sh
```

The script runs Swift tests, Rust tests, and a Rust release build. The full pre-Apple local validation pass is:

```sh
./scripts/preapple-check.sh
```

For local iteration you can also run:

```sh
swift test
cargo test --workspace
cargo run -p qlink-core --bin qlinkctl -- simulate-handshake
cargo run -p qlink-core --bin qlinkctl -- quic-loopback
cargo run -p qlink-core --bin qlinkctl -- mesh-loopback
cargo run -p qlink-core --bin qlinkctl -- relay-loopback
```

The Swift-side transport facade can also be smoked without a Network Extension entitlement:

```sh
cargo build -p qlink-core --release
swift run QuantumLinkSmoke transport-loopback \
  --mode dev-quic-loopback \
  --dylib "$PWD/target/release/libqlink_core.dylib"
```

## Xcode Scaffolding Without Apple Credentials

The repository includes an unsigned XcodeGen project spec at `macos/project.yml`. It can generate an app target, packet-tunnel extension target, and Rust XCFramework dependency without an Apple Developer account:

```sh
./scripts/build-rust-xcframework.sh
./scripts/generate-xcode-project.sh
```

This produces local build scaffolding only. Real packet-tunnel execution still requires Apple-granted Network Extension entitlements and provisioning profiles.

## Run the Development App

```sh
swift run QuantumLinkApp
```

The SwiftUI app currently uses `SimulatedMeshController` so it can run without a signed packet tunnel extension. The actual extension entry point is `PacketTunnelProvider` in `Sources/QuantumLinkTunnel`.

To show live local QUIC transport smoke metrics in the development app, launch it with:

```sh
QLINK_CORE_DYLIB="$PWD/target/release/libqlink_core.dylib" \
QLINK_TRANSPORT_MODE=dev-quic-loopback \
swift run QuantumLinkApp
```

## Development Services

Start the in-memory authenticated rendezvous service:

```sh
cargo run -p qlink-core --bin qlinkctl -- rendezvous --listen 127.0.0.1:9471
cargo run -p qlink-core --bin qlinkctl -- rendezvous-smoke --server 127.0.0.1:9471
```

Start the development relay:

```sh
cargo run -p qlink-core --bin qlinkctl -- relay --listen 127.0.0.1:9472
cargo run -p qlink-core --bin qlinkctl -- relay-smoke --server 127.0.0.1:9472
```

These services are intentionally minimal and are suitable for local protocol work. They are not a hardened public control plane.

Additional `qlinkctl` development commands exercise the current mesh transport surface:

```sh
cargo run -p qlink-core --bin qlinkctl -- generate-device --json
cargo run -p qlink-core --bin qlinkctl -- mesh-connect --scenario direct
cargo run -p qlink-core --bin qlinkctl -- mesh-connect --scenario relay-fallback
```

## Development Artifact Package

```sh
./scripts/package-dev-artifacts.sh
```

This writes `build/dist/QuantumLink-dev.tar.gz`, an unsigned local artifact containing `qlinkctl`, `QuantumLinkSmoke`, `libqlink_core.dylib`, example config, and a runbook. It is for development smoke testing only.

See `docs/pre-apple-development.md` for the complete local runbook and the Apple-only blocker list.

## Contributing and Support

- Contribution workflow: `CONTRIBUTING.md`
- Security reporting: `SECURITY.md`
- General support expectations: `SUPPORT.md`
- Community expectations: `CODE_OF_CONDUCT.md`
- Release notes: `CHANGELOG.md`

## Production Boundaries

QuantumLink v1 is structured around these boundaries:

- No mandatory centralized VPN concentrator in the steady-state data plane.
- Optional rendezvous, STUN/ICE, and relay paths for bootstrap and hostile NAT/firewall conditions.
- L3 overlay through `NEPacketTunnelProvider` and `utun`; no kernel extension and no pf-based core design.
- ML-KEM-768 session establishment without a classical key-exchange fallback.
- ML-DSA-65 default device credential support, with SLH-DSA-SHA2-128S support for the FIPS 205 suite.
- Signed, expiring rendezvous records and authenticated inbound identity assertions.
- Suite-bound ChaCha20-Poly1305 packet-frame protection in the Rust packet core.
- Local-first diagnostics and opt-in export.
