# QuantumLink

[![CI](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml)
[![Release](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml)

QuantumLink is a macOS-first peer-to-peer mesh VPN scaffold with a server-minimized control plane. The repository contains:

- A SwiftUI macOS app surface for mesh status, enrollment, and operator controls.
- A `NEPacketTunnelProvider` implementation scaffold for the packet tunnel extension.
- A Rust mesh core with ML-KEM-768 session establishment, ML-DSA-65 device credentials, signed peer records, routing helpers, replay protection, and development rendezvous/relay services.
- macOS entitlement examples, deployment notes, and build scripts.

This is a v1 implementation baseline, not a signed/notarized production bundle. Apple signing, Network Extension entitlements, MDM pre-approval, and notarization must be completed in an Apple Developer account before installing the tunnel extension on managed or unmanaged Macs.

## Status

This repository is ready for local protocol, app, and packaging development. It is not yet ready for production VPN use.

Tracked GitHub automation includes:

- CI for Swift tests, Rust tests, formatting, local transport smokes, XCFramework generation, and unsigned Xcode project builds.
- Performance workflows for Rust criterion benches and Swift XCTest performance coverage.
- Release workflow scaffolding for unsigned builds and optional Developer ID signing/notarization when secrets are configured.

## Requirements

- macOS 14 or newer
- Swift 6 toolchain
- Rust stable toolchain
- Xcode command line tools
- XcodeGen for unsigned Xcode project generation

## Repository Layout

```text
Sources/QuantumLinkApp       SwiftUI desktop app
Sources/QuantumLinkKit       Shared Swift models, keychain, profile management
Sources/QuantumLinkTunnel    Packet tunnel provider scaffold
rust/qlink-core              Rust mesh core and qlinkctl development CLI
config                       Example mesh configuration
docs                         Architecture, security, and operations notes
macos/entitlements           Example app and extension entitlements
scripts                      Build and packaging helpers
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
- ML-KEM-768 ephemeral session establishment.
- ML-DSA-65 device credential support in the Rust core.
- Local-first diagnostics and opt-in export.
