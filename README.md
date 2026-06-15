# QuantumLink

[![CI](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml)
[![Release](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml)

QuantumLink is a post-quantum, peer-to-peer mesh VPN with a server-minimized control plane. The repository is organized around one shared Rust protocol core and platform-specific product silos.

## Repository Model

- `rust/qlink-core` is the shared protocol, crypto, packet-core, peer-record, rendezvous, relay, QUIC/ICE, and diagnostics foundation.
- macOS, Windows, and Steam editions wrap that shared core with platform-specific tunnel runtimes, user surfaces, packaging, and policy.
- Security-sensitive protocol work should land in `rust/qlink-core` unless it is truly platform-specific.
- Platform-specific code should stay inside its owning silo instead of re-framing the whole repository.

## Platform Silos

| Edition | Path | Status | Notes |
| --- | --- | --- | --- |
| macOS | `macos/`, `Sources/`, `Tests/` | Implemented baseline | SwiftUI app, Network Extension scaffold, MDM helpers, packaging/signing assets. |
| Windows | `windows/` | Platform silo | Windows service/UI/installer work when present in the branch. |
| Steam | `steam/` | Gamer silo | Steam-safe routing and game-aware runtimes layered on the shared core. |

The Steam silo includes the SteamOS/Linux daemon scaffold under `steam/steamos`. That runtime is part of the Steam gamer edition; it does not replace the shared-core/platform-silo architecture.

## SteamOS Quick Start

Build the SteamOS daemon and CLI from the repository root:

```sh
cargo build --release -p qlinkd -p qlinkctl
```

Install the SteamOS runtime assets:

```sh
sudo ./steam/steamos/scripts/install-steamos.sh
```

For details, see `steam/steamos/README.md` and `steam/steamos/docs/architecture.md`.

## Development Checks

Run the broad Rust checks when changing shared or SteamOS Rust code:

```sh
cargo test --workspace
```

For the current SteamOS scaffold subset:

```sh
cargo check -p qlinkd -p qlinkctl -p qlink-linux -p qlink-proto -p qlink-game
cargo test -p qlink-game
bash -n steam/steamos/scripts/install-steamos.sh
```

macOS and Windows platform checks remain owned by their silos.

## Production Boundaries

This repository is still a development baseline, not a hardened public VPN service. Before public production use, QuantumLink still needs production rendezvous/relay operations, authenticated update channels, release signing per platform, production packet-key installation from negotiated sessions, platform data-plane hardening, and compatibility validation on real target hardware.
