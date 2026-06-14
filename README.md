# QuantumLink

[![CI](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml)
[![Windows CI](https://github.com/exocognosis/QuantumLink/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/windows-ci.yml)
[![Release](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml)

**QuantumLink is a post-quantum, peer-to-peer mesh VPN** with a
server-minimized control plane: peers exchange traffic directly when
possible, use rendezvous for discovery, and fall back to relay paths
only in hostile NAT — no centralized VPN concentrator in the steady
state.

It ships as **three platform editions built on one shared Rust core.**
The reusable asset, [`qlink-core`](qlink-core), *is* the product; each
edition wraps it with a native tunnel, UI, and packaging:

- **[QuantumLink for macOS](macos)** — the reference edition.
- **[QuantumLink for Windows](windows)** — the Windows-native port.
- **[QuantumLink for Steam](steam)** — the Steam-safe gamer edition.

Every edition links the **same** `qlink-core` crate — there is no
per-edition copy of the protocol, so the security-critical handshake,
packet core, transport, and peer store are written, audited, and tested
once. The Cargo workspace at the repo root ties `qlink-core` together
with the Windows edition's Rust crates; the macOS edition consumes the
same crate as an XCFramework.

## Editions

| Edition | Path | Status | Stack |
|---------|------|--------|-------|
| **macOS** | [`macos/`](macos) | Implemented baseline | SwiftUI + Network Extension |
| **Windows** | [`windows/`](windows) | Alpha scaffold | WinUI 3 + LocalSystem service |
| **Steam** | [`steam/`](steam) | Planning scaffold (docs) | Steam-safe gamer edition |

### QuantumLink for macOS — implemented baseline

A SwiftUI app plus a `NEPacketTunnelProvider` Network Extension, built on
`QuantumLinkKit` (the Swift bridge that loads `qlink-core` as an
XCFramework). Ships with an XcodeGen project, entitlements, and
Sparkle / DMG / PKG packaging. This is the most mature edition and the
behavioral reference the others port from.
→ [`macos/`](macos)

### QuantumLink for Windows — alpha scaffold

An unprivileged **WinUI 3** dashboard that talks over a newline-delimited
JSON **named pipe** to a **LocalSystem Windows service** owning the data
plane: a Wintun L3 adapter, a WFP kill switch (route ownership), a DPAPI
secret store, route/DNS programming, and an IP Helper path observer.
`qlink-core` is linked natively into the service — no FFI hop on the data
path. Packaged as a WiX MSI.
→ [`windows/`](windows) · [`windows/README.md`](windows/README.md)

### QuantumLink for Steam — planning scaffold

A Steam-safe, low-latency **gamer edition** (a desktop client plus a
mobile companion) that layers game-aware routing and Steam-compliance
policy on top of the Windows service: per-game (PID/app) routing,
Steam Datagram Relay–aware bypass, game-server ping matching, and
streamer-privacy / DDoS-shielding modes — while Steam account, store,
wallet, launcher, and embedded-browser traffic bypass the tunnel by
default. Currently documentation only; first implementation step is a
`quantumlink-steam-policy` crate encoding the Steam-safe rules.
→ [`steam/`](steam) · [`steam/README.md`](steam/README.md)

## Shared core — `qlink-core`

The protocol lives once in [`qlink-core`](qlink-core) and is identical
across editions:

- Protocol version `1`. Cipher suites:
  - `QLINK-FIPS203-MLKEM768-HKDFSHA256-v1`
  - `QLINK-FIPS204-MLDSA65-HKDFSHA256-v1`
  - `QLINK-FIPS205-SLHDSA-SHA2-128S-HKDFSHA256-v1`
- ML-KEM-768 session establishment; transcript hashed with SHA-256 and
  bound into HKDF-SHA-256 directional key derivation. No X25519 fallback
  (the legacy hybrid identifier is rejected).
- ML-DSA-65 default device credentials (SLH-DSA-SHA2-128S for FIPS 205);
  v1 persistence is ML-DSA-seed based.
- Signed peer records bind peer ID, device key, routes, endpoint
  candidates, ICE creds, QUIC cert material, expiration, and sequence.
- `PacketTunnelCore` accepts only protected IPv4 routes and wraps
  transport frames with ChaCha20-Poly1305 under suite-bound HKDF keys;
  replay protection uses a monotonic packet-number window.
- QUIC/ICE transport, rendezvous + relay fallback, and the `qlinkctl`
  developer CLI.

Repo-level spec and feature inventory: [`SPEC.md`](SPEC.md),
[`FEATURES.md`](FEATURES.md).

## Repository layout

```text
qlink-core/                     Shared Rust mesh core + qlinkctl CLI
macos/                          QuantumLink for macOS
  Package.swift, Sources/, Tests/   SwiftPM app, QuantumLinkKit, tunnel
  project.yml, *.xcodeproj           XcodeGen spec + generated project
  entitlements/, Info/, mdm/         Apple packaging
  scripts/                           Build / xcframework / sign / package
windows/                        QuantumLink for Windows
  rust/quantumlink-proto             Shared models + named-pipe IPC schema
  rust/quantumlink-service           Privileged tunnel service
  ui/QuantumLink.Windows             WinUI 3 app
  installer/                         WiX MSI
  docs/                              Architecture, porting notes, runbook
steam/                          QuantumLink for Steam (planning scaffold)
config/                         Example mesh configuration (shared)
docs/                           Cross-cutting architecture / security / perf
Cargo.toml                      Root Cargo workspace
```

## Build

Shared core and all cross-platform Rust (runs on any host):

```sh
cargo test --workspace
cargo run -p qlink-core --bin qlinkctl -- quic-loopback
```

Per edition:

- **macOS** — `cd macos && swift test`; full validation
  `macos/scripts/preapple-check.sh`; Xcode scaffold
  `macos/scripts/build-rust-xcframework.sh && macos/scripts/generate-xcode-project.sh`
  (XcodeGen + Apple toolchain required).
- **Windows** — `windows/scripts/build-windows.ps1` (Rust msvc + .NET 8
  SDK; `-Msi` for the installer). Data-plane check:
  `cargo run -p quantumlink-service -- smoke`. See
  [`windows/README.md`](windows/README.md).
- **Steam** — planning only; see [`steam/README.md`](steam/README.md).

## Status & production boundaries

A v1 implementation baseline, not a signed/notarized production bundle.
macOS needs Apple signing + Network Extension entitlements + notarization
before the tunnel extension can run on real Macs; Windows needs an
Authenticode certificate and real-hardware validation of the Wintun/WFP
data path. CI covers the Rust workspace, Swift tests, transport smokes,
XCFramework generation, unsigned Xcode builds, and the Windows
build/test/smoke + cross-target check.

Design boundaries that hold across every edition:

- No mandatory centralized VPN concentrator in the steady-state data
  plane; optional rendezvous/STUN/ICE/relay only for bootstrap and
  hostile NAT.
- L3 overlay per platform (macOS `NEPacketTunnelProvider`/`utun`,
  Windows Wintun); no kernel extension / custom driver in v1.
- ML-KEM-768 session establishment with no classical fallback;
  ML-DSA-65 default credentials.
- Signed, expiring rendezvous records and authenticated inbound identity
  assertions.
- Suite-bound ChaCha20-Poly1305 packet-frame protection.
- Local-first diagnostics with opt-in export.

## Contributing and support

- Contribution workflow: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security reporting: [`SECURITY.md`](SECURITY.md)
- Support expectations: [`SUPPORT.md`](SUPPORT.md)
- Community expectations: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Release notes: [`CHANGELOG.md`](CHANGELOG.md)
