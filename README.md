# QuantumLink

[![CI](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/ci.yml)
[![Windows CI](https://github.com/exocognosis/QuantumLink/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/windows-ci.yml)
[![Release](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml/badge.svg)](https://github.com/exocognosis/QuantumLink/actions/workflows/release.yml)

QuantumLink is a peer-to-peer mesh VPN with a server-minimized control
plane and a post-quantum cryptographic core. It is built as a **monorepo
of platform silos around one shared Rust core** — the strongest reusable
asset, `qlink-core`, is the product; each platform silo wraps it with a
native tunnel, UI, and packaging.

## Silos

| Silo | Path | Status | What it is |
|------|------|--------|------------|
| **Shared core** | [`qlink-core/`](qlink-core) | Active | Rust protocol/crypto core: ML-KEM-768 sessions, ML-DSA-65 / SLH-DSA credentials, signed peer records, suite-bound packet framing, replay protection, QUIC/ICE, rendezvous/relay, `qlinkctl` dev CLI. Built by every silo. |
| **macOS** | [`macos/`](macos) | Implemented baseline | SwiftUI app + `NEPacketTunnelProvider` tunnel extension + `QuantumLinkKit`. XcodeGen project, entitlements, Sparkle/DMG/PKG packaging. |
| **Windows** | [`windows/`](windows) | Alpha scaffold | Rust privileged service (Wintun, WFP kill switch, DPAPI, named-pipe IPC) + WinUI 3 app + WiX MSI. See [windows/README.md](windows/README.md). |
| **Steam** | [`steam/`](steam) | Planning scaffold | Steam-safe gamer edition (desktop + mobile companion) layering game-aware, Steam-compliant routing on the Windows service. See [steam/README.md](steam/README.md). |

Every silo links the **same** `qlink-core` crate — there is no per-silo
copy. The Cargo workspace at the repo root ties together `qlink-core`
and the Windows silo's Rust crates; the macOS silo additionally consumes
`qlink-core` as an XCFramework built from that same crate.

## Repository layout

```text
qlink-core/                     Shared Rust mesh core + qlinkctl CLI
macos/
  Package.swift, Sources/, Tests/   SwiftPM app, QuantumLinkKit, tunnel
  project.yml, *.xcodeproj           XcodeGen spec + generated project
  entitlements/, Info/, mdm/         Apple packaging
  scripts/                           Build / xcframework / sign / package
windows/
  rust/quantumlink-proto             Shared models + named-pipe IPC schema
  rust/quantumlink-service           Privileged tunnel service
  ui/QuantumLink.Windows             WinUI 3 app
  installer/                         WiX MSI
  docs/                              Architecture, porting notes, runbook
steam/                          Steam gamer edition (planning scaffold)
config/                         Example mesh configuration (shared)
docs/                           Cross-cutting architecture / security / perf
Cargo.toml                      Root Cargo workspace
```

## Cryptographic core

The protocol lives once in [`qlink-core`](qlink-core) and is identical
across platforms:

- Protocol version `1`. Suite identifiers:
  - `QLINK-FIPS203-MLKEM768-HKDFSHA256-v1`
  - `QLINK-FIPS204-MLDSA65-HKDFSHA256-v1`
  - `QLINK-FIPS205-SLHDSA-SHA2-128S-HKDFSHA256-v1`
- ML-KEM-768 session establishment; transcript hashed with SHA-256 and
  bound into HKDF-SHA-256 directional key derivation. No X25519
  fallback (the legacy hybrid identifier is rejected).
- ML-DSA-65 default device credentials (SLH-DSA-SHA2-128S for FIPS 205);
  v1 persistence is ML-DSA-seed based.
- Signed peer records bind peer ID, device key, routes, endpoint
  candidates, ICE creds, QUIC cert material, expiration, sequence.
- `PacketTunnelCore` accepts only protected IPv4 routes and wraps
  transport frames with ChaCha20-Poly1305 under suite-bound HKDF keys;
  replay protection uses a monotonic packet-number window.

Repo-level spec and feature inventory: [`SPEC.md`](SPEC.md),
[`FEATURES.md`](FEATURES.md).

## Build

Shared core and all cross-platform Rust (runs on any host):

```sh
cargo test --workspace
cargo run -p qlink-core --bin qlinkctl -- quic-loopback
```

Per silo:

- **macOS** — `cd macos && swift test`; full validation
  `macos/scripts/preapple-check.sh`; Xcode scaffold
  `macos/scripts/build-rust-xcframework.sh && macos/scripts/generate-xcode-project.sh`.
  (XcodeGen + Apple toolchain required.)
- **Windows** — `windows/scripts/build-windows.ps1` (Rust msvc + .NET 8
  SDK; `-Msi` for the installer). Data-plane check:
  `cargo run -p quantumlink-service -- smoke`. See
  [windows/README.md](windows/README.md).
- **Steam** — planning only; see [steam/README.md](steam/README.md).

## Status

A v1 implementation baseline, not a signed/notarized production bundle.
macOS needs Apple signing + Network Extension entitlements + notarization
before the tunnel extension can run on real Macs; Windows needs an
Authenticode certificate and real-hardware validation of the Wintun/WFP
data path. CI covers Swift tests, the Rust workspace, transport smokes,
XCFramework generation, unsigned Xcode builds, and the Windows
build/test/smoke + cross-target check.

## Contributing and support

- Contribution workflow: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security reporting: [`SECURITY.md`](SECURITY.md)
- Support expectations: [`SUPPORT.md`](SUPPORT.md)
- Community expectations: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Release notes: [`CHANGELOG.md`](CHANGELOG.md)

## Production boundaries

- No mandatory centralized VPN concentrator in the steady-state data
  plane; optional rendezvous/STUN/ICE/relay only for bootstrap and
  hostile NAT.
- L3 overlay per platform (macOS `NEPacketTunnelProvider`/`utun`,
  Windows Wintun); no kernel extension / custom driver in v1.
- ML-KEM-768 session establishment with no classical fallback;
  ML-DSA-65 default credentials.
- Signed, expiring rendezvous records and authenticated inbound
  identity assertions.
- Suite-bound ChaCha20-Poly1305 packet-frame protection.
- Local-first diagnostics with opt-in export.
