# Pre-Apple Development Runbook

This runbook covers everything QuantumLink can validate before an Apple Developer account, Developer ID signing identity, notarization credentials, and Apple-granted Network Extension entitlement are available.

## Implemented Local Capabilities

- SwiftUI development app that runs without installing a packet tunnel extension.
- Packet tunnel provider source that compiles against Network Extension.
- Rust protocol core with hybrid handshake, device signatures, signed peer records, route policy, replay protection, QUIC DATAGRAM development transport, rendezvous, relay, and STUN parser scaffolding.
- Swift FFI bridge to the Rust packet core and development QUIC transport.
- Swift packet-pump integration with fail-closed behavior.
- Local Swift-to-Rust transport smoke path through `QuantumLinkSmoke`.
- Unsigned XcodeGen project scaffolding for app, extension, and smoke targets.
- Rust XCFramework generation.
- Development artifact packaging for local CLI and library testing.

## One-Command Local Validation

```sh
./scripts/preapple-check.sh
```

The script runs Swift tests, Rust formatting, Rust tests, release builds, config validation, Swift transport preflight, Rust loopback smokes, XCFramework generation, and local development artifact packaging. If XcodeGen is installed, it also attempts an unsigned Xcode build.

## Individual Smokes

Validate the example mesh config:

```sh
swift run QuantumLinkSmoke validate-config --config config/mesh.example.json
```

Run Swift packet pump plus Rust QUIC transport loopback:

```sh
cargo build --workspace --release
swift run QuantumLinkSmoke preflight \
  --config config/mesh.example.json \
  --transport \
  --mode dev-quic-loopback \
  --dylib "$PWD/target/release/libqlink_core.dylib"
```

Run Rust core smokes:

```sh
target/release/qlinkctl simulate-handshake
target/release/qlinkctl quic-loopback
target/release/qlinkctl mesh-loopback
target/release/qlinkctl relay-loopback
```

## Unsigned Xcode Build

```sh
brew install xcodegen
./scripts/build-unsigned-xcode.sh
```

This only proves the local Xcode project can generate and build unsigned targets. It does not make the packet tunnel installable.

## Development Artifact Package

```sh
./scripts/package-dev-artifacts.sh
```

The package is written to `build/dist/QuantumLink-dev.tar.gz` and includes local CLI tools, the Rust dylib, example config, and a short runbook. It is not signed or notarized.

## Apple-Blocked Work

These tasks cannot be completed honestly before Apple account setup:

- Requesting and receiving the Packet Tunnel Provider entitlement for the target Team ID.
- Creating provisioning profiles containing `com.apple.developer.networking.networkextension`.
- Installing and starting the real packet tunnel extension through System Settings or MDM.
- Developer ID signing of app, extension, helpers, or PKG.
- Notarization, stapling, and Gatekeeper verification of the distributed artifact.
- Validating MDM extension pre-approval and per-app VPN payloads on managed Macs.

## Developer ID Handoff Inputs

When the Apple Developer account is ready, fill in:

- Team ID
- Production app bundle ID
- Production packet tunnel bundle ID
- App Group ID
- Developer ID Application signing identity
- Provisioning profile names
- Notary profile name for `xcrun notarytool`
