# Pre-Apple Development Runbook

This runbook covers everything QuantumLink can validate before an Apple Developer account, Developer ID signing identity, notarization credentials, and Apple-granted Network Extension entitlement are available.

## Implemented Local Capabilities

- SwiftUI development app that runs without installing a packet tunnel extension.
- Packet tunnel provider source that compiles against Network Extension.
- Rust protocol core with an ML-KEM handshake, device signatures, signed peer records, route policy, replay protection, QUIC DATAGRAM development transport, rendezvous, relay, and STUN parser scaffolding.
- Swift FFI bridge to the Rust packet core and development QUIC transport.
- Swift packet-pump integration with fail-closed behavior.
- Local Swift-to-Rust transport smoke path through `QuantumLinkSmoke`.
- Unsigned XcodeGen project scaffolding for app, extension, and smoke targets.
- Rust XCFramework generation.
- Development artifact packaging for local CLI and library testing.

## One-Command Local Validation

```sh
./macos/scripts/preapple-check.sh
```

The script runs Swift tests, Rust formatting, Rust tests, release builds, config validation, Swift transport preflight, Rust loopback smokes, XCFramework generation, and local development artifact packaging. If XcodeGen is installed, it also performs an unsigned release dry run that archives the app and produces local DMG and PKG artifacts.

On macOS, the release dry run builds a universal Rust XCFramework by default. Install both Rust macOS targets before running the full check:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
```

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
./macos/scripts/build-unsigned-xcode.sh
```

This only proves the local Xcode project can generate and build unsigned targets. It does not make the packet tunnel installable.

## Unsigned Release Packaging Dry Run

```sh
brew install xcodegen
./macos/scripts/package-macos.sh --skip-sign --pkg
```

This validates the release packaging shape before Apple credentials exist:

- Rust XCFramework generation
- Xcode project generation
- Release archive of `QuantumLink.app`
- unsigned DMG creation
- unsigned PKG creation

The artifacts are written under `build/release/`. They are intentionally not trusted install artifacts: `--skip-sign` skips Developer ID signing, notarization, stapling, and Gatekeeper validation.

## Development Artifact Package

```sh
./macos/scripts/package-dev-artifacts.sh
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
- Developer ID Installer signing identity if PKG distribution is enabled
- Provisioning profile names
- Notary profile name for `xcrun notarytool`
- Sparkle feed URL
- Sparkle EdDSA public key

## Credential Cutover Sequence

1. Confirm Apple has granted the Network Extension capability for the Team ID and both production bundle IDs.
2. Create production identifiers for the app and packet tunnel extension, using the same App Group ID in both entitlements.
3. Create provisioning profiles that include `com.apple.developer.networking.networkextension` with `packet-tunnel-provider`.
4. Copy `macos/config/QuantumLink.developer-id.template.xcconfig` to `macos/config/QuantumLink.developer-id.local.xcconfig` and fill in the local Team ID, identity, and profile names.
5. Store notary credentials locally with `xcrun notarytool store-credentials`.
6. Export release build settings locally:

```sh
export APPLE_DEVELOPER_ID_APPLICATION="Developer ID Application: Example Inc (TEAMID)"
export APPLE_DEVELOPER_ID_INSTALLER="Developer ID Installer: Example Inc (TEAMID)"
export APPLE_NOTARY_PROFILE="QLINK_RELEASE_NOTARY"
export QLINK_DEVELOPMENT_TEAM="TEAMID"
export QLINK_APP_BUNDLE_ID="com.example.QuantumLink"
export QLINK_TUNNEL_BUNDLE_ID="com.example.QuantumLink.PacketTunnel"
export QLINK_SPARKLE_FEED_URL="https://updates.example.com/quantumlink/appcast.xml"
export QLINK_SPARKLE_PUBLIC_ED_KEY="BASE64-SPARKLE-PUBLIC-KEY"
```

7. Run `./macos/scripts/package-macos.sh --pkg` locally and verify `codesign`, `notarytool`, `stapler`, and PKG generation.
8. Configure GitHub release secrets and variables:

```text
APPLE_DEVELOPER_ID_CERT_P12_BASE64
APPLE_DEVELOPER_ID_CERT_PASSWORD
APPLE_NOTARY_API_KEY_BASE64
APPLE_NOTARY_API_KEY_ID
APPLE_NOTARY_API_KEY_ISSUER_ID
SPARKLE_EDDSA_PRIVATE_KEY
QLINK_SPARKLE_FEED_URL
QLINK_SPARKLE_PUBLIC_ED_KEY
```

9. Run the release workflow manually once before tagging a public release.
10. Validate the notarized DMG or PKG on a clean Mac with `spctl`, `codesign --verify`, and `xcrun stapler validate`.
11. Validate MDM extension pre-approval and per-app VPN payloads on a managed Mac.
