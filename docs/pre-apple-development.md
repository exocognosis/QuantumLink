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
- Party Mesh invite-code presentation model and macOS launcher UI for gamer
  create/join flows. This layer serializes non-secret join metadata and uses the
  existing mesh transport configuration path; it does not add a separate fake
  transport.
- Static macOS release-readiness checks for bundle identifiers, app group,
  entitlement templates, XcodeGen target wiring, and packaging/notarization
  script prerequisites.

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

Validate macOS release signing and entitlement wiring without Apple credentials:

```sh
./macos/scripts/macos-release-readiness.sh
```

Before a real signed release, require the Developer ID, notary, bundle ID, app
group, provisioning profile, and Sparkle update environment:

```sh
./macos/scripts/macos-release-readiness.sh --require-signing-env
```

Before building a signed PKG release, include the installer identity check:

```sh
./macos/scripts/macos-release-readiness.sh --require-pkg-signing-env
```

The readiness check validates project configuration and packaging workflow
wiring. It does not prove the packet tunnel can install or run on customer Macs;
that still requires Apple-granted Network Extension capability, matching app and
packet-tunnel provisioning profiles, a Developer ID signed archive, successful
notarization, and Gatekeeper validation of the exported artifact.

Use the beta tester and release operator checklists before distributing builds:

- `docs/beta-tester-onboarding.md`
- `docs/release-operator-checklist.md`

`./macos/scripts/preapple-check.sh` requires XcodeGen for package-readiness lanes. Set
`QLINK_ALLOW_SKIP_XCODEGEN=true` only for CI jobs that intentionally skip
unsigned Xcode archive and package validation.

## Dytallix Identity Registry E2E

Install the WASM target before building the registry contract:

```sh
rustup target add wasm32-unknown-unknown
```

Build the QuantumLink CLI and the real Dytallix registry contract:

```sh
cargo build -p qlink-core --bin qlinkctl
cargo build \
  --manifest-path dytallix/quantumlink-node-registry/Cargo.toml \
  --target wasm32-unknown-unknown \
  --release
```

Deploy the built registry WASM with the Dytallix CLI and use the returned contract address. The exact deploy command is intentionally not listed here because no Dytallix deploy command is present in this repository.

For the current public QuantumLink registry deployment, load the checked-in public endpoint and contract address:

```sh
source config/dytallix.public.env
```

For a custom registry deployment, set the network endpoint and deployed contract address explicitly:

```sh
export DYTALLIX_ENDPOINT="https://dytallix.example"
export DYTALLIX_REGISTRY_CONTRACT="dytallix-contract-address"
```

Public meshes must also pin the Dytallix testnet identity surface in the app or
managed configuration:

- `networkId`
- `chainId`
- `allowedRpcEndpoints`

Private and development meshes may omit those pins, but QuantumLink will show
warnings because unpinned testnet verification is provisional trust.

By default, `qlinkctl identity enroll` opens the Dytallix default keystore and creates a persistent `quantumlink` wallet if no active wallet exists. To use a specific keystore or wallet, set either optional variable before running the smoke:

```sh
export DYTALLIX_KEYSTORE_PATH="$HOME/.dytallix/keystore.json"
export DYTALLIX_WALLET_NAME="quantumlink-dev"
```

Run the end-to-end identity registry verification:

```sh
./scripts/dytallix-identity-e2e.sh
```

The script builds `qlinkctl`, builds the real registry WASM contract, creates persistent e2e artifacts under `build/dytallix-identity-e2e/`, enrolls a signed QuantumLink peer record with `qlinkctl identity enroll`, derives the `peer_id` from the enroll output, then verifies it with `qlinkctl identity status`. It fails unless the enroll output includes `tx_hash=`, the status response contains `found=true`, and the registry record is `active`.

Run the opt-in negative registry verification when using a disposable wallet and peer record:

```sh
DYTALLIX_E2E_NEGATIVE=1 ./scripts/dytallix-identity-e2e.sh
```

Negative mode also checks an absent peer (`found=false`), confirms duplicate registration is rejected as already registered, revokes the enrolled peer, and verifies the final status is `revoked`.

The macOS app stores only non-secret enrollment settings: Dytallix endpoint, registry contract, network/chain pins, allowed RPC endpoint pins, public wallet metadata, peer ID, and enrollment status. The installed tunnel profile receives the lookup-only `TunnelConfiguration`; Dytallix keystore paths and wallet private keys stay outside `TunnelConfiguration`, `UserDefaults`, and NetworkExtension provider configuration.

In the app, use the Testnet Wallet/Faucet action to open `https://dytallix.com/build/wallet` when the local wallet is missing, locked, or a registry transaction needs testnet funds or faucet cooldown review.

Do not attach raw `build/dytallix-identity-e2e/` artifacts to beta reports.
They may contain wallet metadata, peer IDs, transaction hashes, contract
addresses, and timing evidence. Use the app's default redacted support bundle
unless an operator explicitly requests raw testnet evidence from a disposable
wallet.

## Party Mesh Gamer Slice

The macOS Home and Connections launcher can create and parse Party Mesh join
codes. A code starts with `QLP1-` and contains the mesh ID, host alias, host
overlay address, rendezvous endpoints, relay endpoints, game port, identity
mode, and mesh trust policy.

This is a product-surface slice over the existing mesh mode. Creating or joining
a Party Mesh code does not simulate NAT traversal, direct path nomination, relay
capacity, or game traffic quality. Latency and direct/relay UI remains pending
until real peer telemetry is reported by the transport.

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

The packaging script stages the Xcode archive under `/tmp` and copies the final
artifacts back to `build/release/`. This avoids FileProvider/cloud-backed
workspace stalls while still producing artifacts from the current source tree.

Unsigned packaging disables the optional Sparkle package link by default so the
dry run does not block on SwiftPM's binary artifact downloader or Keychain
authorization. Signed release packaging keeps Sparkle enabled and requires the
feed URL and public EdDSA key.

The artifacts are written under `build/release/`. They are intentionally not
trusted install artifacts: `--skip-sign` skips Developer ID signing,
notarization, stapling, and Gatekeeper validation. On current macOS builds,
`productbuild` may preserve system provenance metadata as AppleDouble `._*`
entries in the unsigned PKG payload even when the exported `.app` bundle itself
does not contain those files; confirm this again on the signed release machine.

For a signed release, export the required signing environment and run:

```sh
./macos/scripts/macos-release-readiness.sh --require-signing-env
./macos/scripts/package-macos.sh --pkg
```

Required signed-release environment:

- `APPLE_DEVELOPER_ID_APPLICATION`
- `APPLE_DEVELOPER_ID_INSTALLER`
- `APPLE_NOTARY_PROFILE`
- `QLINK_DEVELOPMENT_TEAM`
- `QLINK_APP_BUNDLE_ID`
- `QLINK_TUNNEL_BUNDLE_ID`
- `QLINK_APP_GROUP`
- `QLINK_APP_PROVISIONING_PROFILE_SPECIFIER`
- `QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER`
- `QLINK_SPARKLE_FEED_URL`
- `QLINK_SPARKLE_PUBLIC_ED_KEY`

## Development Artifact Package

```sh
./macos/scripts/package-dev-artifacts.sh
```

The package is written to `macos/build/dist/QuantumLink-dev.tar.gz` with a sibling `.sha256` file. It includes local CLI tools, the Rust dylib, example config, a manifest, and a short runbook. It is not signed or notarized.

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
export QLINK_APP_GROUP="group.com.example.QuantumLink"
export QLINK_APP_PROVISIONING_PROFILE_SPECIFIER="QuantumLink Developer ID App Profile"
export QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER="QuantumLink Developer ID Tunnel Profile"
export QLINK_SPARKLE_FEED_URL="https://updates.example.com/quantumlink/appcast.xml"
export QLINK_SPARKLE_PUBLIC_ED_KEY="BASE64-SPARKLE-PUBLIC-KEY"
```

7. Run `./macos/scripts/package-macos.sh --pkg` locally and verify `codesign`, `notarytool`, `stapler`, and PKG generation.
8. Configure GitHub release secrets:

```text
APPLE_DEVELOPER_ID_CERT_P12_BASE64
APPLE_DEVELOPER_ID_CERT_PASSWORD
APPLE_NOTARY_API_KEY_BASE64
APPLE_NOTARY_API_KEY_ID
APPLE_NOTARY_API_KEY_ISSUER_ID
QLINK_APP_PROVISIONING_PROFILE_BASE64
QLINK_TUNNEL_PROVISIONING_PROFILE_BASE64
SPARKLE_EDDSA_PRIVATE_KEY
```

Configure GitHub release variables:

```text
QLINK_DEVELOPMENT_TEAM
QLINK_APP_BUNDLE_ID
QLINK_TUNNEL_BUNDLE_ID
QLINK_APP_GROUP
QLINK_SPARKLE_FEED_URL
QLINK_SPARKLE_PUBLIC_ED_KEY
QLINK_APP_PROVISIONING_PROFILE_SPECIFIER
QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER
```

9. Run the release workflow manually once before tagging a public release.
10. Validate the notarized DMG or PKG on a clean Mac with `spctl`, `codesign --verify`, and `xcrun stapler validate`.
11. Validate MDM extension pre-approval and per-app VPN payloads on a managed Mac.
