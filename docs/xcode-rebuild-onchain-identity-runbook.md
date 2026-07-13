# Xcode-Machine Runbook — Rebuild QuantumLink.app with On-Chain Identity (SHAKE256)

**Audience:** operator on a Mac with **full Xcode** (not just Command Line Tools).
**Goal:** produce an updated `QuantumLink.app` that links the real SHAKE256
`qlink-core` engine and surfaces the Dytallix on-chain identity features.

**Why this is needed:** the current standalone `QuantumLink.app` is a SwiftUI
shell — its binary contains **zero `qlink-core` symbols** and bundles no
`libqlink_core`, so it runs on simulated state. This session completed the real
engine (SHAKE256 crypto, native carrier, mesh, live on-chain identity, TURN) and
the modular Swift identity module; `macos/project.yml` already links the
xcframework into every target, so a fresh Xcode build wires the real core in.

Everything below is on branch **`feat/macos-full-feature`**.

---

## 0. Prerequisites

```bash
xcode-select -p           # must be an Xcode.app path, NOT /Library/Developer/CommandLineTools
xcodebuild -version       # Xcode present
brew install xcodegen     # if missing
git fetch origin && git checkout feat/macos-full-feature
```

## 1. Build the SHAKE256 xcframework (the engine)

```bash
./scripts/build-rust-xcframework.sh
# → macos/build/qlink-core.xcframework  (universal arm64+x86_64, SHAKE256)
```

Verify it is the SHAKE256 core (not the old HKDF build):

```bash
strings macos/build/qlink-core-universal/libqlink_core.a \
  | grep -o 'QLINK-FIPS203-MLKEM768-[A-Z0-9]*-v1' | sort -u
# expect: QLINK-FIPS203-MLKEM768-SHAKE256-v1   (NOT ...-HKDFSHA256-...)
```

## 2. Wire the identity UI into the app (two edits)

The identity **module** is already in `Sources/QuantumLinkKit/` (DiscoveryIdentityMode,
MeshTrustPolicy, DytallixIdentityConfiguration, DytallixEnrollmentSettings, …) and
a starter view is in `Sources/QuantumLinkApp/DytallixEnrollmentView.swift`. Two
edits connect them:

**2a. Surface the enrollment view.** In the app's configuration/security
navigation (`Sources/QuantumLinkApp/QuantumLinkApp.swift`, the `DashboardDetailView`
section list), add a destination backed by persisted state:

```swift
// App-level persisted state (near the other @State/@StateObject):
@State private var dytallixSettings = DytallixEnrollmentSettings(
    storedJSONString: UserDefaults.standard.string(forKey: "dytallixEnrollment") ?? "{}")
@State private var discoveryIdentityMode: DiscoveryIdentityMode = .verified

// A new section/detail:
DytallixEnrollmentView(
    settings: $dytallixSettings,
    mode: $discoveryIdentityMode,
    isPublicMesh: activeProfile.isPublicMesh   // however the app models mesh type
)
```

Persist on change with `try? dytallixSettings.storedJSONString()` → UserDefaults.
Use Xcode's SwiftUI **preview** (the view ships a `PreviewProvider`) to iterate on
layout — that is exactly what this environment could not do.

**2b. Apply enforcement to the live transport.** In
`Sources/QuantumLinkKit/TunnelTransport.swift` where `meshConfig` is built
(~line 658), apply the composer so public meshes fail closed:

```swift
let meshConfig = MeshTransportConfiguration(
    meshID: configuration.meshID,
    /* …existing args… */
    peerStoreKeyB64: peerStoreKeyB64
).applyingDiscoveryIdentity(
    settings: enrollmentSettings,                 // thread from the profile/app
    mode: discoveryIdentityMode,
    meshTrustPolicy: isPublicMesh ? .publicRequired : .privatePreferred
)
```

The Rust core auto-builds a live `DytallixIdentityRegistry` from `dytallixIdentity`
and gates the connector + responder — verified end-to-end against the deployed
contract in `rust/qlink-core/tests/dytallix_live.rs`. Deployed testnet contract:
`0xbcb5cf5abb50333ee4bfde91f21bbcc24828673d` (see `config/dytallix-testnet.json`
and `config/mesh-transport.public.example.json`).

## 3. Regenerate the Xcode project and build

```bash
./scripts/generate-xcode-project.sh        # xcodegen from macos/project.yml
./scripts/build-unsigned-xcode.sh          # unsigned dev build to validate wiring
# …or a signed/notarized package once Apple creds are configured:
./scripts/package-macos.sh --pkg
```

## 4. Validate the rebuilt app

```bash
APP=DerivedData/UnsignedXcodeBuild/Build/Products/Debug/QuantumLink.app   # adjust path
# The real engine is now linked (this was 0 on the old shell build):
nm "$APP/Contents/MacOS/QuantumLink" 2>/dev/null | grep -c qlink_ ; \
  otool -L "$APP/Contents/MacOS/QuantumLink" | grep -i qlink || true
```

Launch it and confirm the **Discovery Identity** screen is present, the pinned
contract shows, and mode switching works. The packet-tunnel VPN itself still
requires the Network Extension entitlement + Developer ID signing/notarization
(Phase 5) — until then the app runs its UI + identity flows in dev mode.

## 5. Run the full test suites (Xcode present)

```bash
swift test                                  # Swift/XCTest — includes PQCAlgorithm SHAKE256 asserts
cargo test -p qlink-core                     # 193 pass
cargo test -p qlink-core --test dytallix_live -- --ignored   # live enforcement vs deployed contract
```

## Notes

- Security test plan + audit: `docs/security-test-plan-macos.md`,
  `docs/beta-testing/macos-security-audit-2026-07-03.md`.
- A prior local `qlinkctl` WIP is preserved in `git stash` (superseded by the
  reconciled CLI) — `git stash list`.
