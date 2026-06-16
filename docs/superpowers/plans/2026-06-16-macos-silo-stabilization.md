# macOS Silo Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the macOS silo on `main` cleanly runnable through SwiftPM/Codex without stale source artifacts or unhandled-resource warnings.

**Architecture:** Keep the cleanup narrow and source-first. Remove tracked recovery artifacts from `macos/Sources`, declare the SwiftPM app resources explicitly, and verify through the existing `macos/script/build_and_run.sh` path plus focused Swift/Rust checks.

**Tech Stack:** SwiftPM, Swift 6 toolchain, macOS SwiftUI app resources, Rust `qlink-core`, GitHub PR workflow.

---

### Task 1: Remove Tracked Stale Artifacts

**Files:**
- Modify: `.gitignore`
- Delete: `macos/Sources/QuantumLinkApp/UpdateController.swift.blocked-read-20260521`
- Delete: `macos/Sources/QuantumLinkKit/ManagedConfiguration.swift.blocked-read-20260521`
- Delete: `macos/Sources/QuantumLinkKit/MeshController.swift.blocked-read-20260521`
- Delete: `macos/Sources/QuantumLinkKit/PQCAlgorithm.swift.blocked-read-20260521`
- Delete: `macos/Sources/QuantumLinkKit/RustTracingForwarder.swift.blocked-read-20260521`
- Delete: `macos/Sources/QuantumLinkKit/TransportSmokeRunner.swift.blocked-read-20260521`
- Delete: `macos/Sources/QuantumLinkKit/TunnelPacketPump.swift.blocked-read-20260521`
- Delete: `macos/scripts/generate-xcode-project.sh.blocked-read-20260521`
- Delete: `macos/Sources/QuantumLinkApp/Resources/DytallixLogo 2.png`

- [ ] **Step 1: Verify files are tracked**

Run:

```bash
git ls-files 'macos/Sources/**/*.blocked-read-*' 'macos/Sources/**/* 2.*'
```

Expected: the nine `.blocked-read-*` files plus the duplicate logo listed above.

- [ ] **Step 2: Delete only the stale tracked files**

Ensure `.gitignore` contains:

```gitignore
*.blocked-read-*
```

Run:

```bash
git rm \
  macos/Sources/QuantumLinkApp/UpdateController.swift.blocked-read-20260521 \
  macos/Sources/QuantumLinkKit/ManagedConfiguration.swift.blocked-read-20260521 \
  macos/Sources/QuantumLinkKit/MeshController.swift.blocked-read-20260521 \
  macos/Sources/QuantumLinkKit/PQCAlgorithm.swift.blocked-read-20260521 \
  macos/Sources/QuantumLinkKit/RustTracingForwarder.swift.blocked-read-20260521 \
  macos/Sources/QuantumLinkKit/TransportSmokeRunner.swift.blocked-read-20260521 \
  macos/Sources/QuantumLinkKit/TunnelPacketPump.swift.blocked-read-20260521 \
  macos/scripts/generate-xcode-project.sh.blocked-read-20260521 \
  'macos/Sources/QuantumLinkApp/Resources/DytallixLogo 2.png'
```

Expected: all stale paths staged as deleted.

- [ ] **Step 3: Confirm no tracked stale scratch files remain**

Run:

```bash
find macos/Sources \( -name '*.blocked-read-*' -o -name '* 2.*' \) -print
git ls-files '*blocked-read-*'
```

Expected: both commands print no output.

### Task 2: Declare SwiftPM App Resources

**Files:**
- Modify: `macos/Package.swift`

- [ ] **Step 1: Add the asset catalog to the app target resources**

Change the `QuantumLinkApp` executable target resources from:

```swift
resources: [
    .process("Resources")
]
```

to:

```swift
resources: [
    .process("Assets.xcassets"),
    .process("Resources")
]
```

- [ ] **Step 2: Build through the app run script**

Run:

```bash
cd macos
./script/build_and_run.sh --verify
```

Expected: build succeeds and the previous unhandled `Assets.xcassets` warning is gone.

### Task 3: Remove Sendable Date Warning

**Files:**
- Modify: `macos/Sources/QuantumLinkKit/SupportBundleExporter.swift`
- Test: `macos/Tests/QuantumLinkKitTests/SupportBundleExporterTests.swift`

- [ ] **Step 1: Locate the initializer default**

Run:

```bash
rg -n 'now: @Sendable|Date.init' macos/Sources/QuantumLinkKit/SupportBundleExporter.swift macos/Tests/QuantumLinkKitTests/SupportBundleExporterTests.swift
```

Expected: the production initializer defaults `now` to `Date.init`.

- [ ] **Step 2: Replace the non-Sendable default with a sendable closure**

Change:

```swift
now: @Sendable @escaping () -> Date = Date.init,
```

to:

```swift
now: @Sendable @escaping () -> Date = { Date() },
```

- [ ] **Step 3: Run a focused Swift build**

Run:

```bash
cd macos
swift build --product QuantumLink
```

Expected: build succeeds and the `converting non-Sendable function value` warning is gone.

### Task 4: Verification And PR Prep

**Files:**
- Modify: this plan as checklist status changes if useful.

### Task 4: Remove Tracked Generated Xcode Projects

**Files:**
- Modify: `.gitignore`
- Delete: `macos/QuantumLink.xcodeproj/`
- Delete: `macos/QuantumLink 2.xcodeproj/`
- Delete: `macos/QuantumLink 3.xcodeproj/`
- Delete: `macos/QuantumLink 4.xcodeproj/`

- [ ] **Step 1: Verify generated projects are tracked but ignored for future local generation**

Run:

```bash
git ls-files 'macos/*.xcodeproj/**'
git check-ignore -q macos/QuantumLink.xcodeproj && echo ignored
```

Expected: tracked project files are listed, and `ignored` is printed because `.gitignore` excludes generated `macos/*.xcodeproj` directories.

- [ ] **Step 2: Add the generated project ignore rule if missing**

Ensure `.gitignore` contains:

```gitignore
macos/*.xcodeproj/
macos/*.xcodeproj/**
```

Run:

```bash
git check-ignore -q macos/QuantumLink.xcodeproj && echo ignored
```

Expected: `ignored`.

- [ ] **Step 3: Remove the generated projects from version control**

Run:

```bash
git rm -r \
  'macos/QuantumLink.xcodeproj' \
  'macos/QuantumLink 2.xcodeproj' \
  'macos/QuantumLink 3.xcodeproj' \
  'macos/QuantumLink 4.xcodeproj'
```

Expected: all tracked generated project files are staged as deleted.

- [ ] **Step 4: Confirm no tracked generated project files remain**

Run:

```bash
git ls-files 'macos/*.xcodeproj/**'
```

Expected: no output.

### Task 5: Verification And PR Prep

**Files:**
- Modify: this plan as checklist status changes if useful.

- [ ] **Step 1: Verify source warnings are removed**

Run:

```bash
cd macos
./script/build_and_run.sh --verify
```

Expected: build succeeds, app verification succeeds, and no unhandled-resource or stale generated-project warnings appear.

- [ ] **Step 2: Verify Rust core remains clean**

Run:

```bash
cargo test -p qlink-core
```

Expected: all `qlink-core` tests pass.

- [ ] **Step 3: Run Swift tests if local XCTest is available**

Run:

```bash
cd macos
xcrun --find xctest && swift test
```

Expected: if full Xcode is installed, Swift tests pass. If `xctest` is unavailable, record the environment blocker and rely on GitHub CI for Swift test execution.

- [ ] **Step 4: Commit and push**

Run:

```bash
git status -sb
git add .gitignore macos/Package.swift macos/Sources macos/*.xcodeproj docs/superpowers/plans/2026-06-16-macos-silo-stabilization.md
git commit -m "Stabilize macOS silo source hygiene"
git push -u origin codex/macos-silo-stabilization
```

Expected: one branch pushed with only macOS source-hygiene and plan changes.
