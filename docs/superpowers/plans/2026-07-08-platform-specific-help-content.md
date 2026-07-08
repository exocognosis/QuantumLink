# Platform-Specific Help Content Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace generic cross-platform QuantumLink help copy with platform-specific macOS, Windows, and SteamOS help points that use each OS surface's real language and functions.

**Architecture:** Keep shared help primitives in `QuantumLinkKit`, but make topic selection and searchable text platform-aware. macOS defaults to macOS help, Windows owns Windows WinUI help strings, and SteamOS owns `qlinkctl` operator help text.

**Tech Stack:** Swift/SwiftUI, XCTest source tests, WinUI/C# view model strings, Rust `qlinkctl`, Cargo tests, SwiftPM build, Git.

---

### Task 1: Make `QuantumLinkKit` Help Content Platform-Aware

**Files:**
- Modify: `macos/Sources/QuantumLinkKit/HelpContent.swift`
- Modify: `macos/Tests/QuantumLinkKitTests/HelpContentTests.swift`

- [x] **Step 1: Write failing platform-language tests**

Add tests requiring macOS text to mention `Network Extension`, `Keychain`, `MDM`, `Developer ID`, `notarization`, and `Sparkle`; Windows text to mention `Wintun`, `WFP`, `DPAPI`, `named-pipe IPC`, `WinUI`, `MSI`, `WiX`, and `Event Viewer`; SteamOS text to mention `qlinkd`, `qlinkctl status`, `qlinkctl doctor`, `systemd`, `dry-run planning`, `--activate-network`, `qlink0`, `nftables`, `Steam-safe traffic`, `game profile`, and `Deck`.

- [x] **Step 2: Run a source-level red check**

Run a temporary Swift check against the current `HelpContent.swift` that calls the planned platform API and expects compilation failure before the API exists.

- [x] **Step 3: Implement platform-owned topic sets**

Add `HelpKnowledgeBase.topics(for:)`, `HelpKnowledgeBase.topic(_:for:)`, and `HelpKnowledgeBase.searchableText(for:)`. Provide macOS-only, Windows-only, SteamOS-only, and enterprise help points with OS-native terms.

- [x] **Step 4: Run Swift build and source-level green check**

Run `swift build --package-path macos` plus the temporary Swift platform-language check.

### Task 2: Filter macOS Help to macOS by Default

**Files:**
- Modify: `macos/Sources/QuantumLinkApp/QuantumLinkApp.swift`

- [x] **Step 1: Update the Help panel default**

Set `selectedPlatform` to `.macOS`, change the picker from `All` to `macOS`, `Windows`, `SteamOS`, `Enterprise`, and render `HelpKnowledgeBase.topics(for:)` instead of the global generic list.

- [x] **Step 2: Build**

Run `swift build --package-path macos`.

### Task 3: Replace Windows Help Strings With Windows-Native Copy

**Files:**
- Modify: `windows/ui/QuantumLink.Windows/ViewModels/DashboardViewModel.cs`
- Modify: `windows/ui/QuantumLink.Windows/README.md`

- [x] **Step 1: Tighten Windows strings**

Make the WinUI dashboard help/onboarding strings explicitly reference the Windows service, Wintun, WFP kill switch, DPAPI, named-pipe IPC, MSI/WiX, Event Viewer, and admin privilege boundaries.

- [x] **Step 2: Validate locally where macOS permits**

Run `dotnet build windows/ui/QuantumLink.Windows/QuantumLink.Windows.csproj -c Release -p:EnableWindowsTargeting=true` and record the expected Windows-only `XamlCompiler.exe` boundary if it persists.

### Task 4: Keep SteamOS Help in `qlinkctl` Language

**Files:**
- Modify: `steam/steamos/rust/qlinkctl/src/lib.rs`
- Modify: `steam/steamos/README.md`

- [x] **Step 1: Tighten guide copy**

Ensure `qlinkctl guide` describes `qlinkd`, `qlinkctl status`, `qlinkctl doctor`, `systemd`, dry-run planning, explicit `--activate-network`, `qlink0`, nftables, Steam-safe bypass, game profiles, Deck validation, and pre-production gates.

- [x] **Step 2: Run Rust checks**

Run `cargo fmt -p qlinkctl --check` and `cargo test -p qlinkctl`.

### Task 5: Verify, Commit, and Push

**Files:**
- All files above.

- [x] **Step 1: Run final checks**

Run `swift build --package-path macos`, `cargo fmt -p qlinkctl --check`, `cargo test -p qlinkctl`, `git diff --check`, and `git status --short`.

- [x] **Step 2: Commit**

Commit the plan and implementation with `git commit -m "feat: specialize platform help content"`.

- [x] **Step 3: Push**

Push `codex/cross-platform-ux-integration` to `origin`.
