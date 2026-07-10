# QuantumLink Cross-Platform UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a coherent, source-backed UX/help/onboarding layer across the macOS SwiftUI app, Windows WinUI app, and SteamOS `qlinkctl` operator surface.

**Architecture:** Put shared help and onboarding truth in tested platform-neutral models where possible, then consume it from native shells. macOS gets a checked-in help content model and in-app help panel. Windows gets a richer WinUI dashboard layout with platform readiness, onboarding, identity, policy, diagnostics, and help sections. SteamOS gets a guided CLI output that explains daemon mode, readiness, peer/invite flows, and production gates without pretending a GUI exists.

**Tech Stack:** Swift 5.9 / SwiftUI / XCTest, C# WinUI 3 / CommunityToolkit MVVM, Rust 2021 / cargo tests, Markdown docs.

---

## File Structure

- Create `macos/Sources/QuantumLinkKit/HelpContent.swift`: typed help-topic and onboarding content used by the macOS app and tests.
- Create `macos/Tests/QuantumLinkKitTests/HelpContentTests.swift`: regression tests for topic coverage, stale crypto copy, support categories, and platform labels.
- Modify `macos/Sources/QuantumLinkApp/QuantumLinkApp.swift`: add Help sidebar item and help panel wired to `QuantumLinkKit.HelpKnowledgeBase`.
- Modify `windows/ui/QuantumLink.Windows/ViewModels/DashboardViewModel.cs`: add display properties for platform badge, readiness summary, onboarding checklist, identity summary, policy summary, diagnostics summary, and help topics.
- Modify `windows/ui/QuantumLink.Windows/MainWindow.xaml`: replace the sparse single-page grid with grouped cards/sections while still binding only to the unprivileged view model.
- Modify `windows/ui/QuantumLink.Windows/README.md`: document the expanded UX surface and remaining alpha gates.
- Modify `steam/steamos/rust/qlinkctl/src/lib.rs`: add `format_guide()` and tests for the SteamOS guided UX.
- Modify `steam/steamos/rust/qlinkctl/src/main.rs`: add `qlinkctl guide`.
- Modify `steam/steamos/README.md`: document the guided CLI entry point.
- Modify `docs/superpowers/specs/2026-07-06-quantumlink-cross-platform-ux-design.md` only if implementation uncovers a necessary correction.

## Task 1: Tested macOS Help Content Model

**Files:**
- Create: `macos/Sources/QuantumLinkKit/HelpContent.swift`
- Create: `macos/Tests/QuantumLinkKitTests/HelpContentTests.swift`

- [ ] **Step 1: Write failing help content tests**

Create `macos/Tests/QuantumLinkKitTests/HelpContentTests.swift`:

```swift
import XCTest
@testable import QuantumLinkKit

final class HelpContentTests: XCTestCase {
    func testKnowledgeBaseIncludesRequiredTopicsInOrder() {
        XCTAssertEqual(
            HelpKnowledgeBase.topics.map(\.id),
            [
                .gettingStarted,
                .connectingPeers,
                .activityDiagnostics,
                .cryptography,
                .routingProfiles,
                .dytallixIdentityTrust,
                .mdmEnterprise,
                .steamOSGameRouting,
                .privacySecurity,
                .troubleshooting,
                .supportTicket
            ]
        )
    }

    func testCryptographyTopicDoesNotMentionLegacyHybridFallback() throws {
        let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.cryptography))
        let text = topic.searchableText.lowercased()
        XCTAssertFalse(text.contains("x25519"))
        XCTAssertFalse(text.contains("hybrid"))
        XCTAssertTrue(text.contains("ml-kem"))
        XCTAssertTrue(text.contains("ml-dsa"))
    }

    func testSupportTicketCategoriesAreExplicitAndSecurityRoutesToSecurityPolicy() throws {
        let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.supportTicket))
        XCTAssertTrue(topic.searchableText.contains("Bug Report"))
        XCTAssertTrue(topic.searchableText.contains("Feature Request"))
        XCTAssertTrue(topic.searchableText.contains("Connection / Tunnel Issue"))
        XCTAssertTrue(topic.searchableText.contains("Security Concern"))
        XCTAssertTrue(topic.searchableText.contains("Billing / Entitlement"))
        XCTAssertTrue(topic.searchableText.contains("SECURITY.md"))
    }

    func testSteamOSHelpLabelsPreProductionState() throws {
        let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.steamOSGameRouting))
        XCTAssertTrue(topic.platforms.contains(.steamOS))
        XCTAssertTrue(topic.searchableText.contains("pre-production"))
        XCTAssertTrue(topic.searchableText.contains("qlinkd"))
        XCTAssertTrue(topic.searchableText.contains("qlinkctl"))
    }
}
```

- [ ] **Step 2: Run the test and confirm it fails because the model is missing**

Run:

```bash
swift test --package-path macos --filter HelpContentTests
```

Expected: compile failure naming `HelpKnowledgeBase` or `HelpTopicID` as missing.

- [ ] **Step 3: Implement the minimal help content model**

Create `macos/Sources/QuantumLinkKit/HelpContent.swift` with public `HelpTopicID`, `HelpPlatform`, `HelpSection`, `HelpTopic`, and `HelpKnowledgeBase` types. Include all topics asserted in the test. The cryptography topic must describe ML-KEM, ML-DSA, SLH-DSA, and the fact that the legacy hybrid identifier is rejected without using the exact strings `X25519` or `hybrid` in the topic body.

- [ ] **Step 4: Run the focused tests**

Run:

```bash
swift test --package-path macos --filter HelpContentTests
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add macos/Sources/QuantumLinkKit/HelpContent.swift macos/Tests/QuantumLinkKitTests/HelpContentTests.swift
git commit -m "feat: add tested QuantumLink help knowledge base"
```

## Task 2: macOS In-App Help Panel

**Files:**
- Modify: `macos/Sources/QuantumLinkApp/QuantumLinkApp.swift`

- [ ] **Step 1: Add a Help sidebar case**

Add `.help` to `SidebarTab`, return title `"Help"` and symbol `"questionmark.circle"`. Include `SidebarItem(tab: .help)` in the Manage section after Configuration.

- [ ] **Step 2: Route the help tab**

In `DashboardDetailView.body`, add:

```swift
case .help:
  HelpPanel()
```

- [ ] **Step 3: Implement `HelpPanel` and helper views**

Add `HelpPanel`, `HelpTopicRow`, and `HelpSectionView` near the other panel views. Use `HelpKnowledgeBase.topics`, `PanelChrome`, `PanelHeader`, `PanelGrid`, and `ConfigurationCard`. The panel must show a topic list, platform chips, topic sections, and the support email fallback text from the support topic.

- [ ] **Step 4: Build the macOS package**

Run:

```bash
swift build --package-path macos
```

Expected: build succeeds. If SwiftPM reports the existing asset-catalog warning, record it as pre-existing and continue if exit code is 0.

- [ ] **Step 5: Run related tests**

Run:

```bash
swift test --package-path macos --filter HelpContentTests
swift test --package-path macos --filter DiscoveryIdentityPresentationTests
```

Expected: both filters pass.

- [ ] **Step 6: Commit**

```bash
git add macos/Sources/QuantumLinkApp/QuantumLinkApp.swift
git commit -m "feat: surface QuantumLink help in macOS app"
```

## Task 3: Windows Dashboard Parity Shell

**Files:**
- Modify: `windows/ui/QuantumLink.Windows/ViewModels/DashboardViewModel.cs`
- Modify: `windows/ui/QuantumLink.Windows/MainWindow.xaml`
- Modify: `windows/ui/QuantumLink.Windows/README.md`

- [ ] **Step 1: Add view-model display collections**

In `DashboardViewModel.cs`, add read-only collections for onboarding items and help topics:

```csharp
public ObservableCollection<string> OnboardingItems { get; } = [
    "Service pipe reachable",
    "Connect through the LocalSystem tunnel service",
    "Verify Wintun/WFP route policy from service status",
    "Export redacted diagnostics before sharing logs"
];

public ObservableCollection<string> HelpTopics { get; } = [
    "Getting Started",
    "Connecting Peers",
    "Activity & Diagnostics",
    "Cryptography",
    "Routing & Profiles",
    "Dytallix Identity & Trust",
    "Privacy & Security",
    "Troubleshooting"
];
```

Also add string properties:

```csharp
public string PlatformBadge => "Windows alpha";
public string ReadinessSummary => "WinUI dashboard with privileged Rust service; production signing and full Windows validation remain gated.";
public string IdentitySummary => "Dytallix identity follows shared qlink-core policy; wallet addresses stay hidden unless Public Wallet mode is explicitly selected.";
public string PolicySummary => "Routes, DNS, Wintun, and WFP kill-switch state are owned by the service, not this unprivileged UI.";
public string HelpSummary => "Use support exports with redaction enabled. Security reports should follow SECURITY.md.";
```

- [ ] **Step 2: Replace the sparse XAML layout with grouped sections**

In `MainWindow.xaml`, keep the root `Window` and `x:Bind ViewModel` bindings, but reshape the body into a `ScrollViewer` with grouped `Border` cards for:

- Header with `PlatformBadge`, phase, Connect, Disconnect.
- Onboarding checklist bound to `OnboardingItems`.
- Connection status grid bound to existing phase/path/overlay/routes/kill-switch/service fields.
- Identity and policy summaries bound to the new read-only properties.
- Peers list using the existing `Peers` binding.
- Diagnostics export and diagnostics text.
- Help topics bound to `HelpTopics`.

Use WinUI system brushes and keep all operations unprivileged.

- [ ] **Step 3: Update the Windows UI README**

Update `windows/ui/QuantumLink.Windows/README.md` so checked items include onboarding checklist, platform readiness badge, grouped diagnostics, identity/policy summaries, and help topics. Keep configuration editor and live status push marked pending if they remain pending.

- [ ] **Step 4: Build the Windows UI if the host supports .NET**

Run:

```bash
dotnet build windows/ui/QuantumLink.Windows/QuantumLink.Windows.csproj -c Release
```

Expected: build succeeds on a host with the required Windows SDK/App SDK workload. If this non-Windows host cannot build WinUI, capture the exact SDK/workload error and run `git diff --check` for the Windows files.

- [ ] **Step 5: Commit**

```bash
git add windows/ui/QuantumLink.Windows/ViewModels/DashboardViewModel.cs windows/ui/QuantumLink.Windows/MainWindow.xaml windows/ui/QuantumLink.Windows/README.md
git commit -m "feat: expand Windows dashboard UX shell"
```

## Task 4: SteamOS Guided CLI UX

**Files:**
- Modify: `steam/steamos/rust/qlinkctl/src/lib.rs`
- Modify: `steam/steamos/rust/qlinkctl/src/main.rs`
- Modify: `steam/steamos/README.md`

- [ ] **Step 1: Write failing guide-format tests**

Add tests to the existing test module in `steam/steamos/rust/qlinkctl/src/lib.rs`:

```rust
#[test]
fn format_guide_explains_steamos_modes_and_gates() {
    let guide = format_guide();
    assert!(guide.contains("QuantumLink SteamOS Guide"));
    assert!(guide.contains("dry-run planning"));
    assert!(guide.contains("--activate-network"));
    assert!(guide.contains("transport ready"));
    assert!(guide.contains("pre-production"));
}

#[test]
fn format_guide_lists_operator_command_groups() {
    let guide = format_guide();
    assert!(guide.contains("qlinkctl status"));
    assert!(guide.contains("qlinkctl doctor"));
    assert!(guide.contains("qlinkctl invite import"));
    assert!(guide.contains("qlinkctl peer trust"));
    assert!(guide.contains("qlinkctl support-bundle --output"));
}
```

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run:

```bash
cargo test -p qlinkctl format_guide
```

Expected: compile failure for missing `format_guide`.

- [ ] **Step 3: Implement `format_guide()`**

Add `pub fn format_guide() -> String` in `qlinkctl/src/lib.rs`. It should return a multi-section text guide with: onboarding, runtime modes, peer/invite commands, diagnostics/support, Steam-safe routing note, and production gates.

- [ ] **Step 4: Wire the `guide` command**

In `qlinkctl/src/main.rs`, import `format_guide`, add `Some("guide") => println!("{}", format_guide()),`, and update usage to:

```text
usage: qlinkctl <guide|status|doctor|support-bundle --output|invite|peer>
```

- [ ] **Step 5: Update SteamOS README**

Add `qlinkctl guide` to Quick Start after `sudo qlinkctl status`, and state that it is the first operator-facing guided UX until a native SteamOS UI exists.

- [ ] **Step 6: Run SteamOS CLI tests**

Run:

```bash
cargo test -p qlinkctl format_guide
cargo test -p qlinkctl
```

Expected: tests pass.

- [ ] **Step 7: Commit**

```bash
git add steam/steamos/rust/qlinkctl/src/lib.rs steam/steamos/rust/qlinkctl/src/main.rs steam/steamos/README.md
git commit -m "feat: add SteamOS guided CLI UX"
```

## Task 5: Cross-Platform Verification And Docs

**Files:**
- Modify only if needed: `docs/superpowers/specs/2026-07-06-quantumlink-cross-platform-ux-design.md`

- [ ] **Step 1: Run whitespace verification**

Run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 2: Run macOS help tests**

Run:

```bash
swift test --package-path macos --filter HelpContentTests
```

Expected: tests pass.

- [ ] **Step 3: Run SteamOS CLI tests**

Run:

```bash
cargo test -p qlinkctl format_guide
```

Expected: tests pass.

- [ ] **Step 4: Attempt Windows build**

Run:

```bash
dotnet build windows/ui/QuantumLink.Windows/QuantumLink.Windows.csproj -c Release
```

Expected: pass on a configured Windows/.NET host. On this host, if WinUI workloads are unavailable, record the exact failure in the final status and do not claim Windows build verification.

- [ ] **Step 5: Final status commit if docs changed**

If the spec needed correction, commit it:

```bash
git add docs/superpowers/specs/2026-07-06-quantumlink-cross-platform-ux-design.md
git commit -m "docs: align UX design with implementation"
```

If no docs changed, do not create an empty commit.
