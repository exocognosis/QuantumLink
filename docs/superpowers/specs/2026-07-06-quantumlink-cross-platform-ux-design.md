# QuantumLink Cross-Platform UX Design

Date: 2026-07-06

## Brief

Build a coherent frontend UX across QuantumLink for macOS, Windows, and SteamOS/Steam using the product-wide `product.md` as the source of truth. The experience should be attractive, informative, and interactive, with grouped controls for the actual backend surfaces: connection lifecycle, deployment mode, identity and trust, routes and DNS, peers and invites, diagnostics, support export, and platform release gates.

The visual direction should extend the current macOS app screenshots: dark-first native dashboard, left navigation, dense operational cards, clear iconography, compact controls, privacy-preserving redaction, and direct status readouts. It should not become a marketing landing page.

Interactivity target: full working controls wherever a platform backend already exposes a command or status contract; disabled, explained controls only where the backend is intentionally missing or production-gated.

## Goals

- Give macOS, Windows, and SteamOS users the same mental model: onboard, establish identity, connect, inspect route/path state, manage peers, diagnose, and get help.
- Preserve native platform expectations: SwiftUI on macOS, WinUI 3 on Windows, and SteamOS-friendly controller/terminal-first flow backed by `qlinkd` and `qlinkctl`.
- Make product truth visible. macOS is an implemented baseline, Windows is alpha, and SteamOS remains pre-production until its readiness ledger gates pass.
- Rebuild the robust macOS help experience in checked-in source and keep it current with the product-wide spec.
- Keep sensitive details redacted by default, especially peer endpoints, wallet addresses, routes, DNS details, and raw diagnostics.

## Non-Goals

- Do not redesign the Rust transport, packet pump, cryptography, Dytallix registry, Wintun/WFP service, or SteamOS nftables/TUN internals as part of the UX pass.
- Do not promise production readiness from local builds, unsigned packages, CI artifacts, or dry-run daemon states.
- Do not introduce a web frontend unless a later implementation plan explicitly scopes it. No `package.json` or web app exists in the current platform source.
- Do not copy stale help copy from the installed app verbatim. Binary strings are reference material only; checked-in help must match current product and security docs.

## Platform Baseline

### macOS

The macOS app is a SwiftUI dashboard in `macos/Sources/QuantumLinkApp/QuantumLinkApp.swift`. It already has the strongest UI foundation: sidebar navigation, onboarding, connection panels, Dytallix enrollment state, route/security/diagnostics panels, and native styling. The UX work should split large view code into focused source files only where it makes the implementation easier to test and maintain.

The robust standalone help window exists in `/Users/rickglenn/Applications/QuantumLink.app` as compiled SwiftUI content, not as checked-in source. It exposes useful topics, but at least some copy is stale against current `product.md`; for example, the current product spec rejects the legacy hybrid X25519/ML-KEM suite.

### Windows

Windows UI lives in `windows/ui/QuantumLink.Windows`. It is a C# WinUI 3 dashboard that talks to the privileged service through `\\.\pipe\QuantumLinkService`. It currently covers connect/disconnect, phase, path, overlay address, protected routes, kill-switch state, peer list, and diagnostics export. It needs macOS-parity information architecture, onboarding, grouped settings, identity/trust display, and help.

The Windows UI must remain unprivileged. It may call service IPC commands, display service status, and export diagnostics, but it must not perform admin network operations directly.

### SteamOS / Steam

SteamOS is a Linux daemon and CLI surface under `steam/steamos`: `qlinkd`, `qlinkctl`, systemd, Linux route/nftables planning, game profiles, and install scripts. There is no native GUI yet. The UX pass should create a SteamOS operator surface that can work in two layers:

- A robust `qlinkctl` guided text UI for terminal and Deck desktop mode.
- A later graphical shell can consume the same help and status model, but the first implementation should not invent a full GUI without a backend/runtime choice.

SteamOS must distinguish "local TUN packet I/O initialized" from "live authenticated peer transport ready." Dry-run planning, activated network mode, and production-readiness blockers must be explicit.

## Information Architecture

Each platform should expose the same top-level groups, adapted to native conventions:

- **Onboarding**: install/start components, select platform/deployment defaults, set mesh trust policy, configure Dytallix identity mode, import or create peer credentials, verify tunnel/service identity, run first connection readiness checks.
- **Home / Connect**: connection launcher, connect/disconnect/retry, current phase, direct versus relay path, route mode, DNS mode, protected route count, peer count, and prominent platform readiness badge.
- **Connections / Profiles**: reusable profiles for SSH, game, custom protected prefix, direct peer, relay fallback, and local VPN modes where supported.
- **Identity / Trust**: Dytallix mode (`Off`, `Verified`, `Public Wallet`), mesh trust policy, registry endpoint/contract, current registry status, last verification, hidden versus published wallet state, rejection reasons.
- **Network**: path type, candidate or relay status in redacted form, peer mix, RTT/loss when available, traffic counters, last path probe, TUN/adapter/interface state.
- **Peers / Invites**: peer list, invite import/export, peer trust inspection, remove/revoke/quarantine actions where backend support exists.
- **Routes / DNS / Policy**: route mode, protected prefixes, excluded routes, DNS mode, kill switch/fail-closed policy, per-app or game-aware policy where the platform supports it.
- **Security**: PQC suite, key storage boundary, replay drops, rekey thresholds, Dytallix trust policy, packet-frame protection state.
- **Diagnostics**: status/doctor, support bundle export, redaction level, recent errors, service/tunnel logs, readiness ledger links, elevated raw export guardrails.
- **Help**: searchable topic list, contextual help entry points from each screen, troubleshooting, support-ticket flow, and platform-specific limitations.

## Onboarding Flow

Onboarding should be a checklist with platform-specific steps but common semantics:

1. Detect platform runtime status:
   - macOS: app, tunnel provider availability, profile state, local config.
   - Windows: service pipe availability, service state, Wintun/WFP readiness as reported by service.
   - SteamOS: `qlinkd` socket availability, dry-run versus activated mode, systemd unit state.
2. Choose deployment type:
   - Mesh, Direct, Local VPN on macOS where currently modeled.
   - Windows equivalent modes mapped to service configuration support.
   - SteamOS game/party profile and dry-run/activated network mode.
3. Choose mesh trust policy:
   - Public requires Dytallix `Verified` or `Public Wallet`.
   - Private warns when registry is unavailable.
   - Development may use `Off`.
4. Configure or verify identity:
   - Device identity, Dytallix wallet/registry state, and peer record freshness are separate states.
   - The UI must never imply wallet publication unless `Public Wallet` is selected.
5. Add or import peers:
   - Invite import where available.
   - Manual peer details only if the platform already supports it.
6. Validate route and DNS policy:
   - Protected route and DNS summaries must be visible before first connect.
   - SteamOS must show Steam/store/account bypass expectations.
7. Start first connection or first diagnostic:
   - If a platform cannot start a live connection yet, the button must route to the strongest supported validation command and label the missing gate.

## Help And Knowledge Base

Help should be checked into source as structured content instead of hard-coded binary-only UI. Initial topics:

- Getting Started
- Connecting Peers
- Activity & Diagnostics
- Cryptography
- Routing & Profiles
- Dytallix Identity & Trust
- MDM & Enterprise
- SteamOS Game Routing
- Privacy & Security
- Troubleshooting
- Submit a Support Ticket

Each topic should support:

- Title, symbol/icon, short subtitle, applicable platforms, body sections, related actions, and troubleshooting questions.
- Contextual deep links from matching app screens.
- Product-version caveats so platform maturity and unsupported actions remain honest.
- Redacted diagnostic attachment guidance.

The support-ticket flow should offer categories: Bug Report, Feature Request, Connection / Tunnel Issue, Security Concern, Billing / Entitlement, and Other. In development builds, the final action should either open a prefilled mail draft to `help@quantumlinkvpn.com` or produce copyable ticket text when mail cannot open. Security reports should direct users to `SECURITY.md`.

## Data And Control Flow

The UX layer should use platform contracts that already exist:

- macOS reads `TunnelStatus`, `TunnelConfiguration`, Dytallix enrollment state, and controller actions through `QuantumLinkKit`.
- Windows reads mirrored IPC models from `windows/ui/QuantumLink.Windows/Models/IpcModels.cs` and sends allowed commands through `ServicePipeClient`.
- SteamOS reads daemon status/config/invite models from `qlink-proto` and uses `qlinkctl` commands against `/run/quantumlink/qlinkd.sock`.

Where the UI needs a status field that a backend does not expose yet, the implementation plan should add the smallest contract change first with a failing contract test. It should not fake backend readiness in UI-only state.

## Error Handling

- Service unavailable: show exact platform runtime dependency and the first recovery action.
- Registry unavailable: follow mesh trust policy. Public meshes fail closed; private meshes warn; development meshes can continue.
- Unsupported action: disable the control and show the blocker, not a generic error.
- Diagnostics export failure: show the failed path/command and offer copyable status text.
- Mail/support flow failure: show `help@quantumlinkvpn.com` and the generated ticket body for manual sending.
- SteamOS dry-run state: show "planning only" and the command required for explicit activated mode.

## Visual System

Use the existing macOS dashboard screenshots as the source visual language:

- Dark-first, high-contrast native dashboard with restrained accent blue and green status states.
- Left navigation grouped as Overview, Network, and Manage.
- Dense but readable operational cards with compact headings, icons, segmented controls, toggles, menus, and primary action buttons.
- No nested cards, decorative gradients, or marketing hero sections.
- Button and label text must fit at compact window sizes. Long technical strings should wrap, redact, or use monospaced copyable rows.
- Use native icon systems: SF Symbols on macOS, Segoe Fluent icons or equivalent WinUI symbols on Windows, and text/icon-safe terminal markers for SteamOS CLI.

## Testing Strategy

Implementation should be test-first where behavior changes are needed:

- macOS: add Swift tests for help content model, onboarding checklist derivation, identity-mode guardrails, and support-ticket body generation before adding production code.
- Windows: add view-model tests if a test project is introduced; otherwise start with service/IPC contract tests for new status fields and build validation for XAML bindings.
- SteamOS: add Rust tests for formatted onboarding/help/doctor output and any new daemon status fields before changing `qlinkctl` output.
- Cross-platform docs: add a lightweight manifest test or script that checks the help topic IDs and platform labels are present.

Verification should include formatting, targeted platform tests, and at least one rendered/manual UI smoke per native platform where the host supports it. If a host cannot run Windows or SteamOS GUI checks, report that limitation explicitly.

## Implementation Boundaries

Recommended worker ownership:

- macOS UI worker owns `macos/Sources/QuantumLinkApp/**` and app resources.
- macOS control worker owns `macos/Sources/QuantumLinkKit/**` only for status/help adapters required by the UI.
- Windows UI worker owns `windows/ui/QuantumLink.Windows/**`.
- Windows IPC/service worker owns `windows/rust/quantumlink-proto/**` and `windows/rust/quantumlink-service/**` only for needed status/command contract changes.
- SteamOS CLI/control worker owns `steam/steamos/rust/qlinkctl/**`, `steam/steamos/rust/qlink-proto/**`, and tests for guided status/help output.
- Shared docs/content worker owns `docs/**`, `SUPPORT.md`, and any shared help-content source generated from product truth.

Do not edit unrelated release, packaging, or transport internals unless a failing UI/backend contract test proves the change is needed.

## Approval State

The user approved the integration-worktree approach on 2026-07-06. The next step is a detailed implementation plan saved under `docs/superpowers/plans/`, then execution with subagents across disjoint platform file sets.
