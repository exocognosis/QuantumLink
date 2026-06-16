# Windows Full Buildout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Windows alpha scaffold into a signed, installable, beta-validated, fully functional Windows edition of QuantumLink.

**Architecture:** The Windows product remains a two-process system: an unprivileged WinUI 3 app talks over local named-pipe IPC to a LocalSystem Rust service. The service owns Wintun, WFP, route/DNS state, DPAPI secrets, packet pumping, qlink-core transport, diagnostics, and lifecycle cleanup. Release automation produces the MSI, while beta validation proves the privileged networking path on real Windows hosts.

**Tech Stack:** Rust 2021, qlink-core, Windows Service Control Manager, Wintun, Windows Filtering Platform, DPAPI, IP Helper APIs, C# WinUI 3, WiX v4, Authenticode, GitHub Actions.

---

## Workstream Order

1. Windows release pipeline and MSI packaging.
2. Installer install/upgrade/uninstall validation.
3. Service hardening for WFP, routes/DNS, pipe ACLs, and lifecycle recovery.
4. IPC expansion for peer and configuration management.
5. WinUI product workflows.
6. Beta validation matrix and evidence capture.
7. Production readiness: signing, SBOM, threat model, release notes, rollback.

## Task 1: Windows Release Pipeline

Status update 2026-06-16: the Windows release workflow, build script,
release-input docs, Wintun provenance checks, signing gate, artifact staging,
and local verification contracts are implemented. Tag releases still require
Authenticode signing, and release publication still requires external/manual
validation evidence before publication.

**Files:**
- Create: `.github/workflows/windows-release.yml`
- Modify: `windows/scripts/build-windows.ps1`
- Modify: `windows/installer/README.md`
- Modify: `windows/docs/beta-runbook-windows.md`
- Modify: `windows/version.md`

- [x] **Step 1: Add workflow-dispatch and tag release workflow**

Create `.github/workflows/windows-release.yml` with a Windows job that checks out the repo, installs Rust and .NET 8, runs the Windows Rust checks, publishes the WinUI app, downloads Wintun from pinned `WINTUN_DOWNLOAD_URL` and `WINTUN_SHA256` repository variables, verifies the archive before extraction, retains the upstream Wintun license, invokes `windows/scripts/build-windows.ps1 -Msi`, signs when signing secrets are present, computes SHA256 sums, uploads artifacts, and attaches tag artifacts to GitHub Releases only when signing is configured and succeeds.

Run:

```bash
gh workflow view windows-release.yml --repo exocognosis/QuantumLink
```

Expected: before merge this may fail if the workflow is not on the default branch; local YAML parsing should still succeed through `ruby -e 'require "yaml"; YAML.load_file(".github/workflows/windows-release.yml")'` or an equivalent parser.

- [x] **Step 2: Make the packaging script release-friendly**

Modify `windows/scripts/build-windows.ps1` to accept:

```powershell
param(
    [switch]$Msi,
    [switch]$SkipTests,
    [string]$MsiOutputPath,
    [string]$WintunDllPath
)
```

Keep the local default behavior unchanged. When `-SkipTests` is set, skip only `cargo test` and `quantumlink-service smoke`, not the release build or UI publish. When `-Msi` is set, resolve the Wintun DLL from `-WintunDllPath` or `windows\wintun\bin\amd64\wintun.dll`, copy it into the Rust release target, build the MSI, create the output directory if needed, and print the absolute MSI path.

Run:

```powershell
pwsh -NoProfile -Command "[scriptblock]::Create((Get-Content -Raw 'windows/scripts/build-windows.ps1')) | Out-Null"
```

Expected: command exits 0 on hosts with PowerShell.

- [x] **Step 3: Document release inputs and validation gates**

Update Windows installer and beta docs to distinguish:

- CI-proven gates: Rust check, Rust tests, smoke, WinUI build, MSI build.
- Release gates: Authenticode signing, checksums, Wintun provenance, clean install, upgrade, uninstall, SmartScreen publisher display.
- Manual beta gates: leak tests, service crash behavior, sleep/resume, network churn, two-Windows-machine mesh, Windows-to-macOS interop.

Run:

```bash
rg -n "Windows release|Authenticode|SmartScreen|Wintun|SHA256" windows/installer/README.md windows/docs/beta-runbook-windows.md windows/version.md
```

Expected: each release requirement appears in the docs.

- [x] **Step 4: Verify the first workstream**

Run:

```bash
cargo test --workspace --quiet
cargo run -p quantumlink-service --quiet -- smoke
git diff --check
```

Expected: all commands exit 0. On non-Windows hosts, do not claim MSI, WinUI, or Authenticode validation; those are validated by GitHub Actions or a Windows build host.

## Task 2: Installer Lifecycle Validation

Status update 2026-06-16: `windows/scripts/validate-install.ps1` exists with
install, service, state directory, UI binary, network snapshot, cleanup, and
JSON report evidence checks. The release workflow has an explicit manual
`run_install_validation` gate that uploads
`windows/build/validation/install-validation-report.json`. `-SkipNetworkChecks`
only waives adapter, route, and WFP evidence on constrained runners; clean
Windows 10/11 VM, physical-host, leak-test, two-machine, and macOS interop
validation remain manual beta gates.

**Files:**
- Create: `windows/scripts/validate-install.ps1`
- Create: `windows/scripts/validate_install_contract_test.rb`
- Create: `windows/scripts/windows_release_workflow_contract_test.rb`
- Modify: `.github/workflows/windows-release.yml`
- Modify: `windows/docs/beta-runbook-windows.md`
- Modify: `windows/installer/README.md`

- [x] **Step 1: Add install validation script**

Create a PowerShell script that accepts an MSI path, installs it silently, checks `QuantumLinkService`, verifies `C:\ProgramData\QuantumLink`, confirms the UI binary exists, uninstalls the product, and verifies the service is removed.

- [x] **Step 2: Add cleanup checks**

Extend the script to check routes, adapter presence, and WFP sublayer state before and after uninstall.

- [x] **Step 3: Record validation evidence**

Emit a JSON report containing host OS, MSI SHA256, install result, service status, state directory ACL result, uninstall result, and residual-state findings.

- [x] **Step 4: Wire manual release workflow validation**

Add `workflow_dispatch` inputs for `run_install_validation` and
`skip_validation_network_checks`, run `.\windows\scripts\validate-install.ps1`
against `.\windows\QuantumLink.msi`, write
`.\windows\build\validation\install-validation-report.json`, and upload that
report as `QuantumLink-Windows-InstallValidation-<run-number>` with `always()`
when the manual validation gate is enabled.

## Task 3: Service Hardening

**Files:**
- Modify: `windows/rust/quantumlink-service/src/win/wfp.rs`
- Modify: `windows/rust/quantumlink-service/src/win/routes.rs`
- Modify: `windows/rust/quantumlink-service/src/win/pipe_server.rs`
- Modify: `windows/rust/quantumlink-service/src/win/platform.rs`
- Test: `windows/rust/quantumlink-service/src/win/*`

- [ ] **Step 1: Add configurable named-pipe ACL support**

Implement a Windows-only helper that creates the pipe with explicit SDDL, defaulting to local interactive users for consumer builds and allowing an enterprise group override from ProgramData config.

- [ ] **Step 2: Add strict-mode persistent WFP option**

Add persistent WFP filter creation for strict deployments and keep dynamic filters for fail-closed consumer mode. Add tests for filter plan construction on non-Windows hosts and integration validation on Windows.

- [ ] **Step 3: Replace netsh route/DNS calls incrementally**

Introduce an IP Helper route/DNS implementation behind a trait. Keep the current `netsh` implementation as a fallback until Windows beta evidence proves parity.

## Task 4: IPC Peer And Configuration Management

**Files:**
- Modify: `windows/rust/quantumlink-proto/src/ipc.rs`
- Modify: `windows/rust/quantumlink-proto/src/models.rs`
- Modify: `windows/rust/quantumlink-service/src/ipc.rs`
- Modify: `windows/rust/quantumlink-service/src/engine.rs`
- Modify: `windows/ui/QuantumLink.Windows/Models/IpcModels.cs`
- Modify: `windows/ui/QuantumLink.Windows/Services/ServicePipeClient.cs`

- [ ] **Step 1: Add peer-management IPC commands**

Add `addPeer`, `removePeer`, and `listPeers` requests with schema-version tests in Rust and matching C# models.

- [ ] **Step 2: Add import/export configuration IPC commands**

Add `importConfiguration` and `exportConfiguration` commands that round-trip `TunnelConfiguration` and reject invalid protected routes before persistence.

- [ ] **Step 3: Add unsolicited status pushes**

Emit `id: 0` status updates from the service when phase, peer status, path type, or last error changes. Keep polling as a fallback.

## Task 5: WinUI Product Workflows

**Files:**
- Modify: `windows/ui/QuantumLink.Windows/MainWindow.xaml`
- Modify: `windows/ui/QuantumLink.Windows/ViewModels/DashboardViewModel.cs`
- Modify: `windows/ui/QuantumLink.Windows/Services/ServicePipeClient.cs`
- Create: `windows/ui/QuantumLink.Windows/ViewModels/*`
- Create: `windows/ui/QuantumLink.Windows/Views/*`

- [ ] **Step 1: Split the dashboard into views**

Create separate view models and views for dashboard, peers, settings, diagnostics, and first-run setup.

- [ ] **Step 2: Add peer and config UI**

Expose add/remove peer, import/export config, route mode, DNS mode, and kill-switch mode through UI flows backed by IPC.

- [ ] **Step 3: Add tray and notification behavior**

Add system tray status, foreground reconnect/disconnect notifications, and actionable service-unavailable messaging.

## Task 6: Beta Validation Matrix

**Files:**
- Create: `windows/docs/validation-reports/README.md`
- Create: `windows/scripts/run-beta-validation.ps1`
- Modify: `windows/docs/beta-runbook-windows.md`

- [ ] **Step 1: Turn runbook checks into executable probes where possible**

Automate service status, route table, adapter, WFP, state directory ACL, diagnostics redaction, and uninstall residue checks.

- [ ] **Step 2: Define manual evidence captures**

Document Wireshark capture requirements, protected-prefix leak-test setup, two-machine mesh setup, relay-fallback setup, and macOS interop setup.

- [ ] **Step 3: Require validation reports for release candidates**

Add a release checklist gate that links every Windows release candidate to validation evidence from Windows 10, Windows 11, and physical hardware.

## Task 7: Production Readiness

**Files:**
- Create: `windows/docs/security-threat-model.md`
- Create: `windows/docs/release-operator-checklist.md`
- Modify: `.github/workflows/windows-release.yml`
- Modify: `SECURITY.md`

- [ ] **Step 1: Write the Windows threat model**

Cover privileged service boundaries, named pipe access, WFP bypass, Wintun DLL provenance, installer upgrade, DPAPI storage, diagnostics redaction, and update delivery.

- [ ] **Step 2: Add SBOM and dependency review**

Generate a Windows artifact SBOM during release and document third-party licenses including Wintun and Rust/C# dependencies.

- [ ] **Step 3: Add rollback and release notes process**

Document rollback from signed MSI, previous-artifact retention, beta known limitations, and support-bundle requirements.
