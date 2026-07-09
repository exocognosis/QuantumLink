# Windows Beta Runbook

Windows analog of the macOS pre-Apple runbook. Run on clean Windows 10
22H2 and Windows 11 x64 VMs plus at least one physical machine.

This is a beta gate for the current Windows alpha. Passing this runbook means
the artifact is acceptable for limited beta testing only; it does not imply
production readiness.

Production release readiness is tracked separately in
`production-release-readiness.md`. Any unchecked production gate or missing
evidence link in that ledger blocks a production-candidate Windows release.

## CI coverage vs manual validation

Current CI proves:

- `cargo check --workspace --all-targets` on `windows-latest`.
- `cargo test --workspace` on `windows-latest`.
- `cargo run -p quantumlink-service -- smoke` for data-plane fail-closed
  invariants.
- Release Rust artifacts build for `quantumlink-service` and `qlink-core`.
- The WinUI 3 app builds in Release configuration.
- The manual Windows release workflow can run `validate-install.ps1` on
  `windows-latest` when `run_install_validation` is enabled, then upload
  `windows/build/validation/install-validation-report.json` as JSON evidence.
  The release workflow also runs `verify-windows-release.ps1` before artifact
  upload and writes `windows/build/release/windows-release-evidence.json`,
  binding the selected MSI, `SHA256SUMS.txt`, Wintun DLL/license evidence,
  publisher signature evidence, and any install-validation report into one
  release evidence file.
  Tag releases are not forced to run this GitHub-hosted check, but tagged
  publication still requires external/manual validation evidence before
  publication.

Manual Windows validation must still prove:

- Official signed `wintun.dll` is sourced, packaged, and licensed correctly.
- The MSI is built from the release commit, Authenticode-signed, timestamped,
  and has a published SHA-256 checksum.
- Clean install, first run, Wintun adapter creation, WFP kill-switch behavior,
  routing, service lifecycle, upgrade, uninstall, diagnostics, two-machine
  mesh, and macOS interop pass on clean Windows 10/11 VMs and physical
  Windows hardware.

## Release operator checklist

- [ ] Confirm the Windows CI workflow is green for the release commit.
- [ ] Confirm the Windows release workflow has `WINTUN_DOWNLOAD_URL` and
      `WINTUN_SHA256` repository variables pinned to the official Wintun
      archive. Do not store `wintun.dll` as a GitHub binary or base64 secret.
- [ ] Build the release service/core, WinUI app, and WiX MSI on a clean
      Windows release host.
- [ ] Source `wintun.dll` from the official signed Wintun distribution, verify
      its Authenticode signature, and include the Wintun license with the
      artifact.
- [ ] Authenticode-sign and timestamp `QuantumLink.msi`; verify the expected
      publisher is shown by `Get-AuthenticodeSignature`.
- [ ] For manual release workflow runs, set `expected_publisher_subject` and/or
      `expected_publisher_thumbprint` when the publisher identity should be
      enforced by `windows-release-evidence.json`.
- [ ] Generate and publish the MSI SHA-256 checksum.
- [ ] Collect manual install validation evidence from either the release
      workflow artifact `QuantumLink-Windows-InstallValidation-<run-number>`
      or a local `.\windows\build\validation\install-validation-report.json`
      report generated with `.\windows\scripts\validate-install.ps1`.
- [ ] Confirm `windows/build/release/windows-release-evidence.json` is present
      next to the MSI, `SHA256SUMS.txt`, and `WINTUN-LICENSE.txt`; if install
      validation ran, confirm it required and matched
      `install-validation-report.json` for the selected MSI SHA-256.
- [ ] Run every beta gate below on clean Windows 10 22H2 and Windows 11 x64
      VMs plus at least one physical x64 Windows machine.
- [ ] Block beta publication for any signing, checksum, install, Wintun, WFP,
      leak-test, service lifecycle, upgrade, uninstall, or diagnostics failure.

## 0. Build verification

- [ ] `cargo test --workspace` passes on the Windows host.
- [ ] `cargo run -p quantumlink-service -- smoke` exits 0 and reports
      `passed: true` (pump fail-closed invariants).
- [ ] Release automation downloads the pinned Wintun archive, verifies the
      archive SHA-256 checksum before extraction, and stages
      `bin/amd64/wintun.dll`.
- [ ] MSI builds from the release commit and includes the sourced
      `wintun.dll`.
- [ ] MSI is Authenticode-signed and timestamped; SmartScreen shows the
      publisher name.
- [ ] MSI SHA-256 checksum is generated and matches the artifact selected for
      beta distribution.
- [ ] Install/uninstall validation evidence is generated locally or by the
      manual release workflow:

      ```powershell
      .\windows\scripts\validate-install.ps1 -MsiPath .\windows\QuantumLink.msi -ReportPath .\windows\build\validation\install-validation-report.json
      ```

      The workflow's `-SkipNetworkChecks` option only waives adapter, route,
      and WFP evidence for constrained GitHub runners. It does not waive clean
      Windows 10/11 VM, physical-host, leak-test, two-machine, or macOS interop
      beta validation.
- [ ] Optional workflow upgrade validation is configured only with complete
      URL/SHA pairs: `upgrade_from_msi_url` plus
      `upgrade_from_msi_sha256`. To validate rollback, set
      `validate_rollback`, keep the upgrade source configured, and choose
      `rollback_mode` (`UninstallReinstall` or `DirectDowngrade`). If using a
      rollback target other than the upgrade source, set `rollback_to_msi_url`
      plus `rollback_to_msi_sha256`.
- [ ] Release evidence is generated before upload:

      ```powershell
      .\windows\scripts\verify-windows-release.ps1 -ArtifactDirectory .\windows\build\release -MsiPath <staged-msi> -ChecksumsPath .\windows\build\release\SHA256SUMS.txt -WintunLicensePath .\windows\build\release\WINTUN-LICENSE.txt -WintunDllPath .\wintun\bin\amd64\wintun.dll -EvidencePath .\windows\build\release\windows-release-evidence.json
      ```

      Signed/tagged releases require valid MSI signature and timestamp
      evidence. When `run_install_validation` is enabled, the verifier also
      requires `.\windows\build\validation\install-validation-report.json` and
      checks that its MSI SHA-256 matches the staged release MSI.

## 1. Install / first run

- [ ] MSI installs without warnings; `QuantumLinkService` is running
      (`sc query QuantumLinkService`).
- [ ] Capture local install/uninstall JSON evidence for the selected MSI:

      ```powershell
      .\windows\scripts\validate-install.ps1 -MsiPath .\windows\QuantumLink.msi -ReportPath .\windows\build\validation\install-validation-report.json
      ```

      Use `-SkipNetworkChecks` only when a constrained runner cannot collect
      adapter, route, or WFP evidence; it is not acceptable as a substitute for
      full beta validation on clean Windows hosts.
- [ ] `C:\ProgramData\QuantumLink` exists; non-admin user cannot read
      `secrets\*.dpapi`.
- [ ] UI launches unprivileged, completes the `hello` handshake, shows
      phase `idle`.
- [ ] First `connect` creates the "QuantumLink" network adapter
      (`Get-NetAdapter`), assigns the overlay address, installs routes
      (`Get-NetRoute | ? InterfaceAlias -eq QuantumLink`).
- [ ] Device peer id is stable across service restarts (DPAPI seed
      reload - check diagnostics export before/after
      `Restart-Service QuantumLinkService`).

## 1A. Phase 8 Windows-native security proof

Run from an elevated PowerShell session after install and first-run
identity creation:

```powershell
.\windows\scripts\validate-windows-security.ps1 `
    -MsiPath .\QuantumLink.msi `
    -CheckPipeAcl
```

- [ ] Script exits 0 on the installed host.
- [ ] Output confirms `QuantumLinkService` is LocalSystem, auto-start,
      running, and launched from `quantumlink-service.exe service`.
- [ ] Output confirms installed binary placement for
      `quantumlink-service.exe`, `qlink_core.dll`, `wintun.dll`, and
      `QuantumLink.Windows.exe`.
- [ ] Output confirms ACL sanity for
      `C:\Program Files\QuantumLink`, `C:\ProgramData\QuantumLink`,
      `C:\ProgramData\QuantumLink\logs`, and
      `C:\ProgramData\QuantumLink\secrets`.
- [ ] Output confirms the named pipe `\\.\pipe\QuantumLinkService`
      exists. If the host cannot expose pipe ACLs through PowerShell,
      capture the warning and keep the pipe-presence evidence.
- [ ] Output confirms `wintun.dll` placement and Authenticode signature.
- [ ] Output confirms DPAPI service-context prerequisite evidence under
      `C:\ProgramData\QuantumLink\secrets\*.dpapi`.
- [ ] Output confirms the runtime `security-probe` checks pass for
      service-directory Wintun resolution, DPAPI protect/unprotect, WFP
      dynamic attach/remove, and network-monitor restart safety. Capture
      any admin-rights skip as a blocker unless the probe was run outside
      an elevated/LocalSystem context by mistake.

Collect MSI repair evidence without uninstalling:

```powershell
.\windows\scripts\validate-windows-security.ps1 `
    -MsiPath .\QuantumLink.msi `
    -RepairMsi
```

- [ ] Repair exits 0 and the verbose repair log path is captured from
      the script output.
- [ ] Run the main validation command again after repair; it still exits
      0.

Collect uninstall evidence only in a disposable VM:

```powershell
.\windows\scripts\validate-windows-security.ps1 `
    -MsiPath .\QuantumLink.msi `
    -UninstallMsi
```

- [ ] Uninstall exits 0 and the verbose uninstall log path is captured.
- [ ] `Get-Service QuantumLinkService -ErrorAction SilentlyContinue`
      returns no service.
- [ ] `Test-Path 'C:\ProgramData\QuantumLink'` is false.
- [ ] `Test-Path 'C:\Program Files\QuantumLink'` is false or contains
      only externally retained investigation artifacts.

## 2. Kill switch / leak tests

With `killSwitch: failClosed` (default):

- [ ] While connected, `ping` a protected-prefix address: traffic goes
      through the tunnel only (capture on the physical NIC with
      Wireshark; zero protected-prefix packets in plaintext).
- [ ] Stop the transport (block the rendezvous/relay endpoints at the
      router or with an outbound firewall rule): protected-prefix pings
      black-hole; nothing leaks out the physical NIC; pump counters show
      `droppedKillSwitch` increments.
- [ ] Force-kill the service process (`taskkill /f`) while packet capture is
      running. Because current failClosed enforcement uses dynamic WFP
      filters, a service crash can remove those filters and fail open; this
      test does not prove no-leak behavior. Record post-crash adapter, route,
      WFP filter, connectivity, and physical-NIC capture results. Block beta
      unless the observed behavior is explicitly documented and accepted for
      this beta.

With `killSwitch: strict`:

- [ ] Service refuses `connect` when WFP engagement is blocked (e.g.
      BFE service stopped) with a clear error.
- [ ] Sustained transport outage (>30 s) halts the data plane and
      surfaces the watchdog error in the UI.
- [ ] Strict deployments require service-crash hardening before release: WFP
      filters must be persistent/boot-time or otherwise survive service
      termination, and the forced-kill test must prove protected-prefix traffic
      stays blocked after crash. Without that hardening, strict deployment is
      blocked.

## 3. Network churn

- [ ] Sleep/resume: tunnel recovers (PostWake re-probe) within 30 s.
- [ ] Wi-Fi -> Ethernet switch: `PathChanged` logged, transport
      reconnects, pings recover.
- [ ] Captive-portal Wi-Fi: service stays up, kill switch holds, no
      crash loop.
- [ ] Boot with network unplugged: service starts, phase `idle`,
      connect succeeds after plugging in.

## 4. Mesh behavior (two-machine)

- [ ] Two Windows machines + rendezvous server: direct path
      establishes; `pathType: direct` in both UIs.
- [ ] Hostile NAT (block UDP between peers): relay fallback engages;
      `pathType: relay`.
- [ ] macOS <-> Windows interop: macOS app and Windows service
      exchange traffic (same qlink-core wire format).

## 5. Service lifecycle

- [ ] `Restart-Service` while connected: routes/filters cleaned up and
      re-established on reconnect; no orphan routes
      (`Get-NetRoute` clean after stop).
- [ ] Uninstall: service gone, adapter gone, no QuantumLink WFP
      sublayer (`netsh wfp show filters` | find "QuantumLink"), and state
      removal explicitly verified. WiX `RemoveFolder` only removes empty
      directories; if `C:\ProgramData\QuantumLink` remains non-empty, block
      beta or add explicit cleanup implementation and rerun this gate.
- [ ] Reinstall after verified state cleanup: fresh identity generated (peer id
      changes). If the peer id persists because state survived uninstall, treat
      it as an uninstall-cleanup blocker.

## 6. Diagnostics

- [ ] "Export diagnostics" output contains no raw `qlink_*` peer ids
      (only `qlink_[redacted]`), no SSIDs, no external IPs.
- [ ] Service logs under `%ProgramData%\QuantumLink\logs` rotate and
      contain netsh command audit lines.
