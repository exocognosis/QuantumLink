# QuantumLink Windows Installer

WiX v4 MSI replacing the macOS Sparkle/DMG/PKG pipeline.

## Release status

Windows packaging is alpha. The installer can be built for beta validation,
but no Windows artifact is release-ready until all deployment gates in this
file and the [Windows beta runbook](../docs/beta-runbook-windows.md) pass.

Windows deployment requires:

- A WiX-built MSI from the release commit.
- Official signed Wintun DLL sourcing, with the upstream license retained.
- Authenticode signing and timestamping for the MSI.
- SHA-256 checksums published alongside the MSI.
- Clean install, network, service, upgrade, and uninstall validation on
  Windows hardware or VMs.

## Prerequisites (Windows build host)

1. Rust toolchain with the `x86_64-pc-windows-msvc` target.
2. .NET 8 SDK (UI) and the pinned WiX toolset:
   `dotnet tool install --global wix --version 6.0.2`.
3. Windows SDK signing tools (`signtool.exe`) and access to the release
   Authenticode certificate.
4. `wintun.dll` from <https://www.wintun.net/> - download the official
   signed distribution and copy the matching-arch DLL
   (`bin/amd64/wintun.dll` for x64) to
   `windows\wintun\bin\amd64\wintun.dll`, or pass `-WintunDllPath` to the
   build script. Copy the upstream license/copying file to
   `windows\wintun\LICENSE.txt` for manual release staging. Wintun's license
   permits redistribution alongside your application; keep the upstream license
   text with the artifact.

## GitHub release workflow inputs

The Windows release workflow does not store `wintun.dll` in GitHub secrets.
Configure these repository variables before running tagged or manual MSI
builds:

- `WINTUN_DOWNLOAD_URL`: pinned URL for the official Wintun archive.
- `WINTUN_SHA256`: SHA-256 checksum for that archive.

The workflow downloads the archive to runner temp, verifies `WINTUN_SHA256`
before extraction, stages `bin/amd64/wintun.dll` at
`.\wintun\bin\amd64\wintun.dll`, verifies the staged DLL before packaging, and
copies the upstream Wintun license text into the release artifact set.
Tagged releases still require the Authenticode signing secrets and
external/manual validation evidence before publication; manual workflow builds
may upload unsigned internal artifacts when signing is not configured.

Manual workflow runs can also set `run_install_validation` to run
`.\windows\scripts\validate-install.ps1` against the generated MSI on
`windows-latest` and upload
`windows/build/validation/install-validation-report.json` as JSON evidence.
Set `skip_validation_network_checks` only when the runner cannot collect
adapter, route, or WFP evidence; that option does not replace full beta
validation on clean Windows hosts.

Additional manual workflow inputs:

- `expected_publisher_subject`: optional exact Authenticode publisher subject
  enforced by release evidence verification.
- `expected_publisher_thumbprint`: optional publisher certificate thumbprint
  enforced by release evidence verification.
- `upgrade_from_msi_url`: optional older MSI to install before validating an
  upgrade to the generated MSI.
- `upgrade_from_msi_sha256`: required SHA-256 checksum when
  `upgrade_from_msi_url` is supplied.
- `validate_rollback`: runs rollback validation after successful upgrade
  validation. This requires `upgrade_from_msi_url`.
- `rollback_to_msi_url`: optional rollback target MSI. If omitted during
  rollback validation, `validate-install.ps1` rolls back to the upgrade source.
- `rollback_to_msi_sha256`: required SHA-256 checksum when
  `rollback_to_msi_url` is supplied.
- `rollback_mode`: `UninstallReinstall` by default, or `DirectDowngrade` when
  direct downgrade behavior should be exercised.

The release workflow runs `.\windows\scripts\verify-windows-release.ps1` before
uploading artifacts. It writes
`windows/build/release/windows-release-evidence.json` alongside the MSI,
`SHA256SUMS.txt`, and `WINTUN-LICENSE.txt`. For signed manual artifacts and all
tag releases, this evidence requires a valid MSI signature and trusted
timestamp. When `run_install_validation` is enabled, the evidence also requires
`.\windows\build\validation\install-validation-report.json` and checks that the
report's MSI SHA-256 matches the staged release MSI.

## Build steps

Run these commands from the repository root (the directory containing
`Cargo.toml`) in Developer PowerShell. The preferred route is the release build
script, which resolves the Windows silo paths and can build the MSI:

```powershell
.\windows\scripts\build-windows.ps1 -Msi
```

For manual fallback/debug builds, keep every path below relative to the
repository root:

```powershell
# 1. Rust artifacts (service + core DLL)
cargo build --release --target x86_64-pc-windows-msvc -p quantumlink-service -p qlink-core

# 2. UI
dotnet publish windows\ui\QuantumLink.Windows -c Release -r win-x64 -o windows\ui\publish

# 3. Wintun
Copy-Item windows\wintun\bin\amd64\wintun.dll target\x86_64-pc-windows-msvc\release\

# 4. MSI
wix build windows\installer\QuantumLink.wxs `
    -arch x64 `
    -d BuildDir=target\x86_64-pc-windows-msvc\release `
    -d UiPublishDir=windows\ui\publish `
    -ext WixToolset.Util.wixext/6.0.2 `
    -o windows\QuantumLink.msi

# 5. Sign (required for distribution)
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 windows\QuantumLink.msi

# 6. Verify signature
Get-AuthenticodeSignature .\windows\QuantumLink.msi

# 7. Stage release artifacts and checksums
$releaseDir = ".\windows\build\release"
Remove-Item -Path $releaseDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

$stagedMsi = Join-Path $releaseDir "QuantumLink-manual-windows-x64.msi"
Copy-Item -Path ".\windows\QuantumLink.msi" -Destination $stagedMsi -Force
Copy-Item -Path ".\windows\wintun\LICENSE.txt" -Destination (Join-Path $releaseDir "WINTUN-LICENSE.txt") -Force

$checksumsPath = Join-Path $releaseDir "SHA256SUMS.txt"
Get-ChildItem -Path $releaseDir -File |
    Sort-Object Name |
    ForEach-Object {
        $hash = Get-FileHash -Algorithm SHA256 -Path $_.FullName
        "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), $_.Name
    } |
    Set-Content -Path $checksumsPath -Encoding ascii
Get-Content $checksumsPath

# 8. Generate install/uninstall validation evidence
.\windows\scripts\validate-install.ps1 -MsiPath .\windows\QuantumLink.msi -ReportPath .\windows\build\validation\install-validation-report.json

# 9. Generate release evidence for the staged artifact set
.\windows\scripts\verify-windows-release.ps1 `
    -ArtifactDirectory .\windows\build\release `
    -MsiPath $stagedMsi `
    -ChecksumsPath .\windows\build\release\SHA256SUMS.txt `
    -WintunLicensePath .\windows\build\release\WINTUN-LICENSE.txt `
    -WintunDllPath .\windows\wintun\bin\amd64\wintun.dll `
    -EvidencePath .\windows\build\release\windows-release-evidence.json
```

## Release operator checklist

- [ ] Start from a tagged release commit with the Windows CI workflow green.
- [ ] Confirm `WINTUN_DOWNLOAD_URL` and `WINTUN_SHA256` repository variables
      are pinned to the official Wintun archive. Do not store `wintun.dll` as
      a GitHub binary or base64 secret.
- [ ] Build the Rust service/core and WinUI app from that exact commit on a
      clean Windows release host.
- [ ] Source `wintun.dll` from the official signed Wintun distribution,
      verify its Authenticode signature, and retain the upstream license text
      with the release artifact.
- [ ] Build the WiX MSI, then Authenticode-sign and timestamp `QuantumLink.msi`.
- [ ] Verify the MSI signature shows the expected publisher and a trusted
      timestamp.
- [ ] For manual release workflow runs, set `expected_publisher_subject` and/or
      `expected_publisher_thumbprint` when publisher identity should be
      enforced by `windows-release-evidence.json`.
- [ ] Generate and publish the SHA-256 checksum next to the MSI.
- [ ] If validating upgrade, configure `upgrade_from_msi_url` and
      `upgrade_from_msi_sha256`. If validating rollback, also set
      `validate_rollback`, choose `rollback_mode`, and optionally configure
      `rollback_to_msi_url` plus `rollback_to_msi_sha256`.
- [ ] Confirm `windows-release-evidence.json` is uploaded alongside the MSI,
      `SHA256SUMS.txt`, and `WINTUN-LICENSE.txt`.
- [ ] Run the Windows beta runbook on clean Windows 10 22H2 and Windows 11 x64
      VMs plus at least one physical x64 Windows machine.
- [ ] Treat any install, Wintun, WFP, leak-test, service lifecycle, checksum,
      or signing failure as a beta blocker. Do not publish unsigned or
      checksumless artifacts.

## Current CI coverage

The `.github/workflows/windows-ci.yml` workflow currently proves that the
Windows Rust workspace checks and tests on `windows-latest`, the service smoke
command passes, release Rust artifacts build, and the WinUI 3 app builds.

The Windows release workflow sources Wintun from the pinned URL/checksum, builds
the WiX MSI, optionally Authenticode-signs manual artifacts, requires signing
for tag releases, creates checksums, verifies the release evidence contract, and
uploads `windows-release-evidence.json` plus the Wintun license text with the
artifacts. For manual runs with `run_install_validation` enabled, it also
installs and uninstalls the generated MSI on `windows-latest` by running
`.\windows\scripts\validate-install.ps1`, optionally exercises upgrade and
rollback validation from the configured MSI URLs, then uploads
`windows/build/validation/install-validation-report.json` as
`QuantumLink-Windows-InstallValidation-<run-number>`.

CI and the optional manual workflow evidence do not verify SmartScreen/publisher
behavior, exercise real networking and leak-test scenarios, or run two-machine
mesh and macOS interop validation. Those remain manual beta gates on clean
Windows hardware or VMs.

## What install does

- Files to `C:\Program Files\QuantumLink\`.
- Registers + starts `QuantumLinkService` (LocalSystem, auto-start,
  argument `service`).
- Creates `C:\ProgramData\QuantumLink\` ACL'd to SYSTEM/Administrators
  (DPAPI secret blobs, config.json, peers.json, logs).

## What uninstall cleans up

- Stops and deletes the service. During graceful service shutdown, dynamic WFP
  kill-switch filters and the Wintun adapter/session are expected to be torn
  down; protected routes are expected to be removed by the service's disconnect
  path. Verify these on every beta host.
- Schedules recursive removal of `C:\ProgramData\QuantumLink\` with WiX
  `util:RemoveFolderEx`, followed by normal `RemoveFolder` cleanup. State
  removal must be verified after uninstall. If config, logs, encrypted peer
  cache, or DPAPI blobs remain, beta is blocked until cleanup is fixed and
  rerun.
- The Wintun *driver* is reference-counted by Windows and removed when
  the last Wintun-using product uninstalls - no action needed.

## Phase 8 security validation

After installing the signed MSI on a clean Windows test host, run the
Windows-native validation script from an elevated PowerShell session:

```powershell
.\windows\scripts\validate-windows-security.ps1 `
    -MsiPath .\QuantumLink.msi `
    -CheckPipeAcl
```

The script fails when required proof evidence is missing:

- `QuantumLinkService` is installed, running, auto-start, LocalSystem,
  and launched from the expected service binary with the `service`
  argument.
- `quantumlink-service.exe`, `qlink_core.dll`, `wintun.dll`, and
  `QuantumLink.Windows.exe` are present under
  `C:\Program Files\QuantumLink\`.
- Binary, config, log, and DPAPI store directories have conservative
  ACLs: SYSTEM and Administrators retain full control, and broad
  identities do not get write access. ProgramData stores must not be
  broadly readable.
- The named pipe `\\.\pipe\QuantumLinkService` is present while the
  service is running. Pipe ACL inspection is attempted with
  `-CheckPipeAcl` because support varies by host and PowerShell
  provider.
- `wintun.dll` and the MSI have valid Authenticode signatures.
- DPAPI prerequisite evidence exists under
  `C:\ProgramData\QuantumLink\secrets\*.dpapi`, which means the service
  has completed first-run identity creation under its service context.
- `quantumlink-service.exe security-probe` exits 0 and reports runtime
  proof for service-directory Wintun resolution, DPAPI protect/unprotect,
  WFP dynamic filter attach/remove, and network-monitor restart safety.
  Skipped probe checks fail validation because they do not produce
  Phase 7/8 runtime proof.

To collect non-destructive MSI repair evidence, add `-RepairMsi`; it
runs `msiexec /fa` and writes a verbose repair log to `%TEMP%`.

Uninstall evidence is destructive and is intentionally opt-in:

```powershell
.\windows\scripts\validate-windows-security.ps1 `
    -MsiPath .\QuantumLink.msi `
    -UninstallMsi
```

Run the uninstall hook only in a disposable VM after install/repair
proof has been captured.

## Distribution channels

- Direct MSI download (signed).
- Optional `winget` manifest once the MSI is hosted at a stable URL.
- Enterprise: standard MSI deployment via Intune/SCCM/GPO. Configuration
  can be pre-seeded by dropping a managed `config.json` into
  `C:\ProgramData\QuantumLink\` (the Windows analog of the macOS
  `.mobileconfig` managed configuration).

## Updates

v1 strategy: in-app "new version available" check pointing at the signed
MSI; MSI `MajorUpgrade` handles in-place upgrades (service is stopped,
replaced, restarted). Background auto-update (Sparkle equivalent) is
deliberately deferred until the update channel is designed for the
service privilege boundary.
