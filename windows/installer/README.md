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
2. .NET 8 SDK (UI) and the WiX toolset: `dotnet tool install --global wix`.
3. Windows SDK signing tools (`signtool.exe`) and access to the release
   Authenticode certificate.
4. `wintun.dll` from <https://www.wintun.net/> - download the official
   signed distribution and copy the matching-arch DLL
   (`bin/amd64/wintun.dll` for x64) to
   `windows\wintun\bin\amd64\wintun.dll`, or pass `-WintunDllPath` to the
   build script. Wintun's license permits redistribution alongside your
   application; keep the upstream license text with the artifact.

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
Tagged releases still require the Authenticode signing secrets; manual
workflow builds may upload unsigned internal artifacts when signing is not
configured.

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
    -d BuildDir=target\x86_64-pc-windows-msvc\release `
    -d UiPublishDir=windows\ui\publish `
    -ext WixToolset.Util.wixext `
    -o windows\QuantumLink.msi

# 5. Sign (required for distribution)
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 windows\QuantumLink.msi

# 6. Verify signature and publish checksum
Get-AuthenticodeSignature .\windows\QuantumLink.msi
Get-FileHash .\windows\QuantumLink.msi -Algorithm SHA256 | Format-List > .\windows\QuantumLink.msi.sha256
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
- [ ] Generate and publish the SHA-256 checksum next to the MSI.
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
for tag releases, creates checksums, and uploads the Wintun license text with
the artifacts.

CI does not currently install or uninstall the product, verify
SmartScreen/publisher behavior, exercise Wintun/WFP on real networking stacks,
or run two-machine mesh and macOS interop validation. Those remain manual beta
gates on clean Windows hardware or VMs.

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
- Schedules removal of `C:\ProgramData\QuantumLink\`, but WiX `RemoveFolder`
  only removes empty directories. State removal must be verified after
  uninstall. If non-empty config, logs, encrypted peer cache, or DPAPI blobs
  remain, beta is blocked until explicit cleanup implementation is added and
  validated.
- The Wintun *driver* is reference-counted by Windows and removed when
  the last Wintun-using product uninstalls - no action needed.

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
