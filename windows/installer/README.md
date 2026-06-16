# QuantumLink Windows Installer

WiX v4 MSI replacing the macOS Sparkle/DMG/PKG pipeline.

## Prerequisites (Windows build host)

1. Rust toolchain with the `x86_64-pc-windows-msvc` target.
2. .NET 8 SDK (UI) and the WiX toolset: `dotnet tool install --global wix`.
3. `wintun.dll` from <https://www.wintun.net/> — download the official
   signed distribution and copy the matching-arch DLL
   (`bin/amd64/wintun.dll` for x64) into the Rust release dir. Wintun's
   license permits redistribution alongside your application; keep the
   upstream license text with the artifact.

## Build steps

```powershell
# 1. Rust artifacts (service + core DLL)
cargo build --release --target x86_64-pc-windows-msvc -p quantumlink-service -p qlink-core

# 2. UI
dotnet publish ui\QuantumLink.Windows -c Release -r win-x64 -o ui\publish

# 3. Wintun
Copy-Item wintun\bin\amd64\wintun.dll target\x86_64-pc-windows-msvc\release\

# 4. MSI
wix build installer\QuantumLink.wxs `
    -d BuildDir=target\x86_64-pc-windows-msvc\release `
    -d UiPublishDir=ui\publish `
    -ext WixToolset.Util.wixext `
    -o QuantumLink.msi

# 5. Sign (required for distribution; production certs stay outside source)
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 QuantumLink.msi
```

Do not commit Authenticode certificates, private keys, timestamping
credentials, signed MSIs, or local Wintun drops. Production signing is
handled by private release infrastructure before artifacts are attached
to GitHub Releases or another official channel named by the maintainers.

## What install does

- Files to `C:\Program Files\QuantumLink\`.
- Registers + starts `QuantumLinkService` (LocalSystem, auto-start,
  argument `service`).
- Creates `C:\ProgramData\QuantumLink\` ACL'd to SYSTEM/Administrators
  (DPAPI secret blobs, config.json, peers.json, logs).

## What uninstall cleans up

- Stops and deletes the service. The dynamic WFP kill-switch filters
  and the Wintun adapter/session are torn down with the service process;
  protected routes are removed by the service's disconnect path.
- Removes the state folder (config, encrypted peer cache, DPAPI blobs).
- The Wintun *driver* is reference-counted by Windows and removed when
  the last Wintun-using product uninstalls — no action needed.

## Distribution channels

- GitHub Releases direct MSI download (signed).
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
