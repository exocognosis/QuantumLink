# Full Windows build: Rust artifacts + UI + (optionally) MSI.
# Run from anywhere in a Developer PowerShell; the script locates the
# windows/ silo and the monorepo root itself.
#
#   .\windows\scripts\build-windows.ps1            # build everything
#   .\windows\scripts\build-windows.ps1 -Msi       # also produce QuantumLink.msi
#
# Prereqs: Rust (msvc target), .NET 8 SDK, WiX (for -Msi), and
# wintun.dll extracted to <repo>\wintun\bin\amd64\ (see installer/README.md).

param(
    [switch]$Msi
)

$ErrorActionPreference = "Stop"
# $root = the windows/ silo; $repoRoot = monorepo root (holds the Cargo
# workspace and its single target/ output dir, shared with the macOS silo).
$root = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $root
$target = Join-Path $repoRoot "target\release"
Set-Location $root

Write-Host "==> Rust: test workspace" -ForegroundColor Cyan
cargo test --workspace

Write-Host "==> Rust: data-plane smoke" -ForegroundColor Cyan
cargo run -p quantumlink-service -- smoke

Write-Host "==> Rust: release build (service + core DLL)" -ForegroundColor Cyan
cargo build --release -p quantumlink-service -p qlink-core

Write-Host "==> UI: publish" -ForegroundColor Cyan
dotnet publish ui\QuantumLink.Windows -c Release -r win-x64 -o ui\publish

if ($Msi) {
    $wintun = "wintun\bin\amd64\wintun.dll"
    if (-not (Test-Path $wintun)) {
        throw "wintun.dll not found at $wintun — download from https://www.wintun.net/ first"
    }
    Copy-Item $wintun $target -Force

    Write-Host "==> Installer: wix build" -ForegroundColor Cyan
    wix build installer\QuantumLink.wxs `
        -d BuildDir=$target `
        -d UiPublishDir=ui\publish `
        -ext WixToolset.Util.wixext `
        -o QuantumLink.msi
    Write-Host "Built QuantumLink.msi — remember to signtool before distribution." -ForegroundColor Yellow
}
