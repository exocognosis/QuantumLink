# Full Windows build: Rust artifacts + UI + optionally MSI.
# Run from anywhere in a Developer PowerShell; the script locates the
# windows/ silo and the monorepo root itself.
#
#   .\windows\scripts\build-windows.ps1            # build everything
#   .\windows\scripts\build-windows.ps1 -Msi       # also produce QuantumLink.msi
#   .\windows\scripts\build-windows.ps1 -Msi -MsiOutputPath artifacts\QuantumLink.msi -SkipTests
#
# Prereqs: Rust (msvc target), .NET 8 SDK, WiX (for -Msi), and
# wintun.dll extracted to windows\wintun\bin\amd64\ (see installer/README.md).
# Relative -MsiOutputPath and -WintunDllPath values are resolved from the
# monorepo root. Defaults remain under windows/ to preserve local behavior.

param(
    [switch]$Msi,
    [string]$MsiOutputPath,
    [switch]$SkipTests,
    [string]$WintunDllPath
)

$ErrorActionPreference = "Stop"

function Resolve-FilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        $candidate = $Path
    } else {
        $candidate = Join-Path $BasePath $Path
    }

    return [System.IO.Path]::GetFullPath($candidate)
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE."
    }
}

function Assert-Command {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$InstallHint
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is missing. $InstallHint"
    }
}

function Assert-WindowsPrerequisites {
    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        throw "Windows build requires a Windows host with MSVC; current OS is $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)."
    }

    Assert-Command "cargo" "Install Rust from https://rustup.rs/."
    Assert-Command "rustc" "Install Rust from https://rustup.rs/."
    Assert-Command "rustup" "Install Rust from https://rustup.rs/."
    Assert-Command "dotnet" "Install the .NET 8 SDK."

    $installedTargets = rustup target list --installed
    if ($installedTargets -notcontains $rustTarget) {
        throw "Rust target $rustTarget is missing. Run: rustup target add $rustTarget"
    }

    Assert-Command "cl.exe" "Install MSVC Build Tools and run this script from a Developer PowerShell."
    Assert-Command "link.exe" "Install MSVC Build Tools and run this script from a Developer PowerShell."

    $sdkLibRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Lib"
    if (-not (Test-Path -LiteralPath $sdkLibRoot -PathType Container)) {
        throw "Windows SDK libraries not found at '$sdkLibRoot'. Install the Windows 10/11 SDK with MSVC."
    }
    $sdkVersions = Get-ChildItem -LiteralPath $sdkLibRoot -Directory | Sort-Object Name -Descending
    if (-not $sdkVersions) {
        throw "Windows SDK library root exists but has no versioned SDK directories: $sdkLibRoot."
    }
}

function Get-DotNetToolManifestRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SearchRoots
    )

    foreach ($searchRoot in $SearchRoots) {
        $manifestPath = Join-Path $searchRoot ".config\dotnet-tools.json"
        if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
            try {
                $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            } catch {
                throw "Failed to read dotnet tool manifest at '$manifestPath': $($_.Exception.Message)"
            }

            if ($manifest.tools) {
                $toolNames = @($manifest.tools.PSObject.Properties.Name)
                if ($toolNames -contains "wix") {
                    return $searchRoot
                }
            }
        }
    }

    return $null
}

function Invoke-WixBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $toolManifestRoot = Get-DotNetToolManifestRoot -SearchRoots @($root, $repoRoot)
    if ($toolManifestRoot) {
        Write-Host "==> WiX: dotnet tool restore" -ForegroundColor Cyan
        Push-Location $toolManifestRoot
        try {
            Invoke-NativeCommand "dotnet" @("tool", "restore")
            Invoke-NativeCommand "dotnet" (@("tool", "run", "wix", "--") + $Arguments)
        } finally {
            Pop-Location
        }
        return
    }

    $wixCommand = Get-Command "wix" -ErrorAction SilentlyContinue
    if (-not $wixCommand) {
        throw "WiX was not found. Install it with 'dotnet tool install --global wix' or add a local dotnet tool manifest with the wix tool, then rerun this script."
    }

    $wixPath = if ($wixCommand.Path) { $wixCommand.Path } else { $wixCommand.Source }
    if (-not $wixPath) {
        $wixPath = $wixCommand.Name
    }

    Invoke-NativeCommand $wixPath $Arguments
}

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$scriptDir = (Resolve-Path -LiteralPath $scriptDir).Path
# $root = the windows/ silo; $repoRoot = monorepo root (holds the Cargo
# workspace and its single target/ output dir, shared with the macOS silo).
$root = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..")).Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $root "..")).Path
$rustTarget = "x86_64-pc-windows-msvc"
$target = Resolve-FilePath "target\$rustTarget\release" $repoRoot
$cargoManifest = Resolve-FilePath "Cargo.toml" $repoRoot
$uiProject = Resolve-FilePath "ui\QuantumLink.Windows" $root
$uiPublishDir = Resolve-FilePath "ui\publish" $root
$installerSource = Resolve-FilePath "installer\QuantumLink.wxs" $root
$defaultWintunDll = Resolve-FilePath "wintun\bin\amd64\wintun.dll" $root
$protoPackage = "quantumlink-proto"
$servicePackage = "quantumlink-service"
$corePackage = "qlink-core"
$wixVersion = if ([string]::IsNullOrWhiteSpace($env:WIX_VERSION)) { "6.0.2" } else { $env:WIX_VERSION.Trim() }
$wixUtilExtension = "WixToolset.Util.wixext/$wixVersion"

if ([string]::IsNullOrWhiteSpace($MsiOutputPath)) {
    $resolvedMsiOutputPath = Resolve-FilePath "QuantumLink.msi" $root
} else {
    $resolvedMsiOutputPath = Resolve-FilePath $MsiOutputPath $repoRoot
}

Write-Host "==> Windows prerequisites" -ForegroundColor Cyan
Assert-WindowsPrerequisites

Write-Host "==> Rust: verify locked Cargo graph" -ForegroundColor Cyan
Invoke-NativeCommand "cargo" @("metadata", "--manifest-path", $cargoManifest, "--locked", "--format-version", "1", "--no-deps")

Write-Host "==> Rust: fetch locked dependencies for $rustTarget" -ForegroundColor Cyan
Invoke-NativeCommand "cargo" @("fetch", "--manifest-path", $cargoManifest, "--locked", "--target", $rustTarget)

Write-Host "==> Rust: check Windows core + service + protocol crates" -ForegroundColor Cyan
Invoke-NativeCommand "cargo" @("check", "--manifest-path", $cargoManifest, "--locked", "--target", $rustTarget, "-p", $corePackage, "-p", $protoPackage, "-p", $servicePackage, "--all-targets")

if ($SkipTests) {
    Write-Host "==> Rust: tests and smoke skipped" -ForegroundColor Yellow
} else {
    Write-Host "==> Rust: test Windows core + service + protocol crates" -ForegroundColor Cyan
    Invoke-NativeCommand "cargo" @("test", "--manifest-path", $cargoManifest, "--locked", "--target", $rustTarget, "-p", $corePackage, "-p", $protoPackage, "-p", $servicePackage)

    Write-Host "==> Rust: data-plane smoke" -ForegroundColor Cyan
    Invoke-NativeCommand "cargo" @("run", "--manifest-path", $cargoManifest, "--locked", "-p", $servicePackage, "--target", $rustTarget, "--", "smoke")
}

Write-Host "==> Rust: release build (service + core DLL)" -ForegroundColor Cyan
Invoke-NativeCommand "cargo" @("build", "--manifest-path", $cargoManifest, "--locked", "--release", "--target", $rustTarget, "-p", $servicePackage, "-p", "qlink-core")

Write-Host "==> UI: publish" -ForegroundColor Cyan
Invoke-NativeCommand "dotnet" @("publish", $uiProject, "-c", "Release", "-r", "win-x64", "-p:Platform=x64", "-o", $uiPublishDir)

if ($Msi) {
    if ([string]::IsNullOrWhiteSpace($WintunDllPath)) {
        $wintunSource = $defaultWintunDll
    } else {
        $wintunSource = Resolve-FilePath $WintunDllPath $repoRoot
    }

    if (-not (Test-Path -LiteralPath $wintunSource -PathType Leaf)) {
        throw "wintun.dll not found at '$wintunSource'. Download Wintun from https://www.wintun.net/ and place the amd64 DLL there, or pass -WintunDllPath <path>."
    }

    if (-not (Test-Path -LiteralPath $target -PathType Container)) {
        throw "Rust release target directory not found at '$target'. Check the release build output before building the MSI."
    }

    $wintunTarget = Join-Path $target "wintun.dll"
    Copy-Item -LiteralPath $wintunSource -Destination $wintunTarget -Force

    $msiOutputDir = Split-Path -Parent $resolvedMsiOutputPath
    if (-not (Test-Path -LiteralPath $msiOutputDir -PathType Container)) {
        New-Item -ItemType Directory -Path $msiOutputDir -Force | Out-Null
    }

    Write-Host "==> Installer: wix build" -ForegroundColor Cyan
    Invoke-WixBuild @(
        "build",
        "-arch",
        "x64",
        $installerSource,
        "-d",
        "BuildDir=$target",
        "-d",
        "UiPublishDir=$uiPublishDir",
        "-ext",
        $wixUtilExtension,
        "-o",
        $resolvedMsiOutputPath
    )
    Write-Host "Built MSI: $resolvedMsiOutputPath" -ForegroundColor Green
    Write-Host "Remember to signtool before distribution." -ForegroundColor Yellow
}
