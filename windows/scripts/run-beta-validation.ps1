<#
.SYNOPSIS
Runs the Windows-native QuantumLink install and security validation bundle.

.DESCRIPTION
Runs validate-install.ps1 with uninstall deferred, then validates the live
installed service with validate-windows-security.ps1. The script emits a
bounded manifest that references both component reports. A passing manifest
covers only this automated Windows-native scope; manual beta and production
gates remain separate.
#>

[CmdletBinding()]
param(
    [string]$MsiPath,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "../build/validation"),
    [switch]$SkipNetworkChecks,
    [switch]$IncludeHostIdentifiers,
    [int]$SettleTimeoutSeconds = 60,
    [int]$SettleIntervalSeconds = 2,
    [switch]$ContractOnly
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$script:SchemaVersion = "1.0"
$script:MaxCollectionItems = 50
$script:MaxEvidenceLineLength = 400

function Get-BetaValidationTimestamp {
    return (Get-Date).ToUniversalTime().ToString("o")
}

function Resolve-BetaValidationPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
}

function ConvertTo-BetaValidationString {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if (-not $IncludeHostIdentifiers) {
        foreach ($identifier in @($env:COMPUTERNAME, [System.Environment]::UserName)) {
            if (-not [string]::IsNullOrWhiteSpace($identifier)) {
                $text = [regex]::Replace(
                    $text,
                    [regex]::Escape($identifier),
                    "[redacted]",
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                )
            }
        }
    }

    if ($text.Length -le $script:MaxEvidenceLineLength) {
        return $text
    }

    return ($text.Substring(0, $script:MaxEvidenceLineLength) + "...[truncated]")
}

function ConvertTo-BetaHostIdentifier {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($IncludeHostIdentifiers) {
        return (ConvertTo-BetaValidationString -Value $Value)
    }

    if ($null -eq $Value) {
        return $null
    }

    return "[redacted]"
}

function Get-BetaValidationHostSnapshot {
    return [ordered]@{
        computerName = (ConvertTo-BetaHostIdentifier -Value $env:COMPUTERNAME)
        userName = (ConvertTo-BetaHostIdentifier -Value ([System.Environment]::UserName))
        os = [System.Environment]::OSVersion.ToString()
        architecture = (ConvertTo-BetaValidationString -Value $env:PROCESSOR_ARCHITECTURE)
        powerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

function New-BetaValidationComponent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$ReportFileName
    )

    return [ordered]@{
        name = $Name
        required = $true
        status = "blocked"
        invoked = $false
        exitCode = $null
        reportPath = $ReportFileName
        reportExists = $false
        schemaVersion = $null
        reportType = $null
        passed = $false
        reason = "Not started."
    }
}

function Read-BetaValidationComponentReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Component,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [int]$ExitCode,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSchemaVersion,

        [string]$ExpectedReportType,

        [switch]$ContractEvidence
    )

    $Component.invoked = $true
    $Component.exitCode = $ExitCode
    $Component.reportExists = Test-Path -LiteralPath $Path -PathType Leaf

    if (-not $Component.reportExists) {
        $Component.status = "failed"
        $Component.reason = "Required component report was not created."
        return
    }

    try {
        $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        $Component.status = "failed"
        $Component.reason = "Required component report is not valid JSON."
        return
    }

    $Component.schemaVersion = ConvertTo-BetaValidationString -Value $report.schemaVersion
    $Component.reportType = ConvertTo-BetaValidationString -Value $report.reportType
    $Component.passed = [bool]$report.passed

    if ([string]$report.schemaVersion -ne $ExpectedSchemaVersion) {
        $Component.status = "failed"
        $Component.passed = $false
        $Component.reason = "Component report schemaVersion is missing or unsupported."
    } elseif ((-not [string]::IsNullOrWhiteSpace($ExpectedReportType)) -and ([string]$report.reportType -ne $ExpectedReportType)) {
        $Component.status = "failed"
        $Component.passed = $false
        $Component.reason = "Component reportType is missing or unsupported."
    } elseif ($ContractEvidence) {
        $Component.status = "blocked"
        $Component.passed = $false
        $Component.reason = "Contract-only output is not Windows-native validation evidence."
    } elseif (($ExitCode -ne 0) -or (-not [bool]$report.passed)) {
        $Component.status = "failed"
        $Component.reason = "Component validation did not pass."
    } else {
        $Component.status = "passed"
        $Component.reason = $null
    }
}

function Write-BetaValidationManifest {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $json = $Manifest | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function Write-BetaValidationBlockedComponentReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Component,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $report = [ordered]@{
        schemaVersion = "1.0"
        reportType = "quantumlink.windows.validation-placeholder"
        generatedAt = (Get-BetaValidationTimestamp)
        component = $Component
        status = "blocked"
        passed = $false
        contractOnly = [bool]$ContractOnly
        hostIdentifiersIncluded = [bool]$IncludeHostIdentifiers
        host = (Get-BetaValidationHostSnapshot)
        reason = (ConvertTo-BetaValidationString -Value $Reason)
        failures = @()
        warnings = @("This placeholder records missing component evidence and is not promotable.")
    }

    Write-BetaValidationManifest -Manifest $report -Path $Path
}

function Write-BetaValidationFailureManifest {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ErrorRecord
    )

    try {
        $resolvedOutputDirectory = Resolve-BetaValidationPath -Path $OutputDirectory
        if (-not (Test-Path -LiteralPath $resolvedOutputDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
        }

        $manifest = [ordered]@{
            schemaVersion = $script:SchemaVersion
            reportType = "quantumlink.windows.beta-validation-manifest"
            generatedAt = (Get-BetaValidationTimestamp)
            scope = "automated_windows_native_validation"
            status = "failed"
            passed = $false
            requiredEvidencePassed = $false
            productionReady = $false
            contractOnly = [bool]$ContractOnly
            hostIdentifiersIncluded = [bool]$IncludeHostIdentifiers
            host = (Get-BetaValidationHostSnapshot)
            artifact = [ordered]@{
                fileName = if ([string]::IsNullOrWhiteSpace($MsiPath)) { $null } else { [System.IO.Path]::GetFileName($MsiPath) }
                sha256 = $null
            }
            components = @(
                [ordered]@{
                    name = "installValidation"
                    required = $true
                    status = "failed"
                    invoked = $false
                    exitCode = $null
                    reportPath = "install-validation-report.json"
                    reportExists = $false
                    schemaVersion = $null
                    reportType = $null
                    passed = $false
                    reason = "Orchestration stopped before component evidence could be accepted."
                },
                [ordered]@{
                    name = "securityValidation"
                    required = $true
                    status = "blocked"
                    invoked = $false
                    exitCode = $null
                    reportPath = "windows-security-validation-report.json"
                    reportExists = $false
                    schemaVersion = $null
                    reportType = $null
                    passed = $false
                    reason = "Orchestration stopped before security validation could complete."
                }
            )
            blockers = @("Security validation is blocked by an orchestration failure.")
            failures = @("Windows beta validation orchestration failed: $(ConvertTo-BetaValidationString -Value $ErrorRecord.Exception.Message)")
            warnings = @("A failed fallback manifest does not contain promotable validation evidence.")
        }

        Write-BetaValidationManifest `
            -Manifest $manifest `
            -Path (Join-Path $resolvedOutputDirectory "windows-beta-validation-manifest.json")
    } catch {
        Write-Error -Message "Failed to write fallback beta validation manifest: $($_.Exception.Message)" -ErrorAction Continue
    }
}

function Invoke-BetaValidation {
    $resolvedOutputDirectory = Resolve-BetaValidationPath -Path $OutputDirectory
    if (-not (Test-Path -LiteralPath $resolvedOutputDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
    }

    $installReportFileName = "install-validation-report.json"
    $securityReportFileName = "windows-security-validation-report.json"
    $manifestFileName = "windows-beta-validation-manifest.json"
    $installReportPath = Join-Path $resolvedOutputDirectory $installReportFileName
    $securityReportPath = Join-Path $resolvedOutputDirectory $securityReportFileName
    $manifestPath = Join-Path $resolvedOutputDirectory $manifestFileName

    foreach ($staleReportPath in @($installReportPath, $securityReportPath, $manifestPath)) {
        if (Test-Path -LiteralPath $staleReportPath) {
            Remove-Item -LiteralPath $staleReportPath -Force
        }
    }

    $installComponent = New-BetaValidationComponent -Name "installValidation" -ReportFileName $installReportFileName
    $securityComponent = New-BetaValidationComponent -Name "securityValidation" -ReportFileName $securityReportFileName
    $failures = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $blockers = New-Object System.Collections.Generic.List[string]

    $installScript = Join-Path $PSScriptRoot "validate-install.ps1"
    $securityScript = Join-Path $PSScriptRoot "validate-windows-security.ps1"
    $powerShellExecutable = (Get-Process -Id $PID).Path

    if ((-not $ContractOnly) -and [string]::IsNullOrWhiteSpace($MsiPath)) {
        $installComponent.reason = "-MsiPath is required for Windows-native validation."
        $securityComponent.reason = "Security validation requires a passing install validation."
    } else {
        $installArguments = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $installScript,
            "-ReportPath", $installReportPath,
            "-SkipUninstall",
            "-SettleTimeoutSeconds", [string]$SettleTimeoutSeconds,
            "-SettleIntervalSeconds", [string]$SettleIntervalSeconds
        )
        if ($ContractOnly) {
            $installArguments += "-ContractOnly"
        } else {
            $installArguments += @("-MsiPath", $MsiPath)
        }
        if ($SkipNetworkChecks) {
            $installArguments += "-SkipNetworkChecks"
        }
        if ($IncludeHostIdentifiers) {
            $installArguments += "-IncludeHostIdentifiers"
        }

        & $powerShellExecutable @installArguments
        $installExitCode = $LASTEXITCODE
        Read-BetaValidationComponentReport `
            -Component $installComponent `
            -Path $installReportPath `
            -ExitCode $installExitCode `
            -ExpectedSchemaVersion "1.1" `
            -ContractEvidence:$ContractOnly

        if (($installComponent.status -eq "passed") -or $ContractOnly) {
            $securityArguments = @(
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", $securityScript,
                "-ReportPath", $securityReportPath,
                "-CheckPipeAcl"
            )
            if ($ContractOnly) {
                $securityArguments += "-ContractOnly"
            } else {
                $securityArguments += @("-MsiPath", $MsiPath)
            }
            if ($IncludeHostIdentifiers) {
                $securityArguments += "-IncludeHostIdentifiers"
            }

            & $powerShellExecutable @securityArguments
            $securityExitCode = $LASTEXITCODE
            Read-BetaValidationComponentReport `
                -Component $securityComponent `
                -Path $securityReportPath `
                -ExitCode $securityExitCode `
                -ExpectedSchemaVersion "1.0" `
                -ExpectedReportType "quantumlink.windows.security-validation" `
                -ContractEvidence:$ContractOnly

            if ($SkipNetworkChecks -and (-not $ContractOnly) -and ($installComponent.status -eq "passed")) {
                $installComponent.status = "blocked"
                $installComponent.passed = $false
                $installComponent.reason = "Install validation skipped required network evidence."
            }
        } else {
            $securityComponent.reason = "Security validation was blocked by non-passing install validation."
        }
    }

    foreach ($component in @($installComponent, $securityComponent)) {
        if ($component.status -eq "failed") {
            $failures.Add("Required component '$($component.name)' failed: $($component.reason)")
        } elseif ($component.status -ne "passed") {
            $blockers.Add("Required component '$($component.name)' is $($component.status): $($component.reason)")
        }
    }

    if (-not (Test-Path -LiteralPath $installReportPath -PathType Leaf)) {
        Write-BetaValidationBlockedComponentReport `
            -Component "installValidation" `
            -Reason $installComponent.reason `
            -Path $installReportPath
    }
    if (-not (Test-Path -LiteralPath $securityReportPath -PathType Leaf)) {
        Write-BetaValidationBlockedComponentReport `
            -Component "securityValidation" `
            -Reason $securityComponent.reason `
            -Path $securityReportPath
    }

    $warnings.Add("The install validator defers uninstall so the security validator can inspect the live installation.")
    $warnings.Add("A passing manifest covers automated Windows-native checks only; manual beta and production gates remain required.")

    $status = "passed"
    if ($failures.Count -gt 0) {
        $status = "failed"
    } elseif ($blockers.Count -gt 0) {
        $status = "blocked"
    }

    $msiFileName = $null
    $msiSha256 = $null
    if (-not [string]::IsNullOrWhiteSpace($MsiPath)) {
        $msiFileName = [System.IO.Path]::GetFileName($MsiPath)
        if (Test-Path -LiteralPath $MsiPath -PathType Leaf) {
            $msiSha256 = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $manifest = [ordered]@{
        schemaVersion = $script:SchemaVersion
        reportType = "quantumlink.windows.beta-validation-manifest"
        generatedAt = (Get-BetaValidationTimestamp)
        scope = "automated_windows_native_validation"
        status = $status
        passed = ($status -eq "passed")
        requiredEvidencePassed = ($status -eq "passed")
        productionReady = $false
        contractOnly = [bool]$ContractOnly
        hostIdentifiersIncluded = [bool]$IncludeHostIdentifiers
        host = (Get-BetaValidationHostSnapshot)
        artifact = [ordered]@{
            fileName = (ConvertTo-BetaValidationString -Value $msiFileName)
            sha256 = $msiSha256
        }
        components = @($installComponent, $securityComponent)
        blockers = @($blockers | Select-Object -First $script:MaxCollectionItems)
        failures = @($failures | Select-Object -First $script:MaxCollectionItems)
        warnings = @($warnings | Select-Object -First $script:MaxCollectionItems)
    }

    Write-BetaValidationManifest -Manifest $manifest -Path $manifestPath

    Write-Host "Windows beta validation manifest: $manifestPath"
    Write-Host "Status: $status"
    if ($status -eq "passed") {
        return 0
    }

    return 1
}

if ($MyInvocation.InvocationName -eq ".") {
    return
}

try {
    $scriptExitCode = Invoke-BetaValidation
} catch {
    Write-BetaValidationFailureManifest -ErrorRecord $_
    Write-Error -Message "Windows beta validation orchestration failed closed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}

if ($scriptExitCode -ne 0) {
    exit 1
}

exit 0
