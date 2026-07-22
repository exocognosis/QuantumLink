<#
.SYNOPSIS
Validates Windows-native QuantumLink install security evidence.

.DESCRIPTION
Run from an elevated Windows PowerShell session after installing the MSI.
The script checks the installed service identity/path, binary and state
directory ACLs, named-pipe presence, Wintun placement, DPAPI/service-context
prerequisites, and optional MSI repair/uninstall evidence hooks.

It is read-only by default. It never uninstalls unless -UninstallMsi is set.
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "QuantumLinkService",
    [string]$InstallDir = (Join-Path $env:ProgramFiles "QuantumLink"),
    [string]$StateDir = (Join-Path $env:ProgramData "QuantumLink"),
    [string]$PipeName = "\\.\pipe\QuantumLinkService",
    [string]$MsiPath,
    [switch]$RepairMsi,
    [switch]$UninstallMsi,
    [switch]$CheckPipeAcl,
    [string]$ReportPath = (Join-Path $PSScriptRoot "../build/validation/windows-security-validation-report.json"),
    [switch]$IncludeHostIdentifiers,
    [switch]$ContractOnly
)

$ErrorActionPreference = "Stop"
$script:SchemaVersion = "1.0"
$script:MaxEvidenceItems = 100
$script:MaxEvidenceLineLength = 400
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:Passes = New-Object System.Collections.Generic.List[string]
$script:EvidenceTruncated = $false

function Get-SecurityValidationTimestamp {
    return (Get-Date).ToUniversalTime().ToString("o")
}

function ConvertTo-BoundedEvidenceString {
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

    $script:EvidenceTruncated = $true
    return ($text.Substring(0, $script:MaxEvidenceLineLength) + "...[truncated]")
}

function Add-BoundedEvidenceItem {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Items,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Items.Count -ge $script:MaxEvidenceItems) {
        $script:EvidenceTruncated = $true
        return
    }

    $Items.Add((ConvertTo-BoundedEvidenceString -Value $Message))
}

function ConvertTo-HostIdentifierEvidence {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($IncludeHostIdentifiers) {
        return (ConvertTo-BoundedEvidenceString -Value $Value)
    }

    if ($null -eq $Value) {
        return $null
    }

    return "[redacted]"
}

function Get-SecurityValidationHostSnapshot {
    $os = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    } catch {
        # OS metadata is useful but not required for the validation result.
    }

    return [ordered]@{
        computerName = (ConvertTo-HostIdentifierEvidence -Value $env:COMPUTERNAME)
        userName = (ConvertTo-HostIdentifierEvidence -Value ([System.Environment]::UserName))
        osCaption = if ($null -ne $os) { ConvertTo-BoundedEvidenceString -Value $os.Caption } else { [System.Environment]::OSVersion.ToString() }
        osVersion = if ($null -ne $os) { ConvertTo-BoundedEvidenceString -Value $os.Version } else { $null }
        osBuild = if ($null -ne $os) { ConvertTo-BoundedEvidenceString -Value $os.BuildNumber } else { $null }
        architecture = (ConvertTo-BoundedEvidenceString -Value $env:PROCESSOR_ARCHITECTURE)
        powerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

function Resolve-SecurityValidationReportPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
}

function Write-SecurityValidationReport {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("passed", "failed", "contract_only")]
        [string]$Status
    )

    $resolvedPath = Resolve-SecurityValidationReportPath -Path $ReportPath
    $reportDirectory = Split-Path -Parent $resolvedPath
    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    }

    $report = [ordered]@{
        schemaVersion = $script:SchemaVersion
        reportType = "quantumlink.windows.security-validation"
        generatedAt = (Get-SecurityValidationTimestamp)
        status = $Status
        passed = ($Status -eq "passed")
        contractOnly = [bool]$ContractOnly
        hostIdentifiersIncluded = [bool]$IncludeHostIdentifiers
        host = (Get-SecurityValidationHostSnapshot)
        summary = [ordered]@{
            passCount = $script:Passes.Count
            failureCount = $script:Failures.Count
            warningCount = $script:Warnings.Count
        }
        passes = @($script:Passes)
        failures = @($script:Failures)
        warnings = @($script:Warnings)
        evidenceTruncated = [bool]$script:EvidenceTruncated
    }

    $json = $report | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $resolvedPath -Value $json -Encoding UTF8
}

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Add-Failure {
    param([string]$Message)
    Add-BoundedEvidenceItem -Items $script:Failures -Message $Message
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

function Add-Warning {
    param([string]$Message)
    Add-BoundedEvidenceItem -Items $script:Warnings -Message $Message
    Write-Host "WARN: $Message" -ForegroundColor Yellow
}

function Add-Pass {
    param([string]$Message)
    Add-BoundedEvidenceItem -Items $script:Passes -Message $Message
    Write-Host "PASS: $Message" -ForegroundColor Green
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Add-Failure "Run this script from an elevated Administrator PowerShell session."
    } else {
        Add-Pass "Running elevated as Administrator."
    }
}

function ConvertTo-CanonicalIdentity {
    param([string]$Identity)

    switch -Regex ($Identity) {
        "^(NT AUTHORITY\\)?SYSTEM$" { return "SYSTEM" }
        "^(BUILTIN\\)?Administrators$" { return "Administrators" }
        "^(BUILTIN\\)?Users$" { return "Users" }
        "^(NT AUTHORITY\\)?Authenticated Users$" { return "Authenticated Users" }
        "^(Everyone)$" { return "Everyone" }
        default { return $Identity }
    }
}

function Get-PathAccessRules {
    param([string]$Path)

    try {
        return (Get-Acl -LiteralPath $Path).Access
    } catch {
        Add-Failure "Unable to read ACL for '$Path': $($_.Exception.Message)"
        return @()
    }
}

function Test-DirectoryAcl {
    param(
        [string]$Path,
        [string]$Label,
        [switch]$AllowBuiltinUsersRead
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Add-Failure "$Label directory is missing: $Path"
        return
    }

    $rules = @(Get-PathAccessRules -Path $Path)
    if ($rules.Count -eq 0) {
        Add-Failure "$Label directory has no readable ACL entries: $Path"
        return
    }

    $required = @("SYSTEM", "Administrators")
    foreach ($identity in $required) {
        $hasFull = $rules | Where-Object {
            (ConvertTo-CanonicalIdentity $_.IdentityReference.Value) -eq $identity -and
            (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne 0) -and
            $_.AccessControlType -eq "Allow"
        }
        if (-not $hasFull) {
            Add-Failure "$Label directory ACL must grant FullControl to $identity: $Path"
        }
    }

    $broadWriters = $rules | Where-Object {
        $name = ConvertTo-CanonicalIdentity $_.IdentityReference.Value
        $broad = $name -in @("Everyone", "Users", "Authenticated Users")
        $write = (
            (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne 0) -or
            (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -ne 0) -or
            (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0)
        )
        $broad -and $write -and $_.AccessControlType -eq "Allow"
    }
    if ($broadWriters) {
        Add-Failure "$Label directory grants broad write/modify/full-control access: $Path"
    }

    if (-not $AllowBuiltinUsersRead) {
        $broadReaders = $rules | Where-Object {
            $name = ConvertTo-CanonicalIdentity $_.IdentityReference.Value
            $broad = $name -in @("Everyone", "Users", "Authenticated Users")
            $read = (
                (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read) -ne 0) -or
                (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -ne 0)
            )
            $broad -and $read -and $_.AccessControlType -eq "Allow"
        }
        if ($broadReaders) {
            Add-Failure "$Label directory grants broad read access but should be SYSTEM/Administrators only: $Path"
        }
    }

    Add-Pass "$Label directory ACL checked: $Path"
}

function Get-ServiceExecutablePath {
    param([string]$PathName)

    if ($PathName -match '^\s*"([^"]+)"') {
        return $Matches[1]
    }
    if ($PathName -match '^\s*(.+?\.exe)\s+') {
        return $Matches[1]
    }
    if ($PathName -match '^\s*([^\s]+)') {
        return $Matches[1]
    }
    return $null
}

function Test-ServiceIdentity {
    param([string]$Name)

    Write-Step "Service identity and binary path"
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $service) {
        Add-Failure "Windows service '$Name' is not installed."
        return $null
    }

    if ($service.StartName -notin @("LocalSystem", "NT AUTHORITY\LocalSystem")) {
        Add-Failure "$Name must run as LocalSystem; observed StartName='$($service.StartName)'."
    } else {
        Add-Pass "$Name runs as LocalSystem."
    }

    if ($service.StartMode -ne "Auto") {
        Add-Failure "$Name must be auto-start; observed StartMode='$($service.StartMode)'."
    } else {
        Add-Pass "$Name is configured for automatic start."
    }

    if ($service.State -ne "Running") {
        Add-Failure "$Name must be running for Phase 8 evidence; observed State='$($service.State)'."
    } else {
        Add-Pass "$Name is running."
    }

    $exePath = Get-ServiceExecutablePath -PathName $service.PathName
    if (-not $exePath) {
        Add-Failure "$Name service PathName is empty or unparsable: '$($service.PathName)'."
        return $service
    }

    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        Add-Failure "$Name executable path is missing: $exePath"
    } else {
        Add-Pass "$Name executable exists: $exePath"
    }

    if ($service.PathName -notmatch "\bservice\b") {
        Add-Failure "$Name PathName should include the 'service' argument; observed '$($service.PathName)'."
    } else {
        Add-Pass "$Name PathName includes the service argument."
    }

    return $service
}

function Test-InstalledFiles {
    param([string]$Directory)

    Write-Step "Installed binary placement"
    $requiredFiles = @(
        "quantumlink-service.exe",
        "qlink_core.dll",
        "wintun.dll",
        "QuantumLink.Windows.exe"
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        Add-Failure "Install directory is missing: $Directory"
        return
    }

    foreach ($file in $requiredFiles) {
        $path = Join-Path $Directory $file
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Add-Failure "Required installed file is missing: $path"
        } else {
            Add-Pass "Required installed file exists: $path"
        }
    }

    Test-DirectoryAcl -Path $Directory -Label "binary install" -AllowBuiltinUsersRead
}

function Test-StateLayout {
    param([string]$Directory)

    Write-Step "ProgramData store, config, log, and DPAPI layout"
    Test-DirectoryAcl -Path $Directory -Label "ProgramData store"

    $configPath = Join-Path $Directory "config.json"
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        Add-Failure "Config evidence is missing: $configPath"
    } else {
        Add-Pass "Config evidence exists: $configPath"
    }

    $logsPath = Join-Path $Directory "logs"
    Test-DirectoryAcl -Path $logsPath -Label "log store"

    $secretsPath = Join-Path $Directory "secrets"
    Test-DirectoryAcl -Path $secretsPath -Label "DPAPI secret store"

    $dpapiFiles = @(Get-ChildItem -LiteralPath $secretsPath -Filter "*.dpapi" -File -ErrorAction SilentlyContinue)
    if ($dpapiFiles.Count -eq 0) {
        Add-Failure "No DPAPI secret blobs found under $secretsPath; run the service through first-run identity creation."
    } else {
        Add-Pass "DPAPI secret blob evidence found under $secretsPath."
    }
}

function Test-NamedPipe {
    param(
        [string]$Name,
        [switch]$Acl
    )

    Write-Step "Named pipe presence and ACL sanity"
    if (-not (Test-Path -LiteralPath $Name)) {
        Add-Failure "Named pipe is missing: $Name. Confirm $ServiceName is running and serving IPC."
        return
    }
    Add-Pass "Named pipe exists: $Name"

    if (-not $Acl) {
        Add-Warning "Named pipe ACL read was not requested. Re-run with -CheckPipeAcl when the host supports pipe ACL inspection."
        return
    }

    try {
        $pipeAcl = Get-Acl -LiteralPath $Name
        $broadFull = $pipeAcl.Access | Where-Object {
            $name = ConvertTo-CanonicalIdentity $_.IdentityReference.Value
            $name -in @("Everyone", "Users", "Authenticated Users") -and
            (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne 0) -and
            $_.AccessControlType -eq "Allow"
        }
        if ($broadFull) {
            Add-Failure "Named pipe grants broad FullControl access: $Name"
        } else {
            Add-Pass "Named pipe ACL does not grant broad FullControl access."
        }
    } catch {
        Add-Failure "Could not inspect required named pipe ACL for '$Name': $($_.Exception.Message)"
    }
}

function Test-WintunPlacement {
    param([string]$Directory)

    Write-Step "Wintun DLL placement"
    $wintun = Join-Path $Directory "wintun.dll"
    if (-not (Test-Path -LiteralPath $wintun -PathType Leaf)) {
        Add-Failure "wintun.dll is missing from the service install directory: $wintun"
        return
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $wintun
    if ($signature.Status -ne "Valid") {
        Add-Failure "wintun.dll Authenticode signature is not valid; observed Status='$($signature.Status)'."
    } else {
        Add-Pass "wintun.dll Authenticode signature is valid."
    }
}

function Test-RuntimeSecurityProbe {
    param([object]$Service)

    Write-Step "Runtime service security probe"
    if (-not $Service) {
        Add-Failure "Cannot run runtime probe because service metadata was unavailable."
        return
    }

    $exePath = Get-ServiceExecutablePath -PathName $Service.PathName
    if (-not $exePath -or -not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        Add-Failure "Cannot run runtime probe because the service executable is missing: $exePath"
        return
    }

    $probeOutput = & $exePath security-probe 2>&1
    $exitCode = $LASTEXITCODE
    $probeText = ($probeOutput | Out-String).Trim()
    if ($exitCode -ne 0) {
        Add-Failure "Runtime security probe failed with exit code $exitCode."
        return
    }

    try {
        $report = $probeText | ConvertFrom-Json
    } catch {
        Add-Failure "Runtime security probe did not emit valid JSON: $($_.Exception.Message)."
        return
    }

    if (-not $report.passed) {
        Add-Failure "Runtime security probe reported passed=false."
        return
    }

    foreach ($check in @($report.checks)) {
        if ($check.status -eq "failed") {
            Add-Failure "Runtime probe check failed: $($check.name): $($check.detail)"
        } elseif ($check.status -eq "skipped") {
            Add-Failure "Runtime probe check skipped, so required proof is missing: $($check.name): $($check.detail)"
        } else {
            Add-Pass "Runtime probe check passed: $($check.name)"
        }
    }
}

function Invoke-MsiHook {
    param(
        [string]$Path,
        [switch]$Repair,
        [switch]$Uninstall
    )

    if (-not $Path) {
        return
    }

    Write-Step "MSI evidence hooks"
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Failure "MSI path does not exist: $Path"
        return
    }
    Add-Pass "MSI path exists: $Path"

    $msiSignature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($msiSignature.Status -ne "Valid") {
        Add-Failure "MSI Authenticode signature is not valid; observed Status='$($msiSignature.Status)'."
    } else {
        Add-Pass "MSI Authenticode signature is valid."
    }

    if ($Repair) {
        $repairLog = Join-Path $env:TEMP "QuantumLink-msi-repair.log"
        Write-Step "Running non-destructive MSI repair evidence hook"
        $repair = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/fa", "`"$Path`"", "/qn", "/L*v", "`"$repairLog`"") -Wait -PassThru
        if ($repair.ExitCode -ne 0) {
            Add-Failure "MSI repair failed with exit code $($repair.ExitCode). Log: $repairLog"
        } else {
            Add-Pass "MSI repair completed successfully. Log: $repairLog"
        }
    }

    if ($Uninstall) {
        $uninstallLog = Join-Path $env:TEMP "QuantumLink-msi-uninstall.log"
        Write-Step "Running destructive MSI uninstall evidence hook because -UninstallMsi was set"
        $uninstall = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/x", "`"$Path`"", "/qn", "/L*v", "`"$uninstallLog`"") -Wait -PassThru
        if ($uninstall.ExitCode -ne 0) {
            Add-Failure "MSI uninstall failed with exit code $($uninstall.ExitCode). Log: $uninstallLog"
        } else {
            Add-Pass "MSI uninstall completed successfully. Log: $uninstallLog"
        }
    } else {
        Add-Pass "MSI uninstall was not run. Pass -UninstallMsi only in a disposable VM when collecting uninstall evidence."
    }
}

function Invoke-WindowsSecurityValidation {
    if ($ContractOnly) {
        Add-Warning "Contract-only mode emitted schema evidence without Windows-native validation."
        Write-SecurityValidationReport -Status "contract_only"
        return 0
    }

    Assert-Admin
    $service = Test-ServiceIdentity -Name $ServiceName
    Test-InstalledFiles -Directory $InstallDir
    Test-StateLayout -Directory $StateDir
    Test-NamedPipe -Name $PipeName -Acl:$CheckPipeAcl
    Test-WintunPlacement -Directory $InstallDir
    Test-RuntimeSecurityProbe -Service $service
    Invoke-MsiHook -Path $MsiPath -Repair:$RepairMsi -Uninstall:$UninstallMsi

    Write-Host ""
    Write-Host "QuantumLink Windows security validation summary" -ForegroundColor Cyan
    Write-Host "Warnings: $($script:Warnings.Count)"
    Write-Host "Failures: $($script:Failures.Count)"

    if ($script:Failures.Count -gt 0) {
        Write-Host ""
        Write-Host "Required Windows-native evidence is missing:" -ForegroundColor Red
        foreach ($failure in $script:Failures) {
            Write-Host " - $failure" -ForegroundColor Red
        }
        Write-SecurityValidationReport -Status "failed"
        return 1
    }

    Write-SecurityValidationReport -Status "passed"
    Write-Host "All required Windows-native security evidence checks passed." -ForegroundColor Green
    return 0
}

if ($MyInvocation.InvocationName -eq ".") {
    return
}

try {
    $scriptExitCode = Invoke-WindowsSecurityValidation
} catch {
    Add-Failure "Unhandled Windows security validation error: $($_.Exception.Message)"
    try {
        Write-SecurityValidationReport -Status "failed"
    } catch {
        Write-Error -Message "Failed to write fallback security validation report: $($_.Exception.Message)" -ErrorAction Continue
    }
    exit 1
}

if ($scriptExitCode -ne 0) {
    exit 1
}

exit 0
