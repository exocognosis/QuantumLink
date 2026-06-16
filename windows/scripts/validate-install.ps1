<#
.SYNOPSIS
Validates a QuantumLink Windows MSI install and uninstall on a clean host.

.DESCRIPTION
Installs the MSI silently, verifies the expected service, state directory, UI
binary, and network footprint, uninstalls silently, then records cleanup
evidence in a bounded JSON report.
#>

[CmdletBinding()]
param(
    [string]$MsiPath,
    [string]$ReportPath = (Join-Path -Path (Get-Location).Path -ChildPath "quantumlink-install-validation-report.json"),
    [switch]$SkipInstall,
    [switch]$SkipUninstall,
    [switch]$SkipNetworkChecks,
    [string]$ExpectedServiceName = "QuantumLinkService",
    [string]$ExpectedStatePath = "C:\ProgramData\QuantumLink",
    [string]$ExpectedUiExe = "C:\Program Files\QuantumLink\QuantumLink.Windows.exe",
    [int]$SettleTimeoutSeconds = 60,
    [int]$SettleIntervalSeconds = 2,
    [switch]$IncludeHostIdentifiers,
    [switch]$ContractOnly
)

$ErrorActionPreference = "Stop"

$script:SchemaVersion = "1.0"
$script:MaxCollectionItems = 50
$script:MaxEvidenceLineLength = 300

function Get-ValidationTimestamp {
    return (Get-Date).ToUniversalTime().ToString("o")
}

function Resolve-ValidationPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location).Path -ChildPath $Path))
}

function Limit-ValidationString {
    param(
        [AllowNull()]
        [object]$Value,

        [int]$MaxLength = $script:MaxEvidenceLineLength
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ($text.Length -le $MaxLength) {
        return $text
    }

    return ($text.Substring(0, $MaxLength) + "...[truncated]")
}

function ConvertTo-QuantumLinkEvidenceValue {
    param(
        [AllowNull()]
        [object]$Value,

        [switch]$Include
    )

    if ($Include) {
        return (Limit-ValidationString -Value $Value)
    }

    if ($null -eq $Value) {
        return $null
    }

    return "[redacted]"
}

function ConvertTo-QuantumLinkNativeArgument {
    param(
        [AllowNull()]
        [object]$Argument
    )

    if ($null -eq $Argument) {
        return '""'
    }

    $text = [string]$Argument
    if ($text -match '[\s"]') {
        return '"' + ($text -replace '"', '\"') + '"'
    }

    return $text
}

function New-SkippedValidationSection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    return [ordered]@{
        skipped = $true
        passed = $true
        reason = $Reason
    }
}

function Test-QuantumLinkAdministrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-QuantumLinkHostSnapshot {
    param(
        [switch]$IncludeIdentifiers
    )

    $os = $null
    $osError = $null

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    } catch {
        $osError = $_.Exception.Message
    }

    $osCaption = $null
    $osVersion = $null
    $osBuild = $null

    if ($null -ne $os) {
        $osCaption = $os.Caption
        $osVersion = $os.Version
        $osBuild = $os.BuildNumber
    } else {
        $osCaption = [System.Environment]::OSVersion.ToString()
    }

    return [ordered]@{
        computerName = (ConvertTo-QuantumLinkEvidenceValue -Value $env:COMPUTERNAME -Include:$IncludeIdentifiers)
        userName = (ConvertTo-QuantumLinkEvidenceValue -Value ([System.Environment]::UserName) -Include:$IncludeIdentifiers)
        osCaption = $osCaption
        osVersion = $osVersion
        osBuild = $osBuild
        architecture = $env:PROCESSOR_ARCHITECTURE
        powerShellVersion = $PSVersionTable.PSVersion.ToString()
        osQueryError = $osError
    }
}

function Get-QuantumLinkMsiSnapshot {
    param(
        [AllowNull()]
        [string]$Path
    )

    $snapshot = [ordered]@{
        path = $Path
        resolvedPath = $null
        exists = $false
        sha256 = $null
        lengthBytes = $null
        error = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $snapshot.error = "MsiPath is required unless -ContractOnly is used."
        return $snapshot
    }

    try {
        $resolvedPath = Resolve-ValidationPath -Path $Path
        $snapshot.resolvedPath = $resolvedPath
        $snapshot.exists = Test-Path -LiteralPath $resolvedPath -PathType Leaf

        if (-not $snapshot.exists) {
            $snapshot.error = "MSI file was not found."
            return $snapshot
        }

        $file = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
        $snapshot.lengthBytes = $file.Length
        $snapshot.sha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash
    } catch {
        $snapshot.error = $_.Exception.Message
    }

    return $snapshot
}

function Invoke-QuantumLinkNativeProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    $argumentLine = (($Arguments | ForEach-Object { ConvertTo-QuantumLinkNativeArgument -Argument $_ }) -join " ")

    $result = [ordered]@{
        command = $Command
        arguments = $Arguments
        argumentLine = $argumentLine
        exitCode = $null
        stdout = @()
        stderr = @()
        output = @()
        error = $null
    }

    try {
        $process = Start-Process `
            -FilePath $Command `
            -ArgumentList $argumentLine `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -ErrorAction Stop

        $result.exitCode = [int]$process.ExitCode

        if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
            $result.stdout = @(Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue)
        }
        if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            $result.stderr = @(Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue)
        }

        $result.output = @($result.stdout + $result.stderr)
    } catch {
        $result.error = $_.Exception.Message
        if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
            $result.stdout = @(Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue)
        }
        if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            $result.stderr = @(Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue)
        }
        $result.output = @($result.stdout + $result.stderr)
    } finally {
        Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }

    return $result
}

function Invoke-QuantumLinkMsiExec {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Install", "Uninstall")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Action -eq "Install") {
        $arguments = @("/i", $Path, "/qn", "/norestart")
    } else {
        $arguments = @("/x", $Path, "/qn", "/norestart")
    }

    $result = [ordered]@{
        skipped = $false
        action = $Action
        command = "msiexec.exe"
        arguments = $arguments
        startedAt = (Get-ValidationTimestamp)
        endedAt = $null
        exitCode = $null
        stdout = @()
        stderr = @()
        passed = $false
        error = $null
    }

    try {
        $native = Invoke-QuantumLinkNativeProcess -Command "msiexec.exe" -Arguments $arguments
        $result.exitCode = $native.exitCode
        $result.stdout = @(
            $native.stdout |
                Select-Object -First 10 |
                ForEach-Object { Limit-ValidationString -Value $_ }
        )
        $result.stderr = @(
            $native.stderr |
                Select-Object -First 10 |
                ForEach-Object { Limit-ValidationString -Value $_ }
        )
        $result.passed = ($result.exitCode -eq 0)
        if ($native.error) {
            $result.error = $native.error
        } elseif (-not $result.passed) {
            $result.error = "msiexec.exe exited with code $($result.exitCode)."
        }
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        $result.endedAt = Get-ValidationTimestamp
    }

    return $result
}

function Get-QuantumLinkServiceValidation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$ExpectPresent,

        [switch]$RequireRunning
    )

    $result = [ordered]@{
        skipped = $false
        expectedName = $Name
        exists = $false
        displayName = $null
        status = $null
        state = $null
        startType = $null
        processId = $null
        pathName = $null
        passed = $false
        error = $null
    }

    try {
        $escapedName = $Name.Replace("'", "''")
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedName'" -ErrorAction Stop | Select-Object -First 1

        if ($null -ne $service) {
            $result.exists = $true
            $result.displayName = $service.DisplayName
            $result.status = $service.Status
            $result.state = $service.State
            $result.startType = $service.StartMode
            $result.processId = $service.ProcessId
            $result.pathName = $service.PathName
        }

        if ($ExpectPresent) {
            $result.passed = $result.exists
            if ($RequireRunning) {
                $result.passed = ($result.passed -and ($result.state -eq "Running"))
            }
        } else {
            $result.passed = (-not $result.exists)
        }
    } catch {
        $result.error = $_.Exception.Message
        $result.passed = $false
    }

    return $result
}

function ConvertTo-QuantumLinkSidValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$IdentityReference
    )

    try {
        if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            return $IdentityReference.Value
        }

        return $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function Test-QuantumLinkBroadReadAce {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemAccessRule]$Ace
    )

    $targetSids = @(
        "S-1-1-0",
        "S-1-5-32-545",
        "S-1-5-11"
    )
    $riskRights = @(
        [System.Security.AccessControl.FileSystemRights]::Read,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.FileSystemRights]::ListDirectory,
        [System.Security.AccessControl.FileSystemRights]::ReadData,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    )

    $identitySid = ConvertTo-QuantumLinkSidValue -IdentityReference $Ace.IdentityReference
    $hasTargetIdentity = ($targetSids -contains $identitySid)
    $isAllow = ($Ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
    $hasRiskRight = $false

    foreach ($right in $riskRights) {
        if (($Ace.FileSystemRights -band $right) -ne 0) {
            $hasRiskRight = $true
            break
        }
    }

    return [pscustomobject]@{
        IsBroadReadRisk = ($isAllow -and $hasTargetIdentity -and $hasRiskRight)
        Identity = [string]$Ace.IdentityReference
        IdentitySid = $identitySid
        Rights = $Ace.FileSystemRights.ToString()
        AccessControlType = $Ace.AccessControlType.ToString()
        IsInherited = $Ace.IsInherited
    }
}

function Get-QuantumLinkStateDirectoryValidation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $result = [ordered]@{
        skipped = $false
        expectedPath = $Path
        exists = $false
        aclChecked = $false
        broadReadRisk = $false
        broadReadAces = @()
        passed = $false
        error = $null
    }

    try {
        $result.exists = Test-Path -LiteralPath $Path -PathType Container
        if (-not $result.exists) {
            return $result
        }

        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $result.aclChecked = $true
        $riskyAces = @()

        foreach ($ace in $acl.Access) {
            $aceRisk = Test-QuantumLinkBroadReadAce -Ace $ace
            if ($aceRisk.IsBroadReadRisk) {
                $riskyAces += [ordered]@{
                    identity = $aceRisk.Identity
                    identitySid = $aceRisk.IdentitySid
                    rights = $aceRisk.Rights
                    accessControlType = $aceRisk.AccessControlType
                    isInherited = $aceRisk.IsInherited
                }
            }
        }

        $result.broadReadAces = @($riskyAces | Select-Object -First $script:MaxCollectionItems)
        $result.broadReadRisk = ($riskyAces.Count -gt 0)
        $result.passed = ($result.exists -and (-not $result.broadReadRisk))
    } catch {
        $result.error = $_.Exception.Message
        $result.passed = $false
    }

    return $result
}

function Get-QuantumLinkUiBinaryValidation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $result = [ordered]@{
        skipped = $false
        expectedPath = $Path
        exists = $false
        lengthBytes = $null
        passed = $false
        error = $null
    }

    try {
        $result.exists = Test-Path -LiteralPath $Path -PathType Leaf
        if ($result.exists) {
            $file = Get-Item -LiteralPath $Path -ErrorAction Stop
            $result.lengthBytes = $file.Length
        }

        $result.passed = $result.exists
    } catch {
        $result.error = $_.Exception.Message
        $result.passed = $false
    }

    return $result
}

function New-QuantumLinkWfpReferenceReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$ExitCode,

        [AllowEmptyCollection()]
        [string[]]$MatchingLines,

        [AllowNull()]
        [string]$Error
    )

    $result = [ordered]@{
        command = "netsh.exe"
        arguments = $Arguments
        exitCode = $ExitCode
        referenceCount = $MatchingLines.Count
        references = @()
        truncated = $false
        passed = $false
        error = $Error
    }

    $result.references = @(
        $MatchingLines |
            Select-Object -First $script:MaxCollectionItems |
            ForEach-Object { Limit-ValidationString -Value $_ }
    )
    $result.truncated = ($MatchingLines.Count -gt $script:MaxCollectionItems)
    $result.passed = (($ExitCode -eq 0) -and [string]::IsNullOrWhiteSpace($Error))

    if ((-not $result.passed) -and [string]::IsNullOrWhiteSpace($result.error)) {
        $result.error = "$Name query failed with exit code $ExitCode."
    }

    return $result
}

function Invoke-QuantumLinkWfpQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $native = Invoke-QuantumLinkNativeProcess -Command "netsh.exe" -Arguments $Arguments
    $output = @($native.output | ForEach-Object { [string]$_ })
    $matchingLines = @($output | Where-Object { $_ -match "QuantumLink" })

    $errorText = $native.error
    if ([string]::IsNullOrWhiteSpace($errorText) -and ($native.exitCode -ne 0)) {
        $errorLines = @(
            $output |
                Select-Object -First 10 |
                ForEach-Object { Limit-ValidationString -Value $_ }
        )
        $errorText = "$Name query failed. Output: $($errorLines -join ' | ')"
    }

    return [pscustomobject]@{
        Report = (New-QuantumLinkWfpReferenceReport `
            -Name $Name `
            -Arguments $Arguments `
            -ExitCode $native.exitCode `
            -MatchingLines $matchingLines `
            -Error $errorText)
        Lines = $output
    }
}

function Select-QuantumLinkWfpSublayerReferences {
    param(
        [Parameter(Mandatory = $true)]
        [object]$StateReport,

        [AllowEmptyCollection()]
        [string[]]$StateLines
    )

    $matchingLines = [System.Collections.ArrayList]::new()
    $lineCount = $StateLines.Count

    for ($index = 0; $index -lt $lineCount; $index++) {
        $line = [string]$StateLines[$index]
        if ($line -notmatch "QuantumLink") {
            continue
        }

        $start = [Math]::Max(0, $index - 5)
        $end = [Math]::Min($lineCount - 1, $index + 5)
        $window = @($StateLines[$start..$end] | ForEach-Object { [string]$_ })
        $hasSublayerContext = @($window | Where-Object { $_ -match "(?i)sublayer" }).Count -gt 0

        if ($hasSublayerContext) {
            foreach ($windowLine in $window) {
                if ($windowLine -match "QuantumLink") {
                    [void]$matchingLines.Add($windowLine)
                }
            }
        }
    }

    $dedupedLines = @($matchingLines | Select-Object -Unique)
    $report = New-QuantumLinkWfpReferenceReport `
        -Name "WFP sublayers" `
        -Arguments $StateReport.arguments `
        -ExitCode $StateReport.exitCode `
        -MatchingLines $dedupedLines `
        -Error $StateReport.error
    $report["source"] = "wfp.state"
    $report["selection"] = "QuantumLink references with nearby sublayer context"

    return $report
}

function Get-QuantumLinkNetworkSnapshot {
    $adapterSection = [ordered]@{
        command = "Get-NetAdapter"
        count = 0
        items = @()
        truncated = $false
        error = $null
    }
    $routeSection = [ordered]@{
        command = "Get-NetRoute"
        count = 0
        items = @()
        truncated = $false
        error = $null
    }
    $snapshot = [ordered]@{
        skipped = $false
        collectedAt = (Get-ValidationTimestamp)
        adapter = $adapterSection
        routes = $routeSection
        wfp = [ordered]@{
            filters = $null
            state = $null
            sublayers = $null
            totalReferenceCount = 0
        }
        passed = $true
    }

    try {
        $adapters = @(
            Get-NetAdapter -ErrorAction Stop |
                Where-Object {
                    ($_.Name -like "*QuantumLink*") -or
                    ($_.InterfaceDescription -like "*QuantumLink*")
                }
        )
        $adapterSection.count = $adapters.Count
        $adapterSection.items = @(
            $adapters |
                Select-Object -First $script:MaxCollectionItems |
                ForEach-Object {
                    [ordered]@{
                        name = $_.Name
                        interfaceDescription = $_.InterfaceDescription
                        status = $_.Status
                        macAddress = (ConvertTo-QuantumLinkEvidenceValue -Value $_.MacAddress -Include:$IncludeHostIdentifiers)
                        ifIndex = $_.ifIndex
                        linkSpeed = [string]$_.LinkSpeed
                    }
                }
        )
        $adapterSection.truncated = ($adapters.Count -gt $script:MaxCollectionItems)
    } catch {
        $adapterSection.error = $_.Exception.Message
        $snapshot.passed = $false
    }

    try {
        $routes = @(
            Get-NetRoute -ErrorAction Stop |
                Where-Object { $_.InterfaceAlias -like "*QuantumLink*" }
        )
        $routeSection.count = $routes.Count
        $routeSection.items = @(
            $routes |
                Select-Object -First $script:MaxCollectionItems |
                ForEach-Object {
                    [ordered]@{
                        destinationPrefix = $_.DestinationPrefix
                        interfaceAlias = $_.InterfaceAlias
                        ifIndex = $_.ifIndex
                        nextHop = $_.NextHop
                        routeMetric = $_.RouteMetric
                        protocol = [string]$_.Protocol
                        policyStore = $_.PolicyStore
                    }
                }
        )
        $routeSection.truncated = ($routes.Count -gt $script:MaxCollectionItems)
    } catch {
        $routeSection.error = $_.Exception.Message
        $snapshot.passed = $false
    }

    $filterQuery = Invoke-QuantumLinkWfpQuery -Name "WFP filters" -Arguments @("wfp", "show", "filters", "verbose=on")
    $stateQuery = Invoke-QuantumLinkWfpQuery -Name "WFP state" -Arguments @("wfp", "show", "state", "file=-")
    $sublayers = Select-QuantumLinkWfpSublayerReferences -StateReport $stateQuery.Report -StateLines $stateQuery.Lines
    $snapshot.wfp.filters = $filterQuery.Report
    $snapshot.wfp.state = $stateQuery.Report
    $snapshot.wfp.sublayers = $sublayers
    $snapshot.wfp.totalReferenceCount = $filterQuery.Report.referenceCount + $sublayers.referenceCount

    if ((-not $filterQuery.Report.passed) -or (-not $stateQuery.Report.passed) -or (-not $sublayers.passed)) {
        $snapshot.passed = $false
    }

    return $snapshot
}

function New-ResidualCheck {
    param(
        [switch]$Skipped,

        [AllowNull()]
        [bool]$Residual,

        [AllowNull()]
        [string]$Reason,

        [AllowNull()]
        [object]$Detail
    )

    $passed = $true
    if (-not $Skipped) {
        $passed = (-not $Residual)
    }

    return [ordered]@{
        skipped = [bool]$Skipped
        residual = $Residual
        passed = $passed
        reason = $Reason
        detail = $Detail
    }
}

function Add-ResidualFinding {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Items,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [AllowNull()]
        [object]$Detail
    )

    [void]$Items.Add([ordered]@{
        category = $Category
        message = $Message
        detail = $Detail
    })
}

function Test-QuantumLinkPathResidual {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Leaf", "Container")]
        [string]$PathType
    )

    $result = [ordered]@{
        path = $Path
        pathType = $PathType
        exists = $false
        error = $null
    }

    try {
        $result.exists = Test-Path -LiteralPath $Path -PathType $PathType
    } catch {
        $result.error = $_.Exception.Message
    }

    return $result
}

function Get-QuantumLinkResidualFindings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [string]$StatePath,

        [Parameter(Mandatory = $true)]
        [string]$UiExe,

        [AllowNull()]
        [object]$NetworkSnapshot,

        [switch]$NetworkSkipped
    )

    $items = [System.Collections.ArrayList]::new()
    $checks = [ordered]@{}

    $service = Get-QuantumLinkServiceValidation -Name $ServiceName
    $checks.service = New-ResidualCheck -Residual $service.exists -Detail $service
    if ($service.exists) {
        Add-ResidualFinding -Items $items -Category "service" -Message "Service remains after uninstall." -Detail $service
    } elseif (-not $service.passed) {
        Add-ResidualFinding -Items $items -Category "service" -Message "Service removal could not be verified." -Detail $service
        $checks.service.passed = $false
    }

    $uiResidual = Test-QuantumLinkPathResidual -Path $UiExe -PathType Leaf
    $checks.uiBinary = New-ResidualCheck -Residual $uiResidual.exists -Detail $uiResidual
    if ($uiResidual.exists) {
        Add-ResidualFinding -Items $items -Category "uiBinary" -Message "UI executable remains after uninstall." -Detail $uiResidual
    } elseif ($uiResidual.error) {
        Add-ResidualFinding -Items $items -Category "uiBinary" -Message "UI executable cleanup could not be verified." -Detail $uiResidual
        $checks.uiBinary.passed = $false
    }

    $stateResidual = Test-QuantumLinkPathResidual -Path $StatePath -PathType Container
    $checks.stateDirectory = New-ResidualCheck -Residual $stateResidual.exists -Detail $stateResidual
    if ($stateResidual.exists) {
        Add-ResidualFinding -Items $items -Category "stateDirectory" -Message "State directory remains after uninstall." -Detail $stateResidual
    } elseif ($stateResidual.error) {
        Add-ResidualFinding -Items $items -Category "stateDirectory" -Message "State directory cleanup could not be verified." -Detail $stateResidual
        $checks.stateDirectory.passed = $false
    }

    if ($NetworkSkipped) {
        $skipReason = "-SkipNetworkChecks supplied."
        $checks.adapter = New-ResidualCheck -Skipped -Residual $false -Reason $skipReason -Detail $null
        $checks.routes = New-ResidualCheck -Skipped -Residual $false -Reason $skipReason -Detail $null
        $checks.wfpReferences = New-ResidualCheck -Skipped -Residual $false -Reason $skipReason -Detail $null
    } else {
        $adapterResidual = ($NetworkSnapshot.adapter.count -gt 0)
        $routeResidual = ($NetworkSnapshot.routes.count -gt 0)
        $wfpResidual = ($NetworkSnapshot.wfp.totalReferenceCount -gt 0)

        $checks.adapter = New-ResidualCheck -Residual $adapterResidual -Detail $NetworkSnapshot.adapter
        $checks.routes = New-ResidualCheck -Residual $routeResidual -Detail $NetworkSnapshot.routes
        $checks.wfpReferences = New-ResidualCheck -Residual $wfpResidual -Detail $NetworkSnapshot.wfp

        if ($adapterResidual) {
            Add-ResidualFinding -Items $items -Category "adapter" -Message "QuantumLink adapter remains after uninstall." -Detail $NetworkSnapshot.adapter
        }
        if ($routeResidual) {
            Add-ResidualFinding -Items $items -Category "routes" -Message "QuantumLink routes remain after uninstall." -Detail $NetworkSnapshot.routes
        }
        if ($wfpResidual) {
            Add-ResidualFinding -Items $items -Category "wfpReferences" -Message "QuantumLink WFP references remain after uninstall." -Detail $NetworkSnapshot.wfp
        }
    }

    $passed = $true
    foreach ($property in $checks.GetEnumerator()) {
        if (-not $property.Value.passed) {
            $passed = $false
            break
        }
    }

    return [ordered]@{
        skipped = $false
        passed = $passed
        checks = $checks
        items = @($items)
    }
}

function Test-QuantumLinkInstallFootprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [string]$StatePath,

        [Parameter(Mandatory = $true)]
        [string]$UiExe
    )

    $service = Get-QuantumLinkServiceValidation -Name $ServiceName -ExpectPresent
    $stateDirectory = Get-QuantumLinkStateDirectoryValidation -Path $StatePath
    $uiBinary = Get-QuantumLinkUiBinaryValidation -Path $UiExe
    $passed = ($service.passed -and $stateDirectory.passed -and $uiBinary.passed)

    return [ordered]@{
        passed = $passed
        summary = "service=$($service.exists); stateDirectory=$($stateDirectory.exists); uiBinary=$($uiBinary.exists)"
        evidence = [ordered]@{
            service = $service
            stateDirectory = $stateDirectory
            uiBinary = $uiBinary
        }
    }
}

function Test-QuantumLinkResidualCleanup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [string]$StatePath,

        [Parameter(Mandatory = $true)]
        [string]$UiExe,

        [switch]$NetworkSkipped
    )

    if ($NetworkSkipped) {
        $networkSnapshot = New-SkippedValidationSection -Reason "-SkipNetworkChecks supplied."
    } else {
        $networkSnapshot = Get-QuantumLinkNetworkSnapshot
    }

    $residualFindings = Get-QuantumLinkResidualFindings `
        -ServiceName $ServiceName `
        -StatePath $StatePath `
        -UiExe $UiExe `
        -NetworkSnapshot $networkSnapshot `
        -NetworkSkipped:$NetworkSkipped

    $passed = $residualFindings.passed
    if (-not $NetworkSkipped) {
        $passed = ($passed -and $networkSnapshot.passed)
    }

    return [ordered]@{
        passed = $passed
        summary = "residualItems=$(@($residualFindings.items).Count)"
        evidence = [ordered]@{
            networkAfterUninstall = $networkSnapshot
            residualFindings = $residualFindings
        }
    }
}

function Wait-QuantumLinkValidation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [int]$IntervalSeconds,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )

    $boundedTimeoutSeconds = [Math]::Max(0, $TimeoutSeconds)
    $boundedIntervalSeconds = [Math]::Max(1, $IntervalSeconds)
    $deadline = (Get-Date).AddSeconds($boundedTimeoutSeconds)
    $attempts = @()
    $attemptCount = 0
    $attemptsTruncated = $false
    $timedOut = $false
    $lastEvaluation = $null
    $lastError = $null

    while ($true) {
        $attemptCount += 1
        $attemptAt = Get-ValidationTimestamp
        $attemptPassed = $false
        $attemptSummary = $null
        $lastError = $null

        try {
            $lastEvaluation = & $ScriptBlock
            $attemptPassed = [bool]$lastEvaluation.passed
            $attemptSummary = $lastEvaluation.summary
        } catch {
            $lastEvaluation = [ordered]@{
                passed = $false
                summary = "validation attempt failed"
                evidence = $null
            }
            $lastError = $_.Exception.Message
        }

        if ($attempts.Count -lt $script:MaxCollectionItems) {
            $attempts += [ordered]@{
                attempt = $attemptCount
                at = $attemptAt
                passed = $attemptPassed
                summary = $attemptSummary
                error = $lastError
            }
        } else {
            $attemptsTruncated = $true
        }

        if ($attemptPassed) {
            return [ordered]@{
                skipped = $false
                name = $Name
                passed = $true
                timedOut = $false
                timeoutSeconds = $boundedTimeoutSeconds
                intervalSeconds = $boundedIntervalSeconds
                attemptCount = $attemptCount
                attempts = @($attempts)
                attemptsTruncated = $attemptsTruncated
                evidence = $lastEvaluation.evidence
                error = $null
            }
        }

        if ((Get-Date) -ge $deadline) {
            $timedOut = $true
            break
        }

        $remainingSeconds = [Math]::Max(0, ($deadline - (Get-Date)).TotalSeconds)
        $sleepSeconds = [Math]::Min($boundedIntervalSeconds, $remainingSeconds)
        if ($sleepSeconds -gt 0) {
            Start-Sleep -Milliseconds ([int]([Math]::Ceiling($sleepSeconds * 1000)))
        }
    }

    return [ordered]@{
        skipped = $false
        name = $Name
        passed = $false
        timedOut = $timedOut
        timeoutSeconds = $boundedTimeoutSeconds
        intervalSeconds = $boundedIntervalSeconds
        attemptCount = $attemptCount
        attempts = @($attempts)
        attemptsTruncated = $attemptsTruncated
        evidence = $lastEvaluation.evidence
        error = $lastError
    }
}

function New-QuantumLinkBaseReport {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$RequiresElevation
    )

    return [ordered]@{
        schemaVersion = $script:SchemaVersion
        generatedAt = (Get-ValidationTimestamp)
        host = (Get-QuantumLinkHostSnapshot -IncludeIdentifiers:$IncludeHostIdentifiers)
        msi = [ordered]@{}
        elevation = [ordered]@{
            required = $RequiresElevation
            isAdministrator = (Test-QuantumLinkAdministrator)
        }
        install = (New-SkippedValidationSection -Reason "Not started.")
        service = (New-SkippedValidationSection -Reason "Not started.")
        stateDirectory = (New-SkippedValidationSection -Reason "Not started.")
        uiBinary = (New-SkippedValidationSection -Reason "Not started.")
        networkBeforeUninstall = (New-SkippedValidationSection -Reason "Not started.")
        installWait = (New-SkippedValidationSection -Reason "Not started.")
        uninstall = (New-SkippedValidationSection -Reason "Not started.")
        networkAfterUninstall = (New-SkippedValidationSection -Reason "Not started.")
        uninstallWait = (New-SkippedValidationSection -Reason "Not started.")
        residualFindings = (New-SkippedValidationSection -Reason "Not started.")
        failures = @()
        passed = $false
    }
}

function Write-QuantumLinkValidationReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedReportPath = Resolve-ValidationPath -Path $Path
    $reportDirectory = Split-Path -Parent $resolvedReportPath
    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    }

    $json = $Report | ConvertTo-Json -Depth 12
    Set-Content -LiteralPath $resolvedReportPath -Value $json -Encoding UTF8
}

function Complete-QuantumLinkValidation {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,

        [string[]]$Failures,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $Report.failures = @($Failures)
    $Report.passed = ($Failures.Count -eq 0)
    Write-QuantumLinkValidationReport -Report $Report -Path $OutputPath

    if ($Report.passed) {
        return 0
    }

    return 1
}

function New-QuantumLinkContractReport {
    $report = New-QuantumLinkBaseReport -RequiresElevation $false
    $reason = "-ContractOnly supplied."
    $report.msi = [ordered]@{
        skipped = $true
        required = $false
        path = $null
        resolvedPath = $null
        exists = $null
        sha256 = $null
        lengthBytes = $null
    }
    $report.install = New-SkippedValidationSection -Reason $reason
    $report.service = New-SkippedValidationSection -Reason $reason
    $report.stateDirectory = New-SkippedValidationSection -Reason $reason
    $report.uiBinary = New-SkippedValidationSection -Reason $reason
    $report.networkBeforeUninstall = New-SkippedValidationSection -Reason $reason
    $report.installWait = New-SkippedValidationSection -Reason $reason
    $report.uninstall = New-SkippedValidationSection -Reason $reason
    $report.networkAfterUninstall = New-SkippedValidationSection -Reason $reason
    $report.uninstallWait = New-SkippedValidationSection -Reason $reason
    $report.residualFindings = [ordered]@{
        skipped = $true
        passed = $true
        reason = $reason
        checks = [ordered]@{}
        items = @()
    }
    $report.passed = $true
    return $report
}

function Invoke-QuantumLinkInstallValidation {
    $requiresElevation = ((-not $SkipInstall) -or (-not $SkipUninstall)) -and (-not $ContractOnly)
    $report = New-QuantumLinkBaseReport -RequiresElevation $requiresElevation
    $failures = @()

    if ($ContractOnly) {
        $contractReport = New-QuantumLinkContractReport
        Write-QuantumLinkValidationReport -Report $contractReport -Path $ReportPath
        return 0
    }

    $report.msi = Get-QuantumLinkMsiSnapshot -Path $MsiPath
    if (-not $report.msi.exists) {
        $failures += $report.msi.error
        return Complete-QuantumLinkValidation -Report $report -Failures $failures -OutputPath $ReportPath
    }
    if ([string]::IsNullOrWhiteSpace($report.msi.sha256)) {
        $failures += "MSI SHA-256 could not be computed."
        return Complete-QuantumLinkValidation -Report $report -Failures $failures -OutputPath $ReportPath
    }

    if ($requiresElevation -and (-not $report.elevation.isAdministrator)) {
        $failures += "Administrator elevation is required for install/uninstall validation."
        return Complete-QuantumLinkValidation -Report $report -Failures $failures -OutputPath $ReportPath
    }

    if ($SkipInstall) {
        $report.install = New-SkippedValidationSection -Reason "-SkipInstall supplied."
    } else {
        $report.install = Invoke-QuantumLinkMsiExec -Action Install -Path $report.msi.resolvedPath
        if (-not $report.install.passed) {
            $failures += "Silent MSI install failed."
        }
    }

    $report.installWait = Wait-QuantumLinkValidation `
        -Name "Install footprint" `
        -TimeoutSeconds $SettleTimeoutSeconds `
        -IntervalSeconds $SettleIntervalSeconds `
        -ScriptBlock {
            Test-QuantumLinkInstallFootprint `
                -ServiceName $ExpectedServiceName `
                -StatePath $ExpectedStatePath `
                -UiExe $ExpectedUiExe
        }

    if ($null -ne $report.installWait.evidence) {
        $report.service = $report.installWait.evidence.service
        $report.stateDirectory = $report.installWait.evidence.stateDirectory
        $report.uiBinary = $report.installWait.evidence.uiBinary
    }

    if (-not $report.installWait.passed) {
        if ($report.installWait.timedOut) {
            $failures += "Install footprint did not settle within $($report.installWait.timeoutSeconds) seconds."
        } else {
            $failures += "Install footprint validation failed."
        }
    }

    if (-not $report.service.passed) {
        if ($report.service.exists) {
            $failures += "Expected service '$ExpectedServiceName' could not be validated."
        } else {
            $failures += "Expected service '$ExpectedServiceName' was not found."
        }
    }
    if (-not $report.stateDirectory.passed) {
        if (-not $report.stateDirectory.exists) {
            $failures += "Expected state directory '$ExpectedStatePath' was not found."
        } elseif ($report.stateDirectory.broadReadRisk) {
            $failures += "State directory '$ExpectedStatePath' has broad read ACL risk."
        } else {
            $failures += "State directory '$ExpectedStatePath' could not be validated."
        }
    }

    if (-not $report.uiBinary.passed) {
        $failures += "Expected UI executable '$ExpectedUiExe' was not found."
    }

    if ($SkipNetworkChecks) {
        $report.networkBeforeUninstall = New-SkippedValidationSection -Reason "-SkipNetworkChecks supplied."
    } else {
        $report.networkBeforeUninstall = Get-QuantumLinkNetworkSnapshot
        if (-not $report.networkBeforeUninstall.passed) {
            $failures += "Network snapshot before uninstall could not be fully collected."
        }
    }

    if ($SkipUninstall) {
        $report.uninstall = New-SkippedValidationSection -Reason "-SkipUninstall supplied."
        $report.networkAfterUninstall = New-SkippedValidationSection -Reason "-SkipUninstall supplied."
        $report.uninstallWait = New-SkippedValidationSection -Reason "-SkipUninstall supplied."
        $report.residualFindings = [ordered]@{
            skipped = $true
            passed = $true
            reason = "-SkipUninstall supplied."
            checks = [ordered]@{}
            items = @()
        }
        return Complete-QuantumLinkValidation -Report $report -Failures $failures -OutputPath $ReportPath
    }

    $report.uninstall = Invoke-QuantumLinkMsiExec -Action Uninstall -Path $report.msi.resolvedPath
    if (-not $report.uninstall.passed) {
        $failures += "Silent MSI uninstall failed."
    }

    $report.uninstallWait = Wait-QuantumLinkValidation `
        -Name "Uninstall cleanup" `
        -TimeoutSeconds $SettleTimeoutSeconds `
        -IntervalSeconds $SettleIntervalSeconds `
        -ScriptBlock {
            Test-QuantumLinkResidualCleanup `
                -ServiceName $ExpectedServiceName `
                -StatePath $ExpectedStatePath `
                -UiExe $ExpectedUiExe `
                -NetworkSkipped:$SkipNetworkChecks
        }

    if ($null -ne $report.uninstallWait.evidence) {
        $report.networkAfterUninstall = $report.uninstallWait.evidence.networkAfterUninstall
        $report.residualFindings = $report.uninstallWait.evidence.residualFindings
    }

    if ((-not $SkipNetworkChecks) -and (-not $report.networkAfterUninstall.passed)) {
        $failures += "Network snapshot after uninstall could not be fully collected."
    }

    if (-not $report.residualFindings.passed) {
        $failures += "Residual findings remain after uninstall."
    }
    if (-not $report.uninstallWait.passed) {
        if ($report.uninstallWait.timedOut) {
            $failures += "Uninstall cleanup did not settle within $($report.uninstallWait.timeoutSeconds) seconds."
        } else {
            $failures += "Uninstall cleanup validation failed."
        }
    }

    return Complete-QuantumLinkValidation -Report $report -Failures $failures -OutputPath $ReportPath
}

if ($MyInvocation.InvocationName -eq ".") {
    return
}

$scriptExitCode = Invoke-QuantumLinkInstallValidation
if ($scriptExitCode -ne 0) {
    exit 1
}

exit 0
