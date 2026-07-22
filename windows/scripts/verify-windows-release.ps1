<#
.SYNOPSIS
Verifies QuantumLink Windows release artifact evidence.

.DESCRIPTION
Checks staged Windows release artifacts, Authenticode evidence, SHA-256
checksum manifests, Wintun DLL/license evidence, and optional install
validation evidence. The script always writes a bounded JSON evidence report.
#>

[CmdletBinding()]
param(
    [string]$ArtifactDirectory,
    [string]$MsiPath,
    [string]$ChecksumsPath,
    [string]$WintunDllPath,
    [string]$WintunLicensePath,
    [string]$SbomPath,
    [string]$ReleaseManifestPath,
    [string]$InstallValidationReportPath,
    [string]$EvidencePath = (Join-Path -Path (Get-Location).Path -ChildPath "windows-release-evidence.json"),
    [string]$ExpectedPublisherSubject,
    [string]$ExpectedPublisherThumbprint,
    [switch]$RequireValidSignature,
    [switch]$RequireTimestamp,
    [switch]$RequireSbom,
    [switch]$RequireReleaseManifest,
    [switch]$RequireInstallValidation,
    [switch]$ContractOnly
)

$ErrorActionPreference = "Stop"

$script:SchemaVersion = "1.0"
$script:MaxEvidenceItems = 100
$script:MaxChecksumEntriesToVerify = 1000
$script:MaxEvidenceStringLength = 300

function Get-ReleaseTimestamp {
    return (Get-Date).ToUniversalTime().ToString("o")
}

function Limit-ReleaseString {
    param(
        [AllowNull()]
        [object]$Value,

        [int]$MaxLength = $script:MaxEvidenceStringLength
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

function Resolve-ReleasePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location).Path -ChildPath $Path))
}

function Normalize-AuthenticodeSubject {
    param(
        [AllowNull()]
        [string]$Subject
    )

    if ([string]::IsNullOrWhiteSpace($Subject)) {
        return $null
    }

    return (([string]$Subject).Trim() -replace "\s+", " ")
}

function Get-ArtifactDirectorySnapshot {
    param(
        [AllowNull()]
        [string]$Path
    )

    $snapshot = [pscustomobject][ordered]@{
        path = $Path
        resolvedPath = $null
        exists = $null
        defaultPathErrors = @()
        error = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $snapshot
    }

    try {
        $snapshot.resolvedPath = Resolve-ReleasePath -Path $Path
        $snapshot.exists = Test-Path -LiteralPath $snapshot.resolvedPath -PathType Container
        if (-not $snapshot.exists) {
            $snapshot.error = "ArtifactDirectory was not found."
        }
    } catch {
        $snapshot.error = Limit-ReleaseString -Value $_.Exception.Message
        $snapshot.exists = $false
    }

    return $snapshot
}

function Resolve-ReleaseDefaultPath {
    param(
        [AllowNull()]
        [string]$ExplicitPath,

        [AllowNull()]
        [string]$ArtifactRoot,

        [AllowNull()]
        [string]$Pattern,

        [AllowNull()]
        [string[]]$Candidates,

        [switch]$FailOnAmbiguousPattern
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        return [pscustomobject][ordered]@{
            path = $ExplicitPath
            error = $null
            ambiguousMatches = @()
        }
    }

    if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
        return [pscustomobject][ordered]@{
            path = $null
            error = $null
            ambiguousMatches = @()
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Pattern)) {
        if (Test-Path -LiteralPath $ArtifactRoot -PathType Container) {
            $matches = @(
                Get-ChildItem -LiteralPath $ArtifactRoot -File -Filter $Pattern -ErrorAction Stop |
                    Sort-Object -Property Name
            )

            if ($matches.Count -gt 1 -and $FailOnAmbiguousPattern) {
                return [pscustomobject][ordered]@{
                    path = $null
                    error = "QuantumLink*.msi matched multiple files in ArtifactDirectory. Pass -MsiPath explicitly."
                    ambiguousMatches = @($matches | Select-Object -First $script:MaxEvidenceItems | ForEach-Object { $_.FullName })
                }
            }

            if ($matches.Count -eq 1) {
                return [pscustomobject][ordered]@{
                    path = ($matches | Select-Object -First 1).FullName
                    error = $null
                    ambiguousMatches = @()
                }
            }
        }
    }

    foreach ($candidate in @($Candidates)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $candidatePath = Join-Path -Path $ArtifactRoot -ChildPath $candidate
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            return [pscustomobject][ordered]@{
                path = $candidatePath
                error = $null
                ambiguousMatches = @()
            }
        }
    }

    if ($Candidates.Count -gt 0) {
        return [pscustomobject][ordered]@{
            path = (Join-Path -Path $ArtifactRoot -ChildPath $Candidates[0])
            error = $null
            ambiguousMatches = @()
        }
    }

    return [pscustomobject][ordered]@{
        path = $null
        error = $null
        ambiguousMatches = @()
    }
}

function Get-ReleaseFileSnapshot {
    param(
        [AllowNull()]
        [string]$Path,

        [string]$MissingMessage = "File path is required."
    )

    $snapshot = [pscustomobject][ordered]@{
        path = $Path
        resolvedPath = $null
        exists = $false
        sha256 = $null
        lengthBytes = $null
        signatureStatus = $null
        signerSubject = $null
        signerThumbprint = $null
        timestampSubject = $null
        signaturePassed = $false
        timestampPassed = $false
        error = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $snapshot.error = $MissingMessage
        return $snapshot
    }

    try {
        $snapshot.resolvedPath = Resolve-ReleasePath -Path $Path
        $snapshot.exists = Test-Path -LiteralPath $snapshot.resolvedPath -PathType Leaf

        if (-not $snapshot.exists) {
            $snapshot.error = "File was not found."
            return $snapshot
        }

        $file = Get-Item -LiteralPath $snapshot.resolvedPath -ErrorAction Stop
        $snapshot.lengthBytes = $file.Length
        $snapshot.sha256 = (Get-FileHash -LiteralPath $snapshot.resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    } catch {
        $snapshot.error = Limit-ReleaseString -Value $_.Exception.Message
    }

    return $snapshot
}

function Get-ReleaseJsonEvidence {
    param(
        [AllowNull()]
        [string]$Path,

        [string]$MissingMessage = "JSON file path is required."
    )

    $snapshot = Get-ReleaseFileSnapshot -Path $Path -MissingMessage $MissingMessage
    Add-Member -InputObject $snapshot -NotePropertyName parsed -NotePropertyValue $false
    Add-Member -InputObject $snapshot -NotePropertyName schemaVersion -NotePropertyValue $null
    Add-Member -InputObject $snapshot -NotePropertyName spdxVersion -NotePropertyValue $null

    if (-not $snapshot.exists) {
        return $snapshot
    }

    try {
        $json = Get-Content -LiteralPath $snapshot.resolvedPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $snapshot.parsed = $true
        if ($null -ne $json.PSObject.Properties["schemaVersion"]) {
            $snapshot.schemaVersion = Limit-ReleaseString -Value $json.schemaVersion
        }
        if ($null -ne $json.PSObject.Properties["spdxVersion"]) {
            $snapshot.spdxVersion = Limit-ReleaseString -Value $json.spdxVersion
        }
    } catch {
        $snapshot.error = Limit-ReleaseString -Value $_.Exception.Message
    }

    return $snapshot
}

function Get-AuthenticodeEvidence {
    param(
        [AllowNull()]
        [string]$Path
    )

    $evidence = [pscustomobject][ordered]@{
        signatureStatus = $null
        signerSubject = $null
        signerThumbprint = $null
        timestampSubject = $null
        signaturePassed = $false
        timestampPassed = $false
        error = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $evidence.error = "File path is required for Authenticode inspection."
        return $evidence
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $evidence.error = "File was not found for Authenticode inspection."
        return $evidence
    }

    try {
        $signatureCommand = Get-Command -Name Get-AuthenticodeSignature -ErrorAction Stop
        if ($signatureCommand.Parameters.ContainsKey("LiteralPath")) {
            $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        } else {
            $signature = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        }
        $evidence.signatureStatus = Limit-ReleaseString -Value $signature.Status
        $evidence.signaturePassed = ([string]$signature.Status -eq "Valid")

        if ($null -ne $signature.SignerCertificate) {
            $evidence.signerSubject = Limit-ReleaseString -Value $signature.SignerCertificate.Subject
            $evidence.signerThumbprint = Limit-ReleaseString -Value $signature.SignerCertificate.Thumbprint
        }

        $timestampCertificate = $null
        if ($null -ne $signature.PSObject.Properties["TimeStamperCertificate"]) {
            $timestampCertificate = $signature.TimeStamperCertificate
        } elseif ($null -ne $signature.PSObject.Properties["TimestampCertificate"]) {
            $timestampCertificate = $signature.TimestampCertificate
        }

        if ($null -ne $timestampCertificate) {
            $evidence.timestampSubject = Limit-ReleaseString -Value $timestampCertificate.Subject
            $evidence.timestampPassed = $true
        }
    } catch {
        $evidence.signatureStatus = "Unavailable"
        $evidence.error = Limit-ReleaseString -Value $_.Exception.Message
    }

    return $evidence
}

function Add-AuthenticodeEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Snapshot,

        [Parameter(Mandatory = $true)]
        [object]$Signature
    )

    $Snapshot.signatureStatus = $Signature.signatureStatus
    $Snapshot.signerSubject = $Signature.signerSubject
    $Snapshot.signerThumbprint = $Signature.signerThumbprint
    $Snapshot.timestampSubject = $Signature.timestampSubject
    $Snapshot.signaturePassed = $Signature.signaturePassed
    $Snapshot.timestampPassed = $Signature.timestampPassed

    if ([string]::IsNullOrWhiteSpace($Snapshot.error) -and -not [string]::IsNullOrWhiteSpace($Signature.error)) {
        $Snapshot.error = $Signature.error
    }

    return $Snapshot
}

function Test-PathInsideDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullDirectory = [System.IO.Path]::GetFullPath($Directory)
    $trimmedDirectory = $fullDirectory.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )

    if ($fullPath.Equals($trimmedDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $directoryPrefix = $trimmedDirectory + [System.IO.Path]::DirectorySeparatorChar
    $alternatePrefix = $trimmedDirectory + [System.IO.Path]::AltDirectorySeparatorChar

    return (
        $fullPath.StartsWith($directoryPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($alternatePrefix, [System.StringComparison]::OrdinalIgnoreCase)
    )
}

function Get-ChecksumManifestEvidence {
    param(
        [AllowNull()]
        [string]$Path,

        [AllowNull()]
        [string]$ExpectedMsiResolvedPath,

        [AllowNull()]
        [string]$ExpectedMsiSha256
    )

    $file = Get-ReleaseFileSnapshot -Path $Path -MissingMessage "ChecksumsPath is required."
    $snapshot = [pscustomobject][ordered]@{
        path = $file.path
        resolvedPath = $file.resolvedPath
        exists = $file.exists
        entries = @()
        entriesTruncated = $false
        msiEntryFound = $false
        msiHashMatched = $false
        msiExpectedSha256 = $null
        msiActualSha256 = $null
        verified = 0
        passed = $false
        error = $file.error
    }

    if (-not $snapshot.exists) {
        return $snapshot
    }

    $entries = @()
    $verified = 0
    $failed = 0
    $expectedMsiPath = $null
    $expectedMsiHash = $null

    if (-not [string]::IsNullOrWhiteSpace($ExpectedMsiResolvedPath)) {
        $expectedMsiPath = [System.IO.Path]::GetFullPath($ExpectedMsiResolvedPath)
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedMsiSha256)) {
        $expectedMsiHash = $ExpectedMsiSha256.ToLowerInvariant()
        $snapshot.msiActualSha256 = $expectedMsiHash
    }

    try {
        $manifestDirectory = Split-Path -Parent $snapshot.resolvedPath
        $lines = @(Get-Content -LiteralPath $snapshot.resolvedPath -ErrorAction Stop)

        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            if ($verified -ge $script:MaxChecksumEntriesToVerify) {
                $failed += 1
                $snapshot.error = "Checksum manifest exceeds the maximum verification entry count."
                break
            }

            $verified += 1
            $entry = [pscustomobject][ordered]@{
                index = $verified
                path = $null
                resolvedPath = $null
                exists = $false
                expectedSha256 = $null
                actualSha256 = $null
                passed = $false
                error = $null
            }

            if ($line -notmatch "^\s*([A-Fa-f0-9]{64})\s+[* ]?(.+?)\s*$") {
                $entry.error = "Invalid SHA256SUMS line format."
                $failed += 1
            } else {
                $entry.expectedSha256 = $Matches[1].ToLowerInvariant()
                $entryPath = $Matches[2].Trim()
                $entry.path = Limit-ReleaseString -Value $entryPath

                try {
                    if ([System.IO.Path]::IsPathRooted($entryPath)) {
                        $candidatePath = [System.IO.Path]::GetFullPath($entryPath)
                    } else {
                        $candidatePath = [System.IO.Path]::GetFullPath((Join-Path -Path $manifestDirectory -ChildPath $entryPath))
                    }

                    $entry.resolvedPath = $candidatePath

                    if (-not (Test-PathInsideDirectory -Path $candidatePath -Directory $manifestDirectory)) {
                        $entry.error = "Checksum entry resolves outside checksum directory."
                        $failed += 1
                    } elseif (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
                        $entry.error = "Checksum entry file was not found."
                        $failed += 1
                    } else {
                        $entry.exists = $true
                        $entry.actualSha256 = (Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
                        if ($entry.actualSha256 -eq $entry.expectedSha256) {
                            $entry.passed = $true
                        } else {
                            $entry.error = "Checksum mismatch."
                            $failed += 1
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($expectedMsiPath) -and
                        $candidatePath.Equals($expectedMsiPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $snapshot.msiEntryFound = $true
                        $snapshot.msiExpectedSha256 = $entry.expectedSha256
                        $snapshot.msiHashMatched = (
                            -not [string]::IsNullOrWhiteSpace($expectedMsiHash) -and
                            $entry.expectedSha256.Equals($expectedMsiHash, [System.StringComparison]::OrdinalIgnoreCase)
                        )
                    }
                } catch {
                    $entry.error = Limit-ReleaseString -Value $_.Exception.Message
                    $failed += 1
                }
            }

            if ($entries.Count -lt $script:MaxEvidenceItems) {
                $entries += $entry
            } else {
                $snapshot.entriesTruncated = $true
            }
        }

        if ($verified -eq 0) {
            $failed += 1
            $snapshot.error = "Checksum manifest contains no entries."
        }

        if (-not [string]::IsNullOrWhiteSpace($expectedMsiPath) -and -not [string]::IsNullOrWhiteSpace($expectedMsiHash)) {
            if (-not $snapshot.msiEntryFound) {
                $failed += 1
                $snapshot.error = "MSI artifact is not covered by SHA256SUMS.txt."
            } elseif (-not $snapshot.msiHashMatched) {
                $failed += 1
                $snapshot.error = "MSI checksum entry does not match the selected MSI SHA-256."
            }
        }
    } catch {
        $snapshot.error = Limit-ReleaseString -Value $_.Exception.Message
        $failed += 1
    }

    $snapshot.entries = @($entries)
    $snapshot.verified = $verified
    $snapshot.passed = ($snapshot.exists -and $verified -gt 0 -and $failed -eq 0)

    return $snapshot
}

function Get-InstallValidationEvidence {
    param(
        [AllowNull()]
        [string]$Path,

        [switch]$Required,

        [AllowNull()]
        [string]$ExpectedMsiSha256
    )

    $snapshot = [pscustomobject][ordered]@{
        skipped = (-not $Required)
        required = [bool]$Required
        path = $Path
        resolvedPath = $null
        exists = $false
        reportPassed = $null
        reportMsiSha256 = $null
        msiHashMatched = $null
        schemaVersion = $null
        error = $null
    }

    if (-not $Required) {
        if (-not [string]::IsNullOrWhiteSpace($Path)) {
            try {
                $snapshot.resolvedPath = Resolve-ReleasePath -Path $Path
                $snapshot.exists = Test-Path -LiteralPath $snapshot.resolvedPath -PathType Leaf
            } catch {
                $snapshot.error = Limit-ReleaseString -Value $_.Exception.Message
            }
        }

        return $snapshot
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $snapshot.error = "InstallValidationReportPath is required when -RequireInstallValidation is supplied."
        return $snapshot
    }

    try {
        $snapshot.resolvedPath = Resolve-ReleasePath -Path $Path
        $snapshot.exists = Test-Path -LiteralPath $snapshot.resolvedPath -PathType Leaf

        if (-not $snapshot.exists) {
            $snapshot.error = "Install validation report was not found."
            return $snapshot
        }

        $report = Get-Content -LiteralPath $snapshot.resolvedPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $report.PSObject.Properties["schemaVersion"]) {
            $snapshot.schemaVersion = Limit-ReleaseString -Value $report.schemaVersion
        }

        $reportPassed = ($report.passed -eq $true)
        $snapshot.reportPassed = $reportPassed
        if (-not $reportPassed) {
            $snapshot.error = "Install validation report did not pass."
        }

        $reportMsiSha256 = $null
        if ($null -ne $report.PSObject.Properties["msi"] -and
            $null -ne $report.msi -and
            $null -ne $report.msi.PSObject.Properties["sha256"]) {
            $reportMsiSha256 = ([string]$report.msi.sha256).Trim()
        }

        if ([string]::IsNullOrWhiteSpace($reportMsiSha256)) {
            $snapshot.reportMsiSha256 = $null
            $snapshot.msiHashMatched = $false
            $snapshot.error = "Install validation report MSI SHA-256 is missing."
        } else {
            $snapshot.reportMsiSha256 = Limit-ReleaseString -Value $reportMsiSha256.ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($ExpectedMsiSha256)) {
                $snapshot.msiHashMatched = $false
                $snapshot.error = "Selected MSI SHA-256 is unavailable for install validation report comparison."
            } else {
                $snapshot.msiHashMatched = $reportMsiSha256.Equals($ExpectedMsiSha256, [System.StringComparison]::OrdinalIgnoreCase)
                if (-not $snapshot.msiHashMatched) {
                    $snapshot.error = "Install validation report MSI SHA-256 does not match the selected MSI."
                }
            }
        }
    } catch {
        $snapshot.error = Limit-ReleaseString -Value $_.Exception.Message
    }

    return $snapshot
}

function New-ReleaseBaseEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ArtifactDirectoryEvidence
    )

    return [pscustomobject][ordered]@{
        schemaVersion = $script:SchemaVersion
        generatedAt = (Get-ReleaseTimestamp)
        artifactDirectory = $ArtifactDirectoryEvidence
        msi = [ordered]@{}
        checksums = [ordered]@{}
        wintun = [ordered]@{
            dll = [ordered]@{}
            license = [ordered]@{}
        }
        sbom = [ordered]@{}
        releaseManifest = [ordered]@{}
        releaseSummary = [ordered]@{}
        installValidation = [ordered]@{}
        failures = @()
        passed = $false
    }
}

function New-ReleaseContractEvidence {
    $reason = "-ContractOnly supplied."
    return [pscustomobject][ordered]@{
        schemaVersion = $script:SchemaVersion
        generatedAt = (Get-ReleaseTimestamp)
        artifactDirectory = [ordered]@{
            skipped = $true
            path = $ArtifactDirectory
            resolvedPath = $null
            exists = $null
            defaultPathErrors = @()
            reason = $reason
        }
        msi = [ordered]@{
            skipped = $true
            path = $MsiPath
            resolvedPath = $null
            exists = $null
            sha256 = $null
            lengthBytes = $null
            signatureStatus = $null
            signerSubject = $null
            signerThumbprint = $null
            timestampSubject = $null
            signaturePassed = $true
            timestampPassed = $true
            reason = $reason
        }
        checksums = [ordered]@{
            skipped = $true
            path = $ChecksumsPath
            resolvedPath = $null
            exists = $null
            entries = @()
            entriesTruncated = $false
            msiEntryFound = $null
            msiHashMatched = $null
            msiExpectedSha256 = $null
            msiActualSha256 = $null
            verified = 0
            passed = $true
            reason = $reason
        }
        wintun = [ordered]@{
            dll = [ordered]@{
                skipped = $true
                path = $WintunDllPath
                resolvedPath = $null
                exists = $null
                sha256 = $null
                lengthBytes = $null
                signatureStatus = $null
                signerSubject = $null
                signerThumbprint = $null
                signaturePassed = $true
                reason = $reason
            }
            license = [ordered]@{
                skipped = $true
                path = $WintunLicensePath
                resolvedPath = $null
                exists = $null
                sha256 = $null
                lengthBytes = $null
                reason = $reason
            }
        }
        sbom = [ordered]@{
            skipped = $true
            path = $SbomPath
            resolvedPath = $null
            exists = $null
            sha256 = $null
            lengthBytes = $null
            parsed = $true
            schemaVersion = $null
            spdxVersion = "SPDX-2.3"
            reason = $reason
        }
        releaseManifest = [ordered]@{
            skipped = $true
            path = $ReleaseManifestPath
            resolvedPath = $null
            exists = $null
            sha256 = $null
            lengthBytes = $null
            parsed = $true
            schemaVersion = "1.0"
            spdxVersion = $null
            reason = $reason
        }
        releaseSummary = [ordered]@{
            signed = $true
            timestamped = $true
            msiArchitecture = "x64"
            publisher = $null
            wintunDllPassed = $true
            checksumsPassed = $true
            sbomExists = $true
            releaseManifestExists = $true
        }
        installValidation = [ordered]@{
            skipped = $true
            required = [bool]$RequireInstallValidation
            path = $InstallValidationReportPath
            resolvedPath = $null
            exists = $null
            reportPassed = $null
            reportMsiSha256 = $null
            msiHashMatched = $null
            schemaVersion = $null
            error = $null
            reason = $reason
        }
        failures = @()
        passed = $true
    }
}

function Write-ReleaseEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedEvidencePath = Resolve-ReleasePath -Path $Path
    $evidenceDirectory = Split-Path -Parent $resolvedEvidencePath
    if (-not (Test-Path -LiteralPath $evidenceDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    }

    $json = $Evidence | ConvertTo-Json -Depth 12
    Set-Content -LiteralPath $resolvedEvidencePath -Value $json -Encoding UTF8
}

function Complete-ReleaseEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence,

        [string[]]$Failures,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $Evidence.failures = @($Failures)
    $Evidence.passed = ($Failures.Count -eq 0)
    Write-ReleaseEvidence -Evidence $Evidence -Path $OutputPath

    if ($Evidence.passed) {
        return 0
    }

    return 1
}

function Invoke-ReleaseVerification {
    if ($ContractOnly) {
        $contractEvidence = New-ReleaseContractEvidence
        Write-ReleaseEvidence -Evidence $contractEvidence -Path $EvidencePath
        return 0
    }

    $artifactDirectoryEvidence = Get-ArtifactDirectorySnapshot -Path $ArtifactDirectory
    $artifactRoot = $artifactDirectoryEvidence.resolvedPath
    $failures = @()
    $defaultPathErrors = @()

    if (-not [string]::IsNullOrWhiteSpace($ArtifactDirectory) -and -not $artifactDirectoryEvidence.exists) {
        $failures += $artifactDirectoryEvidence.error
    }

    $msiPathEvidence = Resolve-ReleaseDefaultPath `
        -ExplicitPath $MsiPath `
        -ArtifactRoot $artifactRoot `
        -Pattern "QuantumLink*.msi" `
        -Candidates @("QuantumLink.msi") `
        -FailOnAmbiguousPattern
    $MsiPath = $msiPathEvidence.path
    if (-not [string]::IsNullOrWhiteSpace($msiPathEvidence.error)) {
        $defaultPathErrors += $msiPathEvidence.error
    }

    $checksumsPathEvidence = Resolve-ReleaseDefaultPath `
        -ExplicitPath $ChecksumsPath `
        -ArtifactRoot $artifactRoot `
        -Candidates @("SHA256SUMS.txt")
    $ChecksumsPath = $checksumsPathEvidence.path
    if (-not [string]::IsNullOrWhiteSpace($checksumsPathEvidence.error)) {
        $defaultPathErrors += $checksumsPathEvidence.error
    }

    $wintunDllPathEvidence = Resolve-ReleaseDefaultPath `
        -ExplicitPath $WintunDllPath `
        -ArtifactRoot $artifactRoot `
        -Candidates @("wintun.dll", "wintun\bin\amd64\wintun.dll")
    $WintunDllPath = $wintunDllPathEvidence.path
    if (-not [string]::IsNullOrWhiteSpace($wintunDllPathEvidence.error)) {
        $defaultPathErrors += $wintunDllPathEvidence.error
    }

    $wintunLicensePathEvidence = Resolve-ReleaseDefaultPath `
        -ExplicitPath $WintunLicensePath `
        -ArtifactRoot $artifactRoot `
        -Candidates @("WINTUN-LICENSE.txt", "LICENSE.txt")
    $WintunLicensePath = $wintunLicensePathEvidence.path
    if (-not [string]::IsNullOrWhiteSpace($wintunLicensePathEvidence.error)) {
        $defaultPathErrors += $wintunLicensePathEvidence.error
    }

    $sbomPathEvidence = Resolve-ReleaseDefaultPath `
        -ExplicitPath $SbomPath `
        -ArtifactRoot $artifactRoot `
        -Candidates @("windows-sbom.spdx.json", "sbom.spdx.json")
    $SbomPath = $sbomPathEvidence.path
    if (-not [string]::IsNullOrWhiteSpace($sbomPathEvidence.error)) {
        $defaultPathErrors += $sbomPathEvidence.error
    }

    $releaseManifestPathEvidence = Resolve-ReleaseDefaultPath `
        -ExplicitPath $ReleaseManifestPath `
        -ArtifactRoot $artifactRoot `
        -Candidates @("windows-release-manifest.json", "release-manifest.json")
    $ReleaseManifestPath = $releaseManifestPathEvidence.path
    if (-not [string]::IsNullOrWhiteSpace($releaseManifestPathEvidence.error)) {
        $defaultPathErrors += $releaseManifestPathEvidence.error
    }

    if ($RequireInstallValidation -or -not [string]::IsNullOrWhiteSpace($InstallValidationReportPath)) {
        $installValidationPathEvidence = Resolve-ReleaseDefaultPath `
            -ExplicitPath $InstallValidationReportPath `
            -ArtifactRoot $artifactRoot `
            -Candidates @("install-validation-report.json")
        $InstallValidationReportPath = $installValidationPathEvidence.path
        if (-not [string]::IsNullOrWhiteSpace($installValidationPathEvidence.error)) {
            $defaultPathErrors += $installValidationPathEvidence.error
        }
    }

    $artifactDirectoryEvidence.defaultPathErrors = @($defaultPathErrors)
    $failures += @($defaultPathErrors)

    $evidence = New-ReleaseBaseEvidence -ArtifactDirectoryEvidence $artifactDirectoryEvidence

    $msi = Get-ReleaseFileSnapshot -Path $MsiPath -MissingMessage "MsiPath is required."
    if ($msi.exists) {
        $msiSignature = Get-AuthenticodeEvidence -Path $msi.resolvedPath
        $msi = Add-AuthenticodeEvidence -Snapshot $msi -Signature $msiSignature
    }
    $evidence.msi = $msi

    if (-not $msi.exists) {
        $failures += "MSI file was not found."
    } elseif ([string]::IsNullOrWhiteSpace($msi.sha256)) {
        $failures += "MSI SHA-256 could not be computed."
    }

    if ($RequireValidSignature -and $msi.signatureStatus -ne "Valid") {
        $failures += "MSI Authenticode signature is required to be Valid."
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublisherSubject)) {
        $expectedSubject = Normalize-AuthenticodeSubject -Subject $ExpectedPublisherSubject
        $actualSubject = Normalize-AuthenticodeSubject -Subject $msi.signerSubject
        if ([string]::IsNullOrWhiteSpace($actualSubject) -or -not $actualSubject.Equals($expectedSubject, [System.StringComparison]::OrdinalIgnoreCase)) {
            $failures += "MSI signer subject does not exactly match the expected publisher subject."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublisherThumbprint)) {
        if ([string]::IsNullOrWhiteSpace($msi.signerThumbprint) -or -not $msi.signerThumbprint.Equals($ExpectedPublisherThumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
            $failures += "MSI signer thumbprint does not match the expected publisher thumbprint."
        }
    }

    if ($RequireTimestamp -and -not $msi.timestampPassed) {
        $failures += "MSI signature timestamp is required but no timestamp certificate evidence was found."
    }

    $checksums = Get-ChecksumManifestEvidence -Path $ChecksumsPath `
        -ExpectedMsiResolvedPath $msi.resolvedPath `
        -ExpectedMsiSha256 $msi.sha256
    $evidence.checksums = $checksums
    if (-not $checksums.passed) {
        $failures += "SHA256SUMS.txt verification failed."
    }
    if ($msi.exists -and $checksums.exists) {
        if (-not $checksums.msiEntryFound) {
            $failures += "MSI artifact is not covered by SHA256SUMS.txt."
        } elseif (-not $checksums.msiHashMatched) {
            $failures += "MSI checksum entry does not match the selected MSI SHA-256."
        }
    }

    $dll = Get-ReleaseFileSnapshot -Path $WintunDllPath -MissingMessage "WintunDllPath is required."
    if ($dll.exists) {
        $dllSignature = Get-AuthenticodeEvidence -Path $dll.resolvedPath
        $dll = Add-AuthenticodeEvidence -Snapshot $dll -Signature $dllSignature
    }

    $license = Get-ReleaseFileSnapshot -Path $WintunLicensePath -MissingMessage "WintunLicensePath is required."
    $evidence.wintun = [ordered]@{
        dll = $dll
        license = $license
    }

    if (-not $dll.exists) {
        $failures += "Wintun DLL was not found."
    } elseif ($RequireValidSignature -and $dll.signatureStatus -ne "Valid") {
        $failures += "Wintun DLL Authenticode signature is required to be Valid."
    }

    if (-not $license.exists) {
        $failures += "Wintun license was not found."
    }

    $sbom = Get-ReleaseJsonEvidence -Path $SbomPath -MissingMessage "SbomPath is required."
    $evidence.sbom = $sbom
    if ($RequireSbom) {
        if (-not $sbom.exists) {
            $failures += "SBOM is required."
        } elseif (-not $sbom.parsed) {
            $failures += "SBOM JSON could not be parsed."
        }
    }

    $releaseManifest = Get-ReleaseJsonEvidence -Path $ReleaseManifestPath -MissingMessage "ReleaseManifestPath is required."
    $evidence.releaseManifest = $releaseManifest
    if ($RequireReleaseManifest) {
        if (-not $releaseManifest.exists) {
            $failures += "Release manifest is required."
        } elseif (-not $releaseManifest.parsed) {
            $failures += "Release manifest JSON could not be parsed."
        }
    }

    $installValidation = Get-InstallValidationEvidence -Path $InstallValidationReportPath `
        -Required:$RequireInstallValidation `
        -ExpectedMsiSha256 $msi.sha256
    $evidence.installValidation = $installValidation
    if ($RequireInstallValidation) {
        if (-not $installValidation.reportPassed) {
            $failures += "Install validation report is required to have passed."
        }
        if ($installValidation.exists) {
            if ([string]::IsNullOrWhiteSpace($installValidation.reportMsiSha256)) {
                $failures += "Install validation report MSI SHA-256 is missing."
            } elseif (-not $installValidation.msiHashMatched) {
                $failures += "Install validation report MSI SHA-256 does not match the selected MSI."
            }
        }
    }

    $evidence.releaseSummary = [ordered]@{
        signed = ($msi.signatureStatus -eq "Valid")
        timestamped = [bool]$msi.timestampPassed
        msiArchitecture = "x64"
        publisher = $msi.signerSubject
        wintunDllPassed = ($dll.exists -and (-not $RequireValidSignature -or $dll.signatureStatus -eq "Valid"))
        checksumsPassed = ($checksums.passed -and $checksums.msiEntryFound -and $checksums.msiHashMatched)
        sbomExists = [bool]$sbom.exists
        releaseManifestExists = [bool]$releaseManifest.exists
    }

    return Complete-ReleaseEvidence -Evidence $evidence -Failures $failures -OutputPath $EvidencePath
}

$exitCode = Invoke-ReleaseVerification
exit $exitCode
