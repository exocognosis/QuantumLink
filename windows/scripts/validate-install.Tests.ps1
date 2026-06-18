$script:ValidateInstallScript = Join-Path $PSScriptRoot "validate-install.ps1"

BeforeAll {
    . $script:ValidateInstallScript
}

Describe "Test-QuantumLinkBroadReadAce" {
    It "flags Everyone read access" {
        $ace = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0"),
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $result = Test-QuantumLinkBroadReadAce -Ace $ace

        $result.IsBroadReadRisk | Should -BeTrue
        $result.IdentitySid | Should -Be "S-1-1-0"
    }

    It "flags BUILTIN Users full control access" {
        $ace = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-545"),
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $result = Test-QuantumLinkBroadReadAce -Ace $ace

        $result.IsBroadReadRisk | Should -BeTrue
        $result.IdentitySid | Should -Be "S-1-5-32-545"
    }

    It "ignores denied broad read access" {
        $ace = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11"),
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.AccessControlType]::Deny
        )

        $result = Test-QuantumLinkBroadReadAce -Ace $ace

        $result.IsBroadReadRisk | Should -BeFalse
    }

    It "ignores Administrators full control access" {
        $ace = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544"),
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $result = Test-QuantumLinkBroadReadAce -Ace $ace

        $result.IsBroadReadRisk | Should -BeFalse
    }
}

Describe "New-SkippedValidationSection" {
    It "returns an explicit skipped validation result" {
        $result = New-SkippedValidationSection -Reason "manual skip"

        $result.skipped | Should -BeTrue
        $result.passed | Should -BeTrue
        $result.reason | Should -Be "manual skip"
    }
}

Describe "New-SkippedMsiSnapshot" {
    It "includes bounded metadata fields without collecting MSI metadata" {
        $result = New-SkippedMsiSnapshot -Reason "not requested" -Path "previous.msi"

        $result.skipped | Should -BeTrue
        $result.required | Should -BeFalse
        $result.path | Should -Be "previous.msi"
        $result.productName | Should -BeNullOrEmpty
        $result.manufacturer | Should -BeNullOrEmpty
        $result.productVersion | Should -BeNullOrEmpty
        $result.productCode | Should -BeNullOrEmpty
        $result.upgradeCode | Should -BeNullOrEmpty
        $result.packageCode | Should -BeNullOrEmpty
        $result.metadataError | Should -BeNullOrEmpty
    }
}

Describe "Upgrade and rollback report constructors" {
    It "creates skipped upgrade evidence with required keys" {
        $result = New-QuantumLinkUpgradeReport -Reason "not requested"

        $result.skipped | Should -BeTrue
        $result.passed | Should -BeTrue
        $result.baselineInstall.skipped | Should -BeTrue
        $result.baselineInstallWait.skipped | Should -BeTrue
        $result.networkBeforeUpgrade.skipped | Should -BeTrue
        $result.upgradeInstall.skipped | Should -BeTrue
        $result.upgradeWait.skipped | Should -BeTrue
        $result.networkAfterUpgrade.skipped | Should -BeTrue
        $result.footprintContinuity.skipped | Should -BeTrue
        @($result.failures).Count | Should -Be 0
    }

    It "creates skipped rollback evidence with required keys and mode" {
        $result = New-QuantumLinkRollbackReport -Reason "not requested" -Mode "DirectDowngrade"

        $result.skipped | Should -BeTrue
        $result.passed | Should -BeTrue
        $result.mode | Should -Be "DirectDowngrade"
        $result.uninstallBeforeRollback.skipped | Should -BeTrue
        $result.cleanupWait.skipped | Should -BeTrue
        $result.rollbackInstall.skipped | Should -BeTrue
        $result.rollbackWait.skipped | Should -BeTrue
        $result.networkAfterRollback.skipped | Should -BeTrue
        $result.footprintContinuity.skipped | Should -BeTrue
        @($result.failures).Count | Should -Be 0
    }
}

Describe "New-QuantumLinkFootprintContinuityReport" {
    It "passes when before and after waits validate the state directory" {
        $before = [pscustomobject]@{
            passed = $true
            evidence = [pscustomobject]@{
                service = [pscustomobject]@{ exists = $true }
                stateDirectory = [pscustomobject]@{ exists = $true }
                uiBinary = [pscustomobject]@{ exists = $true }
            }
        }
        $after = [pscustomobject]@{
            passed = $true
            evidence = [pscustomobject]@{
                service = [pscustomobject]@{ exists = $true }
                stateDirectory = [pscustomobject]@{ exists = $true }
                uiBinary = [pscustomobject]@{ exists = $true }
            }
        }

        $result = New-QuantumLinkFootprintContinuityReport `
            -BeforeWait $before `
            -AfterWait $after `
            -BeforeLabel "Baseline" `
            -AfterLabel "Upgrade"

        $result.skipped | Should -BeFalse
        $result.passed | Should -BeTrue
        @($result.failures).Count | Should -Be 0
    }

    It "fails when after wait does not validate the state directory" {
        $before = [pscustomobject]@{
            passed = $true
            evidence = [pscustomobject]@{
                service = [pscustomobject]@{ exists = $true }
                stateDirectory = [pscustomobject]@{ exists = $true }
                uiBinary = [pscustomobject]@{ exists = $true }
            }
        }
        $after = [pscustomobject]@{
            passed = $false
            evidence = [pscustomobject]@{
                service = [pscustomobject]@{ exists = $true }
                stateDirectory = [pscustomobject]@{ exists = $false }
                uiBinary = [pscustomobject]@{ exists = $true }
            }
        }

        $result = New-QuantumLinkFootprintContinuityReport `
            -BeforeWait $before `
            -AfterWait $after `
            -BeforeLabel "Baseline" `
            -AfterLabel "Upgrade"

        $result.skipped | Should -BeFalse
        $result.passed | Should -BeFalse
        @($result.failures).Count | Should -BeGreaterThan 0
    }
}
