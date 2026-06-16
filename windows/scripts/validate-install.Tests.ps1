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
