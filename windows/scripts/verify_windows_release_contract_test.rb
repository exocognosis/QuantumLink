# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "open3"
require "tmpdir"

class VerifyWindowsReleaseContractTest < Minitest::Test
  SCRIPT_PATH = File.expand_path("verify-windows-release.ps1", __dir__)

  REQUIRED_PARAMETERS = %w[
    ArtifactDirectory
    MsiPath
    ChecksumsPath
    WintunDllPath
    WintunLicensePath
    InstallValidationReportPath
    EvidencePath
    ExpectedPublisherSubject
    ExpectedPublisherThumbprint
    RequireValidSignature
    RequireTimestamp
    RequireInstallValidation
    ContractOnly
  ].freeze

  REQUIRED_EVIDENCE_KEYS = %w[
    schemaVersion
    generatedAt
    artifactDirectory
    msi
    checksums
    wintun
    installValidation
    failures
    passed
  ].freeze

  REQUIRED_MSI_KEYS = %w[
    path
    resolvedPath
    exists
    sha256
    lengthBytes
    signatureStatus
    signerSubject
    signerThumbprint
    timestampSubject
    signaturePassed
    timestampPassed
  ].freeze

  REQUIRED_CHECKSUM_KEYS = %w[
    path
    resolvedPath
    exists
    entries
    msiEntryFound
    msiHashMatched
    msiExpectedSha256
    msiActualSha256
    verified
    passed
  ].freeze

  REQUIRED_WINTUN_KEYS = %w[
    dll
    license
  ].freeze

  REQUIRED_INSTALL_VALIDATION_KEYS = %w[
    skipped
    required
    path
    reportPassed
    reportMsiSha256
    msiHashMatched
    schemaVersion
    error
  ].freeze

  def setup
    assert File.file?(SCRIPT_PATH), "expected #{SCRIPT_PATH} to exist"
    @script = File.read(SCRIPT_PATH)
  end

  def test_script_is_ascii_only
    assert @script.ascii_only?, "verify-windows-release.ps1 must stay ASCII-only"
  end

  def test_exposes_required_entrypoint_parameters_and_defaults
    REQUIRED_PARAMETERS.each do |parameter|
      assert_match(/\$#{Regexp.escape(parameter)}\b/, @script, "missing -#{parameter} parameter")
    end

    assert_match(/windows-release-evidence\.json/, @script)
    assert_match(/QuantumLink\*\.msi/, @script)
    assert_match(/SHA256SUMS\.txt/, @script)
    assert_match(/wintun\.dll/, @script)
    assert_match(/WINTUN-LICENSE\.txt/, @script)
    assert_match(/install-validation-report\.json/, @script)
  end

  def test_declares_required_json_evidence_contract
    REQUIRED_EVIDENCE_KEYS.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing evidence key #{key}")
    end

    REQUIRED_MSI_KEYS.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing msi key #{key}")
    end

    REQUIRED_CHECKSUM_KEYS.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing checksums key #{key}")
    end

    REQUIRED_WINTUN_KEYS.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing wintun key #{key}")
    end

    REQUIRED_INSTALL_VALIDATION_KEYS.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing installValidation key #{key}")
    end

    assert_match(/schemaVersion\s*=\s*\$script:SchemaVersion/, @script)
    assert_match(/ConvertTo-Json\s+-Depth\s+\d+/, @script)
  end

  def test_verifies_checksums_against_files_beside_checksum_manifest
    assert_match(/Get-Content\b[\s\S]*\$snapshot\.resolvedPath/, @script)
    assert_match(/Split-Path\s+-Parent\s+\$snapshot\.resolvedPath/, @script)
    assert_match(/Get-FileHash\b[\s\S]*-Algorithm\s+SHA256/, @script)
    assert_match(/\$entry\.expectedSha256/i, @script)
    assert_match(/\$entry\.actualSha256/i, @script)
    assert_match(/entriesTruncated/, @script)
    assert_match(/verified\s*=\s*\$verified/, @script)
  end

  def test_checksum_manifest_must_cover_selected_msi_artifact
    assert_match(/ExpectedMsiResolvedPath/, @script)
    assert_match(/ExpectedMsiSha256/, @script)
    assert_match(/msiEntryFound/, @script)
    assert_match(/msiHashMatched/, @script)
    assert_match(/msiExpectedSha256/, @script)
    assert_match(/msiActualSha256/, @script)
    assert_match(/Get-ChecksumManifestEvidence\s+-Path\s+\$ChecksumsPath\s+`\s*\n\s+-ExpectedMsiResolvedPath\s+\$msi\.resolvedPath\s+`\s*\n\s+-ExpectedMsiSha256\s+\$msi\.sha256/, @script)
    assert_match(/MSI artifact is not covered by SHA256SUMS\.txt/, @script)
    assert_match(/MSI checksum entry does not match the selected MSI SHA-256/, @script)
  end

  def test_verifies_authenticode_signature_policy_and_timestamp
    assert_match(/Get-AuthenticodeSignature\b/, @script)
    assert_match(/-LiteralPath\s+\$Path/, @script)
    assert_match(/RequireValidSignature/, @script)
    assert_match(/ExpectedPublisherSubject/, @script)
    assert_match(/ExpectedPublisherThumbprint/, @script)
    assert_match(/RequireTimestamp/, @script)
    assert_match(/signatureStatus/, @script)
    assert_match(/signerSubject/, @script)
    assert_match(/signerThumbprint/, @script)
    assert_match(/timestampSubject/, @script)
    assert_match(/signaturePassed/, @script)
    assert_match(/timestampPassed/, @script)
  end

  def test_expected_publisher_subject_uses_exact_normalized_match
    assert_match(/Normalize-AuthenticodeSubject/, @script)
    assert_match(/expectedSubject\s*=\s*Normalize-AuthenticodeSubject\s+-Subject\s+\$ExpectedPublisherSubject/, @script)
    assert_match(/actualSubject\s*=\s*Normalize-AuthenticodeSubject\s+-Subject\s+\$msi\.signerSubject/, @script)
    assert_match(/Equals\(\$expectedSubject,\s*\[System\.StringComparison\]::OrdinalIgnoreCase\)/, @script)
    refute_match(/signerSubject\.IndexOf\(\$ExpectedPublisherSubject/, @script)
  end

  def test_verifies_wintun_dll_signature_and_license_evidence
    assert_match(/WintunDllPath/, @script)
    assert_match(/WintunLicensePath/, @script)
    assert_match(/Get-ReleaseFileSnapshot\s+-Path\s+\$WintunDllPath/, @script)
    assert_match(/Get-AuthenticodeEvidence\s+-Path\s+\$dll\.resolvedPath/, @script)
    assert_match(/Get-ReleaseFileSnapshot\s+-Path\s+\$WintunLicensePath/, @script)
  end

  def test_parses_required_install_validation_report
    assert_match(/InstallValidationReportPath/, @script)
    assert_match(/RequireInstallValidation/, @script)
    assert_match(/ConvertFrom-Json\b/, @script)
    assert_match(/reportPassed/, @script)
    assert_match(/schemaVersion/, @script)
    assert_match(/passed\s*-eq\s+\$true/, @script)
  end

  def test_required_install_validation_report_must_match_selected_msi_hash
    assert_match(/Get-InstallValidationEvidence[\s\S]*\[string\]\$ExpectedMsiSha256/, @script)
    assert_match(/report\.msi\.sha256/, @script)
    assert_match(/reportMsiSha256/, @script)
    assert_match(/msiHashMatched/, @script)
    assert_match(/Install validation report MSI SHA-256 is missing/, @script)
    assert_match(/Install validation report MSI SHA-256 does not match the selected MSI/, @script)
    assert_match(/Get-InstallValidationEvidence\s+-Path\s+\$InstallValidationReportPath\s+`\s*\n\s+-Required:\$RequireInstallValidation\s+`\s*\n\s+-ExpectedMsiSha256\s+\$msi\.sha256/, @script)
  end

  def test_default_msi_discovery_fails_on_ambiguous_artifact_directory_matches
    assert_match(/Resolve-ReleaseDefaultPath[\s\S]*\[switch\]\$FailOnAmbiguousPattern/, @script)
    assert_match(/ambiguous/i, @script)
    assert_match(/QuantumLink\*\.msi matched multiple files/, @script)
    assert_match(/-FailOnAmbiguousPattern/, @script)
    assert_match(/defaultPathErrors/, @script)
    refute_match(/if \(\$matches\.Count -gt 0\)\s*\{\s*return \$matches\[0\]\.FullName\s*\}/, @script)
  end

  def test_exits_nonzero_when_required_gates_fail
    assert_match(/failures\s*=\s*@\(\$Failures\)/, @script)
    assert_match(/passed\s*=\s*\(\$Failures\.Count\s*-eq\s+0\)/, @script)
    assert_match(/exit\s+\$exitCode/, @script)
  end

  def test_contract_mode_emits_parseable_json_when_pwsh_is_available
    pwsh = find_executable("pwsh")
    skip "pwsh is not available in this environment" unless pwsh

    Dir.mktmpdir("qlink-release-contract") do |dir|
      evidence_path = File.join(dir, "evidence.json")
      stdout, stderr, status = Open3.capture3(
        pwsh,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        SCRIPT_PATH,
        "-ContractOnly",
        "-EvidencePath",
        evidence_path
      )

      assert status.success?, "expected contract mode to exit 0\nstdout=#{stdout}\nstderr=#{stderr}"
      assert File.file?(evidence_path), "expected evidence at #{evidence_path}"

      evidence = JSON.parse(File.read(evidence_path))
      REQUIRED_EVIDENCE_KEYS.each do |key|
        assert evidence.key?(key), "missing evidence key #{key}"
      end

      assert_equal "1.0", evidence.fetch("schemaVersion")
      assert_equal true, evidence.fetch("passed")
      assert_kind_of Hash, evidence.fetch("msi")
      assert_kind_of Hash, evidence.fetch("checksums")
      assert_kind_of Hash, evidence.fetch("wintun")
      assert_kind_of Hash, evidence.fetch("installValidation")
      assert_kind_of Array, evidence.fetch("failures")
    end
  end

  private

  def find_executable(name)
    ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
      candidate = File.join(dir, name)
      return candidate if File.executable?(candidate) && !File.directory?(candidate)
    end

    nil
  end
end
