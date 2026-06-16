# frozen_string_literal: true

require "minitest/autorun"

class ValidateInstallContractTest < Minitest::Test
  SCRIPT_PATH = File.expand_path("validate-install.ps1", __dir__)

  REQUIRED_PARAMETERS = %w[
    MsiPath
    ReportPath
    SkipInstall
    SkipUninstall
    SkipNetworkChecks
    ExpectedServiceName
    ExpectedStatePath
    ExpectedUiExe
  ].freeze

  REQUIRED_REPORT_KEYS = %w[
    schemaVersion
    generatedAt
    host
    msi
    elevation
    install
    service
    stateDirectory
    uiBinary
    networkBeforeUninstall
    uninstall
    networkAfterUninstall
    residualFindings
    passed
  ].freeze

  def setup
    assert File.file?(SCRIPT_PATH), "expected #{SCRIPT_PATH} to exist"
    @script = File.read(SCRIPT_PATH)
  end

  def test_script_is_ascii_only
    assert @script.ascii_only?, "validate-install.ps1 must stay ASCII-only"
  end

  def test_exposes_required_entrypoint_parameters_and_defaults
    REQUIRED_PARAMETERS.each do |parameter|
      assert_match(/\$#{Regexp.escape(parameter)}\b/, @script, "missing -#{parameter} parameter")
    end

    assert_match(/\$ExpectedServiceName\s*=\s*"QuantumLinkService"/, @script)
    assert_match(/\$ExpectedStatePath\s*=\s*"C:\\ProgramData\\QuantumLink"/, @script)
    assert_match(/\$ExpectedUiExe\s*=\s*"C:\\Program Files\\QuantumLink\\QuantumLink\.Windows\.exe"/, @script)
    assert_match(/quantumlink-install-validation-report\.json/, @script)
    assert_match(/\$ContractOnly\b/, @script, "expected an explicit contract/dry mode")
  end

  def test_declares_required_json_report_contract
    REQUIRED_REPORT_KEYS.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing report key #{key}")
    end

    assert_match(/ConvertTo-Json\s+-Depth\s+\d+/, @script)
  end

  def test_covers_install_uninstall_hash_and_exit_contract
    assert_match(/Get-FileHash\b[\s\S]*-Algorithm\s+SHA256/, @script)
    assert_match(/msiexec\.exe/, @script)
    assert_match(/"\/i"/, @script)
    assert_match(/"\/x"/, @script)
    assert_match(/"\/qn"/, @script)
    assert_match(/"\/norestart"/, @script)
    assert_match(/exit\s+1/, @script)
  end

  def test_covers_windows_footprint_and_network_snapshots
    assert_match(/Get-CimInstance\b[\s\S]*Win32_Service/, @script)
    assert_match(/Get-Acl\b/, @script)
    assert_match(/S-1-1-0/, @script, "must check Everyone ACL")
    assert_match(/S-1-5-32-545/, @script, "must check Users ACL")
    assert_match(/S-1-5-11/, @script, "must check Authenticated Users ACL")
    assert_match(/Get-NetAdapter\b/, @script)
    assert_match(/Get-NetRoute\b/, @script)
    assert_match(/netsh\.exe/, @script)
    assert_match(/wfp"\s*,\s*"show"\s*,\s*"filters"\s*,\s*"file=-"/, @script)
    assert_match(/wfp"\s*,\s*"show"\s*,\s*"state"\s*,\s*"file=-"/, @script)
  end
end
