# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "open3"
require "tmpdir"

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
    SettleTimeoutSeconds
    SettleIntervalSeconds
    IncludeHostIdentifiers
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

  def test_service_existence_check_does_not_require_running_state
    assert_match(/\$service\s*=\s*Get-QuantumLinkServiceValidation\s+-Name\s+\$ServiceName\s+-ExpectPresent\b/, @script)
    refute_match(/Get-QuantumLinkServiceValidation[^\n]*-RequireRunning/, @script)
    refute_match(/exists but is not running/, @script)
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
    assert_match(/wfp"\s*,\s*"show"\s*,\s*"filters"\s*,\s*"verbose=on"/, @script)
    assert_match(/wfp"\s*,\s*"show"\s*,\s*"state"\s*,\s*"file=-"/, @script)
    assert_match(/sublayers\s*=\s*\$null/, @script)
    assert_match(/Select-QuantumLinkWfpSublayerReferences/, @script)
    refute_match(/\$sublayers\s*=\s*Get-QuantumLinkWfpReferences\s+-Name\s+"WFP sublayers"/, @script)
    assert_match(/\$snapshot\.wfp\.sublayers\s*=\s*\$sublayers/, @script)
    assert_match(/\$filterQuery\.Report\.referenceCount\s*\+\s*\$sublayers\.referenceCount/, @script)
  end

  def test_install_and_uninstall_checks_are_bounded_by_settle_polling
    assert_match(/\[int\]\$SettleTimeoutSeconds\s*=\s*\d+/, @script)
    assert_match(/\[int\]\$SettleIntervalSeconds\s*=\s*\d+/, @script)
    assert_match(/function Wait-QuantumLinkValidation\b/, @script)
    assert_match(/attempts\s*=\s*@\(\)/, @script)
    assert_match(/timedOut\s*=\s*\$false/, @script)
    assert_match(/\$report\.installWait\s*=/, @script)
    assert_match(/\$report\.uninstallWait\s*=/, @script)
  end

  def test_redacts_host_identifiers_and_adapter_mac_addresses_by_default
    assert_match(/\[switch\]\$IncludeHostIdentifiers/, @script)
    assert_match(/computerName\s*=\s*\(ConvertTo-QuantumLinkEvidenceValue/, @script)
    assert_match(/userName\s*=\s*\(ConvertTo-QuantumLinkEvidenceValue/, @script)
    assert_match(/macAddress\s*=\s*\(ConvertTo-QuantumLinkEvidenceValue/, @script)
  end

  def test_contract_mode_emits_parseable_json_when_pwsh_is_available
    pwsh = find_executable("pwsh")
    skip "pwsh is not available in this environment" unless pwsh

    Dir.mktmpdir("qlink-contract") do |dir|
      report_path = File.join(dir, "report.json")
      stdout, stderr, status = Open3.capture3(
        pwsh,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        SCRIPT_PATH,
        "-ContractOnly",
        "-ReportPath",
        report_path
      )

      assert status.success?, "expected contract mode to exit 0\nstdout=#{stdout}\nstderr=#{stderr}"
      assert File.file?(report_path), "expected report at #{report_path}"

      report = JSON.parse(File.read(report_path))
      REQUIRED_REPORT_KEYS.each do |key|
        assert report.key?(key), "missing report key #{key}"
      end

      assert_equal "1.0", report.fetch("schemaVersion")
      assert_equal true, report.fetch("passed")
      assert_kind_of Hash, report.fetch("host")
      assert_kind_of Hash, report.fetch("elevation")
      assert_kind_of Hash, report.fetch("residualFindings")
      assert_kind_of Array, report.fetch("failures")
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
