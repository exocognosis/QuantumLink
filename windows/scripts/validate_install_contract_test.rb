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
    UpgradeFromMsiPath
    ValidateRollback
    RollbackToMsiPath
    RollbackMode
  ].freeze

  REQUIRED_REPORT_KEYS = %w[
    schemaVersion
    generatedAt
    scenario
    host
    msi
    upgradeFromMsi
    rollbackToMsi
    elevation
    install
    service
    stateDirectory
    uiBinary
    networkBeforeUninstall
    upgrade
    rollback
    uninstall
    networkAfterUninstall
    residualFindings
    warnings
    failures
    passed
  ].freeze

  REQUIRED_MSI_SNAPSHOT_KEYS = %w[
    productName
    manufacturer
    productVersion
    productCode
    upgradeCode
    packageCode
    metadataError
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
    assert_match(/\[ValidateSet\("UninstallReinstall",\s*"DirectDowngrade"\)\]\s*\[string\]\$RollbackMode\s*=\s*"UninstallReinstall"/, @script)
    assert_match(/quantumlink-install-validation-report\.json/, @script)
    assert_match(/\$ContractOnly\b/, @script, "expected an explicit contract/dry mode")
  end

  def test_declares_required_json_report_contract
    REQUIRED_REPORT_KEYS.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing report key #{key}")
    end

    assert_match(/\$script:SchemaVersion\s*=\s*"1\.1"/, @script)
    assert_match(/ConvertTo-Json\s+-Depth\s+16\b/, @script)
  end

  def test_msi_snapshots_include_bounded_installer_metadata
    REQUIRED_MSI_SNAPSHOT_KEYS.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing MSI snapshot key #{key}")
    end

    assert_match(/WindowsInstaller\.Installer/, @script)
    assert_match(/ProductCode/, @script)
    assert_match(/UpgradeCode/, @script)
    assert_match(/PackageCode/, @script)
    assert_match(/metadataError/, @script)
  end

  def test_upgrade_and_rollback_report_sections_cover_required_evidence
    upgrade_keys = %w[
      skipped
      passed
      baselineInstall
      baselineInstallWait
      baselineInstalledProduct
      networkBeforeUpgrade
      upgradeInstall
      upgradeWait
      upgradeInstalledProduct
      baselineProductAbsent
      networkAfterUpgrade
      footprintContinuity
      failures
    ]
    rollback_keys = %w[
      skipped
      passed
      mode
      uninstallBeforeRollback
      cleanupWait
      rollbackInstall
      rollbackWait
      rollbackInstalledProduct
      upgradedProductAbsent
      networkAfterRollback
      footprintContinuity
      failures
    ]

    upgrade_keys.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing upgrade evidence key #{key}")
    end
    rollback_keys.each do |key|
      assert_match(/#{Regexp.escape(key)}/, @script, "missing rollback evidence key #{key}")
    end
  end

  def test_upgrade_and_rollback_static_sequencing_is_opt_in
    assert_match(/if\s*\(\[string\]::IsNullOrWhiteSpace\(\$UpgradeFromMsiPath\)\)/, @script)
    assert_match(/Invoke-QuantumLinkUpgradeValidation/, @script)
    assert_match(/Invoke-QuantumLinkRollbackValidation/, @script)
    assert_match(/\$rollbackTargetPath\s*=\s*\$RollbackToMsiPath/, @script)
    assert_match(/\$rollbackTargetPath\s*=\s*\$UpgradeFromMsiPath/, @script)
    assert_match(/switch\s*\(\$RollbackMode\)/, @script)
    assert_match(/"UninstallReinstall"/, @script)
    assert_match(/"DirectDowngrade"/, @script)
    report_ref = /\$(?:report|Report)/
    assert_match(/Invoke-QuantumLinkMsiExec\s+-Action\s+Install\s+-Path\s+#{report_ref}\.upgradeFromMsi\.resolvedPath[\s\S]*Invoke-QuantumLinkMsiExec\s+-Action\s+Install\s+-Path\s+#{report_ref}\.msi\.resolvedPath/, @script)
    assert_match(/Invoke-QuantumLinkMsiExec\s+-Action\s+Uninstall[\s\S]*Invoke-QuantumLinkMsiExec\s+-Action\s+Install\s+-Path\s+#{report_ref}\.rollbackToMsi\.resolvedPath/, @script)
  end

  def test_candidate_upgrade_requires_baseline_install_and_footprint_success
    assert_match(/\$baselineReadyForUpgrade\s*=\s*\(\$upgrade\.baselineInstall\.passed\s+-and\s+\$upgrade\.baselineInstallWait\.passed\s+-and\s+\$upgrade\.baselineInstalledProduct\.passed\)/, @script)
    assert_match(/if\s*\(\$baselineReadyForUpgrade\)\s*\{[\s\S]*Invoke-QuantumLinkMsiExec\s+-Action\s+Install\s+-Path\s+\$Report\.msi\.resolvedPath/, @script)
    refute_match(/if\s*\(\$upgrade\.baselineInstallWait\.passed\)\s*\{[\s\S]*Invoke-QuantumLinkMsiExec\s+-Action\s+Install\s+-Path\s+\$Report\.msi\.resolvedPath/, @script)
  end

  def test_upgrade_and_rollback_validate_installed_product_identity
    assert_match(/function Get-QuantumLinkInstalledProductIdentity\b/, @script)
    assert_match(/ProductState/, @script)
    assert_match(/ProductInfo/, @script)
    assert_match(/VersionString/, @script)
    assert_match(/productStateInstalled/, @script)
    assert_match(/installed product version does not match the expected MSI ProductVersion/, @script)
    assert_match(/\$upgrade\.baselineInstalledProduct\s*=\s*Get-QuantumLinkInstalledProductIdentity\s+`[\s\S]*-ExpectedMsi\s+\$Report\.upgradeFromMsi/, @script)
    assert_match(/\$upgrade\.upgradeInstalledProduct\s*=\s*Get-QuantumLinkInstalledProductIdentity\s+`[\s\S]*-ExpectedMsi\s+\$Report\.msi/, @script)
    assert_match(/\$rollback\.rollbackInstalledProduct\s*=\s*Get-QuantumLinkInstalledProductIdentity\s+`[\s\S]*-ExpectedMsi\s+\$Report\.rollbackToMsi/, @script)
  end

  def test_upgrade_and_rollback_validate_replaced_product_absence
    assert_match(/function Get-QuantumLinkInstalledProductAbsence\b/, @script)
    assert_match(/replaced-product absence is not applicable/, @script)
    assert_match(/replaced product is still installed/, @script)
    assert_match(/\$upgrade\.baselineProductAbsent\s*=\s*Get-QuantumLinkInstalledProductAbsence\s+`[\s\S]*-ExpectedAbsentMsi\s+\$Report\.upgradeFromMsi\s+`[\s\S]*-ExpectedInstalledMsi\s+\$Report\.msi/, @script)
    assert_match(/\$rollback\.upgradedProductAbsent\s*=\s*Get-QuantumLinkInstalledProductAbsence\s+`[\s\S]*-ExpectedAbsentMsi\s+\$Report\.msi\s+`[\s\S]*-ExpectedInstalledMsi\s+\$Report\.rollbackToMsi/, @script)
  end

  def test_continuity_report_uses_honest_footprint_naming
    assert_match(/New-QuantumLinkFootprintContinuityReport/, @script)
    assert_match(/footprintContinuity/, @script)
    refute_match(/stateContinuity/, @script)
    refute_match(/StateContinuity/, @script)
  end

  def test_rollback_promotion_requires_a_real_rollback_attempt
    assert_match(/\$rollbackAttempted\s*=\s*\(\$ValidateRollback\s+-and\s+\$report\.upgrade\.passed\s+-and\s+\(-not\s+\$report\.upgrade\.skipped\)\)/, @script)
    assert_match(/if\s*\(\$rollbackAttempted\)\s*\{[\s\S]*Invoke-QuantumLinkRollbackValidation/, @script)
    assert_match(/if\s*\(-not\s+\$report\.rollback\.skipped\)\s*\{[\s\S]*\$report\.install\s*=\s*\$report\.rollback\.rollbackInstall/, @script)
  end

  def test_final_cleanup_can_skip_msi_uninstall_when_current_product_known_absent
    assert_match(/\[switch\]\$CurrentProductKnownAbsent/, @script)
    assert_match(/if\s*\(\$CurrentProductKnownAbsent\)\s*\{[\s\S]*No product is currently installed[\s\S]*New-SkippedValidationSection/, @script)
    assert_match(/-CurrentProductKnownAbsent:\$currentProductKnownAbsent/, @script)
  end

  def test_upgrade_and_rollback_results_track_last_attempted_install_msi
    assert_match(/LastAttemptedInstallMsiPath\s*=\s*\$lastAttemptedInstallMsiPath/, @script)
    assert_match(/\$lastAttemptedInstallMsiPath\s*=\s*\$Report\.upgradeFromMsi\.resolvedPath[\s\S]*\$upgrade\.baselineInstall\s*=\s*Invoke-QuantumLinkMsiExec\s+-Action\s+Install\s+-Path\s+\$Report\.upgradeFromMsi\.resolvedPath/, @script)
    assert_match(/\$lastAttemptedInstallMsiPath\s*=\s*\$Report\.rollbackToMsi\.resolvedPath[\s\S]*\$rollback\.rollbackInstall\s*=\s*Invoke-QuantumLinkMsiExec\s+-Action\s+Install\s+-Path\s+\$Report\.rollbackToMsi\.resolvedPath/, @script)
    assert_match(/\$finalCleanupMsiPath\s*=\s*\$currentInstalledMsiPath[\s\S]*\$finalCleanupMsiPath\s*=\s*\$lastAttemptedInstallMsiPath[\s\S]*-InstalledMsiPath\s+\$finalCleanupMsiPath/, @script)
  end

  def test_rollback_install_attempt_makes_current_absence_unknown
    assert_match(/\$currentProductKnownAbsent\s*=\s*\$true[\s\S]*\$lastAttemptedInstallMsiPath\s*=\s*\$Report\.rollbackToMsi\.resolvedPath[\s\S]*\$currentProductKnownAbsent\s*=\s*\$false[\s\S]*\$rollback\.rollbackInstall\s*=\s*Invoke-QuantumLinkMsiExec\s+-Action\s+Install\s+-Path\s+\$Report\.rollbackToMsi\.resolvedPath/, @script)
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

  def test_unhandled_startup_errors_still_write_a_validation_report
    assert_match(/function New-QuantumLinkUnhandledValidationReport\b/, @script)
    assert_match(/scenario\s*=\s*"bootstrapFailure"/, @script)
    assert_match(/unhandledError\s*=\s*\[ordered\]@\{/, @script)
    assert_match(/function Write-QuantumLinkUnhandledValidationReport\b/, @script)
    assert_match(/try\s*\{\s*\$scriptExitCode\s*=\s*Invoke-QuantumLinkInstallValidation\s*\}\s*catch\s*\{[\s\S]*Write-QuantumLinkUnhandledValidationReport\s+-ErrorRecord\s+\$_\s+-Path\s+\$ReportPath[\s\S]*Unhandled install validation error:/, @script)
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

  def test_residual_finding_collector_accepts_empty_collections
    assert_match(/function Add-ResidualFinding\b[\s\S]*\[Parameter\(Mandatory = \$true\)\]\s*\[AllowEmptyCollection\(\)\]\s*\[System\.Collections\.ArrayList\]\$Items/, @script)
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

      assert_equal "1.1", report.fetch("schemaVersion")
      assert_equal true, report.fetch("passed")
      assert_kind_of Hash, report.fetch("host")
      assert_kind_of Hash, report.fetch("elevation")
      assert_kind_of Hash, report.fetch("upgrade")
      assert_kind_of Hash, report.fetch("rollback")
      assert_kind_of Hash, report.fetch("residualFindings")
      assert_equal "cleanInstall", report.fetch("scenario")
      assert_equal true, report.fetch("upgrade").fetch("skipped")
      assert_equal true, report.fetch("rollback").fetch("skipped")
      assert_kind_of Array, report.fetch("warnings")
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
