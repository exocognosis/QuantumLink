# frozen_string_literal: true

require "minitest/autorun"
require "rexml/document"
require "yaml"

class WindowsReleaseWorkflowContractTest < Minitest::Test
  REPO_ROOT = File.expand_path("../..", __dir__)
  WORKFLOW_PATH = File.join(REPO_ROOT, ".github/workflows/windows-release.yml")
  RUNBOOK_PATH = File.join(REPO_ROOT, "windows/docs/beta-runbook-windows.md")
  INSTALLER_README_PATH = File.join(REPO_ROOT, "windows/installer/README.md")
  INSTALLER_WXS_PATH = File.join(REPO_ROOT, "windows/installer/QuantumLink.wxs")
  BUILD_SCRIPT_PATH = File.join(REPO_ROOT, "windows/scripts/build-windows.ps1")
  OPERATOR_CHECKLIST_PATH = File.join(REPO_ROOT, "docs/release-operator-checklist.md")

  SCRIPT_PATH = ".\\windows\\scripts\\validate-install.ps1"
  VERIFY_SCRIPT_PATH = ".\\windows\\scripts\\verify-windows-release.ps1"
  MSI_PATH = ".\\windows\\QuantumLink.msi"
  REPORT_PATH = ".\\windows\\build\\validation\\install-validation-report.json"
  EVIDENCE_PATH = ".\\windows\\build\\release\\windows-release-evidence.json"
  ARTIFACT_REPORT_PATH = "windows/build/validation/install-validation-report.json"
  ARTIFACT_EVIDENCE_PATH = "windows/build/release/windows-release-evidence.json"
  ARTIFACT_NAME = "QuantumLink-Windows-InstallValidation-${{ github.run_number }}"

  def setup
    @workflow = File.read(WORKFLOW_PATH)
    @workflow_yaml = YAML.load_file(WORKFLOW_PATH)
    @runbook = File.read(RUNBOOK_PATH)
    @installer_readme = File.read(INSTALLER_README_PATH)
    @installer_wxs = File.read(INSTALLER_WXS_PATH)
    @build_script = File.read(BUILD_SCRIPT_PATH)
    @operator_checklist = File.read(OPERATOR_CHECKLIST_PATH)
  end

  def test_installer_source_is_well_formed_xml
    REXML::Document.new(@installer_wxs)
  end

  def test_installer_state_directory_acl_uses_wix_supported_permissions
    refute_match(/<CreateFolder\b[^>]*\bDisableInheritance=/, @installer_wxs)
    assert_match(/<CreateFolder>\s*<util:PermissionEx User="SYSTEM" GenericAll="yes" \/>\s*<util:PermissionEx User="Administrators" GenericAll="yes" \/>\s*<\/CreateFolder>/m, @installer_wxs)
  end

  def test_workflow_declares_manual_install_validation_inputs
    inputs = workflow_dispatch_inputs

    run_install_validation = inputs.fetch("run_install_validation")
    assert_match(/installs\/uninstalls the generated MSI.*uploads JSON evidence/i, run_install_validation.fetch("description"))
    assert_equal "boolean", run_install_validation.fetch("type")
    assert_equal false, run_install_validation.fetch("default")

    skip_network_checks = inputs.fetch("skip_validation_network_checks")
    assert_match(/skips adapter\/route\/WFP evidence.*validate-install\.ps1/i, skip_network_checks.fetch("description"))
    assert_equal "boolean", skip_network_checks.fetch("type")
    assert_equal false, skip_network_checks.fetch("default")
  end

  def test_workflow_declares_manual_publisher_and_upgrade_validation_inputs
    inputs = workflow_dispatch_inputs

    {
      "expected_publisher_subject" => "string",
      "expected_publisher_thumbprint" => "string",
      "upgrade_from_msi_url" => "string",
      "upgrade_from_msi_sha256" => "string",
      "rollback_to_msi_url" => "string",
      "rollback_to_msi_sha256" => "string"
    }.each do |input_name, input_type|
      input = inputs.fetch(input_name)
      assert_equal input_type, input.fetch("type")
      assert_equal "", input.fetch("default")
    end

    validate_rollback = inputs.fetch("validate_rollback")
    assert_equal "boolean", validate_rollback.fetch("type")
    assert_equal false, validate_rollback.fetch("default")

    rollback_mode = inputs.fetch("rollback_mode")
    assert_equal "choice", rollback_mode.fetch("type")
    assert_equal "UninstallReinstall", rollback_mode.fetch("default")
    assert_equal %w[UninstallReinstall DirectDowngrade], rollback_mode.fetch("options")
  end

  def test_workflow_runs_validate_install_script_for_manual_opt_in
    step = workflow_step("Validate MSI install and uninstall")
    run = step.fetch("run")

    assert_equal "github.event_name == 'workflow_dispatch' && inputs.run_install_validation", step.fetch("if")
    assert_equal "pwsh", step.fetch("shell")
    assert_equal "${{ inputs.skip_validation_network_checks }}", step.fetch("env").fetch("SKIP_VALIDATION_NETWORK_CHECKS")
    assert_includes run, "windows\\build\\validation"
    assert_includes run, SCRIPT_PATH
    assert_in_order run, [
      '"-MsiPath"',
      "\"#{MSI_PATH}\"",
      '"-ReportPath"',
      "\"#{REPORT_PATH}\""
    ]
    assert_in_order run, [
      "$env:SKIP_VALIDATION_NETWORK_CHECKS -eq \"true\"",
      '$arguments += "-SkipNetworkChecks"'
    ]
  end

  def test_workflow_pins_wix_tool_and_extension_versions
    env = @workflow_yaml.fetch("jobs").fetch("build").fetch("env")
    step = workflow_step("Install WiX")
    run = step.fetch("run")

    assert_equal "6.0.2", env.fetch("WIX_VERSION")
    assert_includes run, "dotnet tool install --global wix --version $env:WIX_VERSION"
    assert_includes run, 'wix extension add -g "$env:WIX_EXTENSION/$env:WIX_VERSION"'
    assert_includes run, "wix extension list -g"
    assert_includes @build_script, '$wixUtilExtension = "WixToolset.Util.wixext/$wixVersion"'
    assert_includes @build_script, '$wixUtilExtension,'
    refute_includes run, "dotnet tool install --global wix\n"
    refute_includes run, "wix extension add -g $env:WIX_EXTENSION\n"
    refute_includes run, "wix extension list\n"
  end

  def test_workflow_downloads_and_verifies_upgrade_and_rollback_validation_inputs
    step = workflow_step("Validate MSI install and uninstall")
    env = step.fetch("env")
    run = step.fetch("run")

    assert_equal "${{ inputs.upgrade_from_msi_url }}", env.fetch("UPGRADE_FROM_MSI_URL")
    assert_equal "${{ inputs.upgrade_from_msi_sha256 }}", env.fetch("UPGRADE_FROM_MSI_SHA256")
    assert_equal "${{ inputs.validate_rollback }}", env.fetch("VALIDATE_ROLLBACK")
    assert_equal "${{ inputs.rollback_to_msi_url }}", env.fetch("ROLLBACK_TO_MSI_URL")
    assert_equal "${{ inputs.rollback_to_msi_sha256 }}", env.fetch("ROLLBACK_TO_MSI_SHA256")
    assert_equal "${{ inputs.rollback_mode }}", env.fetch("ROLLBACK_MODE")

    assert_includes run, "-notmatch '^[0-9a-fA-F]{64}$'"
    assert_includes run, "upgrade_from_msi_sha256 is required when upgrade_from_msi_url is supplied."
    assert_includes run, "upgrade_from_msi_url is required when upgrade_from_msi_sha256 is supplied."
    assert_includes run, "validate_rollback requires upgrade_from_msi_url."
    assert_includes run, "rollback_to_msi_url requires validate_rollback."
    assert_includes run, "rollback_to_msi_sha256 is required when rollback_to_msi_url is supplied."
    assert_includes run, "rollback_to_msi_url is required when rollback_to_msi_sha256 is supplied."

    assert_in_order run, [
      'Invoke-WebRequest -Uri $Url -OutFile $DestinationPath',
      'Get-FileHash -Algorithm SHA256 -Path $DestinationPath',
      '$actualHash -ne $expectedHash'
    ]
    assert_in_order run, [
      '$upgradeMsiPath = Join-Path $validationDir "upgrade-from.msi"',
      '$arguments += "-UpgradeFromMsiPath"',
      '$arguments += $upgradeMsiPath'
    ]
    assert_in_order run, [
      '$arguments += "-ValidateRollback"',
      '$arguments += "-RollbackMode"',
      '$arguments += $env:ROLLBACK_MODE'
    ]
    assert_in_order run, [
      '$rollbackMsiPath = Join-Path $validationDir "rollback-to.msi"',
      '$arguments += "-RollbackToMsiPath"',
      '$arguments += $rollbackMsiPath'
    ]
  end

  def test_workflow_uploads_install_validation_evidence_even_on_failure
    step = workflow_step("Upload install validation report")

    assert_equal "always() && github.event_name == 'workflow_dispatch' && inputs.run_install_validation", step.fetch("if")
    assert_equal ARTIFACT_NAME, step.fetch("with").fetch("name")
    assert_equal ARTIFACT_REPORT_PATH, step.fetch("with").fetch("path")
  end

  def test_workflow_verifies_release_evidence_before_uploading_artifacts
    stage_index = @workflow.index("- name: Stage release artifacts and checksums")
    verify_index = @workflow.index("- name: Verify Windows release evidence")
    upload_index = @workflow.index("- name: Upload release artifacts")

    refute_nil stage_index
    refute_nil verify_index
    refute_nil upload_index
    assert_operator stage_index, :<, verify_index
    assert_operator verify_index, :<, upload_index

    step = workflow_step("Verify Windows release evidence")
    env = step.fetch("env")
    run = step.fetch("run")

    assert_equal "${{ steps.signing.outputs.available }}", env.fetch("SIGNING_AVAILABLE")
    assert_equal "${{ github.event_name == 'workflow_dispatch' && inputs.run_install_validation }}", env.fetch("RUN_INSTALL_VALIDATION")
    assert_equal "${{ inputs.expected_publisher_subject }}", env.fetch("EXPECTED_PUBLISHER_SUBJECT")
    assert_equal "${{ inputs.expected_publisher_thumbprint }}", env.fetch("EXPECTED_PUBLISHER_THUMBPRINT")
    assert_includes run, VERIFY_SCRIPT_PATH
    assert_in_order run, [
      '"-ArtifactDirectory"',
      '".\windows\build\release"',
      '"-MsiPath"',
      '$stagedMsi[0].FullName',
      '"-ChecksumsPath"',
      '".\windows\build\release\SHA256SUMS.txt"',
      '"-WintunLicensePath"',
      '".\windows\build\release\WINTUN-LICENSE.txt"',
      '"-WintunDllPath"',
      '".\wintun\bin\amd64\wintun.dll"',
      '"-EvidencePath"',
      "\"#{EVIDENCE_PATH}\""
    ]
    assert_in_order run, [
      '$env:SIGNING_AVAILABLE -eq "true" -or $env:GITHUB_REF -like "refs/tags/v*"',
      '$arguments += "-RequireValidSignature"',
      '$arguments += "-RequireTimestamp"'
    ]
    assert_in_order run, [
      '$env:EXPECTED_PUBLISHER_SUBJECT',
      '$arguments += "-ExpectedPublisherSubject"',
      '$arguments += $env:EXPECTED_PUBLISHER_SUBJECT.Trim()'
    ]
    assert_in_order run, [
      '$env:EXPECTED_PUBLISHER_THUMBPRINT',
      '$arguments += "-ExpectedPublisherThumbprint"',
      '$arguments += $env:EXPECTED_PUBLISHER_THUMBPRINT.Trim()'
    ]
    assert_in_order run, [
      '$env:RUN_INSTALL_VALIDATION -eq "true"',
      '$arguments += "-InstallValidationReportPath"',
      "\"#{REPORT_PATH}\"",
      '$arguments += "-RequireInstallValidation"'
    ]
  end

  def test_workflow_uploads_release_evidence_with_artifacts_and_github_release
    upload_step = workflow_step("Upload release artifacts")
    release_step = workflow_step("Attach to GitHub Release")

    assert_includes upload_step.fetch("with").fetch("path"), ARTIFACT_EVIDENCE_PATH
    assert_includes release_step.fetch("with").fetch("files"), ARTIFACT_EVIDENCE_PATH
  end

  def test_docs_reference_local_validation_script_and_report
    [@runbook, @installer_readme].each do |doc|
      assert_includes doc, "validate-install.ps1"
      assert_includes doc, "install-validation-report.json"
      assert_includes doc, SCRIPT_PATH
      assert_includes doc, REPORT_PATH
    end
  end

  def test_docs_reference_release_evidence_and_upgrade_workflow_inputs
    [@runbook, @installer_readme, @operator_checklist].each do |doc|
      assert_includes doc, "windows-release-evidence.json"
      assert_includes doc, "expected_publisher_subject"
      assert_includes doc, "expected_publisher_thumbprint"
      assert_includes doc, "upgrade_from_msi_url"
      assert_includes doc, "upgrade_from_msi_sha256"
      assert_includes doc, "validate_rollback"
      assert_includes doc, "rollback_to_msi_url"
      assert_includes doc, "rollback_to_msi_sha256"
      assert_includes doc, "rollback_mode"
    end
  end

  def test_installer_manual_fallback_stages_release_artifacts_before_release_evidence
    block = manual_fallback_powershell_block

    assert_in_order block, [
      "# 6. Verify signature",
      "Get-AuthenticodeSignature .\\windows\\QuantumLink.msi",
      "$releaseDir = \".\\windows\\build\\release\"",
      "Copy-Item -Path \".\\windows\\QuantumLink.msi\" -Destination $stagedMsi -Force",
      "Copy-Item -Path \".\\windows\\wintun\\LICENSE.txt\" -Destination (Join-Path $releaseDir \"WINTUN-LICENSE.txt\") -Force",
      "SHA256SUMS.txt",
      "\"{0}  {1}\" -f $hash.Hash.ToLowerInvariant(), $_.Name",
      ".\\windows\\scripts\\verify-windows-release.ps1"
    ]
    assert_includes block, "-MsiPath $stagedMsi"
    assert_includes block, "-ChecksumsPath .\\windows\\build\\release\\SHA256SUMS.txt"
    assert_includes block, "-WintunLicensePath .\\windows\\build\\release\\WINTUN-LICENSE.txt"
    assert_includes block, "-WintunDllPath .\\windows\\wintun\\bin\\amd64\\wintun.dll"
  end

  def test_operator_checklist_title_covers_macos_and_windows
    assert_match(/\A# Release Operator Checklists\n/, @operator_checklist)
    assert_includes @operator_checklist, "# macOS Release Operator Checklist"
    assert_includes @operator_checklist, "# Windows Release Operator Checklist"
  end

  private

  def workflow_dispatch_inputs
    @workflow_yaml.fetch(true).fetch("workflow_dispatch").fetch("inputs")
  end

  def workflow_step(name)
    step = @workflow_yaml.fetch("jobs").fetch("build").fetch("steps").find do |candidate|
      candidate["name"] == name
    end

    step || flunk("missing workflow step #{name.inspect}")
  end

  def manual_fallback_powershell_block
    match = @installer_readme.match(/For manual fallback\/debug builds[\s\S]*?```powershell\n(?<block>[\s\S]*?)\n```/)
    match ? match[:block] : flunk("missing manual fallback PowerShell block")
  end

  def assert_in_order(text, expected_parts)
    cursor = 0

    expected_parts.each do |part|
      index = text.index(part, cursor)
      refute_nil index, "expected #{part.inspect} after offset #{cursor}"
      cursor = index + part.length
    end
  end
end
