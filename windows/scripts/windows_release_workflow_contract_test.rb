# frozen_string_literal: true

require "minitest/autorun"
require "rexml/document"
require "yaml"

class WindowsReleaseWorkflowContractTest < Minitest::Test
  REPO_ROOT = File.expand_path("../..", __dir__)
  WORKFLOW_PATH = File.join(REPO_ROOT, ".github/workflows/windows-release.yml")
  RUNBOOK_PATH = File.join(REPO_ROOT, "windows/docs/beta-runbook-windows.md")
  PRODUCTION_READINESS_PATH = File.join(REPO_ROOT, "windows/docs/production-release-readiness.md")
  INSTALLER_README_PATH = File.join(REPO_ROOT, "windows/installer/README.md")
  INSTALLER_WXS_PATH = File.join(REPO_ROOT, "windows/installer/QuantumLink.wxs")
  BUILD_SCRIPT_PATH = File.join(REPO_ROOT, "windows/scripts/build-windows.ps1")
  OPERATOR_CHECKLIST_PATH = File.join(REPO_ROOT, "docs/release-operator-checklist.md")

  SCRIPT_PATH = ".\\windows\\scripts\\validate-install.ps1"
  VERIFY_SCRIPT_PATH = ".\\windows\\scripts\\verify-windows-release.ps1"
  RENDEZVOUS_RELAY_EVIDENCE_SCRIPT_PATH = ".\\windows\\scripts\\verify-rendezvous-relay-production-evidence.rb"
  MSI_PATH = ".\\windows\\QuantumLink.msi"
  REPORT_PATH = ".\\windows\\build\\validation\\install-validation-report.json"
  EVIDENCE_PATH = ".\\windows\\build\\release\\windows-release-evidence.json"
  SBOM_PATH = ".\\windows\\build\\release\\windows-sbom.spdx.json"
  RELEASE_MANIFEST_PATH = ".\\windows\\build\\release\\windows-release-manifest.json"
  RENDEZVOUS_RELAY_EVIDENCE_MANIFEST_PATH = "windows/validation/rendezvous-relay-production-evidence.json"
  ARTIFACT_REPORT_PATH = "windows/build/validation/install-validation-report.json"
  ARTIFACT_EVIDENCE_PATH = "windows/build/release/windows-release-evidence.json"
  ARTIFACT_SBOM_PATH = "windows/build/release/windows-sbom.spdx.json"
  ARTIFACT_RELEASE_MANIFEST_PATH = "windows/build/release/windows-release-manifest.json"
  ARTIFACT_NAME = "QuantumLink-Windows-InstallValidation-${{ github.run_number }}"

  def setup
    @workflow = File.read(WORKFLOW_PATH)
    @workflow_yaml = YAML.load_file(WORKFLOW_PATH)
    @runbook = File.read(RUNBOOK_PATH)
    @production_readiness = File.read(PRODUCTION_READINESS_PATH)
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
    assert_match(%r{<CreateFolder>\s*<PermissionEx Id="StateFolderAcl" Sddl="D:P\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BA\)" />\s*</CreateFolder>}m, @installer_wxs)
  end

  def test_build_script_builds_msi_as_x64
    assert_in_order @build_script, [
      "Invoke-WixBuild @(",
      '"build"',
      '"-arch"',
      '"x64"',
      "$installerSource"
    ]
  end

  def test_installer_readme_manual_wix_build_builds_msi_as_x64
    block = manual_fallback_powershell_block

    assert_in_order block, [
      "wix build windows\\installer\\QuantumLink.wxs `",
      "    -arch x64 `",
      "    -d BuildDir=target\\x86_64-pc-windows-msvc\\release `"
    ]
  end

  def test_installer_recursively_removes_state_directory_on_uninstall
    assert_includes @installer_wxs, 'xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util"'
    assert_match(/<Property Id="QL_STATE_FOLDER_PATH" Value="%ProgramData%\\QuantumLink" \/>/, @installer_wxs)
    assert_in_order @installer_wxs, [
      '<PermissionEx Id="StateFolderAcl" Sddl="D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" />',
      '<util:RemoveFolderEx Id="RemoveStateFolderTree" On="uninstall" Property="QL_STATE_FOLDER_PATH" />',
      '<RemoveFolder Id="RemoveStateFolder" On="uninstall" />'
    ]
  end

  def test_workflow_declares_manual_install_validation_inputs
    inputs = workflow_dispatch_inputs

    production_release = inputs.fetch("production_release")
    assert_match(/requires signing.*install validation.*SBOM.*manifest.*release evidence.*rendezvous\/relay production evidence/i, production_release.fetch("description"))
    assert_equal "boolean", production_release.fetch("type")
    assert_equal false, production_release.fetch("default")

    run_install_validation = inputs.fetch("run_install_validation")
    assert_match(/installs\/uninstalls the generated MSI.*uploads JSON evidence/i, run_install_validation.fetch("description"))
    assert_equal "boolean", run_install_validation.fetch("type")
    assert_equal false, run_install_validation.fetch("default")

    skip_network_checks = inputs.fetch("skip_validation_network_checks")
    assert_match(/skips adapter\/route\/WFP evidence.*validate-install\.ps1/i, skip_network_checks.fetch("description"))
    assert_equal "boolean", skip_network_checks.fetch("type")
    assert_equal false, skip_network_checks.fetch("default")

    rendezvous_relay_evidence = inputs.fetch("rendezvous_relay_production_evidence_manifest")
    assert_match(/repo-relative JSON.*rendezvous\/relay production evidence/i, rendezvous_relay_evidence.fetch("description"))
    assert_equal "string", rendezvous_relay_evidence.fetch("type")
    assert_equal RENDEZVOUS_RELAY_EVIDENCE_MANIFEST_PATH, rendezvous_relay_evidence.fetch("default")
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

  def test_workflow_pins_a_ruby_runtime_for_evidence_verification
    step = workflow_step("Setup Ruby evidence verifier")

    assert_equal "ruby/setup-ruby@v1", step.fetch("uses")
    assert_equal "3.3", step.fetch("with").fetch("ruby-version")
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
      "$reportPath"
    ]
    assert_includes run, "$reportPath = \"#{REPORT_PATH}\""
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

  def test_workflow_writes_install_validation_report_for_bootstrap_failures
    step = workflow_step("Validate MSI install and uninstall")
    run = step.fetch("run")
    upload_step = workflow_step("Upload install validation report")

    assert_includes run, "function Write-WorkflowBootstrapFailureReport"
    assert_includes run, "function Write-WorkflowMissingValidationReport"
    assert_includes run, "workflowBootstrapFailure = [ordered]@{"
    assert_includes run, "missingReportAfterValidator = [ordered]@{"
    assert_includes run, 'warnings = @("Windows release workflow failed before validate-install.ps1 completed.")'
    assert_includes run, 'failures = @("Windows install validation workflow bootstrap error: $message")'
    assert_includes run, 'failures = @("Install validation exited with code $ExitCode and did not write its JSON report.")'
    assert_includes run, "passed = $false"
    assert_in_order run, [
      "try {",
      "Assert-Sha256Input -Name \"upgrade_from_msi_sha256\" -Value $upgradeSha256",
      "& pwsh -NoProfile -ExecutionPolicy Bypass -File \".\\windows\\scripts\\validate-install.ps1\" @arguments",
      "$validationExitCode = $LASTEXITCODE",
      "if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {",
      "Write-WorkflowMissingValidationReport",
      "if ($validationExitCode -eq 0) {",
      "$validationExitCode = 1",
      "if ($validationExitCode -ne 0) {",
      "exit $validationExitCode",
      "} catch {",
      "Write-WorkflowBootstrapFailureReport -ErrorRecord $_ -Path $reportPath",
      "exit 1"
    ]
    assert_in_order run, [
      "throw \"upgrade_from_msi_sha256 is required when upgrade_from_msi_url is supplied.\"",
      "throw \"upgrade_from_msi_url is required when upgrade_from_msi_sha256 is supplied.\"",
      "throw \"validate_rollback requires upgrade_from_msi_url.\"",
      "throw \"rollback_to_msi_url requires validate_rollback.\"",
      "throw \"rollback_to_msi_sha256 is required when rollback_to_msi_url is supplied.\"",
      "throw \"rollback_to_msi_url is required when rollback_to_msi_sha256 is supplied.\""
    ]
    refute_includes run, "exit 1\n          }\n          if ($upgradeUrl"
    assert_equal "error", upload_step.fetch("with").fetch("if-no-files-found")
  end

  def test_workflow_uploads_install_validation_evidence_even_on_failure
    step = workflow_step("Upload install validation report")

    assert_equal "always() && github.event_name == 'workflow_dispatch' && inputs.run_install_validation", step.fetch("if")
    assert_equal ARTIFACT_NAME, step.fetch("with").fetch("name")
    assert_equal ARTIFACT_REPORT_PATH, step.fetch("with").fetch("path")
  end

  def test_workflow_requires_signing_and_install_validation_for_production_releases
    signing_step = workflow_step("Require Authenticode signing for production releases")
    validation_step = workflow_step("Require install validation for production releases")

    assert_equal "(startsWith(github.ref, 'refs/tags/v') || (github.event_name == 'workflow_dispatch' && inputs.production_release)) && steps.signing.outputs.available != 'true'", signing_step.fetch("if")
    assert_includes signing_step.fetch("run"), "Windows production releases require Authenticode signing secrets"
    assert_equal "github.event_name == 'workflow_dispatch' && inputs.production_release && !inputs.run_install_validation", validation_step.fetch("if")
    assert_includes validation_step.fetch("run"), "Windows production releases require run_install_validation=true"
  end

  def test_workflow_requires_rendezvous_relay_production_evidence_for_production_releases
    step = workflow_step("Require rendezvous/relay production evidence")

    assert_equal "startsWith(github.ref, 'refs/tags/v') || (github.event_name == 'workflow_dispatch' && inputs.production_release)", step.fetch("if")
    assert_equal "pwsh", step.fetch("shell")
    assert_equal "${{ inputs.rendezvous_relay_production_evidence_manifest || 'windows/validation/rendezvous-relay-production-evidence.json' }}", step.fetch("env").fetch("RENDEZVOUS_RELAY_PRODUCTION_EVIDENCE_MANIFEST")
    assert_includes step.fetch("run"), RENDEZVOUS_RELAY_EVIDENCE_SCRIPT_PATH
    assert_in_order step.fetch("run"), [
      "ruby #{RENDEZVOUS_RELAY_EVIDENCE_SCRIPT_PATH}",
      "--require-ready",
      "--expected-sha $env:GITHUB_SHA",
      "--expected-ref $env:GITHUB_REF",
      "--report windows/build/validation/rendezvous-relay-production-evidence-verification.json",
      "$env:RENDEZVOUS_RELAY_PRODUCTION_EVIDENCE_MANIFEST"
    ]
  end

  def test_workflow_stages_verified_control_plane_evidence_with_release_artifacts
    step = workflow_step("Stage release artifacts, SBOM, manifest, and checksums")
    run = step.fetch("run")

    assert_includes run, "rendezvous-relay-production-evidence-verification.json"
    assert_includes run, "rendezvous-relay-production-evidence.json"
    assert_includes run, "$verifiedEvidence.controlEvidence"
    assert_includes run, '"rendezvous-relay-control-$safeControl.json"'
    assert_in_order run, [
      "$productionEvidenceReport =",
      "Copy-Item -LiteralPath $productionEvidenceReport",
      "$verifiedEvidence = Get-Content",
      "foreach ($controlEvidence in @($verifiedEvidence.controlEvidence))",
      "$releaseArtifacts = @("
    ]
  end

  def test_workflow_verifies_release_evidence_before_uploading_artifacts
    stage_index = @workflow.index("- name: Stage release artifacts, SBOM, manifest, and checksums")
    production_evidence_index = @workflow.index("- name: Require rendezvous/relay production evidence")
    verify_index = @workflow.index("- name: Verify Windows release evidence")
    upload_index = @workflow.index("- name: Upload release artifacts")

    refute_nil stage_index
    refute_nil production_evidence_index
    refute_nil verify_index
    refute_nil upload_index
    assert_operator stage_index, :<, verify_index
    assert_operator production_evidence_index, :<, stage_index
    assert_operator verify_index, :<, upload_index

    step = workflow_step("Verify Windows release evidence")
    env = step.fetch("env")
    run = step.fetch("run")

    assert_equal "${{ steps.signing.outputs.available }}", env.fetch("SIGNING_AVAILABLE")
    assert_equal "${{ (startsWith(github.ref, 'refs/tags/v') || (github.event_name == 'workflow_dispatch' && inputs.production_release)) }}", env.fetch("PRODUCTION_RELEASE")
    assert_equal "${{ github.event_name == 'workflow_dispatch' && inputs.run_install_validation }}", env.fetch("RUN_INSTALL_VALIDATION")
    assert_equal "${{ inputs.expected_publisher_subject }}", env.fetch("EXPECTED_PUBLISHER_SUBJECT")
    assert_equal "${{ inputs.expected_publisher_thumbprint }}", env.fetch("EXPECTED_PUBLISHER_THUMBPRINT")
    assert_includes run, VERIFY_SCRIPT_PATH
    assert_in_order run, [
      "$arguments = @{",
      'ArtifactDirectory = ".\windows\build\release"',
      "MsiPath = $stagedMsi[0].FullName",
      'ChecksumsPath = ".\windows\build\release\SHA256SUMS.txt"',
      'WintunDllPath = ".\wintun\bin\amd64\wintun.dll"',
      'WintunLicensePath = ".\windows\build\release\WINTUN-LICENSE.txt"',
      "SbomPath = \"#{SBOM_PATH}\"",
      "ReleaseManifestPath = \"#{RELEASE_MANIFEST_PATH}\"",
      "EvidencePath = \"#{EVIDENCE_PATH}\"",
      "}"
    ]
    refute_includes run, '"-WintunDllPath"'
    assert_in_order run, [
      '$env:SIGNING_AVAILABLE -eq "true" -or $env:PRODUCTION_RELEASE -eq "true"',
      '$arguments.RequireValidSignature = $true',
      '$arguments.RequireTimestamp = $true'
    ]
    assert_in_order run, [
      '$env:PRODUCTION_RELEASE -eq "true"',
      '$arguments.RequireSbom = $true',
      '$arguments.RequireReleaseManifest = $true'
    ]
    assert_in_order run, [
      '$env:EXPECTED_PUBLISHER_SUBJECT',
      '$arguments.ExpectedPublisherSubject = $env:EXPECTED_PUBLISHER_SUBJECT.Trim()'
    ]
    assert_in_order run, [
      '$env:EXPECTED_PUBLISHER_THUMBPRINT',
      '$arguments.ExpectedPublisherThumbprint = $env:EXPECTED_PUBLISHER_THUMBPRINT.Trim()'
    ]
    assert_in_order run, [
      '$env:RUN_INSTALL_VALIDATION -eq "true"',
      "$arguments.InstallValidationReportPath = \"#{REPORT_PATH}\"",
      '$arguments.RequireInstallValidation = $true'
    ]
    assert_includes run, "& #{VERIFY_SCRIPT_PATH} @arguments"
  end

  def test_workflow_uploads_release_evidence_with_artifacts_and_github_release
    upload_step = workflow_step("Upload release artifacts")
    release_step = workflow_step("Attach to GitHub Release")

    assert_includes upload_step.fetch("with").fetch("path"), ARTIFACT_EVIDENCE_PATH
    assert_includes upload_step.fetch("with").fetch("path"), ARTIFACT_SBOM_PATH
    assert_includes upload_step.fetch("with").fetch("path"), ARTIFACT_RELEASE_MANIFEST_PATH
    assert_includes upload_step.fetch("with").fetch("path"), "windows/build/release/rendezvous-relay-*.json"
    assert_includes release_step.fetch("with").fetch("files"), ARTIFACT_EVIDENCE_PATH
    assert_includes release_step.fetch("with").fetch("files"), ARTIFACT_SBOM_PATH
    assert_includes release_step.fetch("with").fetch("files"), ARTIFACT_RELEASE_MANIFEST_PATH
    assert_includes release_step.fetch("with").fetch("files"), "windows/build/release/rendezvous-relay-*.json"
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

  def test_production_readiness_references_rendezvous_relay_sidecar_contract
    assert_includes @production_readiness, "windows/docs/rendezvous-relay-production.md"
    assert_includes @production_readiness, "windows/docs/production-evidence.md"
    assert_includes @production_readiness, "windows/validation/rendezvous-relay-production-evidence.json"
    assert_includes @production_readiness, "windows/scripts/verify-rendezvous-relay-production-evidence.rb"
    assert_includes @production_readiness, "production_release=true"
    assert_match(/remains \*\*Blocked\*\* until real production endpoint evidence is\s+supplied/i, @production_readiness)
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
