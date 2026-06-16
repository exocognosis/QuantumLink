# frozen_string_literal: true

require "minitest/autorun"

class WindowsReleaseWorkflowContractTest < Minitest::Test
  REPO_ROOT = File.expand_path("../..", __dir__)
  WORKFLOW_PATH = File.join(REPO_ROOT, ".github/workflows/windows-release.yml")
  RUNBOOK_PATH = File.join(REPO_ROOT, "windows/docs/beta-runbook-windows.md")
  INSTALLER_README_PATH = File.join(REPO_ROOT, "windows/installer/README.md")

  SCRIPT_PATH = ".\\windows\\scripts\\validate-install.ps1"
  MSI_PATH = ".\\windows\\QuantumLink.msi"
  REPORT_PATH = ".\\windows\\build\\validation\\install-validation-report.json"
  ARTIFACT_REPORT_PATH = "windows/build/validation/install-validation-report.json"
  ARTIFACT_NAME = "QuantumLink-Windows-InstallValidation-${{ github.run_number }}"

  def setup
    @workflow = File.read(WORKFLOW_PATH)
    @runbook = File.read(RUNBOOK_PATH)
    @installer_readme = File.read(INSTALLER_README_PATH)
  end

  def test_workflow_declares_manual_install_validation_inputs
    assert_match(/\bworkflow_dispatch:\s*\n(?:[^\n]*\n)*?\s+inputs:/, @workflow)

    assert_match(/\brun_install_validation:/, @workflow)
    assert_match(/description:\s*".*installs\/uninstalls the generated MSI.*uploads JSON evidence.*"/i, @workflow)
    assert_match(/run_install_validation:[\s\S]*?type:\s*boolean/, @workflow)
    assert_match(/run_install_validation:[\s\S]*?default:\s*false/, @workflow)

    assert_match(/\bskip_validation_network_checks:/, @workflow)
    assert_match(/description:\s*".*skips adapter\/route\/WFP evidence.*validate-install\.ps1.*"/i, @workflow)
    assert_match(/skip_validation_network_checks:[\s\S]*?type:\s*boolean/, @workflow)
    assert_match(/skip_validation_network_checks:[\s\S]*?default:\s*false/, @workflow)
  end

  def test_workflow_runs_validate_install_script_for_manual_opt_in
    assert_includes @workflow, "github.event_name == 'workflow_dispatch'"
    assert_includes @workflow, "inputs.run_install_validation"
    assert_includes @workflow, "windows\\build\\validation"
    assert_includes @workflow, SCRIPT_PATH
    assert_includes @workflow, "-MsiPath"
    assert_includes @workflow, MSI_PATH
    assert_includes @workflow, "-ReportPath"
    assert_includes @workflow, REPORT_PATH
    assert_includes @workflow, "SkipNetworkChecks"
    assert_includes @workflow, "inputs.skip_validation_network_checks"
  end

  def test_workflow_uploads_install_validation_evidence_even_on_failure
    assert_includes @workflow, "always()"
    assert_includes @workflow, ARTIFACT_NAME
    assert_includes @workflow, ARTIFACT_REPORT_PATH
  end

  def test_docs_reference_local_validation_script_and_report
    [@runbook, @installer_readme].each do |doc|
      assert_includes doc, "validate-install.ps1"
      assert_includes doc, "install-validation-report.json"
      assert_includes doc, SCRIPT_PATH
      assert_includes doc, REPORT_PATH
    end
  end
end
