# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "open3"
require "tmpdir"

class WindowsValidationReportsContractTest < Minitest::Test
  SECURITY_SCRIPT = File.expand_path("validate-windows-security.ps1", __dir__)
  ORCHESTRATOR_SCRIPT = File.expand_path("run-beta-validation.ps1", __dir__)
  REPORTS_README = File.expand_path("../docs/validation-reports/README.md", __dir__)
  BETA_RUNBOOK = File.expand_path("../docs/beta-runbook-windows.md", __dir__)

  SECURITY_REPORT_KEYS = %w[
    schemaVersion reportType generatedAt status passed contractOnly
    hostIdentifiersIncluded host summary passes failures warnings
    evidenceTruncated
  ].freeze
  MANIFEST_KEYS = %w[
    schemaVersion reportType generatedAt scope status passed
    requiredEvidencePassed productionReady contractOnly
    hostIdentifiersIncluded host artifact components blockers failures warnings
  ].freeze
  FORBIDDEN_EVIDENCE_KEYS = %w[
    password accessToken refreshToken privateKey seed seedPhrase secretValue
    machineGuid domainName environment processEnvironment
  ].freeze

  def setup
    @security = File.read(SECURITY_SCRIPT)
    @orchestrator = File.read(ORCHESTRATOR_SCRIPT)
  end

  def test_scripts_are_ascii_only
    assert @security.ascii_only?, "validate-windows-security.ps1 must stay ASCII-only"
    assert @orchestrator.ascii_only?, "run-beta-validation.ps1 must stay ASCII-only"
  end

  def test_security_report_has_explicit_bounded_schema
    SECURITY_REPORT_KEYS.each do |key|
      assert_match(/\b#{Regexp.escape(key)}\s*=/, @security, "missing security report key #{key}")
    end

    assert_match(/\$script:SchemaVersion\s*=\s*"1\.0"/, @security)
    assert_match(/\$script:MaxEvidenceItems\s*=\s*100/, @security)
    assert_match(/\$script:MaxEvidenceLineLength\s*=\s*400/, @security)
    assert_match(/ConvertTo-Json\s+-Depth\s+8/, @security)
    assert_match(/\[ValidateSet\("passed",\s*"failed",\s*"contract_only"\)\]/, @security)
    assert_match(/Write-SecurityValidationReport\s+-Status\s+"failed"/, @security)
  end

  def test_host_identifiers_are_redacted_unless_explicitly_included
    [@security, @orchestrator].each do |script|
      assert_match(/\[switch\]\$IncludeHostIdentifiers/, script)
      assert_match(/if\s*\(\$IncludeHostIdentifiers\)/, script)
      assert_match(/return\s+"\[redacted\]"/, script)
      assert_match(/computerName\s*=\s*\(ConvertTo-/, script)
      assert_match(/userName\s*=\s*\(ConvertTo-/, script)
      refute_match(/\[switch\]\$RedactHostIdentifiers/, script)
    end
  end

  def test_reports_do_not_define_secret_bearing_fields
    [@security, @orchestrator].each do |script|
      FORBIDDEN_EVIDENCE_KEYS.each do |key|
        refute_match(/^\s*#{Regexp.escape(key)}\s*=/i, script, "forbidden evidence field #{key}")
      end
    end
  end

  def test_orchestrator_invokes_both_required_validators_with_report_paths
    assert_match(/Join-Path\s+\$PSScriptRoot\s+"validate-install\.ps1"/, @orchestrator)
    assert_match(/Join-Path\s+\$PSScriptRoot\s+"validate-windows-security\.ps1"/, @orchestrator)
    assert_match(/&\s+\$powerShellExecutable\s+@installArguments/, @orchestrator)
    assert_match(/&\s+\$powerShellExecutable\s+@securityArguments/, @orchestrator)
    assert_match(/"-ReportPath",\s*\$installReportPath/, @orchestrator)
    assert_match(/"-ReportPath",\s*\$securityReportPath/, @orchestrator)
    assert_match(/"-SkipUninstall"/, @orchestrator)
    assert_match(/"-CheckPipeAcl"/, @orchestrator)
  end

  def test_manifest_is_bounded_and_references_component_reports
    MANIFEST_KEYS.each do |key|
      assert_match(/\b#{Regexp.escape(key)}\s*=/, @orchestrator, "missing manifest key #{key}")
    end

    assert_match(/install-validation-report\.json/, @orchestrator)
    assert_match(/windows-security-validation-report\.json/, @orchestrator)
    assert_match(/windows-beta-validation-manifest\.json/, @orchestrator)
    assert_match(/\$script:MaxCollectionItems\s*=\s*50/, @orchestrator)
    assert_match(/\$script:MaxEvidenceLineLength\s*=\s*400/, @orchestrator)
    assert_match(/Select-Object\s+-First\s+\$script:MaxCollectionItems/, @orchestrator)
    assert_match(/ConvertTo-Json\s+-Depth\s+8/, @orchestrator)
  end

  def test_orchestration_fails_closed_for_missing_or_non_passing_evidence
    assert_match(/Required component report was not created/, @orchestrator)
    assert_match(/Required component report is not valid JSON/, @orchestrator)
    assert_match(/Component report schemaVersion is missing or unsupported/, @orchestrator)
    assert_match(/Component reportType is missing or unsupported/, @orchestrator)
    assert_match(/Remove-Item\s+-LiteralPath\s+\$staleReportPath\s+-Force/, @orchestrator)
    assert_match(/\(\$ExitCode\s+-ne\s+0\)\s+-or\s+\(-not\s+\[bool\]\$report\.passed\)/, @orchestrator)
    assert_match(/\$securityComponent\.reason\s*=\s*"Security validation was blocked by non-passing install validation\."/, @orchestrator)
    assert_match(/requiredEvidencePassed\s*=\s*\(\$status\s+-eq\s+"passed"\)/, @orchestrator)
    assert_match(/productionReady\s*=\s*\$false/, @orchestrator)
    assert_match(/Install validation skipped required network evidence/, @orchestrator)
    assert_match(/Write-BetaValidationFailureManifest\s+-ErrorRecord\s+\$_/, @orchestrator)
    assert_match(/if\s*\(\$scriptExitCode\s+-ne\s+0\)\s*\{\s*exit\s+1/s, @orchestrator)
    assert_match(/Write-BetaValidationBlockedComponentReport/, @orchestrator)
    assert_match(/quantumlink\.windows\.validation-placeholder/, @orchestrator)
    assert_match(/Test-Path\s+-LiteralPath\s+\$installReportPath\s+-PathType\s+Leaf/, @orchestrator)
    assert_match(/Test-Path\s+-LiteralPath\s+\$securityReportPath\s+-PathType\s+Leaf/, @orchestrator)
  end

  def test_required_pipe_acl_inspection_fails_closed
    assert_match(/Add-Failure\s+"Could not inspect required named pipe ACL/, @security)
    refute_match(/Add-Warning\s+"Could not inspect named pipe ACL/, @security)
  end

  def test_operator_docs_name_exact_commands_and_evidence_paths
    docs = [File.read(REPORTS_README), File.read(BETA_RUNBOOK)].join("\n")

    assert_includes docs, ".\\windows\\scripts\\run-beta-validation.ps1"
    assert_includes docs, ".\\windows\\scripts\\validate-windows-security.ps1"
    assert_includes docs, "windows/build/validation/windows-beta-validation-manifest.json"
    assert_includes docs, "windows/build/validation/install-validation-report.json"
    assert_includes docs, "windows/build/validation/windows-security-validation-report.json"
    assert_includes docs, "productionReady: false"
    assert_includes docs, "-IncludeHostIdentifiers"
    assert_includes docs, "-ContractOnly"
  end

  def test_contract_reports_are_machine_readable_when_pwsh_is_available
    pwsh = find_executable("pwsh")
    skip "pwsh is not available in this environment" unless pwsh

    Dir.mktmpdir("qlink-windows-validation-contract") do |dir|
      security_report_path = File.join(dir, "security.json")
      stdout, stderr, status = Open3.capture3(
        pwsh, "-NoProfile", "-File", SECURITY_SCRIPT,
        "-ContractOnly", "-ReportPath", security_report_path
      )
      assert status.success?, "security contract mode failed\nstdout=#{stdout}\nstderr=#{stderr}"

      security_report = JSON.parse(File.read(security_report_path))
      SECURITY_REPORT_KEYS.each { |key| assert security_report.key?(key), "missing #{key}" }
      assert_equal "contract_only", security_report.fetch("status")
      assert_equal false, security_report.fetch("passed")
      assert_equal "[redacted]", security_report.fetch("host").fetch("userName")
      assert_bounded_report(security_report, 100)
      assert_no_forbidden_keys(security_report)

      bundle_dir = File.join(dir, "bundle")
      stdout, stderr, status = Open3.capture3(
        pwsh, "-NoProfile", "-File", ORCHESTRATOR_SCRIPT,
        "-ContractOnly", "-OutputDirectory", bundle_dir
      )
      refute status.success?, "contract-only manifest must not be promotable\nstdout=#{stdout}\nstderr=#{stderr}"

      manifest = JSON.parse(File.read(File.join(bundle_dir, "windows-beta-validation-manifest.json")))
      MANIFEST_KEYS.each { |key| assert manifest.key?(key), "missing #{key}" }
      assert_equal "blocked", manifest.fetch("status")
      assert_equal false, manifest.fetch("passed")
      assert_equal false, manifest.fetch("requiredEvidencePassed")
      assert_equal false, manifest.fetch("productionReady")
      assert manifest.fetch("components").all? { |component| component.fetch("status") == "blocked" }
      assert manifest.fetch("components").all? { |component| component.fetch("invoked") }
      assert_bounded_report(manifest, 50)
      assert_no_forbidden_keys(manifest)
    end
  end

  private

  def assert_bounded_report(report, max_items)
    report.each_value do |value|
      assert_operator value.length, :<=, max_items if value.is_a?(Array)
    end
    each_string(report) { |value| assert_operator value.length, :<=, 414 }
  end

  def assert_no_forbidden_keys(value)
    case value
    when Hash
      value.each do |key, child|
        refute_includes FORBIDDEN_EVIDENCE_KEYS.map(&:downcase), key.downcase
        assert_no_forbidden_keys(child)
      end
    when Array
      value.each { |child| assert_no_forbidden_keys(child) }
    end
  end

  def each_string(value, &block)
    case value
    when Hash
      value.each_value { |child| each_string(child, &block) }
    when Array
      value.each { |child| each_string(child, &block) }
    when String
      yield value
    end
  end

  def find_executable(name)
    ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
      candidate = File.join(dir, name)
      return candidate if File.executable?(candidate) && !File.directory?(candidate)
    end
    nil
  end
end
