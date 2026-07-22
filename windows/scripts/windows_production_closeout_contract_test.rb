# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "open3"

class WindowsProductionCloseoutContractTest < Minitest::Test
  REPO_ROOT = File.expand_path("../..", __dir__)
  READINESS = File.join(REPO_ROOT, "windows/docs/production-release-readiness.md")
  DECISION = File.join(REPO_ROOT, "windows/docs/release-candidate-go-no-go.md")
  VERSION = File.join(REPO_ROOT, "windows/version.md")
  VERIFIER = File.join(REPO_ROOT, "windows/scripts/verify-rendezvous-relay-production-evidence.rb")
  DEFAULT_MANIFEST = "windows/validation/rendezvous-relay-production-evidence.json"

  def setup
    @readiness = File.read(READINESS)
    @decision = File.read(DECISION)
    @version = File.read(VERSION)
  end

  def test_release_decision_remains_no_go_and_version_remains_alpha
    assert_match(/^Decision: \*\*NO-GO\*\*$/, @decision)
    assert_match(/^Version: 0\.2\.0-windows-alpha$/, @version)
    assert_match(/^Status: Alpha implementation;/, @version)
    assert_includes @readiness, "The current decision is **No-Go**"
  end

  def test_decision_records_code_and_external_blockers
    [
      "persistent/boot-time",
      "peer-session",
      "rendezvous/relay",
      "Wintun",
      "Authenticode",
      "Windows 10",
      "Windows 11",
      "Two-Windows-host",
      "rollback",
      "support-bundle"
    ].each do |required|
      assert_includes @decision, required
    end
  end

  def test_readiness_links_completed_local_contracts_without_marking_gates_passed
    assert_includes @readiness, "windows/scripts/run-beta-validation.ps1"
    assert_includes @readiness, "windows/docs/diagnostics-support-bundle.md"
    assert_includes @readiness, "windows/docs/release-candidate-go-no-go.md"
    refute_match(/^\| .* \| Passed \|/i, @readiness)
  end

  def test_default_production_manifest_is_intentionally_absent_and_gate_fails
    refute File.exist?(File.join(REPO_ROOT, DEFAULT_MANIFEST))

    stdout, _stderr, status = Open3.capture3(
      "ruby", VERIFIER,
      "--require-ready",
      "--expected-sha", "0" * 40,
      "--expected-ref", "refs/tags/v0.0.0",
      DEFAULT_MANIFEST,
      chdir: REPO_ROOT
    )
    report = JSON.parse(stdout)

    refute status.success?
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("blockers"), "production evidence manifest is missing: #{DEFAULT_MANIFEST}"
  end
end
