# frozen_string_literal: true

require "json"
require "fileutils"
require "minitest/autorun"
require "open3"
require "tmpdir"

class RendezvousRelayProductionEvidenceTest < Minitest::Test
  SCRIPT_PATH = File.expand_path("verify-rendezvous-relay-production-evidence.rb", __dir__)

  def setup
    @tmpdir = Dir.mktmpdir("qlink-windows-rendezvous-relay-evidence")
    required_controls.each do |control|
      path = File.join(@tmpdir, "windows/validation/rendezvous-relay/#{control}.json")
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, %({"control":"#{control}","redacted":true}\n))
    end
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.directory?(@tmpdir)
  end

  def test_valid_manifest_passes_and_reports_ready
    manifest_path = write_manifest("valid.json")

    stdout, stderr, status = run_verifier(manifest_path)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal true, report.fetch("productionEvidenceReady")
    assert_equal [], report.fetch("blockers")
    assert_equal [], report.fetch("failures")
  end

  def test_blocked_manifest_is_structurally_valid_but_not_ready
    manifest_path = write_manifest("blocked.json") do |manifest|
      manifest["status"] = "blocked"
      manifest["rendezvousRelay"]["controls"].first["status"] = "blocked"
    end

    stdout, stderr, status = run_verifier(manifest_path)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("blockers"), "production evidence status is blocked"
    assert_includes report.fetch("blockers"), "rendezvous/relay control tls status is blocked"
    assert_empty report.fetch("failures")
  end

  def test_require_ready_exits_nonzero_for_blocked_manifest
    manifest_path = write_manifest("blocked-required.json") do |manifest|
      manifest["rendezvousRelay"]["controls"].first["status"] = "blocked"
    end

    stdout, _stderr, status = run_verifier(manifest_path, "--require-ready")
    report = JSON.parse(stdout)

    refute status.success?
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("blockers"), "rendezvous/relay control tls status is blocked"
  end

  def test_missing_manifest_reports_blocker_without_schema_failures
    missing_path = File.join(@tmpdir, "missing.json")

    stdout, stderr, status = run_verifier(missing_path)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("blockers"), "production evidence manifest is missing: #{missing_path}"
    assert_empty report.fetch("failures")
  end

  def test_invalid_manifest_reports_schema_failures
    manifest_path = write_manifest("invalid.json") do |manifest|
      manifest["rendezvousRelay"]["rendezvousEndpoints"] = ["http://rv.invalid"]
      manifest["rendezvousRelay"]["relayEndpoints"] = ["turn:relay.invalid:3478"]
      manifest["rendezvousRelay"]["rawPacketPayloadsCommitted"] = true
      manifest["rendezvousRelay"]["controls"].reject! { |entry| entry["control"] == "retention" }
      manifest["rendezvousRelay"]["controls"].first["evidence"] = "/tmp/tls.txt"
    end

    stdout, _stderr, status = run_verifier(manifest_path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_equal false, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("failures"), "rendezvous endpoint must be an https URL"
    assert_includes report.fetch("failures"), "relay endpoint must use turns or https"
    assert_includes report.fetch("failures"), "rendezvousRelay.rawPacketPayloadsCommitted must be false"
    assert_includes report.fetch("failures"), "missing rendezvous/relay control: retention"
    assert_includes report.fetch("failures"), "rendezvous/relay control tls evidence must be a relative path"
  end

  def test_forbidden_secret_marker_fails
    manifest_path = write_manifest("secret.json") do |manifest|
      manifest["notes"] = "BEGIN PRIVATE KEY"
    end

    stdout, _stderr, status = run_verifier(manifest_path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_equal false, report.fetch("valid")
    assert_includes report.fetch("failures"), "forbidden secret marker found in production evidence manifest"
  end

  def test_missing_control_evidence_is_a_readiness_blocker
    FileUtils.rm(File.join(@tmpdir, "windows/validation/rendezvous-relay/tls.json"))
    manifest_path = write_manifest("missing-evidence.json")

    stdout, stderr, status = run_verifier(manifest_path)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("blockers"), "rendezvous/relay control tls evidence file is missing: windows/validation/rendezvous-relay/tls.json"
  end

  def test_duplicate_unknown_and_windows_absolute_paths_fail
    manifest_path = write_manifest("ambiguous-controls.json") do |manifest|
      controls = manifest["rendezvousRelay"]["controls"]
      controls << controls.first.dup
      controls << { "control" => "unreviewed_control", "status" => "pass", "evidence" => "evidence.json", "redacted" => true }
      controls.find { |entry| entry["control"] == "retention" }["evidence"] = "C:\\secrets\\retention.json"
    end

    stdout, _stderr, status = run_verifier(manifest_path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "duplicate rendezvous/relay control: tls"
    assert_includes report.fetch("failures"), "unknown rendezvous/relay control: unreviewed_control"
    assert_includes report.fetch("failures"), "rendezvous/relay control retention evidence must be a relative path"
  end

  def test_secret_marker_in_control_evidence_fails
    evidence_path = File.join(@tmpdir, "windows/validation/rendezvous-relay/tls.json")
    File.write(evidence_path, "BEGIN PRIVATE KEY\n")
    manifest_path = write_manifest("secret-evidence.json")

    stdout, _stderr, status = run_verifier(manifest_path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "forbidden secret marker found in rendezvous/relay control tls evidence"
  end

  def test_oversized_control_evidence_fails
    evidence_path = File.join(@tmpdir, "windows/validation/rendezvous-relay/tls.json")
    File.write(evidence_path, "x" * 1_048_577)
    manifest_path = write_manifest("oversized-evidence.json")

    stdout, _stderr, status = run_verifier(manifest_path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "rendezvous/relay control tls evidence exceeds 1048576 bytes"
  end

  private

  def run_verifier(manifest_path, *extra_args)
    Open3.capture3("ruby", SCRIPT_PATH, *extra_args, "--repo-root", @tmpdir, manifest_path)
  end

  def write_manifest(name)
    path = File.join(@tmpdir, name)
    manifest = valid_manifest
    yield manifest if block_given?
    File.write(path, "#{JSON.pretty_generate(manifest)}\n")
    path
  end

  def valid_manifest
    {
      "schemaVersion" => 1,
      "evidenceKind" => "windowsRendezvousRelayProductionEvidence",
      "product" => "QuantumLink Windows",
      "platform" => "windows",
      "releaseScope" => "windows-x64-production-release",
      "generatedAt" => "2026-07-09T00:00:00Z",
      "status" => "pass",
      "rendezvousRelay" => {
        "status" => "pass",
        "rendezvousEndpoints" => ["https://rv.production.quantumlink.invalid"],
        "relayEndpoints" => ["turns:relay.production.quantumlink.invalid:5349"],
        "abuseLogsRedacted" => true,
        "rawPacketPayloadsCommitted" => false,
        "rawGamePayloadsCommitted" => false,
        "controls" => required_controls.map do |control|
          {
            "control" => control,
            "status" => "pass",
            "evidence" => "windows/validation/rendezvous-relay/#{control}.json",
            "redacted" => true
          }
        end
      }
    }
  end

  def required_controls
    %w[
      tls
      authentication
      signed_expiring_records
      rate_limits
      abuse_logs
      revocation_propagation
      relay_denial
      retention
      key_rotation
      endpoint_rotation
      incident_shutdown
    ]
  end
end
