# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "time"
require "tmpdir"

class RendezvousRelayProductionEvidenceTest < Minitest::Test
  SCRIPT_PATH = File.expand_path("verify-rendezvous-relay-production-evidence.rb", __dir__)
  COMMIT_SHA = "a" * 40
  RELEASE_REF = "refs/tags/v1.0.0"
  DEPLOYMENT_ID = "qlink-control-plane-2026-07-09"

  REQUIRED_ASSERTIONS = {
    "tls" => %w[tls_enabled certificate_valid rotation_tested],
    "authentication" => %w[authorized_accepted unauthorized_rejected],
    "signed_expiring_records" => %w[valid_record_accepted expired_rejected replay_rejected malformed_signature_rejected revoked_key_rejected],
    "rate_limits" => %w[identity_limit_enforced source_limit_enforced endpoint_limit_enforced entitlement_limit_enforced],
    "abuse_logs" => %w[decisions_recorded payloads_excluded secrets_excluded],
    "revocation_propagation" => %w[publish_under_60s lookup_under_60s relay_under_60s],
    "relay_denial" => %w[entitlement_denied policy_denied revoked_denied expired_denied rate_limited_denied],
    "retention" => %w[metadata_only packet_payloads_excluded game_payloads_excluded],
    "key_rotation" => %w[dual_key_rotation_passed old_key_rejected],
    "endpoint_rotation" => %w[replacement_validated old_endpoint_drained],
    "incident_shutdown" => %w[publish_disabled relay_allocations_disabled revocations_applied]
  }.freeze

  def setup
    @tmpdir = Dir.mktmpdir("qlink-windows-rendezvous-relay-evidence")
    @generated_at = Time.now.utc.iso8601
    @rendezvous_endpoints = ["https://rv.quantumlinkvpn.com"]
    @relay_endpoints = ["turns:relay.quantumlinkvpn.com:5349"]
    @endpoint_digest = Digest::SHA256.hexdigest(JSON.generate({
      "rendezvousEndpoints" => @rendezvous_endpoints,
      "relayEndpoints" => @relay_endpoints
    }))
    write_control_evidence
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.directory?(@tmpdir)
  end

  def test_valid_manifest_is_fresh_release_bound_and_ready
    manifest = write_manifest("valid.json")
    stdout, stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal true, report.fetch("productionEvidenceReady")
    assert_equal 11, report.fetch("controlEvidence").length
    assert_empty report.fetch("blockers")
    assert_empty report.fetch("failures")
  end

  def test_blocked_manifest_is_valid_but_not_ready
    manifest = write_manifest("blocked.json") { |value| value["status"] = "blocked" }
    stdout, stderr, status = run_verifier(manifest, require_ready: false)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("blockers"), "production evidence status is blocked"
  end

  def test_require_ready_needs_release_binding_arguments
    manifest = write_manifest("unbound.json")
    stdout, _stderr, status = invoke("--require-ready", manifest)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "--expected-sha is required with --require-ready"
    assert_includes report.fetch("failures"), "--expected-ref is required with --require-ready"
  end

  def test_release_binding_mismatch_fails
    manifest = write_manifest("wrong-release.json")
    stdout, _stderr, status = invoke(
      "--require-ready", "--expected-sha", "b" * 40,
      "--expected-ref", "refs/tags/v2.0.0", manifest
    )
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "release.commitSha does not match the current release commit"
    assert_includes report.fetch("failures"), "release.ref does not match the current release ref"
  end

  def test_reserved_placeholder_endpoints_fail
    manifest = write_manifest("placeholder.json") do |value|
      value["rendezvousRelay"]["rendezvousEndpoints"] = ["https://rv.production.invalid"]
      value["rendezvousRelay"]["relayEndpoints"] = ["turns:relay.production.invalid:5349"]
    end
    stdout, _stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "rendezvousRelay.rendezvousEndpoints must contain only production HTTPS URLs"
    assert_includes report.fetch("failures"), "rendezvousRelay.relayEndpoints must contain only production turns or HTTPS endpoints"
  end

  def test_manifest_must_be_repo_relative_and_contained
    absolute = File.join(@tmpdir, write_manifest("absolute.json"))
    stdout, _stderr, status = invoke(
      "--require-ready", "--expected-sha", COMMIT_SHA,
      "--expected-ref", RELEASE_REF, absolute
    )
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "manifest must be a repo-relative path"
  end

  def test_missing_manifest_is_a_blocker
    missing = "windows/validation/missing.json"
    stdout, stderr, status = run_verifier(missing, require_ready: false)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("blockers"), "production evidence manifest is missing: #{missing}"
  end

  def test_control_evidence_must_be_distinct_control_specific_json
    manifest = write_manifest("shared.json") do |value|
      controls = value["rendezvousRelay"]["controls"]
      controls[1]["evidence"] = controls[0]["evidence"]
      controls[1]["sha256"] = controls[0]["sha256"]
    end
    stdout, _stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)

    refute status.success?
    assert report.fetch("failures").any? { |message| message.include?("must not share an evidence file") }
  end

  def test_control_digest_and_required_assertions_are_enforced
    path = control_path("tls")
    manifest = write_manifest("tampered.json")
    proof = JSON.parse(File.read(File.join(@tmpdir, path)))
    proof["assertions"].reject! { |entry| entry["name"] == "certificate_valid" }
    File.write(File.join(@tmpdir, path), "#{JSON.pretty_generate(proof)}\n")
    stdout, _stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "rendezvous/relay control tls evidence SHA-256 does not match"
    assert_includes report.fetch("failures"), "rendezvous/relay control tls missing passing assertion: certificate_valid"
  end

  def test_stale_and_future_evidence_fail
    stale_path = control_path("tls")
    stale = JSON.parse(File.read(File.join(@tmpdir, stale_path)))
    stale["generatedAt"] = (Time.now.utc - (8 * 24 * 60 * 60)).iso8601
    File.write(File.join(@tmpdir, stale_path), "#{JSON.pretty_generate(stale)}\n")

    manifest = write_manifest("time-invalid.json") do |value|
      value["generatedAt"] = (Time.now.utc + 600).iso8601
      entry = value["rendezvousRelay"]["controls"].find { |item| item["control"] == "tls" }
      entry["sha256"] = Digest::SHA256.file(File.join(@tmpdir, stale_path)).hexdigest
    end
    stdout, _stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)

    refute status.success?
    assert report.fetch("failures").any? { |message| message.include?("generatedAt is more than 300 seconds in the future") }
    assert report.fetch("failures").any? { |message| message.include?("control tls generatedAt is older than 604800 seconds") }
  end

  def test_verification_report_is_written_for_release_staging
    manifest = write_manifest("reported.json")
    report_path = "windows/build/validation/rendezvous-relay-production-evidence-verification.json"
    _stdout, stderr, status = run_verifier(manifest, report: report_path)

    assert status.success?, stderr
    report = JSON.parse(File.read(File.join(@tmpdir, report_path)))
    assert_equal "windowsRendezvousRelayProductionEvidenceVerification", report.fetch("evidenceKind")
    assert_equal COMMIT_SHA, report.fetch("expectedRelease").fetch("commitSha")
    assert_equal 11, report.fetch("controlEvidence").length
  end

  private

  def invoke(*args)
    Open3.capture3("ruby", SCRIPT_PATH, "--repo-root", @tmpdir, *args, chdir: @tmpdir)
  end

  def run_verifier(manifest, require_ready: true, report: nil)
    args = []
    args << "--require-ready" if require_ready
    args += ["--expected-sha", COMMIT_SHA, "--expected-ref", RELEASE_REF]
    args += ["--report", report] if report
    invoke(*args, manifest)
  end

  def control_path(control)
    "windows/validation/rendezvous-relay/#{control}.json"
  end

  def write_control_evidence
    REQUIRED_ASSERTIONS.each do |control, assertions|
      path = File.join(@tmpdir, control_path(control))
      FileUtils.mkdir_p(File.dirname(path))
      proof = {
        "schemaVersion" => 1,
        "evidenceKind" => "windowsRendezvousRelayControlEvidence",
        "control" => control,
        "status" => "pass",
        "generatedAt" => @generated_at,
        "deploymentId" => DEPLOYMENT_ID,
        "releaseCommitSha" => COMMIT_SHA,
        "releaseRef" => RELEASE_REF,
        "endpointSetSha256" => @endpoint_digest,
        "redacted" => true,
        "assertions" => assertions.map { |name| { "name" => name, "status" => "pass" } }
      }
      File.write(path, "#{JSON.pretty_generate(proof)}\n")
    end
  end

  def write_manifest(name)
    relative = "windows/validation/manifests/#{name}"
    path = File.join(@tmpdir, relative)
    FileUtils.mkdir_p(File.dirname(path))
    manifest = valid_manifest
    yield manifest if block_given?
    File.write(path, "#{JSON.pretty_generate(manifest)}\n")
    relative
  end

  def valid_manifest
    {
      "schemaVersion" => 2,
      "evidenceKind" => "windowsRendezvousRelayProductionEvidence",
      "product" => "QuantumLink Windows",
      "platform" => "windows",
      "releaseScope" => "windows-x64-production-release",
      "generatedAt" => @generated_at,
      "status" => "pass",
      "release" => { "commitSha" => COMMIT_SHA, "ref" => RELEASE_REF },
      "deploymentId" => DEPLOYMENT_ID,
      "rendezvousRelay" => {
        "status" => "pass",
        "rendezvousEndpoints" => @rendezvous_endpoints,
        "relayEndpoints" => @relay_endpoints,
        "endpointSetSha256" => @endpoint_digest,
        "abuseLogsRedacted" => true,
        "rawPacketPayloadsCommitted" => false,
        "rawGamePayloadsCommitted" => false,
        "controls" => REQUIRED_ASSERTIONS.keys.map do |control|
          relative = control_path(control)
          {
            "control" => control,
            "status" => "pass",
            "evidence" => relative,
            "sha256" => Digest::SHA256.file(File.join(@tmpdir, relative)).hexdigest,
            "redacted" => true
          }
        end
      }
    }
  end
end
