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
  GENERATOR_PATH = File.expand_path("generate-rendezvous-relay-production-evidence.rb", __dir__)
  COMMIT_SHA = "a" * 40
  RELEASE_REF = "refs/tags/v1.0.0"
  DEPLOYMENT_ID = "qlink-control-plane-2026-07-09"
  MAX_SOURCE_BYTES = 1_048_576

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
    write_source_evidence
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
    assert_equal 35, report.fetch("controlEvidence").sum { |entry| entry.fetch("sources").length }
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

  def test_ip_private_and_example_hosts_fail
    [
      ["https://127.0.0.1", "turns:10.0.0.1:5349"],
      ["https://rv.example.com", "turns:relay.example.net:5349"],
      ["https://..", "turns:..:5349"]
    ].each do |rendezvous, relay|
      manifest = write_manifest("bad-host-#{Digest::SHA256.hexdigest(rendezvous)[0, 8]}.json") do |value|
        value["rendezvousRelay"]["rendezvousEndpoints"] = [rendezvous]
        value["rendezvousRelay"]["relayEndpoints"] = [relay]
      end
      stdout, _stderr, status = run_verifier(manifest)
      report = JSON.parse(stdout)

      refute status.success?
      assert_includes report.fetch("failures"), "rendezvousRelay.rendezvousEndpoints must contain only production HTTPS URLs"
      assert_includes report.fetch("failures"), "rendezvousRelay.relayEndpoints must contain only production turns or HTTPS endpoints"
    end
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

  def test_blocked_control_proof_remains_structurally_valid
    proof_path = File.join(@tmpdir, control_path("tls"))
    proof = JSON.parse(File.read(proof_path))
    proof["status"] = "blocked"
    proof["assertions"].each do |assertion|
      assertion.replace("name" => assertion.fetch("name"), "status" => "blocked", "measured" => false)
    end
    File.write(proof_path, "#{JSON.pretty_generate(proof)}\n")

    manifest = write_manifest("blocked-control.json") do |value|
      entry = value.fetch("rendezvousRelay").fetch("controls").find { |item| item["control"] == "tls" }
      entry["status"] = "blocked"
      entry["sha256"] = Digest::SHA256.file(proof_path).hexdigest
    end
    stdout, stderr, status = run_verifier(manifest, require_ready: false)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert_includes report.fetch("blockers"), "rendezvous/relay control tls status is blocked"
  end

  def test_invented_hashes_and_unmeasured_assertions_cannot_claim_readiness
    tls_path = File.join(@tmpdir, control_path("tls"))
    tls = JSON.parse(File.read(tls_path))
    tls.fetch("assertions").first["sourceSha256"] = "f" * 64
    File.write(tls_path, "#{JSON.pretty_generate(tls)}\n")

    authentication_path = File.join(@tmpdir, control_path("authentication"))
    authentication = JSON.parse(File.read(authentication_path))
    authentication.fetch("assertions").first["measured"] = false
    File.write(authentication_path, "#{JSON.pretty_generate(authentication)}\n")

    manifest = write_manifest("self-attested.json") do |value|
      controls = value.fetch("rendezvousRelay").fetch("controls")
      controls.find { |item| item["control"] == "tls" }["sha256"] = Digest::SHA256.file(tls_path).hexdigest
      controls.find { |item| item["control"] == "authentication" }["sha256"] = Digest::SHA256.file(authentication_path).hexdigest
    end
    stdout, _stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)

    refute status.success?
    assert_equal false, report.fetch("valid")
    assert_equal false, report.fetch("productionEvidenceReady")
    assert report.fetch("failures").any? { |message| message.include?("source SHA-256 does not match") }
    assert report.fetch("failures").any? { |message| message.include?("must be explicitly measured") }
  end

  def test_passing_assertions_cannot_share_a_source_evidence_file
    proof_path = File.join(@tmpdir, control_path("tls"))
    proof = JSON.parse(File.read(proof_path))
    assertions = proof.fetch("assertions")
    assertions[1]["source"] = assertions[0].fetch("source")
    assertions[1]["sourceSha256"] = assertions[0].fetch("sourceSha256")
    File.write(proof_path, "#{JSON.pretty_generate(proof)}\n")

    manifest = write_manifest("shared-source.json") do |value|
      entry = value.fetch("rendezvousRelay").fetch("controls").find { |item| item["control"] == "tls" }
      entry["sha256"] = Digest::SHA256.file(proof_path).hexdigest
    end
    stdout, _stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)

    refute status.success?
    assert_equal false, report.fetch("productionEvidenceReady")
    assert report.fetch("failures").any? { |message| message.include?("must use a distinct source evidence file") }
  end

  def test_source_evidence_must_be_fresh
    source_pathname = File.join(@tmpdir, source_path("tls", "tls_enabled"))
    source = JSON.parse(File.read(source_pathname))
    source["generatedAt"] = (Time.now.utc - (8 * 24 * 60 * 60)).iso8601
    File.write(source_pathname, "#{JSON.pretty_generate(source)}\n")

    proof_path = File.join(@tmpdir, control_path("tls"))
    proof = JSON.parse(File.read(proof_path))
    proof.fetch("assertions").first["sourceSha256"] = Digest::SHA256.file(source_pathname).hexdigest
    File.write(proof_path, "#{JSON.pretty_generate(proof)}\n")
    manifest = write_manifest("stale-source.json") do |value|
      entry = value.fetch("rendezvousRelay").fetch("controls").find { |item| item["control"] == "tls" }
      entry["sha256"] = Digest::SHA256.file(proof_path).hexdigest
    end

    stdout, _stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)
    refute status.success?
    assert_equal false, report.fetch("productionEvidenceReady")
    assert report.fetch("failures").any? { |message| message.include?("source generatedAt is older than 604800 seconds") }
  end

  def test_source_evidence_is_bounded
    source_pathname = File.join(@tmpdir, source_path("tls", "tls_enabled"))
    File.open(source_pathname, "wb") do |file|
      file.write("{\"padding\":\"")
      file.write("a" * MAX_SOURCE_BYTES)
      file.write("\"}\n")
    end

    proof_path = File.join(@tmpdir, control_path("tls"))
    proof = JSON.parse(File.read(proof_path))
    proof.fetch("assertions").first["sourceSha256"] = Digest::SHA256.file(source_pathname).hexdigest
    File.write(proof_path, "#{JSON.pretty_generate(proof)}\n")
    manifest = write_manifest("oversized-source.json") do |value|
      entry = value.fetch("rendezvousRelay").fetch("controls").find { |item| item["control"] == "tls" }
      entry["sha256"] = Digest::SHA256.file(proof_path).hexdigest
    end

    stdout, _stderr, status = run_verifier(manifest)
    report = JSON.parse(stdout)
    refute status.success?
    assert_equal false, report.fetch("productionEvidenceReady")
    assert report.fetch("failures").any? { |message| message.include?("source evidence exceeds #{MAX_SOURCE_BYTES} bytes") }
  end

  def test_generator_hashes_and_preserves_bound_source_evidence
    contract = write_contract
    measurements = write_measurements("measurements.json", include_sources: true)
    stdout, stderr, status = invoke_generator(contract, measurements)
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, result.fetch("productionEvidenceReady")
    proof = JSON.parse(File.read(File.join(@tmpdir, control_path("tls"))))
    assertion = proof.fetch("assertions").find { |item| item["name"] == "tls_enabled" }
    assert_equal source_path("tls", "tls_enabled"), assertion.fetch("source")
    assert_equal Digest::SHA256.file(File.join(@tmpdir, assertion.fetch("source"))).hexdigest,
                 assertion.fetch("sourceSha256")

    verifier_stdout, verifier_stderr, verifier_status = run_verifier(result.fetch("manifest"))
    verifier_report = JSON.parse(verifier_stdout)
    assert verifier_status.success?, verifier_stderr
    assert_equal true, verifier_report.fetch("productionEvidenceReady")
  end

  def test_generator_does_not_accept_invented_hashes_without_source_files
    contract = write_contract
    measurements = write_measurements("invented-measurements.json", include_sources: false)
    stdout, stderr, status = invoke_generator(contract, measurements)
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal false, result.fetch("productionEvidenceReady")
    assert_equal "blocked", result.fetch("status")
    proof = JSON.parse(File.read(File.join(@tmpdir, control_path("tls"))))
    proof.fetch("assertions").each do |assertion|
      assert_equal false, assertion.fetch("measured")
      refute assertion.key?("source")
      refute assertion.key?("sourceSha256")
    end
  end

  def test_generator_rejects_source_evidence_with_wrong_assertion_binding
    source = File.join(@tmpdir, source_path("tls", "tls_enabled"))
    value = JSON.parse(File.read(source))
    value["assertion"] = "certificate_valid"
    File.write(source, "#{JSON.pretty_generate(value)}\n")

    contract = write_contract
    measurements = write_measurements("wrong-binding-measurements.json", include_sources: true)
    _stdout, stderr, status = invoke_generator(contract, measurements)

    refute status.success?
    assert_includes stderr, "source evidence for tls/tls_enabled assertion does not match"
  end

  def test_generator_rejects_claimed_source_digest_that_does_not_match_file
    contract = write_contract
    measurements = write_measurements("wrong-digest-measurements.json", include_sources: true)
    path = File.join(@tmpdir, measurements)
    value = JSON.parse(File.read(path))
    value.fetch("controls").first.fetch("assertions").first["sourceSha256"] = "f" * 64
    File.write(path, "#{JSON.pretty_generate(value)}\n")

    _stdout, stderr, status = invoke_generator(contract, measurements)

    refute status.success?
    assert_includes stderr, "source evidence for tls/tls_enabled sourceSha256 does not match the source file"
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

  def invoke_generator(contract, measurements)
    Open3.capture3(
      "ruby", GENERATOR_PATH,
      "--repo-root", @tmpdir,
      "--contract", contract,
      "--measurements", measurements,
      "--expected-sha", COMMIT_SHA,
      "--expected-ref", RELEASE_REF,
      chdir: @tmpdir
    )
  end

  def control_path(control)
    "windows/validation/rendezvous-relay/#{control}.json"
  end

  def source_path(control, assertion)
    "windows/validation/rendezvous-relay-sources/#{control}/#{assertion}.json"
  end

  def write_source_evidence
    REQUIRED_ASSERTIONS.each do |control, assertions|
      assertions.each do |assertion|
        path = File.join(@tmpdir, source_path(control, assertion))
        FileUtils.mkdir_p(File.dirname(path))
        proof = {
          "schemaVersion" => 1,
          "evidenceKind" => "windowsRendezvousRelayAssertionSourceEvidence",
          "control" => control,
          "assertion" => assertion,
          "status" => "pass",
          "measured" => true,
          "generatedAt" => @generated_at,
          "deploymentId" => DEPLOYMENT_ID,
          "releaseCommitSha" => COMMIT_SHA,
          "releaseRef" => RELEASE_REF,
          "endpointSetSha256" => @endpoint_digest,
          "redacted" => true
        }
        File.write(path, "#{JSON.pretty_generate(proof)}\n")
      end
    end
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
        "assertions" => assertions.map do |name|
          source = source_path(control, name)
          {
            "name" => name,
            "status" => "pass",
            "measured" => true,
            "source" => source,
            "sourceSha256" => Digest::SHA256.file(File.join(@tmpdir, source)).hexdigest
          }
        end
      }
      File.write(path, "#{JSON.pretty_generate(proof)}\n")
    end
  end

  def write_contract
    relative = "windows/deployment/rendezvous-relay-production.json"
    path = File.join(@tmpdir, relative)
    FileUtils.mkdir_p(File.dirname(path))
    contract = {
      "schemaVersion" => 1,
      "evidenceKind" => "windowsRendezvousRelayDeploymentContract",
      "status" => "pass",
      "release" => { "commitSha" => COMMIT_SHA, "ref" => RELEASE_REF },
      "deployment" => { "id" => DEPLOYMENT_ID, "status" => "pass" },
      "rendezvousEndpoints" => @rendezvous_endpoints,
      "relayEndpoints" => @relay_endpoints,
      "prerequisites" => [
        { "id" => "production_measurements", "status" => "pass", "reason" => "Measured production evidence supplied." }
      ],
      "output" => {
        "manifest" => "windows/validation/generated-production-evidence.json",
        "controlDirectory" => "windows/validation/rendezvous-relay",
        "digestManifest" => "windows/validation/generated-production-evidence-digests.json",
        "checksums" => "windows/validation/generated-production-evidence-SHA256SUMS.txt"
      }
    }
    File.write(path, "#{JSON.pretty_generate(contract)}\n")
    relative
  end

  def write_measurements(name, include_sources:)
    relative = "windows/validation/#{name}"
    path = File.join(@tmpdir, relative)
    FileUtils.mkdir_p(File.dirname(path))
    measurement = {
      "schemaVersion" => 1,
      "evidenceKind" => "windowsRendezvousRelayMeasuredControls",
      "measurementKind" => "measured",
      "release" => { "commitSha" => COMMIT_SHA, "ref" => RELEASE_REF },
      "deploymentId" => DEPLOYMENT_ID,
      "endpointSetSha256" => @endpoint_digest,
      "controls" => REQUIRED_ASSERTIONS.map do |control, assertions|
        {
          "control" => control,
          "status" => "pass",
          "assertions" => assertions.map do |assertion|
            item = {
              "name" => assertion,
              "status" => "pass",
              "measured" => true,
              "sourceSha256" => "f" * 64
            }
            if include_sources
              item["source"] = source_path(control, assertion)
              item.delete("sourceSha256")
            end
            item
          end
        }
      end
    }
    File.write(path, "#{JSON.pretty_generate(measurement)}\n")
    relative
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
