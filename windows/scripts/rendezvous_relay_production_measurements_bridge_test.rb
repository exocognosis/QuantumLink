# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "time"
require "tmpdir"

class RendezvousRelayProductionMeasurementsBridgeTest < Minitest::Test
  COLLECTOR = File.expand_path("collect-rendezvous-relay-production-measurements.rb", __dir__)
  GENERATOR = File.expand_path("generate-rendezvous-relay-production-evidence.rb", __dir__)
  VERIFIER = File.expand_path("verify-rendezvous-relay-production-evidence.rb", __dir__)
  COMMIT_SHA = "b" * 40
  RELEASE_REF = "refs/tags/v1.1.0"
  DEPLOYMENT_ID = "qlink-control-plane-2026-07-25"
  PUBLIC_EDGE_ASSERTIONS = [
    ["tls", "tls_enabled"],
    ["authentication", "authorized_accepted"],
    ["authentication", "unauthorized_rejected"]
  ].freeze
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
    @tmpdir = Dir.mktmpdir("qlink-rendezvous-relay-bridge")
    @generated_at = Time.now.utc.iso8601
    @rendezvous_endpoints = ["https://rv.quantumlinkvpn.com"]
    @relay_endpoints = ["turns:relay.quantumlinkvpn.com:5349"]
    @endpoint_digest = Digest::SHA256.hexdigest(JSON.generate({
      "rendezvousEndpoints" => @rendezvous_endpoints,
      "relayEndpoints" => @relay_endpoints
    }))
    @contract = write_contract
    @public_manifest = write_public_edge_manifest
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.directory?(@tmpdir)
  end

  def test_public_edge_bridge_generates_partial_measurements_without_claiming_production_ready
    stdout, stderr, status = invoke_collector
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal "blocked", result.fetch("status")
    assert_equal 3, result.fetch("passingAssertionCount")
    assert_equal 32, result.fetch("blockedAssertionCount")

    measurement = JSON.parse(File.read(File.join(@tmpdir, "windows/build/validation/rendezvous-relay-production-measurements.json")))
    assert_equal "windowsRendezvousRelayMeasuredControls", measurement.fetch("evidenceKind")
    assert_equal "blocked", measurement.fetch("status")
    assert_equal PUBLIC_EDGE_ASSERTIONS.map { |control, assertion| "#{control}/#{assertion}" },
                 measurement.fetch("publicEdgeBridge").fetch("supportedAssertions")
    assert_equal "blocked", measurement.fetch("controls").find { |entry| entry.fetch("control") == "tls" }.fetch("status")
    assert_equal "pass", measurement.fetch("controls").find { |entry| entry.fetch("control") == "authentication" }.fetch("status")

    generator_stdout, generator_stderr, generator_status = invoke_generator
    generator_result = JSON.parse(generator_stdout)
    assert generator_status.success?, generator_stderr
    assert_equal "blocked", generator_result.fetch("status")
    assert_equal false, generator_result.fetch("productionEvidenceReady")

    verifier_stdout, verifier_stderr, verifier_status = invoke_verifier(generator_result.fetch("manifest"), require_ready: false)
    verifier_report = JSON.parse(verifier_stdout)
    assert verifier_status.success?, verifier_stderr
    assert_equal true, verifier_report.fetch("valid")
    assert_equal false, verifier_report.fetch("productionEvidenceReady")
  end

  def test_operator_sources_complete_the_bridge_for_existing_generator_and_verifier
    operator_sources = write_operator_sources
    stdout, stderr, status = invoke_collector(*operator_sources.flat_map { |path| ["--operator-source", path] })
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal "pass", result.fetch("status")
    assert_equal 35, result.fetch("passingAssertionCount")
    assert_equal 0, result.fetch("blockedAssertionCount")

    generator_stdout, generator_stderr, generator_status = invoke_generator
    generator_result = JSON.parse(generator_stdout)
    assert generator_status.success?, generator_stderr
    assert_equal "pass", generator_result.fetch("status")
    assert_equal true, generator_result.fetch("productionEvidenceReady")

    verifier_stdout, verifier_stderr, verifier_status = invoke_verifier(generator_result.fetch("manifest"))
    verifier_report = JSON.parse(verifier_stdout)
    assert verifier_status.success?, verifier_stderr
    assert_equal true, verifier_report.fetch("productionEvidenceReady")
    assert_equal 11, verifier_report.fetch("controlEvidence").length
  end

  def test_public_edge_bridge_rejects_non_ready_public_evidence
    manifest_path = File.join(@tmpdir, @public_manifest)
    manifest = JSON.parse(File.read(manifest_path))
    manifest["status"] = "blocked"
    File.write(manifest_path, "#{JSON.pretty_generate(manifest)}\n")

    stdout, stderr, status = invoke_collector
    refute status.success?, stdout
    assert_includes stderr, "public-edge manifest and verification reports must be passing"
  end

  private

  def invoke_collector(*extra_args)
    Open3.capture3(
      "ruby", COLLECTOR,
      "--repo-root", @tmpdir,
      "--contract", @contract,
      "--public-edge-manifest", @public_manifest,
      "--output", "windows/build/validation/rendezvous-relay-production-measurements.json",
      "--source-directory", "windows/build/validation/rendezvous-relay-sources/from-public-edge",
      *extra_args,
      chdir: @tmpdir
    )
  end

  def invoke_generator
    Open3.capture3(
      "ruby", GENERATOR,
      "--repo-root", @tmpdir,
      "--contract", @contract,
      "--measurements", "windows/build/validation/rendezvous-relay-production-measurements.json",
      "--expected-sha", COMMIT_SHA,
      "--expected-ref", RELEASE_REF,
      chdir: @tmpdir
    )
  end

  def invoke_verifier(manifest, require_ready: true)
    args = []
    args << "--require-ready" if require_ready
    Open3.capture3(
      "ruby", VERIFIER,
      "--repo-root", @tmpdir,
      "--expected-sha", COMMIT_SHA,
      "--expected-ref", RELEASE_REF,
      *args,
      manifest,
      chdir: @tmpdir
    )
  end

  def write_contract
    relative = "windows/deployment/rendezvous-relay-production.json"
    write_json(relative, {
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
        "manifest" => "windows/validation/rendezvous-relay-production-evidence.json",
        "controlDirectory" => "windows/validation/rendezvous-relay",
        "digestManifest" => "windows/validation/rendezvous-relay-production-evidence-digests.json",
        "checksums" => "windows/validation/rendezvous-relay-production-evidence-SHA256SUMS.txt"
      }
    })
    relative
  end

  def write_public_edge_manifest
    app_evidence = write_json("build/public-edge-live-evidence/app-relay/evidence.json", public_edge_evidence("relay"))
    turn_evidence = write_json("build/public-edge-live-evidence/turn-relay/evidence.json", public_edge_evidence("turn-relay"))
    app_verification = write_json("build/public-edge-live-evidence/app-relay-verification.json", public_verification("relay"))
    turn_verification = write_json("build/public-edge-live-evidence/turn-relay-verification.json", public_verification("turn-relay"))
    manifest = {
      "schemaVersion" => 1,
      "evidenceKind" => "quantumLinkPublicEdgeLiveEvidence",
      "generatedAt" => @generated_at,
      "gitSha" => COMMIT_SHA,
      "mode" => "public",
      "status" => "pass",
      "endpoints" => {
        "rendezvous" => "tls://rv.quantumlinkvpn.com:9471",
        "relay" => "tls://relay.quantumlinkvpn.com:9472",
        "stun" => "stun.quantumlinkvpn.com:3478",
        "turn" => "turn.quantumlinkvpn.com:3478"
      },
      "credentialSources" => {
        "controlTlsCa" => "file",
        "rendezvousAuth" => "file",
        "relayAuth" => "file",
        "turnPassword" => "file"
      },
      "proofs" => {
        "appRelay" => {
          "evidence" => app_evidence,
          "verification" => app_verification,
          "selectedPath" => "relay",
          "framesSent" => 3,
          "publicInfraReady" => true
        },
        "turnRelay" => {
          "evidence" => turn_evidence,
          "verification" => turn_verification,
          "selectedPath" => "turn-relay",
          "framesSent" => 3,
          "publicInfraReady" => true
        }
      }
    }
    relative = "build/public-edge-live-evidence/manifest.json"
    write_json(relative, manifest)
    relative
  end

  def public_edge_evidence(selected_path)
    turn_relay = selected_path == "turn-relay"
    {
      "generated_at" => @generated_at,
      "git_sha" => COMMIT_SHA,
      "mode" => "public",
      "mesh_id" => "public-edge-live-evidence",
      "rendezvous" => "tls://rv.quantumlinkvpn.com:9471",
      "relay" => "tls://relay.quantumlinkvpn.com:9472",
      "stun" => "stun.quantumlinkvpn.com:3478",
      "turn" => "turn.quantumlinkvpn.com:3478",
      "control_tls_ca_configured" => true,
      "rendezvous_tls_enabled" => true,
      "relay_tls_enabled" => true,
      "rendezvous_auth_required" => true,
      "relay_auth_required" => true,
      "rendezvous_auth_verified" => true,
      "relay_auth_verified" => true,
      "rendezvous_rate_limit_per_window" => 120,
      "relay_rate_limit_per_window" => 240,
      "admission_rate_limit_window_seconds" => 60,
      "prove_turn_relay" => turn_relay,
      "published_candidate_types" => turn_relay ? "Relay" : "Host,ServerReflexive,Relay,QuantumLinkRelay",
      "selected_path" => selected_path,
      "frames_sent" => 3,
      "total_elapsed_ms" => 57
    }
  end

  def public_verification(selected_path)
    {
      "evidenceKind" => "quantumLinkPublicInfraEvidenceVerification",
      "verifiedAt" => @generated_at,
      "expectedGitSha" => COMMIT_SHA,
      "mode" => "public",
      "requirePublic" => true,
      "valid" => true,
      "publicInfraReady" => true,
      "selectedPath" => selected_path,
      "framesSent" => 3,
      "failures" => [],
      "blockers" => [],
      "warnings" => []
    }
  end

  def write_operator_sources
    sources = []
    REQUIRED_ASSERTIONS.each do |control, assertions|
      assertions.each do |assertion|
        next if PUBLIC_EDGE_ASSERTIONS.include?([control, assertion])

        relative = "windows/validation/operator-sources/#{control}/#{assertion}.json"
        write_json(relative, source_evidence(control, assertion))
        sources << relative
      end
    end
    sources
  end

  def source_evidence(control, assertion)
    {
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
  end

  def write_json(relative, value)
    path = File.join(@tmpdir, relative)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "#{JSON.pretty_generate(value)}\n")
    relative
  end
end
