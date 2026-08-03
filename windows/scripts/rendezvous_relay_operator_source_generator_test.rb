# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "time"
require "tmpdir"

class RendezvousRelayOperatorSourceGeneratorTest < Minitest::Test
  GENERATOR = File.expand_path("generate-rendezvous-relay-operator-sources.rb", __dir__)
  COLLECTOR = File.expand_path("collect-rendezvous-relay-production-measurements.rb", __dir__)
  COMMIT_SHA = "c" * 40
  RELEASE_REF = "refs/tags/v1.2.0"
  DEPLOYMENT_ID = "qlink-control-plane-2026-08-03"
  GENERATED_ASSERTIONS = [
    ["tls", "certificate_valid"],
    ["tls", "rotation_tested"],
    ["signed_expiring_records", "valid_record_accepted"],
    ["signed_expiring_records", "expired_rejected"],
    ["signed_expiring_records", "replay_rejected"],
    ["signed_expiring_records", "malformed_signature_rejected"],
    ["signed_expiring_records", "revoked_key_rejected"],
    ["rate_limits", "identity_limit_enforced"],
    ["rate_limits", "source_limit_enforced"],
    ["rate_limits", "entitlement_limit_enforced"],
    ["abuse_logs", "decisions_recorded"],
    ["abuse_logs", "payloads_excluded"],
    ["abuse_logs", "secrets_excluded"],
    ["relay_denial", "entitlement_denied"],
    ["relay_denial", "policy_denied"],
    ["relay_denial", "revoked_denied"],
    ["relay_denial", "expired_denied"],
    ["retention", "metadata_only"],
    ["retention", "packet_payloads_excluded"],
    ["retention", "game_payloads_excluded"]
  ].freeze

  def setup
    @tmpdir = Dir.mktmpdir("qlink-rendezvous-relay-operator-source-generator")
    @generated_at = Time.now.utc.iso8601
    @rendezvous_endpoints = ["https://rv.quantumlinkvpn.com"]
    @relay_endpoints = ["turns:relay.quantumlinkvpn.com:5349"]
    @endpoint_digest = Digest::SHA256.hexdigest(JSON.generate({
      "rendezvousEndpoints" => @rendezvous_endpoints,
      "relayEndpoints" => @relay_endpoints
    }))
    @contract = write_contract
    @drill_report = write_json("windows/build/operator-drills/operator-controls.json", drill_report)
    @public_manifest = write_public_edge_manifest
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.directory?(@tmpdir)
  end

  def test_generator_writes_tls_and_signed_record_sources_consumed_by_measurement_collector
    stdout, stderr, status = invoke_generator
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal "pass", result.fetch("status")
    assert_equal 20, result.fetch("generatedSourceCount")
    assert_equal GENERATED_ASSERTIONS, result.fetch("sources").map { |entry| [entry.fetch("control"), entry.fetch("assertion")] }

    result.fetch("sources").each do |entry|
      source = JSON.parse(File.read(File.join(@tmpdir, entry.fetch("source"))))
      assert_equal "windowsRendezvousRelayAssertionSourceEvidence", source.fetch("evidenceKind")
      assert_equal true, source.fetch("measured")
      assert_equal true, source.fetch("redacted")
      assert_equal DEPLOYMENT_ID, source.fetch("deploymentId")
      assert_equal COMMIT_SHA, source.fetch("releaseCommitSha")
      assert_equal RELEASE_REF, source.fetch("releaseRef")
      assert_equal @endpoint_digest, source.fetch("endpointSetSha256")
      assert_equal Digest::SHA256.file(File.join(@tmpdir, entry.fetch("source"))).hexdigest, entry.fetch("sourceSha256")
    end

    collector_stdout, collector_stderr, collector_status = invoke_collector(
      *result.fetch("sources").flat_map { |entry| ["--operator-source", entry.fetch("source")] }
    )
    assert collector_status.success?, collector_stderr
    collector_result = JSON.parse(collector_stdout)
    assert_equal "blocked", collector_result.fetch("status")
    assert_equal 25, collector_result.fetch("passingAssertionCount")
    assert_equal 10, collector_result.fetch("blockedAssertionCount")
    measurement = JSON.parse(File.read(File.join(@tmpdir, "windows/build/validation/rendezvous-relay-production-measurements.json")))
    assert_equal "blocked", measurement.fetch("status")
    GENERATED_ASSERTIONS.each do |control, assertion|
      assert_assertion_status(measurement, control, assertion, "pass")
    end
  end

  def test_generator_rejects_unredacted_operator_reports
    report_path = File.join(@tmpdir, @drill_report)
    report = JSON.parse(File.read(report_path))
    report["redacted"] = false
    File.write(report_path, "#{JSON.pretty_generate(report)}\n")

    stdout, stderr, status = invoke_generator

    refute status.success?, stdout
    assert_includes stderr, "operator drill report must be redacted"
  end

  def test_generator_rejects_raw_certificate_material
    report_path = File.join(@tmpdir, @drill_report)
    report = JSON.parse(File.read(report_path))
    report.fetch("tls").fetch("certificateValidation").fetch("endpoints").first["rawCertificatePem"] =
      "-----BEGIN CERTIFICATE-----"
    File.write(report_path, "#{JSON.pretty_generate(report)}\n")

    stdout, stderr, status = invoke_generator

    refute status.success?, stdout
    assert_includes stderr, "operator drill report contains a forbidden secret or raw-evidence marker"
  end

  def test_generator_rejects_incomplete_expired_record_proof
    report_path = File.join(@tmpdir, @drill_report)
    report = JSON.parse(File.read(report_path))
    report.fetch("signedExpiringRecords").fetch("expiredRejected")["relayDenied"] = false
    File.write(report_path, "#{JSON.pretty_generate(report)}\n")

    stdout, stderr, status = invoke_generator("--assertion", "signed_expiring_records/expired_rejected")

    refute status.success?, stdout
    assert_includes stderr, "signed_expiring_records/expired_rejected relayDenied must be true"
  end

  def test_generator_rejects_incomplete_source_limit_proof
    report_path = File.join(@tmpdir, @drill_report)
    report = JSON.parse(File.read(report_path))
    report.fetch("rateLimits").fetch("sourceLimitEnforced")["overLimitDenied"] = false
    File.write(report_path, "#{JSON.pretty_generate(report)}\n")

    stdout, stderr, status = invoke_generator("--assertion", "rate_limits/source_limit_enforced")

    refute status.success?, stdout
    assert_includes stderr, "rate_limits/source_limit_enforced overLimitDenied must be true"
  end

  def test_generator_rejects_incomplete_relay_revoked_denial_proof
    report_path = File.join(@tmpdir, @drill_report)
    report = JSON.parse(File.read(report_path))
    report.fetch("relayDenial").fetch("revokedDenied")["relaySessionNotCreated"] = false
    File.write(report_path, "#{JSON.pretty_generate(report)}\n")

    stdout, stderr, status = invoke_generator("--assertion", "relay_denial/revoked_denied")

    refute status.success?, stdout
    assert_includes stderr, "relay_denial/revoked_denied relaySessionNotCreated must be true"
  end

  def test_generator_rejects_raw_abuse_log_preview_fields
    report_path = File.join(@tmpdir, @drill_report)
    report = JSON.parse(File.read(report_path))
    report.fetch("abuseLogs").fetch("payloadsExcluded")["rawPacketPreview"] = "redacted bytes"
    File.write(report_path, "#{JSON.pretty_generate(report)}\n")

    stdout, stderr, status = invoke_generator("--assertion", "abuse_logs/payloads_excluded")

    refute status.success?, stdout
    assert_includes stderr, "abuse_logs/payloads_excluded contains unsupported proof fields: rawPacketPreview"
  end

  def test_generator_rejects_incomplete_retention_game_payload_proof
    report_path = File.join(@tmpdir, @drill_report)
    report = JSON.parse(File.read(report_path))
    report.fetch("retention").fetch("gamePayloadsExcluded")["retentionScanPassed"] = false
    File.write(report_path, "#{JSON.pretty_generate(report)}\n")

    stdout, stderr, status = invoke_generator("--assertion", "retention/game_payloads_excluded")

    refute status.success?, stdout
    assert_includes stderr, "retention/game_payloads_excluded retentionScanPassed must be true"
  end

  private

  def invoke_generator(*extra_args)
    Open3.capture3(
      "ruby", GENERATOR,
      "--repo-root", @tmpdir,
      "--contract", @contract,
      "--drill-report", @drill_report,
      "--output-directory", "windows/validation/operator-sources",
      *extra_args,
      chdir: @tmpdir
    )
  end

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

  def write_contract
    write_json("windows/deployment/rendezvous-relay-production.json", {
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
  end

  def drill_report
    {
      "schemaVersion" => 1,
      "evidenceKind" => "windowsRendezvousRelayOperatorDrillReport",
      "status" => "pass",
      "generatedAt" => @generated_at,
      "drillId" => "tls-signed-records-2026-08-03",
      "deploymentId" => DEPLOYMENT_ID,
      "releaseCommitSha" => COMMIT_SHA,
      "releaseRef" => RELEASE_REF,
      "endpointSetSha256" => @endpoint_digest,
      "redacted" => true,
      "tls" => {
        "certificateValidation" => {
          "status" => "pass",
          "validatedAt" => @generated_at,
          "endpoints" => (@rendezvous_endpoints + @relay_endpoints).map.with_index do |endpoint, index|
            {
              "endpoint" => endpoint,
              "tlsEnabled" => true,
              "certificateChainValid" => true,
              "hostnameVerified" => true,
              "sanMatched" => true,
              "notExpired" => true,
              "leafFingerprintSha256" => ("%064x" % (index + 1))
            }
          end
        },
        "rotation" => {
          "status" => "pass",
          "validatedAt" => @generated_at,
          "replacementCertificateValid" => true,
          "oldCertificateRejected" => true,
          "rotationWindowValidated" => true,
          "allEndpointsValidated" => true
        }
      },
      "signedExpiringRecords" => {
        "validRecordAccepted" => {
          "status" => "pass",
          "signedByBoundKey" => true,
          "unexpired" => true,
          "publishAccepted" => true,
          "lookupAccepted" => true,
          "relayConsumerAccepted" => true
        },
        "expiredRejected" => {
          "status" => "pass",
          "expiredBeforeDecision" => true,
          "publishRejected" => true,
          "lookupRejected" => true,
          "relayDenied" => true
        },
        "replayRejected" => {
          "status" => "pass",
          "staleSequenceRejected" => true,
          "currentRecordPreserved" => true,
          "cacheUnchanged" => true
        },
        "malformedSignatureRejected" => {
          "status" => "pass",
          "signatureTamperRejected" => true,
          "publishRejected" => true,
          "cacheUnchanged" => true
        },
        "revokedKeyRejected" => {
          "status" => "pass",
          "keyRevokedBeforeSubmission" => true,
          "publishRejected" => true,
          "lookupRejected" => true,
          "relayDenied" => true
        }
      },
      "rateLimits" => {
        "identityLimitEnforced" => rate_limit_proof(limit: 120, attempted: 121),
        "sourceLimitEnforced" => rate_limit_proof(limit: 240, attempted: 241),
        "entitlementLimitEnforced" => rate_limit_proof(limit: 60, attempted: 61)
      },
      "abuseLogs" => {
        "decisionsRecorded" => {
          "status" => "pass",
          "decisionsSampled" => 12,
          "reasonCodes" => %w[auth_required policy_denied relay_quota_exceeded],
          "reasonCodeRecorded" => true,
          "endpointRecorded" => true,
          "decisionTimestampRecorded" => true,
          "requestIdRecorded" => true,
          "operatorReviewable" => true
        },
        "payloadsExcluded" => {
          "status" => "pass",
          "packetPayloadsAbsent" => true,
          "gamePayloadsAbsent" => true,
          "rawBodiesAbsent" => true,
          "payloadHashesOnly" => true,
          "redactionScanPassed" => true
        },
        "secretsExcluded" => {
          "status" => "pass",
          "privateKeysAbsent" => true,
          "walletStoresAbsent" => true,
          "entitlementTokensAbsent" => true,
          "serviceSecretsAbsent" => true,
          "redactionScanPassed" => true
        }
      },
      "relayDenial" => {
        "entitlementDenied" => relay_denial_proof("entitlementMissing", "entitlement_required"),
        "policyDenied" => relay_denial_proof("policyMatched", "policy_denied"),
        "revokedDenied" => relay_denial_proof("revocationApplied", "revoked_identity"),
        "expiredDenied" => relay_denial_proof("recordExpiredBeforeAllocation", "expired_peer_record")
      },
      "retention" => {
        "metadataOnly" => {
          "status" => "pass",
          "metadataOnlyConfigured" => true,
          "boundedRetentionConfigured" => true,
          "retentionDays" => 14,
          "exportDisabled" => true,
          "rawPayloadStorageDisabled" => true
        },
        "packetPayloadsExcluded" => {
          "status" => "pass",
          "packetPayloadsExcluded" => true,
          "packetCaptureDisabled" => true,
          "pcapArtifactsAbsent" => true,
          "retentionScanPassed" => true
        },
        "gamePayloadsExcluded" => {
          "status" => "pass",
          "gamePayloadsExcluded" => true,
          "applicationPayloadsAbsent" => true,
          "retainedBodyBytesZero" => true,
          "retentionScanPassed" => true
        }
      }
    }
  end

  def rate_limit_proof(limit:, attempted:)
    {
      "status" => "pass",
      "limitConfigured" => true,
      "limit" => limit,
      "attemptedCount" => attempted,
      "underLimitAccepted" => true,
      "overLimitDenied" => true,
      "retryAfterReturned" => true,
      "metricsIncremented" => true
    }
  end

  def relay_denial_proof(trigger_field, reason_code)
    {
      "status" => "pass",
      trigger_field => true,
      "allocationDenied" => true,
      "relaySessionNotCreated" => true,
      "clientReceivedDenial" => true,
      "metricsIncremented" => true,
      "reasonCode" => reason_code
    }
  end

  def write_public_edge_manifest
    app_evidence = write_json("build/public-edge-live-evidence/app-relay/evidence.json", public_edge_evidence("relay"))
    turn_evidence = write_json("build/public-edge-live-evidence/turn-relay/evidence.json", public_edge_evidence("turn-relay"))
    app_verification = write_json("build/public-edge-live-evidence/app-relay-verification.json", public_verification("relay"))
    turn_verification = write_json("build/public-edge-live-evidence/turn-relay-verification.json", public_verification("turn-relay"))
    write_json("build/public-edge-live-evidence/manifest.json", {
      "schemaVersion" => 1,
      "evidenceKind" => "quantumLinkPublicEdgeLiveEvidence",
      "generatedAt" => @generated_at,
      "gitSha" => COMMIT_SHA,
      "mode" => "public",
      "status" => "pass",
      "proofs" => {
        "appRelay" => { "evidence" => app_evidence, "verification" => app_verification, "selectedPath" => "relay", "framesSent" => 3, "publicInfraReady" => true },
        "turnRelay" => { "evidence" => turn_evidence, "verification" => turn_verification, "selectedPath" => "turn-relay", "framesSent" => 3, "publicInfraReady" => true }
      }
    })
  end

  def public_edge_evidence(selected_path)
    {
      "control_tls_ca_configured" => true,
      "rendezvous_tls_enabled" => true,
      "relay_tls_enabled" => true,
      "rendezvous_auth_verified" => true,
      "relay_auth_verified" => true,
      "rendezvous_auth_required" => true,
      "relay_auth_required" => true,
      "rendezvous_auth_failures_total" => 1,
      "relay_auth_failures_total" => 1,
      "bounds_verified" => true,
      "max_request_line_bytes" => 131_072,
      "max_concurrent_connections" => 1_024,
      "idle_timeout_seconds" => 300,
      "relay_max_payload_bytes" => 65_536,
      "relay_max_peer_id_bytes" => 256,
      "relay_max_registered_peers" => 2_048,
      "rendezvous_request_too_large_total" => 1,
      "relay_request_too_large_total" => 1,
      "relay_payload_too_large_total" => 1,
      "relay_payload_limit_verified" => true,
      "relay_saturation_limit_verified" => true,
      "relay_peer_rate_limited_total" => 1,
      "selected_path" => selected_path,
      "frames_sent" => 3
    }
  end

  def public_verification(selected_path)
    {
      "evidenceKind" => "quantumLinkPublicInfraEvidenceVerification",
      "verifiedAt" => @generated_at,
      "expectedGitSha" => COMMIT_SHA,
      "mode" => "public",
      "valid" => true,
      "publicInfraReady" => true,
      "selectedPath" => selected_path,
      "framesSent" => 3,
      "failures" => []
    }
  end

  def assert_assertion_status(measurement, control, assertion, expected)
    control_entry = measurement.fetch("controls").find { |entry| entry.fetch("control") == control }
    assertion_entry = control_entry.fetch("assertions").find { |entry| entry.fetch("name") == assertion }

    assert_equal expected, assertion_entry.fetch("status")
  end

  def write_json(relative, value)
    path = File.join(@tmpdir, relative)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "#{JSON.pretty_generate(value)}\n")
    relative
  end
end
