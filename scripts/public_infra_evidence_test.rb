# frozen_string_literal: true

require "json"
require "fileutils"
require "minitest/autorun"
require "open3"
require "time"
require "tmpdir"

class PublicInfraEvidenceTest < Minitest::Test
  REPO_ROOT = File.expand_path("..", __dir__)
  VERIFIER = File.join(REPO_ROOT, "scripts/verify-public-infra-evidence.rb")
  MANIFEST_VERIFIER = File.join(REPO_ROOT, "scripts/verify-public-edge-live-manifest.rb")
  ORCHESTRATOR = File.join(REPO_ROOT, "scripts/public-edge-live-evidence.sh")
  REVOCATION_DRILL = File.join(REPO_ROOT, "scripts/public-edge-service-token-revocation.sh")
  ROLLBACK_DRILL = File.join(REPO_ROOT, "scripts/public-edge-incident-rollback.sh")
  ALERTS = File.join(REPO_ROOT, "infra/public-edge/prometheus/quantumlink-public-edge-alerts.yml")
  RETENTION = File.join(REPO_ROOT, "infra/public-edge/journald/quantumlink-retention.conf.example")
  ENV_EXAMPLE = File.join(REPO_ROOT, "infra/public-edge/public-edge.env.example")
  COMMIT_SHA = "a" * 40

  def setup
    @tmpdir = Dir.mktmpdir("qlink-public-infra-evidence")
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.directory?(@tmpdir)
  end

  def test_public_app_relay_evidence_is_ready
    path = write_evidence("app-relay.json", base_evidence)
    stdout, stderr, status = run_verifier("--require-public", "--expected-sha", COMMIT_SHA, path)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal true, report.fetch("publicInfraReady")
    assert_equal "relay", report.fetch("selectedPath")
    assert_empty report.fetch("failures")
    assert_empty report.fetch("blockers")
  end

  def test_public_turn_relay_evidence_is_ready
    evidence = base_evidence.merge(
      "prove_turn_relay" => true,
      "turn_responder_relayed" => "198.51.100.77:49170",
      "published_candidate_types" => "Relay",
      "selected_path" => "turn-relay",
      "total_elapsed_ms" => 57
    )
    path = write_evidence("turn-relay.json", evidence)
    stdout, stderr, status = run_verifier(
      "--require-public", "--require-turn-relay", "--expected-sha", COMMIT_SHA, path
    )
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("publicInfraReady")
    assert_equal "turn-relay", report.fetch("selectedPath")
  end

  def test_local_evidence_is_valid_but_blocked_for_public_gate
    path = write_evidence(
      "local.json",
      base_evidence.merge(
        "mode" => "local",
        "rendezvous" => "tls://127.0.0.1:19710",
        "relay" => "tls://127.0.0.1:19711",
        "stun" => "127.0.0.1:19712",
        "turn" => "127.0.0.1:19713"
      )
    )
    stdout, _stderr, status = run_verifier("--require-public", "--expected-sha", COMMIT_SHA, path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("publicInfraReady")
    assert_includes report.fetch("blockers"), "mode must be public for deployable evidence"
    assert_includes report.fetch("blockers"), "rendezvous must be a public tls://host:port endpoint"
  end

  def test_public_gate_blocks_placeholders_missing_auth_and_missing_rate_limits
    path = write_evidence(
      "blocked.json",
      base_evidence.merge(
        "rendezvous" => "tls://rv.example.com:9471",
        "relay" => "tls://relay.example.com:9472",
        "stun" => "203.0.113.10:3478",
        "turn" => "203.0.113.10:3478",
        "rendezvous_auth_verified" => false,
        "relay_auth_verified" => false,
        "revoked_token_digest_file_configured" => false,
        "service_token_revocation_verified" => false,
        "rendezvous_revoked_token_rejected" => false,
        "relay_revoked_token_rejected" => false,
        "rendezvous_replacement_token_accepted" => false,
        "relay_replacement_token_accepted" => false,
        "rendezvous_rate_limit_per_window" => 0,
        "relay_rate_limit_per_window" => 0,
        "rendezvous_metrics_scraped" => false,
        "relay_metrics_scraped" => false,
        "bounds_verified" => false,
        "relay_payload_limit_verified" => false,
        "relay_saturation_limit_verified" => false,
        "max_concurrent_connections" => 0,
        "relay_max_peer_datagrams_per_window" => 0,
        "rendezvous_auth_failures_total" => 0,
        "relay_auth_failures_total" => 0,
        "rendezvous_auth_revocations_total" => 0,
        "relay_auth_revocations_total" => 0,
        "rendezvous_requests_succeeded_total" => 0,
        "relay_forwarded_datagrams_total" => 0,
        "rendezvous_request_too_large_total" => 0,
        "relay_request_too_large_total" => 0,
        "relay_payload_too_large_total" => 0,
        "relay_peer_rate_limited_total" => 0,
        "incident_rollback_verified" => false,
        "post_rollback_public_infra_ready" => false
      )
    )
    stdout, _stderr, status = run_verifier("--require-public", "--expected-sha", COMMIT_SHA, path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("blockers"), "rendezvous must be a public tls://host:port endpoint"
    assert_includes report.fetch("blockers"), "stun must be a public host:port endpoint"
    assert_includes report.fetch("blockers"), "rendezvous negative auth proof must pass"
    assert_includes report.fetch("blockers"), "service-token revocation proof must pass"
    assert_includes report.fetch("blockers"), "rendezvous revoked-token rejections must be visible in metrics"
    assert_includes report.fetch("blockers"), "relay rate limit must be enabled"
    assert_includes report.fetch("blockers"), "rendezvous metrics scrape must pass"
    assert_includes report.fetch("blockers"), "relay auth failures must be visible in metrics"
    assert_includes report.fetch("blockers"), "relay forwarded datagrams must be visible in metrics"
    assert_includes report.fetch("blockers"), "request bounds proof must pass"
    assert_includes report.fetch("blockers"), "connection limit must be configured"
    assert_includes report.fetch("blockers"), "relay payload quota rejections must be visible in metrics"
    assert_includes report.fetch("blockers"), "relay saturation limit proof must pass"
    assert_includes report.fetch("blockers"), "relay saturation rejections must be visible in metrics"
    assert_includes report.fetch("blockers"), "incident rollback proof must pass"
  end

  def test_forbidden_secret_markers_fail_the_evidence
    path = File.join(@tmpdir, "secret.json")
    File.write(path, "#{JSON.pretty_generate(base_evidence)}\nlocal-edge-secret\n")
    stdout, _stderr, status = run_verifier("--require-public", "--expected-sha", COMMIT_SHA, path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "forbidden secret marker found in public infra evidence"
  end

  def test_live_manifest_verifier_accepts_complete_public_manifest
    path = write_evidence("manifest.json", base_manifest)
    stdout, stderr, status = run_manifest_verifier("--expected-sha", COMMIT_SHA, path)
    report = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal true, report.fetch("valid")
    assert_equal true, report.fetch("liveEvidenceReady")
    assert_empty report.fetch("failures")
    assert_empty report.fetch("blockers")
  end

  def test_live_manifest_verifier_blocks_missing_operator_proofs
    manifest = JSON.parse(JSON.generate(base_manifest))
    manifest["status"] = "blocked"
    manifest["proofs"]["serviceTokenRevocation"]["rendezvousRevokedTokenRejected"] = false
    manifest["proofs"]["serviceTokenRevocation"]["relayAuthRevocationsTotal"] = 0
    manifest["proofs"]["incidentRollback"]["verified"] = false
    manifest["proofs"]["incidentRollback"]["postRollbackPublicInfraReady"] = false
    path = write_evidence("blocked-manifest.json", manifest)
    stdout, _stderr, status = run_manifest_verifier("--expected-sha", COMMIT_SHA, path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_equal true, report.fetch("valid")
    assert_equal false, report.fetch("liveEvidenceReady")
    assert_includes report.fetch("blockers"), "status must be pass"
    assert_includes report.fetch("blockers"), "rendezvous revoked-token proof must reject old token"
    assert_includes report.fetch("blockers"), "relay auth revocations must be visible in metrics"
    assert_includes report.fetch("blockers"), "incident rollback proof must pass"
    assert_includes report.fetch("blockers"), "post-rollback public infra proof must pass"
  end

  def test_orchestrator_contract_runs_both_smokes_and_verifiers_without_token_args
    script = File.read(ORCHESTRATOR)

    assert script.ascii_only?
    assert_includes script, "scripts/public-infra-smoke.sh"
    assert_includes script, "--prove-turn-relay"
    assert_includes script, "scripts/verify-public-infra-evidence.rb"
    assert_includes script, "scripts/verify-public-edge-live-manifest.rb"
    assert_includes script, "quantumLinkPublicEdgeLiveEvidence"
    assert_includes script, "QLINK_RENDEZVOUS_AUTH_TOKEN_FILE"
    assert_includes script, "QLINK_RELAY_AUTH_TOKEN_FILE"
    assert_includes script, "QLINK_RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE"
    assert_includes script, "QLINK_RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE"
    assert_includes script, "QLINK_RENDEZVOUS_METRICS_ADDR"
    assert_includes script, "QLINK_RELAY_METRICS_ADDR"
    assert_includes script, "QLINK_MAX_REQUEST_LINE_BYTES"
    assert_includes script, "QLINK_RELAY_MAX_PAYLOAD_BYTES"
    assert_includes script, "QLINK_RELAY_MAX_PEER_DATAGRAMS_PER_WINDOW"
    assert_includes script, "rendezvousMetricsScraped"
    assert_includes script, "relayMetricsScraped"
    assert_includes script, "boundsVerified"
    assert_includes script, "relayPayloadLimitVerified"
    assert_includes script, "relaySaturationLimitVerified"
    assert_includes script, "serviceTokenRevocation"
    assert_includes script, "incidentRollback"
    refute_match(/--rendezvous-auth-token(?:\s|$)/, script)
    refute_match(/--relay-auth-token(?:\s|$)/, script)
    refute_match(/--turn-password(?:\s|$)/, script)
  end

  def test_operator_drill_scripts_emit_redacted_evidence_contracts
    revocation = File.read(REVOCATION_DRILL)
    rollback = File.read(ROLLBACK_DRILL)

    assert revocation.ascii_only?
    assert rollback.ascii_only?
    assert_includes revocation, "service-token-digest"
    assert_includes revocation, "auth_revocations_total"
    assert_includes revocation, "--append-revocation-digests"
    assert_includes revocation, "--install-replacement-tokens"
    assert_includes revocation, "quantumLinkPublicEdgeServiceTokenRevocation"
    assert_includes revocation, "QLINK_SERVICE_TOKEN_REVOCATION_VERIFIED=true"
    assert_includes revocation, "QLINK_RENDEZVOUS_REVOKED_TOKEN_REJECTED=true"
    assert_includes revocation, "QLINK_RELAY_REPLACEMENT_TOKEN_ACCEPTED=true"
    assert_includes rollback, "scripts/public-edge-live-evidence.sh"
    assert_includes rollback, "scripts/verify-public-edge-live-manifest.rb"
    assert_includes rollback, "quantumLinkPublicEdgeIncidentRollback"
    assert_includes rollback, "QLINK_INCIDENT_ROLLBACK_VERIFIED=true"
    assert_includes rollback, "QLINK_POST_ROLLBACK_PUBLIC_INFRA_READY=true"
    refute_match(/echo .*TOKEN/i, revocation)
    refute_match(/echo .*PASSWORD/i, revocation)
    refute_match(/echo .*TOKEN/i, rollback)
    refute_match(/echo .*PASSWORD/i, rollback)
  end

  def test_public_edge_env_example_includes_operator_drill_inputs
    env_example = File.read(ENV_EXAMPLE)

    assert env_example.ascii_only?
    assert_includes env_example, "QLINK_RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE"
    assert_includes env_example, "QLINK_RELAY_REPLACEMENT_AUTH_TOKEN_FILE"
    assert_includes env_example, "QLINK_PUBLIC_EDGE_RELEASE_ID"
    assert_includes env_example, "QLINK_PREVIOUS_RELEASE_ID"
    assert_includes env_example, "QLINK_ROLLBACK_MANIFEST"
  end

  def test_operator_alert_and_retention_artifacts_cover_public_edge_metrics
    alerts = File.read(ALERTS)
    retention = File.read(RETENTION)

    assert alerts.ascii_only?
    assert_includes alerts, "quantumlink_relay_peer_rate_limited_total"
    assert_includes alerts, "quantumlink_relay_auth_revocations_total"
    assert_includes alerts, "quantumlink_rendezvous_auth_revocations_total"
    assert_includes alerts, "quantumlink_relay_payload_too_large_total"
    assert_includes alerts, "quantumlink_relay_connection_limit_rejections_total"
    assert_includes alerts, "quantumlink_rendezvous_connection_limit_rejections_total"
    assert retention.ascii_only?
    assert_includes retention, "MaxRetentionSec=14day"
    assert_includes retention, "ForwardToSyslog=no"
  end

  private

  def run_verifier(*args)
    Open3.capture3("ruby", VERIFIER, *args, chdir: REPO_ROOT)
  end

  def run_manifest_verifier(*args)
    Open3.capture3("ruby", MANIFEST_VERIFIER, *args, chdir: REPO_ROOT)
  end

  def write_evidence(name, evidence)
    path = File.join(@tmpdir, name)
    File.write(path, "#{JSON.pretty_generate(evidence)}\n")
    path
  end

  def base_manifest
    {
      "schemaVersion" => 1,
      "evidenceKind" => "quantumLinkPublicEdgeLiveEvidence",
      "generatedAt" => Time.now.utc.iso8601,
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
        "rendezvousRevokedTokenDigests" => "path",
        "relayRevokedTokenDigests" => "path",
        "turnPassword" => "file"
      },
      "proofs" => {
        "serviceTokenRevocation" => {
          "appRelayVerified" => true,
          "turnRelayVerified" => true,
          "rendezvousRevokedTokenRejected" => true,
          "relayRevokedTokenRejected" => true,
          "rendezvousReplacementTokenAccepted" => true,
          "relayReplacementTokenAccepted" => true,
          "rendezvousAuthRevocationsTotal" => 2,
          "relayAuthRevocationsTotal" => 2,
          "revocationListSha256" => "#{"b" * 64}:#{"c" * 64}"
        },
        "incidentRollback" => {
          "verified" => true,
          "incidentId" => "qlink-public-edge-drill-20260727",
          "rollbackFromReleaseId" => "public-edge-current",
          "rollbackToReleaseId" => "public-edge-previous",
          "rollbackManifestSha256" => "d" * 64,
          "rollbackDurationSeconds" => 42,
          "postRollbackPublicInfraReady" => true
        },
        "appRelay" => {
          "evidence" => "/tmp/app-relay/evidence.json",
          "verification" => "/tmp/app-relay-verification.json",
          "selectedPath" => "relay",
          "framesSent" => 3,
          "publicInfraReady" => true
        },
        "turnRelay" => {
          "evidence" => "/tmp/turn-relay/evidence.json",
          "verification" => "/tmp/turn-relay-verification.json",
          "selectedPath" => "turn-relay",
          "framesSent" => 3,
          "publicInfraReady" => true
        }
      }
    }
  end

  def base_evidence
    {
      "generated_at" => Time.now.utc.iso8601,
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
      "revoked_token_digest_file_configured" => true,
      "service_token_revocation_verified" => true,
      "rendezvous_revoked_token_rejected" => true,
      "relay_revoked_token_rejected" => true,
      "rendezvous_replacement_token_accepted" => true,
      "relay_replacement_token_accepted" => true,
      "rendezvous_revocation_list_sha256" => "b" * 64,
      "relay_revocation_list_sha256" => "c" * 64,
      "revocation_list_sha256" => "#{"b" * 64}:#{"c" * 64}",
      "rendezvous_rate_limit_per_window" => 120,
      "relay_rate_limit_per_window" => 240,
      "admission_rate_limit_window_seconds" => 60,
      "rendezvous_metrics_addr" => "127.0.0.1:9571",
      "relay_metrics_addr" => "127.0.0.1:9572",
      "rendezvous_metrics_scraped" => true,
      "relay_metrics_scraped" => true,
      "bounds_verified" => true,
      "relay_payload_limit_verified" => true,
      "relay_saturation_limit_verified" => true,
      "max_request_line_bytes" => 131_072,
      "max_concurrent_connections" => 1_024,
      "idle_timeout_seconds" => 300,
      "relay_max_payload_bytes" => 65_536,
      "relay_max_peer_id_bytes" => 256,
      "relay_max_registered_peers" => 2_048,
      "relay_max_peer_datagrams_per_window" => 120,
      "relay_peer_datagram_window_seconds" => 60,
      "rendezvous_auth_failures_total" => 1,
      "relay_auth_failures_total" => 1,
      "rendezvous_auth_revocations_total" => 1,
      "relay_auth_revocations_total" => 1,
      "rendezvous_requests_succeeded_total" => 3,
      "relay_forwarded_datagrams_total" => 3,
      "relay_unknown_destination_drops_total" => 0,
      "rendezvous_request_too_large_total" => 1,
      "relay_request_too_large_total" => 1,
      "relay_payload_too_large_total" => 1,
      "relay_peer_rate_limited_total" => 1,
      "relay_duplicate_registration_rejections_total" => 0,
      "prove_turn_relay" => false,
      "remote_peer_id" => "qlink_test",
      "advertise_addr" => "127.0.0.1:1",
      "turn_permit_peer_ip" => "198.51.100.44",
      "direct_probe_timeout_ms" => 300,
      "stun_reflexive" => "198.51.100.44:55000",
      "turn_relayed" => "198.51.100.77:49160",
      "turn_responder_relayed" => "",
      "published_candidate_count" => 3,
      "published_candidate_types" => "Host,ServerReflexive,Relay,QuantumLinkRelay",
      "self_publish_stun_failures" => 0,
      "self_publish_turn_failures" => 0,
      "selected_path" => "relay",
      "frames_sent" => 3,
      "total_elapsed_ms" => 402,
      "incident_rollback_verified" => true,
      "incident_id" => "qlink-public-edge-drill-20260727",
      "rollback_from_release_id" => "public-edge-current",
      "rollback_to_release_id" => "public-edge-previous",
      "rollback_manifest_sha256" => "d" * 64,
      "rollback_duration_seconds" => 42,
      "post_rollback_public_infra_ready" => true
    }
  end
end
