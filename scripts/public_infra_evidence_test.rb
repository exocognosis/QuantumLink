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
  ORCHESTRATOR = File.join(REPO_ROOT, "scripts/public-edge-live-evidence.sh")
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
        "rendezvous_rate_limit_per_window" => 0,
        "relay_rate_limit_per_window" => 0
      )
    )
    stdout, _stderr, status = run_verifier("--require-public", "--expected-sha", COMMIT_SHA, path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("blockers"), "rendezvous must be a public tls://host:port endpoint"
    assert_includes report.fetch("blockers"), "stun must be a public host:port endpoint"
    assert_includes report.fetch("blockers"), "rendezvous negative auth proof must pass"
    assert_includes report.fetch("blockers"), "relay rate limit must be enabled"
  end

  def test_forbidden_secret_markers_fail_the_evidence
    path = File.join(@tmpdir, "secret.json")
    File.write(path, "#{JSON.pretty_generate(base_evidence)}\nlocal-edge-secret\n")
    stdout, _stderr, status = run_verifier("--require-public", "--expected-sha", COMMIT_SHA, path)
    report = JSON.parse(stdout)

    refute status.success?
    assert_includes report.fetch("failures"), "forbidden secret marker found in public infra evidence"
  end

  def test_orchestrator_contract_runs_both_smokes_and_verifiers_without_token_args
    script = File.read(ORCHESTRATOR)

    assert script.ascii_only?
    assert_includes script, "scripts/public-infra-smoke.sh"
    assert_includes script, "--prove-turn-relay"
    assert_includes script, "scripts/verify-public-infra-evidence.rb"
    assert_includes script, "quantumLinkPublicEdgeLiveEvidence"
    assert_includes script, "QLINK_RENDEZVOUS_AUTH_TOKEN_FILE"
    assert_includes script, "QLINK_RELAY_AUTH_TOKEN_FILE"
    refute_match(/--rendezvous-auth-token(?:\s|$)/, script)
    refute_match(/--relay-auth-token(?:\s|$)/, script)
    refute_match(/--turn-password(?:\s|$)/, script)
  end

  private

  def run_verifier(*args)
    Open3.capture3("ruby", VERIFIER, *args, chdir: REPO_ROOT)
  end

  def write_evidence(name, evidence)
    path = File.join(@tmpdir, name)
    File.write(path, "#{JSON.pretty_generate(evidence)}\n")
    path
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
      "rendezvous_rate_limit_per_window" => 120,
      "relay_rate_limit_per_window" => 240,
      "admission_rate_limit_window_seconds" => 60,
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
      "total_elapsed_ms" => 402
    }
  end
end
