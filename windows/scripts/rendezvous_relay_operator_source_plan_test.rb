# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "time"
require "tmpdir"

class RendezvousRelayOperatorSourcePlanTest < Minitest::Test
  SCRIPT = File.expand_path("plan-rendezvous-relay-operator-sources.rb", __dir__)
  COMMIT_SHA = "c" * 40
  RELEASE_REF = "refs/tags/v1.2.0"
  DEPLOYMENT_ID = "qlink-control-plane-operator-drill"
  PUBLIC_EDGE_ASSERTIONS = [
    ["tls", "tls_enabled"],
    ["authentication", "authorized_accepted"],
    ["authentication", "unauthorized_rejected"],
    ["rate_limits", "endpoint_limit_enforced"],
    ["relay_denial", "rate_limited_denied"]
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
    @tmpdir = Dir.mktmpdir("qlink-rendezvous-relay-operator-source-plan")
    @rendezvous_endpoints = ["https://rv.quantumlinkvpn.com"]
    @relay_endpoints = ["turns:relay.quantumlinkvpn.com:5349"]
    @endpoint_digest = Digest::SHA256.hexdigest(JSON.generate({
      "rendezvousEndpoints" => @rendezvous_endpoints,
      "relayEndpoints" => @relay_endpoints
    }))
    @contract = write_contract
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.directory?(@tmpdir)
  end

  def test_plan_emits_only_remaining_operator_templates_after_public_edge_measurements
    write_public_edge_source_files
    measurements = write_public_edge_measurements
    stdout, stderr, status = invoke_planner("--measurements", measurements)
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal "blocked", result.fetch("status")
    assert_equal 5, result.fetch("alreadyPassingAssertionCount")
    assert_equal 30, result.fetch("requiredOperatorAssertionCount")

    plan = JSON.parse(File.read(File.join(@tmpdir, "windows/build/validation/operator-plan.json")))
    assert_equal "windowsRendezvousRelayOperatorSourcePlan", plan.fetch("evidenceKind")
    assert_equal 30, plan.fetch("operatorAssertions").length
    planned_pairs = plan.fetch("operatorAssertions").map { |entry| [entry.fetch("control"), entry.fetch("assertion")] }
    PUBLIC_EDGE_ASSERTIONS.each { |pair| refute_includes planned_pairs, pair }
    assert_includes planned_pairs, ["tls", "certificate_valid"]
    assert_includes planned_pairs, ["signed_expiring_records", "revoked_key_rejected"]
    assert_includes planned_pairs, ["rate_limits", "source_limit_enforced"]

    template_path = File.join(@tmpdir, "windows/build/validation/operator-templates/tls/certificate_valid.template.json")
    template = JSON.parse(File.read(template_path))
    assert_equal "windowsRendezvousRelayOperatorSourceTemplate", template.fetch("evidenceKind")
    assert_equal "blocked", template.fetch("status")
    assert_equal false, template.fetch("measured")
    assert_equal "windows/validation/operator-sources/tls/certificate_valid.json", template.fetch("operatorSourcePath")
    assert_equal COMMIT_SHA, template.fetch("releaseCommitSha")
    assert_equal @endpoint_digest, template.fetch("endpointSetSha256")
    refute_equal "windowsRendezvousRelayAssertionSourceEvidence", template.fetch("evidenceKind")
  end

  def test_plan_without_measurements_lists_every_required_assertion
    stdout, stderr, status = invoke_planner
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal "blocked", result.fetch("status")
    assert_equal 0, result.fetch("alreadyPassingAssertionCount")
    assert_equal 35, result.fetch("requiredOperatorAssertionCount")
  end

  def test_pass_measurements_without_source_bindings_still_require_templates
    measurements = write_public_edge_measurements(include_source_bindings: false)
    stdout, stderr, status = invoke_planner("--measurements", measurements)
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal 0, result.fetch("alreadyPassingAssertionCount")
    assert_equal 35, result.fetch("requiredOperatorAssertionCount")
  end

  def test_phantom_source_bindings_still_require_templates
    measurements = write_public_edge_measurements
    stdout, stderr, status = invoke_planner("--measurements", measurements)
    result = JSON.parse(stdout)

    assert status.success?, stderr
    assert_equal 0, result.fetch("alreadyPassingAssertionCount")
    assert_equal 35, result.fetch("requiredOperatorAssertionCount")
  end

  def test_planner_rejects_unbound_placeholder_contract
    contract_path = File.join(@tmpdir, @contract)
    contract = JSON.parse(File.read(contract_path))
    contract["release"]["commitSha"] = ""
    File.write(contract_path, "#{JSON.pretty_generate(contract)}\n")

    stdout, stderr, status = invoke_planner

    refute status.success?, stdout
    assert_includes stderr, "release.commitSha must be an exact 40- or 64-character hexadecimal digest"
  end

  private

  def invoke_planner(*extra_args)
    Open3.capture3(
      "ruby", SCRIPT,
      "--repo-root", @tmpdir,
      "--contract", @contract,
      "--output", "windows/build/validation/operator-plan.json",
      "--template-directory", "windows/build/validation/operator-templates",
      *extra_args,
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

  def write_public_edge_measurements(include_source_bindings: true)
    relative = "windows/build/validation/rendezvous-relay-production-measurements.json"
    controls = REQUIRED_ASSERTIONS.map do |control, assertions|
      assertion_entries = assertions.map do |assertion|
        if PUBLIC_EDGE_ASSERTIONS.include?([control, assertion])
          item = {
            "name" => assertion,
            "status" => "pass",
            "measured" => true
          }
          if include_source_bindings
            source = public_edge_source_path(control, assertion)
            item["source"] = source
            item["sourceSha256"] = Digest::SHA256.file(File.join(@tmpdir, source)).hexdigest if File.file?(File.join(@tmpdir, source))
            item["sourceSha256"] ||= "d" * 64
          end
          item
        else
          { "name" => assertion, "status" => "blocked", "measured" => false }
        end
      end
      {
        "control" => control,
        "status" => assertion_entries.all? { |entry| entry.fetch("status") == "pass" } ? "pass" : "blocked",
        "assertions" => assertion_entries
      }
    end
    write_json(relative, {
      "schemaVersion" => 1,
      "evidenceKind" => "windowsRendezvousRelayMeasuredControls",
      "measurementKind" => "measured",
      "generatedAt" => Time.now.utc.iso8601,
      "status" => "blocked",
      "release" => { "commitSha" => COMMIT_SHA, "ref" => RELEASE_REF },
      "deploymentId" => DEPLOYMENT_ID,
      "endpointSetSha256" => @endpoint_digest,
      "publicEdgeBridge" => {
        "supportedAssertions" => PUBLIC_EDGE_ASSERTIONS.map { |control, assertion| "#{control}/#{assertion}" }
      },
      "controls" => controls
    })
    relative
  end

  def write_public_edge_source_files
    PUBLIC_EDGE_ASSERTIONS.each do |control, assertion|
      relative = public_edge_source_path(control, assertion)
      write_json(relative, {
        "schemaVersion" => 1,
        "evidenceKind" => "windowsRendezvousRelayAssertionSourceEvidence",
        "control" => control,
        "assertion" => assertion,
        "status" => "pass",
        "measured" => true,
        "generatedAt" => Time.now.utc.iso8601,
        "deploymentId" => DEPLOYMENT_ID,
        "releaseCommitSha" => COMMIT_SHA,
        "releaseRef" => RELEASE_REF,
        "endpointSetSha256" => @endpoint_digest,
        "redacted" => true
      })
    end
  end

  def public_edge_source_path(control, assertion)
    "windows/build/validation/rendezvous-relay-sources/from-public-edge/#{control}/#{assertion}.json"
  end

  def write_json(relative, value)
    path = File.join(@tmpdir, relative)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "#{JSON.pretty_generate(value)}\n")
    relative
  end
end
