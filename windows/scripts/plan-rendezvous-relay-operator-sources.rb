#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "optparse"
require "pathname"
require "time"

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

PUBLIC_EDGE_BRIDGE_ASSERTIONS = [
  ["tls", "tls_enabled"],
  ["authentication", "authorized_accepted"],
  ["authentication", "unauthorized_rejected"],
  ["rate_limits", "endpoint_limit_enforced"],
  ["relay_denial", "rate_limited_denied"]
].freeze

SOURCE_REQUIREMENTS = {
  "tls" => {
    "tls_enabled" => ["Public-edge bridge normally supplies this when TLS probes pass."],
    "certificate_valid" => ["Capture certificate-chain validation for every production rendezvous and relay endpoint."],
    "rotation_tested" => ["Run certificate replacement and prove old and new endpoint certificates validate across the rotation window."]
  },
  "authentication" => {
    "authorized_accepted" => ["Public-edge bridge normally supplies this when authenticated publish and relay probes pass."],
    "unauthorized_rejected" => ["Public-edge bridge normally supplies this when negative-authentication probes pass."]
  },
  "signed_expiring_records" => {
    "valid_record_accepted" => ["Publish a correctly signed, unexpired peer record and prove lookup/relay consumers accept it."],
    "expired_rejected" => ["Replay an otherwise valid record after expiry and prove publish, lookup, and relay decisions reject it."],
    "replay_rejected" => ["Replay a stale sequence or nonce and prove it is rejected without replacing the current record."],
    "malformed_signature_rejected" => ["Submit a tampered signature and prove the record is rejected without caching side effects."],
    "revoked_key_rejected" => ["Revoke the peer-record signing key and prove records signed by that key are rejected."]
  },
  "rate_limits" => {
    "identity_limit_enforced" => ["Exceed the configured identity quota and prove the identity bucket blocks further requests."],
    "source_limit_enforced" => ["Exceed the configured source-prefix quota and prove the source bucket blocks further requests."],
    "endpoint_limit_enforced" => ["Public-edge bridge normally supplies this when request and payload bound probes pass."],
    "entitlement_limit_enforced" => ["Exceed the entitlement-class quota and prove lower-tier limits block further requests."]
  },
  "abuse_logs" => {
    "decisions_recorded" => ["Sample redacted abuse-log decisions with reason code, endpoint, timing, and request id."],
    "payloads_excluded" => ["Prove abuse logs omit packet payloads and game payloads."],
    "secrets_excluded" => ["Prove abuse logs omit private keys, wallet stores, entitlement tokens, and service secrets."]
  },
  "revocation_propagation" => {
    "publish_under_60s" => ["Measure revocation-to-publish-denial latency and prove it is under 60 seconds."],
    "lookup_under_60s" => ["Measure revocation-to-lookup-denial latency and prove it is under 60 seconds."],
    "relay_under_60s" => ["Measure revocation-to-relay-denial latency and prove it is under 60 seconds."]
  },
  "relay_denial" => {
    "entitlement_denied" => ["Attempt relay allocation without entitlement and prove it is denied."],
    "policy_denied" => ["Attempt relay allocation against denied policy context and prove it is denied."],
    "revoked_denied" => ["Attempt relay allocation for a revoked identity or key and prove it is denied."],
    "expired_denied" => ["Attempt relay allocation with an expired peer record and prove it is denied."],
    "rate_limited_denied" => ["Public-edge bridge normally supplies this when relay saturation denial is proved."]
  },
  "retention" => {
    "metadata_only" => ["Prove retention configuration stores operational metadata only."],
    "packet_payloads_excluded" => ["Prove retained rendezvous/relay artifacts contain no packet payloads."],
    "game_payloads_excluded" => ["Prove retained rendezvous/relay artifacts contain no game payloads."]
  },
  "key_rotation" => {
    "dual_key_rotation_passed" => ["Run service-key dual-acceptance rotation and prove old/new windows behave as expected."],
    "old_key_rejected" => ["After rotation drain, prove artifacts signed by the old service key are rejected."]
  },
  "endpoint_rotation" => {
    "replacement_validated" => ["Validate replacement rendezvous/relay endpoints behind TLS and auth before traffic moves."],
    "old_endpoint_drained" => ["Drain the old endpoint and prove no new allocations are accepted there."]
  },
  "incident_shutdown" => {
    "publish_disabled" => ["Run incident mode and prove publish is disabled for affected scope."],
    "relay_allocations_disabled" => ["Run incident mode and prove new relay allocations are disabled for affected scope."],
    "revocations_applied" => ["Run incident mode and prove revocation decisions are active before service restoration."]
  }
}.freeze

MAX_INPUT_BYTES = 1_048_576
FORBIDDEN_MARKERS = /
  BEGIN\ (?:RSA\ |EC\ |OPENSSH\ )?PRIVATE\ KEY|
  WALLET_SEED|ENTITLEMENT_TOKEN|DYTALLIX_WALLET_SECRET|
  QLINK_PRODUCTION_ENDPOINT_SECRET|WINDOWS_RELEASE_PRIVATE_KEY|
  local-edge-secret|replace-with-|\.pcapng?\b
/ix.freeze

def abort_with(message)
  warn message
  exit 1
end

def nonempty_string?(value)
  value.is_a?(String) && !value.strip.empty?
end

def repo_relative_path?(value)
  return false unless nonempty_string?(value)
  return false if value.include?("\\") || value.match?(/\A[A-Za-z]:/) || value.start_with?("//")

  path = Pathname.new(value)
  !path.absolute? && !path.each_filename.any? { |part| %w[. ..].include?(part) }
end

def repo_path(repo_root, value, field)
  abort_with("#{field} must be a repo-relative path") unless repo_relative_path?(value)

  candidate = repo_root.join(value).cleanpath
  prefix = "#{repo_root.cleanpath}#{File::SEPARATOR}"
  abort_with("#{field} must resolve inside the repository") unless candidate.to_s.start_with?(prefix)
  candidate
end

def parse_json(path, description)
  abort_with("#{description} is missing: #{path}") unless path.file?
  abort_with("#{description} exceeds #{MAX_INPUT_BYTES} bytes") if path.size > MAX_INPUT_BYTES

  text = path.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
  abort_with("#{description} contains a forbidden secret or raw-evidence marker") if text.match?(FORBIDDEN_MARKERS)
  value = JSON.parse(text)
  abort_with("#{description} must be a JSON object") unless value.is_a?(Hash)
  value
rescue JSON::ParserError => e
  abort_with("#{description} is invalid JSON: #{e.message}")
end

def write_json(path, value)
  FileUtils.mkdir_p(path.dirname)
  path.write("#{JSON.pretty_generate(value)}\n", encoding: "UTF-8")
end

def endpoint_set_sha256(rendezvous_endpoints, relay_endpoints)
  Digest::SHA256.hexdigest(JSON.generate({
    "rendezvousEndpoints" => rendezvous_endpoints.sort,
    "relayEndpoints" => relay_endpoints.sort
  }))
end

def relative_to_repo(repo_root, path)
  path.relative_path_from(repo_root).to_s
end

def valid_source_binding?(repo_root, source_arg, claimed_digest, control, assertion, deployment_id, commit_sha, release_ref, endpoint_digest)
  return false unless repo_relative_path?(source_arg)
  return false unless claimed_digest.is_a?(String) && claimed_digest.match?(/\A[0-9a-f]{64}\z/)

  source_path = repo_root.join(source_arg).cleanpath
  prefix = "#{repo_root.cleanpath}#{File::SEPARATOR}"
  return false unless source_path.to_s.start_with?(prefix)
  return false unless source_path.file?
  return false unless Digest::SHA256.file(source_path).hexdigest == claimed_digest

  source = parse_json(source_path, "source evidence for #{control}/#{assertion}")
  source["schemaVersion"] == 1 &&
    source["evidenceKind"] == "windowsRendezvousRelayAssertionSourceEvidence" &&
    source["control"] == control &&
    source["assertion"] == assertion &&
    source["status"] == "pass" &&
    source["measured"] == true &&
    source["deploymentId"] == deployment_id &&
    source["releaseCommitSha"] == commit_sha &&
    source["releaseRef"] == release_ref &&
    source["endpointSetSha256"] == endpoint_digest &&
    source["redacted"] == true
end

def passing_measurement_assertions(repo_root, measurement, deployment_id, commit_sha, release_ref, endpoint_digest)
  Array(measurement && measurement["controls"]).each_with_object([]) do |control_entry, result|
    next unless control_entry.is_a?(Hash)

    control = control_entry["control"]
    next unless REQUIRED_ASSERTIONS.key?(control)

    Array(control_entry["assertions"]).each do |assertion_entry|
      next unless assertion_entry.is_a?(Hash)
      next unless assertion_entry["status"] == "pass" && assertion_entry["measured"] == true

      assertion = assertion_entry["name"]
      next unless REQUIRED_ASSERTIONS.fetch(control).include?(assertion)
      next unless valid_source_binding?(
        repo_root, assertion_entry["source"], assertion_entry["sourceSha256"], control, assertion,
        deployment_id, commit_sha, release_ref, endpoint_digest
      )

      result << [control, assertion]
    end
  end
end

options = {
  repo_root: Pathname.new(__dir__).join("../..").expand_path,
  contract: "windows/deployment/rendezvous-relay-production.json",
  output: "windows/build/validation/rendezvous-relay-operator-source-plan.json",
  template_directory: "windows/build/validation/rendezvous-relay-operator-source-templates"
}

OptionParser.new do |parser|
  parser.banner = "usage: #{$PROGRAM_NAME} --contract PATH [--measurements PATH] [options]"
  parser.on("--repo-root PATH") { |value| options[:repo_root] = Pathname.new(value).expand_path }
  parser.on("--contract PATH") { |value| options[:contract] = value }
  parser.on("--measurements PATH") { |value| options[:measurements] = value }
  parser.on("--output PATH") { |value| options[:output] = value }
  parser.on("--template-directory PATH") { |value| options[:template_directory] = value }
end.parse!

repo_root = options.fetch(:repo_root)
contract_path = repo_path(repo_root, options.fetch(:contract), "contract")
output_path = repo_path(repo_root, options.fetch(:output), "output")
template_directory = repo_path(repo_root, options.fetch(:template_directory), "template directory")
contract = parse_json(contract_path, "deployment contract")

abort_with("deployment contract schemaVersion must be 1") unless contract["schemaVersion"] == 1
abort_with("deployment contract evidenceKind is invalid") unless contract["evidenceKind"] == "windowsRendezvousRelayDeploymentContract"
commit_sha = contract.dig("release", "commitSha")
release_ref = contract.dig("release", "ref")
deployment_id = contract.dig("deployment", "id")
abort_with("release.commitSha must be an exact 40- or 64-character hexadecimal digest") unless commit_sha.is_a?(String) && commit_sha.match?(/\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/)
abort_with("release.ref must begin with refs/heads/ or refs/tags/") unless release_ref.is_a?(String) && release_ref.match?(%r{\Arefs/(?:heads|tags)/[^\s]+\z})
abort_with("deployment.id is required") unless nonempty_string?(deployment_id)

rendezvous_endpoints = Array(contract["rendezvousEndpoints"])
relay_endpoints = Array(contract["relayEndpoints"])
abort_with("rendezvousEndpoints must be a non-empty array") if rendezvous_endpoints.empty?
abort_with("relayEndpoints must be a non-empty array") if relay_endpoints.empty?
endpoint_digest = endpoint_set_sha256(rendezvous_endpoints, relay_endpoints)

measurement = nil
measurement_path = nil
if options[:measurements]
  measurement_path = repo_path(repo_root, options[:measurements], "measurements")
  measurement = parse_json(measurement_path, "production measurements")
  abort_with("measurements schemaVersion must be 1") unless measurement["schemaVersion"] == 1
  abort_with("measurements evidenceKind is invalid") unless measurement["evidenceKind"] == "windowsRendezvousRelayMeasuredControls"
  abort_with("measurements release binding does not match the deployment contract") unless measurement.dig("release", "commitSha") == commit_sha && measurement.dig("release", "ref") == release_ref
  abort_with("measurements deploymentId does not match the deployment contract") unless measurement["deploymentId"] == deployment_id
  abort_with("measurements endpointSetSha256 does not match the deployment contract") unless measurement["endpointSetSha256"] == endpoint_digest
end

already_passing = passing_measurement_assertions(repo_root, measurement, deployment_id, commit_sha, release_ref, endpoint_digest)
missing = REQUIRED_ASSERTIONS.flat_map do |control, assertions|
  assertions.map { |assertion| [control, assertion] }
end.reject { |pair| already_passing.include?(pair) }

generated_at = Time.now.utc.iso8601
entries = missing.map do |control, assertion|
  template_path = template_directory.join(control, "#{assertion}.template.json")
  operator_source = "windows/validation/operator-sources/#{control}/#{assertion}.json"
  template = {
    "schemaVersion" => 1,
    "evidenceKind" => "windowsRendezvousRelayOperatorSourceTemplate",
    "status" => "blocked",
    "measured" => false,
    "generatedAt" => generated_at,
    "control" => control,
    "assertion" => assertion,
    "deploymentId" => deployment_id,
    "releaseCommitSha" => commit_sha,
    "releaseRef" => release_ref,
    "endpointSetSha256" => endpoint_digest,
    "redacted" => true,
    "operatorSourcePath" => operator_source,
    "requiredProof" => SOURCE_REQUIREMENTS.fetch(control).fetch(assertion),
    "forbiddenEvidence" => [
      "private keys",
      "wallet seeds",
      "entitlement tokens",
      "service endpoint secrets",
      "packet captures",
      "raw packet payloads",
      "raw game payloads",
      "support-bundle archives"
    ],
    "promotionRule" => "Replace this template with windowsRendezvousRelayAssertionSourceEvidence only after the named proof is measured on the bound deployment and redacted."
  }
  write_json(template_path, template)
  {
    "control" => control,
    "assertion" => assertion,
    "template" => relative_to_repo(repo_root, template_path),
    "operatorSourcePath" => operator_source,
    "publicEdgeBridgeAssertion" => PUBLIC_EDGE_BRIDGE_ASSERTIONS.include?([control, assertion]),
    "requiredProof" => SOURCE_REQUIREMENTS.fetch(control).fetch(assertion)
  }
end

plan = {
  "schemaVersion" => 1,
  "evidenceKind" => "windowsRendezvousRelayOperatorSourcePlan",
  "generatedAt" => generated_at,
  "status" => missing.empty? ? "pass" : "blocked",
  "release" => { "commitSha" => commit_sha, "ref" => release_ref },
  "deploymentId" => deployment_id,
  "endpointSetSha256" => endpoint_digest,
  "contract" => options.fetch(:contract),
  "measurements" => options[:measurements],
  "alreadyPassingAssertionCount" => already_passing.length,
  "requiredOperatorAssertionCount" => missing.length,
  "operatorAssertions" => entries
}
write_json(output_path, plan)

puts JSON.generate({
  "status" => plan.fetch("status"),
  "output" => relative_to_repo(repo_root, output_path),
  "templateDirectory" => relative_to_repo(repo_root, template_directory),
  "alreadyPassingAssertionCount" => already_passing.length,
  "requiredOperatorAssertionCount" => missing.length
})
