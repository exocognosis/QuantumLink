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
PUBLIC_EDGE_ASSERTIONS = [
  {
    "control" => "tls",
    "assertion" => "tls_enabled",
    "rationale" => "Public-edge smoke completed authenticated TLS control-plane and TURN-relay probes."
  },
  {
    "control" => "authentication",
    "assertion" => "authorized_accepted",
    "rationale" => "Public-edge smoke published and relayed authenticated traffic successfully."
  },
  {
    "control" => "authentication",
    "assertion" => "unauthorized_rejected",
    "rationale" => "Public-edge verifier confirmed rendezvous and relay negative-authentication probes."
  },
  {
    "control" => "rate_limits",
    "assertion" => "endpoint_limit_enforced",
    "rationale" => "Public-edge rendezvous and relay request-bound probes enforced configured endpoint limits."
  },
  {
    "control" => "relay_denial",
    "assertion" => "rate_limited_denied",
    "rationale" => "Public-edge relay saturation proof denied over-quota peer datagrams and exposed the denial in metrics."
  }
].freeze
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

def contained_path(repo_root, value, field)
  candidate = Pathname.new(value)
  candidate = repo_root.join(value) unless candidate.absolute?
  candidate = candidate.cleanpath
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

def endpoint_set_sha256(rendezvous_endpoints, relay_endpoints)
  Digest::SHA256.hexdigest(JSON.generate({
    "rendezvousEndpoints" => rendezvous_endpoints.sort,
    "relayEndpoints" => relay_endpoints.sort
  }))
end

def boolean_true?(value)
  value == true
end

def positive_integer?(value)
  value.is_a?(Integer) && value.positive?
end

def all_evidence?(app_evidence, turn_evidence, &block)
  [app_evidence, turn_evidence].all? { |evidence| block.call(evidence) }
end

def public_edge_assertion_supported?(control, assertion, app_evidence, turn_evidence)
  case [control, assertion]
  when ["tls", "tls_enabled"]
    all_evidence?(app_evidence, turn_evidence) do |evidence|
      boolean_true?(evidence["control_tls_ca_configured"]) &&
        boolean_true?(evidence["rendezvous_tls_enabled"]) &&
        boolean_true?(evidence["relay_tls_enabled"])
    end
  when ["authentication", "authorized_accepted"]
    positive_integer?(app_evidence["frames_sent"]) &&
      positive_integer?(turn_evidence["frames_sent"]) &&
      app_evidence["selected_path"] == "relay" &&
      turn_evidence["selected_path"] == "turn-relay"
  when ["authentication", "unauthorized_rejected"]
    all_evidence?(app_evidence, turn_evidence) do |evidence|
      boolean_true?(evidence["rendezvous_auth_required"]) &&
        boolean_true?(evidence["relay_auth_required"]) &&
        boolean_true?(evidence["rendezvous_auth_verified"]) &&
        boolean_true?(evidence["relay_auth_verified"])
    end
  when ["rate_limits", "endpoint_limit_enforced"]
    all_evidence?(app_evidence, turn_evidence) do |evidence|
      boolean_true?(evidence["bounds_verified"]) &&
        boolean_true?(evidence["relay_payload_limit_verified"]) &&
        positive_integer?(evidence["max_request_line_bytes"]) &&
        positive_integer?(evidence["max_concurrent_connections"]) &&
        positive_integer?(evidence["idle_timeout_seconds"]) &&
        positive_integer?(evidence["relay_max_payload_bytes"]) &&
        positive_integer?(evidence["relay_max_peer_id_bytes"]) &&
        positive_integer?(evidence["relay_max_registered_peers"]) &&
        positive_integer?(evidence["rendezvous_request_too_large_total"]) &&
        positive_integer?(evidence["relay_request_too_large_total"]) &&
        positive_integer?(evidence["relay_payload_too_large_total"])
    end
  when ["relay_denial", "rate_limited_denied"]
    all_evidence?(app_evidence, turn_evidence) do |evidence|
      boolean_true?(evidence["relay_saturation_limit_verified"]) &&
        positive_integer?(evidence["relay_peer_rate_limited_total"])
    end
  else
    false
  end
end

def write_json(path, value)
  FileUtils.mkdir_p(path.dirname)
  path.write("#{JSON.pretty_generate(value)}\n", encoding: "UTF-8")
end

def relative_to_repo(repo_root, path)
  path.relative_path_from(repo_root).to_s
end

def source_digest(path)
  Digest::SHA256.file(path).hexdigest
end

def validate_source_binding(source, control, assertion, deployment_id, commit_sha, release_ref, endpoint_digest, description)
  abort_with("#{description} schemaVersion must be 1") unless source["schemaVersion"] == 1
  abort_with("#{description} evidenceKind is invalid") unless source["evidenceKind"] == "windowsRendezvousRelayAssertionSourceEvidence"
  abort_with("#{description} control does not match") unless source["control"] == control
  abort_with("#{description} assertion does not match") unless source["assertion"] == assertion
  abort_with("#{description} status must be pass") unless source["status"] == "pass"
  abort_with("#{description} measured must be true") unless source["measured"] == true
  abort_with("#{description} deploymentId does not match") unless source["deploymentId"] == deployment_id
  abort_with("#{description} releaseCommitSha does not match") unless source["releaseCommitSha"] == commit_sha
  abort_with("#{description} releaseRef does not match") unless source["releaseRef"] == release_ref
  abort_with("#{description} endpointSetSha256 does not match") unless source["endpointSetSha256"] == endpoint_digest
  abort_with("#{description} must be redacted") unless source["redacted"] == true
end

def add_source!(sources, key, value)
  prior = sources[key]
  abort_with("duplicate source supplied for #{key.join('/')}") if prior

  sources[key] = value
end

options = {
  repo_root: Pathname.new(__dir__).join("../..").expand_path,
  contract: "windows/deployment/rendezvous-relay-production.template.json",
  output: "windows/build/validation/rendezvous-relay-production-measurements.json",
  source_directory: "windows/build/validation/rendezvous-relay-sources/from-public-edge",
  operator_sources: []
}
OptionParser.new do |parser|
  parser.banner = "usage: #{$PROGRAM_NAME} --public-edge-manifest PATH [--operator-source PATH ...] [options]"
  parser.on("--repo-root PATH") { |value| options[:repo_root] = Pathname.new(value).expand_path }
  parser.on("--contract PATH") { |value| options[:contract] = value }
  parser.on("--public-edge-manifest PATH") { |value| options[:public_edge_manifest] = value }
  parser.on("--operator-source PATH") { |value| options[:operator_sources] << value }
  parser.on("--output PATH") { |value| options[:output] = value }
  parser.on("--source-directory PATH") { |value| options[:source_directory] = value }
end.parse!

abort_with("--public-edge-manifest is required") unless options[:public_edge_manifest]

repo_root = options.fetch(:repo_root)
contract_path = repo_path(repo_root, options.fetch(:contract), "contract")
output_path = repo_path(repo_root, options.fetch(:output), "output")
source_directory = repo_path(repo_root, options.fetch(:source_directory), "source directory")
contract = parse_json(contract_path, "deployment contract")
abort_with("deployment contract schemaVersion must be 1") unless contract["schemaVersion"] == 1
abort_with("deployment contract evidenceKind is invalid") unless contract["evidenceKind"] == "windowsRendezvousRelayDeploymentContract"

commit_sha = contract.dig("release", "commitSha")
release_ref = contract.dig("release", "ref")
deployment_id = contract.dig("deployment", "id")
abort_with("deployment contract release.commitSha must be set") unless nonempty_string?(commit_sha)
abort_with("deployment contract release.ref must be set") unless nonempty_string?(release_ref)
abort_with("deployment contract deployment.id must be set") unless nonempty_string?(deployment_id)

rendezvous_endpoints = Array(contract["rendezvousEndpoints"])
relay_endpoints = Array(contract["relayEndpoints"])
endpoint_digest = endpoint_set_sha256(rendezvous_endpoints, relay_endpoints)
public_manifest_path = contained_path(repo_root, options.fetch(:public_edge_manifest), "public-edge manifest")
public_manifest = parse_json(public_manifest_path, "public-edge manifest")
abort_with("public-edge manifest schemaVersion must be 1") unless public_manifest["schemaVersion"] == 1
abort_with("public-edge manifest evidenceKind is invalid") unless public_manifest["evidenceKind"] == "quantumLinkPublicEdgeLiveEvidence"
abort_with("public-edge manifest must be public") unless public_manifest["mode"] == "public"
abort_with("public-edge manifest gitSha does not match deployment contract") unless public_manifest["gitSha"] == commit_sha

proofs = public_manifest["proofs"]
abort_with("public-edge manifest proofs section is required") unless proofs.is_a?(Hash)
app_proof = proofs["appRelay"]
turn_proof = proofs["turnRelay"]
abort_with("public-edge appRelay proof is required") unless app_proof.is_a?(Hash)
abort_with("public-edge turnRelay proof is required") unless turn_proof.is_a?(Hash)

app_evidence_path = contained_path(repo_root, app_proof["evidence"], "public-edge appRelay evidence")
turn_evidence_path = contained_path(repo_root, turn_proof["evidence"], "public-edge turnRelay evidence")
app_verification_path = contained_path(repo_root, app_proof["verification"], "public-edge appRelay verification")
turn_verification_path = contained_path(repo_root, turn_proof["verification"], "public-edge turnRelay verification")
app_evidence = parse_json(app_evidence_path, "public-edge appRelay evidence")
turn_evidence = parse_json(turn_evidence_path, "public-edge turnRelay evidence")
app_verification = parse_json(app_verification_path, "public-edge appRelay verification")
turn_verification = parse_json(turn_verification_path, "public-edge turnRelay verification")

unless public_manifest["status"] == "pass" && app_verification["publicInfraReady"] == true && turn_verification["publicInfraReady"] == true
  abort_with("public-edge manifest and verification reports must be passing before they can seed Windows production measurements")
end
abort_with("public-edge appRelay selected path must be relay") unless app_evidence["selected_path"] == "relay"
abort_with("public-edge turnRelay selected path must be turn-relay") unless turn_evidence["selected_path"] == "turn-relay"
abort_with("public-edge authentication proof is incomplete") unless app_evidence["rendezvous_auth_verified"] == true && app_evidence["relay_auth_verified"] == true

sources = {}
generated_at = Time.now.utc.iso8601
public_edge_supported_assertions = []
PUBLIC_EDGE_ASSERTIONS.each do |mapping|
  control = mapping.fetch("control")
  assertion = mapping.fetch("assertion")
  next unless public_edge_assertion_supported?(control, assertion, app_evidence, turn_evidence)

  path = source_directory.join(control, "#{assertion}.json")
  proof = {
    "schemaVersion" => 1,
    "evidenceKind" => "windowsRendezvousRelayAssertionSourceEvidence",
    "control" => control,
    "assertion" => assertion,
    "status" => "pass",
    "measured" => true,
    "generatedAt" => generated_at,
    "deploymentId" => deployment_id,
    "releaseCommitSha" => commit_sha,
    "releaseRef" => release_ref,
    "endpointSetSha256" => endpoint_digest,
    "redacted" => true,
    "sourceSystem" => "quantumLinkPublicEdgeLiveEvidence",
    "rationale" => mapping.fetch("rationale"),
    "inputs" => {
      "manifest" => relative_to_repo(repo_root, public_manifest_path),
      "manifestSha256" => source_digest(public_manifest_path),
      "appRelayEvidence" => relative_to_repo(repo_root, app_evidence_path),
      "appRelayEvidenceSha256" => source_digest(app_evidence_path),
      "turnRelayEvidence" => relative_to_repo(repo_root, turn_evidence_path),
      "turnRelayEvidenceSha256" => source_digest(turn_evidence_path),
      "appRelayVerification" => relative_to_repo(repo_root, app_verification_path),
      "appRelayVerificationSha256" => source_digest(app_verification_path),
      "turnRelayVerification" => relative_to_repo(repo_root, turn_verification_path),
      "turnRelayVerificationSha256" => source_digest(turn_verification_path)
    }
  }
  write_json(path, proof)
  add_source!(sources, [control, assertion], { "source" => relative_to_repo(repo_root, path), "sourceSha256" => source_digest(path) })
  public_edge_supported_assertions << "#{control}/#{assertion}"
end

options.fetch(:operator_sources).each do |source_arg|
  path = repo_path(repo_root, source_arg, "operator source")
  source = parse_json(path, "operator source")
  control = source["control"]
  assertion = source["assertion"]
  abort_with("operator source control is unknown: #{control}") unless REQUIRED_ASSERTIONS.key?(control)
  abort_with("operator source assertion is unknown for #{control}: #{assertion}") unless REQUIRED_ASSERTIONS.fetch(control).include?(assertion)
  validate_source_binding(source, control, assertion, deployment_id, commit_sha, release_ref, endpoint_digest, "operator source #{control}/#{assertion}")
  add_source!(sources, [control, assertion], { "source" => source_arg, "sourceSha256" => source_digest(path) })
end

controls = REQUIRED_ASSERTIONS.map do |control, assertions|
  assertion_entries = assertions.map do |assertion|
    source = sources[[control, assertion]]
    if source
      {
        "name" => assertion,
        "status" => "pass",
        "measured" => true,
        "source" => source.fetch("source"),
        "sourceSha256" => source.fetch("sourceSha256")
      }
    else
      { "name" => assertion, "status" => "blocked", "measured" => false }
    end
  end
  {
    "control" => control,
    "status" => assertion_entries.all? { |entry| entry["status"] == "pass" } ? "pass" : "blocked",
    "assertions" => assertion_entries
  }
end

status = controls.all? { |entry| entry["status"] == "pass" } ? "pass" : "blocked"
measurement = {
  "schemaVersion" => 1,
  "evidenceKind" => "windowsRendezvousRelayMeasuredControls",
  "measurementKind" => "measured",
  "generatedAt" => generated_at,
  "status" => status,
  "release" => { "commitSha" => commit_sha, "ref" => release_ref },
  "deploymentId" => deployment_id,
  "endpointSetSha256" => endpoint_digest,
  "publicEdgeBridge" => {
    "manifest" => relative_to_repo(repo_root, public_manifest_path),
    "manifestSha256" => source_digest(public_manifest_path),
    "generatedSourceDirectory" => relative_to_repo(repo_root, source_directory),
    "supportedAssertions" => public_edge_supported_assertions
  },
  "controls" => controls
}
write_json(output_path, measurement)

puts JSON.generate({
  "status" => status,
  "output" => relative_to_repo(repo_root, output_path),
  "generatedSourceDirectory" => relative_to_repo(repo_root, source_directory),
  "passingAssertionCount" => sources.length,
  "blockedAssertionCount" => REQUIRED_ASSERTIONS.values.sum(&:length) - sources.length
})
