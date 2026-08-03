#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "optparse"
require "pathname"
require "time"

SUPPORTED_ASSERTIONS = {
  "tls" => %w[certificate_valid rotation_tested],
  "signed_expiring_records" => %w[
    valid_record_accepted
    expired_rejected
    replay_rejected
    malformed_signature_rejected
    revoked_key_rejected
  ]
}.freeze

SOURCE_RATIONALES = {
  ["tls", "certificate_valid"] => "Operator TLS drill validated every bound rendezvous and relay endpoint certificate chain without retaining raw certificates or packet captures.",
  ["tls", "rotation_tested"] => "Operator TLS drill proved replacement certificate validation and old-certificate rejection across the rotation window.",
  ["signed_expiring_records", "valid_record_accepted"] => "Operator signed-record drill proved a correctly signed unexpired record is accepted by publish, lookup, and relay consumers.",
  ["signed_expiring_records", "expired_rejected"] => "Operator signed-record drill proved expired records are rejected before publish, lookup, or relay use.",
  ["signed_expiring_records", "replay_rejected"] => "Operator signed-record drill proved stale sequence replay is rejected without replacing the current record.",
  ["signed_expiring_records", "malformed_signature_rejected"] => "Operator signed-record drill proved tampered signatures are rejected without cache side effects.",
  ["signed_expiring_records", "revoked_key_rejected"] => "Operator signed-record drill proved records signed by a revoked key are rejected by publish, lookup, and relay decisions."
}.freeze

MAX_INPUT_BYTES = 1_048_576
MAX_EVIDENCE_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
FORBIDDEN_MARKERS = /
  BEGIN\ (?:RSA\ |EC\ |OPENSSH\ )?PRIVATE\ KEY|
  BEGIN\ CERTIFICATE|
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

def endpoint_set_sha256(rendezvous_endpoints, relay_endpoints)
  Digest::SHA256.hexdigest(JSON.generate({
    "rendezvousEndpoints" => rendezvous_endpoints.sort,
    "relayEndpoints" => relay_endpoints.sort
  }))
end

def source_digest(path)
  Digest::SHA256.file(path).hexdigest
end

def relative_to_repo(repo_root, path)
  path.relative_path_from(repo_root).to_s
end

def fresh_timestamp!(value, field, now)
  abort_with("#{field} is required") unless nonempty_string?(value)

  parsed = Time.iso8601(value)
  abort_with("#{field} is more than #{MAX_FUTURE_SKEW_SECONDS} seconds in the future") if parsed > now + MAX_FUTURE_SKEW_SECONDS
  abort_with("#{field} is older than #{MAX_EVIDENCE_AGE_SECONDS} seconds") if parsed < now - MAX_EVIDENCE_AGE_SECONDS
rescue ArgumentError
  abort_with("#{field} must be a valid RFC3339 timestamp")
end

def boolean_true?(value)
  value == true
end

def status_pass?(value)
  value.is_a?(Hash) && value["status"] == "pass"
end

def proof_at(report, *path)
  path.reduce(report) { |current, key| current.is_a?(Hash) ? current[key] : nil }
end

def assertion_pair(value)
  control, assertion = value.to_s.split("/", 2)
  abort_with("--assertion must be CONTROL/ASSERTION") unless nonempty_string?(control) && nonempty_string?(assertion)
  abort_with("unsupported operator source assertion: #{value}") unless SUPPORTED_ASSERTIONS.fetch(control, []).include?(assertion)

  [control, assertion]
end

def expected_endpoint_set(contract)
  Array(contract["rendezvousEndpoints"]) + Array(contract["relayEndpoints"])
end

def validated_endpoint_set(proof)
  Array(proof["endpoints"]).each_with_object({}) do |entry, result|
    next unless entry.is_a?(Hash)

    endpoint = entry["endpoint"]
    result[endpoint] = entry if nonempty_string?(endpoint)
  end
end

def validate_certificate_proof!(report, contract)
  proof = proof_at(report, "tls", "certificateValidation")
  abort_with("tls/certificate_valid proof is missing") unless status_pass?(proof)
  expected = expected_endpoint_set(contract)
  observed = validated_endpoint_set(proof)
  abort_with("tls/certificate_valid proof endpoint set does not match deployment contract") unless observed.keys.sort == expected.sort

  endpoint_summaries = []
  expected.each do |endpoint|
    entry = observed.fetch(endpoint)
    %w[tlsEnabled certificateChainValid hostnameVerified sanMatched notExpired].each do |field|
      abort_with("tls/certificate_valid #{endpoint} #{field} must be true") unless boolean_true?(entry[field])
    end
    fingerprint = entry["leafFingerprintSha256"]
    abort_with("tls/certificate_valid #{endpoint} leafFingerprintSha256 must be a redacted SHA-256 digest") unless fingerprint.is_a?(String) && fingerprint.match?(/\A[0-9a-f]{64}\z/)
    endpoint_summaries << {
      "endpoint" => endpoint,
      "tlsEnabled" => true,
      "certificateChainValid" => true,
      "hostnameVerified" => true,
      "sanMatched" => true,
      "notExpired" => true,
      "leafFingerprintSha256" => fingerprint
    }
  end

  {
    "status" => "pass",
    "endpoints" => endpoint_summaries
  }
end

def validate_rotation_proof!(report)
  proof = proof_at(report, "tls", "rotation")
  abort_with("tls/rotation_tested proof is missing") unless status_pass?(proof)
  %w[replacementCertificateValid oldCertificateRejected rotationWindowValidated allEndpointsValidated].each do |field|
    abort_with("tls/rotation_tested #{field} must be true") unless boolean_true?(proof[field])
  end
  {
    "status" => "pass",
    "replacementCertificateValid" => true,
    "oldCertificateRejected" => true,
    "rotationWindowValidated" => true,
    "allEndpointsValidated" => true
  }
end

def validate_signed_record_proof!(report, assertion)
  section = proof_at(report, "signedExpiringRecords")
  abort_with("signed_expiring_records section is missing") unless section.is_a?(Hash)

  case assertion
  when "valid_record_accepted"
    proof = section["validRecordAccepted"]
    abort_with("signed_expiring_records/valid_record_accepted proof is missing") unless status_pass?(proof)
    %w[signedByBoundKey unexpired publishAccepted lookupAccepted relayConsumerAccepted].each do |field|
      abort_with("signed_expiring_records/valid_record_accepted #{field} must be true") unless boolean_true?(proof[field])
    end
    {
      "status" => "pass",
      "signedByBoundKey" => true,
      "unexpired" => true,
      "publishAccepted" => true,
      "lookupAccepted" => true,
      "relayConsumerAccepted" => true
    }
  when "expired_rejected"
    proof = section["expiredRejected"]
    abort_with("signed_expiring_records/expired_rejected proof is missing") unless status_pass?(proof)
    %w[expiredBeforeDecision publishRejected lookupRejected relayDenied].each do |field|
      abort_with("signed_expiring_records/expired_rejected #{field} must be true") unless boolean_true?(proof[field])
    end
    {
      "status" => "pass",
      "expiredBeforeDecision" => true,
      "publishRejected" => true,
      "lookupRejected" => true,
      "relayDenied" => true
    }
  when "replay_rejected"
    proof = section["replayRejected"]
    abort_with("signed_expiring_records/replay_rejected proof is missing") unless status_pass?(proof)
    %w[staleSequenceRejected currentRecordPreserved cacheUnchanged].each do |field|
      abort_with("signed_expiring_records/replay_rejected #{field} must be true") unless boolean_true?(proof[field])
    end
    {
      "status" => "pass",
      "staleSequenceRejected" => true,
      "currentRecordPreserved" => true,
      "cacheUnchanged" => true
    }
  when "malformed_signature_rejected"
    proof = section["malformedSignatureRejected"]
    abort_with("signed_expiring_records/malformed_signature_rejected proof is missing") unless status_pass?(proof)
    %w[signatureTamperRejected publishRejected cacheUnchanged].each do |field|
      abort_with("signed_expiring_records/malformed_signature_rejected #{field} must be true") unless boolean_true?(proof[field])
    end
    {
      "status" => "pass",
      "signatureTamperRejected" => true,
      "publishRejected" => true,
      "cacheUnchanged" => true
    }
  when "revoked_key_rejected"
    proof = section["revokedKeyRejected"]
    abort_with("signed_expiring_records/revoked_key_rejected proof is missing") unless status_pass?(proof)
    %w[keyRevokedBeforeSubmission publishRejected lookupRejected relayDenied].each do |field|
      abort_with("signed_expiring_records/revoked_key_rejected #{field} must be true") unless boolean_true?(proof[field])
    end
    {
      "status" => "pass",
      "keyRevokedBeforeSubmission" => true,
      "publishRejected" => true,
      "lookupRejected" => true,
      "relayDenied" => true
    }
  else
    abort_with("unsupported signed-record assertion: #{assertion}")
  end
end

def validate_assertion_proof!(report, contract, control, assertion)
  case [control, assertion]
  when ["tls", "certificate_valid"]
    validate_certificate_proof!(report, contract)
  when ["tls", "rotation_tested"]
    validate_rotation_proof!(report)
  else
    validate_signed_record_proof!(report, assertion)
  end
end

def write_json(path, value, force)
  abort_with("operator source already exists; pass --force to replace: #{path}") if path.exist? && !force

  FileUtils.mkdir_p(path.dirname)
  path.write("#{JSON.pretty_generate(value)}\n", encoding: "UTF-8")
end

options = {
  repo_root: Pathname.new(__dir__).join("../..").expand_path,
  contract: "windows/deployment/rendezvous-relay-production.json",
  output_directory: "windows/validation/operator-sources",
  assertions: nil,
  force: false
}

OptionParser.new do |parser|
  parser.banner = "usage: #{$PROGRAM_NAME} --drill-report PATH --contract PATH [--assertion CONTROL/ASSERTION ...] [options]"
  parser.on("--repo-root PATH") { |value| options[:repo_root] = Pathname.new(value).expand_path }
  parser.on("--contract PATH") { |value| options[:contract] = value }
  parser.on("--drill-report PATH") { |value| options[:drill_report] = value }
  parser.on("--output-directory PATH") { |value| options[:output_directory] = value }
  parser.on("--assertion CONTROL/ASSERTION") do |value|
    options[:assertions] ||= []
    options[:assertions] << assertion_pair(value)
  end
  parser.on("--force") { options[:force] = true }
end.parse!

abort_with("--drill-report is required") unless options[:drill_report]

repo_root = options.fetch(:repo_root)
contract_path = repo_path(repo_root, options.fetch(:contract), "contract")
report_path = repo_path(repo_root, options.fetch(:drill_report), "drill report")
output_directory = repo_path(repo_root, options.fetch(:output_directory), "output directory")
contract = parse_json(contract_path, "deployment contract")
report = parse_json(report_path, "operator drill report")
now = Time.now.utc

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

abort_with("operator drill report schemaVersion must be 1") unless report["schemaVersion"] == 1
abort_with("operator drill report evidenceKind is invalid") unless report["evidenceKind"] == "windowsRendezvousRelayOperatorDrillReport"
abort_with("operator drill report status must be pass") unless report["status"] == "pass"
abort_with("operator drill report must be redacted") unless report["redacted"] == true
fresh_timestamp!(report["generatedAt"], "operator drill report generatedAt", now)
abort_with("operator drill report deploymentId does not match") unless report["deploymentId"] == deployment_id
abort_with("operator drill report releaseCommitSha does not match") unless report["releaseCommitSha"] == commit_sha
abort_with("operator drill report releaseRef does not match") unless report["releaseRef"] == release_ref
abort_with("operator drill report endpointSetSha256 does not match") unless report["endpointSetSha256"] == endpoint_digest

assertions = options[:assertions] || SUPPORTED_ASSERTIONS.flat_map { |control, names| names.map { |name| [control, name] } }
generated_at = now.iso8601
drill_id = report["drillId"]
report_relative = relative_to_repo(repo_root, report_path)
report_sha256 = source_digest(report_path)

sources = assertions.map do |control, assertion|
  proof = validate_assertion_proof!(report, contract, control, assertion)
  output_path = output_directory.join(control, "#{assertion}.json")
  source = {
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
    "sourceSystem" => "windowsRendezvousRelayOperatorDrillReport",
    "rationale" => SOURCE_RATIONALES.fetch([control, assertion]),
    "inputs" => {
      "drillReport" => report_relative,
      "drillReportSha256" => report_sha256,
      "drillId" => drill_id
    }.compact,
    "proofSummary" => proof
  }
  write_json(output_path, source, options.fetch(:force))
  {
    "control" => control,
    "assertion" => assertion,
    "source" => relative_to_repo(repo_root, output_path),
    "sourceSha256" => source_digest(output_path)
  }
end

puts JSON.generate({
  "status" => "pass",
  "generatedSourceCount" => sources.length,
  "sources" => sources
})
