#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "ipaddr"
require "json"
require "optparse"
require "pathname"
require "time"
require "uri"

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
ALLOWED_STATUSES = %w[pass blocked fail].freeze
MAX_INPUT_BYTES = 1_048_576
MAX_EVIDENCE_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
FORBIDDEN_MARKERS = /
  BEGIN\ (?:RSA\ |EC\ |OPENSSH\ )?PRIVATE\ KEY|
  WALLET_SEED|ENTITLEMENT_TOKEN|DYTALLIX_WALLET_SECRET|
  QLINK_PRODUCTION_ENDPOINT_SECRET|WINDOWS_RELEASE_PRIVATE_KEY|
  \.pcapng?\b|support-bundle.*\.(?:tar|tar\.gz|tgz|zst|zip)\b
/ix.freeze
RESERVED_ENDPOINT_SUFFIXES = %w[.invalid .localhost .test .example].freeze
RESERVED_ENDPOINT_DOMAINS = %w[example.com example.net example.org].freeze

def abort_with(message)
  warn message
  exit 1
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

def nonempty_string?(value)
  value.is_a?(String) && !value.strip.empty?
end

def repo_relative_path?(value)
  return false unless nonempty_string?(value)
  return false if value.include?("\\") || value.match?(/\A[A-Za-z]:/) || value.start_with?("//")

  path = Pathname.new(value)
  !path.absolute? && !path.each_filename.any? { |part| %w[. ..].include?(part) }
end

def repo_path(repo_root, relative, field)
  abort_with("#{field} must be a repo-relative path") unless repo_relative_path?(relative)

  path = repo_root.join(relative).cleanpath
  prefix = "#{repo_root.cleanpath}#{File::SEPARATOR}"
  abort_with("#{field} must resolve inside the repository") unless path.to_s.start_with?(prefix)
  path
end

def contained_real_file?(repo_root, candidate)
  return false unless candidate.file?

  root = repo_root.realpath.to_s
  candidate.realpath.to_s.start_with?("#{root}#{File::SEPARATOR}")
rescue Errno::ENOENT, Errno::EACCES
  false
end

def fresh_timestamp!(value, field, now)
  abort_with("#{field} must be a UTC RFC3339 timestamp ending in Z") unless nonempty_string?(value) && value.end_with?("Z")

  parsed = Time.iso8601(value)
  abort_with("#{field} is more than #{MAX_FUTURE_SKEW_SECONDS} seconds in the future") if parsed > now + MAX_FUTURE_SKEW_SECONDS
  abort_with("#{field} is older than #{MAX_EVIDENCE_AGE_SECONDS} seconds") if parsed < now - MAX_EVIDENCE_AGE_SECONDS
rescue ArgumentError
  abort_with("#{field} must be a valid RFC3339 timestamp")
end

def validate_source_evidence(repo_root, assertion, control, name, deployment_id, commit_sha, release_ref, endpoint_sha256, now, seen_sources)
  source_arg = assertion["source"]
  return nil unless nonempty_string?(source_arg)

  description = "source evidence for #{control}/#{name}"
  source_path = repo_path(repo_root, source_arg, "#{description} path")
  abort_with("#{description} must resolve inside the repository") unless contained_real_file?(repo_root, source_path)

  canonical_path = source_path.cleanpath.to_s
  real_path = source_path.realpath.to_s
  stat = source_path.stat
  file_identity = [stat.dev, stat.ino]
  abort_with("#{description} must use a distinct source evidence file") if seen_sources.key?(canonical_path) || seen_sources.key?(real_path) || seen_sources.key?(file_identity)

  source = parse_json(source_path, description)
  digest = Digest::SHA256.file(source_path).hexdigest
  claimed_digest = assertion["sourceSha256"]
  if !claimed_digest.nil? && claimed_digest != digest
    abort_with("#{description} sourceSha256 does not match the source file")
  end

  abort_with("#{description} schemaVersion must be 1") unless source["schemaVersion"] == 1
  abort_with("#{description} evidenceKind is invalid") unless source["evidenceKind"] == "windowsRendezvousRelayAssertionSourceEvidence"
  abort_with("#{description} control does not match") unless source["control"] == control
  abort_with("#{description} assertion does not match") unless source["assertion"] == name
  abort_with("#{description} deploymentId does not match") unless source["deploymentId"] == deployment_id
  abort_with("#{description} releaseCommitSha does not match") unless source["releaseCommitSha"] == commit_sha
  abort_with("#{description} releaseRef does not match") unless source["releaseRef"] == release_ref
  abort_with("#{description} endpointSetSha256 does not match") unless source["endpointSetSha256"] == endpoint_sha256
  abort_with("#{description} status must be pass") unless source["status"] == "pass"
  abort_with("#{description} measured must be true") unless source["measured"] == true
  abort_with("#{description} redacted must be true") unless source["redacted"] == true
  fresh_timestamp!(source["generatedAt"], "#{description} generatedAt", now)

  seen_sources[canonical_path] = "#{control}/#{name}"
  seen_sources[real_path] = "#{control}/#{name}"
  seen_sources[file_identity] = "#{control}/#{name}"
  { "path" => source_path, "relative" => source_arg, "sha256" => digest }
end

def production_host?(host)
  return false unless nonempty_string?(host)

  normalized = host.downcase.chomp(".")
  return false unless normalized.match?(/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/)
  return false if RESERVED_ENDPOINT_SUFFIXES.any? { |suffix| normalized.end_with?(suffix) }
  return false if RESERVED_ENDPOINT_DOMAINS.any? { |domain| normalized == domain || normalized.end_with?(".#{domain}") }

  IPAddr.new(normalized)
  false
rescue IPAddr::InvalidAddressError
  true
end

def https_endpoint?(value)
  uri = URI.parse(value)
  uri.scheme == "https" && production_host?(uri.host) && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
rescue URI::InvalidURIError, TypeError
  false
end

def relay_endpoint?(value)
  return true if https_endpoint?(value)
  return false unless nonempty_string?(value)

  match = value.match(/\Aturns:([A-Za-z0-9.-]+)(?::(\d+))?\z/)
  match && production_host?(match[1]) && (match[2].nil? || (1..65_535).cover?(match[2].to_i))
end

def endpoint_digest(rendezvous, relay)
  Digest::SHA256.hexdigest(JSON.generate({
    "rendezvousEndpoints" => rendezvous.sort,
    "relayEndpoints" => relay.sort
  }))
end

def write_json(path, value)
  FileUtils.mkdir_p(path.dirname)
  path.write("#{JSON.pretty_generate(value)}\n", encoding: "UTF-8")
end

options = {
  repo_root: Pathname.new(__dir__).join("../..").expand_path,
  contract: "windows/deployment/rendezvous-relay-production.template.json"
}
OptionParser.new do |parser|
  parser.banner = "usage: #{$PROGRAM_NAME} [options]"
  parser.on("--repo-root PATH") { |value| options[:repo_root] = Pathname.new(value).expand_path }
  parser.on("--contract PATH") { |value| options[:contract] = value }
  parser.on("--measurements PATH") { |value| options[:measurements] = value }
  parser.on("--expected-sha SHA") { |value| options[:expected_sha] = value }
  parser.on("--expected-ref REF") { |value| options[:expected_ref] = value }
end.parse!

repo_root = options.fetch(:repo_root)
contract_path = repo_path(repo_root, options.fetch(:contract), "contract")
contract = parse_json(contract_path, "deployment contract")
abort_with("deployment contract schemaVersion must be 1") unless contract["schemaVersion"] == 1
abort_with("deployment contract evidenceKind is invalid") unless contract["evidenceKind"] == "windowsRendezvousRelayDeploymentContract"
abort_with("deployment contract status must be pass, blocked, or fail") unless ALLOWED_STATUSES.include?(contract["status"])

release = contract["release"]
abort_with("deployment contract release is required") unless release.is_a?(Hash)
commit_sha = release["commitSha"]
release_ref = release["ref"]
abort_with("release.commitSha must be an exact 40- or 64-character hexadecimal digest") unless commit_sha.is_a?(String) && commit_sha.match?(/\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/)
abort_with("release.ref must begin with refs/heads/ or refs/tags/") unless release_ref.is_a?(String) && release_ref.match?(%r{\Arefs/(?:heads|tags)/[^\s]+\z})
abort_with("release.commitSha does not match --expected-sha") if options[:expected_sha] && options[:expected_sha] != commit_sha
abort_with("release.ref does not match --expected-ref") if options[:expected_ref] && options[:expected_ref] != release_ref

deployment = contract["deployment"]
abort_with("deployment section is required") unless deployment.is_a?(Hash)
deployment_id = deployment["id"]
abort_with("deployment.id is required and must be at most 128 characters") unless nonempty_string?(deployment_id) && deployment_id.length <= 128
abort_with("deployment.status must be pass, blocked, or fail") unless ALLOWED_STATUSES.include?(deployment["status"])

rendezvous_endpoints = contract["rendezvousEndpoints"]
relay_endpoints = contract["relayEndpoints"]
abort_with("rendezvousEndpoints must contain production HTTPS endpoints") unless rendezvous_endpoints.is_a?(Array) && !rendezvous_endpoints.empty? && rendezvous_endpoints.all? { |value| https_endpoint?(value) }
abort_with("relayEndpoints must contain production turns or HTTPS endpoints") unless relay_endpoints.is_a?(Array) && !relay_endpoints.empty? && relay_endpoints.all? { |value| relay_endpoint?(value) }
endpoint_sha256 = endpoint_digest(rendezvous_endpoints, relay_endpoints)

prerequisites = contract["prerequisites"]
abort_with("prerequisites must be a non-empty array") unless prerequisites.is_a?(Array) && !prerequisites.empty?
prerequisites.each do |item|
  abort_with("each prerequisite requires an id, status, and reason") unless item.is_a?(Hash) && nonempty_string?(item["id"]) && ALLOWED_STATUSES.include?(item["status"]) && nonempty_string?(item["reason"])
end

measurement = nil
measurement_sha256 = nil
if options[:measurements]
  measurement_path = repo_path(repo_root, options[:measurements], "measurements")
  measurement = parse_json(measurement_path, "production measurements")
  measurement_sha256 = Digest::SHA256.file(measurement_path).hexdigest
  abort_with("measurements schemaVersion must be 1") unless measurement["schemaVersion"] == 1
  abort_with("measurements evidenceKind is invalid") unless measurement["evidenceKind"] == "windowsRendezvousRelayMeasuredControls"
  abort_with("measurements measurementKind must be measured") unless measurement["measurementKind"] == "measured"
  abort_with("measurements release binding does not match the deployment contract") unless measurement.dig("release", "commitSha") == commit_sha && measurement.dig("release", "ref") == release_ref
  abort_with("measurements deploymentId does not match the deployment contract") unless measurement["deploymentId"] == deployment_id
  abort_with("measurements endpointSetSha256 does not match the deployment contract") unless measurement["endpointSetSha256"] == endpoint_sha256
end

output = contract["output"]
abort_with("output section is required") unless output.is_a?(Hash)
manifest_path = repo_path(repo_root, output["manifest"], "output.manifest")
control_directory = repo_path(repo_root, output["controlDirectory"], "output.controlDirectory")
digest_manifest_path = repo_path(repo_root, output["digestManifest"], "output.digestManifest")
checksums_path = repo_path(repo_root, output["checksums"], "output.checksums")

generated_at = Time.now.utc.iso8601
global_ready = contract["status"] == "pass" && deployment["status"] == "pass" && prerequisites.all? { |item| item["status"] == "pass" } && !measurement.nil?
measured_controls = Array(measurement && measurement["controls"]).each_with_object({}) do |item, result|
  next unless item.is_a?(Hash) && nonempty_string?(item["control"])

  abort_with("measurements contain duplicate control #{item["control"]}") if result.key?(item["control"])
  result[item["control"]] = item
end

control_entries = []
control_paths = []
source_paths = []
seen_sources = {}
REQUIRED_ASSERTIONS.each do |control, required_assertions|
  measured = measured_controls[control]
  assertions_by_name = Array(measured && measured["assertions"]).each_with_object({}) do |item, result|
    next unless item.is_a?(Hash) && nonempty_string?(item["name"])

    abort_with("measurements contain duplicate assertion #{control}/#{item["name"]}") if result.key?(item["name"])
    result[item["name"]] = item
  end
  validated_sources = required_assertions.each_with_object({}) do |name, result|
    assertion = assertions_by_name[name]
    next unless assertion && assertion["status"] == "pass" && assertion["measured"] == true

    source = validate_source_evidence(
      repo_root, assertion, control, name, deployment_id, commit_sha, release_ref,
      endpoint_sha256, Time.now.utc, seen_sources
    )
    next unless source

    result[name] = source
    source_paths << source["path"]
  end
  explicit_pass = measured.is_a?(Hash) && measured["status"] == "pass" && required_assertions.all? do |name|
    validated_sources.key?(name)
  end
  control_status = if measured && measured["status"] == "fail"
                     "fail"
                   elsif global_ready && explicit_pass
                     "pass"
                   else
                     "blocked"
                   end

  assertions = required_assertions.map do |name|
    if control_status == "pass"
      validated_source = validated_sources.fetch(name)
      {
        "name" => name,
        "status" => "pass",
        "measured" => true,
        "source" => validated_source["relative"],
        "sourceSha256" => validated_source["sha256"]
      }
    else
      { "name" => name, "status" => control_status, "measured" => false }
    end
  end
  proof = {
    "schemaVersion" => 1,
    "evidenceKind" => "windowsRendezvousRelayControlEvidence",
    "control" => control,
    "status" => control_status,
    "generatedAt" => generated_at,
    "deploymentId" => deployment_id,
    "releaseCommitSha" => commit_sha,
    "releaseRef" => release_ref,
    "endpointSetSha256" => endpoint_sha256,
    "redacted" => true,
    "measurementSha256" => measurement_sha256,
    "assertions" => assertions
  }
  path = control_directory.join("#{control}.json")
  write_json(path, proof)
  relative = path.relative_path_from(repo_root).to_s
  digest = Digest::SHA256.file(path).hexdigest
  control_paths << path
  control_entries << {
    "control" => control,
    "status" => control_status,
    "evidence" => relative,
    "sha256" => digest,
    "redacted" => true
  }
end

overall_status = if control_entries.any? { |entry| entry["status"] == "fail" } || contract["status"] == "fail" || deployment["status"] == "fail" || prerequisites.any? { |item| item["status"] == "fail" }
                   "fail"
                 elsif global_ready && control_entries.all? { |entry| entry["status"] == "pass" }
                   "pass"
                 else
                   "blocked"
                 end

manifest = {
  "schemaVersion" => 2,
  "evidenceKind" => "windowsRendezvousRelayProductionEvidence",
  "product" => "QuantumLink Windows",
  "platform" => "windows",
  "releaseScope" => "windows-x64-production-release",
  "generatedAt" => generated_at,
  "status" => overall_status,
  "release" => { "commitSha" => commit_sha, "ref" => release_ref },
  "deploymentId" => deployment_id,
  "generation" => {
    "contract" => options.fetch(:contract),
    "measurements" => options[:measurements],
    "measurementSha256" => measurement_sha256,
    "prerequisites" => prerequisites
  },
  "rendezvousRelay" => {
    "status" => overall_status,
    "rendezvousEndpoints" => rendezvous_endpoints,
    "relayEndpoints" => relay_endpoints,
    "endpointSetSha256" => endpoint_sha256,
    "abuseLogsRedacted" => true,
    "rawPacketPayloadsCommitted" => false,
    "rawGamePayloadsCommitted" => false,
    "controls" => control_entries
  }
}
write_json(manifest_path, manifest)

evidence_paths = [manifest_path, *control_paths, *source_paths].uniq
digest_manifest = {
  "schemaVersion" => 1,
  "evidenceKind" => "windowsRendezvousRelayProductionEvidenceDigests",
  "generatedAt" => generated_at,
  "status" => overall_status,
  "release" => { "commitSha" => commit_sha, "ref" => release_ref },
  "files" => evidence_paths.sort_by(&:to_s).map do |path|
    {
      "path" => path.relative_path_from(repo_root).to_s,
      "sha256" => Digest::SHA256.file(path).hexdigest,
      "lengthBytes" => path.size
    }
  end
}
write_json(digest_manifest_path, digest_manifest)

checksum_paths = [*evidence_paths, digest_manifest_path].sort_by(&:to_s)
FileUtils.mkdir_p(checksums_path.dirname)
checksums_path.write(checksum_paths.map { |path| "#{Digest::SHA256.file(path).hexdigest}  #{path.relative_path_from(repo_root)}" }.join("\n") + "\n", encoding: "US-ASCII")

puts JSON.generate({
  "status" => overall_status,
  "productionEvidenceReady" => overall_status == "pass",
  "manifest" => manifest_path.relative_path_from(repo_root).to_s,
  "digestManifest" => digest_manifest_path.relative_path_from(repo_root).to_s,
  "checksums" => checksums_path.relative_path_from(repo_root).to_s
})
