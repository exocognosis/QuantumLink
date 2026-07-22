#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "ipaddr"
require "json"
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
REQUIRED_CONTROLS = REQUIRED_ASSERTIONS.keys.freeze
MAX_EVIDENCE_BYTES = 1_048_576
MAX_EVIDENCE_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
RESERVED_ENDPOINT_SUFFIXES = %w[.invalid .localhost .test .example].freeze
RESERVED_ENDPOINT_DOMAINS = %w[example.com example.net example.org].freeze

FORBIDDEN_MARKERS = /
  BEGIN\ (?:RSA\ |EC\ |OPENSSH\ )?PRIVATE\ KEY|
  WALLET_SEED|
  ENTITLEMENT_TOKEN|
  DYTALLIX_WALLET_SECRET|
  QLINK_PRODUCTION_ENDPOINT_SECRET|
  WINDOWS_RELEASE_PRIVATE_KEY|
  \.pcapng?\b|
  support-bundle.*\.(?:tar|tar\.gz|tgz|zst|zip)\b
/ix.freeze

def usage
  warn "usage: #{$PROGRAM_NAME} [--require-ready] [--repo-root PATH] [--expected-sha SHA] [--expected-ref REF] [--report PATH] MANIFEST"
  exit 2
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

def repo_path(repo_root, value)
  return nil unless repo_relative_path?(value)

  candidate = repo_root.join(value).cleanpath
  prefix = "#{repo_root.cleanpath}#{File::SEPARATOR}"
  candidate.to_s.start_with?(prefix) ? candidate : nil
end

def contained_real_file?(repo_root, candidate)
  return false unless candidate.file?

  root = repo_root.realpath.to_s
  candidate.realpath.to_s.start_with?("#{root}#{File::SEPARATOR}")
rescue Errno::ENOENT, Errno::EACCES
  false
end

def parse_fresh_timestamp(value, field, failures, now)
  unless nonempty_string?(value) && value.end_with?("Z")
    failures << "#{field} must be a UTC RFC3339 timestamp ending in Z"
    return nil
  end

  parsed = Time.iso8601(value)
  failures << "#{field} is more than #{MAX_FUTURE_SKEW_SECONDS} seconds in the future" if parsed > now + MAX_FUTURE_SKEW_SECONDS
  failures << "#{field} is older than #{MAX_EVIDENCE_AGE_SECONDS} seconds" if parsed < now - MAX_EVIDENCE_AGE_SECONDS
  parsed
rescue ArgumentError
  failures << "#{field} must be a valid RFC3339 timestamp"
  nil
end

def production_host?(host)
  return false unless nonempty_string?(host)

  normalized = host.downcase.chomp(".")
  return false unless normalized.match?(/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/)
  return false if RESERVED_ENDPOINT_SUFFIXES.any? { |suffix| normalized.end_with?(suffix) }
  return false if RESERVED_ENDPOINT_DOMAINS.any? { |domain| normalized == domain || normalized.end_with?(".#{domain}") }

  begin
    IPAddr.new(normalized)
    return false
  rescue IPAddr::InvalidAddressError
    # A production endpoint must be a DNS host rather than an IP literal.
  end

  true
end

def https_endpoint?(value)
  return false unless nonempty_string?(value)

  uri = URI.parse(value)
  uri.scheme == "https" && production_host?(uri.host) && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
rescue URI::InvalidURIError
  false
end

def relay_endpoint?(value)
  return true if https_endpoint?(value)
  return false unless nonempty_string?(value)

  match = value.match(/\Aturns:([A-Za-z0-9.-]+)(?::(\d+))?\z/)
  return false unless match && production_host?(match[1])

  match[2].nil? || (1..65_535).cover?(match[2].to_i)
end

def validate_status(value, field, failures, blockers)
  case value
  when "pass"
    nil
  when "blocked", "fail"
    blockers << "#{field} is #{value}"
  else
    failures << "#{field} must be pass, blocked, or fail"
  end
end

def endpoint_set_sha256(rendezvous_endpoints, relay_endpoints)
  canonical = JSON.generate({
    "rendezvousEndpoints" => rendezvous_endpoints.sort,
    "relayEndpoints" => relay_endpoints.sort
  })
  Digest::SHA256.hexdigest(canonical)
end

def write_report(path, report)
  FileUtils.mkdir_p(path.dirname)
  path.write("#{JSON.pretty_generate(report)}\n", encoding: "UTF-8")
end

require_ready = false
repo_root = Pathname.new(__dir__).join("../..").expand_path
expected_sha = nil
expected_ref = nil
report_arg = nil
args = ARGV.dup

until args.empty?
  case args.first
  when "--require-ready"
    require_ready = true
    args.shift
  when "--repo-root"
    args.shift
    usage if args.empty?
    repo_root = Pathname.new(args.shift).expand_path
  when "--expected-sha"
    args.shift
    usage if args.empty?
    expected_sha = args.shift
  when "--expected-ref"
    args.shift
    usage if args.empty?
    expected_ref = args.shift
  when "--report"
    args.shift
    usage if args.empty?
    report_arg = args.shift
  else
    break
  end
end
usage unless args.length == 1

manifest_arg = args.first
manifest_path = repo_path(repo_root, manifest_arg)
report_path = report_arg.nil? ? nil : repo_path(repo_root, report_arg)
failures = []
blockers = []
warnings = []
manifest = {}
now = Time.now.utc

failures << "manifest must be a repo-relative path" if manifest_path.nil?
failures << "report must be a repo-relative path" if report_arg && report_path.nil?
if require_ready
  failures << "--expected-sha is required with --require-ready" unless nonempty_string?(expected_sha)
  failures << "--expected-ref is required with --require-ready" unless nonempty_string?(expected_ref)
end

manifest_sha256 = nil
if manifest_path && !manifest_path.file?
  blockers << "production evidence manifest is missing: #{manifest_arg}"
elsif manifest_path && !contained_real_file?(repo_root, manifest_path)
  failures << "production evidence manifest must resolve inside the repository"
elsif manifest_path
  raw_text = manifest_path.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
  manifest_sha256 = Digest::SHA256.hexdigest(raw_text)
  failures << "forbidden secret marker found in production evidence manifest" if raw_text.match?(FORBIDDEN_MARKERS)
  begin
    manifest = JSON.parse(raw_text)
  rescue JSON::ParserError => e
    failures << "production evidence manifest is invalid JSON: #{e.message}"
  end
end

control_digests = []
if manifest_path&.file?
  unless manifest.is_a?(Hash)
    failures << "production evidence manifest must be a JSON object"
    manifest = {}
  end

  failures << "schemaVersion must be 2" unless manifest["schemaVersion"] == 2
  failures << "evidenceKind must be windowsRendezvousRelayProductionEvidence" unless manifest["evidenceKind"] == "windowsRendezvousRelayProductionEvidence"
  failures << "product must be QuantumLink Windows" unless manifest["product"] == "QuantumLink Windows"
  failures << "platform must be windows" unless manifest["platform"] == "windows"
  failures << "releaseScope must be windows-x64-production-release" unless manifest["releaseScope"] == "windows-x64-production-release"
  parse_fresh_timestamp(manifest["generatedAt"], "generatedAt", failures, now)
  validate_status(manifest["status"], "production evidence status", failures, blockers)

  release = manifest["release"]
  if !release.is_a?(Hash)
    failures << "release section is required"
    release = {}
  end
  commit_sha = release["commitSha"]
  release_ref = release["ref"]
  failures << "release.commitSha must be a 40- or 64-character hexadecimal digest" unless commit_sha.is_a?(String) && commit_sha.match?(/\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/)
  failures << "release.ref must begin with refs/heads/ or refs/tags/" unless release_ref.is_a?(String) && release_ref.match?(%r{\Arefs/(?:heads|tags)/[^\s]+\z})
  failures << "release.commitSha does not match the current release commit" if expected_sha && commit_sha != expected_sha
  failures << "release.ref does not match the current release ref" if expected_ref && release_ref != expected_ref

  deployment_id = manifest["deploymentId"]
  failures << "deploymentId is required and must be at most 128 characters" unless nonempty_string?(deployment_id) && deployment_id.length <= 128

  rendezvous = manifest["rendezvousRelay"]
  if !rendezvous.is_a?(Hash)
    failures << "rendezvousRelay section is required"
    rendezvous = {}
  end
  validate_status(rendezvous["status"], "rendezvousRelay.status", failures, blockers)

  rendezvous_endpoints = rendezvous["rendezvousEndpoints"]
  unless rendezvous_endpoints.is_a?(Array) && !rendezvous_endpoints.empty? && rendezvous_endpoints.all? { |entry| https_endpoint?(entry) }
    failures << "rendezvousRelay.rendezvousEndpoints must contain only production HTTPS URLs"
    rendezvous_endpoints = []
  end
  relay_endpoints = rendezvous["relayEndpoints"]
  unless relay_endpoints.is_a?(Array) && !relay_endpoints.empty? && relay_endpoints.all? { |entry| relay_endpoint?(entry) }
    failures << "rendezvousRelay.relayEndpoints must contain only production turns or HTTPS endpoints"
    relay_endpoints = []
  end
  calculated_endpoint_digest = endpoint_set_sha256(rendezvous_endpoints, relay_endpoints)
  failures << "rendezvousRelay.endpointSetSha256 does not match the declared endpoints" unless rendezvous["endpointSetSha256"] == calculated_endpoint_digest

  failures << "rendezvousRelay.abuseLogsRedacted must be true" unless rendezvous["abuseLogsRedacted"] == true
  %w[rawPacketPayloadsCommitted rawGamePayloadsCommitted].each do |field|
    failures << "rendezvousRelay.#{field} must be false" unless rendezvous[field] == false
  end

  controls = rendezvous["controls"]
  unless controls.is_a?(Array)
    failures << "rendezvousRelay.controls must be an array"
    controls = []
  end
  controls_by_name = {}
  evidence_paths = {}
  evidence_digests = {}
  controls.each do |entry|
    unless entry.is_a?(Hash) && nonempty_string?(entry["control"])
      failures << "rendezvousRelay.controls entries must be objects with a control name"
      next
    end
    name = entry["control"]
    unless REQUIRED_CONTROLS.include?(name)
      failures << "unknown rendezvous/relay control: #{name}"
      next
    end
    if controls_by_name.key?(name)
      failures << "duplicate rendezvous/relay control: #{name}"
      next
    end
    controls_by_name[name] = entry
  end

  REQUIRED_CONTROLS.sort.each do |control|
    entry = controls_by_name[control]
    unless entry
      failures << "missing rendezvous/relay control: #{control}"
      next
    end

    validate_status(entry["status"], "rendezvous/relay control #{control} status", failures, blockers)
    failures << "rendezvous/relay control #{control} must be redacted" unless entry["redacted"] == true
    evidence_arg = entry["evidence"]
    evidence = repo_path(repo_root, evidence_arg)
    if evidence.nil?
      failures << "rendezvous/relay control #{control} evidence must be a repo-relative path"
      next
    end
    if evidence_paths.key?(evidence_arg)
      failures << "rendezvous/relay controls #{evidence_paths[evidence_arg]} and #{control} must not share an evidence file"
      next
    end
    evidence_paths[evidence_arg] = control
    unless evidence.file?
      blockers << "rendezvous/relay control #{control} evidence file is missing: #{evidence_arg}"
      next
    end
    unless contained_real_file?(repo_root, evidence)
      failures << "rendezvous/relay control #{control} evidence must resolve inside the repository"
      next
    end
    if evidence.size > MAX_EVIDENCE_BYTES
      failures << "rendezvous/relay control #{control} evidence exceeds #{MAX_EVIDENCE_BYTES} bytes"
      next
    end

    evidence_text = evidence.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
    digest = Digest::SHA256.hexdigest(evidence_text)
    failures << "rendezvous/relay control #{control} evidence SHA-256 does not match" unless entry["sha256"] == digest
    if evidence_digests.key?(digest)
      failures << "rendezvous/relay controls #{evidence_digests[digest]} and #{control} must not share identical evidence"
    end
    evidence_digests[digest] = control
    failures << "forbidden secret marker found in rendezvous/relay control #{control} evidence" if evidence_text.match?(FORBIDDEN_MARKERS)

    begin
      proof = JSON.parse(evidence_text)
    rescue JSON::ParserError
      failures << "rendezvous/relay control #{control} evidence must be valid JSON"
      next
    end
    unless proof.is_a?(Hash)
      failures << "rendezvous/relay control #{control} evidence must be a JSON object"
      next
    end
    failures << "rendezvous/relay control #{control} evidence schemaVersion must be 1" unless proof["schemaVersion"] == 1
    failures << "rendezvous/relay control #{control} evidenceKind is invalid" unless proof["evidenceKind"] == "windowsRendezvousRelayControlEvidence"
    failures << "rendezvous/relay control #{control} evidence control does not match" unless proof["control"] == control
    failures << "rendezvous/relay control #{control} evidence status must be pass" unless proof["status"] == "pass"
    failures << "rendezvous/relay control #{control} evidence must be redacted" unless proof["redacted"] == true
    parse_fresh_timestamp(proof["generatedAt"], "rendezvous/relay control #{control} generatedAt", failures, now)
    failures << "rendezvous/relay control #{control} deploymentId does not match" unless proof["deploymentId"] == deployment_id
    failures << "rendezvous/relay control #{control} releaseCommitSha does not match" unless proof["releaseCommitSha"] == commit_sha
    failures << "rendezvous/relay control #{control} releaseRef does not match" unless proof["releaseRef"] == release_ref
    failures << "rendezvous/relay control #{control} endpointSetSha256 does not match" unless proof["endpointSetSha256"] == calculated_endpoint_digest

    assertions = proof["assertions"]
    assertions_by_name = if assertions.is_a?(Array)
                           assertions.each_with_object({}) do |item, result|
                             result[item["name"]] = item if item.is_a?(Hash) && nonempty_string?(item["name"])
                           end
                         else
                           {}
                         end
    failures << "rendezvous/relay control #{control} assertions must be an array" unless assertions.is_a?(Array)
    REQUIRED_ASSERTIONS.fetch(control).each do |assertion|
      item = assertions_by_name[assertion]
      failures << "rendezvous/relay control #{control} missing passing assertion: #{assertion}" unless item && item["status"] == "pass"
    end

    control_digests << { "control" => control, "evidence" => evidence_arg, "sha256" => digest }
  end
end

ready = failures.empty? && blockers.empty?
report = {
  "schemaVersion" => 1,
  "evidenceKind" => "windowsRendezvousRelayProductionEvidenceVerification",
  "generatedAt" => now.iso8601,
  "valid" => failures.empty?,
  "productionEvidenceReady" => ready,
  "rendezvousRelayReady" => ready,
  "manifest" => manifest_arg,
  "manifestSha256" => manifest_sha256,
  "expectedRelease" => { "commitSha" => expected_sha, "ref" => expected_ref },
  "controlEvidence" => control_digests.sort_by { |entry| entry["control"] },
  "blockers" => blockers,
  "failures" => failures,
  "warnings" => warnings
}

write_report(report_path, report) if report_path
puts JSON.generate(report)
exit((failures.any? || (require_ready && blockers.any?)) ? 1 : 0)
