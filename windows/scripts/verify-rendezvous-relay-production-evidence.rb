#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "pathname"
require "time"
require "uri"

REQUIRED_CONTROLS = %w[
  tls
  authentication
  signed_expiring_records
  rate_limits
  abuse_logs
  revocation_propagation
  relay_denial
  retention
  key_rotation
  endpoint_rotation
  incident_shutdown
].freeze
MAX_EVIDENCE_BYTES = 1_048_576

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
  warn "usage: #{$PROGRAM_NAME} [--require-ready] [--repo-root PATH] windows/validation/rendezvous-relay-production-evidence.json"
  exit 2
end

require_ready = false
repo_root = Pathname.new(__dir__).join("../..").expand_path
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
  else
    break
  end
end
usage unless args.length == 1

manifest_path = Pathname.new(args.first)
failures = []
blockers = []
warnings = []
schema_checks_required = true

def fail_with(failures, message)
  failures << message
end

def block_with(blockers, message)
  blockers << message
end

def nonempty_string?(value)
  value.is_a?(String) && !value.strip.empty?
end

def relative_evidence_path?(value)
  return false unless nonempty_string?(value)
  return false if value.include?("\\") || value.match?(/\A[A-Za-z]:/) || value.start_with?("//")

  path = Pathname.new(value)
  !path.absolute? && !path.each_filename.any? { |part| %w[. ..].include?(part) }
end

def evidence_file(repo_root, value)
  return nil unless relative_evidence_path?(value)

  candidate = repo_root.join(value).cleanpath
  root_prefix = "#{repo_root.cleanpath}#{File::SEPARATOR}"
  return nil unless candidate.to_s.start_with?(root_prefix)

  candidate
end

def contained_real_file?(repo_root, candidate)
  return false unless candidate.file?

  root = repo_root.realpath.to_s
  resolved = candidate.realpath.to_s
  resolved.start_with?("#{root}#{File::SEPARATOR}")
rescue Errno::ENOENT, Errno::EACCES
  false
end

def https_endpoint?(value)
  return false unless nonempty_string?(value)

  uri = URI.parse(value)
  uri.scheme == "https" && nonempty_string?(uri.host) && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
rescue URI::InvalidURIError
  false
end

def relay_endpoint?(value)
  return false unless nonempty_string?(value)
  return true if https_endpoint?(value)

  match = value.match(/\Aturns:([A-Za-z0-9.-]+)(?::(\d+))?\z/)
  return false unless match

  match[2].nil? || (1..65_535).cover?(match[2].to_i)
end

def validate_status(value, field, failures, blockers)
  case value
  when "pass"
    nil
  when "blocked", "fail"
    block_with(blockers, "#{field} is #{value}")
  else
    fail_with(failures, "#{field} must be pass, blocked, or fail")
  end
end

raw_text = ""
manifest = {}

if !manifest_path.file?
  block_with(blockers, "production evidence manifest is missing: #{manifest_path}")
  schema_checks_required = false
else
  raw_text = manifest_path.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
  fail_with(failures, "forbidden secret marker found in production evidence manifest") if raw_text.match?(FORBIDDEN_MARKERS)
  begin
    manifest = JSON.parse(raw_text)
  rescue JSON::ParserError => e
    fail_with(failures, "production evidence manifest is invalid JSON: #{e.message}")
    manifest = {}
  end
end

if schema_checks_required
  unless manifest.is_a?(Hash)
    fail_with(failures, "production evidence manifest must be a JSON object")
    manifest = {}
  end

  fail_with(failures, "schemaVersion must be 1") unless manifest["schemaVersion"] == 1
  unless manifest["evidenceKind"] == "windowsRendezvousRelayProductionEvidence"
    fail_with(failures, "evidenceKind must be windowsRendezvousRelayProductionEvidence")
  end
  fail_with(failures, "product must be QuantumLink Windows") unless manifest["product"] == "QuantumLink Windows"
  fail_with(failures, "platform must be windows") unless manifest["platform"] == "windows"
  unless manifest["releaseScope"] == "windows-x64-production-release"
    fail_with(failures, "releaseScope must be windows-x64-production-release")
  end

  generated_at = manifest["generatedAt"]
  if !nonempty_string?(generated_at)
    fail_with(failures, "generatedAt is required")
  elsif !generated_at.end_with?("Z")
    fail_with(failures, "generatedAt must be a UTC RFC3339 timestamp ending in Z")
  else
    begin
      Time.iso8601(generated_at)
    rescue ArgumentError
      fail_with(failures, "generatedAt must be a valid RFC3339 timestamp")
    end
  end

  validate_status(manifest["status"], "production evidence status", failures, blockers)

  rendezvous = manifest["rendezvousRelay"]
  rendezvous_failures_start = failures.length
  rendezvous_blockers_start = blockers.length

  if !rendezvous.is_a?(Hash)
    fail_with(failures, "rendezvousRelay section is required")
    rendezvous = {}
  else
    validate_status(rendezvous["status"], "rendezvousRelay.status", failures, blockers)

    rendezvous_endpoints = rendezvous["rendezvousEndpoints"]
    if !rendezvous_endpoints.is_a?(Array) || rendezvous_endpoints.empty?
      fail_with(failures, "rendezvousRelay.rendezvousEndpoints must be a non-empty array")
      rendezvous_endpoints = []
    end
    rendezvous_endpoints.each do |endpoint|
      fail_with(failures, "rendezvous endpoint must be an https URL") unless https_endpoint?(endpoint)
    end

    relay_endpoints = rendezvous["relayEndpoints"]
    if !relay_endpoints.is_a?(Array) || relay_endpoints.empty?
      fail_with(failures, "rendezvousRelay.relayEndpoints must be a non-empty array")
      relay_endpoints = []
    end
    relay_endpoints.each do |endpoint|
      fail_with(failures, "relay endpoint must use turns or https") unless relay_endpoint?(endpoint)
    end

    fail_with(failures, "rendezvousRelay.abuseLogsRedacted must be true") unless rendezvous["abuseLogsRedacted"] == true
    %w[rawPacketPayloadsCommitted rawGamePayloadsCommitted].each do |field|
      fail_with(failures, "rendezvousRelay.#{field} must be false") unless rendezvous[field] == false
    end

    controls = rendezvous["controls"]
    if !controls.is_a?(Array)
      fail_with(failures, "rendezvousRelay.controls must be an array")
      controls = []
    end

    controls_by_name = {}
    controls.each do |entry|
      if !entry.is_a?(Hash)
        fail_with(failures, "rendezvousRelay.controls entries must be objects")
        next
      end

      control_name = entry["control"]
      if !nonempty_string?(control_name)
        fail_with(failures, "rendezvousRelay.controls entry is missing control")
        next
      end
      unless REQUIRED_CONTROLS.include?(control_name)
        fail_with(failures, "unknown rendezvous/relay control: #{control_name}")
        next
      end
      if controls_by_name.key?(control_name)
        fail_with(failures, "duplicate rendezvous/relay control: #{control_name}")
        next
      end
      controls_by_name[control_name] = entry
    end

    REQUIRED_CONTROLS.sort.each do |control|
      entry = controls_by_name[control]
      if entry.nil?
        fail_with(failures, "missing rendezvous/relay control: #{control}")
        next
      end

      validate_status(entry["status"], "rendezvous/relay control #{control} status", failures, blockers)
      evidence = evidence_file(repo_root, entry["evidence"])
      if evidence.nil?
        fail_with(failures, "rendezvous/relay control #{control} evidence must be a relative path")
      elsif !evidence.file?
        block_with(blockers, "rendezvous/relay control #{control} evidence file is missing: #{entry["evidence"]}")
      elsif !contained_real_file?(repo_root, evidence)
        fail_with(failures, "rendezvous/relay control #{control} evidence must resolve inside the repository")
      elsif evidence.size > MAX_EVIDENCE_BYTES
        fail_with(failures, "rendezvous/relay control #{control} evidence exceeds #{MAX_EVIDENCE_BYTES} bytes")
      else
        evidence_text = evidence.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
        if evidence_text.match?(FORBIDDEN_MARKERS)
          fail_with(failures, "forbidden secret marker found in rendezvous/relay control #{control} evidence")
        end
      end
      fail_with(failures, "rendezvous/relay control #{control} must be redacted") unless entry["redacted"] == true
    end
  end
else
  rendezvous_failures_start = failures.length
  rendezvous_blockers_start = blockers.length
end

rendezvous_ready = failures.length == rendezvous_failures_start && blockers.length == rendezvous_blockers_start
ready = failures.empty? && blockers.empty?

report = {
  "valid" => failures.empty?,
  "productionEvidenceReady" => ready,
  "rendezvousRelayReady" => rendezvous_ready,
  "manifest" => manifest_path.to_s,
  "blockers" => blockers,
  "failures" => failures,
  "warnings" => warnings
}

puts JSON.generate(report)

exit_code = if failures.any?
              1
            elsif require_ready && blockers.any?
              1
            else
              0
            end
exit exit_code
