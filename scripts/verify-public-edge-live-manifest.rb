#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "ipaddr"
require "json"
require "pathname"
require "time"

MAX_EVIDENCE_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
RESERVED_DOMAINS = %w[example.com example.net example.org].freeze
RESERVED_SUFFIXES = %w[.example .invalid .localhost .test].freeze
RESERVED_NETS = %w[
  0.0.0.0/8
  10.0.0.0/8
  100.64.0.0/10
  127.0.0.0/8
  169.254.0.0/16
  172.16.0.0/12
  192.0.0.0/24
  192.0.2.0/24
  192.168.0.0/16
  198.18.0.0/15
  198.51.100.0/24
  203.0.113.0/24
  2001:db8::/32
  224.0.0.0/4
  ::/128
  ::1/128
  fc00::/7
  fe80::/10
].map { |cidr| IPAddr.new(cidr) }.freeze

FORBIDDEN_MARKERS = /
  BEGIN\ (?:RSA\ |EC\ |OPENSSH\ )?PRIVATE\ KEY|
  WALLET_SEED|
  ENTITLEMENT_TOKEN|
  DYTALLIX_WALLET_SECRET|
  QLINK_PRODUCTION_ENDPOINT_SECRET|
  local-edge-secret|
  replace-with-
/ix.freeze

def usage
  warn "usage: #{$PROGRAM_NAME} [--expected-sha SHA] [--max-age-seconds N] [--report PATH] MANIFEST_JSON"
  exit 2
end

def nonempty_string?(value)
  value.is_a?(String) && !value.strip.empty?
end

def boolean_true?(value)
  value == true
end

def positive_integer?(value)
  value.is_a?(Integer) && value.positive?
end

def parse_timestamp(value, field, failures, now, max_age_seconds)
  unless nonempty_string?(value) && value.end_with?("Z")
    failures << "#{field} must be a UTC RFC3339 timestamp ending in Z"
    return
  end

  parsed = Time.iso8601(value)
  failures << "#{field} is more than #{MAX_FUTURE_SKEW_SECONDS} seconds in the future" if parsed > now + MAX_FUTURE_SKEW_SECONDS
  failures << "#{field} is older than #{max_age_seconds} seconds" if parsed < now - max_age_seconds
rescue ArgumentError
  failures << "#{field} must be a valid RFC3339 timestamp"
end

def endpoint_parts(value)
  return nil unless nonempty_string?(value)

  stripped = value.sub(/\A(?:tcp|tls):\/\//, "")
  if stripped.start_with?("[")
    host, rest = stripped[1..].split("]", 2)
    return nil unless rest&.start_with?(":")

    port = rest[1..]
  else
    separator = stripped.rindex(":")
    return nil unless separator

    host = stripped[0...separator]
    port = stripped[(separator + 1)..]
  end
  return nil unless nonempty_string?(host) && port.to_s.match?(/\A\d+\z/)

  port = port.to_i
  return nil unless (1..65_535).cover?(port)

  [host.downcase, port]
end

def production_host?(host)
  return false unless nonempty_string?(host)

  normalized = host.downcase.chomp(".").delete_prefix("[").delete_suffix("]")
  return false if normalized == "localhost"
  return false if RESERVED_SUFFIXES.any? { |suffix| normalized.end_with?(suffix) }
  return false if RESERVED_DOMAINS.any? { |domain| normalized == domain || normalized.end_with?(".#{domain}") }

  begin
    address = IPAddr.new(normalized)
    return RESERVED_NETS.none? { |network| network.include?(address) }
  rescue IPAddr::InvalidAddressError
    nil
  end

  normalized.match?(/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/)
end

def public_endpoint?(value, tls_required: false)
  return false unless nonempty_string?(value)
  return false if tls_required && !value.start_with?("tls://")

  parts = endpoint_parts(value)
  parts && production_host?(parts.first)
end

def fetch_hash(parent, field, failures)
  value = parent[field]
  unless value.is_a?(Hash)
    failures << "#{field} must be an object"
    return {}
  end
  value
end

expected_sha = nil
report_path = nil
max_age_seconds = MAX_EVIDENCE_AGE_SECONDS
args = ARGV.dup

until args.empty?
  case args.first
  when "--expected-sha"
    args.shift
    usage if args.empty?
    expected_sha = args.shift
  when "--max-age-seconds"
    args.shift
    usage if args.empty?
    max_age_seconds = Integer(args.shift, 10)
    usage unless max_age_seconds.positive?
  when "--report"
    args.shift
    usage if args.empty?
    report_path = args.shift
  else
    break
  end
end
usage unless args.length == 1

manifest_path = Pathname.new(args.first).expand_path
failures = []
blockers = []
warnings = []
manifest = {}
now = Time.now.utc

if !manifest_path.file?
  failures << "public edge live manifest is missing: #{args.first}"
else
  raw_text = manifest_path.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
  failures << "forbidden secret marker found in public edge live manifest" if raw_text.match?(FORBIDDEN_MARKERS)
  begin
    manifest = JSON.parse(raw_text)
  rescue JSON::ParserError => e
    failures << "public edge live manifest is invalid JSON: #{e.message}"
  end
end

unless manifest.is_a?(Hash)
  failures << "public edge live manifest must be a JSON object"
  manifest = {}
end

parse_timestamp(manifest["generatedAt"], "generatedAt", failures, now, max_age_seconds)

failures << "schemaVersion must be 1" unless manifest["schemaVersion"] == 1
failures << "evidenceKind must be quantumLinkPublicEdgeLiveEvidence" unless manifest["evidenceKind"] == "quantumLinkPublicEdgeLiveEvidence"
if expected_sha
  failures << "gitSha does not match expected commit" unless manifest["gitSha"] == expected_sha
elsif !nonempty_string?(manifest["gitSha"])
  failures << "gitSha is required"
end

blockers << "mode must be public" unless manifest["mode"] == "public"
blockers << "status must be pass" unless manifest["status"] == "pass"

endpoints = fetch_hash(manifest, "endpoints", failures)
blockers << "rendezvous endpoint must be public tls://host:port" unless public_endpoint?(endpoints["rendezvous"], tls_required: true)
blockers << "relay endpoint must be public tls://host:port" unless public_endpoint?(endpoints["relay"], tls_required: true)
blockers << "stun endpoint must be public host:port" unless public_endpoint?(endpoints["stun"])
blockers << "turn endpoint must be public host:port" unless public_endpoint?(endpoints["turn"])

credential_sources = fetch_hash(manifest, "credentialSources", failures)
%w[controlTlsCa rendezvousAuth relayAuth rendezvousRevokedTokenDigests relayRevokedTokenDigests turnPassword].each do |field|
  failures << "credentialSources.#{field} is required" unless nonempty_string?(credential_sources[field])
end
if %w[rendezvousAuth relayAuth turnPassword].any? { |field| credential_sources[field] == "command-line" }
  blockers << "credential sources must not be command-line arguments"
end

proofs = fetch_hash(manifest, "proofs", failures)
revocation = fetch_hash(proofs, "serviceTokenRevocation", failures)
blockers << "service-token revocation app-relay proof must pass" unless boolean_true?(revocation["appRelayVerified"])
blockers << "service-token revocation TURN-relay proof must pass" unless boolean_true?(revocation["turnRelayVerified"])
blockers << "rendezvous revoked-token proof must reject old token" unless boolean_true?(revocation["rendezvousRevokedTokenRejected"])
blockers << "relay revoked-token proof must reject old token" unless boolean_true?(revocation["relayRevokedTokenRejected"])
blockers << "rendezvous replacement-token proof must pass" unless boolean_true?(revocation["rendezvousReplacementTokenAccepted"])
blockers << "relay replacement-token proof must pass" unless boolean_true?(revocation["relayReplacementTokenAccepted"])
blockers << "rendezvous auth revocations must be visible in metrics" unless positive_integer?(revocation["rendezvousAuthRevocationsTotal"])
blockers << "relay auth revocations must be visible in metrics" unless positive_integer?(revocation["relayAuthRevocationsTotal"])
blockers << "revocation list digest must be recorded" unless nonempty_string?(revocation["revocationListSha256"]) && revocation["revocationListSha256"] != ":"

rollback = fetch_hash(proofs, "incidentRollback", failures)
blockers << "incident rollback proof must pass" unless boolean_true?(rollback["verified"])
%w[incidentId rollbackFromReleaseId rollbackToReleaseId rollbackManifestSha256].each do |field|
  blockers << "incident rollback #{field} must be recorded" unless nonempty_string?(rollback[field])
end
blockers << "incident rollback duration must be positive" unless positive_integer?(rollback["rollbackDurationSeconds"])
blockers << "post-rollback public infra proof must pass" unless boolean_true?(rollback["postRollbackPublicInfraReady"])

app_relay = fetch_hash(proofs, "appRelay", failures)
blockers << "app-relay public proof must pass" unless boolean_true?(app_relay["publicInfraReady"])
blockers << "app-relay selected path must be relay" unless app_relay["selectedPath"] == "relay"
blockers << "app-relay frames must be positive" unless positive_integer?(app_relay["framesSent"])

turn_relay = fetch_hash(proofs, "turnRelay", failures)
blockers << "TURN-relay public proof must pass" unless boolean_true?(turn_relay["publicInfraReady"])
blockers << "TURN-relay selected path must be turn-relay" unless turn_relay["selectedPath"] == "turn-relay"
blockers << "TURN-relay frames must be positive" unless positive_integer?(turn_relay["framesSent"])

report = {
  "evidenceKind" => "quantumLinkPublicEdgeLiveManifestVerification",
  "verifiedAt" => now.iso8601,
  "manifestPath" => manifest_path.to_s,
  "expectedGitSha" => expected_sha,
  "valid" => failures.empty?,
  "liveEvidenceReady" => failures.empty? && blockers.empty?,
  "status" => manifest["status"],
  "failures" => failures,
  "blockers" => blockers,
  "warnings" => warnings
}

if report_path
  destination = Pathname.new(report_path).expand_path
  FileUtils.mkdir_p(destination.dirname)
  destination.write("#{JSON.pretty_generate(report)}\n", encoding: "UTF-8")
end

puts JSON.pretty_generate(report)
exit(report["liveEvidenceReady"] ? 0 : 1)
