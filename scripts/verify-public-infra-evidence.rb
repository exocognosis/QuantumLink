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
  warn "usage: #{$PROGRAM_NAME} [--require-public] [--require-turn-relay] [--expected-sha SHA] [--max-age-seconds N] [--report PATH] EVIDENCE_JSON"
  exit 2
end

def nonempty_string?(value)
  value.is_a?(String) && !value.strip.empty?
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

def boolean_true?(value)
  value == true
end

def positive_integer?(value)
  value.is_a?(Integer) && value.positive?
end

def nonnegative_integer?(value)
  value.is_a?(Integer) && value >= 0
end

def includes_candidate?(value, candidate)
  return false unless nonempty_string?(value)

  value.split(",").map(&:strip).include?(candidate)
end

def require_field(condition, message, failures)
  failures << message unless condition
end

def block_unless(condition, message, blockers)
  blockers << message unless condition
end

require_public = false
require_turn_relay = false
expected_sha = nil
report_path = nil
max_age_seconds = MAX_EVIDENCE_AGE_SECONDS
args = ARGV.dup

until args.empty?
  case args.first
  when "--require-public"
    require_public = true
    args.shift
  when "--require-turn-relay"
    require_turn_relay = true
    args.shift
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

evidence_path = Pathname.new(args.first).expand_path
failures = []
blockers = []
warnings = []
evidence = {}
raw_text = ""
now = Time.now.utc

if !evidence_path.file?
  failures << "public infra evidence file is missing: #{args.first}"
else
  raw_text = evidence_path.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
  failures << "forbidden secret marker found in public infra evidence" if raw_text.match?(FORBIDDEN_MARKERS)
  begin
    evidence = JSON.parse(raw_text)
  rescue JSON::ParserError => e
    failures << "public infra evidence is invalid JSON: #{e.message}"
  end
end

unless evidence.is_a?(Hash)
  failures << "public infra evidence must be a JSON object"
  evidence = {}
end

parse_timestamp(evidence["generated_at"], "generated_at", failures, now, max_age_seconds)

if expected_sha
  require_field(evidence["git_sha"] == expected_sha, "git_sha does not match expected commit", failures)
elsif !nonempty_string?(evidence["git_sha"])
  failures << "git_sha is required"
end

mode = evidence["mode"]
if require_public
  block_unless(mode == "public", "mode must be public for deployable evidence", blockers)
elsif !%w[local public].include?(mode)
  failures << "mode must be local or public"
end

%w[rendezvous relay stun].each do |field|
  require_field(nonempty_string?(evidence[field]), "#{field} endpoint is required", failures)
end

if require_public
  block_unless(public_endpoint?(evidence["rendezvous"], tls_required: true), "rendezvous must be a public tls://host:port endpoint", blockers)
  block_unless(public_endpoint?(evidence["relay"], tls_required: true), "relay must be a public tls://host:port endpoint", blockers)
  block_unless(public_endpoint?(evidence["stun"]), "stun must be a public host:port endpoint", blockers)
  block_unless(public_endpoint?(evidence["turn"]), "turn must be a public host:port endpoint", blockers)
  block_unless(boolean_true?(evidence["control_tls_ca_configured"]), "control TLS CA must be configured", blockers)
  block_unless(boolean_true?(evidence["rendezvous_tls_enabled"]), "rendezvous TLS must be enabled", blockers)
  block_unless(boolean_true?(evidence["relay_tls_enabled"]), "relay TLS must be enabled", blockers)
  block_unless(boolean_true?(evidence["rendezvous_auth_required"]), "rendezvous auth must be required", blockers)
  block_unless(boolean_true?(evidence["relay_auth_required"]), "relay auth must be required", blockers)
  block_unless(boolean_true?(evidence["rendezvous_auth_verified"]), "rendezvous negative auth proof must pass", blockers)
  block_unless(boolean_true?(evidence["relay_auth_verified"]), "relay negative auth proof must pass", blockers)
  block_unless(positive_integer?(evidence["rendezvous_rate_limit_per_window"]), "rendezvous rate limit must be enabled", blockers)
  block_unless(positive_integer?(evidence["relay_rate_limit_per_window"]), "relay rate limit must be enabled", blockers)
  block_unless(positive_integer?(evidence["admission_rate_limit_window_seconds"]), "admission rate-limit window must be positive", blockers)
  block_unless(boolean_true?(evidence["rendezvous_metrics_scraped"]), "rendezvous metrics scrape must pass", blockers)
  block_unless(boolean_true?(evidence["relay_metrics_scraped"]), "relay metrics scrape must pass", blockers)
  block_unless(positive_integer?(evidence["rendezvous_auth_failures_total"]), "rendezvous auth failures must be visible in metrics", blockers)
  block_unless(positive_integer?(evidence["relay_auth_failures_total"]), "relay auth failures must be visible in metrics", blockers)
  block_unless(positive_integer?(evidence["rendezvous_requests_succeeded_total"]), "rendezvous successful requests must be visible in metrics", blockers)
  block_unless(boolean_true?(evidence["bounds_verified"]), "request bounds proof must pass", blockers)
  block_unless(boolean_true?(evidence["relay_payload_limit_verified"]), "relay payload limit proof must pass", blockers)
  block_unless(positive_integer?(evidence["max_request_line_bytes"]), "request line limit must be configured", blockers)
  block_unless(positive_integer?(evidence["max_concurrent_connections"]), "connection limit must be configured", blockers)
  block_unless(positive_integer?(evidence["idle_timeout_seconds"]), "idle timeout must be configured", blockers)
  block_unless(positive_integer?(evidence["relay_max_payload_bytes"]), "relay payload limit must be configured", blockers)
  block_unless(positive_integer?(evidence["relay_max_peer_id_bytes"]), "relay peer ID limit must be configured", blockers)
  block_unless(positive_integer?(evidence["relay_max_registered_peers"]), "relay registered-peer limit must be configured", blockers)
  block_unless(positive_integer?(evidence["rendezvous_request_too_large_total"]), "rendezvous oversized requests must be visible in metrics", blockers)
  block_unless(positive_integer?(evidence["relay_request_too_large_total"]), "relay oversized requests must be visible in metrics", blockers)
  block_unless(positive_integer?(evidence["relay_payload_too_large_total"]), "relay payload quota rejections must be visible in metrics", blockers)
end

%w[stun_reflexive published_candidate_types selected_path].each do |field|
  require_field(nonempty_string?(evidence[field]), "#{field} is required", failures)
end
require_field(positive_integer?(evidence["frames_sent"]), "frames_sent must be a positive integer", failures)
require_field(evidence["total_elapsed_ms"].is_a?(Integer) && evidence["total_elapsed_ms"] >= 0, "total_elapsed_ms must be a non-negative integer", failures)
require_field(positive_integer?(evidence["direct_probe_timeout_ms"]), "direct_probe_timeout_ms must be a positive integer", failures)
%w[
  rendezvous_auth_failures_total
  relay_auth_failures_total
  rendezvous_requests_succeeded_total
  relay_forwarded_datagrams_total
  relay_unknown_destination_drops_total
  rendezvous_request_too_large_total
  relay_request_too_large_total
  relay_payload_too_large_total
  relay_duplicate_registration_rejections_total
].each do |field|
  require_field(nonnegative_integer?(evidence[field]), "#{field} must be a non-negative integer", failures)
end
%w[
  max_request_line_bytes
  max_concurrent_connections
  idle_timeout_seconds
  relay_max_payload_bytes
  relay_max_peer_id_bytes
  relay_max_registered_peers
].each do |field|
  require_field(positive_integer?(evidence[field]), "#{field} must be a positive integer", failures)
end

turn_relay_mode = require_turn_relay || evidence["prove_turn_relay"] == true
if turn_relay_mode
  block_unless(evidence["prove_turn_relay"] == true, "prove_turn_relay must be true for TURN relay evidence", blockers)
  block_unless(nonempty_string?(evidence["turn_responder_relayed"]), "turn_responder_relayed must be present", blockers)
  block_unless(includes_candidate?(evidence["published_candidate_types"], "Relay"), "published candidates must include Relay", blockers)
  block_unless(evidence["selected_path"] == "turn-relay", "selected_path must be turn-relay", blockers)
else
  block_unless(includes_candidate?(evidence["published_candidate_types"], "ServerReflexive"), "published candidates must include ServerReflexive", blockers)
  block_unless(includes_candidate?(evidence["published_candidate_types"], "QuantumLinkRelay"), "published candidates must include QuantumLinkRelay", blockers)
  block_unless(evidence["selected_path"] == "relay", "selected_path must be relay", blockers)
  if require_public
    block_unless(
      positive_integer?(evidence["relay_forwarded_datagrams_total"]) &&
        positive_integer?(evidence["frames_sent"]) &&
        evidence["relay_forwarded_datagrams_total"] >= evidence["frames_sent"],
      "relay forwarded datagrams must be visible in metrics",
      blockers
    )
  end
end

if require_public
  block_unless(nonempty_string?(evidence["turn_relayed"]) || turn_relay_mode, "turn_relayed must be present for public app-relay evidence", blockers)
  if nonempty_string?(evidence["turn"])
    block_unless(includes_candidate?(evidence["published_candidate_types"], "Relay") || turn_relay_mode, "published candidates must include TURN Relay when TURN is configured", blockers)
  end
end

report = {
  "evidenceKind" => "quantumLinkPublicInfraEvidenceVerification",
  "verifiedAt" => now.iso8601,
  "evidencePath" => evidence_path.to_s,
  "expectedGitSha" => expected_sha,
  "mode" => mode,
  "requirePublic" => require_public,
  "requireTurnRelay" => require_turn_relay,
  "valid" => failures.empty?,
  "publicInfraReady" => failures.empty? && blockers.empty? && (!require_public || mode == "public"),
  "selectedPath" => evidence["selected_path"],
  "framesSent" => evidence["frames_sent"],
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
exit(report["publicInfraReady"] ? 0 : 1)
