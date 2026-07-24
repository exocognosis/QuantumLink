#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "optparse"
require "pathname"
require "resolv"
require "time"
require "timeout"

MAX_INPUT_BYTES = 1_048_576
SHA256_PATTERN = /\A[0-9a-f]{64}\z/.freeze
COMMIT_SHA_PATTERN = /\A[0-9a-f]{40}\z/.freeze
REF_PATTERN = %r{\Arefs/(?:heads|tags)/[^\s]+\z}.freeze

def abort_with(message)
  warn message
  exit 1
end

def parse_json(path, description)
  abort_with("#{description} is missing: #{path}") unless path.file?
  abort_with("#{description} exceeds #{MAX_INPUT_BYTES} bytes") if path.size > MAX_INPUT_BYTES

  value = JSON.parse(path.read(encoding: "UTF-8"))
  abort_with("#{description} must be a JSON object") unless value.is_a?(Hash)
  value
rescue JSON::ParserError => e
  abort_with("#{description} is invalid JSON: #{e.message}")
end

def true_value?(value)
  value.to_s.casecmp("true").zero?
end

def runner_labels(runner)
  Array(runner["labels"]).each_with_object([]) do |label, labels|
    name = label.is_a?(Hash) ? label["name"] : label
    labels << name if name.is_a?(String) && !name.empty?
  end
end

def expected_head_ref(ref)
  ref.sub(%r{\Arefs/(?:heads|tags)/}, "")
end

def positive_integer?(value)
  value.is_a?(Integer) && value.positive?
end

options = {}
OptionParser.new do |parser|
  parser.banner = "usage: #{$PROGRAM_NAME} [options]"
  parser.on("--config PATH") { |value| options[:config] = Pathname.new(value) }
  parser.on("--runner-inventory PATH") { |value| options[:runner_inventory] = Pathname.new(value) }
  parser.on("--release-run-inventory PATH") { |value| options[:release_run_inventory] = Pathname.new(value) }
  parser.on("--artifact-inventory PATH") { |value| options[:artifact_inventory] = Pathname.new(value) }
  parser.on("--expected-sha SHA") { |value| options[:expected_sha] = value }
  parser.on("--expected-ref REF") { |value| options[:expected_ref] = value }
  parser.on("--actual-sha SHA") { |value| options[:actual_sha] = value }
  parser.on("--actual-ref REF") { |value| options[:actual_ref] = value }
  parser.on("--release-run-id ID") { |value| options[:release_run_id] = value }
  parser.on("--signed-artifact-name NAME") { |value| options[:signed_artifact_name] = value }
  parser.on("--runner-inventory-token-configured VALUE") { |value| options[:runner_inventory_token] = value }
  parser.on("--signing-secrets-configured VALUE") { |value| options[:signing_secrets] = value }
  parser.on("--output PATH") { |value| options[:output] = Pathname.new(value) }
end.parse!

required = %i[
  config runner_inventory release_run_inventory artifact_inventory expected_sha expected_ref
  actual_sha actual_ref release_run_id signed_artifact_name runner_inventory_token
  signing_secrets output
]
missing = required.reject { |key| options.key?(key) }
abort_with("missing required options: #{missing.join(', ')}") unless missing.empty?

config = parse_json(options.fetch(:config), "matrix contract")
runners_response = parse_json(options.fetch(:runner_inventory), "runner inventory")
release_run = parse_json(options.fetch(:release_run_inventory), "release run inventory")
artifacts_response = parse_json(options.fetch(:artifact_inventory), "artifact inventory")
abort_with("matrix contract schemaVersion must be 1") unless config["schemaVersion"] == 1
abort_with("matrix contract evidenceKind is invalid") unless config["evidenceKind"] == "windowsProductionValidationMatrixContract"
lanes = config["lanes"]
abort_with("matrix contract lanes must be a non-empty array") unless lanes.is_a?(Array) && !lanes.empty?
abort_with("maxEvidenceBytes must be a positive integer") unless positive_integer?(config["maxEvidenceBytes"])
abort_with("maxReleaseArtifactBytes must be a positive integer") unless positive_integer?(config["maxReleaseArtifactBytes"])

global_blockers = []
global_blockers << "expected commit SHA is invalid" unless options[:expected_sha].match?(COMMIT_SHA_PATTERN)
global_blockers << "expected ref is invalid" unless options[:expected_ref].match?(REF_PATTERN)
global_blockers << "expected commit does not match the workflow commit" unless options[:expected_sha] == options[:actual_sha]
global_blockers << "expected ref does not match the workflow ref" unless options[:expected_ref] == options[:actual_ref]
global_blockers << "release_run_id must be numeric" unless options[:release_run_id].match?(/\A\d+\z/)
global_blockers << "signed artifact name is missing" if options[:signed_artifact_name].strip.empty?

harness_sha256 = config["externalHarnessSha256"]
global_blockers << "external validation harness SHA-256 is unset or invalid" unless harness_sha256.is_a?(String) && harness_sha256.match?(SHA256_PATTERN)
global_blockers << "dedicated runner inventory token is not configured" unless true_value?(options[:runner_inventory_token])
signing_configured = true_value?(options[:signing_secrets])
global_blockers << "Authenticode signing secret presence is not fully configured" unless signing_configured

dns = Array(config["intendedControlPlaneHosts"]).map do |host|
  addresses = Timeout.timeout(3) { Resolv.getaddresses(host) }.uniq.sort
  { "host" => host, "status" => addresses.empty? ? "blocked" : "resolved", "addressCount" => addresses.length }
rescue Resolv::ResolvError, Timeout::Error
  { "host" => host, "status" => "blocked", "addressCount" => 0 }
end
global_blockers << "intended rendezvous or relay DNS is unresolved" unless dns.all? { |entry| entry["status"] == "resolved" }

runner_inventory_available = runners_response["inventoryAvailable"] == true && runners_response["runners"].is_a?(Array)
online_runners = runner_inventory_available ? runners_response["runners"].select { |runner| runner["status"] == "online" } : []
global_blockers << "self-hosted runner inventory is unavailable" unless runner_inventory_available
global_blockers << "GitHub reports zero online self-hosted runners" if runner_inventory_available && online_runners.empty?

release_run_available = release_run["inventoryAvailable"] == true
global_blockers << "release run metadata is unavailable" unless release_run_available
if release_run_available
  global_blockers << "release run id does not match" unless release_run["id"].to_s == options[:release_run_id]
  global_blockers << "release run head SHA does not match" unless release_run["head_sha"] == options[:expected_sha]
  global_blockers << "release run head ref does not match" unless release_run["head_branch"] == expected_head_ref(options[:expected_ref])
  global_blockers << "release run is not completed successfully" unless release_run["status"] == "completed" && release_run["conclusion"] == "success"
end

artifact_inventory_available = artifacts_response["inventoryAvailable"] == true && artifacts_response["artifacts"].is_a?(Array)
release_artifacts = if artifact_inventory_available
                      artifacts_response["artifacts"].select do |artifact|
                        artifact["name"] == options[:signed_artifact_name] && artifact["expired"] != true
                      end
                    else
                      []
                    end
release_artifact = release_artifacts.length == 1 ? release_artifacts.first : nil
global_blockers << "release artifact inventory is unavailable" unless artifact_inventory_available
global_blockers << "the named signed release artifact is missing, duplicated, or expired" if artifact_inventory_available && release_artifact.nil?
if release_artifact
  size = release_artifact["size_in_bytes"]
  global_blockers << "release artifact size is missing, zero, or exceeds the contract cap" unless positive_integer?(size) && size <= config["maxReleaseArtifactBytes"]
  artifact_run = release_artifact["workflow_run"]
  unless artifact_run.is_a?(Hash) && artifact_run["id"].to_s == options[:release_run_id] &&
         artifact_run["head_sha"] == options[:expected_sha] &&
         artifact_run["head_branch"] == expected_head_ref(options[:expected_ref])
    global_blockers << "release artifact workflow metadata does not match the requested run"
  end
end

base_runner_labels = Array(config["requiredRunnerLabels"])
global_blockers << "required runner labels must include the pinned harness label" unless base_runner_labels.include?("quantumlink-validation-harness-v1")
planned_lanes = lanes.map do |lane|
  required_labels = (base_runner_labels + Array(lane["labels"]) + Array(lane["prerequisiteLabels"])).uniq
  topology_labels = Array(lane["prerequisiteLabels"])
  blockers = global_blockers.dup
  blockers << "lane topology prerequisite labels are missing" if topology_labels.empty?
  matching_runner = online_runners.find { |runner| (required_labels - runner_labels(runner)).empty? }
  blockers << "no online self-hosted runner has every harness and topology label" unless matching_runner
  {
    "id" => lane["id"],
    "displayName" => lane["displayName"],
    "status" => blockers.empty? ? "scheduled" : "blocked",
    "labels" => required_labels,
    "timeoutMinutes" => lane["timeoutMinutes"],
    "artifactName" => "#{config['artifactNamePrefix']}-#{lane['id']}",
    "blockers" => blockers.uniq
  }
end

scheduled = planned_lanes.select { |lane| lane["status"] == "scheduled" }
plan = {
  "schemaVersion" => 1,
  "evidenceKind" => "windowsProductionValidationMatrixPlan",
  "generatedAt" => Time.now.utc.iso8601,
  "status" => scheduled.empty? ? "blocked" : "scheduled",
  "release" => {
    "expectedCommitSha" => options[:expected_sha],
    "actualCommitSha" => options[:actual_sha],
    "expectedRef" => options[:expected_ref],
    "actualRef" => options[:actual_ref],
    "releaseRunId" => options[:release_run_id],
    "releaseRunMetadataMatch" => release_run_available && !global_blockers.any? { |entry| entry.start_with?("release run") },
    "signedArtifactName" => options[:signed_artifact_name],
    "artifactInventoryMatch" => !release_artifact.nil?,
    "artifactSizeBytes" => release_artifact && release_artifact["size_in_bytes"],
    "maxArtifactSizeBytes" => config["maxReleaseArtifactBytes"]
  },
  "prerequisites" => {
    "signingSecretPresenceConfigured" => signing_configured,
    "runnerInventoryTokenConfigured" => true_value?(options[:runner_inventory_token]),
    "externalHarnessSha256" => harness_sha256,
    "controlPlaneDns" => dns,
    "runnerInventoryAvailable" => runner_inventory_available,
    "onlineSelfHostedRunnerCount" => online_runners.length,
    "releaseRunInventoryAvailable" => release_run_available,
    "artifactInventoryAvailable" => artifact_inventory_available
  },
  "lastAuditedPrerequisites" => config["lastAuditedPrerequisites"],
  "scheduledCount" => scheduled.length,
  "blockedCount" => planned_lanes.length - scheduled.length,
  "lanes" => planned_lanes
}

options.fetch(:output).dirname.mkpath
text = "#{JSON.pretty_generate(plan)}\n"
abort_with("matrix plan exceeds #{config['maxEvidenceBytes']} bytes") if text.bytesize > config["maxEvidenceBytes"]
options.fetch(:output).write(text, encoding: "UTF-8")
puts JSON.generate({ "scheduledCount" => scheduled.length, "status" => plan["status"] })
