#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "open3"
require "optparse"
require "pathname"
require "resolv"
require "time"
require "timeout"

REQUIRED_SECRETS = %w[
  WINDOWS_RUNNER_INVENTORY_TOKEN
  WINDOWS_SIGNING_CERT_PFX_BASE64
  WINDOWS_SIGNING_CERT_PASSWORD
  WINDOWS_SIGNING_TIMESTAMP_URL
].freeze
REQUIRED_VARIABLES = {
  "WINTUN_DOWNLOAD_URL" => /\Ahttps:\/\/\S+\z/,
  "WINTUN_SHA256" => /\A[0-9a-f]{64}\z/
}.freeze
REQUIRED_RUNNER_LABELS = %w[
  self-hosted
  windows
  x64
  quantumlink-validation-harness-v1
].freeze
DEFAULT_OUTPUT = "windows/build/validation/windows-production-prerequisites-audit.json"
DEFAULT_CONTRACT = "windows/validation/contracts/windows-production-validation-matrix.json"
MAX_INPUT_BYTES = 1_048_576

def abort_with(message)
  warn message
  exit 1
end

def parse_json_file(path, description)
  abort_with("#{description} is missing: #{path}") unless path.file?
  abort_with("#{description} exceeds #{MAX_INPUT_BYTES} bytes") if path.size > MAX_INPUT_BYTES

  value = JSON.parse(path.read(encoding: "UTF-8"))
  abort_with("#{description} must be a JSON object") unless value.is_a?(Hash)
  value
rescue JSON::ParserError => e
  abort_with("#{description} is invalid JSON: #{e.message}")
end

def run_command(*args)
  stdout, stderr, status = Open3.capture3(*args)
  [status.success?, stdout, stderr]
end

def repo_relative_path?(value)
  return false unless value.is_a?(String) && !value.strip.empty?
  return false if value.include?("\\") || value.match?(/\A[A-Za-z]:/) || value.start_with?("//")

  path = Pathname.new(value)
  !path.absolute? && !path.each_filename.any? { |part| %w[. ..].include?(part) }
end

def repo_path(repo_root, value, field)
  abort_with("#{field} must be a repo-relative path") unless repo_relative_path?(value)

  path = repo_root.join(value).cleanpath
  prefix = "#{repo_root.cleanpath}#{File::SEPARATOR}"
  abort_with("#{field} must resolve inside the repository") unless path.to_s.start_with?(prefix)
  path
end

def labels_for(runner)
  Array(runner["labels"]).map do |label|
    label.is_a?(Hash) ? label["name"] : label
  end.compact
end

def normalize_secret_inventory(value)
  names = if value["secrets"].is_a?(Array)
            value["secrets"].map { |entry| entry.is_a?(Hash) ? entry["name"] : entry }
          elsif value["names"].is_a?(Array)
            value["names"]
          else
            []
          end
  { "inventoryAvailable" => value["inventoryAvailable"] == true, "names" => names.compact.map(&:to_s) }
end

def normalize_variable_inventory(value)
  variables = {}
  if value["variables"].is_a?(Array)
    value["variables"].each do |entry|
      next unless entry.is_a?(Hash)

      variables[entry["name"].to_s] = entry["value"].to_s
    end
  elsif value["values"].is_a?(Hash)
    variables = value["values"].transform_keys(&:to_s).transform_values(&:to_s)
  end
  { "inventoryAvailable" => value["inventoryAvailable"] == true, "values" => variables }
end

def live_runners(repo)
  ok, stdout, stderr = run_command("gh", "api", "repos/#{repo}/actions/runners?per_page=100")
  return { "inventoryAvailable" => false, "runners" => [], "error" => stderr.strip } unless ok

  parse = JSON.parse(stdout)
  { "inventoryAvailable" => true, "runners" => Array(parse["runners"]) }
rescue JSON::ParserError => e
  { "inventoryAvailable" => false, "runners" => [], "error" => e.message }
end

def live_secrets(repo)
  ok, stdout, stderr = run_command("gh", "secret", "list", "--repo", repo)
  return { "inventoryAvailable" => false, "names" => [], "error" => stderr.strip } unless ok

  names = stdout.lines.map { |line| line.split(/\s+/).first }.compact.reject(&:empty?)
  { "inventoryAvailable" => true, "names" => names }
end

def live_variables(repo)
  ok, stdout, stderr = run_command("gh", "variable", "list", "--repo", repo)
  return { "inventoryAvailable" => false, "values" => {}, "error" => stderr.strip } unless ok

  values = stdout.lines.each_with_object({}) do |line, result|
    parts = line.split(/\s+/, 3)
    result[parts[0]] = parts[1] if parts.length >= 2
  end
  { "inventoryAvailable" => true, "values" => values }
end

def live_dns(hosts)
  hosts.map do |host|
    addresses = Timeout.timeout(3) { Resolv.getaddresses(host) }.uniq.sort
    { "host" => host, "status" => addresses.empty? ? "blocked" : "resolved", "addressCount" => addresses.length }
  rescue Resolv::ResolvError, Timeout::Error
    { "host" => host, "status" => "blocked", "addressCount" => 0 }
  end
end

def prerequisite(id, status, reason, evidence = {})
  {
    "id" => id,
    "status" => status,
    "reason" => reason,
    "evidence" => evidence
  }
end

options = {
  repo_root: Pathname.new(__dir__).join("../..").expand_path,
  repo: ENV.fetch("GITHUB_REPOSITORY", "exocognosis/QuantumLink"),
  contract: DEFAULT_CONTRACT,
  output: DEFAULT_OUTPUT,
  require_ready: false
}
OptionParser.new do |parser|
  parser.banner = "usage: #{$PROGRAM_NAME} [options]"
  parser.on("--repo-root PATH") { |value| options[:repo_root] = Pathname.new(value).expand_path }
  parser.on("--repo NAME") { |value| options[:repo] = value }
  parser.on("--contract PATH") { |value| options[:contract] = value }
  parser.on("--output PATH") { |value| options[:output] = value }
  parser.on("--runner-inventory PATH") { |value| options[:runner_inventory] = value }
  parser.on("--secret-inventory PATH") { |value| options[:secret_inventory] = value }
  parser.on("--variable-inventory PATH") { |value| options[:variable_inventory] = value }
  parser.on("--dns-inventory PATH") { |value| options[:dns_inventory] = value }
  parser.on("--require-ready") { options[:require_ready] = true }
end.parse!

repo_root = options.fetch(:repo_root)
contract_path = repo_path(repo_root, options.fetch(:contract), "contract")
output_path = repo_path(repo_root, options.fetch(:output), "output")
contract = parse_json_file(contract_path, "Windows production validation contract")
hosts = Array(contract["intendedControlPlaneHosts"])
abort_with("contract intendedControlPlaneHosts must be a non-empty array") if hosts.empty?

runners = if options[:runner_inventory]
            parse_json_file(repo_path(repo_root, options[:runner_inventory], "runner inventory"), "runner inventory")
          else
            live_runners(options.fetch(:repo))
          end
secrets = if options[:secret_inventory]
            normalize_secret_inventory(parse_json_file(repo_path(repo_root, options[:secret_inventory], "secret inventory"), "secret inventory"))
          else
            normalize_secret_inventory(live_secrets(options.fetch(:repo)))
          end
variables = if options[:variable_inventory]
              normalize_variable_inventory(parse_json_file(repo_path(repo_root, options[:variable_inventory], "variable inventory"), "variable inventory"))
            else
              normalize_variable_inventory(live_variables(options.fetch(:repo)))
            end
dns = if options[:dns_inventory]
        parse_json_file(repo_path(repo_root, options[:dns_inventory], "DNS inventory"), "DNS inventory").fetch("hosts")
      else
        live_dns(hosts)
      end

runner_inventory_available = runners["inventoryAvailable"] == true && runners["runners"].is_a?(Array)
online_runners = runner_inventory_available ? runners["runners"].select { |runner| runner["status"] == "online" } : []
matching_runner_count = online_runners.count { |runner| (REQUIRED_RUNNER_LABELS - labels_for(runner)).empty? }

secret_names = secrets.fetch("names")
missing_secrets = REQUIRED_SECRETS - secret_names
variable_values = variables.fetch("values")
missing_or_invalid_variables = REQUIRED_VARIABLES.each_with_object([]) do |(name, pattern), result|
  value = variable_values[name]
  result << name unless value.is_a?(String) && value.match?(pattern)
end
unresolved_hosts = Array(dns).select { |entry| entry["status"] != "resolved" }.map { |entry| entry["host"] }

prerequisites = []
prerequisites << if runner_inventory_available && matching_runner_count.positive?
                   prerequisite("self_hosted_validation_runners", "pass", "At least one online runner has the required Windows validation harness labels.", {
                     "onlineRunnerCount" => online_runners.length,
                     "matchingRunnerCount" => matching_runner_count,
                     "requiredLabels" => REQUIRED_RUNNER_LABELS
                   })
                 else
                   reason = runner_inventory_available ? "No online runner has all required Windows validation harness labels." : "GitHub runner inventory is unavailable."
                   prerequisite("self_hosted_validation_runners", "blocked", reason, {
                     "onlineRunnerCount" => online_runners.length,
                     "matchingRunnerCount" => matching_runner_count,
                     "requiredLabels" => REQUIRED_RUNNER_LABELS
                   })
                 end
prerequisites << if secrets["inventoryAvailable"] && missing_secrets.empty?
                   prerequisite("release_and_matrix_secrets", "pass", "Required production release and validation secrets are configured by name.", {
                     "requiredSecretNames" => REQUIRED_SECRETS
                   })
                 else
                   reason = secrets["inventoryAvailable"] ? "Required production secrets are missing." : "GitHub secret inventory is unavailable."
                   prerequisite("release_and_matrix_secrets", "blocked", reason, {
                     "missingSecretNames" => missing_secrets,
                     "requiredSecretNames" => REQUIRED_SECRETS
                   })
                 end
prerequisites << if variables["inventoryAvailable"] && missing_or_invalid_variables.empty?
                   prerequisite("wintun_release_variables", "pass", "Pinned Wintun download URL and SHA-256 variables are configured.", {
                     "requiredVariableNames" => REQUIRED_VARIABLES.keys
                   })
                 else
                   reason = variables["inventoryAvailable"] ? "Required Wintun variables are missing or malformed." : "GitHub variable inventory is unavailable."
                   prerequisite("wintun_release_variables", "blocked", reason, {
                     "missingOrInvalidVariableNames" => missing_or_invalid_variables,
                     "requiredVariableNames" => REQUIRED_VARIABLES.keys
                   })
                 end
prerequisites << if unresolved_hosts.empty?
                   prerequisite("control_plane_dns", "pass", "All intended rendezvous and relay hosts resolve.", {
                     "hosts" => dns
                   })
                 else
                   prerequisite("control_plane_dns", "blocked", "One or more intended rendezvous or relay hosts do not resolve.", {
                     "unresolvedHosts" => unresolved_hosts,
                     "hosts" => dns
                   })
                 end

status = prerequisites.all? { |entry| entry["status"] == "pass" } ? "pass" : "blocked"
report = {
  "schemaVersion" => 1,
  "evidenceKind" => "windowsProductionPrerequisitesAudit",
  "generatedAt" => Time.now.utc.iso8601,
  "repo" => options.fetch(:repo),
  "status" => status,
  "contract" => options.fetch(:contract),
  "prerequisites" => prerequisites
}
output_path.dirname.mkpath
output_path.write("#{JSON.pretty_generate(report)}\n", encoding: "UTF-8")
puts JSON.generate({ "status" => status, "output" => output_path.relative_path_from(repo_root).to_s })
exit(options[:require_ready] && status != "pass" ? 1 : 0)
