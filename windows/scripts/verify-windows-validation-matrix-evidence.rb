#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require "optparse"
require "pathname"
require "time"

SHA256_PATTERN = /\A[0-9a-f]{64}\z/.freeze
FORBIDDEN_MARKERS = /
  placeholder|synthetic|contract[_ -]?only|BEGIN\ (?:RSA\ |EC\ |OPENSSH\ )?PRIVATE\ KEY|
  ENTITLEMENT_TOKEN|WINDOWS_RELEASE_PRIVATE_KEY|\.pcapng?\b
/ix.freeze
FORBIDDEN_KEYS = %w[
  password accessToken refreshToken privateKey seed seedPhrase secret secretValue
  environment processEnvironment endpointSecret signingCertificatePfx
].map(&:downcase).freeze
MAX_AGE_SECONDS = 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60

def abort_with(message)
  warn message
  exit 2
end

def safe_relative_path?(value)
  return false unless value.is_a?(String) && !value.empty?
  return false if value.include?("\\") || value.match?(/\A[A-Za-z]:/) || value.start_with?("/") || value.start_with?("//")

  parts = value.split("/", -1)
  parts.none? { |part| part.empty? || part == "." || part == ".." }
end

def forbidden_key?(value)
  case value
  when Hash
    value.any? { |key, child| FORBIDDEN_KEYS.include?(key.to_s.downcase) || forbidden_key?(child) }
  when Array
    value.any? { |child| forbidden_key?(child) }
  else
    false
  end
end

def parse_json(path, description, max_bytes, failures)
  unless path.file?
    failures << "#{description} is missing"
    return [nil, nil]
  end
  if path.size > max_bytes
    failures << "#{description} exceeds #{max_bytes} bytes"
    return [nil, nil]
  end

  text = path.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
  failures << "#{description} contains a placeholder, synthetic, contract-only, secret, or raw-evidence marker" if text.match?(FORBIDDEN_MARKERS)
  value = JSON.parse(text)
  unless value.is_a?(Hash)
    failures << "#{description} must be a JSON object"
    return [nil, nil]
  end
  failures << "#{description} contains a forbidden secret-bearing key" if forbidden_key?(value)
  [value, Digest::SHA256.file(path).hexdigest]
rescue JSON::ParserError => e
  failures << "#{description} is invalid JSON: #{e.message}"
  [nil, nil]
end

def bundled_file(root, relative, description, failures)
  unless safe_relative_path?(relative)
    failures << "#{description} path is not a safe relative path"
    return nil
  end

  candidate = root.join(relative)
  unless candidate.file?
    failures << "#{description} is missing"
    return nil
  end

  root_real = root.realpath
  candidate_real = candidate.realpath
  prefix = "#{root_real.to_s.downcase}#{File::SEPARATOR}"
  unless candidate_real.to_s.downcase.start_with?(prefix)
    failures << "#{description} resolves outside the evidence bundle"
    return nil
  end
  candidate_real
rescue Errno::ENOENT
  failures << "#{description} is missing"
  nil
end

def exact_required_names?(entries, required)
  names = entries.map { |entry| entry.is_a?(Hash) ? entry["name"] : nil }
  names.length == required.length && names.all? { |name| name.is_a?(String) } && names.sort == required.sort
end

def artifact_bindings(msi_sha256, manifest_sha256)
  {
    "signedMsiSha256" => msi_sha256,
    "releaseManifestSha256" => manifest_sha256
  }
end

def validate_check_source(source, lane, check, expected_sha, expected_ref, harness_sha256, bindings, failures)
  failures << "check #{check} source schemaVersion must be 1" unless source["schemaVersion"] == 1
  failures << "check #{check} source evidenceKind is invalid" unless source["evidenceKind"] == "windowsProductionValidationCheckEvidence"
  failures << "check #{check} source measurementKind must be measured" unless source["measurementKind"] == "measured"
  failures << "check #{check} source lane does not match" unless source["lane"] == lane
  failures << "check #{check} source check does not match" unless source["check"] == check
  failures << "check #{check} source status must be pass" unless source["status"] == "pass"
  failures << "check #{check} source harness SHA-256 does not match" unless source["harnessSha256"] == harness_sha256
  failures << "check #{check} source release commit does not match" unless source.dig("release", "commitSha") == expected_sha
  failures << "check #{check} source release ref does not match" unless source.dig("release", "ref") == expected_ref
  failures << "check #{check} source artifact hashes do not match" unless source["artifacts"] == bindings
end

def validate_artifact_report(report, lane, expected_sha, expected_ref, release_run_id,
                             artifacts_by_role, failures)
  failures << "artifact verification schemaVersion must be 1" unless report["schemaVersion"] == 1
  failures << "artifact verification evidenceKind is invalid" unless report["evidenceKind"] == "windowsProductionArtifactVerification"
  failures << "artifact verification status must be pass" unless report["status"] == "pass"
  failures << "artifact verification lane does not match" unless report["lane"] == lane
  failures << "artifact verification release commit does not match" unless report.dig("release", "commitSha") == expected_sha
  failures << "artifact verification release ref does not match" unless report.dig("release", "ref") == expected_ref
  failures << "artifact verification release run id does not match" unless report.dig("release", "releaseRunId").to_s == release_run_id

  msi = report.dig("artifacts", "signedMsi")
  manifest = report.dig("artifacts", "releaseManifest")
  failures << "artifact verification signed MSI report is missing" unless msi.is_a?(Hash)
  failures << "artifact verification release manifest report is missing" unless manifest.is_a?(Hash)
  if msi.is_a?(Hash)
    expected = artifacts_by_role["signedMsi"] || {}
    failures << "artifact verification signed MSI path does not match" unless msi["path"] == expected["path"]
    failures << "artifact verification signed MSI hash does not match" unless msi["sha256"] == expected["actualSha256"] && msi["digestMatched"] == true
    failures << "artifact verification signed MSI container was not verified" unless msi["validMsiContainer"] == true
    failures << "artifact verification MSI Authenticode signature is not Valid" unless msi["authenticodeStatus"] == "Valid"
    failures << "artifact verification MSI timestamp is missing" unless msi["timestampPresent"] == true
  end
  if manifest.is_a?(Hash)
    expected = artifacts_by_role["releaseManifest"] || {}
    failures << "artifact verification release manifest path does not match" unless manifest["path"] == expected["path"]
    failures << "artifact verification release manifest hash does not match" unless manifest["sha256"] == expected["actualSha256"] && manifest["digestMatched"] == true
    failures << "artifact verification release manifest JSON was not verified" unless manifest["validJson"] == true
    failures << "artifact verification release binding was not verified" unless manifest["releaseBound"] == true
    failures << "artifact verification MSI hash binding was not verified" unless manifest["artifactHashBound"] == true
  end
  failures << "artifact verification contains failures" unless Array(report["failures"]).empty?
end

options = { require_pass: false }
OptionParser.new do |parser|
  parser.banner = "usage: #{$PROGRAM_NAME} [options] EVIDENCE"
  parser.on("--config PATH") { |value| options[:config] = Pathname.new(value) }
  parser.on("--lane ID") { |value| options[:lane] = value }
  parser.on("--expected-sha SHA") { |value| options[:expected_sha] = value }
  parser.on("--expected-ref REF") { |value| options[:expected_ref] = value }
  parser.on("--release-run-id ID") { |value| options[:release_run_id] = value }
  parser.on("--signed-msi-sha256 SHA") { |value| options[:signed_msi_sha256] = value }
  parser.on("--release-manifest-sha256 SHA") { |value| options[:release_manifest_sha256] = value }
  parser.on("--require-pass") { options[:require_pass] = true }
end.parse!
options[:evidence] = Pathname.new(ARGV.shift) if ARGV.length == 1

required = %i[config lane expected_sha expected_ref release_run_id signed_msi_sha256 release_manifest_sha256 evidence]
missing = required.reject { |key| options.key?(key) }
abort_with("missing required options: #{missing.join(', ')}") unless missing.empty?
abort_with("matrix contract is missing") unless options.fetch(:config).file?
abort_with("matrix contract exceeds 1048576 bytes") if options.fetch(:config).size > 1_048_576
begin
  config = JSON.parse(options.fetch(:config).read(encoding: "UTF-8"))
rescue JSON::ParserError => e
  abort_with("matrix contract is invalid JSON: #{e.message}")
end
abort_with("matrix contract is invalid") unless config.is_a?(Hash) && config["schemaVersion"] == 1 && config["evidenceKind"] == "windowsProductionValidationMatrixContract"
lane = Array(config["lanes"]).find { |entry| entry["id"] == options[:lane] }
abort_with("unknown validation lane: #{options[:lane]}") unless lane
harness_sha256 = config["externalHarnessSha256"]
abort_with("external harness SHA-256 is unset or invalid") unless harness_sha256.is_a?(String) && harness_sha256.match?(SHA256_PATTERN)

evidence_path = options.fetch(:evidence)
abort_with("evidence is missing: #{evidence_path}") unless evidence_path.file?
abort_with("evidence exceeds #{config['maxEvidenceBytes']} bytes") if evidence_path.size > config["maxEvidenceBytes"]
failures = []
evidence, = parse_json(evidence_path, "evidence", config["maxEvidenceBytes"], failures)
evidence ||= {}

failures << "schemaVersion must be 1" unless evidence["schemaVersion"] == 1
failures << "evidenceKind is invalid" unless evidence["evidenceKind"] == "windowsProductionValidationLaneEvidence"
failures << "lane does not match" unless evidence["lane"] == lane["id"]
failures << "status must be pass, blocked, or fail" unless %w[pass blocked fail].include?(evidence["status"])
failures << "release commit does not match" unless evidence.dig("release", "commitSha") == options[:expected_sha]
failures << "release ref does not match" unless evidence.dig("release", "ref") == options[:expected_ref]
failures << "release run id does not match" unless evidence.dig("release", "releaseRunId").to_s == options[:release_run_id]
failures << "contracted harness path does not match" unless evidence.dig("harness", "path") == config["externalHarness"]
failures << "contracted harness SHA-256 does not match" unless evidence.dig("harness", "sha256") == harness_sha256

begin
  generated_at = Time.iso8601(evidence["generatedAt"])
  now = Time.now.utc
  failures << "evidence is stale" if generated_at < now - MAX_AGE_SECONDS
  failures << "evidence is too far in the future" if generated_at > now + MAX_FUTURE_SKEW_SECONDS
rescue ArgumentError, TypeError
  failures << "generatedAt must be RFC3339"
end

expected_artifacts = {
  "signedMsi" => options[:signed_msi_sha256],
  "releaseManifest" => options[:release_manifest_sha256]
}
artifacts = Array(evidence["artifacts"])
artifacts_by_role = {}
expected_artifacts.each do |role, digest|
  entries = artifacts.select { |entry| entry.is_a?(Hash) && entry["role"] == role }
  failures << "#{role} artifact binding must appear exactly once" unless entries.length == 1
  next unless entries.length == 1

  entry = entries.first
  artifacts_by_role[role] = entry
  failures << "#{role} path is not safe" unless safe_relative_path?(entry["path"])
  failures << "#{role} expected digest does not match" unless entry["expectedSha256"] == digest
  if evidence["status"] == "pass"
    failures << "#{role} digest was not verified" unless entry["digestMatched"] == true && entry["actualSha256"] == digest
  end
end

bundle_root = evidence_path.dirname
artifact_verification = evidence["artifactVerification"]
artifact_report = nil
artifact_report_digest = nil
if evidence["status"] == "pass"
  unless artifact_verification.is_a?(Hash) && artifact_verification["provided"] == true && artifact_verification["status"] == "pass"
    failures << "pass evidence requires independent artifact verification"
  end
  if artifact_verification.is_a?(Hash)
    report_path = bundled_file(bundle_root, artifact_verification["path"], "artifact verification", failures)
    if report_path
      artifact_report, artifact_report_digest = parse_json(
        report_path, "artifact verification", config["maxArtifactVerificationBytes"], failures
      )
      failures << "artifact verification SHA-256 does not match the actual report" unless artifact_verification["sha256"] == artifact_report_digest
      validate_artifact_report(
        artifact_report, lane["id"], options[:expected_sha], options[:expected_ref], options[:release_run_id],
        artifacts_by_role, failures
      ) if artifact_report
    end
  end
end

measurement_summary = evidence["measurement"]
measurement = nil
if evidence["status"] == "pass"
  unless measurement_summary.is_a?(Hash) && measurement_summary["provided"] == true && measurement_summary["kind"] == "measured"
    failures << "pass evidence requires a measured source"
  end
  if measurement_summary.is_a?(Hash)
    measurement_path = bundled_file(bundle_root, measurement_summary["path"], "lane measurement", failures)
    if measurement_path
      measurement, measurement_digest = parse_json(
        measurement_path, "lane measurement", config["maxMeasurementBytes"], failures
      )
      failures << "lane measurement SHA-256 does not match the actual report" unless measurement_summary["sha256"] == measurement_digest
    end
  end
end

required_checks = Array(lane["requiredChecks"])
checks = Array(evidence["checks"])
failures << "checks must contain each required check exactly once" unless exact_required_names?(checks, required_checks)
if evidence["status"] == "pass"
  failures << "laneEvidenceReady must be true for pass evidence" unless evidence["laneEvidenceReady"] == true
  failures << "pass evidence must not contain blockers or failures" unless Array(evidence["blockers"]).empty? && Array(evidence["failures"]).empty?

  measurement_checks = Array(measurement && measurement["checks"])
  if measurement
    failures << "lane measurement schemaVersion must be 1" unless measurement["schemaVersion"] == 1
    failures << "lane measurement evidenceKind is invalid" unless measurement["evidenceKind"] == "windowsProductionValidationMeasurement"
    failures << "lane measurement measurementKind must be measured" unless measurement["measurementKind"] == "measured"
    failures << "lane measurement source does not match the contracted harness" unless measurement["source"] == config["externalHarness"]
    failures << "lane measurement harness SHA-256 does not match" unless measurement["harnessSha256"] == harness_sha256
    failures << "lane measurement does not match the requested lane" unless measurement["lane"] == lane["id"]
    failures << "lane measurement release commit does not match" unless measurement.dig("release", "commitSha") == options[:expected_sha]
    failures << "lane measurement release ref does not match" unless measurement.dig("release", "ref") == options[:expected_ref]
    failures << "lane measurement release run id does not match" unless measurement.dig("release", "releaseRunId").to_s == options[:release_run_id]
    failures << "lane measurement did not verify the signed artifact" unless measurement["signedArtifactVerified"] == true
    failures << "lane measurement status must be pass" unless measurement["status"] == "pass"
    failures << "lane measurement artifact-verification hash does not match" unless measurement["artifactVerificationSha256"] == artifact_report_digest
    failures << "lane measurement checks must contain each required check exactly once" unless exact_required_names?(measurement_checks, required_checks)
    expected_artifacts.each do |role, digest|
      matches = Array(measurement["artifacts"]).select { |entry| entry.is_a?(Hash) && entry["role"] == role && entry["sha256"] == digest }
      failures << "lane measurement #{role} binding must appear exactly once" unless matches.length == 1
    end
  end

  seen_paths = {}
  seen_digests = {}
  measured_paths = {}
  measured_digests = {}
  bindings = artifact_bindings(options[:signed_msi_sha256], options[:release_manifest_sha256])
  checks.each do |check|
    name = check.is_a?(Hash) ? check["name"] : nil
    unless check.is_a?(Hash) && check["status"] == "pass" && check["measured"] == true
      failures << "passing check is not explicitly measured: #{name}"
      next
    end
    path_value = check["sourcePath"]
    digest_value = check["sourceSha256"]
    failures << "passing check source path is reused: #{name}" if seen_paths.key?(path_value)
    failures << "passing check source digest is reused: #{name}" if seen_digests.key?(digest_value)
    source_path = bundled_file(bundle_root, path_value, "check #{name} source", failures)
    if source_path
      source, actual_digest = parse_json(source_path, "check #{name} source", config["maxSourceEvidenceBytes"], failures)
      failures << "check #{name} source SHA-256 does not match the actual file" unless digest_value == actual_digest
      validate_check_source(
        source, lane["id"], name, options[:expected_sha], options[:expected_ref], harness_sha256, bindings, failures
      ) if source
      seen_paths[path_value] = true
      seen_digests[actual_digest] = true if actual_digest
    end

    measured = measurement_checks.find { |entry| entry.is_a?(Hash) && entry["name"] == name }
    unless measured && measured["status"] == "pass" && measured["measured"] == true
      failures << "lane measurement does not explicitly pass check #{name}"
      next
    end
    failures << "lane measurement check #{name} source path is unsafe" unless safe_relative_path?(measured["sourcePath"])
    failures << "lane measurement check #{name} source path is reused" if measured_paths.key?(measured["sourcePath"])
    failures << "lane measurement check #{name} source digest is reused" if measured_digests.key?(measured["sourceSha256"])
    failures << "lane measurement check #{name} source digest does not match bundled evidence" unless measured["sourceSha256"] == digest_value
    measured_paths[measured["sourcePath"]] = true
    measured_digests[measured["sourceSha256"]] = true
  end
else
  failures << "laneEvidenceReady must be false unless status is pass" unless evidence["laneEvidenceReady"] == false
end

result = {
  "valid" => failures.empty?,
  "laneEvidenceReady" => failures.empty? && evidence["status"] == "pass",
  "status" => evidence["status"],
  "failures" => failures.uniq
}
puts JSON.generate(result)
exit((failures.any? || (options[:require_pass] && evidence["status"] != "pass")) ? 1 : 0)
