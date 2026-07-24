#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "optparse"
require "pathname"
require "time"

SHA256_PATTERN = /\A[0-9a-f]{64}\z/.freeze
COMMIT_SHA_PATTERN = /\A[0-9a-f]{40}\z/.freeze
REF_PATTERN = %r{\Arefs/(?:heads|tags)/[^\s]+\z}.freeze
MSI_COMPOUND_FILE_MAGIC = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1].pack("C*").freeze
FORBIDDEN_MARKERS = /
  BEGIN\ (?:RSA\ |EC\ |OPENSSH\ )?PRIVATE\ KEY|WALLET_SEED|
  ENTITLEMENT_TOKEN|DYTALLIX_WALLET_SECRET|QLINK_PRODUCTION_ENDPOINT_SECRET|
  WINDOWS_RELEASE_PRIVATE_KEY|\.pcapng?\b|support-bundle.*\.(?:tar|tar\.gz|tgz|zst|zip)\b
/ix.freeze
FORBIDDEN_KEYS = %w[
  password accessToken refreshToken privateKey seed seedPhrase secret secretValue
  environment processEnvironment endpointSecret signingCertificatePfx
].map(&:downcase).freeze
PLACEHOLDER_MARKERS = /placeholder|synthetic|contract[_ -]?only|not[_ -]?measured|example/i.freeze

def abort_with(message)
  warn message
  exit 1
end

def parse_json_file(path, description, max_bytes, scan_markers = true)
  raise "#{description} is missing" unless path.file?
  raise "#{description} exceeds #{max_bytes} bytes" if path.size > max_bytes

  text = path.read(encoding: "UTF-8", invalid: :replace, undef: :replace)
  raise "#{description} contains a forbidden secret or raw-evidence marker" if scan_markers && text.match?(FORBIDDEN_MARKERS)
  value = JSON.parse(text)
  raise "#{description} must be a JSON object" unless value.is_a?(Hash)
  [value, Digest::SHA256.file(path).hexdigest]
rescue JSON::ParserError => e
  raise "#{description} is invalid JSON: #{e.message}"
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

def safe_relative_path?(value)
  return false unless value.is_a?(String) && !value.empty?
  return false if value.include?("\\") || value.match?(/\A[A-Za-z]:/) || value.start_with?("/") || value.start_with?("//")

  parts = value.split("/", -1)
  parts.none? { |part| part.empty? || part == "." || part == ".." }
end

def contained_file(root, relative, field)
  raise "#{field} must be a safe relative path" unless safe_relative_path?(relative)

  root_real = root.realpath
  candidate = root.join(relative)
  raise "#{field} is missing" unless candidate.file?

  candidate_real = candidate.realpath
  prefix = "#{root_real.to_s.downcase}#{File::SEPARATOR}"
  raise "#{field} resolves outside its evidence root" unless candidate_real.to_s.downcase.start_with?(prefix)
  candidate_real
rescue Errno::ENOENT
  raise "#{field} is missing"
end

def artifact_path(root, relative, field)
  raise "#{field} must be a safe relative artifact path" unless safe_relative_path?(relative)

  root_expanded = root.expand_path
  candidate = root_expanded.join(relative).cleanpath
  prefix = "#{root_expanded.to_s.downcase}#{File::SEPARATOR}"
  raise "#{field} must resolve inside the artifact root" unless candidate.to_s.downcase.start_with?(prefix)
  if candidate.exist?
    root_real = root_expanded.realpath
    candidate_real = candidate.realpath
    real_prefix = "#{root_real.to_s.downcase}#{File::SEPARATOR}"
    raise "#{field} resolves outside the artifact root" unless candidate_real.to_s.downcase.start_with?(real_prefix)
  end
  candidate
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

def validate_source(source, lane, check, expected_sha, expected_ref, harness_sha256, bindings)
  failures = []
  failures << "schemaVersion must be 1" unless source["schemaVersion"] == 1
  failures << "evidenceKind is invalid" unless source["evidenceKind"] == "windowsProductionValidationCheckEvidence"
  failures << "measurementKind must be measured" unless source["measurementKind"] == "measured"
  failures << "lane does not match" unless source["lane"] == lane
  failures << "check does not match" unless source["check"] == check
  failures << "status must be pass" unless source["status"] == "pass"
  failures << "harness SHA-256 does not match" unless source["harnessSha256"] == harness_sha256
  failures << "release commit does not match" unless source.dig("release", "commitSha") == expected_sha
  failures << "release ref does not match" unless source.dig("release", "ref") == expected_ref
  failures << "artifact hashes do not match" unless source["artifacts"] == bindings
  failures << "source contains a forbidden secret-bearing key" if forbidden_key?(source)
  failures
end

def validate_artifact_verification(report, lane, expected_sha, expected_ref, release_run_id,
                                   signed_msi_path, signed_msi_sha256,
                                   release_manifest_path, release_manifest_sha256)
  failures = []
  failures << "schemaVersion must be 1" unless report["schemaVersion"] == 1
  failures << "evidenceKind is invalid" unless report["evidenceKind"] == "windowsProductionArtifactVerification"
  failures << "status must be pass" unless report["status"] == "pass"
  failures << "lane does not match" unless report["lane"] == lane
  failures << "release commit does not match" unless report.dig("release", "commitSha") == expected_sha
  failures << "release ref does not match" unless report.dig("release", "ref") == expected_ref
  failures << "release run id does not match" unless report.dig("release", "releaseRunId").to_s == release_run_id

  msi = report.dig("artifacts", "signedMsi")
  manifest = report.dig("artifacts", "releaseManifest")
  failures << "signed MSI report is missing" unless msi.is_a?(Hash)
  failures << "release manifest report is missing" unless manifest.is_a?(Hash)
  if msi.is_a?(Hash)
    failures << "signed MSI path does not match" unless msi["path"] == signed_msi_path
    failures << "signed MSI hash does not match" unless msi["sha256"] == signed_msi_sha256 && msi["digestMatched"] == true
    failures << "signed MSI container was not verified" unless msi["validMsiContainer"] == true
    failures << "MSI Authenticode signature is not Valid" unless msi["authenticodeStatus"] == "Valid"
    failures << "MSI Authenticode timestamp is missing" unless msi["timestampPresent"] == true
  end
  if manifest.is_a?(Hash)
    failures << "release manifest path does not match" unless manifest["path"] == release_manifest_path
    failures << "release manifest hash does not match" unless manifest["sha256"] == release_manifest_sha256 && manifest["digestMatched"] == true
    failures << "release manifest JSON was not verified" unless manifest["validJson"] == true
    failures << "release manifest binding was not verified" unless manifest["releaseBound"] == true
    failures << "release manifest MSI hash binding was not verified" unless manifest["artifactHashBound"] == true
  end
  failures << "artifact verification contains failures" unless Array(report["failures"]).empty?
  failures << "artifact verification contains a forbidden secret-bearing key" if forbidden_key?(report)
  failures
end

options = {}
OptionParser.new do |parser|
  parser.banner = "usage: #{$PROGRAM_NAME} [options]"
  parser.on("--config PATH") { |value| options[:config] = Pathname.new(value) }
  parser.on("--lane ID") { |value| options[:lane] = value }
  parser.on("--expected-sha SHA") { |value| options[:expected_sha] = value }
  parser.on("--expected-ref REF") { |value| options[:expected_ref] = value }
  parser.on("--release-run-id ID") { |value| options[:release_run_id] = value }
  parser.on("--artifact-root PATH") { |value| options[:artifact_root] = Pathname.new(value).expand_path }
  parser.on("--signed-msi-path PATH") { |value| options[:signed_msi_path] = value }
  parser.on("--signed-msi-sha256 SHA") { |value| options[:signed_msi_sha256] = value }
  parser.on("--release-manifest-path PATH") { |value| options[:release_manifest_path] = value }
  parser.on("--release-manifest-sha256 SHA") { |value| options[:release_manifest_sha256] = value }
  parser.on("--artifact-verification PATH") { |value| options[:artifact_verification] = Pathname.new(value) }
  parser.on("--measurement PATH") { |value| options[:measurement] = Pathname.new(value) }
  parser.on("--output PATH") { |value| options[:output] = Pathname.new(value) }
end.parse!

required = %i[
  config lane expected_sha expected_ref release_run_id artifact_root signed_msi_path
  signed_msi_sha256 release_manifest_path release_manifest_sha256 artifact_verification
  measurement output
]
missing = required.reject { |key| options.key?(key) }
abort_with("missing required options: #{missing.join(', ')}") unless missing.empty?

begin
  config, = parse_json_file(options.fetch(:config), "matrix contract", 1_048_576, false)
rescue RuntimeError => e
  abort_with(e.message)
end
abort_with("matrix contract is invalid") unless config["schemaVersion"] == 1 && config["evidenceKind"] == "windowsProductionValidationMatrixContract"
lane = Array(config["lanes"]).find { |entry| entry["id"] == options[:lane] }
abort_with("unknown validation lane: #{options[:lane]}") unless lane
abort_with("expected SHA must be a 40-character lowercase hexadecimal digest") unless options[:expected_sha].match?(COMMIT_SHA_PATTERN)
abort_with("expected ref must begin with refs/heads/ or refs/tags/") unless options[:expected_ref].match?(REF_PATTERN)
abort_with("release run id must be numeric") unless options[:release_run_id].match?(/\A\d+\z/)
harness_sha256 = config["externalHarnessSha256"]
abort_with("external harness SHA-256 is unset or invalid") unless harness_sha256.is_a?(String) && harness_sha256.match?(SHA256_PATTERN)

failures = []
blockers = []
expected_digests = {
  "signedMsi" => options[:signed_msi_sha256],
  "releaseManifest" => options[:release_manifest_sha256]
}
expected_digests.each do |role, digest|
  failures << "#{role} expected SHA-256 is invalid" unless digest.is_a?(String) && digest.match?(SHA256_PATTERN)
end

artifact_specs = [
  ["signedMsi", options[:signed_msi_path], options[:signed_msi_sha256]],
  ["releaseManifest", options[:release_manifest_path], options[:release_manifest_sha256]]
]
artifacts = artifact_specs.map do |role, relative, expected_digest|
  begin
    path = artifact_path(options[:artifact_root], relative, role)
    actual_digest = path.file? ? Digest::SHA256.file(path).hexdigest : nil
    blockers << "#{role} artifact is missing" if actual_digest.nil?
    failures << "#{role} artifact SHA-256 does not match" if actual_digest && actual_digest != expected_digest
    {
      "role" => role,
      "path" => relative,
      "name" => File.basename(relative),
      "expectedSha256" => expected_digest,
      "actualSha256" => actual_digest,
      "digestMatched" => !actual_digest.nil? && actual_digest == expected_digest
    }
  rescue RuntimeError => e
    failures << e.message
    { "role" => role, "path" => relative, "name" => File.basename(relative.to_s), "expectedSha256" => expected_digest, "actualSha256" => nil, "digestMatched" => false }
  end
end

msi_path = artifact_path(options[:artifact_root], options[:signed_msi_path], "signedMsi") rescue nil
if msi_path && msi_path.file?
  header = File.binread(msi_path, MSI_COMPOUND_FILE_MAGIC.bytesize)
  failures << "signedMsi is not an MSI compound-file container" unless header == MSI_COMPOUND_FILE_MAGIC
end

manifest_path = artifact_path(options[:artifact_root], options[:release_manifest_path], "releaseManifest") rescue nil
if manifest_path && manifest_path.file?
  begin
    manifest = JSON.parse(manifest_path.read(encoding: "UTF-8"))
    failures << "release manifest must be a JSON object" unless manifest.is_a?(Hash)
    if manifest.is_a?(Hash)
      failures << "release manifest schemaVersion does not match" unless manifest["schemaVersion"].to_s == "1.0"
      failures << "release manifest commit does not match" unless manifest["sha"] == options[:expected_sha]
      failures << "release manifest ref does not match" unless manifest["ref"] == options[:expected_ref]
      failures << "release manifest run id does not match" unless manifest["runId"].to_s == options[:release_run_id]
      matches = Array(manifest["artifacts"]).select do |entry|
        entry.is_a?(Hash) && entry["name"] == File.basename(options[:signed_msi_path]) &&
          entry["sha256"] == options[:signed_msi_sha256] && msi_path && msi_path.file? &&
          entry["lengthBytes"] == msi_path.size
      end
      failures << "release manifest must bind the selected MSI hash and length exactly once" unless matches.length == 1
    end
  rescue JSON::ParserError
    failures << "release manifest is invalid JSON"
  end
end

output = options.fetch(:output)
sources_directory = output.dirname.join("sources")
FileUtils.rm_rf(sources_directory)
FileUtils.mkdir_p(sources_directory)

artifact_report = nil
artifact_report_sha256 = nil
artifact_report_path = options.fetch(:artifact_verification)
if artifact_report_path.file?
  begin
    artifact_report, artifact_report_sha256 = parse_json_file(
      artifact_report_path, "artifact verification", config.fetch("maxArtifactVerificationBytes")
    )
    failures.concat(validate_artifact_verification(
      artifact_report, lane["id"], options[:expected_sha], options[:expected_ref], options[:release_run_id],
      options[:signed_msi_path], options[:signed_msi_sha256],
      options[:release_manifest_path], options[:release_manifest_sha256]
    ).map { |entry| "artifact verification #{entry}" })
    FileUtils.cp(artifact_report_path, sources_directory.join("artifact-verification.json"))
  rescue RuntimeError => e
    failures << e.message
  end
else
  blockers << "independent artifact verification is unavailable"
end

measurement = nil
measurement_sha256 = nil
measurement_path = options.fetch(:measurement)
if measurement_path.file?
  begin
    measurement, measurement_sha256 = parse_json_file(
      measurement_path, "lane measurement", config.fetch("maxMeasurementBytes")
    )
    failures << "lane measurement contains a forbidden secret-bearing key" if forbidden_key?(measurement)
    FileUtils.cp(measurement_path, sources_directory.join("measurement.json"))
  rescue RuntimeError => e
    failures << e.message
  end
else
  blockers << "external lane measurement is unavailable"
end

bindings = artifact_bindings(options[:signed_msi_sha256], options[:release_manifest_sha256])
required_checks = Array(lane["requiredChecks"])
measurement_checks = Array(measurement && measurement["checks"])
if measurement
  failures << "lane measurement schemaVersion must be 1" unless measurement["schemaVersion"] == 1
  failures << "lane measurement evidenceKind is invalid" unless measurement["evidenceKind"] == "windowsProductionValidationMeasurement"
  failures << "lane measurement measurementKind must be measured" unless measurement["measurementKind"] == "measured"
  failures << "lane measurement source does not match the contracted harness" unless measurement["source"] == config["externalHarness"]
  failures << "lane measurement harness SHA-256 does not match" unless measurement["harnessSha256"] == harness_sha256
  failures << "lane measurement does not match the requested lane" unless measurement["lane"] == lane["id"]
  failures << "lane measurement commit does not match" unless measurement.dig("release", "commitSha") == options[:expected_sha]
  failures << "lane measurement ref does not match" unless measurement.dig("release", "ref") == options[:expected_ref]
  failures << "lane measurement release run id does not match" unless measurement.dig("release", "releaseRunId").to_s == options[:release_run_id]
  failures << "lane measurement did not verify the signed artifact" unless measurement["signedArtifactVerified"] == true
  failures << "lane measurement artifact-verification hash does not match" unless measurement["artifactVerificationSha256"] == artifact_report_sha256
  failures << "lane measurement checks must contain each required check exactly once" unless exact_required_names?(measurement_checks, required_checks)
  measured_artifacts = Array(measurement["artifacts"])
  expected_digests.each do |role, digest|
    matches = measured_artifacts.select { |entry| entry.is_a?(Hash) && entry["role"] == role && entry["sha256"] == digest }
    failures << "lane measurement is not bound to #{role}" unless matches.length == 1
  end
  if measurement["status"] == "fail"
    failures << "lane measurement reported fail"
  elsif measurement["status"] != "pass"
    blockers << "lane measurement did not report pass"
  end
end

seen_source_paths = {}
seen_source_digests = {}
normalized_checks = required_checks.each_with_index.map do |name, index|
  source_entry = measurement_checks.find { |entry| entry.is_a?(Hash) && entry["name"] == name }
  normalized = { "name" => name, "status" => "blocked", "measured" => false, "sourcePath" => nil, "sourceSha256" => nil }
  unless source_entry
    blockers << "required measured check is unavailable: #{name}"
    next normalized
  end

  if source_entry["status"] == "fail"
    failures << "required measured check failed: #{name}"
    normalized["status"] = "fail"
    next normalized
  end
  unless source_entry["status"] == "pass" && source_entry["measured"] == true
    blockers << "required measured check is unavailable: #{name}"
    next normalized
  end

  relative = source_entry["sourcePath"]
  claimed_digest = source_entry["sourceSha256"]
  source_failures = []
  source_failures << "sourcePath is not a safe relative path" unless safe_relative_path?(relative)
  source_failures << "sourceSha256 is invalid" unless claimed_digest.is_a?(String) && claimed_digest.match?(SHA256_PATTERN)
  source_failures << "sourcePath is reused" if seen_source_paths.key?(relative)
  begin
    source_path = contained_file(measurement_path.dirname, relative, "check source #{name}")
    source, actual_digest = parse_json_file(source_path, "check source #{name}", config.fetch("maxSourceEvidenceBytes"))
    source_failures << "source SHA-256 does not match the actual file" unless claimed_digest == actual_digest
    source_failures << "source digest is reused" if seen_source_digests.key?(actual_digest)
    source_failures.concat(validate_source(
      source, lane["id"], name, options[:expected_sha], options[:expected_ref], harness_sha256, bindings
    ))
    if source_failures.empty?
      bundled_relative = format("sources/check-%02d-%s.json", index + 1, name)
      FileUtils.cp(source_path, output.dirname.join(bundled_relative))
      normalized = {
        "name" => name,
        "status" => "pass",
        "measured" => true,
        "sourcePath" => bundled_relative,
        "sourceSha256" => actual_digest
      }
      seen_source_paths[relative] = true
      seen_source_digests[actual_digest] = true
    end
  rescue RuntimeError => e
    source_failures << e.message
  end
  source_failures.each { |failure| failures << "check #{name}: #{failure}" }
  normalized
end

status = failures.any? ? "fail" : (blockers.empty? ? "pass" : "blocked")
report = {
  "schemaVersion" => 1,
  "evidenceKind" => "windowsProductionValidationLaneEvidence",
  "generatedAt" => Time.now.utc.iso8601,
  "status" => status,
  "laneEvidenceReady" => status == "pass",
  "lane" => lane["id"],
  "displayName" => lane["displayName"],
  "release" => { "commitSha" => options[:expected_sha], "ref" => options[:expected_ref], "releaseRunId" => options[:release_run_id] },
  "harness" => { "path" => config["externalHarness"], "sha256" => harness_sha256 },
  "artifacts" => artifacts,
  "artifactVerification" => {
    "provided" => !artifact_report.nil?,
    "path" => artifact_report ? "sources/artifact-verification.json" : nil,
    "sha256" => artifact_report_sha256,
    "status" => artifact_report && artifact_report["status"]
  },
  "measurement" => {
    "provided" => !measurement.nil?,
    "path" => measurement ? "sources/measurement.json" : nil,
    "sha256" => measurement_sha256,
    "kind" => measurement && measurement["measurementKind"],
    "source" => measurement && measurement["source"],
    "harnessSha256" => measurement && measurement["harnessSha256"],
    "artifactVerificationSha256" => measurement && measurement["artifactVerificationSha256"]
  },
  "checks" => normalized_checks,
  "blockers" => blockers.uniq.first(100),
  "failures" => failures.uniq.first(100),
  "warnings" => []
}

output.dirname.mkpath
text = "#{JSON.pretty_generate(report)}\n"
abort_with("lane evidence exceeds #{config['maxEvidenceBytes']} bytes") if text.bytesize > config["maxEvidenceBytes"]
output.write(text, encoding: "UTF-8")
puts JSON.generate({ "lane" => lane["id"], "status" => status, "laneEvidenceReady" => status == "pass" })
