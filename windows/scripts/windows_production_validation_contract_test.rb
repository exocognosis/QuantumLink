# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "rbconfig"
require "tmpdir"
require "time"
require "yaml"

class WindowsProductionValidationContractTest < Minitest::Test
  REPO_ROOT = File.expand_path("../..", __dir__)
  WORKFLOW_PATH = File.join(REPO_ROOT, ".github/workflows/windows-production-validation.yml")
  CONTRACT_PATH = File.join(REPO_ROOT, "windows/validation/contracts/windows-production-validation-matrix.json")
  PLANNER_PATH = File.join(REPO_ROOT, "windows/scripts/plan-windows-validation-matrix.rb")
  GENERATOR_PATH = File.join(REPO_ROOT, "windows/scripts/generate-windows-validation-matrix-evidence.rb")
  VERIFIER_PATH = File.join(REPO_ROOT, "windows/scripts/verify-windows-validation-matrix-evidence.rb")

  EXPECTED_SHA = "a" * 40
  EXPECTED_REF = "refs/tags/v1.0.0"
  RELEASE_RUN_ID = "1234"
  HARNESS_SHA256 = "f" * 64
  MSI_MAGIC = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1].pack("C*").freeze
  EXPECTED_LANE_IDS = %w[
    windows-10-22h2-vm windows-11-x64-vm windows-physical-x64 two-host-direct
    hostile-nat-relay leak-service-crash-strict-wfp upgrade-rollback-uninstall
    macos-windows-interop
  ].freeze

  def setup
    @workflow_text = File.read(WORKFLOW_PATH)
    @workflow = YAML.load_file(WORKFLOW_PATH)
    @contract = JSON.parse(File.read(CONTRACT_PATH))
    @lane = @contract.fetch("lanes").first
  end

  def test_contract_requires_bounded_sources_harness_pin_and_topology_labels
    assert_equal "", @contract.fetch("externalHarnessSha256")
    assert_operator @contract.fetch("maxReleaseArtifactBytes"), :>, 0
    assert_operator @contract.fetch("maxSourceEvidenceBytes"), :>, 0
    assert_operator @contract.fetch("maxSourceEvidenceBytes"), :<=, @contract.fetch("maxEvidenceBytes")
    assert_operator @contract.fetch("maxArtifactVerificationBytes"), :<=, @contract.fetch("maxEvidenceBytes")
    assert_includes @contract.fetch("requiredRunnerLabels"), "quantumlink-validation-harness-v1"

    lanes = @contract.fetch("lanes")
    assert_equal EXPECTED_LANE_IDS, lanes.map { |lane| lane.fetch("id") }
    lanes.each do |lane|
      refute_empty lane.fetch("requiredChecks")
      refute_empty lane.fetch("prerequisiteLabels")
      assert lane.fetch("prerequisiteLabels").all? { |label| label.start_with?("quantumlink-topology-") }
    end
  end

  def test_workflow_uses_read_only_permissions_and_bounded_bundle_uploads
    refute_nil YAML.parse_file(WORKFLOW_PATH)
    assert_equal({ "actions" => "read", "contents" => "read" }, @workflow.fetch("permissions"))

    upload_steps = @workflow.fetch("jobs").values.flat_map { |job| Array(job["steps"]) }.select do |step|
      step["uses"].to_s.start_with?("actions/upload-artifact@")
    end
    assert_equal 2, upload_steps.length
    assert upload_steps.all? { |step| step.fetch("with").fetch("retention-days") == @contract.fetch("retentionDays") }
    bundle_upload = upload_steps.find { |step| step.fetch("name").include?("lane evidence bundle") }
    assert bundle_upload.fetch("with").fetch("path").end_with?("/")
  end

  def test_dispatch_inputs_only_enter_commands_through_environment
    expected_environment = {
      "EXPECTED_SHA" => "expected_commit_sha",
      "EXPECTED_REF" => "expected_ref",
      "RELEASE_RUN_ID" => "release_run_id",
      "SIGNED_ARTIFACT_NAME" => "signed_artifact_name",
      "SIGNED_MSI_PATH" => "signed_msi_path",
      "SIGNED_MSI_SHA256" => "signed_msi_sha256",
      "RELEASE_MANIFEST_PATH" => "release_manifest_path",
      "RELEASE_MANIFEST_SHA256" => "release_manifest_sha256"
    }
    expected_environment.each do |name, input|
      assert_equal "${{ inputs.#{input} }}", @workflow.fetch("env").fetch(name)
    end

    @workflow.fetch("jobs").each_value do |job|
      Array(job["steps"]).each do |step|
        refute_match(/\$\{\{\s*inputs\./, step["run"].to_s, "direct dispatch interpolation in #{step['name']}")
      end
    end

    inventory = workflow_step("preflight", "Read authenticated runner and release inventories")
    assert_equal "${{ secrets.WINDOWS_RUNNER_INVENTORY_TOKEN }}", inventory.fetch("env").fetch("GH_TOKEN")
    planner = workflow_step("preflight", "Generate fail-closed matrix plan")
    assert_equal "${{ secrets.WINDOWS_RUNNER_INVENTORY_TOKEN != '' }}",
                 planner.fetch("env").fetch("RUNNER_INVENTORY_TOKEN_CONFIGURED")
    signing_presence = planner.fetch("env").fetch("SIGNING_SECRETS_CONFIGURED")
    assert_includes signing_presence, "WINDOWS_SIGNING_CERT_PFX_BASE64 != ''"
    assert_includes signing_presence, "WINDOWS_SIGNING_CERT_PASSWORD != ''"
    assert_includes signing_presence, "WINDOWS_SIGNING_TIMESTAMP_URL != ''"
    refute_match(/SIGNING_CERT:|SIGNING_PASSWORD:|SIGNING_TIMESTAMP_URL:/, @workflow_text)
  end

  def test_workflow_independently_verifies_artifact_and_pins_harness_before_invocation
    artifact_step = workflow_step("validate", "Independently verify signed MSI and release manifest").fetch("run")
    assert_in_order artifact_step, [
      "Get-FileHash -LiteralPath $msi -Algorithm SHA256",
      "Get-AuthenticodeSignature -LiteralPath $msi",
      '$signatureStatus -cne "Valid"',
      '$timestampPresent',
      "ConvertFrom-Json -ErrorAction Stop",
      '$manifest.sha -ceq $env:EXPECTED_SHA',
      '$manifest.ref -ceq $env:EXPECTED_REF',
      '$manifest.runId -ceq $env:RELEASE_RUN_ID',
      '$artifactHashBound = $matches.Count -eq 1'
    ]

    harness_step = workflow_step("validate", "Verify and invoke pinned validation harness").fetch("run")
    assert_in_order harness_step, [
      "externalHarnessSha256",
      "Get-FileHash -LiteralPath $hook -Algorithm SHA256",
      '$actualHarnessSha -cne $expectedHarnessSha',
      "& $hook"
    ]
    assert_includes harness_step, "-HarnessSha256 $actualHarnessSha"
    assert_includes harness_step, "-ArtifactVerificationPath $artifactVerification"
  end

  def test_planner_blocks_when_harness_digest_is_unset
    Dir.mktmpdir("windows-validation-planner") do |directory|
      contract = pinned_contract
      contract["externalHarnessSha256"] = ""
      stdout, stderr, status, plan = invoke_planner(directory, contract)

      assert status.success?, "planner failed: #{stderr}\n#{stdout}"
      assert_equal "blocked", plan.fetch("status")
      assert_equal 0, plan.fetch("scheduledCount")
      plan.fetch("lanes").each do |lane|
        assert_includes lane.fetch("blockers"), "external validation harness SHA-256 is unset or invalid"
      end
    end
  end

  def test_planner_schedules_only_exact_successful_bounded_release_and_labeled_runners
    Dir.mktmpdir("windows-validation-planner") do |directory|
      stdout, stderr, status, plan = invoke_planner(directory, pinned_contract)

      assert status.success?, "planner failed: #{stderr}\n#{stdout}"
      assert_equal({ "scheduledCount" => 8, "status" => "scheduled" }, JSON.parse(stdout))
      assert_equal 8, plan.fetch("scheduledCount")
      assert_equal true, plan.fetch("release").fetch("releaseRunMetadataMatch")
      plan.fetch("lanes").each do |lane|
        assert_equal "scheduled", lane.fetch("status")
        assert_includes lane.fetch("labels"), "quantumlink-validation-harness-v1"
        assert lane.fetch("labels").any? { |label| label.start_with?("quantumlink-topology-") }
      end
    end
  end

  def test_planner_rejects_release_metadata_mismatch_and_oversized_artifact
    Dir.mktmpdir("windows-validation-planner") do |directory|
      contract = pinned_contract
      release_run = valid_release_run.merge("head_sha" => "9" * 40, "conclusion" => "failure")
      artifacts = valid_artifact_inventory(contract)
      artifacts.fetch("artifacts").first["size_in_bytes"] = contract.fetch("maxReleaseArtifactBytes") + 1
      _stdout, stderr, status, plan = invoke_planner(
        directory, contract, :release_run => release_run, :artifacts => artifacts
      )

      assert status.success?, "planner failed: #{stderr}"
      blockers = plan.fetch("lanes").first.fetch("blockers")
      assert_includes blockers, "release run head SHA does not match"
      assert_includes blockers, "release run is not completed successfully"
      assert_includes blockers, "release artifact size is missing, zero, or exceeds the contract cap"
    end
  end

  def test_generator_and_verifier_accept_complete_distinct_bounded_sources
    Dir.mktmpdir("windows-validation-evidence") do |directory|
      fixture = prepare_fixture(directory)
      stdout, stderr, status = invoke_generator(fixture)
      assert status.success?, "generator failed: #{stderr}\n#{stdout}"
      assert_equal "pass", JSON.parse(stdout).fetch("status")

      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      assert_equal true, evidence.fetch("laneEvidenceReady")
      source_paths = evidence.fetch("checks").map { |check| check.fetch("sourcePath") }
      source_digests = evidence.fetch("checks").map { |check| check.fetch("sourceSha256") }
      assert_equal source_paths.length, source_paths.uniq.length
      assert_equal source_digests.length, source_digests.uniq.length
      source_paths.each do |relative|
        path = File.join(File.dirname(fixture.fetch(:output)), relative)
        assert File.file?(path)
        check = evidence.fetch("checks").find { |entry| entry.fetch("sourcePath") == relative }
        assert_equal check.fetch("sourceSha256"), Digest::SHA256.file(path).hexdigest
      end
      assert File.file?(File.join(File.dirname(fixture.fetch(:output)), evidence.dig("artifactVerification", "path")))
      assert File.file?(File.join(File.dirname(fixture.fetch(:output)), evidence.dig("measurement", "path")))

      verify_stdout, verify_stderr, verify_status = invoke_verifier(fixture)
      assert verify_status.success?, "verifier failed: #{verify_stderr}\n#{verify_stdout}"
      assert_equal true, JSON.parse(verify_stdout).fetch("laneEvidenceReady")
    end
  end

  def test_generator_rejects_invented_check_hashes
    Dir.mktmpdir("windows-validation-invented-hash") do |directory|
      fixture = prepare_fixture(directory)
      measurement = JSON.parse(File.read(fixture.fetch(:measurement)))
      measurement.fetch("checks").each { |check| check["sourceSha256"] = "e" * 64 }
      write_json_path(fixture.fetch(:measurement), measurement)

      stdout, stderr, status = invoke_generator(fixture)
      assert status.success?, "generator failed unexpectedly: #{stderr}\n#{stdout}"
      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      assert_equal "fail", evidence.fetch("status")
      assert evidence.fetch("failures").any? { |failure| failure.include?("source SHA-256 does not match the actual file") }
      refute evidence.fetch("checks").any? { |check| check.fetch("status") == "pass" }
    end
  end

  def test_unrelated_text_named_msi_cannot_pass_even_with_matching_claims
    Dir.mktmpdir("windows-validation-text-msi") do |directory|
      fixture = prepare_fixture(directory, "this is unrelated text, not an MSI\n")
      stdout, stderr, status = invoke_generator(fixture)

      assert status.success?, "generator failed unexpectedly: #{stderr}\n#{stdout}"
      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      assert_equal "fail", evidence.fetch("status")
      assert_includes evidence.fetch("failures"), "signedMsi is not an MSI compound-file container"
      assert_equal true, evidence.fetch("artifacts").find { |entry| entry.fetch("role") == "signedMsi" }.fetch("digestMatched")
    end
  end

  def test_generator_rejects_reused_or_traversing_check_sources
    Dir.mktmpdir("windows-validation-reused-source") do |directory|
      fixture = prepare_fixture(directory)
      measurement = JSON.parse(File.read(fixture.fetch(:measurement)))
      first = measurement.fetch("checks").first
      second = measurement.fetch("checks")[1]
      second["sourcePath"] = first.fetch("sourcePath")
      second["sourceSha256"] = first.fetch("sourceSha256")
      write_json_path(fixture.fetch(:measurement), measurement)
      invoke_generator(fixture)
      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      assert_equal "fail", evidence.fetch("status")
      assert evidence.fetch("failures").any? { |failure| failure.include?("sourcePath is reused") }

      fixture = prepare_fixture(File.join(directory, "traversal"))
      measurement = JSON.parse(File.read(fixture.fetch(:measurement)))
      measurement.fetch("checks").first["sourcePath"] = "../outside.json"
      write_json_path(fixture.fetch(:measurement), measurement)
      invoke_generator(fixture)
      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      assert_equal "fail", evidence.fetch("status")
      assert evidence.fetch("failures").any? { |failure| failure.include?("sourcePath is not a safe relative path") }
    end
  end

  def test_generator_rejects_oversized_check_source_even_when_claimed_hash_matches
    Dir.mktmpdir("windows-validation-oversized-source") do |directory|
      fixture = prepare_fixture(directory)
      measurement = JSON.parse(File.read(fixture.fetch(:measurement)))
      first = measurement.fetch("checks").first
      source_path = File.join(File.dirname(fixture.fetch(:measurement)), first.fetch("sourcePath"))
      File.open(source_path, "a") do |file|
        file.write(" " * (pinned_contract.fetch("maxSourceEvidenceBytes") + 1))
      end
      first["sourceSha256"] = Digest::SHA256.file(source_path).hexdigest
      write_json_path(fixture.fetch(:measurement), measurement)

      stdout, stderr, status = invoke_generator(fixture)
      assert status.success?, "generator failed unexpectedly: #{stderr}\n#{stdout}"
      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      assert_equal "fail", evidence.fetch("status")
      assert evidence.fetch("failures").any? { |failure| failure.include?("exceeds 131072 bytes") }
    end
  end

  def test_generator_rejects_harness_mismatch_and_failed_independent_artifact_report
    Dir.mktmpdir("windows-validation-binding") do |directory|
      fixture = prepare_fixture(directory, nil, lambda do |report|
        report.fetch("artifacts").fetch("signedMsi")["authenticodeStatus"] = "UnknownError"
        report.fetch("artifacts").fetch("signedMsi")["timestampPresent"] = false
      end)
      measurement = JSON.parse(File.read(fixture.fetch(:measurement)))
      measurement["harnessSha256"] = "9" * 64
      write_json_path(fixture.fetch(:measurement), measurement)
      invoke_generator(fixture)

      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      assert_equal "fail", evidence.fetch("status")
      assert_includes evidence.fetch("failures"), "lane measurement harness SHA-256 does not match"
      assert evidence.fetch("failures").any? { |failure| failure.include?("MSI Authenticode signature is not Valid") }
      assert evidence.fetch("failures").any? { |failure| failure.include?("MSI Authenticode timestamp is missing") }
    end
  end

  def test_verifier_rehashes_copied_sources_and_rejects_tampering
    Dir.mktmpdir("windows-validation-tamper") do |directory|
      fixture = prepare_fixture(directory)
      invoke_generator(fixture)
      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      source_path = File.join(File.dirname(fixture.fetch(:output)), evidence.fetch("checks").first.fetch("sourcePath"))
      File.open(source_path, "a") { |file| file.write(" \n") }

      stdout, stderr, status = invoke_verifier(fixture)
      refute status.success?, "verifier accepted tampering: #{stderr}\n#{stdout}"
      result = JSON.parse(stdout)
      assert_equal false, result.fetch("valid")
      assert result.fetch("failures").any? { |failure| failure.include?("source SHA-256 does not match the actual file") }
    end
  end

  def test_verifier_rejects_invented_artifact_report_hash
    Dir.mktmpdir("windows-validation-report-hash") do |directory|
      fixture = prepare_fixture(directory)
      invoke_generator(fixture)
      evidence = JSON.parse(File.read(fixture.fetch(:output)))
      evidence.fetch("artifactVerification")["sha256"] = "1" * 64
      write_json_path(fixture.fetch(:output), evidence)

      stdout, stderr, status = invoke_verifier(fixture)
      refute status.success?, "verifier accepted invented report hash: #{stderr}\n#{stdout}"
      assert_includes JSON.parse(stdout).fetch("failures"), "artifact verification SHA-256 does not match the actual report"
    end
  end

  private

  def workflow_step(job_name, step_name)
    @workflow.fetch("jobs").fetch(job_name).fetch("steps").find { |step| step["name"] == step_name } ||
      flunk("missing workflow step #{step_name.inspect}")
  end

  def assert_in_order(text, fragments)
    offset = -1
    fragments.each do |fragment|
      next_offset = text.index(fragment, offset + 1)
      refute_nil next_offset, "missing #{fragment.inspect} after byte #{offset}"
      offset = next_offset
    end
  end

  def pinned_contract
    contract = JSON.parse(JSON.generate(@contract))
    contract["externalHarnessSha256"] = HARNESS_SHA256
    contract["intendedControlPlaneHosts"] = ["localhost"]
    contract
  end

  def all_runner_labels(contract)
    (contract.fetch("requiredRunnerLabels") + contract.fetch("lanes").flat_map do |lane|
      lane.fetch("labels") + lane.fetch("prerequisiteLabels")
    end).uniq
  end

  def valid_release_run
    {
      "inventoryAvailable" => true,
      "id" => RELEASE_RUN_ID.to_i,
      "head_sha" => EXPECTED_SHA,
      "head_branch" => "v1.0.0",
      "status" => "completed",
      "conclusion" => "success"
    }
  end

  def valid_artifact_inventory(contract)
    {
      "inventoryAvailable" => true,
      "artifacts" => [
        {
          "name" => "QuantumLink-Windows-signed",
          "expired" => false,
          "size_in_bytes" => [contract.fetch("maxReleaseArtifactBytes"), 10_000_000].min,
          "workflow_run" => {
            "id" => RELEASE_RUN_ID.to_i,
            "head_sha" => EXPECTED_SHA,
            "head_branch" => "v1.0.0"
          }
        }
      ]
    }
  end

  def invoke_planner(directory, contract, release_run: valid_release_run, artifacts: nil)
    artifacts ||= valid_artifact_inventory(contract)
    config_path = write_json(directory, "contract.json", contract)
    runners_path = write_json(directory, "runners.json", {
      "inventoryAvailable" => true,
      "runners" => [{ "status" => "online", "labels" => all_runner_labels(contract) }]
    })
    release_run_path = write_json(directory, "release-run.json", release_run)
    artifacts_path = write_json(directory, "artifacts.json", artifacts)
    output_path = File.join(directory, "plan.json")
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby, PLANNER_PATH,
      "--config", config_path,
      "--runner-inventory", runners_path,
      "--release-run-inventory", release_run_path,
      "--artifact-inventory", artifacts_path,
      "--expected-sha", EXPECTED_SHA,
      "--expected-ref", EXPECTED_REF,
      "--actual-sha", EXPECTED_SHA,
      "--actual-ref", EXPECTED_REF,
      "--release-run-id", RELEASE_RUN_ID,
      "--signed-artifact-name", "QuantumLink-Windows-signed",
      "--runner-inventory-token-configured", "true",
      "--signing-secrets-configured", "true",
      "--output", output_path,
      :chdir => REPO_ROOT
    )
    [stdout, stderr, status, JSON.parse(File.read(output_path))]
  end

  def prepare_fixture(directory, msi_bytes = nil, artifact_report_mutator = nil)
    FileUtils.mkdir_p(directory)
    contract_path = write_json(directory, "contract.json", pinned_contract)
    artifact_root = File.join(directory, "artifacts")
    FileUtils.mkdir_p(artifact_root)
    msi_path = File.join(artifact_root, "QuantumLink.msi")
    File.binwrite(msi_path, msi_bytes || (MSI_MAGIC + "quantumlink fixture\n"))
    msi_sha256 = Digest::SHA256.file(msi_path).hexdigest
    manifest = {
      "schemaVersion" => "1.0",
      "sha" => EXPECTED_SHA,
      "ref" => EXPECTED_REF,
      "runId" => RELEASE_RUN_ID,
      "artifacts" => [
        { "name" => "QuantumLink.msi", "sha256" => msi_sha256, "lengthBytes" => File.size(msi_path) }
      ]
    }
    manifest_path = write_json(artifact_root, "windows-release-manifest.json", manifest)
    manifest_sha256 = Digest::SHA256.file(manifest_path).hexdigest

    artifact_report = {
      "schemaVersion" => 1,
      "evidenceKind" => "windowsProductionArtifactVerification",
      "status" => "pass",
      "lane" => @lane.fetch("id"),
      "release" => { "commitSha" => EXPECTED_SHA, "ref" => EXPECTED_REF, "releaseRunId" => RELEASE_RUN_ID },
      "artifacts" => {
        "signedMsi" => {
          "path" => "QuantumLink.msi", "sha256" => msi_sha256, "digestMatched" => true,
          "validMsiContainer" => true, "authenticodeStatus" => "Valid", "timestampPresent" => true
        },
        "releaseManifest" => {
          "path" => "windows-release-manifest.json", "sha256" => manifest_sha256, "digestMatched" => true,
          "validJson" => true, "releaseBound" => true, "artifactHashBound" => true
        }
      },
      "failures" => []
    }
    artifact_report_mutator.call(artifact_report) if artifact_report_mutator
    artifact_report_path = write_json(directory, "artifact-verification.json", artifact_report)
    artifact_report_sha256 = Digest::SHA256.file(artifact_report_path).hexdigest

    measurement_directory = File.join(directory, "measurement")
    source_directory = File.join(measurement_directory, "check-sources")
    FileUtils.mkdir_p(source_directory)
    bindings = { "signedMsiSha256" => msi_sha256, "releaseManifestSha256" => manifest_sha256 }
    checks = @lane.fetch("requiredChecks").each_with_index.map do |name, index|
      source = {
        "schemaVersion" => 1,
        "evidenceKind" => "windowsProductionValidationCheckEvidence",
        "measurementKind" => "measured",
        "lane" => @lane.fetch("id"),
        "check" => name,
        "status" => "pass",
        "harnessSha256" => HARNESS_SHA256,
        "release" => { "commitSha" => EXPECTED_SHA, "ref" => EXPECTED_REF },
        "artifacts" => bindings
      }
      relative = format("check-sources/%02d-%s.json", index + 1, name)
      path = write_json_path(File.join(measurement_directory, relative), source)
      {
        "name" => name,
        "status" => "pass",
        "measured" => true,
        "sourcePath" => relative,
        "sourceSha256" => Digest::SHA256.file(path).hexdigest
      }
    end
    measurement = {
      "schemaVersion" => 1,
      "evidenceKind" => "windowsProductionValidationMeasurement",
      "measurementKind" => "measured",
      "source" => pinned_contract.fetch("externalHarness"),
      "harnessSha256" => HARNESS_SHA256,
      "artifactVerificationSha256" => artifact_report_sha256,
      "lane" => @lane.fetch("id"),
      "release" => { "commitSha" => EXPECTED_SHA, "ref" => EXPECTED_REF, "releaseRunId" => RELEASE_RUN_ID },
      "signedArtifactVerified" => true,
      "status" => "pass",
      "artifacts" => [
        { "role" => "signedMsi", "sha256" => msi_sha256 },
        { "role" => "releaseManifest", "sha256" => manifest_sha256 }
      ],
      "checks" => checks
    }
    measurement_path = write_json(measurement_directory, "measurement.json", measurement)
    {
      :contract => contract_path,
      :artifact_root => artifact_root,
      :msi_sha256 => msi_sha256,
      :manifest_sha256 => manifest_sha256,
      :artifact_report => artifact_report_path,
      :measurement => measurement_path,
      :output => File.join(directory, "bundle", "evidence.json")
    }
  end

  def invoke_generator(fixture)
    Open3.capture3(
      RbConfig.ruby, GENERATOR_PATH,
      "--config", fixture.fetch(:contract),
      "--lane", @lane.fetch("id"),
      "--expected-sha", EXPECTED_SHA,
      "--expected-ref", EXPECTED_REF,
      "--release-run-id", RELEASE_RUN_ID,
      "--artifact-root", fixture.fetch(:artifact_root),
      "--signed-msi-path", "QuantumLink.msi",
      "--signed-msi-sha256", fixture.fetch(:msi_sha256),
      "--release-manifest-path", "windows-release-manifest.json",
      "--release-manifest-sha256", fixture.fetch(:manifest_sha256),
      "--artifact-verification", fixture.fetch(:artifact_report),
      "--measurement", fixture.fetch(:measurement),
      "--output", fixture.fetch(:output),
      :chdir => REPO_ROOT
    )
  end

  def invoke_verifier(fixture)
    Open3.capture3(
      RbConfig.ruby, VERIFIER_PATH,
      "--require-pass",
      "--config", fixture.fetch(:contract),
      "--lane", @lane.fetch("id"),
      "--expected-sha", EXPECTED_SHA,
      "--expected-ref", EXPECTED_REF,
      "--release-run-id", RELEASE_RUN_ID,
      "--signed-msi-sha256", fixture.fetch(:msi_sha256),
      "--release-manifest-sha256", fixture.fetch(:manifest_sha256),
      fixture.fetch(:output),
      :chdir => REPO_ROOT
    )
  end

  def write_json(directory, name, value)
    FileUtils.mkdir_p(directory)
    write_json_path(File.join(directory, name), value)
  end

  def write_json_path(path, value)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "#{JSON.pretty_generate(value)}\n")
    path
  end
end
