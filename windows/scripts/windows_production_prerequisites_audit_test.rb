# frozen_string_literal: true

require "json"
require "fileutils"
require "minitest/autorun"
require "open3"
require "pathname"
require "rbconfig"
require "tmpdir"

class WindowsProductionPrerequisitesAuditTest < Minitest::Test
  REPO_ROOT = File.expand_path("../..", __dir__)
  SCRIPT_PATH = File.expand_path("audit-windows-production-prerequisites.rb", __dir__)
  TEMP_ROOT = File.join(REPO_ROOT, "build", "windows-production-prerequisites-audit-test")

  def test_audit_passes_with_matching_runner_secrets_variables_and_dns
    FileUtils.mkdir_p(TEMP_ROOT)
    Dir.mktmpdir("pass", TEMP_ROOT) do |directory|
      fixture = write_fixture(directory)
      stdout, stderr, status, report = invoke_audit(fixture)

      assert status.success?, "audit failed: #{stderr}\n#{stdout}"
      assert_equal "pass", JSON.parse(stdout).fetch("status")
      assert_equal "windowsProductionPrerequisitesAudit", report.fetch("evidenceKind")
      assert_equal "pass", report.fetch("status")
      assert_equal(
        %w[self_hosted_validation_runners release_and_matrix_secrets wintun_release_variables control_plane_dns],
        report.fetch("prerequisites").map { |entry| entry.fetch("id") }
      )
      assert report.fetch("prerequisites").all? { |entry| entry.fetch("status") == "pass" }
    end
  end

  def test_audit_blocks_without_manufacturing_readiness
    FileUtils.mkdir_p(TEMP_ROOT)
    Dir.mktmpdir("blocked", TEMP_ROOT) do |directory|
      fixture = write_fixture(
        directory,
        runners: {
          "inventoryAvailable" => true,
          "runners" => [{ "status" => "online", "labels" => %w[self-hosted windows x64] }]
        },
        secrets: { "inventoryAvailable" => true, "names" => ["WINDOWS_SIGNING_CERT_PFX_BASE64"] },
        variables: { "inventoryAvailable" => true, "values" => { "WINTUN_DOWNLOAD_URL" => "ftp://invalid" } },
        dns: {
          "hosts" => [
            { "host" => "rv.quantumlinkvpn.com", "status" => "blocked", "addressCount" => 0 },
            { "host" => "relay.quantumlinkvpn.com", "status" => "resolved", "addressCount" => 1 }
          ]
        }
      )
      stdout, stderr, status, report = invoke_audit(fixture, require_ready: true)

      refute status.success?, "require-ready accepted blocked prerequisites: #{stderr}\n#{stdout}"
      assert_equal "blocked", report.fetch("status")
      blocked = report.fetch("prerequisites").select { |entry| entry.fetch("status") == "blocked" }
      assert_equal 4, blocked.length
      assert_includes blocked.find { |entry| entry.fetch("id") == "self_hosted_validation_runners" }.dig("evidence", "requiredLabels"),
                      "quantumlink-validation-harness-v1"
      assert_includes blocked.find { |entry| entry.fetch("id") == "release_and_matrix_secrets" }.dig("evidence", "missingSecretNames"),
                      "WINDOWS_SIGNING_CERT_PASSWORD"
      assert_includes blocked.find { |entry| entry.fetch("id") == "wintun_release_variables" }.dig("evidence", "missingOrInvalidVariableNames"),
                      "WINTUN_SHA256"
      assert_includes blocked.find { |entry| entry.fetch("id") == "control_plane_dns" }.dig("evidence", "unresolvedHosts"),
                      "rv.quantumlinkvpn.com"
    end
  end

  def test_audit_rejects_unsafe_fixture_paths
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby, SCRIPT_PATH,
      "--runner-inventory", "../outside.json",
      :chdir => REPO_ROOT
    )

    refute status.success?, "audit accepted an unsafe path: #{stdout}"
    assert_match(/runner inventory must be a repo-relative path/, stderr)
  end

  private

  def invoke_audit(fixture, require_ready: false)
    args = [
      RbConfig.ruby, SCRIPT_PATH,
      "--repo-root", REPO_ROOT,
      "--runner-inventory", fixture.fetch(:runners),
      "--secret-inventory", fixture.fetch(:secrets),
      "--variable-inventory", fixture.fetch(:variables),
      "--dns-inventory", fixture.fetch(:dns),
      "--output", fixture.fetch(:output)
    ]
    args << "--require-ready" if require_ready

    stdout, stderr, status = Open3.capture3(*args, :chdir => REPO_ROOT)
    [stdout, stderr, status, JSON.parse(File.read(File.join(REPO_ROOT, fixture.fetch(:output))))]
  end

  def write_fixture(directory, runners: nil, secrets: nil, variables: nil, dns: nil)
    FileUtils.mkdir_p(TEMP_ROOT)
    root_relative = Pathname.new(directory).relative_path_from(Pathname.new(REPO_ROOT)).to_s
    runners ||= {
      "inventoryAvailable" => true,
      "runners" => [
        {
          "status" => "online",
          "labels" => %w[self-hosted windows x64 quantumlink-validation-harness-v1 quantumlink-win11-x64-vm]
        }
      ]
    }
    secrets ||= {
      "inventoryAvailable" => true,
      "names" => %w[
        WINDOWS_RUNNER_INVENTORY_TOKEN
        WINDOWS_SIGNING_CERT_PFX_BASE64
        WINDOWS_SIGNING_CERT_PASSWORD
        WINDOWS_SIGNING_TIMESTAMP_URL
      ]
    }
    variables ||= {
      "inventoryAvailable" => true,
      "values" => {
        "WINTUN_DOWNLOAD_URL" => "https://www.wintun.net/builds/wintun-0.14.1.zip",
        "WINTUN_SHA256" => "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
      }
    }
    dns ||= {
      "hosts" => [
        { "host" => "rv.quantumlinkvpn.com", "status" => "resolved", "addressCount" => 1 },
        { "host" => "relay.quantumlinkvpn.com", "status" => "resolved", "addressCount" => 1 }
      ]
    }

    {
      :runners => write_json(root_relative, "runners.json", runners),
      :secrets => write_json(root_relative, "secrets.json", secrets),
      :variables => write_json(root_relative, "variables.json", variables),
      :dns => write_json(root_relative, "dns.json", dns),
      :output => "#{root_relative}/audit-output.json"
    }
  end

  def write_json(directory, name, value)
    path = File.join(REPO_ROOT, directory, name)
    File.write(path, "#{JSON.pretty_generate(value)}\n")
    "#{directory}/#{name}"
  end
end
