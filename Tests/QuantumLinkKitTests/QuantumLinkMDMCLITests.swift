import Foundation
import Security
import XCTest
@testable import QuantumLinkKit

/// End-to-end tests for the `QuantumLinkMDM` binary. Spawns the
/// release-or-debug-built executable located alongside the test bundle,
/// generates a throwaway PKCS#12 signing identity via openssl, points
/// the CLI at `/System/Applications/Calculator.app`, and parses the
/// resulting signed `.mobileconfig` back through
/// `MobileConfigSigner.verify` + `PropertyListSerialization` to confirm
/// the whole pipeline produces a deployable artifact.
private let calculatorAppPath = "/System/Applications/Calculator.app"

final class QuantumLinkMDMCLITests: XCTestCase {
    private var workDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("qlink-mdm-cli-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: workDir,
            withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        if let workDir, FileManager.default.fileExists(atPath: workDir.path) {
            try FileManager.default.removeItem(at: workDir)
        }
        workDir = nil
        try super.tearDownWithError()
    }

    // MARK: - help / usage

    func testHelpExitsZero() throws {
        let result = try runCLI(["help"])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(result.stdout.contains("Usage: QuantumLinkMDM"))
    }

    func testNoSubcommandReturnsUsageExitCode() throws {
        let result = try runCLI([])
        XCTAssertEqual(result.exitCode, 2)
    }

    func testUnknownSubcommandReturnsUsageExitCode() throws {
        let result = try runCLI(["bogus-subcommand"])
        XCTAssertEqual(result.exitCode, 2)
        XCTAssertTrue(result.stderr.contains("Unknown subcommand: bogus-subcommand"))
    }

    // MARK: - build-perapp end to end

    func testBuildPerAppProducesVerifiableSignedMobileConfig() throws {
        try XCTSkipUnless(
            FileManager.default.fileExists(atPath: calculatorAppPath),
            "Calculator.app missing on this runner; skipping."
        )

        let p12Path = try generateP12(passphrase: "qlink-test")
        let outputPath = workDir.appendingPathComponent("perapp.mobileconfig")
        let vpnUUID = UUID().uuidString

        let result = try runCLI(
            [
                "build-perapp",
                "--apps", calculatorAppPath,
                "--payload-identifier", "com.quantumlink.test.profile",
                "--display-name", "QuantumLink CLI Test",
                "--organization", "QuantumLink",
                "--vpn-payload-uuid", vpnUUID,
                "--signing-p12", p12Path.path,
                "--output", outputPath.path,
            ],
            extraEnvironment: ["QLINK_P12_PASS": "qlink-test"]
        )
        XCTAssertEqual(
            result.exitCode, 0,
            "Non-zero exit; stderr was: \(result.stderr)"
        )
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: outputPath.path),
            "CLI did not write the output file"
        )

        let signed = try Data(contentsOf: outputPath)
        let verification = try MobileConfigSigner().verify(signed)
        XCTAssertEqual(verification.signerStatus, .valid)

        // The embedded payload must be a valid configuration profile
        // wrapping a per-app VPN payload that pins Calculator.
        var format: PropertyListSerialization.PropertyListFormat = .xml
        let plist = try PropertyListSerialization.propertyList(
            from: verification.payload,
            options: [],
            format: &format
        )
        let dict = try XCTUnwrap(plist as? [String: Any])
        XCTAssertEqual(dict["PayloadType"] as? String, "Configuration")
        XCTAssertEqual(
            dict["PayloadIdentifier"] as? String,
            "com.quantumlink.test.profile"
        )
        let content = try XCTUnwrap(dict["PayloadContent"] as? [[String: Any]])
        XCTAssertEqual(content.count, 1)
        XCTAssertEqual(
            content[0]["PayloadType"] as? String,
            "com.apple.vpn.managed.applayer"
        )
        XCTAssertEqual(content[0]["VPNUUID"] as? String, vpnUUID)

        let mappings = try XCTUnwrap(content[0]["AppLayerVPNMapping"] as? [[String: Any]])
        XCTAssertEqual(mappings.count, 1)
        XCTAssertEqual(mappings[0]["Identifier"] as? String, "com.apple.calculator")
        let dr = try XCTUnwrap(mappings[0]["DesignatedRequirement"] as? String)
        XCTAssertTrue(dr.contains("identifier \"com.apple.calculator\""))
        XCTAssertTrue(dr.contains("anchor apple"))
    }

    func testBuildPerAppFailsOnMissingApp() throws {
        let p12Path = try generateP12(passphrase: "qlink-test")
        let outputPath = workDir.appendingPathComponent("should-not-exist.mobileconfig")
        let bogusApp = workDir.appendingPathComponent("Nope.app").path

        let result = try runCLI(
            [
                "build-perapp",
                "--apps", bogusApp,
                "--payload-identifier", "com.quantumlink.test.profile",
                "--display-name", "Test",
                "--organization", "QuantumLink",
                "--vpn-payload-uuid", UUID().uuidString,
                "--signing-p12", p12Path.path,
                "--output", outputPath.path,
            ],
            extraEnvironment: ["QLINK_P12_PASS": "qlink-test"]
        )
        XCTAssertEqual(result.exitCode, 1, "stderr: \(result.stderr)")
        XCTAssertTrue(result.stderr.contains("App bundle not found"))
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: outputPath.path),
            "CLI must not write output on failure"
        )
    }

    func testBuildPerAppFailsOnMissingRequiredArgs() throws {
        let result = try runCLI(["build-perapp"])
        XCTAssertEqual(result.exitCode, 2)
        XCTAssertTrue(result.stderr.contains("Missing required argument: --apps"))
    }

    // MARK: - build-ondemand end to end

    func testBuildOnDemandProducesVerifiableSignedMobileConfig() throws {
        let p12Path = try generateP12(passphrase: "qlink-test")
        let outputPath = workDir.appendingPathComponent("ondemand.mobileconfig")
        let vpnUUID = UUID().uuidString

        let result = try runCLI(
            [
                "build-ondemand",
                "--action", "connect",
                "--ssid", "Acme-Corp,Acme-Guest",
                "--dns-domain", "corp.acme.com",
                "--payload-identifier", "com.quantumlink.test.ondemand",
                "--display-name", "Acme On Demand",
                "--organization", "Acme",
                "--vpn-payload-uuid", vpnUUID,
                "--signing-p12", p12Path.path,
                "--output", outputPath.path,
            ],
            extraEnvironment: ["QLINK_P12_PASS": "qlink-test"]
        )
        XCTAssertEqual(result.exitCode, 0, "stderr: \(result.stderr)")

        let signed = try Data(contentsOf: outputPath)
        let verification = try MobileConfigSigner().verify(signed)
        XCTAssertEqual(verification.signerStatus, .valid)

        var format: PropertyListSerialization.PropertyListFormat = .xml
        let plist = try PropertyListSerialization.propertyList(
            from: verification.payload,
            options: [],
            format: &format
        )
        let dict = try XCTUnwrap(plist as? [String: Any])
        let content = try XCTUnwrap(dict["PayloadContent"] as? [[String: Any]])
        XCTAssertEqual(content.count, 1)
        XCTAssertEqual(
            content[0]["PayloadType"] as? String,
            "com.apple.vpn.managed"
        )
        XCTAssertEqual(content[0]["OnDemandEnabled"] as? Int, 1)
        let rules = try XCTUnwrap(content[0]["OnDemandRules"] as? [[String: Any]])
        // Two rules: the user-supplied one + trailing default-disconnect.
        XCTAssertEqual(rules.count, 2)
        XCTAssertEqual(rules[0]["Action"] as? String, "Connect")
        XCTAssertEqual(rules[0]["SSIDMatch"] as? [String], ["Acme-Corp", "Acme-Guest"])
        XCTAssertEqual(rules[0]["DNSDomainMatch"] as? [String], ["corp.acme.com"])
        XCTAssertEqual(rules[1]["Action"] as? String, "Disconnect")
    }

    func testBuildOnDemandRequiresAtLeastOneMatch() throws {
        let p12Path = try generateP12(passphrase: "qlink-test")
        let result = try runCLI(
            [
                "build-ondemand",
                "--action", "connect",
                "--payload-identifier", "com.quantumlink.test.ondemand",
                "--display-name", "Acme On Demand",
                "--organization", "Acme",
                "--vpn-payload-uuid", UUID().uuidString,
                "--signing-p12", p12Path.path,
                "--output", workDir.appendingPathComponent("nope.mobileconfig").path,
            ],
            extraEnvironment: ["QLINK_P12_PASS": "qlink-test"]
        )
        XCTAssertEqual(result.exitCode, 2, "stderr: \(result.stderr)")
        XCTAssertTrue(
            result.stderr.contains("at least one match condition"),
            "stderr: \(result.stderr)"
        )
    }

    // MARK: - helpers

    private struct CLIResult {
        let exitCode: Int32
        let stdout: String
        let stderr: String
    }

    private func runCLI(
        _ arguments: [String],
        extraEnvironment: [String: String] = [:]
    ) throws -> CLIResult {
        let binary = try locateBinary()
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        var env = ProcessInfo.processInfo.environment
        for (key, value) in extraEnvironment {
            env[key] = value
        }
        process.environment = env

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        return CLIResult(
            exitCode: process.terminationStatus,
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? ""
        )
    }

    /// Locates the `QuantumLinkMDM` binary that was built in the same
    /// build directory as this test bundle. SwiftPM puts the test
    /// `.xctest` bundle and the executables side by side under
    /// `.build/<arch>/<config>/`, so the binary's parent dir is the
    /// test bundle's parent dir.
    private func locateBinary() throws -> URL {
        let bundle = Bundle(for: type(of: self))
        let candidate = bundle.bundleURL
            .deletingLastPathComponent()
            .appendingPathComponent("QuantumLinkMDM")
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw NSError(
                domain: "QuantumLinkMDMCLITests",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "QuantumLinkMDM binary not found at \(candidate.path); "
                        + "run `swift build` first.",
                ]
            )
        }
        return candidate
    }

    /// Generates a fresh self-signed RSA-2048 cert + key, packages them
    /// as PKCS#12 with macOS-importable PBE algorithms, and returns the
    /// `.p12` path. Same approach the signer tests use — no checked-in
    /// fixtures.
    private func generateP12(passphrase: String) throws -> URL {
        let keyPath = workDir.appendingPathComponent("key.pem")
        let certPath = workDir.appendingPathComponent("cert.pem")
        let p12Path = workDir.appendingPathComponent("test.p12")

        try runOpenSSL([
            "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", keyPath.path,
            "-out", certPath.path,
            "-days", "1",
            "-nodes",
            "-subj", "/CN=QuantumLink CLI Test Signer",
        ])
        try runOpenSSL([
            "pkcs12", "-export",
            "-out", p12Path.path,
            "-inkey", keyPath.path,
            "-in", certPath.path,
            "-password", "pass:\(passphrase)",
            "-keypbe", "PBE-SHA1-3DES",
            "-certpbe", "PBE-SHA1-3DES",
            "-macalg", "SHA1",
        ])
        return p12Path
    }

    private func runOpenSSL(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let stderrData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let stderr = String(data: stderrData, encoding: .utf8) ?? "<binary>"
            throw NSError(
                domain: "openssl",
                code: Int(process.terminationStatus),
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "openssl \(arguments.joined(separator: " ")) failed: \(stderr)",
                ]
            )
        }
    }
}
