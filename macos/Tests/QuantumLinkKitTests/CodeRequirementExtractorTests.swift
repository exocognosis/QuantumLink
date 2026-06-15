import Foundation
import XCTest
@testable import QuantumLinkKit

/// Tests against real binaries on the system. We pick `Calculator.app`
/// because it ships on every macOS 11+ install, lives at a stable path,
/// and is signed with the Apple platform identity (predictable DR).
private let calculatorAppPath = "/System/Applications/Calculator.app"

final class CodeRequirementExtractorTests: XCTestCase {
    private var workDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("qlink-cr-extractor-tests-\(UUID().uuidString)")
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

    // MARK: Calculator.app — Apple-signed positive case

    func testExtractFromCalculatorReturnsAppleSignedDR() throws {
        let url = URL(fileURLWithPath: calculatorAppPath)
        try XCTSkipUnless(
            FileManager.default.fileExists(atPath: url.path),
            "Calculator.app missing on this runner; skipping."
        )

        let info = try CodeRequirementExtractor().extract(at: url)

        // The DR for an Apple platform binary is anchored to Apple's
        // root and identifies the bundle by its signing identifier.
        XCTAssertTrue(
            info.designatedRequirement.contains("identifier \"com.apple.calculator\""),
            "Unexpected DR: \(info.designatedRequirement)"
        )
        XCTAssertTrue(
            info.designatedRequirement.contains("anchor apple"),
            "Apple-signed app's DR should contain 'anchor apple': \(info.designatedRequirement)"
        )
        XCTAssertEqual(info.signingIdentifier, "com.apple.calculator")
        // Apple platform binaries don't carry a Team Identifier.
        XCTAssertNil(info.teamIdentifier)
    }

    func testExtractedDRRoundTripsThroughSecRequirementValidator() throws {
        let url = URL(fileURLWithPath: calculatorAppPath)
        try XCTSkipUnless(
            FileManager.default.fileExists(atPath: url.path),
            "Calculator.app missing on this runner; skipping."
        )

        let info = try CodeRequirementExtractor().extract(at: url)
        // The DR strings emitted by SecRequirementCopyString must always
        // re-parse via SecRequirementCreateWithString — that's the same
        // validator PerAppVPNMapping uses, so a round-trip here proves
        // the two paths agree.
        XCTAssertNoThrow(
            try PerAppVPNMapping.validate(
                designatedRequirement: info.designatedRequirement
            )
        )
    }

    // MARK: PerAppVPNMapping.fromInstalledApp convenience

    func testFromInstalledAppBuildsValidMapping() throws {
        let url = URL(fileURLWithPath: calculatorAppPath)
        try XCTSkipUnless(
            FileManager.default.fileExists(atPath: url.path),
            "Calculator.app missing on this runner; skipping."
        )

        let mapping = try PerAppVPNMapping.fromInstalledApp(at: url)
        XCTAssertEqual(mapping.bundleIdentifier, "com.apple.calculator")
        XCTAssertTrue(mapping.designatedRequirement.contains("anchor apple"))
    }

    func testFromInstalledAppPlistRoundTripsCleanly() throws {
        let url = URL(fileURLWithPath: calculatorAppPath)
        try XCTSkipUnless(
            FileManager.default.fileExists(atPath: url.path),
            "Calculator.app missing on this runner; skipping."
        )

        let mapping = try PerAppVPNMapping.fromInstalledApp(at: url)
        let dict = mapping.toPlistDictionary()
        XCTAssertEqual(dict["Identifier"] as? String, "com.apple.calculator")
        XCTAssertEqual(dict["SigningIdentifier"] as? String, "com.apple.calculator")
        let dr = try XCTUnwrap(dict["DesignatedRequirement"] as? String)
        XCTAssertTrue(dr.contains("identifier \"com.apple.calculator\""))
    }

    // MARK: Negative cases

    func testNonexistentPathThrowsCleanError() {
        let url = workDir.appendingPathComponent("does-not-exist.app")
        XCTAssertThrowsError(try CodeRequirementExtractor().extract(at: url)) { error in
            // Either createStaticCodeFailed (file missing entirely) or
            // unsigned (path resolves to something but isn't signed).
            // The important part is that we get a typed error, not a crash.
            XCTAssertTrue(
                error is CodeRequirementExtractorError,
                "Got \(error)"
            )
        }
    }

    func testUnsignedFileThrowsUnsignedError() throws {
        // A plain text file in a tmpdir has no code signature.
        let path = workDir.appendingPathComponent("plain.txt")
        try "not a binary\n".write(to: path, atomically: true, encoding: .utf8)

        XCTAssertThrowsError(try CodeRequirementExtractor().extract(at: path)) { error in
            // Most likely .unsigned, but on some macOS versions the
            // static-code creation itself rejects non-Mach-O / non-bundle
            // paths upfront. Either typed error is acceptable.
            guard let extractorError = error as? CodeRequirementExtractorError else {
                return XCTFail("Expected CodeRequirementExtractorError, got \(error)")
            }
            switch extractorError {
            case .unsigned, .createStaticCodeFailed:
                break
            default:
                XCTFail("Unexpected extractor error: \(extractorError)")
            }
        }
    }
}
