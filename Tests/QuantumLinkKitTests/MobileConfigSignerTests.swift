import Foundation
import Security
import XCTest
@testable import QuantumLinkKit

/// Round-trip CMS signing tests. These shell out to `/usr/bin/openssl` to
/// synthesize a fresh self-signed cert + RSA-2048 key pair per run,
/// import the resulting `.p12` via `SecPKCS12Import`, and exercise the
/// signer end-to-end. No fixture files are checked in; everything lives
/// in a per-test scratch directory and is cleaned up in tearDown.
///
/// The cert is self-signed and only valid for one day; trust-chain
/// evaluation will deliberately fail, so these tests verify the *signature*
/// (CMSSignerStatus.valid) rather than the trust chain.
final class MobileConfigSignerTests: XCTestCase {
    private var workDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("qlink-signer-tests-\(UUID().uuidString)")
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

    func testSignAndVerifyRoundTrip() throws {
        let identity = try makeTestIdentity()
        let payload = Data("Hello from QuantumLink".utf8)

        let signer = MobileConfigSigner()
        let signed = try signer.sign(payload, with: identity)

        // The signed envelope must differ from the input (it's a CMS
        // wrapper around the input plus signature material).
        XCTAssertNotEqual(signed, payload)
        XCTAssertGreaterThan(signed.count, payload.count)

        let verification = try signer.verify(signed)
        XCTAssertEqual(verification.payload, payload)
        XCTAssertEqual(verification.signerCount, 1)
        XCTAssertEqual(verification.signerStatus, .valid)
        // We didn't ask for trust evaluation, so the result should be nil.
        XCTAssertNil(verification.trustEvaluationResult)
    }

    func testSignedEnvelopeStartsWithASN1SequenceTag() throws {
        let identity = try makeTestIdentity()
        let signed = try MobileConfigSigner().sign(Data("x".utf8), with: identity)
        // CMS envelopes are DER-encoded ASN.1 starting with SEQUENCE (0x30).
        XCTAssertEqual(signed.first, 0x30)
    }

    func testTamperingTheContentBreaksVerification() throws {
        let identity = try makeTestIdentity()
        let signer = MobileConfigSigner()
        // Use a payload that's distinctive enough to find inside the CMS
        // envelope without matching cert / signature bytes by accident.
        let payload = Data("QUANTUMLINK-TAMPER-TEST-MARKER-12345".utf8)
        var signed = try signer.sign(payload, with: identity)

        // Locate the embedded content and flip a byte. CMS embeds the
        // payload as an OCTET STRING; the literal payload bytes appear
        // contiguously in the DER. Flipping a content byte invalidates
        // the signedAttrs digest and `signerStatus` should drop to
        // `.invalidSignature`.
        let needle = payload
        guard let range = signed.range(of: needle) else {
            return XCTFail("Could not locate embedded payload in signed envelope")
        }
        signed[range.lowerBound] ^= 0xFF

        do {
            let verification = try signer.verify(signed)
            // The envelope still parses (only content bytes were touched),
            // but the signer status must reflect the tamper.
            XCTAssertNotEqual(
                verification.signerStatus,
                .valid,
                "Tampered content should produce a non-valid signer status"
            )
        } catch {
            // Acceptable: some byte flips also break the digest-of-content
            // ASN.1 substructure such that the decoder rejects the bytes
            // outright. Either way, the tamper was detected.
            XCTAssertTrue(error is MobileConfigSignerError, "Got \(error)")
        }
    }

    func testSignedMobileConfigEnvelopeRoundTripsThroughVerify() throws {
        // End-to-end: build a real mobileconfig envelope with a
        // per-app VPN payload, serialize, sign, verify, and confirm the
        // bytes are byte-identical on the way out.
        let mapping = try PerAppVPNMapping(
            bundleIdentifier: "com.acme.example",
            designatedRequirement: """
            identifier "com.acme.example" and anchor apple generic and \
            certificate leaf[subject.OU] = "ACMEACMEAC"
            """
        )
        let perApp = try PerAppVPNPayload(
            payloadIdentifier: "com.quantumlink.applayer",
            vpnPayloadUUID: UUID(),
            mappings: [mapping]
        )
        let envelope = MobileConfigEnvelope(
            payloadIdentifier: "com.quantumlink.profile",
            payloadDisplayName: "QuantumLink",
            payloadOrganization: "QuantumLink",
            payloadContent: [perApp.toPlistDictionary()]
        )
        let xmlPlist = try envelope.serialize(format: .xml)

        let identity = try makeTestIdentity()
        let signer = MobileConfigSigner()
        let signed = try signer.sign(xmlPlist, with: identity)

        let verification = try signer.verify(signed)
        XCTAssertEqual(verification.payload, xmlPlist)
        XCTAssertEqual(verification.signerStatus, .valid)
    }

    func testTrustEvaluationFailsForSelfSignedCert() throws {
        // Self-signed certs aren't trusted by the system. With
        // evaluateTrust=true, CMSDecoderCopySignerStatus folds the
        // trust failure back into `signerStatus` as `.invalidCert` even
        // though the underlying signature is fine — that's the C API's
        // semantics, not ours. The trust evaluation result is reported
        // separately for diagnostics.
        let identity = try makeTestIdentity()
        let signed = try MobileConfigSigner().sign(Data("hi".utf8), with: identity)

        // Signature-only check: the signature itself is cryptographically
        // valid, even on a self-signed cert.
        let signatureOnly = try MobileConfigSigner().verify(signed, evaluateTrust: false)
        XCTAssertEqual(signatureOnly.signerStatus, .valid)
        XCTAssertNil(signatureOnly.trustEvaluationResult)

        // Trust-evaluating check: the chain doesn't validate against
        // the system trust store, so the signer status reflects the
        // failure and the trust result is non-success.
        let trustChecked = try MobileConfigSigner().verify(signed, evaluateTrust: true)
        XCTAssertNotEqual(
            trustChecked.signerStatus,
            .valid,
            "Self-signed cert should not produce .valid status with trust eval on"
        )
        let trustResult = try XCTUnwrap(trustChecked.trustEvaluationResult)
        XCTAssertNotEqual(
            trustResult,
            errSecSuccess,
            "Self-signed test cert must not pass system trust evaluation"
        )
    }

    // MARK: - Test cert generation

    /// Generates a fresh self-signed RSA-2048 cert via `/usr/bin/openssl`,
    /// packages the cert + private key as PKCS#12, and imports them into
    /// the test process via `SecPKCS12Import` to produce a `SecIdentity`.
    private func makeTestIdentity() throws -> SecIdentity {
        let keyPath = workDir.appendingPathComponent("key.pem")
        let certPath = workDir.appendingPathComponent("cert.pem")
        let p12Path = workDir.appendingPathComponent("test.p12")
        let passphrase = "qlink-test"

        try runOpenSSL([
            "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", keyPath.path,
            "-out", certPath.path,
            "-days", "1",
            "-nodes",
            "-subj", "/CN=QuantumLink Test Signer",
        ])

        // Use the legacy PBE algorithms — macOS's SecPKCS12Import is
        // strict about which key/cert encryption algorithms it accepts.
        // OpenSSL 3 defaults to AES-256, which fails to import on some
        // macOS versions; PBE-SHA1-3DES is the historical compatible
        // choice and is fine for a throwaway test fixture.
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

        let p12Data = try Data(contentsOf: p12Path)
        var importedItems: CFArray?
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: passphrase,
        ]
        let status = SecPKCS12Import(
            p12Data as CFData,
            options as CFDictionary,
            &importedItems
        )
        guard status == errSecSuccess else {
            throw NSError(
                domain: "MobileConfigSignerTests",
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "SecPKCS12Import failed: \(status)"]
            )
        }
        guard
            let items = importedItems as? [[String: Any]],
            let first = items.first,
            let identityRef = first[kSecImportItemIdentity as String]
        else {
            throw NSError(
                domain: "MobileConfigSignerTests",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "PKCS#12 import returned no identity"]
            )
        }
        // CFTypeRef -> SecIdentity. The dictionary stores the identity
        // as a CF type; force-cast through AnyObject is the standard
        // pattern.
        return identityRef as! SecIdentity
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
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let stderrText = String(data: errData, encoding: .utf8) ?? "<binary>"
            throw NSError(
                domain: "openssl",
                code: Int(process.terminationStatus),
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "openssl \(arguments.joined(separator: " ")) failed: \(stderrText)",
                ]
            )
        }
    }
}
