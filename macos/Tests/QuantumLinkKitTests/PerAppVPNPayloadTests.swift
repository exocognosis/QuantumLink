import Foundation
import XCTest
@testable import QuantumLinkKit

/// A canonical Apple-format designated requirement string. The exact
/// identifier and team don't matter for these tests; what matters is
/// that `SecRequirementCreateWithString` parses it.
private let validDesignatedRequirement = """
identifier "com.acme.example" and anchor apple generic and \
certificate leaf[subject.OU] = "ACMEACMEAC"
"""

final class PerAppVPNPayloadTests: XCTestCase {

    // MARK: PerAppVPNMapping

    func testMappingRejectsEmptyBundleIdentifier() {
        XCTAssertThrowsError(
            try PerAppVPNMapping(
                bundleIdentifier: "  ",
                designatedRequirement: validDesignatedRequirement
            )
        ) { error in
            XCTAssertEqual(error as? PerAppVPNPayloadError, .bundleIdentifierEmpty)
        }
    }

    func testMappingRejectsEmptyDesignatedRequirement() {
        XCTAssertThrowsError(
            try PerAppVPNMapping(
                bundleIdentifier: "com.acme.example",
                designatedRequirement: "   "
            )
        ) { error in
            XCTAssertEqual(error as? PerAppVPNPayloadError, .designatedRequirementEmpty)
        }
    }

    func testMappingRejectsMalformedDesignatedRequirementViaSecurityFramework() {
        // Garbage text — the Security framework's parser should reject it.
        XCTAssertThrowsError(
            try PerAppVPNMapping(
                bundleIdentifier: "com.acme.example",
                designatedRequirement: "this is not a valid requirement string ((("
            )
        ) { error in
            guard
                case .designatedRequirementInvalid(let reason) = error as? PerAppVPNPayloadError
            else {
                return XCTFail("Expected designatedRequirementInvalid, got \(error)")
            }
            XCTAssertFalse(reason.isEmpty, "Reason should be populated by Security framework")
        }
    }

    func testMappingTrimsWhitespace() throws {
        let mapping = try PerAppVPNMapping(
            bundleIdentifier: "  com.acme.example  ",
            designatedRequirement: "  \(validDesignatedRequirement)  "
        )
        XCTAssertEqual(mapping.bundleIdentifier, "com.acme.example")
        XCTAssertEqual(mapping.designatedRequirement, validDesignatedRequirement)
    }

    func testMappingPlistDictionaryShape() throws {
        let mapping = try PerAppVPNMapping(
            bundleIdentifier: "com.acme.example",
            designatedRequirement: validDesignatedRequirement
        )
        let dict = mapping.toPlistDictionary()

        XCTAssertEqual(dict["Identifier"] as? String, "com.acme.example")
        XCTAssertEqual(dict["SigningIdentifier"] as? String, "com.acme.example")
        XCTAssertEqual(dict["DesignatedRequirement"] as? String, validDesignatedRequirement)
    }

    // MARK: PerAppVPNPayload

    func testPayloadRejectsEmptyMappings() {
        XCTAssertThrowsError(
            try PerAppVPNPayload(
                payloadIdentifier: "com.quantumlink.applayer",
                vpnPayloadUUID: UUID(),
                mappings: []
            )
        ) { error in
            XCTAssertEqual(error as? PerAppVPNPayloadError, .mappingsEmpty)
        }
    }

    func testPayloadPlistShape() throws {
        let mapping = try PerAppVPNMapping(
            bundleIdentifier: "com.acme.example",
            designatedRequirement: validDesignatedRequirement
        )
        let payloadUUID = UUID()
        let vpnUUID = UUID()
        let payload = try PerAppVPNPayload(
            payloadIdentifier: "com.quantumlink.applayer",
            payloadUUID: payloadUUID,
            payloadDisplayName: "Test Per-App VPN",
            vpnPayloadUUID: vpnUUID,
            mappings: [mapping]
        )

        let dict = payload.toPlistDictionary()
        XCTAssertEqual(dict["PayloadType"] as? String, "com.apple.vpn.managed.applayer")
        XCTAssertEqual(dict["PayloadVersion"] as? Int, 1)
        XCTAssertEqual(dict["PayloadIdentifier"] as? String, "com.quantumlink.applayer")
        XCTAssertEqual(dict["PayloadUUID"] as? String, payloadUUID.uuidString)
        XCTAssertEqual(dict["PayloadDisplayName"] as? String, "Test Per-App VPN")
        XCTAssertEqual(dict["VPNUUID"] as? String, vpnUUID.uuidString)

        let mappings = dict["AppLayerVPNMapping"] as? [[String: Any]]
        XCTAssertEqual(mappings?.count, 1)
        XCTAssertEqual(mappings?.first?["Identifier"] as? String, "com.acme.example")
    }

    func testPayloadSurvivesMultipleMappings() throws {
        let m1 = try PerAppVPNMapping(
            bundleIdentifier: "com.acme.one",
            designatedRequirement: validDesignatedRequirement
        )
        let m2 = try PerAppVPNMapping(
            bundleIdentifier: "com.acme.two",
            designatedRequirement: validDesignatedRequirement
        )

        let payload = try PerAppVPNPayload(
            payloadIdentifier: "com.quantumlink.applayer",
            vpnPayloadUUID: UUID(),
            mappings: [m1, m2]
        )

        let mappings = payload.toPlistDictionary()["AppLayerVPNMapping"] as? [[String: Any]]
        XCTAssertEqual(mappings?.count, 2)
        XCTAssertEqual(mappings?[0]["Identifier"] as? String, "com.acme.one")
        XCTAssertEqual(mappings?[1]["Identifier"] as? String, "com.acme.two")
    }

    // MARK: MobileConfigEnvelope round-trip

    func testEnvelopeWrapsPerAppPayloadAndRoundTripsThroughPlist() throws {
        let mapping = try PerAppVPNMapping(
            bundleIdentifier: "com.acme.example",
            designatedRequirement: validDesignatedRequirement
        )
        let perApp = try PerAppVPNPayload(
            payloadIdentifier: "com.quantumlink.applayer",
            vpnPayloadUUID: UUID(),
            mappings: [mapping]
        )

        let envelope = MobileConfigEnvelope(
            payloadIdentifier: "com.quantumlink.profile",
            payloadDisplayName: "QuantumLink Test",
            payloadOrganization: "QuantumLink",
            payloadContent: [perApp.toPlistDictionary()],
            payloadDescription: "Test envelope"
        )

        let xmlData = try envelope.serialize(format: .xml)
        XCTAssertFalse(xmlData.isEmpty)

        // Parse the XML back and assert on top-level shape.
        var format: PropertyListSerialization.PropertyListFormat = .xml
        let parsed = try PropertyListSerialization.propertyList(
            from: xmlData,
            options: [],
            format: &format
        )
        let dict = try XCTUnwrap(parsed as? [String: Any])
        XCTAssertEqual(dict["PayloadType"] as? String, "Configuration")
        XCTAssertEqual(dict["PayloadVersion"] as? Int, 1)
        XCTAssertEqual(dict["PayloadIdentifier"] as? String, "com.quantumlink.profile")
        XCTAssertEqual(dict["PayloadDisplayName"] as? String, "QuantumLink Test")
        XCTAssertEqual(dict["PayloadOrganization"] as? String, "QuantumLink")
        XCTAssertEqual(dict["PayloadDescription"] as? String, "Test envelope")

        let content = try XCTUnwrap(dict["PayloadContent"] as? [[String: Any]])
        XCTAssertEqual(content.count, 1)
        XCTAssertEqual(content[0]["PayloadType"] as? String, "com.apple.vpn.managed.applayer")
    }

    func testEnvelopeBinaryFormatAlsoSerializes() throws {
        let envelope = MobileConfigEnvelope(
            payloadIdentifier: "com.quantumlink.profile",
            payloadDisplayName: "QuantumLink Test",
            payloadOrganization: "QuantumLink",
            payloadContent: []
        )
        let binaryData = try envelope.serialize(format: .binary)
        XCTAssertFalse(binaryData.isEmpty)
        // Binary plist files start with "bplist".
        let prefix = binaryData.prefix(6)
        XCTAssertEqual(String(data: prefix, encoding: .ascii), "bplist")
    }

    func testEnvelopeOmitsDescriptionWhenNil() throws {
        let envelope = MobileConfigEnvelope(
            payloadIdentifier: "com.quantumlink.profile",
            payloadDisplayName: "QuantumLink Test",
            payloadOrganization: "QuantumLink",
            payloadContent: []
        )
        let dict = envelope.toPlistDictionary()
        XCTAssertNil(dict["PayloadDescription"])
    }
}
