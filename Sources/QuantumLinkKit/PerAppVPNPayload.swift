import Foundation
import Security

/// Errors raised while building a per-app VPN payload.
public enum PerAppVPNPayloadError: Error, Equatable, LocalizedError, Sendable {
    case bundleIdentifierEmpty
    case designatedRequirementEmpty
    case designatedRequirementInvalid(reason: String)
    case mappingsEmpty

    public var errorDescription: String? {
        switch self {
        case .bundleIdentifierEmpty:
            "Per-app VPN mapping requires a non-empty bundle identifier"
        case .designatedRequirementEmpty:
            "Per-app VPN mapping requires a non-empty designated requirement"
        case .designatedRequirementInvalid(let reason):
            "Per-app VPN mapping has an invalid designated requirement: \(reason)"
        case .mappingsEmpty:
            "A per-app VPN payload must contain at least one mapping"
        }
    }
}

/// One row in Apple's `AppLayerVPNMapping`. Identifies an app by its bundle
/// identifier and pins it to a code-signing requirement so that an
/// attacker can't drop a same-bundle-id binary into a managed Mac and
/// inherit the per-app VPN scope.
public struct PerAppVPNMapping: Codable, Equatable, Hashable, Sendable {
    public let bundleIdentifier: String
    /// Apple-format designated requirement string, e.g.
    /// `identifier "com.acme.app" and anchor apple generic and ...`.
    /// Validated against the Security framework's parser via
    /// `SecRequirementCreateWithString` — invalid strings are rejected at
    /// payload-construction time, not at deploy time.
    public let designatedRequirement: String

    public init(bundleIdentifier: String, designatedRequirement: String) throws {
        let trimmedBundle = bundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedBundle.isEmpty else {
            throw PerAppVPNPayloadError.bundleIdentifierEmpty
        }
        let trimmedRequirement = designatedRequirement
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedRequirement.isEmpty else {
            throw PerAppVPNPayloadError.designatedRequirementEmpty
        }
        try Self.validate(designatedRequirement: trimmedRequirement)
        self.bundleIdentifier = trimmedBundle
        self.designatedRequirement = trimmedRequirement
    }

    /// Renders this mapping as the dictionary Apple's per-app VPN payload
    /// expects under `AppLayerVPNMapping`.
    public func toPlistDictionary() -> [String: Any] {
        [
            "Identifier": bundleIdentifier,
            "SigningIdentifier": bundleIdentifier,
            "DesignatedRequirement": designatedRequirement,
        ]
    }

    /// Validates a designated requirement string by handing it to the
    /// Security framework's parser. Catches malformed syntax that
    /// would otherwise only surface when the configuration profile is
    /// deployed to a managed Mac.
    public static func validate(designatedRequirement: String) throws {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(
            designatedRequirement as CFString,
            [],
            &requirement
        )
        guard status == errSecSuccess else {
            let reason = SecCopyErrorMessageString(status, nil) as String?
                ?? "errSecStatus=\(status)"
            throw PerAppVPNPayloadError.designatedRequirementInvalid(reason: reason)
        }
    }
}

/// Apple's per-app VPN payload (`com.apple.vpn.managed.applayer`).
///
/// This payload binds a list of bundle-id-plus-designated-requirement
/// mappings to a parent VPN configuration via `vpnPayloadUUID`. Deploy
/// it inside a `MobileConfigEnvelope` alongside the corresponding
/// `com.apple.vpn.managed` payload so MDM has the matching VPN UUID to
/// activate per-app routing.
///
/// The payload is constructed by Swift code; deployment is gated on an
/// Apple Developer account (the configuration profile must be signed and
/// installed via MDM, both of which require credentials). The
/// construction logic is fully testable today.
public struct PerAppVPNPayload: Equatable, Hashable, Sendable {
    public let payloadIdentifier: String
    public let payloadUUID: UUID
    public let payloadDisplayName: String
    public let vpnPayloadUUID: UUID
    public let mappings: [PerAppVPNMapping]

    public init(
        payloadIdentifier: String,
        payloadUUID: UUID = UUID(),
        payloadDisplayName: String = "QuantumLink Per-App VPN Mapping",
        vpnPayloadUUID: UUID,
        mappings: [PerAppVPNMapping]
    ) throws {
        guard !mappings.isEmpty else {
            throw PerAppVPNPayloadError.mappingsEmpty
        }
        self.payloadIdentifier = payloadIdentifier
        self.payloadUUID = payloadUUID
        self.payloadDisplayName = payloadDisplayName
        self.vpnPayloadUUID = vpnPayloadUUID
        self.mappings = mappings
    }

    /// Renders the payload as Apple's documented dictionary shape. Slot
    /// the result into a `MobileConfigEnvelope`'s `payloadContent` to
    /// produce a deployable `.mobileconfig`.
    public func toPlistDictionary() -> [String: Any] {
        [
            "PayloadType": "com.apple.vpn.managed.applayer",
            "PayloadVersion": 1,
            "PayloadIdentifier": payloadIdentifier,
            "PayloadUUID": payloadUUID.uuidString,
            "PayloadDisplayName": payloadDisplayName,
            "VPNUUID": vpnPayloadUUID.uuidString,
            "AppLayerVPNMapping": mappings.map { $0.toPlistDictionary() },
        ]
    }
}
