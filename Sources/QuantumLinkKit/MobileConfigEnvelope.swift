import Foundation

/// Shapes a top-level Apple `.mobileconfig` Configuration profile.
///
/// A configuration profile is a property list containing a top-level
/// `PayloadType=Configuration` dictionary plus a `PayloadContent` array
/// of inner payload dictionaries. Each inner payload is something like a
/// VPN payload, a per-app VPN payload, an SSO payload, or an extension
/// preapproval payload.
///
/// This envelope is the construction-time companion to the
/// `macos/mdm/*.mobileconfig.template` files in the repo: where the
/// templates are static text with placeholders, this lets us assemble
/// envelopes programmatically — useful for embedding into install
/// scripts, MDM delivery pipelines, and tests.
// Not Sendable: `[String: Any]` is intrinsically not Sendable, and Apple's
// plist shape is heterogeneous by design (strings, numbers, arrays, nested
// dicts). Construct + serialize on the same actor; pass `Data` across
// boundaries instead of the envelope.
public struct MobileConfigEnvelope {
    public let payloadIdentifier: String
    public let payloadUUID: UUID
    public let payloadDisplayName: String
    public let payloadOrganization: String
    public let payloadContent: [[String: Any]]
    public let payloadDescription: String?

    public init(
        payloadIdentifier: String,
        payloadUUID: UUID = UUID(),
        payloadDisplayName: String,
        payloadOrganization: String,
        payloadContent: [[String: Any]],
        payloadDescription: String? = nil
    ) {
        self.payloadIdentifier = payloadIdentifier
        self.payloadUUID = payloadUUID
        self.payloadDisplayName = payloadDisplayName
        self.payloadOrganization = payloadOrganization
        self.payloadContent = payloadContent
        self.payloadDescription = payloadDescription
    }

    /// Renders the top-level dictionary that Apple expects for a
    /// configuration profile.
    public func toPlistDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": payloadIdentifier,
            "PayloadUUID": payloadUUID.uuidString,
            "PayloadDisplayName": payloadDisplayName,
            "PayloadOrganization": payloadOrganization,
            "PayloadContent": payloadContent,
        ]
        if let payloadDescription {
            dict["PayloadDescription"] = payloadDescription
        }
        return dict
    }

    /// Serializes the envelope to a property-list `Data` blob suitable for
    /// writing to a `.mobileconfig` file. Defaults to XML format because
    /// MDM consoles and the `profiles` CLI both prefer that for
    /// inspection; choose `.binary` for compactness when only machines
    /// will read the file.
    public func serialize(format: PropertyListSerialization.PropertyListFormat = .xml) throws -> Data {
        try PropertyListSerialization.data(
            fromPropertyList: toPlistDictionary(),
            format: format,
            options: 0
        )
    }
}
