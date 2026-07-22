import Foundation
import Security

/// Result of inspecting a code-signed binary on disk.
public struct CodeSigningInfo: Equatable, Sendable {
    /// Apple-format designated requirement string, suitable for slotting
    /// directly into a per-app VPN mapping or any other code-anchored
    /// security policy.
    public let designatedRequirement: String
    /// The signing identifier (the value the signature itself records).
    /// For most apps this matches the bundle identifier in `Info.plist`,
    /// but it doesn't have to — the DR's `identifier` clause refers to
    /// this value, not the bundle id.
    public let signingIdentifier: String?
    /// Apple Team Identifier (10-char alphanumeric). Nil for ad-hoc
    /// signatures or Apple platform binaries.
    public let teamIdentifier: String?
}

public enum CodeRequirementExtractorError: Error, LocalizedError {
    case createStaticCodeFailed(OSStatus)
    case unsigned
    case copyDesignatedRequirementFailed(OSStatus)
    case copyRequirementStringFailed(OSStatus)
    case copySigningInformationFailed(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .createStaticCodeFailed(let status):
            "SecStaticCodeCreateWithPath failed (\(status))"
        case .unsigned:
            "Binary at the supplied path is not code-signed"
        case .copyDesignatedRequirementFailed(let status):
            "SecCodeCopyDesignatedRequirement failed (\(status))"
        case .copyRequirementStringFailed(let status):
            "SecRequirementCopyString failed (\(status))"
        case .copySigningInformationFailed(let status):
            "SecCodeCopySigningInformation failed (\(status))"
        }
    }
}

/// Reads the designated-requirement string and signing-identity metadata
/// out of a code-signed binary on disk.
///
/// This wraps the Security-framework calls that ops would otherwise have
/// to invoke through `codesign -d -r-` and parse out by hand. Used by
/// `PerAppVPNMapping.fromInstalledApp(at:)` to build a per-app VPN
/// mapping straight from a `/Applications/*.app` URL.
public struct CodeRequirementExtractor {
    public init() {}

    /// Inspects the bundle / binary at `url` and returns its DR plus the
    /// signing identifier and team identifier. Throws if the path
    /// doesn't exist, isn't signed, or has a malformed signature.
    public func extract(at url: URL) throws -> CodeSigningInfo {
        var staticCodeOut: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            url as CFURL,
            SecCSFlags(rawValue: 0),
            &staticCodeOut
        )
        guard createStatus == errSecSuccess, let staticCode = staticCodeOut else {
            throw CodeRequirementExtractorError.createStaticCodeFailed(createStatus)
        }

        // Designated requirement → string.
        var requirementOut: SecRequirement?
        let drStatus = SecCodeCopyDesignatedRequirement(
            staticCode,
            SecCSFlags(rawValue: 0),
            &requirementOut
        )
        guard drStatus == errSecSuccess, let requirement = requirementOut else {
            // errSecCSUnsigned (-67062) is the canonical "not signed"
            // status. Surface a dedicated error so callers can give a
            // useful message instead of a raw OSStatus.
            if drStatus == errSecCSUnsigned {
                throw CodeRequirementExtractorError.unsigned
            }
            throw CodeRequirementExtractorError.copyDesignatedRequirementFailed(drStatus)
        }

        var requirementStringOut: CFString?
        let stringStatus = SecRequirementCopyString(
            requirement,
            SecCSFlags(rawValue: 0),
            &requirementStringOut
        )
        guard
            stringStatus == errSecSuccess,
            let drString = requirementStringOut as String?
        else {
            throw CodeRequirementExtractorError.copyRequirementStringFailed(stringStatus)
        }

        // Signing-info dictionary → identifier + team id.
        var infoOut: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &infoOut
        )
        guard infoStatus == errSecSuccess else {
            throw CodeRequirementExtractorError.copySigningInformationFailed(infoStatus)
        }
        let infoDict = (infoOut as? [String: Any]) ?? [:]

        let signingIdentifier = infoDict[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = infoDict[kSecCodeInfoTeamIdentifier as String] as? String

        return CodeSigningInfo(
            designatedRequirement: drString,
            signingIdentifier: signingIdentifier,
            teamIdentifier: teamIdentifier
        )
    }
}

extension PerAppVPNMapping {
    /// One-shot helper: read the signing identifier + designated
    /// requirement out of an installed app and produce a per-app VPN
    /// mapping. Eliminates the `codesign -d -r-` copy/paste step that
    /// ops would otherwise have to do.
    ///
    /// Throws `CodeRequirementExtractorError` if the bundle is missing
    /// or unsigned, and `PerAppVPNPayloadError` if the extracted DR
    /// itself is malformed (vanishingly unlikely for a real app, but
    /// the validation step is the same one that runs on hand-written
    /// DR strings, so the failure mode is uniform).
    public static func fromInstalledApp(at url: URL) throws -> PerAppVPNMapping {
        let info = try CodeRequirementExtractor().extract(at: url)
        guard let identifier = info.signingIdentifier, !identifier.isEmpty else {
            throw PerAppVPNPayloadError.bundleIdentifierEmpty
        }
        return try PerAppVPNMapping(
            bundleIdentifier: identifier,
            designatedRequirement: info.designatedRequirement
        )
    }
}
