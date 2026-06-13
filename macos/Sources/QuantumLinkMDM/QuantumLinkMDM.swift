import Darwin
import Foundation
import QuantumLinkKit

/// `QuantumLinkMDM` — command-line frontend for the configuration-profile
/// pipeline. Glues `PerAppVPNMapping.fromInstalledApp(at:)` →
/// `PerAppVPNPayload` → `MobileConfigEnvelope.serialize` →
/// `MobileConfigSigner.sign(_:with:)` so ops can produce a deployable
/// signed `.mobileconfig` from the shell.
///
/// Subcommands:
///   build-perapp   Per-app VPN profile (one or more app paths → DR-pinned mapping)
///   build-ondemand VPN On Demand profile (SSID/DNS/probe match conditions)
///
/// Exit codes:
///   0  success
///   1  user error (bad input, missing file, validation failure)
///   2  unknown subcommand / usage error
@main
enum QuantumLinkMDM {
    static func main() {
        Darwin.exit(run())
    }

    static func run() -> Int32 {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let command = arguments.first else {
            printUsage()
            return 2
        }

        switch command {
        case "build-perapp":
            return runBuildPerApp(arguments: Array(arguments.dropFirst()))
        case "build-ondemand":
            return runBuildOnDemand(arguments: Array(arguments.dropFirst()))
        case "help", "--help", "-h":
            printUsage()
            return 0
        default:
            fputs("Unknown subcommand: \(command)\n", stderr)
            printUsage()
            return 2
        }
    }

    private static func printUsage() {
        let usage = """
        Usage: QuantumLinkMDM <subcommand> [options]

        Subcommands:
          build-perapp     Build a per-app VPN configuration profile.
          build-ondemand   Build a VPN On Demand configuration profile.

        Common options:
          --payload-identifier <id>      Reverse-DNS identifier for the profile (required).
          --display-name <name>          Human-readable profile name (required).
          --organization <org>           Organization name shown in install dialog (required).
          --vpn-payload-uuid <uuid>      UUID of the parent VPN payload (required).
          --signing-p12 <path>           Path to PKCS#12 file with signing identity (required).
          --signing-passphrase-env <var> Env var holding the .p12 passphrase (default: QLINK_P12_PASS).
          --output <path>                Output .mobileconfig path (required).

        build-perapp options:
          --apps <p1,p2,...>             Comma-separated paths to installed .app bundles (required).

        build-ondemand options:
          --action <connect|disconnect|evaluate|ignore>
                                          Action when match conditions hold (default: connect).
          --ssid <s1,s2,...>             SSIDs that trigger this rule (Wi-Fi only).
          --dns-domain <d1,d2,...>       DNS search domains that trigger this rule.
          --dns-server <a1,a2,...>       DNS server addresses that trigger this rule.
          --probe-url <url>              URL probe; rule fires on successful fetch.
          --interface <wifi|ethernet|cellular>
                                          Interface-type filter for the match.
        """
        print(usage)
    }

    // MARK: build-perapp

    private static func runBuildPerApp(arguments: [String]) -> Int32 {
        do {
            let opts = try BuildPerAppOptions(arguments: arguments)
            let mappings = try opts.appPaths.map { path -> PerAppVPNMapping in
                let url = URL(fileURLWithPath: path)
                guard FileManager.default.fileExists(atPath: url.path) else {
                    throw CLIError.appNotFound(path)
                }
                return try PerAppVPNMapping.fromInstalledApp(at: url)
            }
            let common = opts.commonSigning
            let payload = try PerAppVPNPayload(
                payloadIdentifier: common.payloadIdentifier + ".applayer",
                payloadDisplayName: common.displayName,
                vpnPayloadUUID: common.vpnPayloadUUID,
                mappings: mappings
            )
            let envelope = MobileConfigEnvelope(
                payloadIdentifier: common.payloadIdentifier,
                payloadDisplayName: common.displayName,
                payloadOrganization: common.organization,
                payloadContent: [payload.toPlistDictionary()],
                payloadDescription: "QuantumLink per-app VPN mapping for "
                    + "\(mappings.count) app(s)"
            )
            try emitSignedProfile(envelope: envelope, opts: opts.commonSigning)

            for mapping in mappings {
                fputs(
                    "mapped \(mapping.bundleIdentifier) -> "
                    + "\(mapping.designatedRequirement.prefix(80))\n",
                    stderr
                )
            }
            fputs("wrote signed profile -> \(opts.commonSigning.outputPath)\n", stderr)
            return 0
        } catch {
            fputs("build-perapp failed: \(localizedMessage(error))\n", stderr)
            return error is CLIUsageError ? 2 : 1
        }
    }

    // MARK: build-ondemand

    private static func runBuildOnDemand(arguments: [String]) -> Int32 {
        do {
            let opts = try BuildOnDemandOptions(arguments: arguments)
            let rule = OnDemandRule(action: opts.action, matches: opts.matches)
            // A trailing default-disconnect rule means "if nothing matched
            // the user-supplied conditions, don't bring the tunnel up." It's
            // the conventional shape for a single-rule on-demand profile.
            let trailingDefault = OnDemandRule(action: .disconnect)
            let fragment = OnDemandPayloadFragment(
                enabled: true,
                rules: [rule, trailingDefault]
            )

            // The on-demand keys live under a VPN payload — produce a
            // minimal stub VPN payload that carries them. The downstream
            // MDM should layer this over the real VPN payload it owns;
            // this CLI is not the place to invent a full VPN payload.
            var vpnPayload: [String: Any] = [
                "PayloadType": "com.apple.vpn.managed",
                "PayloadVersion": 1,
                "PayloadIdentifier": opts.commonSigning.payloadIdentifier + ".vpn",
                "PayloadUUID": opts.commonSigning.vpnPayloadUUID.uuidString,
                "PayloadDisplayName": opts.commonSigning.displayName,
                "UserDefinedName": opts.commonSigning.displayName,
            ]
            for (key, value) in fragment.plistKeys() {
                vpnPayload[key] = value
            }

            let envelope = MobileConfigEnvelope(
                payloadIdentifier: opts.commonSigning.payloadIdentifier,
                payloadDisplayName: opts.commonSigning.displayName,
                payloadOrganization: opts.commonSigning.organization,
                payloadContent: [vpnPayload],
                payloadDescription: "QuantumLink VPN On Demand rule "
                    + "(\(rule.matches.count) match condition(s))"
            )
            try emitSignedProfile(envelope: envelope, opts: opts.commonSigning)
            fputs(
                "on-demand action=\(opts.action.rawValue), match-count=\(rule.matches.count)\n",
                stderr
            )
            fputs("wrote signed profile -> \(opts.commonSigning.outputPath)\n", stderr)
            return 0
        } catch {
            fputs("build-ondemand failed: \(localizedMessage(error))\n", stderr)
            return error is CLIUsageError ? 2 : 1
        }
    }

    // MARK: signing

    private static func emitSignedProfile(
        envelope: MobileConfigEnvelope,
        opts: CommonSigningOptions
    ) throws {
        let xml = try envelope.serialize(format: .xml)
        let identity = try PKCS12IdentityLoader.loadIdentity(
            from: opts.signingP12URL,
            passphrase: opts.passphrase
        )
        let signer = MobileConfigSigner()
        let signed = try signer.sign(xml, with: identity)

        // Belt-and-braces: round-trip the signed bytes back through the
        // verifier before writing. Catches "signed something that won't
        // re-parse" (e.g. a PropertyListSerialization regression on a
        // weird input shape) at build time, not deploy time.
        let verification = try signer.verify(signed)
        guard verification.signerStatus == .valid else {
            throw CLIError.selfVerificationFailed(verification.signerStatus)
        }
        guard verification.payload == xml else {
            throw CLIError.selfVerificationPayloadMismatch
        }

        let outputURL = URL(fileURLWithPath: opts.outputPath)
        try writeAtomically(signed, to: outputURL)
    }

    private static func writeAtomically(_ data: Data, to url: URL) throws {
        let tempURL = url
            .deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).tmp.\(UUID().uuidString)")
        try data.write(to: tempURL, options: [.atomic])
        // Replace any existing file (Foundation's atomic write already
        // handles the same-path case, but we wrote to a side path so we
        // can preserve the original on failure).
        if FileManager.default.fileExists(atPath: url.path) {
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tempURL)
        } else {
            try FileManager.default.moveItem(at: tempURL, to: url)
        }
    }

    private static func localizedMessage(_ error: Swift.Error) -> String {
        if let localized = error as? LocalizedError, let desc = localized.errorDescription {
            return desc
        }
        return "\(error)"
    }
}

// MARK: - Argument parsing

private protocol CLIUsageError: Swift.Error {}

private enum CLIError: Swift.Error, LocalizedError {
    case appNotFound(String)
    case selfVerificationFailed(CMSSignerStatus)
    case selfVerificationPayloadMismatch

    var errorDescription: String? {
        switch self {
        case .appNotFound(let path):
            "App bundle not found at \(path)"
        case .selfVerificationFailed(let status):
            "Self-verification of signed profile failed (signer status=\(status.rawValue))"
        case .selfVerificationPayloadMismatch:
            "Self-verification of signed profile failed (payload bytes mismatch)"
        }
    }
}

private enum ArgumentError: Swift.Error, CLIUsageError, LocalizedError {
    case missing(String)
    case invalidUUID(String)
    case invalidAction(String)
    case invalidInterface(String)
    case noOnDemandMatchesSupplied

    var errorDescription: String? {
        switch self {
        case .missing(let flag):
            "Missing required argument: --\(flag)"
        case .invalidUUID(let value):
            "Invalid UUID: \(value)"
        case .invalidAction(let value):
            "Invalid --action value: \(value) (use connect|disconnect|evaluate|ignore)"
        case .invalidInterface(let value):
            "Invalid --interface value: \(value) (use wifi|ethernet|cellular)"
        case .noOnDemandMatchesSupplied:
            "build-ondemand needs at least one match condition "
            + "(--ssid, --dns-domain, --dns-server, --probe-url, or --interface)"
        }
    }
}

private struct CommonSigningOptions {
    let payloadIdentifier: String
    let displayName: String
    let organization: String
    let vpnPayloadUUID: UUID
    let signingP12URL: URL
    let passphrase: String
    let outputPath: String
}

private struct BuildPerAppOptions {
    let appPaths: [String]
    let commonSigning: CommonSigningOptions

    init(arguments: [String]) throws {
        let parsed = ArgumentMap(arguments)
        guard let appsCSV = parsed["apps"] else {
            throw ArgumentError.missing("apps")
        }
        appPaths = appsCSV.split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        commonSigning = try CommonSigningOptions(parsed: parsed)
    }
}

private struct BuildOnDemandOptions {
    let action: OnDemandRuleAction
    let matches: [OnDemandRuleMatch]
    let commonSigning: CommonSigningOptions

    init(arguments: [String]) throws {
        let parsed = ArgumentMap(arguments)
        action = try parseAction(parsed["action"] ?? "connect")

        var matches: [OnDemandRuleMatch] = []
        if let interfaceRaw = parsed["interface"] {
            matches.append(.interfaceType(try parseInterface(interfaceRaw)))
        }
        if let ssidsCSV = parsed["ssid"] {
            matches.append(.ssid(splitCSV(ssidsCSV)))
        }
        if let domainsCSV = parsed["dns-domain"] {
            matches.append(.dnsSearchDomain(splitCSV(domainsCSV)))
        }
        if let serversCSV = parsed["dns-server"] {
            matches.append(.dnsServerAddress(splitCSV(serversCSV)))
        }
        if let probeURL = parsed["probe-url"] {
            matches.append(.urlStringProbe(probeURL))
        }
        guard !matches.isEmpty else {
            throw ArgumentError.noOnDemandMatchesSupplied
        }
        self.matches = matches
        commonSigning = try CommonSigningOptions(parsed: parsed)
    }
}

private func parseAction(_ raw: String) throws -> OnDemandRuleAction {
    switch raw {
    case "connect": return .connect
    case "disconnect": return .disconnect
    case "evaluate", "evaluateConnection": return .evaluateConnection
    case "ignore": return .ignore
    default: throw ArgumentError.invalidAction(raw)
    }
}

private func parseInterface(_ raw: String) throws -> OnDemandInterfaceType {
    switch raw {
    case "wifi", "wiFi", "WiFi": return .wifi
    case "ethernet", "Ethernet": return .ethernet
    case "cellular", "Cellular": return .cellular
    default: throw ArgumentError.invalidInterface(raw)
    }
}

private func splitCSV(_ s: String) -> [String] {
    s.split(separator: ",")
        .map { String($0).trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty }
}

extension CommonSigningOptions {
    init(parsed: ArgumentMap) throws {
        guard let payloadIdentifier = parsed["payload-identifier"] else {
            throw ArgumentError.missing("payload-identifier")
        }
        guard let displayName = parsed["display-name"] else {
            throw ArgumentError.missing("display-name")
        }
        guard let organization = parsed["organization"] else {
            throw ArgumentError.missing("organization")
        }
        guard let uuidRaw = parsed["vpn-payload-uuid"] else {
            throw ArgumentError.missing("vpn-payload-uuid")
        }
        guard let uuid = UUID(uuidString: uuidRaw) else {
            throw ArgumentError.invalidUUID(uuidRaw)
        }
        guard let p12 = parsed["signing-p12"] else {
            throw ArgumentError.missing("signing-p12")
        }
        guard let output = parsed["output"] else {
            throw ArgumentError.missing("output")
        }
        let envVar = parsed["signing-passphrase-env"] ?? "QLINK_P12_PASS"
        let passphrase = ProcessInfo.processInfo.environment[envVar] ?? ""

        self.payloadIdentifier = payloadIdentifier
        self.displayName = displayName
        self.organization = organization
        self.vpnPayloadUUID = uuid
        self.signingP12URL = URL(fileURLWithPath: p12)
        self.passphrase = passphrase
        self.outputPath = output
    }
}

/// Tiny `--key value` argument parser. Doesn't support combined short
/// flags or `=` separators; CLI inputs here are scripted from MDM build
/// pipelines, not typed by hand, so the simple shape is fine.
private struct ArgumentMap {
    private let map: [String: String]

    init(_ arguments: [String]) {
        var pairs: [String: String] = [:]
        var index = 0
        while index < arguments.count {
            let token = arguments[index]
            if token.hasPrefix("--"), index + 1 < arguments.count {
                let key = String(token.dropFirst(2))
                pairs[key] = arguments[index + 1]
                index += 2
            } else {
                index += 1
            }
        }
        self.map = pairs
    }

    subscript(key: String) -> String? { map[key] }
}
