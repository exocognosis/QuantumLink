import Foundation

#if canImport(NetworkExtension)
@preconcurrency import NetworkExtension
#endif

/// What the system should do when a rule's match conditions hold.
public enum OnDemandRuleAction: String, Codable, Equatable, Sendable, CaseIterable {
    case connect
    case disconnect
    case evaluateConnection
    case ignore

    /// Apple's wire string for the `Action` key in a configuration-profile
    /// payload. Note the casing exactly matches Apple's documented values.
    public var payloadValue: String {
        switch self {
        case .connect: "Connect"
        case .disconnect: "Disconnect"
        case .evaluateConnection: "EvaluateConnection"
        case .ignore: "Ignore"
        }
    }
}

/// Interface-type filters supported by `NEOnDemandRule.interfaceTypeMatch`
/// and the configuration-profile `InterfaceTypeMatch` key. Mirrors
/// `NEOnDemandRuleInterfaceType` minus `.any` (which is the absence of
/// a filter, not a value).
public enum OnDemandInterfaceType: String, Codable, Equatable, Sendable, CaseIterable {
    case wifi
    case ethernet
    case cellular

    public var payloadValue: String {
        switch self {
        case .wifi: "WiFi"
        case .ethernet: "Ethernet"
        case .cellular: "Cellular"
        }
    }
}

/// One match condition inside an on-demand rule. All match conditions on
/// a single rule are AND-ed together; multiple rules are evaluated in
/// order (first match wins).
public enum OnDemandRuleMatch: Equatable, Hashable, Sendable {
    /// Match by physical interface type (Wi-Fi, Ethernet, cellular).
    case interfaceType(OnDemandInterfaceType)
    /// Match when connected to one of the listed Wi-Fi SSIDs. Only
    /// applies when interfaceType is wifi.
    case ssid([String])
    /// Match when DNS search domains contain any of the listed entries.
    case dnsSearchDomain([String])
    /// Match when DNS server addresses include any of the listed entries.
    case dnsServerAddress([String])
    /// Match by probing a URL (system fetches it; rule fires on success).
    /// Use this for "are we behind the corporate captive portal yet?"
    case urlStringProbe(String)
}

/// A complete on-demand rule. Combine an action with zero or more match
/// conditions; an empty match list means "always match" (typical for a
/// final default rule like `.disconnect` with no conditions).
public struct OnDemandRule: Equatable, Hashable, Sendable {
    public let action: OnDemandRuleAction
    public let matches: [OnDemandRuleMatch]

    public init(action: OnDemandRuleAction, matches: [OnDemandRuleMatch] = []) {
        self.action = action
        self.matches = matches
    }

    /// Renders the rule as Apple's `OnDemandRules` array entry.
    public func toPlistDictionary() -> [String: Any] {
        var dict: [String: Any] = ["Action": action.payloadValue]

        // Apple's payload schema flattens match conditions: each match
        // type gets its own top-level key on the rule dict, not a nested
        // structure. Handle each match independently so callers who
        // pass mixed match types compose correctly.
        for match in matches {
            switch match {
            case .interfaceType(let type):
                dict["InterfaceTypeMatch"] = type.payloadValue
            case .ssid(let ssids):
                dict["SSIDMatch"] = ssids
            case .dnsSearchDomain(let domains):
                dict["DNSDomainMatch"] = domains
            case .dnsServerAddress(let addresses):
                dict["DNSServerAddressMatch"] = addresses
            case .urlStringProbe(let url):
                dict["URLStringProbe"] = url
            }
        }
        return dict
    }

    /// Renders an array of rules as the value to plug into a VPN
    /// payload's `OnDemandRules` key. The companion `OnDemandEnabled`
    /// flag should be set to `1` alongside.
    public static func plistArray(from rules: [OnDemandRule]) -> [[String: Any]] {
        rules.map { $0.toPlistDictionary() }
    }
}

#if canImport(NetworkExtension)

extension OnDemandRule {
    /// Constructs the matching `NEOnDemandRule` subclass for runtime
    /// application via `NETunnelProviderManager.onDemandRules`. Use this
    /// when configuring an unmanaged Mac (or during development); for
    /// managed deployments, prefer `toPlistDictionary()` and ship the
    /// rules through MDM.
    public func toNEOnDemandRule() -> NEOnDemandRule {
        let rule: NEOnDemandRule
        switch action {
        case .connect:
            rule = NEOnDemandRuleConnect()
        case .disconnect:
            rule = NEOnDemandRuleDisconnect()
        case .evaluateConnection:
            rule = NEOnDemandRuleEvaluateConnection()
        case .ignore:
            rule = NEOnDemandRuleIgnore()
        }

        var ssidMatch: [String]?
        var dnsSearchDomainMatch: [String]?
        var dnsServerAddressMatch: [String]?
        var probeURL: URL?
        var interfaceMatch: NEOnDemandRuleInterfaceType = .any

        for match in matches {
            switch match {
            case .interfaceType(let type):
                switch type {
                case .wifi: interfaceMatch = .wiFi
                case .ethernet: interfaceMatch = .ethernet
                case .cellular:
                    // `NEOnDemandRuleInterfaceType.cellular` is iOS-only;
                    // on macOS the symbol is `@available(macOS, unavailable)`.
                    // Macs don't have a cellular interface (in the
                    // NetworkExtension model), so fall back to `.any` —
                    // the payload-format `InterfaceTypeMatch` value still
                    // emits "Cellular" correctly for iOS deployments via
                    // `toPlistDictionary()`.
                    #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
                    interfaceMatch = .cellular
                    #else
                    interfaceMatch = .any
                    #endif
                }
            case .ssid(let ssids):
                ssidMatch = ssids
            case .dnsSearchDomain(let domains):
                dnsSearchDomainMatch = domains
            case .dnsServerAddress(let addresses):
                dnsServerAddressMatch = addresses
            case .urlStringProbe(let url):
                probeURL = URL(string: url)
            }
        }

        rule.interfaceTypeMatch = interfaceMatch
        rule.ssidMatch = ssidMatch
        rule.dnsSearchDomainMatch = dnsSearchDomainMatch
        rule.dnsServerAddressMatch = dnsServerAddressMatch
        rule.probeURL = probeURL
        return rule
    }
}

#endif

/// VPN On Demand can also be expressed as a payload that *replaces* the
/// `OnDemandEnabled` and `OnDemandRules` keys inside a `com.apple.vpn.managed`
/// payload. This struct captures that fragment for callers building a
/// VPN payload by hand.
public struct OnDemandPayloadFragment: Sendable {
    public let enabled: Bool
    public let rules: [OnDemandRule]

    public init(enabled: Bool = true, rules: [OnDemandRule]) {
        self.enabled = enabled
        self.rules = rules
    }

    /// Returns the dictionary keys / values to merge into a VPN payload.
    public func plistKeys() -> [String: Any] {
        [
            "OnDemandEnabled": enabled ? 1 : 0,
            "OnDemandRules": OnDemandRule.plistArray(from: rules),
        ]
    }
}
