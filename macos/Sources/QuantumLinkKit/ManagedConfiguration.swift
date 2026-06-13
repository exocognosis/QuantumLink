import Foundation

/// Reads the dictionary delivered to the app under the
/// `com.apple.configuration.managed` UserDefaults key — Apple's standard
/// AppConfig delivery channel for MDM-managed apps — and overlays it on top
/// of a user-provided `TunnelConfiguration`.
///
/// Supported keys (all optional):
///   - `meshID`, `deviceAlias`, `tunnelRemoteAddress`: strings
///   - `protectedRoutes`, `excludedRoutes`, `dnsServers`, `dnsSearchDomains`,
///     `rendezvousServers`, `relayServers`: arrays of strings
///   - `routeMode`: `splitTunnel` | `protectedPrefixesOnly` | `fullTunnel`
///   - `dnsMode`: `tunnelProvided` | `system` | `disabled`
///   - `killSwitch`: `failClosed` | `strict`
///   - `mtu`: integer
///
/// Anything else is ignored. Values that cannot be parsed are dropped silently
/// and recorded in `unrecognizedKeys`/`rejectedKeys` for diagnostic surfacing.
public struct ManagedConfigurationOverride: Equatable, Sendable {
    public let configuration: TunnelConfiguration
    public let appliedKeys: [String]
    public let rejectedKeys: [String]
    public let isManaged: Bool

    public init(
        configuration: TunnelConfiguration,
        appliedKeys: [String],
        rejectedKeys: [String],
        isManaged: Bool
    ) {
        self.configuration = configuration
        self.appliedKeys = appliedKeys
        self.rejectedKeys = rejectedKeys
        self.isManaged = isManaged
    }
}

public enum ManagedConfigurationLoader {
    public static let managedConfigurationKey = "com.apple.configuration.managed"

    public static func apply(
        managed: [String: Any]?,
        to base: TunnelConfiguration
    ) -> ManagedConfigurationOverride {
        guard let managed, !managed.isEmpty else {
            return ManagedConfigurationOverride(
                configuration: base,
                appliedKeys: [],
                rejectedKeys: [],
                isManaged: false
            )
        }

        var meshID = base.meshID
        var deviceAlias = base.deviceAlias
        var tunnelRemoteAddress = base.tunnelRemoteAddress
        var protectedRoutes = base.protectedRoutes
        var excludedRoutes = base.excludedRoutes
        var dnsServers = base.dnsServers
        var dnsSearchDomains = base.dnsSearchDomains
        var rendezvousServers = base.rendezvousServers
        var relayServers = base.relayServers
        var routeMode = base.routeMode
        var dnsMode = base.dnsMode
        var killSwitch = base.killSwitch
        var mtu = base.mtu

        var applied: [String] = []
        var rejected: [String] = []

        for (key, value) in managed {
            switch key {
            case "meshID":
                if let stringValue = value as? String, !stringValue.isEmpty {
                    meshID = stringValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "deviceAlias":
                if let stringValue = value as? String, !stringValue.isEmpty {
                    deviceAlias = stringValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "tunnelRemoteAddress":
                if let stringValue = value as? String, !stringValue.isEmpty {
                    tunnelRemoteAddress = stringValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "protectedRoutes":
                if let arrayValue = value as? [String] {
                    protectedRoutes = arrayValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "excludedRoutes":
                if let arrayValue = value as? [String] {
                    excludedRoutes = arrayValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "dnsServers":
                if let arrayValue = value as? [String] {
                    dnsServers = arrayValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "dnsSearchDomains":
                if let arrayValue = value as? [String] {
                    dnsSearchDomains = arrayValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "rendezvousServers":
                if let arrayValue = value as? [String] {
                    rendezvousServers = arrayValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "relayServers":
                if let arrayValue = value as? [String] {
                    relayServers = arrayValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "routeMode":
                if let stringValue = value as? String,
                   let parsed = RouteMode(rawValue: stringValue) {
                    routeMode = parsed
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "dnsMode":
                if let stringValue = value as? String,
                   let parsed = DNSMode(rawValue: stringValue) {
                    dnsMode = parsed
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "killSwitch":
                if let stringValue = value as? String,
                   let parsed = KillSwitchPolicy(rawValue: stringValue) {
                    killSwitch = parsed
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            case "mtu":
                if let intValue = value as? Int, intValue >= 576 {
                    mtu = intValue
                    applied.append(key)
                } else {
                    rejected.append(key)
                }
            default:
                rejected.append(key)
            }
        }

        let merged = TunnelConfiguration(
            meshID: meshID,
            deviceAlias: deviceAlias,
            overlayIPv4Address: base.overlayIPv4Address,
            tunnelRemoteAddress: tunnelRemoteAddress,
            protectedRoutes: protectedRoutes,
            excludedRoutes: excludedRoutes,
            dnsServers: dnsServers,
            dnsSearchDomains: dnsSearchDomains,
            routeMode: routeMode,
            dnsMode: dnsMode,
            discoveryModes: base.discoveryModes,
            rendezvousServers: rendezvousServers,
            relayServers: relayServers,
            mtu: mtu,
            crypto: base.crypto,
            killSwitch: killSwitch
        )

        return ManagedConfigurationOverride(
            configuration: merged,
            appliedKeys: applied.sorted(),
            rejectedKeys: rejected.sorted(),
            isManaged: !applied.isEmpty
        )
    }

    /// Convenience: read managed config from `UserDefaults.standard` and merge.
    public static func currentManagedOverride(
        base: TunnelConfiguration,
        defaults: UserDefaults = .standard
    ) -> ManagedConfigurationOverride {
        let managed = defaults.dictionary(forKey: managedConfigurationKey)
        return apply(managed: managed, to: base)
    }
}
