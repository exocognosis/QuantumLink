import Foundation

/// Redaction policy applied to a `DiagnosticsBundle`.
///
/// `default` runs every string field through `PrivacyDefaults.redactNetworkIdentifiers`
/// and replaces address-shaped identifiers, DNS/FQDN endpoint names, URL hosts,
/// and Dytallix wallet/contract addresses with `[redacted-ip]`. Persistent mesh,
/// device, peer, and registry identifiers are also redacted because they can
/// correlate support bundles with Dytallix testnet activity and repeated mesh
/// sessions.
///
/// `raw` preserves every field verbatim. Operators must opt in explicitly —
/// the bundled UI surface defaults to `default` and an explicit "Export raw
/// diagnostics" action is required to switch.
public enum SupportBundleRedactionMode: String, Codable, Equatable, Sendable {
    case `default`
    case raw

    var redactsNetworkIdentifiers: Bool {
        self == .default
    }
}

/// A self-describing diagnostics export. Versioned so a future schema change
/// can add fields without breaking existing parsers.
///
/// Field-level privacy notes:
/// - `app`: build/version metadata. No PII by design.
/// - `tunnel`: enum-typed status fields plus a redactable `lastError`.
/// - `mesh`: numeric counters plus a redactable `lastError`. State and path
///   kind are encoded as ints from the FFI surface.
/// - `pump`: pure counters; never carries PII.
/// - `configuration`: counts of routes/servers and a redactable
///   `overlayIPv4Address`. The full lists of routes / rendezvous URLs /
///   relay URLs are deliberately omitted from the bundle — they contain
///   network identifiers that operators may not want to share.
public struct DiagnosticsBundle: Codable, Equatable, Sendable {
    public static let currentBundleVersion: String = "1"

    public let exportedAt: Date
    public let bundleVersion: String
    public let redactionMode: SupportBundleRedactionMode
    public let app: AppDiagnostics
    public let tunnel: TunnelDiagnostics?
    public let mesh: MeshDiagnostics?
    public let pump: PumpDiagnostics?
    public let peers: [PeerDiagnostics]
    public let blockedPeers: [BlockedPeerDiagnostics]
    public let configuration: ConfigurationDiagnostics

    public init(
        exportedAt: Date,
        redactionMode: SupportBundleRedactionMode,
        app: AppDiagnostics,
        tunnel: TunnelDiagnostics?,
        mesh: MeshDiagnostics?,
        pump: PumpDiagnostics?,
        peers: [PeerDiagnostics] = [],
        blockedPeers: [BlockedPeerDiagnostics] = [],
        configuration: ConfigurationDiagnostics
    ) {
        self.exportedAt = exportedAt
        self.bundleVersion = Self.currentBundleVersion
        self.redactionMode = redactionMode
        self.app = app
        self.tunnel = tunnel
        self.mesh = mesh
        self.pump = pump
        self.peers = peers
        self.blockedPeers = blockedPeers
        self.configuration = configuration
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.exportedAt = try container.decode(Date.self, forKey: .exportedAt)
        self.bundleVersion =
            try container.decodeIfPresent(String.self, forKey: .bundleVersion)
            ?? Self.currentBundleVersion
        self.redactionMode = try container.decode(
            SupportBundleRedactionMode.self,
            forKey: .redactionMode
        )
        self.app = try container.decode(AppDiagnostics.self, forKey: .app)
        self.tunnel = try container.decodeIfPresent(TunnelDiagnostics.self, forKey: .tunnel)
        self.mesh = try container.decodeIfPresent(MeshDiagnostics.self, forKey: .mesh)
        self.pump = try container.decodeIfPresent(PumpDiagnostics.self, forKey: .pump)
        self.peers = try container.decodeIfPresent([PeerDiagnostics].self, forKey: .peers) ?? []
        self.blockedPeers =
            try container.decodeIfPresent([BlockedPeerDiagnostics].self, forKey: .blockedPeers)
            ?? []
        self.configuration = try container.decode(
            ConfigurationDiagnostics.self,
            forKey: .configuration
        )
    }

    private enum CodingKeys: String, CodingKey {
        case exportedAt
        case bundleVersion
        case redactionMode
        case app
        case tunnel
        case mesh
        case pump
        case peers
        case blockedPeers
        case configuration
    }
}

public struct AppDiagnostics: Codable, Equatable, Sendable {
    public let appVersion: String
    public let bundleIdentifier: String?
    public let osVersion: String
    public let architecture: String
    public let isReleaseBuild: Bool

    public init(
        appVersion: String,
        bundleIdentifier: String?,
        osVersion: String,
        architecture: String,
        isReleaseBuild: Bool
    ) {
        self.appVersion = appVersion
        self.bundleIdentifier = bundleIdentifier
        self.osVersion = osVersion
        self.architecture = architecture
        self.isReleaseBuild = isReleaseBuild
    }
}

public struct TunnelDiagnostics: Codable, Equatable, Sendable {
    public let phase: String
    public let pathType: String
    public let routeMode: String
    public let dnsMode: String
    public let killSwitchPolicy: String
    public let dytallixTrustRequired: Bool
    public let dytallixTrustPolicy: String
    public let dytallixIdentityMode: String
    public let dytallixRegistryConfigured: Bool
    public let dytallixVerifiedPeerCount: Int
    public let dytallixUnverifiedPeerCount: Int
    public let dytallixPendingPeerCount: Int
    public let dytallixFailedPeerCount: Int
    public let isReady: Bool
    public let lastError: String?

    public init(
        phase: String,
        pathType: String,
        routeMode: String,
        dnsMode: String,
        killSwitchPolicy: String,
        dytallixTrustRequired: Bool = false,
        dytallixTrustPolicy: String = MeshTrustPolicy.developmentOptional.rawValue,
        dytallixIdentityMode: String = DiscoveryIdentityMode.off.rawValue,
        dytallixRegistryConfigured: Bool = false,
        dytallixVerifiedPeerCount: Int = 0,
        dytallixUnverifiedPeerCount: Int = 0,
        dytallixPendingPeerCount: Int = 0,
        dytallixFailedPeerCount: Int = 0,
        isReady: Bool,
        lastError: String?
    ) {
        self.phase = phase
        self.pathType = pathType
        self.routeMode = routeMode
        self.dnsMode = dnsMode
        self.killSwitchPolicy = killSwitchPolicy
        self.dytallixTrustRequired = dytallixTrustRequired
        self.dytallixTrustPolicy = dytallixTrustPolicy
        self.dytallixIdentityMode = dytallixIdentityMode
        self.dytallixRegistryConfigured = dytallixRegistryConfigured
        self.dytallixVerifiedPeerCount = dytallixVerifiedPeerCount
        self.dytallixUnverifiedPeerCount = dytallixUnverifiedPeerCount
        self.dytallixPendingPeerCount = dytallixPendingPeerCount
        self.dytallixFailedPeerCount = dytallixFailedPeerCount
        self.isReady = isReady
        self.lastError = lastError
    }
}

public struct MeshDiagnostics: Codable, Equatable, Sendable {
    public let stateCode: UInt32
    public let pathKindCode: UInt32
    public let framesSent: UInt64
    public let framesReceived: UInt64
    public let bytesSent: UInt64
    public let bytesReceived: UInt64
    public let sendFailures: UInt64
    public let receiveFailures: UInt64
    public let networkEventCount: UInt64
    public let reconnectCount: UInt64
    public let lastError: String?

    public init(
        stateCode: UInt32,
        pathKindCode: UInt32,
        framesSent: UInt64,
        framesReceived: UInt64,
        bytesSent: UInt64,
        bytesReceived: UInt64,
        sendFailures: UInt64,
        receiveFailures: UInt64,
        networkEventCount: UInt64,
        reconnectCount: UInt64,
        lastError: String?
    ) {
        self.stateCode = stateCode
        self.pathKindCode = pathKindCode
        self.framesSent = framesSent
        self.framesReceived = framesReceived
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.sendFailures = sendFailures
        self.receiveFailures = receiveFailures
        self.networkEventCount = networkEventCount
        self.reconnectCount = reconnectCount
        self.lastError = lastError
    }
}

public struct PumpDiagnostics: Codable, Equatable, Sendable {
    public let packetsObserved: UInt64
    public let queuedForTransport: UInt64
    public let droppedUnprotected: UInt64
    public let droppedFailClosed: UInt64
    public let droppedKillSwitch: UInt64
    public let failedSubmissions: UInt64
    public let transportFramesEmitted: UInt64
    public let transportFramesAccepted: UInt64
    public let failedInboundFrames: UInt64
    public let tunnelPacketsEmitted: UInt64
    /// Per-peer breakdown of `transportFramesAccepted`. Default mode aggregates
    /// these under `[redacted-id]`; raw mode emits the unredacted map verbatim.
    public let transportFramesAcceptedPerPeer: [String: UInt64]

    public init(from counters: PacketPumpCounters) {
        self.init(from: counters, redactionMode: .default)
    }

    public init(from counters: PacketPumpCounters, redactionMode: SupportBundleRedactionMode) {
        self.packetsObserved = counters.packetsObserved
        self.queuedForTransport = counters.queuedForTransport
        self.droppedUnprotected = counters.droppedUnprotected
        self.droppedFailClosed = counters.droppedFailClosed
        self.droppedKillSwitch = counters.droppedKillSwitch
        self.failedSubmissions = counters.failedSubmissions
        self.transportFramesEmitted = counters.transportFramesEmitted
        self.transportFramesAccepted = counters.transportFramesAccepted
        self.failedInboundFrames = counters.failedInboundFrames
        self.tunnelPacketsEmitted = counters.tunnelPacketsEmitted
        self.transportFramesAcceptedPerPeer =
            redactionMode.redactsNetworkIdentifiers
            ? Self.ephemeralPeerCounterMap(counters.transportFramesAcceptedPerPeer)
            : counters.transportFramesAcceptedPerPeer
    }

    private static func ephemeralPeerCounterMap(_ counters: [String: UInt64]) -> [String: UInt64] {
        Dictionary(
            uniqueKeysWithValues: counters
                .sorted { lhs, rhs in lhs.key < rhs.key }
                .enumerated()
                .map { index, element in
                    ("peer_\(index + 1)", element.value)
                }
        )
    }
}

public struct PeerDiagnostics: Codable, Equatable, Sendable {
    public let peerID: String
    public let alias: String
    public let pathType: String
    public let bytesIn: UInt64
    public let bytesOut: UInt64
    public let dytallixTrustState: String?
    public let dytallixTrustPolicy: String?
    public let dytallixIdentityMode: String?
    public let dytallixRegistryPeerID: String?
    public let dytallixTrustSource: String?
    public let dytallixFailureReason: String?

    public init(
        peerID: String,
        alias: String,
        pathType: String,
        bytesIn: UInt64,
        bytesOut: UInt64,
        dytallixTrustState: String?,
        dytallixTrustPolicy: String?,
        dytallixIdentityMode: String?,
        dytallixRegistryPeerID: String?,
        dytallixTrustSource: String?,
        dytallixFailureReason: String?
    ) {
        self.peerID = peerID
        self.alias = alias
        self.pathType = pathType
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.dytallixTrustState = dytallixTrustState
        self.dytallixTrustPolicy = dytallixTrustPolicy
        self.dytallixIdentityMode = dytallixIdentityMode
        self.dytallixRegistryPeerID = dytallixRegistryPeerID
        self.dytallixTrustSource = dytallixTrustSource
        self.dytallixFailureReason = dytallixFailureReason
    }
}

public struct BlockedPeerDiagnostics: Codable, Equatable, Sendable {
    public let peerID: String
    public let direction: String
    public let failureCode: UInt32
    public let failureReason: String
    public let observedAt: Date
    public let checkedAt: Date

    public init(
        peerID: String,
        direction: String,
        failureCode: UInt32,
        failureReason: String,
        observedAt: Date,
        checkedAt: Date
    ) {
        self.peerID = peerID
        self.direction = direction
        self.failureCode = failureCode
        self.failureReason = failureReason
        self.observedAt = observedAt
        self.checkedAt = checkedAt
    }
}

public struct ConfigurationDiagnostics: Codable, Equatable, Sendable {
    public let meshID: String
    public let deviceAlias: String
    public let overlayIPv4Address: String
    public let routeMode: String
    public let dnsMode: String
    public let killSwitchPolicy: String
    public let mtu: Int
    public let cryptoSuite: String
    public let protectedRoutesCount: Int
    public let excludedRoutesCount: Int
    public let rendezvousServersCount: Int
    public let relayServersCount: Int
    public let dnsServersCount: Int
    public let dnsSearchDomainsCount: Int

    public init(
        meshID: String,
        deviceAlias: String,
        overlayIPv4Address: String,
        routeMode: String,
        dnsMode: String,
        killSwitchPolicy: String,
        mtu: Int,
        cryptoSuite: String,
        protectedRoutesCount: Int,
        excludedRoutesCount: Int,
        rendezvousServersCount: Int,
        relayServersCount: Int,
        dnsServersCount: Int,
        dnsSearchDomainsCount: Int
    ) {
        self.meshID = meshID
        self.deviceAlias = deviceAlias
        self.overlayIPv4Address = overlayIPv4Address
        self.routeMode = routeMode
        self.dnsMode = dnsMode
        self.killSwitchPolicy = killSwitchPolicy
        self.mtu = mtu
        self.cryptoSuite = cryptoSuite
        self.protectedRoutesCount = protectedRoutesCount
        self.excludedRoutesCount = excludedRoutesCount
        self.rendezvousServersCount = rendezvousServersCount
        self.relayServersCount = relayServersCount
        self.dnsServersCount = dnsServersCount
        self.dnsSearchDomainsCount = dnsSearchDomainsCount
    }
}

/// Builds a privacy-respecting diagnostics bundle from the current app and
/// tunnel state.
///
/// Usage:
/// ```swift
/// let exporter = SupportBundleExporter()
/// let bundle = exporter.buildBundle(
///     status: meshController.status,
///     meshMetrics: nil,        // populated by the tunnel extension
///     meshLastError: nil,
///     pumpCounters: nil,       // populated by the tunnel extension
///     configuration: meshController.configuration,
///     redactionMode: .default
/// )
/// let json = try exporter.encode(bundle)
/// ```
///
/// The Swift app is the natural home for this code: it has access to
/// `TunnelStatus` (via the controller), `TunnelConfiguration`, and the OS
/// environment. The tunnel extension can also use it for snapshots that
/// include pump counters and live mesh-transport state. Either side
/// produces the same bundle shape, so support consumers see one consistent
/// schema.
public struct SupportBundleExporter: Sendable {
    private let now: @Sendable () -> Date
    private let osVersion: String
    private let architecture: String
    private let appVersion: String
    private let bundleIdentifier: String?
    private let isReleaseBuild: Bool

    public init(
        now: @Sendable @escaping () -> Date = { Date() },
        osVersion: String = SupportBundleExporter.currentOSVersion(),
        architecture: String = SupportBundleExporter.currentArchitecture(),
        appVersion: String = SupportBundleExporter.currentAppVersion(),
        bundleIdentifier: String? = Bundle.main.bundleIdentifier,
        isReleaseBuild: Bool = SupportBundleExporter.detectReleaseBuild()
    ) {
        self.now = now
        self.osVersion = osVersion
        self.architecture = architecture
        self.appVersion = appVersion
        self.bundleIdentifier = bundleIdentifier
        self.isReleaseBuild = isReleaseBuild
    }

    public func buildBundle(
        status: TunnelStatus?,
        meshMetrics: RustMeshTransportMetrics?,
        meshLastError: String?,
        pumpCounters: PacketPumpCounters?,
        configuration: TunnelConfiguration,
        blockedPeerHistory: [RustBlockedPeerHistoryEntry] = [],
        redactionMode: SupportBundleRedactionMode = .default
    ) -> DiagnosticsBundle {
        let app = AppDiagnostics(
            appVersion: appVersion,
            bundleIdentifier: bundleIdentifier,
            osVersion: osVersion,
            architecture: architecture,
            isReleaseBuild: isReleaseBuild
        )

        let tunnel = status.map { status -> TunnelDiagnostics in
            TunnelDiagnostics(
                phase: status.phase.rawValue,
                pathType: status.pathType.rawValue,
                routeMode: status.routeMode.rawValue,
                dnsMode: status.dnsMode.rawValue,
                killSwitchPolicy: configuration.killSwitch.rawValue,
                dytallixTrustRequired: status.peerTrust.required,
                dytallixTrustPolicy: status.peerTrust.policy.rawValue,
                dytallixIdentityMode: status.peerTrust.identityMode.rawValue,
                dytallixRegistryConfigured: status.peerTrust.registryConfigured,
                dytallixVerifiedPeerCount: status.peerTrust.verifiedPeerCount,
                dytallixUnverifiedPeerCount: status.peerTrust.unverifiedPeerCount,
                dytallixPendingPeerCount: status.peerTrust.pendingPeerCount,
                dytallixFailedPeerCount: status.peerTrust.failedPeerCount,
                isReady: status.phase == .connected,
                lastError: redactOptional(status.lastError, mode: redactionMode)
            )
        }

        let mesh = meshMetrics.map { metrics -> MeshDiagnostics in
            MeshDiagnostics(
                stateCode: metrics.stateCode,
                pathKindCode: metrics.pathKindCode,
                framesSent: metrics.framesSent,
                framesReceived: metrics.framesReceived,
                bytesSent: metrics.bytesSent,
                bytesReceived: metrics.bytesReceived,
                sendFailures: metrics.sendFailures,
                receiveFailures: metrics.receiveFailures,
                networkEventCount: metrics.networkEventCount,
                reconnectCount: metrics.reconnectCount,
                lastError: redactOptional(meshLastError, mode: redactionMode)
            )
        }

        let pump = pumpCounters.map {
            PumpDiagnostics(from: $0, redactionMode: redactionMode)
        }
        let peers = status?.peers.map { peer -> PeerDiagnostics in
            let trust = peer.dytallixTrust
            return PeerDiagnostics(
                peerID: redactIdentifier(peer.identity.peerID, mode: redactionMode),
                alias: redactIdentifier(peer.identity.alias, mode: redactionMode),
                pathType: peer.pathType.rawValue,
                bytesIn: peer.bytesIn,
                bytesOut: peer.bytesOut,
                dytallixTrustState: trust?.state.rawValue,
                dytallixTrustPolicy: trust?.policy.rawValue,
                dytallixIdentityMode: trust?.identityMode.rawValue,
                dytallixRegistryPeerID: redactOptionalIdentifier(
                    trust?.registryPeerID,
                    mode: redactionMode
                ),
                dytallixTrustSource: trust?.source,
                dytallixFailureReason: redactOptional(trust?.failureReason, mode: redactionMode)
            )
        } ?? []
        let blockedPeers = blockedPeerHistory.map { entry in
            BlockedPeerDiagnostics(
                peerID: redactIdentifier(entry.peerID, mode: redactionMode),
                direction: entry.direction,
                failureCode: entry.failureCode,
                failureReason: redactString(entry.failureReason, mode: redactionMode),
                observedAt: entry.observedAt,
                checkedAt: entry.checkedAt
            )
        }

        let configurationDiagnostics = ConfigurationDiagnostics(
            meshID: redactIdentifier(configuration.meshID, mode: redactionMode),
            deviceAlias: redactIdentifier(configuration.deviceAlias, mode: redactionMode),
            overlayIPv4Address: redactString(
                configuration.overlayIPv4Address,
                mode: redactionMode
            ),
            routeMode: configuration.routeMode.rawValue,
            dnsMode: configuration.dnsMode.rawValue,
            killSwitchPolicy: configuration.killSwitch.rawValue,
            mtu: configuration.mtu,
            cryptoSuite: configuration.crypto.suite,
            protectedRoutesCount: configuration.protectedRoutes.count,
            excludedRoutesCount: configuration.excludedRoutes.count,
            rendezvousServersCount: configuration.rendezvousServers.count,
            relayServersCount: configuration.relayServers.count,
            dnsServersCount: configuration.dnsServers.count,
            dnsSearchDomainsCount: configuration.dnsSearchDomains.count
        )

        return DiagnosticsBundle(
            exportedAt: now(),
            redactionMode: redactionMode,
            app: app,
            tunnel: tunnel,
            mesh: mesh,
            pump: pump,
            peers: peers,
            blockedPeers: blockedPeers,
            configuration: configurationDiagnostics
        )
    }

    public func encode(
        _ bundle: DiagnosticsBundle,
        prettyPrinted: Bool = true
    ) throws -> Data {
        let encoder = JSONEncoder()
        var formatting: JSONEncoder.OutputFormatting = [.sortedKeys]
        if prettyPrinted {
            formatting.insert(.prettyPrinted)
        }
        encoder.outputFormatting = formatting
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(bundle)
    }

    public func decode(_ data: Data) throws -> DiagnosticsBundle {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(DiagnosticsBundle.self, from: data)
    }

    private func redactOptional(
        _ value: String?,
        mode: SupportBundleRedactionMode
    ) -> String? {
        guard let value else { return nil }
        return redactString(value, mode: mode)
    }

    private func redactOptionalIdentifier(
        _ value: String?,
        mode: SupportBundleRedactionMode
    ) -> String? {
        guard let value else { return nil }
        return redactIdentifier(value, mode: mode)
    }

    private func redactIdentifier(
        _ value: String,
        mode: SupportBundleRedactionMode
    ) -> String {
        mode.redactsNetworkIdentifiers ? "[redacted-id]" : value
    }

    private func redactString(
        _ value: String,
        mode: SupportBundleRedactionMode
    ) -> String {
        mode.redactsNetworkIdentifiers
            ? PrivacyDefaults.redactNetworkIdentifiers(in: value)
            : value
    }
}

// MARK: - Environment helpers

extension SupportBundleExporter {
    public static func currentOSVersion() -> String {
        let info = ProcessInfo.processInfo.operatingSystemVersion
        return "\(info.majorVersion).\(info.minorVersion).\(info.patchVersion)"
    }

    public static func currentArchitecture() -> String {
#if arch(arm64)
        return "arm64"
#elseif arch(x86_64)
        return "x86_64"
#else
        return "unknown"
#endif
    }

    public static func currentAppVersion() -> String {
        if let short = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String {
            return short
        }
        return "unknown"
    }

    public static func detectReleaseBuild() -> Bool {
#if DEBUG
        return false
#else
        return true
#endif
    }
}
