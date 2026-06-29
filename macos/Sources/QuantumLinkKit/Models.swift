import Foundation

public enum ConnectionPhase: String, Codable, CaseIterable, Sendable {
    case idle
    case preparing
    case connecting
    case connected
    case degraded
    case reconnecting
    case disconnected
    case failed
}

public enum PathType: String, Codable, CaseIterable, Sendable {
    case direct
    case relay
    case probing
    case unavailable
}

public enum RouteMode: String, Codable, CaseIterable, Sendable {
    case splitTunnel
    case protectedPrefixesOnly
    case fullTunnel
}

public enum DNSMode: String, Codable, CaseIterable, Sendable {
    case tunnelProvided
    case system
    case disabled
}

public enum DiscoveryMode: String, Codable, CaseIterable, Sendable {
    case rendezvous
    case privateDHT
    case localMDNS
}

public enum MeshTrustPolicy: String, Codable, CaseIterable, Sendable {
    case publicRequired
    case privatePreferred
    case developmentOptional
}

public enum DiscoveryIdentityMode: String, Codable, CaseIterable, Sendable {
    case off
    case verified
    case publicWallet
}

public struct DytallixRegistryConfiguration: Codable, Equatable, Sendable {
    public let endpoint: String
    public let contractAddress: String
    public let keystorePath: String?
    public let walletName: String?
    public let networkID: String?
    public let chainID: String?
    public let allowedRPCEndpoints: [String]

    public init(
        endpoint: String,
        contractAddress: String,
        keystorePath: String? = nil,
        walletName: String? = nil,
        networkID: String? = nil,
        chainID: String? = nil,
        allowedRPCEndpoints: [String] = []
    ) {
        self.endpoint = endpoint
        self.contractAddress = contractAddress
        self.keystorePath = keystorePath
        self.walletName = walletName
        self.networkID = networkID
        self.chainID = chainID
        self.allowedRPCEndpoints = allowedRPCEndpoints
    }

    private enum CodingKeys: String, CodingKey {
        case endpoint
        case contractAddress
        case keystorePath
        case walletName
        case networkID = "networkId"
        case chainID = "chainId"
        case allowedRPCEndpoints = "allowedRpcEndpoints"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.endpoint = try container.decode(String.self, forKey: .endpoint)
        self.contractAddress = try container.decode(String.self, forKey: .contractAddress)
        self.keystorePath = try container.decodeIfPresent(String.self, forKey: .keystorePath)
        self.walletName = try container.decodeIfPresent(String.self, forKey: .walletName)
        self.networkID = try container.decodeIfPresent(String.self, forKey: .networkID)
        self.chainID = try container.decodeIfPresent(String.self, forKey: .chainID)
        self.allowedRPCEndpoints =
            try container.decodeIfPresent([String].self, forKey: .allowedRPCEndpoints) ?? []
    }
}

public struct DytallixIdentityConfiguration: Codable, Equatable, Sendable {
    public let trustPolicy: MeshTrustPolicy
    public let mode: DiscoveryIdentityMode
    public let registry: DytallixRegistryConfiguration?

    public init(
        trustPolicy: MeshTrustPolicy,
        mode: DiscoveryIdentityMode,
        registry: DytallixRegistryConfiguration? = nil
    ) {
        self.trustPolicy = trustPolicy
        self.mode = mode
        self.registry = registry
    }
}

/// Defines how the tunnel behaves when the data plane cannot protect a packet.
///
/// `failClosed` (default): traffic for protected prefixes is dropped at the
/// packet pump whenever the transport is not ready. The OS keeps protected
/// routes pointed at the tunnel, so plaintext packets cannot leak to the
/// default interface even when the transport is degraded.
///
/// `strict`: same as `failClosed`, plus the tunnel refuses to start at all if
/// the transport cannot establish during `startTunnel`. Use on managed Macs
/// where a half-up tunnel is worse than no tunnel.
public enum KillSwitchPolicy: String, Codable, CaseIterable, Sendable {
    case failClosed
    case strict
}

public struct PeerIdentity: Codable, Hashable, Identifiable, Sendable {
    public var id: String { peerID }
    public let peerID: String
    public let alias: String
    public let publicKeyFingerprint: String

    public init(peerID: String, alias: String, publicKeyFingerprint: String) {
        self.peerID = peerID
        self.alias = alias
        self.publicKeyFingerprint = publicKeyFingerprint
    }
}

public struct PeerEndpoint: Codable, Hashable, Sendable {
    public let candidateType: String
    public let address: String
    public let port: Int
    public let priority: Int

    public init(candidateType: String, address: String, port: Int, priority: Int) {
        self.candidateType = candidateType
        self.address = address
        self.port = port
        self.priority = priority
    }
}

public struct PeerStatus: Codable, Hashable, Identifiable, Sendable {
    public var id: String { identity.peerID }
    public let identity: PeerIdentity
    public let pathType: PathType
    public let endpoints: [PeerEndpoint]
    public let overlayAddress: String
    public let rttMilliseconds: Int?
    public let lastRekey: Date?
    public let bytesIn: UInt64
    public let bytesOut: UInt64

    public init(
        identity: PeerIdentity,
        pathType: PathType,
        endpoints: [PeerEndpoint],
        overlayAddress: String,
        rttMilliseconds: Int?,
        lastRekey: Date?,
        bytesIn: UInt64,
        bytesOut: UInt64
    ) {
        self.identity = identity
        self.pathType = pathType
        self.endpoints = endpoints
        self.overlayAddress = overlayAddress
        self.rttMilliseconds = rttMilliseconds
        self.lastRekey = lastRekey
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }
}

public struct MeshMetrics: Codable, Equatable, Sendable {
    public let peerCount: Int
    public let directPeerCount: Int
    public let relayPeerCount: Int
    public let bytesIn: UInt64
    public let bytesOut: UInt64
    public let replayDrops: UInt64
    public let lastPathProbe: Date?

    public init(
        peerCount: Int = 0,
        directPeerCount: Int = 0,
        relayPeerCount: Int = 0,
        bytesIn: UInt64 = 0,
        bytesOut: UInt64 = 0,
        replayDrops: UInt64 = 0,
        lastPathProbe: Date? = nil
    ) {
        self.peerCount = peerCount
        self.directPeerCount = directPeerCount
        self.relayPeerCount = relayPeerCount
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.replayDrops = replayDrops
        self.lastPathProbe = lastPathProbe
    }
}

public struct TunnelStatus: Codable, Equatable, Sendable {
    public let phase: ConnectionPhase
    public let pathType: PathType
    public let routeMode: RouteMode
    public let dnsMode: DNSMode
    public let overlayIPv4Address: String
    public let protectedRoutes: [String]
    public let peers: [PeerStatus]
    public let metrics: MeshMetrics
    public let transport: TunnelTransportMetrics?
    public let dytallixIdentity: DytallixIdentityConfiguration?
    public let lastError: String?

    public init(
        phase: ConnectionPhase,
        pathType: PathType,
        routeMode: RouteMode,
        dnsMode: DNSMode,
        overlayIPv4Address: String,
        protectedRoutes: [String],
        peers: [PeerStatus],
        metrics: MeshMetrics,
        transport: TunnelTransportMetrics? = nil,
        dytallixIdentity: DytallixIdentityConfiguration? = nil,
        lastError: String? = nil
    ) {
        self.phase = phase
        self.pathType = pathType
        self.routeMode = routeMode
        self.dnsMode = dnsMode
        self.overlayIPv4Address = overlayIPv4Address
        self.protectedRoutes = protectedRoutes
        self.peers = peers
        self.metrics = metrics
        self.transport = transport
        self.dytallixIdentity = dytallixIdentity
        self.lastError = lastError
    }

    public static let idle = TunnelStatus(
        phase: .idle,
        pathType: .unavailable,
        routeMode: .splitTunnel,
        dnsMode: .tunnelProvided,
        overlayIPv4Address: PrivacyDefaults.tunnelGatewayIPv4Address,
        protectedRoutes: [PrivacyDefaults.overlayCIDR],
        peers: [],
        metrics: MeshMetrics()
    )
}

public struct CryptoPolicy: Codable, Equatable, Sendable {
    public let suite: String
    public let rekeyAfterSeconds: TimeInterval
    public let rekeyAfterBytes: UInt64

    public init(
        suite: String? = nil,
        pqcAlgorithm: PQCAlgorithm = .fips203,
        rekeyAfterSeconds: TimeInterval = 3600,
        rekeyAfterBytes: UInt64 = 1_073_741_824
    ) {
        self.suite = suite ?? pqcAlgorithm.suiteIdentifier
        self.rekeyAfterSeconds = rekeyAfterSeconds
        self.rekeyAfterBytes = rekeyAfterBytes
    }

    public var pqcAlgorithm: PQCAlgorithm {
        PQCAlgorithm(suiteIdentifier: suite) ?? .fips203
    }
}

public struct TunnelConfiguration: Codable, Equatable, Sendable {
    public let meshID: String
    public let deviceAlias: String
    public let overlayIPv4Address: String
    public let tunnelRemoteAddress: String
    public let protectedRoutes: [String]
    public let excludedRoutes: [String]
    public let dnsServers: [String]
    public let dnsSearchDomains: [String]
    public let routeMode: RouteMode
    public let dnsMode: DNSMode
    public let discoveryModes: [DiscoveryMode]
    public let rendezvousServers: [String]
    public let relayServers: [String]
    public let mtu: Int
    public let crypto: CryptoPolicy
    public let killSwitch: KillSwitchPolicy
    public let dytallixIdentity: DytallixIdentityConfiguration?

    public init(
        meshID: String,
        deviceAlias: String,
        overlayIPv4Address: String,
        tunnelRemoteAddress: String,
        protectedRoutes: [String],
        excludedRoutes: [String] = [],
        dnsServers: [String],
        dnsSearchDomains: [String] = [],
        routeMode: RouteMode = .splitTunnel,
        dnsMode: DNSMode = .tunnelProvided,
        discoveryModes: [DiscoveryMode] = [.rendezvous],
        rendezvousServers: [String] = [],
        relayServers: [String] = [],
        mtu: Int = 1280,
        crypto: CryptoPolicy = CryptoPolicy(),
        killSwitch: KillSwitchPolicy = .failClosed,
        dytallixIdentity: DytallixIdentityConfiguration? = nil
    ) {
        self.meshID = meshID
        self.deviceAlias = deviceAlias
        self.overlayIPv4Address = overlayIPv4Address
        self.tunnelRemoteAddress = tunnelRemoteAddress
        self.protectedRoutes = protectedRoutes
        self.excludedRoutes = excludedRoutes
        self.dnsServers = dnsServers
        self.dnsSearchDomains = dnsSearchDomains
        self.routeMode = routeMode
        self.dnsMode = dnsMode
        self.discoveryModes = discoveryModes
        self.rendezvousServers = rendezvousServers
        self.relayServers = relayServers
        self.mtu = mtu
        self.crypto = crypto
        self.killSwitch = killSwitch
        self.dytallixIdentity = dytallixIdentity
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.meshID = try container.decode(String.self, forKey: .meshID)
        self.deviceAlias = try container.decode(String.self, forKey: .deviceAlias)
        self.overlayIPv4Address = try container.decode(String.self, forKey: .overlayIPv4Address)
        self.tunnelRemoteAddress = try container.decode(String.self, forKey: .tunnelRemoteAddress)
        self.protectedRoutes = try container.decode([String].self, forKey: .protectedRoutes)
        self.excludedRoutes = try container.decodeIfPresent([String].self, forKey: .excludedRoutes) ?? []
        self.dnsServers = try container.decode([String].self, forKey: .dnsServers)
        self.dnsSearchDomains = try container.decodeIfPresent([String].self, forKey: .dnsSearchDomains) ?? []
        self.routeMode = try container.decodeIfPresent(RouteMode.self, forKey: .routeMode) ?? .splitTunnel
        self.dnsMode = try container.decodeIfPresent(DNSMode.self, forKey: .dnsMode) ?? .tunnelProvided
        self.discoveryModes = try container.decodeIfPresent([DiscoveryMode].self, forKey: .discoveryModes) ?? [.rendezvous]
        self.rendezvousServers = try container.decodeIfPresent([String].self, forKey: .rendezvousServers) ?? []
        self.relayServers = try container.decodeIfPresent([String].self, forKey: .relayServers) ?? []
        self.mtu = try container.decodeIfPresent(Int.self, forKey: .mtu) ?? 1280
        self.crypto = try container.decodeIfPresent(CryptoPolicy.self, forKey: .crypto) ?? CryptoPolicy()
        self.killSwitch = try container.decodeIfPresent(KillSwitchPolicy.self, forKey: .killSwitch) ?? .failClosed
        self.dytallixIdentity = try container.decodeIfPresent(DytallixIdentityConfiguration.self, forKey: .dytallixIdentity)
    }

    public static let defaultDevelopment = PrivacyDefaults.defaultTunnelConfiguration()
}
