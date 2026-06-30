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

public enum RelayTLSPolicy: String, Codable, CaseIterable, Sendable {
  case required
  case opportunistic
  case disabled
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
  case publicRequired = "public_required"
  case privatePreferred = "private_preferred"
  case developmentOptional = "development_optional"
}

public enum DiscoveryIdentityMode: String, Codable, CaseIterable, Sendable {
  case off
  case verified
  case publicWallet = "public_wallet"
}

public struct DytallixIdentityConfiguration: Codable, Equatable, Sendable {
  public let endpoint: String
  public let contractAddress: String
  public let publishWalletAddress: Bool
  public let networkID: String?
  public let chainID: String?
  public let allowedRPCEndpoints: [String]

  public init(
    endpoint: String,
    contractAddress: String,
    publishWalletAddress: Bool = false,
    networkID: String? = nil,
    chainID: String? = nil,
    allowedRPCEndpoints: [String] = []
  ) {
    self.endpoint = endpoint
    self.contractAddress = contractAddress
    self.publishWalletAddress = publishWalletAddress
    self.networkID = networkID
    self.chainID = chainID
    self.allowedRPCEndpoints = allowedRPCEndpoints
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.endpoint = try container.decode(String.self, forKey: .endpoint)
    self.contractAddress = try container.decode(String.self, forKey: .contractAddress)
    self.publishWalletAddress =
      try container.decodeIfPresent(Bool.self, forKey: .publishWalletAddress) ?? false
    self.networkID = try container.decodeIfPresent(String.self, forKey: .networkID)
    self.chainID = try container.decodeIfPresent(String.self, forKey: .chainID)
    self.allowedRPCEndpoints =
      try container.decodeIfPresent([String].self, forKey: .allowedRPCEndpoints) ?? []
  }

  private enum CodingKeys: String, CodingKey {
    case endpoint
    case contractAddress
    case publishWalletAddress
    case networkID = "networkId"
    case chainID = "chainId"
    case allowedRPCEndpoints = "allowedRpcEndpoints"
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

public enum DytallixPeerTrustState: String, Codable, Hashable, Sendable {
  case notRequired
  case notConfigured
  case pending
  case verified
  case missingRegistryRecord
  case unverified
  case revoked
  case suspended
  case expired
  case bindingMismatch
  case lookupFailed
  case verificationFailed
  case failed
  case unknown
}

extension DytallixPeerTrustState {
  public init?(rustFailure: RustMeshPeerTrustFailure) {
    switch rustFailure {
    case .none:
      return nil
    case .registryRequired:
      self = .missingRegistryRecord
    case .registryRevoked:
      self = .revoked
    case .registrySuspended:
      self = .suspended
    case .registryExpired:
      self = .expired
    case .registryMismatch:
      self = .bindingMismatch
    case .registryLookupFailed:
      self = .lookupFailed
    case .registryVerificationFailed:
      self = .verificationFailed
    }
  }
}

public struct DytallixPeerTrustStatus: Codable, Hashable, Sendable {
  public let policy: MeshTrustPolicy
  public let identityMode: DiscoveryIdentityMode
  public let state: DytallixPeerTrustState
  public let checkedAt: Date?
  public let expiresAt: Date?
  public let registryPeerID: String?
  public let registryContractFingerprint: String?
  public let source: String?
  public let failureReason: String?

  public init(
    policy: MeshTrustPolicy,
    identityMode: DiscoveryIdentityMode,
    state: DytallixPeerTrustState,
    checkedAt: Date? = nil,
    expiresAt: Date? = nil,
    registryPeerID: String? = nil,
    registryContractFingerprint: String? = nil,
    source: String? = nil,
    failureReason: String? = nil
  ) {
    self.policy = policy
    self.identityMode = identityMode
    self.state = state
    self.checkedAt = checkedAt
    self.expiresAt = expiresAt
    self.registryPeerID = registryPeerID
    self.registryContractFingerprint = registryContractFingerprint
    self.source = source
    self.failureReason = failureReason
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
  public let dytallixTrust: DytallixPeerTrustStatus?

  public init(
    identity: PeerIdentity,
    pathType: PathType,
    endpoints: [PeerEndpoint],
    overlayAddress: String,
    rttMilliseconds: Int?,
    lastRekey: Date?,
    bytesIn: UInt64,
    bytesOut: UInt64,
    dytallixTrust: DytallixPeerTrustStatus? = nil
  ) {
    self.identity = identity
    self.pathType = pathType
    self.endpoints = endpoints
    self.overlayAddress = overlayAddress
    self.rttMilliseconds = rttMilliseconds
    self.lastRekey = lastRekey
    self.bytesIn = bytesIn
    self.bytesOut = bytesOut
    self.dytallixTrust = dytallixTrust
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

public struct DytallixPeerTrustSummary: Codable, Equatable, Sendable {
  public let required: Bool
  public let policy: MeshTrustPolicy
  public let identityMode: DiscoveryIdentityMode
  public let registryConfigured: Bool
  public let verifiedPeerCount: Int
  public let unverifiedPeerCount: Int
  public let pendingPeerCount: Int
  public let failedPeerCount: Int
  public let lastCheckedAt: Date?

  public init(
    required: Bool = false,
    policy: MeshTrustPolicy = .developmentOptional,
    identityMode: DiscoveryIdentityMode = .off,
    registryConfigured: Bool = false,
    verifiedPeerCount: Int = 0,
    unverifiedPeerCount: Int = 0,
    pendingPeerCount: Int = 0,
    failedPeerCount: Int = 0,
    lastCheckedAt: Date? = nil
  ) {
    self.required = required
    self.policy = policy
    self.identityMode = identityMode
    self.registryConfigured = registryConfigured
    self.verifiedPeerCount = verifiedPeerCount
    self.unverifiedPeerCount = unverifiedPeerCount
    self.pendingPeerCount = pendingPeerCount
    self.failedPeerCount = failedPeerCount
    self.lastCheckedAt = lastCheckedAt
  }

  public init(
    peers: [PeerStatus],
    policy: MeshTrustPolicy,
    identityMode: DiscoveryIdentityMode,
    registryConfigured: Bool
  ) {
    var verifiedPeerCount = 0
    var unverifiedPeerCount = 0
    var pendingPeerCount = 0
    var failedPeerCount = 0
    var lastCheckedAt: Date?

    for trust in peers.compactMap(\.dytallixTrust) {
      switch trust.state {
      case .verified:
        verifiedPeerCount += 1
      case .pending:
        pendingPeerCount += 1
      case .unverified, .notConfigured, .unknown:
        unverifiedPeerCount += 1
      case .missingRegistryRecord,
           .revoked,
           .suspended,
           .expired,
           .bindingMismatch,
           .lookupFailed,
           .verificationFailed,
           .failed:
        failedPeerCount += 1
      case .notRequired:
        break
      }

      if let checkedAt = trust.checkedAt,
        lastCheckedAt.map({ checkedAt > $0 }) ?? true
      {
        lastCheckedAt = checkedAt
      }
    }

    self.init(
      required: policy == .publicRequired || identityMode != .off,
      policy: policy,
      identityMode: identityMode,
      registryConfigured: registryConfigured,
      verifiedPeerCount: verifiedPeerCount,
      unverifiedPeerCount: unverifiedPeerCount,
      pendingPeerCount: pendingPeerCount,
      failedPeerCount: failedPeerCount,
      lastCheckedAt: lastCheckedAt
    )
  }

  public static let empty = DytallixPeerTrustSummary()
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
  public let peerTrust: DytallixPeerTrustSummary
  public let transport: TunnelTransportMetrics?
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
    peerTrust: DytallixPeerTrustSummary = .empty,
    transport: TunnelTransportMetrics? = nil,
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
    self.peerTrust = peerTrust
    self.transport = transport
    self.lastError = lastError
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.phase = try container.decode(ConnectionPhase.self, forKey: .phase)
    self.pathType = try container.decode(PathType.self, forKey: .pathType)
    self.routeMode = try container.decode(RouteMode.self, forKey: .routeMode)
    self.dnsMode = try container.decode(DNSMode.self, forKey: .dnsMode)
    self.overlayIPv4Address = try container.decode(String.self, forKey: .overlayIPv4Address)
    self.protectedRoutes = try container.decode([String].self, forKey: .protectedRoutes)
    self.peers = try container.decode([PeerStatus].self, forKey: .peers)
    self.metrics = try container.decode(MeshMetrics.self, forKey: .metrics)
    self.peerTrust =
      try container.decodeIfPresent(DytallixPeerTrustSummary.self, forKey: .peerTrust) ?? .empty
    self.transport = try container.decodeIfPresent(TunnelTransportMetrics.self, forKey: .transport)
    self.lastError = try container.decodeIfPresent(String.self, forKey: .lastError)
  }

  private enum CodingKeys: String, CodingKey {
    case phase
    case pathType
    case routeMode
    case dnsMode
    case overlayIPv4Address
    case protectedRoutes
    case peers
    case metrics
    case peerTrust
    case transport
    case lastError
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
  public let allowedRelayEndpoints: [String]
  public let relayTLSPolicy: RelayTLSPolicy
  public let maximumCandidateAgeSeconds: UInt64
  public let failClosedOnNoCandidate: Bool
  public let mtu: Int
  public let crypto: CryptoPolicy
  public let killSwitch: KillSwitchPolicy
  public let meshTrustPolicy: MeshTrustPolicy
  public let discoveryIdentityMode: DiscoveryIdentityMode
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
    allowedRelayEndpoints: [String] = [],
    relayTLSPolicy: RelayTLSPolicy = .required,
    maximumCandidateAgeSeconds: UInt64 = 120,
    failClosedOnNoCandidate: Bool = true,
    mtu: Int = 1280,
    crypto: CryptoPolicy = CryptoPolicy(),
    killSwitch: KillSwitchPolicy = .failClosed,
    meshTrustPolicy: MeshTrustPolicy = .developmentOptional,
    discoveryIdentityMode: DiscoveryIdentityMode = .off,
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
    self.allowedRelayEndpoints = allowedRelayEndpoints
    self.relayTLSPolicy = relayTLSPolicy
    self.maximumCandidateAgeSeconds = maximumCandidateAgeSeconds
    self.failClosedOnNoCandidate = failClosedOnNoCandidate
    self.mtu = mtu
    self.crypto = crypto
    self.killSwitch = killSwitch
    self.meshTrustPolicy = meshTrustPolicy
    self.discoveryIdentityMode = discoveryIdentityMode
    self.dytallixIdentity = dytallixIdentity
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.meshID = try container.decode(String.self, forKey: .meshID)
    self.deviceAlias = try container.decode(String.self, forKey: .deviceAlias)
    self.overlayIPv4Address = try container.decode(String.self, forKey: .overlayIPv4Address)
    self.tunnelRemoteAddress = try container.decode(String.self, forKey: .tunnelRemoteAddress)
    self.protectedRoutes = try container.decode([String].self, forKey: .protectedRoutes)
    self.excludedRoutes =
      try container.decodeIfPresent([String].self, forKey: .excludedRoutes) ?? []
    self.dnsServers = try container.decode([String].self, forKey: .dnsServers)
    self.dnsSearchDomains =
      try container.decodeIfPresent([String].self, forKey: .dnsSearchDomains) ?? []
    self.routeMode =
      try container.decodeIfPresent(RouteMode.self, forKey: .routeMode) ?? .splitTunnel
    self.dnsMode = try container.decodeIfPresent(DNSMode.self, forKey: .dnsMode) ?? .tunnelProvided
    self.discoveryModes =
      try container.decodeIfPresent([DiscoveryMode].self, forKey: .discoveryModes) ?? [.rendezvous]
    self.rendezvousServers =
      try container.decodeIfPresent([String].self, forKey: .rendezvousServers) ?? []
    self.relayServers = try container.decodeIfPresent([String].self, forKey: .relayServers) ?? []
    self.allowedRelayEndpoints =
      try container.decodeIfPresent([String].self, forKey: .allowedRelayEndpoints) ?? []
    self.relayTLSPolicy =
      try container.decodeIfPresent(RelayTLSPolicy.self, forKey: .relayTLSPolicy) ?? .required
    self.maximumCandidateAgeSeconds =
      try container.decodeIfPresent(UInt64.self, forKey: .maximumCandidateAgeSeconds) ?? 120
    self.failClosedOnNoCandidate =
      try container.decodeIfPresent(Bool.self, forKey: .failClosedOnNoCandidate) ?? true
    self.mtu = try container.decodeIfPresent(Int.self, forKey: .mtu) ?? 1280
    self.crypto =
      try container.decodeIfPresent(CryptoPolicy.self, forKey: .crypto) ?? CryptoPolicy()
    self.killSwitch =
      try container.decodeIfPresent(KillSwitchPolicy.self, forKey: .killSwitch) ?? .failClosed
    self.meshTrustPolicy =
      try container.decodeIfPresent(MeshTrustPolicy.self, forKey: .meshTrustPolicy)
      ?? .developmentOptional
    self.discoveryIdentityMode =
      try container.decodeIfPresent(DiscoveryIdentityMode.self, forKey: .discoveryIdentityMode)
      ?? .off
    self.dytallixIdentity = try container.decodeIfPresent(
      DytallixIdentityConfiguration.self, forKey: .dytallixIdentity)
  }

  public static let defaultDevelopment = PrivacyDefaults.defaultTunnelConfiguration()
}
