import Foundation

/// How discovery presents this node's Dytallix identity. Owned by the identity
/// module so future modes (e.g. zero-knowledge) can be added here without
/// touching the transport wire model.
public enum DiscoveryIdentityMode: String, Codable, CaseIterable, Sendable {
    case off
    case verified
    case publicWallet = "public_wallet"
}

/// Mirrors the Rust `qlink_core::dytallix_identity::MeshTrustPolicy` (serde
/// snake_case). Determines whether the mesh fails closed on a missing/invalid
/// on-chain registry record.
public enum MeshTrustPolicy: String, Codable, CaseIterable, Sendable {
    case publicRequired = "public_required"
    case privatePreferred = "private_preferred"
    case developmentOptional = "development_optional"
}

/// Wire-level Dytallix registry lookup config. Encodes 1:1 to the
/// `dytallixIdentity` block the Rust FFI (`MeshTransportConfig`, which builds a
/// live `DytallixRegistryLookupConfig`) expects. `publishWalletAddress` is an
/// app-side hint the core ignores.
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

extension MeshTransportConfiguration {
    /// The single modular seam that activates on-chain identity on the
    /// transport: returns a copy carrying the Dytallix trust policy and
    /// (optional) registry lookup config. A public mesh passes
    /// `.publicRequired` + a non-nil identity so the Rust connector *and*
    /// responder fail closed on any peer lacking an active registry record.
    public func enforcingDytallixIdentity(
        policy: MeshTrustPolicy,
        identity: DytallixIdentityConfiguration?
    ) -> MeshTransportConfiguration {
        MeshTransportConfiguration(
            meshID: meshID,
            localPeerID: localPeerID,
            remotePeerID: remotePeerID,
            rendezvousURL: rendezvousURL,
            relayURL: relayURL,
            bindAddress: bindAddress,
            overallDeadlineMs: overallDeadlineMs,
            directProbeTimeoutMs: directProbeTimeoutMs,
            probePacingMs: probePacingMs,
            enableICE: enableICE,
            peerStorePath: peerStorePath,
            peerStoreKeyB64: peerStoreKeyB64,
            meshTrustPolicy: policy,
            dytallixIdentity: identity
        )
    }

    /// Composes enforcement from app-level enrollment state + discovery mode.
    /// The caller selects `policy` from the mesh type (public → `.publicRequired`).
    public func applyingDiscoveryIdentity(
        settings: DytallixEnrollmentSettings,
        mode: DiscoveryIdentityMode,
        meshTrustPolicy policy: MeshTrustPolicy
    ) -> MeshTransportConfiguration {
        enforcingDytallixIdentity(
            policy: policy,
            identity: settings.runtimeConfiguration(mode: mode)
        )
    }
}
