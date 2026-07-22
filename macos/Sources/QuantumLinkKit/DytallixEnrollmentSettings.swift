import Foundation

public enum DytallixEnrollmentStatus: String, Codable, CaseIterable, Sendable {
  case notConfigured = "not_configured"
  case notRegistered = "not_registered"
  case enrolling
  case walletReady = "wallet_ready"
  case registered
  case revoked
  case failed

  public var label: String {
    switch self {
    case .notConfigured: "Not Configured"
    case .notRegistered: "Not Registered"
    case .enrolling: "Enrolling"
    case .walletReady: "Wallet Ready"
    case .registered: "Registered"
    case .revoked: "Revoked"
    case .failed: "Failed"
    }
  }
}

public enum DytallixWalletReadinessState: String, Codable, CaseIterable, Sendable {
  case notRequired = "not_required"
  case unavailable
  case availablePrivate = "available_private"
  case availablePublic = "available_public"
}

public struct DytallixWalletReadinessPresentation: Equatable, Sendable {
  public static let walletFaucetURL = URL(string: "https://dytallix.com/build/wallet")!

  public let state: DytallixWalletReadinessState
  public let status: String
  public let detail: String
  public let actionTitle: String
  public let actionURL: URL

  public init(settings: DytallixEnrollmentSettings, mode: DiscoveryIdentityMode) {
    self.actionTitle = "Open Testnet Wallet/Faucet"
    self.actionURL = Self.walletFaucetURL

    guard mode != .off else {
      self.state = .notRequired
      self.status = "Not required"
      self.detail = "Private and development meshes can leave Dytallix wallet setup disabled."
      return
    }

    let walletAddress = settings.walletAddress?.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let walletAddress, !walletAddress.isEmpty else {
      self.state = .unavailable
      self.status = "Wallet needed"
      self.detail =
        "Create or unlock a Dytallix testnet wallet, then use the faucet if a registry transaction needs testnet funds."
      return
    }

    switch mode {
    case .publicWallet:
      self.state = .availablePublic
      self.status = "Published"
      self.detail =
        "Testnet wallet address \(walletAddress) is available for public discovery and may link this node to mesh activity."
    case .verified:
      self.state = .availablePrivate
      self.status = "Ready"
      self.detail = "Wallet is available; verified mode keeps wallet address details hidden."
    case .off:
      self.state = .notRequired
      self.status = "Not required"
      self.detail = "Private and development meshes can leave Dytallix wallet setup disabled."
    }
  }
}

public struct DytallixEnrollmentSettings: Codable, Equatable, Sendable {
  public let endpoint: String
  public let contractAddress: String
  public let networkID: String?
  public let chainID: String?
  public let allowedRPCEndpoints: [String]
  public let walletName: String?
  public let walletAddress: String?
  public let registeredPeerID: String?
  public let status: DytallixEnrollmentStatus

  public static let empty = DytallixEnrollmentSettings(
    endpoint: "",
    contractAddress: "",
    networkID: nil,
    chainID: nil,
    allowedRPCEndpoints: [],
    walletName: nil,
    walletAddress: nil,
    registeredPeerID: nil,
    status: .notConfigured
  )

  public static let emptyJSONString = "{}"

  public init(
    endpoint: String,
    contractAddress: String,
    networkID: String? = nil,
    chainID: String? = nil,
    allowedRPCEndpoints: [String] = [],
    walletName: String?,
    walletAddress: String?,
    registeredPeerID: String?,
    status: DytallixEnrollmentStatus
  ) {
    self.endpoint = endpoint
    self.contractAddress = contractAddress
    self.networkID = networkID
    self.chainID = chainID
    self.allowedRPCEndpoints = allowedRPCEndpoints
    self.walletName = walletName
    self.walletAddress = walletAddress
    self.registeredPeerID = registeredPeerID
    self.status = status
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.endpoint = try container.decodeIfPresent(String.self, forKey: .endpoint) ?? ""
    self.contractAddress =
      try container.decodeIfPresent(String.self, forKey: .contractAddress) ?? ""
    self.networkID = try container.decodeIfPresent(String.self, forKey: .networkID)
    self.chainID = try container.decodeIfPresent(String.self, forKey: .chainID)
    self.allowedRPCEndpoints =
      try container.decodeIfPresent([String].self, forKey: .allowedRPCEndpoints) ?? []
    self.walletName = try container.decodeIfPresent(String.self, forKey: .walletName)
    self.walletAddress = try container.decodeIfPresent(String.self, forKey: .walletAddress)
    self.registeredPeerID = try container.decodeIfPresent(String.self, forKey: .registeredPeerID)
    self.status =
      try container.decodeIfPresent(DytallixEnrollmentStatus.self, forKey: .status)
      ?? .notConfigured
  }

  private enum CodingKeys: String, CodingKey {
    case endpoint
    case contractAddress
    case networkID = "networkId"
    case chainID = "chainId"
    case allowedRPCEndpoints = "allowedRpcEndpoints"
    case walletName
    case walletAddress
    case registeredPeerID
    case status
  }

  public init(storedJSONString: String) {
    guard
      let data = storedJSONString.data(using: .utf8),
      let decoded = try? JSONDecoder().decode(Self.self, from: data)
    else {
      self = .empty
      return
    }
    self = decoded
  }

  public func storedJSONString() throws -> String {
    let data = try JSONEncoder().encode(self)
    return String(data: data, encoding: .utf8) ?? "{}"
  }

  public func replacing(
    endpoint: String? = nil,
    contractAddress: String? = nil,
    networkID: String?? = nil,
    chainID: String?? = nil,
    allowedRPCEndpoints: [String]? = nil,
    walletName: String?? = nil,
    walletAddress: String?? = nil,
    registeredPeerID: String?? = nil,
    status: DytallixEnrollmentStatus? = nil
  ) -> Self {
    DytallixEnrollmentSettings(
      endpoint: endpoint ?? self.endpoint,
      contractAddress: contractAddress ?? self.contractAddress,
      networkID: networkID ?? self.networkID,
      chainID: chainID ?? self.chainID,
      allowedRPCEndpoints: allowedRPCEndpoints ?? self.allowedRPCEndpoints,
      walletName: walletName ?? self.walletName,
      walletAddress: walletAddress ?? self.walletAddress,
      registeredPeerID: registeredPeerID ?? self.registeredPeerID,
      status: status ?? self.status
    )
  }

  public func runtimeConfiguration(mode: DiscoveryIdentityMode) -> DytallixIdentityConfiguration? {
    let trimmedEndpoint = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
    let trimmedContract = contractAddress.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmedEndpoint.isEmpty, !trimmedContract.isEmpty else { return nil }
    return DytallixIdentityConfiguration(
      endpoint: trimmedEndpoint,
      contractAddress: trimmedContract,
      publishWalletAddress: mode == .publicWallet,
      networkID: Self.nonEmptyTrimmed(networkID),
      chainID: Self.nonEmptyTrimmed(chainID),
      allowedRPCEndpoints: allowedRPCEndpoints
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
    )
  }

  private static func nonEmptyTrimmed(_ value: String?) -> String? {
    guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
      !trimmed.isEmpty
    else {
      return nil
    }
    return trimmed
  }

  public var rotationBlockedByActiveRegistryRecord: Bool {
    status == .registered && registeredPeerID != nil
  }

  public var canRotateDeviceIdentity: Bool {
    !rotationBlockedByActiveRegistryRecord
  }

  public func rotatingDeviceIdentity() -> Self {
    guard canRotateDeviceIdentity else {
      return self
    }
    return replacing(
      registeredPeerID: .some(nil),
      status: walletAddress == nil ? .notRegistered : .walletReady
    )
  }
}
