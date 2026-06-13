import Foundation

public struct ConfigurationValidationReport: Equatable, Sendable {
  public let configuration: TunnelConfiguration
  public let warnings: [String]

  public var isUsableForLocalDevelopment: Bool {
    warnings.isEmpty
  }
}

public enum ConfigurationValidationError: Error, LocalizedError {
  case unreadable(URL, String)
  case invalidJSON(String)
  case invalidRoute(String)
  case invalidAddress(String)
  case invalidEndpoint(String)
  case invalidDytallixIdentity(String)

  public var errorDescription: String? {
    switch self {
    case .unreadable(let url, let message):
      "Could not read configuration at \(url.path): \(message)"
    case .invalidJSON(let message):
      "Invalid QuantumLink configuration JSON: \(message)"
    case .invalidRoute(let route):
      "Invalid CIDR route: \(route)"
    case .invalidAddress(let address):
      "Invalid IPv4 address: \(address)"
    case .invalidEndpoint(let endpoint):
      "Invalid endpoint address: \(endpoint)"
    case .invalidDytallixIdentity(let message):
      "Invalid Dytallix identity configuration: \(message)"
    }
  }
}

public enum ConfigurationValidator {
  public static func loadAndValidate(url: URL) throws -> ConfigurationValidationReport {
    let data: Data
    do {
      data = try Data(contentsOf: url)
    } catch {
      throw ConfigurationValidationError.unreadable(url, error.localizedDescription)
    }
    return try validate(data: data)
  }

  public static func validate(data: Data) throws -> ConfigurationValidationReport {
    let configuration: TunnelConfiguration
    do {
      configuration = try JSONDecoder().decode(TunnelConfiguration.self, from: data)
    } catch {
      throw ConfigurationValidationError.invalidJSON(error.localizedDescription)
    }
    return try validate(configuration: configuration)
  }

  public static func validate(configuration: TunnelConfiguration) throws
    -> ConfigurationValidationReport
  {
    try validateIPv4(configuration.overlayIPv4Address)
    try validateIPv4(configuration.tunnelRemoteAddress)

    for route in configuration.protectedRoutes + configuration.excludedRoutes {
      _ = try IPv4CIDR(route)
    }
    for server in configuration.dnsServers {
      try validateIPv4(server)
    }
    for endpoint in configuration.rendezvousServers + configuration.relayServers {
      try validateEndpoint(endpoint)
    }

    var warnings: [String] = []
    if configuration.protectedRoutes.isEmpty {
      warnings.append("protectedRoutes is empty; no traffic will be protected")
    }
    if configuration.dnsMode == .tunnelProvided, configuration.dnsServers.isEmpty {
      warnings.append("dnsMode is tunnelProvided but dnsServers is empty")
    }
    if configuration.discoveryModes.contains(.rendezvous), configuration.rendezvousServers.isEmpty {
      warnings.append("rendezvous discovery is enabled but rendezvousServers is empty")
    }
    if configuration.mtu < 576 {
      warnings.append("mtu is below IPv4 minimum reassembly size")
    }
    try validateDytallixIdentity(configuration, warnings: &warnings)

    return ConfigurationValidationReport(configuration: configuration, warnings: warnings)
  }

  private static func validateDytallixIdentity(
    _ configuration: TunnelConfiguration,
    warnings: inout [String]
  ) throws {
    if configuration.meshTrustPolicy == .publicRequired,
      configuration.discoveryIdentityMode == .off
    {
      throw ConfigurationValidationError.invalidDytallixIdentity(
        "public meshes require Dytallix identity; Off is only valid for private or development meshes"
      )
    }

    guard let identity = configuration.dytallixIdentity else {
      if configuration.meshTrustPolicy == .publicRequired {
        throw ConfigurationValidationError.invalidDytallixIdentity(
          "public meshes require a Dytallix registry endpoint and contract address"
        )
      }
      return
    }

    try validateDytallixEndpoint(identity.endpoint)

    if identity.contractAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      throw ConfigurationValidationError.invalidDytallixIdentity(
        "Dytallix registry contract address is required"
      )
    }

    let hasNetworkPin = !(identity.networkID?.trimmingCharacters(in: .whitespacesAndNewlines)
      .isEmpty ?? true)
    let hasChainPin = !(identity.chainID?.trimmingCharacters(in: .whitespacesAndNewlines)
      .isEmpty ?? true)
    let allowedEndpoints = identity.allowedRPCEndpoints
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }

    if configuration.meshTrustPolicy == .publicRequired {
      guard hasNetworkPin, hasChainPin else {
        throw ConfigurationValidationError.invalidDytallixIdentity(
          "public meshes require pinned Dytallix networkId and chainId values"
        )
      }
      guard !allowedEndpoints.isEmpty else {
        throw ConfigurationValidationError.invalidDytallixIdentity(
          "public meshes require an allowlist of trusted Dytallix RPC endpoints"
        )
      }
      let endpointPin = normalizedEndpointPin(identity.endpoint)
      guard allowedEndpoints.contains(where: { normalizedEndpointPin($0) == endpointPin }) else {
        throw ConfigurationValidationError.invalidDytallixIdentity(
          "Dytallix registry endpoint is not in the trusted RPC endpoint allowlist"
        )
      }
    } else {
      if !hasNetworkPin || !hasChainPin {
        warnings.append(
          "Dytallix identity is configured without pinned networkId and chainId; private/dev meshes should treat verification as beta-only"
        )
      }
      if allowedEndpoints.isEmpty {
        warnings.append(
          "Dytallix identity is configured without a trusted RPC endpoint allowlist"
        )
      }
    }
  }

  private static func validateDytallixEndpoint(_ endpoint: String) throws {
    guard let url = URL(string: endpoint),
      url.scheme?.lowercased() == "https",
      url.host?.isEmpty == false,
      url.user == nil,
      url.password == nil
    else {
      throw ConfigurationValidationError.invalidDytallixIdentity(
        "Dytallix RPC endpoint must be an HTTPS URL without embedded credentials"
      )
    }
  }

  private static func normalizedEndpointPin(_ endpoint: String) -> String {
    endpoint
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
      .lowercased()
  }

  private static func validateIPv4(_ address: String) throws {
    let parts = address.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) else {
      throw ConfigurationValidationError.invalidAddress(address)
    }
  }

  private static func validateEndpoint(_ endpoint: String) throws {
    guard
      let colon = endpoint.lastIndex(of: ":"),
      colon > endpoint.startIndex,
      colon < endpoint.index(before: endpoint.endIndex),
      UInt16(endpoint[endpoint.index(after: colon)...]) != nil
    else {
      throw ConfigurationValidationError.invalidEndpoint(endpoint)
    }
  }
}
