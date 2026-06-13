import Foundation

public enum PartyMeshInviteError: Error, Equatable, Sendable {
  case malformedCode
}

public struct PartyMeshInvite: Codable, Equatable, Sendable {
  public static let codePrefix = "QLP1"

  public let meshID: String
  public let hostAlias: String
  public let hostOverlayAddress: String
  public let rendezvousServers: [String]
  public let relayServers: [String]
  public let gamePort: Int
  public let identityMode: DiscoveryIdentityMode
  public let meshTrustPolicy: MeshTrustPolicy

  public init(
    meshID: String,
    hostAlias: String,
    hostOverlayAddress: String,
    rendezvousServers: [String],
    relayServers: [String],
    gamePort: Int,
    identityMode: DiscoveryIdentityMode,
    meshTrustPolicy: MeshTrustPolicy
  ) {
    self.meshID = meshID
    self.hostAlias = hostAlias
    self.hostOverlayAddress = hostOverlayAddress
    self.rendezvousServers = rendezvousServers
    self.relayServers = relayServers
    self.gamePort = gamePort
    self.identityMode = identityMode
    self.meshTrustPolicy = meshTrustPolicy
  }

  public init(configuration: TunnelConfiguration, gamePort: Int) {
    self.init(
      meshID: configuration.meshID,
      hostAlias: configuration.deviceAlias,
      hostOverlayAddress: configuration.overlayIPv4Address,
      rendezvousServers: configuration.rendezvousServers,
      relayServers: configuration.relayServers,
      gamePort: gamePort,
      identityMode: configuration.discoveryIdentityMode,
      meshTrustPolicy: configuration.meshTrustPolicy
    )
  }

  public init(joinCode: String) throws {
    let trimmed = joinCode.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.hasPrefix(Self.codePrefix + "-") else {
      throw PartyMeshInviteError.malformedCode
    }
    let encoded = String(trimmed.dropFirst(Self.codePrefix.count + 1))
    guard let data = Data(base64URLEncoded: encoded) else {
      throw PartyMeshInviteError.malformedCode
    }
    do {
      self = try JSONDecoder().decode(Self.self, from: data)
    } catch {
      throw PartyMeshInviteError.malformedCode
    }
  }

  public func joinCode() throws -> String {
    let data = try JSONEncoder().encode(self)
    return Self.codePrefix + "-" + data.base64URLEncodedString()
  }

  public var trustSummary: String {
    switch (meshTrustPolicy, identityMode) {
    case (.publicRequired, .verified):
      "Verified Dytallix identity required"
    case (.publicRequired, .publicWallet):
      "Public Dytallix wallet identity required"
    case (.publicRequired, .off):
      "Public mesh identity required"
    case (_, .off):
      "Invite-only identity"
    case (_, .verified):
      "Verified Dytallix identity preferred"
    case (_, .publicWallet):
      "Public Dytallix wallet identity preferred"
    }
  }

  public var pathSummary: String {
    relayServers.isEmpty
      ? "Direct path required"
      : "Direct preferred, relay fallback available"
  }
}

extension Data {
  fileprivate func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  fileprivate init?(base64URLEncoded value: String) {
    var base64 = value
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let padding = base64.count % 4
    if padding > 0 {
      base64.append(String(repeating: "=", count: 4 - padding))
    }
    self.init(base64Encoded: base64)
  }
}
