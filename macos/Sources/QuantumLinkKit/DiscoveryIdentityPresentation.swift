import Foundation

public struct DiscoveryIdentityPresentation: Equatable, Sendable {
  public let rowLabel: String
  public let status: String
  public let summary: String

  public init(configuration: TunnelConfiguration) {
    self.init(
      mode: configuration.discoveryIdentityMode,
      dytallixIdentity: configuration.dytallixIdentity
    )
  }

  public init(
    mode: DiscoveryIdentityMode,
    dytallixIdentity: DytallixIdentityConfiguration? = nil
  ) {
    self.rowLabel = Self.rowLabel(for: mode)
    self.status = Self.status(for: mode, dytallixIdentity: dytallixIdentity)
    self.summary = Self.summary(for: mode)
  }

  private static func rowLabel(for mode: DiscoveryIdentityMode) -> String {
    switch mode {
    case .publicWallet:
      "Contract"
    case .verified, .off:
      "Registry"
    }
  }

  private static func status(
    for mode: DiscoveryIdentityMode,
    dytallixIdentity: DytallixIdentityConfiguration?
  ) -> String {
    switch mode {
    case .publicWallet:
      guard
        let contractAddress = dytallixIdentity?.contractAddress.trimmingCharacters(
          in: .whitespacesAndNewlines),
        !contractAddress.isEmpty
      else {
        return "Registry contract pending"
      }
      return contractAddress
    case .verified:
      return dytallixIdentity == nil
        ? "Dytallix Testnet mode; registry not configured"
        : "Dytallix Testnet configured; identity redacted"
    case .off:
      return "Identity publishing disabled"
    }
  }

  private static func summary(for mode: DiscoveryIdentityMode) -> String {
    switch mode {
    case .off:
      "Discovery does not publish a Dytallix identity for private or development meshes."
    case .verified:
      "Discovery verifies peers through the Dytallix testnet registry without displaying identity details."
    case .publicWallet:
      "Discovery uses the Dytallix testnet registry and displays the configured registry contract."
    }
  }
}
