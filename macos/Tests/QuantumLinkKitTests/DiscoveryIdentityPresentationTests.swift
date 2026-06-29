import XCTest
@testable import QuantumLinkKit

final class DiscoveryIdentityPresentationTests: XCTestCase {
  func testPublicWalletPresentationShowsRegistryContractAddress() {
    let configuration = configuration(
      discoveryIdentityMode: .publicWallet,
      dytallixIdentity: DytallixIdentityConfiguration(
        endpoint: "https://registry.example.test",
        contractAddress: " 0xRegistryContract "
      )
    )

    let presentation = DiscoveryIdentityPresentation(configuration: configuration)

    XCTAssertEqual(presentation.rowLabel, "Contract")
    XCTAssertEqual(presentation.status, "0xRegistryContract")
  }

  func testPublicWalletPresentationUsesRegistryPendingCopyWhenContractMissing() {
    let configuration = configuration(discoveryIdentityMode: .publicWallet)

    let presentation = DiscoveryIdentityPresentation(configuration: configuration)

    XCTAssertEqual(presentation.rowLabel, "Contract")
    XCTAssertEqual(presentation.status, "Registry contract pending")
  }

  func testVerifiedPresentationRedactsRegistryIdentity() {
    let configuration = configuration(
      discoveryIdentityMode: .verified,
      dytallixIdentity: DytallixIdentityConfiguration(
        endpoint: "https://registry.example.test",
        contractAddress: "0xRegistryContract"
      )
    )

    let presentation = DiscoveryIdentityPresentation(configuration: configuration)

    XCTAssertEqual(presentation.rowLabel, "Registry")
    XCTAssertEqual(presentation.status, "Dytallix Testnet configured; identity redacted")
  }

  func testPublicWalletSummaryDescribesRegistryContractDisplay() {
    let presentation = DiscoveryIdentityPresentation(mode: .publicWallet)

    XCTAssertEqual(
      presentation.summary,
      "Discovery uses the Dytallix testnet registry and displays the configured registry contract."
    )
  }

  private func configuration(
    discoveryIdentityMode: DiscoveryIdentityMode,
    dytallixIdentity: DytallixIdentityConfiguration? = nil
  ) -> TunnelConfiguration {
    let base = TunnelConfiguration.defaultDevelopment
    return TunnelConfiguration(
      meshID: base.meshID,
      deviceAlias: base.deviceAlias,
      overlayIPv4Address: base.overlayIPv4Address,
      tunnelRemoteAddress: base.tunnelRemoteAddress,
      protectedRoutes: base.protectedRoutes,
      excludedRoutes: base.excludedRoutes,
      dnsServers: base.dnsServers,
      dnsSearchDomains: base.dnsSearchDomains,
      routeMode: base.routeMode,
      dnsMode: base.dnsMode,
      discoveryModes: base.discoveryModes,
      rendezvousServers: base.rendezvousServers,
      relayServers: base.relayServers,
      mtu: base.mtu,
      crypto: base.crypto,
      killSwitch: base.killSwitch,
      meshTrustPolicy: base.meshTrustPolicy,
      discoveryIdentityMode: discoveryIdentityMode,
      dytallixIdentity: dytallixIdentity
    )
  }
}
