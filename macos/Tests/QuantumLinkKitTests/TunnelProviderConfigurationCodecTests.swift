import XCTest
@testable import QuantumLinkKit

final class TunnelProviderConfigurationCodecTests: XCTestCase {
  func testProviderConfigurationRoundTripsDytallixLookupConfiguration() throws {
    let configuration = TunnelConfiguration(
      meshID: "public-mesh",
      deviceAlias: "mac",
      overlayIPv4Address: "100.127.0.2",
      tunnelRemoteAddress: "203.0.113.10",
      protectedRoutes: ["100.64.0.0/10"],
      dnsServers: ["100.127.0.1"],
      remotePeerID: "qlink_public-peer",
      requirePeerSession: true,
      meshTrustPolicy: .publicRequired,
      discoveryIdentityMode: .publicWallet,
      dytallixIdentity: DytallixIdentityConfiguration(
        endpoint: "https://dytallix.example",
        contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
        publishWalletAddress: true
      )
    )

    let providerConfiguration = try TunnelProviderConfigurationCodec.providerConfiguration(
      for: configuration
    )
    let decoded = try XCTUnwrap(
      TunnelProviderConfigurationCodec.configuration(from: providerConfiguration)
    )

    XCTAssertEqual(decoded.meshID, "public-mesh")
    XCTAssertEqual(decoded.remotePeerID, "qlink_public-peer")
    XCTAssertTrue(decoded.requirePeerSession)
    XCTAssertEqual(decoded.dytallixIdentity?.endpoint, "https://dytallix.example")
    XCTAssertEqual(
      decoded.dytallixIdentity?.contractAddress,
      "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
    )
    XCTAssertEqual(decoded.dytallixIdentity?.publishWalletAddress, true)
    XCTAssertNil(providerConfiguration["keystorePath"])
    XCTAssertNil(providerConfiguration["walletName"])
  }

  func testMalformedProviderConfigurationReturnsNil() {
    XCTAssertNil(
      TunnelProviderConfigurationCodec.configuration(from: ["configurationJSON": "{not-json"])
    )
  }
}
