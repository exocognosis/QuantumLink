import XCTest
@testable import QuantumLinkKit

final class PartyMeshInviteTests: XCTestCase {
  func testInviteCodeRoundTripsNonSecretMeshJoinData() throws {
    let configuration = TunnelConfiguration(
      meshID: "ranked-squad-night",
      deviceAlias: "Host Mac",
      overlayIPv4Address: "100.88.10.4",
      tunnelRemoteAddress: "203.0.113.42",
      protectedRoutes: ["100.64.0.0/10"],
      excludedRoutes: [],
      dnsServers: ["100.64.0.1"],
      dnsSearchDomains: [],
      routeMode: .splitTunnel,
      dnsMode: .tunnelProvided,
      discoveryModes: [.rendezvous],
      rendezvousServers: ["rendezvous.quantumlink.example:9471"],
      relayServers: ["relay.quantumlink.example:9472"],
      mtu: 1280,
      crypto: CryptoPolicy(pqcAlgorithm: .fips203),
      killSwitch: .failClosed,
      meshTrustPolicy: .publicRequired,
      discoveryIdentityMode: .verified,
      dytallixIdentity: DytallixIdentityConfiguration(
        endpoint: "https://dytallix.example",
        contractAddress: "dytallix-registry",
        publishWalletAddress: false
      )
    )

    let invite = PartyMeshInvite(configuration: configuration, gamePort: 27015)
    let code = try invite.joinCode()
    let decoded = try PartyMeshInvite(joinCode: code)

    XCTAssertEqual(decoded.meshID, "ranked-squad-night")
    XCTAssertEqual(decoded.hostAlias, "Host Mac")
    XCTAssertEqual(decoded.hostOverlayAddress, "100.88.10.4")
    XCTAssertEqual(decoded.rendezvousServers, ["rendezvous.quantumlink.example:9471"])
    XCTAssertEqual(decoded.relayServers, ["relay.quantumlink.example:9472"])
    XCTAssertEqual(decoded.gamePort, 27015)
    XCTAssertEqual(decoded.identityMode, .verified)
    XCTAssertEqual(decoded.meshTrustPolicy, .publicRequired)
    XCTAssertFalse(code.contains("dytallix-registry"))
    XCTAssertFalse(code.contains("private"))
    XCTAssertFalse(code.contains("keystore"))
  }

  func testInviteRejectsMalformedJoinCode() {
    XCTAssertThrowsError(try PartyMeshInvite(joinCode: "not-a-valid-party-code"))
  }

  func testInviteSummaryExplainsPublicMeshTrustRequirement() {
    let invite = PartyMeshInvite(
      meshID: "duo-night",
      hostAlias: "Host Mac",
      hostOverlayAddress: "100.88.10.4",
      rendezvousServers: ["rendezvous.quantumlink.example:9471"],
      relayServers: ["relay.quantumlink.example:9472"],
      gamePort: 27015,
      identityMode: .verified,
      meshTrustPolicy: .publicRequired
    )

    XCTAssertEqual(invite.trustSummary, "Verified Dytallix identity required")
    XCTAssertEqual(invite.pathSummary, "Direct preferred, relay fallback available")
  }
}
