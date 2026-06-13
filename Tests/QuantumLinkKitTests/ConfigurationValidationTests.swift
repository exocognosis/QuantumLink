import Foundation
import XCTest

@testable import QuantumLinkKit

final class ConfigurationValidationTests: XCTestCase {
  func testExampleConfigurationDecodesAndValidates() throws {
    let url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
      .appendingPathComponent("config/mesh.example.json")

    let report = try ConfigurationValidator.loadAndValidate(url: url)

    XCTAssertEqual(report.configuration.meshID, "mesh-example7e3a91")
    XCTAssertEqual(report.configuration.overlayIPv4Address, "100.64.10.2")
    XCTAssertTrue(report.warnings.isEmpty)
  }

  func testInvalidEndpointIsRejected() throws {
    let configuration = TunnelConfiguration(
      meshID: "devmesh",
      deviceAlias: "mac",
      overlayIPv4Address: "100.127.0.2",
      tunnelRemoteAddress: "100.127.0.1",
      protectedRoutes: ["100.127.0.0/16"],
      dnsServers: ["100.127.0.1"],
      rendezvousServers: ["127.0.0.1"]
    )

    XCTAssertThrowsError(try ConfigurationValidator.validate(configuration: configuration)) {
      error in
      XCTAssertTrue(error.localizedDescription.contains("Invalid endpoint"))
    }
  }

  func testEmptyProtectedRoutesWarns() throws {
    let configuration = TunnelConfiguration(
      meshID: "devmesh",
      deviceAlias: "mac",
      overlayIPv4Address: "100.127.0.2",
      tunnelRemoteAddress: "100.127.0.1",
      protectedRoutes: [],
      dnsServers: ["100.127.0.1"],
      rendezvousServers: ["127.0.0.1:9471"]
    )

    let report = try ConfigurationValidator.validate(configuration: configuration)

    XCTAssertEqual(report.warnings, ["protectedRoutes is empty; no traffic will be protected"])
  }

  func testTunnelConfigurationDecoderDefaultsKillSwitchToFailClosed() throws {
    // Fail-closed is a load-bearing security default: an MDM payload
    // or operator config that omits the `killSwitch` field MUST NOT
    // silently fall through to a more permissive policy. The
    // explicit decoder default at `Models.swift` is the only thing
    // that guarantees this; pin it with a regression test.
    let json = """
      {
        "meshID": "devmesh",
        "deviceAlias": "mac",
        "overlayIPv4Address": "100.127.0.2",
        "tunnelRemoteAddress": "100.127.0.1",
        "protectedRoutes": ["100.127.0.0/16"],
        "dnsServers": ["100.127.0.1"],
        "rendezvousServers": ["127.0.0.1:9471"]
      }
      """

    let configuration = try JSONDecoder().decode(
      TunnelConfiguration.self,
      from: Data(json.utf8)
    )

    XCTAssertEqual(configuration.killSwitch, .failClosed)
  }

  func testTunnelConfigurationDecoderHonoursExplicitStrictKillSwitch() throws {
    let json = """
      {
        "meshID": "devmesh",
        "deviceAlias": "mac",
        "overlayIPv4Address": "100.127.0.2",
        "tunnelRemoteAddress": "100.127.0.1",
        "protectedRoutes": ["100.127.0.0/16"],
        "dnsServers": ["100.127.0.1"],
        "rendezvousServers": ["127.0.0.1:9471"],
        "killSwitch": "strict"
      }
      """

    let configuration = try JSONDecoder().decode(
      TunnelConfiguration.self,
      from: Data(json.utf8)
    )

    XCTAssertEqual(configuration.killSwitch, .strict)
  }

  func testPublicMeshCannotUseOffDiscoveryIdentityMode() throws {
    let configuration = makeConfiguration(discoveryIdentityMode: .off)

    XCTAssertThrowsError(try ConfigurationValidator.validate(configuration: configuration)) {
      error in
      XCTAssertTrue(error.localizedDescription.contains("public meshes require Dytallix identity"))
    }
  }

  func testPublicMeshRequiresDytallixConfiguration() throws {
    let configuration = makeConfiguration(dytallixIdentity: nil)

    XCTAssertThrowsError(try ConfigurationValidator.validate(configuration: configuration)) {
      error in
      XCTAssertTrue(
        error.localizedDescription.contains("registry endpoint and contract address")
      )
    }
  }

  func testPublicMeshRequiresPinnedDytallixNetworkAndAllowlist() throws {
    let configuration = makeConfiguration(
      dytallixIdentity: DytallixIdentityConfiguration(
        endpoint: "https://dytallix.example",
        contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
      )
    )

    XCTAssertThrowsError(try ConfigurationValidator.validate(configuration: configuration)) {
      error in
      XCTAssertTrue(error.localizedDescription.contains("networkId and chainId"))
    }
  }

  func testPublicMeshRequiresEndpointInsideDytallixAllowlist() throws {
    let configuration = makeConfiguration(
      dytallixIdentity: DytallixIdentityConfiguration(
        endpoint: "https://evil.example",
        contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
        networkID: "dytallix-testnet",
        chainID: "dytallix-testnet-1",
        allowedRPCEndpoints: ["https://dytallix.example"]
      )
    )

    XCTAssertThrowsError(try ConfigurationValidator.validate(configuration: configuration)) {
      error in
      XCTAssertTrue(error.localizedDescription.contains("trusted RPC endpoint allowlist"))
    }
  }

  func testPublicMeshAcceptsPinnedDytallixConfiguration() throws {
    let configuration = makeConfiguration()

    let report = try ConfigurationValidator.validate(configuration: configuration)

    XCTAssertTrue(report.warnings.isEmpty)
  }

  func testPrivateMeshWarnsForUnpinnedDytallixConfiguration() throws {
    let configuration = makeConfiguration(
      meshTrustPolicy: .privatePreferred,
      dytallixIdentity: DytallixIdentityConfiguration(
        endpoint: "https://dytallix.example",
        contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
      )
    )

    let report = try ConfigurationValidator.validate(configuration: configuration)

    XCTAssertTrue(report.warnings.contains { $0.contains("networkId and chainId") })
    XCTAssertTrue(report.warnings.contains { $0.contains("trusted RPC endpoint allowlist") })
  }
}

private func makeConfiguration(
  meshTrustPolicy: MeshTrustPolicy = .publicRequired,
  discoveryIdentityMode: DiscoveryIdentityMode = .verified,
  dytallixIdentity: DytallixIdentityConfiguration? = DytallixIdentityConfiguration(
    endpoint: "https://dytallix.example/",
    contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
    networkID: "dytallix-testnet",
    chainID: "dytallix-testnet-1",
    allowedRPCEndpoints: ["https://dytallix.example"]
  )
) -> TunnelConfiguration {
  TunnelConfiguration(
    meshID: "public-mesh",
    deviceAlias: "mac",
    overlayIPv4Address: "100.127.0.2",
    tunnelRemoteAddress: "100.127.0.1",
    protectedRoutes: ["100.127.0.0/16"],
    dnsServers: ["100.127.0.1"],
    discoveryModes: [.rendezvous],
    rendezvousServers: ["127.0.0.1:9471"],
    meshTrustPolicy: meshTrustPolicy,
    discoveryIdentityMode: discoveryIdentityMode,
    dytallixIdentity: dytallixIdentity
  )
}
