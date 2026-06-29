import Foundation
import XCTest
@testable import QuantumLinkKit

final class ConfigurationValidationTests: XCTestCase {
    func testExampleConfigurationDecodesAndValidates() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // QuantumLinkKitTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // macos
            .deletingLastPathComponent() // repo root
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

        XCTAssertThrowsError(try ConfigurationValidator.validate(configuration: configuration)) { error in
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

    func testDytallixIdentityConfigurationDecodesAndRejectsPublicOff() throws {
        let json = """
        {
          "meshID": "devmesh",
          "deviceAlias": "mac",
          "overlayIPv4Address": "100.127.0.2",
          "tunnelRemoteAddress": "100.127.0.1",
          "protectedRoutes": ["100.127.0.0/16"],
          "dnsServers": ["100.127.0.1"],
          "rendezvousServers": ["127.0.0.1:9471"],
          "dytallixIdentity": {
            "trustPolicy": "publicRequired",
            "mode": "off"
          }
        }
        """

        let configuration = try JSONDecoder().decode(
            TunnelConfiguration.self,
            from: Data(json.utf8)
        )

        XCTAssertEqual(configuration.dytallixIdentity?.trustPolicy, .publicRequired)
        XCTAssertEqual(configuration.dytallixIdentity?.mode, .off)
        XCTAssertThrowsError(try ConfigurationValidator.validate(configuration: configuration)) { error in
            XCTAssertTrue(error.localizedDescription.contains("public meshes cannot disable Dytallix identity"))
        }
    }

    func testMeshTransportConfigurationForwardsDytallixIdentity() throws {
        let identity = DytallixIdentityConfiguration(
            trustPolicy: .publicRequired,
            mode: .verified,
            registry: DytallixRegistryConfiguration(
                endpoint: "https://dytallix.com",
                contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
            )
        )
        let configuration = MeshTransportConfiguration(
            meshID: "devmesh",
            localPeerID: "qlink_local",
            remotePeerID: "qlink_remote",
            rendezvousURL: "127.0.0.1:9471",
            dytallixIdentity: identity
        )

        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(configuration)) as? [String: Any]
        let encodedIdentity = json?["dytallixIdentity"] as? [String: Any]

        XCTAssertEqual(encodedIdentity?["trustPolicy"] as? String, "publicRequired")
        XCTAssertEqual(encodedIdentity?["mode"] as? String, "verified")
    }
}
