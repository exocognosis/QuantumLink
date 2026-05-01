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
}
