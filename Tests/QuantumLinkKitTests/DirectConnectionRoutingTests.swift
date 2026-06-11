import XCTest
@testable import QuantumLinkKit

final class DirectConnectionRoutingTests: XCTestCase {
    func testDirectProfileDoesNotProtectControlEndpointAddress() {
        let base = TunnelConfiguration(
            meshID: "mesh-test",
            deviceAlias: "test-mac",
            overlayIPv4Address: "100.111.16.152",
            tunnelRemoteAddress: "203.0.113.10",
            protectedRoutes: ["100.64.0.0/10"],
            dnsServers: ["100.64.0.1"],
            rendezvousServers: ["203.0.113.10:9471"],
            relayServers: ["203.0.113.11:9472"]
        )
        let profile = ConnectionProfile(
            sourceIPAddress: "100.111.16.152",
            destinationIPAddress: "89.167.52.129",
            connectionType: .ssh,
            deploymentDetails: DeploymentProfileDetails(
                directEndpointPort: 9443,
                protectedPrefixesText: "100.64.10.0/24, 100.64.20.0/24"
            )
        )

        let configuration = QuantumLinkDeploymentMode.direct.configuration(from: base, profile: profile)

        XCTAssertEqual(configuration.tunnelRemoteAddress, "89.167.52.129")
        XCTAssertEqual(configuration.rendezvousServers, ["89.167.52.129:9443"])
        XCTAssertEqual(configuration.routeMode, .protectedPrefixesOnly)
        XCTAssertEqual(configuration.relayServers, [])
        XCTAssertFalse(configuration.protectedRoutes.contains("89.167.52.129/32"))
        XCTAssertEqual(configuration.protectedRoutes, ["100.64.10.0/24", "100.64.20.0/24"])
    }
}
