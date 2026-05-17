import XCTest
@testable import QuantumLinkKit

final class DeploymentModeTests: XCTestCase {
    func testMeshDeploymentKeepsRelayBackedSplitTunnelDefaults() {
        let configuration = QuantumLinkDeploymentMode.mesh.configuration(from: .defaultDevelopment)

        XCTAssertEqual(configuration.routeMode, .splitTunnel)
        XCTAssertEqual(configuration.dnsMode, .tunnelProvided)
        XCTAssertEqual(configuration.discoveryModes, [.rendezvous])
        XCTAssertEqual(configuration.relayServers, ["127.0.0.1:9472"])
    }

    func testDirectDeploymentKeepsDiscoveryButRemovesRelayFallback() {
        let configuration = QuantumLinkDeploymentMode.direct.configuration(from: .defaultDevelopment)

        XCTAssertEqual(configuration.routeMode, .protectedPrefixesOnly)
        XCTAssertEqual(configuration.dnsMode, .tunnelProvided)
        XCTAssertEqual(configuration.discoveryModes, [.rendezvous, .localMDNS])
        XCTAssertTrue(configuration.relayServers.isEmpty)
    }

    func testLocalVPNDeploymentUsesFullTunnelSystemDNSAndLocalDiscovery() {
        let configuration = QuantumLinkDeploymentMode.localVPN.configuration(from: .defaultDevelopment)

        XCTAssertEqual(configuration.routeMode, .fullTunnel)
        XCTAssertEqual(configuration.dnsMode, .system)
        XCTAssertEqual(configuration.protectedRoutes, ["0.0.0.0/0"])
        XCTAssertEqual(configuration.discoveryModes, [.localMDNS])
        XCTAssertTrue(configuration.rendezvousServers.isEmpty)
        XCTAssertTrue(configuration.relayServers.isEmpty)
    }

    func testDirectProfileConfigurationTargetsPeerWithoutRelayFallback() {
        let base = TunnelConfiguration.defaultDevelopment
        let profile = ConnectionProfile(
            sourceIPAddress: " 100.127.200.245 ",
            destinationIPAddress: " 89.167.52.129 ",
            connectionType: .ssh,
            port: 22,
            pqcAlgorithm: .fips205
        )

        let configuration = QuantumLinkDeploymentMode.direct.configuration(
            from: base,
            profile: profile
        )

        XCTAssertEqual(configuration.overlayIPv4Address, "100.127.200.245")
        XCTAssertEqual(configuration.tunnelRemoteAddress, "89.167.52.129")
        XCTAssertEqual(configuration.protectedRoutes, ["89.167.52.129/32"])
        XCTAssertEqual(configuration.rendezvousServers, ["89.167.52.129:9471"])
        XCTAssertTrue(configuration.relayServers.isEmpty)
        XCTAssertEqual(configuration.crypto.pqcAlgorithm, .fips205)
        XCTAssertEqual(configuration.routeMode, .protectedPrefixesOnly)
    }

    func testMeshProfileConfigurationKeepsRelayFallbackAndTargetsPeer() {
        let base = TunnelConfiguration.defaultDevelopment
        let profile = ConnectionProfile(
            sourceIPAddress: "100.127.200.245",
            destinationIPAddress: "89.167.52.129",
            connectionType: .ssh,
            port: 22
        )

        let configuration = QuantumLinkDeploymentMode.mesh.configuration(
            from: base,
            profile: profile
        )

        XCTAssertEqual(configuration.overlayIPv4Address, "100.127.200.245")
        XCTAssertEqual(configuration.tunnelRemoteAddress, "89.167.52.129")
        XCTAssertEqual(configuration.protectedRoutes, ["100.64.0.0/10", "89.167.52.129/32"])
        XCTAssertEqual(configuration.rendezvousServers, ["89.167.52.129:9471"])
        XCTAssertEqual(configuration.relayServers, ["89.167.52.129:9472"])
        XCTAssertEqual(configuration.routeMode, .splitTunnel)
    }

    func testLocalProfileConfigurationUsesFullTunnelAndLocalDiscoveryOnly() {
        let base = TunnelConfiguration.defaultDevelopment
        let profile = ConnectionProfile(
            sourceIPAddress: "100.127.200.245",
            destinationIPAddress: "89.167.52.129",
            connectionType: .ssh,
            port: 22
        )

        let configuration = QuantumLinkDeploymentMode.localVPN.configuration(
            from: base,
            profile: profile
        )

        XCTAssertEqual(configuration.overlayIPv4Address, "100.127.200.245")
        XCTAssertEqual(configuration.tunnelRemoteAddress, "89.167.52.129")
        XCTAssertEqual(configuration.protectedRoutes, ["0.0.0.0/0"])
        XCTAssertEqual(configuration.discoveryModes, [.localMDNS])
        XCTAssertTrue(configuration.rendezvousServers.isEmpty)
        XCTAssertTrue(configuration.relayServers.isEmpty)
        XCTAssertEqual(configuration.routeMode, .fullTunnel)
    }

    @MainActor
    func testControllerConfigurationUpdateRefreshesReadyStatus() {
        let controller = SimulatedMeshController()
        let configuration = QuantumLinkDeploymentMode.localVPN.configuration(from: .defaultDevelopment)

        controller.updateConfiguration(configuration)

        XCTAssertEqual(controller.configuration.routeMode, .fullTunnel)
        XCTAssertEqual(controller.status.routeMode, .fullTunnel)
        XCTAssertEqual(controller.status.dnsMode, .system)
        XCTAssertEqual(controller.status.protectedRoutes, configuration.protectedRoutes)
    }
}
