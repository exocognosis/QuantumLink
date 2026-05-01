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
        XCTAssertEqual(configuration.discoveryModes, [.localMDNS])
        XCTAssertTrue(configuration.rendezvousServers.isEmpty)
        XCTAssertTrue(configuration.relayServers.isEmpty)
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
