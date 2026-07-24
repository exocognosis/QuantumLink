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
        XCTAssertEqual(configuration.protectedRoutes, ["100.64.0.0/10"])
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
            port: 22,
            deploymentDetails: DeploymentProfileDetails(
                peerDevices: [
                    PeerDeviceProfile(
                        alias: "helsinki",
                        peerID: " qlink_helsinki ",
                        endpointAddress: "89.167.52.129",
                        overlayIPAddress: "100.127.0.10",
                        role: .peer,
                        port: 22
                    )
                ]
            )
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
        XCTAssertEqual(configuration.remotePeerID, "qlink_helsinki")
        XCTAssertTrue(configuration.requirePeerSession)
    }

    func testDeploymentConfigurationPreservesRelayPolicyAndIdentitySettings() {
        let dytallixIdentity = DytallixIdentityConfiguration(
            endpoint: "https://dytallix.example",
            contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            publishWalletAddress: true
        )
        let base = TunnelConfiguration(
            meshID: "prod-mesh",
            deviceAlias: "mac",
            overlayIPv4Address: "100.127.0.2",
            tunnelRemoteAddress: "203.0.113.10",
            protectedRoutes: ["100.64.0.0/10"],
            dnsServers: ["100.127.0.1"],
            remotePeerID: "qlink_base-peer",
            allowedRelayEndpoints: ["relay.quantumlink.example:9472"],
            relayTLSPolicy: .required,
            maximumCandidateAgeSeconds: 90,
            failClosedOnNoCandidate: true,
            requirePeerSession: true,
            killSwitch: .strict,
            meshTrustPolicy: .publicRequired,
            discoveryIdentityMode: .publicWallet,
            dytallixIdentity: dytallixIdentity
        )

        let configuration = QuantumLinkDeploymentMode.mesh.configuration(from: base)

        XCTAssertEqual(configuration.remotePeerID, "qlink_base-peer")
        XCTAssertEqual(configuration.allowedRelayEndpoints, ["relay.quantumlink.example:9472"])
        XCTAssertEqual(configuration.relayTLSPolicy, .required)
        XCTAssertEqual(configuration.maximumCandidateAgeSeconds, 90)
        XCTAssertTrue(configuration.failClosedOnNoCandidate)
        XCTAssertTrue(configuration.requirePeerSession)
        XCTAssertEqual(configuration.killSwitch, .strict)
        XCTAssertEqual(configuration.meshTrustPolicy, .publicRequired)
        XCTAssertEqual(configuration.discoveryIdentityMode, .publicWallet)
        XCTAssertEqual(configuration.dytallixIdentity, dytallixIdentity)
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
        XCTAssertNil(configuration.remotePeerID)
        XCTAssertFalse(configuration.requirePeerSession)
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
