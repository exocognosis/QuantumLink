import Foundation
import XCTest
@testable import QuantumLinkKit

final class SupportBundleExporterTests: XCTestCase {
    /// Anchor the bundle's `exportedAt` to a known instant so JSON round-trip
    /// tests can assert exact byte equality.
    private let fixedClock = Date(timeIntervalSince1970: 1_756_000_000)

    private func makeExporter() -> SupportBundleExporter {
        SupportBundleExporter(
            now: { [fixedClock] in fixedClock },
            osVersion: "14.5.0",
            architecture: "arm64",
            appVersion: "0.1.0",
            bundleIdentifier: "com.quantumlink.macos",
            isReleaseBuild: false
        )
    }

    private func tunnelStatusWithLeakyError() -> TunnelStatus {
        TunnelStatus(
            phase: .failed,
            pathType: .unavailable,
            routeMode: .splitTunnel,
            dnsMode: .tunnelProvided,
            overlayIPv4Address: "100.64.0.7",
            protectedRoutes: ["100.64.0.0/10"],
            peers: [],
            metrics: MeshMetrics(),
            transport: nil,
            // Synthesize a "leaky" error string with multiple address forms;
            // the redactor must scrub every one in default mode.
            lastError: "rendezvous 10.0.0.5:9471 unreachable; relay [2001:db8::beef]:9472 timed out from 192.168.1.42"
        )
    }

    private func meshMetricsWithLeakyState() -> RustMeshTransportMetrics {
        RustMeshTransportMetrics(
            stateCode: 1,
            pathKindCode: 1,
            framesSent: 100,
            framesReceived: 100,
            bytesSent: 12_345,
            bytesReceived: 11_111,
            sendFailures: 1,
            receiveFailures: 0,
            networkEventCount: 3,
            reconnectCount: 1
        )
    }

    private func leakyConfiguration() -> TunnelConfiguration {
        TunnelConfiguration(
            meshID: "mesh-abc123",
            deviceAlias: "device-deadbeef",
            overlayIPv4Address: "100.64.255.1",
            tunnelRemoteAddress: "100.64.0.1",
            protectedRoutes: ["100.64.0.0/10", "10.0.0.0/8"],
            excludedRoutes: ["192.168.0.0/16"],
            dnsServers: ["100.64.0.1"],
            dnsSearchDomains: [],
            routeMode: .splitTunnel,
            dnsMode: .tunnelProvided,
            discoveryModes: [.rendezvous],
            rendezvousServers: ["rendezvous.invalid:9471"],
            relayServers: ["relay.invalid:9472"],
            mtu: 1280,
            crypto: CryptoPolicy(),
            killSwitch: .failClosed
        )
    }

    private func leakyPumpCounters() -> PacketPumpCounters {
        var counters = PacketPumpCounters()
        counters.packetsObserved = 50
        counters.queuedForTransport = 48
        counters.droppedUnprotected = 1
        counters.droppedFailClosed = 0
        counters.droppedKillSwitch = 1
        counters.failedSubmissions = 0
        counters.transportFramesEmitted = 48
        counters.transportFramesAccepted = 47
        counters.failedInboundFrames = 0
        counters.tunnelPacketsEmitted = 47
        // Two peers contributing to the accepted-frame total.
        // Surfaced through `PumpDiagnostics.transportFramesAcceptedPerPeer`.
        counters.transportFramesAcceptedPerPeer = [
            "qlink_AAAA1111BBBB2222CCCC33": 30,
            "qlink_DDDD4444EEEE5555FFFF66": 17
        ]
        return counters
    }

    func testDefaultModeStripsAllAddressLiteralsFromLastError() throws {
        let exporter = makeExporter()
        let bundle = exporter.buildBundle(
            status: tunnelStatusWithLeakyError(),
            meshMetrics: meshMetricsWithLeakyState(),
            meshLastError: "QUIC handshake to [fe80::1]:4433 failed",
            pumpCounters: leakyPumpCounters(),
            configuration: leakyConfiguration(),
            redactionMode: .default
        )

        let json = try exporter.encode(bundle)
        let body = String(data: json, encoding: .utf8) ?? ""

        // No raw IPv4 / IPv6 / port literals anywhere in the bundle.
        XCTAssertFalse(body.contains("10.0.0.5"))
        XCTAssertFalse(body.contains("192.168.1.42"))
        XCTAssertFalse(body.contains("2001:db8"))
        XCTAssertFalse(body.contains("fe80::1"))
        XCTAssertFalse(body.contains(":9471"))
        XCTAssertFalse(body.contains(":9472"))
        XCTAssertFalse(body.contains(":4433"))
        // The overlay address — which IS a real address — must also be
        // redacted in default mode.
        XCTAssertFalse(body.contains("100.64.255.1"))

        // Persistent identifiers are redacted because they can correlate
        // support bundles with Dytallix testnet and repeated mesh activity.
        XCTAssertFalse(body.contains("mesh-abc123"))
        XCTAssertFalse(body.contains("device-deadbeef"))
        XCTAssertTrue(body.contains("[redacted-id]"))
        // Redaction sentinel appears at least once.
        XCTAssertTrue(body.contains("[redacted-ip]"))
    }

    func testRawModePreservesAllFieldsVerbatim() throws {
        let exporter = makeExporter()
        let bundle = exporter.buildBundle(
            status: tunnelStatusWithLeakyError(),
            meshMetrics: meshMetricsWithLeakyState(),
            meshLastError: "QUIC handshake to [fe80::1]:4433 failed",
            pumpCounters: leakyPumpCounters(),
            configuration: leakyConfiguration(),
            redactionMode: .raw
        )

        let json = try exporter.encode(bundle)
        let body = String(data: json, encoding: .utf8) ?? ""

        // Raw mode must preserve every address literal verbatim.
        XCTAssertTrue(body.contains("10.0.0.5:9471"))
        XCTAssertTrue(body.contains("192.168.1.42"))
        XCTAssertTrue(body.contains("[2001:db8::beef]:9472"))
        XCTAssertTrue(body.contains("[fe80::1]:4433"))
        XCTAssertTrue(body.contains("100.64.255.1"))
        // No redaction sentinel.
        XCTAssertFalse(body.contains("[redacted-ip]"))
    }

    func testBundleRoundTripsThroughJSON() throws {
        let exporter = makeExporter()
        let original = exporter.buildBundle(
            status: tunnelStatusWithLeakyError(),
            meshMetrics: meshMetricsWithLeakyState(),
            meshLastError: nil,
            pumpCounters: leakyPumpCounters(),
            configuration: leakyConfiguration(),
            redactionMode: .default
        )

        let encoded = try exporter.encode(original)
        let decoded = try exporter.decode(encoded)

        XCTAssertEqual(original, decoded)
        XCTAssertEqual(decoded.bundleVersion, DiagnosticsBundle.currentBundleVersion)
        XCTAssertEqual(decoded.redactionMode, .default)
    }

    func testBundleSurvivesPartialInputs() throws {
        // Tunnel + mesh + pump are all optional. The bundle should render
        // when only the configuration is supplied (e.g. tunnel never
        // started, the app is rendering a "fresh launch" diagnostic).
        let exporter = makeExporter()
        let bundle = exporter.buildBundle(
            status: nil,
            meshMetrics: nil,
            meshLastError: nil,
            pumpCounters: nil,
            configuration: leakyConfiguration(),
            redactionMode: .default
        )
        XCTAssertNil(bundle.tunnel)
        XCTAssertNil(bundle.mesh)
        XCTAssertNil(bundle.pump)
        XCTAssertEqual(bundle.configuration.protectedRoutesCount, 2)
        XCTAssertEqual(bundle.configuration.excludedRoutesCount, 1)
        XCTAssertEqual(bundle.configuration.rendezvousServersCount, 1)
        XCTAssertEqual(bundle.configuration.relayServersCount, 1)

        // Round-trip the partial bundle to confirm Codable handles
        // optionals properly.
        let encoded = try exporter.encode(bundle)
        let decoded = try exporter.decode(encoded)
        XCTAssertEqual(bundle, decoded)
    }

    func testBundleDoesNotEmitRawRouteOrServerLists() throws {
        // The configuration carries protectedRoutes / rendezvousServers /
        // relayServers / dnsServers as full lists with potentially-leaky
        // IPs. The bundle exposes only counts. Verify by encoding and
        // checking that none of the original list contents appear.
        let exporter = makeExporter()
        let bundle = exporter.buildBundle(
            status: nil,
            meshMetrics: nil,
            meshLastError: nil,
            pumpCounters: nil,
            configuration: leakyConfiguration(),
            redactionMode: .default
        )
        let json = try exporter.encode(bundle)
        let body = String(data: json, encoding: .utf8) ?? ""

        // None of the actual route/server strings should appear.
        XCTAssertFalse(body.contains("100.64.0.0/10"))
        XCTAssertFalse(body.contains("10.0.0.0/8"))
        XCTAssertFalse(body.contains("192.168.0.0/16"))
        XCTAssertFalse(body.contains("rendezvous.invalid"))
        XCTAssertFalse(body.contains("relay.invalid"))
        // But counts are present.
        XCTAssertTrue(body.contains("\"protectedRoutesCount\""))
        XCTAssertTrue(body.contains("\"relayServersCount\""))
    }

    func testExporterSurfacesAppEnvironmentMetadata() throws {
        let exporter = makeExporter()
        let bundle = exporter.buildBundle(
            status: nil,
            meshMetrics: nil,
            meshLastError: nil,
            pumpCounters: nil,
            configuration: leakyConfiguration(),
            redactionMode: .default
        )
        XCTAssertEqual(bundle.app.appVersion, "0.1.0")
        XCTAssertEqual(bundle.app.osVersion, "14.5.0")
        XCTAssertEqual(bundle.app.architecture, "arm64")
        XCTAssertEqual(bundle.app.bundleIdentifier, "com.quantumlink.macos")
        XCTAssertFalse(bundle.app.isReleaseBuild)
    }

    func testRedactionModeIsSerializedSoConsumersKnowWhatTheyHave() throws {
        let exporter = makeExporter()
        let defaultBundle = exporter.buildBundle(
            status: nil,
            meshMetrics: nil,
            meshLastError: nil,
            pumpCounters: nil,
            configuration: leakyConfiguration(),
            redactionMode: .default
        )
        let rawBundle = exporter.buildBundle(
            status: nil,
            meshMetrics: nil,
            meshLastError: nil,
            pumpCounters: nil,
            configuration: leakyConfiguration(),
            redactionMode: .raw
        )

        let defaultJSON = String(data: try exporter.encode(defaultBundle), encoding: .utf8) ?? ""
        let rawJSON = String(data: try exporter.encode(rawBundle), encoding: .utf8) ?? ""

        XCTAssertTrue(defaultJSON.contains("\"redactionMode\" : \"default\""))
        XCTAssertTrue(rawJSON.contains("\"redactionMode\" : \"raw\""))
    }

    func testPumpDiagnosticsCarriesPerPeerBreakdown() throws {
        let exporter = makeExporter()
        let bundle = exporter.buildBundle(
            status: tunnelStatusWithLeakyError(),
            meshMetrics: meshMetricsWithLeakyState(),
            meshLastError: nil,
            pumpCounters: leakyPumpCounters(),
            configuration: leakyConfiguration(),
            redactionMode: .default
        )

        let pump = try XCTUnwrap(bundle.pump)
        XCTAssertNil(pump.transportFramesAcceptedPerPeer["qlink_AAAA1111BBBB2222CCCC33"])
        XCTAssertNil(pump.transportFramesAcceptedPerPeer["qlink_DDDD4444EEEE5555FFFF66"])
        XCTAssertEqual(pump.transportFramesAcceptedPerPeer["peer_1"], 30)
        XCTAssertEqual(pump.transportFramesAcceptedPerPeer["peer_2"], 17)
        XCTAssertEqual(
            pump.transportFramesAcceptedPerPeer.values.reduce(0, +),
            pump.transportFramesAccepted
        )
    }

    func testRawPumpDiagnosticsCarriesPerPeerBreakdown() throws {
        let exporter = makeExporter()
        let bundle = exporter.buildBundle(
            status: tunnelStatusWithLeakyError(),
            meshMetrics: meshMetricsWithLeakyState(),
            meshLastError: nil,
            pumpCounters: leakyPumpCounters(),
            configuration: leakyConfiguration(),
            redactionMode: .raw
        )

        let pump = try XCTUnwrap(bundle.pump)
        XCTAssertEqual(pump.transportFramesAcceptedPerPeer["qlink_AAAA1111BBBB2222CCCC33"], 30)
        XCTAssertEqual(pump.transportFramesAcceptedPerPeer["qlink_DDDD4444EEEE5555FFFF66"], 17)
        XCTAssertEqual(
            pump.transportFramesAcceptedPerPeer.values.reduce(0, +),
            pump.transportFramesAccepted
        )
    }

    func testTunnelDiagnosticsCarriesDytallixTrustSummary() throws {
        let exporter = makeExporter()
        let status = TunnelStatus(
            phase: .connected,
            pathType: .direct,
            routeMode: .splitTunnel,
            dnsMode: .tunnelProvided,
            overlayIPv4Address: "100.64.0.7",
            protectedRoutes: ["100.64.0.0/10"],
            peers: [],
            metrics: MeshMetrics(),
            peerTrust: DytallixPeerTrustSummary(
                required: true,
                policy: .publicRequired,
                identityMode: .verified,
                registryConfigured: true,
                verifiedPeerCount: 2,
                unverifiedPeerCount: 1,
                pendingPeerCount: 3,
                failedPeerCount: 4
            )
        )

        let bundle = exporter.buildBundle(
            status: status,
            meshMetrics: nil,
            meshLastError: nil,
            pumpCounters: nil,
            configuration: leakyConfiguration(),
            redactionMode: .default
        )

        XCTAssertEqual(bundle.tunnel?.dytallixTrustRequired, true)
        XCTAssertEqual(bundle.tunnel?.dytallixTrustPolicy, MeshTrustPolicy.publicRequired.rawValue)
        XCTAssertEqual(bundle.tunnel?.dytallixIdentityMode, DiscoveryIdentityMode.verified.rawValue)
        XCTAssertEqual(bundle.tunnel?.dytallixRegistryConfigured, true)
        XCTAssertEqual(bundle.tunnel?.dytallixVerifiedPeerCount, 2)
        XCTAssertEqual(bundle.tunnel?.dytallixUnverifiedPeerCount, 1)
        XCTAssertEqual(bundle.tunnel?.dytallixPendingPeerCount, 3)
        XCTAssertEqual(bundle.tunnel?.dytallixFailedPeerCount, 4)
    }

    func testSupportBundleCarriesBlockedPeerDiagnosticsWithoutTraffic() throws {
        let exporter = makeExporter()
        let blockedPeer = PeerStatus(
            identity: PeerIdentity(
                peerID: "qlink_blocked",
                alias: "blocked-peer",
                publicKeyFingerprint: "fp-blocked"
            ),
            pathType: .unavailable,
            endpoints: [],
            overlayAddress: "",
            rttMilliseconds: nil,
            lastRekey: nil,
            bytesIn: 0,
            bytesOut: 0,
            dytallixTrust: DytallixPeerTrustStatus(
                policy: .publicRequired,
                identityMode: .verified,
                state: .revoked,
                checkedAt: Date(timeIntervalSince1970: 1_756_000_100),
                registryPeerID: "dytallix-registry-peer",
                source: "registry",
                failureReason: "registry record revoked"
            )
        )
        let status = TunnelStatus(
            phase: .failed,
            pathType: .unavailable,
            routeMode: .splitTunnel,
            dnsMode: .tunnelProvided,
            overlayIPv4Address: "100.64.0.7",
            protectedRoutes: ["100.64.0.0/10"],
            peers: [blockedPeer],
            metrics: MeshMetrics(),
            peerTrust: DytallixPeerTrustSummary(
                peers: [blockedPeer],
                policy: .publicRequired,
                identityMode: .verified,
                registryConfigured: true
            )
        )

        let bundle = exporter.buildBundle(
            status: status,
            meshMetrics: nil,
            meshLastError: nil,
            pumpCounters: nil,
            configuration: leakyConfiguration(),
            redactionMode: .default
        )

        let peer = try XCTUnwrap(bundle.peers.first)
        XCTAssertEqual(bundle.peers.count, 1)
        XCTAssertEqual(bundle.tunnel?.dytallixFailedPeerCount, 1)
        XCTAssertEqual(peer.peerID, "[redacted-id]")
        XCTAssertEqual(peer.alias, "[redacted-id]")
        XCTAssertEqual(peer.pathType, PathType.unavailable.rawValue)
        XCTAssertEqual(peer.bytesIn, 0)
        XCTAssertEqual(peer.bytesOut, 0)
        XCTAssertEqual(peer.dytallixTrustState, DytallixPeerTrustState.revoked.rawValue)
        XCTAssertEqual(peer.dytallixTrustPolicy, MeshTrustPolicy.publicRequired.rawValue)
        XCTAssertEqual(peer.dytallixIdentityMode, DiscoveryIdentityMode.verified.rawValue)
        XCTAssertEqual(peer.dytallixRegistryPeerID, "[redacted-id]")
        XCTAssertEqual(peer.dytallixFailureReason, "registry record revoked")
    }

    func testSupportBundleCarriesBlockedPeerHistorySnapshot() throws {
        let exporter = makeExporter()
        let observedAt = Date(timeIntervalSince1970: 3_000)
        let checkedAt = Date(timeIntervalSince1970: 2_999)
        let bundle = exporter.buildBundle(
            status: nil,
            meshMetrics: nil,
            meshLastError: nil,
            pumpCounters: nil,
            configuration: leakyConfiguration(),
            blockedPeerHistory: [
                RustBlockedPeerHistoryEntry(
                    peerID: "qlink_blocked",
                    direction: "outbound",
                    failureCode: 2,
                    failureReason: "registry record is revoked by 10.0.0.7:9471",
                    observedAt: observedAt,
                    checkedAt: checkedAt
                )
            ],
            redactionMode: .default
        )

        let blocked = try XCTUnwrap(bundle.blockedPeers.first)
        XCTAssertEqual(bundle.blockedPeers.count, 1)
        XCTAssertEqual(blocked.peerID, "[redacted-id]")
        XCTAssertEqual(blocked.direction, "outbound")
        XCTAssertEqual(blocked.failureCode, 2)
        XCTAssertEqual(blocked.failureReason, "registry record is revoked by [redacted-ip]")
        XCTAssertEqual(blocked.observedAt, observedAt)
        XCTAssertEqual(blocked.checkedAt, checkedAt)
    }
}
