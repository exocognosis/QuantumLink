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

        // Pseudonymous identifiers are kept (they're public by design).
        XCTAssertTrue(body.contains("mesh-abc123"))
        XCTAssertTrue(body.contains("device-deadbeef"))
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
        // The per-peer counter is the load-bearing piece of the
        // peer-attribution work shipped in earlier sessions; the
        // bundle exposes it (peer_id is pseudonymous + signed,
        // safe to ship in operator diagnostics).
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
        XCTAssertEqual(pump.transportFramesAcceptedPerPeer["qlink_AAAA1111BBBB2222CCCC33"], 30)
        XCTAssertEqual(pump.transportFramesAcceptedPerPeer["qlink_DDDD4444EEEE5555FFFF66"], 17)
        // Sum of the per-peer breakdown is consistent with the
        // overall counter.
        XCTAssertEqual(
            pump.transportFramesAcceptedPerPeer.values.reduce(0, +),
            pump.transportFramesAccepted
        )
    }
}
