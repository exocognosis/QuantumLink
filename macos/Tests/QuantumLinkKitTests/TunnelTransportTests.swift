import Foundation
import XCTest
@testable import QuantumLinkKit

final class TunnelTransportTests: XCTestCase {
    func testDevelopmentDropTransportCountsDroppedFrames() throws {
        let transport = DevelopmentDropTransportSender(reason: "test drop")
        try transport.start()

        try transport.sendTransportFrame(Data([0x01, 0x02, 0x03]))

        XCTAssertEqual(transport.metrics.kind, .developmentDrop)
        XCTAssertEqual(transport.metrics.framesDropped, 1)
        XCTAssertEqual(transport.metrics.bytesDropped, 3)
        XCTAssertEqual(transport.metrics.lastError, "test drop")
        XCTAssertNil(try transport.receiveTransportFrame())
    }

    func testFactoryUsesDropTransportByDefault() {
        let transport = TunnelTransportFactory.makeDefault(
            configuration: .defaultDevelopment,
            environment: [:]
        )

        XCTAssertEqual(transport.metrics.kind, .developmentDrop)
    }

    func testSmokeModeReadsEnvironment() {
        XCTAssertEqual(
            TransportSmokeMode(environment: ["QLINK_TRANSPORT_MODE": "dev-quic-loopback"]),
            .devQuicLoopback
        )
        XCTAssertEqual(
            TransportSmokeMode(environment: ["QLINK_TRANSPORT_MODE": "unknown"]),
            .developmentDrop
        )
    }

    func testTunnelStatusCodableIncludesTransportMetrics() throws {
        let status = TunnelStatus(
            phase: .connected,
            pathType: .direct,
            routeMode: .splitTunnel,
            dnsMode: .tunnelProvided,
            overlayIPv4Address: "100.127.0.2",
            protectedRoutes: ["100.127.0.0/16"],
            peers: [],
            metrics: MeshMetrics(),
            transport: TunnelTransportMetrics(
                kind: .devQuicLoopback,
                state: .ready,
                pathType: .direct,
                framesSent: 1,
                framesReceived: 1
            )
        )

        let decoded = try JSONDecoder().decode(TunnelStatus.self, from: JSONEncoder().encode(status))

        XCTAssertEqual(decoded.transport?.kind, .devQuicLoopback)
        XCTAssertEqual(decoded.transport?.framesSent, 1)
        XCTAssertEqual(decoded.transport?.framesReceived, 1)
    }

    func testProductionTransportMetricsExposeSmokeOutcomeLabels() {
        XCTAssertEqual(
            TunnelTransportMetrics(
                kind: .nativeUdpMesh,
                pathType: .direct
            ).smokeOutcome,
            "native-udp-direct"
        )
        XCTAssertEqual(
            TunnelTransportMetrics(
                kind: .nativeUdpMesh,
                pathType: .relay
            ).smokeOutcome,
            "relay"
        )
        XCTAssertEqual(
            TunnelTransportMetrics(
                kind: .nativeUdpMesh,
                pathType: .unavailable
            ).smokeOutcome,
            "fail-closed"
        )
    }

    func testRustDevQuicLoopbackTransportIsDisabled() throws {
        let transport = RustDevQuicLoopbackTransport()

        XCTAssertThrowsError(try transport.start())
        XCTAssertThrowsError(try transport.sendTransportFrame(Data([0xaa, 0xbb])))
        XCTAssertNil(try transport.receiveTransportFrame())
        XCTAssertEqual(transport.metrics.kind, .devQuicLoopback)
        XCTAssertFalse(transport.isReady)
        XCTAssertEqual(transport.metrics.pathType, .unavailable)
        XCTAssertEqual(transport.metrics.sendFailures, 1)
        XCTAssertEqual(
            transport.metrics.lastError,
            "dev-quic-loopback is disabled because raw Quinn DATAGRAM bypasses the app-layer PQC frame session"
        )
    }

    func testTransportSmokeRunnerDisablesDevQuicLoopbackWhenDylibIsConfigured() throws {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to run the Swift transport smoke integration test.")
        }

        XCTAssertThrowsError(
            try TransportSmokeRunner.run(
                mode: .devQuicLoopback,
                libraryPath: path
            )
        )
    }
}
