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

    func testRustDevQuicLoopbackTransportWhenDylibIsConfigured() throws {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to run the Rust dev QUIC transport integration test.")
        }

        let transport = RustDevQuicLoopbackTransport(library: try RustCoreLibrary(path: path))
        try transport.start()
        try transport.sendTransportFrame(Data([0xaa, 0xbb]))

        let received = try XCTUnwrap(transport.receiveTransportFrame())
        XCTAssertEqual(received.frame, Data([0xaa, 0xbb]))
        // Dev QUIC loopback has no peer identity to attribute.
        XCTAssertNil(received.peerID)
        XCTAssertEqual(transport.metrics.kind, .devQuicLoopback)
        XCTAssertEqual(transport.metrics.pathType, .direct)
        XCTAssertEqual(transport.metrics.framesSent, 1)
        XCTAssertEqual(transport.metrics.framesReceived, 1)
    }

    func testTransportSmokeRunnerWhenDylibIsConfigured() throws {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to run the Swift transport smoke integration test.")
        }

        let result = try TransportSmokeRunner.run(
            mode: .devQuicLoopback,
            libraryPath: path
        )

        XCTAssertTrue(result.packetRoundTrip)
        XCTAssertEqual(result.transportMetrics.kind, .devQuicLoopback)
        XCTAssertEqual(result.transportMetrics.framesSent, 1)
        XCTAssertEqual(result.transportMetrics.framesReceived, 1)
        XCTAssertEqual(result.coreMetrics.transportFramesOut, 1)
        XCTAssertEqual(result.coreMetrics.transportFramesIn, 1)
    }
}
