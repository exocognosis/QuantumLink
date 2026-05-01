import Foundation
import XCTest
@testable import QuantumLinkKit

final class TunnelPacketPumpTests: XCTestCase {
    func testFailsClosedWhenCoreAdapterIsUnavailable() {
        let pump = TunnelPacketPump(coreAdapter: nil)
        let result = pump.handlePackets(
            [Data([1, 2, 3])],
            protocolFamilies: [2],
            transportSink: FailingTransportSink()
        )

        XCTAssertEqual(result.droppedFailClosed, 1)
        XCTAssertEqual(pump.counters.droppedFailClosed, 1)
        XCTAssertEqual(result.droppedKillSwitch, 0)
    }

    func testKillSwitchDropsPacketsWhenTransportNotReady() {
        let adapter = RecordingTunnelCoreAdapter(
            dispositions: [.queuedForTransport],
            frames: [Data([0xff])]
        )
        let pump = TunnelPacketPump(coreAdapter: adapter)
        let sink = NotReadyTransportSink()

        let result = pump.handlePackets(
            [Data([0x45]), Data([0x46])],
            protocolFamilies: [2, 2],
            transportSink: sink
        )

        XCTAssertEqual(result.droppedKillSwitch, 2)
        XCTAssertEqual(result.queuedForTransport, 0)
        XCTAssertEqual(result.transportFramesEmitted, 0)
        XCTAssertEqual(pump.counters.droppedKillSwitch, 2)
        XCTAssertEqual(sink.sendAttempts, 0, "Pump must not call into a not-ready transport")
        XCTAssertEqual(adapter.submissions, 0, "Core must not be invoked under kill switch")
    }

    func testKillSwitchPolicyDefaultIsFailClosed() {
        let pump = TunnelPacketPump(coreAdapter: nil)
        XCTAssertEqual(pump.killSwitchPolicy, .failClosed)
    }

    func testKillSwitchPolicyIsExposed() {
        let pump = TunnelPacketPump(coreAdapter: nil, killSwitch: .strict)
        XCTAssertEqual(pump.killSwitchPolicy, .strict)
    }

    func testDrainsTransportFramesForQueuedPackets() {
        let adapter = RecordingTunnelCoreAdapter(
            dispositions: [.queuedForTransport],
            frames: [Data([0xaa, 0xbb])]
        )
        let pump = TunnelPacketPump(coreAdapter: adapter)
        let sink = RecordingTransportSink()

        let result = pump.handlePackets(
            [Data([0x45])],
            protocolFamilies: [2],
            transportSink: sink
        )

        XCTAssertEqual(result.queuedForTransport, 1)
        XCTAssertEqual(result.transportFramesEmitted, 1)
        XCTAssertEqual(sink.frames, [Data([0xaa, 0xbb])])
        XCTAssertEqual(pump.counters.transportFramesEmitted, 1)
    }

    func testCountsUnprotectedPackets() {
        let adapter = RecordingTunnelCoreAdapter(
            dispositions: [.droppedUnprotected],
            frames: []
        )
        let pump = TunnelPacketPump(coreAdapter: adapter)

        let result = pump.handlePackets(
            [Data([0x45])],
            protocolFamilies: [2],
            transportSink: FailingTransportSink()
        )

        XCTAssertEqual(result.droppedUnprotected, 1)
        XCTAssertEqual(pump.counters.droppedUnprotected, 1)
    }

    func testCountsTransportSinkFailures() {
        let adapter = RecordingTunnelCoreAdapter(
            dispositions: [.queuedForTransport],
            frames: [Data([0xcc])]
        )
        let pump = TunnelPacketPump(coreAdapter: adapter)

        let result = pump.handlePackets(
            [Data([0x45])],
            protocolFamilies: [2],
            transportSink: ThrowingTransportSink()
        )

        XCTAssertEqual(result.queuedForTransport, 1)
        XCTAssertEqual(result.transportFramesEmitted, 0)
        XCTAssertEqual(result.failedSubmissions, 1)
        XCTAssertEqual(pump.counters.failedSubmissions, 1)
    }
}

private final class RecordingTransportSink: TransportFrameSink {
    private(set) var frames: [Data] = []

    func sendTransportFrame(_ frame: Data) throws {
        frames.append(frame)
    }
}

private struct FailingTransportSink: TransportFrameSink {
    func sendTransportFrame(_ frame: Data) throws {
        XCTFail("No transport frames should be emitted")
    }
}

private struct ThrowingTransportSink: TransportFrameSink {
    func sendTransportFrame(_ frame: Data) throws {
        throw NSError(domain: "QuantumLinkTests", code: 1)
    }
}

private final class NotReadyTransportSink: TransportFrameSink {
    var isReady: Bool { false }
    private(set) var sendAttempts = 0

    func sendTransportFrame(_ frame: Data) throws {
        sendAttempts += 1
        XCTFail("Pump must not call sendTransportFrame on a not-ready sink")
    }
}

private final class RecordingTunnelCoreAdapter: TunnelCoreAdapting {
    private var dispositions: [TunnelPacketDisposition]
    private var frames: [Data]
    private(set) var submissions = 0

    init(dispositions: [TunnelPacketDisposition], frames: [Data]) {
        self.dispositions = dispositions
        self.frames = frames
    }

    func submitTunnelPacket(_ packet: Data, protocolFamily: UInt32) throws -> TunnelPacketDisposition {
        submissions += 1
        return dispositions.removeFirst()
    }

    func popTransportFrame() throws -> Data? {
        frames.isEmpty ? nil : frames.removeFirst()
    }

    func acceptTransportFrame(_ frame: Data) throws {}

    func popTunnelPacket() throws -> TunnelCorePacket? {
        nil
    }

    func metrics() throws -> TunnelCoreMetrics {
        TunnelCoreMetrics(
            packetsFromTunnel: 0,
            packetsToTunnel: 0,
            transportFramesOut: 0,
            transportFramesIn: 0,
            droppedUnprotected: 0,
            droppedMalformed: 0
        )
    }
}
