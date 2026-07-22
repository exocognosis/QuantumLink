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

    func testAcceptTransportFrameRecordsPerPeerCounters() throws {
        let adapter = RecordingTunnelCoreAdapter(dispositions: [], frames: [])
        let pump = TunnelPacketPump(coreAdapter: adapter)

        try pump.acceptTransportFrame(Data([0x01]), peerID: "qlink_alpha")
        try pump.acceptTransportFrame(Data([0x02]), peerID: "qlink_alpha")
        try pump.acceptTransportFrame(Data([0x03]), peerID: "qlink_beta")
        // peerID nil and empty string both bypass per-peer accounting:
        // legacy single-peer transports + dev loopback have no identity.
        try pump.acceptTransportFrame(Data([0x04]), peerID: nil)
        try pump.acceptTransportFrame(Data([0x05]), peerID: "")

        XCTAssertEqual(pump.counters.transportFramesAccepted, 5)
        XCTAssertEqual(pump.counters.transportFramesAcceptedPerPeer["qlink_alpha"], 2)
        XCTAssertEqual(pump.counters.transportFramesAcceptedPerPeer["qlink_beta"], 1)
        XCTAssertEqual(pump.counters.transportFramesAcceptedPerPeer.count, 2)
    }

    func testAcceptTransportFrameDefaultsToNoPeerAttribution() throws {
        let adapter = RecordingTunnelCoreAdapter(dispositions: [], frames: [])
        let pump = TunnelPacketPump(coreAdapter: adapter)

        // Calling without the peerID argument keeps the legacy behavior
        // (no per-peer accounting) — exercises the default-arg path.
        try pump.acceptTransportFrame(Data([0xff]))

        XCTAssertEqual(pump.counters.transportFramesAccepted, 1)
        XCTAssertTrue(pump.counters.transportFramesAcceptedPerPeer.isEmpty)
    }

    func testKillSwitchDropsPacketsWhenTransportFlipsFromReadyToNotReadyMidFlight() {
        // Regression coverage for the "transport went unhealthy between
        // batches" case. Existing kill-switch coverage only exercises
        // the never-ready path; this verifies the *transition* — once
        // `isReady` flips false, no further packets are submitted to
        // the core or sent on the transport, even though the previous
        // batch was processed normally.
        let adapter = RecordingTunnelCoreAdapter(
            dispositions: [.queuedForTransport],
            frames: [Data([0xab])]
        )
        let pump = TunnelPacketPump(coreAdapter: adapter)
        let sink = FlippableTransportSink()

        // First batch: transport is ready, packet flows through.
        let firstBatch = pump.handlePackets(
            [Data([0x45])],
            protocolFamilies: [2],
            transportSink: sink
        )
        XCTAssertEqual(firstBatch.queuedForTransport, 1)
        XCTAssertEqual(firstBatch.droppedKillSwitch, 0)
        XCTAssertEqual(sink.frames, [Data([0xab])])
        XCTAssertEqual(adapter.submissions, 1)

        // Transport goes unhealthy.
        sink.flipToNotReady()

        // Second batch: must be dropped under the kill switch with no
        // submission to the core.
        let secondBatch = pump.handlePackets(
            [Data([0x46]), Data([0x47])],
            protocolFamilies: [2, 2],
            transportSink: sink
        )
        XCTAssertEqual(secondBatch.droppedKillSwitch, 2)
        XCTAssertEqual(secondBatch.queuedForTransport, 0)
        XCTAssertEqual(adapter.submissions, 1, "core must not be invoked for the second batch")
        XCTAssertEqual(sink.frames.count, 1, "no new transport frames after the flip")
        XCTAssertEqual(pump.counters.droppedKillSwitch, 2)
    }

    func testDrainTransportFramesDropsEncryptedFrameWhenSendFails() {
        // Documents the deliberate "lost-on-failure" behavior of
        // drainTransportFrames: the encoded transport frame is popped
        // from the core before the send is attempted, so a failed send
        // means the encrypted bytes are dropped — never retried, never
        // falling back to plaintext. That is the failure mode the spec
        // requires (drop, don't leak).
        let adapter = RecordingTunnelCoreAdapter(
            dispositions: [.queuedForTransport],
            frames: [Data([0xc0, 0xde])]
        )
        let pump = TunnelPacketPump(coreAdapter: adapter)
        let sink = ThrowingTransportSink()

        let result = pump.handlePackets(
            [Data([0x45])],
            protocolFamilies: [2],
            transportSink: sink
        )

        XCTAssertEqual(result.queuedForTransport, 1, "core accepted the packet")
        XCTAssertEqual(result.transportFramesEmitted, 0, "send failed")
        XCTAssertEqual(result.failedSubmissions, 1, "send failure surfaced as a counter")
        XCTAssertEqual(pump.counters.failedSubmissions, 1)

        // Verifies the frame was actually popped (gone from the core)
        // rather than left buffered for a hypothetical retry.
        let remainingFrame = try? adapter.popTransportFrame()
        XCTAssertNil(remainingFrame, "frame must be drained, not buffered for retry")
    }
}

private final class FlippableTransportSink: TransportFrameSink {
    private(set) var frames: [Data] = []
    private var ready = true

    var isReady: Bool { ready }

    func sendTransportFrame(_ frame: Data) throws {
        guard ready else {
            XCTFail("Pump must not call sendTransportFrame after the sink is not ready")
            return
        }
        frames.append(frame)
    }

    func flipToNotReady() {
        ready = false
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
