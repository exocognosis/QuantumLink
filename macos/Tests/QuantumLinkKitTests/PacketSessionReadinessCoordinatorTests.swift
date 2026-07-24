import Foundation
import XCTest
@testable import QuantumLinkKit

final class PacketSessionReadinessCoordinatorTests: XCTestCase {
    func testReadyTransportInstallsPeerSession() {
        let core = RecordingPeerSessionCore()
        let source = StubReadinessSource(peerID: "qlink_remote-ready", ready: true)
        let coordinator = PacketSessionReadinessCoordinator()
        let now = Date(timeIntervalSince1970: 1_700_000_000)

        let report = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: makeConfiguration(),
            now: now
        )

        XCTAssertEqual(report.state, .ready)
        XCTAssertEqual(report.peerID, "qlink_remote-ready")
        XCTAssertTrue(report.installed)
        XCTAssertEqual(core.installs.count, 1)
        XCTAssertEqual(core.installs.first?.peerID, "qlink_remote-ready")
        XCTAssertEqual(core.installs.first?.expiresAt, now.addingTimeInterval(60))
        XCTAssertEqual(core.installs.first?.rekeyAfterPackets, 10)
        XCTAssertEqual(core.clearCount, 0)
    }

    func testRepeatedReadySynchronizationIsIdempotent() {
        let core = RecordingPeerSessionCore()
        let source = StubReadinessSource(peerID: "qlink_remote-ready", ready: true)
        let coordinator = PacketSessionReadinessCoordinator()
        let configuration = makeConfiguration()
        let now = Date(timeIntervalSince1970: 1_700_000_000)

        _ = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: configuration,
            now: now
        )
        let secondReport = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: configuration,
            now: now.addingTimeInterval(1)
        )

        XCTAssertEqual(secondReport.state, .ready)
        XCTAssertFalse(secondReport.installed)
        XCTAssertEqual(core.installs.count, 1)
        XCTAssertEqual(core.clearCount, 0)
    }

    func testNotReadyTransportClearsInstalledPeerSession() {
        let core = RecordingPeerSessionCore()
        let source = StubReadinessSource(peerID: "qlink_remote-flapping", ready: true)
        let coordinator = PacketSessionReadinessCoordinator()
        let configuration = makeConfiguration()

        _ = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: configuration,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )
        source.ready = false

        let report = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: configuration,
            now: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let repeatedReport = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: configuration,
            now: Date(timeIntervalSince1970: 1_700_000_011)
        )

        XCTAssertEqual(report.state, .waitingForTransport)
        XCTAssertEqual(report.peerID, "qlink_remote-flapping")
        XCTAssertTrue(report.cleared)
        XCTAssertEqual(repeatedReport.state, .waitingForTransport)
        XCTAssertFalse(repeatedReport.cleared)
        XCTAssertEqual(core.installs.count, 1)
        XCTAssertEqual(core.clearCount, 1)
    }

    func testMissingPeerClearsCoreSessionAndStaysFailClosed() {
        let core = RecordingPeerSessionCore()
        let source = StubReadinessSource(peerID: "qlink_remote-ready", ready: true)
        let coordinator = PacketSessionReadinessCoordinator()
        let configuration = makeConfiguration()

        _ = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: configuration,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let report = coordinator.synchronize(
            coreAdapter: core,
            source: StubReadinessSource(peerID: nil, ready: false),
            configuration: configuration,
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )

        XCTAssertEqual(report.state, .missingPeer)
        XCTAssertNil(report.peerID)
        XCTAssertTrue(report.cleared)
        XCTAssertFalse(core.ready)
        XCTAssertEqual(core.clearCount, 1)
    }

    func testSessionReinstallsAfterExpiry() {
        let core = RecordingPeerSessionCore()
        let source = StubReadinessSource(peerID: "qlink_remote-ready", ready: true)
        let coordinator = PacketSessionReadinessCoordinator()
        let configuration = makeConfiguration()
        let now = Date(timeIntervalSince1970: 1_700_000_000)

        _ = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: configuration,
            now: now
        )
        let report = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: configuration,
            now: now.addingTimeInterval(61)
        )

        XCTAssertEqual(report.state, .ready)
        XCTAssertTrue(report.installed)
        XCTAssertEqual(core.installs.count, 2)
    }

    func testConfigurationThatDoesNotRequirePeerSessionDoesNothing() {
        let core = RecordingPeerSessionCore()
        let source = StubReadinessSource(peerID: "qlink_remote-ready", ready: true)
        let coordinator = PacketSessionReadinessCoordinator()

        let report = coordinator.synchronize(
            coreAdapter: core,
            source: source,
            configuration: makeConfiguration(requirePeerSession: false)
        )

        XCTAssertEqual(report.state, .notRequired)
        XCTAssertTrue(core.installs.isEmpty)
        XCTAssertEqual(core.clearCount, 0)
    }
}

private final class StubReadinessSource: PacketSessionReadinessSource {
    var peerID: String?
    var ready: Bool

    init(peerID: String?, ready: Bool) {
        self.peerID = peerID
        self.ready = ready
    }

    var packetSessionPeerID: String? {
        peerID
    }

    var packetSessionTransportReady: Bool {
        ready
    }
}

private final class RecordingPeerSessionCore: TunnelCoreAdapting {
    struct Install: Equatable {
        let peerID: String
        let expiresAt: Date
        let rekeyAfterPackets: UInt64
    }

    private(set) var installs: [Install] = []
    private(set) var clearCount = 0
    private(set) var ready = false

    func submitTunnelPacket(_ packet: Data, protocolFamily: UInt32) throws -> TunnelPacketDisposition {
        .queuedForTransport
    }

    func popTransportFrame() throws -> Data? {
        nil
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
            droppedMalformed: 0,
            peerSessionRequired: true,
            peerSessionReady: ready
        )
    }

    func installPeerSession(peerID: String, expiresAt: Date, rekeyAfterPackets: UInt64) throws {
        installs.append(Install(
            peerID: peerID,
            expiresAt: expiresAt,
            rekeyAfterPackets: rekeyAfterPackets
        ))
        ready = true
    }

    func clearPeerSession() throws {
        clearCount += 1
        ready = false
    }

    func peerSessionReady() throws -> Bool {
        ready
    }
}

private func makeConfiguration(requirePeerSession: Bool = true) -> TunnelConfiguration {
    TunnelConfiguration(
        meshID: "devmesh",
        deviceAlias: "mac",
        overlayIPv4Address: "100.127.0.2",
        tunnelRemoteAddress: "100.127.0.1",
        protectedRoutes: ["100.127.0.0/16"],
        dnsServers: ["100.127.0.1"],
        maximumCandidateAgeSeconds: 60,
        mtu: 1280,
        crypto: CryptoPolicy(
            rekeyAfterSeconds: 300,
            rekeyAfterBytes: 12_800
        ),
        requirePeerSession: requirePeerSession
    )
}
