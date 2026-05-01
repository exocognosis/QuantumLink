import Foundation

public struct PacketPumpBatchResult: Equatable, Sendable {
    public let packetsObserved: Int
    public let queuedForTransport: Int
    public let droppedUnprotected: Int
    public let droppedFailClosed: Int
    public let droppedKillSwitch: Int
    public let failedSubmissions: Int
    public let transportFramesEmitted: Int

    public init(
        packetsObserved: Int,
        queuedForTransport: Int,
        droppedUnprotected: Int,
        droppedFailClosed: Int,
        droppedKillSwitch: Int = 0,
        failedSubmissions: Int,
        transportFramesEmitted: Int
    ) {
        self.packetsObserved = packetsObserved
        self.queuedForTransport = queuedForTransport
        self.droppedUnprotected = droppedUnprotected
        self.droppedFailClosed = droppedFailClosed
        self.droppedKillSwitch = droppedKillSwitch
        self.failedSubmissions = failedSubmissions
        self.transportFramesEmitted = transportFramesEmitted
    }
}

public struct PacketPumpCounters: Equatable, Sendable {
    public var packetsObserved: UInt64 = 0
    public var queuedForTransport: UInt64 = 0
    public var droppedUnprotected: UInt64 = 0
    public var droppedFailClosed: UInt64 = 0
    public var droppedKillSwitch: UInt64 = 0
    public var failedSubmissions: UInt64 = 0
    public var transportFramesEmitted: UInt64 = 0
    public var transportFramesAccepted: UInt64 = 0
    public var failedInboundFrames: UInt64 = 0
    public var tunnelPacketsEmitted: UInt64 = 0
}

public protocol TransportFrameSink {
    var isReady: Bool { get }
    func sendTransportFrame(_ frame: Data) throws
}

public extension TransportFrameSink {
    var isReady: Bool { true }
}

public struct ClosureTransportFrameSink: TransportFrameSink {
    private let send: (Data) throws -> Void
    public let isReady: Bool

    public init(isReady: Bool = true, _ send: @escaping (Data) throws -> Void) {
        self.send = send
        self.isReady = isReady
    }

    public func sendTransportFrame(_ frame: Data) throws {
        try send(frame)
    }
}

public final class TunnelPacketPump {
    public private(set) var counters = PacketPumpCounters()
    private let coreAdapter: TunnelCoreAdapting?
    private let killSwitch: KillSwitchPolicy

    public init(coreAdapter: TunnelCoreAdapting?, killSwitch: KillSwitchPolicy = .failClosed) {
        self.coreAdapter = coreAdapter
        self.killSwitch = killSwitch
    }

    public func handlePackets(
        _ packets: [Data],
        protocolFamilies: [UInt32],
        transportSink: TransportFrameSink
    ) -> PacketPumpBatchResult {
        counters.packetsObserved += UInt64(packets.count)

        guard let coreAdapter else {
            counters.droppedFailClosed += UInt64(packets.count)
            return PacketPumpBatchResult(
                packetsObserved: packets.count,
                queuedForTransport: 0,
                droppedUnprotected: 0,
                droppedFailClosed: packets.count,
                droppedKillSwitch: 0,
                failedSubmissions: 0,
                transportFramesEmitted: 0
            )
        }

        // Kill switch gate: if the transport is not ready, do not even submit
        // packets to the core. Preserves fail-closed semantics by ensuring no
        // plaintext data crosses the encode boundary while the data plane is
        // unhealthy.
        if !transportSink.isReady {
            counters.droppedKillSwitch += UInt64(packets.count)
            return PacketPumpBatchResult(
                packetsObserved: packets.count,
                queuedForTransport: 0,
                droppedUnprotected: 0,
                droppedFailClosed: 0,
                droppedKillSwitch: packets.count,
                failedSubmissions: 0,
                transportFramesEmitted: 0
            )
        }

        var queued = 0
        var droppedUnprotected = 0
        var failed = 0
        var emitted = 0

        for (packet, family) in zip(packets, protocolFamilies) {
            do {
                switch try coreAdapter.submitTunnelPacket(packet, protocolFamily: family) {
                case .queuedForTransport:
                    queued += 1
                    counters.queuedForTransport += 1
                    let drainResult = drainTransportFrames(from: coreAdapter, transportSink: transportSink)
                    emitted += drainResult.emitted
                    failed += drainResult.failed
                case .droppedUnprotected:
                    droppedUnprotected += 1
                    counters.droppedUnprotected += 1
                }
            } catch {
                failed += 1
                counters.failedSubmissions += 1
            }
        }

        counters.transportFramesEmitted += UInt64(emitted)
        return PacketPumpBatchResult(
            packetsObserved: packets.count,
            queuedForTransport: queued,
            droppedUnprotected: droppedUnprotected,
            droppedFailClosed: 0,
            droppedKillSwitch: 0,
            failedSubmissions: failed,
            transportFramesEmitted: emitted
        )
    }

    public var killSwitchPolicy: KillSwitchPolicy { killSwitch }

    public func coreMetrics() throws -> TunnelCoreMetrics? {
        try coreAdapter?.metrics()
    }

    public func acceptTransportFrame(_ frame: Data) throws {
        guard let coreAdapter else {
            counters.failedInboundFrames += 1
            throw RustCoreBridgeError.operationFailed("Rust core is unavailable for inbound transport frame")
        }

        do {
            try coreAdapter.acceptTransportFrame(frame)
            counters.transportFramesAccepted += 1
        } catch {
            counters.failedInboundFrames += 1
            throw error
        }
    }

    public func popTunnelPacket() throws -> TunnelCorePacket? {
        guard let coreAdapter else {
            return nil
        }
        let packet = try coreAdapter.popTunnelPacket()
        if packet != nil {
            counters.tunnelPacketsEmitted += 1
        }
        return packet
    }

    private func drainTransportFrames(
        from coreAdapter: TunnelCoreAdapting,
        transportSink: TransportFrameSink
    ) -> (emitted: Int, failed: Int) {
        var emitted = 0
        var failed = 0
        while let frame = try? coreAdapter.popTransportFrame() {
            do {
                try transportSink.sendTransportFrame(frame)
                emitted += 1
            } catch {
                failed += 1
                counters.failedSubmissions += 1
            }
        }
        return (emitted, failed)
    }
}
