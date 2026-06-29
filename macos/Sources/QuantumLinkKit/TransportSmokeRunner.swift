import Foundation

public enum TransportSmokeMode: String, CaseIterable, Sendable {
    case developmentDrop = "development-drop"
    case devQuicLoopback = "dev-quic-loopback"

    public init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        if environment["QLINK_TRANSPORT_MODE"]?.lowercased() == Self.devQuicLoopback.rawValue {
            self = .devQuicLoopback
        } else {
            self = .developmentDrop
        }
    }
}

public struct TransportSmokeResult: Equatable, Sendable {
    public let transportMetrics: TunnelTransportMetrics
    public let pumpCounters: PacketPumpCounters
    public let coreMetrics: TunnelCoreMetrics
    public let packetRoundTrip: Bool
    public let packetBytes: Int
    public let protocolFamily: UInt32?
}

public enum TransportSmokeRunner {
    public static func isExpectedDisabledDevQuicLoopback(_ error: Error) -> Bool {
        error.localizedDescription == disabledDevQuicLoopbackReason
    }

    public static func run(
        configuration: TunnelConfiguration = .defaultDevelopment,
        mode: TransportSmokeMode = TransportSmokeMode(),
        libraryPath: String? = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"]
    ) throws -> TransportSmokeResult {
        let library = try makeLibrary(path: libraryPath)
        let core = try RustTunnelCoreAdapter(configuration: configuration, library: library)
        let transport = makeTransport(mode: mode, library: library)
        let pump = TunnelPacketPump(coreAdapter: core)
        let packet = ipv4Packet(destination: [100, 127, 0, 10])

        try transport.start()
        defer {
            transport.stop()
        }

        _ = pump.handlePackets(
            [packet],
            protocolFamilies: [2],
            transportSink: transport
        )

        var restored: TunnelCorePacket?
        while let inbound = try transport.receiveTransportFrame() {
            try pump.acceptTransportFrame(inbound.frame, peerID: inbound.peerID)
            if let packet = try pump.popTunnelPacket() {
                restored = packet
                break
            }
        }

        let metrics = try core.metrics()
        // The Rust core normalizes IPv4 packets (TTL → 64, recomputes the
        // header checksum) before encryption. A successful round-trip is
        // therefore "same length + same destination + valid checksum" rather
        // than byte-for-byte equality with the input.
        let didRoundTrip: Bool
        if let restoredBytes = restored?.bytes,
           restoredBytes.count == packet.count,
           Array(restoredBytes[16..<20]) == Array(packet[16..<20]),
           Self.ipv4HeaderChecksum(restoredBytes) == 0 {
            didRoundTrip = true
        } else {
            didRoundTrip = false
        }

        return TransportSmokeResult(
            transportMetrics: transport.metrics,
            pumpCounters: pump.counters,
            coreMetrics: metrics,
            packetRoundTrip: didRoundTrip,
            packetBytes: restored?.bytes.count ?? 0,
            protocolFamily: restored?.protocolFamily
        )
    }

    private static func ipv4HeaderChecksum(_ packet: Data) -> UInt16 {
        let headerLen = Int(packet[0] & 0x0f) * 4
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < headerLen {
            sum &+= UInt32(packet[index]) << 8 | UInt32(packet[index + 1])
            index += 2
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) &+ (sum >> 16)
        }
        return ~UInt16(truncatingIfNeeded: sum)
    }

    public static func failedMetrics(
        mode: TransportSmokeMode,
        error: Error
    ) -> TunnelTransportMetrics {
        TunnelTransportMetrics(
            kind: mode == .devQuicLoopback ? .devQuicLoopback : .developmentDrop,
            state: .failed,
            pathType: .unavailable,
            lastError: error.localizedDescription
        )
    }

    private static func makeLibrary(path: String?) throws -> RustCoreLibrary {
        if let path, !path.isEmpty {
            return try RustCoreLibrary(path: path)
        }
        return try RustCoreLibrary.openBundledOrConfigured()
    }

    private static func makeTransport(
        mode: TransportSmokeMode,
        library _: RustCoreLibrary
    ) -> TunnelTransporting {
        switch mode {
        case .developmentDrop:
            return DevelopmentDropTransportSender(reason: "Development drop transport selected")
        case .devQuicLoopback:
            return RustDevQuicLoopbackTransport()
        }
    }

    private static func ipv4Packet(destination: [UInt8]) -> Data {
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = 0x45
        packet[2] = 0
        packet[3] = 20
        packet[8] = 64
        packet[9] = 17
        packet[12...15] = [100, 127, 0, 2]
        packet[16...19] = ArraySlice(destination)
        return Data(packet)
    }
}
