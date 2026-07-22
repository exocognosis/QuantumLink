import Darwin
import Foundation

public enum RustCoreBridgeError: Error, LocalizedError {
    case libraryNotFound([String])
    case openFailed(String)
    case missingSymbol(String)
    case initializationFailed
    case operationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .libraryNotFound(let paths):
            "Rust core library was not found. Checked: \(paths.joined(separator: ", "))"
        case .openFailed(let message):
            "Failed to open Rust core library: \(message)"
        case .missingSymbol(let symbol):
            "Rust core library is missing symbol \(symbol)"
        case .initializationFailed:
            "Rust tunnel core initialization failed"
        case .operationFailed(let message):
            message
        }
    }
}

public enum TunnelPacketDisposition: Equatable, Sendable {
    case queuedForTransport
    case droppedUnprotected
    case droppedPeerSessionUnavailable
}

public enum RustMeshPeerTrustDecision: UInt32, Sendable {
    case unknown = 0
    case accepted = 1
    case acceptedWithoutRegistryPrivate = 2
    case acceptedWithoutRegistryDevelopment = 3
}

public enum RustMeshPeerTrustFailure: UInt32, Sendable {
    case none = 0
    case registryRequired = 1
    case registryRevoked = 2
    case registrySuspended = 3
    case registryExpired = 4
    case registryMismatch = 5
    case registryLookupFailed = 6
    case registryVerificationFailed = 7
}

public struct RustMeshPeerTrustStatus: Equatable, Sendable {
    public let decision: RustMeshPeerTrustDecision
    public let failure: RustMeshPeerTrustFailure
    public let checkedAt: Date?
    public let source: RustMeshPeerTrustSource

    public init(
        decision: RustMeshPeerTrustDecision,
        failure: RustMeshPeerTrustFailure = .none,
        checkedAt: Date?,
        source: RustMeshPeerTrustSource = .unknown
    ) {
        self.decision = decision
        self.failure = failure
        self.checkedAt = checkedAt
        self.source = source
    }
}

public enum RustMeshPeerTrustSource: UInt32, Sendable {
    case unknown = 0
    case rendezvousLive = 1
    case peerRecordCache = 2

    public var label: String {
        switch self {
        case .unknown:
            "unknown"
        case .rendezvousLive:
            "rendezvous-live"
        case .peerRecordCache:
            "peer-record-cache"
        }
    }
}

public struct RustBlockedPeerHistoryEntry: Codable, Equatable, Sendable {
    public let peerID: String
    public let direction: String
    public let failureCode: UInt32
    public let failureReason: String
    public let observedAt: Date
    public let checkedAt: Date

    public init(
        peerID: String,
        direction: String,
        failureCode: UInt32,
        failureReason: String,
        observedAt: Date,
        checkedAt: Date
    ) {
        self.peerID = peerID
        self.direction = direction
        self.failureCode = failureCode
        self.failureReason = failureReason
        self.observedAt = observedAt
        self.checkedAt = checkedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.peerID = try container.decode(String.self, forKey: .peerID)
        self.direction = try container.decode(String.self, forKey: .direction)
        self.failureCode = try container.decode(UInt32.self, forKey: .failureCode)
        self.failureReason = try container.decode(String.self, forKey: .failureReason)
        let observedAtUnix = try container.decode(UInt64.self, forKey: .observedAtUnix)
        let checkedAtUnix = try container.decode(UInt64.self, forKey: .checkedAtUnix)
        self.observedAt = Date(timeIntervalSince1970: TimeInterval(observedAtUnix))
        self.checkedAt = Date(timeIntervalSince1970: TimeInterval(checkedAtUnix))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(peerID, forKey: .peerID)
        try container.encode(direction, forKey: .direction)
        try container.encode(failureCode, forKey: .failureCode)
        try container.encode(failureReason, forKey: .failureReason)
        try container.encode(UInt64(observedAt.timeIntervalSince1970), forKey: .observedAtUnix)
        try container.encode(UInt64(checkedAt.timeIntervalSince1970), forKey: .checkedAtUnix)
    }

    private enum CodingKeys: String, CodingKey {
        case peerID = "peer_id"
        case direction
        case failureCode = "failure_code"
        case failureReason = "failure_reason"
        case observedAtUnix = "observed_at_unix"
        case checkedAtUnix = "checked_at_unix"
    }
}

public struct TunnelCorePacket: Equatable, Sendable {
    public let protocolFamily: UInt32
    public let bytes: Data

    public init(protocolFamily: UInt32, bytes: Data) {
        self.protocolFamily = protocolFamily
        self.bytes = bytes
    }
}

public struct TunnelCoreMetrics: Equatable, Sendable {
    public let packetsFromTunnel: UInt64
    public let packetsToTunnel: UInt64
    public let transportFramesOut: UInt64
    public let transportFramesIn: UInt64
    public let droppedUnprotected: UInt64
    public let droppedMalformed: UInt64
    public let droppedPeerSessionUnavailable: UInt64
    public let droppedReplay: UInt64
    public let peerSessionRequired: Bool
    public let peerSessionReady: Bool

    public init(
        packetsFromTunnel: UInt64,
        packetsToTunnel: UInt64,
        transportFramesOut: UInt64,
        transportFramesIn: UInt64,
        droppedUnprotected: UInt64,
        droppedMalformed: UInt64,
        droppedPeerSessionUnavailable: UInt64 = 0,
        droppedReplay: UInt64 = 0,
        peerSessionRequired: Bool = false,
        peerSessionReady: Bool = true
    ) {
        self.packetsFromTunnel = packetsFromTunnel
        self.packetsToTunnel = packetsToTunnel
        self.transportFramesOut = transportFramesOut
        self.transportFramesIn = transportFramesIn
        self.droppedUnprotected = droppedUnprotected
        self.droppedMalformed = droppedMalformed
        self.droppedPeerSessionUnavailable = droppedPeerSessionUnavailable
        self.droppedReplay = droppedReplay
        self.peerSessionRequired = peerSessionRequired
        self.peerSessionReady = peerSessionReady
    }
}

public struct RustDevQuicTransportMetrics: Equatable, Sendable {
    public let framesSent: UInt64
    public let framesReceived: UInt64
    public let bytesSent: UInt64
    public let bytesReceived: UInt64
    public let sendFailures: UInt64
    public let receiveFailures: UInt64
}

public enum RustMeshTransportState: UInt32, Equatable, Sendable {
    case connecting = 0
    case ready = 1
    case failed = 2
    case stopped = 3
}

public enum RustMeshTransportPathKind: UInt32, Equatable, Sendable {
    case none = 0
    case direct = 1
    case relay = 2
}

public enum RustMeshNetworkEvent: UInt32, Equatable, Sendable {
    case pathChanged = 0
    case preSleep = 1
    case postWake = 2
    case reachabilityLost = 3
    case reachabilityGained = 4
}

/// RAII wrapper around a Rust-owned `DeviceKeypair`. The Rust core
/// holds the actual ML-DSA signing material; Swift sees only the
/// opaque pointer plus the `peerID` derived from the public key.
///
/// **Persistence contract**: callers MUST save `seed` somewhere
/// secure (Keychain on macOS) before this object is deallocated, and
/// reload via `RustDeviceKeypair.load(library:seed:)` next launch.
/// Without that round-trip the published `peer_id` changes per
/// process restart and cached peer records become unauthenticatable.
public final class RustDeviceKeypair {
    // Module-internal so other QuantumLinkKit types (notably
    // `RustMeshTransport`) can pass the raw handle through to the
    // FFI layer. External callers should treat the keypair as
    // opaque and only touch `seed` (for persistence) and `peerID`.
    internal let library: RustCoreLibrary
    internal let handle: UnsafeMutableRawPointer
    public let seed: Data
    public let peerID: String

    fileprivate init(library: RustCoreLibrary, handle: UnsafeMutableRawPointer, seed: Data) throws {
        self.library = library
        self.handle = handle
        self.seed = seed
        guard let peerID = library.deviceKeypairPeerID(handle: handle) else {
            library.destroyDeviceKeypair(handle)
            throw RustCoreBridgeError.operationFailed("Rust device keypair peer_id read failed")
        }
        self.peerID = peerID
    }

    deinit {
        library.destroyDeviceKeypair(handle)
    }

    /// Generates a fresh ML-DSA-65 device keypair. The 32-byte
    /// `seed` returned via `seed` MUST be persisted before the
    /// keypair object goes out of scope.
    public static func generate(library: RustCoreLibrary) throws -> RustDeviceKeypair {
        let (handle, seed) = try library.generateDeviceKeypair()
        return try RustDeviceKeypair(library: library, handle: handle, seed: seed)
    }

    /// Reconstructs a keypair previously generated and persisted as
    /// `seed`. Throws if the seed is the wrong length or the bytes
    /// don't decode as a valid ML-DSA-65 seed.
    public static func load(library: RustCoreLibrary, seed: Data) throws -> RustDeviceKeypair {
        let handle = try library.loadDeviceKeypair(seed: seed)
        return try RustDeviceKeypair(library: library, handle: handle, seed: seed)
    }
}

/// Inbound mesh frame paired with the verified peer ID. The Rust
/// responder loop authenticates the peer's `InboundIdentityAssertion`
/// before tagging frames with `peerID`; the FFI surfaces both halves
/// here so Swift consumers can route per-peer.
public struct RustMeshInboundFrame: Equatable, Sendable {
    public let peerID: String
    public let frame: Data

    public init(peerID: String, frame: Data) {
        self.peerID = peerID
        self.frame = frame
    }
}

public struct RustMeshTransportMetrics: Equatable, Sendable {
    public let stateCode: UInt32
    public let pathKindCode: UInt32
    public let framesSent: UInt64
    public let framesReceived: UInt64
    public let bytesSent: UInt64
    public let bytesReceived: UInt64
    public let sendFailures: UInt64
    public let receiveFailures: UInt64
    public let networkEventCount: UInt64
    public let reconnectCount: UInt64

    public var state: RustMeshTransportState {
        RustMeshTransportState(rawValue: stateCode) ?? .failed
    }

    public var pathKind: RustMeshTransportPathKind {
        RustMeshTransportPathKind(rawValue: pathKindCode) ?? .none
    }
}

public protocol TunnelCoreAdapting: AnyObject {
    func submitTunnelPacket(_ packet: Data, protocolFamily: UInt32) throws -> TunnelPacketDisposition
    func popTransportFrame() throws -> Data?
    func acceptTransportFrame(_ frame: Data) throws
    func popTunnelPacket() throws -> TunnelCorePacket?
    func metrics() throws -> TunnelCoreMetrics
    func installPeerSession(peerID: String, expiresAt: Date, rekeyAfterPackets: UInt64) throws
    func clearPeerSession() throws
    func peerSessionReady() throws -> Bool
}

public extension TunnelCoreAdapting {
    func installPeerSession(peerID: String, expiresAt: Date, rekeyAfterPackets: UInt64) throws {
        throw RustCoreBridgeError.operationFailed("Tunnel core adapter does not support peer-session installation")
    }

    func clearPeerSession() throws {
        throw RustCoreBridgeError.operationFailed("Tunnel core adapter does not support peer-session clearing")
    }

    func peerSessionReady() throws -> Bool {
        false
    }
}

public final class RustCoreLibrary {
    public static func openBundledOrConfigured() throws -> RustCoreLibrary {
        let paths = candidateLibraryPaths()
        for path in paths where FileManager.default.fileExists(atPath: path) {
            return try RustCoreLibrary(path: path)
        }
        throw RustCoreBridgeError.libraryNotFound(paths)
    }

    public static func candidateLibraryPaths(bundle: Bundle = .main) -> [String] {
        var paths: [String] = []
        if let configured = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"], !configured.isEmpty {
            paths.append(configured)
        }
        if let frameworksPath = bundle.privateFrameworksPath {
            paths.append((frameworksPath as NSString).appendingPathComponent("libqlink_core.dylib"))
        }
        paths.append(bundle.bundleURL.appendingPathComponent("Contents/Frameworks/libqlink_core.dylib").path)
        paths.append("/usr/local/lib/libqlink_core.dylib")
        paths.append("/opt/homebrew/lib/libqlink_core.dylib")
        return Array(NSOrderedSet(array: paths)) as? [String] ?? paths
    }

    private let libraryHandle: UnsafeMutableRawPointer
    private let symbols: Symbols

    public init(path: String) throws {
        guard let handle = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
            throw RustCoreBridgeError.openFailed(String(cString: dlerror()))
        }
        do {
            self.libraryHandle = handle
            self.symbols = try Symbols(handle: handle)
        } catch {
            dlclose(handle)
            throw error
        }
    }

    deinit {
        dlclose(libraryHandle)
    }

    public var version: String {
        String(cString: symbols.version())
    }

    public var defaultSuite: String {
        String(cString: symbols.defaultSuite())
    }

    fileprivate func createTunnelCore(configurationData: Data) throws -> UnsafeMutableRawPointer {
        let handle = configurationData.withUnsafeBytes { rawBuffer in
            symbols.create(rawBuffer.bindMemory(to: UInt8.self).baseAddress, rawBuffer.count)
        }
        guard let handle else {
            throw RustCoreBridgeError.initializationFailed
        }
        return handle
    }

    fileprivate func destroyTunnelCore(_ handle: UnsafeMutableRawPointer) {
        symbols.destroy(handle)
    }

    fileprivate func submitPacket(
        handle: UnsafeMutableRawPointer,
        protocolFamily: UInt32,
        packet: Data
    ) throws -> TunnelPacketDisposition {
        let result = packet.withUnsafeBytes { rawBuffer in
            symbols.submitPacket(
                handle,
                protocolFamily,
                rawBuffer.bindMemory(to: UInt8.self).baseAddress,
                rawBuffer.count
            )
        }
        switch result {
        case 1:
            return .queuedForTransport
        case 0:
            return .droppedUnprotected
        case 2:
            return .droppedPeerSessionUnavailable
        default:
            throw RustCoreBridgeError.operationFailed("Rust tunnel core rejected packet")
        }
    }

    fileprivate func popTransportFrame(handle: UnsafeMutableRawPointer) -> Data? {
        var buffer = QlinkOwnedBuffer()
        let hasFrame = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbols.popTransportFrame(handle, UnsafeMutableRawPointer(pointer))
        }
        guard hasFrame else {
            return nil
        }
        return consume(buffer: buffer)
    }

    fileprivate func acceptTransportFrame(handle: UnsafeMutableRawPointer, frame: Data) throws {
        let result = frame.withUnsafeBytes { rawBuffer in
            symbols.acceptTransportFrame(
                handle,
                rawBuffer.bindMemory(to: UInt8.self).baseAddress,
                rawBuffer.count
            )
        }
        guard result == 0 else {
            throw RustCoreBridgeError.operationFailed("Rust tunnel core rejected transport frame")
        }
    }

    fileprivate func popTunnelPacket(handle: UnsafeMutableRawPointer) -> TunnelCorePacket? {
        var packet = QlinkOwnedPacket()
        let hasPacket = withUnsafeMutablePointer(to: &packet) { pointer in
            symbols.popTunnelPacket(handle, UnsafeMutableRawPointer(pointer))
        }
        guard hasPacket else {
            return nil
        }
        let bytes = consume(buffer: packet.buffer)
        return TunnelCorePacket(protocolFamily: packet.protocolFamily, bytes: bytes)
    }

    fileprivate func metrics(handle: UnsafeMutableRawPointer) throws -> TunnelCoreMetrics {
        var metrics = QlinkTunnelMetrics()
        let ok = withUnsafeMutablePointer(to: &metrics) { pointer in
            symbols.metrics(handle, UnsafeMutableRawPointer(pointer))
        }
        guard ok else {
            throw RustCoreBridgeError.operationFailed("Rust tunnel core metrics unavailable")
        }
        return TunnelCoreMetrics(
            packetsFromTunnel: metrics.packetsFromTunnel,
            packetsToTunnel: metrics.packetsToTunnel,
            transportFramesOut: metrics.transportFramesOut,
            transportFramesIn: metrics.transportFramesIn,
            droppedUnprotected: metrics.droppedUnprotected,
            droppedMalformed: metrics.droppedMalformed,
            droppedPeerSessionUnavailable: metrics.droppedPeerSessionUnavailable,
            droppedReplay: metrics.droppedReplay,
            peerSessionRequired: metrics.peerSessionRequired != 0,
            peerSessionReady: metrics.peerSessionReady != 0
        )
    }

    fileprivate func installPeerSession(
        handle: UnsafeMutableRawPointer,
        peerID: String,
        expiresAt: Date,
        rekeyAfterPackets: UInt64
    ) throws {
        guard let install = symbols.tunnelCoreInstallPeerSession else {
            throw RustCoreBridgeError.missingSymbol("qlink_tunnel_core_install_peer_session")
        }
        let peerIDData = Data(peerID.utf8)
        let expiresAtUnix = UInt64(max(0, expiresAt.timeIntervalSince1970))
        let ok = peerIDData.withUnsafeBytes { rawBuffer in
            install(
                handle,
                rawBuffer.bindMemory(to: UInt8.self).baseAddress,
                rawBuffer.count,
                expiresAtUnix,
                rekeyAfterPackets
            )
        }
        guard ok else {
            throw RustCoreBridgeError.operationFailed("Rust tunnel core rejected peer-session installation")
        }
    }

    fileprivate func clearPeerSession(handle: UnsafeMutableRawPointer) throws {
        guard let clear = symbols.tunnelCoreClearPeerSession else {
            throw RustCoreBridgeError.missingSymbol("qlink_tunnel_core_clear_peer_session")
        }
        guard clear(handle) else {
            throw RustCoreBridgeError.operationFailed("Rust tunnel core rejected peer-session clear")
        }
    }

    fileprivate func peerSessionReady(handle: UnsafeMutableRawPointer) throws -> Bool {
        guard let ready = symbols.tunnelCorePeerSessionReady else {
            throw RustCoreBridgeError.missingSymbol("qlink_tunnel_core_peer_session_ready")
        }
        return ready(handle)
    }

    func createDevQuicTransport() throws -> UnsafeMutableRawPointer {
        guard let handle = symbols.devQuicTransportCreate() else {
            throw RustCoreBridgeError.operationFailed(
                "Rust dev QUIC transport is disabled because raw Quinn DATAGRAM bypasses the app-layer PQC frame session"
            )
        }
        return handle
    }

    func destroyDevQuicTransport(_ handle: UnsafeMutableRawPointer) {
        symbols.devQuicTransportDestroy(handle)
    }

    func sendDevQuicFrame(handle: UnsafeMutableRawPointer, frame: Data) throws {
        let result = frame.withUnsafeBytes { rawBuffer in
            symbols.devQuicTransportSendFrame(
                handle,
                rawBuffer.bindMemory(to: UInt8.self).baseAddress,
                rawBuffer.count
            )
        }
        guard result == 0 else {
            throw RustCoreBridgeError.operationFailed("Rust dev QUIC transport rejected frame")
        }
    }

    func receiveDevQuicFrame(handle: UnsafeMutableRawPointer) -> Data? {
        var buffer = QlinkOwnedBuffer()
        let hasFrame = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbols.devQuicTransportReceiveFrame(handle, UnsafeMutableRawPointer(pointer))
        }
        guard hasFrame else {
            return nil
        }
        return consume(buffer: buffer)
    }

    func devQuicTransportMetrics(handle: UnsafeMutableRawPointer) throws -> RustDevQuicTransportMetrics {
        var metrics = QlinkTransportMetrics()
        let ok = withUnsafeMutablePointer(to: &metrics) { pointer in
            symbols.devQuicTransportMetrics(handle, UnsafeMutableRawPointer(pointer))
        }
        guard ok else {
            throw RustCoreBridgeError.operationFailed("Rust dev QUIC transport metrics unavailable")
        }
        return RustDevQuicTransportMetrics(
            framesSent: metrics.framesSent,
            framesReceived: metrics.framesReceived,
            bytesSent: metrics.bytesSent,
            bytesReceived: metrics.bytesReceived,
            sendFailures: metrics.sendFailures,
            receiveFailures: metrics.receiveFailures
        )
    }

    // MARK: - Mesh transport (production data plane)

    func createMeshTransport(configJSON: Data) throws -> UnsafeMutableRawPointer {
        let handle = configJSON.withUnsafeBytes { rawBuffer -> UnsafeMutableRawPointer? in
            symbols.meshTransportCreate(
                rawBuffer.bindMemory(to: UInt8.self).baseAddress,
                rawBuffer.count
            )
        }
        guard let handle else {
            throw RustCoreBridgeError.initializationFailed
        }
        return handle
    }

    func destroyMeshTransport(_ handle: UnsafeMutableRawPointer) {
        symbols.meshTransportDestroy(handle)
    }

    func sendMeshTransportFrame(handle: UnsafeMutableRawPointer, frame: Data) throws {
        let result = frame.withUnsafeBytes { rawBuffer in
            symbols.meshTransportSendFrame(
                handle,
                rawBuffer.bindMemory(to: UInt8.self).baseAddress,
                rawBuffer.count
            )
        }
        guard result == 0 else {
            throw RustCoreBridgeError.operationFailed("Rust mesh transport rejected frame")
        }
    }

    func receiveMeshTransportFrame(handle: UnsafeMutableRawPointer) -> RustMeshInboundFrame? {
        var inbound = QlinkInboundFrame()
        let hasFrame = withUnsafeMutablePointer(to: &inbound) { pointer in
            symbols.meshTransportReceiveFrame(handle, UnsafeMutableRawPointer(pointer))
        }
        guard hasFrame else {
            return nil
        }
        // Both buffers are caller-owned. `consume` frees each one.
        let frameBytes = consume(buffer: inbound.frame)
        let peerIDBytes = consume(buffer: inbound.peerId)
        let peerID = String(data: peerIDBytes, encoding: .utf8) ?? ""
        return RustMeshInboundFrame(peerID: peerID, frame: frameBytes)
    }

    func meshTransportMetrics(handle: UnsafeMutableRawPointer) throws -> RustMeshTransportMetrics {
        var raw = QlinkMeshTransportMetricsRaw()
        let ok = withUnsafeMutablePointer(to: &raw) { pointer in
            symbols.meshTransportMetrics(handle, UnsafeMutableRawPointer(pointer))
        }
        guard ok else {
            throw RustCoreBridgeError.operationFailed("Rust mesh transport metrics unavailable")
        }
        return RustMeshTransportMetrics(
            stateCode: raw.stateCode,
            pathKindCode: raw.pathKindCode,
            framesSent: raw.framesSent,
            framesReceived: raw.framesReceived,
            bytesSent: raw.bytesSent,
            bytesReceived: raw.bytesReceived,
            sendFailures: raw.sendFailures,
            receiveFailures: raw.receiveFailures,
            networkEventCount: raw.networkEventCount,
            reconnectCount: raw.reconnectCount
        )
    }

    @discardableResult
    func meshTransportHandleNetworkEvent(
        handle: UnsafeMutableRawPointer,
        event: RustMeshNetworkEvent
    ) -> Int32 {
        symbols.meshTransportHandleNetworkEvent(handle, event.rawValue)
    }

    func meshTransportStateCode(handle: UnsafeMutableRawPointer) -> UInt32 {
        symbols.meshTransportStateCode(handle)
    }

    func meshTransportLastError(handle: UnsafeMutableRawPointer) -> String? {
        var buffer = QlinkOwnedBuffer()
        let hasError = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbols.meshTransportLastError(handle, UnsafeMutableRawPointer(pointer))
        }
        guard hasError else {
            return nil
        }
        let bytes = consume(buffer: buffer)
        return String(data: bytes, encoding: .utf8)
    }

    func meshTransportPeerIDs(handle: UnsafeMutableRawPointer) -> [String]? {
        guard let symbol = symbols.meshTransportPeerIDs else {
            return nil
        }
        var buffer = QlinkOwnedBuffer()
        let ok = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbol(handle, UnsafeMutableRawPointer(pointer))
        }
        guard ok else { return nil }
        let bytes = consume(buffer: buffer)
        guard let string = String(data: bytes, encoding: .utf8) else {
            return []
        }
        return string
            .split(whereSeparator: \.isNewline)
            .map(String.init)
    }

    func meshTransportBlockedPeerHistory(
        handle: UnsafeMutableRawPointer
    ) -> [RustBlockedPeerHistoryEntry]? {
        guard let symbol = symbols.meshTransportBlockedPeerHistory else {
            return nil
        }
        var buffer = QlinkOwnedBuffer()
        let ok = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbol(handle, UnsafeMutableRawPointer(pointer))
        }
        guard ok else { return nil }
        let bytes = consume(buffer: buffer)
        return try? JSONDecoder().decode([RustBlockedPeerHistoryEntry].self, from: bytes)
    }

    // MARK: - Device keypair (cert publishing + persistence)

    /// Generates a fresh ML-DSA-65 device keypair. Returns the opaque
    /// handle plus the 32-byte seed callers must persist (Keychain on
    /// macOS) to reload via `loadDeviceKeypair(seed:)` next launch.
    /// Failing to persist the seed means the published `peer_id`
    /// changes per process restart — defeats the cert-publishing
    /// pipeline.
    func generateDeviceKeypair() throws -> (handle: UnsafeMutableRawPointer, seed: Data) {
        var seed = [UInt8](repeating: 0, count: 32)
        let handle = seed.withUnsafeMutableBufferPointer { buffer in
            symbols.deviceKeypairGenerate(buffer.baseAddress)
        }
        guard let handle else {
            throw RustCoreBridgeError.operationFailed("Rust device keypair generation failed")
        }
        return (handle, Data(seed))
    }

    /// Reconstructs a device keypair from a 32-byte seed previously
    /// returned by `generateDeviceKeypair()`. Returns nil if the
    /// seed is the wrong length or the bytes don't decode.
    func loadDeviceKeypair(seed: Data) throws -> UnsafeMutableRawPointer {
        guard seed.count == 32 else {
            throw RustCoreBridgeError.operationFailed("Device keypair seed must be exactly 32 bytes; got \(seed.count)")
        }
        let handle = seed.withUnsafeBytes { rawBuffer -> UnsafeMutableRawPointer? in
            symbols.deviceKeypairFromSeed(rawBuffer.bindMemory(to: UInt8.self).baseAddress)
        }
        guard let handle else {
            throw RustCoreBridgeError.operationFailed("Rust device keypair seed decode failed")
        }
        return handle
    }

    func destroyDeviceKeypair(_ handle: UnsafeMutableRawPointer) {
        symbols.deviceKeypairDestroy(handle)
    }

    func deviceKeypairPeerID(handle: UnsafeMutableRawPointer) -> String? {
        var buffer = QlinkOwnedBuffer()
        let ok = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbols.deviceKeypairPeerId(handle, UnsafeMutableRawPointer(pointer))
        }
        guard ok else { return nil }
        let bytes = consume(buffer: buffer)
        return String(data: bytes, encoding: .utf8)
    }

    // MARK: - Mesh transport (keypair + multi-peer + cert-publishing)

    func createMeshTransport(
        configJSON: Data,
        keypair: UnsafeMutableRawPointer
    ) throws -> UnsafeMutableRawPointer {
        let handle = configJSON.withUnsafeBytes { rawBuffer -> UnsafeMutableRawPointer? in
            symbols.meshTransportCreateWithKeypair(
                rawBuffer.bindMemory(to: UInt8.self).baseAddress,
                rawBuffer.count,
                keypair
            )
        }
        guard let handle else {
            throw RustCoreBridgeError.initializationFailed
        }
        return handle
    }

    func meshTransportServerCertificateDER(handle: UnsafeMutableRawPointer) -> Data? {
        var buffer = QlinkOwnedBuffer()
        let ok = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbols.meshTransportServerCertificateDer(handle, UnsafeMutableRawPointer(pointer))
        }
        guard ok else { return nil }
        return consume(buffer: buffer)
    }

    func meshTransportResponderLocalAddress(handle: UnsafeMutableRawPointer) -> String? {
        var buffer = QlinkOwnedBuffer()
        let ok = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbols.meshTransportResponderLocalAddr(handle, UnsafeMutableRawPointer(pointer))
        }
        guard ok else { return nil }
        let bytes = consume(buffer: buffer)
        return String(data: bytes, encoding: .utf8)
    }

    func meshTransportPublishSelf(
        handle: UnsafeMutableRawPointer,
        keypair: UnsafeMutableRawPointer,
        rendezvousURL: String,
        ttlSeconds: UInt64,
        sequence: UInt64
    ) throws {
        let urlBytes = Array(rendezvousURL.utf8)
        let result = urlBytes.withUnsafeBufferPointer { buffer in
            symbols.meshTransportPublishSelf(
                handle,
                keypair,
                buffer.baseAddress,
                buffer.count,
                ttlSeconds,
                sequence
            )
        }
        guard result == 0 else {
            throw RustCoreBridgeError.operationFailed("Rust mesh transport publish_self failed (code \(result))")
        }
    }

    func meshTransportAddPeer(
        handle: UnsafeMutableRawPointer,
        peerID: String
    ) throws {
        let bytes = Array(peerID.utf8)
        let result = bytes.withUnsafeBufferPointer { buffer in
            symbols.meshTransportAddPeer(handle, buffer.baseAddress, buffer.count)
        }
        guard result == 0 else {
            throw RustCoreBridgeError.operationFailed("Rust mesh transport add_peer failed (code \(result))")
        }
    }

    func meshTransportRemovePeer(
        handle: UnsafeMutableRawPointer,
        peerID: String
    ) {
        let bytes = Array(peerID.utf8)
        bytes.withUnsafeBufferPointer { buffer in
            symbols.meshTransportRemovePeer(handle, buffer.baseAddress, buffer.count)
        }
    }

    func meshTransportPeerStateCode(
        handle: UnsafeMutableRawPointer,
        peerID: String
    ) -> UInt32? {
        let bytes = Array(peerID.utf8)
        var stateCode: UInt32 = 0
        let ok = bytes.withUnsafeBufferPointer { buffer -> Bool in
            withUnsafeMutablePointer(to: &stateCode) { statePtr in
                symbols.meshTransportPeerStateCode(handle, buffer.baseAddress, buffer.count, statePtr)
            }
        }
        return ok ? stateCode : nil
    }

    func meshTransportPeerTrustStatus(
        handle: UnsafeMutableRawPointer,
        peerID: String
    ) -> RustMeshPeerTrustStatus? {
        guard let symbol = symbols.meshTransportPeerTrustStatus else {
            return nil
        }
        let bytes = Array(peerID.utf8)
        var rawStatus = QlinkPeerTrustStatusRaw()
        let ok = bytes.withUnsafeBufferPointer { buffer -> Bool in
            withUnsafeMutablePointer(to: &rawStatus) { statusPtr in
                symbol(handle, buffer.baseAddress, buffer.count, UnsafeMutableRawPointer(statusPtr))
            }
        }
        guard ok else { return nil }
        let decision = RustMeshPeerTrustDecision(rawValue: rawStatus.decisionCode) ?? .unknown
        let failure = RustMeshPeerTrustFailure(rawValue: rawStatus.failureCode)
            ?? .registryVerificationFailed
        let checkedAt = rawStatus.checkedAtUnix > 0
            ? Date(timeIntervalSince1970: TimeInterval(rawStatus.checkedAtUnix))
            : nil
        let source = RustMeshPeerTrustSource(rawValue: rawStatus.sourceCode) ?? .unknown
        return RustMeshPeerTrustStatus(
            decision: decision,
            failure: failure,
            checkedAt: checkedAt,
            source: source
        )
    }

    func meshTransportSendFrameTo(
        handle: UnsafeMutableRawPointer,
        peerID: String,
        frame: Data
    ) throws {
        let peerBytes = Array(peerID.utf8)
        let result = peerBytes.withUnsafeBufferPointer { peerBuffer -> Int32 in
            frame.withUnsafeBytes { frameRaw in
                symbols.meshTransportSendFrameTo(
                    handle,
                    peerBuffer.baseAddress,
                    peerBuffer.count,
                    frameRaw.bindMemory(to: UInt8.self).baseAddress,
                    frameRaw.count
                )
            }
        }
        guard result == 0 else {
            throw RustCoreBridgeError.operationFailed("Rust mesh transport send_frame_to failed (code \(result))")
        }
    }

    // MARK: - Tracing bridge (Rust warnings/errors → host logger)

    /// Installs the in-process tracing subscriber. Idempotent.
    /// Returns `true` on success; `false` when some other code has
    /// already set a global tracing subscriber for this process (in
    /// which case the bridge is unavailable and Rust diagnostics
    /// stay silent — the Swift caller should treat this as a soft
    /// failure, not an error).
    @discardableResult
    func installTracingBridge() -> Bool {
        symbols.tracingInstall() == 0
    }

    /// Pops the next captured Rust tracing event as a JSON string.
    /// Returns `nil` when the buffer is empty or the bridge isn't
    /// installed. Caller is responsible for redacting the event's
    /// `message` field before forwarding to a user-visible logger
    /// (the message routinely contains peer_ids, addresses, and
    /// rendezvous URLs from Rust-side error context).
    func popTracingEvent() -> String? {
        var buffer = QlinkOwnedBuffer()
        let hasEvent = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbols.tracingPopEvent(UnsafeMutableRawPointer(pointer))
        }
        guard hasEvent else { return nil }
        let bytes = consume(buffer: buffer)
        return String(data: bytes, encoding: .utf8)
    }

    /// Cumulative count of Rust tracing events dropped due to ring
    /// buffer pressure. Non-zero means at least one event was lost
    /// since process start.
    func tracingDroppedCount() -> UInt64 {
        symbols.tracingDroppedCount()
    }

    private func consume(buffer: QlinkOwnedBuffer) -> Data {
        var mutableBuffer = buffer
        defer {
            withUnsafeMutablePointer(to: &mutableBuffer) { pointer in
                symbols.freeBuffer(UnsafeMutableRawPointer(pointer))
            }
        }
        guard let ptr = buffer.ptr, buffer.len > 0 else {
            return Data()
        }
        return Data(bytes: ptr, count: buffer.len)
    }
}

public final class RustTunnelCoreAdapter: TunnelCoreAdapting {
    private let library: RustCoreLibrary
    private let handle: UnsafeMutableRawPointer

    public init(configuration: TunnelConfiguration, library: RustCoreLibrary) throws {
        self.library = library
        let encoder = JSONEncoder()
        let configurationData = try encoder.encode(configuration)
        self.handle = try library.createTunnelCore(configurationData: configurationData)
    }

    deinit {
        library.destroyTunnelCore(handle)
    }

    public func submitTunnelPacket(_ packet: Data, protocolFamily: UInt32) throws -> TunnelPacketDisposition {
        try library.submitPacket(handle: handle, protocolFamily: protocolFamily, packet: packet)
    }

    public func popTransportFrame() throws -> Data? {
        library.popTransportFrame(handle: handle)
    }

    public func acceptTransportFrame(_ frame: Data) throws {
        try library.acceptTransportFrame(handle: handle, frame: frame)
    }

    public func popTunnelPacket() throws -> TunnelCorePacket? {
        library.popTunnelPacket(handle: handle)
    }

    public func metrics() throws -> TunnelCoreMetrics {
        try library.metrics(handle: handle)
    }

    public func installPeerSession(peerID: String, expiresAt: Date, rekeyAfterPackets: UInt64) throws {
        try library.installPeerSession(
            handle: handle,
            peerID: peerID,
            expiresAt: expiresAt,
            rekeyAfterPackets: rekeyAfterPackets
        )
    }

    public func clearPeerSession() throws {
        try library.clearPeerSession(handle: handle)
    }

    public func peerSessionReady() throws -> Bool {
        try library.peerSessionReady(handle: handle)
    }
}

private struct QlinkOwnedBuffer {
    var ptr: UnsafeMutablePointer<UInt8>?
    var len: Int
    var cap: Int

    init(ptr: UnsafeMutablePointer<UInt8>? = nil, len: Int = 0, cap: Int = 0) {
        self.ptr = ptr
        self.len = len
        self.cap = cap
    }
}

private struct QlinkOwnedPacket {
    var protocolFamily: UInt32
    var buffer: QlinkOwnedBuffer

    init(protocolFamily: UInt32 = 0, buffer: QlinkOwnedBuffer = QlinkOwnedBuffer()) {
        self.protocolFamily = protocolFamily
        self.buffer = buffer
    }
}

/// Mirror of the Rust `QlinkInboundFrame` struct (see `ffi.rs`). Field
/// order and layout must stay identical for the FFI cast to be safe.
private struct QlinkInboundFrame {
    var frame: QlinkOwnedBuffer
    var peerId: QlinkOwnedBuffer

    init(frame: QlinkOwnedBuffer = QlinkOwnedBuffer(), peerId: QlinkOwnedBuffer = QlinkOwnedBuffer()) {
        self.frame = frame
        self.peerId = peerId
    }
}

private struct QlinkPeerTrustStatusRaw {
    var decisionCode: UInt32 = 0
    var failureCode: UInt32 = 0
    var checkedAtUnix: UInt64 = 0
    var sourceCode: UInt32 = 0
}

private struct QlinkTunnelMetrics {
    var packetsFromTunnel: UInt64 = 0
    var packetsToTunnel: UInt64 = 0
    var transportFramesOut: UInt64 = 0
    var transportFramesIn: UInt64 = 0
    var droppedUnprotected: UInt64 = 0
    var droppedMalformed: UInt64 = 0
    var droppedPeerSessionUnavailable: UInt64 = 0
    var droppedReplay: UInt64 = 0
    var peerSessionRequired: UInt32 = 0
    var peerSessionReady: UInt32 = 0
}

private struct QlinkTransportMetrics {
    var framesSent: UInt64 = 0
    var framesReceived: UInt64 = 0
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0
    var sendFailures: UInt64 = 0
    var receiveFailures: UInt64 = 0
}

private struct QlinkMeshTransportMetricsRaw {
    var stateCode: UInt32 = 0
    var pathKindCode: UInt32 = 0
    var framesSent: UInt64 = 0
    var framesReceived: UInt64 = 0
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0
    var sendFailures: UInt64 = 0
    var receiveFailures: UInt64 = 0
    var networkEventCount: UInt64 = 0
    var reconnectCount: UInt64 = 0
}

private struct Symbols {
    typealias VersionFn = @convention(c) () -> UnsafePointer<CChar>
    typealias CreateFn = @convention(c) (UnsafePointer<UInt8>?, Int) -> UnsafeMutableRawPointer?
    typealias DestroyFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias SubmitPacketFn = @convention(c) (UnsafeMutableRawPointer?, UInt32, UnsafePointer<UInt8>?, Int) -> Int32
    typealias PopTransportFrameFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias AcceptTransportFrameFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) -> Int32
    typealias PopTunnelPacketFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias MetricsFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias InstallPeerSessionFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, UInt64, UInt64) -> Bool
    typealias ClearPeerSessionFn = @convention(c) (UnsafeMutableRawPointer?) -> Bool
    typealias PeerSessionReadyFn = @convention(c) (UnsafeMutableRawPointer?) -> Bool
    typealias DevQuicCreateFn = @convention(c) () -> UnsafeMutableRawPointer?
    typealias DevQuicDestroyFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias DevQuicSendFrameFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) -> Int32
    typealias DevQuicReceiveFrameFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias FreeBufferFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    // Mesh transport (production data plane).
    typealias MeshCreateFn = @convention(c) (UnsafePointer<UInt8>?, Int) -> UnsafeMutableRawPointer?
    typealias MeshDestroyFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias MeshSendFrameFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) -> Int32
    typealias MeshReceiveFrameFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias MeshMetricsFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias MeshHandleEventFn = @convention(c) (UnsafeMutableRawPointer?, UInt32) -> Int32
    typealias MeshStateCodeFn = @convention(c) (UnsafeMutableRawPointer?) -> UInt32
    typealias MeshLastErrorFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias MeshPeerIDsFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias MeshBlockedPeerHistoryFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    // Device keypair handle management (used for cert publishing).
    typealias DeviceKeypairGenerateFn = @convention(c) (UnsafeMutablePointer<UInt8>?) -> UnsafeMutableRawPointer?
    typealias DeviceKeypairFromSeedFn = @convention(c) (UnsafePointer<UInt8>?) -> UnsafeMutableRawPointer?
    typealias DeviceKeypairDestroyFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias DeviceKeypairPeerIdFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    // Mesh transport — keypair-aware constructor + cert-publishing surface.
    typealias MeshCreateWithKeypairFn = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer?
    typealias MeshServerCertFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias MeshResponderAddrFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Bool
    typealias MeshPublishSelfFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, UInt64, UInt64) -> Int32
    // Multi-peer control surface.
    typealias MeshAddPeerFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) -> Int32
    typealias MeshRemovePeerFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) -> Void
    typealias MeshPeerStateCodeFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UInt32>?) -> Bool
    typealias MeshPeerTrustStatusFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?) -> Bool
    typealias MeshSendFrameToFn = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int) -> Int32
    // Tracing bridge — surfaces Rust-side warnings/errors to the host logger.
    typealias TracingInstallFn = @convention(c) () -> Int32
    typealias TracingPopEventFn = @convention(c) (UnsafeMutableRawPointer?) -> Bool
    typealias TracingDroppedCountFn = @convention(c) () -> UInt64

    let version: VersionFn
    let defaultSuite: VersionFn
    let create: CreateFn
    let destroy: DestroyFn
    let submitPacket: SubmitPacketFn
    let popTransportFrame: PopTransportFrameFn
    let acceptTransportFrame: AcceptTransportFrameFn
    let popTunnelPacket: PopTunnelPacketFn
    let metrics: MetricsFn
    let tunnelCoreInstallPeerSession: InstallPeerSessionFn?
    let tunnelCoreClearPeerSession: ClearPeerSessionFn?
    let tunnelCorePeerSessionReady: PeerSessionReadyFn?
    let devQuicTransportCreate: DevQuicCreateFn
    let devQuicTransportDestroy: DevQuicDestroyFn
    let devQuicTransportSendFrame: DevQuicSendFrameFn
    let devQuicTransportReceiveFrame: DevQuicReceiveFrameFn
    let devQuicTransportMetrics: MetricsFn
    let freeBuffer: FreeBufferFn
    let meshTransportCreate: MeshCreateFn
    let meshTransportDestroy: MeshDestroyFn
    let meshTransportSendFrame: MeshSendFrameFn
    let meshTransportReceiveFrame: MeshReceiveFrameFn
    let meshTransportMetrics: MeshMetricsFn
    let meshTransportHandleNetworkEvent: MeshHandleEventFn
    let meshTransportStateCode: MeshStateCodeFn
    let meshTransportLastError: MeshLastErrorFn
    let meshTransportPeerIDs: MeshPeerIDsFn?
    let meshTransportBlockedPeerHistory: MeshBlockedPeerHistoryFn?
    let deviceKeypairGenerate: DeviceKeypairGenerateFn
    let deviceKeypairFromSeed: DeviceKeypairFromSeedFn
    let deviceKeypairDestroy: DeviceKeypairDestroyFn
    let deviceKeypairPeerId: DeviceKeypairPeerIdFn
    let meshTransportCreateWithKeypair: MeshCreateWithKeypairFn
    let meshTransportServerCertificateDer: MeshServerCertFn
    let meshTransportResponderLocalAddr: MeshResponderAddrFn
    let meshTransportPublishSelf: MeshPublishSelfFn
    let meshTransportAddPeer: MeshAddPeerFn
    let meshTransportRemovePeer: MeshRemovePeerFn
    let meshTransportPeerStateCode: MeshPeerStateCodeFn
    let meshTransportPeerTrustStatus: MeshPeerTrustStatusFn?
    let meshTransportSendFrameTo: MeshSendFrameToFn
    let tracingInstall: TracingInstallFn
    let tracingPopEvent: TracingPopEventFn
    let tracingDroppedCount: TracingDroppedCountFn

    init(handle: UnsafeMutableRawPointer) throws {
        self.version = try load("qlink_core_version", from: handle)
        self.defaultSuite = try load("qlink_core_default_suite", from: handle)
        self.create = try load("qlink_tunnel_core_create", from: handle)
        self.destroy = try load("qlink_tunnel_core_destroy", from: handle)
        self.submitPacket = try load("qlink_tunnel_core_submit_packet", from: handle)
        self.popTransportFrame = try load("qlink_tunnel_core_pop_transport_frame", from: handle)
        self.acceptTransportFrame = try load("qlink_tunnel_core_accept_transport_frame", from: handle)
        self.popTunnelPacket = try load("qlink_tunnel_core_pop_tunnel_packet", from: handle)
        self.metrics = try load("qlink_tunnel_core_metrics", from: handle)
        self.tunnelCoreInstallPeerSession = optionalLoad("qlink_tunnel_core_install_peer_session", from: handle)
        self.tunnelCoreClearPeerSession = optionalLoad("qlink_tunnel_core_clear_peer_session", from: handle)
        self.tunnelCorePeerSessionReady = optionalLoad("qlink_tunnel_core_peer_session_ready", from: handle)
        self.devQuicTransportCreate = try load("qlink_dev_quic_transport_create", from: handle)
        self.devQuicTransportDestroy = try load("qlink_dev_quic_transport_destroy", from: handle)
        self.devQuicTransportSendFrame = try load("qlink_dev_quic_transport_send_frame", from: handle)
        self.devQuicTransportReceiveFrame = try load("qlink_dev_quic_transport_receive_frame", from: handle)
        self.devQuicTransportMetrics = try load("qlink_dev_quic_transport_metrics", from: handle)
        self.freeBuffer = try load("qlink_owned_buffer_free_ptr", from: handle)
        self.meshTransportCreate = try load("qlink_mesh_transport_create", from: handle)
        self.meshTransportDestroy = try load("qlink_mesh_transport_destroy", from: handle)
        self.meshTransportSendFrame = try load("qlink_mesh_transport_send_frame", from: handle)
        self.meshTransportReceiveFrame = try load("qlink_mesh_transport_receive_frame", from: handle)
        self.meshTransportMetrics = try load("qlink_mesh_transport_metrics", from: handle)
        self.meshTransportHandleNetworkEvent = try load(
            "qlink_mesh_transport_handle_network_event", from: handle
        )
        self.meshTransportStateCode = try load("qlink_mesh_transport_state_code", from: handle)
        self.meshTransportLastError = try load("qlink_mesh_transport_last_error", from: handle)
        self.meshTransportPeerIDs = optionalLoad("qlink_mesh_transport_peer_ids", from: handle)
        self.meshTransportBlockedPeerHistory = optionalLoad(
            "qlink_mesh_transport_blocked_peer_history",
            from: handle
        )
        self.deviceKeypairGenerate = try load("qlink_device_keypair_generate", from: handle)
        self.deviceKeypairFromSeed = try load("qlink_device_keypair_from_seed", from: handle)
        self.deviceKeypairDestroy = try load("qlink_device_keypair_destroy", from: handle)
        self.deviceKeypairPeerId = try load("qlink_device_keypair_peer_id", from: handle)
        self.meshTransportCreateWithKeypair = try load(
            "qlink_mesh_transport_create_with_keypair", from: handle
        )
        self.meshTransportServerCertificateDer = try load(
            "qlink_mesh_transport_server_certificate_der", from: handle
        )
        self.meshTransportResponderLocalAddr = try load(
            "qlink_mesh_transport_responder_local_addr", from: handle
        )
        self.meshTransportPublishSelf = try load("qlink_mesh_transport_publish_self", from: handle)
        self.meshTransportAddPeer = try load("qlink_mesh_transport_add_peer", from: handle)
        self.meshTransportRemovePeer = try load("qlink_mesh_transport_remove_peer", from: handle)
        self.meshTransportPeerStateCode = try load(
            "qlink_mesh_transport_peer_state_code", from: handle
        )
        self.meshTransportPeerTrustStatus = optionalLoad(
            "qlink_mesh_transport_peer_trust_status", from: handle
        )
        self.meshTransportSendFrameTo = try load(
            "qlink_mesh_transport_send_frame_to", from: handle
        )
        self.tracingInstall = try load("qlink_tracing_install", from: handle)
        self.tracingPopEvent = try load("qlink_tracing_pop_event", from: handle)
        self.tracingDroppedCount = try load("qlink_tracing_dropped_count", from: handle)
    }
}

private func load<T>(_ symbol: String, from handle: UnsafeMutableRawPointer) throws -> T {
    guard let pointer = dlsym(handle, symbol) else {
        throw RustCoreBridgeError.missingSymbol(symbol)
    }
    return unsafeBitCast(pointer, to: T.self)
}

private func optionalLoad<T>(_ symbol: String, from handle: UnsafeMutableRawPointer) -> T? {
    guard let pointer = dlsym(handle, symbol) else {
        return nil
    }
    return unsafeBitCast(pointer, to: T.self)
}
