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
            droppedMalformed: metrics.droppedMalformed
        )
    }

    func createDevQuicTransport() throws -> UnsafeMutableRawPointer {
        guard let handle = symbols.devQuicTransportCreate() else {
            throw RustCoreBridgeError.initializationFailed
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

    func receiveMeshTransportFrame(handle: UnsafeMutableRawPointer) -> Data? {
        var buffer = QlinkOwnedBuffer()
        let hasFrame = withUnsafeMutablePointer(to: &buffer) { pointer in
            symbols.meshTransportReceiveFrame(handle, UnsafeMutableRawPointer(pointer))
        }
        guard hasFrame else {
            return nil
        }
        return consume(buffer: buffer)
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

private struct QlinkTunnelMetrics {
    var packetsFromTunnel: UInt64 = 0
    var packetsToTunnel: UInt64 = 0
    var transportFramesOut: UInt64 = 0
    var transportFramesIn: UInt64 = 0
    var droppedUnprotected: UInt64 = 0
    var droppedMalformed: UInt64 = 0
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

    let version: VersionFn
    let defaultSuite: VersionFn
    let create: CreateFn
    let destroy: DestroyFn
    let submitPacket: SubmitPacketFn
    let popTransportFrame: PopTransportFrameFn
    let acceptTransportFrame: AcceptTransportFrameFn
    let popTunnelPacket: PopTunnelPacketFn
    let metrics: MetricsFn
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
    }
}

private func load<T>(_ symbol: String, from handle: UnsafeMutableRawPointer) throws -> T {
    guard let pointer = dlsym(handle, symbol) else {
        throw RustCoreBridgeError.missingSymbol(symbol)
    }
    return unsafeBitCast(pointer, to: T.self)
}
