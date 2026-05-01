import Foundation

public enum TunnelTransportKind: String, Codable, Equatable, Sendable {
    case developmentDrop
    case devQuicLoopback
    case meshQuic
}

/// Configuration for the production `mesh-quic` transport. Built on top of
/// the Rust `MeshConnector` (rendezvous → ICE → paced probes → relay
/// fallback). The Swift side is a thin wrapper over the FFI handle.
///
/// Trust is **not** pinned in this config: the Rust connector reads the
/// remote peer's QUIC server certificate from the signed rendezvous record
/// and uses Quinn's per-connection trust API to validate it. The cert is
/// covered by the record's ML-DSA signature, so an attacker can't substitute
/// a cert without forging the device key.
public struct MeshTransportConfiguration: Codable, Equatable, Sendable {
    public let meshID: String
    public let localPeerID: String
    public let remotePeerID: String
    public let rendezvousURL: String
    public let relayURL: String?
    public let bindAddress: String
    public let overallDeadlineMs: UInt64
    public let directProbeTimeoutMs: UInt64
    public let probePacingMs: UInt64
    public let enableICE: Bool

    public init(
        meshID: String,
        localPeerID: String,
        remotePeerID: String,
        rendezvousURL: String,
        relayURL: String? = nil,
        bindAddress: String = "0.0.0.0:0",
        overallDeadlineMs: UInt64 = 3_000,
        directProbeTimeoutMs: UInt64 = 750,
        probePacingMs: UInt64 = 50,
        enableICE: Bool = false
    ) {
        self.meshID = meshID
        self.localPeerID = localPeerID
        self.remotePeerID = remotePeerID
        self.rendezvousURL = rendezvousURL
        self.relayURL = relayURL
        self.bindAddress = bindAddress
        self.overallDeadlineMs = overallDeadlineMs
        self.directProbeTimeoutMs = directProbeTimeoutMs
        self.probePacingMs = probePacingMs
        self.enableICE = enableICE
    }

    private enum CodingKeys: String, CodingKey {
        case meshID = "meshId"
        case localPeerID = "localPeerId"
        case remotePeerID = "remotePeerId"
        case rendezvousURL = "rendezvousUrl"
        case relayURL = "relayUrl"
        case bindAddress = "bindAddr"
        case overallDeadlineMs
        case directProbeTimeoutMs
        case probePacingMs
        case enableICE = "enableIce"
    }
}

public enum TunnelTransportState: String, Codable, Equatable, Sendable {
    case stopped
    case ready
    case failed
}

public struct TunnelTransportMetrics: Codable, Equatable, Sendable {
    public var kind: TunnelTransportKind
    public var state: TunnelTransportState
    public var pathType: PathType
    public var framesSent: UInt64
    public var framesReceived: UInt64
    public var framesDropped: UInt64
    public var bytesSent: UInt64
    public var bytesReceived: UInt64
    public var bytesDropped: UInt64
    public var sendFailures: UInt64
    public var receiveFailures: UInt64
    public var lastError: String?

    public init(
        kind: TunnelTransportKind,
        state: TunnelTransportState = .stopped,
        pathType: PathType = .unavailable,
        framesSent: UInt64 = 0,
        framesReceived: UInt64 = 0,
        framesDropped: UInt64 = 0,
        bytesSent: UInt64 = 0,
        bytesReceived: UInt64 = 0,
        bytesDropped: UInt64 = 0,
        sendFailures: UInt64 = 0,
        receiveFailures: UInt64 = 0,
        lastError: String? = nil
    ) {
        self.kind = kind
        self.state = state
        self.pathType = pathType
        self.framesSent = framesSent
        self.framesReceived = framesReceived
        self.framesDropped = framesDropped
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.bytesDropped = bytesDropped
        self.sendFailures = sendFailures
        self.receiveFailures = receiveFailures
        self.lastError = lastError
    }
}

public protocol TunnelTransporting: AnyObject, TransportFrameSink {
    var metrics: TunnelTransportMetrics { get }
    func start() throws
    func stop()
    func receiveTransportFrame() throws -> Data?
}

public final class DevelopmentDropTransportSender: TunnelTransporting {
    public private(set) var metrics: TunnelTransportMetrics
    private let reason: String

    public init(reason: String = "No QUIC transport sender is configured") {
        self.reason = reason
        self.metrics = TunnelTransportMetrics(
            kind: .developmentDrop,
            state: .ready,
            pathType: .unavailable,
            lastError: reason
        )
    }

    /// The development drop sender never carries traffic. Reporting `isReady`
    /// as false lets the packet pump activate its kill-switch gate and drop
    /// protected packets at the boundary instead of encoding them only to be
    /// silently discarded.
    public var isReady: Bool { false }

    public func start() throws {
        metrics.state = .ready
        metrics.lastError = reason
    }

    public func stop() {
        metrics.state = .stopped
    }

    public func sendTransportFrame(_ frame: Data) throws {
        metrics.framesDropped += 1
        metrics.bytesDropped += UInt64(frame.count)
        metrics.lastError = reason
    }

    public func receiveTransportFrame() throws -> Data? {
        nil
    }
}

public final class RustDevQuicLoopbackTransport: TunnelTransporting {
    private let library: RustCoreLibrary
    private var handle: UnsafeMutableRawPointer?
    public private(set) var metrics = TunnelTransportMetrics(
        kind: .devQuicLoopback,
        state: .stopped,
        pathType: .unavailable
    )

    public var isReady: Bool { handle != nil && metrics.state == .ready }

    public init(library: RustCoreLibrary) {
        self.library = library
    }

    deinit {
        stop()
    }

    public func start() throws {
        if handle != nil {
            return
        }
        do {
            handle = try library.createDevQuicTransport()
            metrics.state = .ready
            metrics.pathType = .direct
            metrics.lastError = nil
            refreshMetrics()
        } catch {
            metrics.state = .failed
            metrics.pathType = .unavailable
            metrics.lastError = error.localizedDescription
            throw error
        }
    }

    public func stop() {
        if let handle {
            library.destroyDevQuicTransport(handle)
        }
        handle = nil
        metrics.state = .stopped
        metrics.pathType = .unavailable
    }

    public func sendTransportFrame(_ frame: Data) throws {
        guard let handle else {
            metrics.sendFailures += 1
            metrics.lastError = "Dev QUIC transport is not started"
            throw RustCoreBridgeError.operationFailed("Dev QUIC transport is not started")
        }

        do {
            try library.sendDevQuicFrame(handle: handle, frame: frame)
            refreshMetrics()
        } catch {
            metrics.sendFailures += 1
            metrics.lastError = error.localizedDescription
            throw error
        }
    }

    public func receiveTransportFrame() throws -> Data? {
        guard let handle else {
            return nil
        }
        let frame = library.receiveDevQuicFrame(handle: handle)
        refreshMetrics()
        return frame
    }

    private func refreshMetrics() {
        guard let handle, let rustMetrics = try? library.devQuicTransportMetrics(handle: handle) else {
            return
        }

        metrics.framesSent = rustMetrics.framesSent
        metrics.framesReceived = rustMetrics.framesReceived
        metrics.bytesSent = rustMetrics.bytesSent
        metrics.bytesReceived = rustMetrics.bytesReceived
        metrics.sendFailures = rustMetrics.sendFailures
        metrics.receiveFailures = rustMetrics.receiveFailures
    }
}

/// Production data-plane transport. Wraps the Rust `MeshTransport` (which
/// owns the live `MeshConnector` session) behind the `TunnelTransporting`
/// surface that the packet pump already speaks.
///
/// Lifecycle:
///   - `start()` constructs the Rust handle (synchronous; the connector's
///     internal connect runs on its own runtime). The handle reports
///     `state_code` so `isReady` can gate the kill-switch correctly.
///   - `sendTransportFrame()` enqueues outbound frames; the Rust side
///     forwards them to the active `MeshLink`.
///   - `receiveTransportFrame()` polls the Rust inbound queue (non-blocking).
///   - `notifyNetworkEvent(_:)` signals path/wake/reachability transitions
///     so the connector can invalidate caches and re-probe.
///   - `stop()` destroys the handle; the Rust runtime is torn down off the
///     calling thread.
public final class RustMeshTransport: TunnelTransporting {
    private let library: RustCoreLibrary
    private let configuration: MeshTransportConfiguration
    private var handle: UnsafeMutableRawPointer?
    public private(set) var metrics = TunnelTransportMetrics(
        kind: .meshQuic,
        state: .stopped,
        pathType: .unavailable
    )

    public init(library: RustCoreLibrary, configuration: MeshTransportConfiguration) {
        self.library = library
        self.configuration = configuration
    }

    deinit {
        stop()
    }

    public var isReady: Bool {
        guard let handle else { return false }
        return library.meshTransportStateCode(handle: handle) == RustMeshTransportState.ready.rawValue
    }

    public func start() throws {
        if handle != nil {
            return
        }
        do {
            let configJSON = try JSONEncoder().encode(configuration)
            handle = try library.createMeshTransport(configJSON: configJSON)
            metrics.state = .ready
            metrics.pathType = .probing
            metrics.lastError = nil
            refreshMetrics()
        } catch {
            metrics.state = .failed
            metrics.pathType = .unavailable
            metrics.lastError = error.localizedDescription
            throw error
        }
    }

    public func stop() {
        if let handle {
            library.destroyMeshTransport(handle)
        }
        handle = nil
        metrics.state = .stopped
        metrics.pathType = .unavailable
    }

    public func sendTransportFrame(_ frame: Data) throws {
        guard let handle else {
            metrics.sendFailures += 1
            metrics.lastError = "Mesh transport is not started"
            throw RustCoreBridgeError.operationFailed("Mesh transport is not started")
        }
        do {
            try library.sendMeshTransportFrame(handle: handle, frame: frame)
            refreshMetrics()
        } catch {
            metrics.sendFailures += 1
            metrics.lastError = error.localizedDescription
            throw error
        }
    }

    public func receiveTransportFrame() throws -> Data? {
        guard let handle else { return nil }
        let frame = library.receiveMeshTransportFrame(handle: handle)
        refreshMetrics()
        return frame
    }

    /// Forwards a system-level network event to the Rust connector. The
    /// `PacketTunnelProvider` calls this from its `NetworkPathObserver`
    /// callback so the live connector can invalidate caches and re-probe.
    public func notifyNetworkEvent(_ event: RustMeshNetworkEvent) {
        guard let handle else { return }
        _ = library.meshTransportHandleNetworkEvent(handle: handle, event: event)
        refreshMetrics()
    }

    public var lastErrorString: String? {
        guard let handle else { return nil }
        return library.meshTransportLastError(handle: handle)
    }

    private func refreshMetrics() {
        guard let handle else { return }
        guard let raw = try? library.meshTransportMetrics(handle: handle) else { return }
        metrics.framesSent = raw.framesSent
        metrics.framesReceived = raw.framesReceived
        metrics.bytesSent = raw.bytesSent
        metrics.bytesReceived = raw.bytesReceived
        metrics.sendFailures = raw.sendFailures
        metrics.receiveFailures = raw.receiveFailures
        switch raw.state {
        case .connecting:
            metrics.state = .ready
            metrics.pathType = .probing
        case .ready:
            metrics.state = .ready
            metrics.pathType = (raw.pathKind == .relay) ? .relay : .direct
        case .failed:
            metrics.state = .failed
            metrics.pathType = .unavailable
            if metrics.lastError == nil {
                metrics.lastError = library.meshTransportLastError(handle: handle)
            }
        case .stopped:
            metrics.state = .stopped
            metrics.pathType = .unavailable
        }
    }
}

public enum TunnelTransportFactory {
    public static func makeDefault(
        configuration: TunnelConfiguration,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> TunnelTransporting {
        let mode = environment["QLINK_TRANSPORT_MODE"]?.lowercased()

        switch mode {
        case "mesh-quic":
            return makeMeshQuicTransport(environment: environment)
        case "dev-quic-loopback":
            return makeDevQuicLoopbackTransport()
        default:
            return DevelopmentDropTransportSender(
                reason: "Set QLINK_TRANSPORT_MODE=mesh-quic for the production data plane, or QLINK_TRANSPORT_MODE=dev-quic-loopback for local QUIC smoke testing"
            )
        }
    }

    private static func makeDevQuicLoopbackTransport() -> TunnelTransporting {
        do {
            let library = try RustCoreLibrary.openBundledOrConfigured()
            return RustDevQuicLoopbackTransport(library: library)
        } catch {
            return DevelopmentDropTransportSender(
                reason: "Rust dev QUIC transport unavailable: \(error.localizedDescription)"
            )
        }
    }

    private static func makeMeshQuicTransport(
        environment: [String: String]
    ) -> TunnelTransporting {
        guard let configPath = environment["QLINK_MESH_TRANSPORT_CONFIG"], !configPath.isEmpty else {
            return DevelopmentDropTransportSender(
                reason: "QLINK_TRANSPORT_MODE=mesh-quic requires QLINK_MESH_TRANSPORT_CONFIG=/path/to/mesh-transport.json"
            )
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)) else {
            return DevelopmentDropTransportSender(
                reason: "Mesh transport config not readable at \(configPath)"
            )
        }
        guard let configuration = try? JSONDecoder().decode(MeshTransportConfiguration.self, from: data) else {
            return DevelopmentDropTransportSender(
                reason: "Mesh transport config at \(configPath) failed to decode"
            )
        }
        do {
            let library = try RustCoreLibrary.openBundledOrConfigured()
            return RustMeshTransport(library: library, configuration: configuration)
        } catch {
            return DevelopmentDropTransportSender(
                reason: "Rust mesh transport unavailable: \(error.localizedDescription)"
            )
        }
    }
}
