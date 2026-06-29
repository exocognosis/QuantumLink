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
    public let dytallixIdentity: DytallixIdentityConfiguration?
    /// Filesystem path of the persistent peer-record cache.
    /// Mirrors the Rust `peer_store_path`; `nil` keeps the
    /// connector's in-memory-only store. The parent directory must
    /// exist before tunnel start.
    public let peerStorePath: String?
    /// Optional 32-byte ChaCha20-Poly1305 key, base64-encoded
    /// (standard alphabet, with padding). Mirrors the Rust
    /// `peer_store_key_b64`. When set together with `peerStorePath`,
    /// the on-disk cache file is written in the v2 encrypted
    /// envelope; without it the file is plaintext JSON. Mint via
    /// `PeerStoreKey.loadOrGenerateBase64()`.
    public let peerStoreKeyB64: String?

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
        enableICE: Bool = false,
        dytallixIdentity: DytallixIdentityConfiguration? = nil,
        peerStorePath: String? = nil,
        peerStoreKeyB64: String? = nil
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
        self.dytallixIdentity = dytallixIdentity
        self.peerStorePath = peerStorePath
        self.peerStoreKeyB64 = peerStoreKeyB64
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
        case dytallixIdentity
        case peerStorePath = "peerStorePath"
        case peerStoreKeyB64 = "peerStoreKeyB64"
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

/// Inbound frame surfaced by a `TunnelTransporting`. For mesh transports
/// `peerID` is the verified peer ID from the inbound responder loop; for
/// transports with no peer concept (development drop, dev QUIC loopback)
/// it's `nil`.
public struct InboundTransportFrame: Equatable, Sendable {
    public let frame: Data
    public let peerID: String?

    public init(frame: Data, peerID: String? = nil) {
        self.frame = frame
        self.peerID = peerID
    }
}

public protocol TunnelTransporting: AnyObject, TransportFrameSink {
    var metrics: TunnelTransportMetrics { get }
    func start() throws
    func stop()
    func receiveTransportFrame() throws -> InboundTransportFrame?
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

    public func receiveTransportFrame() throws -> InboundTransportFrame? {
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

    public func receiveTransportFrame() throws -> InboundTransportFrame? {
        guard let handle else {
            return nil
        }
        let frame = library.receiveDevQuicFrame(handle: handle)
        refreshMetrics()
        // Dev loopback has a single hard-coded session pair; there's no
        // verified peer identity to report.
        return frame.map { InboundTransportFrame(frame: $0, peerID: nil) }
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
    /// Local device keypair for the responder + cert publishing flow.
    /// When `nil`, the connector skips signing inbound assertions and
    /// `publishSelf` is unavailable. Production deployments MUST set
    /// this to enable real multi-peer connectivity.
    private let keypair: RustDeviceKeypair?
    private var handle: UnsafeMutableRawPointer?
    public private(set) var metrics = TunnelTransportMetrics(
        kind: .meshQuic,
        state: .stopped,
        pathType: .unavailable
    )

    public init(
        library: RustCoreLibrary,
        configuration: MeshTransportConfiguration,
        keypair: RustDeviceKeypair? = nil
    ) {
        self.library = library
        self.configuration = configuration
        self.keypair = keypair
    }

    /// Public peer ID this transport will publish under. `nil` when
    /// no keypair was supplied at construction.
    public var localPeerID: String? {
        keypair?.peerID
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
            // Pick the constructor variant based on whether the
            // caller supplied a keypair. Without a keypair the
            // connector won't sign outbound assertions, so any peer
            // running the inbound responder will silently close us
            // out — but legacy single-peer deployments without a
            // responder still work.
            if let keypair {
                handle = try library.createMeshTransport(configJSON: configJSON, keypair: keypair.handle)
            } else {
                handle = try library.createMeshTransport(configJSON: configJSON)
            }
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

    /// DER-encoded QUIC server certificate the responder presents.
    /// `nil` when the responder is disabled or the transport hasn't
    /// started. Required for callers that mint signed peer records.
    public var serverCertificateDER: Data? {
        guard let handle else { return nil }
        return library.meshTransportServerCertificateDER(handle: handle)
    }

    /// Bound address of the inbound responder, formatted as
    /// `host:port`. `nil` when the responder is disabled or the
    /// transport hasn't started.
    public var responderLocalAddress: String? {
        guard let handle else { return nil }
        return library.meshTransportResponderLocalAddress(handle: handle)
    }

    /// Mints + signs a peer record for the local node and publishes
    /// it to the rendezvous server. Synchronous on the calling
    /// thread (FFI uses the Rust runtime internally). Throws when:
    /// - no keypair was supplied at construction
    /// - the transport hasn't been started
    /// - the responder is disabled in the configuration
    /// - the keypair's peer_id doesn't match `configuration.localPeerID`
    /// - the rendezvous publish call fails
    public func publishSelf(
        rendezvousURL: String,
        ttlSeconds: UInt64 = 120,
        sequence: UInt64
    ) throws {
        guard let handle else {
            throw RustCoreBridgeError.operationFailed("Mesh transport is not started")
        }
        guard let keypair else {
            throw RustCoreBridgeError.operationFailed("publishSelf requires a keypair-equipped transport")
        }
        try library.meshTransportPublishSelf(
            handle: handle,
            keypair: keypair.handle,
            rendezvousURL: rendezvousURL,
            ttlSeconds: ttlSeconds,
            sequence: sequence
        )
    }

    /// Adds a peer to the multi-peer transport. Idempotent. The
    /// transport's session manager will start dialing this peer via
    /// rendezvous + ICE in the background.
    public func addPeer(_ peerID: String) throws {
        guard let handle else {
            throw RustCoreBridgeError.operationFailed("Mesh transport is not started")
        }
        try library.meshTransportAddPeer(handle: handle, peerID: peerID)
    }

    /// Removes a peer from the multi-peer transport. Idempotent.
    public func removePeer(_ peerID: String) {
        guard let handle else { return }
        library.meshTransportRemovePeer(handle: handle, peerID: peerID)
    }

    /// Per-peer state code (`RustMeshTransportState`). `nil` when
    /// the peer isn't active.
    public func peerStateCode(_ peerID: String) -> RustMeshTransportState? {
        guard let handle else { return nil }
        guard let raw = library.meshTransportPeerStateCode(handle: handle, peerID: peerID) else {
            return nil
        }
        return RustMeshTransportState(rawValue: raw)
    }

    /// Sends a frame to a specific peer. Use this when `addPeer` /
    /// `removePeer` has populated multiple peers and the caller
    /// knows which one to target. For single-peer back-compat, use
    /// `sendTransportFrame` (which targets the configured default).
    public func sendFrameTo(_ peerID: String, frame: Data) throws {
        guard let handle else {
            metrics.sendFailures += 1
            metrics.lastError = "Mesh transport is not started"
            throw RustCoreBridgeError.operationFailed("Mesh transport is not started")
        }
        do {
            try library.meshTransportSendFrameTo(handle: handle, peerID: peerID, frame: frame)
            refreshMetrics()
        } catch {
            metrics.sendFailures += 1
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

    public func receiveTransportFrame() throws -> InboundTransportFrame? {
        guard let handle else { return nil }
        guard let inbound = library.receiveMeshTransportFrame(handle: handle) else {
            refreshMetrics()
            return nil
        }
        refreshMetrics()
        return InboundTransportFrame(frame: inbound.frame, peerID: inbound.peerID)
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

/// Encapsulates everything `RustMeshTransport.makeProduction(...)`
/// returns: the transport itself plus the auxiliary state the
/// caller needs to drive publishSelf + diagnostics.
public struct ProductionMeshTransportBundle {
    public let transport: RustMeshTransport
    public let keypair: RustDeviceKeypair
    public let library: RustCoreLibrary
    /// First rendezvous URL configured on the tunnel; used by the
    /// caller to invoke `publishSelf`. `nil` when the configuration
    /// has no rendezvous servers — caller should not start the
    /// publish loop in that case.
    public let rendezvousURL: String?
    /// Whether peer-store on-disk encryption is wired. Diagnostics
    /// surface this so operators can confirm the encrypted path is
    /// active.
    public let peerStoreEncryptionEnabled: Bool
}

public enum TunnelTransportFactoryError: Error, LocalizedError {
    case libraryUnavailable(Error)
    case deviceKeypairLoadFailed(Error)

    public var errorDescription: String? {
        switch self {
        case .libraryUnavailable(let underlying):
            "Rust core library unavailable: \(underlying.localizedDescription)"
        case .deviceKeypairLoadFailed(let underlying):
            "Could not load or generate device keypair: \(underlying.localizedDescription)"
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

    /// Production wiring path: loads the device keypair from the
    /// Keychain (or generates + persists on first launch), optionally
    /// loads the peer-store encryption key, stitches a
    /// `MeshTransportConfiguration` from the tunnel configuration,
    /// and constructs a keypair-equipped `RustMeshTransport`.
    ///
    /// Throws when the Rust dylib is unreachable or the Keychain
    /// can't surface a device keypair (entitlement missing,
    /// disk full on first generation, etc). Callers running outside
    /// a signed app bundle (SPM smoke tests, qlinkctl) should fall
    /// back to `makeDefault` on this throw.
    public static func makeProductionMeshTransport(
        configuration: TunnelConfiguration,
        bindAddress: String = "0.0.0.0:0",
        peerStoreDirectory: URL? = nil,
        keychainStore: KeychainSecretStore? = nil
    ) throws -> ProductionMeshTransportBundle {
        let library: RustCoreLibrary
        do {
            library = try RustCoreLibrary.openBundledOrConfigured()
        } catch {
            throw TunnelTransportFactoryError.libraryUnavailable(error)
        }

        let keychain = keychainStore ?? KeychainSecretStore(service: "com.quantumlink.macos.secrets")

        let keypair: RustDeviceKeypair
        do {
            keypair = try DeviceKeypairStore(keychain: keychain).loadOrGenerate(library: library)
        } catch {
            throw TunnelTransportFactoryError.deviceKeypairLoadFailed(error)
        }

        // Peer-store path: only wire the cache if a directory was
        // given. The caller decides where (NEPacketTunnelProvider
        // uses the app-group container; tests pass a tempdir).
        var peerStorePath: String?
        var peerStoreKeyB64: String?
        var peerStoreEncryptionEnabled = false
        if let dir = peerStoreDirectory {
            // The Rust core does not auto-create the parent
            // directory, so ensure it exists before pointing at it.
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            peerStorePath = dir.appendingPathComponent("peers.json").path
            // Encryption is best-effort: if the Keychain isn't
            // available (SPM smoke), silently ship with plaintext
            // on disk rather than failing the whole launch. The
            // file is still mode 0o600 in either case.
            if let keyB64 = try? PeerStoreKey(keychain: keychain).loadOrGenerateBase64() {
                peerStoreKeyB64 = keyB64
                peerStoreEncryptionEnabled = true
            }
        }

        let rendezvousURL = configuration.rendezvousServers.first
        let relayURL = configuration.relayServers.first

        let meshConfig = MeshTransportConfiguration(
            meshID: configuration.meshID,
            localPeerID: keypair.peerID,
            // Default peer for the legacy single-peer fallback
            // surface; production callers should `addPeer(_:)`
            // explicit peers post-start.
            remotePeerID: "qlink_unconfigured",
            rendezvousURL: rendezvousURL ?? "127.0.0.1:9471",
            relayURL: relayURL,
            bindAddress: bindAddress,
            dytallixIdentity: configuration.dytallixIdentity,
            peerStorePath: peerStorePath,
            peerStoreKeyB64: peerStoreKeyB64
        )

        let transport = RustMeshTransport(
            library: library,
            configuration: meshConfig,
            keypair: keypair
        )
        return ProductionMeshTransportBundle(
            transport: transport,
            keypair: keypair,
            library: library,
            rendezvousURL: rendezvousURL,
            peerStoreEncryptionEnabled: peerStoreEncryptionEnabled
        )
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
