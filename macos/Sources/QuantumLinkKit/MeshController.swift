import Combine
import Foundation

#if canImport(NetworkExtension)
@preconcurrency import NetworkExtension
#endif

@MainActor
public protocol MeshControlling: AnyObject {
    var status: TunnelStatus { get }
    var configuration: TunnelConfiguration { get }
    func connect() async
    func disconnect() async
    func refresh() async
    func updateConfiguration(_ configuration: TunnelConfiguration)
}

@MainActor
public final class AppMeshController: ObservableObject, MeshControlling {
    @Published public private(set) var status: TunnelStatus
    @Published public private(set) var configuration: TunnelConfiguration

#if canImport(NetworkExtension)
    private let profileManager: TunnelProfileManager
    private var statusObserverTask: Task<Void, Never>?
#endif

    public init(configuration: TunnelConfiguration = .defaultDevelopment) {
        self.configuration = configuration
        self.status = Self.makeStatus(
            phase: .idle,
            pathType: .unavailable,
            configuration: configuration,
            peers: [],
            metrics: MeshMetrics()
        )

#if canImport(NetworkExtension)
        self.profileManager = TunnelProfileManager()
        self.statusObserverTask = nil
        observeTunnelStatusChanges()
#endif
    }

    public func updateConfiguration(_ configuration: TunnelConfiguration) {
        self.configuration = configuration
        status = Self.makeStatus(
            phase: status.phase,
            pathType: status.pathType,
            configuration: configuration,
            peers: status.peers,
            metrics: status.metrics,
            transport: status.transport,
            lastError: status.lastError
        )
    }

    public func connect() async {
#if canImport(NetworkExtension)
        status = Self.makeStatus(
            phase: .preparing,
            pathType: .probing,
            configuration: configuration,
            peers: status.peers,
            metrics: status.metrics,
            transport: status.transport
        )

        do {
            _ = try ConfigurationValidator.validate(configuration: configuration)
            try await installProfileIfNeeded()
            let connectionStatus = try await profileManager.connectionStatus(providerBundleIdentifier: providerBundleIdentifier)
            if connectionStatus != .connected && connectionStatus != .connecting && connectionStatus != .reasserting {
                try await profileManager.startTunnel(
                    providerBundleIdentifier: providerBundleIdentifier,
                    options: try startOptions(for: configuration)
                )
            }
            await refresh()
        } catch {
            status = Self.makeStatus(
                phase: .failed,
                pathType: .unavailable,
                configuration: configuration,
                peers: [],
                metrics: MeshMetrics(),
                transport: status.transport,
                lastError: error.localizedDescription
            )
        }
#else
        status = Self.unsupportedStatus(configuration: configuration)
#endif
    }

    public func disconnect() async {
#if canImport(NetworkExtension)
        do {
            try await profileManager.stopTunnel(providerBundleIdentifier: providerBundleIdentifier)
            await refresh()
        } catch {
            status = Self.makeStatus(
                phase: .failed,
                pathType: .unavailable,
                configuration: configuration,
                peers: status.peers,
                metrics: status.metrics,
                transport: status.transport,
                lastError: error.localizedDescription
            )
        }
#else
        status = Self.unsupportedStatus(configuration: configuration)
#endif
    }

    public func refresh() async {
#if canImport(NetworkExtension)
        do {
            let connectionStatus = try await profileManager.connectionStatus(providerBundleIdentifier: providerBundleIdentifier)
            guard connectionStatus == .connected else {
                status = Self.makeStatus(
                    phase: Self.phase(for: connectionStatus),
                    pathType: .unavailable,
                    configuration: configuration,
                    peers: [],
                    metrics: MeshMetrics(),
                    transport: nil,
                    lastError: connectionStatus == .invalid ? "Tunnel profile is not installed" : nil
                )
                return
            }

            if let message = try await profileManager.sendMessage(
                providerBundleIdentifier: providerBundleIdentifier,
                envelope: TunnelCommandEnvelope(command: .status, configuration: configuration)
            ) {
                apply(message: message)
            } else {
                status = Self.makeStatus(
                    phase: .connected,
                    pathType: status.pathType,
                    configuration: configuration,
                    peers: status.peers,
                    metrics: status.metrics,
                    transport: status.transport,
                    lastError: status.lastError
                )
            }
        } catch {
            status = Self.makeStatus(
                phase: .failed,
                pathType: .unavailable,
                configuration: configuration,
                peers: [],
                metrics: MeshMetrics(),
                transport: nil,
                lastError: error.localizedDescription
            )
        }
#else
        status = Self.unsupportedStatus(configuration: configuration)
#endif
    }

    private static func makeStatus(
        phase: ConnectionPhase,
        pathType: PathType,
        configuration: TunnelConfiguration,
        peers: [PeerStatus],
        metrics: MeshMetrics,
        transport: TunnelTransportMetrics? = nil,
        lastError: String? = nil
    ) -> TunnelStatus {
        TunnelStatus(
            phase: phase,
            pathType: pathType,
            routeMode: configuration.routeMode,
            dnsMode: configuration.dnsMode,
            overlayIPv4Address: configuration.overlayIPv4Address,
            protectedRoutes: configuration.protectedRoutes,
            peers: peers,
            metrics: metrics,
            transport: transport,
            lastError: lastError
        )
    }

    private static func unsupportedStatus(configuration: TunnelConfiguration) -> TunnelStatus {
        makeStatus(
            phase: .failed,
            pathType: .unavailable,
            configuration: configuration,
            peers: [],
            metrics: MeshMetrics(),
            lastError: "NetworkExtension is unavailable in this build"
        )
    }

#if canImport(NetworkExtension)
    private var providerBundleIdentifier: String {
        if let configured = ProcessInfo.processInfo.environment["QLINK_TUNNEL_BUNDLE_ID"], !configured.isEmpty {
            return configured
        }
        if let appBundleIdentifier = Bundle.main.bundleIdentifier, !appBundleIdentifier.isEmpty {
            return appBundleIdentifier + ".PacketTunnel"
        }
        return "com.quantumlink.macos.PacketTunnel"
    }

    private func installProfileIfNeeded() async throws {
        try await profileManager.installOrUpdate(
            TunnelProfileDescriptor(
                providerBundleIdentifier: providerBundleIdentifier,
                serverAddress: configuration.tunnelRemoteAddress,
                providerConfiguration: [
                    "meshID": configuration.meshID,
                    "deviceAlias": configuration.deviceAlias
                ]
            )
        )
    }

    private func startOptions(for configuration: TunnelConfiguration) throws -> [String: NSObject] {
        let data = try JSONEncoder().encode(configuration)
        return ["configuration": data as NSData]
    }

    private func apply(message: TunnelProviderMessage) {
        switch message {
        case .status(let tunnelStatus):
            status = tunnelStatus
        case .diagnostic(let diagnostic):
            status = Self.makeStatus(
                phase: .connected,
                pathType: status.pathType,
                configuration: configuration,
                peers: status.peers,
                metrics: status.metrics,
                transport: status.transport,
                lastError: diagnostic
            )
        case .error(let message):
            status = Self.makeStatus(
                phase: .failed,
                pathType: .unavailable,
                configuration: configuration,
                peers: [],
                metrics: MeshMetrics(),
                transport: status.transport,
                lastError: message
            )
        }
    }

    private func observeTunnelStatusChanges() {
        statusObserverTask = Task { [weak self] in
            // `NotificationCenter.notifications(named:)` yields non-Sendable
            // `Notification` values. Under the Swift 6 language mode the Xcode
            // project builds with (SWIFT_VERSION = 6.0), those cannot cross
            // this @MainActor Task's isolation boundary, so iterating the raw
            // sequence fails to compile. We only need the change signal, not
            // the notification, so map the sequence to `Void` first.
            let statusChanges = NotificationCenter.default
                .notifications(named: .NEVPNStatusDidChange)
                .map { _ in () }
            for await _ in statusChanges {
                guard let self else { return }
                await self.refresh()
            }
        }
    }

    private static func phase(for status: NEVPNStatus) -> ConnectionPhase {
        switch status {
        case .invalid:
            .idle
        case .disconnected:
            .disconnected
        case .connecting:
            .connecting
        case .connected:
            .connected
        case .reasserting:
            .reconnecting
        case .disconnecting:
            .disconnected
        @unknown default:
            .failed
        }
    }
#endif
}

@MainActor
public final class SimulatedMeshController: ObservableObject, MeshControlling {
    @Published public private(set) var status: TunnelStatus
    @Published public private(set) var configuration: TunnelConfiguration

    public init(configuration: TunnelConfiguration = .defaultDevelopment) {
        self.configuration = configuration
        self.status = Self.status(
            phase: .idle,
            pathType: .unavailable,
            configuration: configuration,
            peers: [],
            metrics: MeshMetrics()
        )
    }

    public func updateConfiguration(_ configuration: TunnelConfiguration) {
        self.configuration = configuration
        status = Self.status(
            phase: status.phase,
            pathType: status.pathType,
            configuration: configuration,
            peers: status.peers,
            metrics: status.metrics,
            transport: status.transport,
            lastError: status.lastError
        )
    }

    public func connect() async {
        status = Self.status(
            phase: .preparing,
            pathType: .probing,
            configuration: configuration,
            peers: [],
            metrics: MeshMetrics(lastPathProbe: Date())
        )

        try? await Task.sleep(for: .milliseconds(250))

        let peers = Self.samplePeers(now: Date())
        let transportProbe = Self.probeTransport(configuration: configuration)
        status = Self.status(
            phase: .connected,
            pathType: .direct,
            configuration: configuration,
            peers: peers,
            metrics: MeshMetrics(
                peerCount: peers.count,
                directPeerCount: peers.filter { $0.pathType == .direct }.count,
                relayPeerCount: peers.filter { $0.pathType == .relay }.count,
                bytesIn: peers.reduce(0) { $0 + $1.bytesIn },
                bytesOut: peers.reduce(0) { $0 + $1.bytesOut },
                replayDrops: 0,
                lastPathProbe: Date()
            ),
            transport: transportProbe.metrics,
            lastError: transportProbe.error
        )
    }

    public func disconnect() async {
        status = Self.status(
            phase: .disconnected,
            pathType: .unavailable,
            configuration: configuration,
            peers: [],
            metrics: MeshMetrics()
        )
    }

    public func refresh() async {
        guard status.phase == .connected || status.phase == .degraded else { return }
        let peers = Self.samplePeers(now: Date())
        let transportProbe = Self.probeTransport(configuration: configuration)
        status = Self.status(
            phase: .connected,
            pathType: peers.contains { $0.pathType == .relay } ? .relay : .direct,
            configuration: configuration,
            peers: peers,
            metrics: MeshMetrics(
                peerCount: peers.count,
                directPeerCount: peers.filter { $0.pathType == .direct }.count,
                relayPeerCount: peers.filter { $0.pathType == .relay }.count,
                bytesIn: peers.reduce(0) { $0 + $1.bytesIn },
                bytesOut: peers.reduce(0) { $0 + $1.bytesOut },
                replayDrops: 0,
                lastPathProbe: Date()
            ),
            transport: transportProbe.metrics,
            lastError: transportProbe.error
        )
    }

    private static func status(
        phase: ConnectionPhase,
        pathType: PathType,
        configuration: TunnelConfiguration,
        peers: [PeerStatus],
        metrics: MeshMetrics,
        transport: TunnelTransportMetrics? = nil,
        lastError: String? = nil
    ) -> TunnelStatus {
        TunnelStatus(
            phase: phase,
            pathType: pathType,
            routeMode: configuration.routeMode,
            dnsMode: configuration.dnsMode,
            overlayIPv4Address: configuration.overlayIPv4Address,
            protectedRoutes: configuration.protectedRoutes,
            peers: peers,
            metrics: metrics,
            transport: transport,
            lastError: lastError
        )
    }

    private static func probeTransport(
        configuration: TunnelConfiguration
    ) -> (metrics: TunnelTransportMetrics, error: String?) {
        let mode = TransportSmokeMode()
        if mode == .developmentDrop,
           ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"]?.isEmpty ?? true {
            return (
                DevelopmentDropTransportSender(
                    reason: "Local transport smoke is disabled in the strict PQC profile; use production mesh integration checks with a mesh transport config"
                ).metrics,
                nil
            )
        }

        do {
            let result = try TransportSmokeRunner.run(configuration: configuration, mode: mode)
            return (result.transportMetrics, result.packetRoundTrip ? nil : "Transport smoke did not round trip a packet")
        } catch {
            return (
                TransportSmokeRunner.failedMetrics(mode: mode, error: error),
                error.localizedDescription
            )
        }
    }

    private static func samplePeers(now: Date) -> [PeerStatus] {
        [
            PeerStatus(
                identity: PeerIdentity(
                    peerID: "qlink_4f5f1c22",
                    alias: "peer-a7f2c91e",
                    publicKeyFingerprint: "MLDSA65:5b3d:2d9a"
                ),
                pathType: .relay,
                endpoints: [
                    PeerEndpoint(candidateType: "relay", address: "relay.quantumlink.invalid", port: 4433, priority: 120)
                ],
                overlayAddress: "100.64.10.10",
                rttMilliseconds: 7,
                lastRekey: now.addingTimeInterval(-340),
                bytesIn: 18_441_920,
                bytesOut: 9_177_088
            ),
            PeerStatus(
                identity: PeerIdentity(
                    peerID: "qlink_8ac9d014",
                    alias: "peer-19d4b6a0",
                    publicKeyFingerprint: "MLDSA65:c92a:6f00"
                ),
                pathType: .relay,
                endpoints: [
                    PeerEndpoint(candidateType: "relay", address: "relay.quantumlink.invalid", port: 9472, priority: 20)
                ],
                overlayAddress: "100.64.10.11",
                rttMilliseconds: 82,
                lastRekey: now.addingTimeInterval(-1020),
                bytesIn: 3_211_264,
                bytesOut: 4_090_880
            )
        ]
    }
}
