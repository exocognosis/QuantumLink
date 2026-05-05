#if canImport(NetworkExtension)
import Foundation
import NetworkExtension
import os
import QuantumLinkKit

public final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "com.quantumlink.macos", category: "packet-tunnel")
    private var isRunning = false
    private var packetCount: UInt64 = 0
    private var lastBatchPacketCount: Int = 0
    private var currentConfiguration = TunnelConfiguration.defaultDevelopment
    private var packetPump = TunnelPacketPump(coreAdapter: nil)
    private var transport: TunnelTransporting = DevelopmentDropTransportSender(reason: "Tunnel transport is not started")
    private var networkObserver: NetworkPathObserver?
    private var pendingReassertion = false
    private var lastNetworkEvent: NetworkLifecycleEvent?
    private var networkEventCount: UInt64 = 0
    private var lastReprobeAt: Date?
    /// Strict-mode watchdog. Periodically checks whether the transport
    /// has stayed unhealthy past `KillSwitchWatchdog.defaultDeadlineSeconds`
    /// and tears down the tunnel if so — the runtime teeth that turn
    /// `KillSwitchPolicy.strict` into something stronger than
    /// `failClosed` (which is purely a per-batch drop policy).
    private var killSwitchWatchdog: KillSwitchWatchdog?
    private var killSwitchWatchdogTask: Task<Void, Never>?
    /// Refreshes the local node's signed peer record with the
    /// rendezvous server on a TTL/2 cadence so dialing peers always
    /// see a fresh entry. Cancelled on stopTunnel. `nil` until
    /// startTunnel constructs a keypair-equipped mesh transport.
    private var publishSelfTask: Task<Void, Never>?
    /// Forwards Rust-side `tracing::warn!`/`error!` events into the
    /// Swift logger, redacted at the seam. Started on startTunnel,
    /// stopped on stopTunnel.
    private var tracingForwarder: RustTracingForwarder?
    /// Production transport bundle held for diagnostics + the
    /// publish loop. `nil` when running through the legacy / dev
    /// transport paths.
    private var productionMeshBundle: ProductionMeshTransportBundle?

    public override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        nonisolated(unsafe) let completion = completionHandler
        let configuration = loadConfiguration(from: options)
        currentConfiguration = configuration

        do {
            let settings = try makeNetworkSettings(configuration: configuration)
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else { return }
                if let error {
                    self.logger.error("Failed to apply tunnel network settings: \(PrivacyDefaults.redactForLog(error), privacy: .public)")
                    completion(error)
                    return
                }

                self.isRunning = true
                self.packetPump = TunnelPacketPump(
                    coreAdapter: self.makeCoreAdapter(configuration: configuration),
                    killSwitch: configuration.killSwitch
                )
                self.transport = self.makeTransport(configuration: configuration)
                do {
                    try self.transport.start()
                } catch {
                    if configuration.killSwitch == .strict {
                        self.logger.error("Strict kill switch: refusing to start tunnel because transport failed: \(PrivacyDefaults.redactForLog(error), privacy: .public)")
                        self.isRunning = false
                        self.transport = DevelopmentDropTransportSender(reason: error.localizedDescription)
                        completion(error)
                        return
                    }
                    self.logger.error("Transport start failed; using development drop sender: \(PrivacyDefaults.redactForLog(error), privacy: .public)")
                    self.transport = DevelopmentDropTransportSender(reason: error.localizedDescription)
                    try? self.transport.start()
                }
                self.logger.info("QuantumLink packet tunnel started for mesh \(configuration.meshID, privacy: .public)")
                self.startNetworkObserver()
                self.startKillSwitchWatchdog(policy: configuration.killSwitch)
                self.startPublishSelfLoop()
                self.startTracingForwarder()
                self.schedulePacketRead()
                completion(nil)
            }
        } catch {
            logger.error("Invalid tunnel configuration: \(PrivacyDefaults.redactForLog(error), privacy: .public)")
            completionHandler(error)
        }
    }

    public override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        isRunning = false
        stopNetworkObserver()
        stopKillSwitchWatchdog()
        stopPublishSelfLoop()
        stopTracingForwarder()
        productionMeshBundle = nil
        packetPump = TunnelPacketPump(coreAdapter: nil)
        transport.stop()
        transport = DevelopmentDropTransportSender(reason: "Tunnel transport is stopped")
        logger.info("QuantumLink packet tunnel stopped with reason \(reason.rawValue, privacy: .public)")
        completionHandler()
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        let decoder = JSONDecoder()
        let encoder = JSONEncoder()

        guard let envelope = try? decoder.decode(TunnelCommandEnvelope.self, from: messageData) else {
            completionHandler?(nil)
            return
        }

        let response: TunnelProviderMessage
        switch envelope.command {
        case .connect:
            response = .diagnostic("Tunnel is managed by Network Extension startTunnel.")
        case .disconnect:
            cancelTunnelWithError(nil)
            response = .diagnostic("Disconnect requested.")
        case .reloadConfiguration:
            response = .diagnostic("Configuration reload queued.")
        case .exportDiagnostics:
            response = .diagnostic(diagnosticSummary())
        case .status:
            response = .status(currentStatus())
        }

        completionHandler?(try? encoder.encode(response))
    }

    private func loadConfiguration(from options: [String: NSObject]?) -> TunnelConfiguration {
        guard
            let data = options?["configuration"] as? Data,
            let configuration = try? JSONDecoder().decode(TunnelConfiguration.self, from: data)
        else {
            return .defaultDevelopment
        }
        return configuration
    }

    private func makeNetworkSettings(configuration: TunnelConfiguration) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: configuration.tunnelRemoteAddress)
        settings.mtu = NSNumber(value: configuration.mtu)

        let ipv4 = NEIPv4Settings(
            addresses: [configuration.overlayIPv4Address],
            subnetMasks: ["255.255.255.255"]
        )
        ipv4.includedRoutes = try configuration.protectedRoutes.map { route in
            let cidr = try IPv4CIDR(route)
            return NEIPv4Route(destinationAddress: cidr.networkAddress, subnetMask: cidr.subnetMask)
        }
        ipv4.excludedRoutes = try configuration.excludedRoutes.map { route in
            let cidr = try IPv4CIDR(route)
            return NEIPv4Route(destinationAddress: cidr.networkAddress, subnetMask: cidr.subnetMask)
        }
        settings.ipv4Settings = ipv4

        if configuration.dnsMode == .tunnelProvided {
            let dns = NEDNSSettings(servers: configuration.dnsServers)
            dns.searchDomains = configuration.dnsSearchDomains
            settings.dnsSettings = dns
        }

        return settings
    }

    private func schedulePacketRead() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.isRunning else { return }
            self.packetCount += UInt64(packets.count)
            self.lastBatchPacketCount = packets.count
            self.handlePackets(packets, protocols: protocols)
            self.schedulePacketRead()
        }
    }

    private func handlePackets(_ packets: [Data], protocols: [NSNumber]) {
        let result = packetPump.handlePackets(
            packets,
            protocolFamilies: protocols.map(\.uint32Value),
            transportSink: transport
        )
        drainInboundTransportFrames()

        if result.droppedFailClosed > 0 {
            logger.debug("Dropped \(result.droppedFailClosed, privacy: .public) protected packets because Rust core is unavailable")
        }
        if result.droppedUnprotected > 0 {
            logger.debug("Dropped \(result.droppedUnprotected, privacy: .public) unprotected packets outside configured route policy")
        }
        if result.failedSubmissions > 0 {
            logger.error("Failed to submit \(result.failedSubmissions, privacy: .public) packets into Rust core")
        }
    }

    private func drainInboundTransportFrames() {
        var packets: [Data] = []
        var protocols: [NSNumber] = []

        while true {
            let inbound: InboundTransportFrame?
            do {
                inbound = try transport.receiveTransportFrame()
            } catch {
                logger.error("Failed to receive transport frame: \(PrivacyDefaults.redactForLog(error), privacy: .public)")
                break
            }

            guard let inbound else {
                break
            }

            do {
                try packetPump.acceptTransportFrame(inbound.frame, peerID: inbound.peerID)
                while true {
                    guard let packet = try packetPump.popTunnelPacket() else {
                        break
                    }
                    packets.append(packet.bytes)
                    protocols.append(NSNumber(value: packet.protocolFamily))
                }
            } catch {
                logger.error("Failed to drain inbound transport frame: \(PrivacyDefaults.redactForLog(error), privacy: .public)")
            }
        }

        if !packets.isEmpty {
            packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

    private func makeCoreAdapter(configuration: TunnelConfiguration) -> TunnelCoreAdapting? {
        do {
            let library = try RustCoreLibrary.openBundledOrConfigured()
            let adapter = try RustTunnelCoreAdapter(configuration: configuration, library: library)
            logger.info("Loaded QuantumLink Rust core \(library.version, privacy: .public)")
            return adapter
        } catch {
            logger.error("Rust core unavailable; tunnel remains fail-closed: \(PrivacyDefaults.redactForLog(error), privacy: .public)")
            return nil
        }
    }

    private func makeTransport(configuration: TunnelConfiguration) -> TunnelTransporting {
        // If `QLINK_TRANSPORT_MODE` is set we honor it as an explicit
        // smoke / dev override and skip the production wiring.
        // Otherwise (the production default), build a keypair-equipped
        // mesh transport from Keychain-persisted material.
        let environment = ProcessInfo.processInfo.environment
        if environment["QLINK_TRANSPORT_MODE"] != nil {
            return TunnelTransportFactory.makeDefault(
                configuration: configuration,
                environment: environment
            )
        }
        do {
            let bundle = try TunnelTransportFactory.makeProductionMeshTransport(
                configuration: configuration,
                peerStoreDirectory: peerStoreDirectory()
            )
            productionMeshBundle = bundle
            logger.info(
                "production mesh transport built (peer_id=\(bundle.keypair.peerID, privacy: .public), peer_store_encryption=\(bundle.peerStoreEncryptionEnabled ? "enabled" : "disabled", privacy: .public))"
            )
            return bundle.transport
        } catch {
            logger.error(
                "Production mesh transport unavailable; falling back to default factory: \(PrivacyDefaults.redactForLog(error), privacy: .public)"
            )
            return TunnelTransportFactory.makeDefault(
                configuration: configuration,
                environment: environment
            )
        }
    }

    /// Resolves the directory the FilePeerStore should live in.
    /// Inside the NEPacketTunnelProvider sandbox, Application
    /// Support is the canonical writable location. If the lookup
    /// fails (which it shouldn't on macOS), return nil so the
    /// factory falls back to in-memory-only storage.
    private func peerStoreDirectory() -> URL? {
        guard
            let base = try? FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            )
        else {
            return nil
        }
        return base.appendingPathComponent("QuantumLink", isDirectory: true)
    }

    /// Cadence for refreshing the local peer record. TTL/2 keeps a
    /// fresh entry visible to dialing peers before the previous one
    /// expires; the Rust side defaults TTL to 120s, so we publish
    /// every 60s.
    private static let publishSelfTTLSeconds: UInt64 = 120
    private static let publishSelfRefreshInterval: Duration = .seconds(60)

    private func startPublishSelfLoop() {
        guard publishSelfTask == nil else { return }
        guard let bundle = productionMeshBundle else {
            // No keypair on this transport — publishSelf would just
            // throw. Skip silently; the dev / drop path doesn't need
            // a published record.
            return
        }
        guard let rendezvousURL = bundle.rendezvousURL else {
            logger.notice("publishSelf loop skipped: no rendezvous URL configured")
            return
        }
        let transport = bundle.transport
        let logger = self.logger
        let refreshInterval = Self.publishSelfRefreshInterval
        let ttlSeconds = Self.publishSelfTTLSeconds
        publishSelfTask = Task.detached {
            var sequence: UInt64 = 1
            while !Task.isCancelled {
                do {
                    try transport.publishSelf(
                        rendezvousURL: rendezvousURL,
                        ttlSeconds: ttlSeconds,
                        sequence: sequence
                    )
                    logger.info("publishSelf ok (sequence=\(sequence, privacy: .public))")
                } catch {
                    logger.error(
                        "publishSelf failed: \(PrivacyDefaults.redactForLog(error), privacy: .public)"
                    )
                }
                // u64 wrap takes ~600 billion years at this cadence;
                // saturate at .max so the build doesn't trap if
                // someone changes the cadence and we hit the
                // theoretical edge.
                sequence = sequence == .max ? sequence : sequence + 1
                try? await Task.sleep(for: refreshInterval)
            }
        }
    }

    private func stopPublishSelfLoop() {
        publishSelfTask?.cancel()
        publishSelfTask = nil
    }

    private func startTracingForwarder() {
        guard tracingForwarder == nil else { return }
        guard let bundle = productionMeshBundle else {
            // Tracing forwarder needs a library handle. The
            // dev / drop transport paths don't construct one;
            // their diagnostics flow through `Logger` directly.
            return
        }
        let forwarder = RustTracingForwarder(library: bundle.library)
        forwarder.start()
        tracingForwarder = forwarder
    }

    private func stopTracingForwarder() {
        tracingForwarder?.stop()
        tracingForwarder = nil
    }

    private func startNetworkObserver() {
        Task { @MainActor [weak self] in
            guard let self else { return }
            let observer = NetworkPathObserver()
            observer.startWithSystemSources { event in
                self.handleNetworkEvent(event)
            }
            self.networkObserver = observer
        }
    }

    private func stopNetworkObserver() {
        let observer = networkObserver
        networkObserver = nil
        Task { @MainActor in
            observer?.stop()
        }
    }

    /// Cadence at which the strict-mode watchdog re-checks the
    /// transport's health. Smaller values catch sustained-failure
    /// faster; larger values reduce wakeups on long-idle tunnels.
    /// 5 s gives ~6 evaluations within the 30 s default deadline.
    private static let killSwitchWatchdogTickInterval: UInt64 = 5_000_000_000

    private func startKillSwitchWatchdog(policy: KillSwitchPolicy) {
        // failClosed needs no runtime teeth — the per-batch pump gate
        // already covers it. Skip the periodic Task entirely so we
        // don't burn wakeups on a no-op.
        guard policy == .strict else { return }
        let watchdog = KillSwitchWatchdog(
            policy: policy,
            readyCheck: { [weak self] in
                guard let self else { return false }
                return self.transport.isReady
            },
            deadlineHandler: { [weak self] in
                guard let self else { return }
                self.logger.error(
                    "Strict kill switch deadline expired: tearing down tunnel after \(KillSwitchWatchdog.defaultDeadlineSeconds, privacy: .public)s of unhealthy transport"
                )
                self.cancelTunnelWithError(NSError(
                    domain: "com.quantumlink.macos",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "Strict kill switch tripped: transport unavailable past deadline"]
                ))
            }
        )
        killSwitchWatchdog = watchdog
        killSwitchWatchdogTask = Task { [weak self] in
            while let self, !Task.isCancelled, self.isRunning {
                self.killSwitchWatchdog?.evaluate()
                try? await Task.sleep(nanoseconds: Self.killSwitchWatchdogTickInterval)
            }
        }
    }

    private func stopKillSwitchWatchdog() {
        killSwitchWatchdogTask?.cancel()
        killSwitchWatchdogTask = nil
        killSwitchWatchdog = nil
    }

    private func handleNetworkEvent(_ event: NetworkLifecycleEvent) {
        networkEventCount += 1
        lastNetworkEvent = event
        let decision = NetworkEventDecision.decide(for: event)
        logger.info(
            "network event: \(String(describing: event), privacy: .public) → reprobe=\(decision.reprobeRecommended, privacy: .public) invalidate=\(decision.invalidateCachedPaths, privacy: .public)"
        )

        // Forward the event into the live Rust mesh transport so the
        // connector can invalidate its cache and re-probe. This is a no-op
        // for the development drop / loopback transports.
        if let mesh = transport as? RustMeshTransport,
           let rustEvent = Self.mapNetworkEvent(event) {
            mesh.notifyNetworkEvent(rustEvent)
        }

        if decision.reprobeRecommended {
            beginReassertion()
            lastReprobeAt = Date()

            // Flip back to non-reasserting after a short window. Real reads
            // of the active path's state come from the transport's metrics
            // refresh; the reasserting flag exists to give the OS UI a
            // visible "Connecting…" state during the transition.
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 500_000_000)
                self?.endReassertion()
            }
        } else if case .preSleep = event {
            // Don't flip reasserting on pre-sleep — the OS already knows it's
            // about to suspend.
        }
    }

    private static func mapNetworkEvent(_ event: NetworkLifecycleEvent) -> RustMeshNetworkEvent? {
        switch event {
        case .pathChanged: return .pathChanged
        case .preSleep: return .preSleep
        case .postWake: return .postWake
        case .reachabilityChanged(let reachable):
            return reachable ? .reachabilityGained : .reachabilityLost
        }
    }

    private func beginReassertion() {
        guard !pendingReassertion else { return }
        pendingReassertion = true
        reasserting = true
        logger.debug("Set reasserting=true")
    }

    private func endReassertion() {
        guard pendingReassertion else { return }
        pendingReassertion = false
        reasserting = false
        logger.debug("Set reasserting=false")
    }

    private func diagnosticSummary() -> String {
        let transportMetrics = transport.metrics
        var fields = [
            "packets_observed=\(packetCount)",
            "transport_kind=\(transportMetrics.kind.rawValue)",
            "transport_state=\(transportMetrics.state.rawValue)",
            "transport_path=\(transportMetrics.pathType.rawValue)",
            "transport_frames_sent=\(transportMetrics.framesSent)",
            "transport_frames_received=\(transportMetrics.framesReceived)",
            "transport_frames_dropped=\(transportMetrics.framesDropped)",
            "transport_send_failures=\(transportMetrics.sendFailures)",
            "transport_receive_failures=\(transportMetrics.receiveFailures)",
            "pump_fail_closed=\(packetPump.counters.droppedFailClosed)",
            "pump_kill_switch_drops=\(packetPump.counters.droppedKillSwitch)",
            "pump_kill_switch_policy=\(packetPump.killSwitchPolicy.rawValue)",
            "pump_dropped_unprotected=\(packetPump.counters.droppedUnprotected)",
            "pump_failed_submissions=\(packetPump.counters.failedSubmissions)",
            "pump_frames_accepted=\(packetPump.counters.transportFramesAccepted)",
            "pump_tunnel_packets_emitted=\(packetPump.counters.tunnelPacketsEmitted)",
            "pump_distinct_peers_seen=\(packetPump.counters.transportFramesAcceptedPerPeer.count)"
        ]
        // Per-peer breakdown surfaced as a single comma-separated
        // field. peer_id is pseudonymous + signed, so safe in the
        // diagnostic export. Truncate at 12 entries to keep the
        // summary readable; operators wanting the full breakdown
        // pull the support bundle.
        if !packetPump.counters.transportFramesAcceptedPerPeer.isEmpty {
            let breakdown = packetPump.counters.transportFramesAcceptedPerPeer
                .sorted { lhs, rhs in lhs.value > rhs.value }
                .prefix(12)
                .map { "\($0.key)=\($0.value)" }
                .joined(separator: ",")
            fields.append("pump_per_peer_frames=\(breakdown)")
        }
        if let lastError = transportMetrics.lastError {
            fields.append("transport_last_error=\(PrivacyDefaults.redactNetworkIdentifiers(in: lastError))")
        }

        if let metrics = try? packetPump.coreMetrics() {
            fields.append("core_packets_from_tunnel=\(metrics.packetsFromTunnel)")
            fields.append("core_packets_to_tunnel=\(metrics.packetsToTunnel)")
            fields.append("core_frames_out=\(metrics.transportFramesOut)")
            fields.append("core_frames_in=\(metrics.transportFramesIn)")
            fields.append("core_dropped_unprotected=\(metrics.droppedUnprotected)")
            fields.append("core_dropped_malformed=\(metrics.droppedMalformed)")
        }

        fields.append("last_batch_packets=\(lastBatchPacketCount)")
        fields.append("network_events_observed=\(networkEventCount)")
        if let last = lastNetworkEvent {
            fields.append("last_network_event=\(String(describing: last))")
        }
        if let at = lastReprobeAt {
            fields.append("last_reprobe_at=\(Int(at.timeIntervalSince1970))")
        }
        fields.append("reasserting_pending=\(pendingReassertion)")

        return fields.joined(separator: " ")
    }

    private func currentStatus() -> TunnelStatus {
        let transportMetrics = transport.metrics
        let pathType = isRunning ? transportMetrics.pathType : .unavailable
        let phase: ConnectionPhase
        if !isRunning {
            phase = .disconnected
        } else if transportMetrics.state == .failed || (transportMetrics.pathType == .unavailable && transportMetrics.lastError != nil) {
            phase = .degraded
        } else if transportMetrics.pathType == .probing {
            phase = .connecting
        } else {
            phase = .connected
        }

        let bytesIn = transportMetrics.bytesReceived
        let bytesOut = transportMetrics.bytesSent
        let replayDrops = (try? packetPump.coreMetrics()?.droppedMalformed) ?? 0
        let metrics = MeshMetrics(
            peerCount: 0,
            directPeerCount: pathType == .direct ? 1 : 0,
            relayPeerCount: pathType == .relay ? 1 : 0,
            bytesIn: bytesIn,
            bytesOut: bytesOut,
            replayDrops: replayDrops,
            lastPathProbe: isRunning ? Date() : nil
        )

        return TunnelStatus(
            phase: phase,
            pathType: pathType,
            routeMode: currentConfiguration.routeMode,
            dnsMode: currentConfiguration.dnsMode,
            overlayIPv4Address: currentConfiguration.overlayIPv4Address,
            protectedRoutes: currentConfiguration.protectedRoutes,
            peers: [],
            metrics: metrics,
            transport: transportMetrics,
            lastError: transportMetrics.lastError
        )
    }
}

extension PacketTunnelProvider: @unchecked Sendable {}
#endif
