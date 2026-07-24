import Foundation

public enum PacketSessionReadinessState: String, Equatable, Sendable {
    case notRequired
    case coreUnavailable
    case missingPeer
    case waitingForTransport
    case ready
    case failed
}

public struct PacketSessionReadinessReport: Equatable, Sendable {
    public let state: PacketSessionReadinessState
    public let peerID: String?
    public let installed: Bool
    public let cleared: Bool
    public let errorDescription: String?

    public init(
        state: PacketSessionReadinessState,
        peerID: String? = nil,
        installed: Bool = false,
        cleared: Bool = false,
        errorDescription: String? = nil
    ) {
        self.state = state
        self.peerID = peerID
        self.installed = installed
        self.cleared = cleared
        self.errorDescription = errorDescription
    }
}

public protocol PacketSessionReadinessSource: AnyObject {
    /// Packet-core target peer for the legacy single-peer packet pump path.
    /// Return `nil` when the runtime has no concrete target; the core remains
    /// fail-closed when `TunnelConfiguration.requirePeerSession` is enabled.
    var packetSessionPeerID: String? { get }
    /// True only after the live transport has established an authenticated
    /// app-layer session for `packetSessionPeerID`.
    var packetSessionTransportReady: Bool { get }
}

public final class PacketSessionReadinessCoordinator {
    private var installedPeerID: String?
    private var installedExpiresAt: Date?
    private var installedRekeyAfterPackets: UInt64?

    public init() {}

    @discardableResult
    public func synchronize(
        coreAdapter: TunnelCoreAdapting?,
        source: PacketSessionReadinessSource?,
        configuration: TunnelConfiguration,
        now: Date = Date()
    ) -> PacketSessionReadinessReport {
        guard configuration.requirePeerSession else {
            return PacketSessionReadinessReport(state: .notRequired)
        }
        guard let coreAdapter else {
            clearLocalInstall()
            return PacketSessionReadinessReport(state: .coreUnavailable)
        }
        guard let peerID = source?.packetSessionPeerID else {
            return clearInstalledSession(
                coreAdapter: coreAdapter,
                state: .missingPeer,
                peerID: nil
            )
        }
        guard source?.packetSessionTransportReady == true else {
            return clearInstalledSession(
                coreAdapter: coreAdapter,
                state: .waitingForTransport,
                peerID: peerID
            )
        }

        let expiresAt = Self.sessionExpiresAt(configuration: configuration, now: now)
        let rekeyAfterPackets = Self.rekeyAfterPackets(configuration: configuration)
        let coreReady = (try? coreAdapter.peerSessionReady()) ?? false
        let shouldInstall =
            installedPeerID != peerID ||
            installedRekeyAfterPackets != rekeyAfterPackets ||
            installedExpiresAt.map { $0 <= now } ?? true ||
            !coreReady

        guard shouldInstall else {
            return PacketSessionReadinessReport(
                state: .ready,
                peerID: peerID
            )
        }

        do {
            try coreAdapter.installPeerSession(
                peerID: peerID,
                expiresAt: expiresAt,
                rekeyAfterPackets: rekeyAfterPackets
            )
            installedPeerID = peerID
            installedExpiresAt = expiresAt
            installedRekeyAfterPackets = rekeyAfterPackets
            return PacketSessionReadinessReport(
                state: .ready,
                peerID: peerID,
                installed: true
            )
        } catch {
            clearLocalInstall()
            return PacketSessionReadinessReport(
                state: .failed,
                peerID: peerID,
                errorDescription: error.localizedDescription
            )
        }
    }

    @discardableResult
    public func clear(coreAdapter: TunnelCoreAdapting?) -> PacketSessionReadinessReport {
        guard let coreAdapter else {
            clearLocalInstall()
            return PacketSessionReadinessReport(state: .coreUnavailable)
        }
        return clearInstalledSession(
            coreAdapter: coreAdapter,
            state: .waitingForTransport,
            peerID: installedPeerID
        )
    }

    public static func sessionExpiresAt(
        configuration: TunnelConfiguration,
        now: Date = Date()
    ) -> Date {
        let rekeySeconds = configuration.crypto.rekeyAfterSeconds
        let candidateSeconds = TimeInterval(configuration.maximumCandidateAgeSeconds)
        let boundedSeconds = [rekeySeconds, candidateSeconds]
            .filter { $0.isFinite && $0 > 0 }
            .min() ?? 120
        return now.addingTimeInterval(max(1, boundedSeconds))
    }

    public static func rekeyAfterPackets(configuration: TunnelConfiguration) -> UInt64 {
        guard configuration.crypto.rekeyAfterBytes > 0 else {
            return 0
        }
        let mtu = UInt64(max(1, configuration.mtu))
        return max(1, configuration.crypto.rekeyAfterBytes / mtu)
    }

    private func clearInstalledSession(
        coreAdapter: TunnelCoreAdapting,
        state: PacketSessionReadinessState,
        peerID: String?
    ) -> PacketSessionReadinessReport {
        let hadInstall = installedPeerID != nil
        do {
            if hadInstall || (try? coreAdapter.peerSessionReady()) == true {
                try coreAdapter.clearPeerSession()
            }
            clearLocalInstall()
            return PacketSessionReadinessReport(
                state: state,
                peerID: peerID,
                cleared: hadInstall
            )
        } catch {
            clearLocalInstall()
            return PacketSessionReadinessReport(
                state: .failed,
                peerID: peerID,
                cleared: hadInstall,
                errorDescription: error.localizedDescription
            )
        }
    }

    private func clearLocalInstall() {
        installedPeerID = nil
        installedExpiresAt = nil
        installedRekeyAfterPackets = nil
    }
}
