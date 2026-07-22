#if canImport(NetworkExtension)
import Foundation
@preconcurrency import NetworkExtension

extension NETunnelProviderManager: @retroactive @unchecked Sendable {}

public struct TunnelProfileDescriptor: Sendable {
    public let localizedDescription: String
    public let providerBundleIdentifier: String
    public let serverAddress: String
    public let providerConfiguration: [String: String]

    public init(
        localizedDescription: String = "QuantumLink",
        providerBundleIdentifier: String,
        serverAddress: String = "QuantumLink Mesh",
        providerConfiguration: [String: String] = [:]
    ) {
        self.localizedDescription = localizedDescription
        self.providerBundleIdentifier = providerBundleIdentifier
        self.serverAddress = serverAddress
        self.providerConfiguration = providerConfiguration
    }
}

@MainActor
public final class TunnelProfileManager {
    public init() {}

    public func installOrUpdate(_ descriptor: TunnelProfileDescriptor) async throws {
        let manager = try await manager(for: descriptor.providerBundleIdentifier) ?? NETunnelProviderManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = descriptor.providerBundleIdentifier
        proto.serverAddress = descriptor.serverAddress
        proto.providerConfiguration = descriptor.providerConfiguration
        proto.disconnectOnSleep = false

        manager.localizedDescription = descriptor.localizedDescription
        manager.protocolConfiguration = proto
        manager.isEnabled = true

        try await save(manager)
        try await reload(manager)
    }

    public func manager(for providerBundleIdentifier: String) async throws -> NETunnelProviderManager? {
        let managers = try await loadManagers()
        return managers.first { existing in
            let proto = existing.protocolConfiguration as? NETunnelProviderProtocol
            return proto?.providerBundleIdentifier == providerBundleIdentifier
        }
    }

    public func startTunnel(
        providerBundleIdentifier: String,
        options: [String: NSObject]? = nil
    ) async throws {
        guard let manager = try await manager(for: providerBundleIdentifier) else {
            throw TunnelProfileManagerError.profileNotFound(providerBundleIdentifier)
        }
        try await reload(manager)
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw TunnelProfileManagerError.invalidSession(providerBundleIdentifier)
        }
        try session.startVPNTunnel(options: options)
    }

    public func stopTunnel(providerBundleIdentifier: String) async throws {
        guard let manager = try await manager(for: providerBundleIdentifier) else {
            return
        }
        try await reload(manager)
        manager.connection.stopVPNTunnel()
    }

    public func connectionStatus(providerBundleIdentifier: String) async throws -> NEVPNStatus {
        guard let manager = try await manager(for: providerBundleIdentifier) else {
            return .invalid
        }
        try await reload(manager)
        return manager.connection.status
    }

    public func sendMessage(
        providerBundleIdentifier: String,
        envelope: TunnelCommandEnvelope
    ) async throws -> TunnelProviderMessage? {
        guard let manager = try await manager(for: providerBundleIdentifier) else {
            return nil
        }
        try await reload(manager)
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw TunnelProfileManagerError.invalidSession(providerBundleIdentifier)
        }

        let payload = try JSONEncoder().encode(envelope)
        let responseData = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            do {
                try session.sendProviderMessage(payload) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }

        guard let responseData else {
            return nil
        }
        return try JSONDecoder().decode(TunnelProviderMessage.self, from: responseData)
    }

    /// Apply a set of On-Demand rules to the tunnel profile. The system
    /// evaluates these in order on every reachability change and decides
    /// whether to bring the tunnel up. Pass an empty array to clear the
    /// rule list (and disable on-demand).
    ///
    /// This is the runtime path — useful for unmanaged Macs and dev. For
    /// managed deployments, ship the rules through MDM by serializing an
    /// `OnDemandPayloadFragment` into a configuration profile.
    public func applyOnDemandRules(
        _ rules: [OnDemandRule],
        providerBundleIdentifier: String
    ) async throws {
        guard let manager = try await manager(for: providerBundleIdentifier) else {
            throw TunnelProfileManagerError.profileNotFound(providerBundleIdentifier)
        }
        try await reload(manager)

        if rules.isEmpty {
            manager.onDemandRules = nil
            manager.isOnDemandEnabled = false
        } else {
            manager.onDemandRules = rules.map { $0.toNEOnDemandRule() }
            manager.isOnDemandEnabled = true
        }

        try await save(manager)
        try await reload(manager)
    }

    public func remove(providerBundleIdentifier: String) async throws {
        let managers = try await loadManagers()
        for manager in managers {
            let proto = manager.protocolConfiguration as? NETunnelProviderProtocol
            if proto?.providerBundleIdentifier == providerBundleIdentifier {
                try await remove(manager)
            }
        }
    }

    private func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func reload(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func remove(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.removeFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }
}

public enum TunnelProfileManagerError: Error, LocalizedError {
    case profileNotFound(String)
    case invalidSession(String)

    public var errorDescription: String? {
        switch self {
        case .profileNotFound(let bundleIdentifier):
            "No tunnel profile exists for \(bundleIdentifier)"
        case .invalidSession(let bundleIdentifier):
            "Tunnel profile \(bundleIdentifier) does not expose a NETunnelProviderSession"
        }
    }
}
#endif
