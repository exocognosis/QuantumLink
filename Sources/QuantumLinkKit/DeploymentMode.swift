import Foundation

public enum QuantumLinkDeploymentMode: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case mesh
    case direct
    case localVPN

    public var id: Self { self }

    public func configuration(from base: TunnelConfiguration) -> TunnelConfiguration {
        TunnelConfiguration(
            meshID: base.meshID,
            deviceAlias: base.deviceAlias,
            overlayIPv4Address: base.overlayIPv4Address,
            tunnelRemoteAddress: base.tunnelRemoteAddress,
            protectedRoutes: base.protectedRoutes,
            excludedRoutes: base.excludedRoutes,
            dnsServers: base.dnsServers,
            dnsSearchDomains: base.dnsSearchDomains,
            routeMode: routeMode,
            dnsMode: dnsMode,
            discoveryModes: discoveryModes,
            rendezvousServers: rendezvousServers(from: base),
            relayServers: relayServers(from: base),
            mtu: base.mtu,
            crypto: base.crypto
        )
    }

    private var routeMode: RouteMode {
        switch self {
        case .mesh:
            .splitTunnel
        case .direct:
            .protectedPrefixesOnly
        case .localVPN:
            .fullTunnel
        }
    }

    private var dnsMode: DNSMode {
        switch self {
        case .mesh, .direct:
            .tunnelProvided
        case .localVPN:
            .system
        }
    }

    private var discoveryModes: [DiscoveryMode] {
        switch self {
        case .mesh:
            [.rendezvous]
        case .direct:
            [.rendezvous, .localMDNS]
        case .localVPN:
            [.localMDNS]
        }
    }

    private func rendezvousServers(from base: TunnelConfiguration) -> [String] {
        switch self {
        case .mesh, .direct:
            base.rendezvousServers
        case .localVPN:
            []
        }
    }

    private func relayServers(from base: TunnelConfiguration) -> [String] {
        switch self {
        case .mesh:
            base.relayServers
        case .direct, .localVPN:
            []
        }
    }
}
