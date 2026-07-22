import Foundation

public enum QuantumLinkDeploymentMode: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case mesh
    case partyMesh
    case direct
    case localVPN

    public var id: Self { self }

    public func configuration(from base: TunnelConfiguration) -> TunnelConfiguration {
        buildConfiguration(
            from: base,
            overlayIPv4Address: base.overlayIPv4Address,
            tunnelRemoteAddress: base.tunnelRemoteAddress,
            protectedRoutes: protectedRoutes(from: base, destinationIPAddress: nil),
            rendezvousServers: rendezvousServers(from: base, destinationIPAddress: nil),
            relayServers: relayServers(from: base, destinationIPAddress: nil),
            remotePeerID: remotePeerID(from: base, profile: nil),
            crypto: base.crypto
        )
    }

    public func configuration(
        from base: TunnelConfiguration,
        profile: ConnectionProfile
    ) -> TunnelConfiguration {
        let sourceIPAddress = profile.sourceIPAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        let destinationIPAddress = profile.destinationIPAddress.trimmingCharacters(in: .whitespacesAndNewlines)

        return buildConfiguration(
            from: base,
            overlayIPv4Address: sourceIPAddress.isEmpty ? base.overlayIPv4Address : sourceIPAddress,
            tunnelRemoteAddress: destinationIPAddress.isEmpty ? base.tunnelRemoteAddress : destinationIPAddress,
            protectedRoutes: protectedRoutes(from: base, destinationIPAddress: destinationIPAddress, profile: profile),
            rendezvousServers: rendezvousServers(from: base, destinationIPAddress: destinationIPAddress, endpointPort: profile.deploymentDetails.directEndpointPort),
            relayServers: relayServers(from: base, destinationIPAddress: destinationIPAddress),
            remotePeerID: remotePeerID(from: base, profile: profile),
            crypto: CryptoPolicy(pqcAlgorithm: profile.pqcAlgorithm)
        )
    }

    private func buildConfiguration(
        from base: TunnelConfiguration,
        overlayIPv4Address: String,
        tunnelRemoteAddress: String,
        protectedRoutes: [String],
        rendezvousServers: [String],
        relayServers: [String],
        remotePeerID: String?,
        crypto: CryptoPolicy
    ) -> TunnelConfiguration {
        let normalizedRemotePeerID = normalizedPeerID(remotePeerID)
        return TunnelConfiguration(
            meshID: base.meshID,
            deviceAlias: base.deviceAlias,
            overlayIPv4Address: overlayIPv4Address,
            tunnelRemoteAddress: tunnelRemoteAddress,
            protectedRoutes: protectedRoutes,
            excludedRoutes: base.excludedRoutes,
            dnsServers: base.dnsServers,
            dnsSearchDomains: base.dnsSearchDomains,
            routeMode: routeMode,
            dnsMode: dnsMode,
            discoveryModes: discoveryModes,
            rendezvousServers: rendezvousServers,
            relayServers: relayServers,
            remotePeerID: normalizedRemotePeerID,
            allowedRelayEndpoints: base.allowedRelayEndpoints,
            relayTLSPolicy: base.relayTLSPolicy,
            maximumCandidateAgeSeconds: base.maximumCandidateAgeSeconds,
            failClosedOnNoCandidate: base.failClosedOnNoCandidate,
            mtu: base.mtu,
            crypto: crypto,
            requirePeerSession: requirePeerSession(
                from: base,
                remotePeerID: normalizedRemotePeerID
            ),
            killSwitch: base.killSwitch,
            meshTrustPolicy: base.meshTrustPolicy,
            discoveryIdentityMode: base.discoveryIdentityMode,
            dytallixIdentity: base.dytallixIdentity
        )
    }

    private func remotePeerID(
        from base: TunnelConfiguration,
        profile: ConnectionProfile?
    ) -> String? {
        switch self {
        case .mesh, .partyMesh, .direct:
            profile?.deploymentDetails.selectedRemotePeerID ?? base.remotePeerID
        case .localVPN:
            nil
        }
    }

    private func normalizedPeerID(_ peerID: String?) -> String? {
        let trimmed = peerID?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? nil : trimmed
    }

    private func requirePeerSession(
        from base: TunnelConfiguration,
        remotePeerID: String?
    ) -> Bool {
        switch self {
        case .mesh, .partyMesh, .direct:
            base.requirePeerSession || remotePeerID != nil
        case .localVPN:
            false
        }
    }

    private func protectedRoutes(
        from base: TunnelConfiguration,
        destinationIPAddress: String?,
        profile: ConnectionProfile? = nil
    ) -> [String] {
        switch self {
        case .mesh, .partyMesh:
            guard let hostRoute = hostRoute(for: destinationIPAddress) else {
                return base.protectedRoutes
            }
            return uniqueRoutes(base.protectedRoutes + [hostRoute])
        case .direct:
            if let protectedPrefixes = profile?.deploymentDetails.protectedPrefixes, !protectedPrefixes.isEmpty {
                return protectedPrefixes
            }
            // The direct endpoint must stay reachable outside the tunnel.
            return base.protectedRoutes
        case .localVPN:
            return ["0.0.0.0/0"]
        }
    }

    private func hostRoute(for destinationIPAddress: String?) -> String? {
        guard let destinationIPAddress else { return nil }
        let trimmed = destinationIPAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return "\(trimmed)/32"
    }

    private func uniqueRoutes(_ routes: [String]) -> [String] {
        var seen = Set<String>()
        return routes.filter { route in
            seen.insert(route).inserted
        }
    }

    private var routeMode: RouteMode {
        switch self {
        case .mesh, .partyMesh:
            .splitTunnel
        case .direct:
            .protectedPrefixesOnly
        case .localVPN:
            .fullTunnel
        }
    }

    private var dnsMode: DNSMode {
        switch self {
        case .mesh, .partyMesh, .direct:
            .tunnelProvided
        case .localVPN:
            .system
        }
    }

    private var discoveryModes: [DiscoveryMode] {
        switch self {
        case .mesh, .partyMesh:
            [.rendezvous]
        case .direct:
            [.rendezvous, .localMDNS]
        case .localVPN:
            [.localMDNS]
        }
    }

    private func rendezvousServers(from base: TunnelConfiguration, destinationIPAddress: String?, endpointPort: Int? = nil) -> [String] {
        switch self {
        case .mesh, .partyMesh, .direct:
            if let endpoint = remappedEndpoint(host: destinationIPAddress, from: base.rendezvousServers, endpointPort: endpointPort) {
                return [endpoint]
            }
            return base.rendezvousServers
        case .localVPN:
            return []
        }
    }

    private func relayServers(from base: TunnelConfiguration, destinationIPAddress: String?, endpointPort: Int? = nil) -> [String] {
        switch self {
        case .mesh, .partyMesh:
            if let endpoint = remappedEndpoint(host: destinationIPAddress, from: base.relayServers, endpointPort: endpointPort) {
                return [endpoint]
            }
            return base.relayServers
        case .direct, .localVPN:
            return []
        }
    }

    private func remappedEndpoint(host: String?, from endpoints: [String], endpointPort: Int? = nil) -> String? {
        guard let host else { return nil }
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHost.isEmpty, let template = endpoints.first else { return nil }
        if let endpointPort, endpointPort > 0 {
            return "\(trimmedHost):\(endpointPort)"
        }
        guard let colon = template.lastIndex(of: ":") else { return nil }
        let port = template[template.index(after: colon)...]
        guard !port.isEmpty else { return nil }
        return "\(trimmedHost):\(port)"
    }
}
