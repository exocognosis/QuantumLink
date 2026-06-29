import Foundation

public enum QuantumLinkConnectionType: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case ssh
    case https
    case rdp
    case vnc
    case custom

    public var id: Self { self }

    public var defaultPort: Int {
        switch self {
        case .ssh:
            22
        case .https:
            443
        case .rdp:
            3389
        case .vnc:
            5900
        case .custom:
            0
        }
    }
}

public enum PeerDeviceRole: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case peer
    case gateway
    case rendezvous
    case relay

    public var id: Self { self }
}

public enum VNCAuthenticationMode: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case none
    case password
    case userPassword

    public var id: Self { self }
}

public struct PeerDeviceProfile: Codable, Equatable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var alias: String
    public var endpointAddress: String
    public var overlayIPAddress: String
    public var role: PeerDeviceRole
    public var port: Int

    public init(
        id: UUID = UUID(),
        alias: String = "",
        endpointAddress: String = "",
        overlayIPAddress: String = "",
        role: PeerDeviceRole = .peer,
        port: Int = 0
    ) {
        self.id = id
        self.alias = alias
        self.endpointAddress = endpointAddress
        self.overlayIPAddress = overlayIPAddress
        self.role = role
        self.port = port
    }
}

public struct DeploymentProfileDetails: Codable, Equatable, Hashable, Sendable {
    public var directEndpointPort: Int
    public var protectedPrefixesText: String
    public var peerDevices: [PeerDeviceProfile]
    public var localDevices: [PeerDeviceProfile]

    public init(
        directEndpointPort: Int = 9471,
        protectedPrefixesText: String = "",
        peerDevices: [PeerDeviceProfile] = [],
        localDevices: [PeerDeviceProfile] = []
    ) {
        self.directEndpointPort = directEndpointPort
        self.protectedPrefixesText = protectedPrefixesText
        self.peerDevices = peerDevices
        self.localDevices = localDevices
    }

    public var protectedPrefixes: [String] {
        protectedPrefixesText
            .split { $0 == "," || $0 == "\n" || $0 == " " || $0 == "\t" }
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
}

public struct SSHConnectionSettings: Codable, Equatable, Hashable, Sendable {
    public var username: String
    public var identityFilePath: String
    public var remoteCommand: String

    public init(username: String = "", identityFilePath: String = "", remoteCommand: String = "") {
        self.username = username
        self.identityFilePath = identityFilePath
        self.remoteCommand = remoteCommand
    }
}

public struct HTTPSConnectionSettings: Codable, Equatable, Hashable, Sendable {
    public var hostOrURL: String
    public var path: String
    public var tlsServerName: String
    public var validateTLS: Bool

    public init(hostOrURL: String = "", path: String = "/", tlsServerName: String = "", validateTLS: Bool = true) {
        self.hostOrURL = hostOrURL
        self.path = path
        self.tlsServerName = tlsServerName
        self.validateTLS = validateTLS
    }
}

public struct RDPConnectionSettings: Codable, Equatable, Hashable, Sendable {
    public var username: String
    public var domain: String
    public var gatewayHost: String

    public init(username: String = "", domain: String = "", gatewayHost: String = "") {
        self.username = username
        self.domain = domain
        self.gatewayHost = gatewayHost
    }
}

public struct VNCConnectionSettings: Codable, Equatable, Hashable, Sendable {
    public var display: String
    public var authMode: VNCAuthenticationMode
    public var username: String

    public init(display: String = "", authMode: VNCAuthenticationMode = .password, username: String = "") {
        self.display = display
        self.authMode = authMode
        self.username = username
    }
}

public struct CustomConnectionSettings: Codable, Equatable, Hashable, Sendable {
    public var protocolName: String
    public var notes: String

    public init(protocolName: String = "", notes: String = "") {
        self.protocolName = protocolName
        self.notes = notes
    }
}

public struct ConnectionProfile: Codable, Equatable, Hashable, Identifiable, Sendable {
    public let id: UUID
    public var name: String
    public var sourceIPAddress: String
    public var destinationIPAddress: String
    public var connectionType: QuantumLinkConnectionType
    public var port: Int
    public var pqcAlgorithm: PQCAlgorithm
    public var deploymentDetails: DeploymentProfileDetails
    public var sshSettings: SSHConnectionSettings
    public var httpsSettings: HTTPSConnectionSettings
    public var rdpSettings: RDPConnectionSettings
    public var vncSettings: VNCConnectionSettings
    public var customSettings: CustomConnectionSettings
    public var lastConnectedAt: Date?

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case sourceIPAddress
        case destinationIPAddress
        case connectionType
        case port
        case pqcAlgorithm
        case deploymentDetails
        case sshSettings
        case httpsSettings
        case rdpSettings
        case vncSettings
        case customSettings
        case lastConnectedAt
    }

    public init(
        id: UUID = UUID(),
        name: String = "",
        sourceIPAddress: String,
        destinationIPAddress: String,
        connectionType: QuantumLinkConnectionType,
        port: Int? = nil,
        pqcAlgorithm: PQCAlgorithm = .fips203,
        deploymentDetails: DeploymentProfileDetails = DeploymentProfileDetails(),
        sshSettings: SSHConnectionSettings = SSHConnectionSettings(),
        httpsSettings: HTTPSConnectionSettings = HTTPSConnectionSettings(),
        rdpSettings: RDPConnectionSettings = RDPConnectionSettings(),
        vncSettings: VNCConnectionSettings = VNCConnectionSettings(),
        customSettings: CustomConnectionSettings = CustomConnectionSettings(),
        lastConnectedAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.sourceIPAddress = sourceIPAddress
        self.destinationIPAddress = destinationIPAddress
        self.connectionType = connectionType
        self.port = port ?? connectionType.defaultPort
        self.pqcAlgorithm = pqcAlgorithm
        self.deploymentDetails = deploymentDetails
        self.sshSettings = sshSettings
        self.httpsSettings = httpsSettings
        self.rdpSettings = rdpSettings
        self.vncSettings = vncSettings
        self.customSettings = customSettings
        self.lastConnectedAt = lastConnectedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(UUID.self, forKey: .id)
        self.name = try container.decode(String.self, forKey: .name)
        self.sourceIPAddress = try container.decode(String.self, forKey: .sourceIPAddress)
        self.destinationIPAddress = try container.decode(String.self, forKey: .destinationIPAddress)
        self.connectionType = try container.decode(QuantumLinkConnectionType.self, forKey: .connectionType)
        self.port = try container.decode(Int.self, forKey: .port)
        self.pqcAlgorithm = try container.decodeIfPresent(PQCAlgorithm.self, forKey: .pqcAlgorithm) ?? .fips203
        self.deploymentDetails = try container.decodeIfPresent(DeploymentProfileDetails.self, forKey: .deploymentDetails) ?? DeploymentProfileDetails()
        self.sshSettings = try container.decodeIfPresent(SSHConnectionSettings.self, forKey: .sshSettings) ?? SSHConnectionSettings()
        self.httpsSettings = try container.decodeIfPresent(HTTPSConnectionSettings.self, forKey: .httpsSettings) ?? HTTPSConnectionSettings()
        self.rdpSettings = try container.decodeIfPresent(RDPConnectionSettings.self, forKey: .rdpSettings) ?? RDPConnectionSettings()
        self.vncSettings = try container.decodeIfPresent(VNCConnectionSettings.self, forKey: .vncSettings) ?? VNCConnectionSettings()
        self.customSettings = try container.decodeIfPresent(CustomConnectionSettings.self, forKey: .customSettings) ?? CustomConnectionSettings()
        self.lastConnectedAt = try container.decodeIfPresent(Date.self, forKey: .lastConnectedAt)
    }

    public var stableKey: String {
        [
            sourceIPAddress.trimmingCharacters(in: .whitespacesAndNewlines),
            destinationIPAddress.trimmingCharacters(in: .whitespacesAndNewlines),
            connectionType.rawValue,
            "\(port)",
            pqcAlgorithm.rawValue,
            deploymentDetails.stableKeyComponent,
            connectionSettingsStableKeyComponent
        ].joined(separator: "|")
    }

    public var displayName: String {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedName.isEmpty {
            return "\(connectionType.rawValue.uppercased()) \(destinationIPAddress)"
        } else {
            return trimmedName
        }
    }

    public var redactedDisplayName: String {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedName.isEmpty {
            return "\(connectionType.rawValue.uppercased()) \(PrivacyDefaults.redactNetworkIdentifiers(in: destinationIPAddress))"
        } else {
            return PrivacyDefaults.redactNetworkIdentifiers(in: trimmedName)
        }
    }

    public var redactedRouteSummary: String {
        PrivacyDefaults.redactNetworkIdentifiers(in: "\(sourceIPAddress) to \(destinationIPAddress)")
    }

    public func missingRequiredFields(for deploymentMode: QuantumLinkDeploymentMode) -> [String] {
        var missing: [String] = []
        if sourceIPAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            missing.append("Source IP")
        }

        switch deploymentMode {
        case .direct:
            if destinationIPAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                missing.append("Destination IP")
            }
        case .mesh, .partyMesh:
            if deploymentDetails.peerDevices.filter(\.hasEndpoint).isEmpty {
                missing.append("Mesh peer")
            }
        case .localVPN:
            if deploymentDetails.localDevices.filter(\.hasEndpoint).isEmpty {
                missing.append("LAN device")
            }
        }

        switch connectionType {
        case .ssh:
            if sshSettings.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                missing.append("SSH username")
            }
        case .https:
            if httpsSettings.hostOrURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
               destinationIPAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                missing.append("HTTPS host")
            }
        case .rdp:
            if rdpSettings.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                missing.append("Windows username")
            }
        case .vnc:
            if vncSettings.authMode == .userPassword,
               vncSettings.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                missing.append("VNC username")
            }
        case .custom:
            if customSettings.protocolName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                missing.append("Protocol")
            }
        }

        return missing
    }

    private var connectionSettingsStableKeyComponent: String {
        switch connectionType {
        case .ssh:
            return [
                sshSettings.username,
                sshSettings.identityFilePath,
                sshSettings.remoteCommand
            ].joined(separator: ",")
        case .https:
            return [
                httpsSettings.hostOrURL,
                httpsSettings.path,
                httpsSettings.tlsServerName,
                "\(httpsSettings.validateTLS)"
            ].joined(separator: ",")
        case .rdp:
            return [
                rdpSettings.username,
                rdpSettings.domain,
                rdpSettings.gatewayHost
            ].joined(separator: ",")
        case .vnc:
            return [
                vncSettings.display,
                vncSettings.authMode.rawValue,
                vncSettings.username
            ].joined(separator: ",")
        case .custom:
            return [
                customSettings.protocolName,
                customSettings.notes
            ].joined(separator: ",")
        }
    }
}

private extension DeploymentProfileDetails {
    var stableKeyComponent: String {
        let peers = peerDevices.map(\.stableKeyComponent).joined(separator: ";")
        let local = localDevices.map(\.stableKeyComponent).joined(separator: ";")
        return [
            "\(directEndpointPort)",
            protectedPrefixesText,
            peers,
            local
        ].joined(separator: "|")
    }
}

private extension PeerDeviceProfile {
    var hasEndpoint: Bool {
        !endpointAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var stableKeyComponent: String {
        [
            alias,
            endpointAddress,
            overlayIPAddress,
            role.rawValue,
            "\(port)"
        ].joined(separator: ",")
    }
}

public enum ConnectionProfileLibrary {
    public static func addRecent(
        _ profile: ConnectionProfile,
        to recents: [ConnectionProfile],
        limit: Int = 3,
        connectedAt: Date = Date()
    ) -> [ConnectionProfile] {
        var updatedProfile = profile
        updatedProfile.lastConnectedAt = connectedAt

        let withoutDuplicate = recents.filter { $0.stableKey != updatedProfile.stableKey }
        return Array(([updatedProfile] + withoutDuplicate).prefix(limit))
    }

    public static func toggleFavorite(
        _ profile: ConnectionProfile,
        in favorites: [ConnectionProfile]
    ) -> [ConnectionProfile] {
        if favorites.contains(where: { $0.stableKey == profile.stableKey }) {
            return favorites.filter { $0.stableKey != profile.stableKey }
        }

        return [profile] + favorites
    }
}
