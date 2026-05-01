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

public struct ConnectionProfile: Codable, Equatable, Hashable, Identifiable, Sendable {
    public let id: UUID
    public var name: String
    public var sourceIPAddress: String
    public var destinationIPAddress: String
    public var connectionType: QuantumLinkConnectionType
    public var port: Int
    public var pqcAlgorithm: PQCAlgorithm
    public var lastConnectedAt: Date?

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case sourceIPAddress
        case destinationIPAddress
        case connectionType
        case port
        case pqcAlgorithm
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
        lastConnectedAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.sourceIPAddress = sourceIPAddress
        self.destinationIPAddress = destinationIPAddress
        self.connectionType = connectionType
        self.port = port ?? connectionType.defaultPort
        self.pqcAlgorithm = pqcAlgorithm
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
        self.lastConnectedAt = try container.decodeIfPresent(Date.self, forKey: .lastConnectedAt)
    }

    public var stableKey: String {
        [
            sourceIPAddress.trimmingCharacters(in: .whitespacesAndNewlines),
            destinationIPAddress.trimmingCharacters(in: .whitespacesAndNewlines),
            connectionType.rawValue,
            "\(port)",
            pqcAlgorithm.rawValue
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
