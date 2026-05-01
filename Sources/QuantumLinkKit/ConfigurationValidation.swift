import Foundation

public struct ConfigurationValidationReport: Equatable, Sendable {
    public let configuration: TunnelConfiguration
    public let warnings: [String]

    public var isUsableForLocalDevelopment: Bool {
        warnings.isEmpty
    }
}

public enum ConfigurationValidationError: Error, LocalizedError {
    case unreadable(URL, String)
    case invalidJSON(String)
    case invalidRoute(String)
    case invalidAddress(String)
    case invalidEndpoint(String)

    public var errorDescription: String? {
        switch self {
        case .unreadable(let url, let message):
            "Could not read configuration at \(url.path): \(message)"
        case .invalidJSON(let message):
            "Invalid QuantumLink configuration JSON: \(message)"
        case .invalidRoute(let route):
            "Invalid CIDR route: \(route)"
        case .invalidAddress(let address):
            "Invalid IPv4 address: \(address)"
        case .invalidEndpoint(let endpoint):
            "Invalid endpoint address: \(endpoint)"
        }
    }
}

public enum ConfigurationValidator {
    public static func loadAndValidate(url: URL) throws -> ConfigurationValidationReport {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw ConfigurationValidationError.unreadable(url, error.localizedDescription)
        }
        return try validate(data: data)
    }

    public static func validate(data: Data) throws -> ConfigurationValidationReport {
        let configuration: TunnelConfiguration
        do {
            configuration = try JSONDecoder().decode(TunnelConfiguration.self, from: data)
        } catch {
            throw ConfigurationValidationError.invalidJSON(error.localizedDescription)
        }
        return try validate(configuration: configuration)
    }

    public static func validate(configuration: TunnelConfiguration) throws -> ConfigurationValidationReport {
        try validateIPv4(configuration.overlayIPv4Address)
        try validateIPv4(configuration.tunnelRemoteAddress)

        for route in configuration.protectedRoutes + configuration.excludedRoutes {
            _ = try IPv4CIDR(route)
        }
        for server in configuration.dnsServers {
            try validateIPv4(server)
        }
        for endpoint in configuration.rendezvousServers + configuration.relayServers {
            try validateEndpoint(endpoint)
        }

        var warnings: [String] = []
        if configuration.protectedRoutes.isEmpty {
            warnings.append("protectedRoutes is empty; no traffic will be protected")
        }
        if configuration.dnsMode == .tunnelProvided, configuration.dnsServers.isEmpty {
            warnings.append("dnsMode is tunnelProvided but dnsServers is empty")
        }
        if configuration.discoveryModes.contains(.rendezvous), configuration.rendezvousServers.isEmpty {
            warnings.append("rendezvous discovery is enabled but rendezvousServers is empty")
        }
        if configuration.mtu < 576 {
            warnings.append("mtu is below IPv4 minimum reassembly size")
        }

        return ConfigurationValidationReport(configuration: configuration, warnings: warnings)
    }

    private static func validateIPv4(_ address: String) throws {
        let parts = address.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) else {
            throw ConfigurationValidationError.invalidAddress(address)
        }
    }

    private static func validateEndpoint(_ endpoint: String) throws {
        guard
            let colon = endpoint.lastIndex(of: ":"),
            colon > endpoint.startIndex,
            colon < endpoint.index(before: endpoint.endIndex),
            UInt16(endpoint[endpoint.index(after: colon)...]) != nil
        else {
            throw ConfigurationValidationError.invalidEndpoint(endpoint)
        }
    }
}
