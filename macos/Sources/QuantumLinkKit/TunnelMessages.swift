import Foundation

public enum TunnelCommand: String, Codable, Sendable {
    case connect
    case disconnect
    case reloadConfiguration
    case exportDiagnostics
    case status
}

public struct TunnelCommandEnvelope: Codable, Sendable {
    public let command: TunnelCommand
    public let issuedAt: Date
    public let configuration: TunnelConfiguration?

    public init(command: TunnelCommand, issuedAt: Date = Date(), configuration: TunnelConfiguration? = nil) {
        self.command = command
        self.issuedAt = issuedAt
        self.configuration = configuration
    }
}

public enum TunnelProviderMessage: Codable, Sendable {
    case status(TunnelStatus)
    case diagnostic(String)
    case error(String)
}

