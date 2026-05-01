import Foundation

public enum IPv4CIDRError: Error, Equatable, LocalizedError {
    case invalidFormat(String)
    case invalidAddress(String)
    case invalidPrefix(Int)

    public var errorDescription: String? {
        switch self {
        case .invalidFormat(let value):
            "Invalid IPv4 CIDR format: \(value)"
        case .invalidAddress(let value):
            "Invalid IPv4 address: \(value)"
        case .invalidPrefix(let value):
            "Invalid IPv4 prefix length: \(value)"
        }
    }
}

public struct IPv4CIDR: Codable, Hashable, Sendable {
    public let networkAddress: String
    public let prefixLength: Int
    public let subnetMask: String

    public init(_ rawValue: String) throws {
        let parts = rawValue.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]) else {
            throw IPv4CIDRError.invalidFormat(rawValue)
        }
        guard (0...32).contains(prefix) else {
            throw IPv4CIDRError.invalidPrefix(prefix)
        }
        let address = String(parts[0])
        let addressValue = try Self.parseAddress(address)
        let maskValue = Self.maskValue(prefixLength: prefix)
        let networkValue = addressValue & maskValue

        self.networkAddress = Self.formatAddress(networkValue)
        self.prefixLength = prefix
        self.subnetMask = Self.formatAddress(maskValue)
    }

    private static func parseAddress(_ address: String) throws -> UInt32 {
        let octets = address.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else {
            throw IPv4CIDRError.invalidAddress(address)
        }

        var value: UInt32 = 0
        for octet in octets {
            guard let byte = UInt8(octet) else {
                throw IPv4CIDRError.invalidAddress(address)
            }
            value = (value << 8) | UInt32(byte)
        }
        return value
    }

    private static func maskValue(prefixLength: Int) -> UInt32 {
        guard prefixLength > 0 else { return 0 }
        return UInt32.max << UInt32(32 - prefixLength)
    }

    private static func formatAddress(_ value: UInt32) -> String {
        let octets = [
            (value >> 24) & 0xff,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff
        ]
        return octets.map(String.init).joined(separator: ".")
    }
}

