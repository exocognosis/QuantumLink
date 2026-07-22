import Foundation
import CryptoKit
import Security

public enum PrivacyDefaultsError: Error, Equatable, LocalizedError {
    case randomBytesUnavailable(Int32)
    case invalidRandomByteCount(expected: Int, actual: Int)
    case invalidAllocatorSeedByteCount(Int)
    case invalidHostRank(UInt32)

    public var errorDescription: String? {
        switch self {
        case .randomBytesUnavailable(let status):
            "Secure random byte generation failed with status \(status)"
        case .invalidRandomByteCount(let expected, let actual):
            "Expected \(expected) random bytes but received \(actual)"
        case .invalidAllocatorSeedByteCount(let actual):
            "Recursive overlay allocation requires at least 16 seed bytes but received \(actual)"
        case .invalidHostRank(let rank):
            "Host rank \(rank) is outside the overlay host space"
        }
    }
}

public struct RecursiveOverlayAllocator: Sendable {
    public static let hostBitCount = 22
    public static let hostMask: UInt32 = (1 << UInt32(hostBitCount)) - 1
    private static let seedByteCount = 16

    private let seed: [UInt8]
    private let rank: UInt32

    public init(seed: [UInt8]) throws {
        guard seed.count >= Self.seedByteCount else {
            throw PrivacyDefaultsError.invalidAllocatorSeedByteCount(seed.count)
        }

        self.seed = seed
        self.rank = Self.rank(from: seed)
    }

    public func hostOffset(forRank rank: UInt32, attempt: UInt32 = 0) throws -> UInt32 {
        guard rank <= Self.hostMask else {
            throw PrivacyDefaultsError.invalidHostRank(rank)
        }

        return recursiveHostOffset(
            rank: rank,
            attempt: attempt,
            depth: 0,
            prefix: 0
        )
    }

    public func candidateHostOffsets(
        limit: Int,
        reservedOffsets: Set<UInt32>
    ) throws -> [UInt32] {
        var candidates: [UInt32] = []
        var seen = reservedOffsets
        var attempt: UInt32 = 0

        while candidates.count < limit, attempt < 512 {
            let offset = try hostOffset(forRank: rank, attempt: attempt)
            if offset > 0, offset < Self.hostMask, !seen.contains(offset) {
                candidates.append(offset)
                seen.insert(offset)
            }
            attempt += 1
        }

        var fallback = (rank % (Self.hostMask - 1)) + 1
        while candidates.count < limit {
            if !seen.contains(fallback) {
                candidates.append(fallback)
                seen.insert(fallback)
            }
            fallback = (fallback % (Self.hostMask - 1)) + 1
        }

        return candidates
    }

    private func recursiveHostOffset(
        rank: UInt32,
        attempt: UInt32,
        depth: Int,
        prefix: UInt32
    ) -> UInt32 {
        guard depth < Self.hostBitCount else {
            return prefix
        }

        let bitIndex = UInt32(Self.hostBitCount - depth - 1)
        let inputBit = (rank >> bitIndex) & 1
        let outputBit = inputBit ^ branchSwapBit(depth: depth, prefix: prefix, attempt: attempt)

        return recursiveHostOffset(
            rank: rank,
            attempt: attempt,
            depth: depth + 1,
            prefix: (prefix << 1) | outputBit
        )
    }

    private func branchSwapBit(depth: Int, prefix: UInt32, attempt: UInt32) -> UInt32 {
        var material = Data(seed)
        material.append(contentsOf: UInt32(depth).bigEndianBytes)
        material.append(contentsOf: prefix.bigEndianBytes)
        material.append(contentsOf: attempt.bigEndianBytes)
        let digest = SHA256.hash(data: material)
        return UInt32(Array(digest)[0] & 0x01)
    }

    private static func rank(from seed: [UInt8]) -> UInt32 {
        let tail = seed.suffix(4)
        return tail.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } & hostMask
    }
}

public enum PrivacyDefaults {
    public static let overlayCIDR = "100.64.0.0/10"
    public static let tunnelGatewayIPv4Address = "100.64.0.1"

    public static func secureRandomBytes(count: Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw PrivacyDefaultsError.randomBytesUnavailable(status)
        }
        return bytes
    }

    public static func randomOverlayIPv4Address(
        excluding excludedAddresses: Set<String> = [],
        randomBytes: (Int) throws -> [UInt8] = secureRandomBytes
    ) throws -> String {
        let network: UInt32 = 0x6440_0000
        let seed = try randomBytes(16)
        guard seed.count == 16 else {
            throw PrivacyDefaultsError.invalidRandomByteCount(expected: 16, actual: seed.count)
        }

        let allocator = try RecursiveOverlayAllocator(seed: seed)
        let reservedOffsets = Set<UInt32>([
            0,
            1,
            RecursiveOverlayAllocator.hostMask
        ])
        for candidateOffset in try allocator.candidateHostOffsets(limit: 64, reservedOffsets: reservedOffsets) {
            let candidate = formatIPv4(network | candidateOffset)
            if !excludedAddresses.contains(candidate) {
                return candidate
            }
        }

        return "100.64.0.2"
    }

    public static func pseudonymousLabel(
        prefix: String,
        randomBytes: (Int) throws -> [UInt8] = secureRandomBytes
    ) throws -> String {
        let bytes = try randomBytes(6)
        guard bytes.count == 6 else {
            throw PrivacyDefaultsError.invalidRandomByteCount(expected: 6, actual: bytes.count)
        }

        return "\(prefix)-\(bytes.map { String(format: "%02x", $0) }.joined())"
    }

    public static func defaultTunnelConfiguration() -> TunnelConfiguration {
        let excluded = Set([tunnelGatewayIPv4Address])
        let overlayAddress = (try? randomOverlayIPv4Address(excluding: excluded)) ?? "100.64.0.2"
        let meshID = (try? pseudonymousLabel(prefix: "mesh")) ?? "mesh-local"
        let deviceAlias = (try? pseudonymousLabel(prefix: "device")) ?? "device-local"

        return TunnelConfiguration(
            meshID: meshID,
            deviceAlias: deviceAlias,
            overlayIPv4Address: overlayAddress,
            tunnelRemoteAddress: tunnelGatewayIPv4Address,
            protectedRoutes: [overlayCIDR],
            dnsServers: [tunnelGatewayIPv4Address],
            dnsSearchDomains: [],
            rendezvousServers: ["127.0.0.1:9471"],
            relayServers: ["127.0.0.1:9472"]
        )
    }

    /// Redacts peer-attributable identifiers that should not appear in
    /// crash reports or `.public`-tagged log output:
    ///
    /// - QuantumLink `peer_id` strings (`qlink_<22-char-base64url>`).
    ///   The format is fixed by `DevicePublicKey::peer_id` in the Rust
    ///   core: `"qlink_"` + URL-safe base64 of the first 16 bytes of
    ///   `SHA-256(public_key_bytes)`, no padding. The pattern is
    ///   deliberately a shade more permissive than the spec (allowing
    ///   20-32 trailing chars) so a future format tweak doesn't
    ///   silently start leaking identifiers.
    ///
    /// Why this is separate from `redactNetworkIdentifiers`: packet-tunnel
    /// diagnostics, logs, crash reports, and default support bundles all treat
    /// peer IDs as persistent identifiers. `redactForLog` combines both network
    /// and peer identifier redaction.
    public static func redactPeerIdentifiers(in value: String) -> String {
        let pattern = #"\bqlink_[A-Za-z0-9_-]{20,32}\b"#
        return value.replacingOccurrences(
            of: pattern,
            with: "[redacted-peer]",
            options: .regularExpression
        )
    }

    /// Combined redaction for crash reports and `.public`-tagged
    /// `Logger` interpolations: drops both network identifiers and
    /// QuantumLink peer IDs.
    ///
    /// Use this for any string that may end up in a user-shareable
    /// artifact (crash reports, Console.app exports, `log show`
    /// output). For support-bundle JSON keep using
    /// `redactNetworkIdentifiers` — that path intentionally retains
    /// `peer_id`s as pseudonymous identifiers.
    public static func redactForLog(_ value: String) -> String {
        redactPeerIdentifiers(in: redactNetworkIdentifiers(in: value))
    }

    /// Convenience overload that pulls `localizedDescription` off the
    /// error and runs `redactForLog` on it. The vast majority of leak
    /// vectors in this codebase are
    /// `\(error.localizedDescription, privacy: .public)` — call sites
    /// can swap straight to `\(PrivacyDefaults.redactForLog(error), privacy: .public)`.
    public static func redactForLog(_ error: Error) -> String {
        redactForLog(error.localizedDescription)
    }

    /// Redacts network identifiers that operators or users might paste into
    /// a support bundle or share over chat. Covers:
    ///
    /// - IPv4 literals, with optional `:port` suffix (`192.168.1.10:4433`)
    /// - IPv6 literals, including bracketed forms (`[fe80::1]:4433`)
    /// - Bracketed IPv6 without ports (`[2001:db8::1]`)
    /// - DNS/FQDN endpoint names and URL hosts (`relay.example.net:9472`)
    /// - Dytallix/EVM-style wallet or contract addresses (`0x...`)
    ///
    /// The regex matches deliberately err on the side of over-redaction:
    /// false positives produce harmless `[redacted-ip]` strings, false
    /// negatives leak addresses. Hostname/FQDN matching deliberately
    /// over-redacts dotted names in diagnostic strings so DNS data and
    /// rendezvous/relay endpoint names do not appear in default support
    /// exports or `.public` log output.
    ///
    /// **Note**: this function does NOT touch `peer_id` strings — by
    /// design, since support bundles use it and intentionally keep
    /// `peer_id`s as pseudonymous identifiers. For crash reports and
    /// log lines, use `redactForLog` instead.
    public static func redactNetworkIdentifiers(in value: String) -> String {
        // Order matters: redact bracketed IPv6 (with optional port) FIRST,
        // because the inner address would otherwise be matched by the
        // bare-IPv6 pattern and leave dangling brackets.
        let dytallixAddress = #"\b0x[0-9a-fA-F]{40}\b"#
        let bracketedIPv6WithOptionalPort =
            #"\[(?:[0-9a-fA-F:]+|::1)\](?::\d{1,5})?"#
        // Bare IPv6: at least two consecutive `<hex-group>:` runs, where
        // each `<hex-group>` may be empty to permit the `::` compression
        // form. Greedy matching consumes the whole address even when it
        // contains nested empty groups (e.g. `fe80::1234:5678`).
        // Tradeoff: this can over-match strings like `1:2:3` that aren't
        // really addresses, but for support-bundle redaction over-matching
        // is the safe default.
        let bareIPv6 = #"(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}"#
        // IPv4 with optional `:port` suffix. Bound by word boundaries so
        // that `192.168.1.10` is captured but `version 1.2.3.4.5` is not.
        let ipv4WithOptionalPort = #"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"#
        // Hostnames/FQDNs with alphabetic TLDs, optionally prefixed by a
        // URL scheme and optionally suffixed by a port. This intentionally
        // redacts support-worthy DNS data but avoids version strings like
        // `1.2.3` because the final label must be alphabetic.
        let fqdnWithOptionalSchemeAndPort =
            #"(?i)\b(?:[a-z][a-z0-9+.-]*://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?\b"#

        let combined = "(?:\(dytallixAddress))|(?:\(bracketedIPv6WithOptionalPort))|(?:\(bareIPv6))|(?:\(ipv4WithOptionalPort))|(?:\(fqdnWithOptionalSchemeAndPort))"

        return value.replacingOccurrences(
            of: combined,
            with: "[redacted-ip]",
            options: .regularExpression
        )
    }

    private static func formatIPv4(_ value: UInt32) -> String {
        [
            (value >> 24) & 0xff,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff
        ]
        .map(String.init)
        .joined(separator: ".")
    }
}

private extension UInt32 {
    var bigEndianBytes: [UInt8] {
        return [
            UInt8((self >> 24) & 0xff),
            UInt8((self >> 16) & 0xff),
            UInt8((self >> 8) & 0xff),
            UInt8(self & 0xff)
        ]
    }
}
