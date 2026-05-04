import XCTest
@testable import QuantumLinkKit

final class PrivacyDefaultsTests: XCTestCase {
    private let seedA = Array(UInt8(0)..<UInt8(16))
    private let seedB = Array(UInt8(16)..<UInt8(32))

    func testRecursiveAllocatorIsDeterministicForSameSeedAndRank() throws {
        let first = try RecursiveOverlayAllocator(seed: seedA)
        let second = try RecursiveOverlayAllocator(seed: seedA)

        XCTAssertEqual(
            try first.hostOffset(forRank: 0x15_5555, attempt: 0),
            try second.hostOffset(forRank: 0x15_5555, attempt: 0)
        )
    }

    func testRecursiveAllocatorDiffusesSeedAndAttemptAcrossHostSpace() throws {
        let first = try RecursiveOverlayAllocator(seed: seedA)
        let second = try RecursiveOverlayAllocator(seed: seedB)
        let rank: UInt32 = 0x15_5555

        let firstOffset = try first.hostOffset(forRank: rank, attempt: 0)
        let secondOffset = try second.hostOffset(forRank: rank, attempt: 0)
        let retryOffset = try first.hostOffset(forRank: rank, attempt: 1)

        XCTAssertNotEqual(firstOffset, rank)
        XCTAssertNotEqual(firstOffset, secondOffset)
        XCTAssertNotEqual(firstOffset, retryOffset)
        XCTAssertLessThan(firstOffset, UInt32(1 << 22))
        XCTAssertLessThan(secondOffset, UInt32(1 << 22))
        XCTAssertLessThan(retryOffset, UInt32(1 << 22))
    }

    func testRecursiveCandidatesSkipReservedHostOffsets() throws {
        let allocator = try RecursiveOverlayAllocator(seed: seedA)
        let reserved = Set<UInt32>([0, 1, RecursiveOverlayAllocator.hostMask])
        let candidates = try allocator.candidateHostOffsets(limit: 8, reservedOffsets: reserved)

        XCTAssertEqual(candidates.count, 8)
        XCTAssertFalse(candidates.contains(0))
        XCTAssertFalse(candidates.contains(1))
        XCTAssertFalse(candidates.contains(RecursiveOverlayAllocator.hostMask))
        XCTAssertEqual(Set(candidates).count, candidates.count)
    }

    func testRandomOverlayAddressUsesRecursiveSeedMaterial() throws {
        var requestedCounts: [Int] = []
        let address = try PrivacyDefaults.randomOverlayIPv4Address(randomBytes: { count in
            requestedCounts.append(count)
            return seedA
        })

        XCTAssertEqual(requestedCounts, [16])
        XCTAssertTrue(address.hasPrefix("100."))
        XCTAssertNotEqual(address, PrivacyDefaults.tunnelGatewayIPv4Address)
    }

    func testGeneratedOverlayAddressAvoidsNetworkAndBroadcastHostOffsets() throws {
        let networkAddress = try PrivacyDefaults.randomOverlayIPv4Address(randomBytes: { _ in
            [UInt8](repeating: 0, count: 16)
        })
        let broadcastAddress = try PrivacyDefaults.randomOverlayIPv4Address(randomBytes: { _ in
            [UInt8](repeating: 0xff, count: 16)
        })

        XCTAssertNotEqual(networkAddress, "100.64.0.0")
        XCTAssertNotEqual(networkAddress, PrivacyDefaults.tunnelGatewayIPv4Address)
        XCTAssertNotEqual(broadcastAddress, "100.127.255.255")
        XCTAssertNotEqual(broadcastAddress, PrivacyDefaults.tunnelGatewayIPv4Address)
    }

    func testPseudonymousLabelsDoNotIncludeHostNames() throws {
        let label = try PrivacyDefaults.pseudonymousLabel(prefix: "device", randomBytes: { count in
            XCTAssertEqual(count, 6)
            return [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]
        })

        XCTAssertEqual(label, "device-abcdef012345")
    }

    func testRedactsIPv4AndEndpointStrings() {
        let redacted = PrivacyDefaults.redactNetworkIdentifiers(
            in: "failed to connect 192.168.1.42:4433 via 100.127.0.2"
        )

        // Ports are redacted along with the address — they can identify
        // services (4433=QUIC, 5900=VNC) and the support-bundle policy is
        // strict over-redaction.
        XCTAssertEqual(redacted, "failed to connect [redacted-ip] via [redacted-ip]")
    }

    func testRedactsIPv6Literals() {
        let redacted = PrivacyDefaults.redactNetworkIdentifiers(
            in: "tunnel target fe80::1234:5678:abcd:1 timed out"
        )
        XCTAssertEqual(redacted, "tunnel target [redacted-ip] timed out")

        let bracketed = PrivacyDefaults.redactNetworkIdentifiers(
            in: "QUIC peer at [2001:db8::1]:4433 unreachable"
        )
        XCTAssertEqual(bracketed, "QUIC peer at [redacted-ip] unreachable")

        let loopback = PrivacyDefaults.redactNetworkIdentifiers(
            in: "responder bound to ::1 (loopback)"
        )
        XCTAssertEqual(loopback, "responder bound to [redacted-ip] (loopback)")
    }

    func testRedactsMultipleAddressesInOneLine() {
        let redacted = PrivacyDefaults.redactNetworkIdentifiers(
            in: "rendezvous=10.0.0.5:9471 relay=[2001:db8::beef]:9472 peer=192.0.2.7"
        )
        XCTAssertFalse(redacted.contains("10.0.0.5"))
        XCTAssertFalse(redacted.contains("2001:db8"))
        XCTAssertFalse(redacted.contains("192.0.2.7"))
        XCTAssertFalse(redacted.contains(":9471"))
        XCTAssertFalse(redacted.contains(":9472"))
    }

    func testRedactionPreservesNonAddressNumbers() {
        // Things that look like decimal numbers but aren't IP addresses
        // must not be redacted: version strings, byte counts, frame counts.
        let preserved = PrivacyDefaults.redactNetworkIdentifiers(
            in: "version 1.2.3 sent 1234 frames over 5678 ms"
        )
        XCTAssertEqual(preserved, "version 1.2.3 sent 1234 frames over 5678 ms")
    }

    func testDefaultDevelopmentConfigurationUsesPrivacyPreservingIdentifiers() {
        let configuration = TunnelConfiguration.defaultDevelopment

        XCTAssertTrue(configuration.overlayIPv4Address.hasPrefix("100."))
        XCTAssertEqual(configuration.protectedRoutes, ["100.64.0.0/10"])
        XCTAssertTrue(configuration.meshID.hasPrefix("mesh-"))
        XCTAssertTrue(configuration.deviceAlias.hasPrefix("device-"))
        XCTAssertEqual(configuration.dnsSearchDomains, [])
    }

    // MARK: - peer-identifier + log redaction (crash-report safety)

    func testRedactsPeerIdentifierInTheCanonicalFormat() {
        // The canonical peer_id is `qlink_` + 22 chars of URL-safe
        // base64-no-pad over the SHA-256-truncated public key.
        let line = "rejected by ACL: peer qlink_7mAA6HLACEO4_WoR6YwJiw"
        let redacted = PrivacyDefaults.redactPeerIdentifiers(in: line)
        XCTAssertEqual(redacted, "rejected by ACL: peer [redacted-peer]")
    }

    func testRedactsMultiplePeerIdentifiersInOneLine() {
        let line = "qlink_AAAA1111BBBB2222CCCC33 talking to qlink_DDDD4444EEEE5555FFFF66"
        let redacted = PrivacyDefaults.redactPeerIdentifiers(in: line)
        XCTAssertEqual(redacted, "[redacted-peer] talking to [redacted-peer]")
    }

    func testPeerRedactionLeavesUnrelatedQlinkPrefixesAlone() {
        // The pattern requires `qlink_` followed by 20+ chars.
        // Configuration keys, log labels, and short identifiers must
        // pass through unchanged.
        let cases = [
            "qlinkctl",                   // CLI binary name
            "qlink_short",                // not enough trailing chars
            "qlink_metrics_endpoint",     // config key
        ]
        for value in cases {
            XCTAssertEqual(
                PrivacyDefaults.redactPeerIdentifiers(in: value),
                value,
                "should not redact: \(value)"
            )
        }
    }

    func testRedactForLogStripsBothNetworkAndPeerIdentifiers() {
        // The shape of an actual Rust-core protocol error that flows
        // up through `localizedDescription` into a `.public` log line:
        // mesh_id, peer_id, and a host:port candidate all in the same
        // string.
        let raw = "peer qlink_7mAA6HLACEO4_WoR6YwJiw not found in rendezvous devmesh; last try 192.168.1.50:9471"
        let redacted = PrivacyDefaults.redactForLog(raw)

        XCTAssertFalse(redacted.contains("qlink_7mAA6HLACEO4_WoR6YwJiw"))
        XCTAssertFalse(redacted.contains("192.168.1.50"))
        XCTAssertFalse(redacted.contains("9471"))
        XCTAssertTrue(redacted.contains("[redacted-peer]"))
        XCTAssertTrue(redacted.contains("[redacted-ip]"))
        // Pseudonymous mesh_id is intentionally preserved — it's a
        // configuration value the operator chose, not an identifier
        // derived from device material.
        XCTAssertTrue(redacted.contains("devmesh"))
    }

    func testRedactForLogErrorOverloadRunsOnLocalizedDescription() {
        struct TestError: LocalizedError {
            let errorDescription: String?
        }
        let error = TestError(errorDescription: "transport handshake failed against qlink_AAAAAAAAAAAAAAAAAAAA at 10.0.0.5:443")
        let redacted = PrivacyDefaults.redactForLog(error)

        XCTAssertFalse(redacted.contains("qlink_AAAAAAAAAAAAAAAAAAAA"))
        XCTAssertFalse(redacted.contains("10.0.0.5"))
        XCTAssertTrue(redacted.contains("transport handshake failed"))
    }

    func testRedactNetworkIdentifiersStillKeepsPeerIdentifiersForSupportBundlePath() {
        // Regression guard for the deliberate split: support bundles
        // keep peer_id by design (see `SupportBundleRedactionMode`
        // doc). Don't accidentally widen `redactNetworkIdentifiers`.
        let line = "peer qlink_7mAA6HLACEO4_WoR6YwJiw at 192.168.1.50"
        let redacted = PrivacyDefaults.redactNetworkIdentifiers(in: line)
        XCTAssertTrue(redacted.contains("qlink_7mAA6HLACEO4_WoR6YwJiw"))
        XCTAssertFalse(redacted.contains("192.168.1.50"))
    }
}
