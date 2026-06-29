import XCTest
@testable import QuantumLinkKit

final class DytallixPeerTrustModelTests: XCTestCase {
  func testTunnelStatusDecodesOlderPayloadWithoutPeerTrust() throws {
    let json = """
    {
      "phase": "idle",
      "pathType": "unavailable",
      "routeMode": "splitTunnel",
      "dnsMode": "tunnelProvided",
      "overlayIPv4Address": "100.127.0.1",
      "protectedRoutes": ["100.127.0.0/24"],
      "peers": [],
      "metrics": {
        "peerCount": 0,
        "directPeerCount": 0,
        "relayPeerCount": 0,
        "bytesIn": 0,
        "bytesOut": 0,
        "replayDrops": 0
      }
    }
    """.data(using: .utf8)!

    let status = try JSONDecoder().decode(TunnelStatus.self, from: json)

    XCTAssertFalse(status.peerTrust.required)
    XCTAssertEqual(status.peerTrust.policy, .developmentOptional)
    XCTAssertEqual(status.peerTrust.identityMode, .off)
  }

  func testPeerStatusRoundTripsDytallixTrust() throws {
    let peer = PeerStatus(
      identity: PeerIdentity(
        peerID: "qlink_peer_123",
        alias: "peer",
        publicKeyFingerprint: "fingerprint"
      ),
      pathType: .direct,
      endpoints: [],
      overlayAddress: "100.127.0.2",
      rttMilliseconds: 12,
      lastRekey: nil,
      bytesIn: 1,
      bytesOut: 2,
      dytallixTrust: DytallixPeerTrustStatus(
        policy: .publicRequired,
        identityMode: .verified,
        state: .verified,
        registryPeerID: "qlink_peer_123",
        registryContractFingerprint: "contract:fingerprint",
        source: "registry"
      )
    )

    let encoded = try JSONEncoder().encode(peer)
    let decoded = try JSONDecoder().decode(PeerStatus.self, from: encoded)

    XCTAssertEqual(decoded.dytallixTrust?.state, .verified)
    XCTAssertEqual(decoded.dytallixTrust?.policy, .publicRequired)
    XCTAssertEqual(decoded.dytallixTrust?.registryPeerID, "qlink_peer_123")
  }

  func testTrustSummaryCountsPeerTrustStates() {
    let checkedAt = Date(timeIntervalSince1970: 1_000)
    let laterCheck = Date(timeIntervalSince1970: 2_000)
    let peers = [
      peer("verified", state: .verified, checkedAt: checkedAt),
      peer("pending", state: .pending, checkedAt: laterCheck),
      peer("revoked", state: .revoked, checkedAt: checkedAt),
      peer("unverified", state: .unverified, checkedAt: checkedAt),
      peer("unknown", state: .unknown, checkedAt: nil),
    ]

    let summary = DytallixPeerTrustSummary(
      peers: peers,
      policy: .publicRequired,
      identityMode: .verified,
      registryConfigured: true
    )

    XCTAssertTrue(summary.required)
    XCTAssertEqual(summary.verifiedPeerCount, 1)
    XCTAssertEqual(summary.pendingPeerCount, 1)
    XCTAssertEqual(summary.unverifiedPeerCount, 2)
    XCTAssertEqual(summary.failedPeerCount, 1)
    XCTAssertEqual(summary.lastCheckedAt, laterCheck)
  }

  func testTrustSummaryCountsBlockedPeerWithNoAcceptedTraffic() {
    let checkedAt = Date(timeIntervalSince1970: 3_000)
    let blockedPeer = PeerStatus(
      identity: PeerIdentity(
        peerID: "qlink_blocked",
        alias: "blocked",
        publicKeyFingerprint: "fingerprint-blocked"
      ),
      pathType: .unavailable,
      endpoints: [],
      overlayAddress: "",
      rttMilliseconds: nil,
      lastRekey: nil,
      bytesIn: 0,
      bytesOut: 0,
      dytallixTrust: DytallixPeerTrustStatus(
        policy: .publicRequired,
        identityMode: .verified,
        state: .revoked,
        checkedAt: checkedAt,
        failureReason: "The peer's Dytallix registry record is revoked."
      )
    )

    let summary = DytallixPeerTrustSummary(
      peers: [blockedPeer],
      policy: .publicRequired,
      identityMode: .verified,
      registryConfigured: true
    )

    XCTAssertEqual(summary.verifiedPeerCount, 0)
    XCTAssertEqual(summary.failedPeerCount, 1)
    XCTAssertEqual(summary.lastCheckedAt, checkedAt)
  }

  func testRustFailureCodesMapToDistinctPeerTrustStates() {
    XCTAssertEqual(DytallixPeerTrustState(rustFailure: .registryRequired), .missingRegistryRecord)
    XCTAssertEqual(DytallixPeerTrustState(rustFailure: .registryRevoked), .revoked)
    XCTAssertEqual(DytallixPeerTrustState(rustFailure: .registrySuspended), .suspended)
    XCTAssertEqual(DytallixPeerTrustState(rustFailure: .registryExpired), .expired)
    XCTAssertEqual(DytallixPeerTrustState(rustFailure: .registryMismatch), .bindingMismatch)
    XCTAssertEqual(DytallixPeerTrustState(rustFailure: .registryLookupFailed), .lookupFailed)
    XCTAssertEqual(
      DytallixPeerTrustState(rustFailure: .registryVerificationFailed),
      .verificationFailed
    )
  }

  func testTrustSummaryCountsDistinctNegativeStatesAsFailed() {
    let peers = [
      peer("missing", state: .missingRegistryRecord, checkedAt: nil),
      peer("suspended", state: .suspended, checkedAt: nil),
      peer("mismatch", state: .bindingMismatch, checkedAt: nil),
      peer("lookup", state: .lookupFailed, checkedAt: nil),
      peer("verification", state: .verificationFailed, checkedAt: nil),
    ]

    let summary = DytallixPeerTrustSummary(
      peers: peers,
      policy: .publicRequired,
      identityMode: .verified,
      registryConfigured: true
    )

    XCTAssertEqual(summary.failedPeerCount, 5)
    XCTAssertEqual(summary.unverifiedPeerCount, 0)
  }

  func testRustBlockedPeerHistoryEntryDecodesSnakeCaseJSON() throws {
    let json = """
    [
      {
        "peer_id": "qlink_blocked",
        "direction": "outbound",
        "failure_code": 2,
        "failure_reason": "registry record is revoked",
        "observed_at_unix": 3000,
        "checked_at_unix": 2999
      }
    ]
    """.data(using: .utf8)!

    let entries = try JSONDecoder().decode([RustBlockedPeerHistoryEntry].self, from: json)

    XCTAssertEqual(entries.count, 1)
    XCTAssertEqual(entries[0].peerID, "qlink_blocked")
    XCTAssertEqual(entries[0].direction, "outbound")
    XCTAssertEqual(entries[0].failureCode, 2)
    XCTAssertEqual(entries[0].failureReason, "registry record is revoked")
    XCTAssertEqual(entries[0].observedAt, Date(timeIntervalSince1970: 3_000))
    XCTAssertEqual(entries[0].checkedAt, Date(timeIntervalSince1970: 2_999))
  }

  private func peer(
    _ id: String,
    state: DytallixPeerTrustState,
    checkedAt: Date?
  ) -> PeerStatus {
    PeerStatus(
      identity: PeerIdentity(
        peerID: "qlink_peer_\(id)",
        alias: id,
        publicKeyFingerprint: "fingerprint-\(id)"
      ),
      pathType: .direct,
      endpoints: [],
      overlayAddress: "100.127.0.2",
      rttMilliseconds: nil,
      lastRekey: nil,
      bytesIn: 0,
      bytesOut: 0,
      dytallixTrust: DytallixPeerTrustStatus(
        policy: .publicRequired,
        identityMode: .verified,
        state: state,
        checkedAt: checkedAt
      )
    )
  }
}
