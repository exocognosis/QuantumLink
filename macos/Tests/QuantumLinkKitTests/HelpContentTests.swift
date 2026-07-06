import XCTest

@testable import QuantumLinkKit

final class HelpContentTests: XCTestCase {
  func testKnowledgeBaseIncludesRequiredTopicsInOrder() {
    XCTAssertEqual(
      HelpKnowledgeBase.topics.map(\.id),
      [
        .gettingStarted,
        .connectingPeers,
        .activityDiagnostics,
        .cryptography,
        .routingProfiles,
        .dytallixIdentityTrust,
        .mdmEnterprise,
        .steamOSGameRouting,
        .privacySecurity,
        .troubleshooting,
        .supportTicket,
      ]
    )
  }

  func testCryptographyTopicDoesNotMentionLegacyHybridFallback() throws {
    let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.cryptography))
    let text = topic.searchableText.lowercased()
    XCTAssertFalse(text.contains("x25519"))
    XCTAssertFalse(text.contains("hybrid"))
    XCTAssertTrue(text.contains("ml-kem"))
    XCTAssertTrue(text.contains("ml-dsa"))
  }

  func testSupportTicketCategoriesAreExplicitAndSecurityRoutesToSecurityPolicy() throws {
    let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.supportTicket))
    XCTAssertTrue(topic.searchableText.contains("Bug Report"))
    XCTAssertTrue(topic.searchableText.contains("Feature Request"))
    XCTAssertTrue(topic.searchableText.contains("Connection / Tunnel Issue"))
    XCTAssertTrue(topic.searchableText.contains("Security Concern"))
    XCTAssertTrue(topic.searchableText.contains("Billing / Entitlement"))
    XCTAssertTrue(topic.searchableText.contains("SECURITY.md"))
  }

  func testSteamOSHelpLabelsPreProductionState() throws {
    let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.steamOSGameRouting))
    XCTAssertTrue(topic.platforms.contains(.steamOS))
    XCTAssertTrue(topic.searchableText.contains("pre-production"))
    XCTAssertTrue(topic.searchableText.contains("qlinkd"))
    XCTAssertTrue(topic.searchableText.contains("qlinkctl"))
  }
}
