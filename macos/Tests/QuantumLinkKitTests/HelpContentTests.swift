import XCTest

@testable import QuantumLinkKit

final class HelpContentTests: XCTestCase {
  func testMacOSKnowledgeBaseIncludesMacOSTopicsInOrder() {
    XCTAssertEqual(
      HelpKnowledgeBase.topics(for: .macOS).map(\.id),
      [
        .gettingStarted,
        .connectingPeers,
        .activityDiagnostics,
        .cryptography,
        .routingProfiles,
        .dytallixIdentityTrust,
        .mdmEnterprise,
        .privacySecurity,
        .troubleshooting,
        .supportTicket,
      ]
    )
  }

  func testMacOSHelpUsesMacOSSpecificLanguageOnly() {
    let text = HelpKnowledgeBase.searchableText(for: .macOS)
    XCTAssertTrue(text.contains("Network Extension"))
    XCTAssertTrue(text.contains("Keychain"))
    XCTAssertTrue(text.contains("MDM"))
    XCTAssertTrue(text.contains("Developer ID"))
    XCTAssertTrue(text.contains("notarization"))
    XCTAssertTrue(text.contains("Sparkle"))

    XCTAssertFalse(text.contains("Wintun"))
    XCTAssertFalse(text.contains("WFP"))
    XCTAssertFalse(text.contains("nftables"))
    XCTAssertFalse(text.contains("qlinkd"))
  }

  func testWindowsHelpUsesWindowsSpecificLanguageOnly() {
    let text = HelpKnowledgeBase.searchableText(for: .windows)
    XCTAssertTrue(text.contains("Windows service"))
    XCTAssertTrue(text.contains("Wintun"))
    XCTAssertTrue(text.contains("WFP"))
    XCTAssertTrue(text.contains("DPAPI"))
    XCTAssertTrue(text.contains("named-pipe IPC"))
    XCTAssertTrue(text.contains("WinUI"))
    XCTAssertTrue(text.contains("MSI"))
    XCTAssertTrue(text.contains("WiX"))
    XCTAssertTrue(text.contains("Event Viewer"))

    XCTAssertFalse(text.contains("Network Extension"))
    XCTAssertFalse(text.contains("Keychain"))
    XCTAssertFalse(text.contains("qlinkd"))
    XCTAssertFalse(text.contains("nftables"))
  }

  func testSteamOSHelpUsesSteamOSSpecificLanguageOnly() {
    let text = HelpKnowledgeBase.searchableText(for: .steamOS)
    XCTAssertTrue(text.contains("qlinkd"))
    XCTAssertTrue(text.contains("qlinkctl guide"))
    XCTAssertTrue(text.contains("qlinkctl status"))
    XCTAssertTrue(text.contains("qlinkctl doctor"))
    XCTAssertTrue(text.contains("systemd"))
    XCTAssertTrue(text.contains("dry-run planning"))
    XCTAssertTrue(text.contains("--activate-network"))
    XCTAssertTrue(text.contains("qlink0"))
    XCTAssertTrue(text.contains("nftables"))
    XCTAssertTrue(text.contains("Steam-safe traffic"))
    XCTAssertTrue(text.contains("game profile"))
    XCTAssertTrue(text.contains("Deck"))

    XCTAssertFalse(text.contains("Network Extension"))
    XCTAssertFalse(text.contains("Wintun"))
    XCTAssertFalse(text.contains("WinUI"))
    XCTAssertFalse(text.contains("Keychain"))
  }

  func testPlatformTopicLookupDoesNotLeakSteamOSIntoMacOS() {
    XCTAssertNil(HelpKnowledgeBase.topic(.steamOSGameRouting, for: .macOS))
    XCTAssertNotNil(HelpKnowledgeBase.topic(.steamOSGameRouting, for: .steamOS))
  }

  func testCryptographyTopicDoesNotMentionLegacyHybridFallback() throws {
    let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.cryptography, for: .macOS))
    let text = topic.searchableText.lowercased()
    XCTAssertFalse(text.contains("x25519"))
    XCTAssertFalse(text.contains("hybrid"))
    XCTAssertTrue(text.contains("ml-kem"))
    XCTAssertTrue(text.contains("ml-dsa"))
  }

  func testSupportTicketCategoriesAreExplicitAndSecurityRoutesToSecurityPolicy() throws {
    let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.supportTicket, for: .macOS))
    XCTAssertTrue(topic.searchableText.contains("Bug Report"))
    XCTAssertTrue(topic.searchableText.contains("Feature Request"))
    XCTAssertTrue(topic.searchableText.contains("Connection / Tunnel Issue"))
    XCTAssertTrue(topic.searchableText.contains("Security Concern"))
    XCTAssertTrue(topic.searchableText.contains("Billing / Entitlement"))
    XCTAssertTrue(topic.searchableText.contains("SECURITY.md"))
  }

  func testSteamOSHelpLabelsPreProductionState() throws {
    let topic = try XCTUnwrap(HelpKnowledgeBase.topic(.steamOSGameRouting, for: .steamOS))
    XCTAssertTrue(topic.platforms.contains(.steamOS))
    XCTAssertTrue(topic.searchableText.contains("pre-production"))
    XCTAssertTrue(topic.searchableText.contains("qlinkd"))
    XCTAssertTrue(topic.searchableText.contains("qlinkctl"))
  }
}
