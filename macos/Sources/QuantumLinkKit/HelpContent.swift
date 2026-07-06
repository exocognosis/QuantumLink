public enum HelpTopicID: String, CaseIterable, Equatable, Hashable, Sendable {
  case gettingStarted
  case connectingPeers
  case activityDiagnostics
  case cryptography
  case routingProfiles
  case dytallixIdentityTrust
  case mdmEnterprise
  case steamOSGameRouting
  case privacySecurity
  case troubleshooting
  case supportTicket
}

public enum HelpPlatform: String, CaseIterable, Equatable, Hashable, Sendable {
  case macOS
  case windows
  case steamOS
  case enterprise

  public var label: String {
    switch self {
    case .macOS:
      return "macOS"
    case .windows:
      return "Windows"
    case .steamOS:
      return "SteamOS"
    case .enterprise:
      return "Enterprise"
    }
  }
}

public struct HelpSection: Equatable, Sendable {
  public let title: String
  public let body: String
  public let bullets: [String]

  public init(title: String, body: String, bullets: [String] = []) {
    self.title = title
    self.body = body
    self.bullets = bullets
  }
}

public struct HelpTopic: Equatable, Sendable {
  public let id: HelpTopicID
  public let title: String
  public let summary: String
  public let platforms: [HelpPlatform]
  public let sections: [HelpSection]

  public init(
    id: HelpTopicID,
    title: String,
    summary: String,
    platforms: [HelpPlatform],
    sections: [HelpSection]
  ) {
    self.id = id
    self.title = title
    self.summary = summary
    self.platforms = platforms
    self.sections = sections
  }

  public var searchableText: String {
    ([title, summary]
      + sections.flatMap { section in
        [section.title, section.body] + section.bullets
      }).joined(separator: "\n")
  }
}

public enum HelpKnowledgeBase {
  public static let topics: [HelpTopic] = [
    HelpTopic(
      id: .gettingStarted,
      title: "Getting Started",
      summary:
        "Install QuantumLink, enroll identity, and confirm the local service is ready before connecting.",
      platforms: [.macOS, .windows, .steamOS],
      sections: [
        HelpSection(
          title: "First run",
          body:
            "Open the app or CLI, verify the service status, then complete Dytallix enrollment if the deployment requires identity-backed trust.",
          bullets: [
            "Confirm the local daemon or tunnel service is reachable.",
            "Import or create the device identity required by your deployment.",
            "Keep diagnostics redaction enabled before sharing support bundles.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .connectingPeers,
      title: "Connecting Peers",
      summary: "Use invites, peer trust records, and route state to connect approved devices.",
      platforms: [.macOS, .windows, .steamOS],
      sections: [
        HelpSection(
          title: "Peer setup",
          body:
            "Accept only expected invites, verify peer identity metadata, and confirm the tunnel reports an active path before relying on the connection.",
          bullets: [
            "Review invite source and expiration.",
            "Confirm peer trust status before routing sensitive traffic.",
            "Disconnect and export diagnostics if the path does not stabilize.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .activityDiagnostics,
      title: "Activity & Diagnostics",
      summary:
        "Inspect activity, tunnel readiness, and redacted support exports without exposing private wallet or route details.",
      platforms: [.macOS, .windows, .steamOS],
      sections: [
        HelpSection(
          title: "Diagnostic exports",
          body:
            "Support bundles should keep redaction enabled by default and include enough service state to debug tunnel, DNS, route, and policy failures.",
          bullets: [
            "Check recent connection phase changes.",
            "Include daemon status when reporting service failures.",
            "Review redaction output before attaching logs.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .cryptography,
      title: "Cryptography",
      summary:
        "QuantumLink uses post-quantum suites centered on ML-KEM for key establishment and ML-DSA for signatures.",
      platforms: [.macOS, .windows, .steamOS],
      sections: [
        HelpSection(
          title: "Current algorithms",
          body:
            "The supported cryptography surface describes ML-KEM, ML-DSA, and SLH-DSA. Older compatibility suite identifiers are rejected by policy and should not be presented as selectable options.",
          bullets: [
            "ML-KEM protects key establishment.",
            "ML-DSA protects signature workflows.",
            "SLH-DSA remains documented for stateless hash-based signature coverage.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .routingProfiles,
      title: "Routing & Profiles",
      summary:
        "Profiles describe which traffic QuantumLink should protect and how local route policy is applied.",
      platforms: [.macOS, .windows, .steamOS, .enterprise],
      sections: [
        HelpSection(
          title: "Route ownership",
          body:
            "The privileged service owns DNS, route, and kill-switch changes. The UI should display the active policy instead of applying privileged changes directly.",
          bullets: [
            "Use direct routes for explicit peer paths.",
            "Use managed profiles when policy is supplied by an administrator.",
            "Treat route drift as a diagnostics event.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .dytallixIdentityTrust,
      title: "Dytallix Identity & Trust",
      summary:
        "Dytallix identity anchors peer trust while keeping wallet details private unless explicitly disclosed.",
      platforms: [.macOS, .windows, .steamOS],
      sections: [
        HelpSection(
          title: "Identity handling",
          body:
            "Device trust is derived from shared qlink-core policy. Wallet addresses should remain hidden unless Public Wallet mode is intentionally enabled.",
          bullets: [
            "Verify enrollment before accepting sensitive routes.",
            "Use trust-source labels to explain how a peer was accepted.",
            "Avoid sending raw identity material in support messages.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .mdmEnterprise,
      title: "MDM & Enterprise",
      summary:
        "Managed deployments use administrator-supplied profiles, per-app VPN policy, and auditable signing requirements.",
      platforms: [.macOS, .enterprise],
      sections: [
        HelpSection(
          title: "Managed configuration",
          body:
            "Administrators can distribute policy through MDM profiles and should validate signing, entitlements, and per-app VPN scope before rollout.",
          bullets: [
            "Confirm bundle identifiers match production values.",
            "Review per-app VPN payload scope.",
            "Keep unsigned artifacts out of release channels.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .steamOSGameRouting,
      title: "SteamOS Game Routing",
      summary:
        "SteamOS support is a pre-production operator flow for qlinkd and qlinkctl, not a full graphical shell.",
      platforms: [.steamOS],
      sections: [
        HelpSection(
          title: "Operator guide",
          body:
            "Use qlinkd for daemon mode and qlinkctl for readiness, invite, peer, and diagnostics commands while the SteamOS experience remains pre-production.",
          bullets: [
            "Start qlinkd before validating route readiness.",
            "Use qlinkctl to inspect peers and connection state.",
            "Treat game-routing policy as pre-production until release gates are complete.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .privacySecurity,
      title: "Privacy & Security",
      summary:
        "Privacy defaults minimize exposed identity details and keep diagnostics redacted unless the operator changes policy.",
      platforms: [.macOS, .windows, .steamOS, .enterprise],
      sections: [
        HelpSection(
          title: "Safe sharing",
          body:
            "Support and security workflows should avoid raw secrets, private wallet data, unredacted routes, and local account details.",
          bullets: [
            "Leave diagnostics redaction enabled.",
            "Send vulnerability reports through SECURITY.md.",
            "Confirm public identity settings before screen sharing.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .troubleshooting,
      title: "Troubleshooting",
      summary:
        "Start with service readiness, route policy, peer trust, and diagnostics export checks.",
      platforms: [.macOS, .windows, .steamOS],
      sections: [
        HelpSection(
          title: "Connection triage",
          body:
            "Most connection failures can be narrowed by checking service reachability, peer trust, route state, DNS policy, and recent daemon errors.",
          bullets: [
            "Restart the local service only after exporting useful diagnostics.",
            "Check whether managed policy is overriding local settings.",
            "Attach redacted support bundles to bug reports.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .supportTicket,
      title: "Support Ticket",
      summary: "Choose a specific support category and route security reports to SECURITY.md.",
      platforms: [.macOS, .windows, .steamOS, .enterprise],
      sections: [
        HelpSection(
          title: "Categories",
          body:
            "Use Bug Report, Feature Request, Connection / Tunnel Issue, Security Concern, or Billing / Entitlement so support can route the request correctly.",
          bullets: [
            "Bug Report",
            "Feature Request",
            "Connection / Tunnel Issue",
            "Security Concern",
            "Billing / Entitlement",
            "Security vulnerabilities and sensitive reports should follow SECURITY.md.",
          ]
        )
      ]
    ),
  ]

  public static func topic(_ id: HelpTopicID) -> HelpTopic? {
    topics.first { $0.id == id }
  }
}
