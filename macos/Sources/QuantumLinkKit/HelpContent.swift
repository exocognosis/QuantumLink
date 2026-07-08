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
  public static var topics: [HelpTopic] {
    topics(for: .macOS)
  }

  public static func topics(for platform: HelpPlatform) -> [HelpTopic] {
    switch platform {
    case .macOS:
      return macOSTopics
    case .windows:
      return windowsTopics
    case .steamOS:
      return steamOSTopics
    case .enterprise:
      return enterpriseTopics
    }
  }

  public static func topic(_ id: HelpTopicID, for platform: HelpPlatform = .macOS) -> HelpTopic? {
    topics(for: platform).first { $0.id == id }
  }

  public static func searchableText(for platform: HelpPlatform) -> String {
    topics(for: platform).map(\.searchableText).joined(separator: "\n\n")
  }

  private static let macOSTopics: [HelpTopic] = [
    HelpTopic(
      id: .gettingStarted,
      title: "macOS First Run",
      summary:
        "Install QuantumLink for macOS, allow the Network Extension packet tunnel, and confirm the SwiftUI app can reach the tunnel controller.",
      platforms: [.macOS],
      sections: [
        HelpSection(
          title: "Network Extension setup",
          body:
            "The macOS app uses an NEPacketTunnelProvider-based Network Extension. The first run should confirm tunnel permission, Keychain-backed device identity, and Dytallix registry enrollment when the mesh requires public trust.",
          bullets: [
            "Approve the Network Extension prompt before connecting.",
            "Keep device identity and local secrets in Keychain-backed storage.",
            "Use the Onboarding and Configuration panels to confirm Dytallix endpoint, contract, wallet name, and registry status.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .connectingPeers,
      title: "macOS Connections",
      summary:
        "Start protected sessions from the SwiftUI Home or Connections panel after verifying peer identity and protected route policy.",
      platforms: [.macOS],
      sections: [
        HelpSection(
          title: "Connection launcher",
          body:
            "Use the macOS connection launcher for SSH or direct peer sessions. The app displays current phase, direct versus relay path, overlay address, and protected routes reported by the tunnel controller.",
          bullets: [
            "Verify destination IP and port before connecting.",
            "Confirm peer trust state before routing sensitive traffic.",
            "Disconnect from the SwiftUI app before changing identity or route defaults.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .activityDiagnostics,
      title: "macOS Activity & Diagnostics",
      summary:
        "Use the Activity and Diagnostics panels to inspect tunnel phase, path type, traffic counters, and redacted support bundle output.",
      platforms: [.macOS],
      sections: [
        HelpSection(
          title: "Support bundles",
          body:
            "macOS support bundles should preserve diagnostics redaction by default. Raw peer IDs, wallet addresses, routes, DNS data, endpoint candidates, and packet captures require an explicit elevated export path.",
          bullets: [
            "Check Activity for recent session transitions and tunnel phase changes.",
            "Use Diagnostics for redacted route, DNS, identity, and packet-pump status.",
            "Review support bundle output before attaching it to a ticket.",
          ]
        )
      ]
    ),
    sharedCryptographyTopic(platform: .macOS),
    HelpTopic(
      id: .routingProfiles,
      title: "macOS Routing & DNS",
      summary:
        "Review protected routes, DNS tunnel mode, and fail-closed behavior owned by the Network Extension lifecycle.",
      platforms: [.macOS],
      sections: [
        HelpSection(
          title: "Packet tunnel policy",
          body:
            "The macOS product should not depend on kernel extensions, custom kernel drivers, or a pf-based core security model. Protected-route fail-closed behavior belongs in the Network Extension packet tunnel and managed policy.",
          bullets: [
            "Use Configuration to inspect protected routes and excluded routes.",
            "Use managed configuration when route policy is supplied by MDM.",
            "Treat route drift, DNS drift, or packet tunnel failure as a Diagnostics event.",
          ]
        )
      ]
    ),
    sharedDytallixTopic(platform: .macOS),
    HelpTopic(
      id: .mdmEnterprise,
      title: "macOS MDM & Release",
      summary:
        "Managed macOS deployments use MDM payloads, Developer ID signing, notarization, and Sparkle-style direct updates where appropriate.",
      platforms: [.macOS, .enterprise],
      sections: [
        HelpSection(
          title: "Managed configuration",
          body:
            "Administrators should validate MDM payload scope, bundle identifiers, Network Extension entitlements, Developer ID signing, notarization, and Sparkle update metadata before rollout.",
          bullets: [
            "Confirm per-app VPN and managed route payloads match the production bundle ID.",
            "Keep unsigned or ad-hoc builds out of release channels.",
            "Use the release readiness scripts before distributing Developer ID artifacts.",
          ]
        )
      ]
    ),
    sharedPrivacyTopic(platform: .macOS),
    HelpTopic(
      id: .troubleshooting,
      title: "macOS Troubleshooting",
      summary:
        "Start with Network Extension permission, Keychain identity, packet tunnel status, route policy, DNS mode, and redacted diagnostics.",
      platforms: [.macOS],
      sections: [
        HelpSection(
          title: "Connection triage",
          body:
            "Most macOS failures can be narrowed by checking Network Extension permission, Keychain identity availability, Dytallix registry state, route mode, DNS mode, and recent tunnel errors.",
          bullets: [
            "Re-open the app after changing Network Extension permission.",
            "Re-enroll identity only after checking existing registry status.",
            "Export a redacted support bundle before deleting local state.",
          ]
        )
      ]
    ),
    sharedSupportTopic(platform: .macOS),
  ]

  private static let windowsTopics: [HelpTopic] = [
    HelpTopic(
      id: .gettingStarted,
      title: "Windows Service Setup",
      summary:
        "Install the MSI, start the QuantumLink Windows service, and let the WinUI dashboard communicate over named-pipe IPC.",
      platforms: [.windows],
      sections: [
        HelpSection(
          title: "Service boundary",
          body:
            "Windows networking is owned by the privileged QuantumLink Windows service. The WinUI dashboard should request connect, disconnect, status, and diagnostics actions over named-pipe IPC instead of applying network changes directly.",
          bullets: [
            "Confirm the Windows service is installed and running.",
            "Use admin privileges for service install, Wintun adapter setup, and WFP kill-switch policy.",
            "Use MSI or WiX install logs when setup fails.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .connectingPeers,
      title: "Windows Connections",
      summary:
        "Connect through the LocalSystem service after Wintun, WFP, DPAPI, and named-pipe IPC are ready.",
      platforms: [.windows],
      sections: [
        HelpSection(
          title: "Tunnel control",
          body:
            "The dashboard sends connect and disconnect requests to the service. The service owns Wintun interface state, WFP kill switch state, protected routes, and persisted configuration.",
          bullets: [
            "Verify service status before pressing Connect.",
            "Confirm the Wintun adapter and WFP policy are reported by service status.",
            "Use Disconnect before changing persisted route or identity configuration.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .activityDiagnostics,
      title: "Windows Diagnostics",
      summary:
        "Use the WinUI dashboard, Windows service status, Event Viewer, and redacted diagnostics export to inspect Windows tunnel behavior.",
      platforms: [.windows],
      sections: [
        HelpSection(
          title: "Diagnostic export",
          body:
            "Diagnostics should describe Windows service state, Wintun adapter state, WFP policy, named-pipe IPC reachability, protected routes, and peer status without leaking raw identity or endpoint material.",
          bullets: [
            "Use Event Viewer for service install, startup, and runtime errors.",
            "Export redacted diagnostics from the dashboard before restarting the service.",
            "Keep raw wallet, peer, route, DNS, and packet data out of tickets.",
          ]
        )
      ]
    ),
    sharedCryptographyTopic(platform: .windows),
    HelpTopic(
      id: .routingProfiles,
      title: "Windows Routing & Kill Switch",
      summary:
        "Inspect route mode, protected prefixes, Wintun state, and WFP kill-switch enforcement owned by the Windows service.",
      platforms: [.windows],
      sections: [
        HelpSection(
          title: "Service-owned policy",
          body:
            "The unprivileged WinUI dashboard displays policy. The privileged service applies Wintun, route, DNS, and WFP kill-switch changes and stores local secrets with DPAPI where appropriate.",
          bullets: [
            "Treat WFP policy drift as a service diagnostics event.",
            "Use DPAPI-backed storage for Windows-local secrets.",
            "Validate route and kill-switch behavior inside Windows before release.",
          ]
        )
      ]
    ),
    sharedDytallixTopic(platform: .windows),
    sharedPrivacyTopic(platform: .windows),
    HelpTopic(
      id: .troubleshooting,
      title: "Windows Troubleshooting",
      summary:
        "Start with service installation, named-pipe IPC, Wintun adapter state, WFP policy, Event Viewer, and diagnostics export.",
      platforms: [.windows],
      sections: [
        HelpSection(
          title: "Connection triage",
          body:
            "Most Windows failures can be narrowed by checking whether the service is running, the named-pipe IPC channel is reachable, Wintun is present, WFP policy applied, and the dashboard can export diagnostics.",
          bullets: [
            "Repair or reinstall the MSI before editing service files manually.",
            "Check Event Viewer before restarting the Windows service.",
            "Attach redacted dashboard diagnostics to bug reports.",
          ]
        )
      ]
    ),
    sharedSupportTopic(platform: .windows),
  ]

  private static let steamOSTopics: [HelpTopic] = [
    HelpTopic(
      id: .gettingStarted,
      title: "SteamOS Runtime Setup",
      summary:
        "Install qlinkd and qlinkctl, edit /etc/quantumlink/config.json, and start the qlinkd systemd service in dry-run planning mode.",
      platforms: [.steamOS],
      sections: [
        HelpSection(
          title: "Operator setup",
          body:
            "SteamOS uses a Linux daemon and CLI surface. Start with qlinkctl guide, qlinkctl status, and qlinkctl doctor before enabling live network mutation with --activate-network.",
          bullets: [
            "Install qlinkd and qlinkctl from the SteamOS package or repository build output.",
            "Use systemd to start the qlinkd service.",
            "Keep support bundles redacted before sharing logs outside the Deck.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .connectingPeers,
      title: "SteamOS Peer Commands",
      summary:
        "Use qlinkctl invite and peer commands to inspect, import, trust, revoke, or remove peers before routing game traffic.",
      platforms: [.steamOS],
      sections: [
        HelpSection(
          title: "CLI peer flow",
          body:
            "SteamOS peer operations are explicit CLI actions. Use qlinkctl invite decode before storing an invite, qlinkctl invite import to persist it, and qlinkctl peer trust to inspect mesh and Dytallix requirements.",
          bullets: [
            "Run qlinkctl status before changing peer state.",
            "Run qlinkctl doctor after importing a peer.",
            "Use qlinkctl peer revoke or qlinkctl peer remove when a peer should no longer be trusted.",
          ]
        )
      ]
    ),
    HelpTopic(
      id: .activityDiagnostics,
      title: "SteamOS Doctor & Support",
      summary:
        "Use qlinkctl doctor and qlinkctl support-bundle --output to inspect daemon readiness, packet I/O, transport readiness, and redacted status.",
      platforms: [.steamOS],
      sections: [
        HelpSection(
          title: "Operator diagnostics",
          body:
            "qlinkctl doctor reports daemon phase, network ownership, packet I/O, data-plane health, and whether transport ready is yes or no. support-bundle exports redacted daemon status and doctor output.",
          bullets: [
            "Use qlinkctl doctor before activating live networking.",
            "Use qlinkctl support-bundle --output <path> for bug reports.",
            "Do not paste raw packet payloads, wallet seeds, tokens, or unredacted routes into tickets.",
          ]
        )
      ]
    ),
    sharedCryptographyTopic(platform: .steamOS),
    HelpTopic(
      id: .routingProfiles,
      title: "Steam-Safe Routing",
      summary:
        "Protect selected game or party traffic while keeping Steam account, store, wallet, launcher, marketplace, and embedded browser traffic off the VPN by default.",
      platforms: [.steamOS],
      sections: [
        HelpSection(
          title: "Game profile routing",
          body:
            "SteamOS routing is game profile oriented. dry-run planning reports the intended qlink0 TUN, overlay routes, and nftables plan without mutating networking; --activate-network is the explicit opt-in for live TUN, route, and nftables application.",
          bullets: [
            "Keep the default route off QuantumLink unless a profile explicitly requires it.",
            "Validate Steam-safe traffic bypass before broad use.",
            "Treat LAN discovery, voice chat, launch options, and anti-cheat behavior as per-title validation gates.",
          ]
        )
      ]
    ),
    sharedDytallixTopic(platform: .steamOS),
    HelpTopic(
      id: .steamOSGameRouting,
      title: "Deck Validation",
      summary:
        "SteamOS remains pre-production until real Deck validation, production-signed artifacts, public Dytallix evidence, and game compatibility gates pass.",
      platforms: [.steamOS],
      sections: [
        HelpSection(
          title: "Pre-production boundary",
          body:
            "Local dry-run planning, qlink0 packet I/O initialization, or transport ready: no status is not proof of protected peer traffic. Real readiness requires a two-Deck or equivalent SteamOS/Linux validation path.",
          bullets: [
            "Validate qlinkd under systemd on the target host.",
            "Validate nftables ownership and teardown behavior after --activate-network.",
            "Validate real peer transport and selected game profile behavior before release claims.",
          ]
        )
      ]
    ),
    sharedPrivacyTopic(platform: .steamOS),
    HelpTopic(
      id: .troubleshooting,
      title: "SteamOS Troubleshooting",
      summary:
        "Start with qlinkd service state, qlinkctl status, qlinkctl doctor, systemd logs, qlink0 ownership, nftables rules, and game profile configuration.",
      platforms: [.steamOS],
      sections: [
        HelpSection(
          title: "Daemon triage",
          body:
            "Most SteamOS failures can be narrowed by checking qlinkd under systemd, config validation, dry-run planning output, qlink0 packet I/O, nftables ownership, and peer trust status.",
          bullets: [
            "Use journalctl for qlinkd service errors.",
            "Return to dry-run planning mode before editing config.",
            "Export a redacted support bundle before reinstalling the SteamOS package.",
          ]
        )
      ]
    ),
    sharedSupportTopic(platform: .steamOS),
  ]

  private static let enterpriseTopics: [HelpTopic] = [
    macOSTopics.first { $0.id == .mdmEnterprise }!,
    HelpTopic(
      id: .routingProfiles,
      title: "Enterprise Policy",
      summary:
        "Enterprise deployments should treat route, DNS, identity, entitlement, and diagnostics policy as administrator-owned configuration.",
      platforms: [.enterprise],
      sections: [
        HelpSection(
          title: "Administrator scope",
          body:
            "Use managed profiles and release validation to keep local users from bypassing identity, route, kill-switch, or support-export policy.",
          bullets: [
            "Validate entitlement and registry requirements before rollout.",
            "Keep support exports redacted unless an elevated raw export is explicitly approved.",
            "Keep production signing material outside the public repository.",
          ]
        )
      ]
    ),
    sharedPrivacyTopic(platform: .enterprise),
    sharedSupportTopic(platform: .enterprise),
  ]

  private static func sharedCryptographyTopic(platform: HelpPlatform) -> HelpTopic {
    HelpTopic(
      id: .cryptography,
      title: "\(platform.label) Cryptography",
      summary:
        "QuantumLink uses post-quantum suites centered on ML-KEM for key establishment and ML-DSA for signatures.",
      platforms: [platform],
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
    )
  }

  private static func sharedDytallixTopic(platform: HelpPlatform) -> HelpTopic {
    HelpTopic(
      id: .dytallixIdentityTrust,
      title: "\(platform.label) Dytallix Identity & Trust",
      summary:
        "Dytallix identity anchors peer trust while keeping wallet details private unless Public Wallet mode is explicitly enabled.",
      platforms: [platform],
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
    )
  }

  private static func sharedPrivacyTopic(platform: HelpPlatform) -> HelpTopic {
    HelpTopic(
      id: .privacySecurity,
      title: "\(platform.label) Privacy & Security",
      summary:
        "Privacy defaults minimize exposed identity details and keep diagnostics redacted unless the operator changes policy.",
      platforms: [platform],
      sections: [
        HelpSection(
          title: "Safe sharing",
          body:
            "Support and security workflows should avoid raw secrets, private wallet data, unredacted routes, local account details, and raw packet data.",
          bullets: [
            "Leave diagnostics redaction enabled.",
            "Send vulnerability reports through SECURITY.md.",
            "Confirm public identity settings before screen sharing.",
          ]
        )
      ]
    )
  }

  private static func sharedSupportTopic(platform: HelpPlatform) -> HelpTopic {
    HelpTopic(
      id: .supportTicket,
      title: "\(platform.label) Support Ticket",
      summary: "Choose a specific support category and route security reports to SECURITY.md.",
      platforms: [platform],
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
    )
  }
}
