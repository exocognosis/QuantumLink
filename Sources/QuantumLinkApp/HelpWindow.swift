import AppKit
import QuantumLinkKit
import SwiftUI

// MARK: - Help topics

/// Catalog of every section the in-app Help window exposes. Adding a
/// new entry here is enough to surface it in the sidebar; the matching
/// `HelpContentView` switch handles rendering.
enum HelpTopic: String, CaseIterable, Identifiable, Hashable {
    case gettingStarted
    case connectingPeers
    case activityDiagnostics
    case cryptography
    case routingProfiles
    case mdmEnterprise
    case privacySecurity
    case troubleshooting
    case submitTicket

    var id: String { rawValue }

    var title: String {
        switch self {
        case .gettingStarted: return "Getting Started"
        case .connectingPeers: return "Connecting Peers"
        case .activityDiagnostics: return "Activity & Diagnostics"
        case .cryptography: return "Cryptography"
        case .routingProfiles: return "Routing & Profiles"
        case .mdmEnterprise: return "MDM & Enterprise"
        case .privacySecurity: return "Privacy & Security"
        case .troubleshooting: return "Troubleshooting"
        case .submitTicket: return "Submit a Support Ticket"
        }
    }

    var systemImage: String {
        switch self {
        case .gettingStarted: return "sparkles"
        case .connectingPeers: return "point.3.connected.trianglepath.dotted"
        case .activityDiagnostics: return "waveform.path.ecg"
        case .cryptography: return "lock.shield"
        case .routingProfiles: return "arrow.triangle.branch"
        case .mdmEnterprise: return "building.2"
        case .privacySecurity: return "hand.raised"
        case .troubleshooting: return "wrench.and.screwdriver"
        case .submitTicket: return "envelope.badge"
        }
    }

    var subtitle: String {
        switch self {
        case .gettingStarted:
            return "First-launch checklist and the QuantumLink mental model"
        case .connectingPeers:
            return "Adding peers, verifying identity, and on-demand activation"
        case .activityDiagnostics:
            return "What each panel shows and how to read transport health"
        case .cryptography:
            return "Hybrid post-quantum key exchange, signatures, and rotation"
        case .routingProfiles:
            return "Split tunnel, full tunnel, deployment modes, per-app VPN"
        case .mdmEnterprise:
            return "Managed configuration, kill switch postures, profile templates"
        case .privacySecurity:
            return "What's encrypted, what's logged, and how diagnostics are scrubbed"
        case .troubleshooting:
            return "Symptom → diagnosis → fix for the issues most users hit"
        case .submitTicket:
            return "Email a ticket to help@quantumlinkvpn.com with diagnostic context"
        }
    }
}

// MARK: - Window scene

/// Top-level Scene for the Help window. Registered alongside the main
/// `WindowGroup` in `QuantumLinkMacApp` and invoked via the Help menu.
struct HelpWindowScene: Scene {
    var body: some Scene {
        Window("QuantumLink Help", id: HelpWindowScene.windowID) {
            HelpView()
                .frame(minWidth: 820, minHeight: 560)
        }
        .windowResizability(.contentMinSize)
    }

    static let windowID = "quantumlink.help"
}

// MARK: - Root help view

struct HelpView: View {
    @State private var selection: HelpTopic? = .gettingStarted

    var body: some View {
        NavigationSplitView {
            List(HelpTopic.allCases, selection: $selection) { topic in
                NavigationLink(value: topic) {
                    Label(topic.title, systemImage: topic.systemImage)
                }
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 240)
            .navigationTitle("Help")
        } detail: {
            if let topic = selection {
                HelpContentView(topic: topic)
            } else {
                ContentUnavailableView(
                    "Choose a topic",
                    systemImage: "book.closed",
                    description: Text("Select a section in the sidebar to read about it.")
                )
            }
        }
    }
}

// MARK: - Content router

private struct HelpContentView: View {
    let topic: HelpTopic

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HelpSectionHeader(topic: topic)

                Group {
                    switch topic {
                    case .gettingStarted: GettingStartedSection()
                    case .connectingPeers: ConnectingPeersSection()
                    case .activityDiagnostics: ActivitySection()
                    case .cryptography: CryptographySection()
                    case .routingProfiles: RoutingSection()
                    case .mdmEnterprise: MDMSection()
                    case .privacySecurity: PrivacySection()
                    case .troubleshooting: TroubleshootingSection()
                    case .submitTicket: SubmitTicketSection()
                    }
                }

                if topic != .submitTicket {
                    Divider().padding(.top, 12)
                    SupportFooter()
                }
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }
}

private struct HelpSectionHeader: View {
    let topic: HelpTopic

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: topic.systemImage)
                .font(.title2)
                .foregroundStyle(.tint)
                .frame(width: 28, height: 28, alignment: .center)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(topic.title)
                    .font(.title2.weight(.semibold))
                Text(topic.subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
        }
    }
}

// MARK: - Reusable building blocks

private struct HelpQA: View {
    let question: String
    let answer: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(question)
                .font(.headline)
            Text(answer)
                .font(.body)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct HelpStep: View {
    let number: Int
    let title: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.callout.weight(.semibold).monospacedDigit())
                .frame(width: 22, height: 22)
                .background(.tint.opacity(0.18), in: Circle())
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.callout.weight(.semibold))
                Text(text)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct HelpCallout: View {
    enum Tone { case info, warning }
    let tone: Tone
    let title: String
    let text: String

    private var icon: String {
        switch tone {
        case .info: return "info.circle"
        case .warning: return "exclamationmark.triangle"
        }
    }

    private var tint: Color {
        switch tone {
        case .info: return .accentColor
        case .warning: return .orange
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(tint)
                .font(.callout)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.callout.weight(.semibold))
                Text(text)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

private struct SupportFooter: View {
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "envelope.badge")
                .font(.title3)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 4) {
                Text("Still stuck?")
                    .font(.callout.weight(.semibold))
                Text("Open the Submit a Support Ticket section to email help@quantumlinkvpn.com with diagnostic context auto-attached.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .background(Color.accentColor.opacity(0.06),
                    in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

// MARK: - Section content

private struct GettingStartedSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("QuantumLink is a peer-to-peer mesh VPN with post-quantum cryptography. Each device on the mesh holds its own keypair and talks directly to other devices on the same mesh ID — there's no central server proxying your traffic.")
                .fixedSize(horizontal: false, vertical: true)

            HelpStep(number: 1,
                     title: "Set your mesh ID",
                     text: "Configuration → Mesh ID. Devices that share a mesh ID can find each other; devices with different IDs are completely isolated. Pick something unique to you (e.g. 'rick-home').")

            HelpStep(number: 2,
                     title: "Generate your device keypair",
                     text: "First launch creates a hybrid X25519 + ML-KEM-768 keypair backed by the macOS Keychain and a Secure Enclave trust key. You don't need to manage these manually.")

            HelpStep(number: 3,
                     title: "Add at least one peer",
                     text: "Connections panel → Add Peer. You'll need the peer's public-key fingerprint (a short base32 string they share with you out-of-band).")

            HelpStep(number: 4,
                     title: "Start the tunnel",
                     text: "Tunnel → Connect (⌘K). Once connected, the Activity panel shows a heartbeat from each peer.")

            HelpCallout(tone: .info,
                        title: "Local builds run with limits",
                        text: "An ad-hoc-signed build (the kind you double-clicked into) cannot attach to the macOS packet tunnel without an Apple Developer Network Extension entitlement. The UI runs end-to-end against the Rust core and the smoke transports work; real packet flow needs a signed Developer-ID build.")
        }
    }
}

private struct ConnectingPeersSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HelpQA(
                question: "How do I add a peer?",
                answer: "Open the Connections panel and click Add Peer. Enter the peer's display name and their public-key fingerprint (the short base32 string from their Configuration panel). Once added, the peer appears in the Peers list and a handshake is attempted on the next refresh."
            )

            HelpQA(
                question: "What's a public-key fingerprint?",
                answer: "It's a short, human-readable summary of a peer's hybrid public key (X25519 + ML-KEM-768 concatenated and hashed). Verifying fingerprints out-of-band — read them aloud, send via Signal, swap on paper — defeats man-in-the-middle attempts at first contact."
            )

            HelpQA(
                question: "Can I trust a peer without verifying?",
                answer: "You can, but you shouldn't. The first contact is the only moment a network attacker can substitute their key. After verification, ML-DSA-65 signatures lock in the identity for every subsequent handshake."
            )

            HelpQA(
                question: "What if a peer rotates their key?",
                answer: "Rotation produces a new fingerprint. The new fingerprint must be re-verified — by design. You'll see a 'fingerprint changed' warning in the Activity panel on the next handshake; ignore at your own risk."
            )

            HelpQA(
                question: "On-demand rules — what are they?",
                answer: "Rules that auto-connect or auto-disconnect the tunnel based on network conditions: SSID match, DNS suffix, interface type (cellular vs Wi-Fi), or a captive-portal probe URL. Configure them under Routes → On-Demand."
            )
        }
    }
}

private struct ActivitySection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HelpQA(
                question: "Home panel",
                answer: "At-a-glance status: tunnel state, mesh ID, peer count, and the last few session events. Click any tile to drill into the relevant panel."
            )

            HelpQA(
                question: "Connections panel",
                answer: "Lists every connection profile, both saved and recent. The Quick Connect form on the right composes a one-shot tunnel session without saving."
            )

            HelpQA(
                question: "Activity panel",
                answer: "Live session timeline + transport heartbeat. Each peer shows last-seen, RTT, and packets in/out. Red badges mean the transport is unhealthy and the kill switch (if enabled) is about to engage."
            )

            HelpQA(
                question: "Network / Peers / Routes / Security / Diagnostics",
                answer: "The detail tabs under the Configuration sidebar group. Network shows the overlay IP plan; Peers manages the trust roster; Routes covers split-tunnel CIDRs and on-demand rules; Security exposes PQC settings + key rotation; Diagnostics runs transport smoke tests and exports support bundles."
            )

            HelpCallout(tone: .info,
                        title: "Smoke tests are your friend",
                        text: "Diagnostics → Run Smoke Test exercises every transport in isolation (loopback, ICE, QUIC) and reports per-transport latency. If your tunnel works but feels slow, smoke tests pinpoint which leg of the path is the bottleneck.")
        }
    }
}

private struct CryptographySection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("QuantumLink uses a hybrid post-quantum design: classical curves for proven hardness today, lattice-based KEM/signatures for resistance against a future cryptographically-relevant quantum computer. Both halves must succeed for a session to establish — neither half can authorize traffic alone.")
                .fixedSize(horizontal: false, vertical: true)

            HelpQA(
                question: "Key exchange",
                answer: "Hybrid X25519 + ML-KEM-768 (FIPS 203). Each handshake derives a session key by concatenating the X25519 shared secret with the ML-KEM ciphertext output and feeding the pair into HKDF-SHA-256."
            )

            HelpQA(
                question: "Signatures",
                answer: "ML-DSA-65 (FIPS 204) for peer identity and configuration profile signatures. The Secure Enclave trust key cross-signs the device public key on first launch so a stolen Keychain entry alone can't impersonate the device."
            )

            HelpQA(
                question: "Symmetric layer",
                answer: "ChaCha20-Poly1305 AEAD per-packet, with per-session keys rotated on a 64 MiB or 5-minute counter (whichever fires first). Replay protection uses a sliding-window sequence counter."
            )

            HelpQA(
                question: "Key rotation",
                answer: "Configuration → Security → Rotate Device Key. Rotation produces a new fingerprint that peers must re-verify. The old key remains valid for one grace handshake to avoid bricking your sessions during the swap."
            )

            HelpCallout(tone: .warning,
                        title: "Rotation does not erase past exposure",
                        text: "If a session key was recorded by an attacker before rotation, that captured traffic remains decryptable with that captured key. Rotation prevents future capture from being decryptable; it does not retroactively re-encrypt past traffic.")
        }
    }
}

private struct RoutingSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HelpQA(
                question: "Split tunnel vs full tunnel",
                answer: "Split tunnel routes only specific CIDRs through the mesh; everything else uses your default network. Full tunnel routes ALL traffic through the mesh. Configure under Routes → Mode."
            )

            HelpQA(
                question: "Deployment modes",
                answer: "Mesh: every device talks to every other device peer-to-peer. Hub-and-spoke: spokes only talk to a designated hub; useful for centralized auditing. Pick under Configuration → Deployment Mode."
            )

            HelpQA(
                question: "Per-app VPN",
                answer: "Managed Macs only. A managed deployment can map specific managed apps to the mesh while leaving everything else on the default network. See the MDM section."
            )

            HelpQA(
                question: "On-demand rules",
                answer: "Rules evaluate top-to-bottom; the first match wins. SSIDMatch, DNSDomainMatch, DNSServerAddressMatch, InterfaceTypeMatch, and URLStringProbe are the predicates supported. End with a catch-all Connect or Ignore depending on your default posture."
            )
        }
    }
}

private struct MDMSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("QuantumLink ships .mobileconfig templates for managed deployments. Operators fill in placeholders, sign with their MDM identity, and push the resulting profile through their MDM server.")
                .fixedSize(horizontal: false, vertical: true)

            HelpQA(
                question: "Where are the templates?",
                answer: "macos/mdm/ in the source tree, or generated on-demand via swift run QuantumLinkMDM. Templates cover system-extension pre-approval, per-app VPN, default tunnel, on-demand exemplar, and strict kill-switch postures."
            )

            HelpQA(
                question: "Kill-switch postures",
                answer: "Lenient: drop protected packets when the transport is unhealthy, but keep the tunnel alive. Strict: a runtime watchdog tears the tunnel down after sustained unreadiness — combined with PayloadRemovalDisallowed=true and always-on on-demand, this is the maximum-enforcement posture."
            )

            HelpQA(
                question: "What's the VendorConfig block?",
                answer: "Custom payload that the Swift app reads at launch: rendezvous + relay servers, mesh ID, kill-switch policy, route mode. Lets MDM admins pin the production endpoints without touching app source."
            )

            HelpCallout(tone: .info,
                        title: "Pre-approval first",
                        text: "Without a system-extension pre-approval profile, every managed Mac will prompt the user to approve QuantumLink's network extension on first install. Ship the pre-approval profile before the others.")
        }
    }
}

private struct PrivacySection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HelpQA(
                question: "What's encrypted on disk?",
                answer: "Device private keys live in the macOS Keychain (hardware-bound). The peer roster (PeerStore) is encrypted with ChaCha20-Poly1305 using a key derived from the Secure Enclave trust key. Recent connection profiles in app-storage are NOT encrypted — they're treated as user preferences, not secrets."
            )

            HelpQA(
                question: "What's logged?",
                answer: "Tunnel events (connect, disconnect, key rotation, transport health) go to os_log. The Rust core forwards tracing spans through a redacting subscriber that drops payload bytes before they leave the process."
            )

            HelpQA(
                question: "Diagnostic bundles",
                answer: "Diagnostics → Export Support Bundle produces a JSON envelope with versions, transport state, peer fingerprints, and recent log lines. Three redaction modes: full (no scrubbing — local debugging only), partial (user-identifiable IPs scrubbed), and strict (only public-by-design fields kept — peer fingerprints, version strings, error codes)."
            )

            HelpQA(
                question: "Telemetry",
                answer: "QuantumLink does not send telemetry. Update checks (Sparkle) hit a single configured feed URL and report only the running version + macOS version. Sparkle update validation requires a signed build; ad-hoc local builds skip update checking entirely."
            )
        }
    }
}

private struct TroubleshootingSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HelpQA(
                question: "The tunnel won't start.",
                answer: "Check Diagnostics → Transport State. If you see 'NetworkExtension entitlement missing,' you're running a local ad-hoc build — the packet tunnel needs an Apple-granted entitlement to attach to utun. The UI works; real packets don't flow until you rebuild with a signed Developer-ID profile."
            )

            HelpQA(
                question: "A peer is stuck on 'handshaking'.",
                answer: "First, refresh from the Activity panel. If still stuck: confirm the peer's fingerprint matches what they shared. Run Diagnostics → Smoke Test to confirm at least one transport works locally. If smoke tests pass but the peer doesn't, the peer is offline or behind a NAT that needs the rendezvous server's help."
            )

            HelpQA(
                question: "RTT is high / throughput is low.",
                answer: "Activity panel → click the peer → see which transport is in use. If you're on the relay (slowest path), check whether ICE direct is failing — that usually means symmetric NAT on one or both ends. Switch to a different network briefly to confirm."
            )

            HelpQA(
                question: "I rotated my key and now peers reject me.",
                answer: "Expected. Rotation produces a new fingerprint and peers refuse to handshake until they've re-verified out-of-band. Share your new fingerprint (Configuration → Security → Public-Key Fingerprint) and have each peer add it."
            )

            HelpQA(
                question: "The kill switch keeps tearing down my tunnel.",
                answer: "You're running the strict kill switch on a flaky network. Two options: switch to lenient (Configuration → Security → Kill Switch → Lenient), which drops protected packets but keeps the tunnel up; or fix the underlying network instability, which the strict kill switch is correctly reporting."
            )

            HelpQA(
                question: "Help menu shows 'Help isn't available'.",
                answer: "You're seeing this — that means the in-app Help window opened. If you saw the OS dialog instead, the build may have shipped without HelpWindow.swift wired up; rebuild from a clean checkout."
            )
        }
    }
}

// MARK: - Submit ticket

private struct SubmitTicketSection: View {
    @State private var category: TicketCategory = .bug
    @State private var subject = ""
    @State private var details = ""
    @State private var includeDiagnostics = true
    @State private var lastError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Send a ticket directly to the QuantumLink support team. Pressing Send opens your default mail client with the ticket pre-composed; you stay in control of the actual send.")
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 12) {
                Picker("Category", selection: $category) {
                    ForEach(TicketCategory.allCases) { cat in
                        Text(cat.title).tag(cat)
                    }
                }
                .pickerStyle(.menu)

                LabeledField(title: "Subject") {
                    TextField("One-line summary", text: $subject)
                        .textFieldStyle(.roundedBorder)
                }

                LabeledField(title: "Details") {
                    TextEditor(text: $details)
                        .frame(minHeight: 140)
                        .font(.body)
                        .scrollContentBackground(.hidden)
                        .padding(8)
                        .background(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(Color.secondary.opacity(0.25))
                        )
                }

                Toggle("Include diagnostic context (recommended)",
                       isOn: $includeDiagnostics)
                    .toggleStyle(.checkbox)

                if let lastError {
                    Text(lastError)
                        .font(.callout)
                        .foregroundStyle(.red)
                }

                HStack {
                    Spacer()
                    Button("Send via Mail") { send() }
                        .buttonStyle(.borderedProminent)
                        .disabled(subject.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }

            HelpCallout(tone: .info,
                        title: "What gets sent",
                        text: "Your subject + details, plus (if checked) app version, macOS version, architecture, and current transport state. No log payloads, no peer fingerprints, no key material. You can edit anything in the mail draft before sending.")
        }
    }

    private func send() {
        lastError = nil
        let body = TicketComposer.makeBody(
            category: category,
            details: details,
            includeDiagnostics: includeDiagnostics
        )
        let mailto = TicketComposer.makeMailtoURL(
            category: category,
            subject: subject,
            body: body
        )
        if !NSWorkspace.shared.open(mailto) {
            lastError = "Couldn't open your mail client. Email help@quantumlinkvpn.com directly with the subject and details above."
        }
    }
}

enum TicketCategory: String, CaseIterable, Identifiable {
    case bug, feature, connection, security, billing, other

    var id: String { rawValue }

    var title: String {
        switch self {
        case .bug: return "Bug Report"
        case .feature: return "Feature Request"
        case .connection: return "Connection / Tunnel Issue"
        case .security: return "Security Concern"
        case .billing: return "Billing / Account"
        case .other: return "Other"
        }
    }

    var prefix: String {
        switch self {
        case .bug: return "[Bug]"
        case .feature: return "[Feature]"
        case .connection: return "[Connection]"
        case .security: return "[Security]"
        case .billing: return "[Billing]"
        case .other: return "[Support]"
        }
    }
}

private struct LabeledField<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.callout.weight(.medium))
            content()
        }
    }
}

// MARK: - Mailto composition

/// Builds the support-ticket mailto: URL. Pulled out of the view so
/// it's unit-testable without running SwiftUI; encoding rules for
/// query components (RFC 3986) need to handle newlines via %0A and
/// reserved characters individually.
enum TicketComposer {
    static let supportAddress = "help@quantumlinkvpn.com"

    static func makeBody(
        category: TicketCategory,
        details: String,
        includeDiagnostics: Bool
    ) -> String {
        var lines: [String] = []
        let trimmed = details.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            lines.append(trimmed)
            lines.append("")
        }
        if includeDiagnostics {
            lines.append("---")
            lines.append("Diagnostic context (auto-attached):")
            for (k, v) in DiagnosticSnapshot.current().summaryPairs {
                lines.append("\(k): \(v)")
            }
            lines.append("Category: \(category.title)")
        }
        return lines.joined(separator: "\n")
    }

    static func makeMailtoURL(
        category: TicketCategory,
        subject: String,
        body: String
    ) -> URL {
        let trimmedSubject = subject.trimmingCharacters(in: .whitespaces)
        let fullSubject = "\(category.prefix) \(trimmedSubject)"
        var components = URLComponents()
        components.scheme = "mailto"
        components.path = supportAddress
        components.queryItems = [
            URLQueryItem(name: "subject", value: fullSubject),
            URLQueryItem(name: "body", value: body)
        ]
        // URLComponents encodes `+` as a literal, but mail clients
        // interpret `+` in a query as a space. Force the canonical
        // percent-encoding for it so the body lands intact.
        let encoded = (components.url?.absoluteString ?? "")
            .replacingOccurrences(of: "+", with: "%2B")
        return URL(string: encoded) ?? URL(string: "mailto:\(supportAddress)")!
    }
}

// MARK: - Diagnostic snapshot for the ticket body

/// Lightweight snapshot used in the support-ticket auto-attached
/// context. Deliberately separate from `DiagnosticsBundle` (which is
/// the full export) — we don't want a 50KB JSON envelope inlined in a
/// mailto: URL, and the user shouldn't have to scroll through it
/// before they hit Send.
struct DiagnosticSnapshot {
    let appVersion: String
    let buildNumber: String
    let osVersion: String
    let architecture: String

    var summaryPairs: [(String, String)] {
        [
            ("App version", "\(appVersion) (\(buildNumber))"),
            ("macOS", osVersion),
            ("Architecture", architecture)
        ]
    }

    static func current() -> DiagnosticSnapshot {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "unknown"
        let build = info?["CFBundleVersion"] as? String ?? "unknown"
        let os = ProcessInfo.processInfo.operatingSystemVersionString
        #if arch(arm64)
        let arch = "arm64"
        #elseif arch(x86_64)
        let arch = "x86_64"
        #else
        let arch = "unknown"
        #endif
        return DiagnosticSnapshot(
            appVersion: version,
            buildNumber: build,
            osVersion: os,
            architecture: arch
        )
    }
}
