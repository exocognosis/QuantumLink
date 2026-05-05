import QuantumLinkKit
import SwiftUI

/// Top-level Scene for the Privacy & Anonymity preferences window.
/// Registered alongside the main `WindowGroup` and `HelpWindowScene`
/// in `QuantumLinkMacApp` and invoked from the Window menu.
struct PrivacyWindowScene: Scene {
    var body: some Scene {
        Window("Privacy & Anonymity", id: PrivacyWindowScene.windowID) {
            PrivacyView()
                .frame(minWidth: 720, minHeight: 580)
        }
        .windowResizability(.contentMinSize)
    }

    static let windowID = "quantumlink.privacy"
}

/// SwiftUI view that exposes the Rust-side anonymity controls.
/// State is persisted via `PrivacySettings` (which lives in the
/// Kit module so both the GUI and the Rust FFI bridge can read it).
struct PrivacyView: View {
    @State private var settings: PrivacySettings = PrivacySettings.load()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header

                Group {
                    section("Pluggable Transport",
                            subtitle: "Make your traffic indistinguishable from common protocols on the wire.") {
                        Picker("Wire shape", selection: $settings.transportObfuscation) {
                            ForEach(PrivacySettings.TransportObfuscation.allCases, id: \.self) { o in
                                Text(o.displayName).tag(o)
                            }
                        }
                        .pickerStyle(.segmented)
                        Text(settings.transportObfuscation.summary)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    section("Onion Routing",
                            subtitle: "Multi-hop circuits so no single peer can link you to your destination.") {
                        Toggle("Route through multiple mesh hops", isOn: $settings.enableOnionRouting)
                            .toggleStyle(.switch)

                        if settings.enableOnionRouting {
                            Stepper(value: $settings.onionCircuitLength, in: 2...5) {
                                HStack {
                                    Text("Circuit length")
                                    Text("\(settings.onionCircuitLength) hops")
                                        .foregroundStyle(.tint)
                                        .font(.callout.weight(.semibold))
                                }
                            }
                            Text("Each additional hop reduces linkability but adds round-trip latency.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }

                    section("Cover Traffic",
                            subtitle: "Constant-rate frames so observers can't tell when you're active.") {
                        Picker("Cover level", selection: $settings.coverTrafficLevel) {
                            ForEach(PrivacySettings.CoverTrafficLevel.allCases, id: \.self) { l in
                                Text(l.displayName).tag(l)
                            }
                        }
                        .pickerStyle(.menu)
                        Text(settings.coverTrafficLevel.summary)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    section("Decoy Connections",
                            subtitle: "Periodic fetches to popular sites — defeats interest profiling.") {
                        Picker("Cadence", selection: $settings.decoyCadence) {
                            ForEach(PrivacySettings.DecoyCadence.allCases, id: \.self) { c in
                                Text(c.displayName).tag(c)
                            }
                        }
                        .pickerStyle(.menu)
                        Text(settings.decoyCadence.summary)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    section("Identity Rotation",
                            subtitle: "Periodically regenerate your device keypair to sever cross-session linkability.") {
                        Picker("Policy", selection: $settings.rotationPolicy) {
                            ForEach(PrivacySettings.RotationPolicy.allCases, id: \.self) { p in
                                Text(p.displayName).tag(p)
                            }
                        }
                        .pickerStyle(.segmented)
                        Text(settings.rotationPolicy.summary)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    section("Network Privacy",
                            subtitle: "Always-on protections that cost nothing.") {
                        Toggle("DNS-over-QuantumLink (recommended)",
                               isOn: $settings.enableDnsOverQuantumLink)
                            .toggleStyle(.switch)
                        Text("Closes the biggest leak in most VPNs: DNS queries going to the local resolver in plaintext. Tunnel them instead so the local network sees zero domain names.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)

                        Divider().padding(.vertical, 4)

                        Toggle("SOCKS5 proxy on 127.0.0.1:1080",
                               isOn: $settings.enableSocks5Proxy)
                            .toggleStyle(.switch)
                        Text("Per-app routing without the system-level utun integration. Configure your browser's proxy to use it; everything else stays on the default network.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Divider()
                Button("Save Changes") { settings.save() }
                    .buttonStyle(.borderedProminent)
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .onChange(of: settings) { _, newValue in
            // Auto-persist on every change — feels right for a
            // settings UI; the explicit Save button is for users
            // who want a clear "applied" signal.
            newValue.save()
            // Live-apply: starting/stopping the relevant Rust
            // services in-process. This is what makes the toggles
            // actually do something instead of just persisting bits.
            PrivacyOrchestrator.shared.apply(newValue)
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "hand.raised")
                .font(.title2)
                .foregroundStyle(.tint)
                .frame(width: 28, height: 28, alignment: .center)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text("Privacy & Anonymity")
                    .font(.title2.weight(.semibold))
                Text("Layered defenses for data sovereignty and resistance to traffic analysis. Every option here is documented in detail in the in-app Help.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
        }
    }

    @ViewBuilder
    private func section<Content: View>(
        _ title: String,
        subtitle: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            content()
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.accentColor.opacity(0.04))
        )
    }
}
