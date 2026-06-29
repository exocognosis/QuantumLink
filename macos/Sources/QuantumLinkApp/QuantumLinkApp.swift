import QuantumLinkKit
import AppKit
import SwiftUI

@main
struct QuantumLinkMacApp: App {
    @StateObject private var controller = AppMeshController()
    private let updates = UpdateController()

    init() {
        updates.start()
    }

    var body: some Scene {
        WindowGroup(AppBrand.title) {
            DashboardView()
                .environmentObject(controller)
                .frame(minWidth: 860, minHeight: 560)
        }
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") {
                    updates.checkForUpdates()
                }
            }
            CommandMenu("Tunnel") {
                Button("Connect") {
                    Task { await controller.connect() }
                }
                .keyboardShortcut("k", modifiers: [.command])

                Button("Disconnect") {
                    Task { await controller.disconnect() }
                }
                .keyboardShortcut("d", modifiers: [.command, .shift])

                Button("Refresh") {
                    Task { await controller.refresh() }
                }
                .keyboardShortcut("r", modifiers: [.command])
            }
        }
    }
}

private struct DashboardView: View {
    @EnvironmentObject private var controller: AppMeshController
    @AppStorage(PreferenceKeys.onboardingTabVisible) private var onboardingTabVisible = true
    @AppStorage(PreferenceKeys.deploymentMode) private var deploymentModeRaw = QuantumLinkDeploymentMode.mesh.rawValue
    @AppStorage(PreferenceKeys.appearance) private var appearanceRaw = AppearancePreference.system.rawValue
    @AppStorage(PreferenceKeys.pqcAlgorithm) private var pqcAlgorithmRaw = PQCAlgorithm.fips203.rawValue
    @AppStorage(PreferenceKeys.recentConnectionProfiles) private var recentConnectionProfilesJSON = ""
    @AppStorage(PreferenceKeys.favoriteConnectionProfiles) private var favoriteConnectionProfilesJSON = ""
    @State private var selectedTab: SidebarTab?
    @State private var hasInitializedSelection = false
    @State private var recentSessions: [RecentSession] = []
    @State private var draftConnectionProfile = ConnectionProfile(
        sourceIPAddress: TunnelConfiguration.defaultDevelopment.overlayIPv4Address,
        destinationIPAddress: "",
        connectionType: .ssh
    )

    var body: some View {
        NavigationSplitView {
            List(selection: $selectedTab) {
                Section("Overview") {
                    ForEach(overviewTabs) { tab in
                        SidebarItem(tab: tab)
                            .tag(tab)
                    }
                }

                Section("Network") {
                    ForEach([SidebarTab.network, .peers, .routes, .security, .diagnostics]) { tab in
                        SidebarItem(tab: tab)
                            .tag(tab)
                    }
                }

                Section("Manage") {
                    SidebarItem(tab: .configuration)
                        .tag(SidebarTab.configuration)
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("")
        } detail: {
            DashboardDetailView(
                tab: selectedTab ?? defaultTab,
                status: controller.status,
                configuration: controller.configuration,
                deploymentMode: deploymentMode,
                draftConnectionProfile: $draftConnectionProfile,
                recentConnectionProfiles: recentConnectionProfiles,
                favoriteConnectionProfiles: favoriteConnectionProfiles,
                recentSessions: RecentSession.displayList(
                    status: controller.status,
                    deploymentMode: deploymentMode,
                    completedSessions: recentSessions
                ),
                onboardingTabVisibleBinding: $onboardingTabVisible,
                deploymentModeBinding: deploymentModeBinding,
                appearancePreferenceBinding: appearancePreferenceBinding,
                globalPQCAlgorithmBinding: globalPQCAlgorithmBinding,
                onConnect: { Task { await controller.connect() } },
                onDisconnect: { Task { await controller.disconnect() } },
                onRefresh: { Task { await controller.refresh() } },
                onStartConnection: { profile in
                    startConnection(profile)
                },
                onToggleFavoriteConnection: { profile in
                    toggleFavoriteConnection(profile)
                }
            )
                .padding(24)
                .toolbar {
                    ToolbarItem(placement: .navigation) {
                        TitleBarBrandView()
                    }
                }
        }
        .removingWindowToolbarTitle()
        .preferredColorScheme(appearancePreference.colorScheme)
        .onAppear {
            applyStoredConfiguration()
            selectInitialTabIfNeeded()
        }
        .onChange(of: deploymentModeRaw) { _, _ in
            applyStoredConfiguration()
        }
        .onChange(of: pqcAlgorithmRaw) { _, _ in
            applyStoredConfiguration()
            if draftConnectionProfile.destinationIPAddress.isEmpty {
                draftConnectionProfile.pqcAlgorithm = globalPQCAlgorithm
            }
        }
        .onChange(of: controller.status) { oldStatus, newStatus in
            recordSessionTransition(from: oldStatus, to: newStatus)
        }
        .onChange(of: onboardingTabVisible) { _, isVisible in
            if !isVisible, selectedTab == .onboarding {
                selectedTab = .home
            }
        }
    }

    private var overviewTabs: [SidebarTab] {
        var tabs: [SidebarTab] = [.home, .connections, .activity]
        if onboardingTabVisible {
            tabs.insert(.onboarding, at: 0)
        }
        return tabs
    }

    private var defaultTab: SidebarTab {
        onboardingTabVisible ? .onboarding : .home
    }

    private var deploymentMode: QuantumLinkDeploymentMode {
        QuantumLinkDeploymentMode(rawValue: deploymentModeRaw) ?? .mesh
    }

    private var appearancePreference: AppearancePreference {
        AppearancePreference(rawValue: appearanceRaw) ?? .system
    }

    private var globalPQCAlgorithm: PQCAlgorithm {
        PQCAlgorithm(rawValue: pqcAlgorithmRaw) ?? .fips203
    }

    private var recentConnectionProfiles: [ConnectionProfile] {
        decodeConnectionProfiles(from: recentConnectionProfilesJSON)
    }

    private var favoriteConnectionProfiles: [ConnectionProfile] {
        decodeConnectionProfiles(from: favoriteConnectionProfilesJSON)
    }

    private var deploymentModeBinding: Binding<QuantumLinkDeploymentMode> {
        Binding(
            get: { deploymentMode },
            set: { deploymentModeRaw = $0.rawValue }
        )
    }

    private var appearancePreferenceBinding: Binding<AppearancePreference> {
        Binding(
            get: { appearancePreference },
            set: { appearanceRaw = $0.rawValue }
        )
    }

    private var globalPQCAlgorithmBinding: Binding<PQCAlgorithm> {
        Binding(
            get: { globalPQCAlgorithm },
            set: { pqcAlgorithmRaw = $0.rawValue }
        )
    }

    private func selectInitialTabIfNeeded() {
        guard !hasInitializedSelection else { return }
        selectedTab = defaultTab
        hasInitializedSelection = true
    }

    private func applyStoredConfiguration() {
        controller.updateConfiguration(configuration(pqcAlgorithm: globalPQCAlgorithm))
    }

    private func recordSessionTransition(from oldStatus: TunnelStatus, to newStatus: TunnelStatus) {
        guard oldStatus.phase == .connected, newStatus.phase != .connected else { return }

        recentSessions.insert(
            RecentSession.completed(status: oldStatus, deploymentMode: deploymentMode, endedAt: Date()),
            at: 0
        )
        recentSessions = Array(recentSessions.prefix(4))
    }

    private func startConnection(_ profile: ConnectionProfile) {
        let normalizedProfile = normalized(profile)
        guard !normalizedProfile.sourceIPAddress.isEmpty,
              !normalizedProfile.destinationIPAddress.isEmpty else { return }

        draftConnectionProfile = normalizedProfile
        recentConnectionProfilesJSON = encodeConnectionProfiles(
            ConnectionProfileLibrary.addRecent(normalizedProfile, to: recentConnectionProfiles)
        )
        controller.updateConfiguration(
            configuration(
                pqcAlgorithm: normalizedProfile.pqcAlgorithm,
                profile: normalizedProfile
            )
        )
        Task { await controller.connect() }
    }

    private func toggleFavoriteConnection(_ profile: ConnectionProfile) {
        favoriteConnectionProfilesJSON = encodeConnectionProfiles(
            ConnectionProfileLibrary.toggleFavorite(normalized(profile), in: favoriteConnectionProfiles)
        )
    }

    private func normalized(_ profile: ConnectionProfile) -> ConnectionProfile {
        var normalizedProfile = profile
        normalizedProfile.sourceIPAddress = profile.sourceIPAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        normalizedProfile.destinationIPAddress = profile.destinationIPAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        if normalizedProfile.port <= 0 {
            normalizedProfile.port = profile.connectionType.defaultPort
        }
        return normalizedProfile
    }

    private func configuration(
        pqcAlgorithm: PQCAlgorithm,
        profile: ConnectionProfile? = nil
    ) -> TunnelConfiguration {
        var baseConfiguration = TunnelConfiguration.defaultDevelopment
        baseConfiguration = TunnelConfiguration(
            meshID: baseConfiguration.meshID,
            deviceAlias: baseConfiguration.deviceAlias,
            overlayIPv4Address: baseConfiguration.overlayIPv4Address,
            tunnelRemoteAddress: baseConfiguration.tunnelRemoteAddress,
            protectedRoutes: baseConfiguration.protectedRoutes,
            excludedRoutes: baseConfiguration.excludedRoutes,
            dnsServers: baseConfiguration.dnsServers,
            dnsSearchDomains: baseConfiguration.dnsSearchDomains,
            routeMode: baseConfiguration.routeMode,
            dnsMode: baseConfiguration.dnsMode,
            discoveryModes: baseConfiguration.discoveryModes,
            rendezvousServers: baseConfiguration.rendezvousServers,
            relayServers: baseConfiguration.relayServers,
            mtu: baseConfiguration.mtu,
            crypto: CryptoPolicy(pqcAlgorithm: pqcAlgorithm)
        )
        if let profile {
            return deploymentMode.configuration(from: baseConfiguration, profile: profile)
        }
        return deploymentMode.configuration(from: baseConfiguration)
    }

    private func decodeConnectionProfiles(from json: String) -> [ConnectionProfile] {
        guard let data = json.data(using: .utf8) else { return [] }
        return (try? JSONDecoder().decode([ConnectionProfile].self, from: data)) ?? []
    }

    private func encodeConnectionProfiles(_ profiles: [ConnectionProfile]) -> String {
        guard let data = try? JSONEncoder().encode(profiles) else { return "[]" }
        return String(data: data, encoding: .utf8) ?? "[]"
    }
}

private extension View {
    @ViewBuilder
    func removingWindowToolbarTitle() -> some View {
        if #available(macOS 15.0, *) {
            toolbar(removing: .title)
        } else {
            background(WindowTitleVisibilityHider())
        }
    }
}

private struct WindowTitleVisibilityHider: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        HiddenTitleView()
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        nsView.window?.titleVisibility = .hidden
    }

    private final class HiddenTitleView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            window?.titleVisibility = .hidden
        }
    }
}

private enum AppBrand {
    static let title = "QuantumLink PQC VPN by Dytallix"

    static var logoImage: NSImage? {
#if SWIFT_PACKAGE
        let resourceBundle = Bundle.module
#else
        let resourceBundle = Bundle.main
#endif
        guard let url = resourceBundle.url(forResource: "DytallixLogo", withExtension: "png") else {
            return nil
        }
        return NSImage(contentsOf: url)
    }
}

private struct TitleBarBrandView: View {
    var body: some View {
        Group {
            if let logo = AppBrand.logoImage {
                Image(nsImage: logo)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 176, height: 48)
            } else {
                Text(AppBrand.title)
                    .font(.headline.weight(.semibold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(AppBrand.title)
    }
}

private enum SidebarTab: CaseIterable, Hashable, Identifiable {
    case onboarding
    case home
    case connections
    case activity
    case network
    case peers
    case routes
    case security
    case diagnostics
    case configuration

    var id: Self { self }

    var title: String {
        switch self {
        case .onboarding: "Onboarding"
        case .home: "Home"
        case .connections: "Connections"
        case .activity: "Activity"
        case .network: "Network"
        case .peers: "Peers"
        case .routes: "Routes"
        case .security: "Security"
        case .diagnostics: "Diagnostics"
        case .configuration: "Configuration"
        }
    }

    var systemImage: String {
        switch self {
        case .onboarding: "sparkles"
        case .home: "house"
        case .connections: "terminal"
        case .activity: "clock.arrow.circlepath"
        case .network: "network"
        case .peers: "desktopcomputer.and.arrow.down"
        case .routes: "arrow.triangle.branch"
        case .security: "lock.shield"
        case .diagnostics: "waveform.path.ecg"
        case .configuration: "slider.horizontal.3"
        }
    }
}

private enum AppearancePreference: String, CaseIterable, Hashable, Identifiable {
    case system
    case light
    case dark

    var id: Self { self }

    var title: String {
        switch self {
        case .system: "System"
        case .light: "Light"
        case .dark: "Dark"
        }
    }

    var systemImage: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .light: "sun.max"
        case .dark: "moon"
        }
    }

    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}

private enum PreferenceKeys {
    static let onboardingTabVisible = "QuantumLink.onboardingTabVisible"
    static let deploymentMode = "QuantumLink.deploymentMode"
    static let appearance = "QuantumLink.appearance"
    static let pqcAlgorithm = "QuantumLink.pqcAlgorithm"
    static let recentConnectionProfiles = "QuantumLink.recentConnectionProfiles"
    static let favoriteConnectionProfiles = "QuantumLink.favoriteConnectionProfiles"
}

private struct SidebarItem: View {
    let tab: SidebarTab

    var body: some View {
        Label(tab.title, systemImage: tab.systemImage)
    }
}

private struct DashboardDetailView: View {
    let tab: SidebarTab
    let status: TunnelStatus
    let configuration: TunnelConfiguration
    let deploymentMode: QuantumLinkDeploymentMode
    @Binding var draftConnectionProfile: ConnectionProfile
    let recentConnectionProfiles: [ConnectionProfile]
    let favoriteConnectionProfiles: [ConnectionProfile]
    let recentSessions: [RecentSession]
    let onboardingTabVisibleBinding: Binding<Bool>
    let deploymentModeBinding: Binding<QuantumLinkDeploymentMode>
    let appearancePreferenceBinding: Binding<AppearancePreference>
    let globalPQCAlgorithmBinding: Binding<PQCAlgorithm>
    let onConnect: () -> Void
    let onDisconnect: () -> Void
    let onRefresh: () -> Void
    let onStartConnection: (ConnectionProfile) -> Void
    let onToggleFavoriteConnection: (ConnectionProfile) -> Void

    var body: some View {
        Group {
            switch tab {
            case .onboarding:
                OnboardingPanel(
                    deploymentMode: deploymentModeBinding,
                    appearancePreference: appearancePreferenceBinding,
                    globalPQCAlgorithm: globalPQCAlgorithmBinding,
                    onboardingTabVisible: onboardingTabVisibleBinding,
                    configuration: configuration,
                    status: status
                )
            case .home:
                HomePanel(
                    status: status,
                    configuration: configuration,
                    deploymentMode: deploymentMode,
                    deploymentModeBinding: deploymentModeBinding,
                    globalPQCAlgorithm: globalPQCAlgorithmBinding,
                    draftConnectionProfile: $draftConnectionProfile,
                    recentConnectionProfiles: recentConnectionProfiles,
                    favoriteConnectionProfiles: favoriteConnectionProfiles,
                    recentSessions: recentSessions,
                    onConnect: onConnect,
                    onDisconnect: onDisconnect,
                    onRefresh: onRefresh,
                    onStartConnection: onStartConnection,
                    onToggleFavoriteConnection: onToggleFavoriteConnection
                )
            case .connections:
                ConnectionsPanel(
                    draftConnectionProfile: $draftConnectionProfile,
                    deploymentMode: deploymentModeBinding,
                    globalPQCAlgorithm: globalPQCAlgorithmBinding,
                    recentConnectionProfiles: recentConnectionProfiles,
                    favoriteConnectionProfiles: favoriteConnectionProfiles,
                    overlayAddress: status.overlayIPv4Address,
                    onStartConnection: onStartConnection,
                    onToggleFavoriteConnection: onToggleFavoriteConnection
                )
            case .activity:
                ActivityPanel(
                    status: status,
                    recentSessions: recentSessions,
                    recentConnectionProfiles: recentConnectionProfiles,
                    favoriteConnectionProfiles: favoriteConnectionProfiles,
                    onStartConnection: onStartConnection,
                    onToggleFavoriteConnection: onToggleFavoriteConnection
                )
            case .network:
                NetworkOverview(status: status, configuration: configuration, deploymentMode: deploymentMode)
            case .peers:
                PeerList(peers: status.peers)
            case .routes:
                RoutesDetail(status: status)
            case .security:
                SecurityDetail(status: status, configuration: configuration)
            case .diagnostics:
                DiagnosticsDetail(status: status)
            case .configuration:
                ConfigurationPanel(
                    deploymentMode: deploymentModeBinding,
                    appearancePreference: appearancePreferenceBinding,
                    globalPQCAlgorithm: globalPQCAlgorithmBinding,
                    onboardingTabVisible: onboardingTabVisibleBinding,
                    configuration: configuration,
                    status: status
                )
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct OnboardingPanel: View {
    @Binding var deploymentMode: QuantumLinkDeploymentMode
    @Binding var appearancePreference: AppearancePreference
    @Binding var globalPQCAlgorithm: PQCAlgorithm
    @Binding var onboardingTabVisible: Bool
    @State private var selectedDytallixIdentityMode: DiscoveryIdentityMode = .off
    let configuration: TunnelConfiguration
    let status: TunnelStatus

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .onboarding,
                subtitle: "Choose your deployment defaults, verify tunnel identity, and confirm you are ready to send your first post-quantum protected session."
            )

            ConfigurationCard(title: "Welcome to QuantumLink", systemImage: "sparkles.rectangle.stack") {
                HStack(spacing: 10) {
                    OnboardingBadge(title: deploymentMode.title, systemImage: deploymentMode.systemImage)
                    OnboardingBadge(title: globalPQCAlgorithm.shortTitle, systemImage: "lock.shield")
                    OnboardingBadge(title: status.phase.label, systemImage: status.phase == .connected ? "checkmark.circle" : "shield")
                }
            }

            PanelGrid {
                ConfigurationCard(title: "Choose Deployment", systemImage: "network") {
                        Picker("Deployment", selection: $deploymentMode) {
                            ForEach(QuantumLinkDeploymentMode.allCases) { mode in
                                Label(mode.title, systemImage: mode.systemImage)
                                    .tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)

                        DeploymentModeSummary(mode: deploymentMode)
                    }

                    ConfigurationCard(title: "Set Defaults", systemImage: "slider.horizontal.3") {
                        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
                            GridRow {
                                LabeledContent("Appearance") {
                                    Picker("Appearance", selection: $appearancePreference) {
                                        ForEach(AppearancePreference.allCases) { preference in
                                            Label(preference.title, systemImage: preference.systemImage)
                                                .tag(preference)
                                        }
                                    }
                                    .labelsHidden()
                                    .pickerStyle(.menu)
                                }

                                LabeledContent("PQC Default") {
                                    Picker("PQC Default", selection: $globalPQCAlgorithm) {
                                        ForEach(PQCAlgorithm.allCases) { algorithm in
                                            Text(algorithm.shortTitle)
                                                .tag(algorithm)
                                        }
                                    }
                                    .labelsHidden()
                                    .pickerStyle(.menu)
                                }
                            }
                        }

                        Text("Your current baseline is \(appearancePreference.title) appearance with \(globalPQCAlgorithm.title) as the default cryptographic profile for new sessions.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    ConfigurationCard(title: "Validate Tunnel Identity", systemImage: "person.text.rectangle") {
                        InfoRow(label: "Device", value: configuration.deviceAlias)
                        InfoRow(label: "Mesh ID", value: configuration.meshID)
                        InfoRow(label: "Overlay", value: PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address))
                        InfoRow(label: "Remote", value: PrivacyDefaults.redactNetworkIdentifiers(in: configuration.tunnelRemoteAddress))
                    }

                    ConfigurationCard(title: "First-Run Checklist", systemImage: "checklist") {
                        OnboardingStepRow(
                            title: "Deployment mode selected",
                            detail: deploymentMode.summary,
                            isComplete: true
                        )
                        OnboardingStepRow(
                            title: "Security default confirmed",
                            detail: globalPQCAlgorithm.summary,
                            isComplete: true
                        )
                        OnboardingStepRow(
                            title: "Overlay identity available",
                            detail: status.overlayIPv4Address.isEmpty ? "QuantumLink will populate this after configuration is loaded." : PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address),
                            isComplete: !status.overlayIPv4Address.isEmpty
                        )
                        OnboardingStepRow(
                            title: "Ready to start first connection",
                            detail: status.phase == .connected ? "Tunnel is already active. You can move straight to Home or Connections." : "After confirming a destination IP and port in Home or Connections, start your first session.",
                            isComplete: status.phase == .connected
                        )
                    }
                }

            ConfigurationCard(title: "Completion", systemImage: "sidebar.left") {
                Toggle("Remove Onboarding Tab", isOn: removeOnboardingBinding)
                    .toggleStyle(.checkbox)

                Text("Hide this tab after your initial setup is complete. You can restore it at any time from Configuration.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var removeOnboardingBinding: Binding<Bool> {
        Binding(
            get: { !onboardingTabVisible },
            set: { onboardingTabVisible = !$0 }
        )
    }
}

private struct OnboardingBadge: View {
    let title: String
    let systemImage: String

    var body: some View {
        Label(title, systemImage: systemImage)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(.thinMaterial, in: Capsule())
    }
}

private struct OnboardingStepRow: View {
    let title: String
    let detail: String
    let isComplete: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: isComplete ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(isComplete ? .green : .secondary)
                .frame(width: 16)

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.callout.weight(.semibold))
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
    }
}

private struct HomePanel: View {
    let status: TunnelStatus
    let configuration: TunnelConfiguration
    let deploymentMode: QuantumLinkDeploymentMode
    let deploymentModeBinding: Binding<QuantumLinkDeploymentMode>
    let globalPQCAlgorithm: Binding<PQCAlgorithm>
    @Binding var draftConnectionProfile: ConnectionProfile
    let recentConnectionProfiles: [ConnectionProfile]
    let favoriteConnectionProfiles: [ConnectionProfile]
    let recentSessions: [RecentSession]
    let onConnect: () -> Void
    let onDisconnect: () -> Void
    let onRefresh: () -> Void
    let onStartConnection: (ConnectionProfile) -> Void
    let onToggleFavoriteConnection: (ConnectionProfile) -> Void

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .home,
                subtitle: "\(status.phase.label) · \(deploymentMode.title) · \(status.routeMode.label) · DNS \(status.dnsMode.label)"
            ) {
                HStack(spacing: 8) {
                    Button(action: onRefresh) {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    Button(action: status.phase == .connected ? onDisconnect : onConnect) {
                        Label(
                            status.phase == .connected ? "Disconnect" : "Connect",
                            systemImage: status.phase == .connected ? "power" : "bolt.horizontal.circle"
                        )
                    }
                    .buttonStyle(.borderedProminent)
                }
            }

            ConnectionLauncherPanel(
                draft: $draftConnectionProfile,
                deploymentMode: deploymentModeBinding,
                globalPQCAlgorithm: globalPQCAlgorithm,
                recentProfiles: recentConnectionProfiles,
                favoriteProfiles: favoriteConnectionProfiles,
                overlayAddress: status.overlayIPv4Address,
                onStart: onStartConnection,
                onToggleFavorite: onToggleFavoriteConnection
            )

            ConfigurationCard(title: "Status", systemImage: "shield.lefthalf.filled") {
                StatusHeader(status: status)
                Divider()
                KPIGrid(status: status)
            }

            PanelGrid {
                RecentSessionsPanel(sessions: recentSessions)
                TechnicalInfoPanel(
                    status: status,
                    configuration: configuration,
                    deploymentMode: deploymentMode
                )
            }
        }
    }
}

private struct ConnectionsPanel: View {
    @Binding var draftConnectionProfile: ConnectionProfile
    @Binding var deploymentMode: QuantumLinkDeploymentMode
    @Binding var globalPQCAlgorithm: PQCAlgorithm
    let recentConnectionProfiles: [ConnectionProfile]
    let favoriteConnectionProfiles: [ConnectionProfile]
    let overlayAddress: String
    let onStartConnection: (ConnectionProfile) -> Void
    let onToggleFavoriteConnection: (ConnectionProfile) -> Void

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .connections,
                subtitle: "Create, favorite, and relaunch connection profiles."
            )

            ConnectionLauncherPanel(
                draft: $draftConnectionProfile,
                deploymentMode: $deploymentMode,
                globalPQCAlgorithm: $globalPQCAlgorithm,
                recentProfiles: recentConnectionProfiles,
                favoriteProfiles: favoriteConnectionProfiles,
                overlayAddress: overlayAddress,
                onStart: onStartConnection,
                onToggleFavorite: onToggleFavoriteConnection
            )
        }
    }
}

private struct ActivityPanel: View {
    let status: TunnelStatus
    let recentSessions: [RecentSession]
    let recentConnectionProfiles: [ConnectionProfile]
    let favoriteConnectionProfiles: [ConnectionProfile]
    let onStartConnection: (ConnectionProfile) -> Void
    let onToggleFavoriteConnection: (ConnectionProfile) -> Void

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .activity,
                subtitle: "\(status.metrics.bytesIn.byteCount) in · \(status.metrics.bytesOut.byteCount) out · \(status.metrics.replayDrops) replay drops"
            )

            ConfigurationCard(title: "Live Metrics", systemImage: "speedometer") {
                KPIGrid(status: status)
            }

            PanelGrid {
                RecentSessionsPanel(sessions: recentSessions)

                ConnectionProfileList(
                    title: "Recent Connections",
                    systemImage: "clock.arrow.circlepath",
                    emptyTitle: "No recent connections",
                    profiles: recentConnectionProfiles,
                    favoriteProfiles: favoriteConnectionProfiles,
                    onStart: onStartConnection,
                    onToggleFavorite: onToggleFavoriteConnection
                )
            }
        }
    }
}

private struct HomeHeader: View {
    let status: TunnelStatus
    let deploymentMode: QuantumLinkDeploymentMode
    let onConnect: () -> Void
    let onDisconnect: () -> Void
    let onRefresh: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: statusIcon)
                .font(.system(size: 34, weight: .semibold))
                .foregroundStyle(statusColor)
                .frame(width: 52, height: 52)

            VStack(alignment: .leading, spacing: 6) {
                Text("QuantumLink Home")
                    .font(.title2.weight(.semibold))
                Text("\(status.phase.label) · \(deploymentMode.title) · \(status.routeMode.label) · DNS \(status.dnsMode.label)")
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            Spacer(minLength: 16)

            HStack(spacing: 8) {
                Button(action: onRefresh) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }

                Button(action: status.phase == .connected ? onDisconnect : onConnect) {
                    Label(status.phase == .connected ? "Disconnect" : "Connect", systemImage: status.phase == .connected ? "power" : "bolt.horizontal.circle")
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }

    private var statusIcon: String {
        switch status.phase {
        case .connected: "checkmark.shield"
        case .degraded, .reconnecting: "exclamationmark.shield"
        case .failed: "xmark.shield"
        default: "shield"
        }
    }

    private var statusColor: Color {
        switch status.phase {
        case .connected: .green
        case .degraded, .reconnecting: .orange
        case .failed: .red
        default: .secondary
        }
    }
}

private struct ConnectionLauncherPanel: View {
    @Binding var draft: ConnectionProfile
    @Binding var deploymentMode: QuantumLinkDeploymentMode
    @Binding var globalPQCAlgorithm: PQCAlgorithm
    let recentProfiles: [ConnectionProfile]
    let favoriteProfiles: [ConnectionProfile]
    let overlayAddress: String
    let onStart: (ConnectionProfile) -> Void
    let onToggleFavorite: (ConnectionProfile) -> Void

    private var isFavorite: Bool {
        favoriteProfiles.contains { $0.stableKey == draft.stableKey }
    }

    private var canStart: Bool {
        draft.missingRequiredFields(for: deploymentMode).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center) {
                Label("Connection", systemImage: "terminal")
                    .font(.headline)

                Spacer()

                Button {
                    onToggleFavorite(draft)
                } label: {
                    Image(systemName: isFavorite ? "star.fill" : "star")
                }
                .help(isFavorite ? "Remove favorite" : "Add favorite")
                .disabled(!canStart)
            }

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
                GridRow {
                    LabeledContent("Profile") {
                        TextField("Optional name", text: $draft.name)
                            .textFieldStyle(.roundedBorder)
                    }
                    LabeledContent("Deployment") {
                        Picker("Deployment", selection: $deploymentMode) {
                            ForEach(QuantumLinkDeploymentMode.allCases) { mode in
                                Label(mode.title, systemImage: mode.systemImage)
                                    .tag(mode)
                            }
                        }
                        .labelsHidden()
                        .pickerStyle(.menu)
                    }
                }

                GridRow {
                    LabeledContent("Session PQC") {
                        Picker("Session PQC", selection: $draft.pqcAlgorithm) {
                            ForEach(PQCAlgorithm.allCases) { algorithm in
                                Text(algorithm.shortTitle)
                                    .tag(algorithm)
                            }
                        }
                        .labelsHidden()
                        .pickerStyle(.menu)
                    }
                    LabeledContent("Global Default") {
                        Text(globalPQCAlgorithm.shortTitle)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }

                GridRow {
                    LabeledContent("Type") {
                        Picker("Connection Type", selection: $draft.connectionType) {
                            ForEach(QuantumLinkConnectionType.allCases) { type in
                                Label(type.title, systemImage: type.systemImage)
                                    .tag(type)
                            }
                        }
                        .labelsHidden()
                        .pickerStyle(.menu)
                        .onChange(of: draft.connectionType) { oldValue, newValue in
                            if draft.port == oldValue.defaultPort || draft.port <= 0 {
                                draft.port = newValue.defaultPort
                            }
                        }
                    }
                    LabeledContent("Required") {
                        Text(requiredFieldSummary)
                            .foregroundStyle(canStart ? Color.secondary : Color.orange)
                            .lineLimit(1)
                    }
                }
            }

            PanelGrid {
                AdaptiveDeploymentFields(
                    draft: $draft,
                    deploymentMode: deploymentMode,
                    overlayAddress: overlayAddress
                )

                AdaptiveConnectionFields(draft: $draft)
            }

            HStack {
                Spacer()
                Button {
                    onStart(draft)
                } label: {
                    Label("Connect", systemImage: "bolt.horizontal.circle")
                        .frame(minWidth: 220)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canStart)
            }

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 12)], alignment: .leading, spacing: 12) {
                ConnectionProfileList(
                    title: "Favorites",
                    systemImage: "star.fill",
                    emptyTitle: "No favorite profiles",
                    profiles: favoriteProfiles,
                    favoriteProfiles: favoriteProfiles,
                    onStart: onStart,
                    onToggleFavorite: onToggleFavorite
                )

                ConnectionProfileList(
                    title: "Recent Connections",
                    systemImage: "clock.arrow.circlepath",
                    emptyTitle: "No recent connections",
                    profiles: recentProfiles,
                    favoriteProfiles: favoriteProfiles,
                    onStart: onStart,
                    onToggleFavorite: onToggleFavorite
                )
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .onAppear {
            if draft.sourceIPAddress.isEmpty {
                draft.sourceIPAddress = overlayAddress
            }
            if draft.destinationIPAddress.isEmpty {
                draft.pqcAlgorithm = globalPQCAlgorithm
            }
        }
    }

    private var requiredFieldSummary: String {
        let missing = draft.missingRequiredFields(for: deploymentMode)
        return missing.isEmpty ? "Ready" : missing.joined(separator: ", ")
    }
}

private struct AdaptiveDeploymentFields: View {
    @Binding var draft: ConnectionProfile
    let deploymentMode: QuantumLinkDeploymentMode
    let overlayAddress: String

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("\(deploymentMode.title) Setup", systemImage: deploymentMode.systemImage)
                .font(.callout.weight(.semibold))

            switch deploymentMode {
            case .direct:
                directFields
            case .mesh:
                deviceFields(
                    title: "Mesh Devices",
                    emptyTitle: "Add at least one peer device",
                    devices: $draft.deploymentDetails.peerDevices,
                    defaultRole: .peer
                )
            case .localVPN:
                deviceFields(
                    title: "LAN Devices",
                    emptyTitle: "Add at least one LAN device or subnet",
                    devices: $draft.deploymentDetails.localDevices,
                    defaultRole: .gateway
                )
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var directFields: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
            GridRow {
                LabeledContent("Local Overlay") {
                    TextField(overlayAddress, text: $draft.sourceIPAddress)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("Remote Endpoint") {
                    TextField("89.167.52.129", text: $draft.destinationIPAddress)
                        .textFieldStyle(.roundedBorder)
                }
            }
            GridRow {
                LabeledContent("Endpoint Port") {
                    TextField("9471", text: endpointPortBinding)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 96)
                }
                LabeledContent("Protected Prefixes") {
                    TextField("100.64.0.0/10", text: $draft.deploymentDetails.protectedPrefixesText)
                        .textFieldStyle(.roundedBorder)
                }
            }
        }
    }

    private func deviceFields(
        title: String,
        emptyTitle: String,
        devices: Binding<[PeerDeviceProfile]>,
        defaultRole: PeerDeviceRole
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            LabeledContent("Local Overlay") {
                TextField(overlayAddress, text: $draft.sourceIPAddress)
                    .textFieldStyle(.roundedBorder)
            }

            PeerDeviceList(
                title: title,
                emptyTitle: emptyTitle,
                devices: devices,
                defaultRole: defaultRole
            )
        }
    }

    private var endpointPortBinding: Binding<String> {
        Binding(
            get: { draft.deploymentDetails.directEndpointPort > 0 ? "\(draft.deploymentDetails.directEndpointPort)" : "" },
            set: { value in
                draft.deploymentDetails.directEndpointPort = Int(value.filter(\.isNumber)) ?? 0
            }
        )
    }
}

private struct PeerDeviceList: View {
    let title: String
    let emptyTitle: String
    @Binding var devices: [PeerDeviceProfile]
    let defaultRole: PeerDeviceRole

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(title, systemImage: "desktopcomputer.and.arrow.down")
                    .font(.callout.weight(.semibold))

                Spacer()

                Button {
                    devices.append(PeerDeviceProfile(role: defaultRole))
                } label: {
                    Image(systemName: "plus")
                }
                .help("Add device")
            }

            if devices.isEmpty {
                ContentUnavailableView(emptyTitle, systemImage: "plus.circle")
                    .frame(maxWidth: .infinity, minHeight: 92)
            } else {
                VStack(spacing: 8) {
                    ForEach($devices) { $device in
                        PeerDeviceEditorRow(device: $device) {
                            devices.removeAll { $0.id == device.id }
                        }
                    }
                }
            }
        }
    }
}

private struct PeerDeviceEditorRow: View {
    @Binding var device: PeerDeviceProfile
    let onRemove: () -> Void

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
            GridRow {
                TextField("Alias", text: $device.alias)
                    .textFieldStyle(.roundedBorder)
                TextField("Endpoint IP or subnet", text: $device.endpointAddress)
                    .textFieldStyle(.roundedBorder)
            }
            GridRow {
                TextField("Overlay IP", text: $device.overlayIPAddress)
                    .textFieldStyle(.roundedBorder)
                HStack(spacing: 8) {
                    Picker("Role", selection: $device.role) {
                        ForEach(PeerDeviceRole.allCases) { role in
                            Text(role.title)
                                .tag(role)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)

                    TextField("Port", text: portBinding)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 72)

                    Button {
                        onRemove()
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .help("Remove device")
                }
            }
        }
        .padding(10)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 8))
    }

    private var portBinding: Binding<String> {
        Binding(
            get: { device.port > 0 ? "\(device.port)" : "" },
            set: { value in
                device.port = Int(value.filter(\.isNumber)) ?? 0
            }
        )
    }
}

private struct AdaptiveConnectionFields: View {
    @Binding var draft: ConnectionProfile

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("\(draft.connectionType.title) Details", systemImage: draft.connectionType.systemImage)
                .font(.callout.weight(.semibold))

            switch draft.connectionType {
            case .ssh:
                sshFields
            case .https:
                httpsFields
            case .rdp:
                rdpFields
            case .vnc:
                vncFields
            case .custom:
                customFields
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var sshFields: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
            GridRow {
                LabeledContent("Username") {
                    TextField("ubuntu", text: $draft.sshSettings.username)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("SSH Port") {
                    TextField("22", text: servicePortBinding)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 96)
                }
            }
            GridRow {
                LabeledContent("Identity File") {
                    TextField("~/.ssh/id_ed25519", text: $draft.sshSettings.identityFilePath)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("Command") {
                    TextField("Optional", text: $draft.sshSettings.remoteCommand)
                        .textFieldStyle(.roundedBorder)
                }
            }
        }
    }

    private var httpsFields: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
            GridRow {
                LabeledContent("Host or URL") {
                    TextField("https://app.example.com", text: $draft.httpsSettings.hostOrURL)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("HTTPS Port") {
                    TextField("443", text: servicePortBinding)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 96)
                }
            }
            GridRow {
                LabeledContent("Path") {
                    TextField("/", text: $draft.httpsSettings.path)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("TLS SNI") {
                    TextField("Optional", text: $draft.httpsSettings.tlsServerName)
                        .textFieldStyle(.roundedBorder)
                }
            }
            GridRow {
                Toggle("Validate TLS", isOn: $draft.httpsSettings.validateTLS)
                    .toggleStyle(.checkbox)
                Color.clear
            }
        }
    }

    private var rdpFields: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
            GridRow {
                LabeledContent("Username") {
                    TextField("DOMAIN\\user", text: $draft.rdpSettings.username)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("RDP Port") {
                    TextField("3389", text: servicePortBinding)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 96)
                }
            }
            GridRow {
                LabeledContent("Domain") {
                    TextField("Optional", text: $draft.rdpSettings.domain)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("Gateway") {
                    TextField("Optional RD Gateway", text: $draft.rdpSettings.gatewayHost)
                        .textFieldStyle(.roundedBorder)
                }
            }
        }
    }

    private var vncFields: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
            GridRow {
                LabeledContent("Display") {
                    TextField(":0", text: $draft.vncSettings.display)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("VNC Port") {
                    TextField("5900", text: servicePortBinding)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 96)
                }
            }
            GridRow {
                LabeledContent("Auth") {
                    Picker("Auth", selection: $draft.vncSettings.authMode) {
                        ForEach(VNCAuthenticationMode.allCases) { mode in
                            Text(mode.title)
                                .tag(mode)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                }
                LabeledContent("Username") {
                    TextField("Optional", text: $draft.vncSettings.username)
                        .textFieldStyle(.roundedBorder)
                }
            }
        }
    }

    private var customFields: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
            GridRow {
                LabeledContent("Protocol") {
                    TextField("postgres, mqtt, admin", text: $draft.customSettings.protocolName)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("Port") {
                    TextField("Port", text: servicePortBinding)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 96)
                }
            }
            GridRow {
                LabeledContent("Notes") {
                    TextField("Optional", text: $draft.customSettings.notes)
                        .textFieldStyle(.roundedBorder)
                }
                Color.clear
            }
        }
    }

    private var servicePortBinding: Binding<String> {
        Binding(
            get: { draft.port > 0 ? "\(draft.port)" : "" },
            set: { value in
                draft.port = Int(value.filter(\.isNumber)) ?? 0
            }
        )
    }
}

private struct ConnectionProfileList: View {
    let title: String
    let systemImage: String
    let emptyTitle: String
    let profiles: [ConnectionProfile]
    let favoriteProfiles: [ConnectionProfile]
    let onStart: (ConnectionProfile) -> Void
    let onToggleFavorite: (ConnectionProfile) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: systemImage)
                .font(.callout.weight(.semibold))

            if profiles.isEmpty {
                ContentUnavailableView(emptyTitle, systemImage: systemImage)
                    .frame(maxWidth: .infinity, minHeight: 116)
            } else {
                VStack(spacing: 0) {
                    ForEach(profiles) { profile in
                        ConnectionProfileRow(
                            profile: profile,
                            isFavorite: favoriteProfiles.contains { $0.stableKey == profile.stableKey },
                            onStart: onStart,
                            onToggleFavorite: onToggleFavorite
                        )

                        if profile.id != profiles.last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct ConnectionProfileRow: View {
    let profile: ConnectionProfile
    let isFavorite: Bool
    let onStart: (ConnectionProfile) -> Void
    let onToggleFavorite: (ConnectionProfile) -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            Button {
                onToggleFavorite(profile)
            } label: {
                Image(systemName: isFavorite ? "star.fill" : "star")
                    .foregroundStyle(isFavorite ? .yellow : .secondary)
                    .frame(width: 18)
            }
            .buttonStyle(.plain)
            .help(isFavorite ? "Remove favorite" : "Add favorite")

            Button {
                onStart(profile)
            } label: {
                HStack(alignment: .center, spacing: 10) {
                    Image(systemName: profile.connectionType.systemImage)
                        .foregroundStyle(.secondary)
                        .frame(width: 20)

                    VStack(alignment: .leading, spacing: 3) {
                        Text(profile.redactedDisplayName)
                            .font(.callout.weight(.semibold))
                            .lineLimit(1)
                        Text(profile.redactedRouteSummary)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()

                    VStack(alignment: .trailing, spacing: 3) {
                        Text(profile.connectionType.title)
                            .font(.callout)
                            .lineLimit(1)
                        Text(":\(profile.port) · \(profile.pqcAlgorithm.standardName)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 9)
    }
}

private struct KPIGrid: View {
    let status: TunnelStatus

    private let columns = [
        GridItem(.adaptive(minimum: 148), spacing: 12)
    ]

    var body: some View {
        LazyVGrid(columns: columns, alignment: .leading, spacing: 12) {
            KPICard(
                title: "Peers",
                value: "\(status.metrics.peerCount)",
                detail: "\(status.metrics.directPeerCount) direct, \(status.metrics.relayPeerCount) relay",
                systemImage: "desktopcomputer.and.arrow.down"
            )
            KPICard(
                title: "Bytes In",
                value: status.metrics.bytesIn.byteCount,
                detail: "Received traffic",
                systemImage: "arrow.down.circle"
            )
            KPICard(
                title: "Bytes Out",
                value: status.metrics.bytesOut.byteCount,
                detail: "Sent traffic",
                systemImage: "arrow.up.circle"
            )
            KPICard(
                title: "Path",
                value: status.pathType.label,
                detail: status.metrics.lastPathProbe?.formatted(date: .omitted, time: .shortened) ?? "No probe yet",
                systemImage: status.pathType.systemImage
            )
            KPICard(
                title: "Replay Drops",
                value: "\(status.metrics.replayDrops)",
                detail: "Rejected frames",
                systemImage: "shield.lefthalf.filled"
            )
            KPICard(
                title: "Routes",
                value: "\(status.protectedRoutes.count)",
                detail: status.routeMode.label,
                systemImage: "lock"
            )
        }
    }
}

private struct KPICard: View {
    let title: String
    let value: String
    let detail: String
    let systemImage: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: systemImage)
                    .foregroundStyle(.secondary)
                    .frame(width: 18)
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }

            Text(value)
                .font(.title3.weight(.semibold).monospacedDigit())
                .lineLimit(1)
                .minimumScaleFactor(0.75)

            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 112, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct RecentSessionsPanel: View {
    let sessions: [RecentSession]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Tunnel Sessions", systemImage: "clock.arrow.circlepath")
                .font(.headline)

            if sessions.isEmpty {
                ContentUnavailableView("No sessions recorded", systemImage: "clock")
                    .frame(maxWidth: .infinity, minHeight: 160)
            } else {
                VStack(spacing: 0) {
                    ForEach(sessions) { session in
                        RecentSessionRow(session: session)
                        if session.id != sessions.last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct RecentSessionRow: View {
    let session: RecentSession

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: session.systemImage)
                .foregroundStyle(session.tint)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 3) {
                Text(session.title)
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                Text("\(session.startedAt.formatted(date: .abbreviated, time: .shortened)) · \(session.duration)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 3) {
                Text(session.path)
                    .font(.callout)
                    .lineLimit(1)
                Text(session.transferred)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 10)
    }
}

private struct RecentSession: Identifiable {
    let id: String
    let title: String
    let startedAt: Date
    let duration: String
    let path: String
    let transferred: String
    let systemImage: String
    let tint: Color

    static func displayList(
        status: TunnelStatus,
        deploymentMode: QuantumLinkDeploymentMode,
        completedSessions: [RecentSession]
    ) -> [RecentSession] {
        let now = Date()
        var sessions = completedSessions

        if status.phase == .connected {
            sessions.insert(
                RecentSession(
                    id: "current",
                    title: "\(deploymentMode.title) session",
                    startedAt: status.metrics.lastPathProbe ?? now,
                    duration: "Active",
                    path: status.pathType.label,
                    transferred: "\(status.metrics.bytesIn.byteCount) in",
                    systemImage: "bolt.horizontal.circle",
                    tint: .green
                ),
                at: 0
            )
        }

        return Array(sessions.prefix(4))
    }

    static func completed(
        status: TunnelStatus,
        deploymentMode: QuantumLinkDeploymentMode,
        endedAt: Date
    ) -> RecentSession {
        let startedAt = status.metrics.lastPathProbe ?? endedAt
        return RecentSession(
            id: "session-\(Int(endedAt.timeIntervalSince1970))",
            title: "\(deploymentMode.title) session",
            startedAt: startedAt,
            duration: endedAt.timeIntervalSince(startedAt).durationLabel,
            path: status.pathType.label,
            transferred: "\(status.metrics.bytesIn.byteCount) in",
            systemImage: "checkmark.circle",
            tint: .green
        )
    }
}

private struct TechnicalInfoPanel: View {
    let status: TunnelStatus
    let configuration: TunnelConfiguration
    let deploymentMode: QuantumLinkDeploymentMode

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Technical Info", systemImage: "info.circle")
                .font(.headline)

            VStack(spacing: 0) {
                InfoRow(label: "Deployment", value: deploymentMode.title)
                InfoRow(label: "Mesh ID", value: configuration.meshID)
                InfoRow(label: "Device", value: configuration.deviceAlias)
                InfoRow(label: "Overlay", value: PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address))
                InfoRow(label: "Remote", value: PrivacyDefaults.redactNetworkIdentifiers(in: configuration.tunnelRemoteAddress))
                InfoRow(label: "MTU", value: "\(configuration.mtu)")
                InfoRow(label: "Discovery", value: configuration.discoveryModes.map(\.label).joined(separator: ", "))
                InfoRow(label: "PQC", value: configuration.crypto.pqcAlgorithm.shortTitle)
                InfoRow(label: "Crypto", value: configuration.crypto.suite)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct ConfigurationPanel: View {
    @Binding var deploymentMode: QuantumLinkDeploymentMode
    @Binding var appearancePreference: AppearancePreference
    @Binding var globalPQCAlgorithm: PQCAlgorithm
    @Binding var onboardingTabVisible: Bool
    let configuration: TunnelConfiguration
    let status: TunnelStatus

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .configuration,
                subtitle: "\(configuration.deviceAlias) · \(configuration.meshID) · \(status.phase.label)"
            )

            PanelGrid {
                ConfigurationCard(title: "Deployment", systemImage: "network") {
                        Picker("Deployment", selection: $deploymentMode) {
                            ForEach(QuantumLinkDeploymentMode.allCases) { mode in
                                Label(mode.title, systemImage: mode.systemImage)
                                    .tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)

                        DeploymentModeSummary(mode: deploymentMode)
                    }

                    ConfigurationCard(title: "Appearance", systemImage: "paintbrush") {
                        Picker("Appearance", selection: $appearancePreference) {
                            ForEach(AppearancePreference.allCases) { preference in
                                Label(preference.title, systemImage: preference.systemImage)
                                    .tag(preference)
                            }
                        }
                        .pickerStyle(.segmented)

                        HStack(spacing: 10) {
                            ForEach(AppearancePreference.allCases) { preference in
                                Label(preference.title, systemImage: preference.systemImage)
                                    .font(.callout)
                                    .foregroundStyle(preference == appearancePreference ? .primary : .secondary)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 7)
                                    .background(
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(preference == appearancePreference ? Color.accentColor.opacity(0.16) : Color.clear)
                                    )
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 8)
                                            .stroke(preference == appearancePreference ? Color.accentColor.opacity(0.35) : Color.secondary.opacity(0.18))
                                    )
                            }
                        }
                    }

                    ConfigurationCard(title: "PQC Default", systemImage: "lock.shield") {
                        Picker("PQC Default", selection: $globalPQCAlgorithm) {
                            ForEach(PQCAlgorithm.allCases) { algorithm in
                                Text(algorithm.shortTitle)
                                    .tag(algorithm)
                            }
                        }
                        .pickerStyle(.segmented)

                        VStack(alignment: .leading, spacing: 8) {
                            Text(globalPQCAlgorithm.title)
                                .font(.callout.weight(.semibold))
                            Text(globalPQCAlgorithm.summary)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            InfoRow(label: "Suite", value: globalPQCAlgorithm.suiteIdentifier)
                        }
                    }

                    ConfigurationCard(title: "Dytallix Identity", systemImage: "person.badge.key") {
                        Picker("Identity", selection: $selectedDytallixIdentityMode) {
                            ForEach(DiscoveryIdentityMode.allCases, id: \.self) { mode in
                                Text(mode.title)
                                    .tag(mode)
                                    .disabled(mode == .off && configuration.dytallixIdentity?.trustPolicy == .publicRequired)
                            }
                        }
                        .pickerStyle(.segmented)
                        .onAppear {
                            let configured = configuration.dytallixIdentity?.mode ?? .off
                            selectedDytallixIdentityMode =
                                configured == .off && configuration.dytallixIdentity?.trustPolicy == .publicRequired
                                ? .verified
                                : configured
                        }
                        .onChange(of: selectedDytallixIdentityMode) { _, newValue in
                            if newValue == .off && configuration.dytallixIdentity?.trustPolicy == .publicRequired {
                                selectedDytallixIdentityMode = .verified
                            }
                        }

                        InfoRow(label: "Policy", value: configuration.dytallixIdentity?.trustPolicy.title ?? "Development Optional")
                        InfoRow(label: "Registry", value: configuration.dytallixIdentity?.registry?.endpoint ?? "Not configured")
                    }

                    ConfigurationCard(title: "Routing", systemImage: "arrow.triangle.branch") {
                        InfoRow(label: "Route Mode", value: configuration.routeMode.label)
                        InfoRow(label: "DNS Mode", value: configuration.dnsMode.label)
                        InfoRow(label: "Protected Routes", value: PrivacyDefaults.redactNetworkIdentifiers(in: configuration.protectedRoutes.joined(separator: ", ")))
                        InfoRow(label: "Excluded Routes", value: configuration.excludedRoutes.isEmpty ? "None" : PrivacyDefaults.redactNetworkIdentifiers(in: configuration.excludedRoutes.joined(separator: ", ")))
                    }

                    ConfigurationCard(title: "Transport", systemImage: "antenna.radiowaves.left.and.right") {
                        InfoRow(label: "Discovery", value: configuration.discoveryModes.map(\.label).joined(separator: ", "))
                        InfoRow(label: "Rendezvous", value: configuration.rendezvousServers.isEmpty ? "Disabled" : PrivacyDefaults.redactNetworkIdentifiers(in: configuration.rendezvousServers.joined(separator: ", ")))
                        InfoRow(label: "Relay", value: configuration.relayServers.isEmpty ? "Disabled" : PrivacyDefaults.redactNetworkIdentifiers(in: configuration.relayServers.joined(separator: ", ")))
                        InfoRow(label: "Current Path", value: status.pathType.label)
                    }

                ConfigurationCard(title: "Workflow", systemImage: "sidebar.left") {
                    Toggle("Show onboarding tab in sidebar", isOn: $onboardingTabVisible)
                        .toggleStyle(.checkbox)

                    Text("Re-enable the onboarding workspace if you want to revisit first-run guidance or walkthrough settings later.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

private struct ConfigurationCard<Content: View>: View {
    let title: String
    let systemImage: String
    let content: Content

    init(title: String, systemImage: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.systemImage = systemImage
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(title, systemImage: systemImage)
                .font(.headline)

            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Unified panel-title row used at the top of every detail panel.
/// Pulls the icon + display name straight off the `SidebarTab` so the
/// panel header always matches whatever's selected in the sidebar.
/// Optional `subtitle` carries the panel's one-line context (mesh ID,
/// device alias, current state) in the same `secondary` style the
/// rest of the app uses. Optional `trailing` slot lets a panel hang
/// action buttons (Refresh, Connect, Disconnect) on the right edge
/// without breaking the title alignment.
private struct PanelHeader<Trailing: View>: View {
    let tab: SidebarTab
    let subtitle: String?
    let trailing: Trailing

    init(
        tab: SidebarTab,
        subtitle: String? = nil,
        @ViewBuilder trailing: () -> Trailing = { EmptyView() }
    ) {
        self.tab = tab
        self.subtitle = subtitle
        self.trailing = trailing()
    }

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: tab.systemImage)
                .font(.title2)
                .foregroundStyle(.tint)
                .frame(width: 28, height: 28, alignment: .center)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(tab.title)
                    .font(.title2.weight(.semibold))
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }

            Spacer()

            trailing
        }
    }
}

/// Wraps every detail panel in the same scroll + spacing chrome so
/// padding, gutters, and panel-title alignment are identical across
/// Network, Peers, Routes, Security, Diagnostics, Configuration.
private struct PanelChrome<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                content
            }
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .padding(.bottom, 8)
        }
    }
}

/// Shared card grid used by every panel that lays out cards. Adaptive
/// columns at 320pt-min keep the layout consistent at every window
/// size; explicit `alignment: .leading` matches the panel header's
/// alignment so card edges line up with the title above.
private struct PanelGrid<Content: View>: View {
    let content: Content

    private let columns = [
        GridItem(.adaptive(minimum: 320), spacing: 16, alignment: .top)
    ]

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        LazyVGrid(columns: columns, alignment: .leading, spacing: 16) {
            content
        }
    }
}

private struct DeploymentModeSummary: View {
    let mode: QuantumLinkDeploymentMode

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: mode.systemImage)
                .font(.title3)
                .foregroundStyle(mode.tint)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 4) {
                Text(mode.title)
                    .font(.callout.weight(.semibold))
                Text(mode.summary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: 118, alignment: .leading)

            Text(value)
                .font(.callout.monospacedDigit())
                .textSelection(.enabled)
                .lineLimit(2)
                .minimumScaleFactor(0.8)

            Spacer(minLength: 0)
        }
        .padding(.vertical, 7)
    }
}

private struct NetworkOverview: View {
    let status: TunnelStatus
    let configuration: TunnelConfiguration
    let deploymentMode: QuantumLinkDeploymentMode

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .network,
                subtitle: "\(configuration.meshID) · \(status.phase.label) · \(status.pathType.label)"
            )

            ConfigurationCard(title: "Status", systemImage: "shield.lefthalf.filled") {
                StatusHeader(status: status)
                Divider()
                KPIGrid(status: status)
            }

            PanelGrid {
                ConfigurationCard(title: "Deployment", systemImage: deploymentMode.systemImage) {
                    DeploymentModeSummary(mode: deploymentMode)
                    InfoRow(label: "Phase", value: status.phase.label)
                    InfoRow(label: "Path", value: status.pathType.label)
                    InfoRow(label: "Route Mode", value: status.routeMode.label)
                    InfoRow(label: "DNS", value: status.dnsMode.label)
                }

                ConfigurationCard(title: "Addressing", systemImage: "number") {
                    InfoRow(label: "Overlay", value: PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address))
                    InfoRow(label: "Remote", value: PrivacyDefaults.redactNetworkIdentifiers(in: configuration.tunnelRemoteAddress))
                    InfoRow(label: "MTU", value: "\(configuration.mtu)")
                    InfoRow(label: "Protected", value: PrivacyDefaults.redactNetworkIdentifiers(in: status.protectedRoutes.joined(separator: ", ")))
                }

                ConfigurationCard(title: "Discovery", systemImage: "antenna.radiowaves.left.and.right") {
                    InfoRow(label: "Modes", value: configuration.discoveryModes.map(\.label).joined(separator: ", "))
                    InfoRow(label: "Rendezvous", value: configuration.rendezvousServers.isEmpty ? "Disabled" : PrivacyDefaults.redactNetworkIdentifiers(in: configuration.rendezvousServers.joined(separator: ", ")))
                    InfoRow(label: "Relay", value: configuration.relayServers.isEmpty ? "Disabled" : PrivacyDefaults.redactNetworkIdentifiers(in: configuration.relayServers.joined(separator: ", ")))
                    InfoRow(label: "Last Probe", value: status.metrics.lastPathProbe?.formatted(date: .abbreviated, time: .shortened) ?? "Never")
                }

                ConfigurationCard(title: "Peer Mix", systemImage: "desktopcomputer.and.arrow.down") {
                    InfoRow(label: "Total", value: "\(status.metrics.peerCount)")
                    InfoRow(label: "Direct", value: "\(status.metrics.directPeerCount)")
                    InfoRow(label: "Relay", value: "\(status.metrics.relayPeerCount)")
                    InfoRow(label: "Replay Drops", value: "\(status.metrics.replayDrops)")
                }
            }
        }
    }
}

private struct RoutesDetail: View {
    let status: TunnelStatus

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .routes,
                subtitle: "\(status.protectedRoutes.count) protected · \(status.routeMode.label)"
            )

            PanelGrid {
                ConfigurationCard(title: "Protected Routes", systemImage: "lock") {
                    if status.protectedRoutes.isEmpty {
                        Text("No protected routes configured.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else {
                        FlowLayout(spacing: 8) {
                            ForEach(status.protectedRoutes, id: \.self) { route in
                                Label(route, systemImage: "lock")
                                    .font(.callout.monospaced())
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 6)
                                    .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 6))
                            }
                        }
                    }
                }

                ConfigurationCard(title: "Route Policy", systemImage: "arrow.triangle.branch") {
                    InfoRow(label: "Route Mode", value: status.routeMode.label)
                    InfoRow(label: "DNS Mode", value: status.dnsMode.label)
                    InfoRow(label: "Overlay", value: PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address))
                }
            }
        }
    }
}

private struct SecurityDetail: View {
    let status: TunnelStatus
    let configuration: TunnelConfiguration

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .security,
                subtitle: "\(configuration.crypto.pqcAlgorithm.title) · \(status.metrics.replayDrops) replay drops"
            )

            PanelGrid {
                ConfigurationCard(title: "Crypto Policy", systemImage: "key.horizontal") {
                        InfoRow(label: "PQC", value: configuration.crypto.pqcAlgorithm.title)
                        InfoRow(label: "Suite", value: configuration.crypto.suite)
                        InfoRow(label: "Rekey Time", value: "\(Int(configuration.crypto.rekeyAfterSeconds)) sec")
                        InfoRow(label: "Rekey Bytes", value: configuration.crypto.rekeyAfterBytes.byteCount)
                        InfoRow(label: "Replay Drops", value: "\(status.metrics.replayDrops)")
                    }

                    ConfigurationCard(title: "Tunnel Policy", systemImage: "lock.shield") {
                        InfoRow(label: "DNS", value: status.dnsMode.label)
                        InfoRow(label: "Route Mode", value: status.routeMode.label)
                        InfoRow(label: "Protected", value: PrivacyDefaults.redactNetworkIdentifiers(in: status.protectedRoutes.joined(separator: ", ")))
                        InfoRow(label: "Excluded", value: configuration.excludedRoutes.isEmpty ? "None" : PrivacyDefaults.redactNetworkIdentifiers(in: configuration.excludedRoutes.joined(separator: ", ")))
                    }

                ConfigurationCard(title: "Peer Keys", systemImage: "person.badge.key") {
                    if status.peers.isEmpty {
                        ContentUnavailableView("No peer keys available", systemImage: "person.badge.key")
                            .frame(maxWidth: .infinity, minHeight: 120)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(status.peers) { peer in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(peer.identity.alias)
                                        .font(.callout.weight(.semibold))
                                    Text(peer.identity.publicKeyFingerprint)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                    Text("Last rekey: \(peer.lastRekey?.formatted(date: .abbreviated, time: .shortened) ?? "Unknown")")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.vertical, 8)

                                if peer.id != status.peers.last?.id {
                                    Divider()
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

private struct DiagnosticsDetail: View {
    let status: TunnelStatus

    var body: some View {
        PanelChrome {
            PanelHeader(
                tab: .diagnostics,
                subtitle: "\(status.phase.label) · \(status.pathType.label) · \(status.metrics.peerCount) peers"
            )

            ConfigurationCard(title: "Status", systemImage: "shield.lefthalf.filled") {
                StatusHeader(status: status)
                Divider()
                MetricsStrip(status: status)
            }

            PanelGrid {
                ConfigurationCard(title: "Session", systemImage: "clock.arrow.circlepath") {
                    InfoRow(label: "Phase", value: status.phase.label)
                    InfoRow(label: "Last Probe", value: lastPathProbe)
                    InfoRow(label: "Replay Drops", value: "\(status.metrics.replayDrops)")
                    InfoRow(label: "Last Error", value: status.lastError.map { PrivacyDefaults.redactNetworkIdentifiers(in: $0) } ?? "None")
                }

                ConfigurationCard(title: "Traffic", systemImage: "arrow.up.arrow.down") {
                    InfoRow(label: "Bytes In", value: status.metrics.bytesIn.byteCount)
                    InfoRow(label: "Bytes Out", value: status.metrics.bytesOut.byteCount)
                }

                ConfigurationCard(title: "Transport", systemImage: "antenna.radiowaves.left.and.right") {
                    InfoRow(label: "Kind", value: transportKind)
                    InfoRow(label: "State", value: transportState)
                    InfoRow(label: "Path", value: transportPath)
                }

                ConfigurationCard(title: "Frames", systemImage: "rectangle.stack") {
                    InfoRow(label: "Sent", value: transportFramesSent)
                    InfoRow(label: "Received", value: transportFramesReceived)
                    InfoRow(label: "Dropped", value: transportFramesDropped)
                }
            }
        }
    }

    private var lastPathProbe: String {
        status.metrics.lastPathProbe?.formatted(date: .abbreviated, time: .standard) ?? "Never"
    }

    private var transportKind: String {
        status.transport?.kind.label ?? "Unavailable"
    }

    private var transportState: String {
        status.transport?.state.label ?? "Unavailable"
    }

    private var transportPath: String {
        status.transport?.pathType.label ?? "Unavailable"
    }

    private var transportFramesSent: String {
        status.transport.map { "\($0.framesSent)" } ?? "0"
    }

    private var transportFramesReceived: String {
        status.transport.map { "\($0.framesReceived)" } ?? "0"
    }

    private var transportFramesDropped: String {
        status.transport.map { "\($0.framesDropped)" } ?? "0"
    }
}

private struct StatusHeader: View {
    let status: TunnelStatus

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: iconName)
                .font(.system(size: 34))
                .foregroundStyle(color)
                .frame(width: 48, height: 48)

            VStack(alignment: .leading, spacing: 6) {
                Text(title)
                    .font(.title2.weight(.semibold))
                Text("Overlay \(PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address)) · \(status.routeMode.label) · DNS \(status.dnsMode.label)")
                    .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 6) {
                Text(status.pathType.label)
                    .font(.headline)
                Text("\(status.metrics.peerCount) peers")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var title: String {
        status.phase.label
    }

    private var iconName: String {
        switch status.phase {
        case .connected: "checkmark.shield"
        case .degraded, .reconnecting: "exclamationmark.shield"
        case .failed: "xmark.shield"
        default: "shield"
        }
    }

    private var color: Color {
        switch status.phase {
        case .connected: .green
        case .degraded, .reconnecting: .orange
        case .failed: .red
        default: .secondary
        }
    }
}

private struct MetricsStrip: View {
    let status: TunnelStatus

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 36, verticalSpacing: 8) {
            GridRow {
                MetricCell(label: "Direct", value: "\(status.metrics.directPeerCount)")
                MetricCell(label: "Relay", value: "\(status.metrics.relayPeerCount)")
                MetricCell(label: "Bytes In", value: status.metrics.bytesIn.byteCount)
                MetricCell(label: "Bytes Out", value: status.metrics.bytesOut.byteCount)
                MetricCell(label: "Replay Drops", value: "\(status.metrics.replayDrops)")
            }
        }
    }
}

private struct MetricCell: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.headline.monospacedDigit())
        }
        .frame(minWidth: 96, alignment: .leading)
    }
}

private struct PeerList: View {
    let peers: [PeerStatus]

    var body: some View {
        PanelChrome {
            PanelHeader(tab: .peers, subtitle: subtitleText)

            ConfigurationCard(title: "Connected Peers", systemImage: "desktopcomputer.and.arrow.down") {
                if peers.isEmpty {
                    ContentUnavailableView("No connected peers", systemImage: "network.slash")
                        .frame(maxWidth: .infinity, minHeight: 160)
                } else {
                    Table(peers) {
                        TableColumn("Alias") { peer in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(peer.identity.alias)
                                    .font(.callout)
                                Text(peer.identity.peerID)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                        }
                        TableColumn("Overlay") { peer in
                            Text(PrivacyDefaults.redactNetworkIdentifiers(in: peer.overlayAddress))
                                .font(.callout.monospaced())
                        }
                        TableColumn("Path") { peer in
                            Label(peer.pathType.label, systemImage: peer.pathType.systemImage)
                                .font(.callout)
                        }
                        TableColumn("RTT") { peer in
                            Text(peer.rttMilliseconds.map { "\($0) ms" } ?? "unknown")
                                .font(.callout.monospacedDigit())
                        }
                        TableColumn("Traffic") { peer in
                            Text("\(peer.bytesIn.byteCount) / \(peer.bytesOut.byteCount)")
                                .font(.callout.monospacedDigit())
                        }
                    }
                    .frame(minHeight: 220)
                }
            }
        }
    }

    private var subtitleText: String {
        peers.isEmpty
            ? "No peers connected"
            : "\(peers.count) connected · \(peers.filter { $0.pathType == .direct }.count) direct"
    }
}

private struct RouteList: View {
    let routes: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Protected Routes")
                .font(.headline)
            FlowLayout(spacing: 8) {
                ForEach(routes, id: \.self) { route in
                    Label(route, systemImage: "lock")
                        .font(.callout.monospaced())
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 6))
                }
            }
        }
    }
}

private struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 600
        var x: CGFloat = 0
        var y: CGFloat = 0
        var lineHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > width, x > 0 {
                x = 0
                y += lineHeight + spacing
                lineHeight = 0
            }
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }

        return CGSize(width: width, height: y + lineHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var lineHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX
                y += lineHeight + spacing
                lineHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }
    }
}

private extension RouteMode {
    var label: String {
        switch self {
        case .splitTunnel: "Split Tunnel"
        case .protectedPrefixesOnly: "Protected Prefixes"
        case .fullTunnel: "Full Tunnel"
        }
    }
}

private extension ConnectionPhase {
    var label: String {
        switch self {
        case .idle: "Ready"
        case .preparing: "Preparing Tunnel"
        case .connecting: "Connecting"
        case .connected: "Connected"
        case .degraded: "Degraded"
        case .reconnecting: "Reconnecting"
        case .disconnected: "Disconnected"
        case .failed: "Failed"
        }
    }
}

private extension DNSMode {
    var label: String {
        switch self {
        case .tunnelProvided: "Tunnel"
        case .system: "System"
        case .disabled: "Disabled"
        }
    }
}

private extension PathType {
    var label: String {
        switch self {
        case .direct: "Direct"
        case .relay: "Relay"
        case .probing: "Probing"
        case .unavailable: "Unavailable"
        }
    }

    var systemImage: String {
        switch self {
        case .direct: "link"
        case .relay: "arrow.triangle.swap"
        case .probing: "antenna.radiowaves.left.and.right"
        case .unavailable: "slash.circle"
        }
    }
}

private extension QuantumLinkDeploymentMode {
    var title: String {
        switch self {
        case .mesh: "Mesh"
        case .direct: "Direct"
        case .localVPN: "Local VPN"
        }
    }

    var summary: String {
        switch self {
        case .mesh:
            "Multi-peer overlay with rendezvous discovery and relay fallback."
        case .direct:
            "Peer-to-peer protected prefixes with relay fallback disabled."
        case .localVPN:
            "Single-device local tunnel with full routing and system DNS."
        }
    }

    var systemImage: String {
        switch self {
        case .mesh: "point.3.connected.trianglepath.dotted"
        case .direct: "link"
        case .localVPN: "network"
        }
    }

    var tint: Color {
        switch self {
        case .mesh: .blue
        case .direct: .green
        case .localVPN: .orange
        }
    }
}

private extension QuantumLinkConnectionType {
    var title: String {
        switch self {
        case .ssh: "SSH"
        case .https: "HTTPS"
        case .rdp: "RDP"
        case .vnc: "VNC"
        case .custom: "Custom"
        }
    }

    var systemImage: String {
        switch self {
        case .ssh: "terminal"
        case .https: "lock.laptopcomputer"
        case .rdp: "display"
        case .vnc: "rectangle.connected.to.line.below"
        case .custom: "slider.horizontal.3"
        }
    }
}

private extension PeerDeviceRole {
    var title: String {
        switch self {
        case .peer: "Peer"
        case .gateway: "Gateway"
        case .rendezvous: "Rendezvous"
        case .relay: "Relay"
        }
    }
}

private extension VNCAuthenticationMode {
    var title: String {
        switch self {
        case .none: "None"
        case .password: "Password"
        case .userPassword: "User + Password"
        }
    }
}

private extension PQCAlgorithm {
    var shortTitle: String {
        "\(standardName) \(algorithmName)"
    }

    var title: String {
        "\(standardName) - \(algorithmName)"
    }

    var summary: String {
        switch self {
        case .fips203:
            "Module-lattice key encapsulation profile for VPN session key establishment."
        case .fips204:
            "Module-lattice digital signature profile for the session crypto policy."
        case .fips205:
            "Stateless hash-based digital signature profile for conservative diversity."
        }
    }
}

private extension DiscoveryMode {
    var label: String {
        switch self {
        case .rendezvous: "Rendezvous"
        case .privateDHT: "Private DHT"
        case .localMDNS: "Local mDNS"
        }
    }
}

private extension MeshTrustPolicy {
    var title: String {
        switch self {
        case .publicRequired: "Public Required"
        case .privatePreferred: "Private Preferred"
        case .developmentOptional: "Development Optional"
        }
    }
}

private extension DiscoveryIdentityMode {
    var title: String {
        switch self {
        case .off: "Off"
        case .verified: "Verified"
        case .publicWallet: "Public Wallet"
        }
    }
}

private extension TunnelTransportKind {
    var label: String {
        switch self {
        case .developmentDrop: "Development Drop"
        case .devQuicLoopback: "Dev QUIC Loopback"
        case .meshQuic: "Mesh QUIC"
        }
    }
}

private extension TunnelTransportState {
    var label: String {
        switch self {
        case .stopped: "Stopped"
        case .ready: "Ready"
        case .failed: "Failed"
        }
    }
}

private extension UInt64 {
    var byteCount: String {
        ByteCountFormatter.string(fromByteCount: Int64(self), countStyle: .binary)
    }
}

private extension TimeInterval {
    var durationLabel: String {
        let totalSeconds = max(Int(self.rounded()), 0)
        let minutes = totalSeconds / 60
        let seconds = totalSeconds % 60

        if minutes > 0 {
            return "\(minutes) min"
        }
        return "\(seconds) sec"
    }
}
