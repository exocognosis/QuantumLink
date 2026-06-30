import AppKit
import QuantumLinkKit
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
  @AppStorage(PreferenceKeys.deploymentMode) private var deploymentModeRaw =
    QuantumLinkDeploymentMode.mesh.rawValue
  @AppStorage(PreferenceKeys.discoveryIdentityMode) private var discoveryIdentityModeRaw =
    DiscoveryIdentityMode.verified.rawValue
  @AppStorage(PreferenceKeys.dytallixEnrollmentSettings) private
    var dytallixEnrollmentSettingsJSON = ""
  @AppStorage(PreferenceKeys.appearance) private var appearanceRaw = AppearancePreference.system
    .rawValue
  @AppStorage(PreferenceKeys.pqcAlgorithm) private var pqcAlgorithmRaw = PQCAlgorithm.fips203
    .rawValue
  @AppStorage(PreferenceKeys.recentConnectionProfiles) private var recentConnectionProfilesJSON = ""
  @AppStorage(PreferenceKeys.favoriteConnectionProfiles) private
    var favoriteConnectionProfilesJSON = ""
  @State private var selectedTab: SidebarTab?
  @State private var hasInitializedSelection = false
  @State private var recentSessions: [RecentSession] = []
  @State private var dytallixEnrollmentInProgress = false
  @State private var dytallixIdentityOperationInProgress: DytallixIdentityOperation?
  @State private var dytallixKeyRotationInProgress = false
  @State private var dytallixLastIdentityError: String?
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
        discoveryIdentityModeBinding: discoveryIdentityModeBinding,
        dytallixEnrollmentSettingsBinding: dytallixEnrollmentSettingsBinding,
        dytallixEnrollmentInProgress: dytallixEnrollmentInProgress,
        dytallixIdentityOperationInProgress: dytallixIdentityOperationInProgress,
        dytallixKeyRotationInProgress: dytallixKeyRotationInProgress,
        dytallixLastIdentityError: dytallixLastIdentityError,
        appearancePreferenceBinding: appearancePreferenceBinding,
        globalPQCAlgorithmBinding: globalPQCAlgorithmBinding,
        onConnect: { Task { await controller.connect() } },
        onDisconnect: { Task { await controller.disconnect() } },
        onRefresh: { Task { await controller.refresh() } },
        onEnrollDytallixIdentity: { enrollDytallixIdentity() },
        onRefreshDytallixIdentityStatus: { runDytallixIdentityCommand(.status) },
        onUpdateDytallixIdentity: { runDytallixIdentityCommand(.update) },
        onRevokeDytallixIdentity: { runDytallixIdentityCommand(.revoke) },
        onRotateDytallixDeviceIdentity: { rotateDytallixDeviceIdentity() },
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
    .onChange(of: discoveryIdentityModeRaw) { _, _ in
      applyStoredConfiguration()
    }
    .onChange(of: dytallixEnrollmentSettingsJSON) { _, _ in
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

  private var discoveryIdentityMode: DiscoveryIdentityMode {
    DiscoveryIdentityMode(rawValue: discoveryIdentityModeRaw) ?? .verified
  }

  private var effectiveDiscoveryIdentityMode: DiscoveryIdentityMode {
    deploymentMode.requiresPublicIdentity && discoveryIdentityMode == .off
      ? .verified
      : discoveryIdentityMode
  }

  private var dytallixEnrollmentSettings: DytallixEnrollmentSettings {
    DytallixEnrollmentSettings(storedJSONString: dytallixEnrollmentSettingsJSON)
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
      set: { newMode in
        deploymentModeRaw = newMode.rawValue
        if newMode.requiresPublicIdentity, discoveryIdentityMode == .off {
          discoveryIdentityModeRaw = DiscoveryIdentityMode.verified.rawValue
        }
      }
    )
  }

  private var discoveryIdentityModeBinding: Binding<DiscoveryIdentityMode> {
    Binding(
      get: { effectiveDiscoveryIdentityMode },
      set: { newMode in
        let guardedMode: DiscoveryIdentityMode =
          deploymentMode.requiresPublicIdentity && newMode == .off ? .verified : newMode
        discoveryIdentityModeRaw = guardedMode.rawValue
      }
    )
  }

  private var dytallixEnrollmentSettingsBinding: Binding<DytallixEnrollmentSettings> {
    Binding(
      get: { dytallixEnrollmentSettings },
      set: { newSettings in
        dytallixEnrollmentSettingsJSON =
          (try? newSettings.storedJSONString()) ?? DytallixEnrollmentSettings.emptyJSONString
      }
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
      !normalizedProfile.destinationIPAddress.isEmpty
    else { return }

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

  private func enrollDytallixIdentity() {
    runDytallixIdentityCommand(.enroll)
  }

  private func runDytallixIdentityCommand(_ operation: DytallixIdentityOperation) {
    guard dytallixIdentityOperationInProgress == nil, !dytallixKeyRotationInProgress else { return }
    let settings = dytallixEnrollmentSettings
    guard settings.runtimeConfiguration(mode: effectiveDiscoveryIdentityMode) != nil else {
      dytallixEnrollmentSettingsBinding.wrappedValue = settings.replacing(status: .failed)
      dytallixLastIdentityError = "Missing Dytallix endpoint or registry contract."
      return
    }
    if operation.requiresRegisteredPeer, settings.registeredPeerID == nil {
      dytallixEnrollmentSettingsBinding.wrappedValue = settings.replacing(status: .notRegistered)
      dytallixLastIdentityError = "No registered peer ID is available for this operation."
      return
    }
    let configuration = controller.configuration
    dytallixEnrollmentInProgress = true
    dytallixIdentityOperationInProgress = operation
    dytallixLastIdentityError = nil
    dytallixEnrollmentSettingsBinding.wrappedValue = settings.replacing(status: .enrolling)

    Task {
      let result = await Task.detached {
        Result {
          try DytallixIdentityProcess.run(
            operation: operation,
            settings: settings,
            configuration: configuration
          )
        }
      }.value
      dytallixEnrollmentInProgress = false
      dytallixIdentityOperationInProgress = nil
      switch result {
      case .success(let output):
        dytallixEnrollmentSettingsBinding.wrappedValue =
          settings.applying(identityCommandOutput: output)
      case .failure(let error):
        dytallixEnrollmentSettingsBinding.wrappedValue = settings.replacing(status: .failed)
        dytallixLastIdentityError = DytallixIdentityFailurePresentation(
          operation: operation,
          commandOutput: error.dytallixCommandOutput
        ).message
      }
    }
  }

  private func rotateDytallixDeviceIdentity() {
    guard !dytallixKeyRotationInProgress, dytallixIdentityOperationInProgress == nil else { return }
    let settings = dytallixEnrollmentSettings
    guard controller.status.phase != .connected else {
      dytallixLastIdentityError = "Disconnect the tunnel before rotating the Dytallix device key."
      return
    }
    guard settings.canRotateDeviceIdentity else {
      dytallixLastIdentityError =
        "Revoke or update the active registry record before rotating the Dytallix device key."
      return
    }

    dytallixKeyRotationInProgress = true
    dytallixLastIdentityError = nil
    Task {
      let result = await Task.detached {
        Result {
          try DytallixIdentityProcess.rotateDeviceIdentity(settings: settings)
        }
      }.value
      dytallixKeyRotationInProgress = false
      switch result {
      case .success(let rotated):
        dytallixEnrollmentSettingsBinding.wrappedValue = rotated
      case .failure:
        dytallixLastIdentityError = "Dytallix device key rotation failed."
      }
    }
  }

  private func normalized(_ profile: ConnectionProfile) -> ConnectionProfile {
    var normalizedProfile = profile
    normalizedProfile.sourceIPAddress = profile.sourceIPAddress.trimmingCharacters(
      in: .whitespacesAndNewlines)
    normalizedProfile.destinationIPAddress = profile.destinationIPAddress.trimmingCharacters(
      in: .whitespacesAndNewlines)
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
      crypto: CryptoPolicy(pqcAlgorithm: pqcAlgorithm),
	      killSwitch: baseConfiguration.killSwitch,
	      meshTrustPolicy: baseConfiguration.meshTrustPolicy,
	      discoveryIdentityMode: effectiveDiscoveryIdentityMode,
      dytallixIdentity: dytallixEnrollmentSettings.runtimeConfiguration(
        mode: effectiveDiscoveryIdentityMode
      )
    )
    baseConfiguration = ManagedConfigurationLoader.currentManagedOverride(
      base: baseConfiguration
    ).configuration
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

extension View {
  @ViewBuilder
  fileprivate func removingWindowToolbarTitle() -> some View {
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
    HStack(spacing: 8) {
      if let logo = AppBrand.logoImage {
        Image(nsImage: logo)
          .resizable()
          .scaledToFit()
          .frame(width: 24, height: 24)
          .clipShape(RoundedRectangle(cornerRadius: 5))
      }

      Text(AppBrand.title)
        .font(.headline.weight(.semibold))
        .lineLimit(1)
        .minimumScaleFactor(0.8)
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
  static let discoveryIdentityMode = "QuantumLink.discoveryIdentityMode"
  static let dytallixEnrollmentSettings = "QuantumLink.dytallixEnrollmentSettings"
  static let appearance = "QuantumLink.appearance"
  static let pqcAlgorithm = "QuantumLink.pqcAlgorithm"
  static let recentConnectionProfiles = "QuantumLink.recentConnectionProfiles"
  static let favoriteConnectionProfiles = "QuantumLink.favoriteConnectionProfiles"
}

private enum DytallixIdentityProcess {
  static func run(
    operation: DytallixIdentityOperation,
    settings: DytallixEnrollmentSettings,
    configuration: TunnelConfiguration
  ) throws -> DytallixIdentityCommandOutput {
    let executableURL = try qlinkctlExecutableURL()
    let keyfile = try deviceSeedURL()
    let runtime = try requireRuntimeConfiguration(settings: settings)
    let pipe = Pipe()
    let process = Process()
    process.executableURL = executableURL
    process.standardOutput = pipe
    process.standardError = pipe
    process.arguments = arguments(
      operation: operation,
      runtime: runtime,
      settings: settings,
      configuration: configuration,
      keyfile: keyfile
    )

    try process.run()
    process.waitUntilExit()

    let output = String(
      data: pipe.fileHandleForReading.readDataToEndOfFile(),
      encoding: .utf8
    ) ?? ""
    guard process.terminationStatus == 0 else {
      throw DytallixEnrollmentProcessError.commandFailed(output)
    }
    return try DytallixIdentityCommandOutput(output: output)
  }

  static func rotateDeviceIdentity(
    settings: DytallixEnrollmentSettings
  ) throws -> DytallixEnrollmentSettings {
    guard settings.canRotateDeviceIdentity else {
      throw DytallixEnrollmentProcessError.activeRegistryRecord
    }
    let keyfile = try deviceSeedURL()
    if FileManager.default.fileExists(atPath: keyfile.path) {
      try FileManager.default.removeItem(at: keyfile)
    }
    return settings.rotatingDeviceIdentity()
  }

  private static func arguments(
    operation: DytallixIdentityOperation,
    runtime: DytallixIdentityConfiguration,
    settings: DytallixEnrollmentSettings,
    configuration: TunnelConfiguration,
    keyfile: URL
  ) -> [String] {
    switch operation {
    case .enroll, .register, .update:
      return writeArguments(
        operation: operation,
        runtime: runtime,
        settings: settings,
        configuration: configuration,
        keyfile: keyfile
      )
    case .revoke:
      guard let peerID = settings.registeredPeerID else { return [] }
      return registryArguments(
        operation: operation,
        runtime: runtime,
        settings: settings
      ) + [
        "--peer-id",
        peerID,
      ]
    case .status:
      guard let peerID = settings.registeredPeerID else { return [] }
      return [
        "identity",
        "status",
        "--endpoint",
        runtime.endpoint,
        "--contract-address",
        runtime.contractAddress,
        "--peer-id",
        peerID,
      ]
    }
  }

  private static func writeArguments(
    operation: DytallixIdentityOperation,
    runtime: DytallixIdentityConfiguration,
    settings: DytallixEnrollmentSettings,
    configuration: TunnelConfiguration,
    keyfile: URL
  ) -> [String] {
    var arguments = [
      "identity",
      operation.rawValue,
      "--endpoint",
      runtime.endpoint,
      "--contract-address",
      runtime.contractAddress,
      "--keyfile",
      keyfile.path,
      "--mesh-id",
      configuration.meshID,
      "--alias",
      configuration.deviceAlias,
      "--address",
      candidateAddress(from: configuration),
      "--port",
      "4433",
      "--route",
      configuration.protectedRoutes.first ?? "\(configuration.overlayIPv4Address)/32",
      "--ttl-seconds",
      "300",
      "--sequence",
      "\(Int(Date().timeIntervalSince1970))",
    ]
    if let walletName = settings.walletName?.trimmingCharacters(in: .whitespacesAndNewlines),
      !walletName.isEmpty
    {
      arguments += ["--wallet-name", walletName]
    }
    return arguments
  }

  private static func registryArguments(
    operation: DytallixIdentityOperation,
    runtime: DytallixIdentityConfiguration,
    settings: DytallixEnrollmentSettings
  ) -> [String] {
    var arguments = [
      "identity",
      operation.rawValue,
      "--endpoint",
      runtime.endpoint,
      "--contract-address",
      runtime.contractAddress,
    ]
    if let walletName = settings.walletName?.trimmingCharacters(in: .whitespacesAndNewlines),
      !walletName.isEmpty
    {
      arguments += ["--wallet-name", walletName]
    }
    return arguments
  }

  private static func candidateAddress(from configuration: TunnelConfiguration) -> String {
    let trimmed = configuration.tunnelRemoteAddress.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return "127.0.0.1" }
    return trimmed.split(separator: ":").first.map(String.init) ?? trimmed
  }

  private static func requireRuntimeConfiguration(
    settings: DytallixEnrollmentSettings
  ) throws -> DytallixIdentityConfiguration {
    guard let runtime = settings.runtimeConfiguration(mode: .verified) else {
      throw DytallixEnrollmentProcessError.missingRegistryConfiguration
    }
    return runtime
  }

  private static func applicationSupportDirectory() throws -> URL {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
      .first ?? FileManager.default.homeDirectoryForCurrentUser
    let directory = base.appendingPathComponent("QuantumLink", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory
  }

  private static func deviceSeedURL() throws -> URL {
    try applicationSupportDirectory().appendingPathComponent("dytallix-device.seed")
  }

  private static func qlinkctlExecutableURL() throws -> URL {
    if let path = ProcessInfo.processInfo.environment["QLINKCTL_PATH"], !path.isEmpty {
      return URL(fileURLWithPath: path)
    }
    if let bundled = Bundle.main.url(forAuxiliaryExecutable: "qlinkctl") {
      return bundled
    }
    for path in [
      "/usr/local/bin/qlinkctl",
      "/opt/homebrew/bin/qlinkctl",
      FileManager.default.currentDirectoryPath + "/target/debug/qlinkctl",
    ] where FileManager.default.isExecutableFile(atPath: path) {
      return URL(fileURLWithPath: path)
    }
    throw DytallixEnrollmentProcessError.qlinkctlNotFound
  }
}

private enum DytallixEnrollmentProcessError: Error {
  case missingRegistryConfiguration
  case qlinkctlNotFound
  case commandFailed(String)
  case activeRegistryRecord
}

extension Error {
  fileprivate var dytallixCommandOutput: String? {
    guard
      let processError = self as? DytallixEnrollmentProcessError,
      case .commandFailed(let output) = processError
    else {
      return nil
    }
    return output
  }
}

extension DytallixIdentityOperation {
  fileprivate var requiresRegisteredPeer: Bool {
    switch self {
    case .enroll, .register:
      false
    case .update, .revoke, .status:
      true
    }
  }

  fileprivate var inProgressLabel: String {
    switch self {
    case .enroll, .register:
      "Registering"
    case .update:
      "Updating Registry"
    case .revoke:
      "Revoking Identity"
    case .status:
      "Refreshing Status"
    }
  }

  fileprivate var failureLabel: String {
    switch self {
    case .enroll, .register:
      "Identity registration failed."
    case .update:
      "Registry update failed."
    case .revoke:
      "Identity revocation failed."
    case .status:
      "Identity status refresh failed."
    }
  }
}

private enum DytallixLinks {
  static let wallet = URL(string: "https://dytallix.com/build/wallet")!
  static let faucet = DytallixWalletReadinessPresentation.walletFaucetURL
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
  let discoveryIdentityModeBinding: Binding<DiscoveryIdentityMode>
  let dytallixEnrollmentSettingsBinding: Binding<DytallixEnrollmentSettings>
  let dytallixEnrollmentInProgress: Bool
  let dytallixIdentityOperationInProgress: DytallixIdentityOperation?
  let dytallixKeyRotationInProgress: Bool
  let dytallixLastIdentityError: String?
  let appearancePreferenceBinding: Binding<AppearancePreference>
  let globalPQCAlgorithmBinding: Binding<PQCAlgorithm>
  let onConnect: () -> Void
  let onDisconnect: () -> Void
  let onRefresh: () -> Void
  let onEnrollDytallixIdentity: () -> Void
  let onRefreshDytallixIdentityStatus: () -> Void
  let onUpdateDytallixIdentity: () -> Void
  let onRevokeDytallixIdentity: () -> Void
  let onRotateDytallixDeviceIdentity: () -> Void
  let onStartConnection: (ConnectionProfile) -> Void
  let onToggleFavoriteConnection: (ConnectionProfile) -> Void

  var body: some View {
    Group {
      switch tab {
      case .onboarding:
        OnboardingPanel(
          deploymentMode: deploymentModeBinding,
          discoveryIdentityMode: discoveryIdentityModeBinding,
          dytallixEnrollmentSettings: dytallixEnrollmentSettingsBinding,
          dytallixEnrollmentInProgress: dytallixEnrollmentInProgress,
          dytallixIdentityOperationInProgress: dytallixIdentityOperationInProgress,
          dytallixKeyRotationInProgress: dytallixKeyRotationInProgress,
          appearancePreference: appearancePreferenceBinding,
          globalPQCAlgorithm: globalPQCAlgorithmBinding,
          onboardingTabVisible: onboardingTabVisibleBinding,
          configuration: configuration,
          status: status,
          onEnrollDytallixIdentity: onEnrollDytallixIdentity,
          onUpdateDytallixIdentity: onUpdateDytallixIdentity,
          onRotateDytallixDeviceIdentity: onRotateDytallixDeviceIdentity
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
          configuration: configuration,
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
        NetworkOverview(
          status: status, configuration: configuration, deploymentMode: deploymentMode)
      case .peers:
        PeerList(status: status)
      case .routes:
        RoutesDetail(status: status)
      case .security:
        SecurityDetail(
          status: status,
          configuration: configuration,
          dytallixEnrollmentSettings: dytallixEnrollmentSettingsBinding.wrappedValue
        )
      case .diagnostics:
        DiagnosticsDetail(
          status: status,
          configuration: configuration,
          dytallixEnrollmentSettings: dytallixEnrollmentSettingsBinding.wrappedValue,
          dytallixLastIdentityError: dytallixLastIdentityError
        )
      case .configuration:
        ConfigurationPanel(
          deploymentMode: deploymentModeBinding,
          discoveryIdentityMode: discoveryIdentityModeBinding,
          dytallixEnrollmentSettings: dytallixEnrollmentSettingsBinding,
          dytallixEnrollmentInProgress: dytallixEnrollmentInProgress,
          dytallixIdentityOperationInProgress: dytallixIdentityOperationInProgress,
          dytallixKeyRotationInProgress: dytallixKeyRotationInProgress,
          dytallixLastIdentityError: dytallixLastIdentityError,
          appearancePreference: appearancePreferenceBinding,
          globalPQCAlgorithm: globalPQCAlgorithmBinding,
          onboardingTabVisible: onboardingTabVisibleBinding,
          configuration: configuration,
          status: status,
          onEnrollDytallixIdentity: onEnrollDytallixIdentity,
          onRefreshDytallixIdentityStatus: onRefreshDytallixIdentityStatus,
          onUpdateDytallixIdentity: onUpdateDytallixIdentity,
          onRevokeDytallixIdentity: onRevokeDytallixIdentity,
          onRotateDytallixDeviceIdentity: onRotateDytallixDeviceIdentity
        )
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
  }
}

private struct OnboardingPanel: View {
  @Binding var deploymentMode: QuantumLinkDeploymentMode
  @Binding var discoveryIdentityMode: DiscoveryIdentityMode
  @Binding var dytallixEnrollmentSettings: DytallixEnrollmentSettings
  let dytallixEnrollmentInProgress: Bool
  let dytallixIdentityOperationInProgress: DytallixIdentityOperation?
  let dytallixKeyRotationInProgress: Bool
  @Binding var appearancePreference: AppearancePreference
  @Binding var globalPQCAlgorithm: PQCAlgorithm
  @Binding var onboardingTabVisible: Bool
  let configuration: TunnelConfiguration
  let status: TunnelStatus
  let onEnrollDytallixIdentity: () -> Void
  let onUpdateDytallixIdentity: () -> Void
  let onRotateDytallixDeviceIdentity: () -> Void

  var body: some View {
    PanelChrome {
      PanelHeader(
        tab: .onboarding,
        subtitle:
          "Choose deployment defaults, verify Dytallix registry identity, and confirm you are ready to send your first post-quantum protected session."
      )

      ConfigurationCard(title: "Welcome to QuantumLink", systemImage: "sparkles.rectangle.stack") {
        HStack(spacing: 10) {
          OnboardingBadge(title: deploymentMode.title, systemImage: deploymentMode.systemImage)
          OnboardingBadge(title: globalPQCAlgorithm.shortTitle, systemImage: "lock.shield")
          OnboardingBadge(
            title: status.phase.label,
            systemImage: status.phase == .connected ? "checkmark.circle" : "shield")
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

        ConfigurationCard(title: "Party Mesh", systemImage: "gamecontroller") {
          Text(
            "Create an invite-based mesh for game sessions. Party Mesh uses the same verified Dytallix identity policy as public mesh mode and keeps direct paths preferred with relay fallback available."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)

          Button {
            deploymentMode = .partyMesh
            discoveryIdentityMode = .verified
          } label: {
            Label("Use Party Mesh", systemImage: "gamecontroller")
          }
          .buttonStyle(.borderedProminent)
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

          Text(
            "Your current baseline is \(appearancePreference.title) appearance with \(globalPQCAlgorithm.title) as the default cryptographic profile for new sessions."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        }

        ConfigurationCard(title: "Validate Tunnel Identity", systemImage: "person.text.rectangle") {
          InfoRow(label: "Device", value: configuration.deviceAlias)
          InfoRow(label: "Mesh ID", value: configuration.meshID)
          InfoRow(
            label: "Overlay",
            value: PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address))
          InfoRow(
            label: "Remote",
            value: PrivacyDefaults.redactNetworkIdentifiers(in: configuration.tunnelRemoteAddress))
        }

        ConfigurationCard(
          title: "Blockchain Identity",
          systemImage: "person.badge.shield.checkmark"
        ) {
          Picker("Discovery Identity", selection: $discoveryIdentityMode) {
            ForEach(DiscoveryIdentityMode.allCases, id: \.self) { mode in
              Label(mode.onboardingTitle, systemImage: mode.systemImage)
                .tag(mode)
            }
          }
          .pickerStyle(.segmented)

          IdentityModeSummary(mode: discoveryIdentityMode)

          InfoRow(label: "Policy", value: configuration.meshTrustPolicy.label)
          InfoRow(label: "Registry", value: registryStatusLabel)
          InfoRow(label: "Enrollment", value: dytallixEnrollmentSettings.status.label)
          InfoRow(label: "Wallet", value: walletPresentation.status)
          if let peerID = dytallixEnrollmentSettings.registeredPeerID {
            InfoRow(label: "Peer ID", value: peerID)
          }

          HStack(spacing: 10) {
            Link(destination: DytallixLinks.faucet) {
              Label(walletPresentation.actionTitle, systemImage: "wallet.pass")
            }
            .buttonStyle(.bordered)

            Button {
              primaryIdentityAction()
            } label: {
              Label(
                dytallixIdentityOperationInProgress?.inProgressLabel ?? identityActionTitle,
                systemImage: dytallixIdentityOperationInProgress == nil
                  ? identityActionSystemImage
                  : "clock.arrow.circlepath"
              )
            }
            .buttonStyle(.borderedProminent)
            .disabled(identityActionDisabled)
          }

          if discoveryIdentityMode == .off {
            Text("Enable Verified Registry or Public Wallet mode before registering identity.")
              .font(.callout)
              .foregroundStyle(.secondary)
              .fixedSize(horizontal: false, vertical: true)
          } else if walletPresentation.state == .unavailable {
            Text(walletPresentation.detail)
              .font(.callout)
              .foregroundStyle(.secondary)
              .fixedSize(horizontal: false, vertical: true)
          }

          VStack(alignment: .leading, spacing: 4) {
            Label("Device Key", systemImage: "key")
              .font(.callout.weight(.semibold))
            Text(
              "Rotate the device key only after updating or revoking the current registry record so peers do not trust stale identity data."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            Button {
              onRotateDytallixDeviceIdentity()
            } label: {
              Label(
                dytallixKeyRotationInProgress ? "Rotating Device Key" : "Rotate Device Key",
                systemImage: dytallixKeyRotationInProgress
                  ? "clock.arrow.circlepath"
                  : "key.viewfinder"
              )
            }
            .buttonStyle(.bordered)
            .disabled(deviceKeyRotationDisabled)
          }
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
            title: "Identity mode selected",
            detail: discoveryIdentityMode.summary,
            isComplete: true
          )
          OnboardingStepRow(
            title: "Dytallix registry configured",
            detail: registryChecklistDetail,
            isComplete: registryConfigured
          )
          OnboardingStepRow(
            title: "Wallet ready",
            detail: walletChecklistDetail,
            isComplete: walletReady
          )
          OnboardingStepRow(
            title: "Device identity registered",
            detail: identityRegistrationDetail,
            isComplete: identityRegistered
          )
          OnboardingStepRow(
            title: "Overlay identity available",
            detail: status.overlayIPv4Address.isEmpty
              ? "QuantumLink will populate this after configuration is loaded."
              : PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address),
            isComplete: !status.overlayIPv4Address.isEmpty
          )
          OnboardingStepRow(
            title: "Ready to start first connection",
            detail: status.phase == .connected
              ? "Tunnel is already active. You can move straight to Home or Connections."
              : firstConnectionChecklistDetail,
            isComplete: status.phase == .connected
          )
        }
      }

      ConfigurationCard(title: "Completion", systemImage: "sidebar.left") {
        Toggle("Remove Onboarding Tab", isOn: removeOnboardingBinding)
          .toggleStyle(.checkbox)

        Text(
          "Hide this tab after your initial setup is complete. You can restore it at any time from Configuration."
        )
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

  private var registryConfiguration: DytallixIdentityConfiguration? {
    dytallixEnrollmentSettings.runtimeConfiguration(mode: discoveryIdentityMode)
  }

  private var identityRequiresRegistry: Bool {
    discoveryIdentityMode != .off
  }

  private var registryConfigured: Bool {
    !identityRequiresRegistry || registryConfiguration != nil
  }

  private var walletReady: Bool {
    !identityRequiresRegistry || dytallixEnrollmentSettings.walletAddress != nil
  }

  private var walletPresentation: DytallixWalletReadinessPresentation {
    DytallixWalletReadinessPresentation(
      settings: dytallixEnrollmentSettings,
      mode: discoveryIdentityMode
    )
  }

  private var identityRegistered: Bool {
    !identityRequiresRegistry || dytallixEnrollmentSettings.status == .registered
  }

  private var identityActionTitle: String {
    dytallixEnrollmentSettings.status == .registered
      ? "Update Registry Record"
      : "Register Identity"
  }

  private var identityActionSystemImage: String {
    dytallixEnrollmentSettings.status == .registered
      ? "arrow.triangle.2.circlepath"
      : "link.badge.plus"
  }

  private var identityActionDisabled: Bool {
    dytallixIdentityOperationInProgress != nil
      || dytallixKeyRotationInProgress
      || !identityRequiresRegistry
      || registryConfiguration == nil
  }

  private var deviceKeyRotationDisabled: Bool {
    dytallixKeyRotationInProgress
      || dytallixIdentityOperationInProgress != nil
      || dytallixEnrollmentSettings.rotationBlockedByActiveRegistryRecord
      || status.phase == .connected
  }

  private func primaryIdentityAction() {
    if dytallixEnrollmentSettings.status == .registered {
      onUpdateDytallixIdentity()
    } else {
      onEnrollDytallixIdentity()
    }
  }

  private var registryStatusLabel: String {
    if !identityRequiresRegistry {
      return "Disabled for private/dev mesh"
    }
    return registryConfiguration == nil ? "Missing endpoint or contract" : "Configured"
  }

  private var registryChecklistDetail: String {
    if !identityRequiresRegistry {
      return "Private and development meshes can keep Dytallix publishing off."
    }
    return registryConfiguration == nil
      ? "Add a Dytallix endpoint and registry contract in Configuration."
      : "Endpoint and registry contract are available for enrollment."
  }

  private var walletChecklistDetail: String {
    if !identityRequiresRegistry {
      return "No wallet is needed while identity publishing is disabled."
    }
    guard walletPresentation.state != .unavailable else {
      return walletPresentation.detail
    }
    return walletPresentation.detail
  }

  private var identityRegistrationDetail: String {
    if !identityRequiresRegistry {
      return "Registry enrollment is optional for this mesh."
    }
    if let peerID = dytallixEnrollmentSettings.registeredPeerID {
      return "Registered peer \(peerID)"
    }
    return "Run Register Identity after the wallet and registry settings are ready."
  }

  private var firstConnectionChecklistDetail: String {
    if identityRequiresRegistry {
      return "Public/interoperable meshes accept discovery only after this device has an active registry identity."
    }
    return "After confirming a destination IP and port in Home or Connections, start your first session."
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
        subtitle:
          "\(status.phase.label) · \(deploymentMode.title) · \(status.routeMode.label) · DNS \(status.dnsMode.label)"
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
        configuration: configuration,
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
  let configuration: TunnelConfiguration
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
        configuration: configuration,
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
        subtitle:
          "\(status.metrics.bytesIn.byteCount) in · \(status.metrics.bytesOut.byteCount) out · \(status.metrics.replayDrops) replay drops"
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
        Text(
          "\(status.phase.label) · \(deploymentMode.title) · \(status.routeMode.label) · DNS \(status.dnsMode.label)"
        )
        .foregroundStyle(.secondary)
        .lineLimit(2)
      }

      Spacer(minLength: 16)

      HStack(spacing: 8) {
        Button(action: onRefresh) {
          Label("Refresh", systemImage: "arrow.clockwise")
        }

        Button(action: status.phase == .connected ? onDisconnect : onConnect) {
          Label(
            status.phase == .connected ? "Disconnect" : "Connect",
            systemImage: status.phase == .connected ? "power" : "bolt.horizontal.circle")
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
  @State private var partyInviteCode = ""
  @State private var partyJoinCode = ""
  @State private var partyJoinMessage: String?
  let recentProfiles: [ConnectionProfile]
  let favoriteProfiles: [ConnectionProfile]
  let configuration: TunnelConfiguration
  let overlayAddress: String
  let onStart: (ConnectionProfile) -> Void
  let onToggleFavorite: (ConnectionProfile) -> Void

  private var isFavorite: Bool {
    favoriteProfiles.contains { $0.stableKey == draft.stableKey }
  }

  private var canStart: Bool {
    !draft.sourceIPAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      && !draft.destinationIPAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
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
          LabeledContent("Source IP") {
            TextField(overlayAddress, text: $draft.sourceIPAddress)
              .textFieldStyle(.roundedBorder)
          }
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
        }

        GridRow {
          LabeledContent("Destination IP") {
            TextField("100.64.10.10", text: $draft.destinationIPAddress)
              .textFieldStyle(.roundedBorder)
          }
          LabeledContent("Port") {
            TextField("Port", text: portBinding)
              .textFieldStyle(.roundedBorder)
              .frame(width: 96)
          }
        }

        GridRow {
          LabeledContent("Create Party") {
            HStack(spacing: 8) {
              Button {
                createPartyInvite()
              } label: {
                Label("Create Code", systemImage: "gamecontroller")
              }
              .buttonStyle(.bordered)

              Button {
                copyPartyInvite()
              } label: {
                Image(systemName: "doc.on.doc")
              }
              .help("Copy party code")
              .disabled(partyInviteCode.isEmpty)
            }
          }

          LabeledContent("Join Party") {
            HStack(spacing: 8) {
              TextField("QLP1-...", text: $partyJoinCode)
                .textFieldStyle(.roundedBorder)
                .font(.system(.caption, design: .monospaced))
              Button {
                joinPartyInvite()
              } label: {
                Label("Join", systemImage: "arrow.down.forward.and.arrow.up.backward")
              }
              .buttonStyle(.bordered)
              .disabled(partyJoinCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
          }
        }

        if !partyInviteCode.isEmpty || partyJoinMessage != nil {
          GridRow {
            Color.clear
            VStack(alignment: .leading, spacing: 6) {
              if !partyInviteCode.isEmpty {
                Text(partyInviteCode)
                  .font(.system(.caption, design: .monospaced))
                  .foregroundStyle(.secondary)
                  .lineLimit(2)
                  .textSelection(.enabled)
              }
              if let partyJoinMessage {
                Text(partyJoinMessage)
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  .fixedSize(horizontal: false, vertical: true)
              }
            }
          }
        }

        GridRow {
          Color.clear
          Button {
            onStart(draft)
          } label: {
            Label("Connect", systemImage: "bolt.horizontal.circle")
              .frame(maxWidth: .infinity)
          }
          .buttonStyle(.borderedProminent)
          .disabled(!canStart)
        }
      }

      LazyVGrid(
        columns: [GridItem(.adaptive(minimum: 300), spacing: 12)], alignment: .leading, spacing: 12
      ) {
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

  private var portBinding: Binding<String> {
    Binding(
      get: { draft.port > 0 ? "\(draft.port)" : "" },
      set: { value in
        let digits = value.filter(\.isNumber)
        draft.port = Int(digits) ?? 0
      }
    )
  }

  private func createPartyInvite() {
    let invite = PartyMeshInvite(
      configuration: deploymentMode.configuration(from: configuration),
      gamePort: draft.port > 0 ? draft.port : 27015
    )
    partyInviteCode = (try? invite.joinCode()) ?? ""
    partyJoinMessage = partyInviteCode.isEmpty
      ? "Party code could not be created from the current configuration."
      : "\(invite.trustSummary). \(invite.pathSummary)."
    deploymentMode = .partyMesh
  }

  private func copyPartyInvite() {
    guard !partyInviteCode.isEmpty else { return }
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(partyInviteCode, forType: .string)
  }

  private func joinPartyInvite() {
    do {
      let invite = try PartyMeshInvite(joinCode: partyJoinCode)
      deploymentMode = .partyMesh
      draft.name = invite.meshID
      draft.destinationIPAddress = invite.hostOverlayAddress
      draft.connectionType = .custom
      draft.port = invite.gamePort
      partyJoinMessage = "\(invite.hostAlias) · \(invite.trustSummary). \(invite.pathSummary)."
    } catch {
      partyJoinMessage = "Party code is not valid."
    }
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

  private var peerMixDetail: String {
    status.metrics.peerCount == 0
      ? "Path telemetry pending"
      : "\(status.metrics.directPeerCount) direct, \(status.metrics.relayPeerCount) relay"
  }

  private var latencyValue: String {
    let rtts = status.peers.compactMap(\.rttMilliseconds)
    guard !rtts.isEmpty else { return "Pending" }
    return "\(rtts.reduce(0, +) / rtts.count) ms"
  }

  var body: some View {
    LazyVGrid(columns: columns, alignment: .leading, spacing: 12) {
      KPICard(
        title: "Peers",
        value: "\(status.metrics.peerCount)",
        detail: peerMixDetail,
        systemImage: "desktopcomputer.and.arrow.down"
      )
      KPICard(
        title: "Latency",
        value: latencyValue,
        detail: status.peers.contains { $0.rttMilliseconds != nil } ? "Average peer RTT" : "RTT not reported",
        systemImage: "speedometer"
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
        detail: status.metrics.lastPathProbe?.formatted(date: .omitted, time: .shortened)
          ?? "No probe yet",
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
        Text(
          "\(session.startedAt.formatted(date: .abbreviated, time: .shortened)) · \(session.duration)"
        )
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
        InfoRow(
          label: "Overlay",
          value: PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address))
        InfoRow(
          label: "Remote",
          value: PrivacyDefaults.redactNetworkIdentifiers(in: configuration.tunnelRemoteAddress))
        InfoRow(label: "MTU", value: "\(configuration.mtu)")
        InfoRow(
          label: "Discovery",
          value: configuration.discoveryModes.map(\.label).joined(separator: ", "))
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
  @Binding var discoveryIdentityMode: DiscoveryIdentityMode
  @Binding var dytallixEnrollmentSettings: DytallixEnrollmentSettings
  let dytallixEnrollmentInProgress: Bool
  let dytallixIdentityOperationInProgress: DytallixIdentityOperation?
  let dytallixKeyRotationInProgress: Bool
  let dytallixLastIdentityError: String?
  @Binding var appearancePreference: AppearancePreference
  @Binding var globalPQCAlgorithm: PQCAlgorithm
  @Binding var onboardingTabVisible: Bool
  let configuration: TunnelConfiguration
  let status: TunnelStatus
  let onEnrollDytallixIdentity: () -> Void
  let onRefreshDytallixIdentityStatus: () -> Void
  let onUpdateDytallixIdentity: () -> Void
  let onRevokeDytallixIdentity: () -> Void
  let onRotateDytallixDeviceIdentity: () -> Void

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

        ConfigurationCard(title: "Party Mesh", systemImage: "gamecontroller") {
          Text(
            "Party Mesh is the gamer-facing public mesh profile: create a party code, share it out of band, and require verified Dytallix identity before peers are accepted."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)

          KnowledgeRow(title: "Invite", detail: "Create Code packages the mesh ID, host overlay address, rendezvous endpoints, relay endpoints, game port, and trust mode.")
          KnowledgeRow(title: "Join", detail: "Join parses a Party Mesh code and fills the host overlay address and game port in the connection launcher.")
          KnowledgeRow(title: "Telemetry", detail: "Latency and direct/relay status display only after the transport reports real peer path data.")
        }

        ConfigurationCard(
          title: "Dytallix Identity Registry",
          systemImage: "person.badge.shield.checkmark"
        ) {
          Picker("Discovery Identity", selection: $discoveryIdentityMode) {
            ForEach(DiscoveryIdentityMode.allCases, id: \.self) { mode in
              Label(mode.title, systemImage: mode.systemImage)
                .tag(mode)
            }
          }
          .pickerStyle(.segmented)

          Text(
            "Choose how this device interoperates with Dytallix blockchain identity. Verified mode proves registry membership without exposing wallet details; Public Wallet also displays the registered wallet address."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)

          VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 12) {
              Image(systemName: configuration.discoveryIdentityMode.systemImage)
                .font(.title3)
                .foregroundStyle(.tint)
                .frame(width: 28)

              VStack(alignment: .leading, spacing: 4) {
                Text(configuration.discoveryIdentityMode.title)
                  .font(.callout.weight(.semibold))
                Text(discoveryIdentityPresentation.summary)
                  .font(.callout)
                  .foregroundStyle(.secondary)
                  .fixedSize(horizontal: false, vertical: true)
              }
            }

            InfoRow(label: "Trust", value: configuration.meshTrustPolicy.label)
            InfoRow(
              label: discoveryIdentityPresentation.rowLabel,
              value: discoveryIdentityPresentation.status
            )
            InfoRow(label: "Peer ID", value: dytallixEnrollmentSettings.registeredPeerID ?? "Not registered")
            InfoRow(label: "Registry", value: registryConfiguration == nil ? "Missing endpoint or contract" : "Configured")
            InfoRow(label: "Enrollment", value: dytallixEnrollmentSettings.status.label)
            InfoRow(label: "Wallet Status", value: walletPresentation.status)
            if let walletAddress = dytallixEnrollmentSettings.walletAddress,
              configuration.discoveryIdentityMode == .publicWallet
            {
              InfoRow(label: "Wallet", value: walletAddress)
            }

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
              GridRow {
                Text("Endpoint")
                  .foregroundStyle(.secondary)
                TextField("https://dytallix.example", text: dytallixEndpointBinding)
                  .textFieldStyle(.roundedBorder)
              }
              GridRow {
                Text("Contract")
                  .foregroundStyle(.secondary)
                TextField("0x...", text: dytallixContractBinding)
                  .textFieldStyle(.roundedBorder)
              }
              GridRow {
                Text("Wallet")
                  .foregroundStyle(.secondary)
                HStack(spacing: 8) {
                  TextField("quantumlink", text: dytallixWalletNameBinding)
                    .textFieldStyle(.roundedBorder)
                  Link(destination: DytallixLinks.faucet) {
                    Label(walletPresentation.actionTitle, systemImage: "wallet.pass")
                  }
                }
              }
            }

            if configuration.discoveryIdentityMode != .off
              && walletPresentation.state == .unavailable
            {
              Text(walletPresentation.detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: 8) {
              Button {
                primaryIdentityAction()
              } label: {
                Label(
                  dytallixIdentityOperationInProgress?.inProgressLabel ?? identityActionTitle,
                  systemImage: dytallixIdentityOperationInProgress == nil
                    ? identityActionSystemImage : "clock.arrow.circlepath"
                )
              }
              .buttonStyle(.borderedProminent)
              .disabled(identityActionsDisabled)

              Button {
                onRefreshDytallixIdentityStatus()
              } label: {
                Label("Refresh Status", systemImage: "arrow.clockwise")
              }
              .disabled(identityActionsDisabled || dytallixEnrollmentSettings.registeredPeerID == nil)

              Button(role: .destructive) {
                onRevokeDytallixIdentity()
              } label: {
                Label("Revoke", systemImage: "xmark.shield")
              }
              .disabled(
                identityActionsDisabled
                  || dytallixEnrollmentSettings.status != .registered
                  || dytallixEnrollmentSettings.registeredPeerID == nil
              )
            }

            if let dytallixLastIdentityError {
              Label(dytallixLastIdentityError, systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            } else if configuration.discoveryIdentityMode == .off {
              Text("Identity publishing is off. Enable Verified or Public Wallet mode before using registry actions.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            VStack(alignment: .leading, spacing: 4) {
              Label("Device Key", systemImage: "key")
                .font(.callout.weight(.semibold))
              Text(
                "Rotating the device key creates a new peer identity. Update or revoke the existing registry record before rotating so other peers do not trust stale identity data."
              )
              .font(.callout)
              .foregroundStyle(.secondary)
              .fixedSize(horizontal: false, vertical: true)
              Button {
                onRotateDytallixDeviceIdentity()
              } label: {
                Label(
                  dytallixKeyRotationInProgress ? "Rotating Device Key" : "Rotate Device Key",
                  systemImage: dytallixKeyRotationInProgress
                    ? "clock.arrow.circlepath"
                    : "key.viewfinder"
                )
              }
              .buttonStyle(.bordered)
              .disabled(deviceKeyRotationDisabled)
            }
          }
        }

        ConfigurationCard(title: "Dytallix Interoperability", systemImage: "link.badge.plus") {
          Text(
            "QuantumLink can publish a signed peer record to the Dytallix registry so other Dytallix-aware meshes can verify this device before accepting discovery candidates."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)

          KnowledgeRow(
            title: "Verified",
            detail: "Peers verify registry records while wallet details stay hidden."
          )
          KnowledgeRow(
            title: "Public Wallet",
            detail: "Peers verify the registry record and can see the configured wallet address."
          )
          KnowledgeRow(
            title: "Wallet/Faucet",
            detail: "Open the Dytallix wallet page when the local wallet is missing or a registry transaction needs testnet funds."
          )
          KnowledgeRow(
            title: "Off",
            detail: "Use only for private or development meshes that do not require public identity."
          )
        }

        ConfigurationCard(title: "Enrollment Checklist", systemImage: "checklist") {
          Text(
            "To enroll this device, provide a Dytallix endpoint and registry contract, choose a wallet name, then register the identity."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)

          KnowledgeRow(title: "Endpoint", detail: "RPC or service URL for the Dytallix registry.")
          KnowledgeRow(title: "Contract", detail: "Registry contract address used for peer records.")
          KnowledgeRow(title: "Wallet", detail: "Dytallix wallet name resolved by the local CLI.")
          KnowledgeRow(title: "Faucet", detail: "Use the Dytallix wallet/faucet page if enrollment fails because the wallet needs testnet funds.")
          KnowledgeRow(title: "Key Rotation", detail: "Update or revoke the active registry record before rotating this device key.")
          KnowledgeRow(title: "Result", detail: "Registered peer ID and wallet address returned by enrollment.")
        }

        ConfigurationCard(title: "Privacy Boundary", systemImage: "hand.raised") {
          Text(
            "QuantumLink stores non-secret enrollment settings in the app. Wallet private keys and Dytallix keystore paths stay outside UserDefaults, TunnelConfiguration, and NetworkExtension provider configuration."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)

          KnowledgeRow(title: "Stored", detail: "Endpoint, contract, wallet name, wallet address, peer ID, and enrollment status.")
          KnowledgeRow(title: "Not Stored", detail: "Wallet private keys, passphrases, and local keystore paths.")
          KnowledgeRow(title: "Public Wallet", detail: "Only enable when the mesh should publish wallet identity for discovery.")
        }

        ConfigurationCard(title: "Registry Troubleshooting", systemImage: "wrench.and.screwdriver") {
          KnowledgeRow(title: "Wallet Needed", detail: "Open Wallet/Faucet, create or unlock a Dytallix wallet, then retry registration.")
          KnowledgeRow(title: "Transaction Fails", detail: "Use Wallet/Faucet to check testnet funds, faucet cooldown, or wallet availability.")
          KnowledgeRow(title: "Already Registered", detail: "Use Update Registry Record for the same device, or revoke before rotating the device key.")
          KnowledgeRow(title: "Peer Blocked", detail: "Security and Peers show exact registry states such as missing, revoked, expired, suspended, or binding mismatch.")
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
                    .fill(
                      preference == appearancePreference
                        ? Color.accentColor.opacity(0.16) : Color.clear)
                )
                .overlay(
                  RoundedRectangle(cornerRadius: 8)
                    .stroke(
                      preference == appearancePreference
                        ? Color.accentColor.opacity(0.35) : Color.secondary.opacity(0.18))
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

        ConfigurationCard(title: "Routing", systemImage: "arrow.triangle.branch") {
          InfoRow(label: "Route Mode", value: configuration.routeMode.label)
          InfoRow(label: "DNS Mode", value: configuration.dnsMode.label)
          InfoRow(
            label: "Protected Routes",
            value: PrivacyDefaults.redactNetworkIdentifiers(
              in: configuration.protectedRoutes.joined(separator: ", ")))
          InfoRow(
            label: "Excluded Routes",
            value: configuration.excludedRoutes.isEmpty
              ? "None"
              : PrivacyDefaults.redactNetworkIdentifiers(
                in: configuration.excludedRoutes.joined(separator: ", ")))
        }

        ConfigurationCard(title: "Transport", systemImage: "antenna.radiowaves.left.and.right") {
          InfoRow(
            label: "Discovery",
            value: configuration.discoveryModes.map(\.label).joined(separator: ", "))
          InfoRow(
            label: "Rendezvous",
            value: configuration.rendezvousServers.isEmpty
              ? "Disabled"
              : PrivacyDefaults.redactNetworkIdentifiers(
                in: configuration.rendezvousServers.joined(separator: ", ")))
          InfoRow(
            label: "Relay",
            value: configuration.relayServers.isEmpty
              ? "Disabled"
              : PrivacyDefaults.redactNetworkIdentifiers(
                in: configuration.relayServers.joined(separator: ", ")))
          InfoRow(label: "Current Path", value: status.pathType.label)
        }

        ConfigurationCard(title: "Workflow", systemImage: "sidebar.left") {
          Toggle("Show onboarding tab in sidebar", isOn: $onboardingTabVisible)
            .toggleStyle(.checkbox)

          Text(
            "Re-enable the onboarding workspace if you want to revisit first-run guidance or walkthrough settings later."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        }
      }
    }
  }

  private var discoveryIdentityPresentation: DiscoveryIdentityPresentation {
    DiscoveryIdentityPresentation(configuration: configuration)
  }

  private var registryConfiguration: DytallixIdentityConfiguration? {
    dytallixEnrollmentSettings.runtimeConfiguration(mode: configuration.discoveryIdentityMode)
  }

  private var walletPresentation: DytallixWalletReadinessPresentation {
    DytallixWalletReadinessPresentation(
      settings: dytallixEnrollmentSettings,
      mode: configuration.discoveryIdentityMode
    )
  }

  private var identityActionTitle: String {
    dytallixEnrollmentSettings.status == .registered
      ? "Update Registry Record"
      : "Register Identity"
  }

  private var identityActionSystemImage: String {
    dytallixEnrollmentSettings.status == .registered
      ? "arrow.triangle.2.circlepath"
      : "link.badge.plus"
  }

  private var identityActionsDisabled: Bool {
    dytallixIdentityOperationInProgress != nil
      || dytallixKeyRotationInProgress
      || configuration.discoveryIdentityMode == .off
      || dytallixEnrollmentSettings.runtimeConfiguration(
        mode: configuration.discoveryIdentityMode
      ) == nil
  }

  private var deviceKeyRotationDisabled: Bool {
    dytallixKeyRotationInProgress
      || dytallixIdentityOperationInProgress != nil
      || dytallixEnrollmentSettings.rotationBlockedByActiveRegistryRecord
      || status.phase == .connected
  }

  private func primaryIdentityAction() {
    if dytallixEnrollmentSettings.status == .registered {
      onUpdateDytallixIdentity()
    } else {
      onEnrollDytallixIdentity()
    }
  }

  private var dytallixEndpointBinding: Binding<String> {
    Binding(
      get: { dytallixEnrollmentSettings.endpoint },
      set: { dytallixEnrollmentSettings = dytallixEnrollmentSettings.replacing(endpoint: $0) }
    )
  }

  private var dytallixContractBinding: Binding<String> {
    Binding(
      get: { dytallixEnrollmentSettings.contractAddress },
      set: { dytallixEnrollmentSettings = dytallixEnrollmentSettings.replacing(contractAddress: $0) }
    )
  }

  private var dytallixWalletNameBinding: Binding<String> {
    Binding(
      get: { dytallixEnrollmentSettings.walletName ?? "" },
      set: { value in
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        dytallixEnrollmentSettings = dytallixEnrollmentSettings.replacing(
          walletName: trimmed.isEmpty ? .some(nil) : .some(trimmed)
        )
      }
    )
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

private struct IdentityModeSummary: View {
  let mode: DiscoveryIdentityMode

  var body: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: mode.systemImage)
        .font(.title3)
        .foregroundStyle(.tint)
        .frame(width: 28)

      VStack(alignment: .leading, spacing: 4) {
        Text(mode.onboardingTitle)
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

private struct KnowledgeRow: View {
  let title: String
  let detail: String

  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(title)
        .font(.callout.weight(.semibold))
      Text(detail)
        .font(.callout)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.vertical, 4)
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
          InfoRow(
            label: "Overlay",
            value: PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address))
          InfoRow(
            label: "Remote",
            value: PrivacyDefaults.redactNetworkIdentifiers(in: configuration.tunnelRemoteAddress))
          InfoRow(label: "MTU", value: "\(configuration.mtu)")
          InfoRow(
            label: "Protected",
            value: PrivacyDefaults.redactNetworkIdentifiers(
              in: status.protectedRoutes.joined(separator: ", ")))
        }

        ConfigurationCard(title: "Discovery", systemImage: "antenna.radiowaves.left.and.right") {
          InfoRow(
            label: "Modes", value: configuration.discoveryModes.map(\.label).joined(separator: ", ")
          )
          InfoRow(
            label: "Rendezvous",
            value: configuration.rendezvousServers.isEmpty
              ? "Disabled"
              : PrivacyDefaults.redactNetworkIdentifiers(
                in: configuration.rendezvousServers.joined(separator: ", ")))
          InfoRow(
            label: "Relay",
            value: configuration.relayServers.isEmpty
              ? "Disabled"
              : PrivacyDefaults.redactNetworkIdentifiers(
                in: configuration.relayServers.joined(separator: ", ")))
          InfoRow(
            label: "Last Probe",
            value: status.metrics.lastPathProbe?.formatted(date: .abbreviated, time: .shortened)
              ?? "Never")
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
          InfoRow(
            label: "Overlay",
            value: PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address))
        }
      }
    }
  }
}

private struct SecurityDetail: View {
  let status: TunnelStatus
  let configuration: TunnelConfiguration
  let dytallixEnrollmentSettings: DytallixEnrollmentSettings

  var body: some View {
    PanelChrome {
      PanelHeader(
        tab: .security,
        subtitle:
          "\(configuration.crypto.pqcAlgorithm.title) · \(status.metrics.replayDrops) replay drops"
      )

      PanelGrid {
        ConfigurationCard(title: "Dytallix Trust Anchor", systemImage: "person.badge.shield.checkmark") {
          InfoRow(label: "Discovery", value: configuration.discoveryIdentityMode.title)
          InfoRow(label: "Trust Policy", value: configuration.meshTrustPolicy.label)
          InfoRow(label: "Trust Required", value: status.peerTrust.required ? "Yes" : "No")
          InfoRow(label: "Registry", value: status.peerTrust.registryConfigured ? "Configured" : "Not configured")
          InfoRow(label: "Verified", value: "\(status.peerTrust.verifiedPeerCount)")
          InfoRow(label: "Pending", value: "\(status.peerTrust.pendingPeerCount)")
          InfoRow(label: "Unverified", value: "\(status.peerTrust.unverifiedPeerCount)")
          InfoRow(label: "Blocked", value: "\(status.peerTrust.failedPeerCount)")
          InfoRow(label: "Last Checked", value: trustLastCheckedLabel)
          InfoRow(label: "Enrollment", value: dytallixEnrollmentSettings.status.label)
          InfoRow(label: "Peer ID", value: dytallixEnrollmentSettings.registeredPeerID ?? "Not registered")

          Text(
            "Public meshes require a registry-backed identity before peer discovery is trusted. Private and development meshes can keep identity publishing off."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        }

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
          InfoRow(
            label: "Protected",
            value: PrivacyDefaults.redactNetworkIdentifiers(
              in: status.protectedRoutes.joined(separator: ", ")))
          InfoRow(
            label: "Excluded",
            value: configuration.excludedRoutes.isEmpty
              ? "None"
              : PrivacyDefaults.redactNetworkIdentifiers(
                in: configuration.excludedRoutes.joined(separator: ", ")))
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
                  Text(
                    "Last rekey: \(peer.lastRekey?.formatted(date: .abbreviated, time: .shortened) ?? "Unknown")"
                  )
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  PeerTrustBadge(peer: peer, summary: status.peerTrust)
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

  private var trustLastCheckedLabel: String {
    status.peerTrust.lastCheckedAt?.formatted(date: .abbreviated, time: .shortened) ?? "Never"
  }
}

private struct DiagnosticsDetail: View {
  let status: TunnelStatus
  let configuration: TunnelConfiguration
  let dytallixEnrollmentSettings: DytallixEnrollmentSettings
  let dytallixLastIdentityError: String?

  var body: some View {
    PanelChrome {
      PanelHeader(
        tab: .diagnostics,
        subtitle:
          "\(status.phase.label) · \(status.pathType.label) · \(status.metrics.peerCount) peers"
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
          InfoRow(
            label: "Last Error",
            value: status.lastError.map { PrivacyDefaults.redactNetworkIdentifiers(in: $0) }
              ?? "None")
        }

        ConfigurationCard(title: "Identity", systemImage: "person.badge.shield.checkmark") {
          InfoRow(label: "Policy", value: configuration.meshTrustPolicy.label)
          InfoRow(label: "Discovery", value: configuration.discoveryIdentityMode.title)
          InfoRow(label: "Trust Required", value: status.peerTrust.required ? "Yes" : "No")
          InfoRow(label: "Registry", value: status.peerTrust.registryConfigured ? "Configured" : "Not configured")
          InfoRow(label: "Enrollment", value: dytallixEnrollmentSettings.status.label)
          InfoRow(label: "Wallet", value: walletDiagnosticsLabel)
          InfoRow(label: "Verified Peers", value: "\(status.peerTrust.verifiedPeerCount)")
          InfoRow(label: "Pending", value: "\(status.peerTrust.pendingPeerCount)")
          InfoRow(label: "Unverified", value: "\(status.peerTrust.unverifiedPeerCount)")
          InfoRow(label: "Blocked", value: "\(status.peerTrust.failedPeerCount)")
          InfoRow(label: "Last Checked", value: trustLastCheckedLabel)
          InfoRow(label: "Last Identity Error", value: dytallixLastIdentityError ?? "None")
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
    status.transport?.kind.label ?? "Not reported"
  }

  private var transportState: String {
    status.transport?.state.label ?? "Not reported"
  }

  private var transportPath: String {
    status.transport?.pathType.label ?? "Waiting for telemetry"
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

  private var walletDiagnosticsLabel: String {
    DytallixWalletReadinessPresentation(
      settings: dytallixEnrollmentSettings,
      mode: configuration.discoveryIdentityMode
    ).status
  }

  private var trustLastCheckedLabel: String {
    status.peerTrust.lastCheckedAt?.formatted(date: .abbreviated, time: .shortened) ?? "Never"
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
        Text(
          "Overlay \(PrivacyDefaults.redactNetworkIdentifiers(in: status.overlayIPv4Address)) · \(status.routeMode.label) · DNS \(status.dnsMode.label)"
        )
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
  let status: TunnelStatus

  private var peers: [PeerStatus] {
    status.peers
  }

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
            TableColumn("Trust") { peer in
              PeerTrustBadge(peer: peer, summary: status.peerTrust)
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

private struct PeerTrustBadge: View {
  let peer: PeerStatus
  let summary: DytallixPeerTrustSummary

  var body: some View {
    Label(label, systemImage: state.systemImage)
      .font(.callout)
      .foregroundStyle(state.tint)
      .help(helpText)
  }

  private var state: DytallixPeerTrustState {
    if let state = peer.dytallixTrust?.state {
      return state
    }
    if !summary.required {
      return .notRequired
    }
    if !summary.registryConfigured {
      return .notConfigured
    }
    return .unknown
  }

  private var label: String {
    state.label
  }

  private var helpText: String {
    if let failureReason = peer.dytallixTrust?.failureReason {
      return failureReason
    }
    switch state {
    case .verified:
      return "Peer identity matched an active Dytallix testnet registry record."
    case .pending:
      return "QuantumLink is waiting for the transport to report the Dytallix registry decision."
    case .missingRegistryRecord:
      return "Public mesh policy requires an active Dytallix registry record for this peer."
    case .unverified:
      return "Peer was accepted by private/development policy without an active registry proof."
    case .revoked:
      return "Peer registry record is revoked and should not be trusted for public discovery."
    case .suspended:
      return "Peer registry record is suspended or inactive."
    case .expired:
      return "Peer registry record has expired and must be updated before public discovery."
    case .bindingMismatch:
      return "Peer record does not match the Dytallix registry binding."
    case .lookupFailed:
      return "Dytallix registry lookup failed under the active mesh policy."
    case .verificationFailed:
      return "Dytallix registry verification failed."
    case .failed:
      return "Peer registry verification failed."
    case .notConfigured:
      return "Dytallix registry endpoint or contract is missing."
    case .notRequired:
      return "This mesh does not require Dytallix registry verification."
    case .unknown:
      return "Peer registry trust has not been reported yet."
    }
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

  func placeSubviews(
    in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
  ) {
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

extension RouteMode {
  fileprivate var label: String {
    switch self {
    case .splitTunnel: "Split Tunnel"
    case .protectedPrefixesOnly: "Protected Prefixes"
    case .fullTunnel: "Full Tunnel"
    }
  }
}

extension ConnectionPhase {
  fileprivate var label: String {
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

extension DNSMode {
  fileprivate var label: String {
    switch self {
    case .tunnelProvided: "Tunnel"
    case .system: "System"
    case .disabled: "Disabled"
    }
  }
}

extension MeshTrustPolicy {
  fileprivate var label: String {
    switch self {
    case .publicRequired: "Public Required"
    case .privatePreferred: "Private Preferred"
    case .developmentOptional: "Development Optional"
    }
  }
}

extension DytallixPeerTrustState {
  fileprivate var label: String {
    switch self {
    case .notRequired: "Not required"
    case .notConfigured: "Registry missing"
    case .pending: "Pending"
    case .verified: "Dytallix Testnet Verified"
    case .missingRegistryRecord: "Missing registry"
    case .unverified: "Unverified"
    case .revoked: "Revoked"
    case .suspended: "Suspended"
    case .expired: "Expired"
    case .bindingMismatch: "Binding mismatch"
    case .lookupFailed: "Lookup failed"
    case .verificationFailed: "Verification failed"
    case .failed: "Failed"
    case .unknown: "Unknown"
    }
  }

  fileprivate var systemImage: String {
    switch self {
    case .notRequired: "checkmark.circle"
    case .notConfigured: "exclamationmark.triangle"
    case .pending: "clock"
    case .verified: "checkmark.shield"
    case .missingRegistryRecord: "shield.slash"
    case .unverified: "questionmark.shield"
    case .revoked: "xmark.shield"
    case .suspended: "pause.shield"
    case .expired: "timer"
    case .bindingMismatch: "exclamationmark.shield"
    case .lookupFailed: "network.slash"
    case .verificationFailed: "exclamationmark.shield"
    case .failed: "exclamationmark.shield"
    case .unknown: "questionmark.circle"
    }
  }

  fileprivate var tint: Color {
    switch self {
    case .notRequired, .verified: .green
    case .pending, .unknown: .secondary
    case .notConfigured, .unverified, .expired, .lookupFailed: .orange
    case .missingRegistryRecord,
         .revoked,
         .suspended,
         .bindingMismatch,
         .verificationFailed,
         .failed: .red
    }
  }
}

extension PathType {
  fileprivate var label: String {
    switch self {
    case .direct: "Direct"
    case .relay: "Relay"
    case .probing: "Probing"
    case .unavailable: "Unavailable"
    }
  }

  fileprivate var systemImage: String {
    switch self {
    case .direct: "link"
    case .relay: "arrow.triangle.swap"
    case .probing: "antenna.radiowaves.left.and.right"
    case .unavailable: "slash.circle"
    }
  }
}

extension QuantumLinkDeploymentMode {
  fileprivate var title: String {
    switch self {
    case .mesh: "Mesh"
    case .partyMesh: "Party Mesh"
    case .direct: "Direct"
    case .localVPN: "Local VPN"
    }
  }

  fileprivate var summary: String {
    switch self {
    case .mesh:
      "Multi-peer overlay with rendezvous discovery and relay fallback."
    case .partyMesh:
      "Invite-based gamer mesh with verified identity and relay fallback."
    case .direct:
      "Peer-to-peer protected prefixes with relay fallback disabled."
    case .localVPN:
      "Single-device local tunnel with full routing and system DNS."
    }
  }

  fileprivate var systemImage: String {
    switch self {
    case .mesh: "point.3.connected.trianglepath.dotted"
    case .partyMesh: "gamecontroller"
    case .direct: "link"
    case .localVPN: "network"
    }
  }

  fileprivate var tint: Color {
    switch self {
    case .mesh: .blue
    case .partyMesh: .purple
    case .direct: .green
    case .localVPN: .orange
    }
  }

  fileprivate var requiresPublicIdentity: Bool {
    switch self {
    case .mesh, .partyMesh:
      true
    case .direct, .localVPN:
      false
    }
  }
}

extension QuantumLinkConnectionType {
  fileprivate var title: String {
    switch self {
    case .ssh: "SSH"
    case .https: "HTTPS"
    case .rdp: "RDP"
    case .vnc: "VNC"
    case .custom: "Custom"
    }
  }

  fileprivate var systemImage: String {
    switch self {
    case .ssh: "terminal"
    case .https: "lock.laptopcomputer"
    case .rdp: "display"
    case .vnc: "rectangle.connected.to.line.below"
    case .custom: "slider.horizontal.3"
    }
  }
}

extension PQCAlgorithm {
  fileprivate var shortTitle: String {
    "\(standardName) \(algorithmName)"
  }

  fileprivate var title: String {
    "\(standardName) - \(algorithmName)"
  }

  fileprivate var summary: String {
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

extension DiscoveryMode {
  fileprivate var label: String {
    switch self {
    case .rendezvous: "Rendezvous"
    case .privateDHT: "Private DHT"
    case .localMDNS: "Local mDNS"
    }
  }
}

extension DiscoveryIdentityMode {
  fileprivate var title: String {
    switch self {
    case .off: "Off"
    case .verified: "Testnet Verified"
    case .publicWallet: "Public Wallet"
    }
  }

  fileprivate var onboardingTitle: String {
    switch self {
    case .off: "Private Mesh"
    case .verified: "Dytallix Testnet Verified"
    case .publicWallet: "Public Wallet"
    }
  }

  fileprivate var summary: String {
    DiscoveryIdentityPresentation(mode: self).summary
  }

  fileprivate var systemImage: String {
    switch self {
    case .off: "person.crop.circle.badge.xmark"
    case .verified: "person.badge.shield.checkmark"
    case .publicWallet: "wallet.pass"
    }
  }
}

extension TunnelTransportKind {
  fileprivate var label: String {
    switch self {
    case .developmentDrop: "Development Drop"
    case .devQuicLoopback: "Dev QUIC Loopback"
    case .nativeUdpMesh: "Native UDP Mesh"
    case .meshQuic: "Mesh QUIC"
    }
  }
}

extension TunnelTransportState {
  fileprivate var label: String {
    switch self {
    case .stopped: "Stopped"
    case .ready: "Ready"
    case .failed: "Failed"
    }
  }
}

extension UInt64 {
  fileprivate var byteCount: String {
    ByteCountFormatter.string(fromByteCount: Int64(self), countStyle: .binary)
  }
}

extension TimeInterval {
  fileprivate var durationLabel: String {
    let totalSeconds = max(Int(self.rounded()), 0)
    let minutes = totalSeconds / 60
    let seconds = totalSeconds % 60

    if minutes > 0 {
      return "\(minutes) min"
    }
    return "\(seconds) sec"
  }
}
