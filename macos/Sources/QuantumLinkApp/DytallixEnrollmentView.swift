import QuantumLinkKit
import SwiftUI

/// Starter SwiftUI surface for the Dytallix on-chain identity: discovery-identity
/// mode, enrollment status, wallet readiness, and the pinned registry contract.
///
/// Self-contained and preview-friendly — embed it in the app's configuration /
/// security navigation. It edits a `DytallixEnrollmentSettings` + a
/// `DiscoveryIdentityMode`; the runtime enforcement config is produced by
/// `settings.runtimeConfiguration(mode:)` and applied to the transport via
/// `MeshTransportConfiguration.applyingDiscoveryIdentity(settings:mode:meshTrustPolicy:)`.
public struct DytallixEnrollmentView: View {
    @Binding public var settings: DytallixEnrollmentSettings
    @Binding public var mode: DiscoveryIdentityMode

    /// Public meshes must not select `.off`; the caller supplies whether this
    /// mesh is public so the picker can constrain the choice.
    public let isPublicMesh: Bool

    public init(
        settings: Binding<DytallixEnrollmentSettings>,
        mode: Binding<DiscoveryIdentityMode>,
        isPublicMesh: Bool
    ) {
        self._settings = settings
        self._mode = mode
        self.isPublicMesh = isPublicMesh
    }

    private var presentation: DiscoveryIdentityPresentation {
        DiscoveryIdentityPresentation(
            mode: mode,
            dytallixIdentity: settings.runtimeConfiguration(mode: mode)
        )
    }

    private var walletReadiness: DytallixWalletReadinessPresentation {
        DytallixWalletReadinessPresentation(settings: settings, mode: mode)
    }

    public var body: some View {
        Form {
            Section("Discovery Identity") {
                Picker("Mode", selection: $mode) {
                    ForEach(availableModes, id: \.self) { mode in
                        Text(label(for: mode)).tag(mode)
                    }
                }
                LabeledContent(presentation.rowLabel, value: presentation.status)
                Text(presentation.summary)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section("Enrollment") {
                LabeledContent("Status", value: settings.status.label)
                if !settings.endpoint.isEmpty {
                    LabeledContent("Registry Endpoint", value: settings.endpoint)
                }
                if !settings.contractAddress.isEmpty {
                    LabeledContent("Contract", value: settings.contractAddress)
                        .textSelection(.enabled)
                }
                if let peerID = settings.registeredPeerID {
                    LabeledContent("Registered Peer", value: peerID)
                        .textSelection(.enabled)
                }
            }

            Section("Wallet") {
                LabeledContent("State", value: walletReadiness.status)
                Text(walletReadiness.detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Link(walletReadiness.actionTitle, destination: walletReadiness.actionURL)
            }
        }
        .formStyle(.grouped)
        .onChange(of: isPublicMesh) { _, nowPublic in
            if nowPublic, mode == .off {
                mode = .verified
            }
        }
    }

    /// Public meshes require chain-backed eligibility, so `.off` is not offered.
    private var availableModes: [DiscoveryIdentityMode] {
        isPublicMesh ? [.verified, .publicWallet] : DiscoveryIdentityMode.allCases
    }

    private func label(for mode: DiscoveryIdentityMode) -> String {
        switch mode {
        case .off: "Off"
        case .verified: "Verified"
        case .publicWallet: "Public Wallet"
        }
    }
}

#if DEBUG
    struct DytallixEnrollmentView_Previews: PreviewProvider {
        struct Harness: View {
            @State private var settings = DytallixEnrollmentSettings(
                endpoint: "https://dytallix.com",
                contractAddress: "0xbcb5cf5abb50333ee4bfde91f21bbcc24828673d",
                walletName: "default",
                walletAddress: "dytallix1example",
                registeredPeerID: nil,
                status: .walletReady
            )
            @State private var mode: DiscoveryIdentityMode = .verified

            var body: some View {
                DytallixEnrollmentView(
                    settings: $settings,
                    mode: $mode,
                    isPublicMesh: true
                )
            }
        }

        static var previews: some View {
            Harness()
        }
    }
#endif
