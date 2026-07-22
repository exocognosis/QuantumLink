import Foundation

extension MeshTransportConfiguration {
    /// The single modular seam that activates on-chain identity on the
    /// transport: returns a copy carrying the Dytallix trust policy and
    /// (optional) registry lookup config. A public mesh passes
    /// `.publicRequired` + a non-nil identity so the Rust connector *and*
    /// responder fail closed on any peer lacking an active registry record.
    public func enforcingDytallixIdentity(
        policy: MeshTrustPolicy,
        identity: DytallixIdentityConfiguration?
    ) -> MeshTransportConfiguration {
        MeshTransportConfiguration(
            meshID: meshID,
            localPeerID: localPeerID,
            remotePeerID: remotePeerID,
            rendezvousURL: rendezvousURL,
            relayURL: relayURL,
            bindAddress: bindAddress,
            overallDeadlineMs: overallDeadlineMs,
            directProbeTimeoutMs: directProbeTimeoutMs,
            probePacingMs: probePacingMs,
            enableICE: enableICE,
            peerStorePath: peerStorePath,
            peerStoreKeyB64: peerStoreKeyB64,
            meshTrustPolicy: policy,
            dytallixIdentity: identity
        )
    }

    /// Composes enforcement from app-level enrollment state + discovery mode.
    /// The caller selects `policy` from the mesh type (public → `.publicRequired`).
    public func applyingDiscoveryIdentity(
        settings: DytallixEnrollmentSettings,
        mode: DiscoveryIdentityMode,
        meshTrustPolicy policy: MeshTrustPolicy
    ) -> MeshTransportConfiguration {
        enforcingDytallixIdentity(
            policy: policy,
            identity: settings.runtimeConfiguration(mode: mode)
        )
    }
}
