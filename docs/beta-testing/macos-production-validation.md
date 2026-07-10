# macOS Production Validation

## Required Artifacts

- Signed `QuantumLink.app`
- Signed installer package
- Notarization JSON evidence
- Stapled app and package
- SHA256SUMS.txt
- Signed Sparkle appcast
- Post-quantum release manifest

## Test Machines

- Clean unmanaged macOS install
- Existing-user macOS install with previous QuantumLink state
- MDM-managed macOS install
- Apple Silicon Mac
- Intel Mac if supported by the release target

## Required Scenarios

- First launch after Gatekeeper download quarantine
- Packet tunnel install and enable from System Settings
- MDM profile install and per-app VPN policy apply
- Dytallix identity enrollment and public-mesh verification
- Native UDP direct peer path
- Relay fallback path
- Sleep, wake, network roam, captive portal, tethering, and offline recovery
- Update from previous signed build to current signed build
- Uninstall, reinstall, and stale credential recovery

## Release Decision

Release is blocked if any required artifact is unsigned, unstapled,
unnotarized, fails Gatekeeper, fails packet-tunnel enablement, leaks raw peer
identifiers in default support exports, or loses protected-route fail-closed
behavior.
