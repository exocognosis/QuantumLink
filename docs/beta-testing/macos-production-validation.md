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
- Host, STUN server-reflexive, and TURN relay candidate gathering
- Sleep, wake, network roam, captive portal, tethering, and offline recovery
- Update from previous signed build to current signed build
- Uninstall, reinstall, and stale credential recovery

## Current Non-Apple Evidence

As of the 2026-07-18 non-Apple closeout batch, these checks can run before
Developer ID signing, notarization, and Apple Network Extension entitlement
approval:

- Native UDP live mesh direct path establishes a signed inbound assertion,
  app-layer ML-KEM/SHAKE session, and protected frame.
- Native UDP direct-probe exhaustion falls back to a relay carrier only after
  establishing the same end-to-end PQC session; raw relay fallback remains
  rejected when responder binding material is missing.
- Default builds gather host and STUN server-reflexive candidates; `turn-relay`
  builds additionally gather TURN relay candidates and report per-server
  failures.
- Public Dytallix mesh configuration fails closed without network ID, chain ID,
  and trusted RPC endpoint pins in both Swift configuration validation and Rust
  transport startup.
- Packet-pump defaults remain fail-closed and default support bundles redact
  mesh IDs, peer IDs, registry IDs, wallet/contract addresses, and IP endpoints.

## Release Decision

Release is blocked if any required artifact is unsigned, unstapled,
unnotarized, fails Gatekeeper, fails packet-tunnel enablement, leaks raw peer
identifiers in default support exports, or loses protected-route fail-closed
behavior.
