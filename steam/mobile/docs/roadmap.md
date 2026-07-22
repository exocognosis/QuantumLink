# Steam Mobile Roadmap

QuantumLink Steam Mobile is a planning-stage scaffold. This roadmap defines the
phased gates from scaffold to a shippable companion. Each gate must be met and
evidenced before the next begins; nothing here is production-ready yet.

## Phase 0 — Scaffold (current)

- [x] Silo created under `steam/mobile` inside the Steam silo.
- [x] `qlink-mobile-proto` companion model crate compiles and tests in the
      workspace.
- [x] Product direction, architecture, and roadmap documented.
- [ ] Companion channel transport decision recorded.

## Phase 1 — Companion protocol

- [ ] Authenticated pairing handshake against a desktop/SteamOS test runtime.
- [ ] Scope-enforced remote-control command execution end to end.
- [ ] Redacted status/diagnostics stream validated against privacy rules.
- [ ] `qlink-core` FFI packaging feasibility for mobile targets assessed.

## Phase 2 — Mobile app shells

- [ ] iOS companion shell under `steam/mobile/ios` with Keychain/Secure Enclave
      key storage.
- [ ] Android companion shell under `steam/mobile/android` with Keystore key
      storage.
- [ ] Push-notification model for tunnel health, failover, and bypass alerts.
- [ ] Steam-safe compliance review of app behavior and copy.

## Phase 3 — Optional mobile tunnel (separate feasibility gate)

- [ ] Platform VPN API (NEPacketTunnelProvider / Android VpnService) feasibility.
- [ ] App-store VPN policy review passed for each store.
- [ ] Steam-safe routing proven to keep account/commerce traffic off the tunnel.

## Release Boundary

The mobile silo is not shippable until at least Phase 2 completes with an
app-store policy review and a Steam-safe compliance sign-off. The optional
mobile tunnel in Phase 3 is gated independently and is not required for a
companion-only release.
