# Steam Mobile Companion Architecture

QuantumLink Steam Mobile is a native mobile companion app that pairs with a
desktop or SteamOS Steam runtime. It is a status/control surface, not a tunnel
endpoint. This document describes the planned companion architecture; it is a
planning-stage scaffold and no mobile client is built yet.

## Roles

- Desktop/SteamOS runtime: owns the tunnel, routing, Steam-safe bypass policy,
  peer sessions, and packet path. It is the source of truth for status and the
  executor of remote-control commands.
- Mobile companion: a paired, least-privilege remote that reads redacted status
  and diagnostics, syncs gamer-profile preferences, and (when explicitly
  granted) issues account-safe remote-control commands.
- `qlink-core`: shared protocol/crypto/peer-record core, reused only where
  mobile FFI packaging and app-store policy permit.

## Pairing And Trust

1. The companion generates a device key in platform secure storage (iOS
   Keychain/Secure Enclave, Android Keystore) and sends a `PairingRequest` with
   its device name, platform, device public-key hash, and requested scopes.
2. The desktop runtime prompts the user to approve the pairing and the granted
   scopes, then returns a `PairingGrant` with a session id, granted scopes, and
   an expiry.
3. Scopes are least-privilege: `StatusRead` and `Diagnostics` are read-only;
   `ProfileSync` writes preferences; `RemoteControl` is required for
   connect/disconnect/profile-selection commands and is opt-in.
4. Raw device keys never leave the device; only key hashes travel in pairing
   messages. Grants expire and must be re-authorized.

## Companion Message Model

The `qlink-mobile-proto` crate defines the account-safe data models exchanged
over the authenticated companion channel:

- `PairingRequest` / `PairingGrant` / `CompanionScope`: pairing and authorization.
- `CompanionCommand`: remote-control commands, each mapped to a required scope.
- `TunnelHealthStatus`: a redacted status snapshot for display (no raw peer ids,
  wallet addresses, or network addresses).
- `GamerProfilePreferences`: latency, DDoS shielding, streamer privacy, and
  adaptive-bypass preferences synced to the desktop runtime.

The transport for this channel (paired LAN link, relay-assisted control path, or
push) is a future decision gated in the roadmap. The models are transport
agnostic.

## Privacy

Diagnostics shown on the companion are redacted at the source. Identifiers such
as peer ids, wallet addresses, and IPs are reduced to non-reversible hints via
`redact_identifier` before they leave the desktop runtime, matching the
repository privacy defaults.

## Explicit Non-Goals

- No Windows Filtering Platform, Wintun, Windows service, or Linux daemon.
- No PID routing, anti-cheat process detection, or fullscreen game detection.
- No control of Steam launcher, storefront, wallet, or account-security traffic.
- No mobile game tunneling until a separate platform-VPN/app-store feasibility
  gate passes.
