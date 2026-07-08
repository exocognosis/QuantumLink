# QuantumLink Steam Mobile Version

Version: 0.1.0-steam-mobile-scaffold
Status: Planning scaffold
Date: 2026-05-20
Target: Steam mobile companion edition

## Baseline

QuantumLink Steam Mobile is a companion-focused mobile edition for Steam users. It is separate from the Windows desktop tunnel client because mobile platforms do not expose the same per-process routing, Windows Filtering Platform, Wintun adapter, or anti-cheat-safe desktop game detection model.

This edition should share account-safe policy, diagnostics concepts, privacy redaction, mesh status display, game profile metadata, and route recommendation logic with the desktop Steam version. It should not attempt to behave like the Windows service or desktop packet driver.

## Steam Compliance Position

QuantumLink Steam Mobile must not disguise Steam account residence, route Steam commerce traffic for regional pricing, emulate Steam protocols, modify Steam app behavior, or interfere with Steam Guard, checkout, marketplace, wallet, inventory, or account-security flows.

Steam account, store, wallet, checkout, inventory, marketplace, launcher, and embedded browser traffic must bypass any QuantumLink tunnel by default.

Mobile app behavior should be explicit: companion controls and diagnostics are safe defaults; mobile game tunneling is an opt-in future track only where platform VPN APIs and app-store policies allow it.

## Target Architecture

- UI: Native mobile companion app, with platform-specific shells for iOS and Android if built.
- Privileged runtime: Platform VPN extension/service only for future mobile tunnel experiments.
- Core bridge: Rust `qlink-core` reuse only where mobile FFI packaging and platform policy permit it.
- Routing: Platform VPN APIs, not Windows PID routing.
- Secrets: iOS Keychain/Secure Enclave where available; Android Keystore on Android.
- Packaging: App Store/TestFlight for iOS and Play/Internal testing for Android, subject to store VPN policy review.

## Core Features

- Steam-safe account protection status.
- Remote control and monitoring for the desktop Steam tunnel.
- Gamer profile sync for latency, DDoS protection, streamer privacy, and bypass policy preferences.
- Match-session diagnostics viewer with redacted IPs, mesh IDs, peer IDs, and server details.
- Push alerts for desktop tunnel health, failover, packet loss, and bypass decisions.
- Steam Datagram Relay awareness surfaced as advisory status.
- Mobile hotspot/tethering guidance for desktop failover without claiming seamless game-session migration until tested.

## Not Desktop Features

- No Windows Filtering Platform integration.
- No Wintun adapter lifecycle.
- No Windows Service.
- No PID-based routing.
- No desktop anti-cheat process detection.
- No fullscreen game engine detection.
- No direct Steam desktop launcher/storefront traffic control.

## Reused From Desktop Steam

- Steam-safe routing policy semantics.
- Account/storefront bypass rules.
- SDR-aware recommendation logic.
- Privacy redaction and diagnostics concepts.
- Game profile metadata.
- Rust protocol core where mobile packaging permits.

## Mobile-Specific Work

- Mobile companion UI.
- Desktop pairing and authenticated remote-control channel.
- Mobile push notification model.
- Platform key storage.
- App-store policy review notes.
- Optional future mobile VPN mode behind a separate feasibility gate.
