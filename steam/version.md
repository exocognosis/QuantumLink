# QuantumLink Steam Desktop Version

Version: 0.1.0-steam-desktop-scaffold
Status: Planning scaffold
Date: 2026-05-20
Target: Windows Steam desktop gamer edition

## Baseline

QuantumLink Steam Desktop is a Windows-native gamer edition of QuantumLink designed for Steam-safe, low-latency game traffic optimization.

This edition reuses the existing QuantumLink Rust core for protocol, crypto, peer records, replay protection, route validation, rendezvous, relay, QUIC/ICE development transport, and packet-core behavior.

## Steam Compliance Position

QuantumLink Steam must not disguise Steam account residence, route Steam commerce traffic through the VPN, emulate Steam protocols, modify Steam networking APIs, or inject into game/Steam processes.

Steam account, store, wallet, checkout, inventory, marketplace, launcher, and embedded browser traffic must bypass the tunnel by default.

Games that already use Steam Datagram Relay should default to bypass or observe-only mode unless a title-specific profile proves QuantumLink improves latency without conflicting with Steam networking behavior.

## Target Architecture

- UI: C# WinUI 3 gamer-focused desktop app.
- Privileged runtime: Windows Service.
- Core bridge: C# P/Invoke wrapper over `qlink_core.dll`.
- Packet adapter: Wintun-compatible tunnel adapter.
- Routing: Windows Filtering Platform plus PID/app policy.
- Secrets: Windows DPAPI/CNG-backed storage.
- Packaging: MSIX or installer-backed service deployment with Authenticode signing.

## Core Features

- Dynamic MTU and MSS clamping for PQC overhead.
- UDP buffer-bloat mitigation with low-latency queueing.
- PID-based per-game routing.
- Steam Account Protection Toggle.
- Steam storefront and launcher bypass.
- SDR-aware game bypass.
- Game server ping matching.
- Twitch dual-path planning.
- DDoS shielding through mesh nodes.
- Zero-disconnect rekeying and path failover.
- Low-overhead ML-KEM-backed crypto path.
- Fullscreen game/resource detection.
- Streamer privacy mode.
- Adaptive bypass when QuantumLink worsens latency.

## Reused From macOS

- Rust `qlink-core`.
- Configuration and status model semantics.
- Privacy defaults and redaction concepts.
- Diagnostics bundle concepts.
- Transport smoke and packet-core behavior as parity references.

## New Windows/Steam Work

- WinUI 3 app.
- Windows Service.
- Wintun adapter lifecycle.
- Windows route, DNS, firewall, and kill-switch management.
- Steam-safe routing policy.
- SDR-aware detection.
- Anti-cheat-safe process detection.
- Game profile database.
- Windows packaging, signing, and update flow.

## SteamOS Release Readiness

Status: Pre-production daemon scaffold

Production readiness is tracked in `steam/steamos/docs/production-readiness.md`.
SteamOS remains pre-production until live transport, signed release, Steam-safe
routing, and Deck validation gates pass.
