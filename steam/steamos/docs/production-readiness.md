# SteamOS Production Readiness

## Release Target

- Product: QuantumLink for SteamOS
- Channel: production candidate
- Distribution: direct Steam Deck / SteamOS installer
- Runtime: `qlinkd` systemd daemon plus `qlinkctl`
- Shared core: `qlink-core`
- Default mesh: private friends mesh with invite-based trusted peers

## Blocking Gates

| Gate | Status | Evidence |
|---|---|---|
| Live TUN to peer transport | Blocked | Two-Deck packet roundtrip required |
| Production packet-session keys | Blocked | Fail-closed packet-frame tests required |
| Steam-safe bypass | Blocked | Route/profile leak report required |
| nftables rollback | Blocked | Activation failure and crash cleanup report required |
| Private invite peer lifecycle | Blocked | Invite import, revoke, stale peer rejection required |
| Public Dytallix policy | Blocked | Public mesh reject/accept matrix required |
| Rendezvous/relay production profile | Blocked | Hardened endpoint runbook required |
| Non-root local control | Blocked | Socket ACL and qlinkctl status proof required |
| Signed release artifacts | Blocked | Signatures, checksums, manifest, SBOM required |
| Deck validation | Blocked | Hardware validation report required; runbook: [`deck-validation.md`](deck-validation.md), harness: [`../tests/deck-validation.sh`](../tests/deck-validation.sh), evidence placeholder: `../validation/deck/<timestamp>/validation-report.json` |
| Game compatibility | Blocked | Representative titles and anti-cheat notes required; matrix placeholder: [`deck-validation.md`](deck-validation.md), profiles: `../config/games/factorio.toml`, `../config/games/minecraft.toml`, `../config/games/steam-remote-play.toml` |
| Diagnostics redaction | Blocked | Support bundle redaction report required |

## Go / No-Go Rule

Do not label SteamOS production-ready until every blocking gate is `Passed`
and the evidence path is linked from this file.
