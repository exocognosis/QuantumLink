# Steam Deck Validation

This runbook defines the required Steam Deck hardware validation for the
SteamOS production gate. It is a validation plan and evidence index only; no
Steam Deck hardware results are claimed until completed evidence directories are
linked from `steam/steamos/docs/production-readiness.md`.

## Required Hosts

| Host | Role | Required setup |
|---|---|---|
| Deck A | game host and service lifecycle host | Steam Deck on current stable SteamOS, developer mode enabled, wired or stable 5 GHz Wi-Fi, QuantumLink SteamOS installed |
| Deck B | peer/client host | Steam Deck on current stable SteamOS, developer mode enabled, separate trusted peer identity, same LAN for baseline and alternate WAN/NAT path for traversal checks |
| Relay/rendezvous host | fallback control-plane host | Hardened staging rendezvous/relay endpoint with test-only credentials and no production secrets |
| LAN controller | observation host | Local shell access for ping/UDP probes and Steam-safe route checks; packet captures are not committed |

Do not use production signing keys, wallet seed material, hosted relay secrets,
private endpoints, raw support bundles, or raw packet captures in committed
evidence.

## Required Scenarios

| Scenario | Hosts | Gate covered | Required evidence |
|---|---|---|---|
| Preflight dry-run status | Deck A, Deck B | daemon install shape, dry-run safety | `status-before.json`, `doctor.txt`, `ip-route.txt`, `nftables.txt` |
| Install / reinstall | Deck A, Deck B | SteamOS installer idempotence | `validation-report.json` with installer exit status and no live activation drop-in created by default |
| Activated network lifecycle | Deck A, Deck B | TUN, route, nftables ownership, cleanup | `status-before.json`, `status-after.json`, `journal-qlinkd.txt`, `ip-route.txt`, `nftables.txt` |
| Two-Deck protected roundtrip | Deck A, Deck B | live TUN to peer transport | game/overlay probe notes in `route-leak-check.txt` and status showing ready peer session |
| Steam-safe bypass | Deck A, Deck B | Steam account/store/wallet bypass | `route-leak-check.txt` showing no default route replacement and no Steam account, store, checkout, inventory, marketplace, launcher, embedded browser, or wallet categories protected |
| Dedicated server traffic | Deck A, Deck B, LAN controller | game compatibility | Factorio dedicated UDP `34197` with split-tunnel game-only profile |
| LAN-discovery-heavy title | Deck A, Deck B | LAN discovery behavior | Minecraft Bedrock/LAN discovery profile with only title traffic protected |
| Peer-hosted world title | Deck A, Deck B | peer-hosted game compatibility | Minecraft Java/Bedrock peer-hosted world join, reconnect, suspend/resume notes |
| Steam Remote Play style traffic | Deck A, Deck B | streaming traffic compatibility | Remote Play profile using game/streaming UDP only; Steam account/store/wallet bypass remains intact |
| Voice-chat-safe profile | Deck A, Deck B | voice chat preservation | Profile with `voice_chat_safe = true`, in-game or overlay voice sanity notes |
| Relay-disallowed low-latency profile | Deck A, Deck B | latency-sensitive direct-path behavior | Low-latency title profile documented as direct-path required; validation fails rather than silently using relay |
| Support bundle redaction | Deck A | diagnostics privacy | `support-bundle-redaction.txt` with redaction assertions and no raw bundle archive |
| Uninstall / rollback | Deck A, Deck B | cleanup | `status-after.json`, `ip-route.txt`, `nftables.txt`, `journal-qlinkd.txt` showing no QuantumLink-owned live network state |

## SLO Targets

The Deck validation pass must report these product SLOs from warm discovery and
reasonable WAN/LAN conditions:

| SLO | Target |
|---|---|
| Median direct connect with warm discovery | < 300 ms |
| Median post-event recovery from `PathChanged` to ready | < 1 s |
| Median relay-fallback activation | < 2 s |

Degraded mobile networks, captive portals, blocked UDP, and high-loss networks
can exceed the SLOs, but those cases must be labeled as degraded-network
behavior rather than production-ready SLO evidence.

## Evidence Script

Run `steam/steamos/tests/deck-validation.sh` on each Deck. The script supports
these modes:

```sh
bash steam/steamos/tests/deck-validation.sh preflight
sudo bash steam/steamos/tests/deck-validation.sh install
sudo bash steam/steamos/tests/deck-validation.sh activate
bash steam/steamos/tests/deck-validation.sh route-leak-check
bash steam/steamos/tests/deck-validation.sh support-bundle-check
sudo bash steam/steamos/tests/deck-validation.sh uninstall
```

Run the device-local runtime gate from the signed-in desktop session. Do not
run it through `sudo`:

```sh
export QLINK_DECK_RUNTIME_EVIDENCE_DIR="$HOME/quantumlink-deck-runtime-$(date -u +%Y%m%dT%H%M%SZ)"
bash steam/steamos/tests/deck-runtime-qualification.sh preflight

export QLINK_DECK_RUNTIME_EVIDENCE_DIR="$HOME/quantumlink-deck-runtime-run-$(date -u +%Y%m%dT%H%M%SZ)"
QLINK_DECK_CONFIRM_NETWORK_MUTATION=YES \
  bash steam/steamos/tests/deck-runtime-qualification.sh run

QLINK_DECK_RUNTIME_REQUIRE_COMPLETE=1 \
  bash steam/steamos/tests/verify-deck-runtime-evidence.sh \
  "$QLINK_DECK_RUNTIME_EVIDENCE_DIR"
```

The `run` mode changes the selected profile to Factorio and restarts `qlinkd`
through the packaged PolicyKit boundary. It requires all reported host
capabilities to be `supported`. It then tests native scope classification,
descendant cgroup inheritance, crash cleanup, concurrent launch rejection,
launcher interruption cleanup, and daemon restart cleanup.

The runtime gate uses temporary executable fixtures. It proves Steam Deck
kernel and lifecycle behavior. It does not prove Valve Proton behavior, a real
game, two-Deck packet flow, anti-cheat compatibility, voice behavior, or the
game compatibility matrix.

Each run writes redacted text evidence under
`steam/steamos/validation/deck/<timestamp>/`:

- `status-before.json`
- `status-after.json`
- `doctor.txt`
- `route-leak-check.txt`
- `journal-qlinkd.txt`
- `nftables.txt`
- `ip-route.txt`
- `support-bundle-redaction.txt`
- `validation-report.json`

The device-local runtime gate writes a separate evidence directory with:

- `runtime-report.json`
- `status-before.json`
- `status-after.json`

The script must not be used to commit raw pcaps, raw support bundles, private
endpoints, secrets, wallet material, or unredacted host-specific logs. If a
local elevated export is required for debugging, keep it outside the repository
and summarize only redacted assertions in the evidence directory.

## Pass Criteria

Deck validation and game compatibility remain `Blocked` until:

1. Deck A and Deck B both have completed evidence directories linked from
   `production-readiness.md`.
2. The install, activate, route-leak, support-redaction, and uninstall modes all
   exit successfully on real Steam Deck hardware.
3. The game matrix above has human notes and status evidence for every scenario.
4. Steam account, store, wallet, checkout, inventory, marketplace, launcher, and
   embedded browser traffic are shown to bypass QuantumLink by default.
5. No committed evidence contains raw packet captures, private endpoint
   addresses, secrets, wallet material, or raw support bundles.
6. The complete device-local runtime report passes
   `verify-deck-runtime-evidence.sh` with
   `QLINK_DECK_RUNTIME_REQUIRE_COMPLETE=1`.
