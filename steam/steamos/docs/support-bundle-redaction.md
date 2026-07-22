# SteamOS Support Bundle Redaction

`qlinkctl support-bundle --output /tmp/qlink-steamos-support.tar.zst` creates a
privacy-safe diagnostic archive for operator handoff. The bundle is intended for
status triage, network-plan review, and release/build identification only.

## Bundle Contents

| File | Purpose | Redaction rule |
| --- | --- | --- |
| `status.json` | Pretty-printed daemon status snapshot. | Redact private key material, wallet seed material, entitlement tokens, raw packet payload markers, and exact peer endpoints. |
| `doctor.txt` | Human-readable health verdict from the same status snapshot. | Redact the same sensitive values before writing. |
| `network-plan.txt` | Rendered planned network commands from daemon status. | Redact entitlement tokens and exact peer endpoints. |
| `nftables-plan.txt` | Rendered planned nftables rules from daemon status. | Redact raw packet payload markers and exact peer endpoints. |
| `release-info.json` | Product, version, and platform metadata for the qlinkctl build. | Contains no secrets; still passes through the redactor. |
| `redaction-report.json` | Counts of redacted sensitive categories. | Contains counts only, not original values. |

## Never Include

| Sensitive category | Examples | Bundle handling |
| --- | --- | --- |
| Private keys | Device private keys, PEM private-key blocks, local keystore secrets. | Replace with `[REDACTED-SECRET]`; count as `privateKeyMaterial`. |
| Wallet seed material | Seed phrases, mnemonic text, wallet recovery material. | Replace with `[REDACTED-SECRET]`; count as `walletSeedMaterial`. |
| Entitlement tokens | Paid-access tokens, bearer tokens, entitlement proof secrets. | Replace token value with `[REDACTED-SECRET]`; count as `entitlementTokens`. |
| Raw packet payloads | Captured packet bytes or payload markers. | Replace with `[REDACTED-RAW-PACKET-PAYLOAD]`; count as `rawPacketPayloads`. |
| Exact peer endpoints | Public IP or host endpoint with port for a peer path. | Replace with `[REDACTED-ENDPOINT]`; count as `exactPeerEndpoints`. |

The support bundle must not be used as a packet capture, identity export, wallet
backup, or entitlement proof export. If future daemon status fields add endpoint
lists, token-like values, packet samples, or identity secrets, those fields must
be added to the redaction tests before bundle publication.
