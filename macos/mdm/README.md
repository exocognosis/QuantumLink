# Managed Deployment Payload Templates

These files are templates for the managed deployment work that can be
prepared before Apple Developer account setup. They are not installable
as-is — every file ships with `REPLACE-WITH-*` placeholders that an
operator (or the `QuantumLinkMDM` CLI) fills in before signing.

## Templates

| File | Posture | When to start here |
|---|---|---|
| `extension-preapproval.mobileconfig.template` | System extension pre-approval | Required before any of the others can install on a managed Mac without per-machine user prompts. |
| `per-app-vpn.mobileconfig.template` | Per-app VPN mapping | Specific managed apps route through the mesh; everything else uses the default network. |
| `managed-default.mobileconfig.template` | Tunnel-wide default | Every managed app should route through the mesh. Includes a `VendorConfig` block with `rendezvousServers`, `relayServers`, `killSwitch`, etc., that the Swift app reads at launch. |
| `on-demand-exemplar.mobileconfig.template` | On-demand rules reference | Reference for every match predicate the `OnDemandRule` generators support (SSID, DNS suffix, DNS server, interface type, URL probe). Copy individual rules; the file as a whole is contradictory by design. |
| `kill-switch-strict.mobileconfig.template` | Strict / regulated-data | `killSwitch=strict` runtime watchdog + `RemovalDisallowed=true` + always-on on-demand. Maximum enforcement; confirms with the support model before shipping. |

## Placeholder reference

Every template uses these tokens. Replace before signing:

- `REPLACE-WITH-VPN-PAYLOAD-UUID` — generated UUID for the VPN payload
  in this profile (must be unique within the profile).
- `REPLACE-WITH-PER-APP-PAYLOAD-UUID` — UUID for the App-Layer VPN
  Mapping payload (`per-app-vpn` only).
- `REPLACE-WITH-PROFILE-UUID` — UUID for the outer Configuration
  payload.
- `REPLACE-WITH-CODE-SIGNING-REQUIREMENT` — output of
  `codesign -d -r-` against the managed-app binary, or what
  `CodeRequirementExtractor` returns for an installed app.

The `QuantumLinkMDM` CLI (`Sources/QuantumLinkMDM`) automates the
common cases: it can generate UUIDs, extract designated requirements
from installed apps, build the per-app VPN + on-demand payloads, and
sign the resulting `.mobileconfig` with a PKCS#12 identity. Run
`swift run QuantumLinkMDM --help` for the subcommand list.

## What's still gated on Apple Dev

Real validation requires Apple-granted Network Extension entitlements,
signed bundles, provisioning profiles, and an MDM-managed Mac. These
templates compile + parse fine without those (XML well-formedness,
plist structure, payload-type names are validated by the Swift unit
tests in `MobileConfigEnvelopeTests`), but actually installing them on
a Mac and seeing the tunnel come up requires the full Apple-Dev chain.
