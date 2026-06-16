# Security Policy

## Supported Versions

Security fixes target supported release branches and the default
development branch.

| Channel | Supported |
|---------|-----------|
| Latest signed macOS release | Yes |
| Latest signed Windows release | Yes |
| Previous minor release line | Security fixes when maintainers announce support |
| Unsigned local builds and CI artifacts | No production support |
| Steam/SteamOS planning track | Not a production client until announced |

## Reporting a Vulnerability

Do not open a public issue for suspected vulnerabilities.

Use GitHub private vulnerability reporting or a private security advisory
for this repository when available. If GitHub private reporting is not
available, contact the maintainers through the security contact listed
on the repository owner profile.

Maintainers aim to acknowledge actionable reports within 5 business days
and provide a remediation or disclosure plan once impact and affected
versions are understood. Coordinated disclosure timelines depend on
severity, exploitability, affected release channels, and dependency
coordination.

Useful reports include:

- affected commit, tag, or branch
- reproduction steps
- expected and actual behavior
- impact assessment
- relevant logs with secrets, keys, IPs, hostnames, peer identifiers,
  customer data, and personal data removed

## Scope

In scope:

- Rust mesh core crypto, replay, routing, discovery, relay, and transport code
- Swift keychain, profile, tunnel, packet pump, and support bundle code
- Windows service privilege boundary, Wintun/WFP integration, DPAPI
  secret handling, named-pipe IPC, installer, and update behavior
- packaging, signing, notarization, update, and release automation
- privacy defaults and diagnostics export behavior
- production rendezvous, relay, and update channels when operated by the
  project maintainers

Out of scope:

- attacks requiring physical access to an unlocked developer workstation
- public exposure of the development rendezvous or relay binaries without additional hardening
- vulnerabilities in third-party services outside this repository
- unsigned local builds, unofficial packages, or modified binaries not
  distributed by the maintainers

## Operational Caveats

The development rendezvous and relay binaries are local protocol tools.
Do not expose them on the public internet without TLS, authentication
policy, rate limits, abuse monitoring, durable revocation, retention
controls, and operational monitoring.

There is no bug bounty program unless one is announced by the
maintainers. Valid reports may receive public credit if the reporter
requests it and coordinated disclosure permits it.
