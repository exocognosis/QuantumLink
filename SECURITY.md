# Security Policy

## Supported Status

QuantumLink is a development baseline. It is not currently a signed, notarized, production-ready VPN distribution.

Security fixes should target the default branch until formal release branches exist.

## Reporting a Vulnerability

Do not open a public issue for suspected vulnerabilities.

Use GitHub private vulnerability reporting or a private security advisory for this repository when available. If that is unavailable, contact the maintainers through a private channel associated with the repository owner.

Useful reports include:

- affected commit, tag, or branch
- reproduction steps
- expected and actual behavior
- impact assessment
- relevant logs with secrets, keys, IPs, and personal data removed

## Scope

In scope:

- Rust mesh core crypto, replay, routing, discovery, relay, and transport code
- Swift keychain, profile, tunnel, packet pump, and support bundle code
- packaging, signing, notarization, update, and release automation
- privacy defaults and diagnostics export behavior

Out of scope:

- attacks requiring physical access to an unlocked developer workstation
- public exposure of the development rendezvous or relay binaries without additional hardening
- vulnerabilities in third-party services outside this repository

## Operational Caveats

The development rendezvous and relay binaries are local protocol tools. Do not expose them on the public internet without TLS, authentication policy, rate limits, abuse monitoring, durable revocation, and retention controls.

There is no bug bounty program unless one is announced by the maintainers.
