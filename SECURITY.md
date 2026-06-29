# Security Policy

The QuantumLink maintainers take security vulnerabilities seriously. If you discover a security issue, report it responsibly and privately so it can be validated and fixed before public disclosure.

## Supported Status and Versions

QuantumLink is a development baseline. It is not currently a signed, notarized, production-ready VPN distribution.

Security fixes should target the default branch until formal release branches exist. When release branches or tagged production builds exist, this policy should be updated with explicit supported versions.

The current threat model is maintained in `THREAT_MODEL.md`. Quantum-era risks are covered in `QUANTUM_THREATS.md`.

## Reporting a Vulnerability

Do not open a public issue for suspected vulnerabilities, suspected key leaks, bypasses of peer authentication, or weaknesses that could expose user traffic.

Preferred contact:

- Email: `security@quantumlink.network`
- If encrypted communication is required, include your public key and the maintainers will establish a secure channel.

Additional private channels:

- GitHub private vulnerability reporting or private security advisory, when available: `https://github.com/exocognosis/QuantumLink/security/advisories/new`
- Another private maintainer channel associated with the repository owner if email and GitHub private reporting are unavailable.

Do not include exploit details in a public issue, discussion, pull request, commit message, or social-media post before coordinated disclosure.

## What To Include

Please provide:

- Affected commit, tag, branch, or release artifact.
- Description of the vulnerability.
- Impact assessment.
- Steps to reproduce.
- Proof of concept, if available.
- Expected and actual behavior.
- Suggested remediation, if known.
- Whether the issue affects local development only, public control-plane services, macOS tunnel behavior, cryptography, key storage, diagnostics, MDM/profile generation, release signing, or updates.
- Relevant logs with secrets, keys, IPs, hostnames, wallet data, peer IDs, and personal data removed.
- Any known exploitation, public disclosure, or dependency advisory references.

The more detail provided, the faster maintainers can validate and address the issue. Do not send private keys, wallet passphrases, signing identities, raw support bundles, unredacted production traffic, or third-party personal data unless a maintainer explicitly requests a secure transfer path.

## Response Targets

Maintainers should aim to:

- Acknowledge private reports within 72 hours.
- Validate findings or request more information within 14 days.
- Keep the reporter informed of material status changes.
- Coordinate public disclosure after a fix or mitigation is available when possible.

These timelines are targets for a development-stage project, not a contractual service-level agreement.

## Responsible Disclosure

Researchers are asked to:

- Avoid public disclosure before remediation or an agreed disclosure date.
- Avoid accessing, modifying, deleting, or exfiltrating user data unnecessarily.
- Avoid disrupting production systems or systems operated by third parties.
- Avoid denial-of-service testing against public infrastructure unless explicitly authorized.
- Stop testing after demonstrating impact.
- Use local builds, test accounts, local services, or explicitly authorized environments whenever possible.

Good-faith research conducted under these guidelines will not be considered unauthorized activity by the maintainers. This statement does not authorize testing against third-party services, Apple infrastructure, GitHub infrastructure, Dytallix infrastructure, or systems operated by other users.

## Scope

In scope:

- Cryptographic implementations
- ML-KEM integration
- ML-DSA integration
- SLH-DSA integration
- handshake security
- peer discovery
- authentication logic
- routing integrity
- key management
- transport encryption
- identity verification
- Rust mesh core crypto, replay, routing, discovery, relay, and transport code
- Swift keychain, profile, tunnel, packet pump, and support bundle code
- Windows Wintun/WFP service, named-pipe IPC, route/DNS programming, kill switch, and DPAPI secret storage
- Swift/Rust FFI boundaries and bundled Rust dynamic library loading
- peer authentication, signed peer records, inbound identity assertions, peer ACLs, and Dytallix registry binding
- route policy, kill-switch behavior, packet confidentiality, packet integrity, and HNDL-relevant key handling
- packaging, signing, notarization, update, and release automation
- privacy defaults and diagnostics export behavior
- example configuration that could mislead users into insecure deployment

Out of scope:

- social engineering, spam, phishing, or attacks against maintainers outside project infrastructure
- attacks requiring physical access to an unlocked developer workstation
- vulnerabilities requiring root access or full local compromise of a user's device unless they expose an additional QuantumLink-specific escalation or persistence risk
- public exposure of the development rendezvous or relay binaries without additional hardening
- vulnerabilities in third-party services outside this repository
- denial-of-service reports that do not identify an amplification, crash, resource-exhaustion, authentication-bypass, or production-exposure issue
- issues in unsupported forks or modified builds that cannot be reproduced against this repository

## Disclosure Process

1. Report received through a private channel.
2. Maintainers acknowledge receipt and may request more information.
3. Vulnerability is validated and severity is assessed.
4. Remediation, mitigation, or documentation is developed.
5. Fix is released or merged.
6. Coordinated disclosure is published when appropriate.

## Operational Caveats

The development rendezvous and relay binaries are local protocol tools. Do not expose them on the public internet without TLS, authentication policy, rate limits, abuse monitoring, durable revocation, and retention controls.

The current packet-frame encryption path is development-scaffolded. Production peer sessions still need to install negotiated session keys into packet-frame encryption before QuantumLink should be used or marketed as a production traffic-confidential VPN.

## Security Principles

QuantumLink is designed around:

- Post-quantum cryptography
- Zero-trust networking
- Decentralized identity
- Defense in depth
- Fail-closed packet handling
- Privacy-preserving defaults
- Open-source review

Community review and responsible disclosure are essential to improving the security of the project.

There is no bug bounty program unless one is announced by the maintainers in this repository.
