# QuantumLink Agent Feature Specification

## Feature thesis

QuantumLink Agent is an agentic, post-quantum mesh VPN where software agents help users and operators create, verify, repair, and govern private connectivity without turning the VPN into a centralized traffic service.

The core product promise is:

**Identity on-chain. Traffic off-chain. Policy agent-assisted. Transport post-quantum.**

The agentic layer should not replace the cryptographic protocol, bypass user consent, or become a privileged cloud controller. Its job is to make the mesh understandable and operable: propose safe routes, diagnose failed peer paths, explain trust decisions, automate routine enrollment, and surface policy conflicts before traffic leaks or peers are misclassified.

## Silo boundary

QuantumLink Agent is a distinct product silo alongside the macOS, Windows, and SteamOS client silos. It depends on shared `qlink-core` mesh, cryptography, identity, and transport primitives, but owns the agent runtime, policy guardrails, operator workflows, diagnostics interpretation, and Agent-specific UX model.

QuantumLink Agent should not redefine platform VPN packaging, native Network Extension behavior, Windows service behavior, SteamOS daemon behavior, or the shared cryptographic protocol. Those remain owned by their respective platform and core silos.

## Primary user outcomes

- Create a private peer-to-peer mesh without operating a mandatory VPN concentrator.
- Bind each peer to a post-quantum device identity and an optional Dytallix on-chain identity record.
- Let an agent inspect mesh state, explain connectivity failures, and recommend safe fixes.
- Enforce trust policies that distinguish public meshes, private meshes, and development meshes.
- Keep data-plane traffic end-to-end encrypted and off-chain, even when rendezvous or relay fallback is used.
- Preserve accountless access patterns by separating entitlement, identity, billing, and transport.

## Architecture pillars

### 1. PQC mesh data plane

QuantumLink Agent's transport model centers on a peer-to-peer mesh data plane, not a hub-and-spoke VPN concentrator. Peers establish protected sessions using the shared Rust `qlink-core` protocol surface and carry tunnel traffic through the Agent product's native packet path.

Required capabilities:

- ML-KEM-768 session establishment as the default post-quantum key agreement path.
- ML-DSA-65 device credentials for practical post-quantum peer authentication.
- Optional SLH-DSA suite support for high-assurance or specialized signing flows.
- Strict suite binding and anti-downgrade behavior.
- Signed, expiring peer records for rendezvous publication.
- ChaCha20-Poly1305 packet-frame protection with monotonic packet numbers and replay defense.
- Direct UDP path preference with relay fallback when NAT or firewall conditions block direct connectivity.
- Clear surfacing of path state: direct, relay, reconnecting, degraded, blocked, or policy-denied.

### 2. On-chain identity, off-chain traffic

QuantumLink Agent should use Dytallix-backed on-chain identity as a trust anchor for who is allowed to participate in an Agent-managed mesh, not as a place to publish traffic contents, DNS activity, routes, private endpoint metadata, or packet timing.

Identity modes:

- `Off`: no chain lookup is required; suitable for local development or isolated private testing.
- `Verified`: peers must resolve to an active registry record before joining a protected mesh.
- `Public Wallet`: peers may expose a public wallet-linked identity for public or community meshes.

Trust policy modes:

- `public-required`: fail closed if a peer lacks an active on-chain identity record.
- `private-preferred`: prefer verified peers while allowing explicit private allowlist exceptions.
- `development-optional`: allow local/dev peers without chain validation, with visible warnings.

On-chain identity must answer four questions:

- Is this peer registered?
- Is this device or wallet identity active?
- Is the peer revoked, expired, or quarantined?
- Which mesh policies is this peer allowed to satisfy?

It must not answer:

- What traffic did this peer send?
- Which websites, DNS names, or services did this peer access?
- Which private routes exist inside a user or organization mesh?
- Which endpoint candidates were used during a live session?

### 3. Agentic mesh operations

The agentic layer should act as a constrained local or enterprise operator assistant. It observes signed state, diagnostics, policy, and user intent, then proposes or executes bounded actions according to permission level.

Agent capabilities:

- Mesh onboarding assistant: creates device credentials, explains identity mode choices, and joins a mesh using invite material.
- Trust-policy explainer: shows why a peer was accepted, denied, relayed, quarantined, or marked unverifiable.
- Route planner: recommends split-tunnel routes, host routes, DNS behavior, and protected prefixes.
- Failure triage: diagnoses NAT, relay, identity, key, entitlement, DNS, and route conflicts.
- Recovery agent: retries candidate gathering, rotates rendezvous records, clears stale peer records, and suggests relay fallback.
- Security monitor: detects downgrade attempts, replay-window anomalies, unexpected peer-record changes, expired chain records, and local keychain access failures.
- Support-bundle assistant: prepares redacted diagnostics and explains exactly what will be exported.

Agent constraints:

- The agent must not silently weaken cryptographic policy.
- The agent must not silently switch a public mesh from `public-required` to a weaker policy.
- The agent must not publish private routes, endpoint candidates, DNS queries, or traffic metadata on-chain.
- The agent must request explicit approval before exporting diagnostics, changing identity mode, trusting a new peer, disabling a kill switch, or moving traffic to a relay when policy forbids relay usage.
- All agent actions must be logged locally with actor, reason, previous state, new state, and rollback guidance.

## Feature set

### Agentic onboarding

The onboarding flow should guide a user from install to working mesh membership with minimal manual protocol knowledge.

User-visible steps:

- Generate or import post-quantum device credentials.
- Select identity mode: `Off`, `Verified`, or `Public Wallet`.
- Join a mesh through an invite, private registry entry, or public identity record.
- Verify the peer trust chain and explain which authority or contract accepted the device.
- Test direct connectivity and relay fallback.
- Confirm protected routes and DNS behavior before enabling the tunnel.

Acceptance criteria:

- A non-expert user can understand whether they are joining a private, verified, or development mesh.
- Public meshes fail closed when required identity proof is absent.
- The UI separates user identity, device identity, wallet identity, and network route policy.

### PQC path intelligence

The VPN should expose the post-quantum session state without forcing users to read protocol logs.

User-visible state:

- Active PQC suite.
- Peer credential type.
- Last successful handshake time.
- Rekey status.
- Direct or relay path.
- Replay protection status.
- Identity verification status.

Agent-visible diagnostics:

- Handshake transcript class, without secret material.
- Suite negotiation result.
- Peer-record sequence and expiration.
- Candidate pair selection.
- Relay reason.
- Policy gate that allowed or denied the session.

Acceptance criteria:

- The agent can explain a failed connection in plain language and map it to the exact failing layer.
- The agent can distinguish cryptographic failure, identity failure, NAT traversal failure, route conflict, and platform entitlement failure.
- The agent cannot reveal private keys, session keys, packet payloads, or raw DNS contents.

### Dytallix identity integration

The identity layer should use Dytallix registry state to authorize peer participation while preserving off-chain privacy.

Required flows:

- Register a device or wallet-linked identity.
- Resolve a peer's active registry state.
- Detect revoked, expired, or missing records.
- Cache signed verification results with short TTLs.
- Re-check identity state before accepting public-mesh peer records.
- Surface chain lookup failures separately from peer cryptographic failures.

Policy behavior:

- Public mesh: verified registry record required.
- Private mesh: local allowlist can override registry absence only when policy explicitly permits it.
- Development mesh: registry lookup can be bypassed, but the UI must label the mesh as development-grade.

Acceptance criteria:

- The identity subsystem can be disabled for local development without changing the PQC transport.
- Public identity enforcement is a transport admission gate, not a billing or account-login substitute.
- Billing, entitlement checks, and account state stay outside the packet transport path.

### Agentic policy guardrails

The product should support agents that help operators manage policy without becoming an unaccountable policy authority.

Supported policy objects:

- Mesh trust mode.
- Peer allowlist and denylist.
- Route ownership.
- Relay permission.
- DNS behavior.
- Diagnostics export scope.
- Device quarantine.
- Credential rotation and revocation.

Agent actions:

- Recommend a policy change.
- Generate a reversible policy patch.
- Explain blast radius before applying a change.
- Apply low-risk changes under pre-approved automation.
- Require approval for high-risk changes.

High-risk changes:

- Weakening identity verification.
- Disabling fail-closed routing.
- Trusting a new peer.
- Allowing relay paths for sensitive meshes.
- Exporting raw diagnostics.
- Changing default DNS or full-tunnel behavior.
- Clearing quarantine or revocation state.

### Privacy-preserving operations

QuantumLink Agent should minimize persistent metadata at every layer.

Privacy rules:

- Traffic payloads remain encrypted end-to-end and off-chain.
- DNS content is not exported by default.
- Private routes are not published to public chain records.
- Rendezvous records are signed, scoped, and expiring.
- Relay services should not learn payload contents.
- Diagnostics are local-first and redacted by default.
- Agent prompts and summaries must not include packet payloads, private keys, raw DNS logs, or stable private endpoint metadata unless an operator explicitly exports them.

Acceptance criteria:

- A support bundle can explain failures without exposing raw packet contents.
- Agent-generated explanations use redacted peer aliases unless the user chooses to reveal identity labels.
- Chain records prove membership or trust state, not behavior.

## Reference product flows

### Flow 1: Join a verified public mesh

1. User receives an invite or discovers a public QuantumLink Agent mesh.
2. The onboarding agent checks whether the mesh requires `public-required` identity.
3. The client creates or imports PQC device credentials.
4. The client resolves the user's Dytallix identity record.
5. The client publishes a signed, expiring peer record.
6. The mesh validates registry state before accepting the peer.
7. The tunnel establishes an ML-KEM-768 session and selects direct or relay path.
8. The agent explains the final trust decision and path state.

### Flow 2: Diagnose a failed peer connection

1. User asks why a peer is unreachable.
2. The agent checks identity state, peer-record freshness, candidate gathering, relay policy, and route ownership.
3. The agent classifies the failure as identity, cryptographic, network traversal, relay, platform, or policy.
4. The agent recommends the safest fix.
5. If the fix changes trust or routing policy, the user approves it before application.

### Flow 3: Quarantine a suspicious peer

1. The security monitor detects a revoked registry record, unexpected peer-record sequence jump, repeated replay-window failure, or admin report.
2. The agent proposes quarantine with evidence.
3. QuantumLink Agent blocks new sessions for that peer.
4. Existing protected routes for that peer fail closed.
5. The admin can rotate credentials, revoke identity, or restore trust with an auditable action.

## Product surfaces

### User app

- Mesh status.
- Identity status.
- Current route and DNS policy.
- Peer list with trust labels.
- Direct vs relay connection state.
- Agent explanation panel.
- Safe-fix action cards.
- Diagnostics export flow.

### Admin surface

- Mesh trust-mode configuration.
- Dytallix registry integration.
- Peer enrollment and revocation.
- Device quarantine.
- Route ownership.
- Relay policy.
- Audit log.
- Managed deployment policy.

### CLI

- Generate device credentials.
- Resolve identity status.
- Simulate handshake.
- Inspect peer record.
- Test rendezvous.
- Test direct and relay paths.
- Export redacted diagnostics.
- Apply signed policy patches.

## Non-goals

- No claim of anonymous browsing.
- No promise that public-internet meshes require zero helper services.
- No centralized VPN concentrator as the required steady-state data plane.
- No publication of traffic, DNS, private routes, or endpoint candidates on-chain.
- No agent authority to weaken cryptography or identity policy without approval.
- No production claim until signing, notarization, hardened rendezvous/relay operations, and full platform rebuilds are complete.

## Roadmap

### Phase 1: Explainable verified mesh

- Surface identity mode and trust policy in the app.
- Add agent-readable diagnostics for handshake, route, relay, and identity state.
- Build plain-language failure explanations.
- Keep all agent actions recommendation-only.

### Phase 2: Bounded agent actions

- Add reversible policy patches.
- Allow approved low-risk recovery actions.
- Add route-conflict and relay-policy remediation.
- Add local audit log for agent recommendations and actions.

### Phase 3: Enterprise-ready agentic operations

- Integrate managed policy delivery.
- Add device quarantine workflows.
- Add registry-backed revocation monitoring.
- Add admin-scoped diagnostics and approval gates.
- Add production relay and rendezvous hardening.

## Success metrics

- Time to first verified mesh connection.
- Percentage of failed connections with correctly classified cause.
- Percentage of public-mesh admissions backed by active registry records.
- Direct-path success rate before relay fallback.
- Mean time to recover after sleep, network change, or peer-record expiry.
- Number of policy changes applied without weakening trust mode.
- Diagnostics exports completed with default redaction intact.

## Positioning line

QuantumLink Agent is an agentic post-quantum mesh VPN that uses on-chain identity for trust, keeps traffic off-chain for privacy, and lets constrained agents help people operate secure peer-to-peer networks without centralizing the data plane.
