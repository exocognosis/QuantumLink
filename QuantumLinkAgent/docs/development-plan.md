# QuantumLink Agent Development Plan

## Phase 0: Silo scaffold

Status: initialized.

Deliverables:

- Product feature spec.
- Silo README.
- Architecture notes.
- Policy and permissions model.
- Source, config, scripts, and tests placeholders.

## Phase 1: Typed recommendation model

Goal: represent Agent output without giving the model direct command authority.

Deliverables:

- Recommendation schema.
- Risk classification enum.
- Approval requirement enum.
- Redacted diagnostic input schema.
- Audit event schema.

Exit criteria:

- A route, identity, relay, or handshake issue can produce a typed recommendation.
- The recommendation can be rendered by any platform UI without parsing prose.

## Phase 2: Mesh diagnostics adapter

Goal: translate `qlink-core` mesh state into safe Agent evidence.

Deliverables:

- Peer status evidence.
- Handshake status evidence.
- Candidate and path state evidence.
- Relay fallback reason evidence.
- Replay and suite-negotiation status evidence.

Exit criteria:

- The Agent can distinguish identity, cryptographic, NAT traversal, relay, route, DNS, and platform failures.
- No secret material is exposed to the runtime.

## Phase 3: Dytallix identity adapter

Goal: explain and enforce on-chain identity admission decisions for Agent-managed meshes.

Deliverables:

- Active/missing/expired/revoked identity resolution.
- Trust-policy mapping.
- Short-TTL verification cache.
- Public-required fail-closed explanation.

Exit criteria:

- Public mesh admission can be explained from Dytallix identity evidence.
- Development bypasses are visibly labeled as development-grade.

## Phase 4: Policy patches and approvals

Goal: allow safe changes without creating an unaccountable operator agent.

Deliverables:

- Reversible policy patch format.
- Approval-gated action executor.
- Local audit log.
- Rollback guidance.

Exit criteria:

- High-risk changes require approval.
- Forbidden actions remain blocked.
- Low-risk changes are reversible and audited.

## Phase 5: Platform adapters

Goal: expose Agent recommendations through macOS, Windows, and SteamOS surfaces without merging those silos.

Deliverables:

- Shared UI contract.
- CLI adapter.
- Platform handoff contract.
- Support-bundle integration.

Exit criteria:

- Each platform can render Agent recommendations using its own native UI.
- Platform-specific tunnel behavior remains owned by the platform silo.
