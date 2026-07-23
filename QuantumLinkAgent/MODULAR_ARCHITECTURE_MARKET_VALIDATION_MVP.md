# QuantumLink Agent: Modular Architecture, Market Validation, and MVP

## Summary

QuantumLink Agent is a **governed private-connectivity layer for autonomous software agents, tools, and MCP services**. Its function is to give each workload a verifiable identity, establish post-quantum protected paths, enforce least-privilege network policy, explain failures, and apply only bounded, auditable remediation.

The initial customer is an enterprise platform or security team deploying agents across laptops, private clouds, edge systems, and internal services. The strongest value proposition is:

> Give every agent a trusted identity and a private path to exactly the tools it may use—without exposing those services publicly or giving an AI model control of the network.

The current determination is a promising problem/solution-fit hypothesis, but product/market fit is not yet proven. Enterprise vendors are extending zero-trust identity, authorization, runtime guardrails, and auditability to autonomous agents, confirming the problem category. Broad experimentation combined with limited production adoption indicates urgency and an immature buying market rather than established demand for this specific product.

## Product and Architecture

The initial job is to securely connect an identified autonomous agent to approved tools, MCP servers, APIs, and peer agents across private infrastructure.

The ownership boundaries are:

- `qlink-core` owns cryptography, sessions, replay protection, rendezvous, relay, and packet transport.
- QuantumLink Agent owns intent handling, diagnostic interpretation, policy decisions, approvals, remediation workflows, and audit records.
- Native platform silos retain tunnel installation and operating-system integration.

The modular Rust workspace contains:

- `agent-contracts`: versioned, serialization-only API types.
- `agent-runtime`: orchestration and workflow state machine.
- `agent-evidence`: redaction, freshness, provenance, and diagnostic classification.
- `agent-policy`: deterministic authorization and risk evaluation.
- `agent-actions`: allowlisted executors with preconditions, postconditions, and rollback.
- `agent-identity`: local identity and optional Dytallix verification behind a provider interface.
- `agent-reasoning`: deterministic fallback plus a pluggable local-model or enterprise-approved API boundary.
- `agent-audit`: append-only, tamper-evident action and approval records.
- `agent-cli`: the MVP operator surface.

The language model remains outside the security boundary. It may convert intent and redacted evidence into typed proposals, but the deterministic policy engine independently validates every proposal before execution. Capability-based adapters allow future reasoning models, identity systems, policy stores, mesh integrations, and platform clients without changing the runtime or transport core.

Dytallix is an optional trust provider rather than an adoption prerequisite. It adds independently verifiable registry and revocation evidence for cross-organization use cases. Post-quantum cryptography is a defensible technical property supporting the larger enterprise outcome; it is not the product by itself.

## Public Interfaces

The versioned public contracts are:

- `AgentRequest`: actor, target workload, intent, requested capability, request ID, and correlation ID.
- `EvidenceEnvelope`: redacted facts, source, collection time, expiry, and sensitivity label.
- `Recommendation`: diagnosis, confidence, evidence references, proposed action, expected result, and alternatives.
- `PolicyDecision`: allow, deny, approval-required, or forbidden, with machine-readable reasons.
- `ActionPlan`: ordered allowlisted actions, preconditions, expected state changes, and rollback guidance.
- `ApprovalRecord`: approving principal, scope, expiry, policy version, plan ID, and plan digest.
- `ActionResult`: actual state, verification result, failure category, and rollback status.
- `AuditEvent`: actor, request, evidence IDs, policy decision, before/after state, and integrity metadata.
- `IdentityProvider`: resolve, verify, revoke, refresh, and report provenance.
- `ReasoningProvider`: consume only validated redacted evidence and return schema-constrained proposals.

Contract versions are independent from UI and provider implementations. Executions reject unsupported versions, unknown action types, stale evidence, altered plan digests, expired approvals, insufficient approval scope, mismatched request IDs, and policy-version drift.

## Enterprise Value and PMF Validation

The enterprise value hypotheses are:

- Reduce the time needed to securely onboard an autonomous workload to private resources.
- Replace broad network credentials with identity-bound, least-privilege connectivity.
- Prevent autonomous agents from bypassing policy or reaching unintended services.
- Give security teams an attributable record of every recommendation, approval, and applied change.
- Reduce troubleshooting time for identity, routing, relay, DNS, and handshake failures.
- Provide a migration path toward post-quantum workload connectivity without immediately replacing existing IAM.

Existing mesh products compete strongly on device posture, granular access rules, audit logs, and reversible configuration. QuantumLink therefore must win on **agent-native identity, intent-aware bounded actions, private cross-boundary connectivity, and post-quantum sessions**, not generic mesh networking.

The design-partner program should recruit two or three organizations already operating autonomous agents against private tools. Each partner must identify one concrete production-relevant workflow, such as a CI remediation agent reaching private build infrastructure or an operations agent accessing an internal MCP server.

PMF gates:

- At least 15 qualified interviews with platform, security, and AI-infrastructure owners.
- At least 5 confirm the problem is funded or tied to a production-blocking risk.
- At least 3 agree to a time-bounded pilot using a real private workload.
- At least 2 complete the pilot and request continued use, procurement, or a paid extension.
- Median onboarding time below 30 minutes.
- At least 90% of policy decisions correctly enforced in the pilot test suite.
- At least 80% of injected connectivity failures correctly classified.
- At least 50% reduction in operator diagnosis time versus the partner's current workflow.
- Zero private-key, session-key, packet-payload, or raw-DNS disclosure through Agent evidence or reasoning prompts.

Failure to obtain paid continuation means PMF is not demonstrated. Interview enthusiasm, technical novelty, downloads, and successful demonstrations are supporting evidence only.

## MVP

The MVP is a CLI-first, single-organization design-partner release supporting one workflow:

1. Register an autonomous workload and bind it to a local or enterprise identity.
2. Optionally attach a Dytallix-backed verification record.
3. Grant access to one private MCP server or internal API through explicit policy.
4. Establish a protected direct path with relay fallback where policy permits.
5. Display identity, session, route, and policy evidence.
6. Diagnose a failed connection and generate a typed remediation plan.
7. Require approval for trust, route, DNS, or relay-policy changes.
8. Apply one allowlisted reversible recovery action and record the complete audit trail.

The MVP includes:

- CLI onboarding, status, diagnosis, planning, approval, application, rollback, and audit workflows.
- Deterministic diagnosis for identity, stale peer records, handshake failures, direct-path failures, relay-policy denials, route conflicts, DNS failures, and platform failures.
- Pluggable local-first reasoning with a fully functional deterministic fallback.
- Local append-only, hash-chained audit storage and JSON export.
- A local identity provider and optional Dytallix adapter.
- One platform and `qlink-core` integration selected with the first design partner.

The MVP excludes:

- General consumer VPN functionality.
- A full administrative web console.
- Unsupervised policy changes.
- A multi-tenant hosted control plane.
- Billing, marketplace, agent reputation, and behavioral data on-chain.
- Broad Windows, macOS, and SteamOS parity.
- Claims of production readiness or established PMF.

## Verification and Acceptance

Verification covers schema compatibility, policy decisions, stale and malicious evidence, prompt injection inside diagnostic text, secret-redaction canaries, approval replay, altered plan digests, provider outages, relay denial, audit integrity, rollback behavior, and model unavailability.

Acceptance requires:

- The workflow remains safe and operable with model reasoning disabled.
- Every mutation passes deterministic authorization immediately before execution.
- No Agent component receives private keys, session keys, packet payloads, or raw DNS data.
- Unknown actions, stale evidence, approval alteration, expiry, scope mismatch, and policy drift fail closed.
- Successful mutations can be rolled back and both operations appear in a valid audit hash chain.

The current repository implements the modular control-plane MVP and its CLI demonstration. A real `qlink-core` evidence/transport adapter and an end-to-end private MCP or API connection remain required before claiming a live networking MVP or production readiness.

## Assumptions

- QuantumLink Agent remains a separate product silo and integrates with `qlink-core` through a narrow adapter.
- Core cryptographic, replay, rendezvous, relay, and identity primitives are implementation foundations rather than evidence that Agent workflows are already shipped.
- The primary market wedge is infrastructure for autonomous software agents, not an assistant added to a conventional employee VPN.
- The MVP targets design partners rather than self-serve adoption.
- Dytallix remains optional and provider-based.
- Reasoning is pluggable and local-first; policy enforcement is always deterministic.
- PMF remains unvalidated until real pilot retention or paid continuation meets the stated gates.
