# QuantumLink Agent Architecture

## Purpose

QuantumLink Agent provides an agent-assisted control and explanation layer over the QuantumLink post-quantum mesh. It makes mesh behavior operable without centralizing traffic or weakening the cryptographic data plane.

## Runtime layers

```text
User or admin intent
  -> Agent UI or CLI adapter
  -> Agent runtime
  -> Policy and permissions engine
  -> Mesh, identity, diagnostics, and platform adapters
  -> Proposed action, explanation, or approved change
```

## Components

### Agent runtime

Coordinates requests, gathers redacted state, invokes constrained reasoning, and returns typed recommendations or action plans.

Responsibilities:

- Normalize user/admin intent.
- Request only the diagnostic fields needed for the task.
- Produce typed outputs, not free-form privileged commands.
- Record recommendation and action audit events.

### Policy and permissions engine

Decides whether an action is allowed, blocked, or approval-gated.

Responsibilities:

- Enforce trust-mode floors.
- Prevent silent policy weakening.
- Require approval for high-risk changes.
- Generate reversible policy patches.

### Mesh adapter

Reads `qlink-core` mesh state through a narrow, redacted interface.

Responsibilities:

- Expose peer status, path state, candidate class, relay reason, and handshake class.
- Hide private keys, session keys, packet payloads, and raw DNS contents.
- Map mesh failures to stable diagnostic categories.

### Identity adapter

Interprets Dytallix-backed identity state for Agent workflows.

Responsibilities:

- Resolve active, expired, revoked, and missing identity records.
- Cache verification results with short TTLs.
- Explain admission decisions.
- Keep traffic behavior off-chain.

### Diagnostics adapter

Builds safe evidence packets for the runtime.

Responsibilities:

- Redact sensitive fields by default.
- Preserve enough context for root-cause analysis.
- Label evidence freshness and source.
- Require approval for raw export.

### UI and CLI adapters

Expose Agent recommendations through product-specific surfaces.

Responsibilities:

- Show safe-fix cards.
- Explain approval requirements.
- Separate device identity, user identity, wallet identity, route policy, and mesh trust.
- Display direct, relay, degraded, blocked, and policy-denied states.

## Trust boundary

The Agent runtime is not part of the cryptographic trust base. It can recommend, explain, and apply approved policy changes, but it must not hold long-term secrets or change protocol invariants.

Hard exclusions:

- No private keys.
- No session keys.
- No raw packet payloads.
- No raw DNS logs.
- No on-chain traffic or route publication.
- No unapproved trust-policy downgrade.

## Action classes

`read`: inspect redacted state and explain it.

`recommend`: produce a safe action plan without changing state.

`low_risk_apply`: apply reversible non-security-sensitive cleanup under pre-approval.

`approval_required`: require explicit user or admin approval.

`forbidden`: reject the request regardless of user prompt wording.
