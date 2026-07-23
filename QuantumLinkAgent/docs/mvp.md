# Design-partner MVP

The CLI-first MVP proves one workflow: register an autonomous workload, authorize its access to one private tool or MCP server, inspect redacted path evidence, diagnose a failure, produce a typed remediation plan, approve the exact plan, apply one reversible action, and verify the audit trail.

## Included

- Local workload identity plus optional Dytallix resolution.
- Versioned JSON contracts.
- Identity, stale-record, handshake, direct-path, relay-policy, route, DNS, and platform diagnosis.
- Deterministic policy and reasoning fallback.
- Pluggable local-first reasoning adapter.
- Approval-bound low-risk recovery.
- Local hash-chained JSONL audit.
- CLI commands for onboarding, status, diagnosis, planning, approval, application, rollback, and audit.

## Excluded

- Consumer VPN features, a hosted multi-tenant control plane, billing, marketplace, agent reputation, an administrative web console, unsupervised trust changes, behavioral data on-chain, broad platform parity, and production-readiness claims.

## Acceptance

- The complete workflow operates with model reasoning disabled.
- Every mutation is re-authorized immediately before execution.
- Secret-bearing fields are rejected before reasoning.
- Approval replay, alteration, expiry, scope mismatch, and policy drift fail closed.
- A successful mutation can be rolled back and both operations appear in a valid audit hash chain.
