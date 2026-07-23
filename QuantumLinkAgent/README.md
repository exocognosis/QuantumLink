# QuantumLink Agent

QuantumLink Agent is a governed private-connectivity layer for autonomous software agents, tools, APIs, and MCP services. It binds workloads to verifiable identities, explains post-quantum mesh state, evaluates every proposed mutation through deterministic policy, and records approved remediation in a tamper-evident audit trail.

> Give every agent a trusted identity and a private path to exactly the tools it may use—without exposing those services publicly or giving an AI model control of the network.

## Product status

This repository is an MVP foundation for design-partner validation. Product/market fit is not proven, and the repository does not claim production readiness. The current release implements the safe control-plane contracts and a local CLI workflow. Integration with QuantumLink's `qlink-core` data plane remains an adapter boundary.

## Security boundary

- Models can explain redacted evidence and propose typed actions.
- Deterministic policy independently allows, gates, or forbids every action.
- Only allowlisted executors can mutate state.
- Approvals bind to a plan digest, policy version, capability scope, and expiry.
- Agent components must never receive private keys, session keys, packet payloads, or raw DNS data.
- Dytallix is an optional identity provider, not an adoption prerequisite.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `qlink-agent-contracts` | Versioned public request, evidence, recommendation, policy, plan, approval, result, and audit types |
| `qlink-agent-evidence` | Secret-field rejection, redaction, hostile-text neutralization, and deterministic classification |
| `qlink-agent-policy` | Model-independent fail-closed authorization |
| `qlink-agent-actions` | Allowlisted reversible action execution |
| `qlink-agent-identity` | Local and optional Dytallix identity providers |
| `qlink-agent-reasoning` | Deterministic fallback and pluggable reasoning boundary |
| `qlink-agent-audit` | Append-only JSONL audit log with hash-chain verification |
| `qlink-agent-runtime` | Diagnosis, planning, approval validation, execution, rollback, and audit orchestration |
| `qlink-agent-cli` | CLI-first MVP operator workflow |

## Development

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo run -p qlink-agent-cli -- --help
```

See [docs/architecture.md](docs/architecture.md), [docs/mvp.md](docs/mvp.md), and [docs/market-validation.md](docs/market-validation.md).
