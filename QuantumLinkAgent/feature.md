# QuantumLink Agent Feature Specification

## Feature thesis

QuantumLink Agent is a governed private-connectivity layer for autonomous software agents, tools, APIs, and MCP services. It gives each workload a verifiable identity, connects it only to approved private resources, explains failures, and permits only bounded, deterministic-policy-controlled remediation.

The product promise is:

> Give every agent a trusted identity and a private path to exactly the tools it may use—without exposing those services publicly or giving an AI model control of the network.

Post-quantum transport is a defensible property of the connectivity layer, not the product by itself. Dytallix is an optional independently verifiable identity provider, not a mandatory account or billing system.

## Function

QuantumLink Agent sits above the QuantumLink mesh data plane. It:

- Registers autonomous workloads and binds them to a local, enterprise, or optional Dytallix identity.
- Translates signed, redacted network evidence into stable failure categories.
- Produces typed recommendations instead of privileged free-form commands.
- Enforces least-privilege connectivity and trust-mode floors deterministically.
- Requires digest-bound, expiring approval for mutable operations unless a low-risk action was explicitly pre-approved.
- Applies only allowlisted actions and records before/after state plus rollback guidance.
- Preserves a local tamper-evident audit trail.

The Agent is not part of the cryptographic trust base. It cannot hold private or session keys, inspect packet payloads or raw DNS, silently weaken policy, publish private network activity on-chain, or turn model output directly into a shell or network command.

## Initial customer and value

The initial customer is an enterprise platform or security team deploying autonomous agents across private clouds, endpoints, edge systems, and internal services.

Enterprise value is expected to come from faster secure onboarding, identity-bound least privilege, fewer broad credentials, auditable responsibility for non-human actions, faster network diagnosis, and a gradual path to post-quantum connectivity without replacing enterprise IAM.

Product/market fit remains unvalidated. The design-partner evidence gates and success measures are maintained in `docs/market-validation.md`; demos and technical novelty do not constitute PMF.

## MVP workflow

1. Register one workload and bind it to a local identity.
2. Optionally resolve a Dytallix assertion through the provider interface.
3. Associate one approved private MCP server or API resource.
4. ingest redacted mesh evidence through a future `qlink-core` adapter.
5. Diagnose identity, peer-record, handshake, path, relay, route, DNS, or platform failures.
6. Generate a versioned recommendation and action plan.
7. Evaluate the action with deterministic policy.
8. Bind approval to the exact plan digest, policy version, scope, and expiry.
9. Apply an allowlisted reversible recovery action.
10. Verify the local audit chain and roll back when requested.

## Product boundaries

- `qlink-core` owns cryptography, sessions, replay protection, rendezvous, relay, and packet transport.
- QuantumLink Agent owns intent, evidence interpretation, policy, approvals, remediation, and audit.
- Platform products own native tunnel installation and operating-system integration.
- Identity providers implement a replaceable capability interface.
- Reasoning providers implement a replaceable, redacted-evidence-only interface.

## Non-goals

- Consumer VPN functionality.
- Anonymous browsing claims.
- A hosted multi-tenant control plane in the MVP.
- Unsupervised trust, route, DNS, relay, or quarantine changes.
- Billing, marketplace, reputation, or behavioral data on-chain.
- Broad platform parity before the first design-partner integration.
- Production-readiness or PMF claims before their respective gates are met.
