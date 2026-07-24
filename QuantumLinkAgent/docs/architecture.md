# Modular architecture

QuantumLink Agent is a control plane above QuantumLink's post-quantum mesh. The future `qlink-core` adapter owns cryptography, sessions, replay protection, rendezvous, relay, and packets. QuantumLink Agent owns workload intent, redacted evidence, diagnosis, policy, approval, allowlisted remediation, and audit. Native platform components retain tunnel installation and operating-system integration.

```text
operator or workload intent
        |
        v
versioned contracts -> redacted evidence -> reasoning provider
                                             |
                                             v
                               typed recommendation only
                                             |
                                             v
deterministic policy -> digest-bound approval -> allowlisted executor
                                             |
                                             v
                                 hash-chained audit event
```

The reasoning provider is replaceable and never authoritative. The deterministic fallback supports a fully functional, model-free workflow. A local model or enterprise-approved API receives only evidence that passed the same redaction and forbidden-field checks.

Identity is capability-based. The MVP local provider supports workload registration and revocation. The Dytallix provider resolves independently verifiable registry state but cannot make conventional enterprise identity optional by accident. Later OIDC, SPIFFE/SPIRE, cloud workload identity, and directory providers can implement the same interface.

All wire-facing structures carry an explicit contract version. Executions reject unsupported versions, unknown action types, stale evidence, changed plan digests, expired approvals, insufficient approval scope, mismatched request IDs, and policy-version changes.
