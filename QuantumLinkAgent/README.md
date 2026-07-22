# QuantumLink Agent

QuantumLink Agent is the agentic VPN product silo for QuantumLink. It turns the shared post-quantum mesh architecture into an agent-assisted operating surface for onboarding, trust verification, policy repair, diagnostics, and guarded automation.

This silo is intentionally separate from the macOS, Windows, and SteamOS client silos. Platform clients own native packaging and tunnel integration. `qlink-core` owns shared cryptography, mesh transport, identity primitives, peer records, and packet protection. QuantumLink Agent owns the agent runtime and the decision layer that explains, recommends, and safely applies mesh operations.

## Product boundary

QuantumLink Agent owns:

- Agent runtime orchestration.
- Policy guardrails and approval gates.
- Mesh diagnostics interpretation.
- Dytallix identity explanation and admission decisions.
- Route, relay, DNS, and trust recommendations.
- Agent-specific prompts, workflows, and audit records.
- UI and CLI adapters for Agent workflows.

QuantumLink Agent does not own:

- macOS Network Extension packaging.
- Windows service packaging.
- SteamOS daemon packaging.
- Shared PQC suite definitions.
- `qlink-core` packet encryption.
- Dytallix chain contracts.
- Billing or account entitlement systems.

## Directory structure

```text
QuantumLinkAgent/
  README.md                       Silo overview and ownership boundary
  feature.md                      Product feature specification
  docs/
    architecture.md               Agent runtime architecture
    development-plan.md           Implementation roadmap
    policy-and-permissions.md     Guardrails and approval model
  src/
    README.md                     Source layout contract
    runtime/README.md             Agent runtime orchestration
    identity/README.md            Dytallix identity adapter boundary
    mesh/README.md                qlink-core mesh adapter boundary
    policy/README.md              Policy engine and patch model
    diagnostics/README.md         Redacted evidence model
    ui/README.md                  Agent-facing UI surface contracts
  config/
    agent-policy.example.toml     Example policy configuration
    prompts/mesh-diagnostics.md   Redacted diagnostics prompt template
  scripts/
    README.md                     Future local development scripts
  tests/
    README.md                     Test strategy
    fixtures/README.md            Safe fixture guidance
```

## Development stance

The current scaffold is build-neutral. It does not add a Swift package target, Rust crate, service manifest, or CI job yet. That keeps the silo visible and reviewable without disturbing active macOS, Windows, SteamOS, or `qlink-core` work.

The first implementation step should be a small Agent runtime crate or package that consumes redacted mesh state and emits typed recommendations. It should not receive private keys, session keys, raw packet payloads, or raw DNS contents.

## Initial integration points

- Shared core: `qlink-core`
- Identity source: Dytallix registry state through existing identity primitives
- Platform surfaces: macOS, Windows, and SteamOS adapters can consume Agent recommendations later
- Diagnostics: redacted support-bundle style evidence only
- Policy: explicit approval gates for high-risk changes
