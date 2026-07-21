# Identity Adapter

The identity adapter interprets Dytallix-backed identity state for Agent workflows.

Initial responsibilities:

- Resolve active, missing, expired, and revoked identity records.
- Map identity state to mesh trust policy.
- Explain admission decisions.
- Cache verification state with short TTLs.

The adapter must not publish traffic behavior, DNS activity, private routes, or endpoint candidates on-chain.
