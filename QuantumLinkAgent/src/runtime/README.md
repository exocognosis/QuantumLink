# Runtime

The runtime coordinates Agent requests and returns typed recommendations.

Initial responsibilities:

- Accept user or admin intent.
- Gather redacted evidence.
- Classify the request.
- Produce a typed recommendation.
- Attach risk tier and approval requirements.
- Emit audit events for applied actions.

The runtime must not hold private keys, session keys, raw packet payloads, or raw DNS contents.
