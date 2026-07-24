# Tests

QuantumLink Agent tests should start with deterministic policy and recommendation behavior before platform integration.

Initial test areas:

- Risk-tier classification.
- Trust-mode floor enforcement.
- Forbidden-action rejection.
- Redacted diagnostic parsing.
- Typed recommendation rendering.
- Dytallix identity state mapping.
- Mesh failure classification.

Platform-specific integration tests should live in the relevant macOS, Windows, or SteamOS silo unless they are explicitly testing the Agent contract.
