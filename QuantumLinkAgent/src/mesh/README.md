# Mesh Adapter

The mesh adapter exposes safe `qlink-core` state to QuantumLink Agent.

Initial responsibilities:

- Read peer state.
- Read handshake status.
- Read direct or relay path state.
- Read replay and suite-negotiation status.
- Classify failures without exposing secrets.

The adapter boundary should stay stable across macOS, Windows, and SteamOS client integrations.
