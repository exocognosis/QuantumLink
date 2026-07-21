# QuantumLink Agent Source Layout

This directory is reserved for the Agent implementation. It is not wired into the build yet.

Expected source areas:

- `runtime`: orchestration, typed recommendations, and audit events.
- `identity`: Dytallix identity adapter interfaces.
- `mesh`: shared `qlink-core` state adapter interfaces.
- `policy`: trust-mode, permissions, and patch evaluation.
- `diagnostics`: redacted evidence models.
- `ui`: platform-neutral UI contracts for Agent recommendations.

Implementation should start with typed data models before any autonomous action executor.
