# Public Beta Hardening Gates

Do not broadly expose public rendezvous or relay services until these gates are
satisfied. Bearer-token admission and per-client IP rate limits are implemented;
TLS, quotas, telemetry, revocation, and operator abuse workflows remain release
gates.

## Rendezvous

- Require non-placeholder admission tokens for publication and lookup paths.
- Enforce per-source and per-mesh rate limits beyond the current per-client IP
  window.
- Bound request line size, record size, endpoint count, and concurrent TCP connections.
- Add structured audit logs with redacted peer identifiers.
- Add expiry pruning and abuse metrics to the service-level telemetry.
- Run malformed-input, connection-churn, and record-flood stress after every change.

## Relay

- Require non-placeholder admission tokens for peer registration.
- Enforce payload size, per-peer queue depth, per-peer send rate, connection
  quotas, and idle timeouts.
- Protect against peer ID squatting and duplicate registration abuse.
- Add backpressure metrics for dropped, queued, and forwarded datagrams.
- Run relay-fallback stress with intentionally unreachable direct candidates.

## Release Gate

- Private LAN harness passes at 10, 25, and 50 peers.
- Resource sampling shows no unbounded CPU, memory, file descriptor, or socket growth.
- Expired peer records and stale certificate rotation tests pass.
- Public services run behind firewall rules that expose only intended ports.
- Incident rollback path is documented and tested.
