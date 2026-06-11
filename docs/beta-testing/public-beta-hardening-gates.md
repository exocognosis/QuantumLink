# Public Beta Hardening Gates

Do not expose public rendezvous or relay services until these gates are satisfied.

## Rendezvous

- Authenticate publication paths and reject malformed records without expensive work.
- Enforce per-source and per-mesh rate limits.
- Bound request line size, record size, endpoint count, and concurrent TCP connections.
- Add structured audit logs with redacted peer identifiers.
- Add expiry pruning and abuse metrics to the service-level telemetry.
- Run malformed-input, connection-churn, and record-flood stress after every change.

## Relay

- Authenticate or capability-gate peer registration.
- Enforce payload size, per-peer queue depth, per-peer send rate, and idle timeouts.
- Protect against peer ID squatting and duplicate registration abuse.
- Add backpressure metrics for dropped, queued, and forwarded datagrams.
- Run relay-fallback stress with intentionally unreachable direct candidates.

## Release Gate

- Private LAN harness passes at 10, 25, and 50 peers.
- Resource sampling shows no unbounded CPU, memory, file descriptor, or socket growth.
- Expired peer records and stale certificate rotation tests pass.
- Public services run behind firewall rules that expose only intended ports.
- Incident rollback path is documented and tested.
