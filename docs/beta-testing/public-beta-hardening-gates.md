# Public Beta Hardening Gates

Do not broadly expose public rendezvous or relay services until these gates are
satisfied. Bearer-token admission, per-client IP rate limits, loopback
OpenMetrics service counters, bounded request lines, connection ceilings, idle
timeouts, and relay payload/registration caps are implemented; TLS
control-plane support is implemented behind the explicit `public-edge-tls`
feature. Per-peer saturation quotas, durable revocation, retention controls,
and operator abuse workflows remain release gates.

## Rendezvous

- Require non-placeholder admission tokens for publication and lookup paths.
- Enforce per-source and per-mesh rate limits beyond the current per-client IP
  window.
- Extend record-specific bounds for endpoint count and per-mesh publication
  volume beyond the current request-line and connection ceilings.
- Add structured audit logs with redacted peer identifiers.
- Add expiry-pruning counters and connect the service metrics to the operator
  alerting pipeline.
- Run malformed-input, connection-churn, and record-flood stress after every change.

## Relay

- Require non-placeholder admission tokens for peer registration.
- Extend per-peer queue depth and per-peer send-rate quotas beyond the current
  payload, registered-peer, connection, and idle-timeout caps.
- Protect against peer ID squatting and duplicate registration abuse.
- Extend backpressure metrics for queued datagrams and per-peer saturation.
- Run relay-fallback stress with intentionally unreachable direct candidates.

## Release Gate

- Private LAN harness passes at 10, 25, and 50 peers.
- Resource sampling shows no unbounded CPU, memory, file descriptor, or socket growth.
- Expired peer records and stale certificate rotation tests pass.
- Public services run behind firewall rules that expose only intended ports.
- Off-host `scripts/public-edge-live-evidence.sh` produces a passing
  `manifest.json` with both app-relay and resident TURN relay proofs plus
  metrics-scrape proof.
- `scripts/verify-public-infra-evidence.rb --require-public` rejects local,
  placeholder, stale, unauthenticated, non-TLS, and no-rate-limit evidence.
- Incident rollback path is documented and tested.
