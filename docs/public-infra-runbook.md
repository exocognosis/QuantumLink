# Public Rendezvous, STUN, TURN, And Relay Runbook

This runbook covers a production-candidate public edge for QuantumLink macOS
validation while Apple credentials are still pending.

## Current Boundary

The repo can now prove live rendezvous, STUN, optional TURN allocation, signed
peer-record publication of gathered ICE candidates, end-to-end PQC app-relay
fallback, resident TURN data-plane behavior, and app-layer rendezvous/relay
admission with `scripts/public-infra-smoke.sh`.

Do not treat the in-repo rendezvous and QuantumLink relay binaries as broadly
open internet production services yet. They now support TLS for their control
protocols behind the explicit `public-edge-tls` feature, bearer-token admission
from credential files, per-client IP rate limits, loopback OpenMetrics service
counters, bounded request lines, connection ceilings, idle timeouts, relay
payload/peer caps, and smoke proof that unauthenticated and oversized clients
are rejected and counted. Keep those two ports source-limited for named testers
until per-peer saturation quotas, retention policy, durable revocation, and a
complete operator abuse workflow are in place.

STUN and coturn TURN may be internet-facing. Published TURN relay candidates
are consumed by the mesh connector when the responder keeps a live allocation.
The QuantumLink data-plane relay is the app relay path and is published as a
signed `quantum_link_relay` candidate when a responder is configured with
`--relay`. The default public smoke uses coturn to prove allocation and
candidate gathering, then proves end-to-end PQC fallback through the
QuantumLink app relay. The `--prove-turn-relay` mode instead publishes a
resident TURN allocation and requires the connector to report
`selected_path=turn-relay`.

## Edge Layout

Use the templates under `infra/public-edge/`:

- `public-edge.env.example`: central port, path, realm, and TURN values.
- `systemd/quantumlink-rendezvous.service`: TLS rendezvous service.
- `systemd/quantumlink-relay.service`: end-to-end PQC relay carrier.
- `systemd/quantumlink-stun-primary.service`: auxiliary STUN port for NAT mapping checks.
- `systemd/quantumlink-stun-secondary.service`: second auxiliary STUN port for NAT mapping checks.
- `coturn/turnserver.conf.template`: authenticated coturn allocation service.
- `ufw.rules.example`: source allowlisting and public UDP/TURN firewall shape.

Expected default ports:

| Service | Port | Exposure |
|---|---:|---|
| Rendezvous | TCP 9471 | TLS plus token admission; source-limited for beta |
| QuantumLink relay | TCP 9472 | TLS plus token admission; source-limited for beta |
| coturn STUN/TURN | UDP 3478 | public |
| QuantumLink STUN auxiliary | UDP 3479-3480 | public |
| TURN TLS | TCP 5349 | public when configured with a real certificate |
| TURN relay allocation range | UDP 49160-49200 | public |
| Rendezvous metrics | TCP 9571 | loopback only |
| Relay metrics | TCP 9572 | loopback only |

## Deploy

On a clean Ubuntu edge host:

```sh
sudo useradd --system --home /var/lib/quantumlink --shell /usr/sbin/nologin quantumlink || true
sudo apt-get update
sudo apt-get install -y coturn
sudo install -d -o quantumlink -g quantumlink /opt/quantumlink/bin /var/lib/quantumlink /var/log/quantumlink
sudo install -d -o turnserver -g turnserver -m 0750 /var/log/turnserver

cargo build -p qlink-core --release --bin qlinkctl --features dev-quic-carrier,public-edge-tls
sudo install -m 0755 target/release/qlinkctl /opt/quantumlink/bin/qlinkctl

sudo install -d -m 0755 /etc/quantumlink /etc/quantumlink/tls
sudo install -d -m 0750 /etc/quantumlink/secrets
sudo install -m 0640 infra/public-edge/public-edge.env.example /etc/quantumlink/public-edge.env
sudo install -m 0644 infra/public-edge/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Edit `/etc/quantumlink/public-edge.env` before starting services. Set the real
public IP, realm, TLS cert/key paths, rate-limit windows, and high-entropy TURN
password. Keep `QLINK_RENDEZVOUS_METRICS_ADDR` and
`QLINK_RELAY_METRICS_ADDR` bound to loopback unless a local collector owns a
different private bind. Write rendezvous and relay service tokens into
root-owned credential files instead of `ExecStart` arguments:

```sh
openssl rand -base64 32 | sudo tee /etc/quantumlink/secrets/rendezvous-auth-token >/dev/null
openssl rand -base64 32 | sudo tee /etc/quantumlink/secrets/relay-auth-token >/dev/null
sudo chown root:root /etc/quantumlink/secrets/*-auth-token
sudo chmod 0400 /etc/quantumlink/secrets/*-auth-token
```

Install a real edge certificate and key at the paths configured by
`QLINK_RENDEZVOUS_TLS_CERT`, `QLINK_RENDEZVOUS_TLS_KEY`,
`QLINK_RELAY_TLS_CERT`, and `QLINK_RELAY_TLS_KEY`. For shared beta testing,
prefer a publicly trusted certificate for the DNS name testers will use; for a
private rehearsal, distribute the matching CA file and pass
`--control-tls-ca`.

Then apply equivalent firewall rules from
`infra/public-edge/ufw.rules.example`.

Start the QuantumLink services only after TLS files, credential files, and
firewall allowlisting are in place:

```sh
sudo systemctl enable --now quantumlink-rendezvous quantumlink-relay
sudo systemctl enable --now quantumlink-stun-primary quantumlink-stun-secondary
```

For TURN, render `turnserver.conf.template` with the values from
`/etc/quantumlink/public-edge.env`, install it to `/etc/turnserver.conf`, then
restart coturn:

```sh
set -a
. /etc/quantumlink/public-edge.env
set +a
envsubst < infra/public-edge/coturn/turnserver.conf.template | sudo tee /etc/turnserver.conf >/dev/null
sudo chown root:turnserver /etc/turnserver.conf
sudo chmod 0640 /etc/turnserver.conf
sudo systemctl enable --now coturn
```

coturn owns UDP 3478 and also answers STUN binding requests there. Keep
coturn's relay port range narrow and explicitly opened in the host and cloud
firewalls.

TURN TLS on TCP 5349 requires `QLINK_TURN_CERT` and `QLINK_TURN_PKEY` to
point to readable certificate and private-key files. Use a real edge certificate
for shared testing; a short-lived self-signed cert is acceptable only for
allocation-path smoke proof.

## Proof

From a tester machine outside the edge host, prefer the live evidence
orchestrator. It runs both required public paths, verifies each
`evidence.json` with `scripts/verify-public-infra-evidence.rb`, and writes a
single redacted manifest under
`build/public-edge-live-evidence/<timestamp>/manifest.json`:

Create a tester-side `edge-public.env` containing:

```sh
QLINK_PUBLIC_EDGE_HOST=EDGE_HOST
QLINK_CONTROL_TLS_CA=/path/to/control-ca-or-public-chain.pem
QLINK_RENDEZVOUS_AUTH_TOKEN_FILE=/path/to/rendezvous-auth-token
QLINK_RELAY_AUTH_TOKEN_FILE=/path/to/relay-auth-token
QLINK_TURN_USERNAME=qlink-turn
QLINK_TURN_PASSWORD_FILE=/path/to/turn-password
QLINK_TURN_REALM=turn.quantumlink.example
QLINK_TURN_PERMIT_PEER_IP=TESTER_PUBLIC_IP
QLINK_RENDEZVOUS_METRICS_ADDR=127.0.0.1:9571
QLINK_RELAY_METRICS_ADDR=127.0.0.1:9572
QLINK_MAX_REQUEST_LINE_BYTES=131072
QLINK_MAX_CONCURRENT_CONNECTIONS=1024
QLINK_IDLE_TIMEOUT_SECONDS=300
QLINK_RELAY_MAX_PAYLOAD_BYTES=65536
QLINK_RELAY_MAX_PEER_ID_BYTES=256
QLINK_RELAY_MAX_REGISTERED_PEERS=2048
```

Then run:

```sh
scripts/public-edge-live-evidence.sh --env-file ./edge-public.env --build
```

If those values are already exported in the shell, omit `--env-file`. For an
off-host tester, forward the edge loopback metrics ports first, for example
`ssh -N -L 9571:127.0.0.1:9571 -L 9572:127.0.0.1:9572 EDGE_HOST`.

The orchestrator deliberately uses environment variables or token files for
secrets instead of passing service tokens as command-line arguments. It records
only credential-source metadata such as `file` or `environment` in the manifest.

If you need to debug one proof at a time, run the underlying smoke command
directly. This default command proves TLS rendezvous/relay admission, STUN,
TURN allocation, signed candidate publication, and app-layer PQC fallback
through the QuantumLink relay:

```sh
scripts/public-infra-smoke.sh \
  --rendezvous tls://EDGE_HOST:9471 \
  --relay tls://EDGE_HOST:9472 \
  --stun EDGE_HOST:3478 \
  --control-tls-ca /path/to/control-ca-or-public-chain.pem \
  --rendezvous-auth-token "$QLINK_RENDEZVOUS_AUTH_TOKEN" \
  --relay-auth-token "$QLINK_RELAY_AUTH_TOKEN" \
  --turn EDGE_HOST:3478 \
  --turn-username "$QLINK_TURN_USERNAME" \
  --turn-password "$QLINK_TURN_PASSWORD" \
  --turn-realm "$QLINK_TURN_REALM" \
  --rendezvous-metrics-addr "$QLINK_RENDEZVOUS_METRICS_ADDR" \
  --relay-metrics-addr "$QLINK_RELAY_METRICS_ADDR" \
  --max-request-line-bytes "$QLINK_MAX_REQUEST_LINE_BYTES" \
  --max-concurrent-connections "$QLINK_MAX_CONCURRENT_CONNECTIONS" \
  --idle-timeout-seconds "$QLINK_IDLE_TIMEOUT_SECONDS" \
  --relay-max-payload-bytes "$QLINK_RELAY_MAX_PAYLOAD_BYTES" \
  --relay-max-peer-id-bytes "$QLINK_RELAY_MAX_PEER_ID_BYTES" \
  --relay-max-registered-peers "$QLINK_RELAY_MAX_REGISTERED_PEERS" \
  --build
```

To prove the TURN data plane instead of the QuantumLink app-relay path, run the
same command with `--prove-turn-relay` and set the permitted peer IP to the
tester machine's public egress address:

```sh
scripts/public-infra-smoke.sh \
  --rendezvous tls://EDGE_HOST:9471 \
  --relay tls://EDGE_HOST:9472 \
  --stun EDGE_HOST:3478 \
  --control-tls-ca /path/to/control-ca-or-public-chain.pem \
  --rendezvous-auth-token "$QLINK_RENDEZVOUS_AUTH_TOKEN" \
  --relay-auth-token "$QLINK_RELAY_AUTH_TOKEN" \
  --turn EDGE_HOST:3478 \
  --turn-username "$QLINK_TURN_USERNAME" \
  --turn-password "$QLINK_TURN_PASSWORD" \
  --turn-realm "$QLINK_TURN_REALM" \
  --turn-permit-peer-ip "$TESTER_PUBLIC_IP" \
  --rendezvous-metrics-addr "$QLINK_RENDEZVOUS_METRICS_ADDR" \
  --relay-metrics-addr "$QLINK_RELAY_METRICS_ADDR" \
  --max-request-line-bytes "$QLINK_MAX_REQUEST_LINE_BYTES" \
  --max-concurrent-connections "$QLINK_MAX_CONCURRENT_CONNECTIONS" \
  --idle-timeout-seconds "$QLINK_IDLE_TIMEOUT_SECONDS" \
  --relay-max-payload-bytes "$QLINK_RELAY_MAX_PAYLOAD_BYTES" \
  --relay-max-peer-id-bytes "$QLINK_RELAY_MAX_PEER_ID_BYTES" \
  --relay-max-registered-peers "$QLINK_RELAY_MAX_REGISTERED_PEERS" \
  --prove-turn-relay \
  --build
```

For an offline local rehearsal:

```sh
scripts/public-infra-smoke.sh --local --admission-token local-edge-secret --build
scripts/public-infra-smoke.sh --local --control-tls --admission-token local-edge-secret --build
scripts/public-infra-smoke.sh --local --prove-turn-relay --admission-token local-edge-secret --build
```

The smoke run writes `build/public-infra-smoke/<timestamp>/evidence.json`. A
passing evidence file must show:

- `stun_reflexive` is non-empty;
- `rendezvous_tls_enabled` and `relay_tls_enabled` are `true` for public edge
  runs;
- `rendezvous_auth_required`, `relay_auth_required`,
  `rendezvous_auth_verified`, and `relay_auth_verified` are `true` for public
  edge runs;
- `rendezvous_metrics_scraped` and `relay_metrics_scraped` are `true`, with
  auth failure counters greater than zero;
- `bounds_verified` and `relay_payload_limit_verified` are `true`;
- `rendezvous_request_too_large_total`, `relay_request_too_large_total`, and
  `relay_payload_too_large_total` are greater than zero;
- request-line, connection, idle-timeout, relay-payload, peer-ID, and
  registered-peer limits are positive;
- `turn_relayed` is non-empty when `--turn` was supplied;
- `published_candidate_types` includes `ServerReflexive`;
- `published_candidate_types` includes `QuantumLinkRelay`;
- `published_candidate_types` includes `Relay` when `--turn` was supplied;
- `selected_path` is `relay`;
- `relay_forwarded_datagrams_total` is greater than or equal to `frames_sent`;
- `frames_sent` matches the requested count.

For `--prove-turn-relay`, the passing evidence changes to:

- `prove_turn_relay` is `true`;
- `turn_responder_relayed` is non-empty;
- `published_candidate_types` is `Relay`;
- `selected_path` is `turn-relay`;
- `frames_sent` matches the requested count.

The responder deliberately publishes `127.0.0.1:1` by default as its host
candidate in default app-relay mode. STUN/TURN candidates are gathered and
signed into the record, but the unreachable host candidate forces direct
probing to fail quickly so the result proves the configured rendezvous plus
published QuantumLink PQC relay candidate rather than a local direct path. In
`--prove-turn-relay` mode, the resident responder publishes only its TURN relay
candidate and accepts the native carrier through TURN Send/Data indications.

To reject local or placeholder evidence before a release ledger link, run:

```sh
ruby scripts/verify-public-infra-evidence.rb \
  --require-public \
  --expected-sha "$(git rev-parse HEAD)" \
  build/public-infra-smoke/<timestamp>/evidence.json
```

For TURN data-plane evidence, add `--require-turn-relay`. The verifier blocks
loopback/private/documentation endpoints, missing TLS/auth/rate-limit proof,
missing metrics scrape proof, missing TURN proof, stale evidence, and obvious
secret placeholders.

## Hardening Checks

Before widening tester access:

- Confirm cloud firewall and host firewall expose only the listed ports.
- Confirm rendezvous and QuantumLink relay require non-placeholder admission
  token files, present TLS certificates, enforce appropriate rate limits, and
  expose only loopback service metrics while enforcing request, connection,
  idle-timeout, and relay quota bounds during source-limited beta.
- Confirm coturn uses long-term credentials and a constrained relay port range.
- Confirm coturn has readable TLS cert/key paths before exposing TCP/UDP 5349.
- Confirm `journalctl -u quantumlink-*` contains control-plane metadata only.
- Rotate the rendezvous, relay, and TURN credentials and redeploy if any appear
  in a shared transcript.
- Re-run `scripts/public-edge-live-evidence.sh` from an off-host network after
  every firewall, DNS, binary, or unit-file change.
