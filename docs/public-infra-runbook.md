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
from credential files, per-client IP rate limits, and smoke proof that
unauthenticated clients are rejected. Keep those two ports source-limited for
named testers until connection quotas, abuse telemetry, retention policy, and
off-host deployed evidence are in place.

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
password. Write rendezvous and relay service tokens into root-owned credential
files instead of `ExecStart` arguments:

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

From a tester machine outside the edge host, run:

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
- `turn_relayed` is non-empty when `--turn` was supplied;
- `published_candidate_types` includes `ServerReflexive`;
- `published_candidate_types` includes `QuantumLinkRelay`;
- `published_candidate_types` includes `Relay` when `--turn` was supplied;
- `selected_path` is `relay`;
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

## Hardening Checks

Before widening tester access:

- Confirm cloud firewall and host firewall expose only the listed ports.
- Confirm rendezvous and QuantumLink relay require non-placeholder admission
  token files, present TLS certificates, enforce appropriate rate limits, and
  remain source-limited during beta.
- Confirm coturn uses long-term credentials and a constrained relay port range.
- Confirm coturn has readable TLS cert/key paths before exposing TCP/UDP 5349.
- Confirm `journalctl -u quantumlink-*` contains control-plane metadata only.
- Rotate the rendezvous, relay, and TURN credentials and redeploy if any appear
  in a shared transcript.
- Re-run `scripts/public-infra-smoke.sh` from an off-host network after every
  firewall, DNS, binary, or unit-file change.
