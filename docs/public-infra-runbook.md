# Public Rendezvous, STUN, TURN, And Relay Runbook

This runbook covers a production-candidate public edge for QuantumLink macOS
validation while Apple credentials are still pending.

## Current Boundary

The repo can now prove live rendezvous, STUN, optional TURN allocation, signed
peer-record publication of gathered ICE candidates, and end-to-end PQC relay
fallback with `scripts/public-infra-smoke.sh`.

Do not treat the in-repo rendezvous and QuantumLink relay binaries as open
internet production services yet. Their client protocol is still raw TCP. Until
client-side TLS/auth lands, expose those two ports only through one of:

- a source-allowlisted firewall for named testers;
- a private overlay such as WireGuard;
- an SSH tunnel for one-off validation.

STUN and coturn TURN may be internet-facing. The QuantumLink data-plane relay is
the app relay path and is published as a signed `quantum_link_relay` candidate
when a responder is configured with `--relay`; coturn is currently used to prove
TURN allocation and ICE relay-candidate gathering.

## Edge Layout

Use the templates under `infra/public-edge/`:

- `public-edge.env.example`: central port, path, realm, and TURN values.
- `systemd/quantumlink-rendezvous.service`: raw TCP rendezvous service.
- `systemd/quantumlink-relay.service`: end-to-end PQC relay carrier.
- `systemd/quantumlink-stun-primary.service`: auxiliary STUN port for NAT mapping checks.
- `systemd/quantumlink-stun-secondary.service`: second auxiliary STUN port for NAT mapping checks.
- `coturn/turnserver.conf.template`: authenticated coturn allocation service.
- `ufw.rules.example`: source allowlisting and public UDP/TURN firewall shape.

Expected default ports:

| Service | Port | Exposure |
|---|---:|---|
| Rendezvous | TCP 9471 | allowlisted/tunneled only |
| QuantumLink relay | TCP 9472 | allowlisted/tunneled only |
| coturn STUN/TURN | UDP 3478 | public |
| QuantumLink STUN auxiliary | UDP 3479-3480 | public |
| TURN TLS | TCP 5349 | public |
| TURN relay allocation range | UDP 49160-49200 | public |

## Deploy

On a clean Ubuntu edge host:

```sh
sudo useradd --system --home /var/lib/quantumlink --shell /usr/sbin/nologin quantumlink || true
sudo install -d -o quantumlink -g quantumlink /opt/quantumlink/bin /var/lib/quantumlink /var/log/quantumlink
sudo install -d -o turnserver -g turnserver -m 0750 /var/log/turnserver

cargo build -p qlink-core --release --bin qlinkctl --features dev-quic-carrier
sudo install -m 0755 target/release/qlinkctl /opt/quantumlink/bin/qlinkctl

sudo install -d /etc/quantumlink
sudo install -m 0640 infra/public-edge/public-edge.env.example /etc/quantumlink/public-edge.env
sudo install -m 0644 infra/public-edge/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Edit `/etc/quantumlink/public-edge.env` before starting services. Set the real
public IP, realm, and high-entropy TURN password. Then apply equivalent firewall
rules from `infra/public-edge/ufw.rules.example`.

Start the raw QuantumLink services only after firewall allowlisting is in place:

```sh
sudo systemctl enable --now quantumlink-rendezvous quantumlink-relay
sudo systemctl enable --now quantumlink-stun-primary quantumlink-stun-secondary
```

For TURN, install coturn, render `turnserver.conf.template` with the values from
`/etc/quantumlink/public-edge.env`, then restart coturn. coturn owns UDP 3478
and also answers STUN binding requests there. Keep coturn's relay port range
narrow and explicitly opened in the host and cloud firewalls.

TURN TLS on TCP/UDP 5349 requires `QLINK_TURN_CERT` and `QLINK_TURN_PKEY` to
point to readable certificate and private-key files. Use a real edge certificate
for shared testing; a short-lived self-signed cert is acceptable only for
allocation-path smoke proof.

## Proof

From a tester machine outside the edge host, run:

```sh
scripts/public-infra-smoke.sh \
  --rendezvous EDGE_HOST:9471 \
  --relay EDGE_HOST:9472 \
  --stun EDGE_HOST:3478 \
  --turn EDGE_HOST:3478 \
  --turn-username "$QLINK_TURN_USERNAME" \
  --turn-password "$QLINK_TURN_PASSWORD" \
  --turn-realm "$QLINK_TURN_REALM" \
  --build
```

For an offline local rehearsal:

```sh
scripts/public-infra-smoke.sh --local --build
```

The smoke run writes `build/public-infra-smoke/<timestamp>/evidence.json`. A
passing evidence file must show:

- `stun_reflexive` is non-empty;
- `turn_relayed` is non-empty when `--turn` was supplied;
- `published_candidate_types` includes `ServerReflexive`;
- `published_candidate_types` includes `QuantumLinkRelay`;
- `published_candidate_types` includes `Relay` when `--turn` was supplied;
- `selected_path` is `relay`;
- `frames_sent` matches the requested count.

The responder deliberately publishes `127.0.0.1:1` by default as its host
candidate. STUN/TURN candidates are still gathered and signed into the record,
but that unreachable host candidate forces direct probing to fail quickly so the
result proves the configured rendezvous plus published QuantumLink PQC relay
candidate rather than a local direct path.

## Hardening Checks

Before widening tester access:

- Confirm cloud firewall and host firewall expose only the listed ports.
- Confirm rendezvous and QuantumLink relay are not globally reachable unless a
  TLS/auth client path has shipped.
- Confirm coturn uses long-term credentials and a constrained relay port range.
- Confirm coturn has readable TLS cert/key paths before exposing TCP/UDP 5349.
- Confirm `journalctl -u quantumlink-*` contains control-plane metadata only.
- Rotate the TURN password and redeploy if it appears in any shared transcript.
- Re-run `scripts/public-infra-smoke.sh` from an off-host network after every
  firewall, DNS, binary, or unit-file change.
