# Public Rendezvous, STUN, TURN, And Relay Runbook

This runbook covers a production-candidate public edge for QuantumLink macOS
validation while Apple credentials are still pending.

## Current Boundary

The repo can now prove live rendezvous, STUN, optional TURN allocation, and
end-to-end PQC relay fallback with `scripts/public-infra-smoke.sh`.

Do not treat the in-repo rendezvous and QuantumLink relay binaries as open
internet production services yet. Their client protocol is still raw TCP. Until
client-side TLS/auth lands, expose those two ports only through one of:

- a source-allowlisted firewall for named testers;
- a private overlay such as WireGuard;
- an SSH tunnel for one-off validation.

STUN and coturn TURN may be internet-facing. The QuantumLink data-plane relay is
still the app relay path; coturn is currently used to prove TURN allocation and
ICE relay-candidate gathering.

## Edge Layout

Use the templates under `infra/public-edge/`:

- `public-edge.env.example`: central port, path, realm, and TURN values.
- `systemd/quantumlink-rendezvous.service`: raw TCP rendezvous service.
- `systemd/quantumlink-relay.service`: end-to-end PQC relay carrier.
- `systemd/quantumlink-stun-primary.service`: STUN on the primary UDP port.
- `systemd/quantumlink-stun-secondary.service`: second STUN port for NAT mapping checks.
- `coturn/turnserver.conf.template`: authenticated coturn allocation service.
- `ufw.rules.example`: source allowlisting and public UDP/TURN firewall shape.

Expected default ports:

| Service | Port | Exposure |
|---|---:|---|
| Rendezvous | TCP 9471 | allowlisted/tunneled only |
| QuantumLink relay | TCP 9472 | allowlisted/tunneled only |
| STUN primary | UDP 3478 | public |
| STUN secondary | UDP 3479 | public |
| TURN TLS | TCP 5349 | public |
| TURN relay allocation range | UDP 49160-49200 | public |

## Deploy

On a clean Ubuntu edge host:

```sh
sudo useradd --system --home /var/lib/quantumlink --shell /usr/sbin/nologin quantumlink || true
sudo install -d -o quantumlink -g quantumlink /opt/quantumlink/bin /var/lib/quantumlink /var/log/quantumlink

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
`/etc/quantumlink/public-edge.env`, then restart coturn. Keep coturn's relay port
range narrow and explicitly opened in the host and cloud firewalls.

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
- `selected_path` is `relay`;
- `frames_sent` matches the requested count.

The responder deliberately publishes `127.0.0.1:1` by default as its direct
candidate. That forces direct probing to fail quickly so the result proves the
configured rendezvous plus relay path rather than a local direct path.

## Hardening Checks

Before widening tester access:

- Confirm cloud firewall and host firewall expose only the listed ports.
- Confirm rendezvous and QuantumLink relay are not globally reachable unless a
  TLS/auth client path has shipped.
- Confirm coturn uses long-term credentials and a constrained relay port range.
- Confirm `journalctl -u quantumlink-*` contains control-plane metadata only.
- Rotate the TURN password and redeploy if it appears in any shared transcript.
- Re-run `scripts/public-infra-smoke.sh` from an off-host network after every
  firewall, DNS, binary, or unit-file change.
