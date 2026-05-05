# Self-hosted QuantumLink coordinator

Stand up your own rendezvous + relay infrastructure in under five minutes. Two paths — pick the one that matches your ops posture.

## TL;DR

```bash
# Path A: Docker Compose (recommended for VPS deployments)
git clone https://github.com/exocognosis/QuantumLink && cd QuantumLink/deploy
docker compose up -d
docker compose logs -f qlinkd      # confirm services bound
```

```bash
# Path B: systemd (recommended for bare-metal or LXC)
cargo build --release --bin qlinkd --manifest-path rust/qlink-core/Cargo.toml
sudo install -m 755 rust/qlink-core/target/release/qlinkd /usr/local/bin/qlinkd
sudo useradd --system --no-create-home --shell /usr/sbin/nologin quantumlink
sudo install -m 644 deploy/qlinkd.service /etc/systemd/system/qlinkd.service
sudo systemctl daemon-reload
sudo systemctl enable --now qlinkd
sudo journalctl -u qlinkd -f       # confirm services bound
```

## Why self-host

QuantumLink's mesh model needs a rendezvous service for peers to find each other and a relay for traffic between peers stuck behind symmetric NATs. **You don't have to use ours** — you almost certainly shouldn't, if you care about sovereignty:

- Whoever runs the rendezvous can see *which peers are talking to which* (not the contents — that's PQ-encrypted end-to-end — but the metadata: peer A asked for peer B's record at time T).
- Whoever runs the relay sees the *encrypted* bytes pass through. Useless without the keys, but it's a record of "peer A and peer B exchanged ciphertext at time T."
- Both rendezvous and relay can be subpoenaed.

Running your own coordinator on infrastructure you control means **you own the metadata**.

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 9471 | TCP | Rendezvous (peer record store + lookup) |
| 9472 | TCP | Relay (TURN-style traffic relay for symmetric-NAT'd peers) |
| 9473 | UDP | STUN (server-reflexive address discovery) |
| 9474 | UDP | Exit relay (optional, see below) |

Open these in your cloud security group / firewall before starting the daemon.

## Optional: exit relay

By default `qlinkd` is a coordinator only — peers find each other through it and relay through it, but their traffic exits to the public internet from *their own* connection. If you want the server to act as the **exit point** (so peers' traffic appears to come from this server's IP), pass `--exit-relay`:

```yaml
# docker-compose.yml
command:
  - "qlinkd"
  - "--exit-relay"
```

This requires `CAP_NET_ADMIN` (already granted by the compose file / systemd unit) so the daemon can open `/dev/net/tun`. You'll also need to enable IP forwarding on the host:

```bash
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-qlinkd.conf
sudo sysctl -p /etc/sysctl.d/99-qlinkd.conf
```

And add an iptables masquerade rule (replace `eth0` with your egress interface):

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -j ACCEPT
```

For persistence across reboots, install `iptables-persistent` (Debian/Ubuntu) or `iptables-services` (RHEL/Fedora).

## Pointing your client at this coordinator

Once `qlinkd` is up, configure your QuantumLink client to use it. In the macOS app:

1. **Configuration → Network**
2. Set **Rendezvous URL** to `https://your-server.example.com:9471`
3. Set **Relay URL** to `your-server.example.com:9472`
4. Set **STUN server** to `your-server.example.com:9473`
5. Save.

For managed deployments, edit your `.mobileconfig` template's `VendorConfig.rendezvousServers` / `relayServers` arrays and reinstall the profile.

## Verifying the deployment

After bringing the daemon up:

```bash
# Confirm all three core services are listening:
sudo ss -tlnp sport = :9471
sudo ss -tlnp sport = :9472
sudo ss -ulnp sport = :9473

# Smoke test from a separate machine:
nc -z your-server.example.com 9471 && echo "rendezvous reachable"
nc -z your-server.example.com 9472 && echo "relay reachable"
```

If the client can't reach the server, the most common cause is a firewall in front of the box (cloud security group, hosting-provider firewall) — `qlinkd` listens on `0.0.0.0` by default but can't open ports on its own.

## Resource expectations

`qlinkd` is light. A coordinator-only deployment supporting hundreds of peers fits comfortably on:
- 1 vCPU
- 256 MB RAM
- 5 GB disk (most of which is the OS + Docker)
- 1 TB/month bandwidth (most peers establish direct paths after rendezvous; relay traffic is the exception)

Exit-relay deployments scale with how much traffic peers route through the exit. Plan for ~10x the bandwidth budget if you're the primary exit for a household-sized mesh.

## Updating

```bash
# Path A
cd /path/to/QuantumLink && git pull && docker compose up -d --build

# Path B
cd /path/to/QuantumLink && git pull
cargo build --release --bin qlinkd --manifest-path rust/qlink-core/Cargo.toml
sudo install -m 755 rust/qlink-core/target/release/qlinkd /usr/local/bin/qlinkd
sudo systemctl restart qlinkd
```

The wire protocol is versioned. A coordinator running an older revision will refuse handshakes from clients running a newer one (and vice versa) with a clear error in `journalctl`.
