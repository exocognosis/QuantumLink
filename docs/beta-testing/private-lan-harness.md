# Private LAN Harness

Use this checklist for the multi-machine LAN run. The loopback harness is useful for scale and churn, but it cannot prove switch, Wi-Fi, multicast, firewall, or host-routing behavior.

## Topology

- 3 or more Macs or Linux hosts on the same private subnet.
- One controller host with the current QuantumLink source tree.
- One rendezvous service bound to a private address, for example `192.168.1.20:9471`.
- One relay service bound to a private address, for example `192.168.1.20:9472`.
- Peer hosts started with `qlinkctl publish-self --bind-addr 0.0.0.0:0 --rendezvous <private-rendezvous>`.

## Run

1. Build the same `qlinkctl` commit on every host.
2. Start rendezvous and relay on the controller or a dedicated host.
3. Start 10, then 25, then 50 published peers across the available machines.
4. From the controller, run `qlinkctl direct-send` to every published peer with bounded parallelism matching `scripts/lan-stress-harness.sh --direct-concurrency`.
5. Capture `phase_timing_json` from every `direct-send` output and resource samples from every host.
6. Repeat with host firewalls blocking the peer UDP responder ports to force relay fallback.

## Pass Criteria

- 10, 25, and 50 peer runs complete with zero unexpected direct-send failures.
- Relay fallback succeeds when direct candidates are intentionally unreachable.
- Rendezvous, QUIC connect, identity assertion, and datagram delivery timings are present for every send.
- CPU, RSS, file descriptor, and socket counts stay bounded on every service and peer host.
- Final rendezvous and relay smoke checks pass after stress.
