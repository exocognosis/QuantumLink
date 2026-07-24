# QuantumLink Beta Stress Test and Security Harness Analysis

**Date:** May 19, 2026
**Status:** Development beta validation
**Scope:** QuantumLink Rust development mesh services, direct QUIC responder path, and simulated LAN mesh behavior
**Result:** All bounded stress and negative-path suites completed without service failure in the tested development configuration.

## Executive Summary

QuantumLink completed three beta validation exercises covering remote provisioning, direct mesh connectivity, and simulated LAN stress behavior. The tests used the current development mesh stack: `qlinkctl` rendezvous, relay, signed peer publication, and direct QUIC DATAGRAM responder paths.

The remote Hetzner test in Falkenstein validated that a clean Ubuntu 24.04 server could build and host QuantumLink development services, publish a signed mesh peer record, survive malformed control-plane input, and continue serving smoke checks after bounded probing. The direct tunnel test then verified that the local QuantumLink instance selected a direct path to the remote responder at `46.224.175.155:9480` and remained usable after negative authorization checks, malformed input, UDP noise, and repeated connection churn. The simulated LAN test created five local peers, ran 100 direct sends, injected malformed probes and UDP noise, restarted a peer, and verified recovery.

These results are suitable for beta engineering validation, website-facing progress reporting, and investor/customer technical updates. They should not be represented as production VPN certification. The macOS Network Extension tunnel remains Apple-entitlement and signing gated, and the development rendezvous/relay services are not hardened public infrastructure.

## Test Scope

The validation covered:

- Development rendezvous service over TCP.
- Development relay service over TCP.
- Signed peer record publication.
- Direct QUIC DATAGRAM responder reachability.
- Local-to-remote direct mesh path selection.
- Local simulated LAN mesh operation with multiple peers.
- Bounded malformed-input and negative-lookup testing.
- Service restart and peer restart recovery.

The validation did not cover:

- A notarized production macOS packet tunnel extension.
- Apple-granted Network Extension deployment.
- Full ICE/STUN/TURN traversal across varied NAT environments.
- Production relay abuse controls, TLS policy, account policy, or durable revocation.
- Volumetric denial-of-service testing.
- Credential attacks, persistence, exploit chaining, or third-party target scanning.

## System Under Test

QuantumLink is a macOS-first peer-to-peer mesh VPN scaffold with a Rust protocol core and Swift/macOS surface. The tested Rust core includes:

- ML-KEM-768 session establishment without a classical key-exchange fallback.
- Transcript-bound HKDF-SHA-256 key derivation.
- ML-DSA-65 device credentials.
- Signed, expiring peer records.
- QUIC DATAGRAM development transport.
- Rendezvous and relay development services.
- Monotonic replay protection in the packet core.
- Privacy-preserving peer labels and minimized public peer records.

The project documentation explicitly marks the rendezvous and relay binaries as development protocol tools. They are useful for beta validation and now support bearer-token admission plus per-client IP rate limits, but they still require TLS, abuse monitoring, durable revocation, quota controls, and retention controls before broad public production exposure.

## Test Environments

### Remote Hetzner Environment

| Field | Value |
| --- | --- |
| Provider | Hetzner |
| Location | Falkenstein, Germany |
| Host | `46.224.175.155` |
| OS | Ubuntu 24.04 |
| Build toolchain | Rust `1.95.0` |
| Source path | `/opt/quantumlink/source` |
| Mesh ID | `hetzner-fsn1-test` |
| Published peer | `qlink_ixpCrMvwXYlcFFr9h7ECmQ` |
| Rendezvous | `0.0.0.0:9471/tcp` |
| Relay | `0.0.0.0:9472/tcp` |
| Direct responder | `46.224.175.155:9480/udp` |

### Local LAN Simulation

| Field | Value |
| --- | --- |
| Host | Local macOS development workstation |
| Network model | Loopback simulated LAN |
| Mesh ID | `lan-sim-20260519144145` |
| Rendezvous | `127.0.0.1:10000/tcp` |
| Relay | `127.0.0.1:10001/tcp` |
| Simulated peers | 5 |
| Peer responders | `127.0.0.1:10011` through `127.0.0.1:10015` |
| Stress rounds | 20 |
| Direct sends | 100 |

## Harnesses and Artifacts

| Harness | Purpose | Evidence |
| --- | --- | --- |
| Hetzner provisioning harness | Build and run remote development services | `build/security-harness/hetzner-2026-05-19.log` |
| Direct tunnel attack harness | Validate direct path and bounded negative probes | `build/security-harness/direct-tunnel-attacks-2026-05-19.log` |
| LAN stress harness | Simulate multi-peer LAN stress and peer recovery | `build/security-harness/lan-sim-20260519-144145/summary.log` |

The LAN stress harness is reusable:

```bash
scripts/lan-stress-harness.sh --peers 5 --rounds 20
```

The direct remote harness used the new `qlinkctl direct-send` command to connect through rendezvous and send a frame over the selected mesh path:

```bash
qlinkctl direct-send \
  --rendezvous 46.224.175.155:9471 \
  --mesh-id hetzner-fsn1-test \
  --remote-peer-id qlink_ixpCrMvwXYlcFFr9h7ECmQ \
  --payload verification-direct-frame
```

## Scenario 1: Remote Provisioning and Control-Plane Probe

The Hetzner host started from a clean Ubuntu server with SSH as the only exposed service. QuantumLink source was uploaded, Rust dependencies were installed, and `qlinkctl` was built natively on Linux. Three systemd services were then installed:

- `quantumlink-rendezvous.service`
- `quantumlink-relay.service`
- `quantumlink-publish-self.service`

Initial smoke checks passed:

| Check | Result |
| --- | --- |
| Rendezvous publish and lookup | Passed |
| Relay datagram smoke | Passed |
| Signed peer record verification | Passed |
| Services active after bounded probes | Passed |

Bounded probes included:

- TCP reachability checks for `22`, `9471`, and `9472`.
- Malformed rendezvous JSON.
- Rendezvous schema violation.
- Relay registration probe.
- 20 sequential TCP connection attempts to rendezvous.
- 20 sequential TCP connection attempts to relay.

Observed result:

```text
port=9471 sequential_connect_ok=20 sequential_connect_fail=0
port=9472 sequential_connect_ok=20 sequential_connect_fail=0
services=active,active,active
lookup_type=found peer_id=qlink_ixpCrMvwXYlcFFr9h7ECmQ endpoint=46.224.175.155:9480 sequence=1
```

Assessment: the remote development services were provisioned successfully, rejected malformed rendezvous input with structured errors, and remained active after bounded control-plane probing.

## Scenario 2: Direct Remote Tunnel and Bounded Attack Suite

The direct tunnel test connected from the local QuantumLink CLI to the published Hetzner peer through rendezvous. The selected path was direct QUIC DATAGRAM to the remote responder.

Baseline result:

```text
selected_path=direct
selected_remote_addr=46.224.175.155:9480
probe_attempts=1
```

The direct suite included:

- Baseline direct send.
- Post-restart direct send after remote service rebuild and restart.
- TCP control-plane inventory for SSH, rendezvous, and relay.
- UDP direct responder reachability marker.
- Wrong mesh ID negative check.
- Nonexistent peer negative check.
- Malformed rendezvous requests.
- Malformed relay requests.
- 10 short UDP noise datagrams to the direct responder.
- 5 sequential direct connection churn attempts.
- Final rendezvous, relay, and direct-send smoke verification.

Key results:

| Metric | Result |
| --- | --- |
| Direct sends measured | 10 |
| Direct path selections | 10 direct |
| Remote direct endpoint | `46.224.175.155:9480` |
| Min direct elapsed | 1169 ms |
| Max direct elapsed | 1444 ms |
| Average direct elapsed | 1249.1 ms |
| Direct churn | 5 succeeded, 0 failed |
| Wrong mesh ID | Expected failure |
| Nonexistent peer | Expected failure |
| Final rendezvous smoke | Passed |
| Final relay smoke | Passed |
| Final direct smoke | Passed |
| Final services | `active, active, active` |

Corrected negative-path evidence:

```text
wrong_mesh_result=expected_failure
missing_peer_result=expected_failure
```

Assessment: the direct path selected correctly, remained stable through bounded noise and connection churn, and failed closed for wrong mesh and missing peer conditions.

## Scenario 3: Simulated LAN Stress Test

The LAN simulation started a local rendezvous service, local relay service, and five published peer responders. It then ran baseline direct sends, malformed probes, negative lookup testing, UDP responder noise, 100 direct sends, a peer restart, and post-restart recovery checks.

Peer layout:

| Peer | Responder |
| --- | --- |
| Peer 1 | `127.0.0.1:10011` |
| Peer 2 | `127.0.0.1:10012` |
| Peer 3 | `127.0.0.1:10013` |
| Peer 4 | `127.0.0.1:10014` |
| Peer 5 | `127.0.0.1:10015` |

Run summary:

```text
baseline_success=5 baseline_fail=0
missing_peer_result=expected_failure
direct_stress_success=100 direct_stress_fail=0
post_restart_success=5 post_restart_fail=0
result=passed
```

Timing summary for the 100 direct stress sends:

| Metric | Result |
| --- | --- |
| Direct sends | 100 |
| Direct path selections | 100 direct |
| Min elapsed | 3 ms |
| Max elapsed | 8 ms |
| Average elapsed | 4.9 ms |

Malformed probe evidence:

```text
{"type":"error","message":"json error: expected ident at line 1 column 2"}
{"type":"error","message":"json error: missing field `peer_id`"}
{"type":"registered","peer_id":"lan-probe"}
Error: Protocol("peer qlink_missing_peer not found in rendezvous lan-sim-20260519144145")
```

Assessment: the simulated LAN mesh delivered all direct stress sends successfully, handled malformed control-plane probes without crashing, and recovered after a peer responder restart.

## Security and Resilience Observations

### Positive Findings

- Signed peer publication worked on both local and remote meshes.
- Direct path selection consistently chose the expected QUIC responder endpoint.
- Wrong mesh and nonexistent peer conditions failed before direct data-path establishment.
- Malformed rendezvous input returned structured JSON errors.
- Local LAN direct stress completed without failed sends.
- Remote services remained active after bounded malformed input, UDP noise, and connection churn.
- Peer restart recovery succeeded in the simulated LAN harness.

### Beta Risks Still Open

- The rendezvous and relay services are development tools and should not be exposed as production services without hardening.
- Relay malformed payload handling did not emit a visible error response in every probe case; this should be evaluated for operator observability.
- The remote direct path elapsed time was consistently around 1.2 seconds in this harness, which is acceptable for beta smoke validation but should be decomposed into DNS-free connect, rendezvous lookup, QUIC handshake, identity assertion, and datagram-send timing before performance claims.
- The direct responder UDP noise test was bounded and non-volumetric; it does not prove denial-of-service resistance.
- The macOS packet tunnel extension is still not production-deployable without Apple Network Extension entitlement, Developer ID signing, notarization, and installation validation.
- The current LAN simulation uses loopback processes, not separate physical hosts or hostile network hardware.

## Readiness Assessment

| Area | Beta Assessment |
| --- | --- |
| Remote dev deployment | Passed |
| Rendezvous smoke | Passed |
| Relay smoke | Passed |
| Signed peer publication | Passed |
| Direct remote path | Passed |
| Direct remote churn | Passed |
| Negative lookup behavior | Passed |
| Simulated LAN direct stress | Passed |
| Peer restart recovery | Passed |
| Production macOS tunnel | Not yet in scope |
| Production control-plane hardening | Not yet in scope |

## Recommended Next Beta Tests

1. Increase simulated LAN scale to 10, 25, and 50 local peers.
2. Add parallel direct-send concurrency, not only sequential sends.
3. Capture structured per-phase timings for rendezvous lookup, QUIC connect, identity assertion, and datagram delivery.
4. Add relay-fallback stress where direct candidates are intentionally unreachable.
5. Add expired peer record and stale certificate rotation tests.
6. Run the LAN harness across multiple machines on a real private network.
7. Add CPU, memory, file descriptor, and socket usage sampling to every harness run.
8. Harden rendezvous and relay before any public beta exposure.
9. Validate the macOS Network Extension path once Apple entitlement and signing are available.

## Website Summary

QuantumLink’s beta mesh core successfully completed remote deployment, direct peer connectivity, bounded security probing, and simulated LAN stress testing. In the remote test, a Hetzner-hosted peer in Falkenstein published a signed peer record and accepted direct QUIC DATAGRAM traffic from a local QuantumLink instance. The direct path survived malformed control-plane input, wrong-mesh and missing-peer checks, bounded UDP noise, and repeated direct connection churn. In local LAN simulation, five peers completed 100 direct sends with zero failures and recovered after a peer restart.

These results validate the current development mesh foundation: signed rendezvous publication, direct responder discovery, QUIC DATAGRAM transport, and basic resilience under controlled beta stress. Production VPN deployment remains gated by macOS Network Extension entitlement, signing, notarization, and control-plane hardening.

## Evidence Index

- Hetzner provisioning and control-plane probes: `build/security-harness/hetzner-2026-05-19.log`
- Direct remote tunnel and bounded attack suite: `build/security-harness/direct-tunnel-attacks-2026-05-19.log`
- Simulated LAN summary: `build/security-harness/lan-sim-20260519-144145/summary.log`
- LAN direct stress details: `build/security-harness/lan-sim-20260519-144145/direct-stress.log`
- LAN malformed probes: `build/security-harness/lan-sim-20260519-144145/malformed-probes.log`
