# Windows Beta Runbook

Windows analog of the macOS pre-Apple runbook. Run on clean Windows 10
22H2 and Windows 11 x64 VMs plus at least one physical machine.

## 0. Build verification

- [ ] `cargo test --workspace` passes on the Windows host.
- [ ] `cargo run -p quantumlink-service -- smoke` exits 0 and reports
      `passed: true` (pump fail-closed invariants).
- [ ] MSI builds and is Authenticode-signed; SmartScreen shows the
      publisher name.

## 1. Install / first run

- [ ] MSI installs without warnings; `QuantumLinkService` is running
      (`sc query QuantumLinkService`).
- [ ] `C:\ProgramData\QuantumLink` exists; non-admin user cannot read
      `secrets\*.dpapi`.
- [ ] UI launches unprivileged, completes the `hello` handshake, shows
      phase `idle`.
- [ ] First `connect` creates the "QuantumLink" network adapter
      (`Get-NetAdapter`), assigns the overlay address, installs routes
      (`Get-NetRoute | ? InterfaceAlias -eq QuantumLink`).
- [ ] Device peer id is stable across service restarts (DPAPI seed
      reload — check diagnostics export before/after
      `Restart-Service QuantumLinkService`).

## 2. Kill switch / leak tests

With `killSwitch: failClosed` (default):

- [ ] While connected, `ping` a protected-prefix address: traffic goes
      through the tunnel only (capture on the physical NIC with
      Wireshark; zero protected-prefix packets in plaintext).
- [ ] Stop the transport (block the rendezvous/relay endpoints at the
      router or with an outbound firewall rule): protected-prefix pings
      black-hole; nothing leaks out the physical NIC; pump counters show
      `droppedKillSwitch` increments.
- [ ] Kill the service process (`taskkill /f`): Wintun adapter and WFP
      filters disappear; protected prefixes become unreachable (no
      route), not leaked.

With `killSwitch: strict`:

- [ ] Service refuses `connect` when WFP engagement is blocked (e.g.
      BFE service stopped) with a clear error.
- [ ] Sustained transport outage (>30 s) halts the data plane and
      surfaces the watchdog error in the UI.

## 3. Network churn

- [ ] Sleep/resume: tunnel recovers (PostWake re-probe) within 30 s.
- [ ] Wi-Fi -> Ethernet switch: `PathChanged` logged, transport
      reconnects, pings recover.
- [ ] Captive-portal Wi-Fi: service stays up, kill switch holds, no
      crash loop.
- [ ] Boot with network unplugged: service starts, phase `idle`,
      connect succeeds after plugging in.

## 4. Mesh behavior (two-machine)

- [ ] Two Windows machines + rendezvous server: direct path
      establishes; `pathType: direct` in both UIs.
- [ ] Hostile NAT (block UDP between peers): relay fallback engages;
      `pathType: relay`.
- [ ] macOS <-> Windows interop: macOS app and Windows service
      exchange traffic (same qlink-core wire format).

## 5. Service lifecycle

- [ ] `Restart-Service` while connected: routes/filters cleaned up and
      re-established on reconnect; no orphan routes
      (`Get-NetRoute` clean after stop).
- [ ] Uninstall: service gone, adapter gone, no QuantumLink WFP
      sublayer (`netsh wfp show filters` | find "QuantumLink"), state
      dir removed.
- [ ] Reinstall after uninstall: fresh identity generated (peer id
      changes — secrets were removed with the state dir).

## 6. Diagnostics

- [ ] "Export diagnostics" output contains no raw `qlink_*` peer ids
      (only `qlink_[redacted]`), no SSIDs, no external IPs.
- [ ] Service logs under `%ProgramData%\QuantumLink\logs` rotate and
      contain netsh command audit lines.
