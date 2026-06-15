# SteamOS Production Buildout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the SteamOS runtime from scaffold to production-capable gamer mesh VPN while keeping `rust/qlink-core` as the shared protocol core.

**Architecture:** SteamOS-specific daemon, CLI, Linux networking, game profile, packaging, and install code live under `steam/steamos`. Shared cryptography, packet framing, peer records, rendezvous, relay, traversal, and transport primitives remain in `rust/qlink-core`. Work proceeds in vertical slices: workspace stability, daemon/config foundation, Linux network ownership, packet pump integration, identity/enrollment, traversal/relay, game policy, user experience, packaging, and hardening.

**Tech Stack:** Rust workspace, `qlink-core`, SteamOS/Linux systemd, Unix sockets, Linux TUN, policy routing, nftables, TOML/JSON config, Bash installer, cargo tests.

---

## File Ownership Map

- Shared core: `rust/qlink-core/**`
- SteamOS daemon: `steam/steamos/rust/qlinkd/**`
- SteamOS local protocol: `steam/steamos/rust/qlink-proto/**`
- SteamOS CLI: `steam/steamos/rust/qlinkctl/**`
- Linux network helpers: `steam/steamos/rust/qlink-linux/**`
- Game policy/profile helpers: `steam/steamos/rust/qlink-game/**`
- SteamOS install/package assets: `steam/steamos/scripts/**`, `steam/steamos/packaging/**`, `steam/steamos/config/**`
- SteamOS docs: `steam/README.md`, `steam/steamos/README.md`, `steam/steamos/docs/**`

## Wave 0: Workspace And Baseline Repair

### Task 0.1: Restore Shared-Core Binary Targets

**Files:**
- Create: `rust/qlink-core/src/bin/qlinkctl.rs`
- Create: `rust/qlink-core/src/bin/perfgate.rs`

- [ ] **Step 1: Verify failing baseline**

Run:

```sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test --workspace --offline
```

Expected: FAIL because `rust/qlink-core/src/bin/qlinkctl.rs` and `rust/qlink-core/src/bin/perfgate.rs` are missing.

- [ ] **Step 2: Add minimal `qlink-devctl` binary**

Create `rust/qlink-core/src/bin/qlinkctl.rs` with a small CLI that supports `--help` and a harmless `crypto-suite` command that validates the default ML-KEM suite through `qlink_core::crypto::validate_suite_name`.

- [ ] **Step 3: Add minimal `perfgate` binary**

Create `rust/qlink-core/src/bin/perfgate.rs` with argument parsing for `--baseline`, repeated `--slo-log`, and `--criterion-dir`. It must parse the baseline JSON with `serde_json`, verify referenced SLO logs exist, and print `perfgate: structural validation passed` when structural validation succeeds.

- [ ] **Step 4: Verify shared-core package**

Run:

```sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlink-core --offline
```

Expected: PASS or a non-missing-file failure that is recorded as the next shared-core bug.

### Task 0.2: Repair Worktree/Git Usability

**Files:**
- Inspect only unless a non-destructive repair is identified.

- [ ] **Step 1: Capture current Git failure**

Run:

```sh
git status --short --branch --untracked-files=all
```

Expected: currently fails with exit `138` in this worktree.

- [ ] **Step 2: Inspect worktree metadata without deleting anything**

Run:

```sh
git rev-parse --git-dir
git rev-parse --git-common-dir
file "$(git rev-parse --git-dir)/index"
ls -la "$(git rev-parse --git-dir)"
```

Expected: identify whether the linked worktree index exists and is readable.

- [ ] **Step 3: Produce a repair recommendation**

If the index is corrupt, write down the safe repair sequence before running it: back up the worktree directory, back up the worktree index, and recreate index state from HEAD only if the current working tree files are preserved. Do not run destructive reset commands.

## Wave 1: SteamOS Daemon Foundation

### Task 1.1: Config Validation

**Files:**
- Modify: `steam/steamos/rust/qlink-proto/src/lib.rs`
- Modify: `steam/steamos/rust/qlinkd/src/lib.rs`

- [ ] **Step 1: Add failing config validation tests**

Add qlinkd tests for:
- default config validates
- empty interface name fails
- malformed overlay CIDR fails
- malformed overlay IPv4 address fails

- [ ] **Step 2: Implement `DaemonConfig::validate`**

Validation must be deterministic and dependency-light:
- `interface_name` is non-empty, ASCII alphanumeric plus `_`, `-`, `.`, length at most 15
- `overlay_cidr` contains one slash, parses IP as IPv4, prefix length is 1 through 32
- `overlay_ipv4_address` parses as IPv4
- `rendezvous_servers` and `relay_servers` entries are non-empty if present

- [ ] **Step 3: Validate loaded and default config**

`load_config_or_default` must validate loaded config and the default config. Return `ErrorKind::InvalidData` with a message beginning `invalid qlinkd config:` when validation fails.

- [ ] **Step 4: Verify**

Run:

```sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlinkd -p qlink-proto --offline
```

Expected: PASS.

### Task 1.2: Daemon Runtime State

**Files:**
- Modify: `steam/steamos/rust/qlink-proto/src/lib.rs`
- Modify: `steam/steamos/rust/qlinkd/src/lib.rs`

- [ ] **Step 1: Add failing status-state tests**

Add tests that assert status includes:
- daemon version string
- config route mode
- interface name
- last error field

- [ ] **Step 2: Extend status model**

Add fields to `DaemonStatus` with `serde(default)` compatibility where needed:
- `daemon_version: String`
- `interface_name: String`
- `route_mode: RouteMode`
- `last_error: Option<String>`

- [ ] **Step 3: Populate status from config**

`DaemonStatus::idle` should accept the config or a config-derived status seed so status reflects actual route mode and interface.

- [ ] **Step 4: Verify**

Run:

```sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlinkd -p qlink-proto --offline
```

Expected: PASS.

## Wave 2: Linux Network Ownership

### Task 2.1: Typed Network Plans

**Files:**
- Modify: `steam/steamos/rust/qlink-linux/src/lib.rs`

- [ ] **Step 1: Add tests for typed operations**

Add tests that construct a plan for `qlink0`, `100.64.10.2`, and `100.64.0.0/10` and assert typed operations exist for TUN creation, address assignment, link up, policy rule, route, nft table, nft mark rule, and nft drop rule.

- [ ] **Step 2: Replace string-only plans with typed operations**

Introduce:

```rust
pub enum NetworkOperation {
    CreateTun { name: String },
    AddAddress { interface: String, address: String },
    SetLinkUp { interface: String, mtu: u16 },
    AddRule { fwmark: u32, table: u32 },
    AddRoute { cidr: String, interface: String, table: u32 },
}
```

Keep a `to_command()` renderer for compatibility.

- [ ] **Step 3: Verify**

Run:

```sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlink-linux --offline
```

Expected: PASS.

### Task 2.2: Dry-Run Apply/Rollback Interface

**Files:**
- Modify: `steam/steamos/rust/qlink-linux/src/lib.rs`

- [ ] **Step 1: Add failing dry-run tests**

Add tests for an executor that records operations without running system commands.

- [ ] **Step 2: Implement `NetworkExecutor` trait**

Add:

```rust
pub trait NetworkExecutor {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError>;
}
```

Add `DryRunExecutor` that records rendered commands.

- [ ] **Step 3: Verify**

Run:

```sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlink-linux --offline
```

Expected: PASS.

## Wave 3: TUN Packet Pump

### Task 3.1: Packet Pump Interface

**Files:**
- Create: `steam/steamos/rust/qlinkd/src/packet_pump.rs`
- Modify: `steam/steamos/rust/qlinkd/src/lib.rs`

- [ ] **Step 1: Add failing in-memory packet pump tests**

Test that an in-memory packet source sends bytes into a packet sink and records packet count.

- [ ] **Step 2: Add interfaces**

Define:

```rust
pub trait PacketSource {
    fn read_packet(&mut self, buffer: &mut [u8]) -> std::io::Result<usize>;
}

pub trait PacketSink {
    fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()>;
}
```

- [ ] **Step 3: Add single-step pump**

Implement a side-effect-free `pump_once` for tests. Do not open `/dev/net/tun` in this task.

- [ ] **Step 4: Verify**

Run:

```sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlinkd --offline
```

Expected: PASS.

## Wave 4: Identity, Enrollment, And Invites

### Task 4.1: CLI Command Model

**Files:**
- Modify: `steam/steamos/rust/qlink-proto/src/lib.rs`
- Modify: `steam/steamos/rust/qlinkctl/src/main.rs`
- Modify: `steam/steamos/rust/qlinkctl/src/lib.rs`

- [ ] Add local protocol request/response enums for `status`, `invite decode`, `invite create`, `peers`, and `diagnostics`.
- [ ] Add parser tests for CLI command routing.
- [ ] Keep command execution network-free until daemon handlers are added.

## Wave 5: Game Policy

### Task 5.1: Profile Loader

**Files:**
- Modify: `steam/steamos/rust/qlink-game/src/profile.rs`
- Modify: `steam/steamos/rust/qlink-game/src/lib.rs`

- [ ] Add profile directory loader tests using `steam/steamos/config/games`.
- [ ] Validate IDs, executable lists, UDP ports, and flags.
- [ ] Return structured errors for malformed profiles.

## Wave 6: Packaging And Release

### Task 6.1: Installer Validation

**Files:**
- Modify: `steam/steamos/scripts/install-steamos.sh`
- Create: `steam/steamos/scripts/uninstall-steamos.sh`
- Create: `steam/steamos/packaging/README.md`

- [ ] Add shell syntax checks.
- [ ] Add `DESTDIR` install test script.
- [ ] Add uninstall behavior for binaries, unit, and generated dirs while preserving config unless explicitly requested.

## Verification Contract

At the end of each wave, run:

```sh
bash -n steam/steamos/scripts/install-steamos.sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlinkd -p qlinkctl -p qlink-linux -p qlink-proto -p qlink-game --offline
```

When Wave 0 restores `qlink-core` binaries, also run:

```sh
CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test --workspace --offline
```
