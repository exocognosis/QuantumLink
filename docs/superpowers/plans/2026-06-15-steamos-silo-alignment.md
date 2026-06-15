# SteamOS Silo Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep `qlink-core` as the shared protocol core while moving the SteamOS/Linux daemon scaffold into the Steam silo.

**Architecture:** The root workspace keeps `rust/qlink-core` as the common core. SteamOS-specific daemon, CLI, Linux networking, game profile, installer, systemd, and game profile assets live under `steam/steamos`. Root docs describe shared core plus macOS, Windows, and Steam silos without declaring SteamOS as the whole repo's primary platform.

**Tech Stack:** Rust workspace, Cargo path dependencies, Bash installer, systemd unit, Markdown docs.

---

### Task 1: Restore qlink-game Behavior

**Files:**
- Create: `rust/qlink-game/tests/game_profile.rs`
- Create: `rust/qlink-game/src/lib.rs`
- Create: `rust/qlink-game/src/profile.rs`
- Create: `rust/qlink-game/src/host_selection.rs`

- [ ] **Step 1: Write the failing profile parsing test**

```rust
use qlink_game::GameProfile;

#[test]
fn parses_game_profile_and_matches_executable_basename() {
    let profile = GameProfile::from_toml_str(
        r#"
        id = "factorio"
        display_name = "Factorio"
        executables = ["factorio"]
        udp_ports = [34197]
        lan_discovery = true
        voice_chat_safe = true
        low_latency = true
        "#,
    )
    .expect("profile parses");

    assert_eq!(profile.id, "factorio");
    assert_eq!(profile.display_name, "Factorio");
    assert_eq!(profile.udp_ports, vec![34197]);
    assert!(profile.lan_discovery);
    assert!(profile.voice_chat_safe);
    assert!(profile.low_latency);
    assert!(profile.matches_executable("/usr/bin/factorio"));
    assert!(!profile.matches_executable("/usr/bin/steam"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlink-game --offline`

Expected: FAIL because `rust/qlink-game/src/lib.rs` is missing.

- [ ] **Step 3: Add minimal profile and host-selection implementation**

```rust
pub mod host_selection;
pub mod profile;

pub use host_selection::{select_lowest_latency_host, GameHostCandidate};
pub use profile::GameProfile;
```

```rust
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GameProfile {
    pub id: String,
    pub display_name: String,
    pub executables: Vec<String>,
    pub udp_ports: Vec<u16>,
    pub lan_discovery: bool,
    pub voice_chat_safe: bool,
    pub low_latency: bool,
}

impl GameProfile {
    pub fn from_toml_str(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    pub fn matches_executable(&self, executable: &str) -> bool {
        let basename = Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(executable);
        self.executables.iter().any(|candidate| candidate == basename)
    }
}
```

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameHostCandidate {
    pub address: String,
    pub median_rtt_ms: u32,
}

pub fn select_lowest_latency_host(candidates: &[GameHostCandidate]) -> Option<&GameHostCandidate> {
    candidates.iter().min_by_key(|candidate| candidate.median_rtt_ms)
}
```

- [ ] **Step 4: Run the qlink-game test to verify it passes**

Run: `CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo test -p qlink-game --offline`

Expected: PASS.

### Task 2: Move SteamOS Assets Into Steam Silo

**Files:**
- Move: `rust/qlink-game` to `steam/steamos/rust/qlink-game`
- Move: `rust/qlink-linux` to `steam/steamos/rust/qlink-linux`
- Move: `rust/qlink-proto` to `steam/steamos/rust/qlink-proto`
- Move: `rust/qlinkd` to `steam/steamos/rust/qlinkd`
- Move: `rust/qlinkctl` to `steam/steamos/rust/qlinkctl`
- Move: `packaging/systemd/qlinkd.service` to `steam/steamos/packaging/systemd/qlinkd.service`
- Move: `scripts/install-steamos.sh` to `steam/steamos/scripts/install-steamos.sh`
- Move: `config/games/*.toml` to `steam/steamos/config/games/*.toml`
- Move: `docs/steamos-architecture.md` to `steam/steamos/docs/architecture.md`
- Modify: `Cargo.toml`

- [ ] **Step 1: Move files mechanically**

Run the directory moves, preserving file contents.

- [ ] **Step 2: Update workspace members**

Change `Cargo.toml` members to:

```toml
members = [
    "rust/qlink-core",
    "steam/steamos/rust/qlink-game",
    "steam/steamos/rust/qlink-proto",
    "steam/steamos/rust/qlink-linux",
    "steam/steamos/rust/qlinkd",
    "steam/steamos/rust/qlinkctl",
]
```

- [ ] **Step 3: Update the moved installer path model**

Make `steam/steamos/scripts/install-steamos.sh` use `STEAMOS_ROOT` for SteamOS assets and `REPO_ROOT` for `target/release` binaries.

- [ ] **Step 4: Run moved package checks**

Run: `CARGO_TARGET_DIR=/tmp/qlink-steamos-target cargo check -p qlinkd -p qlinkctl -p qlink-linux -p qlink-proto -p qlink-game --offline`

Expected: PASS.

### Task 3: Align Documentation

**Files:**
- Modify: `README.md`
- Create: `steam/README.md`
- Create: `steam/steamos/README.md`
- Modify: `steam/steamos/docs/architecture.md`

- [ ] **Step 1: Rewrite root README positioning**

Root README must describe the shared-core architecture and list platform silos. It must not describe macOS as legacy or SteamOS as the whole repo's primary product.

- [ ] **Step 2: Add Steam silo README**

`steam/README.md` must state that Steam is the gamer silo layered on `qlink-core`, with SteamOS under `steam/steamos`.

- [ ] **Step 3: Add SteamOS README**

`steam/steamos/README.md` must contain the daemon quick start and production boundaries using moved paths.

- [ ] **Step 4: Verify documentation references**

Run: `rg -n "docs/steamos-architecture|scripts/install-steamos|packaging/systemd|rust/qlinkd|Linux/SteamOS-first|macOS support is now legacy" README.md steam Cargo.toml`

Expected: no stale root-positioning references.
