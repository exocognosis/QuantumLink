# Dev QUIC Feature Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove Quinn/rustls/rcgen from the default `qlink-core` build graph by making the QUIC carrier explicitly dev-only behind `dev-quic-carrier`.

**Architecture:** Keep the native UDP carrier and PQC app-layer session as the default direction. Preserve legacy QUIC coverage only when `dev-quic-carrier` is enabled. Default builds must compile and fail closed for live direct/responder mesh paths until native UDP live dialing is wired.

**Tech Stack:** Rust features/cfg gates, Cargo optional dependencies, existing `CarrierSession`, targeted cargo metadata checks.

---

### Task 1: Add Policy Guard For Optional Dev QUIC

**Files:**
- Modify: `qlink-core/src/lib.rs`
- Modify: `qlink-core/Cargo.toml`

- [ ] **Step 1: Write the failing policy test**

Add a test in `pqc_policy_tests` that asserts:

```rust
#[test]
fn dev_quic_carrier_dependencies_are_optional_and_feature_gated() {
    let manifest = include_str!("../Cargo.toml");
    for dependency in ["quinn", "rustls", "rcgen"] {
        let line = manifest
            .lines()
            .find(|line| line.starts_with(&format!("{dependency} = ")))
            .unwrap_or_else(|| panic!("qlink-core Cargo.toml must declare {dependency}"));
        assert!(
            line.contains("optional = true"),
            "{dependency} must be optional and excluded from default native-UDP builds"
        );
    }
    assert!(
        manifest.contains(
            "dev-quic-carrier = [\"dep:quinn\", \"dep:rustls\", \"dep:rcgen\"]"
        ),
        "dev-quic-carrier must be the only feature that enables Quinn/rustls/rcgen"
    );
}
```

- [ ] **Step 2: Verify red**

Run:

```sh
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib pqc_policy_tests -- --nocapture
```

Expected: fail because the three dependencies are not optional and `dev-quic-carrier` is empty.

- [ ] **Step 3: Update manifest**

Set:

```toml
quinn = { version = "0.11.9", optional = true, default-features = false, features = ["bloom", "log", "platform-verifier", "runtime-tokio", "rustls-aws-lc-rs"] }
rcgen = { version = "0.14.7", optional = true }
rustls = { version = "0.23", optional = true }

[features]
default = ["native-udp-carrier"]
native-udp-carrier = []
dev-quic-carrier = ["dep:quinn", "dep:rustls", "dep:rcgen"]
```

- [ ] **Step 4: Verify green**

Run the same `pqc_policy_tests` command and expect pass.

### Task 2: Gate QUIC Module And Carrier Variant

**Files:**
- Modify: `qlink-core/src/lib.rs`
- Modify: `qlink-core/src/carrier_transport.rs`
- Modify: `qlink-core/src/quic_transport.rs`

- [ ] **Step 1: Gate module export**

Change:

```rust
pub mod quic_transport;
```

to:

```rust
#[cfg(feature = "dev-quic-carrier")]
pub mod quic_transport;
```

- [ ] **Step 2: Gate `CarrierSession::Quic`**

In `carrier_transport.rs`, wrap the `QuicDatagramSession` import, enum variant, match arms, and `From<QuicDatagramSession>` impl in `#[cfg(feature = "dev-quic-carrier")]`.

- [ ] **Step 3: Verify default compile red/green loop**

Run:

```sh
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo check -p qlink-core --lib --no-default-features --features native-udp-carrier
```

Expected before call-site gating: fail on remaining QUIC references. Expected after Task 3: pass.

### Task 3: Gate Live QUIC Mesh Paths Fail-Closed By Default

**Files:**
- Modify: `qlink-core/src/mesh_connection.rs`
- Modify: `qlink-core/src/mesh_transport.rs`
- Modify: `qlink-core/src/bin/qlinkctl.rs`

- [ ] **Step 1: Gate imports and fields**

Gate `QuicEndpoint`, `QuicCertificate`, direct QUIC responder setup, and responder loop code with `#[cfg(feature = "dev-quic-carrier")]`.

- [ ] **Step 2: Provide default fail-closed constructors**

Default `MeshTransportHandle::new` should return a protocol error when live mesh transport requires the not-yet-wired native UDP dialer:

```text
native UDP live mesh carrier is not wired yet; enable dev-quic-carrier for legacy Quinn development carrier
```

Default `MeshConnector::connect` should return a similar fail-closed error before rendezvous/direct probing attempts use QUIC-only state.

- [ ] **Step 3: Gate QUIC-only tests**

Mark QUIC-dependent tests with:

```rust
#[cfg(feature = "dev-quic-carrier")]
```

Native UDP carrier and PQC session-wire native tests must remain available in default builds.

### Task 4: Verify Dependency Graph And Docs

**Files:**
- Modify: `README.md`
- Modify: `docs/security.md`

- [ ] **Step 1: Update docs wording**

Document that default `qlink-core` builds exclude Quinn/rustls/rcgen, while dev QUIC remains available with `--features dev-quic-carrier`. Do not claim full zero-classical compliance because platform/transitive non-default/dev and non-transport classical behavior remain.

- [ ] **Step 2: Verify default metadata**

Run:

```sh
forbidden_native_deps="$(
  cargo metadata --manifest-path qlink-core/Cargo.toml --locked --no-default-features --features native-udp-carrier --format-version=1 \
    | jq -r '.resolve.nodes as $nodes
      | def normal_deps($id):
          ($nodes[] | select(.id == $id) | .deps[]? | select(any(.dep_kinds[]?; .kind == null)) | .pkg);
        def walk_normal($id):
          $id, (normal_deps($id) as $dep | walk_normal($dep));
        [walk_normal(.resolve.root)] | unique[]
        | select(test("#(quinn|quinn-proto|rustls|rcgen|aws-lc-rs|ring)@"))'
)"
test -z "$forbidden_native_deps"
```

Expected: no resolved normal dependencies.

- [ ] **Step 3: Verify targeted Rust checks**

Run:

```sh
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib pqc_policy_tests --no-default-features --features native-udp-carrier -- --nocapture
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib native_udp_session --no-default-features --features native-udp-carrier -- --nocapture
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib pqc_session_wire_establishes_keys_over_native_udp_carrier --no-default-features --features native-udp-carrier -- --nocapture
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo check -p qlink-core --bin qlinkctl --no-default-features --features native-udp-carrier
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo check -p qlink-core --lib --features dev-quic-carrier
rustfmt --edition 2021 --check --config skip_children=true qlink-core/src/carrier_transport.rs qlink-core/src/lib.rs qlink-core/src/mesh_connection.rs qlink-core/src/mesh_transport.rs qlink-core/src/bin/qlinkctl.rs
```

Expected: all pass.
