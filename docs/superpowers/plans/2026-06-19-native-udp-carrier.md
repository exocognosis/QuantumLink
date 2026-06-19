# Native UDP Carrier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a Quinn-independent carrier seam and prove QuantumLink's PQC session/control-frame flow can run over a native UDP carrier.

**Architecture:** Keep `MeshTransportHandle` and FFI stable. Add a carrier-neutral `CarrierSession` below `MeshLink` with `send_frame`, `receive_frame`, authenticated control-message send/receive, and `close`. Wrap existing Quinn sessions first, then add a native connected-UDP session that uses a small typed datagram envelope for data and control messages.

**Tech Stack:** Rust, Tokio UDP sockets, existing ML-KEM/ML-DSA/SHAKE session modules, existing `PqcFrameProtector`; no new third-party dependencies.

---

### Task 1: Carrier Session Seam And Native UDP Proof

**Files:**
- Create: `qlink-core/src/carrier_transport.rs`
- Modify: `qlink-core/src/lib.rs`
- Modify: `qlink-core/src/pqc_session_wire.rs`
- Modify: `qlink-core/src/inbound_identity.rs`
- Modify: `qlink-core/src/mesh_connection.rs`

- [ ] **Step 1: Write failing carrier tests**

Add tests in `qlink-core/src/carrier_transport.rs`:

```rust
#[tokio::test]
async fn native_udp_session_round_trips_frames_and_authenticated_messages() {
    let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
    let left = CarrierSession::from(left);
    let right = CarrierSession::from(right);

    left.send_authenticated_message(b"identity".to_vec()).await.unwrap();
    assert_eq!(
        right.receive_authenticated_message(64).await.unwrap(),
        b"identity"
    );

    right.send_frame(b"protected-frame".to_vec()).await.unwrap();
    assert_eq!(left.receive_frame().await.unwrap(), b"protected-frame");
}

#[tokio::test]
async fn native_udp_session_rejects_oversized_authenticated_messages() {
    let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
    let left = CarrierSession::from(left);
    let right = CarrierSession::from(right);

    left.send_authenticated_message(vec![0x42; 32]).await.unwrap();
    let error = right.receive_authenticated_message(8).await.unwrap_err();
    assert!(error.to_string().contains("authenticated message"));
}
```

Expected before implementation: compile fails because `carrier_transport`, `NativeUdpSession`, and `CarrierSession` do not exist.

- [ ] **Step 2: Write failing PQC-over-native-UDP test**

Add this test to `qlink-core/src/pqc_session_wire.rs`:

```rust
#[tokio::test]
async fn pqc_session_wire_establishes_keys_over_native_udp_carrier() {
    let initiator_key = DeviceKeypair::generate().unwrap();
    let responder_key = DeviceKeypair::generate().unwrap();
    let responder_peer_id = responder_key.public_key().peer_id();
    let (initiator_session, responder_session) =
        crate::carrier_transport::NativeUdpSession::loopback_pair()
            .await
            .unwrap();
    let initiator_session = crate::carrier_transport::CarrierSession::from(initiator_session);
    let responder_session = crate::carrier_transport::CarrierSession::from(responder_session);
    let carrier_binding = b"native-udp-loopback-test".to_vec();

    let responder_context = PqcSessionContext::new(
        "native-wire-mesh",
        initiator_key.public_key().peer_id(),
        responder_peer_id.clone(),
        carrier_binding.clone(),
    );
    let responder_task = tokio::spawn(async move {
        run_pqc_session_responder(&responder_session, responder_context, &responder_key)
            .await
            .unwrap()
    });

    let initiator_context = PqcSessionContext::new(
        "native-wire-mesh",
        initiator_key.public_key().peer_id(),
        responder_peer_id,
        carrier_binding,
    );
    let initiator_keys =
        run_pqc_session_initiator(&initiator_session, initiator_context, &initiator_key)
            .await
            .unwrap();
    let responder_keys = responder_task.await.unwrap();

    assert_eq!(initiator_keys.suite, PQC_SESSION_SUITE);
    assert_eq!(responder_keys.suite, PQC_SESSION_SUITE);
    assert_eq!(initiator_keys.tx_key, responder_keys.rx_key);
    assert_eq!(initiator_keys.rx_key, responder_keys.tx_key);
    assert_eq!(initiator_keys.handshake_hash, responder_keys.handshake_hash);
}
```

Run:

```sh
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib native_udp_session -- --nocapture
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib pqc_session_wire_establishes_keys_over_native_udp_carrier -- --nocapture
```

Expected before implementation: compile failure for missing carrier types or mismatched `QuicDatagramSession` signatures.

- [ ] **Step 3: Implement `CarrierSession` wrapper**

Create `carrier_transport.rs` with:

- `CarrierSession::Quic(QuicDatagramSession)`
- `CarrierSession::NativeUdp(NativeUdpSession)`
- forwarding methods: `send_frame`, `receive_frame`, `send_authenticated_message`, `receive_authenticated_message`, `close`
- `From<QuicDatagramSession>` and `From<NativeUdpSession>` impls

Use an enum instead of an async trait to avoid adding dependencies or object-safety churn.

- [ ] **Step 4: Implement native UDP datagram envelope**

In `carrier_transport.rs`, implement `NativeUdpSession` over `Arc<UdpSocket>`:

- `loopback_pair()` binds two localhost UDP sockets and connects them to each other.
- `send_frame()` sends `QLCAR1 | version 1 | kind frame | u32 length | payload`.
- `send_authenticated_message()` sends the same envelope with kind `auth`.
- `receive_frame()` loops until it receives a frame envelope.
- `receive_authenticated_message(max_size)` loops until it receives an auth envelope, rejects messages above `max_size`, and rejects malformed envelope magic/version/length.
- `close()` sends a best-effort close envelope and otherwise no-ops.

- [ ] **Step 5: Retarget control helpers to `CarrierSession`**

Change `pqc_session_wire::{run_pqc_session_initiator, run_pqc_session_responder}` and `inbound_identity::{send_inbound_assertion, receive_and_evaluate_inbound}` to accept `&CarrierSession`.

Update existing Quinn tests by wrapping:

```rust
let session = CarrierSession::from(session);
run_pqc_session_initiator(&session, context, &keypair).await.unwrap();
```

- [ ] **Step 6: Retarget direct mesh link storage**

Change `DirectLink.session`, `DirectProbeResult::Established.session`, and `ProbeOutcomeRecord.session` from `QuicDatagramSession` to `CarrierSession`. After a successful Quinn connect, immediately wrap it:

```rust
let session = CarrierSession::from(session);
```

Leave the actual direct probe transport as Quinn in this task. This task creates the seam and native proof; switching rendezvous/direct probe publication to native UDP is a future task.

- [ ] **Step 7: Run verification**

Run targeted checks only:

```sh
rustfmt --edition 2021 --check --config skip_children=true qlink-core/src/carrier_transport.rs qlink-core/src/lib.rs qlink-core/src/pqc_session_wire.rs qlink-core/src/inbound_identity.rs qlink-core/src/mesh_connection.rs
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib native_udp_session -- --nocapture
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib pqc_session_wire -- --nocapture
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib inbound_identity -- --nocapture
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib mesh_connection -- --nocapture
```

Avoid `cargo fmt --all` and `cargo test --workspace`; both have known hang behavior in this repo.

- [ ] **Step 8: Commit**

```sh
git add docs/superpowers/plans/2026-06-19-native-udp-carrier.md qlink-core/src/carrier_transport.rs qlink-core/src/lib.rs qlink-core/src/pqc_session_wire.rs qlink-core/src/inbound_identity.rs qlink-core/src/mesh_connection.rs
git commit -m "Add native UDP carrier seam"
```

### Task 2: Default-Feature Policy Guard For Native Carrier

**Files:**
- Modify: `qlink-core/src/lib.rs`
- Modify: `qlink-core/Cargo.toml`
- Modify: `README.md`
- Modify: `docs/security.md`

- [ ] **Step 1: Add a failing policy test**

Extend `pqc_policy_tests` to assert the default production boundary has a native carrier module and that Quinn/rustls are explicitly documented as non-production blockers until moved behind a dev feature.

- [ ] **Step 2: Add feature skeleton**

Add feature names:

```toml
[features]
default = ["native-udp-carrier"]
native-udp-carrier = []
dev-quic-carrier = []
```

Do not make Quinn optional in this task unless all compile sites are fully gated. The safe first policy step is naming the intended default and adding tests/docs that prevent backsliding.

- [ ] **Step 3: Update docs**

Document: native UDP carrier proof exists, mesh direct probe still uses Quinn until Task 3, and zero-classical dependency graph is not complete until `quinn/rustls/rcgen` are optional and disabled by default.

- [ ] **Step 4: Verify**

```sh
CARGO_TARGET_DIR=/tmp/nist-pqc-transport-target cargo test -p qlink-core --lib pqc_policy_tests -- --nocapture
```

- [ ] **Step 5: Commit**

```sh
git add qlink-core/Cargo.toml qlink-core/src/lib.rs README.md docs/security.md
git commit -m "Track native carrier production policy"
```
