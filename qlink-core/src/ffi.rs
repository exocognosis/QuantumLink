use crate::{
    crypto::DeviceKeypair,
    dytallix_identity::{ensure_dytallix_enrollment_wallet, DytallixRegistryConfig},
    mesh_connection::NetworkEvent,
    mesh_transport::{
        MeshTransportConfig, MeshTransportHandle, MeshTransportState, PeerTrustStatusRaw,
    },
    packet_core::{PacketDisposition, PacketTunnelCore},
    tracing_bridge,
};
use std::{
    os::raw::c_char,
    ptr, slice, str,
    sync::{Arc, Mutex},
};

static VERSION: &[u8] = b"0.1.0\0";
static SUITE: &[u8] = b"QLINK-FIPS203-MLKEM768-SHAKE256-v1\0";

pub struct QlinkTunnelCoreHandle {
    core: Mutex<PacketTunnelCore>,
}

pub struct QlinkDevQuicTransportHandle {
    metrics: QlinkTransportMetrics,
}

#[repr(C)]
#[derive(Default)]
pub struct QlinkOwnedBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

#[repr(C)]
pub struct QlinkOwnedPacket {
    pub protocol_family: u32,
    pub buffer: QlinkOwnedBuffer,
}

/// Two owned buffers: the inbound mesh frame and the verified peer ID
/// (UTF-8, no NUL terminator) the inbound responder authenticated.
/// Both buffers are caller-owned — free each with
/// `qlink_owned_buffer_free` (or `qlink_owned_buffer_free_ptr`).
#[repr(C)]
pub struct QlinkInboundFrame {
    pub frame: QlinkOwnedBuffer,
    pub peer_id: QlinkOwnedBuffer,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QlinkTunnelMetrics {
    pub packets_from_tunnel: u64,
    pub packets_to_tunnel: u64,
    pub transport_frames_out: u64,
    pub transport_frames_in: u64,
    pub dropped_unprotected: u64,
    pub dropped_malformed: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QlinkTransportMetrics {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_failures: u64,
    pub receive_failures: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QlinkPeerTrustStatus {
    pub decision_code: u32,
    pub failure_code: u32,
    pub checked_at_unix: u64,
    pub source_code: u32,
}

impl From<PeerTrustStatusRaw> for QlinkPeerTrustStatus {
    fn from(value: PeerTrustStatusRaw) -> Self {
        Self {
            decision_code: value.decision_code,
            failure_code: value.failure_code,
            checked_at_unix: value.checked_at_unix,
            source_code: value.source_code,
        }
    }
}

#[no_mangle]
pub extern "C" fn qlink_core_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn qlink_core_default_suite() -> *const c_char {
    SUITE.as_ptr().cast()
}

#[no_mangle]
pub unsafe extern "C" fn qlink_tunnel_core_create(
    config_json: *const u8,
    config_json_len: usize,
) -> *mut QlinkTunnelCoreHandle {
    let Some(config) = borrowed_slice(config_json, config_json_len) else {
        return ptr::null_mut();
    };

    match PacketTunnelCore::from_json(config) {
        Ok(core) => Box::into_raw(Box::new(QlinkTunnelCoreHandle {
            core: Mutex::new(core),
        })),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_tunnel_core_destroy(handle: *mut QlinkTunnelCoreHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_tunnel_core_submit_packet(
    handle: *mut QlinkTunnelCoreHandle,
    protocol_family: u32,
    packet: *const u8,
    packet_len: usize,
) -> i32 {
    let Some(handle) = handle.as_ref() else {
        return -1;
    };
    let Some(packet) = borrowed_slice(packet, packet_len) else {
        return -1;
    };

    let Ok(mut core) = handle.core.lock() else {
        return -1;
    };

    match core.submit_tunnel_packet(protocol_family, packet) {
        Ok(PacketDisposition::QueuedForTransport) => 1,
        Ok(
            PacketDisposition::DroppedUnprotected
            | PacketDisposition::DroppedPeerSessionUnavailable,
        ) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_tunnel_core_pop_transport_frame(
    handle: *mut QlinkTunnelCoreHandle,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    let Ok(mut core) = handle.core.lock() else {
        return false;
    };

    match core.pop_transport_frame() {
        Some(frame) => {
            *out = owned_buffer_from_vec(frame);
            true
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_tunnel_core_accept_transport_frame(
    handle: *mut QlinkTunnelCoreHandle,
    frame: *const u8,
    frame_len: usize,
) -> i32 {
    let Some(handle) = handle.as_ref() else {
        return -1;
    };
    let Some(frame) = borrowed_slice(frame, frame_len) else {
        return -1;
    };
    let Ok(mut core) = handle.core.lock() else {
        return -1;
    };

    match core.accept_transport_frame(frame) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_tunnel_core_pop_tunnel_packet(
    handle: *mut QlinkTunnelCoreHandle,
    out: *mut QlinkOwnedPacket,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    let Ok(mut core) = handle.core.lock() else {
        return false;
    };

    match core.pop_tunnel_packet() {
        Some(packet) => {
            *out = QlinkOwnedPacket {
                protocol_family: packet.protocol_family,
                buffer: owned_buffer_from_vec(packet.bytes),
            };
            true
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_tunnel_core_metrics(
    handle: *mut QlinkTunnelCoreHandle,
    out: *mut QlinkTunnelMetrics,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    let Ok(core) = handle.core.lock() else {
        return false;
    };

    let metrics = core.metrics();
    *out = QlinkTunnelMetrics {
        packets_from_tunnel: metrics.packets_from_tunnel,
        packets_to_tunnel: metrics.packets_to_tunnel,
        transport_frames_out: metrics.transport_frames_out,
        transport_frames_in: metrics.transport_frames_in,
        dropped_unprotected: metrics.dropped_unprotected,
        dropped_malformed: metrics.dropped_malformed,
    };
    true
}

#[no_mangle]
pub extern "C" fn qlink_dev_quic_transport_create() -> *mut QlinkDevQuicTransportHandle {
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn qlink_dev_quic_transport_destroy(
    handle: *mut QlinkDevQuicTransportHandle,
) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_dev_quic_transport_send_frame(
    handle: *mut QlinkDevQuicTransportHandle,
    frame: *const u8,
    frame_len: usize,
) -> i32 {
    let Some(handle) = handle.as_mut() else {
        return -1;
    };
    if borrowed_slice(frame, frame_len).is_none() {
        handle.metrics.send_failures += 1;
        return -1;
    }
    handle.metrics.send_failures += 1;
    -1
}

#[no_mangle]
pub unsafe extern "C" fn qlink_dev_quic_transport_receive_frame(
    handle: *mut QlinkDevQuicTransportHandle,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_mut() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        handle.metrics.receive_failures += 1;
        return false;
    };
    *out = QlinkOwnedBuffer::default();
    handle.metrics.receive_failures += 1;
    false
}

#[no_mangle]
pub unsafe extern "C" fn qlink_dev_quic_transport_metrics(
    handle: *mut QlinkDevQuicTransportHandle,
    out: *mut QlinkTransportMetrics,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    *out = handle.metrics;
    true
}

#[no_mangle]
pub unsafe extern "C" fn qlink_owned_buffer_free(buffer: QlinkOwnedBuffer) {
    if buffer.ptr.is_null() || buffer.cap == 0 {
        return;
    }
    drop(Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.cap));
}

#[no_mangle]
pub unsafe extern "C" fn qlink_owned_buffer_free_ptr(buffer: *mut QlinkOwnedBuffer) {
    let Some(buffer) = buffer.as_mut() else {
        return;
    };
    let owned = QlinkOwnedBuffer {
        ptr: buffer.ptr,
        len: buffer.len,
        cap: buffer.cap,
    };
    buffer.ptr = ptr::null_mut();
    buffer.len = 0;
    buffer.cap = 0;
    qlink_owned_buffer_free(owned);
}

unsafe fn borrowed_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() && len != 0 {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

fn owned_buffer_from_vec(mut bytes: Vec<u8>) -> QlinkOwnedBuffer {
    let buffer = QlinkOwnedBuffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
        cap: bytes.capacity(),
    };
    std::mem::forget(bytes);
    buffer
}

// ===================================================================
// Mesh transport FFI — production data-plane surface.
// ===================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QlinkMeshTransportMetrics {
    pub state_code: u32,
    pub path_kind_code: u32,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_failures: u64,
    pub receive_failures: u64,
    pub network_event_count: u64,
    pub reconnect_count: u64,
}

/// Network-event codes used by the FFI. Mirror of
/// [`crate::mesh_connection::NetworkEvent`].
const NETWORK_EVENT_PATH_CHANGED: u32 = 0;
const NETWORK_EVENT_PRE_SLEEP: u32 = 1;
const NETWORK_EVENT_POST_WAKE: u32 = 2;
const NETWORK_EVENT_REACHABILITY_LOST: u32 = 3;
const NETWORK_EVENT_REACHABILITY_GAINED: u32 = 4;

#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_create(
    config_json: *const u8,
    config_json_len: usize,
) -> *mut MeshTransportHandle {
    let Some(config) = borrowed_slice(config_json, config_json_len) else {
        return ptr::null_mut();
    };
    match MeshTransportHandle::from_json_config(config) {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(error) => {
            tracing::warn!(?error, "qlink_mesh_transport_create failed");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_destroy(handle: *mut MeshTransportHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_send_frame(
    handle: *mut MeshTransportHandle,
    frame: *const u8,
    frame_len: usize,
) -> i32 {
    let Some(handle) = handle.as_ref() else {
        return -1;
    };
    let Some(frame) = borrowed_slice(frame, frame_len) else {
        return -1;
    };
    match handle.send_frame(frame.to_vec()) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_receive_frame(
    handle: *mut MeshTransportHandle,
    out: *mut QlinkInboundFrame,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    // Multi-peer surface: the responder loop tags every accepted frame
    // with the verified peer_id (see `inbound_identity::evaluate_inbound`).
    // Stripping it here used to leave Swift unable to route per-peer.
    match handle.try_receive_frame_from_any() {
        Some(inbound) => {
            out.frame = owned_buffer_from_vec(inbound.frame);
            out.peer_id = owned_buffer_from_vec(inbound.peer_id.into_bytes());
            true
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_metrics(
    handle: *mut MeshTransportHandle,
    out: *mut QlinkMeshTransportMetrics,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    let raw = handle.metrics();
    *out = QlinkMeshTransportMetrics {
        state_code: handle.state_code(),
        path_kind_code: handle.path_kind_code(),
        frames_sent: raw.frames_sent,
        frames_received: raw.frames_received,
        bytes_sent: raw.bytes_sent,
        bytes_received: raw.bytes_received,
        send_failures: raw.send_failures,
        receive_failures: raw.receive_failures,
        network_event_count: raw.network_event_count,
        reconnect_count: raw.reconnect_count,
    };
    true
}

#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_handle_network_event(
    handle: *mut MeshTransportHandle,
    event_code: u32,
) -> i32 {
    let Some(handle) = handle.as_ref() else {
        return -1;
    };
    let event = match event_code {
        NETWORK_EVENT_PATH_CHANGED => NetworkEvent::PathChanged,
        NETWORK_EVENT_PRE_SLEEP => NetworkEvent::PreSleep,
        NETWORK_EVENT_POST_WAKE => NetworkEvent::PostWake,
        NETWORK_EVENT_REACHABILITY_LOST => NetworkEvent::ReachabilityChanged { reachable: false },
        NETWORK_EVENT_REACHABILITY_GAINED => NetworkEvent::ReachabilityChanged { reachable: true },
        _ => return -1,
    };
    let response = handle.handle_network_event(event);
    if response.reprobe_recommended {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_state_code(handle: *mut MeshTransportHandle) -> u32 {
    match handle.as_ref() {
        Some(handle) => handle.state_code(),
        None => MeshTransportState::Failed.as_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_last_error(
    handle: *mut MeshTransportHandle,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    match handle.last_error() {
        Some(error) => {
            *out = owned_buffer_from_vec(error.into_bytes());
            true
        }
        None => false,
    }
}

// ===================================================================
// Device keypair FFI — needed for cert publishing + persistence.
// ===================================================================

/// Generates a fresh ML-DSA-65 device keypair and writes its 32-byte
/// persistence seed to `out_seed`. The caller MUST save the seed
/// (Keychain on macOS, encrypted key file otherwise) and reload via
/// `qlink_device_keypair_from_seed` on next launch — without that
/// round-trip the published peer_id changes per process restart.
///
/// Returns an owned handle that the caller frees with
/// `qlink_device_keypair_destroy`. Returns null on failure.
#[no_mangle]
pub unsafe extern "C" fn qlink_device_keypair_generate(out_seed: *mut u8) -> *mut DeviceKeypair {
    if out_seed.is_null() {
        return ptr::null_mut();
    }
    let keypair = match DeviceKeypair::generate() {
        Ok(kp) => kp,
        Err(error) => {
            tracing::warn!(?error, "qlink_device_keypair_generate failed");
            return ptr::null_mut();
        }
    };
    let Some(seed) = keypair.seed() else {
        tracing::warn!("device keypair generated without a persistable seed");
        return ptr::null_mut();
    };
    ptr::copy_nonoverlapping(seed.as_ptr(), out_seed, 32);
    Box::into_raw(Box::new(keypair))
}

/// Reconstructs an ML-DSA-65 device keypair from a 32-byte seed
/// previously emitted by `qlink_device_keypair_generate`. Returns
/// null if the seed pointer is invalid or the bytes don't decode.
#[no_mangle]
pub unsafe extern "C" fn qlink_device_keypair_from_seed(seed: *const u8) -> *mut DeviceKeypair {
    let Some(seed_slice) = borrowed_slice(seed, 32) else {
        return ptr::null_mut();
    };
    let mut seed_array = [0_u8; 32];
    seed_array.copy_from_slice(seed_slice);
    match DeviceKeypair::from_seed(seed_array) {
        Ok(kp) => Box::into_raw(Box::new(kp)),
        Err(error) => {
            tracing::warn!(?error, "qlink_device_keypair_from_seed failed");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn qlink_device_keypair_destroy(handle: *mut DeviceKeypair) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Writes the keypair's `peer_id` (UTF-8, no NUL terminator) into
/// the supplied owned buffer. Caller frees via
/// `qlink_owned_buffer_free`. Returns false on bad arguments.
#[no_mangle]
pub unsafe extern "C" fn qlink_device_keypair_peer_id(
    handle: *mut DeviceKeypair,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    *out = owned_buffer_from_vec(handle.public_key().peer_id().into_bytes());
    true
}

// ===================================================================
// Dytallix enrollment wallet
// ===================================================================

/// Ensures a Dytallix enrollment wallet exists in the keystore at
/// `keystore_path`, generating + activating one if absent. On success writes a
/// newline-delimited `key=value` summary (`wallet_name`, `wallet_address`,
/// `created_wallet`) to `out` and returns true; the buffer is caller-owned and
/// must be freed with `qlink_owned_buffer_free`. An empty `wallet_name_len`
/// means "use the active/default wallet". `endpoint` + `contract` are validated
/// into the registry config but only the keystore is touched here — no network.
#[no_mangle]
pub unsafe extern "C" fn qlink_dytallix_ensure_wallet(
    endpoint_ptr: *const u8,
    endpoint_len: usize,
    contract_ptr: *const u8,
    contract_len: usize,
    keystore_path_ptr: *const u8,
    keystore_path_len: usize,
    wallet_name_ptr: *const u8,
    wallet_name_len: usize,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(out) = out.as_mut() else {
        return false;
    };
    let (Some(endpoint), Some(contract), Some(keystore_path)) = (
        borrowed_slice(endpoint_ptr, endpoint_len).and_then(|b| str::from_utf8(b).ok()),
        borrowed_slice(contract_ptr, contract_len).and_then(|b| str::from_utf8(b).ok()),
        borrowed_slice(keystore_path_ptr, keystore_path_len).and_then(|b| str::from_utf8(b).ok()),
    ) else {
        return false;
    };
    let wallet_name = if wallet_name_len == 0 {
        None
    } else {
        match borrowed_slice(wallet_name_ptr, wallet_name_len).and_then(|b| str::from_utf8(b).ok()) {
            Some(name) => Some(name.to_string()),
            None => return false,
        }
    };

    let config = match DytallixRegistryConfig::new(endpoint, contract, keystore_path, wallet_name) {
        Ok(config) => config,
        Err(_) => return false,
    };
    let wallet = match ensure_dytallix_enrollment_wallet(&config) {
        Ok(wallet) => wallet,
        Err(_) => return false,
    };
    let summary = format!(
        "wallet_name={}\nwallet_address={}\ncreated_wallet={}\n",
        wallet.wallet_name, wallet.wallet_address, wallet.created_wallet
    );
    *out = owned_buffer_from_vec(summary.into_bytes());
    true
}

// ===================================================================
// Mesh transport — keypair-aware constructor + multi-peer control.
// ===================================================================

/// Variant of `qlink_mesh_transport_create` that also installs a
/// local device keypair on the connector. Without this, the Rust
/// connector skips the inbound `InboundIdentityAssertion` and the
/// remote peer's responder closes the connection silently. Use this
/// constructor for any production deployment where the responder is
/// enabled on either side.
///
/// The keypair handle is **borrowed** for the duration of this call.
/// Internally the FFI re-derives an owned keypair from the borrowed
/// keypair's seed (`DeviceKeypair::seed`) so the Swift side keeps
/// ownership and can free the keypair handle independently. This
/// requires the keypair to have been generated via the seedable
/// ML-DSA path (any keypair from `qlink_device_keypair_generate` or
/// `qlink_device_keypair_from_seed`); SLH-DSA keypairs return null.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_create_with_keypair(
    config_json: *const u8,
    config_json_len: usize,
    keypair: *mut DeviceKeypair,
) -> *mut MeshTransportHandle {
    let Some(config_bytes) = borrowed_slice(config_json, config_json_len) else {
        return ptr::null_mut();
    };
    let config: MeshTransportConfig = match serde_json::from_slice(config_bytes) {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::warn!(
                ?error,
                "qlink_mesh_transport_create_with_keypair config decode failed"
            );
            return ptr::null_mut();
        }
    };
    let Some(keypair_ref) = keypair.as_ref() else {
        return ptr::null_mut();
    };
    // Re-derive an owned keypair from the borrowed seed so the FFI
    // owns the Arc that gets passed into the connector. The Swift
    // side keeps the original handle and can free it whenever.
    let Some(seed) = keypair_ref.seed() else {
        tracing::warn!("qlink_mesh_transport_create_with_keypair received non-seedable keypair");
        return ptr::null_mut();
    };
    let owned_keypair = match DeviceKeypair::from_seed(seed) {
        Ok(kp) => Arc::new(kp),
        Err(error) => {
            tracing::warn!(
                ?error,
                "qlink_mesh_transport_create_with_keypair seed decode failed"
            );
            return ptr::null_mut();
        }
    };
    match MeshTransportHandle::new_with_keypair(config, Some(owned_keypair)) {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(error) => {
            tracing::warn!(?error, "qlink_mesh_transport_create_with_keypair failed");
            ptr::null_mut()
        }
    }
}

/// DER-encoded QUIC server certificate the responder presents.
/// Required for callers that mint signed peer records (the
/// `device_certificate_der` field on `UnsignedPeerRecord`). Returns
/// false when the responder is disabled.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_server_certificate_der(
    handle: *mut MeshTransportHandle,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    match handle.server_certificate_der() {
        Some(der) => {
            *out = owned_buffer_from_vec(der.to_vec());
            true
        }
        None => false,
    }
}

/// Bound address of the inbound responder, formatted as a UTF-8
/// `host:port` string ("127.0.0.1:54321"). Returns false when the
/// responder is disabled.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_responder_local_addr(
    handle: *mut MeshTransportHandle,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    match handle.responder_local_addr() {
        Some(addr) => {
            *out = owned_buffer_from_vec(addr.to_string().into_bytes());
            true
        }
        None => false,
    }
}

/// Mints + signs a peer record for the local node and publishes it
/// to the rendezvous server. Wraps the async `publish_self` via the
/// handle's internal runtime, so the FFI is synchronous from the
/// caller's perspective. Returns 0 on success, -1 on failure (the
/// reason is available via `qlink_mesh_transport_last_error`-style
/// surfaces or by re-publishing with logging enabled on the Rust
/// side).
///
/// Pre-conditions:
/// - the responder is enabled (`disable_inbound_responder = false`)
/// - the keypair's `peer_id` matches the handle's `local_peer_id`
/// - the rendezvous server is reachable
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_publish_self(
    handle: *mut MeshTransportHandle,
    keypair: *mut DeviceKeypair,
    rendezvous_url: *const u8,
    rendezvous_url_len: usize,
    ttl_seconds: u64,
    sequence: u64,
) -> i32 {
    let Some(handle) = handle.as_ref() else {
        return -1;
    };
    let Some(keypair) = keypair.as_ref() else {
        return -1;
    };
    let Some(url_bytes) = borrowed_slice(rendezvous_url, rendezvous_url_len) else {
        return -1;
    };
    let Ok(url) = str::from_utf8(url_bytes) else {
        return -1;
    };
    match handle.publish_self_blocking(keypair, url, ttl_seconds, sequence, Vec::new()) {
        Ok(_record) => 0,
        Err(error) => {
            tracing::warn!(?error, "qlink_mesh_transport_publish_self failed");
            -1
        }
    }
}

/// Adds a peer to the multi-peer transport. Idempotent — adding a
/// peer that's already active is a no-op. The session manager that
/// drives `connector.connect(peer_id)` is spawned on the handle's
/// runtime and runs until the peer is removed or the handle is
/// dropped.
///
/// Returns 0 on success, -1 on bad arguments / poisoned mutex / no
/// runtime.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_add_peer(
    handle: *mut MeshTransportHandle,
    peer_id: *const u8,
    peer_id_len: usize,
) -> i32 {
    let Some(handle) = handle.as_ref() else {
        return -1;
    };
    let Some(peer_id_bytes) = borrowed_slice(peer_id, peer_id_len) else {
        return -1;
    };
    let Ok(peer_id_str) = str::from_utf8(peer_id_bytes) else {
        return -1;
    };
    match handle.add_peer(peer_id_str) {
        Ok(()) => 0,
        Err(error) => {
            tracing::warn!(?error, "qlink_mesh_transport_add_peer failed");
            -1
        }
    }
}

/// Removes a peer from the multi-peer transport. Idempotent.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_remove_peer(
    handle: *mut MeshTransportHandle,
    peer_id: *const u8,
    peer_id_len: usize,
) {
    let Some(handle) = handle.as_ref() else {
        return;
    };
    let Some(peer_id_bytes) = borrowed_slice(peer_id, peer_id_len) else {
        return;
    };
    let Ok(peer_id_str) = str::from_utf8(peer_id_bytes) else {
        return;
    };
    handle.remove_peer(peer_id_str);
}

/// Returns the active managed peer IDs as a newline-separated UTF-8
/// buffer. The list includes peers whose session managers are currently
/// failed/backing off, which lets operators see registry-rejected peers
/// even before any inbound traffic is accepted.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_peer_ids(
    handle: *mut MeshTransportHandle,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    let mut peer_ids = handle.peer_ids();
    peer_ids.sort();
    *out = owned_buffer_from_vec(peer_ids.join("\n").into_bytes());
    true
}

/// Returns retained blocked/rejected peer history as a UTF-8 JSON array.
/// Each entry contains `peer_id`, `direction`, `failure_code`,
/// `failure_reason`, `observed_at_unix`, and `checked_at_unix`.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_blocked_peer_history(
    handle: *mut MeshTransportHandle,
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    let Ok(json) = serde_json::to_vec(&handle.blocked_peer_history()) else {
        return false;
    };
    *out = owned_buffer_from_vec(json);
    true
}

/// Per-peer state code (matches `qlink_mesh_transport_state_code`'s
/// integer mapping: 0=connecting, 1=ready, 2=failed, 3=stopped).
/// Returns false when the peer isn't active.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_peer_state_code(
    handle: *mut MeshTransportHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    out_state_code: *mut u32,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(peer_id_bytes) = borrowed_slice(peer_id, peer_id_len) else {
        return false;
    };
    let Ok(peer_id_str) = str::from_utf8(peer_id_bytes) else {
        return false;
    };
    let Some(out) = out_state_code.as_mut() else {
        return false;
    };
    match handle.peer_state_code(peer_id_str) {
        Some(code) => {
            *out = code;
            true
        }
        None => false,
    }
}

/// Per-peer Dytallix registry trust decision.
/// Decision code: 0=unknown, 1=accepted/verified,
/// 2=accepted without registry for private mesh,
/// 3=accepted without registry for development mesh.
/// Failure code: 0=none, 1=required record missing,
/// 2=revoked, 3=suspended/inactive, 4=expired, 5=mismatch,
/// 6=lookup failure, 7=verification failure.
/// Returns false when the peer isn't active.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_peer_trust_status(
    handle: *mut MeshTransportHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    out_status: *mut QlinkPeerTrustStatus,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(peer_id_bytes) = borrowed_slice(peer_id, peer_id_len) else {
        return false;
    };
    let Ok(peer_id_str) = str::from_utf8(peer_id_bytes) else {
        return false;
    };
    let Some(out) = out_status.as_mut() else {
        return false;
    };
    match handle.peer_trust_status(peer_id_str) {
        Some(status) => {
            *out = status.into();
            true
        }
        None => false,
    }
}

// ===================================================================
// Tracing bridge — surface Rust-side `tracing::warn!`/`error!` events
// into the Swift host's logger. See `tracing_bridge.rs` for design.
// ===================================================================

/// Installs the in-process tracing subscriber that captures
/// WARN-and-above events. Idempotent — second call is a no-op.
/// Returns 0 on success, -1 if some other code already set a global
/// tracing subscriber (in which case the bridge is unavailable for
/// this process; the Swift side should fall back to "no Rust
/// diagnostics" rather than failing hard).
///
/// Call this once at app/dylib initialization, before any code that
/// might emit tracing events. After installation, drain via
/// `qlink_tracing_pop_event` on a polling cadence.
#[no_mangle]
pub unsafe extern "C" fn qlink_tracing_install() -> i32 {
    match tracing_bridge::install() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Pops the next captured event as a JSON string into the supplied
/// owned buffer. Returns true if an event was popped, false when
/// the buffer is empty (or the bridge isn't installed).
///
/// JSON shape:
/// `{"level":"warn","target":"qlink_core::mesh_connection","message":"..."}`
///
/// The Swift caller MUST redact the message field before forwarding
/// to `os_log` — Rust events routinely embed peer_ids, addresses,
/// and rendezvous URLs verbatim.
#[no_mangle]
pub unsafe extern "C" fn qlink_tracing_pop_event(out: *mut QlinkOwnedBuffer) -> bool {
    let Some(out) = out.as_mut() else {
        return false;
    };
    let Some(buffer) = tracing_bridge::global() else {
        return false;
    };
    match buffer.pop() {
        Some(event) => {
            *out = owned_buffer_from_vec(event.to_json().into_bytes());
            true
        }
        None => false,
    }
}

/// Cumulative count of events evicted from the bridge buffer due to
/// capacity pressure. Operators can watch this for oversaturation:
/// a non-zero value means at least one tracing event was dropped
/// since process start. Returns 0 if the bridge isn't installed.
#[no_mangle]
pub unsafe extern "C" fn qlink_tracing_dropped_count() -> u64 {
    tracing_bridge::global()
        .map(|b| b.dropped_count())
        .unwrap_or(0)
}

/// Sends a frame to a specific peer. Returns 0 on success, -1 on
/// bad arguments or when the peer isn't active.
#[no_mangle]
pub unsafe extern "C" fn qlink_mesh_transport_send_frame_to(
    handle: *mut MeshTransportHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    frame: *const u8,
    frame_len: usize,
) -> i32 {
    let Some(handle) = handle.as_ref() else {
        return -1;
    };
    let Some(peer_id_bytes) = borrowed_slice(peer_id, peer_id_len) else {
        return -1;
    };
    let Ok(peer_id_str) = str::from_utf8(peer_id_bytes) else {
        return -1;
    };
    let Some(frame_bytes) = borrowed_slice(frame, frame_len) else {
        return -1;
    };
    match handle.send_frame_to(peer_id_str, frame_bytes.to_vec()) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_wallet_ffi_generates_dytallix_address() {
        let dir = std::env::temp_dir().join(format!(
            "qlink-wallet-ffi-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let keystore = dir.join("keystore.json");
        let keystore_str = keystore.to_str().unwrap();
        let endpoint = "https://dytallix.com";
        let contract = "0xbcb5cf5abb50333ee4bfde91f21bbcc24828673d";
        let mut out = QlinkOwnedBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let ok = unsafe {
            qlink_dytallix_ensure_wallet(
                endpoint.as_ptr(),
                endpoint.len(),
                contract.as_ptr(),
                contract.len(),
                keystore_str.as_ptr(),
                keystore_str.len(),
                std::ptr::null(),
                0,
                &mut out,
            )
        };
        assert!(ok, "ensure_wallet returned false");
        let summary =
            unsafe { String::from_utf8(slice::from_raw_parts(out.ptr, out.len).to_vec()).unwrap() };
        unsafe { qlink_owned_buffer_free(out) };
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            summary.contains("wallet_address=dytallix1"),
            "expected a dytallix1 address, got: {summary}"
        );
        assert!(
            summary.contains("created_wallet=true"),
            "expected created_wallet=true, got: {summary}"
        );
    }

    #[test]
    fn ffi_core_round_trips_transport_frame() {
        let config = br#"{
            "protectedRoutes": ["100.127.0.0/16"],
            "excludedRoutes": [],
            "routeMode": "splitTunnel",
            "mtu": 1280
        }"#;

        let handle = unsafe { qlink_tunnel_core_create(config.as_ptr(), config.len()) };
        assert!(!handle.is_null());

        let packet = test_ipv4_packet([100, 127, 0, 9]);
        let disposition =
            unsafe { qlink_tunnel_core_submit_packet(handle, 2, packet.as_ptr(), packet.len()) };
        assert_eq!(disposition, 1);

        let mut frame = QlinkOwnedBuffer {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert!(unsafe { qlink_tunnel_core_pop_transport_frame(handle, &mut frame) });

        let accepted =
            unsafe { qlink_tunnel_core_accept_transport_frame(handle, frame.ptr, frame.len) };
        assert_eq!(accepted, 0);
        unsafe { qlink_owned_buffer_free(frame) };

        let mut restored = QlinkOwnedPacket {
            protocol_family: 0,
            buffer: QlinkOwnedBuffer {
                ptr: ptr::null_mut(),
                len: 0,
                cap: 0,
            },
        };
        assert!(unsafe { qlink_tunnel_core_pop_tunnel_packet(handle, &mut restored) });
        assert_eq!(restored.protocol_family, 2);

        let restored_bytes =
            unsafe { slice::from_raw_parts(restored.buffer.ptr, restored.buffer.len).to_vec() };
        assert_eq!(restored_bytes[16..20], packet[16..20]);
        assert_eq!(ipv4_header_checksum(&restored_bytes), 0);
        unsafe { qlink_owned_buffer_free(restored.buffer) };
        unsafe { qlink_tunnel_core_destroy(handle) };
    }

    #[test]
    fn ffi_dev_quic_transport_is_disabled() {
        let handle = qlink_dev_quic_transport_create();
        assert!(handle.is_null());

        let frame = b"qlink-frame";
        let sent =
            unsafe { qlink_dev_quic_transport_send_frame(handle, frame.as_ptr(), frame.len()) };
        assert_eq!(sent, -1);

        let mut received = QlinkOwnedBuffer {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert!(!unsafe { qlink_dev_quic_transport_receive_frame(handle, &mut received) });
        assert!(received.ptr.is_null());
        assert_eq!(received.len, 0);

        let mut metrics = QlinkTransportMetrics::default();
        assert!(!unsafe { qlink_dev_quic_transport_metrics(handle, &mut metrics) });
    }

    fn test_ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = 20;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 127, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn ipv4_header_checksum(packet: &[u8]) -> u16 {
        let header_len = ((packet[0] & 0x0f) as usize) * 4;
        let mut sum = 0_u32;
        for chunk in packet[..header_len].chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
