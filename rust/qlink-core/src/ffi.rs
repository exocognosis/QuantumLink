use crate::{
    mesh_connection::NetworkEvent,
    mesh_transport::{MeshTransportHandle, MeshTransportState},
    packet_core::{PacketDisposition, PacketTunnelCore},
    quic_transport::{QuicDatagramSession, QuicEndpoint},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::raw::c_char,
    ptr, slice,
    sync::Mutex,
    time::Duration,
};
use tokio::runtime::Runtime;

static VERSION: &[u8] = b"0.1.0\0";
static SUITE: &[u8] = b"QLINK-FIPS203-MLKEM768-HKDFSHA256-v1\0";

pub struct QlinkTunnelCoreHandle {
    core: Mutex<PacketTunnelCore>,
}

pub struct QlinkDevQuicTransportHandle {
    _client_endpoint: QuicEndpoint,
    _server_endpoint: QuicEndpoint,
    client_session: QuicDatagramSession,
    server_session: QuicDatagramSession,
    metrics: QlinkTransportMetrics,
    runtime: Runtime,
}

#[repr(C)]
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
        Ok(PacketDisposition::DroppedUnprotected) => 0,
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
    match create_dev_quic_transport() {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(_) => ptr::null_mut(),
    }
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
    let Some(frame) = borrowed_slice(frame, frame_len) else {
        handle.metrics.send_failures += 1;
        return -1;
    };

    match handle
        .runtime
        .block_on(async { handle.client_session.send_frame(frame.to_vec()).await })
    {
        Ok(()) => {
            handle.metrics.frames_sent += 1;
            handle.metrics.bytes_sent += frame_len as u64;
            0
        }
        Err(_) => {
            handle.metrics.send_failures += 1;
            -1
        }
    }
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

    match handle.runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_millis(25),
            handle.server_session.receive_frame(),
        )
        .await
    }) {
        Ok(Ok(frame)) => {
            handle.metrics.frames_received += 1;
            handle.metrics.bytes_received += frame.len() as u64;
            *out = owned_buffer_from_vec(frame);
            true
        }
        Ok(Err(_)) => {
            handle.metrics.receive_failures += 1;
            false
        }
        Err(_) => false,
    }
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

fn create_dev_quic_transport() -> crate::Result<QlinkDevQuicTransportHandle> {
    let runtime = Runtime::new()
        .map_err(|err| crate::QlinkError::Protocol(format!("failed to create runtime: {err}")))?;
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let _runtime_guard = runtime.enter();
    let (server_endpoint, server_cert) = QuicEndpoint::server(bind)?;
    let client_endpoint = QuicEndpoint::client(bind, &[server_cert])?;
    let server_addr = server_endpoint.local_addr()?;
    let (client_session, server_session) = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                client_endpoint.connect(server_addr),
                server_endpoint.accept_one()
            )
        })
        .await
        .map_err(|_| crate::QlinkError::Protocol("dev QUIC transport timed out".into()))
    })?;

    Ok(QlinkDevQuicTransportHandle {
        _client_endpoint: client_endpoint,
        _server_endpoint: server_endpoint,
        client_session: client_session?,
        server_session: server_session?,
        metrics: QlinkTransportMetrics::default(),
        runtime,
    })
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
    out: *mut QlinkOwnedBuffer,
) -> bool {
    let Some(handle) = handle.as_ref() else {
        return false;
    };
    let Some(out) = out.as_mut() else {
        return false;
    };
    match handle.try_receive_frame() {
        Some(frame) => {
            *out = owned_buffer_from_vec(frame);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ffi_dev_quic_transport_round_trips_frame() {
        let handle = qlink_dev_quic_transport_create();
        assert!(!handle.is_null());

        let frame = b"qlink-frame";
        let sent =
            unsafe { qlink_dev_quic_transport_send_frame(handle, frame.as_ptr(), frame.len()) };
        assert_eq!(sent, 0);

        let mut received = QlinkOwnedBuffer {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert!(unsafe { qlink_dev_quic_transport_receive_frame(handle, &mut received) });
        let bytes = unsafe { slice::from_raw_parts(received.ptr, received.len).to_vec() };
        assert_eq!(bytes, frame);
        unsafe { qlink_owned_buffer_free(received) };

        let mut metrics = QlinkTransportMetrics::default();
        assert!(unsafe { qlink_dev_quic_transport_metrics(handle, &mut metrics) });
        assert_eq!(metrics.frames_sent, 1);
        assert_eq!(metrics.frames_received, 1);

        unsafe { qlink_dev_quic_transport_destroy(handle) };
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
