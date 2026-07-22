#ifndef QLINK_CORE_H
#define QLINK_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct QlinkTunnelCoreHandle QlinkTunnelCoreHandle;
typedef struct QlinkDevQuicTransportHandle QlinkDevQuicTransportHandle;

typedef struct QlinkOwnedBuffer {
    uint8_t *ptr;
    uintptr_t len;
    uintptr_t cap;
} QlinkOwnedBuffer;

typedef struct QlinkOwnedPacket {
    uint32_t protocol_family;
    QlinkOwnedBuffer buffer;
} QlinkOwnedPacket;

typedef struct QlinkInboundFrame {
    QlinkOwnedBuffer frame;
    QlinkOwnedBuffer peer_id;
} QlinkInboundFrame;

typedef struct QlinkTunnelMetrics {
    uint64_t packets_from_tunnel;
    uint64_t packets_to_tunnel;
    uint64_t transport_frames_out;
    uint64_t transport_frames_in;
    uint64_t dropped_unprotected;
    uint64_t dropped_malformed;
} QlinkTunnelMetrics;

typedef struct QlinkTransportMetrics {
    uint64_t frames_sent;
    uint64_t frames_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t send_failures;
    uint64_t receive_failures;
} QlinkTransportMetrics;

typedef struct QlinkPeerTrustStatus {
    uint32_t decision_code;
    uint32_t failure_code;
    uint64_t checked_at_unix;
    uint32_t source_code;
} QlinkPeerTrustStatus;

const char *qlink_core_version(void);
const char *qlink_core_default_suite(void);

QlinkTunnelCoreHandle *qlink_tunnel_core_create(
    const uint8_t *config_json,
    uintptr_t config_json_len
);

void qlink_tunnel_core_destroy(QlinkTunnelCoreHandle *handle);

int32_t qlink_tunnel_core_submit_packet(
    QlinkTunnelCoreHandle *handle,
    uint32_t protocol_family,
    const uint8_t *packet,
    uintptr_t packet_len
);

bool qlink_tunnel_core_pop_transport_frame(
    QlinkTunnelCoreHandle *handle,
    QlinkOwnedBuffer *out
);

int32_t qlink_tunnel_core_accept_transport_frame(
    QlinkTunnelCoreHandle *handle,
    const uint8_t *frame,
    uintptr_t frame_len
);

bool qlink_tunnel_core_pop_tunnel_packet(
    QlinkTunnelCoreHandle *handle,
    QlinkOwnedPacket *out
);

bool qlink_tunnel_core_metrics(
    QlinkTunnelCoreHandle *handle,
    QlinkTunnelMetrics *out
);

// Disabled in the strict PQC profile because raw Quinn DATAGRAM bypasses the
// app-layer ML-KEM/SHAKE frame session. Always returns NULL.
QlinkDevQuicTransportHandle *qlink_dev_quic_transport_create(void);

void qlink_dev_quic_transport_destroy(QlinkDevQuicTransportHandle *handle);

int32_t qlink_dev_quic_transport_send_frame(
    QlinkDevQuicTransportHandle *handle,
    const uint8_t *frame,
    uintptr_t frame_len
);

bool qlink_dev_quic_transport_receive_frame(
    QlinkDevQuicTransportHandle *handle,
    QlinkOwnedBuffer *out
);

bool qlink_dev_quic_transport_metrics(
    QlinkDevQuicTransportHandle *handle,
    QlinkTransportMetrics *out
);

void qlink_owned_buffer_free(QlinkOwnedBuffer buffer);
void qlink_owned_buffer_free_ptr(QlinkOwnedBuffer *buffer);

// Mesh transport: production data-plane surface.
// state_code:    0 = connecting, 1 = ready, 2 = failed, 3 = stopped
// path_kind_code: 0 = none, 1 = direct, 2 = relay
typedef struct QlinkMeshTransportHandle QlinkMeshTransportHandle;

typedef struct QlinkMeshTransportMetrics {
    uint32_t state_code;
    uint32_t path_kind_code;
    uint64_t frames_sent;
    uint64_t frames_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t send_failures;
    uint64_t receive_failures;
    uint64_t network_event_count;
    uint64_t reconnect_count;
} QlinkMeshTransportMetrics;

// Network event codes for qlink_mesh_transport_handle_network_event:
//   0 = PathChanged, 1 = PreSleep, 2 = PostWake,
//   3 = ReachabilityLost, 4 = ReachabilityGained
QlinkMeshTransportHandle *qlink_mesh_transport_create(
    const uint8_t *config_json,
    uintptr_t config_json_len
);

void qlink_mesh_transport_destroy(QlinkMeshTransportHandle *handle);

int32_t qlink_mesh_transport_send_frame(
    QlinkMeshTransportHandle *handle,
    const uint8_t *frame,
    uintptr_t frame_len
);

bool qlink_mesh_transport_receive_frame(
    QlinkMeshTransportHandle *handle,
    QlinkInboundFrame *out
);

bool qlink_mesh_transport_metrics(
    QlinkMeshTransportHandle *handle,
    QlinkMeshTransportMetrics *out
);

// Returns 1 if a re-probe is recommended, 0 otherwise, -1 on error.
int32_t qlink_mesh_transport_handle_network_event(
    QlinkMeshTransportHandle *handle,
    uint32_t event_code
);

uint32_t qlink_mesh_transport_state_code(QlinkMeshTransportHandle *handle);

bool qlink_mesh_transport_last_error(
    QlinkMeshTransportHandle *handle,
    QlinkOwnedBuffer *out
);

bool qlink_mesh_transport_peer_ids(
    QlinkMeshTransportHandle *handle,
    QlinkOwnedBuffer *out
);

bool qlink_mesh_transport_blocked_peer_history(
    QlinkMeshTransportHandle *handle,
    QlinkOwnedBuffer *out
);

bool qlink_mesh_transport_peer_state_code(
    QlinkMeshTransportHandle *handle,
    const uint8_t *peer_id,
    uintptr_t peer_id_len,
    uint32_t *out_state_code
);

bool qlink_mesh_transport_peer_trust_status(
    QlinkMeshTransportHandle *handle,
    const uint8_t *peer_id,
    uintptr_t peer_id_len,
    QlinkPeerTrustStatus *out
);

#ifdef __cplusplus
}
#endif

#endif
