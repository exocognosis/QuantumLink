//! Default-safe diagnostics export for user-shareable Windows support bundles.

use quantumlink_proto::models::{
    ConnectionPhase, DiscoveryIdentityMode, DnsMode, MeshTrustPolicy, PathType, RouteMode,
    TunnelStatus,
};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SUPPORT_BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const REDACTION_POLICY: &str = "default-safe-v1";
pub const MAX_SUPPORT_BUNDLE_BYTES: usize = 64 * 1024;
pub const MAX_PEER_ENTRIES: usize = 32;

const BOUNDED_FALLBACK: &str = r#"{"schemaVersion":1,"service":"unknown","qlinkCoreSuite":"QLINK-FIPS203-MLKEM768-SHAKE256-v1","redactionPolicy":{"name":"default-safe-v1","maxBytes":65536,"maxPeerEntries":32,"rawExportAvailable":false},"generatedAt":0,"exportState":"bounded_fallback","status":{"phase":"idle","pathType":"unavailable","routeMode":"splitTunnel","dnsMode":"tunnelProvided","overlayAddressPresent":false,"protectedRouteCount":0,"peers":[],"metrics":{"peerCount":0,"directPeerCount":0,"relayPeerCount":0,"bytesIn":0,"bytesOut":0,"replayDrops":0,"lastPathProbeUnix":null},"transport":null,"pump":null,"peerSessionKeyAvailable":false,"peerSessionKeyState":"unknown","killSwitchEngaged":null,"peerTrust":{"required":false,"policy":"developmentOptional","identityMode":"off","registryConfigured":false,"verifiedPeerCount":0,"unverifiedPeerCount":0,"pendingPeerCount":0,"failedPeerCount":0,"lastCheckedAtUnix":null,"lastFailureCode":null,"lastFailurePresent":false,"warningPresent":false},"lastError":null},"diagnostics":{"peerTotalCount":0,"peerIncludedCount":0,"peerEntriesTruncated":false,"logsIncluded":false,"packetCapturesIncluded":false}}"#;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportBundle {
    schema_version: u32,
    service: &'static str,
    qlink_core_suite: &'static str,
    redaction_policy: RedactionPolicy,
    generated_at: u64,
    export_state: &'static str,
    status: SupportStatus,
    diagnostics: SupportDiagnostics,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RedactionPolicy {
    name: &'static str,
    max_bytes: usize,
    max_peer_entries: usize,
    raw_export_available: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportStatus {
    phase: ConnectionPhase,
    path_type: PathType,
    route_mode: RouteMode,
    dns_mode: DnsMode,
    overlay_address_present: bool,
    protected_route_count: usize,
    peers: Vec<PeerSummary>,
    metrics: SupportMeshMetrics,
    transport: Option<SupportTransportMetrics>,
    pump: Option<SupportPumpMetrics>,
    peer_session_key_available: bool,
    peer_session_key_state: &'static str,
    kill_switch_engaged: Option<bool>,
    peer_trust: PeerTrustDiagnostics,
    last_error: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerSummary {
    identity: PeerIdentitySummary,
    path_type: PathType,
    endpoint_count: usize,
    overlay_address_present: bool,
    rtt_milliseconds: Option<u32>,
    last_rekey_unix: Option<u64>,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerIdentitySummary {
    #[serde(rename = "peerID")]
    peer_id: String,
    alias_present: bool,
    public_key_fingerprint_present: bool,
}

// Support-only DTOs intentionally copy approved fields. Shared model additions
// cannot enter the export without an explicit change here.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportMeshMetrics {
    peer_count: u32,
    direct_peer_count: u32,
    relay_peer_count: u32,
    bytes_in: u64,
    bytes_out: u64,
    replay_drops: u64,
    last_path_probe_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportTransportMetrics {
    state_code: u32,
    path_kind_code: u32,
    frames_sent: u64,
    frames_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    send_failures: u64,
    receive_failures: u64,
    network_event_count: u64,
    reconnect_count: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportPumpMetrics {
    packets_observed: u64,
    queued_for_transport: u64,
    dropped_unprotected: u64,
    dropped_fail_closed: u64,
    dropped_kill_switch: u64,
    failed_submissions: u64,
    transport_frames_emitted: u64,
    transport_frames_accepted: u64,
    failed_inbound_frames: u64,
    tunnel_packets_emitted: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerTrustDiagnostics {
    required: bool,
    policy: MeshTrustPolicy,
    identity_mode: DiscoveryIdentityMode,
    registry_configured: bool,
    verified_peer_count: u32,
    unverified_peer_count: u32,
    pending_peer_count: u32,
    failed_peer_count: u32,
    last_checked_at_unix: Option<u64>,
    last_failure_code: Option<&'static str>,
    last_failure_present: bool,
    warning_present: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportDiagnostics {
    peer_total_count: usize,
    peer_included_count: usize,
    peer_entries_truncated: bool,
    logs_included: bool,
    packet_captures_included: bool,
}

pub fn export(status: &TunnelStatus) -> String {
    export_at(status, generated_at_unix())
}

fn generated_at_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn export_at(status: &TunnelStatus, generated_at: u64) -> String {
    export_at_with_limit(status, generated_at, MAX_SUPPORT_BUNDLE_BYTES)
}

fn export_at_with_limit(status: &TunnelStatus, generated_at: u64, limit: usize) -> String {
    let peers = status
        .peers
        .iter()
        .take(MAX_PEER_ENTRIES)
        .enumerate()
        .map(|(index, peer)| PeerSummary {
            identity: PeerIdentitySummary {
                peer_id: format!("peer_{}", index + 1),
                alias_present: !peer.identity.alias.is_empty(),
                public_key_fingerprint_present: !peer.identity.public_key_fingerprint.is_empty(),
            },
            path_type: peer.path_type,
            endpoint_count: peer.endpoints.len(),
            overlay_address_present: !peer.overlay_address.is_empty(),
            rtt_milliseconds: peer.rtt_milliseconds,
            last_rekey_unix: peer.last_rekey_unix,
            bytes_in: peer.bytes_in,
            bytes_out: peer.bytes_out,
        })
        .collect::<Vec<_>>();
    let included_count = peers.len();
    let total_count = status.peers.len();
    let metrics = &status.metrics;

    let bundle = SupportBundle {
        schema_version: SUPPORT_BUNDLE_SCHEMA_VERSION,
        service: env!("CARGO_PKG_VERSION"),
        qlink_core_suite: "QLINK-FIPS203-MLKEM768-SHAKE256-v1",
        redaction_policy: RedactionPolicy {
            name: REDACTION_POLICY,
            max_bytes: MAX_SUPPORT_BUNDLE_BYTES,
            max_peer_entries: MAX_PEER_ENTRIES,
            raw_export_available: false,
        },
        generated_at,
        export_state: "complete",
        status: SupportStatus {
            phase: status.phase,
            path_type: status.path_type,
            route_mode: status.route_mode,
            dns_mode: status.dns_mode,
            overlay_address_present: !status.overlay_ipv4_address.is_empty(),
            protected_route_count: status.protected_routes.len(),
            peers,
            metrics: SupportMeshMetrics {
                peer_count: metrics.peer_count,
                direct_peer_count: metrics.direct_peer_count,
                relay_peer_count: metrics.relay_peer_count,
                bytes_in: metrics.bytes_in,
                bytes_out: metrics.bytes_out,
                replay_drops: metrics.replay_drops,
                last_path_probe_unix: metrics.last_path_probe_unix,
            },
            transport: status.transport.map(|value| SupportTransportMetrics {
                state_code: value.state_code,
                path_kind_code: value.path_kind_code,
                frames_sent: value.frames_sent,
                frames_received: value.frames_received,
                bytes_sent: value.bytes_sent,
                bytes_received: value.bytes_received,
                send_failures: value.send_failures,
                receive_failures: value.receive_failures,
                network_event_count: value.network_event_count,
                reconnect_count: value.reconnect_count,
            }),
            pump: status.pump.as_ref().map(|value| SupportPumpMetrics {
                packets_observed: value.packets_observed,
                queued_for_transport: value.queued_for_transport,
                dropped_unprotected: value.dropped_unprotected,
                dropped_fail_closed: value.dropped_fail_closed,
                dropped_kill_switch: value.dropped_kill_switch,
                failed_submissions: value.failed_submissions,
                transport_frames_emitted: value.transport_frames_emitted,
                transport_frames_accepted: value.transport_frames_accepted,
                failed_inbound_frames: value.failed_inbound_frames,
                tunnel_packets_emitted: value.tunnel_packets_emitted,
            }),
            peer_session_key_available: status.peer_session_key_available,
            peer_session_key_state: safe_session_key_state(&status.peer_session_key_state),
            kill_switch_engaged: status.kill_switch_engaged,
            peer_trust: PeerTrustDiagnostics {
                required: status.peer_trust.required,
                policy: status.peer_trust.policy,
                identity_mode: status.peer_trust.identity_mode,
                registry_configured: status.peer_trust.registry_configured,
                verified_peer_count: status.peer_trust.verified_peer_count,
                unverified_peer_count: status.peer_trust.unverified_peer_count,
                pending_peer_count: status.peer_trust.pending_peer_count,
                failed_peer_count: status.peer_trust.failed_peer_count,
                last_checked_at_unix: status.peer_trust.last_checked_at_unix,
                last_failure_code: safe_trust_failure_code(
                    status.peer_trust.last_failure_code.as_deref(),
                ),
                last_failure_present: status.peer_trust.last_failure_code.is_some()
                    || status.peer_trust.last_failure_summary.is_some(),
                warning_present: status.peer_trust.warning.is_some(),
            },
            last_error: status.last_error.as_deref().map(safe_error_category),
        },
        diagnostics: SupportDiagnostics {
            peer_total_count: total_count,
            peer_included_count: included_count,
            peer_entries_truncated: total_count > included_count,
            logs_included: false,
            packet_captures_included: false,
        },
    };

    match serde_json::to_string_pretty(&bundle) {
        Ok(output) if output.len() <= limit => output,
        _ => BOUNDED_FALLBACK.to_string(),
    }
}

fn safe_session_key_state(value: &str) -> &'static str {
    match value {
        "available" => "available",
        "unavailable" => "unavailable",
        "notRequired" => "notRequired",
        _ => "unknown",
    }
}

fn safe_trust_failure_code(value: Option<&str>) -> Option<&'static str> {
    match value {
        Some("rejected_missing_registry") => Some("rejected_missing_registry"),
        Some("rejected_revoked") => Some("rejected_revoked"),
        Some("rejected_suspended") => Some("rejected_suspended"),
        Some("rejected_expired") => Some("rejected_expired"),
        Some("rejected_key_mismatch") => Some("rejected_key_mismatch"),
        Some("rejected_record_hash_mismatch") => Some("rejected_record_hash_mismatch"),
        Some("rejected_stake_or_reputation") => Some("rejected_stake_or_reputation"),
        Some("registry_unavailable") => Some("registry_unavailable"),
        Some(_) => Some("identity_policy_rejected"),
        None => None,
    }
}

fn safe_error_category(value: &str) -> &'static str {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("dns") {
        "dns"
    } else if normalized.contains("registry") || normalized.contains("dytallix") {
        "identity_registry"
    } else if normalized.contains("wintun") || normalized.contains("adapter") {
        "adapter"
    } else if normalized.contains("wfp") || normalized.contains("kill switch") {
        "kill_switch"
    } else if normalized.contains("route") {
        "routing"
    } else if normalized.contains("relay")
        || normalized.contains("rendezvous")
        || normalized.contains("transport")
    {
        "transport"
    } else if normalized.contains("config") {
        "configuration"
    } else {
        "internal"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quantumlink_proto::models::{
        DytallixPeerTrustSummary, PeerEndpoint, PeerIdentity, PeerStatus,
    };

    fn sensitive_status(peer_count: usize) -> TunnelStatus {
        let peer = PeerStatus {
            identity: PeerIdentity {
                peer_id: "qlink_UmF3UGVlcklkZW50aWZpZXI".to_string(),
                alias: "wallet-0xfeedface operator-wallet".to_string(),
                public_key_fingerprint: "private-key-fingerprint".to_string(),
            },
            path_type: PathType::Direct,
            endpoints: vec![PeerEndpoint {
                candidate_type: "SecretWifiSSID".to_string(),
                address: "203.0.113.42".to_string(),
                port: 443,
                priority: 1,
            }],
            overlay_address: "100.127.10.20".to_string(),
            rtt_milliseconds: Some(24),
            last_rekey_unix: Some(1_700_000_000),
            bytes_in: 123,
            bytes_out: 456,
        };
        let mut status = TunnelStatus::idle();
        status.overlay_ipv4_address = "100.127.10.20".to_string();
        status.protected_routes = vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()];
        status.peers = vec![peer; peer_count];
        status.peer_session_key_state = "secret session key material".to_string();
        status.last_error = Some(
            "registry.private.example dns.private.example payload-capture.pcap hunter2".to_string(),
        );
        status.peer_trust = DytallixPeerTrustSummary {
            last_failure_code: Some("raw-wallet-address".to_string()),
            last_failure_summary: Some("packet/game payload bytes".to_string()),
            warning: Some(r"C:\QuantumLink\wallet.secret".to_string()),
            ..DytallixPeerTrustSummary::default()
        };
        status
    }

    #[test]
    fn support_bundle_omits_sensitive_samples_and_forbidden_markers() {
        let output = export_at(&sensitive_status(1), 1_725_000_000);

        for forbidden in [
            "qlink_UmF3",
            "0xfeedface",
            "operator-wallet",
            "private-key-fingerprint",
            "SecretWifiSSID",
            "203.0.113.42",
            "100.127.10.20",
            "10.0.0.0/8",
            "fd00::/8",
            "registry.private.example",
            "dns.private.example",
            "payload-capture.pcap",
            "hunter2",
            "wallet.secret",
            "raw-wallet-address",
            "packet/game payload bytes",
            "secret session key material",
        ] {
            assert!(
                !output.contains(forbidden),
                "leaked forbidden value: {forbidden}"
            );
        }
        assert!(output.contains(r#""lastError": "dns""#));
        assert!(output.contains(r#""lastFailureCode": "identity_policy_rejected""#));
        assert!(output.contains(r#""peerSessionKeyState": "unknown""#));
        assert!(output.contains(r#""rawExportAvailable": false"#));
        assert!(output.contains(r#""packetCapturesIncluded": false"#));
    }

    #[test]
    fn support_bundle_enforces_peer_count_and_size_bounds() {
        let output = export_at(&sensitive_status(1_000), 1_725_000_000);
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(json["diagnostics"]["peerTotalCount"], 1_000);
        assert_eq!(json["diagnostics"]["peerIncludedCount"], MAX_PEER_ENTRIES);
        assert_eq!(
            json["status"]["peers"].as_array().unwrap().len(),
            MAX_PEER_ENTRIES
        );
        assert_eq!(json["diagnostics"]["peerEntriesTruncated"], true);
        assert!(output.len() <= MAX_SUPPORT_BUNDLE_BYTES);
    }

    #[test]
    fn support_bundle_uses_valid_bounded_fallback_without_panicking() {
        let output = export_at_with_limit(&sensitive_status(1), 1_725_000_000, 1);
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(json["exportState"], "bounded_fallback");
        assert_eq!(json["redactionPolicy"]["rawExportAvailable"], false);
        assert!(output.len() <= MAX_SUPPORT_BUNDLE_BYTES);
    }

    #[test]
    fn support_bundle_preserves_legacy_top_level_shape_and_is_deterministic() {
        let status = sensitive_status(2);
        let first = export_at(&status, 1_725_000_000);
        let second = export_at(&status, 1_725_000_000);
        assert_eq!(first, second);

        let json: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(json["schemaVersion"], SUPPORT_BUNDLE_SCHEMA_VERSION);
        assert!(json["service"].is_string());
        assert_eq!(json["qlinkCoreSuite"], "QLINK-FIPS203-MLKEM768-SHAKE256-v1");
        assert_eq!(json["redactionPolicy"]["name"], REDACTION_POLICY);
        assert_eq!(json["generatedAt"], 1_725_000_000_u64);
        assert!(json["status"].is_object());
        assert_eq!(json["status"]["peers"][0]["identity"]["peerID"], "peer_1");
        assert_eq!(json["status"]["peers"][1]["identity"]["peerID"], "peer_2");
    }
}
