use qlink_game::{recommend_host, HostCandidateMetrics};

#[test]
fn recommend_host_prefers_lowest_weighted_network_score() {
    let candidates = vec![
        HostCandidateMetrics {
            peer_id: "relay-fast".to_string(),
            median_rtt_ms: 20.0,
            jitter_ms: 2.0,
            packet_loss_percent: 0.0,
            relay: true,
            nat_penalty: 0.0,
        },
        HostCandidateMetrics {
            peer_id: "direct-stable".to_string(),
            median_rtt_ms: 45.0,
            jitter_ms: 1.0,
            packet_loss_percent: 0.0,
            relay: false,
            nat_penalty: 0.0,
        },
        HostCandidateMetrics {
            peer_id: "lossy".to_string(),
            median_rtt_ms: 25.0,
            jitter_ms: 2.0,
            packet_loss_percent: 3.0,
            relay: false,
            nat_penalty: 0.0,
        },
    ];

    let host = recommend_host(&candidates).expect("candidate should be selected");

    assert_eq!(host.peer_id, "direct-stable");
}

#[test]
fn recommend_host_applies_nat_penalty() {
    let candidates = vec![
        HostCandidateMetrics {
            peer_id: "low-rtt-bad-nat".to_string(),
            median_rtt_ms: 20.0,
            jitter_ms: 1.0,
            packet_loss_percent: 0.0,
            relay: false,
            nat_penalty: 40.0,
        },
        HostCandidateMetrics {
            peer_id: "higher-rtt-open-nat".to_string(),
            median_rtt_ms: 35.0,
            jitter_ms: 1.0,
            packet_loss_percent: 0.0,
            relay: false,
            nat_penalty: 0.0,
        },
    ];

    let host = recommend_host(&candidates).expect("candidate should be selected");

    assert_eq!(host.peer_id, "higher-rtt-open-nat");
}

#[test]
fn recommend_host_returns_none_for_empty_candidates() {
    assert!(recommend_host(&[]).is_none());
}
