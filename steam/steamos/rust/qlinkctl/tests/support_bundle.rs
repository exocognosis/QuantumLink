use qlink_proto::{
    ConnectionPhase, DaemonStatus, DataPlaneStatus, NetworkPlanState, NetworkStatus, PathKind,
    PeerStatus, RouteMode,
};
use qlinkctl::{write_support_bundle, SupportBundleOptions, SupportBundleReleaseInfo};
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn support_bundle_contains_expected_redacted_files() {
    let temp = unique_temp_dir("qlinkctl-support-bundle");
    std::fs::create_dir_all(&temp).expect("create temp dir");
    let output = temp.join("qlink-steamos-support.tar.zst");

    write_support_bundle(SupportBundleOptions {
        output: output.clone(),
        status: sensitive_status_fixture(),
        release_info: SupportBundleReleaseInfo {
            product: "QuantumLink SteamOS".to_string(),
            version: "test-build".to_string(),
            platform: "steamos".to_string(),
        },
    })
    .expect("write support bundle");

    let listing = list_archive(&output);
    assert_eq!(
        listing,
        vec![
            "status.json",
            "doctor.txt",
            "network-plan.txt",
            "nftables-plan.txt",
            "release-info.json",
            "redaction-report.json",
        ]
    );

    let unpacked = temp.join("unpacked");
    std::fs::create_dir_all(&unpacked).expect("create unpack dir");
    unpack_archive(&output, &unpacked);

    let forbidden = [
        "PRIVATE_KEY_MATERIAL",
        "wallet seed phrase",
        "entitlement_token=secret",
        "203.0.113.10:4242",
        "raw_packet_payload",
    ];
    for entry in &listing {
        let body = std::fs::read_to_string(unpacked.join(entry)).expect("read bundle entry");
        for secret in forbidden {
            assert!(
                !body.contains(secret),
                "{entry} leaked forbidden value {secret}: {body}"
            );
        }
    }

    let status_json =
        std::fs::read_to_string(unpacked.join("status.json")).expect("read status.json");
    assert!(status_json.contains("[REDACTED-ENDPOINT]"));
    assert!(status_json.contains("[REDACTED-SECRET]"));

    let report = std::fs::read_to_string(unpacked.join("redaction-report.json"))
        .expect("read redaction report");
    assert!(report.contains("\"privateKeyMaterial\""));
    assert!(report.contains("\"walletSeedMaterial\""));
    assert!(report.contains("\"entitlementTokens\""));
    assert!(report.contains("\"exactPeerEndpoints\""));
    assert!(report.contains("\"rawPacketPayloads\""));
}

fn sensitive_status_fixture() -> DaemonStatus {
    DaemonStatus {
        phase: ConnectionPhase::Connected,
        active_party: Some("squad".to_string()),
        peers: vec![PeerStatus {
            peer_id: "peer-PRIVATE_KEY_MATERIAL-203.0.113.10:4242".to_string(),
            alias: "teammate wallet seed phrase".to_string(),
            path: PathKind::Direct,
            median_rtt_ms: Some(21),
            jitter_ms: Some(4),
            packet_loss_percent: Some(0.2),
            nat_type: Some("endpoint 203.0.113.10:4242".to_string()),
            relay_privacy: false,
        }],
        kill_switch: true,
        network: NetworkStatus {
            state: NetworkPlanState::Planned,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run: true,
            ownership_record_present: false,
            commands: vec!["peer connect 203.0.113.10:4242 entitlement_token=secret".to_string()],
            nftables_rules: vec!["drop raw_packet_payload bytes".to_string()],
            error: Some("PRIVATE_KEY_MATERIAL should not leave diagnostics".to_string()),
        },
        data_plane: DataPlaneStatus::not_started(),
    }
}

fn list_archive(output: &Path) -> Vec<String> {
    let shell = Command::new("sh")
        .arg("-c")
        .arg("zstd -dc \"$BUNDLE\" | tar -tf -")
        .env("BUNDLE", output)
        .output()
        .expect("list support bundle archive");
    assert!(
        shell.status.success(),
        "archive list failed: {}",
        String::from_utf8_lossy(&shell.stderr)
    );
    String::from_utf8(shell.stdout)
        .expect("listing is utf8")
        .lines()
        .map(str::to_string)
        .collect()
}

fn unpack_archive(output: &Path, destination: &Path) {
    let shell = Command::new("sh")
        .arg("-c")
        .arg("zstd -dc \"$BUNDLE\" | tar -xf - -C \"$DESTINATION\"")
        .env("BUNDLE", output)
        .env("DESTINATION", destination)
        .output()
        .expect("unpack support bundle archive");
    assert!(
        shell.status.success(),
        "archive unpack failed: {}",
        String::from_utf8_lossy(&shell.stderr)
    );
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos()
    ))
}
