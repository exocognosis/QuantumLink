use qlink_core::dytallix_identity::DytallixPolicyStatus;
use qlink_proto::{InviteCode, MeshTrustMode};
use qlinkd::{
    dial_candidates, import_invite, load_peer_store, peer_store_path, revoke_peer,
    validate_peer_dytallix_policy, DaemonPaths, PeerLifecycleError,
};

fn test_paths(temp: &tempfile::TempDir) -> DaemonPaths {
    DaemonPaths {
        config_file: temp.path().join("config.json"),
        state_dir: temp.path().join("state"),
        socket: temp.path().join("qlinkd.sock"),
    }
}

fn invite(expires_at_unix: u64, trust_mode: MeshTrustMode) -> InviteCode {
    InviteCode {
        mesh_id: "mesh-steam-squad".to_string(),
        party_id: "party-nightly".to_string(),
        rendezvous: vec!["203.0.113.10:9471".to_string()],
        relay: vec!["198.51.100.15:9472".to_string()],
        host_peer_id: "peer-host-deck".to_string(),
        host_alias: "Host Deck".to_string(),
        trust_mode,
        trust_source: "invite".to_string(),
        expires_at_unix,
    }
}

#[test]
fn peer_lifecycle_imported_invite_persists_peer_without_raw_endpoint_leakage() {
    let temp = tempfile::tempdir().unwrap();
    let paths = test_paths(&temp);
    let encoded = invite(4_102_444_800, MeshTrustMode::PrivateFriends)
        .encode()
        .unwrap();

    let peer = import_invite(&paths, &encoded, 1_767_139_200).unwrap();

    assert_eq!(peer.peer_id, "peer-host-deck");
    assert_eq!(peer.alias, "Host Deck");
    assert_eq!(peer.mesh_id, "mesh-steam-squad");
    assert_eq!(peer.party_id, "party-nightly");
    assert_eq!(peer.trust_mode, MeshTrustMode::PrivateFriends);
    assert_eq!(peer.trust_source, "invite");
    assert!(!peer.revoked);
    assert_eq!(peer.expires_at_unix, 4_102_444_800);

    let raw_store = std::fs::read_to_string(peer_store_path(&paths)).unwrap();
    assert!(raw_store.contains("peer-host-deck"));
    assert!(!raw_store.contains("203.0.113.10"));
    assert!(!raw_store.contains("198.51.100.15"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(peer_store_path(&paths))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn peer_lifecycle_revoked_peer_is_removed_from_dial_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let paths = test_paths(&temp);
    let encoded = invite(4_102_444_800, MeshTrustMode::PrivateFriends)
        .encode()
        .unwrap();

    import_invite(&paths, &encoded, 1_767_139_200).unwrap();
    assert_eq!(dial_candidates(&paths, 1_767_139_200).unwrap().len(), 1);

    revoke_peer(&paths, "peer-host-deck").unwrap();

    assert!(dial_candidates(&paths, 1_767_139_200).unwrap().is_empty());
    assert!(load_peer_store(&paths)
        .unwrap()
        .peers
        .iter()
        .any(|peer| peer.peer_id == "peer-host-deck" && peer.revoked));
}

#[test]
fn peer_lifecycle_expired_invite_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let paths = test_paths(&temp);
    let encoded = invite(1_767_139_199, MeshTrustMode::PrivateFriends)
        .encode()
        .unwrap();

    let error = import_invite(&paths, &encoded, 1_767_139_200).unwrap_err();

    assert!(matches!(error, PeerLifecycleError::ExpiredInvite { .. }));
    assert!(!peer_store_path(&paths).exists());
}

#[test]
fn peer_lifecycle_private_mesh_warns_when_dytallix_registry_is_unavailable() {
    let temp = tempfile::tempdir().unwrap();
    let paths = test_paths(&temp);
    let encoded = invite(4_102_444_800, MeshTrustMode::PrivateFriends)
        .encode()
        .unwrap();
    let peer = import_invite(&paths, &encoded, 1_767_139_200).unwrap();

    let decision = validate_peer_dytallix_policy(&peer, DytallixPolicyStatus::Unavailable).unwrap();

    assert!(decision.accepted);
    assert!(decision.warning.unwrap().contains("registry unavailable"));
}

#[test]
fn peer_lifecycle_public_mesh_rejects_peer_without_active_dytallix_record() {
    let temp = tempfile::tempdir().unwrap();
    let paths = test_paths(&temp);
    let encoded = invite(4_102_444_800, MeshTrustMode::PublicDytallixRequired)
        .encode()
        .unwrap();
    let peer = import_invite(&paths, &encoded, 1_767_139_200).unwrap();

    let error = validate_peer_dytallix_policy(&peer, DytallixPolicyStatus::Missing).unwrap_err();

    assert!(error.to_string().contains("public mesh"));
    assert!(error.to_string().contains("active Dytallix"));
}
