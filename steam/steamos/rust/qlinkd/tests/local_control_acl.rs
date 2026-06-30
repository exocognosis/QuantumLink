use qlinkd::{
    local_control_command_policy, local_control_socket_acl, ControlPolicy, DaemonPaths,
    LOCAL_CONTROL_GROUP, LOCAL_CONTROL_SOCKET_MODE, LOCAL_CONTROL_SOCKET_OWNER_UID,
};

#[test]
fn local_control_acl_matches_steamos_service_contract() {
    let acl = local_control_socket_acl();
    let paths = DaemonPaths::default();

    assert_eq!(
        paths.socket.display().to_string(),
        "/run/quantumlink/qlinkd.sock"
    );
    assert_eq!(acl.path, paths.socket);
    assert_eq!(acl.owner_uid, LOCAL_CONTROL_SOCKET_OWNER_UID);
    assert_eq!(acl.owner_uid, 0);
    assert_eq!(acl.group_name, LOCAL_CONTROL_GROUP);
    assert_eq!(acl.group_name, "quantumlink");
    assert_eq!(acl.mode, LOCAL_CONTROL_SOCKET_MODE);
    assert_eq!(acl.mode, 0o660);
}

#[test]
fn local_control_acl_is_declared_in_systemd_unit() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let unit = std::fs::read_to_string(format!(
        "{manifest_dir}/../../packaging/systemd/qlinkd.service"
    ))
    .expect("read qlinkd systemd unit");

    assert!(unit.contains("RuntimeDirectory=quantumlink"));
    assert!(unit.contains("RuntimeDirectoryMode=0750"));
    assert!(unit.contains("Group=quantumlink"));
    assert!(unit.contains("UMask=0007"));
}

#[test]
fn local_control_acl_group_members_can_only_read_status_diagnostics() {
    assert_eq!(
        local_control_command_policy("status"),
        ControlPolicy::QuantumlinkGroup
    );
    assert_eq!(
        local_control_command_policy(r#"{"type":"status"}"#),
        ControlPolicy::QuantumlinkGroup
    );
    assert_eq!(
        local_control_command_policy("doctor"),
        ControlPolicy::QuantumlinkGroup
    );

    assert_eq!(
        local_control_command_policy("--activate-network"),
        ControlPolicy::ElevatedOnly
    );
    assert_eq!(
        local_control_command_policy("activate-network"),
        ControlPolicy::ElevatedOnly
    );
    assert_eq!(
        local_control_command_policy("revoke-peer peer_1"),
        ControlPolicy::ElevatedOnly
    );
}
