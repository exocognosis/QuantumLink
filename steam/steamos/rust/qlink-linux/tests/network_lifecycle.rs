use qlink_linux::{
    LinuxNetworkPlan, LinuxRuntimePlan, NetworkApplyError, NetworkExecutor, NetworkOperation,
    NftablesExecutor, NftablesOperation, OwnedRuntimePlanStore,
};
use qlink_proto::{DaemonConfig, RouteMode};
use std::cell::RefCell;
use std::rc::Rc;

#[test]
fn network_lifecycle_full_tunnel_fails_closed_without_explicit_underlay_exemptions() {
    let config = DaemonConfig {
        route_mode: RouteMode::FullTunnel,
        rendezvous_servers: vec!["rendezvous.quantumlink.example:443".to_string()],
        relay_servers: vec!["relay.quantumlink.example:443".to_string()],
        ..DaemonConfig::default()
    };

    let error = LinuxRuntimePlan::from_config(&config).unwrap_err();

    assert_eq!(
        error.to_string(),
        "full tunnel requires explicit underlay exemptions before activation"
    );
}

#[test]
fn network_lifecycle_full_tunnel_bypasses_explicit_underlay_before_mark_and_drop() {
    let config = DaemonConfig {
        route_mode: RouteMode::FullTunnel,
        underlay_exemptions: vec!["203.0.113.10/32".to_string(), "198.51.100.0/24".to_string()],
        rendezvous_servers: vec!["203.0.113.10:9471".to_string()],
        relay_servers: vec!["198.51.100.15:9472".to_string()],
        ..DaemonConfig::default()
    };

    let plan = LinuxRuntimePlan::from_config(&config).expect("full tunnel plan");

    assert_eq!(plan.protected_cidr(), "0.0.0.0/0");
    assert_eq!(
        plan.nftables.rules,
        vec![
            "add table inet qlink",
            "add chain inet qlink route_output { type route hook output priority 0; policy accept; }",
            "add chain inet qlink filter_output { type filter hook output priority 0; policy accept; }",
            "add rule inet qlink route_output ip daddr 203.0.113.10/32 return",
            "add rule inet qlink route_output ip daddr 198.51.100.0/24 return",
            "add rule inet qlink route_output ip daddr 0.0.0.0/0 meta mark set 0x514c",
            "add rule inet qlink filter_output ip daddr 203.0.113.10/32 return",
            "add rule inet qlink filter_output ip daddr 198.51.100.0/24 return",
            "add rule inet qlink filter_output ip daddr 0.0.0.0/0 oifname != \"qlink0\" drop",
        ]
    );
}

#[test]
fn network_lifecycle_nftables_failure_after_route_setup_rolls_back_tun_rule_and_route() {
    let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut network = RecordingNetworkExecutor::new(events.clone());
    let mut nftables = RecordingNftablesExecutor::new(events.clone()).fail_on_apply(2);

    let error = plan
        .apply_with_rollback(&mut network, &mut nftables)
        .unwrap_err();

    assert!(error
        .message()
        .contains("runtime apply failed: nftables apply failed"));
    assert_eq!(
        events.borrow().as_slice(),
        &[
            "network:ip tuntap add dev qlink0 mode tun",
            "network:ip addr add 100.64.10.2/32 dev qlink0",
            "network:ip link set dev qlink0 mtu 1280 up",
            "network:ip rule add fwmark 0x514c table 51820",
            "network:ip route add 100.64.0.0/10 dev qlink0 table 51820",
            "nftables:add table inet qlink",
            "nftables:add chain inet qlink route_output { type route hook output priority 0; policy accept; }",
            "nftables:delete table inet qlink",
            "network:ip route del 100.64.0.0/10 dev qlink0 table 51820",
            "network:ip rule del fwmark 0x514c table 51820",
            "network:ip link delete dev qlink0",
        ]
    );
}

#[test]
fn network_lifecycle_route_failure_after_tun_creation_deletes_created_tun() {
    let plan = LinuxRuntimePlan {
        network: LinuxNetworkPlan::from_operations(vec![
            NetworkOperation::CreateTun {
                name: "qlink0".to_string(),
            },
            NetworkOperation::AddRoute {
                cidr: "100.64.0.0/10".to_string(),
                interface: "qlink0".to_string(),
                table: 51820,
            },
        ]),
        nftables: qlink_linux::NftablesPlan::from_operations(Vec::new()),
        protected_cidr: "100.64.0.0/10".to_string(),
        game_udp_ports: Vec::new(),
    };
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut network = RecordingNetworkExecutor::new(events.clone()).fail_on_apply(2);
    let mut nftables = RecordingNftablesExecutor::new(events.clone());

    let error = plan
        .apply_with_rollback(&mut network, &mut nftables)
        .unwrap_err();

    assert!(error.message().contains("network apply failed at 2"));
    assert_eq!(
        events.borrow().as_slice(),
        &[
            "network:ip tuntap add dev qlink0 mode tun",
            "network:ip route add 100.64.0.0/10 dev qlink0 table 51820",
            "network:ip link delete dev qlink0",
        ]
    );
}

#[test]
fn network_lifecycle_owned_runtime_record_survives_daemon_crash_and_deactivation_removes_owned_state(
) {
    let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
    let store = OwnedRuntimePlanStore::from_plan(plan.clone());
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut network = RecordingNetworkExecutor::new(events.clone());
    let mut nftables = RecordingNftablesExecutor::new(events.clone());

    store
        .deactivate_owned(&mut network, &mut nftables)
        .expect("owned deactivate should succeed");

    assert!(!store.has_record());
    assert_eq!(
        events.borrow().as_slice(),
        &[
            "nftables:delete table inet qlink",
            "network:ip route del 100.64.0.0/10 dev qlink0 table 51820",
            "network:ip rule del fwmark 0x514c table 51820",
            "network:ip link delete dev qlink0",
        ]
    );
}

#[test]
fn network_lifecycle_owned_deactivation_failure_leaves_record_for_retry() {
    let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
    let store = OwnedRuntimePlanStore::from_plan(plan);
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut network = RecordingNetworkExecutor::new(events.clone()).fail_on_revert(2);
    let mut nftables = RecordingNftablesExecutor::new(events.clone());

    let error = store
        .deactivate_owned(&mut network, &mut nftables)
        .unwrap_err();

    assert!(error.message().contains("runtime deactivate failed"));
    assert!(store.has_record());
}

#[test]
fn network_lifecycle_destdir_installer_test_remains_staged_and_non_mutating() {
    let installer = include_str!("../../../scripts/install-steamos.sh");
    let installer_test = include_str!("../../../tests/install-steamos-test.sh");

    assert!(
        installer.contains("if command -v systemctl >/dev/null 2>&1 && [ -z \"$DESTDIR\" ]; then")
    );
    assert!(installer.contains(
        "Skipping systemctl daemon-reload because systemctl is unavailable or DESTDIR is set"
    ));
    assert!(installer_test.contains("DESTDIR=\"$TMP_ROOT/destdir\""));
    assert!(installer_test.contains("DESTDIR resolves to the live root"));
    assert!(
        installer_test.contains("expected live non-root install without DESTDIR to be rejected")
    );
}

type SharedEvents = Rc<RefCell<Vec<String>>>;

struct RecordingNetworkExecutor {
    events: SharedEvents,
    applied: usize,
    reverted: usize,
    fail_apply_on: Option<usize>,
    fail_revert_on: Option<usize>,
}

impl RecordingNetworkExecutor {
    fn new(events: SharedEvents) -> Self {
        Self {
            events,
            applied: 0,
            reverted: 0,
            fail_apply_on: None,
            fail_revert_on: None,
        }
    }

    fn fail_on_apply(mut self, operation_index: usize) -> Self {
        self.fail_apply_on = Some(operation_index);
        self
    }

    fn fail_on_revert(mut self, operation_index: usize) -> Self {
        self.fail_revert_on = Some(operation_index);
        self
    }
}

impl NetworkExecutor for RecordingNetworkExecutor {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
        if matches!(
            operation,
            NetworkOperation::RemoveRoute { .. }
                | NetworkOperation::RemoveRule { .. }
                | NetworkOperation::DeleteTun { .. }
        ) {
            self.reverted += 1;
            self.events
                .borrow_mut()
                .push(format!("network:{}", operation.to_command()));
            if self.fail_revert_on == Some(self.reverted) {
                return Err(NetworkApplyError::new(format!(
                    "network revert failed at {}",
                    self.reverted
                )));
            }
        } else {
            self.applied += 1;
            self.events
                .borrow_mut()
                .push(format!("network:{}", operation.to_command()));
            if self.fail_apply_on == Some(self.applied) {
                return Err(NetworkApplyError::new(format!(
                    "network apply failed at {}",
                    self.applied
                )));
            }
        }
        Ok(())
    }
}

struct RecordingNftablesExecutor {
    events: SharedEvents,
    applied: usize,
    reverted: usize,
    fail_apply_on: Option<usize>,
}

impl RecordingNftablesExecutor {
    fn new(events: SharedEvents) -> Self {
        Self {
            events,
            applied: 0,
            reverted: 0,
            fail_apply_on: None,
        }
    }

    fn fail_on_apply(mut self, operation_index: usize) -> Self {
        self.fail_apply_on = Some(operation_index);
        self
    }
}

impl NftablesExecutor for RecordingNftablesExecutor {
    fn apply_nftables(&mut self, operation: &NftablesOperation) -> Result<(), NetworkApplyError> {
        if matches!(operation, NftablesOperation::DeleteTable { .. }) {
            self.reverted += 1;
            self.events
                .borrow_mut()
                .push(format!("nftables:{}", operation.to_rule()));
        } else {
            self.applied += 1;
            self.events
                .borrow_mut()
                .push(format!("nftables:{}", operation.to_rule()));
            if self.fail_apply_on == Some(self.applied) {
                return Err(NetworkApplyError::new(format!(
                    "nftables apply failed at {}",
                    self.applied
                )));
            }
        }
        Ok(())
    }
}
