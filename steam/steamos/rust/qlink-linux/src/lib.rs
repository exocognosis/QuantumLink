use std::{error::Error, fmt};

use qlink_proto::{ConfigValidationError, DaemonConfig, RouteMode};

const DEFAULT_MTU: u16 = 1280;
const QLINK_FWMARK: u32 = 0x514c;
const QLINK_ROUTE_TABLE: u32 = 51820;
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "qlink";
const NFT_OUTPUT_HOOK: &str = "output";
const NFT_ROUTE_OUTPUT_CHAIN: &str = "route_output";
const NFT_FILTER_OUTPUT_CHAIN: &str = "filter_output";
const FULL_TUNNEL_CIDR: &str = "0.0.0.0/0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxRuntimePlan {
    pub network: LinuxNetworkPlan,
    pub nftables: NftablesPlan,
    pub protected_cidr: String,
}

impl LinuxRuntimePlan {
    pub fn from_config(config: &DaemonConfig) -> Result<Self, NetworkPlanError> {
        config.validate().map_err(NetworkPlanError::InvalidConfig)?;

        let protected_cidr = protected_cidr_for_route_mode(config).to_string();
        let overlay_address = format!("{}/32", config.overlay_ipv4_address);

        Ok(Self {
            network: LinuxNetworkPlan::for_interface(
                &config.interface_name,
                &overlay_address,
                &protected_cidr,
            ),
            nftables: NftablesPlan::fail_closed(&config.interface_name, &protected_cidr),
            protected_cidr,
        })
    }

    pub fn protected_cidr(&self) -> &str {
        &self.protected_cidr
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPlanError {
    InvalidConfig(ConfigValidationError),
}

impl fmt::Display for NetworkPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid daemon config: {error}"),
        }
    }
}

impl Error for NetworkPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error),
        }
    }
}

fn protected_cidr_for_route_mode(config: &DaemonConfig) -> &str {
    match config.route_mode {
        RouteMode::GameOnly | RouteMode::ProtectedPrefixesOnly => &config.overlay_cidr,
        RouteMode::FullTunnel => FULL_TUNNEL_CIDR,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkOperation {
    CreateTun {
        name: String,
    },
    AddAddress {
        interface: String,
        address: String,
    },
    SetLinkUp {
        interface: String,
        mtu: u16,
    },
    AddRule {
        fwmark: u32,
        table: u32,
    },
    AddRoute {
        cidr: String,
        interface: String,
        table: u32,
    },
}

impl NetworkOperation {
    pub fn to_command(&self) -> String {
        match self {
            Self::CreateTun { name } => format!("ip tuntap add dev {name} mode tun"),
            Self::AddAddress { interface, address } => {
                format!("ip addr add {address} dev {interface}")
            }
            Self::SetLinkUp { interface, mtu } => {
                format!("ip link set dev {interface} mtu {mtu} up")
            }
            Self::AddRule { fwmark, table } => {
                format!("ip rule add fwmark {} table {table}", format_mark(*fwmark))
            }
            Self::AddRoute {
                cidr,
                interface,
                table,
            } => format!("ip route add {cidr} dev {interface} table {table}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxNetworkPlan {
    pub operations: Vec<NetworkOperation>,
    pub commands: Vec<String>,
}

impl LinuxNetworkPlan {
    pub fn for_interface(name: &str, overlay_address: &str, protected_cidr: &str) -> Self {
        Self::from_operations(vec![
            NetworkOperation::CreateTun {
                name: name.to_string(),
            },
            NetworkOperation::AddAddress {
                interface: name.to_string(),
                address: overlay_address.to_string(),
            },
            NetworkOperation::SetLinkUp {
                interface: name.to_string(),
                mtu: DEFAULT_MTU,
            },
            NetworkOperation::AddRule {
                fwmark: QLINK_FWMARK,
                table: QLINK_ROUTE_TABLE,
            },
            NetworkOperation::AddRoute {
                cidr: protected_cidr.to_string(),
                interface: name.to_string(),
                table: QLINK_ROUTE_TABLE,
            },
        ])
    }

    pub fn from_operations(operations: Vec<NetworkOperation>) -> Self {
        let commands = operations
            .iter()
            .map(NetworkOperation::to_command)
            .collect();
        Self {
            operations,
            commands,
        }
    }

    pub fn apply<E: NetworkExecutor>(&self, executor: &mut E) -> Result<(), NetworkApplyError> {
        for operation in &self.operations {
            executor.apply(operation)?;
        }
        Ok(())
    }
}

pub trait NetworkExecutor {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkApplyError {
    message: String,
}

impl NetworkApplyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NetworkApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for NetworkApplyError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DryRunExecutor {
    recorded_commands: Vec<String>,
}

impl DryRunExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recorded_commands(&self) -> &[String] {
        &self.recorded_commands
    }

    pub fn recorded_operations(&self) -> &[String] {
        &self.recorded_commands
    }

    pub fn into_recorded_commands(self) -> Vec<String> {
        self.recorded_commands
    }
}

impl NetworkExecutor for DryRunExecutor {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
        self.recorded_commands.push(operation.to_command());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NftablesOperation {
    AddTable {
        family: String,
        table: String,
    },
    AddChain {
        family: String,
        table: String,
        chain: String,
        chain_type: String,
        hook: String,
        priority: i32,
        policy: String,
    },
    MarkTraffic {
        family: String,
        table: String,
        chain: String,
        cidr: String,
        mark: u32,
    },
    DropOutsideInterface {
        family: String,
        table: String,
        chain: String,
        cidr: String,
        interface: String,
    },
}

impl NftablesOperation {
    pub fn to_rule(&self) -> String {
        match self {
            Self::AddTable { family, table } => format!("add table {family} {table}"),
            Self::AddChain {
                family,
                table,
                chain,
                chain_type,
                hook,
                priority,
                policy,
            } => format!(
                "add chain {family} {table} {chain} {{ type {chain_type} hook {hook} priority {priority}; policy {policy}; }}"
            ),
            Self::MarkTraffic {
                family,
                table,
                chain,
                cidr,
                mark,
            } => format!(
                "add rule {family} {table} {chain} ip daddr {cidr} meta mark set {}",
                format_mark(*mark)
            ),
            Self::DropOutsideInterface {
                family,
                table,
                chain,
                cidr,
                interface,
            } => format!(
                "add rule {family} {table} {chain} ip daddr {cidr} oifname != \"{interface}\" drop"
            ),
        }
    }
}

pub trait NftablesExecutor {
    fn apply_nftables(&mut self, operation: &NftablesOperation) -> Result<(), NetworkApplyError>;
}

impl NftablesExecutor for DryRunExecutor {
    fn apply_nftables(&mut self, operation: &NftablesOperation) -> Result<(), NetworkApplyError> {
        self.recorded_commands.push(operation.to_rule());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftablesPlan {
    pub operations: Vec<NftablesOperation>,
    pub rules: Vec<String>,
}

impl NftablesPlan {
    pub fn fail_closed(interface_name: &str, protected_cidr: &str) -> Self {
        Self::from_operations(vec![
            NftablesOperation::AddTable {
                family: NFT_FAMILY.to_string(),
                table: NFT_TABLE.to_string(),
            },
            NftablesOperation::AddChain {
                family: NFT_FAMILY.to_string(),
                table: NFT_TABLE.to_string(),
                chain: NFT_ROUTE_OUTPUT_CHAIN.to_string(),
                chain_type: "route".to_string(),
                hook: NFT_OUTPUT_HOOK.to_string(),
                priority: 0,
                policy: "accept".to_string(),
            },
            NftablesOperation::AddChain {
                family: NFT_FAMILY.to_string(),
                table: NFT_TABLE.to_string(),
                chain: NFT_FILTER_OUTPUT_CHAIN.to_string(),
                chain_type: "filter".to_string(),
                hook: NFT_OUTPUT_HOOK.to_string(),
                priority: 0,
                policy: "accept".to_string(),
            },
            NftablesOperation::MarkTraffic {
                family: NFT_FAMILY.to_string(),
                table: NFT_TABLE.to_string(),
                chain: NFT_ROUTE_OUTPUT_CHAIN.to_string(),
                cidr: protected_cidr.to_string(),
                mark: QLINK_FWMARK,
            },
            NftablesOperation::DropOutsideInterface {
                family: NFT_FAMILY.to_string(),
                table: NFT_TABLE.to_string(),
                chain: NFT_FILTER_OUTPUT_CHAIN.to_string(),
                cidr: protected_cidr.to_string(),
                interface: interface_name.to_string(),
            },
        ])
    }

    pub fn from_operations(operations: Vec<NftablesOperation>) -> Self {
        let rules = operations.iter().map(NftablesOperation::to_rule).collect();
        Self { operations, rules }
    }

    pub fn apply<E: NftablesExecutor>(&self, executor: &mut E) -> Result<(), NetworkApplyError> {
        for operation in &self.operations {
            executor.apply_nftables(operation)?;
        }
        Ok(())
    }
}

fn format_mark(mark: u32) -> String {
    format!("0x{mark:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlink_proto::{DaemonConfig, RouteMode};

    #[test]
    fn runtime_plan_from_default_config_routes_overlay_cidr() {
        let config = DaemonConfig::default();

        let plan = LinuxRuntimePlan::from_config(&config).expect("default config should plan");

        assert_eq!(plan.protected_cidr, "100.64.0.0/10");
        assert_eq!(
            plan.network.commands,
            vec![
                "ip tuntap add dev qlink0 mode tun",
                "ip addr add 100.64.10.2/32 dev qlink0",
                "ip link set dev qlink0 mtu 1280 up",
                "ip rule add fwmark 0x514c table 51820",
                "ip route add 100.64.0.0/10 dev qlink0 table 51820",
            ]
        );
        assert!(plan
            .nftables
            .rules
            .iter()
            .any(|rule| rule.contains("ip daddr 100.64.0.0/10")));
    }

    #[test]
    fn runtime_plan_full_tunnel_routes_default_ipv4_cidr() {
        let config = DaemonConfig {
            route_mode: RouteMode::FullTunnel,
            ..DaemonConfig::default()
        };

        let plan = LinuxRuntimePlan::from_config(&config).expect("full tunnel config should plan");

        assert_eq!(plan.protected_cidr, "0.0.0.0/0");
        assert!(plan
            .network
            .commands
            .iter()
            .any(|command| command == "ip route add 0.0.0.0/0 dev qlink0 table 51820"));
        assert!(plan
            .nftables
            .rules
            .iter()
            .any(|rule| rule.contains("ip daddr 0.0.0.0/0")));
    }

    #[test]
    fn runtime_plan_protected_prefixes_only_routes_overlay_cidr() {
        let config = DaemonConfig {
            route_mode: RouteMode::ProtectedPrefixesOnly,
            ..DaemonConfig::default()
        };

        let plan = LinuxRuntimePlan::from_config(&config)
            .expect("protected-prefixes-only config should plan");

        assert_eq!(plan.protected_cidr, "100.64.0.0/10");
        assert!(plan
            .network
            .commands
            .iter()
            .any(|command| command == "ip route add 100.64.0.0/10 dev qlink0 table 51820"));
        assert!(plan
            .nftables
            .rules
            .iter()
            .any(|rule| rule.contains("ip daddr 100.64.0.0/10")));
    }

    #[test]
    fn runtime_plan_rejects_invalid_config_before_building_plan() {
        let config = DaemonConfig {
            interface_name: String::new(),
            ..DaemonConfig::default()
        };

        let error = LinuxRuntimePlan::from_config(&config).unwrap_err();

        assert!(matches!(error, NetworkPlanError::InvalidConfig(_)));
        assert!(error.to_string().contains("invalid interfaceName"));
    }

    #[test]
    fn routing_plan_uses_dedicated_table_and_mark() {
        let plan = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");

        assert!(plan
            .commands
            .iter()
            .any(|cmd| cmd == "ip tuntap add dev qlink0 mode tun"));
        assert!(plan
            .commands
            .iter()
            .any(|cmd| cmd == "ip rule add fwmark 0x514c table 51820"));
        assert!(plan
            .commands
            .iter()
            .any(|cmd| cmd == "ip route add 100.64.0.0/10 dev qlink0 table 51820"));
    }

    #[test]
    fn routing_plan_preserves_exact_command_order() {
        let plan = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");

        assert_eq!(
            plan.commands,
            vec![
                "ip tuntap add dev qlink0 mode tun",
                "ip addr add 100.64.10.2/32 dev qlink0",
                "ip link set dev qlink0 mtu 1280 up",
                "ip rule add fwmark 0x514c table 51820",
                "ip route add 100.64.0.0/10 dev qlink0 table 51820",
            ]
        );
    }

    #[test]
    fn nftables_plan_fails_closed_for_protected_cidr() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");

        assert!(plan
            .rules
            .iter()
            .any(|rule| rule.contains("table inet qlink")));
        assert!(plan
            .rules
            .iter()
            .any(|rule| rule.contains("ip daddr 100.64.0.0/10")));
        assert!(plan
            .rules
            .iter()
            .any(|rule| rule.contains("oifname != \"qlink0\" drop")));
    }

    #[test]
    fn nftables_plan_marks_in_route_chain_and_drops_in_filter_chain() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");

        assert!(plan.rules.iter().any(|rule| {
            rule == "add chain inet qlink route_output { type route hook output priority 0; policy accept; }"
        }));
        assert!(plan.rules.iter().any(|rule| {
            rule == "add rule inet qlink route_output ip daddr 100.64.0.0/10 meta mark set 0x514c"
        }));
        assert!(plan.rules.iter().any(|rule| {
            rule == "add chain inet qlink filter_output { type filter hook output priority 0; policy accept; }"
        }));
        assert!(plan.rules.iter().any(|rule| {
            rule == "add rule inet qlink filter_output ip daddr 100.64.0.0/10 oifname != \"qlink0\" drop"
        }));
    }

    #[test]
    fn nftables_plan_preserves_exact_rule_order() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");

        assert_eq!(
            plan.rules,
            vec![
                "add table inet qlink",
                "add chain inet qlink route_output { type route hook output priority 0; policy accept; }",
                "add chain inet qlink filter_output { type filter hook output priority 0; policy accept; }",
                "add rule inet qlink route_output ip daddr 100.64.0.0/10 meta mark set 0x514c",
                "add rule inet qlink filter_output ip daddr 100.64.0.0/10 oifname != \"qlink0\" drop",
            ]
        );
    }

    #[test]
    fn nftables_plan_marks_protected_traffic_for_policy_routing() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");

        assert!(plan.rules.iter().any(|rule| {
            rule.contains("route_output")
                && rule.contains("ip daddr 100.64.0.0/10")
                && rule.contains("meta mark set 0x514c")
        }));
    }

    #[test]
    fn network_plan_exposes_typed_operations() {
        let plan = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");

        assert_eq!(
            plan.operations,
            vec![
                NetworkOperation::CreateTun {
                    name: "qlink0".to_string()
                },
                NetworkOperation::AddAddress {
                    interface: "qlink0".to_string(),
                    address: "100.64.10.2/32".to_string()
                },
                NetworkOperation::SetLinkUp {
                    interface: "qlink0".to_string(),
                    mtu: 1280
                },
                NetworkOperation::AddRule {
                    fwmark: 0x514c,
                    table: 51820
                },
                NetworkOperation::AddRoute {
                    cidr: "100.64.0.0/10".to_string(),
                    interface: "qlink0".to_string(),
                    table: 51820
                },
            ]
        );
    }

    #[test]
    fn network_operations_render_to_compatible_commands() {
        assert_eq!(
            NetworkOperation::CreateTun {
                name: "qlink0".to_string(),
            }
            .to_command(),
            "ip tuntap add dev qlink0 mode tun"
        );
        assert_eq!(
            NetworkOperation::AddAddress {
                interface: "qlink0".to_string(),
                address: "100.64.10.2/32".to_string(),
            }
            .to_command(),
            "ip addr add 100.64.10.2/32 dev qlink0"
        );
        assert_eq!(
            NetworkOperation::SetLinkUp {
                interface: "qlink0".to_string(),
                mtu: 1280,
            }
            .to_command(),
            "ip link set dev qlink0 mtu 1280 up"
        );
        assert_eq!(
            NetworkOperation::AddRule {
                fwmark: 0x514c,
                table: 51820
            }
            .to_command(),
            "ip rule add fwmark 0x514c table 51820"
        );
        assert_eq!(
            NetworkOperation::AddRoute {
                cidr: "100.64.0.0/10".to_string(),
                interface: "qlink0".to_string(),
                table: 51820
            }
            .to_command(),
            "ip route add 100.64.0.0/10 dev qlink0 table 51820"
        );
    }

    #[test]
    fn nftables_plan_exposes_typed_operations() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");

        assert_eq!(
            plan.operations,
            vec![
                NftablesOperation::AddTable {
                    family: "inet".to_string(),
                    table: "qlink".to_string()
                },
                NftablesOperation::AddChain {
                    family: "inet".to_string(),
                    table: "qlink".to_string(),
                    chain: "route_output".to_string(),
                    chain_type: "route".to_string(),
                    hook: "output".to_string(),
                    priority: 0,
                    policy: "accept".to_string()
                },
                NftablesOperation::AddChain {
                    family: "inet".to_string(),
                    table: "qlink".to_string(),
                    chain: "filter_output".to_string(),
                    chain_type: "filter".to_string(),
                    hook: "output".to_string(),
                    priority: 0,
                    policy: "accept".to_string()
                },
                NftablesOperation::MarkTraffic {
                    family: "inet".to_string(),
                    table: "qlink".to_string(),
                    chain: "route_output".to_string(),
                    cidr: "100.64.0.0/10".to_string(),
                    mark: 0x514c
                },
                NftablesOperation::DropOutsideInterface {
                    family: "inet".to_string(),
                    table: "qlink".to_string(),
                    chain: "filter_output".to_string(),
                    cidr: "100.64.0.0/10".to_string(),
                    interface: "qlink0".to_string()
                },
            ]
        );
    }

    #[test]
    fn nftables_operations_render_to_compatible_rules() {
        assert_eq!(
            NftablesOperation::AddTable {
                family: "inet".to_string(),
                table: "qlink".to_string(),
            }
            .to_rule(),
            "add table inet qlink"
        );
        assert_eq!(
            NftablesOperation::AddChain {
                family: "inet".to_string(),
                table: "qlink".to_string(),
                chain: "route_output".to_string(),
                chain_type: "route".to_string(),
                hook: "output".to_string(),
                priority: 0,
                policy: "accept".to_string(),
            }
            .to_rule(),
            "add chain inet qlink route_output { type route hook output priority 0; policy accept; }"
        );
        assert_eq!(
            NftablesOperation::AddChain {
                family: "inet".to_string(),
                table: "qlink".to_string(),
                chain: "filter_output".to_string(),
                chain_type: "filter".to_string(),
                hook: "output".to_string(),
                priority: 0,
                policy: "accept".to_string(),
            }
            .to_rule(),
            "add chain inet qlink filter_output { type filter hook output priority 0; policy accept; }"
        );
        assert_eq!(
            NftablesOperation::MarkTraffic {
                family: "inet".to_string(),
                table: "qlink".to_string(),
                chain: "route_output".to_string(),
                cidr: "100.64.0.0/10".to_string(),
                mark: 0x514c
            }
            .to_rule(),
            "add rule inet qlink route_output ip daddr 100.64.0.0/10 meta mark set 0x514c"
        );
        assert_eq!(
            NftablesOperation::DropOutsideInterface {
                family: "inet".to_string(),
                table: "qlink".to_string(),
                chain: "filter_output".to_string(),
                cidr: "100.64.0.0/10".to_string(),
                interface: "qlink0".to_string()
            }
            .to_rule(),
            "add rule inet qlink filter_output ip daddr 100.64.0.0/10 oifname != \"qlink0\" drop"
        );
    }

    #[test]
    fn dry_run_executor_records_rendered_network_operations() {
        let plan = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");
        let mut executor = DryRunExecutor::default();

        plan.apply(&mut executor)
            .expect("dry-run apply should record");

        assert_eq!(executor.recorded_commands(), plan.commands.as_slice());
    }

    #[test]
    fn dry_run_executor_records_rendered_nftables_operations() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");
        let mut executor = DryRunExecutor::new();

        plan.apply(&mut executor)
            .expect("dry-run apply should record");

        assert_eq!(executor.recorded_operations(), plan.rules.as_slice());
    }

    #[test]
    fn network_apply_propagates_executor_failures_and_stops() {
        #[derive(Default)]
        struct FailingNetworkExecutor {
            applied: usize,
        }

        impl NetworkExecutor for FailingNetworkExecutor {
            fn apply(&mut self, _operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
                self.applied += 1;
                Err(NetworkApplyError::new("network executor failed"))
            }
        }

        let plan = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");
        let mut executor = FailingNetworkExecutor::default();

        let error = plan.apply(&mut executor).unwrap_err();

        assert_eq!(error.message(), "network executor failed");
        assert_eq!(executor.applied, 1);
    }

    #[test]
    fn nftables_apply_propagates_executor_failures_and_stops() {
        #[derive(Default)]
        struct FailingNftablesExecutor {
            applied: usize,
        }

        impl NftablesExecutor for FailingNftablesExecutor {
            fn apply_nftables(
                &mut self,
                _operation: &NftablesOperation,
            ) -> Result<(), NetworkApplyError> {
                self.applied += 1;
                Err(NetworkApplyError::new("nftables executor failed"))
            }
        }

        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");
        let mut executor = FailingNftablesExecutor::default();

        let error = plan.apply(&mut executor).unwrap_err();

        assert_eq!(error.message(), "nftables executor failed");
        assert_eq!(executor.applied, 1);
    }
}
