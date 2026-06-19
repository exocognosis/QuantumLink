use std::{error::Error, fmt, process::Command as ProcessCommand};

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
const IP_COMMAND: &str = "/usr/bin/ip";
const NFT_COMMAND: &str = "/usr/bin/nft";

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

    pub fn apply_with_rollback<N, T>(
        &self,
        network_executor: &mut N,
        nftables_executor: &mut T,
    ) -> Result<(), NetworkApplyError>
    where
        N: NetworkExecutor,
        T: NftablesExecutor,
    {
        let mut completed_network = Vec::new();
        let mut completed_nftables = Vec::new();

        for operation in &self.network.operations {
            if let Err(error) = network_executor.apply(operation) {
                return Err(self.rollback_error(
                    format!("network apply failed: {error}"),
                    &completed_network,
                    &completed_nftables,
                    network_executor,
                    nftables_executor,
                ));
            }
            completed_network.push(operation.clone());
        }

        for operation in &self.nftables.operations {
            if let Err(error) = nftables_executor.apply_nftables(operation) {
                return Err(self.rollback_error(
                    format!("nftables apply failed: {error}"),
                    &completed_network,
                    &completed_nftables,
                    network_executor,
                    nftables_executor,
                ));
            }
            completed_nftables.push(operation.clone());
        }

        Ok(())
    }

    pub fn deactivate<N, T>(
        &self,
        network_executor: &mut N,
        nftables_executor: &mut T,
    ) -> Result<(), NetworkApplyError>
    where
        N: NetworkExecutor,
        T: NftablesExecutor,
    {
        let mut errors = Vec::new();

        if let Err(error) =
            NftablesPlan::revert_operations_with(nftables_executor, &self.nftables.operations)
        {
            errors.push(error.to_string());
        }

        if let Err(error) =
            LinuxNetworkPlan::revert_operations_with(network_executor, &self.network.operations)
        {
            errors.push(error.to_string());
        }

        if !errors.is_empty() {
            return Err(NetworkApplyError::new(format!(
                "runtime deactivate failed: {}",
                errors.join("; ")
            )));
        }

        Ok(())
    }

    fn rollback_error<N, T>(
        &self,
        original: String,
        completed_network: &[NetworkOperation],
        completed_nftables: &[NftablesOperation],
        network_executor: &mut N,
        nftables_executor: &mut T,
    ) -> NetworkApplyError
    where
        N: NetworkExecutor,
        T: NftablesExecutor,
    {
        let mut message = format!("runtime apply failed: {original}");

        if let Err(error) =
            NftablesPlan::revert_operations_with(nftables_executor, completed_nftables)
        {
            message.push_str(&format!("; rollback nftables revert failed: {error}"));
        }

        if let Err(error) =
            LinuxNetworkPlan::revert_operations_with(network_executor, completed_network)
        {
            message.push_str(&format!("; rollback network revert failed: {error}"));
        }

        NetworkApplyError::new(message)
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
pub struct SystemCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl SystemCommand {
    pub fn new<I, S>(program: impl Into<String>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn rendered(&self) -> String {
        format!("{:?} {:?}", self.program, self.args)
    }
}

pub trait CommandRunner {
    fn run(&mut self, command: &SystemCommand) -> Result<(), NetworkApplyError>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StdCommandRunner;

impl CommandRunner for StdCommandRunner {
    fn run(&mut self, command: &SystemCommand) -> Result<(), NetworkApplyError> {
        let output = ProcessCommand::new(&command.program)
            .args(&command.args)
            .output()
            .map_err(|error| {
                NetworkApplyError::new(format!("failed to spawn `{}`: {error}", command.rendered()))
            })?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.trim().is_empty() {
            format!(": stderr: {}", stderr.trim())
        } else if !stdout.trim().is_empty() {
            format!(": stdout: {}", stdout.trim())
        } else {
            String::new()
        };

        Err(NetworkApplyError::new(format!(
            "command `{}` exited with status {}{detail}",
            command.rendered(),
            output.status
        )))
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
    RemoveRoute {
        cidr: String,
        interface: String,
        table: u32,
    },
    RemoveRule {
        fwmark: u32,
        table: u32,
    },
    DeleteTun {
        name: String,
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
            Self::RemoveRoute {
                cidr,
                interface,
                table,
            } => format!("ip route del {cidr} dev {interface} table {table}"),
            Self::RemoveRule { fwmark, table } => {
                format!("ip rule del fwmark {} table {table}", format_mark(*fwmark))
            }
            Self::DeleteTun { name } => format!("ip link delete dev {name}"),
        }
    }

    pub fn to_system_command(&self) -> SystemCommand {
        match self {
            Self::CreateTun { name } => SystemCommand::new(
                IP_COMMAND,
                vec![
                    "tuntap".to_string(),
                    "add".to_string(),
                    "dev".to_string(),
                    name.clone(),
                    "mode".to_string(),
                    "tun".to_string(),
                ],
            ),
            Self::AddAddress { interface, address } => SystemCommand::new(
                IP_COMMAND,
                vec![
                    "addr".to_string(),
                    "add".to_string(),
                    address.clone(),
                    "dev".to_string(),
                    interface.clone(),
                ],
            ),
            Self::SetLinkUp { interface, mtu } => SystemCommand::new(
                IP_COMMAND,
                vec![
                    "link".to_string(),
                    "set".to_string(),
                    "dev".to_string(),
                    interface.clone(),
                    "mtu".to_string(),
                    mtu.to_string(),
                    "up".to_string(),
                ],
            ),
            Self::AddRule { fwmark, table } => SystemCommand::new(
                IP_COMMAND,
                vec![
                    "rule".to_string(),
                    "add".to_string(),
                    "fwmark".to_string(),
                    format_mark(*fwmark),
                    "table".to_string(),
                    table.to_string(),
                ],
            ),
            Self::AddRoute {
                cidr,
                interface,
                table,
            } => SystemCommand::new(
                IP_COMMAND,
                vec![
                    "route".to_string(),
                    "add".to_string(),
                    cidr.clone(),
                    "dev".to_string(),
                    interface.clone(),
                    "table".to_string(),
                    table.to_string(),
                ],
            ),
            Self::RemoveRoute {
                cidr,
                interface,
                table,
            } => SystemCommand::new(
                IP_COMMAND,
                vec![
                    "route".to_string(),
                    "del".to_string(),
                    cidr.clone(),
                    "dev".to_string(),
                    interface.clone(),
                    "table".to_string(),
                    table.to_string(),
                ],
            ),
            Self::RemoveRule { fwmark, table } => SystemCommand::new(
                IP_COMMAND,
                vec![
                    "rule".to_string(),
                    "del".to_string(),
                    "fwmark".to_string(),
                    format_mark(*fwmark),
                    "table".to_string(),
                    table.to_string(),
                ],
            ),
            Self::DeleteTun { name } => SystemCommand::new(
                IP_COMMAND,
                vec![
                    "link".to_string(),
                    "delete".to_string(),
                    "dev".to_string(),
                    name.clone(),
                ],
            ),
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

    pub fn revert_operations(&self) -> Vec<NetworkOperation> {
        Self::revert_operations_for(&self.operations)
    }

    fn revert_operations_for(operations: &[NetworkOperation]) -> Vec<NetworkOperation> {
        operations
            .iter()
            .rev()
            .filter_map(|operation| match operation {
                NetworkOperation::AddRoute {
                    cidr,
                    interface,
                    table,
                } => Some(NetworkOperation::RemoveRoute {
                    cidr: cidr.clone(),
                    interface: interface.clone(),
                    table: *table,
                }),
                NetworkOperation::AddRule { fwmark, table } => Some(NetworkOperation::RemoveRule {
                    fwmark: *fwmark,
                    table: *table,
                }),
                NetworkOperation::CreateTun { name } => {
                    Some(NetworkOperation::DeleteTun { name: name.clone() })
                }
                NetworkOperation::AddAddress { .. }
                | NetworkOperation::SetLinkUp { .. }
                | NetworkOperation::RemoveRoute { .. }
                | NetworkOperation::RemoveRule { .. }
                | NetworkOperation::DeleteTun { .. } => None,
            })
            .collect()
    }

    pub fn revert_commands(&self) -> Vec<String> {
        self.revert_operations()
            .iter()
            .map(NetworkOperation::to_command)
            .collect()
    }

    pub fn revert<E: NetworkExecutor>(&self, executor: &mut E) -> Result<(), NetworkApplyError> {
        Self::revert_operations_with(executor, &self.operations)
    }

    fn revert_operations_with<E: NetworkExecutor>(
        executor: &mut E,
        operations: &[NetworkOperation],
    ) -> Result<(), NetworkApplyError> {
        let mut errors = Vec::new();

        for operation in Self::revert_operations_for(operations) {
            if let Err(error) = executor.revert(&operation) {
                errors.push(error.to_string());
            }
        }

        if !errors.is_empty() {
            return Err(NetworkApplyError::new(errors.join("; ")));
        }

        Ok(())
    }
}

pub trait NetworkExecutor {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError>;

    fn revert(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
        self.apply(operation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemNetworkExecutor<R> {
    runner: R,
}

impl<R> SystemNetworkExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    pub fn runner_mut(&mut self) -> &mut R {
        &mut self.runner
    }

    pub fn into_runner(self) -> R {
        self.runner
    }
}

impl<R: CommandRunner> NetworkExecutor for SystemNetworkExecutor<R> {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
        self.runner.run(&operation.to_system_command())
    }

    fn revert(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
        match self.runner.run(&operation.to_system_command()) {
            Ok(()) => Ok(()),
            Err(error) if is_absent_network_revert_error(operation, error.message()) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn is_absent_network_revert_error(operation: &NetworkOperation, message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    let Some(stderr) = stderr_detail(&lower) else {
        return false;
    };

    match operation {
        NetworkOperation::RemoveRoute { .. } => contains_any(
            stderr,
            &[
                "rtnetlink answers: no such process",
                "rtnetlink answers: no such file or directory",
                "fib table does not exist",
                "cannot find device",
            ],
        ),
        NetworkOperation::RemoveRule { .. } => contains_any(
            stderr,
            &[
                "rtnetlink answers: no such process",
                "rtnetlink answers: no such file or directory",
            ],
        ),
        NetworkOperation::DeleteTun { .. } => {
            contains_any(stderr, &["cannot find device", "no such device"])
        }
        NetworkOperation::CreateTun { .. }
        | NetworkOperation::AddAddress { .. }
        | NetworkOperation::SetLinkUp { .. }
        | NetworkOperation::AddRule { .. }
        | NetworkOperation::AddRoute { .. } => false,
    }
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
    DeleteTable {
        family: String,
        table: String,
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
            Self::DeleteTable { family, table } => format!("delete table {family} {table}"),
        }
    }

    pub fn to_system_command(&self) -> SystemCommand {
        match self {
            Self::AddTable { family, table } => SystemCommand::new(
                NFT_COMMAND,
                vec![
                    "add".to_string(),
                    "table".to_string(),
                    family.clone(),
                    table.clone(),
                ],
            ),
            Self::AddChain {
                family,
                table,
                chain,
                chain_type,
                hook,
                priority,
                policy,
            } => SystemCommand::new(
                NFT_COMMAND,
                vec![
                    "add".to_string(),
                    "chain".to_string(),
                    family.clone(),
                    table.clone(),
                    chain.clone(),
                    "{".to_string(),
                    "type".to_string(),
                    chain_type.clone(),
                    "hook".to_string(),
                    hook.clone(),
                    "priority".to_string(),
                    priority.to_string(),
                    ";".to_string(),
                    "policy".to_string(),
                    policy.clone(),
                    ";".to_string(),
                    "}".to_string(),
                ],
            ),
            Self::MarkTraffic {
                family,
                table,
                chain,
                cidr,
                mark,
            } => SystemCommand::new(
                NFT_COMMAND,
                vec![
                    "add".to_string(),
                    "rule".to_string(),
                    family.clone(),
                    table.clone(),
                    chain.clone(),
                    "ip".to_string(),
                    "daddr".to_string(),
                    cidr.clone(),
                    "meta".to_string(),
                    "mark".to_string(),
                    "set".to_string(),
                    format_mark(*mark),
                ],
            ),
            Self::DropOutsideInterface {
                family,
                table,
                chain,
                cidr,
                interface,
            } => SystemCommand::new(
                NFT_COMMAND,
                vec![
                    "add".to_string(),
                    "rule".to_string(),
                    family.clone(),
                    table.clone(),
                    chain.clone(),
                    "ip".to_string(),
                    "daddr".to_string(),
                    cidr.clone(),
                    "oifname".to_string(),
                    "!=".to_string(),
                    interface.clone(),
                    "drop".to_string(),
                ],
            ),
            Self::DeleteTable { family, table } => SystemCommand::new(
                NFT_COMMAND,
                vec![
                    "delete".to_string(),
                    "table".to_string(),
                    family.clone(),
                    table.clone(),
                ],
            ),
        }
    }
}

pub trait NftablesExecutor {
    fn apply_nftables(&mut self, operation: &NftablesOperation) -> Result<(), NetworkApplyError>;

    fn revert_nftables(&mut self, operation: &NftablesOperation) -> Result<(), NetworkApplyError> {
        self.apply_nftables(operation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemNftablesExecutor<R> {
    runner: R,
}

impl<R> SystemNftablesExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    pub fn runner_mut(&mut self) -> &mut R {
        &mut self.runner
    }

    pub fn into_runner(self) -> R {
        self.runner
    }
}

impl<R: CommandRunner> NftablesExecutor for SystemNftablesExecutor<R> {
    fn apply_nftables(&mut self, operation: &NftablesOperation) -> Result<(), NetworkApplyError> {
        self.runner.run(&operation.to_system_command())
    }

    fn revert_nftables(&mut self, operation: &NftablesOperation) -> Result<(), NetworkApplyError> {
        match self.runner.run(&operation.to_system_command()) {
            Ok(()) => Ok(()),
            Err(error) if is_absent_nftables_revert_error(operation, error.message()) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn is_absent_nftables_revert_error(operation: &NftablesOperation, message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    let Some(stderr) = stderr_detail(&lower) else {
        return false;
    };

    match operation {
        NftablesOperation::DeleteTable { .. } => contains_any(
            stderr,
            &[
                "could not process rule: no such file or directory",
                "table does not exist",
                "no such table",
            ],
        ),
        NftablesOperation::AddTable { .. }
        | NftablesOperation::AddChain { .. }
        | NftablesOperation::MarkTraffic { .. }
        | NftablesOperation::DropOutsideInterface { .. } => false,
    }
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

    pub fn revert_operations(&self) -> Vec<NftablesOperation> {
        Self::revert_operations_for(&self.operations)
    }

    fn revert_operations_for(operations: &[NftablesOperation]) -> Vec<NftablesOperation> {
        operations
            .iter()
            .rev()
            .filter_map(|operation| match operation {
                NftablesOperation::AddTable { family, table } => {
                    Some(NftablesOperation::DeleteTable {
                        family: family.clone(),
                        table: table.clone(),
                    })
                }
                NftablesOperation::AddChain { .. }
                | NftablesOperation::MarkTraffic { .. }
                | NftablesOperation::DropOutsideInterface { .. }
                | NftablesOperation::DeleteTable { .. } => None,
            })
            .collect()
    }

    pub fn revert_rules(&self) -> Vec<String> {
        self.revert_operations()
            .iter()
            .map(NftablesOperation::to_rule)
            .collect()
    }

    pub fn revert<E: NftablesExecutor>(&self, executor: &mut E) -> Result<(), NetworkApplyError> {
        Self::revert_operations_with(executor, &self.operations)
    }

    fn revert_operations_with<E: NftablesExecutor>(
        executor: &mut E,
        operations: &[NftablesOperation],
    ) -> Result<(), NetworkApplyError> {
        let mut errors = Vec::new();

        for operation in Self::revert_operations_for(operations) {
            if let Err(error) = executor.revert_nftables(&operation) {
                errors.push(error.to_string());
            }
        }

        if !errors.is_empty() {
            return Err(NetworkApplyError::new(errors.join("; ")));
        }

        Ok(())
    }
}

fn format_mark(mark: u32) -> String {
    format!("0x{mark:x}")
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn stderr_detail(message: &str) -> Option<&str> {
    message
        .split_once("stderr:")
        .map(|(_, stderr)| stderr.trim())
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
    fn network_operations_render_to_exact_system_commands() {
        assert_eq!(
            NetworkOperation::CreateTun {
                name: "qlink0".to_string(),
            }
            .to_system_command(),
            system_command(
                IP_COMMAND,
                &["tuntap", "add", "dev", "qlink0", "mode", "tun"]
            )
        );
        assert_eq!(
            NetworkOperation::AddAddress {
                interface: "qlink0".to_string(),
                address: "100.64.10.2/32".to_string(),
            }
            .to_system_command(),
            system_command(
                IP_COMMAND,
                &["addr", "add", "100.64.10.2/32", "dev", "qlink0"]
            )
        );
        assert_eq!(
            NetworkOperation::SetLinkUp {
                interface: "qlink0".to_string(),
                mtu: 1280,
            }
            .to_system_command(),
            system_command(
                IP_COMMAND,
                &["link", "set", "dev", "qlink0", "mtu", "1280", "up"]
            )
        );
        assert_eq!(
            NetworkOperation::AddRule {
                fwmark: 0x514c,
                table: 51820,
            }
            .to_system_command(),
            system_command(
                IP_COMMAND,
                &["rule", "add", "fwmark", "0x514c", "table", "51820"]
            )
        );
        assert_eq!(
            NetworkOperation::AddRoute {
                cidr: "100.64.0.0/10".to_string(),
                interface: "qlink0".to_string(),
                table: 51820,
            }
            .to_system_command(),
            system_command(
                IP_COMMAND,
                &[
                    "route",
                    "add",
                    "100.64.0.0/10",
                    "dev",
                    "qlink0",
                    "table",
                    "51820",
                ],
            )
        );
    }

    #[test]
    fn network_revert_uses_reverse_dependency_order() {
        let plan = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");

        assert_eq!(
            plan.revert_operations(),
            vec![
                NetworkOperation::RemoveRoute {
                    cidr: "100.64.0.0/10".to_string(),
                    interface: "qlink0".to_string(),
                    table: 51820,
                },
                NetworkOperation::RemoveRule {
                    fwmark: 0x514c,
                    table: 51820,
                },
                NetworkOperation::DeleteTun {
                    name: "qlink0".to_string(),
                },
            ]
        );
        assert_eq!(
            plan.revert_commands(),
            vec![
                "ip route del 100.64.0.0/10 dev qlink0 table 51820",
                "ip rule del fwmark 0x514c table 51820",
                "ip link delete dev qlink0",
            ]
        );
    }

    #[test]
    fn network_revert_operations_render_to_exact_system_commands() {
        assert_eq!(
            NetworkOperation::RemoveRoute {
                cidr: "100.64.0.0/10".to_string(),
                interface: "qlink0".to_string(),
                table: 51820,
            }
            .to_system_command(),
            system_command(
                IP_COMMAND,
                &[
                    "route",
                    "del",
                    "100.64.0.0/10",
                    "dev",
                    "qlink0",
                    "table",
                    "51820",
                ],
            )
        );
        assert_eq!(
            NetworkOperation::RemoveRule {
                fwmark: 0x514c,
                table: 51820,
            }
            .to_system_command(),
            system_command(
                IP_COMMAND,
                &["rule", "del", "fwmark", "0x514c", "table", "51820"]
            )
        );
        assert_eq!(
            NetworkOperation::DeleteTun {
                name: "qlink0".to_string(),
            }
            .to_system_command(),
            system_command(IP_COMMAND, &["link", "delete", "dev", "qlink0"])
        );
    }

    #[test]
    fn nftables_operations_render_to_exact_system_commands() {
        assert_eq!(
            NftablesOperation::AddTable {
                family: "inet".to_string(),
                table: "qlink".to_string(),
            }
            .to_system_command(),
            system_command(NFT_COMMAND, &["add", "table", "inet", "qlink"])
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
            .to_system_command(),
            system_command(
                NFT_COMMAND,
                &[
                    "add",
                    "chain",
                    "inet",
                    "qlink",
                    "route_output",
                    "{",
                    "type",
                    "route",
                    "hook",
                    "output",
                    "priority",
                    "0",
                    ";",
                    "policy",
                    "accept",
                    ";",
                    "}",
                ],
            )
        );
        assert_eq!(
            NftablesOperation::MarkTraffic {
                family: "inet".to_string(),
                table: "qlink".to_string(),
                chain: "route_output".to_string(),
                cidr: "100.64.0.0/10".to_string(),
                mark: 0x514c,
            }
            .to_system_command(),
            system_command(
                NFT_COMMAND,
                &[
                    "add",
                    "rule",
                    "inet",
                    "qlink",
                    "route_output",
                    "ip",
                    "daddr",
                    "100.64.0.0/10",
                    "meta",
                    "mark",
                    "set",
                    "0x514c",
                ],
            )
        );
        assert_eq!(
            NftablesOperation::DropOutsideInterface {
                family: "inet".to_string(),
                table: "qlink".to_string(),
                chain: "filter_output".to_string(),
                cidr: "100.64.0.0/10".to_string(),
                interface: "qlink0".to_string(),
            }
            .to_system_command(),
            system_command(
                NFT_COMMAND,
                &[
                    "add",
                    "rule",
                    "inet",
                    "qlink",
                    "filter_output",
                    "ip",
                    "daddr",
                    "100.64.0.0/10",
                    "oifname",
                    "!=",
                    "qlink0",
                    "drop",
                ],
            )
        );
    }

    #[test]
    fn nftables_revert_deletes_quantumlink_table() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");

        assert_eq!(
            plan.revert_operations(),
            vec![NftablesOperation::DeleteTable {
                family: "inet".to_string(),
                table: "qlink".to_string(),
            }]
        );
        assert_eq!(plan.revert_rules(), vec!["delete table inet qlink"]);
    }

    #[test]
    fn nftables_revert_operations_render_to_exact_system_commands() {
        assert_eq!(
            NftablesOperation::DeleteTable {
                family: "inet".to_string(),
                table: "qlink".to_string(),
            }
            .to_system_command(),
            system_command(NFT_COMMAND, &["delete", "table", "inet", "qlink"])
        );
    }

    #[test]
    fn network_system_commands_use_trusted_ip_binary() {
        let command = NetworkOperation::CreateTun {
            name: "qlink0".to_string(),
        }
        .to_system_command();

        assert_eq!(command.program, "/usr/bin/ip");
        assert_eq!(
            command.args,
            vec!["tuntap", "add", "dev", "qlink0", "mode", "tun"]
        );
    }

    #[test]
    fn nftables_system_commands_use_trusted_nft_binary() {
        let command = NftablesOperation::AddTable {
            family: "inet".to_string(),
            table: "qlink".to_string(),
        }
        .to_system_command();

        assert_eq!(command.program, "/usr/bin/nft");
        assert_eq!(command.args, vec!["add", "table", "inet", "qlink"]);
    }

    #[test]
    fn rendered_system_command_preserves_argument_boundaries() {
        let command = SystemCommand::new("/bin/echo", ["two words", "semi;colon"]);

        assert_eq!(
            command.rendered(),
            r#""/bin/echo" ["two words", "semi;colon"]"#
        );
    }

    #[test]
    fn system_network_executor_runs_exact_argv_in_order() {
        let plan = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");
        let mut executor = SystemNetworkExecutor::new(FakeRunner::default());

        plan.apply(&mut executor).expect("fake runner should apply");

        assert_eq!(
            executor.runner().commands,
            vec![
                system_command(
                    IP_COMMAND,
                    &["tuntap", "add", "dev", "qlink0", "mode", "tun"]
                ),
                system_command(
                    IP_COMMAND,
                    &["addr", "add", "100.64.10.2/32", "dev", "qlink0"]
                ),
                system_command(
                    IP_COMMAND,
                    &["link", "set", "dev", "qlink0", "mtu", "1280", "up"]
                ),
                system_command(
                    IP_COMMAND,
                    &["rule", "add", "fwmark", "0x514c", "table", "51820"]
                ),
                system_command(
                    IP_COMMAND,
                    &[
                        "route",
                        "add",
                        "100.64.0.0/10",
                        "dev",
                        "qlink0",
                        "table",
                        "51820",
                    ],
                ),
            ]
        );
    }

    #[test]
    fn system_nftables_executor_runs_exact_argv_in_order() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");
        let mut executor = SystemNftablesExecutor::new(FakeRunner::default());

        plan.apply(&mut executor).expect("fake runner should apply");

        assert_eq!(
            executor.runner().commands,
            vec![
                system_command(NFT_COMMAND, &["add", "table", "inet", "qlink"]),
                system_command(
                    NFT_COMMAND,
                    &[
                        "add",
                        "chain",
                        "inet",
                        "qlink",
                        "route_output",
                        "{",
                        "type",
                        "route",
                        "hook",
                        "output",
                        "priority",
                        "0",
                        ";",
                        "policy",
                        "accept",
                        ";",
                        "}",
                    ],
                ),
                system_command(
                    NFT_COMMAND,
                    &[
                        "add",
                        "chain",
                        "inet",
                        "qlink",
                        "filter_output",
                        "{",
                        "type",
                        "filter",
                        "hook",
                        "output",
                        "priority",
                        "0",
                        ";",
                        "policy",
                        "accept",
                        ";",
                        "}",
                    ],
                ),
                system_command(
                    NFT_COMMAND,
                    &[
                        "add",
                        "rule",
                        "inet",
                        "qlink",
                        "route_output",
                        "ip",
                        "daddr",
                        "100.64.0.0/10",
                        "meta",
                        "mark",
                        "set",
                        "0x514c",
                    ],
                ),
                system_command(
                    NFT_COMMAND,
                    &[
                        "add",
                        "rule",
                        "inet",
                        "qlink",
                        "filter_output",
                        "ip",
                        "daddr",
                        "100.64.0.0/10",
                        "oifname",
                        "!=",
                        "qlink0",
                        "drop",
                    ],
                ),
            ]
        );
    }

    #[test]
    fn system_network_executor_stops_on_first_runner_failure() {
        let plan = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");
        let mut executor = SystemNetworkExecutor::new(FakeRunner::fail_on(2));

        let error = plan.apply(&mut executor).unwrap_err();

        assert_eq!(error.message(), "runner failed");
        assert_eq!(
            executor.runner().commands,
            vec![
                system_command(
                    IP_COMMAND,
                    &["tuntap", "add", "dev", "qlink0", "mode", "tun"]
                ),
                system_command(
                    IP_COMMAND,
                    &["addr", "add", "100.64.10.2/32", "dev", "qlink0"]
                ),
            ]
        );
    }

    #[test]
    fn system_nftables_executor_stops_on_first_runner_failure() {
        let plan = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");
        let mut executor = SystemNftablesExecutor::new(FakeRunner::fail_on(2));

        let error = plan.apply(&mut executor).unwrap_err();

        assert_eq!(error.message(), "runner failed");
        assert_eq!(
            executor.runner().commands,
            vec![
                system_command(NFT_COMMAND, &["add", "table", "inet", "qlink"]),
                system_command(
                    NFT_COMMAND,
                    &[
                        "add",
                        "chain",
                        "inet",
                        "qlink",
                        "route_output",
                        "{",
                        "type",
                        "route",
                        "hook",
                        "output",
                        "priority",
                        "0",
                        ";",
                        "policy",
                        "accept",
                        ";",
                        "}",
                    ],
                ),
            ]
        );
    }

    #[test]
    fn system_network_revert_treats_known_absent_objects_as_success() {
        let cases = [
            (
                LinuxNetworkPlan::from_operations(vec![NetworkOperation::AddRoute {
                    cidr: "100.64.0.0/10".to_string(),
                    interface: "qlink0".to_string(),
                    table: 51820,
                }]),
                "RTNETLINK answers: No such process",
                system_command(
                    IP_COMMAND,
                    &[
                        "route",
                        "del",
                        "100.64.0.0/10",
                        "dev",
                        "qlink0",
                        "table",
                        "51820",
                    ],
                ),
            ),
            (
                LinuxNetworkPlan::from_operations(vec![NetworkOperation::AddRoute {
                    cidr: "100.64.0.0/10".to_string(),
                    interface: "qlink0".to_string(),
                    table: 51820,
                }]),
                "Cannot find device \"qlink0\"",
                system_command(
                    IP_COMMAND,
                    &[
                        "route",
                        "del",
                        "100.64.0.0/10",
                        "dev",
                        "qlink0",
                        "table",
                        "51820",
                    ],
                ),
            ),
            (
                LinuxNetworkPlan::from_operations(vec![NetworkOperation::AddRule {
                    fwmark: 0x514c,
                    table: 51820,
                }]),
                "RTNETLINK answers: No such file or directory",
                system_command(
                    IP_COMMAND,
                    &["rule", "del", "fwmark", "0x514c", "table", "51820"],
                ),
            ),
            (
                LinuxNetworkPlan::from_operations(vec![NetworkOperation::CreateTun {
                    name: "qlink0".to_string(),
                }]),
                "Cannot find device \"qlink0\"",
                system_command(IP_COMMAND, &["link", "delete", "dev", "qlink0"]),
            ),
        ];

        for (plan, stderr, expected_command) in cases {
            let mut executor =
                SystemNetworkExecutor::new(FakeRunner::fail_with(command_stderr(stderr)));

            plan.revert(&mut executor)
                .expect("known absent network teardown should be idempotent");

            assert_eq!(executor.runner().commands, vec![expected_command]);
        }
    }

    #[test]
    fn system_nftables_revert_treats_absent_table_as_success() {
        let plan = NftablesPlan::from_operations(vec![NftablesOperation::AddTable {
            family: "inet".to_string(),
            table: "qlink".to_string(),
        }]);
        let mut executor = SystemNftablesExecutor::new(FakeRunner::fail_with(command_stderr(
            "Error: Could not process rule: No such file or directory",
        )));

        plan.revert(&mut executor)
            .expect("known absent nftables table teardown should be idempotent");

        assert_eq!(
            executor.runner().commands,
            vec![system_command(
                NFT_COMMAND,
                &["delete", "table", "inet", "qlink"]
            )]
        );
    }

    #[test]
    fn system_revert_reports_unknown_teardown_stderr() {
        let network_plan = LinuxNetworkPlan::from_operations(vec![NetworkOperation::AddRoute {
            cidr: "100.64.0.0/10".to_string(),
            interface: "qlink0".to_string(),
            table: 51820,
        }]);
        let mut network_executor =
            SystemNetworkExecutor::new(FakeRunner::fail_with(command_stderr("permission denied")));

        let network_error = network_plan.revert(&mut network_executor).unwrap_err();

        assert!(network_error.message().contains("permission denied"));

        let nftables_plan = NftablesPlan::from_operations(vec![NftablesOperation::AddTable {
            family: "inet".to_string(),
            table: "qlink".to_string(),
        }]);
        let mut nftables_executor =
            SystemNftablesExecutor::new(FakeRunner::fail_with(command_stderr("syntax error")));

        let nftables_error = nftables_plan.revert(&mut nftables_executor).unwrap_err();

        assert!(nftables_error.message().contains("syntax error"));
    }

    #[test]
    fn system_network_revert_reports_generic_missing_text_as_unknown() {
        let cases = [
            (
                LinuxNetworkPlan::from_operations(vec![NetworkOperation::AddRoute {
                    cidr: "100.64.0.0/10".to_string(),
                    interface: "qlink0".to_string(),
                    table: 51820,
                }]),
                "route cache helper failed: No such file or directory",
            ),
            (
                LinuxNetworkPlan::from_operations(vec![NetworkOperation::AddRule {
                    fwmark: 0x514c,
                    table: 51820,
                }]),
                "rule parser include missing: No such file or directory",
            ),
            (
                LinuxNetworkPlan::from_operations(vec![NetworkOperation::CreateTun {
                    name: "qlink0".to_string(),
                }]),
                "qlink cleanup helper does not exist",
            ),
        ];

        for (plan, stderr) in cases {
            let mut executor =
                SystemNetworkExecutor::new(FakeRunner::fail_with(command_stderr(stderr)));

            let error = plan.revert(&mut executor).unwrap_err();

            assert!(error.message().contains(stderr));
        }
    }

    #[test]
    fn system_nftables_revert_reports_generic_missing_text_as_unknown() {
        let plan = NftablesPlan::from_operations(vec![NftablesOperation::AddTable {
            family: "inet".to_string(),
            table: "qlink".to_string(),
        }]);
        let mut executor = SystemNftablesExecutor::new(FakeRunner::fail_with(command_stderr(
            "loading qlink include failed: No such file or directory",
        )));

        let error = plan.revert(&mut executor).unwrap_err();

        assert!(error
            .message()
            .contains("loading qlink include failed: No such file or directory"));
    }

    #[test]
    fn system_revert_reports_spawn_failure_even_when_it_mentions_no_such_file() {
        let network_plan = LinuxNetworkPlan::from_operations(vec![NetworkOperation::AddRoute {
            cidr: "100.64.0.0/10".to_string(),
            interface: "qlink0".to_string(),
            table: 51820,
        }]);
        let mut network_executor = SystemNetworkExecutor::new(FakeRunner::fail_with(
            "failed to spawn `/usr/bin/ip`: No such file or directory",
        ));

        let network_error = network_plan.revert(&mut network_executor).unwrap_err();

        assert!(network_error.message().contains("failed to spawn"));

        let nftables_plan = NftablesPlan::from_operations(vec![NftablesOperation::AddTable {
            family: "inet".to_string(),
            table: "qlink".to_string(),
        }]);
        let mut nftables_executor = SystemNftablesExecutor::new(FakeRunner::fail_with(
            "failed to spawn `/usr/bin/nft`: No such file or directory",
        ));

        let nftables_error = nftables_plan.revert(&mut nftables_executor).unwrap_err();

        assert!(nftables_error.message().contains("failed to spawn"));
    }

    #[test]
    fn system_apply_reports_absent_object_stderr_strictly() {
        let mut network_executor = SystemNetworkExecutor::new(FakeRunner::fail_with(
            command_stderr("RTNETLINK answers: No such process"),
        ));

        let network_error = network_executor
            .apply(&NetworkOperation::RemoveRoute {
                cidr: "100.64.0.0/10".to_string(),
                interface: "qlink0".to_string(),
                table: 51820,
            })
            .unwrap_err();

        assert!(network_error
            .message()
            .contains("RTNETLINK answers: No such process"));

        let mut nftables_executor = SystemNftablesExecutor::new(FakeRunner::fail_with(
            command_stderr("Error: Could not process rule: No such file or directory"),
        ));

        let nftables_error = nftables_executor
            .apply_nftables(&NftablesOperation::DeleteTable {
                family: "inet".to_string(),
                table: "qlink".to_string(),
            })
            .unwrap_err();

        assert!(nftables_error
            .message()
            .contains("No such file or directory"));
    }

    #[test]
    fn std_command_runner_reports_spawn_failure_with_command_context() {
        let mut runner = StdCommandRunner;
        let command = system_command("/definitely/not/a/qlink-test-command", &["--nope"]);

        let error = runner.run(&command).unwrap_err();

        assert!(error.message().contains("failed to spawn"));
        assert!(error
            .message()
            .contains("\"/definitely/not/a/qlink-test-command\" [\"--nope\"]"));
    }

    #[test]
    fn std_command_runner_reports_non_zero_exit_with_command_context() {
        let mut runner = StdCommandRunner;
        let command = non_zero_exit_command();
        let rendered = command.rendered();

        let error = runner.run(&command).unwrap_err();

        assert!(
            error.message().contains("exited with status"),
            "{}",
            error.message()
        );
        assert!(error.message().contains(&rendered), "{}", error.message());
    }

    #[cfg(windows)]
    fn non_zero_exit_command() -> SystemCommand {
        system_command("cmd", &["/C", "exit", "7"])
    }

    #[cfg(not(windows))]
    fn non_zero_exit_command() -> SystemCommand {
        let false_program = if std::path::Path::new("/usr/bin/false").exists() {
            "/usr/bin/false"
        } else {
            "/bin/false"
        };
        system_command(false_program, &[])
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
    fn dry_run_executor_records_rendered_revert_operations() {
        let network = LinuxNetworkPlan::for_interface("qlink0", "100.64.10.2/32", "100.64.0.0/10");
        let nftables = NftablesPlan::fail_closed("qlink0", "100.64.0.0/10");
        let mut executor = DryRunExecutor::new();

        nftables
            .revert(&mut executor)
            .expect("dry-run nftables revert should record");
        network
            .revert(&mut executor)
            .expect("dry-run network revert should record");

        assert_eq!(
            executor.recorded_commands(),
            &[
                "delete table inet qlink",
                "ip route del 100.64.0.0/10 dev qlink0 table 51820",
                "ip rule del fwmark 0x514c table 51820",
                "ip link delete dev qlink0",
            ]
        );
    }

    #[test]
    fn runtime_deactivate_tears_down_nftables_before_network() {
        let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut network = RecordingNetworkExecutor::new(events.clone());
        let mut nftables = RecordingNftablesExecutor::new(events.clone());

        plan.deactivate(&mut network, &mut nftables)
            .expect("runtime deactivate should succeed");

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
    fn runtime_deactivate_reports_cleanup_failures_after_attempting_both_layers() {
        let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut network = RecordingNetworkExecutor::new(events.clone()).fail_on_revert(2);
        let mut nftables = RecordingNftablesExecutor::new(events.clone()).fail_on_revert(1);

        let error = plan.deactivate(&mut network, &mut nftables).unwrap_err();

        assert!(error
            .message()
            .contains("runtime deactivate failed: nftables revert failed at 1"));
        assert!(error.message().contains("network revert failed at 2"));
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
    fn runtime_apply_succeeds_without_rollback() {
        let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut network = RecordingNetworkExecutor::new(events.clone());
        let mut nftables = RecordingNftablesExecutor::new(events.clone());

        plan.apply_with_rollback(&mut network, &mut nftables)
            .expect("runtime apply should succeed");

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
                "nftables:add chain inet qlink filter_output { type filter hook output priority 0; policy accept; }",
                "nftables:add rule inet qlink route_output ip daddr 100.64.0.0/10 meta mark set 0x514c",
                "nftables:add rule inet qlink filter_output ip daddr 100.64.0.0/10 oifname != \"qlink0\" drop",
            ]
        );
    }

    #[test]
    fn runtime_apply_rolls_back_only_completed_network_operations_when_network_apply_fails() {
        let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut network = RecordingNetworkExecutor::new(events.clone()).fail_on_apply(2);
        let mut nftables = RecordingNftablesExecutor::new(events.clone());

        let error = plan
            .apply_with_rollback(&mut network, &mut nftables)
            .unwrap_err();

        assert!(error
            .message()
            .contains("runtime apply failed: network apply failed"));
        assert!(error.message().contains("network apply failed at 2"));
        assert_eq!(
            events.borrow().as_slice(),
            &[
                "network:ip tuntap add dev qlink0 mode tun",
                "network:ip addr add 100.64.10.2/32 dev qlink0",
                "network:ip link delete dev qlink0",
            ]
        );
    }

    #[test]
    fn runtime_apply_rolls_back_network_only_when_first_nftables_apply_fails() {
        let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut network = RecordingNetworkExecutor::new(events.clone());
        let mut nftables = RecordingNftablesExecutor::new(events.clone()).fail_on_apply(1);

        let error = plan
            .apply_with_rollback(&mut network, &mut nftables)
            .unwrap_err();

        assert!(error
            .message()
            .contains("runtime apply failed: nftables apply failed"));
        assert!(error.message().contains("nftables apply failed at 1"));
        assert_eq!(
            events.borrow().as_slice(),
            &[
                "network:ip tuntap add dev qlink0 mode tun",
                "network:ip addr add 100.64.10.2/32 dev qlink0",
                "network:ip link set dev qlink0 mtu 1280 up",
                "network:ip rule add fwmark 0x514c table 51820",
                "network:ip route add 100.64.0.0/10 dev qlink0 table 51820",
                "nftables:add table inet qlink",
                "network:ip route del 100.64.0.0/10 dev qlink0 table 51820",
                "network:ip rule del fwmark 0x514c table 51820",
                "network:ip link delete dev qlink0",
            ]
        );
    }

    #[test]
    fn runtime_apply_rolls_back_nftables_table_when_table_add_succeeded() {
        let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut network = RecordingNetworkExecutor::new(events.clone());
        let mut nftables = RecordingNftablesExecutor::new(events.clone()).fail_on_apply(2);

        let error = plan
            .apply_with_rollback(&mut network, &mut nftables)
            .unwrap_err();

        assert!(error
            .message()
            .contains("runtime apply failed: nftables apply failed"));
        assert!(error.message().contains("nftables apply failed at 2"));
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
    fn runtime_apply_reports_rollback_failures_with_original_failure() {
        let plan = LinuxRuntimePlan::from_config(&DaemonConfig::default()).expect("valid plan");
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut network = RecordingNetworkExecutor::new(events.clone()).fail_on_revert(2);
        let mut nftables = RecordingNftablesExecutor::new(events.clone())
            .fail_on_apply(2)
            .fail_on_revert(1);

        let error = plan
            .apply_with_rollback(&mut network, &mut nftables)
            .unwrap_err();

        assert!(error.message().contains("nftables apply failed at 2"));
        assert!(error
            .message()
            .contains("rollback nftables revert failed: nftables revert failed at 1"));
        assert!(error
            .message()
            .contains("rollback network revert failed: network revert failed at 2"));
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

    fn system_command(program: &str, args: &[&str]) -> SystemCommand {
        SystemCommand {
            program: program.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
        }
    }

    fn command_stderr(stderr: &str) -> String {
        format!("command exited with status exit status: 2: stderr: {stderr}")
    }

    #[derive(Default)]
    struct FakeRunner {
        commands: Vec<SystemCommand>,
        fail_on: Option<usize>,
        failure_message: Option<String>,
    }

    impl FakeRunner {
        fn fail_on(command_index: usize) -> Self {
            Self {
                commands: Vec::new(),
                fail_on: Some(command_index),
                failure_message: None,
            }
        }

        fn fail_with(message: impl Into<String>) -> Self {
            Self {
                commands: Vec::new(),
                fail_on: Some(1),
                failure_message: Some(message.into()),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&mut self, command: &SystemCommand) -> Result<(), NetworkApplyError> {
            self.commands.push(command.clone());
            if self.fail_on == Some(self.commands.len()) {
                return Err(NetworkApplyError::new(
                    self.failure_message
                        .clone()
                        .unwrap_or_else(|| "runner failed".to_string()),
                ));
            }
            Ok(())
        }
    }

    type SharedEvents = std::rc::Rc<std::cell::RefCell<Vec<String>>>;

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
        fail_revert_on: Option<usize>,
    }

    impl RecordingNftablesExecutor {
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

    impl NftablesExecutor for RecordingNftablesExecutor {
        fn apply_nftables(
            &mut self,
            operation: &NftablesOperation,
        ) -> Result<(), NetworkApplyError> {
            if matches!(operation, NftablesOperation::DeleteTable { .. }) {
                self.reverted += 1;
                self.events
                    .borrow_mut()
                    .push(format!("nftables:{}", operation.to_rule()));
                if self.fail_revert_on == Some(self.reverted) {
                    return Err(NetworkApplyError::new(format!(
                        "nftables revert failed at {}",
                        self.reverted
                    )));
                }
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
}
