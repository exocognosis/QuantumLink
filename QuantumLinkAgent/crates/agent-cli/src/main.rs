use clap::{Parser, Subcommand};
use qlink_agent_actions::MvpActionExecutor;
use qlink_agent_audit::AuditLog;
use qlink_agent_contracts::{
    AgentRequest, Capability, EvidenceEnvelope, Sensitivity, CONTRACT_VERSION,
};
use qlink_agent_identity::{IdentityProvider, LocalIdentityProvider};
use qlink_agent_policy::AgentPolicy;
use qlink_agent_reasoning::DeterministicReasoning;
use qlink_agent_runtime::{approval_for, AgentRuntime};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "qlink-agent",
    version,
    about = "Governed private connectivity for autonomous workloads"
)]
struct Cli {
    #[arg(long, default_value = ".quantumlink-agent")]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Onboard {
        workload: String,
        #[arg(long)]
        resource: String,
    },
    Status {
        workload: String,
    },
    Diagnose {
        workload: String,
        #[arg(long, default_value = "stale-peer-record")]
        scenario: String,
    },
    Plan {
        workload: String,
        #[arg(long, default_value = "stale-peer-record")]
        scenario: String,
    },
    Approve {
        workload: String,
        #[arg(long, default_value = "operator")]
        approver: String,
    },
    Apply {
        workload: String,
        #[arg(long, default_value = "operator")]
        approver: String,
    },
    Rollback {
        workload: String,
        #[arg(long, default_value = "operator")]
        approver: String,
    },
    Audit {
        #[arg(long)]
        verify: bool,
    },
    Demo {
        workload: String,
        #[arg(long)]
        resource: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WorkloadState {
    workload: String,
    resource: String,
    identity_provider: String,
    status: String,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    fs::create_dir_all(&cli.state_dir).map_err(|error| error.to_string())?;
    let audit = AuditLog::new(cli.state_dir.join("audit.jsonl"));
    match cli.command {
        Command::Onboard { workload, resource } => {
            onboard(&cli.state_dir, &workload, &resource)?;
            print_json(&load_state(&cli.state_dir, &workload)?)
        }
        Command::Status { workload } => print_json(&load_state(&cli.state_dir, &workload)?),
        Command::Diagnose { workload, scenario } => {
            let (request, evidence) = inputs(&workload, &scenario);
            let runtime = AgentRuntime::new(
                AgentPolicy::default(),
                DeterministicReasoning,
                MvpActionExecutor::default(),
                audit,
            );
            print_json(&runtime.diagnose(&request, &[evidence], now())?)
        }
        Command::Plan { workload, scenario } => {
            let (request, evidence) = inputs(&workload, &scenario);
            let runtime = AgentRuntime::new(
                AgentPolicy::default(),
                DeterministicReasoning,
                MvpActionExecutor::default(),
                audit,
            );
            let recommendation = runtime.diagnose(&request, &[evidence], now())?;
            print_json(&runtime.plan(&request, &recommendation)?)
        }
        Command::Approve { workload, approver } => {
            let (request, evidence) = inputs(&workload, "stale-peer-record");
            let runtime = AgentRuntime::new(
                AgentPolicy::default(),
                DeterministicReasoning,
                MvpActionExecutor::default(),
                audit,
            );
            let recommendation = runtime.diagnose(&request, &[evidence], now())?;
            let (plan, _) = runtime.plan(&request, &recommendation)?;
            print_json(&approval_for(&plan, approver, now(), 300)?)
        }
        Command::Apply { workload, approver } => execute(audit, &workload, &approver, false),
        Command::Rollback { workload, approver } => execute(audit, &workload, &approver, true),
        Command::Audit { verify } => {
            if verify {
                print_json(&serde_json::json!({"valid": audit.verify()?}))
            } else {
                print_json(&audit.read_all()?)
            }
        }
        Command::Demo { workload, resource } => {
            onboard(&cli.state_dir, &workload, &resource)?;
            execute(audit, &workload, "demo-operator", false)
        }
    }
}

fn execute(audit: AuditLog, workload: &str, approver: &str, rollback: bool) -> Result<(), String> {
    let (request, evidence) = inputs(workload, "stale-peer-record");
    let mut runtime = AgentRuntime::new(
        AgentPolicy::default(),
        DeterministicReasoning,
        MvpActionExecutor::default(),
        audit,
    );
    let recommendation = runtime.diagnose(&request, &[evidence], now())?;
    let (plan, decision) = runtime.plan(&request, &recommendation)?;
    let approval = approval_for(&plan, approver, now(), 300)?;
    let applied = runtime.apply(&request, &plan, Some(&approval), now())?;
    if rollback {
        let rolled_back = runtime.rollback(&request, &plan, now())?;
        print_json(
            &serde_json::json!({"decision": decision, "applied": applied, "rolled_back": rolled_back, "audit_valid": runtime.audit().verify()?}),
        )
    } else {
        print_json(
            &serde_json::json!({"decision": decision, "applied": applied, "audit_valid": runtime.audit().verify()?}),
        )
    }
}

fn onboard(dir: &std::path::Path, workload: &str, resource: &str) -> Result<(), String> {
    let mut identities = LocalIdentityProvider::default();
    identities.register(workload);
    let assertion = identities.resolve(workload, now());
    if !identities.verify(&assertion, now()) {
        return Err("identity verification failed".into());
    }
    let state = WorkloadState {
        workload: workload.into(),
        resource: resource.into(),
        identity_provider: assertion.provider,
        status: "registered".into(),
    };
    fs::write(
        state_path(dir, workload),
        serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn load_state(dir: &std::path::Path, workload: &str) -> Result<WorkloadState, String> {
    serde_json::from_slice(
        &fs::read(state_path(dir, workload))
            .map_err(|_| "workload is not onboarded".to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn state_path(dir: &std::path::Path, workload: &str) -> PathBuf {
    let safe: String = workload
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect();
    dir.join(format!("{safe}.json"))
}

fn inputs(workload: &str, scenario: &str) -> (AgentRequest, EvidenceEnvelope) {
    let now = now();
    let facts: BTreeMap<String, String> = match scenario {
        "identity" => [("identity_status".into(), "revoked".into())].into(),
        "handshake" => [("handshake_status".into(), "failed".into())].into(),
        "direct-path" => [
            ("direct_path_status".into(), "failed".into()),
            ("relay_allowed".into(), "true".into()),
        ]
        .into(),
        "relay-policy" => [
            ("direct_path_status".into(), "failed".into()),
            ("relay_allowed".into(), "false".into()),
        ]
        .into(),
        "route-conflict" => [("route_status".into(), "conflict".into())].into(),
        "healthy" => [("session_status".into(), "healthy".into())].into(),
        _ => [("peer_record_status".into(), "stale".into())].into(),
    };
    (
        AgentRequest {
            version: CONTRACT_VERSION.into(),
            request_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4().to_string(),
            actor: "local-operator".into(),
            target_workload: workload.into(),
            intent: "diagnose private connectivity".into(),
            requested_capability: Capability::Diagnose,
        },
        EvidenceEnvelope {
            version: CONTRACT_VERSION.into(),
            evidence_id: Uuid::new_v4(),
            source: "mvp-fixture-adapter".into(),
            collected_at_unix: now,
            expires_at_unix: now + 60,
            sensitivity: Sensitivity::Redacted,
            facts,
        },
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn print_json(value: &impl Serialize) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}
