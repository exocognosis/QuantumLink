use qlink_game::{GameLaunchPlan, GameProfile};
use qlink_proto::{
    load_peer_store_at, peer_store_path_from_state_dir, store_peer_store_at, ConnectionPhase,
    DaemonControlRequest, DaemonStatus, DataPlaneState, DytallixBindingVersion,
    DytallixTrustDecision, DytallixTrustHealth, DytallixTrustStatus,
    GameProcessClassificationState, GameProfilePortEnforcementState, GameProfileStatus, InviteCode,
    LocalRegistryBindingState, MeshTrustMode, NetworkPlanState, PathKind, PeerStore,
    PublicationErrorCode, PublicationState, PublicationStatus, RouteMode, RuntimeCapabilityState,
    RuntimeCapabilityStatus, SteamOsRuntimeCapabilities, StoredPeer,
};

pub mod dytallix;

#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("qlinkd is unavailable at {path}: {source}")]
    Unavailable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to exchange a daemon control request: {0}")]
    Write(#[from] std::io::Error),
    #[error("invalid qlinkd status response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("qlinkd returned an error: {0}")]
    Daemon(String),
}

pub const DEFAULT_STATE_DIR: &str = "/var/lib/quantumlink";
pub const DEVICE_IDENTITY_SEED_FILE: &str = "device-identity.seed";

pub fn load_provisioning_device_keypair(
    state_dir: &Path,
) -> Result<qlink_core::crypto::DeviceKeypair, std::io::Error> {
    let path = state_dir.join(DEVICE_IDENTITY_SEED_FILE);
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "device identity seed {} is not a regular file",
                path.display()
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "device identity seed {} must not be group- or world-accessible",
                    path.display()
                ),
            ));
        }
    }
    let bytes = std::fs::read(&path)?;
    let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "device identity seed {} must be exactly 32 bytes; got {}",
                path.display(),
                bytes.len()
            ),
        )
    })?;
    qlink_core::crypto::DeviceKeypair::from_seed(seed).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "device identity seed {} is invalid: {error}",
                path.display()
            ),
        )
    })
}

pub fn format_guide() -> String {
    [
        "QuantumLink SteamOS Guide",
        "",
        "Onboarding",
        "- Build and install qlinkd, qlinkctl, and qlink-desktop, then edit /etc/quantumlink/config.json.",
        "- Begin with qlinkctl status and qlinkctl doctor before changing any network state.",
        "- Keep support bundles redacted before sharing logs outside the Deck.",
        "",
        "Runtime modes",
        "- The packaged qlinkd service starts with active TUN, route, and nftables application.",
        "- qlinkd without --activate-network remains the planning-only recovery mode.",
        "- qlinkd --check validates configuration/status and exits.",
        "- qlinkd --activate-network applies live TUN, route, and nftables state.",
        "- qlinkd --deactivate-network removes only QuantumLink-owned network state from the persisted ownership record.",
        "- qlinkctl doctor reports packet I/O, data-plane health, and whether transport ready is yes or no.",
        "- Publication and Dytallix failures are fail-closed: protected transport must remain disabled until qlinkctl doctor reports a current signed record and healthy required trust.",
        "",
        "Peer and invite commands",
        "- qlinkctl status shows daemon status as JSON.",
        "- qlinkctl doctor summarizes readiness and failure/warning verdicts.",
        "- qlinkctl invite import <encoded-invite> stores a private mesh peer invite.",
        "- qlinkctl invite decode <code> inspects an invite without storing it.",
        "- qlinkctl peer list lists stored peers.",
        "- qlinkctl peer state returns peers and the selected peer as JSON.",
        "- qlinkctl peer clear clears the selected peer without revoking it.",
        "- qlinkctl peer select <peer-id> selects the single protected packet target.",
        "- qlinkctl peer trust <peer-id> explains trust source, mesh mode, and Dytallix requirements.",
        "- qlinkctl peer revoke <peer-id> marks a peer revoked; qlinkctl peer remove <peer-id> deletes it.",
        "- qlinkctl profile list shows installed game profiles.",
        "- qlinkctl profile status shows the active selection and profile policy flags.",
        "- qlinkctl profile select <profile-id> validates and activates one installed profile through qlinkd.",
        "- qlinkctl profile clear removes the active profile without deleting profile files.",
        "- qlinkctl game launch -- <command> [args...] starts the selected executable in a classified cgroup v2 scope.",
        "- qlinkctl service start|stop|restart requests a fixed qlinkd systemd operation through pkexec.",
        "- qlinkctl dytallix status reads stable-identity-v2 state without contacting qlinkd or loading a wallet.",
        "- qlinkctl dytallix register|update|suspend|reactivate|revoke performs one-shot wallet-authorized lifecycle operations while qlinkd remains wallet-free.",
        "- Dytallix mutation commands require an explicit owner-only keystore path; wallet seeds and private keys must never be passed through command arguments.",
        "",
        "Diagnostics and support",
        "- qlinkctl support-bundle --output <path> exports redacted daemon status and doctor output.",
        "- Share support bundles instead of raw logs when reporting bugs, tunnel issues, or security concerns.",
        "- Route security-sensitive reports through SECURITY.md and keep secrets, wallet seeds, tokens, and raw packet payloads out of tickets.",
        "",
        "Steam-safe routing",
        "{{STEAM_SAFE_BYPASS}}",
        "- QuantumLink protects selected game or party traffic through explicit game profile routing and keeps the default route off the VPN by default.",
        "- Activated mode owns qlink0, overlay routes, and qlink nftables state; teardown removes only owned state.",
        "- Validate Steam launch options, LAN discovery, voice chat, and anti-cheat behavior per title before broad use.",
        "",
        "Production gates",
        "- SteamOS remains pre-production until Deck validation proves real two-Deck transport, production-signed release artifacts, public Dytallix registry evidence, hardened rendezvous/relay evidence, and game compatibility validation.",
        "- Local planning, packet I/O initialization, or transport ready: no status is not proof of protected peer traffic.",
    ]
    .join("\n")
    .replace("{{STEAM_SAFE_BYPASS}}", &steam_safe_bypass_sentence())
}

/// Builds the Steam-safe disclosure line from the shared `qlink-game` bypass
/// policy so the operator guide and the daemon's enforced policy stay in sync.
fn steam_safe_bypass_sentence() -> String {
    let policy = qlink_game::profile::SteamBypassPolicy::default();
    format!(
        "- Steam-safe traffic bypass keeps {} traffic off QuantumLink by default (policy default action: {}).",
        format_bypass_categories(policy.bypass_categories()),
        policy.default_action()
    )
}

/// Renders bypass category slugs (`embedded_browser`) as a readable,
/// comma-and-`and` joined phrase (`... launcher, embedded browser, ...`).
fn format_bypass_categories(categories: &[String]) -> String {
    let readable: Vec<String> = categories
        .iter()
        .map(|category| category.replace('_', " "))
        .collect();
    match readable.split_last() {
        None => "no Steam".to_string(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{}, and {last}", rest.join(", ")),
    }
}

pub fn format_onboarding_checklist(status: &DaemonStatus, peer_store: &PeerStore) -> String {
    let now_unix = current_unix_seconds();
    let active_peer_count = peer_store.peers.iter().filter(|peer| !peer.revoked).count();
    let network_ready = matches!(
        (
            status.network.state,
            status.network.dry_run,
            status.network.ownership_record_present,
        ),
        (NetworkPlanState::Planned, true, false) | (NetworkPlanState::Applied, false, true)
    );
    let network_label = if status.network.state == NetworkPlanState::Applied
        && !status.network.dry_run
        && status.network.ownership_record_present
    {
        "Activated networking has teardown ownership"
    } else {
        "Dry-run planning healthy"
    };
    let peer_detail = match active_peer_count {
        0 => "no active peers imported".to_string(),
        1 => "1 active peer imported".to_string(),
        count => format!("{count} active peers imported"),
    };

    [
        "QuantumLink SteamOS Onboarding".to_string(),
        "".to_string(),
        checklist_line(
            true,
            "qlinkd reachable",
            "daemon status was returned from /run/quantumlink/qlinkd.sock",
        ),
        checklist_line(
            network_ready,
            network_label,
            "use qlinkctl doctor before switching from dry-run planning to --activate-network",
        ),
        checklist_line(
            active_peer_count > 0,
            "Import at least one peer invite",
            &peer_detail,
        ),
        checklist_line(
            status.data_plane.packet_io_available,
            "Packet I/O available",
            data_plane_state_label(status.data_plane.state),
        ),
        checklist_line(
            status.data_plane.transport_ready && status.data_plane.peer_session_ready,
            "Transport ready",
            "requires a live peer session; dry-run planning alone is not protected traffic",
        ),
        checklist_line(
            publication_ready(&status.publication, now_unix),
            "Signed peer record current",
            &publication_action(&status.publication, now_unix),
        ),
        checklist_line(
            dytallix_trust_ready(&status.publication),
            "Dytallix enrollment and peer trust ready",
            &dytallix_action(&status.publication),
        ),
        "".to_string(),
        "Next operator commands".to_string(),
        "- qlinkctl guide".to_string(),
        "- qlinkctl status".to_string(),
        "- qlinkctl doctor".to_string(),
        "- qlinkctl invite import <encoded-invite>".to_string(),
        "- qlinkctl peer select <peer-id>".to_string(),
        "- qlinkctl peer trust <peer-id>".to_string(),
        "- qlinkctl support-bundle --output <path>".to_string(),
        "".to_string(),
        "Identity provisioning boundary".to_string(),
        "- qlinkd accepts public identity references and trust decisions only; it never stores or uses wallet seeds, wallet private keys, or wallet signing credentials.".to_string(),
        "- Complete wallet enrollment in the external Dytallix wallet/provisioning workflow, then restart qlinkd and confirm publication with qlinkctl doctor.".to_string(),
        "".to_string(),
        "SteamOS release boundary".to_string(),
        "- SteamOS remains pre-production until two-Deck or equivalent SteamOS/Linux validation proves real protected peer traffic, production signing, public Dytallix registry evidence, hardened rendezvous/relay evidence, and game compatibility.".to_string(),
    ]
    .join("\n")
}

fn publication_ready(publication: &PublicationStatus, now_unix: u64) -> bool {
    publication.state == PublicationState::Active
        && publication
            .expires_at_unix
            .is_some_and(|expires_at| expires_at > now_unix)
}

fn dytallix_trust_ready(publication: &PublicationStatus) -> bool {
    let remote = remote_peer_trust(publication);
    if !remote.required && !publication.local_registry_binding.required {
        return true;
    }
    remote.required
        && remote.decision == DytallixTrustDecision::Accepted
        && remote.health == DytallixTrustHealth::Healthy
        && publication.local_registry_binding.required
        && publication.local_registry_binding.version
            == Some(DytallixBindingVersion::StableIdentityV2)
        && publication.local_registry_binding.state == LocalRegistryBindingState::Active
}

fn publication_action(publication: &PublicationStatus, now_unix: u64) -> String {
    if publication.state == PublicationState::Active
        && publication
            .expires_at_unix
            .is_some_and(|expires_at| expires_at > now_unix)
    {
        return "signed peer record is active and unexpired".to_string();
    }
    if publication
        .expires_at_unix
        .is_some_and(|expires_at| expires_at <= now_unix)
        || publication.state == PublicationState::Expired
    {
        return "record expired; keep protected transport disabled and restore publication"
            .to_string();
    }
    match publication.state {
        PublicationState::Failed => format!(
            "publication failed ({error}); keep protected transport disabled",
            error = publication
                .last_error
                .as_ref()
                .map(|error| publication_error_code_label(error.code))
                .unwrap_or("unknown")
        ),
        PublicationState::Degraded => {
            "publication degraded; restore refresh health before protected transport".to_string()
        }
        PublicationState::Publishing => {
            "publication is in progress; wait for an active unexpired record".to_string()
        }
        PublicationState::Active => {
            "active publication has no usable expiry; keep protected transport disabled".to_string()
        }
        PublicationState::NotStarted => {
            "publication not started; configure public identity references and restart qlinkd"
                .to_string()
        }
        PublicationState::Unknown => {
            "publication state unsupported; update qlinkctl before protected transport".to_string()
        }
        PublicationState::Expired => unreachable!("expired state handled above"),
    }
}

fn dytallix_action(publication: &PublicationStatus) -> String {
    let local = &publication.local_registry_binding;
    if local.required {
        match local.state {
            LocalRegistryBindingState::Active
                if local.version == Some(DytallixBindingVersion::StableIdentityV2) => {}
            LocalRegistryBindingState::Revoked => {
                return "local Dytallix identity revoked; keep protected transport disabled"
                    .to_string()
            }
            LocalRegistryBindingState::Suspended => {
                return "local Dytallix identity suspended; keep protected transport disabled"
                    .to_string()
            }
            LocalRegistryBindingState::Unavailable => {
                return "local Dytallix registry unavailable; keep protected transport disabled"
                    .to_string()
            }
            LocalRegistryBindingState::Active => {
                return "local identity uses an unsupported registry binding; migrate explicitly to stableIdentityV2"
                    .to_string()
            }
            _ => {
                return "local stable Dytallix enrollment is not active; keep protected transport disabled"
                    .to_string()
            }
        }
    }
    let remote = remote_peer_trust(publication);
    match (remote.required, remote.decision, remote.health) {
        (false, _, _) => "Dytallix trust is not required for this private mesh".to_string(),
        (true, DytallixTrustDecision::Accepted, DytallixTrustHealth::Healthy) => {
            "public identity is allowed and the trust lookup is healthy".to_string()
        }
        (true, DytallixTrustDecision::Denied, _) => {
            "public identity denied; keep protected transport disabled".to_string()
        }
        (true, DytallixTrustDecision::Revoked, _) => {
            "public identity revoked; keep protected transport disabled".to_string()
        }
        (true, DytallixTrustDecision::Suspended, _) => {
            "public identity suspended; keep protected transport disabled".to_string()
        }
        (true, DytallixTrustDecision::Mismatched, _) => {
            "public identity mismatch; keep protected transport disabled".to_string()
        }
        (true, _, DytallixTrustHealth::Unavailable) => {
            "Dytallix trust unavailable; keep protected transport disabled".to_string()
        }
        (true, _, DytallixTrustHealth::Degraded) => {
            "Dytallix trust degraded; restore healthy validation before protected transport"
                .to_string()
        }
        (true, DytallixTrustDecision::NotChecked | DytallixTrustDecision::Unknown, _) => {
            "required trust decision not checked; configure public identity references".to_string()
        }
        (true, DytallixTrustDecision::Accepted, _) => {
            "identity allowed but trust health is not confirmed; keep protected transport disabled"
                .to_string()
        }
    }
}

fn remote_peer_trust(publication: &PublicationStatus) -> &DytallixTrustStatus {
    if publication.remote_peer_trust != DytallixTrustStatus::default() {
        &publication.remote_peer_trust
    } else {
        &publication.dytallix
    }
}

fn checklist_line(complete: bool, title: &str, detail: &str) -> String {
    let marker = if complete { "[x]" } else { "[ ]" };
    format!("{marker} {title} - {detail}")
}

#[derive(Debug, thiserror::Error)]
pub enum PeerCommandError {
    #[error("{0}")]
    InviteDecode(#[from] qlink_proto::InviteDecodeError),
    #[error("invite expired at {expires_at_unix}; current time is {now_unix}")]
    ExpiredInvite { expires_at_unix: u64, now_unix: u64 },
    #[error("unknown peer {0}")]
    UnknownPeer(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
}

pub fn import_invite_to_store(
    state_dir: &Path,
    encoded_invite: &str,
    now_unix: u64,
) -> Result<StoredPeer, PeerCommandError> {
    let invite = InviteCode::decode(encoded_invite)?;
    if invite.expires_at_unix <= now_unix {
        return Err(PeerCommandError::ExpiredInvite {
            expires_at_unix: invite.expires_at_unix,
            now_unix,
        });
    }

    let peer = invite.stored_peer();
    let mut store = load_peer_store_for_state_dir(state_dir)?;
    store.upsert(peer.clone());
    store_peer_store_at(state_dir, &store)?;
    Ok(peer)
}

pub fn load_peer_store_for_state_dir(state_dir: &Path) -> Result<PeerStore, PeerCommandError> {
    load_peer_store_at(peer_store_path_from_state_dir(state_dir)).map_err(Into::into)
}

pub fn remove_peer_from_store(state_dir: &Path, peer_id: &str) -> Result<(), PeerCommandError> {
    let mut store = load_peer_store_for_state_dir(state_dir)?;
    if !store.remove(peer_id) {
        return Err(PeerCommandError::UnknownPeer(peer_id.to_string()));
    }
    store_peer_store_at(state_dir, &store)?;
    Ok(())
}

pub fn revoke_peer_in_store(state_dir: &Path, peer_id: &str) -> Result<(), PeerCommandError> {
    let mut store = load_peer_store_for_state_dir(state_dir)?;
    if !store.revoke(peer_id) {
        return Err(PeerCommandError::UnknownPeer(peer_id.to_string()));
    }
    store_peer_store_at(state_dir, &store)?;
    Ok(())
}

pub fn select_peer_in_store(
    state_dir: &Path,
    peer_id: &str,
    now_unix: u64,
) -> Result<(), PeerCommandError> {
    let mut store = load_peer_store_for_state_dir(state_dir)?;
    if !store.select(peer_id, now_unix) {
        return Err(PeerCommandError::UnknownPeer(peer_id.to_string()));
    }
    store_peer_store_at(state_dir, &store)?;
    Ok(())
}

pub fn clear_peer_selection_in_store(state_dir: &Path) -> Result<(), PeerCommandError> {
    let mut store = load_peer_store_for_state_dir(state_dir)?;
    store.clear_selection();
    store_peer_store_at(state_dir, &store)?;
    Ok(())
}

pub fn peer_from_store(state_dir: &Path, peer_id: &str) -> Result<StoredPeer, PeerCommandError> {
    load_peer_store_for_state_dir(state_dir)?
        .peers
        .into_iter()
        .find(|peer| peer.peer_id == peer_id)
        .ok_or_else(|| PeerCommandError::UnknownPeer(peer_id.to_string()))
}

pub fn format_peer_list(store: &PeerStore) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&store.peers)
}

pub fn format_peer_state(store: &PeerStore) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(store)
}

const PKEXEC_COMMAND: &str = "/usr/bin/pkexec";
const SERVICE_HELPER_COMMAND: &str = "/usr/local/libexec/quantumlink-service-control";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    pub fn parse(value: &str) -> Result<Self, ServiceCommandError> {
        match value {
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            "restart" => Ok(Self::Restart),
            _ => Err(ServiceCommandError::UnsupportedAction(value.to_string())),
        }
    }

    fn systemctl_verb(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceCommandError {
    #[error("unsupported service action `{0}`")]
    UnsupportedAction(String),
    #[error("failed to run the SteamOS service command: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("qlinkd service command failed: {0}")]
    Failed(String),
}

pub fn service_command_argv(action: ServiceAction) -> [&'static str; 2] {
    [SERVICE_HELPER_COMMAND, action.systemctl_verb()]
}

pub fn run_service_action(action: ServiceAction) -> Result<(), ServiceCommandError> {
    let output = std::process::Command::new(PKEXEC_COMMAND)
        .args(service_command_argv(action))
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(ServiceCommandError::Failed(if message.is_empty() {
        format!(
            "systemctl {} exited with {}",
            action.systemctl_verb(),
            output.status
        )
    } else {
        message
    }))
}

pub fn format_peer_trust(peer: &StoredPeer) -> String {
    format!(
        "peer: {peer_id}\n\
         mesh: {mesh}\n\
         mesh id: {mesh_id}\n\
         trust source: {trust_source}\n\
         dytallix: {dytallix}\n\
         revoked: {revoked}\n\
         expires: {expires}",
        peer_id = peer.peer_id,
        mesh = mesh_trust_mode_label(peer.trust_mode),
        mesh_id = peer.mesh_id,
        trust_source = peer.trust_source,
        dytallix = dytallix_label(peer.trust_mode),
        revoked = yes_no(peer.revoked),
        expires = format_unix_utc(peer.expires_at_unix),
    )
}

fn dytallix_label(mode: MeshTrustMode) -> &'static str {
    match mode {
        MeshTrustMode::PrivateFriends => "not required",
        MeshTrustMode::PublicDytallixRequired => "required (not checked)",
        MeshTrustMode::DevelopmentOptional => "optional development (not checked)",
    }
}

fn mesh_trust_mode_label(mode: MeshTrustMode) -> &'static str {
    match mode {
        MeshTrustMode::PrivateFriends => "privateFriends",
        MeshTrustMode::PublicDytallixRequired => "publicDytallixRequired",
        MeshTrustMode::DevelopmentOptional => "developmentOptional",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_unix_utc(seconds: u64) -> String {
    const SECONDS_PER_DAY: u64 = 86_400;
    let days = (seconds / SECONDS_PER_DAY).min(i64::MAX as u64) as i64;
    let seconds_of_day = seconds % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_unix_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_unix_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };

    (year, month as u32, day as u32)
}

pub fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleReleaseInfo {
    pub product: String,
    pub version: String,
    pub platform: String,
}

impl SupportBundleReleaseInfo {
    pub fn current() -> Self {
        Self {
            product: "QuantumLink SteamOS".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: std::env::consts::OS.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SupportBundleOptions {
    pub output: PathBuf,
    pub status: DaemonStatus,
    pub release_info: SupportBundleReleaseInfo,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionReport {
    pub private_key_material: usize,
    pub wallet_seed_material: usize,
    pub entitlement_tokens: usize,
    pub exact_peer_endpoints: usize,
    pub raw_packet_payloads: usize,
}

#[cfg(unix)]
pub fn status_from_daemon(socket: &Path) -> Result<DaemonStatus, ControlError> {
    request_daemon(socket, &DaemonControlRequest::Status)
}

#[cfg(unix)]
pub fn select_game_profile(
    socket: &Path,
    profile_id: impl Into<String>,
) -> Result<DaemonStatus, ControlError> {
    request_daemon(
        socket,
        &DaemonControlRequest::SelectGameProfile {
            profile_id: profile_id.into(),
        },
    )
}

#[cfg(unix)]
pub fn clear_game_profile(socket: &Path) -> Result<DaemonStatus, ControlError> {
    request_daemon(socket, &DaemonControlRequest::ClearGameProfile)
}

#[cfg(unix)]
pub fn begin_game_process(
    socket: &Path,
    profile_id: impl Into<String>,
    executable: impl Into<String>,
    session_id: impl Into<String>,
) -> Result<DaemonStatus, ControlError> {
    request_daemon(
        socket,
        &DaemonControlRequest::BeginGameProcess {
            profile_id: profile_id.into(),
            executable: executable.into(),
            session_id: session_id.into(),
        },
    )
}

#[cfg(unix)]
pub fn end_game_process(
    socket: &Path,
    session_id: impl Into<String>,
) -> Result<DaemonStatus, ControlError> {
    request_daemon(
        socket,
        &DaemonControlRequest::EndGameProcess {
            session_id: session_id.into(),
        },
    )
}

pub fn build_game_launch_plan(
    status: &GameProfileStatus,
    session_id: &str,
    qlinkctl_path: &Path,
    command: &str,
    command_args: &[String],
) -> Result<GameLaunchPlan, String> {
    let selected = status
        .selected_profile
        .as_ref()
        .ok_or_else(|| "select a game profile before launch".to_string())?;
    let profile = GameProfile {
        id: selected.id.clone(),
        display_name: selected.display_name.clone(),
        executables: selected.executables.clone(),
        udp_ports: selected.udp_ports.clone(),
        lan_discovery: selected.lan_discovery,
        voice_chat_safe: selected.voice_chat_safe,
        low_latency: selected.low_latency,
    };
    profile.validate()?;
    GameLaunchPlan::new(&profile, session_id, qlinkctl_path, command, command_args)
}

pub fn validate_game_launch_capabilities(
    capabilities: &SteamOsRuntimeCapabilities,
) -> Result<(), String> {
    for (name, capability) in [
        ("cgroup v2", &capabilities.cgroup_v2),
        ("nftables cgroup v2", &capabilities.nftables_cgroup_v2),
        ("TUN", &capabilities.tun),
        ("systemd user scopes", &capabilities.systemd_user_scopes),
    ] {
        if capability.state != RuntimeCapabilityState::Supported {
            return Err(format!(
                "game launch blocked: {name} is {}{}",
                runtime_capability_state_label(capability.state),
                capability
                    .detail
                    .as_deref()
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn request_daemon(
    socket: &Path,
    request: &DaemonControlRequest,
) -> Result<DaemonStatus, ControlError> {
    let mut stream = UnixStream::connect(socket).map_err(|source| ControlError::Unavailable {
        path: socket.display().to_string(),
        source,
    })?;
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line)?;
    parse_status_response(line.trim_end())
}

pub fn format_status(status: &DaemonStatus) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(status)
}

pub fn format_game_profile_status(status: &GameProfileStatus) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(status)
}

pub fn format_doctor(status: &DaemonStatus) -> String {
    format_doctor_at(status, current_unix_seconds())
}

fn format_doctor_at(status: &DaemonStatus, now_unix: u64) -> String {
    let network = &status.network;
    let data_plane = &status.data_plane;
    let publication = &status.publication;
    let game_profile = &status.game_profile;
    let phase = phase_label(status.phase);
    let state = network_state_label(network.state);
    let data_plane_state = data_plane_state_label(data_plane.state);
    let mode = if network.dry_run {
        "dry-run"
    } else if network.state == NetworkPlanState::Applied {
        "activated"
    } else {
        "unknown"
    };
    let ownership_record = if network.ownership_record_present {
        "present"
    } else {
        "absent"
    };
    let apply_error = network.error.as_deref().unwrap_or("none");
    let network_verdict = match (
        network.state,
        network.dry_run,
        network.ownership_record_present,
    ) {
        (NetworkPlanState::ApplyFailed, _, _) => match network.error.as_deref() {
            Some(error) => format!("FAIL - network apply failed: {error}"),
            None => "FAIL - network apply failed".to_string(),
        },
        (NetworkPlanState::Applied, _, false) => {
            "FAIL - applied networking without ownership record".to_string()
        }
        (NetworkPlanState::Planned, true, false) => "OK - dry-run planning healthy".to_string(),
        (NetworkPlanState::Applied, false, true) => {
            "OK - activated networking has teardown ownership".to_string()
        }
        (NetworkPlanState::NotStarted, _, true)
        | (NetworkPlanState::Planned, _, true)
        | (_, true, true) => "WARN - ownership record present; teardown may be pending".to_string(),
        _ => format!("WARN - network state {state} with mode {mode}"),
    };
    let data_plane_verdict =
        data_plane_health_verdict(data_plane.state, data_plane.error.as_deref());
    let publication_verdict = publication_health_verdict(
        publication,
        now_unix,
        network.state == NetworkPlanState::Applied && !network.dry_run,
    );
    let profile_verdict = game_profile
        .port_enforcement
        .restart_required
        .then(|| "WARN - service restart required to apply game profile ports".to_string());
    let classification_verdict = (game_profile.process_classification.state
        == GameProcessClassificationState::ApplyFailed)
        .then(|| {
            format!(
                "FAIL - game process classification failed: {}",
                game_profile
                    .process_classification
                    .error
                    .as_deref()
                    .unwrap_or("unknown error")
            )
        });
    let capability_verdict = runtime_capability_verdict(&status.runtime_capabilities);
    let verdict = match status.phase {
        ConnectionPhase::Failed => "FAIL - daemon phase failed".to_string(),
        _ if data_plane_verdict
            .as_deref()
            .is_some_and(|verdict| verdict.starts_with("FAIL")) =>
        {
            data_plane_verdict.unwrap()
        }
        _ if network_verdict.starts_with("FAIL") => network_verdict,
        _ if capability_verdict
            .as_deref()
            .is_some_and(|verdict| verdict.starts_with("FAIL")) =>
        {
            capability_verdict.clone().unwrap()
        }
        _ if publication_verdict.starts_with("FAIL") => publication_verdict,
        _ if classification_verdict.is_some() => classification_verdict.unwrap(),
        ConnectionPhase::Degraded => "WARN - daemon phase degraded".to_string(),
        _ if data_plane_verdict
            .as_deref()
            .is_some_and(|verdict| verdict.starts_with("WARN")) =>
        {
            data_plane_verdict.unwrap()
        }
        _ if network_verdict.starts_with("WARN") => network_verdict,
        _ if publication_verdict.starts_with("WARN") => publication_verdict,
        _ if capability_verdict
            .as_deref()
            .is_some_and(|verdict| verdict.starts_with("WARN")) =>
        {
            capability_verdict.unwrap()
        }
        _ if profile_verdict.is_some() => profile_verdict.unwrap(),
        _ => network_verdict,
    };

    format!(
        "verdict: {verdict}\n\
         phase: {phase}\n\
         kill switch: {kill_switch}\n\
         network state: {state}\n\
         mode: {mode}\n\
         interface: {interface}\n\
         route mode: {route_mode}\n\
         protected CIDR: {protected_cidr}\n\
         ownership record: {ownership_record}\n\
         apply error: {apply_error}\n\
         data-plane state: {data_plane_state}\n\
         data-plane interface: {data_plane_interface}\n\
         packet I/O: {packet_io}\n\
         transport ready: {transport_ready}\n\
         transport path: {transport_path}\n\
         peer session: {peer_session}\n\
         last transport error: {last_transport_error}\n\
         packet counters: observed={observed_packets} queued={queued_packets} dropped={dropped_packets} emitted={emitted_packets} accepted={accepted_packets} rejected={rejected_packets} transportErrors={transport_errors}\n\
         data-plane error: {data_plane_error}\n\
         game profile: {selected_game_profile}\n\
         applied game profile: {applied_game_profile}\n\
         game profile port enforcement: {game_profile_port_enforcement}\n\
         enforced UDP ports: {enforced_udp_ports}\n\
         game process classification: {game_process_classification}\n\
         classified executable: {classified_executable}\n\
         game cgroup unit: {game_cgroup_unit}\n\
         classification error: {classification_error}\n\
         game profile restart required: {game_profile_restart_required}\n\
         game profile warning: {game_profile_warning}\n\
         capability cgroup v2: {capability_cgroup_v2}\n\
         capability nftables cgroup v2: {capability_nftables_cgroup_v2}\n\
         capability TUN: {capability_tun}\n\
         capability systemd user scopes: {capability_systemd_user_scopes}\n\
         capability PolicyKit: {capability_policykit}\n\
         capability logind session: {capability_logind_session}\n\
         publication state: {publication_state}\n\
         publication sequence: {publication_sequence}\n\
         publication expiry (unix): {publication_expiry}\n\
         publication last success (unix): {publication_last_success}\n\
         publication last attempt (unix): {publication_last_attempt}\n\
         publication error: {publication_error}\n\
         local Dytallix binding: {local_registry_binding}\n\
         local Dytallix revision: {local_registry_revision}\n\
         remote Dytallix trust decision: {dytallix_decision}\n\
         remote Dytallix trust health: {dytallix_health}\n\
         action: {publication_action}\n\
         identity boundary: qlinkd never owns wallet secrets; provision externally and configure public identity references only",
        kill_switch = if status.kill_switch {
            "enabled"
        } else {
            "disabled"
        },
        interface = network.interface_name.as_deref().unwrap_or("unknown"),
        route_mode = network
            .route_mode
            .map(route_mode_label)
            .unwrap_or("unknown"),
        protected_cidr = network.protected_cidr.as_deref().unwrap_or("unknown"),
        data_plane_interface = data_plane.interface_name.as_deref().unwrap_or("unknown"),
        packet_io = if data_plane.packet_io_available {
            "available"
        } else {
            "unavailable"
        },
        transport_ready = if data_plane.transport_ready {
            "yes"
        } else {
            "no"
        },
        transport_path = data_plane
            .transport_path
            .map(path_kind_label)
            .unwrap_or("unknown"),
        peer_session = if data_plane.peer_session_ready {
            "ready"
        } else {
            "not ready"
        },
        last_transport_error = data_plane
            .last_transport_error
            .as_deref()
            .unwrap_or("none"),
        observed_packets = data_plane.metrics.observed_packets,
        queued_packets = data_plane.metrics.queued_packets,
        dropped_packets = data_plane.metrics.dropped_packets,
        emitted_packets = data_plane.metrics.emitted_packets,
        accepted_packets = data_plane.metrics.accepted_packets,
        rejected_packets = data_plane.metrics.rejected_packets,
        transport_errors = data_plane.metrics.transport_errors,
        data_plane_error = data_plane.error.as_deref().unwrap_or("none"),
        selected_game_profile = game_profile
            .selected_profile
            .as_ref()
            .map(|profile| profile.id.as_str())
            .unwrap_or("none"),
        applied_game_profile = game_profile
            .port_enforcement
            .profile_id
            .as_deref()
            .unwrap_or("none"),
        game_profile_port_enforcement = game_profile_port_enforcement_label(
            game_profile.port_enforcement.state,
        ),
        enforced_udp_ports = if game_profile.port_enforcement.udp_ports.is_empty() {
            "none".to_string()
        } else {
            game_profile
                .port_enforcement
                .udp_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        },
        game_process_classification = game_process_classification_label(
            game_profile.process_classification.state,
        ),
        classified_executable = game_profile
            .process_classification
            .executable
            .as_deref()
            .unwrap_or("none"),
        game_cgroup_unit = game_profile
            .process_classification
            .cgroup_unit
            .as_deref()
            .unwrap_or("none"),
        classification_error = game_profile
            .process_classification
            .error
            .as_deref()
            .unwrap_or("none"),
        game_profile_restart_required = if game_profile.port_enforcement.restart_required {
            "yes"
        } else {
            "no"
        },
        game_profile_warning = game_profile.selection_warning.as_deref().unwrap_or("none"),
        capability_cgroup_v2 = runtime_capability_label(&status.runtime_capabilities.cgroup_v2),
        capability_nftables_cgroup_v2 =
            runtime_capability_label(&status.runtime_capabilities.nftables_cgroup_v2),
        capability_tun = runtime_capability_label(&status.runtime_capabilities.tun),
        capability_systemd_user_scopes =
            runtime_capability_label(&status.runtime_capabilities.systemd_user_scopes),
        capability_policykit = runtime_capability_label(&status.runtime_capabilities.policykit),
        capability_logind_session =
            runtime_capability_label(&status.runtime_capabilities.logind_session),
        publication_state = publication_state_label(publication.state),
        publication_sequence = optional_u64_label(publication.sequence),
        publication_expiry = optional_u64_label(publication.expires_at_unix),
        publication_last_success = optional_u64_label(publication.last_success_at_unix),
        publication_last_attempt = optional_u64_label(publication.last_attempt_at_unix),
        publication_error = publication
            .last_error
            .as_ref()
            .map(|error| publication_error_code_label(error.code))
            .unwrap_or("none"),
        local_registry_binding =
            local_registry_binding_state_label(publication.local_registry_binding.state),
        local_registry_revision =
            optional_u64_label(publication.local_registry_binding.identity_revision),
        dytallix_decision = dytallix_decision_label(remote_peer_trust(publication).decision),
        dytallix_health = dytallix_health_label(remote_peer_trust(publication).health),
        publication_action = combined_publication_action(publication, now_unix),
    )
}

fn runtime_capability_verdict(capabilities: &SteamOsRuntimeCapabilities) -> Option<String> {
    for (name, capability) in [
        ("cgroup v2", &capabilities.cgroup_v2),
        ("nftables cgroup v2", &capabilities.nftables_cgroup_v2),
        ("TUN", &capabilities.tun),
        ("systemd user scopes", &capabilities.systemd_user_scopes),
    ] {
        if matches!(
            capability.state,
            RuntimeCapabilityState::Unsupported | RuntimeCapabilityState::Unavailable
        ) {
            return Some(format!(
                "FAIL - {name} capability is {}{}",
                runtime_capability_state_label(capability.state),
                capability
                    .detail
                    .as_deref()
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            ));
        }
    }
    for (name, capability) in [
        ("PolicyKit", &capabilities.policykit),
        ("logind session", &capabilities.logind_session),
    ] {
        if matches!(
            capability.state,
            RuntimeCapabilityState::Unsupported | RuntimeCapabilityState::Unavailable
        ) {
            return Some(format!(
                "WARN - {name} capability is {}{}",
                runtime_capability_state_label(capability.state),
                capability
                    .detail
                    .as_deref()
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            ));
        }
    }
    None
}

fn runtime_capability_label(capability: &RuntimeCapabilityStatus) -> String {
    match capability.detail.as_deref() {
        Some(detail) => format!(
            "{} ({detail})",
            runtime_capability_state_label(capability.state)
        ),
        None => runtime_capability_state_label(capability.state).to_string(),
    }
}

fn runtime_capability_state_label(state: RuntimeCapabilityState) -> &'static str {
    match state {
        RuntimeCapabilityState::NotChecked => "not checked",
        RuntimeCapabilityState::Supported => "supported",
        RuntimeCapabilityState::Unsupported => "unsupported",
        RuntimeCapabilityState::Unavailable => "unavailable",
    }
}

#[cfg(unix)]
pub fn write_support_bundle(options: SupportBundleOptions) -> std::io::Result<()> {
    let staging_dir = unique_support_bundle_staging_dir();
    std::fs::create_dir_all(&staging_dir)?;

    let result = (|| {
        let mut report = RedactionReport::default();
        let status_json = serde_json::to_string_pretty(&options.status).map_err(json_to_io)?;
        write_bundle_file(
            &staging_dir,
            "status.json",
            &redact_diagnostic_text(&status_json, &mut report),
        )?;
        write_bundle_file(
            &staging_dir,
            "doctor.txt",
            &redact_diagnostic_text(&format_doctor(&options.status), &mut report),
        )?;
        write_bundle_file(
            &staging_dir,
            "network-plan.txt",
            &redact_diagnostic_text(&plan_text(&options.status.network.commands), &mut report),
        )?;
        write_bundle_file(
            &staging_dir,
            "nftables-plan.txt",
            &redact_diagnostic_text(
                &plan_text(&options.status.network.nftables_rules),
                &mut report,
            ),
        )?;
        let release_info = serde_json::json!({
            "product": options.release_info.product,
            "version": options.release_info.version,
            "platform": options.release_info.platform,
        });
        write_bundle_file(
            &staging_dir,
            "release-info.json",
            &redact_diagnostic_text(
                &serde_json::to_string_pretty(&release_info).map_err(json_to_io)?,
                &mut report,
            ),
        )?;
        write_bundle_file(
            &staging_dir,
            "redaction-report.json",
            &serde_json::to_string_pretty(&report).map_err(json_to_io)?,
        )?;

        if let Some(parent) = options.output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        archive_staging_dir(&staging_dir, &options.output)
    })();

    let cleanup = std::fs::remove_dir_all(&staging_dir);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
    }
}

#[cfg(not(unix))]
pub fn write_support_bundle(_options: SupportBundleOptions) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "support bundles are only supported on Unix-like SteamOS hosts",
    ))
}

fn json_to_io(error: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

fn write_bundle_file(staging_dir: &Path, name: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(staging_dir.join(name), contents)
}

fn plan_text(lines: &[String]) -> String {
    if lines.is_empty() {
        "none\n".to_string()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

#[cfg(unix)]
fn unique_support_bundle_staging_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "qlinkctl-support-bundle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

#[cfg(unix)]
fn archive_staging_dir(staging_dir: &Path, output: &Path) -> std::io::Result<()> {
    let entries = [
        "status.json",
        "doctor.txt",
        "network-plan.txt",
        "nftables-plan.txt",
        "release-info.json",
        "redaction-report.json",
    ];
    let mut tar = Command::new("tar")
        .arg("-C")
        .arg(staging_dir)
        .arg("-cf")
        .arg("-")
        .args(entries)
        .stdout(Stdio::piped())
        .spawn()?;
    let tar_stdout = tar
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture tar stdout"))?;
    let mut zstd = Command::new("zstd")
        .arg("-q")
        .arg("-f")
        .arg("-o")
        .arg(output)
        .arg("-")
        .stdin(Stdio::from(tar_stdout))
        .spawn()?;
    let zstd_status = zstd.wait()?;
    let tar_status = tar.wait()?;

    if !tar_status.success() {
        return Err(std::io::Error::other(format!(
            "tar failed with status {tar_status}"
        )));
    }
    if !zstd_status.success() {
        return Err(std::io::Error::other(format!(
            "zstd failed with status {zstd_status}"
        )));
    }
    Ok(())
}

fn redact_diagnostic_text(input: &str, report: &mut RedactionReport) -> String {
    let mut redacted = input.to_string();
    redacted = replace_counted(
        &redacted,
        "PRIVATE_KEY_MATERIAL",
        "[REDACTED-SECRET]",
        &mut report.private_key_material,
    );
    redacted = replace_counted(
        &redacted,
        "private key",
        "[REDACTED-SECRET]",
        &mut report.private_key_material,
    );
    redacted = replace_counted(
        &redacted,
        "wallet seed phrase",
        "[REDACTED-SECRET]",
        &mut report.wallet_seed_material,
    );
    redacted = replace_counted(
        &redacted,
        "wallet seed",
        "[REDACTED-SECRET]",
        &mut report.wallet_seed_material,
    );
    redacted = replace_counted(
        &redacted,
        "entitlement_token=secret",
        "entitlement_token=[REDACTED-SECRET]",
        &mut report.entitlement_tokens,
    );
    redacted = replace_counted(
        &redacted,
        "raw_packet_payload",
        "[REDACTED-RAW-PACKET-PAYLOAD]",
        &mut report.raw_packet_payloads,
    );
    redact_ipv4_socket_endpoints(&redacted, report)
}

fn replace_counted(input: &str, needle: &str, replacement: &str, count: &mut usize) -> String {
    let matches = input.matches(needle).count();
    *count += matches;
    input.replace(needle, replacement)
}

fn redact_ipv4_socket_endpoints(input: &str, report: &mut RedactionReport) -> String {
    let mut output = String::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if let Some(end) = ipv4_socket_endpoint_end(input, index) {
            output.push_str("[REDACTED-ENDPOINT]");
            report.exact_peer_endpoints += 1;
            index = end;
        } else {
            let ch = input[index..]
                .chars()
                .next()
                .expect("index is on a char boundary");
            output.push(ch);
            index += ch.len_utf8();
        }
    }
    output
}

fn ipv4_socket_endpoint_end(input: &str, start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    if start > 0 && bytes[start - 1].is_ascii_digit() {
        return None;
    }

    let mut index = start;
    for octet_index in 0..4 {
        let octet_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if octet_start == index || index - octet_start > 3 {
            return None;
        }
        let octet = input[octet_start..index].parse::<u16>().ok()?;
        if octet > 255 {
            return None;
        }
        if octet_index < 3 {
            if bytes.get(index).copied() != Some(b'.') {
                return None;
            }
            index += 1;
        }
    }

    if bytes.get(index).copied() != Some(b':') {
        return None;
    }
    index += 1;
    let port_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if port_start == index {
        return None;
    }
    if index < bytes.len() && bytes[index].is_ascii_digit() {
        return None;
    }
    Some(index)
}

fn phase_label(phase: ConnectionPhase) -> &'static str {
    match phase {
        ConnectionPhase::Idle => "idle",
        ConnectionPhase::Preparing => "preparing",
        ConnectionPhase::Connecting => "connecting",
        ConnectionPhase::Connected => "connected",
        ConnectionPhase::Degraded => "degraded",
        ConnectionPhase::Failed => "failed",
    }
}

fn network_state_label(state: NetworkPlanState) -> &'static str {
    match state {
        NetworkPlanState::NotStarted => "notStarted",
        NetworkPlanState::Planned => "planned",
        NetworkPlanState::ApplyFailed => "applyFailed",
        NetworkPlanState::Applied => "applied",
    }
}

fn game_profile_port_enforcement_label(state: GameProfilePortEnforcementState) -> &'static str {
    match state {
        GameProfilePortEnforcementState::NotApplicable => "notApplicable",
        GameProfilePortEnforcementState::Planned => "planned",
        GameProfilePortEnforcementState::FailClosed => "failClosed",
        GameProfilePortEnforcementState::Applied => "applied",
        GameProfilePortEnforcementState::ApplyFailed => "applyFailed",
    }
}

fn game_process_classification_label(state: GameProcessClassificationState) -> &'static str {
    match state {
        GameProcessClassificationState::NotApplicable => "notApplicable",
        GameProcessClassificationState::FailClosed => "failClosed",
        GameProcessClassificationState::Armed => "armed",
        GameProcessClassificationState::Active => "active",
        GameProcessClassificationState::ApplyFailed => "applyFailed",
    }
}

fn data_plane_state_label(state: DataPlaneState) -> &'static str {
    match state {
        DataPlaneState::NotStarted => "notStarted",
        DataPlaneState::Starting => "starting",
        DataPlaneState::Ready => "ready",
        DataPlaneState::Degraded => "degraded",
        DataPlaneState::Failed => "failed",
    }
}

fn data_plane_health_verdict(state: DataPlaneState, error: Option<&str>) -> Option<String> {
    match (state, error) {
        (DataPlaneState::Failed, Some(error)) => Some(format!("FAIL - data plane failed: {error}")),
        (DataPlaneState::Failed, None) => Some("FAIL - data plane failed".to_string()),
        (DataPlaneState::Degraded, Some(error)) => {
            Some(format!("WARN - data plane degraded: {error}"))
        }
        (DataPlaneState::Degraded, None) => Some("WARN - data plane degraded".to_string()),
        _ => None,
    }
}

fn publication_health_verdict(
    publication: &PublicationStatus,
    now_unix: u64,
    protected_network_active: bool,
) -> String {
    if publication
        .expires_at_unix
        .is_some_and(|expires_at| expires_at <= now_unix)
        || publication.state == PublicationState::Expired
    {
        return "FAIL - signed peer record expired; protected transport must remain disabled"
            .to_string();
    }
    let remote = remote_peer_trust(publication);
    if remote.required || publication.local_registry_binding.required {
        if !publication.local_registry_binding.required {
            return "FAIL - required local Dytallix enrollment status is unavailable".to_string();
        }
        if publication.local_registry_binding.version
            != Some(DytallixBindingVersion::StableIdentityV2)
        {
            return "FAIL - local Dytallix enrollment is not stableIdentityV2".to_string();
        }
        match publication.local_registry_binding.state {
            LocalRegistryBindingState::Active => {}
            LocalRegistryBindingState::Revoked => {
                return "FAIL - local Dytallix identity revoked".to_string()
            }
            LocalRegistryBindingState::Suspended => {
                return "FAIL - local Dytallix identity suspended".to_string()
            }
            LocalRegistryBindingState::Unavailable => {
                return "FAIL - local Dytallix registry unavailable".to_string()
            }
            state => {
                return format!(
                    "FAIL - local Dytallix enrollment is {}",
                    local_registry_binding_state_label(state)
                )
            }
        }
        if !remote.required {
            return "FAIL - required remote Dytallix trust status is unavailable".to_string();
        }
        match remote.decision {
            DytallixTrustDecision::Denied => {
                return "FAIL - required remote Dytallix identity denied".to_string()
            }
            DytallixTrustDecision::Revoked => {
                return "FAIL - required remote Dytallix identity revoked".to_string()
            }
            DytallixTrustDecision::Suspended => {
                return "FAIL - required remote Dytallix identity suspended".to_string()
            }
            DytallixTrustDecision::Mismatched => {
                return "FAIL - required remote Dytallix identity mismatched".to_string()
            }
            DytallixTrustDecision::NotChecked | DytallixTrustDecision::Unknown => {
                return "FAIL - required remote Dytallix trust decision is unavailable".to_string()
            }
            DytallixTrustDecision::Accepted => {}
        }
        if remote.health == DytallixTrustHealth::Unavailable {
            return "FAIL - required remote Dytallix trust service unavailable".to_string();
        }
    }
    match publication.state {
        PublicationState::Failed => format!(
            "FAIL - peer record publication failed: {error}",
            error = publication
                .last_error
                .as_ref()
                .map(|error| publication_error_code_label(error.code))
                .unwrap_or("unknown")
        ),
        PublicationState::Degraded => "WARN - peer record publication degraded".to_string(),
        PublicationState::Publishing => "WARN - peer record publication in progress".to_string(),
        PublicationState::NotStarted if protected_network_active => {
            "FAIL - protected networking active without peer record publication".to_string()
        }
        PublicationState::NotStarted => "WARN - peer record publication not started".to_string(),
        PublicationState::Unknown => {
            "FAIL - peer record publication state is unsupported".to_string()
        }
        PublicationState::Active if publication.expires_at_unix.is_none() => {
            "FAIL - active peer record has no expiry".to_string()
        }
        PublicationState::Active
            if remote.required && remote.health != DytallixTrustHealth::Healthy =>
        {
            "WARN - required Dytallix trust health degraded".to_string()
        }
        PublicationState::Active => "OK - signed peer record current".to_string(),
        PublicationState::Expired => unreachable!("expired state handled above"),
    }
}

fn local_registry_binding_state_label(state: LocalRegistryBindingState) -> &'static str {
    match state {
        LocalRegistryBindingState::NotConfigured => "notConfigured",
        LocalRegistryBindingState::Pending => "pending",
        LocalRegistryBindingState::Active => "active",
        LocalRegistryBindingState::Missing => "missing",
        LocalRegistryBindingState::Revoked => "revoked",
        LocalRegistryBindingState::Suspended => "suspended",
        LocalRegistryBindingState::Mismatched => "mismatched",
        LocalRegistryBindingState::Expired => "expired",
        LocalRegistryBindingState::Unavailable => "unavailable",
        LocalRegistryBindingState::Unknown => "unknown",
    }
}

fn combined_publication_action(publication: &PublicationStatus, now_unix: u64) -> String {
    if !dytallix_trust_ready(publication) {
        dytallix_action(publication)
    } else {
        publication_action(publication, now_unix)
    }
}

fn optional_u64_label(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn publication_state_label(state: PublicationState) -> &'static str {
    match state {
        PublicationState::NotStarted => "notStarted",
        PublicationState::Publishing => "publishing",
        PublicationState::Active => "active",
        PublicationState::Degraded => "degraded",
        PublicationState::Failed => "failed",
        PublicationState::Expired => "expired",
        PublicationState::Unknown => "unknown",
    }
}

fn publication_error_code_label(code: PublicationErrorCode) -> &'static str {
    match code {
        PublicationErrorCode::PublishRejected => "publishRejected",
        PublicationErrorCode::AuthenticationFailed => "authenticationFailed",
        PublicationErrorCode::TrustUnavailable => "trustUnavailable",
        PublicationErrorCode::InvalidResponse => "invalidResponse",
        PublicationErrorCode::Transport => "transport",
        PublicationErrorCode::Expired => "expired",
        PublicationErrorCode::Internal => "internal",
        PublicationErrorCode::Unknown => "unknown",
    }
}

fn dytallix_decision_label(decision: DytallixTrustDecision) -> &'static str {
    match decision {
        DytallixTrustDecision::NotChecked => "notChecked",
        DytallixTrustDecision::Accepted => "accepted",
        DytallixTrustDecision::Denied => "denied",
        DytallixTrustDecision::Revoked => "revoked",
        DytallixTrustDecision::Suspended => "suspended",
        DytallixTrustDecision::Mismatched => "mismatched",
        DytallixTrustDecision::Unknown => "unknown",
    }
}

fn dytallix_health_label(health: DytallixTrustHealth) -> &'static str {
    match health {
        DytallixTrustHealth::Unknown => "unknown",
        DytallixTrustHealth::Healthy => "healthy",
        DytallixTrustHealth::Degraded => "degraded",
        DytallixTrustHealth::Unavailable => "unavailable",
    }
}

fn route_mode_label(route_mode: RouteMode) -> &'static str {
    match route_mode {
        RouteMode::GameOnly => "gameOnly",
        RouteMode::ProtectedPrefixesOnly => "protectedPrefixesOnly",
        RouteMode::FullTunnel => "fullTunnel",
    }
}

fn path_kind_label(path: PathKind) -> &'static str {
    match path {
        PathKind::Direct => "direct",
        PathKind::Relay => "relay",
        PathKind::Probing => "probing",
        PathKind::Unavailable => "unavailable",
    }
}

fn parse_status_response(line: &str) -> Result<DaemonStatus, ControlError> {
    let value = serde_json::from_str::<serde_json::Value>(line)?;
    if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        let message = value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown daemon error")
            .to_string();
        return Err(ControlError::Daemon(message));
    }
    serde_json::from_value(value).map_err(ControlError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlink_proto::{
        DataPlaneState, DataPlaneStatus, DytallixTrustStatus, InviteCode, MeshTrustMode,
        NetworkPlanState, NetworkStatus, PacketPumpMetrics, PublicationErrorStatus, RouteMode,
        StoredPeer,
    };
    use std::path::PathBuf;

    fn status_with_network(
        state: NetworkPlanState,
        dry_run: bool,
        ownership_record_present: bool,
        error: Option<&str>,
    ) -> DaemonStatus {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run,
            ownership_record_present,
            commands: Vec::new(),
            nftables_rules: Vec::new(),
            error: error.map(str::to_string),
        };
        status
    }

    fn packet_pump_metrics() -> PacketPumpMetrics {
        PacketPumpMetrics {
            observed_packets: 18,
            queued_packets: 17,
            dropped_packets: 1,
            emitted_packets: 16,
            accepted_packets: 15,
            rejected_packets: 2,
            transport_errors: 1,
        }
    }

    fn status_with_data_plane(
        state: DataPlaneState,
        packet_io_available: bool,
        transport_ready: bool,
        error: Option<&str>,
    ) -> DaemonStatus {
        let mut status = status_with_network(NetworkPlanState::Planned, true, false, None);
        status.data_plane = DataPlaneStatus {
            interface_name: Some("qlink0".to_string()),
            state,
            packet_io_available,
            transport_ready,
            transport_path: if transport_ready {
                Some(PathKind::Direct)
            } else {
                Some(PathKind::Unavailable)
            },
            peer_session_ready: transport_ready,
            last_transport_error: None,
            metrics: packet_pump_metrics(),
            error: error.map(str::to_string),
        };
        status
    }

    fn healthy_publication(required: bool) -> PublicationStatus {
        let remote_peer_trust = DytallixTrustStatus {
            required,
            decision: if required {
                DytallixTrustDecision::Accepted
            } else {
                DytallixTrustDecision::NotChecked
            },
            health: if required {
                DytallixTrustHealth::Healthy
            } else {
                DytallixTrustHealth::Unknown
            },
        };
        PublicationStatus {
            state: PublicationState::Active,
            sequence: Some(9),
            expires_at_unix: Some(4_102_444_800),
            last_success_at_unix: Some(1_767_139_200),
            last_attempt_at_unix: Some(1_767_139_200),
            last_error: None,
            dytallix: remote_peer_trust.clone(),
            remote_peer_trust,
            local_registry_binding: qlink_proto::LocalRegistryBindingStatus {
                required,
                version: required.then_some(qlink_proto::DytallixBindingVersion::StableIdentityV2),
                state: if required {
                    qlink_proto::LocalRegistryBindingState::Active
                } else {
                    qlink_proto::LocalRegistryBindingState::NotConfigured
                },
                identity_revision: required.then_some(1),
                checked_at_unix: required.then_some(1_767_139_200),
                last_error: None,
            },
        }
    }

    fn supported_runtime_capabilities() -> SteamOsRuntimeCapabilities {
        SteamOsRuntimeCapabilities {
            cgroup_v2: RuntimeCapabilityStatus::supported(),
            nftables_cgroup_v2: RuntimeCapabilityStatus::supported(),
            tun: RuntimeCapabilityStatus::supported(),
            systemd_user_scopes: RuntimeCapabilityStatus::supported(),
            policykit: RuntimeCapabilityStatus::supported(),
            logind_session: RuntimeCapabilityStatus::supported(),
        }
    }

    #[test]
    fn format_guide_explains_steamos_modes_and_gates() {
        let guide = format_guide();
        assert!(guide.contains("QuantumLink SteamOS Guide"));
        assert!(guide.contains("planning-only recovery"));
        assert!(guide.contains("systemd"));
        assert!(guide.contains("--activate-network"));
        assert!(guide.contains("qlink0"));
        assert!(guide.contains("nftables"));
        assert!(guide.contains("Steam-safe traffic"));
        assert!(guide.contains("game profile"));
        assert!(guide.contains("Deck validation"));
        assert!(guide.contains("transport ready"));
        assert!(guide.contains("pre-production"));
    }

    #[test]
    fn steam_safe_disclosure_is_derived_from_the_shared_bypass_policy() {
        let guide = format_guide();
        // Every category the daemon enforces must appear in the operator
        // disclosure — including `updates` and `login`, which the previous
        // hardcoded sentence omitted. The guide is now generated from the same
        // `qlink-game` policy the daemon validates against.
        let policy = qlink_game::profile::SteamBypassPolicy::default();
        for category in policy.bypass_categories() {
            let readable = category.replace('_', " ");
            assert!(
                guide.contains(&readable),
                "guide should disclose bypass category '{readable}'"
            );
        }
        assert!(guide.contains("embedded browser"));
        assert!(guide.contains("updates"));
        assert!(guide.contains("login"));
        assert!(guide.contains("policy default action: bypass"));
        assert!(!guide.contains("{{STEAM_SAFE_BYPASS}}"));
    }

    #[test]
    fn format_guide_lists_operator_command_groups() {
        let guide = format_guide();
        assert!(guide.contains("qlinkctl status"));
        assert!(guide.contains("qlinkctl doctor"));
        assert!(guide.contains("qlinkctl invite import"));
        assert!(guide.contains("qlinkctl peer trust"));
        assert!(guide.contains("qlinkctl profile select"));
        assert!(guide.contains("qlinkctl support-bundle --output"));
    }

    #[test]
    fn format_onboarding_checklist_shows_pending_peer_import_and_safe_next_commands() {
        let status = status_with_network(NetworkPlanState::Planned, true, false, None);
        let checklist = format_onboarding_checklist(&status, &PeerStore::default());
        assert!(checklist.contains("QuantumLink SteamOS Onboarding"));
        assert!(checklist.contains("[x] qlinkd reachable"));
        assert!(checklist.contains("[x] Dry-run planning healthy"));
        assert!(checklist.contains("[ ] Import at least one peer invite"));
        assert!(checklist.contains("[ ] Signed peer record current"));
        assert!(checklist.contains("[x] Dytallix enrollment and peer trust ready"));
        assert!(checklist.contains("not required for this private mesh"));
        assert!(checklist.contains("never stores or uses wallet seeds"));
        assert!(checklist.contains("qlinkctl invite import <encoded-invite>"));
        assert!(checklist.contains("qlinkctl peer trust <peer-id>"));
        assert!(checklist.contains("qlinkctl doctor"));
        assert!(checklist.contains("qlinkctl support-bundle --output <path>"));
        assert!(checklist.contains("pre-production"));
    }

    #[test]
    fn format_onboarding_checklist_marks_active_peer_and_live_transport_ready() {
        let mut status = status_with_data_plane(DataPlaneState::Ready, true, true, None);
        status.publication = healthy_publication(true);
        let peer_store = PeerStore {
            selected_peer_id: None,
            peers: vec![StoredPeer {
                peer_id: "peer-a".to_string(),
                alias: "deck two".to_string(),
                mesh_id: "party-mesh".to_string(),
                party_id: "party-a".to_string(),
                trust_mode: MeshTrustMode::PrivateFriends,
                trust_source: "invite".to_string(),
                revoked: false,
                expires_at_unix: 4_102_444_800,
            }],
        };
        let checklist = format_onboarding_checklist(&status, &peer_store);
        assert!(checklist.contains("[x] Import at least one peer invite"));
        assert!(checklist.contains("1 active peer"));
        assert!(checklist.contains("[x] Packet I/O available"));
        assert!(checklist.contains("[x] Transport ready"));
        assert!(checklist.contains("[x] Signed peer record current"));
        assert!(checklist.contains("[x] Dytallix enrollment and peer trust ready"));
        assert!(checklist.contains("two-Deck or equivalent SteamOS/Linux validation"));
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

    #[cfg(unix)]
    #[test]
    fn provisioning_device_loader_requires_owner_only_regular_seed() {
        use std::os::unix::fs::PermissionsExt;

        let state_dir = unique_temp_dir("qlinkctl-provisioning-seed");
        std::fs::create_dir_all(&state_dir).unwrap();
        let seed_path = state_dir.join(DEVICE_IDENTITY_SEED_FILE);
        std::fs::write(&seed_path, [7_u8; 32]).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let loaded = load_provisioning_device_keypair(&state_dir).unwrap();
        assert_eq!(
            loaded.public_key().peer_id(),
            qlink_core::crypto::DeviceKeypair::from_seed([7_u8; 32])
                .unwrap()
                .public_key()
                .peer_id()
        );

        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_provisioning_device_keypair(&state_dir)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[cfg(unix)]
    #[test]
    fn provisioning_device_loader_rejects_symlink_and_wrong_length() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let state_dir = unique_temp_dir("qlinkctl-provisioning-seed-invalid");
        std::fs::create_dir_all(&state_dir).unwrap();
        let outside = state_dir.with_extension("outside");
        std::fs::write(&outside, [9_u8; 32]).unwrap();
        let seed_path = state_dir.join(DEVICE_IDENTITY_SEED_FILE);
        symlink(&outside, &seed_path).unwrap();
        assert_eq!(
            load_provisioning_device_keypair(&state_dir)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        std::fs::remove_file(&seed_path).unwrap();
        std::fs::write(&seed_path, b"short").unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_provisioning_device_keypair(&state_dir)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        let _ = std::fs::remove_file(outside);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    fn peer_fixture() -> StoredPeer {
        StoredPeer {
            peer_id: "peer-host-deck".to_string(),
            alias: "Host Deck".to_string(),
            mesh_id: "mesh-steam-squad".to_string(),
            party_id: "party-nightly".to_string(),
            trust_mode: MeshTrustMode::PublicDytallixRequired,
            trust_source: "invite".to_string(),
            revoked: false,
            expires_at_unix: 4_102_444_800,
        }
    }

    #[test]
    fn import_invite_to_store_persists_peer_metadata() {
        let state_dir = unique_temp_dir("qlinkctl-peer-import");
        let invite = InviteCode {
            mesh_id: "mesh-steam-squad".to_string(),
            party_id: "party-nightly".to_string(),
            rendezvous: vec!["203.0.113.10:9471".to_string()],
            relay: vec!["198.51.100.15:9472".to_string()],
            host_peer_id: "peer-host-deck".to_string(),
            host_alias: "Host Deck".to_string(),
            trust_mode: MeshTrustMode::PublicDytallixRequired,
            trust_source: "invite".to_string(),
            expires_at_unix: 4_102_444_800,
        }
        .encode()
        .unwrap();

        let peer = import_invite_to_store(&state_dir, &invite, 1_767_139_200).unwrap();

        assert_eq!(peer.peer_id, "peer-host-deck");
        assert_eq!(peer.trust_mode, MeshTrustMode::PublicDytallixRequired);
        let store = load_peer_store_for_state_dir(&state_dir).unwrap();
        assert_eq!(store.peers.len(), 1);
        let raw = std::fs::read_to_string(peer_store_path_from_state_dir(&state_dir)).unwrap();
        assert!(!raw.contains("203.0.113.10"));
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[test]
    fn peer_trust_output_has_required_shape() {
        let output = format_peer_trust(&peer_fixture());

        assert!(output.contains("peer: peer-host-deck"));
        assert!(output.contains("mesh: publicDytallixRequired"));
        assert!(output.contains("mesh id: mesh-steam-squad"));
        assert!(output.contains("trust source: invite"));
        assert!(output.contains("dytallix: required (not checked)"));
        assert!(output.contains("revoked: no"));
        assert!(output.contains("expires: 2100-01-01T00:00:00Z"));
    }

    #[test]
    fn peer_store_remove_and_revoke_commands_mutate_store() {
        let state_dir = unique_temp_dir("qlinkctl-peer-mutate");
        let mut store = PeerStore::default();
        store.upsert(peer_fixture());
        store_peer_store_at(&state_dir, &store).unwrap();

        revoke_peer_in_store(&state_dir, "peer-host-deck").unwrap();
        assert!(
            peer_from_store(&state_dir, "peer-host-deck")
                .unwrap()
                .revoked
        );

        remove_peer_from_store(&state_dir, "peer-host-deck").unwrap();
        assert!(matches!(
            peer_from_store(&state_dir, "peer-host-deck").unwrap_err(),
            PeerCommandError::UnknownPeer(_)
        ));
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[test]
    fn peer_store_select_persists_only_current_non_revoked_peer() {
        let state_dir = unique_temp_dir("qlinkctl-peer-select");
        let mut store = PeerStore::default();
        store.upsert(StoredPeer {
            peer_id: "peer-a".to_string(),
            alias: "deck".to_string(),
            mesh_id: "mesh-a".to_string(),
            party_id: "party-a".to_string(),
            trust_mode: MeshTrustMode::PrivateFriends,
            trust_source: "invite".to_string(),
            revoked: false,
            expires_at_unix: 100,
        });
        store_peer_store_at(&state_dir, &store).unwrap();

        select_peer_in_store(&state_dir, "peer-a", 10).unwrap();
        let selected = load_peer_store_for_state_dir(&state_dir).unwrap();
        assert_eq!(selected.selected_peer_id.as_deref(), Some("peer-a"));
        assert!(format_peer_state(&selected)
            .unwrap()
            .contains("\"selectedPeerId\": \"peer-a\""));

        clear_peer_selection_in_store(&state_dir).unwrap();
        let cleared = load_peer_store_for_state_dir(&state_dir).unwrap();
        assert_eq!(cleared.selected_peer_id, None);

        select_peer_in_store(&state_dir, "peer-a", 10).unwrap();

        revoke_peer_in_store(&state_dir, "peer-a").unwrap();
        let revoked = load_peer_store_for_state_dir(&state_dir).unwrap();
        assert_eq!(revoked.selected_peer_id, None);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[test]
    fn service_commands_use_fixed_absolute_argv() {
        assert_eq!(
            service_command_argv(ServiceAction::Start),
            ["/usr/local/libexec/quantumlink-service-control", "start"]
        );
        assert_eq!(
            service_command_argv(ServiceAction::Stop),
            ["/usr/local/libexec/quantumlink-service-control", "stop"]
        );
        assert_eq!(
            service_command_argv(ServiceAction::Restart),
            ["/usr/local/libexec/quantumlink-service-control", "restart"]
        );
        assert!(ServiceAction::parse("start;reboot").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn status_reports_daemon_unavailable_when_socket_is_missing() {
        let missing = PathBuf::from("/tmp/qlinkctl-missing-test.sock");
        let error = status_from_daemon(&missing).unwrap_err();

        assert!(error.to_string().contains("qlinkd is unavailable"));
    }

    #[test]
    fn format_status_includes_network_plan_details() {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state: NetworkPlanState::Planned,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run: true,
            ownership_record_present: false,
            commands: vec!["ip tuntap add dev qlink0 mode tun".to_string()],
            nftables_rules: vec!["add table inet qlink".to_string()],
            error: None,
        };

        let json = format_status(&status).unwrap();

        assert!(json.contains("\"network\""));
        assert!(json.contains("\"state\": \"planned\""));
        assert!(json.contains("\"protectedCidr\": \"100.64.0.0/10\""));
        assert!(json.contains("\"dryRun\": true"));
    }

    #[test]
    fn format_doctor_warns_when_publication_is_missing_in_dry_run() {
        let status = status_with_network(NetworkPlanState::Planned, true, false, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - peer record publication not started"));
        assert!(doctor.contains("network state: planned"));
        assert!(doctor.contains("mode: dry-run"));
        assert!(doctor.contains("publication state: notStarted"));
        assert!(doctor.contains("action: publication not started"));
        assert!(doctor.contains("qlinkd never owns wallet secrets"));
    }

    #[test]
    fn format_doctor_warns_when_profile_ports_need_restart() {
        let mut status = status_with_network(NetworkPlanState::Planned, true, false, None);
        status.publication = healthy_publication(false);
        status.game_profile.port_enforcement = qlink_proto::GameProfilePortEnforcementStatus {
            state: GameProfilePortEnforcementState::Applied,
            profile_id: Some("factorio".to_string()),
            udp_ports: vec![34197],
            restart_required: true,
        };

        let doctor = format_doctor(&status);

        assert!(
            doctor.contains("verdict: WARN - service restart required to apply game profile ports")
        );
        assert!(doctor.contains("applied game profile: factorio"));
        assert!(doctor.contains("enforced UDP ports: 34197"));
        assert!(doctor.contains("game profile restart required: yes"));
    }

    #[test]
    fn format_doctor_fails_when_daemon_phase_failed() {
        let mut status = status_with_network(NetworkPlanState::Planned, true, false, None);
        status.phase = ConnectionPhase::Failed;

        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - daemon phase failed"));
        assert!(doctor.contains("phase: failed"));
        assert!(doctor.contains("network state: planned"));
    }

    #[test]
    fn format_doctor_warns_when_daemon_phase_degraded() {
        let mut status = status_with_network(NetworkPlanState::Planned, true, false, None);
        status.phase = ConnectionPhase::Degraded;

        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - daemon phase degraded"));
        assert!(doctor.contains("phase: degraded"));
        assert!(doctor.contains("network state: planned"));
    }

    #[test]
    fn format_doctor_fails_for_activated_network_without_publication() {
        let status = status_with_network(NetworkPlanState::Applied, false, true, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains(
            "verdict: FAIL - protected networking active without peer record publication"
        ));
        assert!(doctor.contains("network state: applied"));
        assert!(doctor.contains("mode: activated"));
        assert!(doctor.contains("ownership record: present"));
    }

    #[test]
    fn format_doctor_reports_current_publication_and_healthy_required_trust() {
        let mut status = status_with_network(NetworkPlanState::Applied, false, true, None);
        status.publication = healthy_publication(true);

        let doctor = format_doctor_at(&status, 1_767_139_200);

        assert!(doctor.contains("verdict: OK - activated networking has teardown ownership"));
        assert!(doctor.contains("publication state: active"));
        assert!(doctor.contains("publication sequence: 9"));
        assert!(doctor.contains("local Dytallix binding: active"));
        assert!(doctor.contains("remote Dytallix trust decision: accepted"));
        assert!(doctor.contains("remote Dytallix trust health: healthy"));
        assert!(doctor.contains("action: signed peer record is active and unexpired"));
    }

    #[test]
    fn format_doctor_fails_closed_for_expired_publication() {
        let mut status = status_with_network(NetworkPlanState::Applied, false, true, None);
        status.publication = healthy_publication(false);
        status.publication.expires_at_unix = Some(100);
        status.publication.last_error = Some(PublicationErrorStatus {
            code: PublicationErrorCode::Expired,
            retryable: true,
        });

        let doctor = format_doctor_at(&status, 101);

        assert!(doctor.contains("verdict: FAIL - signed peer record expired"));
        assert!(doctor.contains("publication error: expired"));
        assert!(doctor.contains("keep protected transport disabled"));
    }

    #[test]
    fn format_doctor_fails_closed_for_required_dytallix_denial() {
        let mut status = status_with_network(NetworkPlanState::Applied, false, true, None);
        status.publication = healthy_publication(true);
        status.publication.remote_peer_trust.decision = DytallixTrustDecision::Revoked;

        let doctor = format_doctor_at(&status, 1_767_139_200);

        assert!(doctor.contains("verdict: FAIL - required remote Dytallix identity revoked"));
        assert!(doctor.contains("action: public identity revoked"));
    }

    #[test]
    fn format_doctor_fails_closed_when_required_dytallix_is_unavailable() {
        let mut status = status_with_network(NetworkPlanState::Applied, false, true, None);
        status.publication = healthy_publication(true);
        status.publication.remote_peer_trust.health = DytallixTrustHealth::Unavailable;

        let doctor = format_doctor_at(&status, 1_767_139_200);

        assert!(
            doctor.contains("verdict: FAIL - required remote Dytallix trust service unavailable")
        );
        assert!(doctor.contains("action: Dytallix trust unavailable"));
    }

    #[test]
    fn format_doctor_fails_closed_without_local_stable_enrollment() {
        let mut status = status_with_network(NetworkPlanState::Applied, false, true, None);
        status.publication = healthy_publication(true);
        status.publication.local_registry_binding.state = LocalRegistryBindingState::NotConfigured;

        let doctor = format_doctor_at(&status, 1_767_139_200);

        assert!(doctor.contains("verdict: FAIL - local Dytallix enrollment is notConfigured"));
        assert!(doctor.contains("action: local stable Dytallix enrollment is not active"));
    }

    #[test]
    fn format_doctor_warns_when_ownership_record_is_present_before_activation() {
        let status = status_with_network(NetworkPlanState::Planned, true, true, None);
        let doctor = format_doctor(&status);

        assert!(
            doctor.contains("verdict: WARN - ownership record present; teardown may be pending")
        );
        assert!(doctor.contains("network state: planned"));
        assert!(doctor.contains("mode: dry-run"));
        assert!(doctor.contains("ownership record: present"));
    }

    #[test]
    fn format_doctor_fails_apply_failed_status_with_error() {
        let status = status_with_network(
            NetworkPlanState::ApplyFailed,
            false,
            false,
            Some("nftables apply failed"),
        );
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - network apply failed: nftables apply failed"));
        assert!(doctor.contains("network state: applyFailed"));
        assert!(doctor.contains("mode: unknown"));
        assert!(doctor.contains("apply error: nftables apply failed"));
    }

    #[test]
    fn format_doctor_fails_applied_status_without_ownership_record() {
        let status = status_with_network(NetworkPlanState::Applied, false, false, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - applied networking without ownership record"));
        assert!(doctor.contains("network state: applied"));
        assert!(doctor.contains("mode: activated"));
        assert!(doctor.contains("ownership record: absent"));
    }

    #[test]
    fn format_doctor_warns_with_state_and_mode_for_other_combinations() {
        let status = status_with_network(NetworkPlanState::Planned, false, false, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - network state planned with mode unknown"));
        assert!(doctor.contains("mode: unknown"));
    }

    #[test]
    fn format_doctor_handles_legacy_not_started_status_without_panic() {
        let status = DaemonStatus::idle(false);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - network state notStarted with mode dry-run"));
        assert!(doctor.contains("kill switch: disabled"));
        assert!(doctor.contains("network state: notStarted"));
        assert!(doctor.contains("interface: unknown"));
        assert!(doctor.contains("route mode: unknown"));
        assert!(doctor.contains("protected CIDR: unknown"));
        assert!(doctor.contains("ownership record: absent"));
        assert!(doctor.contains("data-plane state: notStarted"));
        assert!(doctor.contains("packet I/O: unavailable"));
        assert!(doctor.contains("transport ready: no"));
        assert!(doctor.contains("transport path: unknown"));
        assert!(doctor.contains("peer session: not ready"));
        assert!(doctor.contains("packet counters: observed=0 queued=0 dropped=0 emitted=0 accepted=0 rejected=0 transportErrors=0"));
    }

    #[test]
    fn format_doctor_reports_starting_data_plane_without_peer_transport_claims() {
        let status = status_with_data_plane(DataPlaneState::Starting, true, false, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - peer record publication not started"));
        assert!(doctor.contains("data-plane state: starting"));
        assert!(doctor.contains("data-plane interface: qlink0"));
        assert!(doctor.contains("packet I/O: available"));
        assert!(doctor.contains("transport ready: no"));
        assert!(doctor.contains("transport path: unavailable"));
        assert!(doctor.contains("peer session: not ready"));
        assert!(doctor.contains("packet counters: observed=18 queued=17 dropped=1 emitted=16 accepted=15 rejected=2 transportErrors=1"));
        assert!(!doctor.contains("peer transport ready"));
    }

    #[test]
    fn format_doctor_fails_when_data_plane_failed() {
        let status = status_with_data_plane(
            DataPlaneState::Failed,
            false,
            false,
            Some("packet pump stopped"),
        );
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - data plane failed: packet pump stopped"));
        assert!(doctor.contains("data-plane state: failed"));
        assert!(doctor.contains("data-plane error: packet pump stopped"));
        assert!(doctor.contains("last transport error: none"));
    }

    #[test]
    fn format_doctor_warns_when_data_plane_degraded() {
        let status = status_with_data_plane(
            DataPlaneState::Degraded,
            true,
            false,
            Some("transport backpressure"),
        );
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - data plane degraded: transport backpressure"));
        assert!(doctor.contains("data-plane state: degraded"));
        assert!(doctor.contains("transport ready: no"));
        assert!(doctor.contains("transport path: unavailable"));
    }

    #[test]
    fn format_doctor_keeps_fail_precedence_over_data_plane_degraded_warning() {
        let mut status = status_with_data_plane(DataPlaneState::Degraded, true, false, None);
        status.network.state = NetworkPlanState::ApplyFailed;
        status.network.dry_run = false;
        status.network.error = Some("nftables apply failed".to_string());

        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - network apply failed: nftables apply failed"));
        assert!(doctor.contains("data-plane state: degraded"));
    }

    #[test]
    fn format_status_includes_applied_network_state() {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state: NetworkPlanState::Applied,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run: false,
            ownership_record_present: true,
            commands: vec!["ip tuntap add dev qlink0 mode tun".to_string()],
            nftables_rules: vec!["add table inet qlink".to_string()],
            error: None,
        };

        let json = format_status(&status).unwrap();

        assert!(json.contains("\"state\": \"applied\""));
        assert!(json.contains("\"dryRun\": false"));
        assert!(json.contains("\"ownershipRecordPresent\": true"));
    }

    #[test]
    fn format_status_includes_apply_failed_error() {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state: NetworkPlanState::ApplyFailed,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run: false,
            ownership_record_present: true,
            commands: vec!["ip tuntap add dev qlink0 mode tun".to_string()],
            nftables_rules: vec!["add table inet qlink".to_string()],
            error: Some("nftables apply failed".to_string()),
        };

        let json = format_status(&status).unwrap();

        assert!(json.contains("\"state\": \"applyFailed\""));
        assert!(json.contains("\"error\": \"nftables apply failed\""));
    }

    #[test]
    fn parse_status_response_reports_daemon_error_envelope() {
        let error = parse_status_response(r#"{"type":"error","message":"unsupported request"}"#)
            .unwrap_err();

        assert!(error.to_string().contains("unsupported request"));
    }

    #[test]
    fn game_launch_plan_uses_selected_profile_and_fixed_systemd_boundary() {
        let status = GameProfileStatus {
            selected_profile: Some(qlink_proto::GameProfileInfo {
                id: "factorio".to_string(),
                display_name: "Factorio".to_string(),
                executables: vec!["factorio".to_string()],
                udp_ports: vec![34197],
                lan_discovery: true,
                voice_chat_safe: true,
                low_latency: true,
            }),
            ..Default::default()
        };

        let plan = build_game_launch_plan(
            &status,
            "s123abc",
            Path::new("/usr/local/bin/qlinkctl"),
            "/home/deck/factorio",
            &["--start-server".to_string()],
        )
        .unwrap();

        assert_eq!(plan.scope_unit, "quantumlink-game-s123abc.scope");
        assert_eq!(plan.systemd_run_args[0], "--user");
        assert!(plan.systemd_run_args.iter().any(|arg| arg == "factorio"));
        assert!(!plan.systemd_run_args.iter().any(|arg| arg == "sh"));
    }

    #[test]
    fn game_launch_capability_preflight_accepts_supported_host() {
        validate_game_launch_capabilities(&supported_runtime_capabilities()).unwrap();
    }

    #[test]
    fn game_launch_capability_preflight_fails_closed() {
        let mut capabilities = supported_runtime_capabilities();
        capabilities.nftables_cgroup_v2 =
            RuntimeCapabilityStatus::unsupported("kernel expression is unavailable");

        let error = validate_game_launch_capabilities(&capabilities).unwrap_err();

        assert_eq!(
            error,
            "game launch blocked: nftables cgroup v2 is unsupported: kernel expression is unavailable"
        );
    }

    #[test]
    fn doctor_fails_when_required_game_capability_is_unsupported() {
        let mut status = status_with_network(NetworkPlanState::Applied, false, true, None);
        status.publication = healthy_publication(true);
        status.runtime_capabilities = supported_runtime_capabilities();
        status.runtime_capabilities.nftables_cgroup_v2 =
            RuntimeCapabilityStatus::unsupported("kernel expression is unavailable");

        let doctor = format_doctor_at(&status, 1_767_139_200);

        assert!(doctor.contains(
            "verdict: FAIL - nftables cgroup v2 capability is unsupported: kernel expression is unavailable"
        ));
        assert!(doctor.contains("capability cgroup v2: supported"));
        assert!(doctor.contains(
            "capability nftables cgroup v2: unsupported (kernel expression is unavailable)"
        ));
    }

    #[test]
    fn doctor_warns_when_desktop_authorization_capability_is_unavailable() {
        let mut status = status_with_network(NetworkPlanState::Applied, false, true, None);
        status.publication = healthy_publication(true);
        status.runtime_capabilities = supported_runtime_capabilities();
        status.runtime_capabilities.policykit =
            RuntimeCapabilityStatus::unavailable("pkexec is not installed");

        let doctor = format_doctor_at(&status, 1_767_139_200);

        assert!(doctor.contains(
            "verdict: WARN - PolicyKit capability is unavailable: pkexec is not installed"
        ));
        assert!(doctor.contains("capability PolicyKit: unavailable (pkexec is not installed)"));
    }

    #[test]
    fn doctor_fails_when_game_process_classification_fails() {
        let mut status = DaemonStatus::idle(true);
        status.game_profile.process_classification = qlink_proto::GameProcessClassificationStatus {
            state: GameProcessClassificationState::ApplyFailed,
            error: Some("nftables cgroup expression unavailable".to_string()),
            ..Default::default()
        };

        let doctor = format_doctor(&status);

        assert!(doctor.contains(
            "verdict: FAIL - game process classification failed: nftables cgroup expression unavailable"
        ));
    }
}
