use qlink_proto::{
    load_peer_store_at, peer_store_path_from_state_dir, store_peer_store_at, ConnectionPhase,
    DaemonStatus, DataPlaneState, InviteCode, MeshTrustMode, NetworkPlanState, PathKind, PeerStore,
    RouteMode, StoredPeer,
};

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
    #[error("failed to send status request: {0}")]
    Write(#[from] std::io::Error),
    #[error("invalid qlinkd status response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("qlinkd returned an error: {0}")]
    Daemon(String),
}

pub const DEFAULT_STATE_DIR: &str = "/var/lib/quantumlink";

pub fn format_guide() -> String {
    [
        "QuantumLink SteamOS Guide",
        "",
        "Onboarding",
        "- Build and install qlinkd plus qlinkctl, edit /etc/quantumlink/config.json, then start qlinkd under systemd.",
        "- Begin with qlinkctl status and qlinkctl doctor before changing any network state.",
        "- Keep support bundles redacted before sharing logs outside the Deck.",
        "",
        "Runtime modes",
        "- qlinkd starts in dry-run planning mode by default; it validates config and reports the intended TUN, route, and nftables plan without mutating networking.",
        "- qlinkd --check validates configuration/status and exits.",
        "- qlinkd --activate-network is the explicit operator opt-in for live TUN, route, and nftables application.",
        "- qlinkd --deactivate-network removes only QuantumLink-owned network state from the persisted ownership record.",
        "- qlinkctl doctor reports packet I/O, data-plane health, and whether transport ready is yes or no.",
        "",
        "Peer and invite commands",
        "- qlinkctl status shows daemon status as JSON.",
        "- qlinkctl doctor summarizes readiness and failure/warning verdicts.",
        "- qlinkctl invite import <encoded-invite> stores a private mesh peer invite.",
        "- qlinkctl invite decode <code> inspects an invite without storing it.",
        "- qlinkctl peer list lists stored peers.",
        "- qlinkctl peer trust <peer-id> explains trust source, mesh mode, and Dytallix requirements.",
        "- qlinkctl peer revoke <peer-id> marks a peer revoked; qlinkctl peer remove <peer-id> deletes it.",
        "",
        "Diagnostics and support",
        "- qlinkctl support-bundle --output <path> exports redacted daemon status and doctor output.",
        "- Share support bundles instead of raw logs when reporting bugs, tunnel issues, or security concerns.",
        "- Route security-sensitive reports through SECURITY.md and keep secrets, wallet seeds, tokens, and raw packet payloads out of tickets.",
        "",
        "Steam-safe routing",
        "- Steam-safe traffic bypass keeps Steam account, store, wallet, checkout, inventory, marketplace, launcher, and embedded browser traffic off QuantumLink by default.",
        "- QuantumLink protects selected game or party traffic through explicit game profile routing and keeps the default route off the VPN by default.",
        "- Activated mode owns qlink0, overlay routes, and qlink nftables state; teardown removes only owned state.",
        "- Validate Steam launch options, LAN discovery, voice chat, and anti-cheat behavior per title before broad use.",
        "",
        "Production gates",
        "- SteamOS remains pre-production until Deck validation proves real two-Deck transport, production-signed release artifacts, public Dytallix registry evidence, hardened rendezvous/relay evidence, and game compatibility validation.",
        "- Local dry-run planning, packet I/O initialization, or transport ready: no status is not proof of protected peer traffic.",
    ]
    .join("\n")
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
    let mut stream = UnixStream::connect(socket).map_err(|source| ControlError::Unavailable {
        path: socket.display().to_string(),
        source,
    })?;
    stream.write_all(br#"{"type":"status"}"#)?;
    stream.write_all(b"\n")?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line)?;
    parse_status_response(line.trim_end())
}

pub fn format_status(status: &DaemonStatus) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(status)
}

pub fn format_doctor(status: &DaemonStatus) -> String {
    let network = &status.network;
    let data_plane = &status.data_plane;
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
    let verdict = match status.phase {
        ConnectionPhase::Failed => "FAIL - daemon phase failed".to_string(),
        _ if data_plane_verdict
            .as_deref()
            .is_some_and(|verdict| verdict.starts_with("FAIL")) =>
        {
            data_plane_verdict.unwrap()
        }
        _ if network_verdict.starts_with("FAIL") => network_verdict,
        ConnectionPhase::Degraded => "WARN - daemon phase degraded".to_string(),
        _ if data_plane_verdict
            .as_deref()
            .is_some_and(|verdict| verdict.starts_with("WARN")) =>
        {
            data_plane_verdict.unwrap()
        }
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
         data-plane error: {data_plane_error}",
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
    )
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
        DataPlaneState, DataPlaneStatus, InviteCode, MeshTrustMode, NetworkPlanState,
        NetworkStatus, PacketPumpMetrics, RouteMode, StoredPeer,
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

    #[test]
    fn format_guide_explains_steamos_modes_and_gates() {
        let guide = format_guide();
        assert!(guide.contains("QuantumLink SteamOS Guide"));
        assert!(guide.contains("dry-run planning"));
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
    fn format_guide_lists_operator_command_groups() {
        let guide = format_guide();
        assert!(guide.contains("qlinkctl status"));
        assert!(guide.contains("qlinkctl doctor"));
        assert!(guide.contains("qlinkctl invite import"));
        assert!(guide.contains("qlinkctl peer trust"));
        assert!(guide.contains("qlinkctl support-bundle --output"));
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
    fn format_doctor_reports_ok_for_healthy_dry_run_plan() {
        let status = status_with_network(NetworkPlanState::Planned, true, false, None);

        assert_eq!(
            format_doctor(&status),
            "verdict: OK - dry-run planning healthy\n\
             phase: idle\n\
             kill switch: enabled\n\
             network state: planned\n\
             mode: dry-run\n\
             interface: qlink0\n\
             route mode: gameOnly\n\
             protected CIDR: 100.64.0.0/10\n\
             ownership record: absent\n\
             apply error: none\n\
             data-plane state: notStarted\n\
             data-plane interface: unknown\n\
             packet I/O: unavailable\n\
             transport ready: no\n\
             transport path: unknown\n\
             peer session: not ready\n\
             last transport error: none\n\
             packet counters: observed=0 queued=0 dropped=0 emitted=0 accepted=0 rejected=0 transportErrors=0\n\
             data-plane error: none"
        );
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
    fn format_doctor_reports_ok_for_activated_network_with_ownership() {
        let status = status_with_network(NetworkPlanState::Applied, false, true, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: OK - activated networking has teardown ownership"));
        assert!(doctor.contains("network state: applied"));
        assert!(doctor.contains("mode: activated"));
        assert!(doctor.contains("ownership record: present"));
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

        assert!(doctor.contains("verdict: OK - dry-run planning healthy"));
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
}
