//! Steam-safe bypass policy and game-aware routing wiring.
//!
//! `qlink-game` owns the product's Steam-safe boundary (account, store, wallet,
//! checkout, inventory, marketplace, launcher, embedded browser, updates, and
//! login traffic bypass the tunnel by default), the game-profile model, and the
//! latency-aware host-selection scorer. This module makes the daemon a real
//! consumer of that crate rather than leaving it orphaned: the engine loads the
//! shipped policy, validates that the protected overlay CIDR it is about to
//! program matches the policy's `protect_overlay_cidr`, and surfaces the active
//! bypass categories in status/doctor output so the spec's disclosure
//! requirement ("clear disclosure about what traffic is and is not protected")
//! is backed by the same configuration the routing decision uses.

use qlink_game::profile::SteamBypassPolicy;
use qlink_game::{
    load_game_profile_selection, recommend_host, store_game_profile_selection, GameProfile,
    GameProfileSelection, HostCandidateMetrics,
};
use qlink_proto::{DaemonConfig, GameProfileInfo, GameProfileStatus, RouteMode};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// File name of the Steam-safe bypass policy inside the config directory.
pub const STEAM_BYPASS_FILE: &str = "steam-bypass.toml";
/// Sub-directory of per-game routing profiles inside the config directory.
pub const GAMES_DIR: &str = "games";

/// Where an active bypass policy came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SteamBypassSource {
    /// Built-in production-safe defaults (no config file present).
    Default,
    /// Loaded from `steam-bypass.toml` in the config directory.
    ConfigFile,
}

/// A serializable, non-sensitive summary of the daemon's Steam-safe posture.
/// Surfaced in the startup banner and to `qlinkctl doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SteamBypassSummary {
    pub source: SteamBypassSource,
    pub default_action: String,
    pub protect_overlay_cidr: String,
    pub protect_game_profile_routes: bool,
    pub bypass_categories: Vec<String>,
    pub game_profile_count: usize,
    pub game_profiles: Vec<GameProfile>,
    pub selected_profile: Option<GameProfile>,
    pub selection_warning: Option<String>,
    /// Set when the policy's protected overlay disagrees with the daemon's
    /// configured overlay, or the route mode is inconsistent with the policy.
    pub alignment_warning: Option<String>,
    /// Non-fatal warnings from loading the policy or game profiles (e.g. a
    /// malformed optional file that was skipped in favor of defaults).
    pub load_warnings: Vec<String>,
}

impl SteamBypassSummary {
    /// Loads the bypass policy and game profiles from the config directory,
    /// validates alignment with the daemon config, and packs a summary. Never
    /// fails: missing or malformed optional files fall back to production-safe
    /// defaults with a recorded warning, so a bad game config cannot brick the
    /// daemon.
    pub fn load(config_dir: &Path, state_dir: &Path, config: &DaemonConfig) -> Self {
        let mut load_warnings = Vec::new();

        let (policy, source) = match load_steam_bypass_policy(config_dir) {
            Ok(Some(policy)) => (policy, SteamBypassSource::ConfigFile),
            Ok(None) => (SteamBypassPolicy::default(), SteamBypassSource::Default),
            Err(warning) => {
                load_warnings.push(warning);
                (SteamBypassPolicy::default(), SteamBypassSource::Default)
            }
        };

        let (profiles, profile_warnings) = load_game_profiles(config_dir);
        load_warnings.extend(profile_warnings);

        let (selected_profile, selection_warning) = match load_game_profile_selection(state_dir) {
            Ok(selection) => match selection.selected_profile_id {
                Some(profile_id) => {
                    match profiles.iter().find(|profile| profile.id == profile_id) {
                        Some(profile) => (Some(profile.clone()), None),
                        None => (
                            None,
                            Some(format!(
                                "selected game profile `{profile_id}` is not installed"
                            )),
                        ),
                    }
                }
                None => (None, None),
            },
            Err(error) => (
                None,
                Some(format!("failed to load game profile selection: {error}")),
            ),
        };

        let alignment_warning = validate_bypass_alignment(config, &policy);

        Self {
            source,
            default_action: policy.default_action().to_string(),
            protect_overlay_cidr: policy.protect_overlay_cidr().to_string(),
            protect_game_profile_routes: policy.protect_game_profile_routes(),
            bypass_categories: policy.bypass_categories().to_vec(),
            game_profile_count: profiles.len(),
            game_profiles: profiles,
            selected_profile,
            selection_warning,
            alignment_warning,
            load_warnings,
        }
    }

    /// One-line banner for the daemon log, e.g.
    /// `steam-safe: bypass 10 categories, overlay 100.64.0.0/10, 3 game profiles`.
    pub fn banner(&self) -> String {
        format!(
            "steam-safe: bypass {} categories, overlay {}, {} game profile(s), selected {}",
            self.bypass_categories.len(),
            self.protect_overlay_cidr,
            self.game_profile_count,
            self.selected_profile
                .as_ref()
                .map(|profile| profile.id.as_str())
                .unwrap_or("none")
        )
    }

    pub fn profile_status(&self) -> GameProfileStatus {
        GameProfileStatus {
            available_profiles: self.game_profiles.iter().map(profile_info).collect(),
            selected_profile: self.selected_profile.as_ref().map(profile_info),
            selection_warning: self.selection_warning.clone(),
            ..Default::default()
        }
    }

    pub fn select_profile(&mut self, state_dir: &Path, profile_id: &str) -> Result<(), String> {
        let profile = self
            .game_profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned()
            .ok_or_else(|| format!("unknown game profile `{profile_id}`"))?;
        store_game_profile_selection(state_dir, &GameProfileSelection::selected(profile_id))
            .map_err(|error| format!("failed to store game profile selection: {error}"))?;
        self.selected_profile = Some(profile);
        self.selection_warning = None;
        Ok(())
    }

    pub fn clear_profile(&mut self, state_dir: &Path) -> Result<(), String> {
        store_game_profile_selection(state_dir, &GameProfileSelection::default())
            .map_err(|error| format!("failed to clear game profile selection: {error}"))?;
        self.selected_profile = None;
        self.selection_warning = None;
        Ok(())
    }
}

fn profile_info(profile: &GameProfile) -> GameProfileInfo {
    GameProfileInfo {
        id: profile.id.clone(),
        display_name: profile.display_name.clone(),
        executables: profile.executables.clone(),
        udp_ports: profile.udp_ports.clone(),
        lan_discovery: profile.lan_discovery,
        voice_chat_safe: profile.voice_chat_safe,
        low_latency: profile.low_latency,
    }
}

/// Loads the Steam-safe bypass policy from `<config_dir>/steam-bypass.toml`.
/// Returns `Ok(None)` when the file is absent (defaults apply), `Ok(Some)` when
/// it parses, and `Err(message)` when it exists but cannot be read or parsed.
pub fn load_steam_bypass_policy(config_dir: &Path) -> Result<Option<SteamBypassPolicy>, String> {
    let path = config_dir.join(STEAM_BYPASS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => SteamBypassPolicy::from_toml_str(&text)
            .map(Some)
            .map_err(|error| format!("failed to parse {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("failed to read {}: {error}", path.display())),
    }
}

/// Loads all per-game routing profiles from `<config_dir>/games/*.toml`.
/// Returns the parsed profiles plus non-fatal warnings for any file that could
/// not be read or parsed. A missing directory yields an empty list.
pub fn load_game_profiles(config_dir: &Path) -> (Vec<GameProfile>, Vec<String>) {
    let games_dir = config_dir.join(GAMES_DIR);
    let mut profiles = Vec::new();
    let mut warnings = Vec::new();

    let entries = match std::fs::read_dir(&games_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (profiles, warnings),
        Err(error) => {
            warnings.push(format!("failed to read {}: {error}", games_dir.display()));
            return (profiles, warnings);
        }
    };

    let mut toml_paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("toml"))
        .collect();
    // Deterministic order so the profile list and warnings are stable.
    toml_paths.sort();

    for path in toml_paths {
        match std::fs::read_to_string(&path) {
            Ok(text) => match GameProfile::from_toml_str(&text) {
                Ok(profile) => match profile.validate() {
                    Ok(()) if profiles.iter().any(|loaded| loaded.id == profile.id) => warnings
                        .push(format!(
                            "duplicate game profile id `{}` in {}",
                            profile.id,
                            path.display()
                        )),
                    Ok(()) => profiles.push(profile),
                    Err(error) => {
                        warnings.push(format!("invalid game profile {}: {error}", path.display()))
                    }
                },
                Err(error) => warnings.push(format!("failed to parse {}: {error}", path.display())),
            },
            Err(error) => warnings.push(format!("failed to read {}: {error}", path.display())),
        }
    }

    (profiles, warnings)
}

/// Validates that the daemon's routing configuration is consistent with the
/// Steam-safe bypass policy. Returns a human-readable warning when the policy's
/// protected overlay disagrees with the configured overlay, or when a
/// game/split route mode runs under a policy whose default action is not
/// `bypass` (which would risk pulling Steam-safe traffic into the tunnel).
pub fn validate_bypass_alignment(
    config: &DaemonConfig,
    policy: &SteamBypassPolicy,
) -> Option<String> {
    if policy.protect_overlay_cidr() != config.overlay_cidr {
        return Some(format!(
            "steam-safe bypass policy protects overlay {} but daemon is configured for {}",
            policy.protect_overlay_cidr(),
            config.overlay_cidr
        ));
    }

    if matches!(
        config.route_mode,
        RouteMode::GameOnly | RouteMode::ProtectedPrefixesOnly
    ) && policy.default_action() != "bypass"
    {
        return Some(format!(
            "route mode {:?} expects the steam-safe default action 'bypass' but policy uses '{}'",
            config.route_mode,
            policy.default_action()
        ));
    }

    None
}

/// Selects the lowest-cost game host among candidates using the shared
/// `qlink-game` latency scorer (RTT + jitter + loss + relay/NAT penalties).
/// Thin wrapper so the daemon is a real consumer of the host-selection logic
/// and future dial-candidate ranking has a single home.
pub fn recommend_game_host(candidates: &[HostCandidateMetrics]) -> Option<&HostCandidateMetrics> {
    recommend_host(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn missing_config_dir_yields_production_safe_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let summary = SteamBypassSummary::load(temp.path(), temp.path(), &DaemonConfig::default());

        assert_eq!(summary.source, SteamBypassSource::Default);
        assert_eq!(summary.default_action, "bypass");
        assert_eq!(summary.bypass_categories.len(), 10);
        assert_eq!(summary.game_profile_count, 0);
        assert!(summary.alignment_warning.is_none());
        assert!(summary.load_warnings.is_empty());
    }

    #[test]
    fn loads_shipped_policy_and_game_profiles() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join(STEAM_BYPASS_FILE),
            r#"
                [policy]
                default_action = "bypass"
                protect_overlay_cidr = "100.64.0.0/10"
                protect_game_profile_routes = true
                full_tunnel_requires_explicit_underlay_exemptions = true

                [steam]
                bypass_categories = ["account", "store", "wallet"]
            "#,
        );
        write(
            &temp.path().join(GAMES_DIR).join("factorio.toml"),
            r#"
                id = "factorio"
                display_name = "Factorio"
                executables = ["factorio"]
                udp_ports = [34197]
                lan_discovery = true
                voice_chat_safe = true
                low_latency = true
            "#,
        );

        let summary = SteamBypassSummary::load(temp.path(), temp.path(), &DaemonConfig::default());

        assert_eq!(summary.source, SteamBypassSource::ConfigFile);
        assert_eq!(summary.bypass_categories, ["account", "store", "wallet"]);
        assert_eq!(summary.game_profile_count, 1);
        assert!(summary.selected_profile.is_none());
        assert!(summary.alignment_warning.is_none());
        assert!(summary.load_warnings.is_empty());
        assert!(summary.banner().contains("100.64.0.0/10"));
    }

    #[test]
    fn loads_and_clears_a_valid_persisted_profile_selection() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join(GAMES_DIR).join("factorio.toml"),
            r#"
                id = "factorio"
                display_name = "Factorio"
                executables = ["factorio"]
                udp_ports = [34197]
                lan_discovery = true
                voice_chat_safe = true
                low_latency = true
            "#,
        );
        store_game_profile_selection(temp.path(), &GameProfileSelection::selected("factorio"))
            .unwrap();

        let mut summary =
            SteamBypassSummary::load(temp.path(), temp.path(), &DaemonConfig::default());

        assert_eq!(
            summary
                .selected_profile
                .as_ref()
                .map(|profile| profile.id.as_str()),
            Some("factorio")
        );
        summary.clear_profile(temp.path()).unwrap();
        assert!(summary.selected_profile.is_none());
        assert!(load_game_profile_selection(temp.path())
            .unwrap()
            .selected_profile_id
            .is_none());
    }

    #[test]
    fn malformed_policy_falls_back_to_defaults_with_warning() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join(STEAM_BYPASS_FILE),
            "this is not valid toml = [[[",
        );

        let summary = SteamBypassSummary::load(temp.path(), temp.path(), &DaemonConfig::default());

        assert_eq!(summary.source, SteamBypassSource::Default);
        assert_eq!(summary.default_action, "bypass");
        assert_eq!(summary.load_warnings.len(), 1);
        assert!(summary.load_warnings[0].contains("failed to parse"));
    }

    #[test]
    fn overlay_mismatch_produces_alignment_warning() {
        let temp = tempfile::tempdir().unwrap();
        let config = DaemonConfig {
            overlay_cidr: "10.0.0.0/8".to_string(),
            ..DaemonConfig::default()
        };

        let summary = SteamBypassSummary::load(temp.path(), temp.path(), &config);

        let warning = summary.alignment_warning.expect("mismatch should warn");
        assert!(warning.contains("10.0.0.0/8"));
        assert!(warning.contains("100.64.0.0/10"));
    }

    #[test]
    fn recommend_game_host_prefers_lowest_latency_direct_candidate() {
        let candidates = vec![
            HostCandidateMetrics {
                peer_id: "relay-peer".to_string(),
                median_rtt_ms: 20.0,
                jitter_ms: 1.0,
                packet_loss_percent: 0.0,
                relay: true,
                nat_penalty: 0.0,
            },
            HostCandidateMetrics {
                peer_id: "direct-peer".to_string(),
                median_rtt_ms: 30.0,
                jitter_ms: 1.0,
                packet_loss_percent: 0.0,
                relay: false,
                nat_penalty: 0.0,
            },
        ];

        let best = recommend_game_host(&candidates).unwrap();
        // Direct beats relay despite higher RTT (relay penalty = 30).
        assert_eq!(best.peer_id, "direct-peer");
    }
}
