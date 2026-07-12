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
use qlink_game::{recommend_host, GameProfile, HostCandidateMetrics};
use qlink_proto::{DaemonConfig, RouteMode};
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
    pub fn load(config_dir: &Path, config: &DaemonConfig) -> Self {
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

        let alignment_warning = validate_bypass_alignment(config, &policy);

        Self {
            source,
            default_action: policy.default_action().to_string(),
            protect_overlay_cidr: policy.protect_overlay_cidr().to_string(),
            protect_game_profile_routes: policy.protect_game_profile_routes(),
            bypass_categories: policy.bypass_categories().to_vec(),
            game_profile_count: profiles.len(),
            alignment_warning,
            load_warnings,
        }
    }

    /// One-line banner for the daemon log, e.g.
    /// `steam-safe: bypass 10 categories, overlay 100.64.0.0/10, 3 game profiles`.
    pub fn banner(&self) -> String {
        format!(
            "steam-safe: bypass {} categories, overlay {}, {} game profile(s)",
            self.bypass_categories.len(),
            self.protect_overlay_cidr,
            self.game_profile_count
        )
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
                Ok(profile) => profiles.push(profile),
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
        let summary = SteamBypassSummary::load(temp.path(), &DaemonConfig::default());

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

        let summary = SteamBypassSummary::load(temp.path(), &DaemonConfig::default());

        assert_eq!(summary.source, SteamBypassSource::ConfigFile);
        assert_eq!(summary.bypass_categories, ["account", "store", "wallet"]);
        assert_eq!(summary.game_profile_count, 1);
        assert!(summary.alignment_warning.is_none());
        assert!(summary.load_warnings.is_empty());
        assert!(summary.banner().contains("100.64.0.0/10"));
    }

    #[test]
    fn malformed_policy_falls_back_to_defaults_with_warning() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join(STEAM_BYPASS_FILE),
            "this is not valid toml = [[[",
        );

        let summary = SteamBypassSummary::load(temp.path(), &DaemonConfig::default());

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

        let summary = SteamBypassSummary::load(temp.path(), &config);

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
