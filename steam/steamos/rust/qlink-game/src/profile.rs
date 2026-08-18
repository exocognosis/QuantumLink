use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameProfile {
    pub id: String,
    pub display_name: String,
    pub executables: Vec<String>,
    pub udp_ports: Vec<u16>,
    pub lan_discovery: bool,
    pub voice_chat_safe: bool,
    pub low_latency: bool,
}

impl GameProfile {
    pub fn from_toml_str(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    pub fn matches_executable(&self, executable: &str) -> bool {
        let basename = Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(executable);

        self.executables
            .iter()
            .any(|candidate| candidate == basename)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(
                "profile id must contain 1-64 lowercase ASCII letters, digits, or hyphens"
                    .to_string(),
            );
        }
        if self.display_name.trim().is_empty() || self.display_name.len() > 80 {
            return Err("profile display name must contain 1-80 characters".to_string());
        }
        if self.executables.is_empty() {
            return Err("profile must declare at least one executable basename".to_string());
        }
        for executable in &self.executables {
            if executable.is_empty()
                || executable.len() > 128
                || Path::new(executable)
                    .file_name()
                    .and_then(|name| name.to_str())
                    != Some(executable)
            {
                return Err(format!(
                    "profile executable `{executable}` must be a basename of 1-128 characters"
                ));
            }
        }
        if self.udp_ports.is_empty() || self.udp_ports.contains(&0) {
            return Err("profile must declare at least one non-zero UDP port".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SteamBypassPolicy {
    policy: SteamBypassPolicySettings,
    steam: SteamBypassCategories,
}

impl SteamBypassPolicy {
    pub fn from_toml_str(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    pub fn default_action(&self) -> &str {
        &self.policy.default_action
    }

    pub fn protect_overlay_cidr(&self) -> &str {
        &self.policy.protect_overlay_cidr
    }

    pub fn protect_game_profile_routes(&self) -> bool {
        self.policy.protect_game_profile_routes
    }

    pub fn full_tunnel_requires_explicit_underlay_exemptions(&self) -> bool {
        self.policy
            .full_tunnel_requires_explicit_underlay_exemptions
    }

    pub fn bypass_categories(&self) -> &[String] {
        &self.steam.bypass_categories
    }

    pub fn protects_category(&self, _profile: &GameProfile, category: &str) -> bool {
        let normalized = category.strip_prefix("steam_").unwrap_or(category);
        if self
            .steam
            .bypass_categories
            .iter()
            .any(|candidate| candidate == normalized)
        {
            return false;
        }

        self.policy.protect_game_profile_routes && self.policy.default_action != "bypass"
    }
}

impl Default for SteamBypassPolicy {
    fn default() -> Self {
        Self {
            policy: SteamBypassPolicySettings {
                default_action: "bypass".to_string(),
                protect_overlay_cidr: "100.64.0.0/10".to_string(),
                protect_game_profile_routes: true,
                full_tunnel_requires_explicit_underlay_exemptions: true,
            },
            steam: SteamBypassCategories {
                bypass_categories: vec![
                    "account".to_string(),
                    "store".to_string(),
                    "wallet".to_string(),
                    "checkout".to_string(),
                    "inventory".to_string(),
                    "marketplace".to_string(),
                    "launcher".to_string(),
                    "embedded_browser".to_string(),
                    "updates".to_string(),
                    "login".to_string(),
                ],
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SteamBypassPolicySettings {
    default_action: String,
    protect_overlay_cidr: String,
    protect_game_profile_routes: bool,
    full_tunnel_requires_explicit_underlay_exemptions: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SteamBypassCategories {
    bypass_categories: Vec<String>,
}
