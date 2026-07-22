use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
