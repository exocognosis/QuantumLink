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
