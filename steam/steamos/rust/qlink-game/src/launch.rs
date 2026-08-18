use crate::GameProfile;
use std::path::Path;

pub const QLINK_GAME_SLICE: &str = "quantumlink-game.slice";
pub const QLINK_GAME_SCOPE_PREFIX: &str = "quantumlink-game-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameLaunchPlan {
    pub session_id: String,
    pub scope_unit: String,
    pub systemd_run_args: Vec<String>,
}

impl GameLaunchPlan {
    pub fn new(
        profile: &GameProfile,
        session_id: &str,
        qlinkctl_path: &Path,
        command: &str,
        command_args: &[String],
    ) -> Result<Self, String> {
        validate_session_id(session_id)?;
        if command.is_empty() {
            return Err("game command is required".to_string());
        }
        if !qlinkctl_path.is_absolute() {
            return Err("qlinkctl path must be absolute".to_string());
        }
        if !profile.matches_executable(command) {
            return Err(format!(
                "executable `{}` is not allowed by game profile `{}`",
                executable_basename(command),
                profile.id
            ));
        }

        let scope_unit = format!("{QLINK_GAME_SCOPE_PREFIX}{session_id}.scope");
        let mut systemd_run_args = vec![
            "--user".to_string(),
            "--scope".to_string(),
            "--quiet".to_string(),
            "--collect".to_string(),
            "--unit".to_string(),
            scope_unit.clone(),
            "--slice".to_string(),
            QLINK_GAME_SLICE.to_string(),
            qlinkctl_path.display().to_string(),
            "game".to_string(),
            "enter".to_string(),
            profile.id.clone(),
            session_id.to_string(),
            "--".to_string(),
            command.to_string(),
        ];
        systemd_run_args.extend(command_args.iter().cloned());

        Ok(Self {
            session_id: session_id.to_string(),
            scope_unit,
            systemd_run_args,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameCgroupIdentity {
    pub relative_path: String,
    pub level: u32,
    pub scope_unit: String,
}

pub fn validate_game_cgroup_path(
    path: &str,
    uid: u32,
    session_id: &str,
) -> Result<GameCgroupIdentity, String> {
    validate_session_id(session_id)?;
    if path.contains(" (deleted)") {
        return Err("game cgroup was deleted".to_string());
    }

    let components: Vec<&str> = path
        .strip_prefix('/')
        .ok_or_else(|| "game cgroup path must be absolute".to_string())?
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    if components.len() < 5 {
        return Err("game cgroup path is too shallow".to_string());
    }
    if components[0] != "user.slice" || components[1] != format!("user-{uid}.slice") {
        return Err("game cgroup is outside the caller user slice".to_string());
    }
    if !components.contains(&QLINK_GAME_SLICE) {
        return Err("game cgroup is outside the QuantumLink game slice".to_string());
    }

    let scope_unit = format!("{QLINK_GAME_SCOPE_PREFIX}{session_id}.scope");
    if components.last().copied() != Some(scope_unit.as_str()) {
        return Err("game cgroup scope does not match the launch session".to_string());
    }
    if components.iter().any(|component| {
        component.is_empty()
            || *component == "."
            || *component == ".."
            || !component.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b':')
            })
    }) {
        return Err("game cgroup path contains an invalid component".to_string());
    }

    Ok(GameCgroupIdentity {
        relative_path: components.join("/"),
        level: components.len() as u32,
        scope_unit,
    })
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty()
        || session_id.len() > 48
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(
            "game session ID must contain 1-48 lowercase ASCII letters or digits".to_string(),
        );
    }
    Ok(())
}

fn executable_basename(command: &str) -> &str {
    Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factorio_profile() -> GameProfile {
        GameProfile::from_toml_str(
            r#"
                id = "factorio"
                display_name = "Factorio"
                executables = ["factorio"]
                udp_ports = [34197]
                lan_discovery = true
                voice_chat_safe = true
                low_latency = true
            "#,
        )
        .unwrap()
    }

    #[test]
    fn builds_launch_bound_systemd_scope_without_a_shell() {
        let plan = GameLaunchPlan::new(
            &factorio_profile(),
            "s123abc",
            Path::new("/usr/local/bin/qlinkctl"),
            "/home/deck/factorio",
            &["--start-server".to_string(), "save.zip".to_string()],
        )
        .unwrap();

        assert_eq!(plan.scope_unit, "quantumlink-game-s123abc.scope");
        assert_eq!(plan.systemd_run_args[0], "--user");
        assert!(plan
            .systemd_run_args
            .windows(2)
            .any(|args| args == ["--slice", QLINK_GAME_SLICE]));
        assert!(!plan.systemd_run_args.iter().any(|arg| arg == "--wait"));
        let qlinkctl_index = plan
            .systemd_run_args
            .iter()
            .position(|arg| arg == "/usr/local/bin/qlinkctl")
            .unwrap();
        assert_eq!(
            &plan.systemd_run_args[qlinkctl_index..qlinkctl_index + 6],
            [
                "/usr/local/bin/qlinkctl",
                "game",
                "enter",
                "factorio",
                "s123abc",
                "--"
            ]
        );
    }

    #[test]
    fn rejects_an_executable_outside_the_profile() {
        let error = GameLaunchPlan::new(
            &factorio_profile(),
            "s123abc",
            Path::new("/usr/local/bin/qlinkctl"),
            "/usr/bin/steam",
            &[],
        )
        .unwrap_err();

        assert!(error.contains("not allowed"));
    }

    #[test]
    fn validates_the_exact_user_scope_and_depth() {
        let identity = validate_game_cgroup_path(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/quantumlink-game.slice/quantumlink-game-s123abc.scope",
            1000,
            "s123abc",
        )
        .unwrap();

        assert_eq!(identity.level, 6);
        assert_eq!(identity.scope_unit, "quantumlink-game-s123abc.scope");
        assert_eq!(
            identity.relative_path,
            "user.slice/user-1000.slice/user@1000.service/app.slice/quantumlink-game.slice/quantumlink-game-s123abc.scope"
        );
    }

    #[test]
    fn rejects_a_scope_from_another_user_or_session() {
        let path = "/user.slice/user-1001.slice/user@1001.service/app.slice/quantumlink-game.slice/quantumlink-game-wrong.scope";
        assert!(validate_game_cgroup_path(path, 1000, "s123abc").is_err());
        assert!(validate_game_cgroup_path(path, 1001, "s123abc").is_err());
    }
}
