use qlink_proto::{RuntimeCapabilityStatus, SteamOsRuntimeCapabilities};

#[cfg(target_os = "linux")]
use std::os::unix::fs::FileTypeExt;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

pub fn detect_steamos_runtime_capabilities() -> SteamOsRuntimeCapabilities {
    detect_platform_capabilities()
}

#[cfg(target_os = "linux")]
fn detect_platform_capabilities() -> SteamOsRuntimeCapabilities {
    let cgroup_v2 = if Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
        RuntimeCapabilityStatus::supported()
    } else {
        RuntimeCapabilityStatus::unsupported("unified cgroup v2 is not mounted")
    };
    let tun = match std::fs::metadata("/dev/net/tun") {
        Ok(metadata) if metadata.file_type().is_char_device() => {
            RuntimeCapabilityStatus::supported()
        }
        Ok(_) => RuntimeCapabilityStatus::unsupported("/dev/net/tun is not a character device"),
        Err(error) => RuntimeCapabilityStatus::unavailable(format!("/dev/net/tun: {error}")),
    };
    let systemd_run = first_file(&["/usr/bin/systemd-run", "/usr/sbin/systemd-run"]);
    let systemd_user_scopes = if !Path::new("/run/systemd/system").is_dir() {
        RuntimeCapabilityStatus::unavailable("systemd is not the active service manager")
    } else if systemd_run.is_none() {
        RuntimeCapabilityStatus::unavailable("systemd-run is not installed in a trusted path")
    } else {
        RuntimeCapabilityStatus::supported()
    };
    let policykit = if !Path::new("/usr/bin/pkexec").is_file() {
        RuntimeCapabilityStatus::unavailable("/usr/bin/pkexec is not installed")
    } else if !Path::new("/usr/local/libexec/quantumlink-service-control").is_file() {
        RuntimeCapabilityStatus::unavailable("QuantumLink service helper is not installed")
    } else if !Path::new("/etc/polkit-1/rules.d/49-quantumlink-service-control.rules").is_file() {
        RuntimeCapabilityStatus::unavailable("QuantumLink PolicyKit rule is not installed")
    } else {
        RuntimeCapabilityStatus::supported()
    };
    let logind_session = match directory_has_entries("/run/systemd/sessions") {
        Ok(true) => RuntimeCapabilityStatus::supported(),
        Ok(false) => RuntimeCapabilityStatus::unavailable("no active logind session was found"),
        Err(error) => {
            RuntimeCapabilityStatus::unavailable(format!("cannot inspect logind sessions: {error}"))
        }
    };
    let nftables_cgroup_v2 = if cgroup_v2.state != qlink_proto::RuntimeCapabilityState::Supported {
        RuntimeCapabilityStatus::unsupported("nftables cgroup matching requires cgroup v2")
    } else {
        probe_nftables_cgroup_v2()
    };

    SteamOsRuntimeCapabilities {
        cgroup_v2,
        nftables_cgroup_v2,
        tun,
        systemd_user_scopes,
        policykit,
        logind_session,
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_platform_capabilities() -> SteamOsRuntimeCapabilities {
    let unsupported = || RuntimeCapabilityStatus::unsupported("Linux is required");
    SteamOsRuntimeCapabilities {
        cgroup_v2: unsupported(),
        nftables_cgroup_v2: unsupported(),
        tun: unsupported(),
        systemd_user_scopes: unsupported(),
        policykit: unsupported(),
        logind_session: unsupported(),
    }
}

#[cfg(target_os = "linux")]
fn probe_nftables_cgroup_v2() -> RuntimeCapabilityStatus {
    let Some(nft) = first_file(&["/usr/bin/nft", "/usr/sbin/nft"]) else {
        return RuntimeCapabilityStatus::unavailable("nft is not installed in a trusted path");
    };
    let cgroup = match std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| error.to_string())
        .and_then(|content| parse_unified_cgroup(&content))
    {
        Ok(cgroup) => cgroup,
        Err(error) => {
            return RuntimeCapabilityStatus::unavailable(format!(
                "cannot identify the qlinkd cgroup: {error}"
            ))
        }
    };
    let level = cgroup.split('/').count().to_string();
    let probe_table = format!("qlink_cap_probe_{}", std::process::id());
    let mut table_created = false;
    let result = (|| {
        run_nft(&nft, &["add", "table", "inet", &probe_table])?;
        table_created = true;
        run_nft(
            &nft,
            &[
                "add",
                "chain",
                "inet",
                &probe_table,
                "output",
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
        )?;
        let cgroup_literal = nft_string_literal(&cgroup);
        run_nft(
            &nft,
            &[
                "add",
                "rule",
                "inet",
                &probe_table,
                "output",
                "socket",
                "cgroupv2",
                "level",
                &level,
                &cgroup_literal,
                "counter",
            ],
        )
    })();
    let cleanup = table_created
        .then(|| run_nft(&nft, &["delete", "table", "inet", &probe_table]))
        .transpose();

    match (result, cleanup) {
        (Ok(()), Ok(_)) => RuntimeCapabilityStatus::supported(),
        (Ok(()), Err(error)) => RuntimeCapabilityStatus::unavailable(format!(
            "nftables cgroup probe cleanup failed: {error}"
        )),
        (Err(error), _) if is_kernel_unsupported_error(&error) => {
            RuntimeCapabilityStatus::unsupported(error)
        }
        (Err(error), _) => RuntimeCapabilityStatus::unavailable(error),
    }
}

#[cfg(target_os = "linux")]
fn first_file(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
}

#[cfg(target_os = "linux")]
fn directory_has_entries(path: &str) -> std::io::Result<bool> {
    Ok(std::fs::read_dir(path)?.next().transpose()?.is_some())
}

#[cfg(target_os = "linux")]
fn run_nft(program: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run {}: {error}", program.display()))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.lines().next().unwrap_or("nft command failed").trim();
    Err(format!("nftables cgroup probe failed: {detail}"))
}

#[cfg(any(target_os = "linux", test))]
fn parse_unified_cgroup(content: &str) -> Result<String, String> {
    let path = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "unified cgroup entry is missing".to_string())?;
    let relative = path.trim().trim_start_matches('/');
    if relative.is_empty() {
        return Err("process is attached to the cgroup root".to_string());
    }
    if relative.split('/').any(|component| {
        component.is_empty()
            || !component.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b':')
            })
    }) {
        return Err("cgroup path contains an unsupported component".to_string());
    }
    Ok(relative.to_string())
}

#[cfg(any(target_os = "linux", test))]
fn nft_string_literal(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
}

#[cfg(any(target_os = "linux", test))]
fn is_kernel_unsupported_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("no such file or directory")
        || error.contains("operation not supported")
        || error.contains("not supported")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_root_relative_unified_cgroup() {
        assert_eq!(
            parse_unified_cgroup("0::/user.slice/user-1000.slice/app.scope\n").unwrap(),
            "user.slice/user-1000.slice/app.scope"
        );
    }

    #[test]
    fn rejects_root_and_unsafe_cgroup_paths() {
        assert!(parse_unified_cgroup("0::/\n").is_err());
        assert!(parse_unified_cgroup("0::/user.slice/bad path.scope\n").is_err());
    }

    #[test]
    fn classifies_kernel_feature_errors() {
        assert!(is_kernel_unsupported_error(
            "Could not process rule: No such file or directory"
        ));
        assert!(is_kernel_unsupported_error("Operation not supported"));
        assert!(!is_kernel_unsupported_error("Permission denied"));
    }

    #[test]
    fn encodes_nft_string_literals() {
        assert_eq!(nft_string_literal("a\\b\"c"), "\"a\\\\b\\\"c\"");
    }
}
