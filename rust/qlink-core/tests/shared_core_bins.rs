use std::fs;
use std::process::Command;

fn qlink_devctl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_qlink-devctl"))
}

fn perfgate() -> Command {
    Command::new(env!("CARGO_BIN_EXE_perfgate"))
}

#[test]
fn qlink_devctl_help_lists_local_smoke_command() {
    let output = qlink_devctl()
        .arg("--help")
        .output()
        .expect("qlink-devctl --help runs");

    assert!(
        output.status.success(),
        "status: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(stdout.contains("replay-smoke"), "{stdout}");
}

#[test]
fn qlink_devctl_replay_smoke_exercises_core_logic() {
    let output = qlink_devctl()
        .arg("replay-smoke")
        .output()
        .expect("qlink-devctl replay-smoke runs");

    assert!(
        output.status.success(),
        "status: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains("qlink-devctl: replay smoke passed"),
        "{stdout}"
    );
}

#[test]
fn perfgate_validates_baseline_slo_logs_and_criterion_directory() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let baseline = tempdir.path().join("baseline.json");
    let slo_log = tempdir.path().join("slo.log");
    let criterion_dir = tempdir.path().join("criterion");
    fs::create_dir(&criterion_dir).expect("criterion dir");
    fs::write(
        &baseline,
        r#"{
  "regression_threshold_pct": 20.0,
  "metrics": [
    { "name": "slo.direct_warm", "kind": "slo_p50_ms", "value_ms": 1.9 }
  ]
}"#,
    )
    .expect("baseline");
    fs::write(&slo_log, "slo.direct_warm p50_ms=1.9\n").expect("slo log");

    let output = perfgate()
        .arg("--baseline")
        .arg(&baseline)
        .arg("--slo-log")
        .arg(&slo_log)
        .arg("--criterion-dir")
        .arg(&criterion_dir)
        .output()
        .expect("perfgate runs");

    assert!(
        output.status.success(),
        "status: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains("perfgate: structural validation passed"),
        "{stdout}"
    );
}

#[test]
fn perfgate_rejects_malformed_baseline_json() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let baseline = tempdir.path().join("baseline.json");
    fs::write(&baseline, "{ not json").expect("baseline");

    let output = perfgate()
        .arg("--baseline")
        .arg(&baseline)
        .output()
        .expect("perfgate runs");

    assert!(!output.status.success(), "perfgate unexpectedly succeeded");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");
    assert!(stderr.contains("malformed baseline JSON"), "{stderr}");
}

#[test]
fn perfgate_rejects_negative_regression_threshold() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let baseline = tempdir.path().join("baseline.json");
    fs::write(
        &baseline,
        r#"{
  "regression_threshold_pct": -1.0,
  "metrics": [
    { "name": "slo.direct_warm", "kind": "slo_p50_ms", "value_ms": 1.9 }
  ]
}"#,
    )
    .expect("baseline");

    let output = perfgate()
        .arg("--baseline")
        .arg(&baseline)
        .output()
        .expect("perfgate runs");

    assert!(!output.status.success(), "perfgate unexpectedly succeeded");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");
    assert!(
        stderr.contains("regression_threshold_pct must be a non-negative number"),
        "{stderr}"
    );
}

#[test]
fn perfgate_rejects_negative_metric_value_ms() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let baseline = tempdir.path().join("baseline.json");
    fs::write(
        &baseline,
        r#"{
  "regression_threshold_pct": 20.0,
  "metrics": [
    { "name": "slo.direct_warm", "kind": "slo_p50_ms", "value_ms": -0.1 }
  ]
}"#,
    )
    .expect("baseline");

    let output = perfgate()
        .arg("--baseline")
        .arg(&baseline)
        .output()
        .expect("perfgate runs");

    assert!(!output.status.success(), "perfgate unexpectedly succeeded");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");
    assert!(
        stderr.contains("metrics[0].value_ms must be a non-negative number"),
        "{stderr}"
    );
}

#[test]
fn perfgate_rejects_missing_baseline_file() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let baseline = tempdir.path().join("missing.json");

    let output = perfgate()
        .arg("--baseline")
        .arg(&baseline)
        .output()
        .expect("perfgate runs");

    assert!(!output.status.success(), "perfgate unexpectedly succeeded");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");
    assert!(
        stderr.contains("failed to read required baseline"),
        "{stderr}"
    );
}
