use clap::Parser;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "perfgate",
    about = "Structurally validate QuantumLink performance inputs"
)]
struct Cli {
    /// Machine-readable performance baseline JSON.
    #[arg(long)]
    baseline: PathBuf,

    /// Optional SLO log files to prove the referenced inputs are readable.
    #[arg(long = "slo-log")]
    slo_logs: Vec<PathBuf>,

    /// Optional Criterion output directory to prove the referenced input exists.
    #[arg(long = "criterion-dir")]
    criterion_dir: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("perfgate: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let baseline = read_baseline(&cli.baseline)?;
    validate_baseline(&baseline)?;

    for path in &cli.slo_logs {
        read_file(path, "SLO log")?;
    }

    if let Some(path) = &cli.criterion_dir {
        read_directory(path, "Criterion directory")?;
    }

    println!("perfgate: structural validation passed");
    Ok(())
}

fn read_baseline(path: &Path) -> Result<Value, String> {
    let bytes = read_file(path, "required baseline")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("malformed baseline JSON {}: {error}", path.display()))
}

fn read_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("failed to read {label} {}: {error}", path.display()))
}

fn read_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} {} is not a directory", label, path.display()));
    }
    fs::read_dir(path)
        .map_err(|error| format!("failed to read {label} {}: {error}", path.display()))?;
    Ok(())
}

fn validate_baseline(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "baseline JSON must be an object".to_string())?;

    if let Some(threshold) = object.get("regression_threshold_pct") {
        require_number(threshold, "regression_threshold_pct")?;
    }

    let metrics = object
        .get("metrics")
        .and_then(Value::as_array)
        .ok_or_else(|| "baseline JSON must contain a metrics array".to_string())?;

    for (index, metric) in metrics.iter().enumerate() {
        let metric = metric
            .as_object()
            .ok_or_else(|| format!("metrics[{index}] must be an object"))?;
        validate_metric(index, metric)?;
    }

    Ok(())
}

fn validate_metric(index: usize, metric: &Map<String, Value>) -> Result<(), String> {
    require_string(metric.get("name"), &format!("metrics[{index}].name"))?;
    require_string(metric.get("kind"), &format!("metrics[{index}].kind"))?;
    require_number_value(
        metric.get("value_ms"),
        &format!("metrics[{index}].value_ms"),
    )?;
    Ok(())
}

fn require_string(value: Option<&Value>, field: &str) -> Result<(), String> {
    match value.and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err(format!("{field} must be a non-empty string")),
    }
}

fn require_number_value(value: Option<&Value>, field: &str) -> Result<(), String> {
    match value {
        Some(value) => require_number(value, field),
        None => Err(format!("{field} must be a number")),
    }
}

fn require_number(value: &Value, field: &str) -> Result<(), String> {
    match value.as_f64() {
        Some(number) if number >= 0.0 => Ok(()),
        Some(_) => Err(format!("{field} must be a non-negative number")),
        None => Err(format!("{field} must be a number")),
    }
}
