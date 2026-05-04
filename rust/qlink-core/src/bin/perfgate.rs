//! Compares observed perf-bench output against a stored baseline and
//! exits with a non-zero status when any metric regresses past the
//! configured threshold.
//!
//! Two metric kinds are supported:
//!
//! - `slo_p50_ms` — parses `slo.*: n=<N> p50=<value><unit> ...` lines from
//!   the given log files (the SLO scenario harness emits one per scenario).
//! - `criterion_estimate` — reads
//!   `<criterion-dir>/<metric-name>/new/estimates.json` and uses the
//!   `mean.point_estimate` field (criterion's default mean estimate, in ns).
//!
//! Skipping rules: if the relevant flag (`--slo-log` for SLO metrics,
//! `--criterion-dir` for criterion metrics) is not supplied, baseline
//! entries of that kind are silently skipped — handy for local runs that
//! only cover one bench surface. If the flag *is* supplied but a metric's
//! data is absent, that's a hard failure (the bench probably broke).
//!
//! See `docs/perf-baseline.json` for the baseline schema and
//! `docs/perf-baseline.md` for the SLO targets.

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process,
};

#[derive(Debug, Parser)]
#[command(
    name = "perfgate",
    about = "Diff perf bench output against a stored baseline; exit 1 on regression."
)]
struct Cli {
    /// Path to the baseline JSON.
    #[arg(long, default_value = "docs/perf-baseline.json")]
    baseline: PathBuf,
    /// SLO bench log file. Repeat the flag to feed in multiple logs
    /// (e.g. `--slo-log build/perf-slos.log --slo-log build/perf-slos-wan.log`).
    #[arg(long = "slo-log")]
    slo_logs: Vec<PathBuf>,
    /// Root of the criterion output directory (typically `target/criterion`).
    #[arg(long)]
    criterion_dir: Option<PathBuf>,
    /// Override the regression threshold (percent) from the baseline file.
    #[arg(long)]
    threshold_pct: Option<f64>,
    /// Print the report but always exit 0. Useful for previewing the
    /// gate output during baseline refreshes.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct Baseline {
    regression_threshold_pct: f64,
    #[serde(default)]
    captured_at: String,
    #[serde(default)]
    captured_on: Option<String>,
    metrics: Vec<BaselineMetric>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BaselineMetric {
    name: String,
    kind: BaselineKind,
    value_ms: f64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BaselineKind {
    SloP50Ms,
    CriterionEstimate,
}

impl BaselineKind {
    fn label(self) -> &'static str {
        match self {
            BaselineKind::SloP50Ms => "slo p50",
            BaselineKind::CriterionEstimate => "criterion",
        }
    }
}

#[derive(Debug, Deserialize)]
struct CriterionFile {
    mean: CriterionMean,
}

#[derive(Debug, Deserialize)]
struct CriterionMean {
    point_estimate: f64,
}

/// Parses the unit-tagged numbers `Duration`'s `Debug` impl produces
/// (e.g. "1.9ms", "204.9ms", "28.0µs", "1.6s") to milliseconds.
/// Returns `None` if the suffix isn't recognized.
fn parse_duration_ms(token: &str) -> Option<f64> {
    // Order matters: "ms" must be checked before "s", and Greek µ before
    // ascii "u" so "µs" doesn't fall through to the "s" branch.
    if let Some(rest) = token.strip_suffix("ns") {
        return rest.parse::<f64>().ok().map(|v| v / 1_000_000.0);
    }
    if let Some(rest) = token.strip_suffix("µs") {
        return rest.parse::<f64>().ok().map(|v| v / 1_000.0);
    }
    if let Some(rest) = token.strip_suffix("us") {
        return rest.parse::<f64>().ok().map(|v| v / 1_000.0);
    }
    if let Some(rest) = token.strip_suffix("ms") {
        return rest.parse::<f64>().ok();
    }
    if let Some(rest) = token.strip_suffix('s') {
        return rest.parse::<f64>().ok().map(|v| v * 1_000.0);
    }
    None
}

/// Extracts the `<label> -> p50_ms` map from a SLO scenario log.
/// Recognized lines start with `slo.` or `slo_wan.` and follow the
/// shape:
///
/// ```text
/// slo.direct_warm: n=30 p50=1.9ms p90=2.1ms p99=2.7ms max=2.7ms
/// slo.direct_warm.cable (direct=15 relay=0): n=15 p50=160.4ms p90=189.5ms p99=199.9ms max=199.9ms
/// ```
///
/// The optional `(direct=N relay=M)` parenthetical attached to the
/// WAN bench's direct + post-event lines is stripped from the label
/// because its contents shift run-to-run with the success rate, and
/// a stable-name baseline is what the gate compares against.
fn parse_slo_log(text: &str) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("slo.") && !trimmed.starts_with("slo_wan.") {
            continue;
        }
        let (label, rest) = match trimmed.split_once(": ") {
            Some(parts) => parts,
            None => continue,
        };
        let label = strip_label_annotation(label);
        for token in rest.split_whitespace() {
            if let Some(value) = token.strip_prefix("p50=") {
                if let Some(ms) = parse_duration_ms(value) {
                    out.insert(label.to_string(), ms);
                }
                break;
            }
        }
    }
    out
}

/// Drops a trailing ` (...)` annotation from a SLO label so the
/// stable name can be used as a baseline key. Whitespace before the
/// `(` is also trimmed. Labels without a parenthetical pass through
/// unchanged.
fn strip_label_annotation(label: &str) -> &str {
    match label.find(" (") {
        Some(idx) => &label[..idx],
        None => label,
    }
}

fn read_criterion_estimate_ms(criterion_dir: &Path, name: &str) -> Option<f64> {
    let path = criterion_dir.join(name).join("new").join("estimates.json");
    let bytes = fs::read(&path).ok()?;
    let parsed: CriterionFile = serde_json::from_slice(&bytes).ok()?;
    Some(parsed.mean.point_estimate / 1_000_000.0) // ns → ms
}

#[derive(Debug)]
struct Row {
    name: String,
    kind: BaselineKind,
    baseline_ms: f64,
    observed_ms: Option<f64>,
    delta_pct: Option<f64>,
    status: Status,
}

#[derive(Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Regressed,
    Skipped,
    Missing,
}

impl Status {
    fn tag(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Regressed => "REGRESSED",
            Status::Skipped => "skipped",
            Status::Missing => "MISSING",
        }
    }
}

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("perfgate: {}", msg.as_ref());
    process::exit(2);
}

fn main() {
    let cli = Cli::parse();

    let baseline_text = fs::read_to_string(&cli.baseline).unwrap_or_else(|err| {
        fail(format!(
            "failed to read baseline at {}: {err}",
            cli.baseline.display()
        ));
    });
    let baseline: Baseline = serde_json::from_str(&baseline_text)
        .unwrap_or_else(|err| fail(format!("failed to parse baseline JSON: {err}")));

    let threshold = cli.threshold_pct.unwrap_or(baseline.regression_threshold_pct);
    if !threshold.is_finite() || threshold <= 0.0 {
        fail(format!("threshold_pct must be > 0; got {threshold}"));
    }

    // Aggregate observed SLO p50s across every supplied log file. Later
    // files override earlier ones if they emit the same label (last-wins
    // matches operator intuition for re-running a single bench).
    let mut observed_slos: BTreeMap<String, f64> = BTreeMap::new();
    for path in &cli.slo_logs {
        let text = fs::read_to_string(path).unwrap_or_else(|err| {
            fail(format!(
                "failed to read SLO log at {}: {err}",
                path.display()
            ));
        });
        for (name, value) in parse_slo_log(&text) {
            observed_slos.insert(name, value);
        }
    }

    let slo_logs_present = !cli.slo_logs.is_empty();

    let mut rows: Vec<Row> = Vec::with_capacity(baseline.metrics.len());
    for metric in &baseline.metrics {
        let observed = match metric.kind {
            BaselineKind::SloP50Ms => {
                if !slo_logs_present {
                    None
                } else {
                    Some(observed_slos.get(&metric.name).copied())
                }
            }
            BaselineKind::CriterionEstimate => match cli.criterion_dir.as_deref() {
                None => None,
                Some(dir) => Some(read_criterion_estimate_ms(dir, &metric.name)),
            },
        };
        match observed {
            None => rows.push(Row {
                name: metric.name.clone(),
                kind: metric.kind,
                baseline_ms: metric.value_ms,
                observed_ms: None,
                delta_pct: None,
                status: Status::Skipped,
            }),
            Some(None) => rows.push(Row {
                name: metric.name.clone(),
                kind: metric.kind,
                baseline_ms: metric.value_ms,
                observed_ms: None,
                delta_pct: None,
                status: Status::Missing,
            }),
            Some(Some(observed_ms)) => {
                let delta_pct = (observed_ms - metric.value_ms) / metric.value_ms * 100.0;
                let status = if delta_pct > threshold {
                    Status::Regressed
                } else {
                    Status::Ok
                };
                rows.push(Row {
                    name: metric.name.clone(),
                    kind: metric.kind,
                    baseline_ms: metric.value_ms,
                    observed_ms: Some(observed_ms),
                    delta_pct: Some(delta_pct),
                    status,
                });
            }
        }
    }

    // Print a tidy text table. Width fits inside a typical 80-col CI log
    // line, but wraps cleanly in a GitHub step summary block.
    println!(
        "perfgate — baseline: {} (threshold: {:.1}%)",
        cli.baseline.display(),
        threshold
    );
    if !baseline.captured_at.is_empty() {
        println!("baseline captured: {}", baseline.captured_at);
    }
    if let Some(captured_on) = baseline.captured_on.as_ref() {
        println!("baseline captured on: {captured_on}");
    }
    println!();
    println!(
        "{:<46}  {:<10}  {:>11}  {:>11}  {:>9}  {}",
        "metric", "kind", "baseline", "observed", "delta", "status"
    );
    println!("{}", "-".repeat(46 + 2 + 10 + 2 + 11 + 2 + 11 + 2 + 9 + 2 + 9));
    for row in &rows {
        let observed_disp = row
            .observed_ms
            .map(|v| format!("{v:>9.3} ms"))
            .unwrap_or_else(|| "          —".into());
        let delta_disp = row
            .delta_pct
            .map(|v| format!("{v:+8.1}%"))
            .unwrap_or_else(|| "        —".into());
        println!(
            "{:<46}  {:<10}  {:>9.3} ms  {}  {}  {}",
            row.name,
            row.kind.label(),
            row.baseline_ms,
            observed_disp,
            delta_disp,
            row.status.tag()
        );
    }

    let regressed: Vec<&Row> = rows.iter().filter(|r| r.status == Status::Regressed).collect();
    let missing: Vec<&Row> = rows.iter().filter(|r| r.status == Status::Missing).collect();

    println!();
    println!(
        "summary: {} ok, {} regressed, {} missing, {} skipped",
        rows.iter().filter(|r| r.status == Status::Ok).count(),
        regressed.len(),
        missing.len(),
        rows.iter().filter(|r| r.status == Status::Skipped).count()
    );

    if !missing.is_empty() {
        eprintln!();
        eprintln!("perfgate: {} metric(s) had no observed value despite their data source being supplied:", missing.len());
        for row in &missing {
            eprintln!("  - {} ({:?})", row.name, row.kind);
        }
    }
    if !regressed.is_empty() {
        eprintln!();
        eprintln!(
            "perfgate: {} metric(s) regressed past {:.1}%:",
            regressed.len(),
            threshold
        );
        for row in &regressed {
            if let (Some(observed), Some(delta)) = (row.observed_ms, row.delta_pct) {
                eprintln!(
                    "  - {}: {:.3} ms → {:.3} ms ({:+.1}%)",
                    row.name, row.baseline_ms, observed, delta
                );
            }
        }
    }

    let any_failure = !regressed.is_empty() || !missing.is_empty();
    if any_failure && !cli.dry_run {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_handles_every_unit_the_harness_emits() {
        assert_eq!(parse_duration_ms("0ns"), Some(0.0));
        assert_eq!(parse_duration_ms("500ns"), Some(0.0005));
        assert_eq!(parse_duration_ms("28.0µs"), Some(0.028));
        assert_eq!(parse_duration_ms("28.0us"), Some(0.028));
        assert_eq!(parse_duration_ms("1.9ms"), Some(1.9));
        assert_eq!(parse_duration_ms("1.6s"), Some(1_600.0));
        assert_eq!(parse_duration_ms("garbage"), None);
        assert_eq!(parse_duration_ms("1.9 ms"), None, "no spaces in Debug output");
    }

    #[test]
    fn slo_log_parser_extracts_p50_for_loopback_and_wan_lines() {
        let log = "\
# QuantumLink SLO scenarios — product.md targets
slo.direct_warm: n=30 p50=1.9ms p90=2.1ms p99=2.7ms max=2.7ms
slo.post_event_recovery: n=30 p50=2.0ms p90=2.0ms p99=2.3ms max=2.3ms
slo.relay_fallback: n=30 p50=204.9ms p90=206.5ms p99=208.6ms max=208.6ms
ignore me
slo_wan.cable.direct_warm: n=15 p50=160.4ms p90=189.5ms p99=199.9ms max=199.9ms
";
        let parsed = parse_slo_log(log);
        assert_eq!(parsed.get("slo.direct_warm").copied(), Some(1.9));
        assert_eq!(parsed.get("slo.post_event_recovery").copied(), Some(2.0));
        assert_eq!(parsed.get("slo.relay_fallback").copied(), Some(204.9));
        assert_eq!(parsed.get("slo_wan.cable.direct_warm").copied(), Some(160.4));
        assert_eq!(parsed.len(), 4);
    }

    #[test]
    fn slo_log_parser_skips_malformed_lines_without_panicking() {
        let log = "\
slo.no_p50_field: n=30 p99=5ms
slo.broken
slo.unparseable_unit: n=30 p50=4.2eons
slo.ok: n=10 p50=3.5ms
";
        let parsed = parse_slo_log(log);
        // Only the well-formed line survives.
        assert_eq!(parsed.get("slo.ok").copied(), Some(3.5));
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn slo_log_parser_strips_run_specific_annotation_from_wan_labels() {
        // The WAN bench's direct + post-event lines append a
        // `(direct=N relay=M)` annotation to the label that shifts
        // run-to-run with the success rate. The parser must strip
        // that so a stable-name baseline can match.
        let log = "\
slo.direct_warm.lan (direct=15 relay=0): n=15 p50=15.5ms p90=16.8ms p99=17.2ms max=17.2ms
slo.direct_warm.cable (direct=14 relay=1): n=15 p50=162.1ms p90=173.1ms p99=180.3ms max=180.3ms
slo.relay_fallback.lan: n=15 p50=204.6ms p90=206.5ms p99=207.0ms max=207.0ms
";
        let parsed = parse_slo_log(log);
        assert_eq!(parsed.get("slo.direct_warm.lan").copied(), Some(15.5));
        // Same metric, different run — the same baseline row matches
        // even though the annotation changed direct count.
        assert_eq!(parsed.get("slo.direct_warm.cable").copied(), Some(162.1));
        assert_eq!(parsed.get("slo.relay_fallback.lan").copied(), Some(204.6));
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn strip_label_annotation_only_strips_trailing_paren_block() {
        assert_eq!(strip_label_annotation("slo.direct_warm.lan"), "slo.direct_warm.lan");
        assert_eq!(
            strip_label_annotation("slo.direct_warm.cable (direct=15 relay=0)"),
            "slo.direct_warm.cable"
        );
        // No-op when there's no leading space before the paren.
        assert_eq!(
            strip_label_annotation("slo.bench(no-space)"),
            "slo.bench(no-space)"
        );
    }
}
