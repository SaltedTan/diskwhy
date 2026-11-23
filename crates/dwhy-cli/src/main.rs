//! `dwhy`: command-line front end for diskwhy.
//!
//! Exit codes (docs/DESIGN.md): 0 ok, 1 error (including usage errors),
//! 2 items skipped by a guard or changed fingerprint, 3 refused by policy.

mod guide;
mod human;

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use dwhy_core::apply::{self, Audit, Check, Policy};
use dwhy_core::detect;
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::policy::PolicyConfig;
use dwhy_core::report::{
    DEFAULT_SUMMARY_DEPTH, DEFAULT_SUMMARY_DIRS, DEFAULT_SUMMARY_FINDINGS, ErrorKind, ErrorReport,
    SummaryLimits, Tier,
};
use dwhy_core::scan::{self, Progress};
use dwhy_core::{doctor, ops, snapshot, units};

pub const EXIT_OK: u8 = 0;
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_SKIPPED: u8 = 2;
pub const EXIT_REFUSED: u8 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "dwhy",
    version,
    about = "Why is my disk filling up, and what is safe to remove?",
    long_about = None,
    after_help = "\
Workflow: `dwhy scan PATH` finds what is large and reclaimable, `dwhy plan PATH -o FILE`
selects findings and checks guards, `dwhy apply FILE --yes` removes what the tier policy
allows (default: regenerable only). Agents and scripts: run `dwhy guide` first.

Exit codes: 0 ok, 1 error, 2 items skipped or a `--select` finding blocked by a guard,
3 refused by policy."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Measure disk usage and find what is reclaimable: sizes, findings, unreadable directories,
    /// and space df counts but the scan cannot see.
    #[command(after_help = "\
`scan` runs detector guards only: an empty `guards` list on a finding does not mean the
pre-removal git, process and container guards passed. `plan`, `apply` and `explain` run them.

Exit codes: 0 ok, 1 error.")]
    Scan(ScanArgs),
    /// Select findings for removal and write a plan for `dwhy apply` (guards run, nothing is removed).
    #[command(after_help = "\
Exit codes: 0 ok, 1 error, 2 a `--select` finding was blocked by a guard (the plan is still
written).")]
    Plan(PlanArgs),
    /// Carry out a plan: re-detect, re-run the guards, and remove what the tier policy allows.
    #[command(after_help = "\
/etc/diskwhy/policy.toml and ~/.config/diskwhy/policy.toml can lower --max-tier and require a
terminal for (or refuse) review items; neither flags nor the user file can raise /etc.

Exit codes: 0 ok, 1 error or a failed removal, 2 items skipped by a guard or a changed
fingerprint, 3 refused by policy (above --max-tier or policy.toml, no --confirm), no terminal
and no --yes, or the plan is expired or from another host or user (make a fresh plan).")]
    Apply(ApplyArgs),
    /// Show what grew since a snapshot (`scan --snapshot`): rescans now and compares.
    #[command(after_help = "\
Snapshots record only directories of at least 100 MiB; smaller directories are not compared.

Exit codes: 0 ok, 1 error.")]
    Diff(DiffArgs),
    /// Measure growth now: walks twice, --for apart, and reports bytes per minute (writes nothing).
    #[command(after_help = "Exit codes: 0 ok, 1 error.")]
    Watch(WatchArgs),
    /// Explain one finding, by id or path: evidence, guards, growth, action and recovery cost.
    #[command(after_help = "Exit codes: 0 ok, 1 error.")]
    Explain(ExplainArgs),
    /// Open the TUI (what bare `dwhy` does on the current directory): browse sizes and findings,
    /// mark findings, preview or save plans, and apply with confirmation.
    Tui(TuiArgs),
    /// Show permissions, optional tools on PATH, and which detectors and probes they enable.
    #[command(after_help = "Exit codes: 0 ok, 1 error.")]
    Doctor {
        /// Print diskwhy/v1 JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Show what `dwhy apply` and the TUI did: the audit log's records, newest first.
    #[command(after_help = "\
Records are read from $XDG_STATE_HOME/diskwhy/audit.jsonl (else ~/.local/state/diskwhy/).
Each removal has a `start` record before it runs and an `end` record with its outcome.

Exit codes: 0 ok (also when there is no audit log yet), 1 error.")]
    Audit(AuditArgs),
    /// Print a concise quickstart for AI agents and automation (version-matched).
    #[command(after_help = "Exit codes: 0 ok, 1 error.")]
    Guide,
}

#[derive(Args, Debug)]
struct AuditArgs {
    /// Show the newest N records (0: all).
    #[arg(long, value_name = "N", default_value_t = apply::AUDIT_DEFAULT_LIMIT)]
    limit: usize,
    /// Print diskwhy/v1 JSON instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Directories to scan (default: the current directory).
    paths: Vec<PathBuf>,
    /// Print diskwhy/v1 JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Stay on one filesystem (the default; accepted for du muscle memory).
    #[arg(short = 'x', long = "one-file-system")]
    one_file_system: bool,
    /// Descend into other filesystems mounted below the roots (never into proc, sysfs, ...).
    #[arg(long, conflicts_with = "one_file_system")]
    cross_filesystems: bool,
    /// Smallest directory to report [default: 1% of the scanned total, at most 100M].
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size)]
    min_size: Option<u64>,
    /// Text output: how many levels of the directory tree to show; with --summary, also the
    /// deepest level kept in the JSON `scan.dirs`.
    #[arg(long, default_value_t = DEFAULT_SUMMARY_DEPTH)]
    depth: u32,
    /// Text output: largest children shown per directory.
    #[arg(long, default_value_t = 8)]
    top: usize,
    /// Worker threads [default: one per CPU].
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// No progress line on stderr (implied by --json).
    #[arg(short, long)]
    quiet: bool,
    /// Only measure; do not run detectors.
    #[arg(long, conflicts_with = "detectors")]
    no_detectors: bool,
    /// Run only these detectors (comma-separated names, see `dwhy doctor`).
    #[arg(long, value_delimiter = ',', value_name = "NAME,…")]
    detectors: Option<Vec<String>>,
    /// Findings listed before "… N more" in text output; with --summary, also the most
    /// findings kept in the JSON `findings`.
    #[arg(long, default_value_t = DEFAULT_SUMMARY_FINDINGS)]
    max_findings: usize,
    /// Only report findings in these tiers (comma-separated: regenerable, rebuildable, review,
    /// blocked).
    #[arg(long, value_enum, value_delimiter = ',', value_name = "TIER,…")]
    tier: Option<Vec<ScanTierArg>>,
    /// Compact report for agents: keep the largest directories (--depth deep, 25 at most) and
    /// --max-findings findings, and add `findings_summary` totals over every finding.
    #[arg(long)]
    summary: bool,
    /// Save a snapshot for `dwhy diff` under ~/.local/state/diskwhy/snapshots (old ones are
    /// pruned). It holds the whole scan, whatever --tier and --summary leave out.
    #[arg(long)]
    snapshot: bool,
}

/// Tiers `scan --tier` accepts: exactly these, `blocked` included.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ScanTierArg {
    Regenerable,
    Rebuildable,
    Review,
    Blocked,
}

impl From<ScanTierArg> for Tier {
    fn from(t: ScanTierArg) -> Tier {
        match t {
            ScanTierArg::Regenerable => Tier::Regenerable,
            ScanTierArg::Rebuildable => Tier::Rebuildable,
            ScanTierArg::Review => Tier::Review,
            ScanTierArg::Blocked => Tier::Blocked,
        }
    }
}

#[derive(Args, Debug)]
struct TuiArgs {
    /// Directories to scan (default: the current directory).
    paths: Vec<PathBuf>,
    /// Stay on one filesystem (the default; accepted for du muscle memory).
    #[arg(short = 'x', long = "one-file-system")]
    one_file_system: bool,
    /// Descend into other filesystems mounted below the roots (never into proc, sysfs, ...).
    #[arg(long, conflicts_with = "one_file_system")]
    cross_filesystems: bool,
    /// Preview a plan file written by `dwhy plan -o` instead of scanning (it names its own roots).
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["paths", "one_file_system", "cross_filesystems"]
    )]
    plan: Option<PathBuf>,
    /// Applying from the TUI only shows what would happen: `y` is a dry run too.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug)]
struct DiffArgs {
    /// Directories to rescan [default: the roots of the snapshot compared with].
    paths: Vec<PathBuf>,
    /// Snapshot to compare with (taken by `scan --snapshot`): last (the newest), an id, a file,
    /// a duration (24h, 7d: the newest at least that old) or an RFC 3339 time (the newest
    /// taken by then).
    #[arg(long, default_value = "last", value_name = "WHEN")]
    since: String,
    /// Also save the fresh scan as a snapshot.
    #[arg(long)]
    snapshot: bool,
    /// Print diskwhy/v1 JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Leave out directories, Docker objects and findings whose size changed by less than this
    /// (either way).
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size, default_value = "10M")]
    min_change: u64,
    /// Descend into other filesystems mounted below the PATHs given (needs PATH; without PATH,
    /// diff reuses the snapshot's roots and setting).
    #[arg(long, requires = "paths")]
    cross_filesystems: bool,
    /// Only measure; do not run detectors (findings are not compared).
    #[arg(long, conflicts_with = "detectors")]
    no_detectors: bool,
    /// Run only these detectors (comma-separated names, see `dwhy doctor`).
    #[arg(long, value_delimiter = ',', value_name = "NAME,…")]
    detectors: Option<Vec<String>>,
    /// Text output: entries listed per section.
    #[arg(long, default_value_t = 15)]
    top: usize,
    /// Worker threads [default: one per CPU].
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// No progress line on stderr (implied by --json).
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args, Debug)]
struct WatchArgs {
    /// Directories to watch (default: the current directory).
    paths: Vec<PathBuf>,
    /// How long to watch: the second walk starts this long after the first one started
    /// (30s, 5m, 1h).
    #[arg(long = "for", default_value = "60s", value_name = "DURATION", value_parser = parse_window)]
    window: u64,
    /// Print diskwhy/v1 JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Leave out directories and Docker objects that changed by less than this.
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size, default_value = "1M")]
    min_change: u64,
    /// Stay on one filesystem (the default; accepted for du muscle memory).
    #[arg(short = 'x', long = "one-file-system")]
    one_file_system: bool,
    /// Descend into other filesystems mounted below the roots (never into proc, sysfs, ...).
    #[arg(long, conflicts_with = "one_file_system")]
    cross_filesystems: bool,
    /// Do not ask the Docker daemon for its figures.
    #[arg(long)]
    no_docker: bool,
    /// Text output: entries listed per section.
    #[arg(long, default_value_t = 15)]
    top: usize,
    /// Worker threads [default: one per CPU].
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// No progress line on stderr (implied by --json).
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args, Debug)]
struct ExplainArgs {
    /// A finding id (f_…, looked up in the snapshots), a path, or a pseudo-path
    /// such as docker://volume/NAME.
    target: OsString,
    /// Print diskwhy/v1 JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Run only these detectors (comma-separated names, see `dwhy doctor`).
    #[arg(long, value_delimiter = ',', value_name = "NAME,…")]
    detectors: Option<Vec<String>>,
    /// Worker threads [default: one per CPU].
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// No progress line on stderr (implied by --json).
    #[arg(short, long)]
    quiet: bool,
}

/// `--for`: a duration of at least a second.
fn parse_window(s: &str) -> std::result::Result<u64, String> {
    match units::parse_duration(s)? {
        n if n >= 1 => Ok(n as u64),
        _ => Err("must be at least 1s".into()),
    }
}

/// Tiers `--tier` accepts (`blocked` is never selected).
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum TierArg {
    Regenerable,
    Rebuildable,
    Review,
}

impl From<TierArg> for Tier {
    fn from(t: TierArg) -> Tier {
        match t {
            TierArg::Regenerable => Tier::Regenerable,
            TierArg::Rebuildable => Tier::Rebuildable,
            TierArg::Review => Tier::Review,
        }
    }
}

#[derive(Args, Debug)]
struct PlanArgs {
    /// Directories to scan (default: the current directory).
    paths: Vec<PathBuf>,
    /// Highest tier to select [default: regenerable, or no limit with --select].
    #[arg(long, value_enum)]
    tier: Option<TierArg>,
    /// Select these findings only: ids or paths (comma-separated or repeated).
    #[arg(long, value_delimiter = ',', value_name = "ID|PATH,…")]
    select: Vec<String>,
    /// Select cheapest tiers first (largest within each tier) until at least SIZE bytes are planned.
    #[arg(long, value_name = "SIZE", value_parser = parse_free_target, conflicts_with = "select")]
    free: Option<u64>,
    /// Write the plan (diskwhy/v1 JSON) to this file.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Print the plan as diskwhy/v1 JSON instead of a summary.
    #[arg(long)]
    json: bool,
    /// Stay on one filesystem (the default).
    #[arg(short = 'x', long = "one-file-system")]
    one_file_system: bool,
    /// Descend into other filesystems mounted below the roots.
    #[arg(long, conflicts_with = "one_file_system")]
    cross_filesystems: bool,
    /// Run only these detectors (comma-separated names, see `dwhy doctor`).
    #[arg(long, value_delimiter = ',', value_name = "NAME,…")]
    detectors: Option<Vec<String>>,
    /// Worker threads [default: one per CPU].
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// No progress line on stderr (implied by --json).
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args, Debug)]
struct ApplyArgs {
    /// Plan file written by `dwhy plan -o`.
    plan: PathBuf,
    /// Highest tier removed without per-item confirmation. Review items always need
    /// --confirm ID, so `review` lets through no more than `rebuildable` (accepted for
    /// compatibility).
    #[arg(long, value_enum, default_value = "regenerable")]
    max_tier: TierArg,
    /// Review items the user confirmed, by id (comma-separated or repeated).
    #[arg(long, value_delimiter = ',', value_name = "ID,…")]
    confirm: Vec<String>,
    /// Remove without asking (required when there is no terminal).
    #[arg(short, long)]
    yes: bool,
    /// Show what would be removed; remove nothing.
    #[arg(long)]
    dry_run: bool,
    /// Print diskwhy/v1 JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Worker threads for the rescan [default: one per CPU].
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// No progress line on stderr (implied by --json).
    #[arg(short, long)]
    quiet: bool,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap exits 2 on usage errors, but 2 means "skipped by a guard" here.
            let code = if e.use_stderr() { EXIT_ERROR } else { EXIT_OK };
            let _ = e.print();
            // --help and --version are not errors: they print what was asked.
            if e.use_stderr() && json_requested(std::env::args_os().skip(1)) {
                let (message, hint) = usage_message(&e.render().to_string());
                print_error_json(&ErrorReport::new(ErrorKind::Usage, message, hint, code));
            }
            return ExitCode::from(code);
        }
    };
    let json = match &cli.command {
        Some(Command::Scan(a)) => a.json,
        Some(Command::Plan(a)) => a.json,
        Some(Command::Apply(a)) => a.json,
        Some(Command::Diff(a)) => a.json,
        Some(Command::Watch(a)) => a.json,
        Some(Command::Explain(a)) => a.json,
        Some(Command::Doctor { json }) => *json,
        Some(Command::Audit(a)) => a.json,
        Some(Command::Tui(_) | Command::Guide) | None => false,
    };
    let res = match cli.command {
        Some(Command::Scan(args)) => run_scan(args),
        Some(Command::Plan(args)) => run_plan(args),
        Some(Command::Apply(args)) => run_apply(args),
        Some(Command::Diff(args)) => run_diff(args),
        Some(Command::Watch(args)) => run_watch(args),
        Some(Command::Explain(args)) => run_explain(args),
        Some(Command::Doctor { json }) => run_doctor(json),
        Some(Command::Audit(args)) => run_audit(args),
        Some(Command::Guide) => guide::run(),
        Some(Command::Tui(args)) => run_tui(args),
        None => run_tui(TuiArgs {
            paths: Vec::new(),
            one_file_system: false,
            cross_filesystems: false,
            plan: None,
            dry_run: false,
        }),
    };
    match res {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            // Not eprintln!: it panics when the terminal has hung up (dwhy tui).
            // Errors can name paths; `dwhy-core` escapes its own, so escape
            // only the control characters left.
            let _ = writeln!(
                std::io::stderr(),
                "dwhy: error: {}",
                human::escape_only_controls(&e.to_string())
            );
            // A report already started on stdout stays the only document there.
            if json && !REPORT_STARTED.load(Ordering::Relaxed) {
                print_error_json(&ErrorReport::new(
                    ErrorKind::Error,
                    e.to_string(),
                    None,
                    EXIT_ERROR,
                ));
            }
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Set once a command starts writing its report on stdout: from then on a
/// failure is told on stderr only, never as a second JSON document.
static REPORT_STARTED: AtomicBool = AtomicBool::new(false);

/// Writes `value` as the command's pretty-printed diskwhy/v1 report.
fn print_json(value: &impl serde::Serialize) -> Result<()> {
    REPORT_STARTED.store(true, Ordering::Relaxed);
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

/// Writes `report` on stdout for `--json` readers of a failed command
/// (stderr has said the same in text). Write errors are ignored: the exit
/// code still tells.
fn print_error_json(report: &ErrorReport) {
    let mut out = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut out, report).is_ok() {
        let _ = writeln!(out);
    }
    let _ = out.flush();
}

/// Says `dwhy: refused: …` on stderr (with the hint when `hint_on_stderr`)
/// and, with `json`, as an [`ErrorReport`] on stdout. Returns the exit code
/// for a refusal.
fn refuse(json: bool, message: &str, hint: Option<&str>, hint_on_stderr: bool) -> u8 {
    let text = match hint {
        Some(hint) if hint_on_stderr => format!("{message}; {hint}"),
        _ => message.to_owned(),
    };
    eprintln!("dwhy: refused: {}", human::escape_only_controls(&text));
    if json {
        print_error_json(&ErrorReport::new(
            ErrorKind::Refused,
            message,
            hint.map(str::to_owned),
            EXIT_REFUSED,
        ));
    }
    EXIT_REFUSED
}

/// True when `--json` is among `args` (the arguments after the program
/// name) before any `--`, which ends the options.
fn json_requested(args: impl IntoIterator<Item = OsString>) -> bool {
    args.into_iter()
        .take_while(|a| a != "--")
        .any(|a| a == "--json")
}

/// The message and hint of a usage error, from clap's plain-text rendering:
/// the `error:` paragraph, and its `tip:` lines (else the usage line, else
/// the pointer to `--help`).
fn usage_message(rendered: &str) -> (String, Option<String>) {
    let mut paragraphs = rendered
        .split("\n\n")
        .map(str::trim)
        .filter(|p| !p.is_empty());
    let first = paragraphs.next().unwrap_or_default();
    let message = first
        .strip_prefix("error:")
        .unwrap_or(first)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let rest: Vec<&str> = paragraphs.flat_map(str::lines).map(str::trim).collect();
    let tips: Vec<&str> = rest
        .iter()
        .filter_map(|l| l.strip_prefix("tip:"))
        .map(str::trim)
        .collect();
    let hint = if tips.is_empty() {
        let line = |start: &str| rest.iter().find(|l| l.starts_with(start));
        line("Usage:")
            .or_else(|| line("For more information"))
            .map(|l| l.to_string())
    } else {
        Some(tips.join("; "))
    };
    (message, hint)
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The policy config (`/etc/diskwhy/policy.toml`, then the user's). A file
/// that exists but is unreadable or invalid is an error: commands fail
/// closed rather than run without a limit someone set.
fn policy_config() -> Result<PolicyConfig> {
    Ok(PolicyConfig::load()?)
}

fn run_tui(args: TuiArgs) -> Result<u8> {
    let policy = policy_config()?;
    let opts = dwhy_tui::Options {
        paths: args.paths,
        cross_filesystems: args.cross_filesystems,
        detectors: None,
        threads: 0,
        snapshot_dir: snapshot::default_dir(),
        dry_run: args.dry_run,
        audit_log: Audit::default_path(),
        context: None,
        cancel: Default::default(),
        policy,
    };
    match &args.plan {
        Some(file) => dwhy_tui::run_plan(file, opts),
        None => dwhy_tui::run(opts),
    }
    .map_err(|e| {
        let mut message = String::new();
        for c in e.to_string().chars() {
            if c.is_control() {
                message.extend(c.escape_default());
            } else {
                message.push(c);
            }
        }
        message.into()
    })
}

/// How the CLI walks and reports progress: progress and status lines on a
/// terminal stderr unless `quiet`, warnings on stderr.
struct Term {
    threads: usize,
    quiet: bool,
}

impl ops::Frontend for Term {
    fn measure(
        &self,
        paths: &[PathBuf],
        one_filesystem: bool,
        min_dir_bytes: u64,
        mounts: &MountTable,
    ) -> std::result::Result<scan::ScanResult, scan::ScanError> {
        measure(
            paths,
            one_filesystem,
            min_dir_bytes,
            self.threads,
            self.quiet,
            mounts,
        )
    }

    fn status(&self, msg: Option<&str>) {
        if self.quiet || !std::io::stderr().is_terminal() {
            return;
        }
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[2K{}", msg.unwrap_or_default());
        let _ = err.flush();
    }

    fn warn(&self, msg: &str) {
        eprintln!("dwhy: warning: {}", human::escape_only_controls(msg));
    }
}

fn run_scan(args: ScanArgs) -> Result<u8> {
    let tiers: Option<Vec<Tier>> = args
        .tier
        .as_ref()
        .map(|t| t.iter().copied().map(Tier::from).collect());
    let req = ops::ScanRequest {
        paths: args.paths.clone(),
        cross_filesystems: args.cross_filesystems,
        min_size: args.min_size,
        no_detectors: args.no_detectors,
        detectors: args.detectors.clone(),
        tiers: tiers.clone(),
        summary: args.summary.then_some(SummaryLimits {
            max_findings: args.max_findings,
            max_dirs: DEFAULT_SUMMARY_DIRS,
            max_depth: args.depth,
        }),
        snapshot: args.snapshot,
    };
    let term = Term {
        threads: args.threads,
        quiet: silent_progress(args.quiet, args.json),
    };
    let ops::ScanOutcome {
        report,
        snapshot_error,
    } = ops::scan(&req, &term)?;

    if args.json {
        print_json(&report)?;
    } else {
        let mut out = std::io::stdout().lock();
        human::render_scan(
            &mut out,
            &report,
            args.depth,
            args.top,
            args.max_findings,
            tiers.is_some(),
        )?;
    }
    if let Some(e) = snapshot_error {
        eprintln!(
            "dwhy: error: snapshot not saved: {}",
            human::escape_only_controls(&e)
        );
        return Ok(EXIT_ERROR);
    }
    Ok(EXIT_OK)
}

fn run_diff(args: DiffArgs) -> Result<u8> {
    let req = ops::DiffRequest {
        paths: args.paths.clone(),
        since: args.since.clone(),
        min_change: args.min_change,
        cross_filesystems: args.cross_filesystems,
        no_detectors: args.no_detectors,
        detectors: args.detectors.clone(),
        snapshot: args.snapshot,
    };
    let term = Term {
        threads: args.threads,
        quiet: silent_progress(args.quiet, args.json),
    };
    let ops::DiffOutcome {
        report: d,
        snapshot_error,
    } = ops::diff(&req, &term)?;
    if args.json {
        print_json(&d)?;
    } else {
        human::render_diff(&mut std::io::stdout().lock(), &d, args.top)?;
    }
    if let Some(e) = snapshot_error {
        eprintln!(
            "dwhy: error: snapshot not saved: {}",
            human::escape_only_controls(&e)
        );
        return Ok(EXIT_ERROR);
    }
    Ok(EXIT_OK)
}

fn run_watch(args: WatchArgs) -> Result<u8> {
    let req = ops::WatchRequest {
        paths: args.paths.clone(),
        window_secs: args.window,
        min_change: args.min_change,
        cross_filesystems: args.cross_filesystems,
        no_docker: args.no_docker,
    };
    let term = Term {
        threads: args.threads,
        quiet: silent_progress(args.quiet, args.json),
    };
    let r = ops::watch(&req, &term)?;
    if args.json {
        print_json(&r)?;
    } else {
        human::render_watch(&mut std::io::stdout().lock(), &r, args.top)?;
    }
    Ok(EXIT_OK)
}

fn run_explain(args: ExplainArgs) -> Result<u8> {
    let query = args.target.to_str().ok_or(ops::EXPLAIN_UTF8_PATH)?;
    let term = Term {
        threads: args.threads,
        quiet: silent_progress(args.quiet, args.json),
    };
    let report = ops::explain(query, args.detectors.as_deref(), &term)?;
    if args.json {
        print_json(&report)?;
    } else {
        human::render_explain(&mut std::io::stdout().lock(), &report)?;
    }
    Ok(EXIT_OK)
}

/// `--free SIZE`: a size above 0.
fn parse_free_target(s: &str) -> std::result::Result<u64, String> {
    match units::parse_size(s)? {
        0 => Err("must be greater than 0".into()),
        n => Ok(n),
    }
}

fn run_plan(args: PlanArgs) -> Result<u8> {
    let req = ops::PlanRequest {
        paths: args.paths.clone(),
        cross_filesystems: args.cross_filesystems,
        detectors: args.detectors.clone(),
        selection: Selection {
            tier: args.tier.map(Tier::from),
            select: args.select.clone(),
            free: args.free,
        },
    };
    let term = Term {
        threads: args.threads,
        quiet: silent_progress(args.quiet, args.json),
    };
    let ops::PlanOutcome {
        plan,
        above_ceiling: above,
    } = ops::plan(&req, &term)?;
    if let Some(path) = &args.output {
        let text = plan::to_json(&plan)?;
        std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    if args.json {
        print_json(&plan)?;
    } else {
        human::render_plan(
            &mut std::io::stdout().lock(),
            &plan,
            args.output.as_deref(),
            above,
        )?;
    }
    Ok(if plan::selected_blocked(&plan) {
        EXIT_SKIPPED
    } else {
        EXIT_OK
    })
}

fn run_apply(args: ApplyArgs) -> Result<u8> {
    let text = std::fs::read_to_string(&args.plan)
        .map_err(|e| format!("cannot read {}: {e}", args.plan.display()))?;
    let plan = plan::parse(&text)?;
    if let Some(names) = &plan.scan.detectors {
        detect::validate_selection(names)?;
    }
    let config = policy_config()?;
    if let Some(bad) = args
        .confirm
        .iter()
        .find(|c| !plan.items.iter().any(|i| i.finding.id == **c))
    {
        return Err(format!(
            "--confirm {}: not an item of this plan",
            detect::escape_controls(bad)
        )
        .into());
    }
    let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    // A person confirms on the terminal unless --yes skips the prompt.
    let policy = Policy::with_config(
        args.max_tier.into(),
        args.confirm.clone(),
        &config,
        terminal && !args.yes,
    );
    let env = apply::Env::from_system().with_invocation(apply::AuditInvocation {
        max_tier: policy.max_tier,
        confirm: args.confirm.clone(),
        yes: args.yes,
        tty: terminal,
    });
    if let Err(e) = plan::usable(&plan, &env.host, env.uid, ops::now_secs()) {
        return Ok(refuse(
            args.json,
            &e.to_string(),
            ops::unusable_hint(&e),
            false,
        ));
    }
    let ask = !args.yes && !args.dry_run;
    if ask && !terminal {
        return Ok(refuse(
            args.json,
            "no terminal to confirm on",
            Some("pass --yes to remove without asking, or --dry-run to preview"),
            true,
        ));
    }
    let term = Term {
        threads: args.threads,
        quiet: silent_progress(args.quiet, args.json),
    };
    let mut checks = ops::survey(&plan, &policy, &config, &term)?;
    let ready: Vec<&Check> = checks.iter().filter(|c| c.ready()).collect();
    // Counts a root mounted below another root on its own, as `plan.bytes` does.
    let would_free = apply::total_bytes_for_checks(ready.iter().copied());
    if args.dry_run {
        let r = apply::report(&plan, &checks, &policy, true, &env);
        print_apply(&r, args.json, None, Some(would_free))?;
        return Ok(apply::exit_code(&r));
    }
    if ask && !ready.is_empty() {
        let preview = apply::report(&plan, &checks, &policy, true, &env);
        let mut err = std::io::stderr().lock();
        human::render_apply(&mut err, &preview, None, true, Some(would_free))?;
        let bytes = would_free;
        write!(
            err,
            "remove {} item{} ({})? [y/N] ",
            ready.len(),
            if ready.len() == 1 { "" } else { "s" },
            units::human(bytes)
        )?;
        err.flush()?;
        drop(err);
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes") {
            eprintln!("nothing removed");
            return Ok(EXIT_OK);
        }
        // Check again right before removing: time has passed at the prompt.
        if let Err(e) = plan::usable(&plan, &env.host, env.uid, ops::now_secs()) {
            return Ok(refuse(
                args.json,
                &e.to_string(),
                ops::unusable_hint(&e),
                false,
            ));
        }
        let again = ops::survey(&plan, &policy, &config, &term)?;
        for (c, a) in checks.iter_mut().zip(again) {
            // Only what was shown may run; it must still be ready.
            if c.ready() {
                *c = a;
            }
        }
    }
    let mut audit = Audit::open_placed(Audit::default_path().as_deref())?;
    let mounts = MountTable::read().map_err(|e| format!("cannot read the mount table: {e}"))?;
    let quiet = silent_progress(args.quiet, args.json);
    let mut status: Option<StatusLine> = None;
    let audit_errors = apply::execute(&plan, &mut checks, &mut audit, &mounts, &env, &mut |item| {
        drop(status.take());
        status = status_line(
            quiet,
            &format!(
                "removing {}…",
                dwhy_core::detect::escape_controls(&item.path)
            ),
        );
    });
    drop(status);
    for error in audit_errors {
        eprintln!("dwhy: error: {}", error.escape_debug());
    }
    let mut r = apply::report(&plan, &checks, &policy, false, &env);
    r.audit_log = Some(audit.path().to_string_lossy().into_owned());
    print_apply(&r, args.json, Some(audit.path()), None)?;
    Ok(apply::exit_code(&r))
}

fn print_apply(
    r: &dwhy_core::report::ApplyReport,
    json: bool,
    audit: Option<&std::path::Path>,
    would_free: Option<u64>,
) -> Result<()> {
    if json {
        print_json(r)?;
    } else {
        human::render_apply(&mut std::io::stdout().lock(), r, audit, false, would_free)?;
    }
    Ok(())
}

/// True when progress and status lines must stay off stderr: with
/// `--quiet`, and with `--json`, whose readers want only the document.
fn silent_progress(quiet: bool, json: bool) -> bool {
    quiet || json
}

/// Shows `msg` on a terminal stderr until dropped.
fn status_line(quiet: bool, msg: &str) -> Option<StatusLine> {
    (!quiet && std::io::stderr().is_terminal()).then(|| {
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[2K{msg}");
        let _ = err.flush();
        StatusLine
    })
}

struct StatusLine;

impl Drop for StatusLine {
    fn drop(&mut self) {
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[2K");
        let _ = err.flush();
    }
}

/// Walks `paths` (default: the current directory, see [`ops::prepare`]) with
/// a progress line on a terminal stderr unless `quiet`.
fn measure(
    paths: &[PathBuf],
    one_fs: bool,
    min_dir_bytes: u64,
    threads: usize,
    quiet: bool,
    mounts: &MountTable,
) -> std::result::Result<scan::ScanResult, scan::ScanError> {
    let roots = ops::prepare(paths, one_fs, &|msg| {
        ops::Frontend::warn(&Term { threads, quiet }, msg)
    })?;
    let opts = ops::scan_options(one_fs, min_dir_bytes, threads);
    let progress = Arc::new(Progress::default());
    let done = Arc::new(AtomicBool::new(false));
    let ticker = (!quiet && std::io::stderr().is_terminal()).then(|| {
        let (progress, done) = (progress.clone(), done.clone());
        std::thread::spawn(move || {
            let mut err = std::io::stderr();
            while !done.load(Ordering::Relaxed) {
                let _ = write!(
                    err,
                    "\r\x1b[2Kscanning… {} entries, {}",
                    units::thousands(progress.entries.load(Ordering::Relaxed)),
                    units::human(progress.allocated.load(Ordering::Relaxed))
                );
                let _ = err.flush();
                std::thread::sleep(Duration::from_millis(200));
            }
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        })
    });
    let result = scan::scan(&roots, &opts, mounts, &progress);
    done.store(true, Ordering::Relaxed);
    if let Some(t) = ticker {
        let _ = t.join();
    }
    result
}

fn run_audit(args: AuditArgs) -> Result<u8> {
    let path = Audit::default_path().ok_or(apply::AUDIT_UNPLACED)?;
    let report = apply::read_audit_log(&path, args.limit, &apply::Env::from_system())?;
    if args.json {
        print_json(&report)?;
    } else {
        human::render_audit(&mut std::io::stdout().lock(), &report)?;
    }
    Ok(EXIT_OK)
}

fn run_doctor(json: bool) -> Result<u8> {
    let report = doctor::doctor();
    if json {
        print_json(&report)?;
    } else {
        human::render_doctor(&mut std::io::stdout().lock(), &report)?;
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::silent_progress;

    #[test]
    fn json_output_silences_progress() {
        assert!(!silent_progress(false, false));
        assert!(silent_progress(true, false));
        assert!(silent_progress(false, true));
        assert!(silent_progress(true, true));
    }
}
