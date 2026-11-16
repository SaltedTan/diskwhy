//! `dwhy`: command-line front end for diskwhy.
//!
//! Exit codes (docs/DESIGN.md): 0 ok, 1 error (including usage errors),
//! 2 items skipped by a guard or changed fingerprint, 3 refused by policy.

mod human;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use dwhy_core::account::{self, ReportEnv};
use dwhy_core::detect::{self, DetectContext};
use dwhy_core::guard::Processes;
use dwhy_core::mounts::{self, MountTable};
use dwhy_core::plan::{self, Selection};
use dwhy_core::report::{ActionKind, PlanScan, Tier};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::{docker, doctor, system, units};

pub const EXIT_OK: u8 = 0;
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_SKIPPED: u8 = 2;

#[derive(Parser, Debug)]
#[command(
    name = "dwhy",
    version,
    about = "Why is my disk filling up, and what is safe to remove?",
    long_about = None,
    after_help = "Exit codes: 0 ok, 1 error, 2 items skipped by a guard, 3 refused by policy."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Measure disk usage: sizes, unreadable directories, and space df counts but the scan cannot see.
    Scan(ScanArgs),
    /// Select findings for removal and write a plan for `dwhy apply` (guards run, nothing is removed).
    Plan(PlanArgs),
    /// Show permissions, optional tools on PATH, and which detectors they enable.
    Doctor {
        /// Print diskwhy/v1 JSON instead of text.
        #[arg(long)]
        json: bool,
    },
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
    /// Text output: how many levels of the directory tree to show.
    #[arg(long, default_value_t = 3)]
    depth: u32,
    /// Text output: largest children shown per directory.
    #[arg(long, default_value_t = 8)]
    top: usize,
    /// Worker threads [default: one per CPU].
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// No progress line on stderr.
    #[arg(short, long)]
    quiet: bool,
    /// Only measure; do not run detectors.
    #[arg(long, conflicts_with = "detectors")]
    no_detectors: bool,
    /// Run only these detectors (comma-separated names, see `dwhy doctor`).
    #[arg(long, value_delimiter = ',', value_name = "NAME,…")]
    detectors: Option<Vec<String>>,
    /// Text output: findings listed before "… N more".
    #[arg(long, default_value_t = 20)]
    max_findings: usize,
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
    /// No progress line on stderr.
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
            return ExitCode::from(code);
        }
    };
    let res = match cli.command {
        Some(Command::Scan(args)) => run_scan(args),
        Some(Command::Plan(args)) => run_plan(args),
        Some(Command::Doctor { json }) => run_doctor(json),
        None => {
            Err("the TUI is not built yet (milestone M4); try `dwhy scan` or `dwhy --help`".into())
        }
    };
    match res {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("dwhy: error: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn run_scan(args: ScanArgs) -> Result<u8> {
    if let Some(names) = &args.detectors {
        detect::validate_selection(names)?;
    }
    let mounts = MountTable::read().unwrap_or_default();
    let mut result = measure(
        &args.paths,
        !args.cross_filesystems,
        // Keep enough to pick a threshold after the scan.
        args.min_size.unwrap_or(1 << 20),
        args.threads,
        args.quiet,
        &mounts,
    )?;

    // Default threshold: 1% of what was scanned, between 1M and 100M.
    let threshold = args
        .min_size
        .unwrap_or_else(|| (result.totals().allocated / 100).clamp(1 << 20, 100 << 20));
    result.dirs.retain(|d| d.totals.allocated >= threshold);
    result.min_dir_bytes = threshold;

    let euid = system::euid();
    let env = ReportEnv {
        host: system::hostname(),
        uid: euid,
        root: euid == 0,
        generated_at: system::now_rfc3339(),
        users: system::users(),
        deleted_open: system::deleted_open_files(),
        exe: std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "dwhy".into()),
        docker_access: doctor::docker_access(),
    };
    let mut report =
        account::build_scan_report(&result, &mounts, &env, &|p| mounts::statvfs(p).ok());
    if !args.no_detectors {
        let ctx = DetectContext::from_system();
        let (findings, runs) = detect::run_with(
            &result.tree,
            &ctx,
            &dwhy_core::detectors::registry(),
            args.detectors.as_deref(),
        );
        report.findings = findings;
        report.detectors = runs;
        if let Some(snap) = ctx.docker.fetched() {
            account::attach_docker(&mut report, &docker::usage(&snap));
        }
    }

    let mut out = std::io::stdout().lock();
    if args.json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        human::render_scan(&mut out, &report, args.depth, args.top, args.max_findings)?;
    }
    Ok(EXIT_OK)
}

fn run_plan(args: PlanArgs) -> Result<u8> {
    if let Some(names) = &args.detectors {
        detect::validate_selection(names)?;
    }
    let mounts = MountTable::read().unwrap_or_default();
    let one_fs = !args.cross_filesystems;
    // Detectors read the tree; no directory list is needed.
    let result = measure(
        &args.paths,
        one_fs,
        u64::MAX,
        args.threads,
        args.quiet,
        &mounts,
    )?;
    let ctx = DetectContext::from_system();
    let (findings, _) = detect::run_with(
        &result.tree,
        &ctx,
        &dwhy_core::detectors::registry(),
        args.detectors.as_deref(),
    );
    let sel = Selection {
        tier: args.tier.map(Tier::from),
        select: args.select.clone(),
    };
    let above = sel.ceiling().map_or(0, |c| {
        findings
            .iter()
            .filter(|f| {
                f.tier > c && f.tier != Tier::Blocked && f.action.kind != ActionKind::Advice
            })
            .count()
    });
    let status = status_line(args.quiet, "checking guards…");
    let plan = plan::build(
        findings,
        &sel,
        &result.tree,
        &ctx,
        &Processes::read(),
        system::hostname(),
        PlanScan {
            roots: result
                .roots
                .iter()
                .map(|r| r.path.to_string_lossy().into_owned())
                .collect(),
            one_filesystem: one_fs,
            detectors: args.detectors.clone(),
        },
    );
    drop(status);
    let plan = plan?;
    if let Some(path) = &args.output {
        let mut text = serde_json::to_string_pretty(&plan)?;
        text.push('\n');
        std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    let mut out = std::io::stdout().lock();
    if args.json {
        serde_json::to_writer_pretty(&mut out, &plan)?;
        writeln!(out)?;
    } else {
        human::render_plan(&mut out, &plan, args.output.as_deref(), above)?;
    }
    Ok(if plan::selected_blocked(&plan) {
        EXIT_SKIPPED
    } else {
        EXIT_OK
    })
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

/// Walks `paths` (default: the current directory) with a progress line on
/// a terminal stderr unless `quiet`.
fn measure(
    paths: &[PathBuf],
    one_fs: bool,
    min_dir_bytes: u64,
    threads: usize,
    quiet: bool,
    mounts: &MountTable,
) -> Result<scan::ScanResult> {
    let paths = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };
    for p in &paths {
        if let Ok(md) = std::fs::symlink_metadata(p)
            && md.file_type().is_symlink()
        {
            eprintln!(
                "dwhy: warning: {} is a symlink; counting the link itself (symlinks are never followed)",
                p.display()
            );
        }
    }
    let roots = scan::prepare_roots(&paths, one_fs)?;
    let opts = ScanOptions {
        one_filesystem: one_fs,
        min_dir_bytes,
        threads,
        ..ScanOptions::default()
    };
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
    Ok(result?)
}

fn run_doctor(json: bool) -> Result<u8> {
    let report = doctor::doctor();
    let mut out = std::io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        human::render_doctor(&mut out, &report)?;
    }
    Ok(EXIT_OK)
}
