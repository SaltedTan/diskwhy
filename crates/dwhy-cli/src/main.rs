//! `dwhy`: command-line front end for diskwhy.
//!
//! Exit codes (docs/DESIGN.md): 0 ok, 1 error (including usage errors),
//! 2 items skipped by a guard or changed fingerprint, 3 refused by policy.

mod human;

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use dwhy_core::account;
use dwhy_core::apply::{self, Audit, Check, Policy};
use dwhy_core::detect::{self, DetectContext};
use dwhy_core::explain::{self, Place, Query, Walk};
use dwhy_core::guard::Processes;
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::report::{
    ActionKind, ExplainReport, ExplainResolved, ExplainSize, ExplainVia, Plan, PlanScan,
    SavedSnapshot, SnapshotFinding, Tier, Totals,
};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;
use dwhy_core::{docker, doctor, growth, probes, snapshot, system, units};

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
    /// Carry out a plan: re-detect, re-run the guards, and remove what the tier policy allows.
    Apply(ApplyArgs),
    /// Show what grew since a snapshot (`scan --snapshot`): rescans now and compares.
    Diff(DiffArgs),
    /// Measure growth now: walks twice, --for apart, and reports bytes per minute (writes nothing).
    Watch(WatchArgs),
    /// Explain one finding, by id or path: evidence, guards, growth, action and recovery cost.
    Explain(ExplainArgs),
    /// Open the TUI (what bare `dwhy` does on the current directory): browse sizes and findings,
    /// mark findings and preview their plan; writes only a plan file you ask for.
    Tui(TuiArgs),
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
    /// Save a snapshot for `dwhy diff` under ~/.local/state/diskwhy/snapshots (old ones are pruned).
    #[arg(long)]
    snapshot: bool,
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
    /// Snapshot to compare with: last, an id, a file, a duration (24h, 7d: the newest at
    /// least that old) or an RFC 3339 time (the newest taken by then).
    #[arg(long, default_value = "last", value_name = "WHEN")]
    since: String,
    /// Also save the fresh scan as a snapshot.
    #[arg(long)]
    snapshot: bool,
    /// Print diskwhy/v1 JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Leave out directories, Docker objects and findings that changed by less than this.
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size, default_value = "10M")]
    min_change: u64,
    /// Descend into other filesystems mounted below the roots [without PATH: the snapshot's setting].
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
    /// No progress line on stderr.
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
    /// No progress line on stderr.
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
    /// No progress line on stderr.
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

#[derive(Args, Debug)]
struct ApplyArgs {
    /// Plan file written by `dwhy plan -o`.
    plan: PathBuf,
    /// Highest tier to remove (review items need --confirm instead).
    #[arg(long, value_enum, default_value = "regenerable")]
    max_tier: TierArg,
    /// Review items a person confirmed, by id (comma-separated or repeated).
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
        Some(Command::Apply(args)) => run_apply(args),
        Some(Command::Diff(args)) => run_diff(args),
        Some(Command::Watch(args)) => run_watch(args),
        Some(Command::Explain(args)) => run_explain(args),
        Some(Command::Doctor { json }) => run_doctor(json),
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
            eprintln!("dwhy: error: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn run_tui(args: TuiArgs) -> Result<u8> {
    let opts = dwhy_tui::Options {
        paths: args.paths,
        cross_filesystems: args.cross_filesystems,
        detectors: None,
        threads: 0,
        snapshot_dir: snapshot::default_dir(),
        dry_run: args.dry_run,
        audit_log: Audit::default_path(),
        context: None,
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

    let mut report = account::system_scan_report(&result, &mounts);
    let docker_snap = if args.no_detectors {
        None
    } else {
        detect::detect_into(&mut report, &result.tree, args.detectors.as_deref(), true)
    };

    // Growth on findings, from a snapshot of the same roots old enough for
    // a meaningful rate. Best effort: without one, findings have no growth.
    if let Some(dir) = snapshot::default_dir() {
        growth::fill_scan_growth(&mut report, &dir, now_secs());
    }

    // The report is still printed when the snapshot cannot be saved.
    let mut save_error = None;
    if args.snapshot {
        let snap = snapshot::build(
            &report,
            &result.tree,
            docker_snap.as_deref(),
            snapshot::MIN_DIR_BYTES,
        );
        match save_snapshot(&snap) {
            Ok(saved) => report.snapshot = Some(saved),
            Err(e) => save_error = Some(e),
        }
    }

    let mut out = std::io::stdout().lock();
    if args.json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        human::render_scan(&mut out, &report, args.depth, args.top, args.max_findings)?;
    }
    if let Some(e) = save_error {
        eprintln!("dwhy: error: snapshot not saved: {e}");
        return Ok(EXIT_ERROR);
    }
    Ok(EXIT_OK)
}

/// Saves `snap` in the snapshot directory, warning when pruning failed.
fn save_snapshot(snap: &dwhy_core::report::Snapshot) -> std::result::Result<SavedSnapshot, String> {
    let dir = snapshot::default_dir().ok_or_else(|| {
        "cannot place snapshots: neither XDG_STATE_HOME nor HOME is an absolute path".to_string()
    })?;
    let saved = snapshot::save(&dir, snap, now_secs())?;
    if let Some(e) = saved.prune_error {
        eprintln!("dwhy: warning: old snapshots not pruned: {e}");
    }
    Ok(saved.snapshot)
}

fn run_diff(args: DiffArgs) -> Result<u8> {
    if let Some(names) = &args.detectors {
        detect::validate_selection(names)?;
    }
    let since = snapshot::parse_since(&args.since)?;
    let dir = match (snapshot::default_dir(), &since) {
        (Some(d), _) => d,
        (None, snapshot::Since::File(_)) => PathBuf::new(),
        (None, _) => {
            return Err(
                "cannot find snapshots: neither XDG_STATE_HOME nor HOME is an absolute path".into(),
            );
        }
    };
    let host = system::hostname();
    let uid = system::euid();
    // With PATH, compare with a snapshot of those roots; without, with the
    // newest of any roots, and rescan its roots.
    let given = if args.paths.is_empty() {
        None
    } else {
        let one_fs = !args.cross_filesystems;
        let roots: Vec<String> = scan::prepare_roots(&args.paths, one_fs)?
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        Some((roots, one_fs))
    };
    let found = snapshot::find(
        &dir,
        &since,
        &host,
        uid,
        given.as_ref().map(|(r, x)| (r.as_slice(), *x)),
        now_secs(),
    )?;
    let (roots, one_fs) = given.unwrap_or_else(|| {
        (
            found.snapshot.scan.roots.clone(),
            found.snapshot.scan.one_filesystem,
        )
    });
    let roots: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();

    let mounts = MountTable::read().unwrap_or_default();
    // The snapshot records directories from the tree; no list is needed.
    let result = measure(&roots, one_fs, u64::MAX, args.threads, args.quiet, &mounts)?;
    let mut report = account::system_scan_report(&result, &mounts);
    let docker_snap = if args.no_detectors {
        None
    } else {
        detect::detect_into(&mut report, &result.tree, args.detectors.as_deref(), false)
    };
    let fresh = snapshot::build(
        &report,
        &result.tree,
        docker_snap.as_deref(),
        snapshot::MIN_DIR_BYTES,
    );
    let tree = &result.tree;
    let size_now = |p: &str| {
        tree.find(std::path::Path::new(p))
            .filter(|&id| tree.node(id).is_dir)
            .map(|id| tree.node(id).total.allocated)
    };
    let mut d = growth::diff(
        &found.snapshot,
        found.id,
        found.path.to_string_lossy().into_owned(),
        &fresh,
        &size_now,
        args.min_change,
    );
    let mut save_error = None;
    if args.snapshot {
        match save_snapshot(&fresh) {
            Ok(saved) => d.snapshot = Some(saved),
            Err(e) => save_error = Some(e),
        }
    }
    let mut out = std::io::stdout().lock();
    if args.json {
        serde_json::to_writer_pretty(&mut out, &d)?;
        writeln!(out)?;
    } else {
        human::render_diff(&mut out, &d, args.top)?;
    }
    if let Some(e) = save_error {
        eprintln!("dwhy: error: snapshot not saved: {e}");
        return Ok(EXIT_ERROR);
    }
    Ok(EXIT_OK)
}

fn run_watch(args: WatchArgs) -> Result<u8> {
    let one_fs = !args.cross_filesystems;
    let window = Duration::from_secs(args.window);
    let t0 = std::time::Instant::now();
    let started_at = system::now_rfc3339();
    let mut start = watch_sample(&args, one_fs)?;
    start.snapshot.created_at = started_at;
    // The second walk starts `--for` after the first one started.
    let deadline = t0 + window;
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        if left.is_zero() {
            break;
        }
        let _status = status_line(
            args.quiet,
            &format!("watching… {}s left", left.as_secs_f64().ceil() as u64),
        );
        std::thread::sleep(left.min(Duration::from_secs(1)));
    }
    let elapsed_ms = t0.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let end = watch_sample(&args, one_fs)?;
    let mut r = growth::watch(
        &start.snapshot,
        &end.snapshot,
        args.window,
        elapsed_ms,
        args.min_change,
        [&start.unreadable, &end.unreadable],
    );
    let mut reasons: Vec<String> = [start.docker.err(), end.docker.err()]
        .into_iter()
        .flatten()
        .collect();
    reasons.dedup();
    if !reasons.is_empty() {
        r.notes
            .push(format!("Docker not compared: {}", reasons.join("; ")));
    }
    let mut out = std::io::stdout().lock();
    if args.json {
        serde_json::to_writer_pretty(&mut out, &r)?;
        writeln!(out)?;
    } else {
        human::render_watch(&mut out, &r, args.top)?;
    }
    Ok(EXIT_OK)
}

struct WatchSample {
    snapshot: dwhy_core::report::Snapshot,
    unreadable: Vec<String>,
    docker: std::result::Result<(), String>,
}

/// One end of a watch window: a walk of the roots recording every
/// directory, and Docker's figures (`Err` with the reason when there are
/// none). Nothing is saved.
fn watch_sample(args: &WatchArgs, one_fs: bool) -> Result<WatchSample> {
    let mounts = MountTable::read().unwrap_or_default();
    let result = measure(
        &args.paths,
        one_fs,
        u64::MAX,
        args.threads,
        args.quiet,
        &mounts,
    )?;
    if result.error_count > result.errors.len() as u64 {
        return Err("watch sample has unrecorded scan errors; coverage is unknown".into());
    }
    let unreadable = result
        .unreadable
        .iter()
        .map(|u| &u.path)
        .chain(result.errors.iter().map(|(path, _)| path))
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let report = account::system_scan_report(&result, &mounts);
    let docker = if args.no_docker {
        Err("--no-docker given".to_string())
    } else {
        let _status = status_line(args.quiet, "asking Docker…");
        docker_now()
    };
    let snap = snapshot::build(&report, &result.tree, docker.as_deref().ok(), 0);
    Ok(WatchSample {
        snapshot: snap,
        unreadable,
        docker: docker.map(|_| ()),
    })
}

/// Docker's figures now, from `GET /system/df` and `/info`.
fn docker_now() -> std::result::Result<Arc<docker::Snapshot>, String> {
    let sock = doctor::docker_socket();
    if !sock.exists {
        return Err(format!("no Docker socket at {}", sock.path));
    }
    if !sock.accessible {
        return Err(format!(
            "cannot use {} (not root and not in the docker group)",
            sock.path
        ));
    }
    docker::Source::socket(std::path::Path::new(&sock.path), docker::DEFAULT_TIMEOUT).get()
}

fn run_explain(args: ExplainArgs) -> Result<u8> {
    const UTF8_PATH: &str = "explain needs a UTF-8 path (diskwhy/v1 reports paths as UTF-8)";
    let query = args.target.to_str().ok_or(UTF8_PATH)?;
    if let Some(names) = &args.detectors {
        detect::validate_selection(names)?;
    }
    let host = system::hostname();
    let uid = system::euid();
    let dir = snapshot::default_dir();
    let mut notes = Vec::new();

    // A finding id becomes the path it had in the newest snapshot listing it.
    let (place, resolved) = match explain::classify(query) {
        Query::Id(id) => {
            let dir = dir.as_deref().ok_or_else(|| format!(
                "cannot find snapshots: neither XDG_STATE_HOME nor HOME is an absolute path; {}",
                explain::PATH_HINT
            ))?;
            let resolved = explain::resolve_id(dir, &host, uid, &id)?;
            (explain::place(&resolved.finding.path), Some(resolved))
        }
        Query::Place(p) => (p, None),
    };
    let (snap, saved, saved_object) = match resolved {
        Some(r) => (Some(r.snapshot), Some(r.finding), r.docker),
        None => (None, None, None),
    };

    let generated_at = system::now_rfc3339();
    let ctx = DetectContext::from_system();
    let mut size = None;
    let is_docker = matches!(&place, Place::Docker(_));
    let (path, tree, only, scan_issue) = match place {
        // Docker objects are not on the walked filesystem: an empty tree.
        Place::Docker(p) => {
            let only = explain::docker_selection(args.detectors.as_deref());
            if only.is_empty() {
                notes.push("no Docker detector selected (--detectors)".into());
            }
            (p, Some(ScanTree::default()), Some(only), None)
        }
        Place::Path(p) => {
            let abs = std::path::absolute(&p)?;
            let input = abs.to_str().ok_or(UTF8_PATH)?;
            let (path, walked) = match scan::absolute_nofollow(&abs) {
                Ok(resolved) => (
                    resolved.to_str().ok_or(UTF8_PATH)?.to_owned(),
                    explain_path(&resolved, &args, &mut notes),
                ),
                Err(source) => (
                    input.to_owned(),
                    Err(scan::ScanError::Root { path: p, source }),
                ),
            };
            match walked {
                Ok((totals, tree, issue)) => {
                    size = Some(ExplainSize {
                        allocated: totals.allocated,
                        apparent: totals.apparent,
                    });
                    (path, Some(tree), args.detectors.clone(), issue)
                }
                Err(e) if saved.is_some() => {
                    (path, None, args.detectors.clone(), Some(e.to_string()))
                }
                Err(e) => return Err(e.into()),
            }
        }
    };

    let (findings, runs) = tree.as_ref().map_or_else(Default::default, |tree| {
        let (candidates, runs) = detect::run_candidates(
            tree,
            &ctx,
            &dwhy_core::detectors::registry(),
            only.as_deref(),
        );
        let mut candidates = candidates.into_iter().map(|c| c.finding).collect();
        if !is_docker {
            explain::exclude_lossy_paths(&mut candidates, tree);
        }
        (candidates, runs)
    });
    notes.extend(explain::detector_notes(&runs, only.as_deref()));
    let detector_issue = |saved: &SnapshotFinding| {
        tree.as_ref()
            .and_then(|_| explain::detector_gap(&runs, only.as_deref(), &saved.detector))
    };
    let daemon = ctx.docker.fetched();
    let mut path = path;
    let mut gone = false;
    let (mut finding, inside) = match &saved {
        // A saved Docker object is matched by its immutable id.
        Some(saved) if is_docker => {
            let out = explain::explain_docker_id(
                saved,
                saved_object.as_ref(),
                daemon.as_deref(),
                findings,
                detector_issue(saved),
            );
            path = out.path;
            gone = out.gone;
            notes.extend(out.notes);
            (out.finding, out.inside)
        }
        _ => {
            let (finding, inside) =
                explain::pick(findings, &path, saved.as_ref().map(|f| f.id.as_str()));
            if let Some(saved) = &saved
                && finding.is_none()
            {
                gone = explain_missing(&saved.path, detector_issue(saved), scan_issue, &mut notes);
            }
            (finding, inside)
        }
    };
    if let (Some(f), Some(tree)) = (&mut finding, &tree) {
        let one = std::slice::from_mut(f);
        probes::run(one, &ctx);
        detect::block_lossy(one);
        let status = status_line(args.quiet, "checking guards…");
        let processes = if is_docker {
            Processes::default()
        } else {
            Processes::read()
        };
        dwhy_core::guard::check(one, tree, &ctx, &processes);
        drop(status);
        let base = dir
            .as_deref()
            .and_then(|dir| explain::growth_base(dir, &host, uid, &f.id, &generated_at));
        notes.extend(explain::fill_growth(
            f,
            base.as_ref(),
            &generated_at,
            daemon.as_deref(),
        ));
    }
    let report = ExplainReport {
        schema: dwhy_core::SCHEMA.into(),
        tool: dwhy_core::report::Tool::current(),
        host,
        uid,
        generated_at,
        query: query.to_owned(),
        resolved: ExplainResolved {
            via: if saved.is_some() {
                ExplainVia::Id
            } else {
                ExplainVia::Path
            },
            snapshot: snap,
        },
        path,
        gone,
        finding,
        size,
        inside,
        notes,
    };
    let mut out = std::io::stdout().lock();
    if args.json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        human::render_explain(&mut out, &report)?;
    }
    Ok(EXIT_OK)
}

/// Notes on a saved filesystem path that no finding matched now.
fn explain_missing(
    path: &str,
    detector_issue: Option<String>,
    scan_issue: Option<String>,
    notes: &mut Vec<String>,
) -> bool {
    let exists = match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(format!("{path}: {e}")),
    };
    explain::absence(path, exists, detector_issue, scan_issue, None, notes)
}

fn explain_path(
    abs: &Path,
    args: &ExplainArgs,
    notes: &mut Vec<String>,
) -> std::result::Result<(Totals, ScanTree, Option<String>), scan::ScanError> {
    let mounts = MountTable::read().unwrap_or_default();
    let scan = |root: &Path| {
        measure(
            &[root.to_path_buf()],
            true,
            u64::MAX,
            args.threads,
            args.quiet,
            &mounts,
        )
    };
    let read_issue = |result: &scan::ScanResult| {
        result
            .unreadable
            .iter()
            .map(|u| u.path.as_path())
            .chain(result.errors.iter().map(|(p, _)| p.as_path()))
            .find(|p| abs.starts_with(p) || p.starts_with(abs))
            .map(|p| format!("{} could not be read", p.display()))
            .or_else(|| {
                (result.error_count > result.errors.len() as u64)
                    .then(|| "the scan has unrecorded errors".to_string())
            })
    };
    match explain::walk_for(abs, &mounts) {
        Walk::Parent(parent) => {
            let result = scan(&parent)?;
            let issue = read_issue(&result);
            if let Some(node) = result.tree.find(abs) {
                let totals = result.tree.node(node).total;
                return Ok((totals, result.tree, issue));
            }
            notes.push(format!(
                "{} was not in the scan of its parent {}: scanned it alone",
                abs.display(),
                parent.display()
            ));
            notes.extend(issue);
        }
        Walk::Itself(note) => {
            notes.extend(note);
        }
    }
    let result = scan(abs)?;
    let issue = read_issue(&result);
    Ok((result.totals(), result.tree, issue))
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
        let text = plan::to_json(&plan)?;
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

fn run_apply(args: ApplyArgs) -> Result<u8> {
    let text = std::fs::read_to_string(&args.plan)
        .map_err(|e| format!("cannot read {}: {e}", args.plan.display()))?;
    let plan = plan::parse(&text)?;
    if let Some(names) = &plan.scan.detectors {
        detect::validate_selection(names)?;
    }
    if let Some(bad) = args
        .confirm
        .iter()
        .find(|c| !plan.items.iter().any(|i| i.finding.id == **c))
    {
        return Err(format!("--confirm {bad}: not an item of this plan").into());
    }
    let env = apply::Env::from_system();
    if let Err(e) = plan::usable(&plan, &env.host, env.uid, now_secs()) {
        eprintln!("dwhy: refused: {e}");
        return Ok(EXIT_REFUSED);
    }
    let ask = !args.yes && !args.dry_run;
    if ask && !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        eprintln!(
            "dwhy: refused: no terminal to confirm on; pass --yes to remove without asking, or --dry-run to preview"
        );
        return Ok(EXIT_REFUSED);
    }
    let policy = Policy {
        max_tier: args.max_tier.into(),
        confirm: args.confirm.clone(),
    };
    let mut checks = survey(&plan, &policy, args.threads, args.quiet)?;
    if args.dry_run {
        let r = apply::report(&plan, &checks, &policy, true, &env);
        print_apply(&r, args.json, None)?;
        return Ok(apply::exit_code(&r));
    }
    let ready: Vec<&Check> = checks.iter().filter(|c| c.ready()).collect();
    if ask && !ready.is_empty() {
        let preview = apply::report(&plan, &checks, &policy, true, &env);
        let mut err = std::io::stderr().lock();
        human::render_apply(&mut err, &preview, None, true)?;
        let bytes = apply::total_bytes(ready.iter().map(|c| &c.item));
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
        if let Err(e) = plan::usable(&plan, &env.host, env.uid, now_secs()) {
            eprintln!("dwhy: refused: {e}");
            return Ok(EXIT_REFUSED);
        }
        let again = survey(&plan, &policy, args.threads, args.quiet)?;
        for (c, a) in checks.iter_mut().zip(again) {
            // Only what was shown may run; it must still be ready.
            if c.ready() {
                *c = a;
            }
        }
    }
    let path = Audit::default_path()
        .ok_or("cannot place the audit log: neither XDG_STATE_HOME nor HOME is an absolute path")?;
    let mut audit = Audit::open(&path)?;
    let mounts = MountTable::read().map_err(|e| format!("cannot read the mount table: {e}"))?;
    let quiet = args.quiet;
    let mut status: Option<StatusLine> = None;
    let audit_errors = apply::execute(&plan, &mut checks, &mut audit, &mounts, &env, &mut |item| {
        drop(status.take());
        status = status_line(quiet, &format!("removing {}…", item.path));
    });
    drop(status);
    for error in audit_errors {
        eprintln!("dwhy: error: {}", error.escape_debug());
    }
    let r = apply::report(&plan, &checks, &policy, false, &env);
    print_apply(&r, args.json, Some(audit.path()))?;
    Ok(apply::exit_code(&r))
}

/// Rescans the plan's roots, re-runs its detectors, and decides each item.
fn survey(plan: &Plan, policy: &Policy, threads: usize, quiet: bool) -> Result<Vec<Check>> {
    let mounts = MountTable::read().unwrap_or_default();
    let roots: Vec<PathBuf> = plan.scan.roots.iter().map(PathBuf::from).collect();
    let result = measure(
        &roots,
        plan.scan.one_filesystem,
        u64::MAX,
        threads,
        quiet,
        &mounts,
    )?;
    let ctx = DetectContext::from_system();
    let (findings, _) = detect::run_with(
        &result.tree,
        &ctx,
        &dwhy_core::detectors::registry(),
        plan.scan.detectors.as_deref(),
    );
    let _status = status_line(quiet, "checking guards…");
    Ok(apply::evaluate(
        plan,
        findings,
        &result.tree,
        &ctx,
        &Processes::read(),
        policy,
    ))
}

fn print_apply(
    r: &dwhy_core::report::ApplyReport,
    json: bool,
    audit: Option<&std::path::Path>,
) -> Result<()> {
    let mut out = std::io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, r)?;
        writeln!(out)?;
    } else {
        human::render_apply(&mut out, r, audit, false)?;
    }
    Ok(())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
) -> std::result::Result<scan::ScanResult, scan::ScanError> {
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
    result
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
