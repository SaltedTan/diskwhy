//! The commands both front ends run: `scan`, `diff`, `watch`, `explain` and
//! `plan`, and the rescan `apply` makes before removing ([`survey`]).
//! `dwhy` (the CLI) and `dwhy-mcp` (the MCP server) call these so the two
//! give the same answers; each renders the reports its own way. A
//! [`Frontend`] decides how a walk shows progress, whether status lines are
//! shown, and where warnings go.
//!
//! Errors are messages, as `dwhy` prints them after `dwhy: error:`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::account;
use crate::apply::{self, Check, Policy};
use crate::detect::{self, DetectContext};
use crate::detectors;
use crate::docker;
use crate::doctor;
use crate::explain::{self, Place, Query, Walk};
use crate::growth;
use crate::guard::{self, Processes};
use crate::mounts::MountTable;
use crate::plan::{self, Selection};
use crate::policy::PolicyConfig;
use crate::probes;
use crate::report::{
    ActionKind, DiffReport, ExplainReport, ExplainResolved, ExplainSize, ExplainVia, Plan,
    PlanScan, SavedSnapshot, ScanReport, Snapshot, SnapshotFinding, SummaryLimits, Tier, Tool,
    Totals, WatchReport,
};
use crate::scan::{self, Progress, ScanError, ScanOptions, ScanResult};
use crate::snapshot;
use crate::system;
use crate::tree::ScanTree;

pub type Result<T> = std::result::Result<T, String>;

/// What a front end decides for the commands: how a walk runs and shows
/// progress, the status lines, and where warnings go. Nothing here may
/// write to stdout for `dwhy-mcp`, whose stdout carries the protocol.
pub trait Frontend {
    /// Walks `paths` (the current directory when empty), usually with
    /// [`walk`] and the front end's thread count.
    fn measure(
        &self,
        paths: &[PathBuf],
        one_filesystem: bool,
        min_dir_bytes: u64,
        mounts: &MountTable,
    ) -> std::result::Result<ScanResult, ScanError>;

    /// Shows `msg` as what is happening now; `None` clears it.
    fn status(&self, msg: Option<&str>) {
        let _ = msg;
    }

    /// A problem that does not stop the command. Paths in `msg` are already
    /// escaped.
    fn warn(&self, msg: &str);
}

/// Walks `paths` (the current directory when empty) on `threads` workers
/// (0: one per CPU), counting into `progress`; see [`prepare`].
pub fn walk(
    paths: &[PathBuf],
    one_filesystem: bool,
    min_dir_bytes: u64,
    threads: usize,
    mounts: &MountTable,
    progress: &Progress,
    warn: &dyn Fn(&str),
) -> std::result::Result<ScanResult, ScanError> {
    let roots = prepare(paths, one_filesystem, warn)?;
    scan::scan(
        &roots,
        &scan_options(one_filesystem, min_dir_bytes, threads),
        mounts,
        progress,
    )
}

/// The roots to walk for `paths` (the current directory when empty), as
/// [`scan::prepare_roots`] makes them. A path that is a symlink is counted
/// as the link itself, with a warning through `warn`.
pub fn prepare(
    paths: &[PathBuf],
    one_filesystem: bool,
    warn: &dyn Fn(&str),
) -> std::result::Result<Vec<PathBuf>, ScanError> {
    let paths = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };
    for p in &paths {
        if let Ok(md) = std::fs::symlink_metadata(p)
            && md.file_type().is_symlink()
        {
            warn(&format!(
                "{} is a symlink; counting the link itself (symlinks are never followed)",
                detect::escape_controls(&p.to_string_lossy())
            ));
        }
    }
    scan::prepare_roots(&paths, one_filesystem)
}

/// Scan options for a command's walk.
pub fn scan_options(one_filesystem: bool, min_dir_bytes: u64, threads: usize) -> ScanOptions {
    ScanOptions {
        one_filesystem,
        min_dir_bytes,
        threads,
        ..ScanOptions::default()
    }
}

/// Seconds since the Unix epoch (0 when the clock is before it).
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The policy config (`/etc/diskwhy/policy.toml`, then the user's). A file
/// that exists but is unreadable or invalid is an error: commands fail
/// closed rather than run without a limit someone set.
pub fn policy_config() -> Result<PolicyConfig> {
    PolicyConfig::load()
}

/// What detectors know about this system, with the policy config's scratch
/// settings.
pub fn detect_context(policy: &PolicyConfig) -> DetectContext {
    DetectContext::from_system().with_policy(policy)
}

/// Docker's figures now, from `GET /system/df` and `/info`.
pub fn docker_now() -> Result<Arc<docker::Snapshot>> {
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
    docker::Source::socket(Path::new(&sock.path), docker::DEFAULT_TIMEOUT).get()
}

/// Saves `snap` in the snapshot directory, warning through `fe` when old
/// snapshots could not be pruned.
pub fn save_snapshot(snap: &Snapshot, fe: &dyn Frontend) -> Result<SavedSnapshot> {
    let dir = snapshot::default_dir().ok_or_else(|| {
        "cannot place snapshots: neither XDG_STATE_HOME nor HOME is an absolute path".to_string()
    })?;
    let saved = snapshot::save(&dir, snap, now_secs())?;
    if let Some(e) = saved.prune_error {
        fe.warn(&format!("old snapshots not pruned: {e}"));
    }
    Ok(saved.snapshot)
}

/// `scan`: what to walk and what to report.
#[derive(Debug, Clone, Default)]
pub struct ScanRequest {
    pub paths: Vec<PathBuf>,
    pub cross_filesystems: bool,
    /// Smallest directory listed (default: 1% of the scanned total, between
    /// 1M and 100M).
    pub min_size: Option<u64>,
    pub no_detectors: bool,
    pub detectors: Option<Vec<String>>,
    /// Only report findings in these tiers.
    pub tiers: Option<Vec<Tier>>,
    /// Compact the report ([`ScanReport::summarize`]) with these limits.
    pub summary: Option<SummaryLimits>,
    /// Save a snapshot of the whole scan, whatever `tiers` and `summary`
    /// leave out.
    pub snapshot: bool,
}

/// What `scan` made: the report, and why the snapshot asked for was not
/// saved (the report is still good).
#[derive(Debug)]
pub struct ScanOutcome {
    pub report: ScanReport,
    pub snapshot_error: Option<String>,
}

pub fn scan(req: &ScanRequest, fe: &dyn Frontend) -> Result<ScanOutcome> {
    if let Some(names) = &req.detectors {
        detect::validate_selection(names)?;
    }
    let policy = policy_config()?;
    let mounts = MountTable::read().unwrap_or_default();
    let mut result = fe
        .measure(
            &req.paths,
            !req.cross_filesystems,
            // Keep enough to pick a threshold after the scan.
            req.min_size.unwrap_or(1 << 20),
            &mounts,
        )
        .map_err(|e| e.to_string())?;

    // Default threshold: 1% of what was scanned, between 1M and 100M.
    let threshold = req
        .min_size
        .unwrap_or_else(|| (result.totals().allocated / 100).clamp(1 << 20, 100 << 20));
    result.dirs.retain(|d| d.totals.allocated >= threshold);
    result.min_dir_bytes = threshold;

    let mut report = account::system_scan_report(&result, &mounts);
    let docker_snap = if req.no_detectors {
        None
    } else {
        detect::detect_into_with(
            &mut report,
            &result.tree,
            &detect_context(&policy),
            req.detectors.as_deref(),
            true,
        )
    };

    // Growth on findings, from a snapshot of the same roots old enough for
    // a meaningful rate. Best effort: without one, findings have no growth.
    if let Some(dir) = snapshot::default_dir() {
        growth::fill_scan_growth(&mut report, &dir, now_secs());
    }

    let mut snapshot_error = None;
    if req.snapshot {
        let snap = snapshot::build(
            &report,
            &result.tree,
            docker_snap.as_deref(),
            snapshot::MIN_DIR_BYTES,
        );
        match save_snapshot(&snap, fe) {
            Ok(saved) => report.snapshot = Some(saved),
            Err(e) => snapshot_error = Some(e),
        }
    }

    // Only now, so growth and the snapshot above saw every finding and directory.
    if let Some(limits) = req.summary {
        report.summarize(req.tiers.as_deref(), limits);
    } else if let Some(tiers) = &req.tiers {
        report.filter_tiers(tiers);
    }
    Ok(ScanOutcome {
        report,
        snapshot_error,
    })
}

/// `diff`: what to compare with and how.
#[derive(Debug, Clone)]
pub struct DiffRequest {
    /// Roots to rescan (default: the roots of the snapshot compared with).
    pub paths: Vec<PathBuf>,
    /// Which snapshot (`last`, an id, a file, a duration or a time).
    pub since: String,
    pub min_change: u64,
    /// With `paths` only; without, the snapshot's setting is used.
    pub cross_filesystems: bool,
    pub no_detectors: bool,
    pub detectors: Option<Vec<String>>,
    /// Also save the fresh scan as a snapshot.
    pub snapshot: bool,
}

/// What `diff` made: the report, and why the snapshot asked for was not
/// saved (the report is still good).
#[derive(Debug)]
pub struct DiffOutcome {
    pub report: DiffReport,
    pub snapshot_error: Option<String>,
}

pub fn diff(req: &DiffRequest, fe: &dyn Frontend) -> Result<DiffOutcome> {
    if let Some(names) = &req.detectors {
        detect::validate_selection(names)?;
    }
    let since = snapshot::parse_since(&req.since)?;
    let policy = policy_config()?;
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
    // newest of any roots, and rescan its roots. Given roots are rescanned
    // as given, byte for byte; only the snapshot lookup uses their text.
    let given = if req.paths.is_empty() {
        None
    } else {
        let one_fs = !req.cross_filesystems;
        let roots = scan::prepare_roots(&req.paths, one_fs).map_err(|e| e.to_string())?;
        let names: Vec<String> = roots
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        Some((roots, names, one_fs))
    };
    let found = snapshot::find(
        &dir,
        &since,
        &host,
        uid,
        given.as_ref().map(|(_, n, x)| (n.as_slice(), *x)),
        now_secs(),
    )?;
    let (roots, one_fs) = match given {
        Some((roots, _, one_fs)) => (roots, one_fs),
        None => {
            if let Some(root) = found
                .snapshot
                .scan
                .roots
                .iter()
                .find(|root| root.contains('\u{FFFD}'))
            {
                return Err(format!(
                    "snapshot root {} contains U+FFFD, which v1 snapshots also write in place \
                     of non-UTF-8 bytes; pass the path explicitly to `dwhy diff <PATH>`",
                    detect::escape_controls(root),
                ));
            }
            (
                found
                    .snapshot
                    .scan
                    .roots
                    .iter()
                    .map(PathBuf::from)
                    .collect(),
                found.snapshot.scan.one_filesystem,
            )
        }
    };

    let mounts = MountTable::read().unwrap_or_default();
    // The snapshot records directories from the tree; no list is needed.
    let result = fe
        .measure(&roots, one_fs, u64::MAX, &mounts)
        .map_err(|e| e.to_string())?;
    let mut report = account::system_scan_report(&result, &mounts);
    let docker_snap = if req.no_detectors {
        None
    } else {
        detect::detect_into_with(
            &mut report,
            &result.tree,
            &detect_context(&policy),
            req.detectors.as_deref(),
            false,
        )
    };
    let fresh = snapshot::build(
        &report,
        &result.tree,
        docker_snap.as_deref(),
        snapshot::MIN_DIR_BYTES,
    );
    let tree = &result.tree;
    let size_now = |p: &str| {
        tree.find(Path::new(p))
            .filter(|&id| tree.node(id).is_dir)
            .map(|id| tree.node(id).total.allocated)
    };
    let mut d = growth::diff(
        &found.snapshot,
        found.id,
        found.path.to_string_lossy().into_owned(),
        &fresh,
        &size_now,
        req.min_change,
    );
    let mut snapshot_error = None;
    if req.snapshot {
        match save_snapshot(&fresh, fe) {
            Ok(saved) => d.snapshot = Some(saved),
            Err(e) => snapshot_error = Some(e),
        }
    }
    Ok(DiffOutcome {
        report: d,
        snapshot_error,
    })
}

/// `watch`: what to walk twice, and how far apart.
#[derive(Debug, Clone)]
pub struct WatchRequest {
    pub paths: Vec<PathBuf>,
    /// Seconds from the start of the first walk to the start of the second
    /// (at least 1).
    pub window_secs: u64,
    pub min_change: u64,
    pub cross_filesystems: bool,
    /// Do not ask the Docker daemon for its figures.
    pub no_docker: bool,
}

/// `watch`: walks twice, `window_secs` apart, and reports growth per
/// minute. Writes nothing; blocks for the window.
pub fn watch(req: &WatchRequest, fe: &dyn Frontend) -> Result<WatchReport> {
    let one_fs = !req.cross_filesystems;
    let window = Duration::from_secs(req.window_secs);
    let t0 = Instant::now();
    let started_at = system::now_rfc3339();
    let mut start = watch_sample(req, one_fs, fe)?;
    start.snapshot.created_at = started_at;
    // The second walk starts the window after the first one started.
    let deadline = t0 + window;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        if left.is_zero() {
            break;
        }
        fe.status(Some(&format!(
            "watching… {}s left",
            left.as_secs_f64().ceil() as u64
        )));
        std::thread::sleep(left.min(Duration::from_secs(1)));
        fe.status(None);
    }
    let elapsed_ms = t0.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let end = watch_sample(req, one_fs, fe)?;
    let mut r = growth::watch(
        &start.snapshot,
        &end.snapshot,
        req.window_secs,
        elapsed_ms,
        req.min_change,
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
    Ok(r)
}

struct WatchSample {
    snapshot: Snapshot,
    unreadable: Vec<String>,
    docker: Result<()>,
}

/// One end of a watch window: a walk of the roots recording every
/// directory, and Docker's figures (`Err` with the reason when there are
/// none). Nothing is saved.
fn watch_sample(req: &WatchRequest, one_fs: bool, fe: &dyn Frontend) -> Result<WatchSample> {
    let mounts = MountTable::read().unwrap_or_default();
    let result = fe
        .measure(&req.paths, one_fs, u64::MAX, &mounts)
        .map_err(|e| e.to_string())?;
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
    let docker = if req.no_docker {
        Err("--no-docker given".to_string())
    } else {
        fe.status(Some("asking Docker…"));
        let now = docker_now();
        fe.status(None);
        now
    };
    let snap = snapshot::build(&report, &result.tree, docker.as_deref().ok(), 0);
    Ok(WatchSample {
        snapshot: snap,
        unreadable,
        docker: docker.map(|_| ()),
    })
}

/// The error for an `explain` target that is not valid UTF-8.
pub const EXPLAIN_UTF8_PATH: &str =
    "explain needs a UTF-8 path (diskwhy/v1 reports paths as UTF-8)";

/// `explain`: one finding, by id (`f_…`, looked up in the snapshots), path,
/// or pseudo-path such as `docker://volume/NAME`; `detectors` limits the
/// detectors run. Runs probes and guards on the finding; removes nothing.
pub fn explain(
    query: &str,
    detectors: Option<&[String]>,
    fe: &dyn Frontend,
) -> Result<ExplainReport> {
    if let Some(names) = detectors {
        detect::validate_selection(names)?;
    }
    let policy = policy_config()?;
    let host = system::hostname();
    let uid = system::euid();
    let dir = snapshot::default_dir();
    let mut notes = Vec::new();

    // A finding id becomes the path it had in the newest snapshot listing it.
    let (place, resolved) = match explain::classify(query) {
        Query::Id(id) => {
            let dir = dir.as_deref().ok_or_else(|| {
                format!(
                    "cannot find snapshots: neither XDG_STATE_HOME nor HOME is an absolute path; {}",
                    explain::PATH_HINT
                )
            })?;
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
    let ctx = detect_context(&policy);
    let mut size = None;
    let is_docker = matches!(&place, Place::Docker(_));
    // A walk that could not read part of the path; a failed walk of a
    // saved path is only a scan issue.
    let mut coverage = None;
    let (path, tree, only, scan_issue) = match place {
        // Docker objects are not on the walked filesystem: an empty tree.
        Place::Docker(p) => {
            let only = explain::docker_selection(detectors);
            if only.is_empty() {
                notes.push("no Docker detector selected (--detectors)".into());
            }
            (p, Some(ScanTree::default()), Some(only), None)
        }
        Place::Path(p) => {
            // Docker detectors never claim a filesystem path: don't wait on the daemon.
            let only = explain::filesystem_selection(detectors);
            if only.is_empty() {
                notes.push("no filesystem detector selected (--detectors)".into());
            }
            let abs = std::path::absolute(&p).map_err(|e| e.to_string())?;
            let input = abs.to_str().ok_or(EXPLAIN_UTF8_PATH)?;
            // tool-versions compares a version with what sits around it,
            // which can be more than one level up.
            let context = if only.iter().any(|n| n == "tool-versions") {
                detectors::ToolVersions::from_system().context_roots(&ctx)
            } else {
                Vec::new()
            };
            let (path, walked) = match scan::absolute_nofollow(&abs) {
                Ok(resolved) => (
                    resolved.to_str().ok_or(EXPLAIN_UTF8_PATH)?.to_owned(),
                    explain_path(&resolved, &context, fe, &mut notes),
                ),
                Err(source) => (input.to_owned(), Err(ScanError::Root { path: p, source })),
            };
            match walked {
                Ok((totals, tree, issue)) => {
                    size = totals.map(|t| ExplainSize {
                        allocated: t.allocated,
                        apparent: t.apparent,
                    });
                    coverage.clone_from(&issue);
                    (path, Some(tree), Some(only), issue)
                }
                Err(e) if saved.is_some() => (path, None, Some(only), Some(e.to_string())),
                Err(e) => return Err(e.to_string()),
            }
        }
    };

    let (findings, runs) = tree.as_ref().map_or_else(Default::default, |tree| {
        let (candidates, runs) =
            detect::run_candidates(tree, &ctx, &detectors::registry(), only.as_deref());
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
    // What the walk of the path could not read, whatever was found.
    if let Some(issue) = coverage
        && !notes.contains(&issue)
    {
        notes.push(issue);
    }
    if let (Some(f), Some(tree)) = (&mut finding, &tree) {
        let one = std::slice::from_mut(f);
        probes::run(one, &ctx);
        detect::block_lossy(one);
        fe.status(Some("checking guards…"));
        let processes = if is_docker {
            Processes::default()
        } else {
            Processes::read()
        };
        guard::check(one, tree, &ctx, &processes);
        fe.status(None);
        let base = dir
            .as_deref()
            .and_then(|dir| explain::growth_base(dir, &host, uid, &f.id, &generated_at));
        notes.extend(explain::fill_growth(
            f,
            base.as_ref(),
            &generated_at,
            daemon.as_deref(),
            saved_object.as_ref(),
        ));
    }
    Ok(ExplainReport {
        schema: crate::SCHEMA.into(),
        tool: Tool::current(),
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
    })
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

/// Walks what [`explain::walk_for`] says for `abs`. Returns `abs`'s size
/// (`None` when it could not be measured), the walked tree, and a note on
/// partial coverage when the walk could not read something at, above or
/// below `abs`.
fn explain_path(
    abs: &Path,
    context: &[(PathBuf, usize)],
    fe: &dyn Frontend,
    notes: &mut Vec<String>,
) -> std::result::Result<(Option<Totals>, ScanTree, Option<String>), ScanError> {
    let mounts = MountTable::read().unwrap_or_default();
    let scan = |root: &Path| fe.measure(&[root.to_path_buf()], true, u64::MAX, &mounts);
    let read_issue = |result: &ScanResult| {
        result
            .unreadable
            .iter()
            .map(|u| u.path.as_path())
            .chain(result.errors.iter().map(|(p, _)| p.as_path()))
            .find(|p| abs.starts_with(p) || p.starts_with(abs))
            .map(|p| format!("partial coverage: {} could not be read", p.display()))
            .or_else(|| {
                (result.error_count > result.errors.len() as u64)
                    .then(|| "partial coverage: the scan has unrecorded errors".to_string())
            })
    };
    let dir = match explain::walk_for(abs, &mounts, context) {
        Walk::Above { dir, note } => {
            notes.extend(note);
            Some(dir)
        }
        Walk::Itself(note) => {
            notes.extend(note);
            None
        }
    };
    if let Some(dir) = dir {
        let result = scan(&dir)?;
        let issue = read_issue(&result);
        // The tree has nodes for directories only: a file is in the walk
        // when its directory is.
        let is_dir = std::fs::symlink_metadata(abs).is_ok_and(|md| md.is_dir());
        let node = if is_dir {
            result.tree.find(abs)
        } else {
            abs.parent().and_then(|p| result.tree.find(p))
        };
        if let Some(node) = node {
            // The wider walk credits a hardlinked file to its smallest path
            // in the walk, which can lie outside `abs`, and has no node for
            // a file: measure `abs` on its own then, as `du` would.
            let totals = if is_dir && result.totals().hardlinks_deduped == 0 {
                Some(result.tree.node(node).total.totals())
            } else {
                match scan(abs) {
                    Ok(own) => Some(own.totals()),
                    Err(e) => {
                        notes.push(format!("could not measure {}: {e}", abs.display()));
                        None
                    }
                }
            };
            return Ok((totals, result.tree, issue));
        }
        notes.push(format!(
            "{} was not in the scan of {}: scanned it alone",
            abs.display(),
            dir.display()
        ));
        notes.extend(issue);
    }
    let result = scan(abs)?;
    let issue = read_issue(&result);
    Ok((Some(result.totals()), result.tree, issue))
}

/// `plan`: what to walk and select.
#[derive(Debug, Clone, Default)]
pub struct PlanRequest {
    pub paths: Vec<PathBuf>,
    pub cross_filesystems: bool,
    pub detectors: Option<Vec<String>>,
    pub selection: Selection,
}

/// What `plan` made: the plan, and how many findings were left out for
/// being above the selection's ceiling (not blocked, not advice).
#[derive(Debug)]
pub struct PlanOutcome {
    pub plan: Plan,
    pub above_ceiling: usize,
}

/// `plan`: walks, detects, selects and runs the guards. Writes nothing.
pub fn plan(req: &PlanRequest, fe: &dyn Frontend) -> Result<PlanOutcome> {
    if let Some(names) = &req.detectors {
        detect::validate_selection(names)?;
    }
    let policy = policy_config()?;
    let mounts = MountTable::read().unwrap_or_default();
    let one_fs = !req.cross_filesystems;
    // Detectors read the tree; no directory list is needed.
    let result = fe
        .measure(&req.paths, one_fs, u64::MAX, &mounts)
        .map_err(|e| e.to_string())?;
    let ctx = detect_context(&policy);
    let (findings, _) = detect::run_with(
        &result.tree,
        &ctx,
        &detectors::registry(),
        req.detectors.as_deref(),
    );
    let sel = &req.selection;
    let above_ceiling = sel.ceiling().map_or(0, |c| {
        findings
            .iter()
            .filter(|f| {
                f.tier > c && f.tier != Tier::Blocked && f.action.kind != ActionKind::Advice
            })
            .count()
    });
    fe.status(Some("checking guards…"));
    let plan = plan::build(
        findings,
        sel,
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
            detectors: req.detectors.clone(),
        },
    );
    fe.status(None);
    Ok(PlanOutcome {
        plan: plan?,
        above_ceiling,
    })
}

/// The hint of a refusal to apply a plan: a fresh plan helps when it is
/// stale or not for here, but not when its root is not valid UTF-8.
pub fn unusable_hint(e: &plan::Unusable) -> Option<&'static str> {
    match e {
        plan::Unusable::Expired(_) | plan::Unusable::Elsewhere(_) => {
            Some("run `dwhy plan` to create a fresh plan")
        }
        plan::Unusable::LossyRoot(_) => None,
    }
}

/// Rescans the plan's roots, re-runs its detectors, and decides each item
/// under `policy` (guards, fingerprints, tiers). Removes nothing.
pub fn survey(
    plan: &Plan,
    policy: &Policy,
    config: &PolicyConfig,
    fe: &dyn Frontend,
) -> Result<Vec<Check>> {
    let mounts = MountTable::read().unwrap_or_default();
    let roots: Vec<PathBuf> = plan.scan.roots.iter().map(PathBuf::from).collect();
    let result = fe
        .measure(&roots, plan.scan.one_filesystem, u64::MAX, &mounts)
        .map_err(|e| e.to_string())?;
    let ctx = detect_context(config);
    let (findings, _) = detect::run_with(
        &result.tree,
        &ctx,
        &detectors::registry(),
        plan.scan.detectors.as_deref(),
    );
    fe.status(Some("checking guards…"));
    let checks = apply::evaluate(
        plan,
        findings,
        &result.tree,
        &ctx,
        &Processes::read(),
        policy,
    );
    fe.status(None);
    Ok(checks)
}
