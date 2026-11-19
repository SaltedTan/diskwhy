//! The scan the TUI runs: the same pipeline as `dwhy scan` (roots, walk,
//! filesystems and unaccounted space, detectors, probes, growth on
//! findings), with no snapshot saved. Also the plan work: rescanning for
//! marked findings, building with core `plan::build`, and handling plan
//! files; and applying a plan through core `apply`, as `dwhy apply` does.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::account;
use dwhy_core::apply::{self, Audit, Policy};
use dwhy_core::detect::{self, DetectContext};
use dwhy_core::growth;
use dwhy_core::guard::Processes;
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::report::{
    ApplyItem, ApplyReport, DetectorRun, Finding, Plan, PlanScan, ScanReport, UnreadableReason,
};
use dwhy_core::scan::{self, Progress, ScanOptions, ScanResult};
use dwhy_core::system;
use dwhy_core::tree::{NodeId, ScanTree};

/// What to scan, and how this session applies plans.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Directories to scan; empty means the current directory, as in `dwhy scan`.
    pub paths: Vec<PathBuf>,
    /// Descend into other filesystems mounted below the roots.
    pub cross_filesystems: bool,
    /// Run only these detectors (`None`: all of them, as `dwhy scan` does).
    pub detectors: Option<Vec<String>>,
    /// Worker threads; 0 means one per CPU.
    pub threads: usize,
    /// Snapshots to read growth from, as `dwhy scan` does
    /// (`snapshot::default_dir()`); `None`: findings get no growth.
    /// Only read, never written.
    pub snapshot_dir: Option<PathBuf>,
    /// `dwhy tui --dry-run`: `y` in the confirm dialog is a dry run too.
    pub dry_run: bool,
    /// The audit log apply appends to, as `dwhy apply` does
    /// (`apply::Audit::default_path()`); `None`: a real apply fails before
    /// removing anything. A dry run writes no audit line.
    pub audit_log: Option<PathBuf>,
    /// What detectors know about the system; `None`: the real system
    /// (`DetectContext::from_system`). Tests pass a fixed one; its `now` is
    /// replaced with the current time on each use.
    pub context: Option<DetectContext>,
}

impl Options {
    /// The roots to scan, made absolute (symlinks in the last component are
    /// not followed). Fails like `dwhy scan` does on a missing root or an
    /// unknown detector name.
    fn roots(&self) -> Result<Vec<PathBuf>, String> {
        if let Some(names) = &self.detectors {
            detect::validate_selection(names)?;
        }
        self.prepare_roots()
    }

    fn prepare_roots(&self) -> Result<Vec<PathBuf>, String> {
        let paths = if self.paths.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            self.paths.clone()
        };
        scan::prepare_roots(&paths, !self.cross_filesystems).map_err(|e| e.to_string())
    }

    fn walk(
        &self,
        roots: &[PathBuf],
        mounts: &MountTable,
        progress: &Progress,
    ) -> Result<ScanResult, String> {
        let opts = ScanOptions {
            one_filesystem: !self.cross_filesystems,
            min_dir_bytes: u64::MAX,
            threads: self.threads,
            ..ScanOptions::default()
        };
        scan::scan(roots, &opts, mounts, progress).map_err(|e| e.to_string())
    }

    fn detect_context(&self) -> DetectContext {
        match &self.context {
            Some(ctx) => DetectContext {
                now: now(),
                ..ctx.clone()
            },
            None => DetectContext::from_system(),
        }
    }

    /// The options a rescan of `plan` uses: its roots, filesystem setting
    /// and detectors, as `dwhy apply` rescans them; the rest from `self`.
    pub fn for_plan(&self, plan: &Plan) -> Options {
        Options {
            paths: plan.scan.roots.iter().map(PathBuf::from).collect(),
            cross_filesystems: !plan.scan.one_filesystem,
            detectors: plan.scan.detectors.clone(),
            ..self.clone()
        }
    }
}

/// Where a running scan is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Walking,
    Accounting,
    Detecting,
}

/// Why a directory's contents are not (fully) counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMark {
    /// It could not be listed.
    Unreadable,
    /// It was listed, but this many entries could not be `lstat`ed.
    EntriesDenied(u64),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Mark {
    pub permission: Option<PermissionMark>,
    pub read_error: bool,
    pub skipped_mounts: usize,
}

/// A finished scan. The report supplies filesystem figures and scan diagnostics.
/// The full tree supplies directory rows independently of the report's size cutoff.
#[derive(Debug, Clone)]
pub struct Scanned {
    pub report: ScanReport,
    pub tree: ScanTree,
    /// Directories whose contents are not fully counted.
    pub marks: HashMap<NodeId, Mark>,
    /// `created_at` of the snapshot the findings' growth was measured from;
    /// `None` when there was none to measure from.
    pub growth_base: Option<String>,
    /// Prepared roots and options for the plan's rescan.
    pub plan_options: Options,
}

/// Runs the whole scan on this thread, reporting each stage to `stage`.
pub fn scan(
    opts: &Options,
    progress: &Progress,
    stage: &mut dyn FnMut(Stage),
) -> Result<Scanned, String> {
    stage(Stage::Walking);
    let roots = opts.roots()?;
    let mounts = MountTable::read().unwrap_or_default();
    let result = opts.walk(&roots, &mounts, progress)?;

    stage(Stage::Accounting);
    let mut report = account::system_scan_report(&result, &mounts);

    stage(Stage::Detecting);
    detect::detect_into_with(
        &mut report,
        &result.tree,
        &opts.detect_context(),
        opts.detectors.as_deref(),
        true,
    );
    let growth_base = opts
        .snapshot_dir
        .as_deref()
        .and_then(|dir| growth::fill_scan_growth(&mut report, dir, now()));

    let marks = coverage_marks(&result);
    Ok(Scanned {
        report,
        tree: result.tree,
        marks,
        growth_base,
        plan_options: Options {
            paths: roots,
            ..opts.clone()
        },
    })
}

/// A scan to run off the UI thread: the rescan after an apply.
#[derive(Debug)]
pub struct ScanJob {
    pub options: Options,
    pub progress: Arc<Progress>,
}

pub struct ScanOutcome {
    pub scanned: Option<Scanned>,
    pub removed: Vec<PathBuf>,
}

impl ScanJob {
    pub fn run(mut self, stage: &mut dyn FnMut(Stage)) -> Result<ScanOutcome, String> {
        let mut removed = Vec::new();
        self.options.paths.retain(|path| {
            if fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
                removed.push(path.clone());
                false
            } else {
                true
            }
        });
        let scanned = if self.options.paths.is_empty() && !removed.is_empty() {
            None
        } else {
            Some(scan(&self.options, &self.progress, stage)?)
        };
        Ok(ScanOutcome { scanned, removed })
    }
}

/// A plan to build off the UI thread.
#[derive(Debug)]
pub struct PlanJob {
    pub options: Options,
    pub progress: Arc<Progress>,
    pub marks: Vec<PlanMark>,
}

#[derive(Debug)]
pub struct PlanMark {
    id: String,
    detector: String,
    path: String,
}

impl From<&Finding> for PlanMark {
    fn from(finding: &Finding) -> Self {
        Self {
            id: finding.id.clone(),
            detector: finding.detector.clone(),
            path: finding.path.clone(),
        }
    }
}

#[derive(Debug)]
pub struct BuiltPlan {
    pub plan: Plan,
    pub unplanned: Vec<UnplannedMark>,
}

#[derive(Debug)]
pub enum UnplannedMark {
    Gone(String),
    NotChecked { path: String, reason: String },
}

impl fmt::Display for UnplannedMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gone(path) => write!(f, "gone since the scan: {path}"),
            Self::NotChecked { path, reason } => write!(f, "not checked: {reason} ({path})"),
        }
    }
}

impl PlanJob {
    /// Builds a plan for marks found on the rescan and reports missing marks
    /// separately so the preview can explain why they were left out.
    pub fn build(
        self,
        read_processes: impl FnOnce() -> Processes,
        host: String,
    ) -> Result<BuiltPlan, String> {
        let opts = self.options;
        let roots = opts.roots()?;
        let mounts = MountTable::read().unwrap_or_default();
        let result = opts.walk(&roots, &mounts, &self.progress)?;
        let ctx = opts.detect_context();
        let (findings, runs) = detect::run_with(
            &result.tree,
            &ctx,
            &dwhy_core::detectors::registry(),
            opts.detectors.as_deref(),
        );
        let ids: HashSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        let mut select = Vec::new();
        let mut unplanned = Vec::new();
        for PlanMark { id, detector, path } in self.marks {
            if ids.contains(id.as_str()) {
                select.push(id);
                continue;
            }
            let reason = match runs.iter().find(|run| run.name == detector) {
                Some(DetectorRun {
                    error: Some(error), ..
                }) => format!("{detector} failed: {error}"),
                Some(run) if run.ran => {
                    unplanned.push(UnplannedMark::Gone(path));
                    continue;
                }
                Some(run) => format!("{detector} did not run: {}", run.detail),
                None => format!("{detector} did not run"),
            };
            unplanned.push(UnplannedMark::NotChecked { path, reason });
        }
        if select.is_empty() {
            if unplanned
                .iter()
                .all(|mark| matches!(mark, UnplannedMark::Gone(_)))
            {
                return Err("all marked findings are gone since the scan".into());
            }
            return Err(unplanned
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" · "));
        }
        let plan = plan::build(
            findings,
            &Selection { tier: None, select },
            &result.tree,
            &ctx,
            &read_processes(),
            host,
            PlanScan {
                roots: result
                    .roots
                    .iter()
                    .map(|r| r.path.to_string_lossy().into_owned())
                    .collect(),
                one_filesystem: !opts.cross_filesystems,
                detectors: opts.detectors,
            },
        )?;
        Ok(BuiltPlan { plan, unplanned })
    }
}

/// Reads and parses a plan file, as `dwhy apply` does.
pub fn read_plan(path: &Path) -> Result<Plan, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    plan::parse(&text)
}

/// An apply to run off the UI thread: `dwhy apply PLAN --max-tier review
/// --confirm <the review items ticked in the dialog>`, with `--yes` (the
/// dialog was the confirmation) or `--dry-run`.
#[derive(Debug)]
pub struct ApplyJob {
    pub plan: Plan,
    pub policy: Policy,
    pub dry_run: bool,
    /// Threads, detector context and audit log; the roots come from the plan.
    pub options: Options,
    pub progress: Arc<ApplyProgress>,
}

/// What a running apply is doing, for the progress line, and the request
/// to stop it.
#[derive(Debug, Default)]
pub struct ApplyProgress {
    /// The rescan's counters.
    pub scan: Progress,
    step: Mutex<ApplyStep>,
    stop: Arc<AtomicUsize>,
}

pub(crate) const APPLY_STOP_REQUESTED: usize = usize::MAX;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ApplyStep {
    #[default]
    Rescanning,
    /// Detectors and guards.
    Checking,
    /// Running item `done + 1` of `total` (deepest first).
    Removing {
        done: usize,
        total: usize,
        path: String,
    },
}

impl ApplyProgress {
    pub(crate) fn with_stop(stop: Arc<AtomicUsize>) -> Self {
        Self {
            scan: Progress::default(),
            step: Mutex::default(),
            stop,
        }
    }

    pub fn step(&self) -> ApplyStep {
        self.step.lock().map(|s| s.clone()).unwrap_or_default()
    }

    fn set(&self, step: ApplyStep) {
        if let Ok(mut s) = self.step.lock() {
            *s = step;
        }
    }

    /// Asks the apply to stop: the item in progress finishes, no other runs.
    pub fn stop(&self) {
        let _ = self.stop.compare_exchange(
            0,
            APPLY_STOP_REQUESTED,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed) != 0
    }
}

/// A finished apply.
#[derive(Debug, Clone)]
pub struct Applied {
    pub report: ApplyReport,
    /// The audit log written to; `None` for a dry run.
    pub audit: Option<PathBuf>,
    /// What `dwhy apply` exits with for this report.
    pub exit: u8,
    pub audit_errors: Vec<String>,
}

/// An apply that failed before running any item: what `dwhy apply` prints
/// as `dwhy: refused: …` (exit 3) or `dwhy: error: …` (exit 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyFailed {
    pub message: String,
    pub exit: u8,
    pub audit_error: bool,
}

impl ApplyFailed {
    fn error(message: impl Into<String>) -> ApplyFailed {
        ApplyFailed {
            message: message.into(),
            exit: 1,
            audit_error: false,
        }
    }

    fn audit(message: impl Into<String>) -> ApplyFailed {
        ApplyFailed {
            audit_error: true,
            ..Self::error(message)
        }
    }
}

impl ApplyJob {
    /// Runs the apply as `dwhy apply --yes` (or `--dry-run`) does: checks
    /// the plan is usable here and now, rescans its roots, re-runs its
    /// detectors and the guards, decides every item with core
    /// `apply::evaluate`, and (unless a dry run) runs the ready ones with
    /// `apply::execute_until`, writing the audit log. Commands run with
    /// their output captured by core, never on the terminal.
    pub fn run(
        self,
        read_processes: impl FnOnce() -> Processes,
        env: &apply::Env,
    ) -> Result<Applied, ApplyFailed> {
        let ApplyJob {
            plan,
            policy,
            dry_run,
            options,
            progress,
        } = self;
        if let Some(names) = &plan.scan.detectors {
            detect::validate_selection(names).map_err(ApplyFailed::error)?;
        }
        if let Err(e) = plan::usable(&plan, &env.host, env.uid, now()) {
            return Err(ApplyFailed {
                message: format!("refused: {e}"),
                exit: 3,
                audit_error: false,
            });
        }
        progress.set(ApplyStep::Rescanning);
        let opts = options.for_plan(&plan);
        let roots = opts.prepare_roots().map_err(ApplyFailed::error)?;
        let mounts = MountTable::read().unwrap_or_default();
        let result = opts
            .walk(&roots, &mounts, &progress.scan)
            .map_err(ApplyFailed::error)?;
        progress.set(ApplyStep::Checking);
        let ctx = opts.detect_context();
        let (findings, _) = detect::run_with(
            &result.tree,
            &ctx,
            &dwhy_core::detectors::registry(),
            opts.detectors.as_deref(),
        );
        let mut checks = apply::evaluate(
            &plan,
            findings,
            &result.tree,
            &ctx,
            &read_processes(),
            &policy,
        );
        if dry_run {
            let report = apply::report(&plan, &checks, &policy, true, env);
            let exit = apply::exit_code(&report);
            return Ok(Applied {
                report,
                audit: None,
                exit,
                audit_errors: Vec::new(),
            });
        }
        let path = opts.audit_log.as_deref().ok_or_else(|| {
            ApplyFailed::audit(
                "cannot place the audit log: neither XDG_STATE_HOME nor HOME is an absolute path",
            )
        })?;
        let mut audit = Audit::open(path).map_err(ApplyFailed::audit)?;
        let mounts = MountTable::read()
            .map_err(|e| ApplyFailed::error(format!("cannot read the mount table: {e}")))?;
        let total = checks.iter().filter(|c| c.ready()).count();
        let mut done = 0;
        let audit_errors = apply::execute_until(
            &plan,
            &mut checks,
            &mut audit,
            &mounts,
            env,
            &mut |item: &ApplyItem| {
                progress.set(ApplyStep::Removing {
                    done,
                    total,
                    path: item.path.clone(),
                });
                done += 1;
            },
            apply::ExecuteOptions {
                stop: &|| progress.stopping(),
                isolate_commands: true,
            },
        );
        let report = apply::report(&plan, &checks, &policy, false, env);
        let exit = apply::exit_code(&report);
        Ok(Applied {
            report,
            audit: Some(audit.path().to_path_buf()),
            exit,
            audit_errors,
        })
    }
}

#[derive(Debug)]
pub enum WriteError {
    BeforeWrite(io::Error),
    Incomplete(io::Error),
}

impl From<io::Error> for WriteError {
    fn from(error: io::Error) -> Self {
        Self::BeforeWrite(error)
    }
}

/// Creates a new file with the same JSON as `dwhy plan -o`.
pub fn write_plan(path: &Path, plan: &Plan) -> Result<(), WriteError> {
    let text = plan::to_json(plan).map_err(io::Error::from)?;
    let mut file = system::create_new_file_nofollow(path)?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(WriteError::Incomplete)
}

/// Seconds since the epoch.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn coverage_marks(result: &ScanResult) -> HashMap<NodeId, Mark> {
    let tree = &result.tree;
    let mut marks = HashMap::<NodeId, Mark>::new();
    for u in &result.unreadable {
        if let Some(id) = tree.find(&u.path) {
            let mark = match u.reason {
                UnreadableReason::PermissionDenied => PermissionMark::Unreadable,
                UnreadableReason::EntriesDenied => PermissionMark::EntriesDenied(u.entries_unknown),
            };
            marks.entry(id).or_default().permission = Some(mark);
        }
    }
    for (path, _) in &result.errors {
        if let Some(id) = path
            .ancestors()
            .filter_map(|p| tree.find(p))
            .find(|&id| tree.node(id).is_dir)
        {
            marks.entry(id).or_default().read_error = true;
        }
    }
    for skip in &result.skipped_mounts {
        if let Some(id) = skip.path.parent().and_then(|parent| tree.find(parent)) {
            marks.entry(id).or_default().skipped_mounts += 1;
        }
    }
    marks
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use dwhy_core::report::SkipReason;
    use dwhy_core::scan::{SkippedRecord, UnreadableRecord};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::{App, ui};

    #[test]
    fn browser_shows_directory_diagnostics_and_skipped_mounts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let mixed = root.join("mixed");
        let omitted = root.join("omitted");
        fs::create_dir(&mixed).unwrap();
        fs::create_dir(&omitted).unwrap();
        fs::write(mixed.join("measured"), b"data").unwrap();
        let mounts = MountTable::default();
        let opts = ScanOptions {
            threads: 2,
            ..ScanOptions::default()
        };
        let mut result = scan::scan(&[root], &opts, &mounts, &Progress::default()).unwrap();
        let dev = result.roots[0].dev;
        result.unreadable.push(UnreadableRecord {
            path: mixed.clone(),
            dev,
            reason: UnreadableReason::EntriesDenied,
            entries_unknown: 1,
            known_bytes: 0,
            owner_uid: dwhy_core::system::euid(),
        });
        result
            .errors
            .push((mixed.join("failed-stat"), "I/O error".into()));
        result.error_count = 1;
        result.skipped_mounts.extend([
            SkippedRecord {
                path: omitted.join("volume"),
                parent_dev: dev,
                fstype: Some("ext4".into()),
                reason: SkipReason::OtherFilesystem,
            },
            SkippedRecord {
                path: omitted.join("bind-file"),
                parent_dev: dev,
                fstype: Some("ext4".into()),
                reason: SkipReason::BindMount,
            },
        ]);
        let mut app = App::new(Vec::new(), Arc::new(Progress::default()));
        app.finish(Scanned {
            report: account::system_scan_report(&result, &mounts),
            marks: coverage_marks(&result),
            tree: result.tree,
            growth_base: None,
            plan_options: Options::default(),
        });
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut screen = |app: &mut App| {
            term.draw(|f| ui::draw(f, app)).unwrap();
            term.backend().to_string()
        };
        let press = |app: &mut App, code| {
            assert!(!app.on_key(KeyEvent::new(code, KeyModifiers::NONE)));
        };
        press(&mut app, KeyCode::Char('a'));
        let tree = screen(&mut app);
        assert!(
            tree.contains("mixed/  [1 entry unreadable, read error]"),
            "{tree}"
        );
        assert!(tree.contains("omitted/  [2 mounts skipped]"), "{tree}");
        assert!(tree.contains("2 mounts skipped in scan"), "{tree}");

        press(&mut app, KeyCode::Enter);
        let inside = screen(&mut app);
        assert!(inside.contains("[files]"), "{inside}");
        assert!(
            inside.contains("this directory: 1 entry unreadable, read error"),
            "{inside}"
        );

        for key in [KeyCode::Backspace, KeyCode::Down, KeyCode::Enter] {
            press(&mut app, key);
        }
        let inside = screen(&mut app);
        assert!(
            inside.contains("this directory: 2 mounts skipped"),
            "{inside}"
        );
        assert!(inside.contains("2 mounts skipped in scan"), "{inside}");
        assert!(!inside.contains("(empty)"), "{inside}");
    }
}
