//! The scan the TUI runs: the same pipeline as `dwhy scan` (roots, walk,
//! filesystems and unaccounted space, detectors, probes, growth on
//! findings), with no snapshot saved. Also the plan work: building a plan
//! from marked findings as `dwhy plan --select` does, reading a plan file,
//! and writing one.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::account;
use dwhy_core::detect::{self, DetectContext};
use dwhy_core::growth;
use dwhy_core::guard::Processes;
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::probes;
use dwhy_core::report::{Finding, Plan, PlanScan, ScanReport, UnreadableReason};
use dwhy_core::scan::{self, Progress, ScanOptions, ScanResult};
use dwhy_core::tree::{NodeId, ScanTree};

/// What to scan.
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
}

impl Options {
    /// The roots to scan, made absolute (symlinks in the last component are
    /// not followed). Fails like `dwhy scan` does on a missing root or an
    /// unknown detector name.
    fn roots(&self) -> Result<Vec<PathBuf>, String> {
        if let Some(names) = &self.detectors {
            detect::validate_selection(names)?;
        }
        let paths = if self.paths.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            self.paths.clone()
        };
        scan::prepare_roots(&paths, !self.cross_filesystems).map_err(|e| e.to_string())
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
    /// Shared with a plan build on its worker thread.
    pub tree: Arc<ScanTree>,
    /// Directories whose contents are not fully counted.
    pub marks: HashMap<NodeId, Mark>,
    /// `created_at` of the snapshot the findings' growth was measured from;
    /// `None` when there was none to measure from.
    pub growth_base: Option<String>,
    /// What a plan is built from, as `dwhy plan` would on the same scan.
    pub plan: PlanSource,
}

/// What `plan::build` needs from the scan: the findings as `dwhy plan`
/// sees them (from the detectors, before probes and growth), the detector
/// context (its `now` is the plan's creation time), and the roots.
#[derive(Debug, Clone)]
pub struct PlanSource {
    pub findings: Vec<Finding>,
    pub ctx: DetectContext,
    pub scan: PlanScan,
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
    let one_fs = !opts.cross_filesystems;
    let scan_opts = ScanOptions {
        one_filesystem: one_fs,
        // The tree has every directory; the report's size-filtered list is not shown.
        min_dir_bytes: u64::MAX,
        threads: opts.threads,
        ..ScanOptions::default()
    };
    let result = scan::scan(&roots, &scan_opts, &mounts, progress).map_err(|e| e.to_string())?;

    stage(Stage::Accounting);
    let mut report = account::system_scan_report(&result, &mounts);

    stage(Stage::Detecting);
    let ctx = DetectContext::from_system();
    let only = opts.detectors.as_deref();
    detect::detect_into_with(&mut report, &result.tree, &ctx, only, false);
    // `dwhy plan` runs no probes and measures no growth.
    let plan = PlanSource {
        findings: report.findings.clone(),
        scan: PlanScan {
            roots: result
                .roots
                .iter()
                .map(|r| r.path.to_string_lossy().into_owned())
                .collect(),
            one_filesystem: one_fs,
            detectors: opts.detectors.clone(),
        },
        ctx,
    };
    probes::run(&mut report.findings, &plan.ctx);
    let growth_base = opts
        .snapshot_dir
        .as_deref()
        .and_then(|dir| growth::fill_scan_growth(&mut report, dir, now()));

    let marks = coverage_marks(&result);
    Ok(Scanned {
        report,
        tree: Arc::new(result.tree),
        marks,
        growth_base,
        plan,
    })
}

/// A plan to build off the UI thread.
#[derive(Debug, Clone)]
pub struct PlanJob {
    pub source: PlanSource,
    pub tree: Arc<ScanTree>,
    /// The marked findings' ids.
    pub select: Vec<String>,
}

impl PlanJob {
    /// Builds the plan as `dwhy plan --select <ids>` does: no tier ceiling,
    /// guards run on the selection with `procs`, fingerprints and expiry.
    pub fn build(&self, procs: &Processes, host: String) -> Result<Plan, String> {
        let sel = Selection {
            tier: None,
            select: self.select.clone(),
        };
        plan::build(
            self.source.findings.clone(),
            &sel,
            &self.tree,
            &self.source.ctx,
            procs,
            host,
            self.source.scan.clone(),
        )
    }
}

/// Reads and parses a plan file, as `dwhy apply` does.
pub fn read_plan(path: &Path) -> Result<Plan, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    plan::parse(&text)
}

/// What is at the path a plan is about to be written to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Nothing: the plan can be written.
    Free,
    /// A regular file: ask before overwriting it.
    File,
    /// A symlink or something else that is not a regular file.
    Refused(String),
}

pub fn target(path: &Path) -> io::Result<Target> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Target::Free),
        Err(e) => Err(e),
        Ok(md) if md.file_type().is_symlink() => Ok(Target::Refused("it is a symlink".into())),
        Ok(md) if !md.is_file() => Ok(Target::Refused("it is not a regular file".into())),
        Ok(_) => Ok(Target::File),
    }
}

/// Writes `plan` to `path` exactly as `dwhy plan -o` does, never through a
/// symlink. Without `overwrite` the file must not exist (`O_CREAT|O_EXCL`,
/// which does not follow a symlink either). With it, the plan goes to a new
/// file in the same directory that is then renamed over `path`: the rename
/// replaces the directory entry, so a symlink put there meanwhile is
/// replaced, not followed.
pub fn write_plan(path: &Path, plan: &Plan, overwrite: bool) -> io::Result<()> {
    let text = plan::to_json(plan)?;
    if !overwrite {
        return write_new(path, &text);
    }
    if let Target::Refused(why) = target(path)? {
        return Err(io::Error::other(why));
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    write_new(&tmp, &text)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

fn write_new(path: &Path, text: &str) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .inspect_err(|_| {
            let _ = fs::remove_file(path);
        })
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
            tree: Arc::new(result.tree),
            growth_base: None,
            plan: PlanSource {
                findings: Vec::new(),
                ctx: DetectContext::from_system(),
                scan: PlanScan {
                    roots: Vec::new(),
                    one_filesystem: true,
                    detectors: None,
                },
            },
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
