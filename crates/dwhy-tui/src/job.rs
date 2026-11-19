//! The scan the TUI runs: the same pipeline as `dwhy scan` (roots, walk,
//! filesystems and unaccounted space, detectors, probes, growth on
//! findings), with no snapshot saved. Also the plan work: building a plan
//! from marked findings as `dwhy plan --select` does, reading a plan file,
//! and writing one.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::account;
use dwhy_core::detect::{self, DetectContext};
use dwhy_core::explain::lossy_finding_paths;
use dwhy_core::growth;
use dwhy_core::guard::Processes;
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::report::{Plan, PlanScan, ScanReport, UnreadableReason};
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
    detect::detect_into(&mut report, &result.tree, opts.detectors.as_deref(), true);
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
            snapshot_dir: None,
            ..opts.clone()
        },
    })
}

/// A plan to build off the UI thread.
#[derive(Debug)]
pub struct PlanJob {
    pub options: Options,
    pub progress: Arc<Progress>,
    /// The marked findings' ids.
    pub select: Vec<String>,
}

#[derive(Debug)]
pub struct BuiltPlan {
    pub plan: Plan,
    pub gone: Vec<String>,
    pub lossy_paths: HashSet<String>,
}

impl PlanJob {
    /// Builds the plan as `dwhy plan --select <ids>` does, after a fresh walk.
    pub fn build(
        self,
        read_processes: impl FnOnce() -> Processes,
        host: String,
    ) -> Result<BuiltPlan, String> {
        let opts = self.options;
        let mounts = MountTable::read().unwrap_or_default();
        let result = opts.walk(&opts.paths, &mounts, &self.progress)?;
        let ctx = DetectContext::from_system();
        let (findings, _) = detect::run_with(
            &result.tree,
            &ctx,
            &dwhy_core::detectors::registry(),
            opts.detectors.as_deref(),
        );
        let ids: HashSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        let (select, gone): (Vec<_>, Vec<_>) = self
            .select
            .into_iter()
            .partition(|id| ids.contains(id.as_str()));
        if select.is_empty() {
            return Err("all marked findings are gone since the scan".into());
        }
        let lossy_paths = lossy_finding_paths(&findings, &result.tree);
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
        Ok(BuiltPlan {
            plan,
            gone,
            lossy_paths,
        })
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
    File { identity: FileIdentity, mode: u32 },
    /// A symlink or something else that is not a regular file.
    Refused(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl FileIdentity {
    fn from_metadata(md: &fs::Metadata) -> Self {
        Self {
            dev: md.dev(),
            ino: md.ino(),
        }
    }
}

pub fn target(path: &Path) -> io::Result<Target> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Target::Free),
        Err(e) => Err(e),
        Ok(md) if md.file_type().is_symlink() => Ok(Target::Refused("it is a symlink".into())),
        Ok(md) if !md.is_file() => Ok(Target::Refused("it is not a regular file".into())),
        Ok(md) => Ok(Target::File {
            identity: FileIdentity::from_metadata(&md),
            mode: md.mode() & 0o7777,
        }),
    }
}

/// Writes the same JSON as `dwhy plan -o`. An existing regular file can be
/// replaced only after confirmation of its identity.
pub fn write_plan(path: &Path, plan: &Plan, overwrite: Option<FileIdentity>) -> io::Result<()> {
    let text = plan::to_json(plan)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let Some(confirmed) = overwrite else {
        let mut file = options.open(path)?;
        return write_contents(&mut file, &text).inspect_err(|_| {
            remove_created(path, &file);
        });
    };
    confirmed_mode(path, confirmed)?;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let (tmp, mut file) = loop {
        let n = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_file_name(format!(".dwhy-plan.{}.{n}.tmp", std::process::id()));
        if tmp == path {
            continue;
        }
        match options.mode(0o600).open(&tmp) {
            Ok(file) => break (tmp, file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        write_contents(&mut file, &text)?;
        let mode = confirmed_mode(path, confirmed)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        remove_created(&tmp, &file);
    }
    result
}

fn confirmed_mode(path: &Path, confirmed: FileIdentity) -> io::Result<u32> {
    match target(path)? {
        Target::File { identity, mode } if identity == confirmed => Ok(mode),
        _ => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the target changed since the overwrite prompt",
        )),
    }
}

fn write_contents(file: &mut fs::File, text: &str) -> io::Result<()> {
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

fn remove_created(path: &Path, file: &fs::File) {
    if let (Ok(md), Ok(Target::File { identity, .. })) = (file.metadata(), target(path))
        && FileIdentity::from_metadata(&md) == identity
    {
        let _ = fs::remove_file(path);
    }
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
