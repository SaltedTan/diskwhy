//! The scan the TUI runs: the same pipeline as `dwhy scan` (roots, walk,
//! filesystems and unaccounted space, detectors, probes, growth on
//! findings), with no snapshot saved.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::account;
use dwhy_core::detect;
use dwhy_core::growth;
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ScanReport, UnreadableReason};
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
    pub tree: ScanTree,
    /// Directories whose contents are not fully counted.
    pub marks: HashMap<NodeId, Mark>,
    /// `created_at` of the snapshot the findings' growth was measured from;
    /// `None` when there was none to measure from.
    pub growth_base: Option<String>,
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
    detect::detect_into(&mut report, &result.tree, opts.detectors.as_deref(), true);
    let growth_base = opts.snapshot_dir.as_deref().and_then(|dir| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        growth::fill_scan_growth(&mut report, dir, now)
    });

    let marks = coverage_marks(&result);
    Ok(Scanned {
        report,
        tree: result.tree,
        marks,
        growth_base,
    })
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
