//! The scan the TUI runs: the same pipeline as `dwhy scan` (roots, walk,
//! filesystems and unaccounted space, detectors, probes), with no snapshot.

use std::collections::HashMap;
use std::path::PathBuf;

use dwhy_core::account;
use dwhy_core::detect;
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ScanReport, UnreadableReason};
use dwhy_core::scan::{self, Progress, ScanOptions};
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
pub enum Mark {
    /// It could not be listed.
    Unreadable,
    /// It was listed, but this many entries could not be `lstat`ed.
    EntriesDenied(u64),
    Error,
}

/// A finished scan: the report `dwhy scan --json` would print (without its
/// directory list) and the directory tree.
#[derive(Debug, Clone)]
pub struct Scanned {
    pub report: ScanReport,
    pub tree: ScanTree,
    /// Directories whose contents are not fully counted.
    pub marks: HashMap<NodeId, Mark>,
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

    let tree = result.tree;
    let mut marks = HashMap::new();
    for u in &result.unreadable {
        if let Some(id) = tree.find(&u.path) {
            let mark = match u.reason {
                UnreadableReason::PermissionDenied => Mark::Unreadable,
                UnreadableReason::EntriesDenied => Mark::EntriesDenied(u.entries_unknown),
            };
            marks.insert(id, mark);
        }
    }
    for (path, _) in &result.errors {
        if let Some(id) = path
            .ancestors()
            .filter_map(|p| tree.find(p))
            .find(|&id| tree.node(id).is_dir)
        {
            marks.entry(id).or_insert(Mark::Error);
        }
    }
    Ok(Scanned {
        report,
        tree,
        marks,
    })
}
