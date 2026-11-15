//! Parallel, read-only directory walk.
//!
//! * Never follows symlinks: every entry is `lstat`ed, and a symlink is
//!   counted as a symlink (its own blocks), never descended into.
//! * Stays on the root's filesystem by default (`-x`). Mount points are
//!   recorded as skipped. Virtual filesystems (proc, sysfs, ...) are never
//!   entered, even when crossing filesystems.
//! * Counts each inode with more than one link once, keyed by (dev, inode).
//! * Records directories it cannot list or whose entries it cannot stat,
//!   instead of skipping them silently.
//!
//! The walk opens directories read-only (`O_NOFOLLOW`) and `fstatat`s each
//! entry relative to its directory with `AT_SYMLINK_NOFOLLOW`; it never
//! writes, and changes nothing beyond the atime a directory read may set.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, Stat};
use rustix::io::Errno;

use crate::mounts::MountTable;
pub use crate::report::{SkipReason, Totals, UnreadableReason};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Stay on each root's filesystem (default true).
    pub one_filesystem: bool,
    /// Directories at least this large (allocated, recursive) are recorded.
    pub min_dir_bytes: u64,
    /// Worker threads; 0 means one per CPU.
    pub threads: usize,
    /// Cap on non-permission errors kept with paths (all are counted).
    pub max_errors: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            one_filesystem: true,
            min_dir_bytes: 1 << 20,
            threads: 0,
            max_errors: 200,
        }
    }
}

/// Live counters, readable from another thread while a scan runs.
#[derive(Debug, Default)]
pub struct Progress {
    pub entries: AtomicU64,
    pub allocated: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct RootResult {
    pub path: PathBuf,
    pub dev: u64,
    pub totals: Totals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirRecord {
    pub path: PathBuf,
    pub depth: u32,
    pub totals: Totals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableRecord {
    pub path: PathBuf,
    pub dev: u64,
    pub reason: UnreadableReason,
    pub entries_unknown: u64,
    /// Allocated bytes of the directory inode itself (already in the totals).
    pub known_bytes: u64,
    pub owner_uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRecord {
    pub path: PathBuf,
    /// Device of the filesystem the mount point sits on.
    pub parent_dev: u64,
    pub fstype: Option<String>,
    pub reason: SkipReason,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub one_filesystem: bool,
    pub min_dir_bytes: u64,
    pub roots: Vec<RootResult>,
    /// Sorted largest first.
    pub dirs: Vec<DirRecord>,
    /// Sorted by path.
    pub unreadable: Vec<UnreadableRecord>,
    /// Sorted by path.
    pub skipped_mounts: Vec<SkippedRecord>,
    /// Allocated bytes counted per device.
    pub per_dev: HashMap<u64, Totals>,
    pub errors: Vec<(PathBuf, String)>,
    pub error_count: u64,
    pub elapsed: Duration,
}

impl ScanResult {
    pub fn totals(&self) -> Totals {
        let mut t = Totals::default();
        for r in &self.roots {
            t += r.totals;
        }
        t
    }
}

#[derive(Debug)]
pub enum ScanError {
    Root { path: PathBuf, source: io::Error },
    ThreadPool(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Root { path, source } => write!(f, "{}: {source}", path.display()),
            ScanError::ThreadPool(e) => write!(f, "cannot start worker threads: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Makes each root absolute without following a symlink in its last
/// component, and drops roots already covered by another root.
pub fn prepare_roots(paths: &[PathBuf], one_filesystem: bool) -> Result<Vec<PathBuf>, ScanError> {
    let mut out: Vec<(PathBuf, u64)> = Vec::new();
    for p in paths {
        let abs = absolute_nofollow(p).map_err(|source| ScanError::Root {
            path: p.clone(),
            source,
        })?;
        let md = fs::symlink_metadata(&abs).map_err(|source| ScanError::Root {
            path: p.clone(),
            source,
        })?;
        out.push((abs, md.dev()));
    }
    // Shorter paths first so that ancestors are kept and descendants dropped.
    out.sort_by_key(|a| a.0.as_os_str().len());
    let mut kept: Vec<(PathBuf, u64)> = Vec::new();
    for (p, dev) in out {
        let covered = kept
            .iter()
            .any(|(k, kdev)| p.starts_with(k) && (!one_filesystem || *kdev == dev));
        if !covered {
            kept.push((p, dev));
        }
    }
    Ok(kept.into_iter().map(|(p, _)| p).collect())
}

fn absolute_nofollow(p: &Path) -> io::Result<PathBuf> {
    let abs = std::path::absolute(p)?;
    match (abs.parent(), abs.file_name()) {
        (Some(parent), Some(name)) => Ok(fs::canonicalize(parent)?.join(name)),
        // "/" or a path ending in ".." — canonicalizing is safe: there is no
        // final symlink component to avoid following.
        _ => fs::canonicalize(&abs),
    }
}

const LINK_SHARDS: usize = 64;
const NO_PARENT: u32 = u32::MAX;

/// One directory (or a non-directory root) of the in-memory tree. Children
/// are always pushed after their parent, so a reverse pass over the arena
/// sums subtrees.
struct Node {
    parent: u32,
    depth: u32,
    is_dir: bool,
    /// Last path component; the full path for a root.
    name: Box<OsStr>,
    /// The directory inode plus its non-directory entries.
    own: Totals,
}

/// An inode with more than one link. It is counted once and attributed to
/// its lexicographically smallest path, so per-directory sizes do not depend
/// on which thread reached a link first.
struct Link {
    path: PathBuf,
    node: u32,
    dev: u64,
    leaf: Totals,
    seen: u64,
}

struct Shared<'a> {
    opts: &'a ScanOptions,
    mounts: &'a MountTable,
    mount_points: HashSet<&'a Path>,
    nodes: Mutex<Vec<Node>>,
    links: Vec<Mutex<HashMap<(u64, u64), Link>>>,
    unreadable: Mutex<Vec<UnreadableRecord>>,
    skipped: Mutex<Vec<SkippedRecord>>,
    per_dev: Mutex<HashMap<u64, Totals>>,
    errors: Mutex<Vec<(PathBuf, String)>>,
    error_count: AtomicU64,
    progress: &'a Progress,
}

impl Shared<'_> {
    fn push_node(&self, node: Node) -> u32 {
        let mut nodes = self.nodes.lock().unwrap();
        let id = nodes.len() as u32;
        nodes.push(node);
        id
    }

    fn add_link(&self, st: &Stat, path: PathBuf, node: u32) {
        let key = (st.st_dev, st.st_ino);
        let shard = ((key.1 ^ key.0.rotate_left(17)) as usize) % LINK_SHARDS;
        let mut map = self.links[shard].lock().unwrap();
        match map.entry(key) {
            Entry::Vacant(v) => {
                v.insert(Link {
                    path,
                    node,
                    dev: key.0,
                    leaf: leaf_totals(st),
                    seen: 1,
                });
            }
            Entry::Occupied(mut o) => {
                let l = o.get_mut();
                l.seen += 1;
                if path < l.path {
                    l.path = path;
                    l.node = node;
                }
            }
        }
    }

    fn error(&self, path: &Path, e: &io::Error) {
        let n = self.error_count.fetch_add(1, Ordering::Relaxed);
        if (n as usize) < self.opts.max_errors {
            self.errors
                .lock()
                .unwrap()
                .push((path.to_path_buf(), e.to_string()));
        }
    }

    fn add_dev(&self, dev: u64, t: Totals) {
        *self.per_dev.lock().unwrap().entry(dev).or_default() += t;
    }

    fn skip(&self, path: PathBuf, parent_dev: u64, reason: SkipReason) {
        let fstype = self.mounts.at(&path).map(|m| m.fstype.clone());
        self.skipped.lock().unwrap().push(SkippedRecord {
            path,
            parent_dev,
            fstype,
            reason,
        });
    }

    /// Decides whether to descend into `path` (on `dev`), found inside a
    /// directory on `parent_dev`.
    fn crosses_boundary(&self, path: &Path, dev: u64, parent_dev: u64) -> Option<SkipReason> {
        let other_dev = dev != parent_dev;
        // A bind mount of the same filesystem keeps st_dev; the mount table still knows it.
        let is_mount_point = other_dev || self.mount_points.contains(path);
        if !is_mount_point {
            return None;
        }
        let is_virtual = self
            .mounts
            .at(path)
            .map(|m| m.is_virtual())
            .unwrap_or(false);
        if is_virtual {
            Some(SkipReason::Virtual)
        } else if !other_dev {
            // Its contents are reachable at the original location; entering
            // would count them twice.
            Some(SkipReason::BindMount)
        } else if self.opts.one_filesystem {
            Some(SkipReason::OtherFilesystem)
        } else {
            None
        }
    }
}

fn is_perm(e: Errno) -> bool {
    e == Errno::ACCESS || e == Errno::PERM
}

fn bytes(st: &Stat) -> u64 {
    (st.st_blocks as u64).saturating_mul(512)
}

fn is_dir(st: &Stat) -> bool {
    FileType::from_raw_mode(st.st_mode) == FileType::Directory
}

fn lstat(path: &Path) -> io::Result<Stat> {
    Ok(rustix::fs::lstat(path)?)
}

/// Counts for one non-directory entry.
fn leaf_totals(st: &Stat) -> Totals {
    let mut t = Totals {
        allocated: bytes(st),
        apparent: st.st_size as u64,
        ..Totals::default()
    };
    match FileType::from_raw_mode(st.st_mode) {
        FileType::RegularFile => t.files = 1,
        FileType::Symlink => t.symlinks = 1,
        _ => t.other = 1,
    }
    t
}

/// Scans `roots` (already prepared with [`prepare_roots`]).
pub fn scan(
    roots: &[PathBuf],
    opts: &ScanOptions,
    mounts: &MountTable,
    progress: &Progress,
) -> Result<ScanResult, ScanError> {
    let start = Instant::now();
    let shared = Shared {
        opts,
        mounts,
        mount_points: mounts
            .mounts
            .iter()
            .map(|m| m.mount_point.as_path())
            .collect(),
        nodes: Mutex::default(),
        links: (0..LINK_SHARDS).map(|_| Mutex::default()).collect(),
        unreadable: Mutex::default(),
        skipped: Mutex::default(),
        per_dev: Mutex::default(),
        errors: Mutex::default(),
        error_count: AtomicU64::new(0),
        progress,
    };

    let mut builder = rayon::ThreadPoolBuilder::new()
        .stack_size(16 << 20)
        .thread_name(|i| format!("dwhy-scan-{i}"));
    if opts.threads > 0 {
        builder = builder.num_threads(opts.threads);
    }
    let pool = builder
        .build()
        .map_err(|e| ScanError::ThreadPool(e.to_string()))?;

    let mut root_nodes = Vec::new();
    for root in roots {
        let st = lstat(root).map_err(|source| ScanError::Root {
            path: root.clone(),
            source,
        })?;
        let name: Box<OsStr> = root.as_os_str().into();
        let id = if is_dir(&st) {
            pool.install(|| walk_dir(&shared, root.clone(), &st, 0, NO_PARENT, name))
        } else {
            let linked = st.st_nlink > 1;
            let own = if linked {
                Totals::default()
            } else {
                leaf_totals(&st)
            };
            shared.add_dev(st.st_dev, own);
            let id = shared.push_node(Node {
                parent: NO_PARENT,
                depth: 0,
                is_dir: false,
                name,
                own,
            });
            if linked {
                shared.add_link(&st, root.clone(), id);
            }
            id
        };
        root_nodes.push((root.clone(), st.st_dev, id));
    }

    let mut nodes = shared.nodes.into_inner().unwrap();
    let mut per_dev = shared.per_dev.into_inner().unwrap();
    for shard in shared.links {
        for (_, l) in shard.into_inner().unwrap() {
            let mut t = l.leaf;
            t.hardlinks_deduped = l.seen - 1;
            t.hardlink_bytes_deduped = (l.seen - 1) * l.leaf.allocated;
            nodes[l.node as usize].own += t;
            *per_dev.entry(l.dev).or_default() += t;
        }
    }

    // Subtree sums: children always come after their parent.
    let mut sums: Vec<Totals> = nodes.iter().map(|n| n.own).collect();
    for i in (0..nodes.len()).rev() {
        let p = nodes[i].parent;
        if p != NO_PARENT {
            let t = sums[i];
            sums[p as usize] += t;
        }
    }

    let mut dirs: Vec<DirRecord> = (0..nodes.len())
        .filter(|&i| nodes[i].is_dir && sums[i].allocated >= opts.min_dir_bytes)
        .map(|i| DirRecord {
            path: node_path(&nodes, i),
            depth: nodes[i].depth,
            totals: sums[i],
        })
        .collect();
    dirs.sort_by(|a, b| {
        b.totals
            .allocated
            .cmp(&a.totals.allocated)
            .then_with(|| a.path.cmp(&b.path))
    });
    let mut unreadable = shared.unreadable.into_inner().unwrap();
    unreadable.sort_by(|a, b| a.path.cmp(&b.path));
    let mut skipped_mounts = shared.skipped.into_inner().unwrap();
    skipped_mounts.sort_by(|a, b| a.path.cmp(&b.path));
    let mut errors = shared.errors.into_inner().unwrap();
    errors.sort();

    Ok(ScanResult {
        one_filesystem: opts.one_filesystem,
        min_dir_bytes: opts.min_dir_bytes,
        roots: root_nodes
            .into_iter()
            .map(|(path, dev, id)| RootResult {
                path,
                dev,
                totals: sums[id as usize],
            })
            .collect(),
        dirs,
        unreadable,
        skipped_mounts,
        per_dev,
        errors,
        error_count: shared.error_count.into_inner(),
        elapsed: start.elapsed(),
    })
}

fn node_path(nodes: &[Node], mut i: usize) -> PathBuf {
    let mut parts: Vec<&OsStr> = Vec::new();
    loop {
        parts.push(&nodes[i].name);
        match nodes[i].parent {
            NO_PARENT => break,
            p => i = p as usize,
        }
    }
    let mut path = PathBuf::new();
    for part in parts.into_iter().rev() {
        path.push(part);
    }
    path
}

/// Opens a directory without following a symlink that may have replaced it.
fn open_dir(path: &Path) -> Result<OwnedFd, Errno> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

thread_local! {
    static DIRENT_BUFFER: std::cell::RefCell<Vec<MaybeUninit<u8>>> =
        std::cell::RefCell::new(vec![MaybeUninit::uninit(); 32 << 10]);
}

/// Walks one directory and, in parallel, its subdirectories. Returns its node id.
fn walk_dir(
    sh: &Shared<'_>,
    path: PathBuf,
    st: &Stat,
    depth: u32,
    parent: u32,
    name: Box<OsStr>,
) -> u32 {
    let dev = st.st_dev;
    // Like GNU du (coreutils >= 9.2), a directory's st_size is not counted as
    // apparent size: it is filesystem-specific bookkeeping, not data.
    let mut own = Totals {
        allocated: bytes(st),
        dirs: 1,
        ..Totals::default()
    };
    // Files bind-mounted from another filesystem (only when crossing).
    let mut foreign = Totals::default();
    let mut subdirs: Vec<(PathBuf, Stat)> = Vec::new();
    let mut linked: Vec<(PathBuf, Stat)> = Vec::new();
    match open_dir(&path) {
        Err(e) => {
            if is_perm(e) {
                sh.unreadable.lock().unwrap().push(UnreadableRecord {
                    path: path.clone(),
                    dev,
                    reason: UnreadableReason::PermissionDenied,
                    entries_unknown: 0,
                    known_bytes: bytes(st),
                    owner_uid: st.st_uid,
                });
            } else if e != Errno::NOENT {
                sh.error(&path, &e.into());
            }
        }
        Ok(fd) => {
            let mut denied = 0u64;
            let mut seen = 0u64;
            // One getdents buffer per worker thread. It is only borrowed
            // while this loop runs, which makes no rayon calls, so a nested
            // walk_dir on the same thread never sees it borrowed.
            DIRENT_BUFFER.with_borrow_mut(|buf| {
                let mut dir = RawDir::new(&fd, buf);
                while let Some(ent) = dir.next() {
                    let ent = match ent {
                        Ok(e) => e,
                        Err(e) => {
                            sh.error(&path, &e.into());
                            break;
                        }
                    };
                    let fname = ent.file_name();
                    let nb = fname.to_bytes();
                    if nb == b"." || nb == b".." {
                        continue;
                    }
                    seen += 1;
                    let cst = match rustix::fs::statat(&fd, fname, AtFlags::SYMLINK_NOFOLLOW) {
                        Ok(m) => m,
                        Err(e) if is_perm(e) => {
                            denied += 1;
                            continue;
                        }
                        // Removed between readdir and stat.
                        Err(Errno::NOENT) => continue,
                        Err(e) => {
                            sh.error(&path.join(OsStr::from_bytes(nb)), &e.into());
                            continue;
                        }
                    };
                    let child_dev = cst.st_dev;
                    if is_dir(&cst) {
                        let child = path.join(OsStr::from_bytes(nb));
                        if let Some(reason) = sh.crosses_boundary(&child, child_dev, dev) {
                            sh.skip(child, dev, reason);
                        } else {
                            subdirs.push((child, cst));
                        }
                    } else if child_dev != dev {
                        // A file bind-mounted from another filesystem.
                        let child = path.join(OsStr::from_bytes(nb));
                        if let Some(reason) = sh.crosses_boundary(&child, child_dev, dev) {
                            sh.skip(child, dev, reason);
                        } else {
                            let t = leaf_totals(&cst);
                            sh.add_dev(child_dev, t);
                            foreign += t;
                        }
                    } else if cst.st_nlink > 1 {
                        linked.push((path.join(OsStr::from_bytes(nb)), cst));
                    } else {
                        own += leaf_totals(&cst);
                    }
                }
            });
            if denied > 0 {
                sh.unreadable.lock().unwrap().push(UnreadableRecord {
                    path: path.clone(),
                    dev,
                    reason: UnreadableReason::EntriesDenied,
                    entries_unknown: denied,
                    known_bytes: 0,
                    owner_uid: st.st_uid,
                });
            }
            sh.progress.entries.fetch_add(seen, Ordering::Relaxed);
        }
    }
    sh.add_dev(dev, own);
    own += foreign;
    sh.progress
        .allocated
        .fetch_add(own.allocated, Ordering::Relaxed);

    let id = sh.push_node(Node {
        parent,
        depth,
        is_dir: true,
        name,
        own,
    });
    for (p, m) in linked {
        sh.add_link(&m, p, id);
    }
    drop(path);
    subdirs.into_par_iter().for_each(|(p, m)| {
        let name: Box<OsStr> = p.file_name().unwrap_or(p.as_os_str()).into();
        walk_dir(sh, p, &m, depth + 1, id, name);
    });
    id
}
