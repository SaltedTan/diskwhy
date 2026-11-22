//! Parallel, read-only directory walk.
//!
//! * Never follows symlinks: every entry is `lstat`ed, and a symlink is
//!   counted as a symlink (its own blocks), never descended into.
//! * Stays on the root's filesystem by default (`-x`). Mount points are
//!   recorded as skipped. A btrfs subvolume that is not mounted on its own
//!   has its own `st_dev` but is part of the same filesystem, and is entered. Virtual filesystems (proc, sysfs, ...) are never
//!   entered, even when crossing filesystems.
//! * Counts each inode with more than one link once, keyed by (dev, inode).
//! * Records directories it cannot list or whose entries it cannot stat,
//!   instead of skipping them silently.
//!
//! The walk opens directories read-only (`O_NOFOLLOW`) and `fstatat`s each
//! entry relative to its directory with `AT_SYMLINK_NOFOLLOW`; it never
//! writes, and changes nothing beyond the atime a directory read may set.

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, HashSet};
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

use crate::mounts::{self, MountTable};
pub use crate::report::{SkipReason, Totals, UnreadableReason};
use crate::tree::{Markers, NO_PARENT, NodeId, ScanTree, TreeNode};

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
    /// Allocated bytes counted per device (`st_dev`).
    pub per_dev: HashMap<u64, Totals>,
    /// For each device the walk reached, the id of the mount (in the mount
    /// table the scan ran with) it was reached through. Nested btrfs
    /// subvolumes map to the mount of the subvolume holding them.
    pub dev_mounts: HashMap<u64, u32>,
    /// Ids of mounts entered at their mount point while crossing
    /// filesystems.
    pub entered_mounts: BTreeSet<u32>,
    pub errors: Vec<(PathBuf, String)>,
    pub error_count: u64,
    pub elapsed: Duration,
    /// Every directory scanned, for detectors.
    pub tree: ScanTree,
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
    prepare_roots_with(
        paths,
        one_filesystem,
        &|| MountTable::read().ok(),
        &mounts::btrfs_fsid,
    )
}

/// [`prepare_roots`] with the mount table (read only when needed) and the
/// btrfs id lookup supplied.
fn prepare_roots_with(
    paths: &[PathBuf],
    one_filesystem: bool,
    read_mounts: &dyn Fn() -> Option<MountTable>,
    btrfs_fsid: &dyn Fn(&Path, u64) -> Option<u64>,
) -> Result<Vec<PathBuf>, ScanError> {
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
    let mut table: Option<Option<MountTable>> = None;
    for (p, dev) in out {
        let covered = kept.iter().any(|(k, kdev)| {
            p.starts_with(k)
                && (!one_filesystem
                    || *kdev == dev
                    || table
                        .get_or_insert_with(read_mounts)
                        .as_ref()
                        .is_some_and(|t| in_nested_subvolume(t, k, *kdev, &p, dev, btrfs_fsid)))
        });
        if !covered {
            kept.push((p, dev));
        }
    }
    Ok(kept.into_iter().map(|(p, _)| p).collect())
}

/// Whether a one-filesystem walk from `outer` (on `outer_dev`) reaches
/// `inner` (on another device below it): `inner` is in a btrfs subvolume of
/// the same filesystem, and no mount point lies below `outer` on the way.
fn in_nested_subvolume(
    mounts: &MountTable,
    outer: &Path,
    outer_dev: u64,
    inner: &Path,
    inner_dev: u64,
    btrfs_fsid: &dyn Fn(&Path, u64) -> Option<u64>,
) -> bool {
    let on_btrfs = mounts.for_path(inner).is_some_and(|m| m.fstype == "btrfs");
    let mount_between = mounts.mounts.iter().any(|m| {
        m.mount_point != outer
            && m.mount_point.starts_with(outer)
            && inner.starts_with(&m.mount_point)
    });
    on_btrfs
        && !mount_between
        && match (btrfs_fsid(outer, outer_dev), btrfs_fsid(inner, inner_dev)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
}

pub fn absolute_nofollow(p: &Path) -> io::Result<PathBuf> {
    let abs = std::path::absolute(p)?;
    match (abs.parent(), abs.file_name()) {
        (Some(parent), Some(name)) => Ok(fs::canonicalize(parent)?.join(name)),
        // "/" or a path ending in ".." — canonicalizing is safe: there is no
        // final symlink component to avoid following.
        _ => fs::canonicalize(&abs),
    }
}

const LINK_SHARDS: usize = 64;

/// An inode with more than one link. It is counted once and attributed to
/// its lexicographically smallest path, so per-directory sizes do not depend
/// on which thread reached a link first.
struct Link {
    path: PathBuf,
    node: u32,
    dev: u64,
    leaf: Totals,
    nlink: u64,
    /// The node of every link seen.
    locs: Vec<NodeId>,
}

/// Looks up the btrfs filesystem id of a path on a given device
/// ([`mounts::btrfs_fsid`] outside tests).
type BtrfsFsid<'a> = &'a (dyn Fn(&Path, u64) -> Option<u64> + Sync);

struct Shared<'a> {
    opts: &'a ScanOptions,
    mounts: &'a MountTable,
    mount_points: HashSet<&'a Path>,
    btrfs_fsid: BtrfsFsid<'a>,
    /// btrfs filesystem id by device, for devices found to be on btrfs.
    fsids: Mutex<HashMap<u64, u64>>,
    dev_mounts: Mutex<HashMap<u64, u32>>,
    entered_mounts: Mutex<BTreeSet<u32>>,
    nodes: Mutex<Vec<TreeNode>>,
    links: Vec<Mutex<HashMap<(u64, u64), Link>>>,
    unreadable: Mutex<Vec<UnreadableRecord>>,
    skipped: Mutex<Vec<SkippedRecord>>,
    per_dev: Mutex<HashMap<u64, Totals>>,
    errors: Mutex<Vec<(PathBuf, String)>>,
    error_count: AtomicU64,
    progress: &'a Progress,
}

impl<'a> Shared<'a> {
    fn new(
        opts: &'a ScanOptions,
        mounts: &'a MountTable,
        progress: &'a Progress,
        btrfs_fsid: BtrfsFsid<'a>,
    ) -> Self {
        Shared {
            opts,
            mounts,
            mount_points: mounts
                .mounts
                .iter()
                .map(|m| m.mount_point.as_path())
                .collect(),
            btrfs_fsid,
            fsids: Mutex::default(),
            dev_mounts: Mutex::default(),
            entered_mounts: Mutex::default(),
            nodes: Mutex::default(),
            links: (0..LINK_SHARDS).map(|_| Mutex::default()).collect(),
            unreadable: Mutex::default(),
            skipped: Mutex::default(),
            per_dev: Mutex::default(),
            errors: Mutex::default(),
            error_count: AtomicU64::new(0),
            progress,
        }
    }

    fn push_node(&self, node: TreeNode) -> NodeId {
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
                let mut locs = Vec::with_capacity(2);
                locs.push(node);
                v.insert(Link {
                    path,
                    node,
                    dev: key.0,
                    leaf: leaf_totals(st),
                    nlink: nlink(st),
                    locs,
                });
            }
            Entry::Occupied(mut o) => {
                let l = o.get_mut();
                l.locs.push(node);
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

    /// Records the mount through which the walk reached device `dev` at
    /// `path` (a root, or an entry entered on a new device).
    fn note_dev(&self, path: &Path, dev: u64) {
        let mut map = self.dev_mounts.lock().unwrap();
        if let Entry::Vacant(v) = map.entry(dev)
            && let Some(m) = self.mounts.for_path(path)
        {
            v.insert(m.id);
        }
    }

    /// Records that the walk entered `path` (on device `dev`, not its
    /// parent's), which [`Self::crosses_boundary`] let it enter.
    fn note_entered(&self, path: &Path, dev: u64) {
        if self.mount_points.contains(path)
            && let Some(m) = self.mounts.at(path)
        {
            self.entered_mounts.lock().unwrap().insert(m.id);
        }
        self.note_dev(path, dev);
    }

    /// The btrfs filesystem id of device `dev`, looked up at `path`.
    fn fsid(&self, path: &Path, dev: u64) -> Option<u64> {
        if let Some(&id) = self.fsids.lock().unwrap().get(&dev) {
            return Some(id);
        }
        let id = (self.btrfs_fsid)(path, dev)?;
        self.fsids.lock().unwrap().insert(dev, id);
        Some(id)
    }

    /// Whether `path` (on `dev`), inside a directory on `parent_dev`, is a
    /// btrfs subvolume of the same filesystem that is not mounted on its own.
    fn nested_subvolume(&self, path: &Path, dev: u64, parent_dev: u64) -> bool {
        if self.mount_points.contains(path)
            || !self
                .mounts
                .for_path(path)
                .is_some_and(|m| m.fstype == "btrfs")
        {
            return false;
        }
        let Some(parent) = path.parent() else {
            return false;
        };
        match (self.fsid(path, dev), self.fsid(parent, parent_dev)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
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
        // A btrfs subvolume has its own st_dev but is the same filesystem.
        // Anything else on another device that the mount table does not
        // list (mounted after it was read) still counts as a boundary.
        if other_dev && self.nested_subvolume(path, dev, parent_dev) {
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

/// mtime in seconds; `st_mtime` is narrower than i64 on 32-bit targets.
#[allow(clippy::unnecessary_cast)]
fn mtime(st: &Stat) -> i64 {
    st.st_mtime as i64
}

/// Link count; `st_nlink` is narrower than u64 on some targets.
#[allow(clippy::unnecessary_cast)]
fn nlink(st: &Stat) -> u64 {
    st.st_nlink as u64
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
    let shared = Shared::new(opts, mounts, progress, &mounts::btrfs_fsid);

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
        shared.note_dev(root, st.st_dev);
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
            let id = shared.push_node(TreeNode {
                parent: NO_PARENT,
                depth: 0,
                is_dir: false,
                name,
                own,
                directory_allocated: 0,
                has_direct_files: false,
                total: Totals::default(),
                markers: Markers::empty(),
                newest_mtime: mtime(&st),
                shared: 0,
                dev: st.st_dev,
                ino: st.st_ino,
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
    // Per-node change in `shared`: a linked inode is shared by its attributed
    // node and every ancestor strictly below the lowest common ancestor of
    // all its links, or every ancestor when some link was not scanned.
    let mut shared_delta = vec![0i64; nodes.len()];
    for shard in shared.links {
        for (_, l) in shard.into_inner().unwrap() {
            let seen = l.locs.len() as u64;
            let mut t = l.leaf;
            t.hardlinks_deduped = seen - 1;
            t.hardlink_bytes_deduped = (seen - 1) * l.leaf.allocated;
            nodes[l.node as usize].own += t;
            *per_dev.entry(l.dev).or_default() += t;
            let b = l.leaf.allocated as i64;
            shared_delta[l.node as usize] += b;
            if seen >= l.nlink
                && let Some(lca) = l
                    .locs
                    .iter()
                    .try_fold(l.node, |a, &b| common_ancestor(&nodes, a, b))
            {
                shared_delta[lca as usize] -= b;
            }
        }
    }

    // Subtree sums and newest mtimes: children always come after their parent.
    for n in nodes.iter_mut() {
        n.total = n.own;
    }
    for i in (0..nodes.len()).rev() {
        nodes[i].shared = shared_delta[i] as u64;
        let p = nodes[i].parent;
        if p != NO_PARENT {
            let (t, m) = (nodes[i].total, nodes[i].newest_mtime);
            shared_delta[p as usize] += shared_delta[i];
            let parent = &mut nodes[p as usize];
            parent.total += t;
            parent.newest_mtime = parent.newest_mtime.max(m);
        }
    }
    let tree = ScanTree::new(nodes, root_nodes.iter().map(|r| r.2).collect());

    let mut dirs: Vec<DirRecord> = tree
        .ids()
        .filter(|&i| {
            let n = tree.node(i);
            n.is_dir && n.total.allocated >= opts.min_dir_bytes
        })
        .map(|i| DirRecord {
            path: tree.path(i),
            depth: tree.node(i).depth,
            totals: tree.node(i).total,
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
    let dev_mounts = shared.dev_mounts.into_inner().unwrap();
    let entered_mounts = shared.entered_mounts.into_inner().unwrap();

    Ok(ScanResult {
        one_filesystem: opts.one_filesystem,
        min_dir_bytes: opts.min_dir_bytes,
        roots: root_nodes
            .into_iter()
            .map(|(path, dev, id)| RootResult {
                path,
                dev,
                totals: tree.node(id).total,
            })
            .collect(),
        dirs,
        unreadable,
        skipped_mounts,
        per_dev,
        dev_mounts,
        entered_mounts,
        errors,
        error_count: shared.error_count.into_inner(),
        elapsed: start.elapsed(),
        tree,
    })
}

/// The lowest node that is `a` or an ancestor of it and `b` or an ancestor of
/// it; `None` when they lie under different roots.
fn common_ancestor(nodes: &[TreeNode], mut a: NodeId, mut b: NodeId) -> Option<NodeId> {
    while nodes[a as usize].depth > nodes[b as usize].depth {
        a = nodes[a as usize].parent;
    }
    while nodes[b as usize].depth > nodes[a as usize].depth {
        b = nodes[b as usize].parent;
    }
    while a != b {
        a = nodes[a as usize].parent;
        b = nodes[b as usize].parent;
        if a == NO_PARENT || b == NO_PARENT {
            return None;
        }
    }
    Some(a)
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
    let directory_allocated = bytes(st);
    // Like GNU du (coreutils >= 9.2), a directory's st_size is not counted as
    // apparent size: it is filesystem-specific bookkeeping, not data.
    let mut own = Totals {
        allocated: directory_allocated,
        dirs: 1,
        ..Totals::default()
    };
    let mut markers = Markers::empty();
    let mut newest_mtime = mtime(st);
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
                    known_bytes: directory_allocated,
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
                    let ft = FileType::from_raw_mode(cst.st_mode);
                    markers.insert(Markers::for_entry(
                        nb,
                        ft == FileType::RegularFile,
                        ft == FileType::Directory,
                    ));
                    if ft != FileType::Directory {
                        newest_mtime = newest_mtime.max(mtime(&cst));
                    }
                    if is_dir(&cst) {
                        let child = path.join(OsStr::from_bytes(nb));
                        if let Some(reason) = sh.crosses_boundary(&child, child_dev, dev) {
                            sh.skip(child, dev, reason);
                        } else {
                            if child_dev != dev {
                                sh.note_entered(&child, child_dev);
                            }
                            subdirs.push((child, cst));
                        }
                    } else if child_dev != dev {
                        // A file bind-mounted from another filesystem.
                        let child = path.join(OsStr::from_bytes(nb));
                        if let Some(reason) = sh.crosses_boundary(&child, child_dev, dev) {
                            sh.skip(child, dev, reason);
                        } else {
                            sh.note_entered(&child, child_dev);
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
    let has_direct_files = own.files > 0 || own.symlinks > 0 || own.other > 0 || !linked.is_empty();
    sh.progress
        .allocated
        .fetch_add(own.allocated, Ordering::Relaxed);

    let id = sh.push_node(TreeNode {
        parent,
        depth,
        is_dir: true,
        name,
        own,
        directory_allocated,
        has_direct_files,
        total: Totals::default(),
        markers,
        newest_mtime,
        shared: 0,
        dev,
        ino: st.st_ino,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A btrfs filesystem at /mnt/b with a subvolume also mounted on its own
    /// at /mnt/b/mounted, and an ext4 filesystem at /mnt/e.
    const TABLE: &str = "\
1 0 0:27 / /mnt/b rw - btrfs /dev/b rw,subvol=/
2 1 0:27 /mounted /mnt/b/mounted rw - btrfs /dev/b rw,subvol=/mounted
3 0 259:7 / /mnt/e rw - ext4 /dev/e rw
";

    /// Devices 28, 31 and 32 are subvolumes of btrfs filesystem 1, device 40
    /// is on btrfs filesystem 2. 50 and 51 claim filesystem 1 too, but the
    /// mount table says they are on ext4.
    fn fsid(_: &Path, dev: u64) -> Option<u64> {
        match dev {
            28 | 31 | 32 | 50 | 51 => Some(1),
            40 => Some(2),
            _ => None,
        }
    }

    fn check(one_filesystem: bool, path: &str, dev: u64, parent_dev: u64) -> Option<SkipReason> {
        let opts = ScanOptions {
            one_filesystem,
            ..ScanOptions::default()
        };
        let mounts = MountTable::parse(TABLE);
        let progress = Progress::default();
        let sh = Shared::new(&opts, &mounts, &progress, &fsid);
        sh.crosses_boundary(Path::new(path), dev, parent_dev)
    }

    #[test]
    fn nested_btrfs_subvolume_is_entered_on_one_filesystem() {
        assert_eq!(check(true, "/mnt/b/sub", 31, 28), None);
        assert_eq!(check(false, "/mnt/b/sub", 31, 28), None);
    }

    #[test]
    fn mounted_btrfs_subvolume_is_a_boundary() {
        assert_eq!(
            check(true, "/mnt/b/mounted", 32, 28),
            Some(SkipReason::OtherFilesystem)
        );
        assert_eq!(check(false, "/mnt/b/mounted", 32, 28), None);
    }

    #[test]
    fn other_btrfs_filesystem_is_a_boundary() {
        assert_eq!(
            check(true, "/mnt/b/other", 40, 28),
            Some(SkipReason::OtherFilesystem)
        );
        // Unknown filesystem id: fail safe.
        assert_eq!(
            check(true, "/mnt/b/gone", 99, 28),
            Some(SkipReason::OtherFilesystem)
        );
    }

    #[test]
    fn unlisted_device_change_off_btrfs_is_a_boundary() {
        assert_eq!(
            check(true, "/mnt/e/x", 50, 51),
            Some(SkipReason::OtherFilesystem)
        );
    }

    #[test]
    fn btrfs_ids_are_looked_up_once_per_device() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        let counting = |p: &Path, dev: u64| {
            CALLS.fetch_add(1, Ordering::Relaxed);
            fsid(p, dev)
        };
        let opts = ScanOptions::default();
        let mounts = MountTable::parse(TABLE);
        let progress = Progress::default();
        let sh = Shared::new(&opts, &mounts, &progress, &counting);
        assert_eq!(sh.crosses_boundary(Path::new("/mnt/b/a"), 31, 28), None);
        assert_eq!(sh.crosses_boundary(Path::new("/mnt/b/a/b"), 32, 31), None);
        assert_eq!(sh.crosses_boundary(Path::new("/mnt/b/c"), 31, 28), None);
        assert_eq!(CALLS.load(Ordering::Relaxed), 3, "28, 31 and 32 once each");
    }

    #[test]
    fn nested_root_is_covered_only_inside_an_unmounted_subvolume() {
        let t = MountTable::parse(TABLE);
        let covered = |inner: &str, dev: u64| {
            in_nested_subvolume(&t, Path::new("/mnt/b"), 28, Path::new(inner), dev, &fsid)
        };
        assert!(covered("/mnt/b/sub/x", 31));
        // The walk of /mnt/b stops at the mount point /mnt/b/mounted.
        assert!(!covered("/mnt/b/mounted", 32));
        assert!(!covered("/mnt/b/mounted/x", 32));
        assert!(!covered("/mnt/b/other", 40));
        assert!(!in_nested_subvolume(
            &t,
            Path::new("/mnt/e"),
            51,
            Path::new("/mnt/e/x"),
            50,
            &fsid
        ));
    }
}
