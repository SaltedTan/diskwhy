//! The directory tree a scan leaves behind, for detectors.
//!
//! One node per directory (and per non-directory root). Each node knows its
//! own bytes, its subtree's bytes, the newest mtime in its subtree, and which
//! well-known marker files it directly contains. Non-directory entries are
//! not kept, so the tree costs memory per directory, not per file.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::report::Totals;

/// Well-known entries recorded per directory during the walk, so detectors
/// can recognise things without a second walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Markers(u16);

impl Markers {
    /// Regular file `CACHEDIR.TAG` (<https://bford.info/cachedir/>).
    pub const CACHEDIR_TAG: Markers = Markers(1);
    /// Regular file `Cargo.toml`.
    pub const CARGO_TOML: Markers = Markers(1 << 1);
    /// Regular file `package.json`.
    pub const PACKAGE_JSON: Markers = Markers(1 << 2);
    /// Regular file `pyvenv.cfg`.
    pub const PYVENV_CFG: Markers = Markers(1 << 3);
    /// `.git`, a directory (repository) or a regular file (worktree or submodule).
    pub const DOT_GIT: Markers = Markers(1 << 4);
    /// Regular file `.rustc_info.json`, which cargo writes into a target dir.
    pub const RUSTC_INFO: Markers = Markers(1 << 5);
    /// Regular file `package-lock.json` or `npm-shrinkwrap.json`.
    pub const NPM_LOCK: Markers = Markers(1 << 6);
    /// Regular file `pnpm-lock.yaml`.
    pub const PNPM_LOCK: Markers = Markers(1 << 7);
    /// Regular file `yarn.lock`.
    pub const YARN_LOCK: Markers = Markers(1 << 8);
    /// Regular file `bun.lock` or `bun.lockb`.
    pub const BUN_LOCK: Markers = Markers(1 << 9);
    /// Regular file `pnpm-workspace.yaml`.
    pub const PNPM_WORKSPACE: Markers = Markers(1 << 10);
    /// Regular file `.dwhy-scratch`: the directory is a scratch location.
    pub const SCRATCH: Markers = Markers(1 << 11);
    /// Regular file pinning a tool version: `rust-toolchain.toml`,
    /// `rust-toolchain`, `.python-version`, `.nvmrc` or `.node-version`.
    pub const TOOL_PIN: Markers = Markers(1 << 12);
    /// Regular file `HEAD`, as in a git directory (bare repository or
    /// separate git dir).
    pub const GIT_HEAD: Markers = Markers(1 << 13);

    pub const fn empty() -> Markers {
        Markers(0)
    }

    pub fn contains(self, other: Markers) -> bool {
        self.0 & other.0 == other.0
    }

    /// True if any marker in `other` is present.
    pub fn intersects(self, other: Markers) -> bool {
        self.0 & other.0 != 0
    }

    /// The union of two marker sets.
    pub const fn union(self, other: Markers) -> Markers {
        Markers(self.0 | other.0)
    }

    pub fn insert(&mut self, other: Markers) {
        self.0 |= other.0;
    }

    /// The marker for a directory entry, if it is one. `is_file` and `is_dir`
    /// describe the entry itself (never a symlink target).
    pub fn for_entry(name: &[u8], is_file: bool, is_dir: bool) -> Markers {
        match name {
            b"CACHEDIR.TAG" if is_file => Markers::CACHEDIR_TAG,
            b"Cargo.toml" if is_file => Markers::CARGO_TOML,
            b"package.json" if is_file => Markers::PACKAGE_JSON,
            b"pyvenv.cfg" if is_file => Markers::PYVENV_CFG,
            b".git" if is_file || is_dir => Markers::DOT_GIT,
            b".rustc_info.json" if is_file => Markers::RUSTC_INFO,
            b"package-lock.json" | b"npm-shrinkwrap.json" if is_file => Markers::NPM_LOCK,
            b"pnpm-lock.yaml" if is_file => Markers::PNPM_LOCK,
            b"yarn.lock" if is_file => Markers::YARN_LOCK,
            b"bun.lock" | b"bun.lockb" if is_file => Markers::BUN_LOCK,
            b"pnpm-workspace.yaml" if is_file => Markers::PNPM_WORKSPACE,
            b".dwhy-scratch" if is_file => Markers::SCRATCH,
            b"HEAD" if is_file => Markers::GIT_HEAD,
            b"rust-toolchain.toml"
            | b"rust-toolchain"
            | b".python-version"
            | b".nvmrc"
            | b".node-version"
                if is_file =>
            {
                Markers::TOOL_PIN
            }
            _ => Markers::empty(),
        }
    }
}

pub type NodeId = u32;
pub(crate) const NO_PARENT: NodeId = NodeId::MAX;

/// A node's subtree totals, stored compactly. Byte counts are exact.
/// Entry counts saturate at `u32::MAX` (over 4 billion entries in one
/// subtree); [`crate::scan::RootResult::totals`] keeps exact counts per root.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeTotals {
    pub allocated: u64,
    pub apparent: u64,
    pub hardlink_bytes_deduped: u64,
    pub files: u32,
    pub dirs: u32,
    pub symlinks: u32,
    pub other: u32,
    pub hardlinks_deduped: u32,
}

impl NodeTotals {
    /// The same figures as a [`Totals`].
    pub fn totals(&self) -> Totals {
        Totals {
            allocated: self.allocated,
            apparent: self.apparent,
            files: self.files.into(),
            dirs: self.dirs.into(),
            symlinks: self.symlinks.into(),
            other: self.other.into(),
            hardlinks_deduped: self.hardlinks_deduped.into(),
            hardlink_bytes_deduped: self.hardlink_bytes_deduped,
        }
    }

    pub(crate) fn from_totals(t: &Totals) -> NodeTotals {
        let c = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
        NodeTotals {
            allocated: t.allocated,
            apparent: t.apparent,
            hardlink_bytes_deduped: t.hardlink_bytes_deduped,
            files: c(t.files),
            dirs: c(t.dirs),
            symlinks: c(t.symlinks),
            other: c(t.other),
            hardlinks_deduped: c(t.hardlinks_deduped),
        }
    }

    /// Adds `o`: bytes as [`Totals`] does, counts saturating.
    pub(crate) fn add(&mut self, o: &NodeTotals) {
        self.allocated += o.allocated;
        self.apparent += o.apparent;
        self.hardlink_bytes_deduped += o.hardlink_bytes_deduped;
        self.files = self.files.saturating_add(o.files);
        self.dirs = self.dirs.saturating_add(o.dirs);
        self.symlinks = self.symlinks.saturating_add(o.symlinks);
        self.other = self.other.saturating_add(o.other);
        self.hardlinks_deduped = self.hardlinks_deduped.saturating_add(o.hardlinks_deduped);
    }
}

/// One directory (or non-directory root). Kept small: a big scan holds one
/// per directory, and its name lives in the [`ScanTree`]'s name arena.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// `st_dev` and `st_ino` of the directory (or non-directory root) the
    /// walk measured. Roots use the initial `lstat`. Subdirectories use
    /// the parent's `fstatat` result, also used to size the directory itself.
    pub dev: u64,
    pub ino: u64,
    /// Newest mtime (seconds since the epoch) of the directory and anything in it, recursively.
    pub newest_mtime: i64,
    /// Allocated bytes in `total` of hardlinked files that also have a link
    /// outside this subtree (or outside the scan), so removing it would not
    /// free them.
    pub shared: u64,
    /// Allocated bytes of the non-directory entries directly in this
    /// directory (hardlinked inodes included where they are attributed to
    /// it), not counting the directory inode itself. For a non-directory
    /// root, the root itself.
    pub direct_allocated: u64,
    /// Apparent bytes of the same entries.
    pub direct_apparent: u64,
    /// This node and all its descendants: the directory inode, its direct
    /// entries, and every subdirectory's total.
    pub total: NodeTotals,
    pub(crate) parent: NodeId,
    pub depth: u32,
    /// Byte range of the name in [`ScanTree`]'s name arena.
    pub(crate) name_start: u32,
    pub(crate) name_len: u32,
    pub markers: Markers,
    pub is_dir: bool,
    pub has_direct_files: bool,
}

impl TreeNode {
    /// What removing this subtree is expected to free: `total.allocated`
    /// minus `shared`.
    pub fn freeable(&self) -> u64 {
        self.total.allocated.saturating_sub(self.shared)
    }
}

/// Appends `name` to a name arena and returns its `(start, len)`.
///
/// # Panics
///
/// If the arena would grow past 4 GiB, which takes hundreds of millions of
/// names (and far more memory for the nodes holding them).
pub(crate) fn push_name(arena: &mut Vec<u8>, name: &[u8]) -> (u32, u32) {
    let fits = |n: usize| u32::try_from(n).expect("name arena exceeds 4 GiB");
    let start = fits(arena.len());
    let len = fits(name.len());
    fits(arena.len() + name.len());
    arena.extend_from_slice(name);
    (start, len)
}

#[derive(Debug, Clone, Default)]
pub struct ScanTree {
    nodes: Vec<TreeNode>,
    /// Every node's name, back to back; see [`TreeNode::name_start`].
    names: Vec<u8>,
    /// Children of node `i` are `child_ids[child_start[i]..child_start[i + 1]]`, sorted by name.
    child_start: Vec<u32>,
    child_ids: Vec<NodeId>,
    roots: Vec<NodeId>,
}

/// The name of `node` in `names`.
pub(crate) fn name_in<'a>(names: &'a [u8], node: &TreeNode) -> &'a OsStr {
    let start = node.name_start as usize;
    OsStr::from_bytes(&names[start..start + node.name_len as usize])
}

impl ScanTree {
    /// Builds the child index. `nodes` must have every child after its
    /// parent; their names are in `names`.
    pub(crate) fn new(nodes: Vec<TreeNode>, names: Vec<u8>, roots: Vec<NodeId>) -> ScanTree {
        let n = nodes.len();
        let mut counts = vec![0u32; n + 1];
        for node in &nodes {
            if node.parent != NO_PARENT {
                counts[node.parent as usize + 1] += 1;
            }
        }
        for i in 0..n {
            counts[i + 1] += counts[i];
        }
        let child_start = counts.clone();
        let mut fill = counts;
        let mut child_ids = vec![0; child_start[n] as usize];
        for (i, node) in nodes.iter().enumerate() {
            if node.parent != NO_PARENT {
                let slot = &mut fill[node.parent as usize];
                child_ids[*slot as usize] = i as NodeId;
                *slot += 1;
            }
        }
        drop(fill);
        for i in 0..n {
            let (a, b) = (child_start[i] as usize, child_start[i + 1] as usize);
            child_ids[a..b].sort_by(|x, y| {
                name_in(&names, &nodes[*x as usize]).cmp(name_in(&names, &nodes[*y as usize]))
            });
        }
        ScanTree {
            nodes,
            names,
            child_start,
            child_ids,
            roots,
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Root node ids, in scan order.
    pub fn roots(&self) -> &[NodeId] {
        &self.roots
    }

    pub fn node(&self, id: NodeId) -> &TreeNode {
        &self.nodes[id as usize]
    }

    /// All node ids. Parents always come before their children.
    pub fn ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        0..self.nodes.len() as NodeId
    }

    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        match self.nodes[id as usize].parent {
            NO_PARENT => None,
            p => Some(p),
        }
    }

    /// Child directories, sorted by name.
    pub fn children(&self, id: NodeId) -> &[NodeId] {
        let i = id as usize;
        &self.child_ids[self.child_start[i] as usize..self.child_start[i + 1] as usize]
    }

    /// Last path component (the full path for a root).
    pub fn name(&self, id: NodeId) -> &OsStr {
        name_in(&self.names, &self.nodes[id as usize])
    }

    /// Allocated bytes of the directory inode itself (0 for a non-directory
    /// root): `total.allocated` less the direct entries and the subdirectories.
    pub fn directory_allocated(&self, id: NodeId) -> u64 {
        let n = self.node(id);
        let kids: u64 = self
            .children(id)
            .iter()
            .map(|&c| self.node(c).total.allocated)
            .sum();
        n.total.allocated - n.direct_allocated - kids
    }

    pub fn child_named(&self, id: NodeId, name: &str) -> Option<NodeId> {
        let kids = self.children(id);
        kids.binary_search_by(|k| self.name(*k).cmp(OsStr::new(name)))
            .ok()
            .map(|i| kids[i])
    }

    pub fn path(&self, mut id: NodeId) -> PathBuf {
        let mut parts: Vec<&OsStr> = Vec::new();
        loop {
            parts.push(self.name(id));
            match self.parent(id) {
                None => break,
                Some(p) => id = p,
            }
        }
        let mut path = PathBuf::new();
        for part in parts.into_iter().rev() {
            path.push(part);
        }
        path
    }

    /// The node for an absolute directory path inside one of the roots.
    pub fn find(&self, path: &Path) -> Option<NodeId> {
        for &root in &self.roots {
            let Ok(rest) = path.strip_prefix(Path::new(self.name(root))) else {
                continue;
            };
            let mut id = root;
            let mut ok = true;
            for c in rest.components() {
                let Component::Normal(name) = c else {
                    ok = false;
                    break;
                };
                let kids = self.children(id);
                match kids.binary_search_by(|k| self.name(*k).cmp(name)) {
                    Ok(i) => id = kids[i],
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return Some(id);
            }
        }
        None
    }

    /// True if `id` is `ancestor` or lies below it.
    pub fn is_within(&self, mut id: NodeId, ancestor: NodeId) -> bool {
        loop {
            if id == ancestor {
                return true;
            }
            match self.parent(id) {
                Some(p) => id = p,
                None => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(names: &mut Vec<u8>, parent: NodeId, name: &str, own: u64) -> TreeNode {
        let (name_start, name_len) = push_name(names, name.as_bytes());
        TreeNode {
            parent,
            depth: 0,
            is_dir: true,
            name_start,
            name_len,
            direct_allocated: 0,
            direct_apparent: 0,
            has_direct_files: false,
            total: NodeTotals {
                allocated: own,
                ..NodeTotals::default()
            },
            markers: Markers::empty(),
            newest_mtime: 0,
            shared: 0,
            dev: 0,
            ino: 0,
        }
    }

    #[test]
    fn navigation() {
        // /r, /r/b, /r/a, /r/a/x
        let mut names = Vec::new();
        let nodes = vec![
            node(&mut names, NO_PARENT, "/r", 1),
            node(&mut names, 0, "b", 1),
            node(&mut names, 0, "a", 1),
            node(&mut names, 2, "x", 1),
        ];
        let t = ScanTree::new(nodes, names, vec![0]);
        assert_eq!(t.name(0), OsStr::new("/r"));
        assert_eq!(t.name(3), OsStr::new("x"));
        assert_eq!(t.children(0), &[2, 1], "sorted by name");
        assert_eq!(t.children(3), &[] as &[NodeId]);
        assert_eq!(t.path(3), PathBuf::from("/r/a/x"));
        assert_eq!(t.find(Path::new("/r/a/x")), Some(3));
        assert_eq!(t.find(Path::new("/r")), Some(0));
        assert_eq!(t.find(Path::new("/r/zz")), None);
        assert_eq!(t.find(Path::new("/other")), None);
        assert_eq!(t.child_named(0, "b"), Some(1));
        assert!(t.is_within(3, 0) && t.is_within(3, 2) && !t.is_within(3, 1));
        assert_eq!(t.parent(0), None);
    }

    #[test]
    fn node_stays_small() {
        // One per directory: a few million on a big disk.
        assert!(
            std::mem::size_of::<TreeNode>() <= 128,
            "{}",
            std::mem::size_of::<TreeNode>()
        );
    }

    #[test]
    fn node_totals_round_trip_and_saturate() {
        let t = Totals {
            allocated: 1 << 40,
            apparent: 3 << 33,
            files: 7,
            dirs: 2,
            symlinks: 1,
            other: 4,
            hardlinks_deduped: 5,
            hardlink_bytes_deduped: 1 << 35,
        };
        assert_eq!(NodeTotals::from_totals(&t).totals(), t);
        let mut big = NodeTotals::from_totals(&Totals {
            files: u64::from(u32::MAX) + 9,
            ..Totals::default()
        });
        assert_eq!(big.files, u32::MAX);
        big.add(&NodeTotals::from_totals(&t));
        assert_eq!(big.files, u32::MAX);
        assert_eq!(big.allocated, 1 << 40);
    }

    #[test]
    fn markers() {
        let mut m = Markers::empty();
        m.insert(Markers::for_entry(b"Cargo.toml", true, false));
        m.insert(Markers::for_entry(b"CACHEDIR.TAG", false, false)); // a symlink: ignored
        m.insert(Markers::for_entry(b".git", false, true));
        m.insert(Markers::for_entry(b".dwhy-scratch", false, true)); // a directory: ignored
        assert!(m.contains(Markers::CARGO_TOML));
        assert!(m.contains(Markers::DOT_GIT));
        assert!(!m.contains(Markers::CACHEDIR_TAG));
        assert!(!m.contains(Markers::SCRATCH));
        assert!(Markers::for_entry(b".dwhy-scratch", true, false).contains(Markers::SCRATCH));
    }
}
