//! The directory tree a scan leaves behind, for detectors.
//!
//! One node per directory (and per non-directory root). Each node knows its
//! own bytes, its subtree's bytes, the newest mtime in its subtree, and which
//! well-known marker files it directly contains. Non-directory entries are
//! not kept, so the tree costs memory per directory, not per file.

use std::ffi::OsStr;
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

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub(crate) parent: NodeId,
    pub depth: u32,
    pub is_dir: bool,
    /// Last path component; the full path for a root.
    pub(crate) name: Box<OsStr>,
    /// The directory inode and its non-directory entries (hardlinked inodes
    /// included where they are attributed to this directory).
    pub own: Totals,
    /// `own` plus all descendants.
    pub total: Totals,
    pub markers: Markers,
    /// Newest mtime (seconds since the epoch) of the directory and anything in it, recursively.
    pub newest_mtime: i64,
    /// Allocated bytes in `total` of hardlinked files that also have a link
    /// outside this subtree (or outside the scan), so removing it would not
    /// free them.
    pub shared: u64,
}

impl TreeNode {
    /// What removing this subtree is expected to free: `total.allocated`
    /// minus `shared`.
    pub fn freeable(&self) -> u64 {
        self.total.allocated.saturating_sub(self.shared)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanTree {
    nodes: Vec<TreeNode>,
    /// Children of node `i` are `child_ids[child_start[i]..child_start[i + 1]]`, sorted by name.
    child_start: Vec<u32>,
    child_ids: Vec<NodeId>,
    roots: Vec<NodeId>,
}

impl ScanTree {
    /// Builds the child index. `nodes` must have every child after its parent.
    pub(crate) fn new(nodes: Vec<TreeNode>, roots: Vec<NodeId>) -> ScanTree {
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
        for i in 0..n {
            let (a, b) = (child_start[i] as usize, child_start[i + 1] as usize);
            child_ids[a..b].sort_by(|x, y| nodes[*x as usize].name.cmp(&nodes[*y as usize].name));
        }
        ScanTree {
            nodes,
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
        &self.nodes[id as usize].name
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

    fn node(parent: NodeId, name: &str, own: u64) -> TreeNode {
        TreeNode {
            parent,
            depth: 0,
            is_dir: true,
            name: OsStr::new(name).into(),
            own: Totals {
                allocated: own,
                ..Totals::default()
            },
            total: Totals::default(),
            markers: Markers::empty(),
            newest_mtime: 0,
            shared: 0,
        }
    }

    #[test]
    fn navigation() {
        // /r, /r/b, /r/a, /r/a/x
        let nodes = vec![
            node(NO_PARENT, "/r", 1),
            node(0, "b", 1),
            node(0, "a", 1),
            node(2, "x", 1),
        ];
        let t = ScanTree::new(nodes, vec![0]);
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
