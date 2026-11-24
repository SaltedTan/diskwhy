//! `apt-cache`: what `apt-get clean` removes from apt's cache directory,
//! `/var/cache/apt`. Root only (the catalog's `Needs::RootAnd`).
//!
//! The action pins the measured directory and the names in it
//! (`-o Dir::Cache=<dir> -o Dir::Cache::archives=archives/ -o
//! Dir::Cache::pkgcache=pkgcache.bin -o Dir::Cache::srcpkgcache=srcpkgcache.bin`),
//! so a local apt configuration cannot point the clean somewhere else. Run
//! on temp-dir layouts, apt 3.2's `apt-get clean` removed (unlinked, never
//! following a symlink):
//!
//! - every entry directly in `archives/` but `lock`, `partial`, `auxfiles`
//!   and `lost+found` (hidden names and names that are not `.deb` included);
//!   a subdirectory only gets a warning and stays, with all below it;
//! - every entry directly in `archives/partial/` but those same names;
//! - `pkgcache.bin` and `srcpkgcache.bin`, and `pkgcache.bin.<suffix>` and
//!   `srcpkgcache.bin.<suffix>` (left by an interrupted cache build) when
//!   the name is made only of ASCII letters, digits, `_`, `-` and `.` and
//!   does not end in `.`, the rule apt's `GetListOfFilesInDir` applies;
//!   anything else in the directory stays;
//! - `partial/` entries under apt's lists directory (`Dir::State::lists`,
//!   `/var/lib/apt/lists/partial/`), outside the finding: interrupted index
//!   downloads that `apt update` fetches again. They are not counted.
//!
//! It opens `archives/` and `archives/partial/` following symlinks, so a
//! symlink there would make it empty another directory; it fails, removing
//! nothing, when `archives/` cannot be read or `partial` is not a
//! directory; and it succeeds without `archives/`, removing the binary
//! caches. So the detector reports nothing when `archives/` or
//! `archives/partial/` is a symlink, not a directory, on another device,
//! or cannot be opened and read, and counts only the binary caches when
//! `archives/` does not exist.
//!
//! Reading follows the walk's rules: every directory is opened with
//! `O_NOFOLLOW` and checked to be the inode just `lstat`ed (the cache
//! directory against the walk's node), entries are `fstatat`ed without
//! following symlinks, nothing on another device is looked at, and only
//! regular files count (unlinking a symlink frees nothing). A hardlinked
//! file counts once, and only when the clean removes every link to it; the
//! total is also capped at the directory's [`TreeNode::freeable`] bytes.
//!
//! The finding is `regenerable`: apt rebuilds its binary caches on the
//! next run and downloads a package again when it needs it. `apt` and
//! `dpkg` hold `archives/lock` open while they work, so the process guards
//! (`in-use-cwd`, `in-use-open`) apply; the git guards do not.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, Stat};
use rustix::io::Errno;

use crate::detect::{Candidate, DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, Recovery, Tier};
use crate::tree::{ScanTree, TreeNode};
use crate::units::human;

/// Reclaimable totals below this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// Names `apt-get clean` leaves in `archives/` and `archives/partial/`.
const KEPT: &[&[u8]] = &[b"lock", b"partial", b"auxfiles", b"lost+found"];

/// `apt-cache`. Holds the cache directory it looks at.
pub struct AptCache {
    root: PathBuf,
}

impl AptCache {
    /// apt's cache directory (`Dir::Cache`).
    pub const DEFAULT_ROOT: &str = "/var/cache/apt";

    /// Looks at [`AptCache::DEFAULT_ROOT`].
    pub fn from_system() -> AptCache {
        AptCache::with_root(PathBuf::from(AptCache::DEFAULT_ROOT))
    }

    /// Looks at `root` instead (fixture tests).
    pub fn with_root(root: PathBuf) -> AptCache {
        AptCache { root }
    }
}

/// What one read of the cache directory found.
#[derive(Default)]
struct Tally {
    reclaimable_bytes: u64,
    /// Names in `archives/` and `archives/partial/` of inodes the clean frees.
    package_files: u64,
    /// Binary cache names of inodes the clean frees.
    cache_files: u64,
    newest_mtime: Option<i64>,
    /// Files the clean removes that stay hardlinked to a name it keeps.
    linked_bytes: u64,
}

/// One inode the clean removes a name of.
struct Inode {
    allocated: u64,
    nlink: u64,
    mtime: i64,
    package_names: u64,
    cache_names: u64,
}

impl Detector for AptCache {
    fn name(&self) -> &'static str {
        "apt-cache"
    }

    fn detect_candidates(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
    ) -> Result<Vec<Candidate>, String> {
        let Some(id) = tree.find(&self.root) else {
            return Ok(Vec::new());
        };
        let node = tree.node(id);
        if !node.is_dir {
            return Ok(Vec::new());
        }
        let Some(tally) = self.read(node) else {
            return Ok(Vec::new());
        };
        let bytes = tally.reclaimable_bytes.min(node.freeable());
        let reclaimable_files = tally.package_files + tally.cache_files;
        if reclaimable_files == 0 || bytes < MIN_BYTES {
            return Ok(Vec::new());
        }

        let path_s = self.root.to_string_lossy().into_owned();
        let apt_get = ctx
            .tool_command("apt-get")
            .unwrap_or_else(|| "apt-get".into());
        let argv = vec![
            apt_get,
            "-o".into(),
            format!("Dir::Cache={path_s}"),
            "-o".into(),
            "Dir::Cache::archives=archives/".into(),
            "-o".into(),
            "Dir::Cache::pkgcache=pkgcache.bin".into(),
            "-o".into(),
            "Dir::Cache::srcpkgcache=srcpkgcache.bin".into(),
            "clean".into(),
        ];
        let plural = |n: u64| if n == 1 { "" } else { "s" };
        let mut what = Vec::new();
        if tally.package_files > 0 {
            what.push(format!(
                "{} downloaded package file{}",
                tally.package_files,
                plural(tally.package_files)
            ));
        }
        if tally.cache_files > 0 {
            what.push(format!(
                "{} binary package cache file{}",
                tally.cache_files,
                plural(tally.cache_files)
            ));
        }
        let mut reason = format!(
            "{} in {} ({}), removed by `apt-get clean`",
            what.join(" and "),
            self.root.display(),
            human(bytes),
        );
        if let Some(t) = tally.newest_mtime {
            reason.push_str(&format!("; the newest written {} ago", age(ctx.now, t)));
        }
        if tally.linked_bytes > 0 {
            reason.push_str(&format!(
                "; {} more is hardlinked elsewhere and is not freed",
                human(tally.linked_bytes)
            ));
        }

        let finding = Finding {
            file_identity: None,
            id: finding_id(self.name(), &path_s),
            detector: self.name().into(),
            probe: None,
            evidence: None,
            bytes,
            nested_bytes: None,
            last_modified: tally.newest_mtime.map(rfc3339),
            growth: None,
            tier: Tier::Regenerable,
            reason,
            guards: Vec::new(),
            action: Action {
                kind: ActionKind::Command,
                text: argv
                    .iter()
                    .map(|a| shell_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
                argv: Some(argv),
            },
            recovery: Recovery {
                cost: "apt rebuilds its binary package cache automatically and re-downloads packages if reinstalled".into(),
                how: None,
            },
            path: path_s,
        };
        Ok(vec![Candidate::new(self.root.clone(), finding)])
    }
}

impl AptCache {
    /// Reads the cache directory (the walk's `node`), `archives/` and
    /// `archives/partial/`. `None` when any of them cannot be read safely,
    /// so `apt-get clean` could follow a symlink or leave the filesystem.
    fn read(&self, node: &TreeNode) -> Option<Tally> {
        let root = rustix::fs::open(&self.root, DIR_FLAGS, Mode::empty()).ok()?;
        let st = rustix::fs::fstat(&root).ok()?;
        if (st.st_dev, st.st_ino) != (node.dev, node.ino) {
            return None;
        }
        let dev = node.dev;
        let mut inodes: HashMap<(u64, u64), Inode> = HashMap::new();
        for (name, st) in entries(&root, dev)? {
            if is_regular(&st) && removed_cache(&name) {
                inode(&mut inodes, &st).cache_names += 1;
            }
        }
        if let Some(archives) = subdir(&root, b"archives", dev)? {
            let partial = subdir(&archives, b"partial", dev)?;
            for dir in std::iter::once(&archives).chain(partial.as_ref()) {
                for (name, st) in entries(dir, dev)? {
                    if is_regular(&st) && !KEPT.contains(&name.as_slice()) {
                        inode(&mut inodes, &st).package_names += 1;
                    }
                }
            }
        }
        let mut t = Tally::default();
        for i in inodes.values() {
            // The clean frees the inode only when it removes every name.
            if i.package_names + i.cache_names < i.nlink {
                t.linked_bytes += i.allocated;
                continue;
            }
            t.reclaimable_bytes += i.allocated;
            t.package_files += i.package_names;
            t.cache_files += i.cache_names;
            t.newest_mtime = Some(t.newest_mtime.map_or(i.mtime, |m| m.max(i.mtime)));
        }
        Some(t)
    }
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// The directory `name` in `dir`: `Some(None)` when there is none,
/// `None` when it is there but is a symlink, not a directory, on another
/// device than `dev`, cannot be opened, or is not the inode just stat'ed.
fn subdir(dir: &OwnedFd, name: &[u8], dev: u64) -> Option<Option<OwnedFd>> {
    let name = OsStr::from_bytes(name);
    let st = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Some(None),
        Err(_) => return None,
    };
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory || st.st_dev != dev {
        return None;
    }
    let fd = rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty()).ok()?;
    let fst = rustix::fs::fstat(&fd).ok()?;
    ((fst.st_dev, fst.st_ino) == (st.st_dev, st.st_ino)).then_some(Some(fd))
}

/// The entries of `dir` on device `dev`, `fstatat`ed without following
/// symlinks; entries gone before the stat are left out. `None` when the
/// directory cannot be read to the end.
fn entries(dir: &OwnedFd, dev: u64) -> Option<Vec<(Vec<u8>, Stat)>> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 16 << 10];
    let mut raw = RawDir::new(dir, &mut buf);
    while let Some(ent) = raw.next() {
        let n = ent.ok()?.file_name().to_bytes().to_vec();
        if n != b"." && n != b".." {
            names.push(n);
        }
    }
    let mut out = Vec::with_capacity(names.len());
    for n in names {
        match rustix::fs::statat(dir, OsStr::from_bytes(&n), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if st.st_dev == dev => out.push((n, st)),
            Ok(_) | Err(Errno::NOENT) => {}
            Err(_) => return None,
        }
    }
    Some(out)
}

fn is_regular(st: &Stat) -> bool {
    FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
}

/// Whether `apt-get clean` (`pkgCacheFile::RemoveCaches`) removes the
/// cache directory's entry `name`: a binary cache, or one with a suffix
/// that `GetListOfFilesInDir` lists (ASCII letters, digits, `_`, `-` and
/// `.` only, not ending in `.`).
fn removed_cache(name: &[u8]) -> bool {
    if name == b"pkgcache.bin" || name == b"srcpkgcache.bin" {
        return true;
    }
    (name.starts_with(b"pkgcache.bin.") || name.starts_with(b"srcpkgcache.bin."))
        && !name.ends_with(b".")
        && name
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

/// The entry for the inode `st`.
fn inode<'a>(inodes: &'a mut HashMap<(u64, u64), Inode>, st: &Stat) -> &'a mut Inode {
    inodes.entry((st.st_dev, st.st_ino)).or_insert(Inode {
        allocated: st.st_blocks.max(0) as u64 * 512,
        nlink: nlink(st),
        mtime: mtime(st),
        package_names: 0,
        cache_names: 0,
    })
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

#[cfg(test)]
mod tests {
    use super::removed_cache;

    /// Names checked against `apt-get clean` on a temp dir (apt 3.2).
    #[test]
    fn removed_cache_names() {
        for removed in [
            "pkgcache.bin",
            "srcpkgcache.bin",
            "pkgcache.bin.ABC",
            "pkgcache.bin.A_b-C.d",
            "pkgcache.bin..x",
            "srcpkgcache.bin.Q",
            "srcpkgcache.bin.q.r",
        ] {
            assert!(removed_cache(removed.as_bytes()), "{removed}");
        }
        for kept in [
            "keep.bin",
            "pkgcache.binX",
            "pkgcache.bin-x",
            "pkgcache.bin.",
            "srcpkgcache.bin.",
            "pkgcache.bin.a~b",
            "pkgcache.bin.a b",
            "pkgcache.bin.a:b",
            "pkgcache.bin.\u{e9}",
            ".pkgcache.bin.h",
            "xpkgcache.bin",
        ] {
            assert!(!removed_cache(kept.as_bytes()), "{kept}");
        }
    }
}
