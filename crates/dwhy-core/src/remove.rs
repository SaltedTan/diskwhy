//! Removing a finding's root (docs/DESIGN.md "Safety rules"): a path
//! removal limited to that root, which never follows a symlink and never
//! crosses a filesystem boundary.
//!
//! - The parent is reached from `/` one component at a time with
//!   `O_NOFOLLOW`, so a symlink anywhere in the path stops the removal.
//! - The root is `lstat`ed through the parent: a symlink root is refused,
//!   and so is a root whose device and inode differ from the expected pair.
//! - A root with a mount point at or below it is refused before anything is
//!   removed (bind mounts of the same filesystem have the same `st_dev`).
//! - Each directory is opened with `O_NOFOLLOW` relative to its parent's
//!   descriptor, and checked to be the inode just `lstat`ed; entries are
//!   removed with `unlinkat`, so a symlink inside is unlinked, never
//!   followed. An entry on another device than the root stops the removal
//!   (a btrfs subvolume inside the root too: `rmdir` cannot remove one).
//! - A directory of the caller's own without write or search permission
//!   (Go's read-only module cache) gets `u+rwx` before it is emptied; it is
//!   inside the root being removed.

use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, Stat};
use rustix::io::Errno;

use crate::mounts::MountTable;

/// What a removal took away.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Removed {
    /// Non-directories unlinked (files, symlinks, sockets...).
    pub files: u64,
    pub dirs: u64,
    /// Allocated bytes of unlinked files that had no other link.
    pub bytes: u64,
}

/// Removes `path` (a directory and everything in it, or a single file).
/// `expect` is the root's expected `(st_dev, st_ino)`, taken from the fresh
/// measurement when called by `apply`. `mounts` is the mount table. A mount
/// point at or below the root stops removal. On error, part of the tree may
/// already be gone. The error says where removal stopped.
pub fn remove_tree(
    path: &Path,
    expect: Option<(u64, u64)>,
    mounts: &MountTable,
) -> Result<Removed, String> {
    let names = components(path)?;
    if let Some(m) = mounts
        .mounts
        .iter()
        .find(|m| m.mount_point.starts_with(path))
    {
        return Err(format!(
            "{} is a mount point inside it; refusing to cross a filesystem boundary",
            m.mount_point.display()
        ));
    }
    let (parent, name) = open_parent(path, &names)?;
    let st = rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| at(path, "cannot stat", e))?;
    if let Some((dev, ino)) = expect
        && (st.st_dev, st.st_ino) != (dev, ino)
    {
        return Err(format!(
            "{} is not the inode the plan recorded; refusing",
            path.display()
        ));
    }
    let mut done = Removed::default();
    match FileType::from_raw_mode(st.st_mode) {
        FileType::Symlink => {
            return Err(format!(
                "{} is a symlink; symlinks are never followed",
                path.display()
            ));
        }
        FileType::Directory => {
            let fd = open_dir_at(&parent, name, &st, path)?;
            empty(&fd, st.st_dev, path, &mut done, &classify_boundary)?;
            drop(fd);
            rustix::fs::unlinkat(&parent, name, AtFlags::REMOVEDIR)
                .map_err(|e| at(path, "cannot remove", e))?;
            done.dirs += 1;
        }
        _ => {
            rustix::fs::unlinkat(&parent, name, AtFlags::empty())
                .map_err(|e| at(path, "cannot remove", e))?;
            done.files += 1;
            done.bytes += own_bytes(&st);
        }
    }
    Ok(done)
}

/// The normal components of an absolute path; refuses `.`/`..` and paths
/// less than two levels deep (`/`, `/home`).
fn components(path: &Path) -> Result<Vec<&OsStr>, String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    let mut out = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => out.push(n),
            _ => {
                return Err(format!(
                    "{} has `.` or `..` in it; refusing",
                    path.display()
                ));
            }
        }
    }
    if out.len() < 2 {
        return Err(format!(
            "{} is too close to / to remove; refusing",
            path.display()
        ));
    }
    Ok(out)
}

/// Opens the parent of `path` from `/` without following any symlink.
fn open_parent<'a>(path: &Path, names: &[&'a OsStr]) -> Result<(OwnedFd, &'a OsStr), String> {
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = rustix::fs::open("/", flags, Mode::empty())
        .map_err(|e| at(Path::new("/"), "cannot open", e))?;
    let (last, dirs) = names.split_last().expect("at least two components");
    let mut so_far = PathBuf::from("/");
    for n in dirs {
        so_far.push(n);
        fd = rustix::fs::openat(&fd, *n, flags, Mode::empty()).map_err(|e| match e {
            Errno::LOOP | Errno::NOTDIR => format!(
                "{} is a symlink or not a directory; symlinks are never followed (removing {})",
                so_far.display(),
                path.display()
            ),
            e => at(&so_far, "cannot open", e),
        })?;
    }
    Ok((fd, last))
}

/// Opens directory `name` in `parent` for reading, without following a
/// symlink, and checks it is the inode `st`. A directory of ours without
/// read, write or search permission gets `u+rwx` first.
fn open_dir_at(
    parent: &impl AsFd,
    name: &OsStr,
    st: &Stat,
    path: &Path,
) -> Result<OwnedFd, String> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let owned = st.st_uid == rustix::process::geteuid().as_raw();
    let fd = match rustix::fs::openat(parent, name, flags, Mode::empty()) {
        Err(Errno::ACCESS) if owned => {
            // Grant ourselves access through an O_PATH descriptor of this
            // very inode (/proc/self/fd/N names it, not a path that a
            // symlink could replace), then open it again.
            let p = rustix::fs::openat(
                parent,
                name,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| at(path, "cannot open", e))?;
            same_inode(&p, st, path)?;
            let mode = Mode::from_raw_mode(st.st_mode & 0o7777) | Mode::RWXU;
            rustix::fs::chmod(format!("/proc/self/fd/{}", p.as_raw_fd()), mode)
                .map_err(|e| at(path, "cannot make writable", e))?;
            rustix::fs::openat(parent, name, flags, Mode::empty())
                .map_err(|e| at(path, "cannot open", e))?
        }
        r => r.map_err(|e| at(path, "cannot open", e))?,
    };
    same_inode(&fd, st, path)?;
    if owned && st.st_mode & 0o300 != 0o300 {
        let mode = Mode::from_raw_mode(st.st_mode & 0o7777) | Mode::RWXU;
        rustix::fs::fchmod(&fd, mode).map_err(|e| at(path, "cannot make writable", e))?;
    }
    Ok(fd)
}

fn same_inode(fd: &impl AsFd, st: &Stat, path: &Path) -> Result<(), String> {
    let now = rustix::fs::fstat(fd).map_err(|e| at(path, "cannot stat", e))?;
    if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino) {
        return Err(format!(
            "{} changed while it was being removed; stopped",
            path.display()
        ));
    }
    Ok(())
}

/// What lies past an entry on another device than the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boundary {
    /// Another filesystem (or one the kernel cannot tell apart from it).
    Filesystem,
    /// A btrfs subvolume that is not mounted on its own.
    BtrfsSubvolume,
}

/// Tells what entry `name` of directory `dir` is, given that it is on
/// another device than the root being removed ([`classify_boundary`]
/// outside tests).
type Classify = dyn Fn(&OwnedFd, &OsStr) -> Boundary;

/// [`Classify`]: an entry reached through the same mount as its btrfs
/// directory, though on another device, is a btrfs subvolume. Reads only.
fn classify_boundary(dir: &OwnedFd, name: &OsStr) -> Boundary {
    use rustix::fs::{Statx, StatxFlags, statx};
    let mount = |st: Statx| (st.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(st.stx_mnt_id);
    let here = statx(dir, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .ok()
        .and_then(mount);
    let there = statx(
        dir,
        name,
        AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
        StatxFlags::MNT_ID,
    )
    .ok()
    .and_then(mount);
    if here.is_some() && here == there && crate::mounts::on_btrfs(dir) {
        Boundary::BtrfsSubvolume
    } else {
        Boundary::Filesystem
    }
}

/// Removes everything in the directory `fd` (at `path`), staying on device
/// `dev`. `classify` words the error at an entry on another device.
fn empty(
    fd: &OwnedFd,
    dev: u64,
    path: &Path,
    done: &mut Removed,
    classify: &Classify,
) -> Result<(), String> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 32 << 10];
    let mut dir = RawDir::new(fd, &mut buf);
    while let Some(ent) = dir.next() {
        let ent = ent.map_err(|e| at(path, "cannot list", e))?;
        let n = ent.file_name().to_bytes();
        if n != b"." && n != b".." {
            names.push(n.to_vec());
        }
    }
    for n in names {
        let name = OsStr::from_bytes(&n);
        let child = path.join(name);
        let st = match rustix::fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::NOENT) => continue,
            Err(e) => return Err(at(&child, "cannot stat", e)),
        };
        if st.st_dev != dev {
            return Err(match classify(fd, name) {
                Boundary::BtrfsSubvolume => format!(
                    "{} is a btrfs subvolume; stopped there (rmdir cannot remove a subvolume; \
                     `btrfs subvolume delete` does)",
                    child.display()
                ),
                Boundary::Filesystem => format!(
                    "{} is on another filesystem; stopped there (nothing crosses a filesystem boundary)",
                    child.display()
                ),
            });
        }
        if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            let sub = open_dir_at(fd, name, &st, &child)?;
            empty(&sub, dev, &child, done, classify)?;
            drop(sub);
            rustix::fs::unlinkat(fd, name, AtFlags::REMOVEDIR)
                .map_err(|e| at(&child, "cannot remove", e))?;
            done.dirs += 1;
        } else {
            rustix::fs::unlinkat(fd, name, AtFlags::empty())
                .map_err(|e| at(&child, "cannot remove", e))?;
            done.files += 1;
            done.bytes += own_bytes(&st);
        }
    }
    Ok(())
}

/// Allocated bytes freed by unlinking a file with this stat.
fn own_bytes(st: &Stat) -> u64 {
    if st.st_nlink <= 1 {
        (st.st_blocks as u64).saturating_mul(512)
    } else {
        0
    }
}

fn at(path: &Path, what: &str, e: Errno) -> String {
    format!(
        "{what} {}: {}",
        path.display(),
        std::io::Error::from_raw_os_error(e.raw_os_error())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Empties a fixture root as if it were on another device than its
    /// entries, with `classify` telling what that boundary is.
    fn empty_across_a_boundary(classify: &Classify) -> String {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap().join("r");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/f"), "x").unwrap();
        let st = rustix::fs::lstat(&root).unwrap();
        let fd = rustix::fs::open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let mut done = Removed::default();
        let err = empty(&fd, st.st_dev.wrapping_add(1), &root, &mut done, classify).unwrap_err();
        assert!(root.join("sub/f").exists(), "nothing was removed");
        assert_eq!(done, Removed::default());
        assert!(
            err.starts_with(&root.join("sub").display().to_string()),
            "{err}"
        );
        err
    }

    #[test]
    fn emptying_stops_at_another_device() {
        let err = empty_across_a_boundary(&|_, _| Boundary::Filesystem);
        assert!(
            err.contains("is on another filesystem; stopped there"),
            "{err}"
        );
    }

    #[test]
    fn emptying_stops_at_a_btrfs_subvolume_and_says_so() {
        let err = empty_across_a_boundary(&|_, name| {
            assert_eq!(name, "sub");
            Boundary::BtrfsSubvolume
        });
        assert!(err.contains("is a btrfs subvolume; stopped there"), "{err}");
        assert!(err.contains("btrfs subvolume delete"), "{err}");
        assert!(!err.contains("another filesystem"), "{err}");
    }

    #[test]
    fn a_boundary_off_btrfs_is_another_filesystem() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        let fd = rustix::fs::open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        // `sub` is on the same mount as its directory; only btrfs gives
        // such an entry a device of its own.
        let want = if crate::mounts::on_btrfs(&fd) {
            Boundary::BtrfsSubvolume
        } else {
            Boundary::Filesystem
        };
        assert_eq!(classify_boundary(&fd, OsStr::new("sub")), want);
        assert_eq!(
            classify_boundary(&fd, OsStr::new("missing")),
            Boundary::Filesystem
        );
    }

    #[test]
    fn shallow_or_relative_paths_are_refused() {
        for p in ["/", "/home", "relative/path", "/home/../etc", "/./home"] {
            assert!(components(Path::new(p)).is_err(), "{p}");
        }
        assert_eq!(components(Path::new("/home/me")).unwrap().len(), 2);
    }
}
