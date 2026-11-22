//! Mount table (`/proc/self/mountinfo`) and `statvfs` figures.

use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub id: u32,
    pub parent: u32,
    pub major: u32,
    pub minor: u32,
    /// The directory of the filesystem mounted here (`/` unless this is a
    /// bind mount of a subdirectory or a btrfs subvolume other than the
    /// top-level one).
    pub root: PathBuf,
    pub mount_point: PathBuf,
    pub fstype: String,
    pub source: String,
}

impl Mount {
    pub fn dev(&self) -> u64 {
        rustix::fs::makedev(self.major, self.minor)
    }

    pub fn is_virtual(&self) -> bool {
        is_virtual_fstype(&self.fstype)
    }

    /// Whether the whole filesystem is visible below this mount point, so
    /// that a walk from it can account for everything `statvfs` counts.
    pub fn is_whole_filesystem(&self) -> bool {
        self.root == Path::new("/")
    }
}

/// Filesystem types that hold no disk data and are never entered.
pub fn is_virtual_fstype(fstype: &str) -> bool {
    matches!(
        fstype,
        "proc"
            | "sysfs"
            | "devtmpfs"
            | "devpts"
            | "cgroup"
            | "cgroup2"
            | "securityfs"
            | "debugfs"
            | "tracefs"
            | "pstore"
            | "bpf"
            | "configfs"
            | "fusectl"
            | "mqueue"
            | "hugetlbfs"
            | "autofs"
            | "binfmt_misc"
            | "efivarfs"
            | "nsfs"
            | "rpc_pipefs"
            | "selinuxfs"
    )
}

#[derive(Debug, Clone, Default)]
pub struct MountTable {
    /// In mountinfo order; later entries shadow earlier ones at the same mount point.
    pub mounts: Vec<Mount>,
}

impl MountTable {
    pub fn read() -> io::Result<Self> {
        let s = std::fs::read_to_string("/proc/self/mountinfo")?;
        Ok(Self::parse(&s))
    }

    pub fn parse(s: &str) -> Self {
        MountTable {
            mounts: s.lines().filter_map(parse_line).collect(),
        }
    }

    /// The mount that `path` (absolute, canonical) lives on: the longest
    /// mount-point prefix, with later mounts winning ties.
    pub fn for_path(&self, path: &Path) -> Option<&Mount> {
        let mut best: Option<&Mount> = None;
        for m in &self.mounts {
            if path.starts_with(&m.mount_point) {
                let better = match best {
                    None => true,
                    Some(b) => m.mount_point.as_os_str().len() >= b.mount_point.as_os_str().len(),
                };
                if better {
                    best = Some(m);
                }
            }
        }
        best
    }

    /// The mount mounted exactly at `path`, if any (last one wins).
    pub fn at(&self, path: &Path) -> Option<&Mount> {
        self.mounts.iter().rev().find(|m| m.mount_point == path)
    }

    pub fn by_id(&self, id: u32) -> Option<&Mount> {
        self.mounts.iter().find(|m| m.id == id)
    }

    /// Mounts stacked directly on `parent` (each hides whatever `parent` holds
    /// at that mount point).
    pub fn children_of<'a>(&'a self, parent: &'a Mount) -> impl Iterator<Item = &'a Mount> {
        self.mounts
            .iter()
            .filter(move |m| m.parent == parent.id && m.id != parent.id)
    }
}

fn parse_line(line: &str) -> Option<Mount> {
    // 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
    let (pre, post) = line.split_once(" - ")?;
    let mut pre = pre.split(' ');
    let id = pre.next()?.parse().ok()?;
    let parent = pre.next()?.parse().ok()?;
    let (major, minor) = pre.next()?.split_once(':')?;
    let root = unescape(pre.next()?);
    let mount_point = unescape(pre.next()?);
    let mut post = post.split(' ');
    let fstype = post.next()?.to_string();
    let source = unescape(post.next().unwrap_or("none"));
    Some(Mount {
        id,
        parent,
        major: major.parse().ok()?,
        minor: minor.parse().ok()?,
        root: PathBuf::from(root),
        mount_point: PathBuf::from(mount_point),
        fstype,
        source,
    })
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `df`-style figures for the filesystem containing `path`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsStats {
    pub size: u64,
    pub used: u64,
    pub avail: u64,
}

pub fn statvfs(path: &Path) -> io::Result<FsStats> {
    let s = rustix::fs::statvfs(path)?;
    let frsize = if s.f_frsize > 0 {
        s.f_frsize
    } else {
        s.f_bsize
    };
    Ok(FsStats {
        size: s.f_blocks.saturating_mul(frsize),
        used: s.f_blocks.saturating_sub(s.f_bfree).saturating_mul(frsize),
        avail: s.f_bavail.saturating_mul(frsize),
    })
}

/// The id (as in `/proc/self/mountinfo`) of the mount through which `path`
/// is reached, provided `path` is on device `dev`. A btrfs subvolume that
/// is not mounted on its own has its own `st_dev` but is reached through
/// the mount holding it, so this is how a walk tells it apart from a
/// filesystem mounted since the mount table was read. (`statfs` `f_fsid`
/// cannot: btrfs mixes each subvolume's id into it.) `None` if `path` is
/// gone, is no longer on `dev`, or the kernel cannot report mount ids.
/// Never follows a symlink or triggers an automount, and opens nothing.
pub fn mount_id(path: &Path, dev: u64) -> Option<u32> {
    use rustix::fs::{AtFlags, StatxFlags};
    let st = rustix::fs::statx(
        rustix::fs::CWD,
        path,
        AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
        StatxFlags::MNT_ID,
    )
    .ok()?;
    if st.stx_mask & StatxFlags::MNT_ID.bits() == 0
        || rustix::fs::makedev(st.stx_dev_major, st.stx_dev_minor) != dev
    {
        return None;
    }
    u32::try_from(st.stx_mnt_id).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
22 1 259:7 / / rw,relatime shared:1 - ext4 /dev/nvme1n1p3 rw,errors=remount-ro
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
24 22 0:47 / /tmp rw,nosuid shared:20 - tmpfs tmpfs rw
25 22 259:9 / /boot/efi rw,relatime shared:30 - vfat /dev/nvme1n1p4 rw
26 22 259:7 /home/x /mnt/with\\040space rw shared:1 - ext4 /dev/nvme1n1p3 rw
27 24 0:50 / /tmp rw shared:21 - tmpfs tmpfs2 rw
";

    #[test]
    fn parses_mountinfo() {
        let t = MountTable::parse(SAMPLE);
        assert_eq!(t.mounts.len(), 6);
        assert_eq!(t.mounts[0].fstype, "ext4");
        assert_eq!(t.mounts[0].source, "/dev/nvme1n1p3");
        assert_eq!((t.mounts[0].major, t.mounts[0].minor), (259, 7));
        assert_eq!(t.mounts[4].mount_point, PathBuf::from("/mnt/with space"));
        assert!(t.mounts[1].is_virtual());
        assert!(!t.mounts[2].is_virtual());
    }

    #[test]
    fn parses_mount_root() {
        let t = MountTable::parse(concat!(
            "22 1 259:7 / / rw - ext4 /dev/a rw\n",
            "26 22 259:7 /home/x /mnt/x rw shared:1 - ext4 /dev/a rw\n",
            "27 22 259:7 /sub\\040dir /mnt/y rw - ext4 /dev/a rw\n",
            "28 1 0:27 /@ / rw - btrfs /dev/b rw,subvol=/@\n",
        ));
        let roots: Vec<&Path> = t.mounts.iter().map(|m| m.root.as_path()).collect();
        assert_eq!(
            roots,
            [
                Path::new("/"),
                Path::new("/home/x"),
                Path::new("/sub dir"),
                Path::new("/@")
            ]
        );
        let whole: Vec<bool> = t.mounts.iter().map(Mount::is_whole_filesystem).collect();
        assert_eq!(whole, [true, false, false, false]);
        assert_eq!(t.by_id(27).unwrap().mount_point, Path::new("/mnt/y"));
        assert!(t.by_id(99).is_none());
    }

    #[test]
    fn mount_id_matches_mountinfo_on_the_same_device_only() {
        let d = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(d.path()).unwrap();
        let dev = std::os::unix::fs::MetadataExt::dev(&std::fs::metadata(&path).unwrap());
        let table = MountTable::read().unwrap();
        let expected = table.for_path(&path).map(|m| m.id);
        assert!(expected.is_some());
        assert_eq!(mount_id(&path, dev), expected);
        assert_eq!(mount_id(&path, dev.wrapping_add(1)), None);
        assert_eq!(mount_id(&path.join("missing"), dev), None);
        let link = path.join("link");
        std::os::unix::fs::symlink("/", &link).unwrap();
        let root_dev = std::os::unix::fs::MetadataExt::dev(&std::fs::metadata("/").unwrap());
        if root_dev != dev {
            assert_eq!(mount_id(&link, root_dev), None, "not followed");
        }
    }

    #[test]
    fn longest_prefix_and_shadowing() {
        let t = MountTable::parse(SAMPLE);
        assert_eq!(
            t.for_path(Path::new("/home/a")).unwrap().mount_point,
            Path::new("/")
        );
        assert_eq!(
            t.for_path(Path::new("/boot/efi/EFI")).unwrap().fstype,
            "vfat"
        );
        // The later /tmp mount shadows the earlier one.
        assert_eq!(t.for_path(Path::new("/tmp/x")).unwrap().source, "tmpfs2");
        assert_eq!(t.at(Path::new("/tmp")).unwrap().source, "tmpfs2");
        // /tmpfoo is not under /tmp.
        assert_eq!(
            t.for_path(Path::new("/tmpfoo")).unwrap().mount_point,
            Path::new("/")
        );
        let root = t.at(Path::new("/")).unwrap();
        let kids: Vec<_> = t.children_of(root).map(|m| m.mount_point.clone()).collect();
        assert!(kids.contains(&PathBuf::from("/boot/efi")));
        assert!(!kids.contains(&PathBuf::from("/")));
        // Mount 27 sits on mount 24 (the first /tmp), not on /.
        assert_eq!(
            kids.iter()
                .filter(|k| k.as_path() == Path::new("/tmp"))
                .count(),
            1
        );
    }

    #[test]
    fn statvfs_root_is_consistent() {
        let s = statvfs(Path::new("/")).unwrap();
        assert!(s.size > 0);
        assert!(s.used <= s.size);
        assert!(s.avail <= s.size);
    }
}
