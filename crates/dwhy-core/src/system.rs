//! Facts about the running system: host, uid, users, open-but-deleted files.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::{fs, io};

use rustix::fs::OFlags;

use crate::report::DeletedOpen;

pub fn hostname() -> String {
    rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned()
}

pub fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub fn open_for_write_nofollow(path: &Path, create_new: bool) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(create_new)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY).bits() as i32)
        .open(path)
}

/// diskwhy's own state: `$XDG_STATE_HOME/diskwhy`, else
/// `$HOME/.local/state/diskwhy`. A relative or empty `XDG_STATE_HOME` is
/// ignored, as the XDG spec says; a relative or empty `HOME` gives `None`,
/// so state never lands under the current directory.
pub fn state_dir() -> Option<PathBuf> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|h| h.join(".local/state"))
        })?;
    Some(state.join("diskwhy"))
}

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
}

/// Users from `/etc/passwd` (empty on error).
pub fn users() -> Vec<User> {
    fs::read_to_string("/etc/passwd")
        .map(|s| parse_passwd(&s))
        .unwrap_or_default()
}

pub fn parse_passwd(s: &str) -> Vec<User> {
    s.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(User {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                home: PathBuf::from(f[5]),
            })
        })
        .collect()
}

/// Members of a group by name from `/etc/group`, plus its gid.
pub fn group(name: &str) -> Option<(u32, Vec<String>)> {
    let s = fs::read_to_string("/etc/group").ok()?;
    s.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 4 && f[0] == name {
            let members = f[3]
                .split(',')
                .filter(|m| !m.is_empty())
                .map(String::from)
                .collect();
            Some((f[2].parse().ok()?, members))
        } else {
            None
        }
    })
}

/// True if the current process has `gid` as its effective or a supplementary group.
pub fn in_group(gid: u32) -> bool {
    if rustix::process::getegid().as_raw() == gid {
        return true;
    }
    rustix::process::getgroups()
        .map(|g| g.iter().any(|g| g.as_raw() == gid))
        .unwrap_or(false)
}

/// Deleted files still held open, grouped by device.
#[derive(Debug, Clone, Default)]
pub struct DeletedOpenScan {
    pub per_dev: HashMap<u64, DeletedOpen>,
    /// Processes whose `/proc/<pid>/fd` could not be listed.
    pub processes_unreadable: u64,
}

impl DeletedOpenScan {
    pub fn for_dev(&self, dev: u64) -> DeletedOpen {
        DeletedOpen {
            processes_unreadable: self.processes_unreadable,
            ..self.per_dev.get(&dev).copied().unwrap_or_default()
        }
    }
}

/// Deleted files still held open, from `/proc/*/fd`. Only processes whose
/// fds this user may inspect are counted, so the figures are a lower bound.
pub fn deleted_open_files() -> DeletedOpenScan {
    deleted_open_files_in(Path::new("/proc"))
}

fn deleted_open_files_in(proc: &Path) -> DeletedOpenScan {
    let mut out: HashMap<u64, DeletedOpen> = HashMap::new();
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut unreadable = 0u64;
    let Ok(rd) = fs::read_dir(proc) else {
        return DeletedOpenScan::default();
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let fd_dir = ent.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            unreadable += 1;
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            if !target.to_string_lossy().ends_with(" (deleted)") {
                continue;
            }
            // stat through the magic link reaches the still-open inode.
            let Ok(md) = fs::metadata(fd.path()) else {
                continue;
            };
            if !md.is_file() || md.nlink() != 0 || !seen.insert((md.dev(), md.ino())) {
                continue;
            }
            let e = out.entry(md.dev()).or_default();
            e.files += 1;
            e.bytes += md.blocks().saturating_mul(512);
        }
    }
    DeletedOpenScan {
        per_dev: out,
        processes_unreadable: unreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn passwd_parsing() {
        let u = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n# comment\nbad\nalice:x:1001:1001::/home/alice:/bin/sh\n",
        );
        assert_eq!(u.len(), 2);
        assert_eq!(u[1].name, "alice");
        assert_eq!(u[1].uid, 1001);
        assert_eq!(u[1].home, PathBuf::from("/home/alice"));
    }

    #[test]
    fn finds_our_own_deleted_open_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("gone");
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(&vec![7u8; 256 * 1024]).unwrap();
        f.sync_all().unwrap();
        let dev = f.metadata().unwrap().dev();
        fs::remove_file(&p).unwrap();
        let found = deleted_open_files();
        let d = found.for_dev(dev);
        assert!(
            d.files >= 1,
            "expected our deleted file on dev {dev}: {found:?}"
        );
        assert!(d.bytes >= 256 * 1024, "{d:?}");
        drop(f);
    }
}
