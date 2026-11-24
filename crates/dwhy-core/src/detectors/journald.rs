//! `journald`: archived systemd journal files started more than
//! [`Journald::VACUUM_DAYS`] days ago in the persistent journal,
//! `/var/log/journal`. Root only (the catalog's `Needs::RootAnd`).
//!
//! The journal directory holds the active journals (`system.journal`,
//! `user-<uid>.journal`), which `systemd-journald` keeps open and writes,
//! and archived ones it rotated out. `journalctl --vacuum-time` removes only
//! archived files named as journald names them,
//! `<prefix>@<32 hex seqnum id>-<16 hex head seqnum>-<16 hex head realtime>.journal`,
//! or `<prefix>@<16 hex head realtime>-<16 hex>.journal~` for a file closed
//! uncleanly; it treats every other `.journal` or `.journal~` file as active
//! and leaves it. It looks directly in the journal directory and in its
//! subdirectories named by a 128-bit ID (`<machine-id>/`), so the detector
//! reads the directory and those immediate subdirectories, no deeper.
//!
//! Reading follows the walk's rules: every directory is opened with
//! `O_NOFOLLOW` and checked to be the inode just `lstat`ed, entries are
//! `fstatat`ed without following symlinks, symlinks are skipped, nothing on
//! another device is looked at, and only regular files count. Hardlinked
//! files count once, and only when every link to them is an old archived
//! journal (otherwise vacuuming would not free them); the total is also
//! capped at the directory's [`TreeNode::freeable`] bytes.
//!
//! Age is judged as `journalctl` judges it: the head (first-entry) realtime
//! in the file's name, or the file's ctime, atime or mtime when earlier. The
//! vacuum removes a whole file started more than 14 days ago, entries from
//! the last 14 days in it included, so such a file counts in full.
//! The finding is `review`: logs are not regenerable. The action is
//! `journalctl --directory <dir> --vacuum-time=14d`, which leaves the
//! directory, the active journals and archived files started in the last
//! 14 days in place.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, Stat};

use crate::detect::{Candidate, DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, Recovery, Tier};
use crate::tree::{ScanTree, TreeNode};
use crate::units::human;

/// Reclaimable totals below this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// `journald`. Holds the journal directory it looks at.
pub struct Journald {
    root: PathBuf,
}

impl Journald {
    /// The persistent journal directory.
    pub const DEFAULT_ROOT: &str = "/var/log/journal";

    /// Archived journals started more than this many days ago are
    /// reclaimable; the action vacuums with the same age.
    pub const VACUUM_DAYS: i64 = 14;

    /// Looks at [`Journald::DEFAULT_ROOT`].
    pub fn from_system() -> Journald {
        Journald::with_root(PathBuf::from(Journald::DEFAULT_ROOT))
    }

    /// Looks at `root` instead (fixture tests).
    pub fn with_root(root: PathBuf) -> Journald {
        Journald { root }
    }
}

/// What one read of the journal directory found.
#[derive(Default)]
struct Tally {
    reclaimable_bytes: u64,
    reclaimable_files: u64,
    newest_old_mtime: Option<i64>,
    /// Journal files the vacuum leaves: active ones, recent archived ones.
    kept_bytes: u64,
    /// Old archived journals hardlinked to a name vacuuming keeps.
    linked_bytes: u64,
}

/// One inode seen under the journal directory.
struct Inode {
    allocated: u64,
    nlink: u64,
    mtime: i64,
    /// Names of it that are old archived journals.
    old_names: u64,
    /// Whether some name of it is a journal file that stays.
    kept_name: bool,
}

impl Detector for Journald {
    fn name(&self) -> &'static str {
        "journald"
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
        let cutoff = ctx.now - Journald::VACUUM_DAYS * 86_400;
        let Some(tally) = self.read(node, cutoff) else {
            return Ok(Vec::new());
        };
        let bytes = tally.reclaimable_bytes.min(node.freeable());
        if tally.reclaimable_files == 0 || bytes < MIN_BYTES {
            return Ok(Vec::new());
        }

        let path_s = self.root.to_string_lossy().into_owned();
        let days = Journald::VACUUM_DAYS;
        let journalctl = ctx
            .tool_command("journalctl")
            .unwrap_or_else(|| "journalctl".into());
        let argv = vec![
            journalctl,
            "--directory".into(),
            path_s.clone(),
            format!("--vacuum-time={days}d"),
        ];
        let n = tally.reclaimable_files;
        let mut reason = format!(
            "{n} archived journal file{} started over {days} days ago in {} ({})",
            if n == 1 { "" } else { "s" },
            self.root.display(),
            human(bytes),
        );
        if let Some(t) = tally.newest_old_mtime {
            reason.push_str(&format!(
                "; the newest of them last written {} ago",
                age(ctx.now, t)
            ));
        }
        if tally.linked_bytes > 0 {
            reason.push_str(&format!(
                "; {} more is hardlinked elsewhere and is not freed",
                human(tally.linked_bytes)
            ));
        }
        reason.push_str(&format!(
            "; active journals and archived ones started in the last {days} days are kept"
        ));
        if tally.kept_bytes > 0 {
            reason.push_str(&format!(
                " ({} of {} total)",
                human(tally.kept_bytes),
                human(tally.kept_bytes + bytes + tally.linked_bytes)
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
            last_modified: tally.newest_old_mtime.map(rfc3339),
            growth: None,
            tier: Tier::Review,
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
                cost: format!(
                    "vacuuming removes whole archived journal files started over {days} days ago, newer entries in them included, and they cannot be recovered; active journals stay"
                ),
                how: None,
            },
            path: path_s,
        };
        Ok(vec![Candidate::new(self.root.clone(), finding)])
    }
}

impl Journald {
    /// Reads the journal directory (the walk's `node`) and its immediate
    /// subdirectories. `None` when it cannot be opened or is no longer the
    /// directory the walk measured.
    fn read(&self, node: &TreeNode, cutoff: i64) -> Option<Tally> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let root = rustix::fs::open(&self.root, flags, Mode::empty()).ok()?;
        let st = rustix::fs::fstat(&root).ok()?;
        if (st.st_dev, st.st_ino) != (node.dev, node.ino) {
            return None;
        }
        let dev = node.dev;
        let mut inodes: HashMap<(u64, u64), Inode> = HashMap::new();
        for (name, st) in entries(&root, dev) {
            match FileType::from_raw_mode(st.st_mode) {
                FileType::RegularFile => note(&mut inodes, &name, &st, cutoff),
                FileType::Directory => {
                    // A `<machine-id>/` directory, checked to be the inode
                    // just stat'ed; nothing below it is read. journalctl
                    // vacuums no other subdirectory.
                    if !is_id128(&name) {
                        continue;
                    }
                    let Ok(sub) = rustix::fs::openat(&root, name.as_slice(), flags, Mode::empty())
                    else {
                        continue;
                    };
                    let Ok(sst) = rustix::fs::fstat(&sub) else {
                        continue;
                    };
                    if (sst.st_dev, sst.st_ino) != (st.st_dev, st.st_ino) {
                        continue;
                    }
                    for (name, st) in entries(&sub, dev) {
                        if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile {
                            note(&mut inodes, &name, &st, cutoff);
                        }
                    }
                }
                // Symlinks are never followed; anything else is not a journal.
                _ => {}
            }
        }
        let mut t = Tally::default();
        for i in inodes.values() {
            if i.old_names == 0 {
                if i.kept_name {
                    t.kept_bytes += i.allocated;
                }
                continue;
            }
            // Vacuuming frees the inode only when it removes every name.
            if i.kept_name || i.old_names < i.nlink {
                t.linked_bytes += i.allocated;
                continue;
            }
            t.reclaimable_bytes += i.allocated;
            t.reclaimable_files += i.old_names;
            t.newest_old_mtime = Some(t.newest_old_mtime.map_or(i.mtime, |m| m.max(i.mtime)));
        }
        Some(t)
    }
}

/// The entries of `dir` on device `dev`, `fstatat`ed without following
/// symlinks. Unreadable entries are left out.
fn entries(dir: &OwnedFd, dev: u64) -> Vec<(Vec<u8>, Stat)> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 16 << 10];
    let mut raw = RawDir::new(dir, &mut buf);
    while let Some(ent) = raw.next() {
        let Ok(ent) = ent else {
            break;
        };
        let n = ent.file_name().to_bytes();
        if n != b"." && n != b".." {
            names.push(n.to_vec());
        }
    }
    names
        .into_iter()
        .filter_map(|n| {
            let st =
                rustix::fs::statat(dir, OsStr::from_bytes(&n), AtFlags::SYMLINK_NOFOLLOW).ok()?;
            (st.st_dev == dev).then_some((n, st))
        })
        .collect()
}

/// Records the regular file `name` if it is a journal file.
fn note(inodes: &mut HashMap<(u64, u64), Inode>, name: &[u8], st: &Stat, cutoff: i64) {
    let head = archived_head(name);
    if head.is_none() && !name.ends_with(b".journal") && !name.ends_with(b".journal~") {
        return;
    }
    let i = inodes.entry((st.st_dev, st.st_ino)).or_insert(Inode {
        allocated: st.st_blocks.max(0) as u64 * 512,
        nlink: nlink(st),
        mtime: mtime(st),
        old_names: 0,
        kept_name: false,
    });
    match head {
        Some(head) if vacuum_time(st, head) < cutoff => i.old_names += 1,
        _ => i.kept_name = true,
    }
}

/// The head realtime, in seconds, that `journalctl --vacuum-time` reads
/// from the name of an archived journal it may remove; `None` for any other
/// name, which the vacuum leaves alone.
fn archived_head(name: &[u8]) -> Option<i64> {
    let usec = if let Some(stem) = name.strip_suffix(b".journal") {
        // `@<32 hex seqnum id>-<16 hex head seqnum>-<16 hex head realtime>`
        let t = &stem[stem.len().checked_sub(67)?..];
        let ok = t[0] == b'@' && is_id128(&t[1..33]) && t[33] == b'-' && t[50] == b'-';
        hex(&t[34..50])?;
        ok.then_some(hex(&t[51..])?)?
    } else {
        // `@<16 hex head realtime>-<16 hex>`
        let stem = name.strip_suffix(b".journal~")?;
        let t = &stem[stem.len().checked_sub(34)?..];
        hex(&t[18..])?;
        (t[0] == b'@' && t[17] == b'-').then_some(hex(&t[1..17])?)?
    };
    Some((usec / 1_000_000) as i64)
}

/// A 128-bit ID in its plain form: 32 hex digits.
fn is_id128(s: &[u8]) -> bool {
    s.len() == 32 && s.iter().all(u8::is_ascii_hexdigit)
}

/// `s`, 16 hex digits, as a number.
fn hex(s: &[u8]) -> Option<u64> {
    if s.len() != 16 || !s.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok()
}

/// The time `journalctl --vacuum-time` judges an archived file by: `head`,
/// or the file's ctime, atime or mtime when earlier.
#[allow(clippy::unnecessary_cast)]
fn vacuum_time(st: &Stat, head: i64) -> i64 {
    [st.st_ctime as i64, st.st_atime as i64, mtime(st)]
        .into_iter()
        .filter(|&t| t > 0)
        .fold(head, i64::min)
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
    use super::archived_head;

    #[test]
    fn archived_journal_names() {
        // 0x0005f0a1b2c3d4e5 microseconds.
        let head = 0x0005f0a1b2c3d4e5_i64 / 1_000_000;
        for archived in [
            "system@70c2d3c15eb342d091269c9ee491d117-0000000000000001-0005f0a1b2c3d4e5.journal",
            "user-1000@70C2D3C15EB342D091269C9EE491D117-00000000000a0001-0005f0a1b2c3d4e5.journal",
            "@70c2d3c15eb342d091269c9ee491d117-0000000000000001-0005f0a1b2c3d4e5.journal",
            "system@0005f0a1b2c3d4e5-9d3e1f0a2b4c6d8e.journal~",
            "user-1000@0005f0a1b2c3d4e5-9d3e1f0a2b4c6d8e.journal~",
        ] {
            assert_eq!(archived_head(archived.as_bytes()), Some(head), "{archived}");
        }
        for other in [
            "system.journal",
            "user-1000.journal",
            "system.journal~",
            "README",
            ".journal",
            "system@x.journal",
            "user-1000@x.journal~",
            "system@0123abcd-0000000000000001-0005f0a1b2c3d4e5.journal",
            "system@70c2d3c15eb342d091269c9ee491d11g-0000000000000001-0005f0a1b2c3d4e5.journal",
            "system#70c2d3c15eb342d091269c9ee491d117-0000000000000001-0005f0a1b2c3d4e5.journal",
            "system@70c2d3c15eb342d091269c9ee491d117_0000000000000001-0005f0a1b2c3d4e5.journal",
            "system@70c2d3c15eb342d091269c9ee491d117-0000000000000001-0005f0a1b2c3d4e.journal",
            "system@70c2d3c15eb342d091269c9ee491d117-0000000000000001-0005f0a1b2c3d4e5.journal.gz",
            "system@0005f0a1b2c3d4e5-9d3e1f0a2b4c6d8.journal~",
            "system@0005f0a1b2c3d4e5_9d3e1f0a2b4c6d8e.journal~",
            "system-0005f0a1b2c3d4e5-9d3e1f0a2b4c6d8e.journal~",
        ] {
            assert_eq!(archived_head(other.as_bytes()), None, "{other}");
        }
    }
}
