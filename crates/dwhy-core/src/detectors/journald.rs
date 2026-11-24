//! `journald`: archived systemd journal files older than
//! [`Journald::VACUUM_DAYS`] days in the persistent journal,
//! `/var/log/journal`. Root only (the catalog's `Needs::RootAnd`).
//!
//! The journal directory holds the active journals (`system.journal`,
//! `user-<uid>.journal`), which `systemd-journald` keeps open and writes,
//! and archived ones it rotated out: `system@<id>.journal`, or
//! `system@<id>.journal~` for a file closed uncleanly. Only archived files
//! are vacuum targets; `journalctl --vacuum-time` never touches an active
//! journal. They sit directly in the journal directory or in its
//! `<machine-id>/` subdirectories, so the detector reads the directory and
//! its immediate subdirectories, no deeper.
//!
//! Reading follows the walk's rules: every directory is opened with
//! `O_NOFOLLOW` and checked to be the inode just `lstat`ed, entries are
//! `fstatat`ed without following symlinks, symlinks are skipped, nothing on
//! another device is looked at, and only regular files count. Hardlinked
//! files count once, and only when every link to them is an old archived
//! journal (otherwise vacuuming would not free them); the total is also
//! capped at the directory's [`TreeNode::freeable`] bytes.
//!
//! Age is the file's mtime, the time of its last entry. `journalctl`
//! judges by the entry times inside, so the estimate errs towards keeping.
//! The finding is `review`: logs are not regenerable. The action is
//! `journalctl --directory <dir> --vacuum-time=14d`, which leaves the
//! directory, the active journals and the last 14 days in place.

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

    /// Archived journals whose last write is older than this many days are
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
    /// Active and recent journal files that stay.
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
            "{n} archived journal file{} older than {days} days in {} ({})",
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
        reason.push_str(&format!("; active and recent (<{days}d) journals are kept"));
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
                cost: "vacuumed journal entries older than 14 days cannot be recovered; active logs and the last 14 days stay".into(),
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
                    // just stat'ed; nothing below it is read.
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
    let Some(archived) = journal_kind(name) else {
        return;
    };
    let mtime = mtime(st);
    let i = inodes.entry((st.st_dev, st.st_ino)).or_insert(Inode {
        allocated: st.st_blocks.max(0) as u64 * 512,
        nlink: nlink(st),
        mtime,
        old_names: 0,
        kept_name: false,
    });
    if archived && mtime <= cutoff {
        i.old_names += 1;
    } else {
        i.kept_name = true;
    }
}

/// `Some(true)` for an archived journal (`<name>@<id>.journal` or
/// `.journal~`), `Some(false)` for an active one, `None` for anything else.
fn journal_kind(name: &[u8]) -> Option<bool> {
    let stem = name
        .strip_suffix(b".journal")
        .or_else(|| name.strip_suffix(b".journal~"))?;
    if stem.is_empty() {
        return None;
    }
    let archived = match stem.iter().position(|&b| b == b'@') {
        Some(at) => {
            if at == 0 || at + 1 == stem.len() {
                return None;
            }
            true
        }
        None => false,
    };
    // An active journal is never `.journal~`: that is a file closed uncleanly.
    if !archived && name.ends_with(b"~") {
        return None;
    }
    Some(archived)
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
    use super::journal_kind;

    #[test]
    fn journal_names() {
        for archived in [
            "system@0123abcd-0000000000000001-0005f0a1b2c3d4e5.journal",
            "system@0123abcd-0000000000000001-0005f0a1b2c3d4e5.journal~",
            "user-1000@0123abcd-0000000000000001-0005f0a1b2c3d4e5.journal",
            "user-1000@x.journal~",
        ] {
            assert_eq!(journal_kind(archived.as_bytes()), Some(true), "{archived}");
        }
        for active in ["system.journal", "user-1000.journal"] {
            assert_eq!(journal_kind(active.as_bytes()), Some(false), "{active}");
        }
        for other in [
            "README",
            "foo.log",
            "system.journal.bak",
            "foo@bar.txt",
            ".journal",
            "@.journal",
            "@x.journal",
            "system@.journal",
            "system.journal~",
            "system@x.journal.gz",
        ] {
            assert_eq!(journal_kind(other.as_bytes()), None, "{other}");
        }
    }
}
