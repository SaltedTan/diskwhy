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
//! the last 14 days in it included, so such a file counts in full. It goes
//! through each directory's archived files oldest first (by head seqnum
//! within one seqnum ID, otherwise by that time, to the microsecond), in
//! the order glibc's `qsort` puts them, and stops at the first that is not
//! old, so an old file sorted after a recent one (the clock went back
//! between rotations) stays and does not count.
//! The finding is `review`: logs are not regenerable. The action is
//! `journalctl --directory <dir> --vacuum-time=14d`, which leaves the
//! directory, the active journals and archived files started in the last
//! 14 days in place.

use std::cmp::Ordering;
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
        let top = entries(&root, dev);
        let files = top
            .iter()
            .filter(|(_, st)| FileType::from_raw_mode(st.st_mode) == FileType::RegularFile);
        note_dir(&mut inodes, files, cutoff);
        for (name, st) in &top {
            match FileType::from_raw_mode(st.st_mode) {
                FileType::Directory => {
                    // A `<machine-id>/` directory, checked to be the inode
                    // just stat'ed; nothing below it is read. journalctl
                    // vacuums no other subdirectory.
                    if !is_id128(name) {
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
                    let sub = entries(&sub, dev);
                    let files = sub.iter().filter(|(_, st)| {
                        FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
                    });
                    note_dir(&mut inodes, files, cutoff);
                }
                // Regular files are noted above. Symlinks are never
                // followed; anything else is not a journal.
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

/// An archived journal the vacuum of one directory may remove.
#[derive(Clone, Copy)]
struct Archived<'a> {
    name: &'a [u8],
    st: &'a Stat,
    /// The time the vacuum judges it by, in microseconds ([`vacuum_time`]).
    time: u64,
    /// `(seqnum id, head seqnum)`; `None` for a `.journal~`.
    seq: Option<(u128, u64)>,
}

/// journal-vacuum.c's `vacuum_compare`: by head seqnum within one seqnum ID,
/// otherwise by time, then seqnum ID, then name.
fn vacuum_order(a: &Archived, b: &Archived) -> Ordering {
    if let (Some((ia, sa)), Some((ib, sb))) = (a.seq, b.seq) {
        if ia == ib {
            return sa.cmp(&sb);
        }
    }
    a.time.cmp(&b.time).then_with(|| match (a.seq, b.seq) {
        (Some((ia, _)), Some((ib, _))) => ia.cmp(&ib),
        _ => a.name.cmp(b.name),
    })
}

/// Sorts as journalctl's `qsort` does: glibc's merge sort, which splits at
/// `n / 2`, sorts each half and merges them, taking from the left half
/// unless it compares greater. `vacuum_compare` is not a total order when
/// times disagree with seqnums (the clock went back), so the order, and
/// where the vacuum stops, depends on the algorithm and on readdir order;
/// `files` keep readdir order, as journalctl's list does. (`sort_by` may
/// also panic on such an order.)
fn vacuum_sort(v: &mut [Archived]) {
    if v.len() <= 1 {
        return;
    }
    let n1 = v.len() / 2;
    vacuum_sort(&mut v[..n1]);
    vacuum_sort(&mut v[n1..]);
    let (mut i, mut j) = (0, n1);
    let mut merged = Vec::with_capacity(v.len());
    while i < n1 && j < v.len() {
        if vacuum_order(&v[i], &v[j]) == Ordering::Greater {
            merged.push(v[j]);
            j += 1;
        } else {
            merged.push(v[i]);
            i += 1;
        }
    }
    merged.extend_from_slice(&v[i..n1]);
    merged.extend_from_slice(&v[j..]);
    v.copy_from_slice(&merged);
}

/// Records the journal files among one directory's regular `files`. Its
/// archived ones are old, as `journalctl --vacuum-time` removes them, up to
/// the first in vacuum order that is not; the rest stay.
fn note_dir<'a>(
    inodes: &mut HashMap<(u64, u64), Inode>,
    files: impl Iterator<Item = &'a (Vec<u8>, Stat)>,
    cutoff: i64,
) {
    let mut archived: Vec<Archived> = Vec::new();
    for (name, st) in files {
        if let Some(a) = archived_journal(name) {
            archived.push(Archived {
                name,
                st,
                time: vacuum_time(st, a.head),
                seq: a.seq,
            });
        } else if name.ends_with(b".journal") || name.ends_with(b".journal~") {
            inode(inodes, st).kept_name = true;
        }
    }
    vacuum_sort(&mut archived);
    let cutoff = cutoff.max(0) as u64 * 1_000_000;
    let mut old = true;
    for a in &archived {
        old = old && a.time < cutoff;
        let i = inode(inodes, a.st);
        if old {
            i.old_names += 1;
        } else {
            i.kept_name = true;
        }
    }
}

/// The entry for the inode `st`.
fn inode<'a>(inodes: &'a mut HashMap<(u64, u64), Inode>, st: &Stat) -> &'a mut Inode {
    inodes.entry((st.st_dev, st.st_ino)).or_insert(Inode {
        allocated: st.st_blocks.max(0) as u64 * 512,
        nlink: nlink(st),
        mtime: mtime(st),
        old_names: 0,
        kept_name: false,
    })
}

/// What `journalctl --vacuum-time` reads from an archived journal's name.
struct ArchivedName {
    /// Head realtime, in microseconds.
    head: u64,
    /// `(seqnum id, head seqnum)`; `None` for a `.journal~`.
    seq: Option<(u128, u64)>,
}

/// The name of an archived journal the vacuum may remove, parsed; `None`
/// for any other name, which the vacuum leaves alone.
fn archived_journal(name: &[u8]) -> Option<ArchivedName> {
    let (usec, seq) = if let Some(stem) = name.strip_suffix(b".journal") {
        // `@<32 hex seqnum id>-<16 hex head seqnum>-<16 hex head realtime>`
        let t = &stem[stem.len().checked_sub(67)?..];
        if !(t[0] == b'@' && is_id128(&t[1..33]) && t[33] == b'-' && t[50] == b'-') {
            return None;
        }
        let id = u128::from_str_radix(std::str::from_utf8(&t[1..33]).ok()?, 16).ok()?;
        (hex(&t[51..])?, Some((id, hex(&t[34..50])?)))
    } else {
        // `@<16 hex head realtime>-<16 hex>`
        let stem = name.strip_suffix(b".journal~")?;
        let t = &stem[stem.len().checked_sub(34)?..];
        hex(&t[18..])?;
        if !(t[0] == b'@' && t[17] == b'-') {
            return None;
        }
        (hex(&t[1..17])?, None)
    };
    Some(ArchivedName { head: usec, seq })
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

/// The time `journalctl --vacuum-time` judges an archived file by, in
/// microseconds as it compares and sorts them: `head`, or the file's ctime,
/// atime or mtime when earlier.
#[allow(clippy::unnecessary_cast)]
fn vacuum_time(st: &Stat, head: u64) -> u64 {
    [
        (st.st_ctime as i64, st.st_ctime_nsec as u64),
        (st.st_atime as i64, st.st_atime_nsec as u64),
        (st.st_mtime as i64, st.st_mtime_nsec as u64),
    ]
    .into_iter()
    .filter(|&(s, _)| s > 0)
    .map(|(s, ns)| s as u64 * 1_000_000 + ns / 1_000)
    .fold(head, u64::min)
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
    use super::archived_journal;

    /// journalctl sorts a directory's archived files with glibc's `qsort`,
    /// so glibc's own `qsort_r` is the oracle for the order: with seqnums
    /// and times that disagree (the clock went back), across several seqnum
    /// IDs and `.journal~` files, `vacuum_order` is not a total order and
    /// another algorithm (an insertion sort, say) gives a different order,
    /// so the vacuum stops at a different file.
    #[cfg(target_env = "gnu")]
    #[test]
    #[allow(unsafe_code)]
    fn vacuum_sort_orders_as_glibc_qsort() {
        use super::{Archived, vacuum_order, vacuum_sort};
        use std::cmp::Ordering;
        use std::ffi::c_void;

        unsafe extern "C" {
            fn qsort_r(
                base: *mut c_void,
                n: usize,
                size: usize,
                cmp: unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> i32,
                arg: *mut c_void,
            );
        }
        /// The size of journalctl's `struct vacuum_info`.
        #[repr(C)]
        struct Elem {
            idx: usize,
            _pad: [u8; 48],
        }
        unsafe extern "C" fn cmp(a: *const c_void, b: *const c_void, arg: *mut c_void) -> i32 {
            // SAFETY: qsort_r passes two elements of the `Elem` array and the
            // `arg` given below, a `&[Archived]` that outlives the call.
            let (a, b, v) = unsafe {
                (
                    &*(a as *const Elem),
                    &*(b as *const Elem),
                    &*(arg as *const &[Archived]),
                )
            };
            match vacuum_order(&v[a.idx], &v[b.idx]) {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            }
        }

        let st = rustix::fs::stat("/").unwrap();
        let names: Vec<Vec<u8>> = (0..12).map(|i| format!("f{i:02}").into_bytes()).collect();
        let mut seed: u64 = 0x2545f4914f6cdd1d;
        let mut rnd = |n: u64| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) % n
        };
        for _ in 0..2000 {
            let n = 2 + rnd(11) as usize;
            let mut seqs = [0u64; 3];
            let v: Vec<Archived> = (0..n)
                .map(|k| {
                    let seq = (rnd(5) != 0).then(|| {
                        let id = rnd(3) as usize;
                        seqs[id] += 1;
                        (id as u128, seqs[id])
                    });
                    Archived {
                        name: &names[k],
                        st: &st,
                        time: rnd(8),
                        seq,
                    }
                })
                .collect();
            let mut elems: Vec<Elem> = (0..n).map(|idx| Elem { idx, _pad: [0; 48] }).collect();
            let arg: &[Archived] = &v;
            // SAFETY: `elems` holds `n` initialised `Elem`s, and `cmp` reads
            // only them and `arg`.
            unsafe {
                qsort_r(
                    elems.as_mut_ptr().cast(),
                    n,
                    size_of::<Elem>(),
                    cmp,
                    (&arg as *const &[Archived]).cast_mut().cast(),
                );
            }
            let want: Vec<&[u8]> = elems.iter().map(|e| v[e.idx].name).collect();
            let mut got = v.clone();
            vacuum_sort(&mut got);
            let got: Vec<&[u8]> = got.iter().map(|a| a.name).collect();
            assert_eq!(got, want);
        }
    }

    fn archived_head(name: &[u8]) -> Option<u64> {
        archived_journal(name).map(|a| a.head)
    }

    #[test]
    fn archived_journal_names() {
        // 0x0005f0a1b2c3d4e5 microseconds.
        let head = 0x0005f0a1b2c3d4e5_u64;
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
