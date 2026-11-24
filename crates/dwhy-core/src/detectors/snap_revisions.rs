//! `snap-revisions`: disabled (non-current) revisions of installed snaps,
//! each removed with `snap remove --revision=<rev> <name>`. Root only (the
//! catalog's `Needs::RootAnd`).
//!
//! The revisions come from snapd's REST API, `GET /v2/snaps?select=all` on
//! `/run/snapd.socket` (read-only, like the Docker Engine API GETs): JSON
//! that does not depend on the locale, unlike `snap list --all`, whose
//! header and `disabled` note are translated. A response that is not a
//! `sync` 200 with a `result` list, or an entry without `name`, `revision`,
//! `status` or `type`, fails the detector, so nothing is offered. A snap is
//! looked at only when its instance name and every revision are valid as
//! snapd spells them (`snap/naming.ValidateInstance`, `snap.Revision.String`:
//! `<n>` or `x<n>` for a local revision), no revision is listed twice,
//! exactly one revision is `active` and the others `installed`, and its type
//! is `app`, `base`, `os` or `snapd`. A snap with no active revision
//! (`snap disable`) is left alone: snapd lets `--revision` remove the current
//! revision of an inactive snap. Kernel and gadget snaps are left to a
//! kernel detector: their revisions are what the device boots and falls
//! back to.
//!
//! What `snap remove --revision` does (snapd 2.78, `overlord/snapstate`):
//! `removeTasks` refuses the active revision while another remains ("cannot
//! remove active revision"); with more than one revision it runs only
//! `removeInactiveRevision`, the tasks snapd's own refresh uses to drop
//! revisions beyond `refresh.retain`, and takes no automatic snapshot
//! (`AutomaticSnapshot` is only for the last revision of an app). The
//! policies' `CanRemove` allow any named revision, except that on a device
//! booting the model's base, kernel or core, `boot.InUse` refuses one the
//! bootloader uses. `clear-snap` (`doClearSnapData`, `backend.RemoveSnapData`)
//! deletes `/var/snap/<name>/<rev>`, `/root/snap/<name>/<rev>` and each
//! user's `~/snap/<name>/<rev>`, keeping the `common` directories while
//! another revision remains; `discard-snap` (`backend.RemoveSnapFiles`)
//! stops the mount at `/snap/<name>/<rev>` and removes
//! `/var/lib/snapd/snaps/<name>_<rev>.snap`.
//!
//! Only that `.snap` file counts: the data directories are small, lie
//! elsewhere and are not counted, and the mount is another filesystem. The
//! file counts when removing it frees its inode:
//!
//! - it has no other link; or
//! - its only other link is an entry in snapd's download cache
//!   (`/var/lib/snapd/cache/<sha3-384>`, found by device and inode) whose
//!   mtime (the shared inode's) is more than 30 days old. Removing the
//!   revision leaves the entry with one link, which makes it a candidate for
//!   `store.CachePolicy.Apply`; `DefaultCachePolicyClassic` removes such
//!   entries older than 30 days (`MaxAge`) and, oldest first, all but the
//!   newest 5 (`MaxItems`). snapd runs that cleanup every 24 hours
//!   (`ensureStoreDownloadsCacheCleaned`), when it starts, and after each
//!   download (`CacheManager.Put`). The 5-entry rule depends on what else
//!   is removed, so it is not counted; a younger cache entry keeps its bytes
//!   and the file does not count.
//!
//! A file with other links, or a cache that cannot be read safely, does not
//! count. Nothing under 1 MiB.
//!
//! Reading follows the walk's rules: `<snapd>/snaps` must be the directory
//! the walk measured (opened with `O_NOFOLLOW` and checked against its
//! node), the cache directory is opened the same way on the same device,
//! entries are `fstatat`ed without following symlinks, and only regular
//! files on that device count.
//!
//! The finding is `review`: `snap revert` can no longer go back to the
//! revision, and its data copy goes with it.

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, Stat};
use rustix::io::Errno;
use serde::Deserialize;

use crate::detect::{Candidate, DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, FileIdentity, Finding, Recovery, Tier};
use crate::tree::ScanTree;
use crate::units::human;

/// Reclaimable totals below this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// How long to wait for snapd's answer.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Snap types whose disabled revisions are offered.
const TYPES: &[&str] = &["app", "base", "os", "snapd"];

/// `snap-revisions`. Holds snapd's state directory and where the revision
/// list comes from.
pub struct SnapRevisions {
    root: PathBuf,
    listing: Listing,
}

enum Listing {
    Socket(PathBuf),
    Fixed(Result<Vec<u8>, String>),
}

impl SnapRevisions {
    /// snapd's state directory (`dirs.SnapdStateDir`), holding `snaps/`
    /// (`dirs.SnapBlobDir`) and `cache/` (`dirs.SnapDownloadCacheDir`).
    pub const DEFAULT_ROOT: &str = "/var/lib/snapd";

    /// snapd's REST API socket.
    pub const SOCKET: &str = "/run/snapd.socket";

    /// `MaxAge` of snapd's `DefaultCachePolicyClassic`: an unreferenced
    /// download cache entry older than this goes at the next cleanup.
    pub const CACHE_MAX_AGE_DAYS: i64 = 30;

    /// Looks at [`SnapRevisions::DEFAULT_ROOT`] and asks snapd at
    /// [`SnapRevisions::SOCKET`].
    pub fn from_system() -> SnapRevisions {
        SnapRevisions {
            root: PathBuf::from(SnapRevisions::DEFAULT_ROOT),
            listing: Listing::Socket(PathBuf::from(SnapRevisions::SOCKET)),
        }
    }

    /// Looks at `root` and takes `listing` as the body of
    /// `GET /v2/snaps?select=all` (fixture tests); an `Err` is a failed GET.
    pub fn with_listing(root: PathBuf, listing: Result<Vec<u8>, String>) -> SnapRevisions {
        SnapRevisions {
            root,
            listing: Listing::Fixed(listing),
        }
    }

    /// The directory holding the `.snap` files the findings name.
    pub fn snaps_dir(&self) -> PathBuf {
        self.root.join("snaps")
    }

    fn fetch(&self) -> Result<Vec<u8>, String> {
        match &self.listing {
            Listing::Socket(sock) => {
                crate::docker::unix_get(sock, TIMEOUT, "snapd", "snapd API", "/v2/snaps?select=all")
                    .map_err(|e| e.to_string())
            }
            Listing::Fixed(body) => body.clone(),
        }
    }
}

/// `GET /v2/snaps?select=all` (only the fields diskwhy uses).
#[derive(Deserialize)]
struct Response {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "status-code")]
    status_code: u16,
    result: Vec<Entry>,
}

/// One installed revision of a snap.
#[derive(Deserialize)]
struct Entry {
    /// The instance name (`<name>` or `<name>_<key>`).
    name: String,
    revision: String,
    /// `active` for the current revision of an enabled snap, `installed`
    /// for every other revision.
    status: String,
    #[serde(rename = "type")]
    kind: String,
}

/// A disabled revision of a snap with an active one.
#[derive(Debug, PartialEq, Eq)]
struct Disabled {
    name: String,
    revision: String,
    active: String,
}

/// The disabled revisions of the snaps `body` lists. `Err` when the body is
/// not a listing.
fn disabled_revisions(body: &[u8]) -> Result<Vec<Disabled>, String> {
    let r: Response =
        serde_json::from_slice(body).map_err(|e| format!("snapd API /v2/snaps: {e}"))?;
    if r.kind != "sync" || r.status_code != 200 {
        return Err(format!(
            "snapd API /v2/snaps: a {} response with status {}",
            r.kind, r.status_code
        ));
    }
    let mut by_name: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
    for e in &r.result {
        by_name.entry(&e.name).or_default().push(e);
    }
    let mut out = Vec::new();
    'snap: for (name, revs) in by_name {
        if !valid_instance_name(name) || revs.len() < 2 {
            continue;
        }
        let kind = &revs[0].kind;
        if !TYPES.contains(&kind.as_str()) {
            continue;
        }
        let mut seen = HashSet::new();
        let mut active = None;
        for e in &revs {
            if &e.kind != kind || !valid_revision(&e.revision) || !seen.insert(&e.revision) {
                continue 'snap;
            }
            match e.status.as_str() {
                "active" if active.is_none() => active = Some(&e.revision),
                "installed" => {}
                _ => continue 'snap,
            }
        }
        let Some(active) = active else {
            continue;
        };
        for e in revs.iter().filter(|e| e.status == "installed") {
            out.push(Disabled {
                name: name.to_string(),
                revision: e.revision.clone(),
                active: active.clone(),
            });
        }
    }
    Ok(out)
}

/// `snap.MountFile`: `<instance name>_<revision>.snap`.
fn file_name(name: &str, revision: &str) -> String {
    format!("{name}_{revision}.snap")
}

/// `naming.ValidateInstance`: a snap name (2 to 40 of `a-z`, `0-9` and
/// `-`, at least one letter, no leading, trailing or doubled `-`),
/// optionally `_` and an instance key of 1 to 10 of `a-z` and `0-9`.
fn valid_instance_name(s: &str) -> bool {
    let (name, key) = match s.split_once('_') {
        Some((n, k)) => (n, Some(k)),
        None => (s, None),
    };
    let name_ok = (2..=40).contains(&name.len())
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && name.bytes().any(|c| c.is_ascii_lowercase())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--");
    let key_ok = key.is_none_or(|k| {
        (1..=10).contains(&k.len())
            && k.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    });
    name_ok && key_ok
}

/// A revision as `snap.Revision.String` spells a set one: a positive
/// number, or `x` and a positive number for a local revision.
fn valid_revision(s: &str) -> bool {
    let n = s.strip_prefix('x').unwrap_or(s);
    !n.is_empty() && !n.starts_with('0') && n.bytes().all(|c| c.is_ascii_digit())
}

/// Why removing a revision frees its `.snap` file.
enum Freed {
    /// No other link.
    Now,
    /// The other link is an old download cache entry.
    CacheCleanup,
}

impl Detector for SnapRevisions {
    fn name(&self) -> &'static str {
        "snap-revisions"
    }

    fn detect_candidates(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
    ) -> Result<Vec<Candidate>, String> {
        let snaps_dir = self.snaps_dir();
        let Some(node) = tree.find(&snaps_dir).map(|id| tree.node(id)) else {
            return Ok(Vec::new());
        };
        if !node.is_dir {
            return Ok(Vec::new());
        }
        let disabled = disabled_revisions(&self.fetch()?)?;
        if disabled.is_empty() {
            return Ok(Vec::new());
        }
        let Some(root) = rustix::fs::open(&self.root, DIR_FLAGS, Mode::empty()).ok() else {
            return Ok(Vec::new());
        };
        let dev = node.dev;
        let snaps = match subdir(&root, b"snaps", dev) {
            Some(Some((fd, st))) if (st.st_dev, st.st_ino) == (node.dev, node.ino) => fd,
            _ => return Ok(Vec::new()),
        };
        let mut cache: Option<HashSet<(u64, u64)>> = None;
        let cutoff = ctx.now - SnapRevisions::CACHE_MAX_AGE_DAYS * 86_400;

        let snap = ctx.tool_command("snap").unwrap_or_else(|| "snap".into());
        let mut out = Vec::new();
        for d in disabled {
            let file = file_name(&d.name, &d.revision);
            let st = match rustix::fs::statat(
                &snaps,
                OsStr::from_bytes(file.as_bytes()),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(st) if is_regular(&st) && st.st_dev == dev => st,
                _ => continue,
            };
            let freed = match nlink(&st) {
                1 => Freed::Now,
                2 if mtime(&st) < cutoff
                    && cache
                        .get_or_insert_with(|| self.cache_inodes(tree, &root, dev))
                        .contains(&(st.st_dev, st.st_ino)) =>
                {
                    Freed::CacheCleanup
                }
                _ => continue,
            };
            let bytes = st.st_blocks.max(0) as u64 * 512;
            if bytes < MIN_BYTES {
                continue;
            }
            let path = snaps_dir.join(&file);
            out.push(self.candidate(ctx, &snap, &d, path, &st, bytes, freed));
        }
        out.sort_by(|a, b| a.path().cmp(b.path()));
        Ok(out)
    }
}

impl SnapRevisions {
    #[allow(clippy::too_many_arguments)]
    fn candidate(
        &self,
        ctx: &DetectContext,
        snap: &str,
        d: &Disabled,
        path: PathBuf,
        st: &Stat,
        bytes: u64,
        freed: Freed,
    ) -> Candidate {
        let (name, rev) = (d.name.as_str(), d.revision.as_str());
        let path_s = path.to_string_lossy().into_owned();
        let argv = vec![
            snap.to_string(),
            "remove".into(),
            format!("--revision={rev}"),
            name.to_string(),
        ];
        let text = argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let mut reason = format!(
            "disabled revision {rev} of snap {name} (active revision {}): {} ({}), written {} ago",
            d.active,
            path.display(),
            human(bytes),
            age(ctx.now, mtime(st)),
        );
        match freed {
            Freed::Now => reason.push_str(&format!(
                "; nothing else links to it, so `{text}` frees it"
            )),
            Freed::CacheCleanup => reason.push_str(&format!(
                "; its only other link is in snapd's download cache and is over {} days old, so once `{text}` removes the file, snapd frees it at its next cache cleanup (daily, when snapd starts, or after a download)",
                SnapRevisions::CACHE_MAX_AGE_DAYS
            )),
        }
        reason.push_str(&format!(
            "; the removal also unmounts /snap/{name}/{rev} and deletes the revision's data directories (/var/snap/{name}/{rev} and each user's ~/snap/{name}/{rev}), which are not counted"
        ));
        let mut cost = format!(
            "`snap revert {name}` can no longer return to revision {rev}, and the copy of the snap's data kept for that revision is deleted"
        );
        if rev.starts_with('x') {
            cost.push_str("; the revision was installed from a local file, so getting it back needs that .snap file");
        } else {
            cost.push_str("; getting the revision back depends on the store still offering it");
        }

        let finding = Finding {
            file_identity: Some(FileIdentity {
                dev: st.st_dev,
                ino: st.st_ino,
                mtime: mtime(st),
            }),
            id: finding_id(self.name(), &path_s),
            detector: self.name().into(),
            probe: None,
            evidence: None,
            bytes,
            nested_bytes: None,
            last_modified: Some(rfc3339(mtime(st))),
            growth: None,
            tier: Tier::Review,
            reason,
            guards: Vec::new(),
            action: Action {
                kind: ActionKind::Command,
                text,
                argv: Some(argv),
            },
            recovery: Recovery { cost, how: None },
            path: path_s,
        };
        Candidate::new(path, finding)
    }

    /// Device and inode of every regular file directly in snapd's download
    /// cache, `<root>/cache`. Empty when the cache is missing or cannot be
    /// read safely: a symlink, not a directory, on another device than `dev`,
    /// not the directory the walk measured, or unreadable.
    fn cache_inodes(&self, tree: &ScanTree, root: &OwnedFd, dev: u64) -> HashSet<(u64, u64)> {
        let Some(Some((fd, st))) = subdir(root, b"cache", dev) else {
            return HashSet::new();
        };
        if let Some(id) = tree.find(&self.root.join("cache")) {
            let n = tree.node(id);
            if (n.dev, n.ino) != (st.st_dev, st.st_ino) {
                return HashSet::new();
            }
        }
        entries(&fd, dev)
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, st)| is_regular(st))
            .map(|(_, st)| (st.st_dev, st.st_ino))
            .collect()
    }
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// The directory `name` in `dir` and its `fstat`: `Some(None)` when there
/// is none, `None` when it is there but is a symlink, not a directory, on
/// another device than `dev`, cannot be opened, or is not the inode just
/// stat'ed.
fn subdir(dir: &OwnedFd, name: &[u8], dev: u64) -> Option<Option<(OwnedFd, Stat)>> {
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
    ((fst.st_dev, fst.st_ino) == (st.st_dev, st.st_ino)).then_some(Some((fd, fst)))
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
    use super::*;

    #[test]
    fn instance_names_as_snapd_validates_them() {
        for ok in [
            "firefox",
            "core22",
            "gnome-46-2404",
            "a1",
            "x2",
            "snap-store",
            "hello_foo",
            "hello_1",
            "hello_abcdefghij",
            "0ad",
        ] {
            assert!(valid_instance_name(ok), "{ok}");
        }
        for bad in [
            "",
            "a",
            "12",
            "-foo",
            "foo-",
            "foo--bar",
            "Foo",
            "foo.bar",
            "foo/bar",
            "../foo",
            "foo bar",
            "foo_",
            "foo_bar_baz",
            "foo_ABC",
            "foo_abcdefghijk",
            "foo_a-b",
            "_foo",
            &"a".repeat(41),
        ] {
            assert!(!valid_instance_name(bad), "{bad}");
        }
    }

    #[test]
    fn revisions_as_snapd_prints_them() {
        for ok in ["1", "9057", "x1", "x42"] {
            assert!(valid_revision(ok), "{ok}");
        }
        for bad in [
            "", "0", "x0", "x", "-1", "+5", "007", "x07", "1.5", "unset", "12a", "xx1", " 1",
        ] {
            assert!(!valid_revision(bad), "{bad}");
        }
    }

    fn entry(name: &str, rev: &str, status: &str, kind: &str) -> String {
        format!(
            r#"{{"name":"{name}","revision":"{rev}","status":"{status}","type":"{kind}","mounted-from":"/var/lib/snapd/snaps/{name}_{rev}.snap"}}"#
        )
    }

    fn listing(entries: &[String]) -> Vec<u8> {
        format!(
            r#"{{"type":"sync","status-code":200,"status":"OK","result":[{}]}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    fn parse(entries: &[String]) -> Vec<(String, String, String)> {
        disabled_revisions(&listing(entries))
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.revision, d.active))
            .collect()
    }

    #[test]
    fn only_inactive_revisions_of_snaps_with_one_active_one() {
        let got = parse(&[
            entry("firefox", "9057", "installed", "app"),
            entry("firefox", "9137", "active", "app"),
            entry("core22", "2955", "installed", "base"),
            entry("core22", "2987", "active", "base"),
            entry("local", "x1", "installed", "app"),
            entry("local", "x2", "active", "app"),
            // Only one revision.
            entry("bare", "5", "active", "base"),
            // Disabled with `snap disable`: no active revision.
            entry("off", "3", "installed", "app"),
            entry("off", "4", "installed", "app"),
            // Kernel and gadget revisions are not offered.
            entry("pc-kernel", "1", "installed", "kernel"),
            entry("pc-kernel", "2", "active", "kernel"),
            entry("pc", "1", "installed", "gadget"),
            entry("pc", "2", "active", "gadget"),
        ]);
        assert_eq!(
            got,
            [
                ("core22".into(), "2955".into(), "2987".into()),
                ("firefox".into(), "9057".into(), "9137".into()),
                ("local".into(), "x1".into(), "x2".into()),
            ]
        );
    }

    #[test]
    fn garbled_snaps_are_skipped_whole() {
        let got = parse(&[
            // Two active revisions.
            entry("two", "1", "active", "app"),
            entry("two", "2", "active", "app"),
            entry("two", "3", "installed", "app"),
            // A revision listed twice.
            entry("dup", "1", "installed", "app"),
            entry("dup", "1", "installed", "app"),
            entry("dup", "2", "active", "app"),
            // An unknown status.
            entry("odd", "1", "available", "app"),
            entry("odd", "2", "active", "app"),
            // A revision snapd would not print.
            entry("bad-rev", "01", "installed", "app"),
            entry("bad-rev", "2", "active", "app"),
            // Types that differ between revisions.
            entry("mixed", "1", "installed", "kernel"),
            entry("mixed", "2", "active", "app"),
            // A name snapd would not accept.
            entry("Bad", "1", "installed", "app"),
            entry("Bad", "2", "active", "app"),
            entry("ok", "1", "installed", "app"),
            entry("ok", "2", "active", "app"),
        ]);
        assert_eq!(got, [("ok".into(), "1".into(), "2".into())]);
    }

    #[test]
    fn a_body_that_is_not_a_listing_is_an_error() {
        for body in [
            &b""[..],
            b"not json",
            b"{}",
            br#"{"type":"error","status-code":400,"result":{"message":"bad"}}"#,
            br#"{"type":"async","status-code":202,"result":[]}"#,
            br#"{"type":"sync","status-code":200,"result":{}}"#,
            br#"{"type":"sync","status-code":200,"result":[{"name":"a","revision":"1","status":"installed"}]}"#,
            br#"{"type":"sync","status-code":200,"result":[{"name":"a","revision":1,"status":"installed","type":"app"}]}"#,
        ] {
            assert!(
                disabled_revisions(body).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        assert_eq!(
            disabled_revisions(br#"{"type":"sync","status-code":200,"result":[]}"#).unwrap(),
            []
        );
    }
}
