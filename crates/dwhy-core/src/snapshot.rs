//! Snapshots (M3): compact records of scans, kept so later runs can tell
//! what grew (docs/DESIGN.md, "Growth without a background job").
//!
//! `dwhy scan --snapshot` saves one as gzip-compressed `diskwhy/v1` JSON in
//! `$XDG_STATE_HOME/diskwhy/snapshots/` (default
//! `~/.local/state/diskwhy/snapshots/`), named
//! `<YYYYMMDDTHHMMSSZ>-<scope>[-<n>].json.gz`. The scope is a hash of the
//! host, uid, scan roots and `one_filesystem`, so snapshots of the same
//! roots can be found and pruned together. Saving one prunes old ones
//! ([`to_prune`]); only files with that name pattern are ever removed.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use time::format_description::well_known::Rfc3339;

use crate::docker;
use crate::report::{
    SCHEMA, SavedSnapshot, ScanReport, Snapshot, SnapshotContainer, SnapshotDir, SnapshotDocker,
    SnapshotFinding, SnapshotFs, SnapshotImage, SnapshotScan, SnapshotVolume, Tool, check_schema,
};
use crate::tree::ScanTree;

/// Directories at least this large are recorded.
pub const MIN_DIR_BYTES: u64 = 100 << 20;
/// Every snapshot younger than this is kept.
pub const KEEP_ALL_SECS: i64 = 48 * 3600;
/// Older snapshots are kept up to this age, the newest per UTC day of each scope.
pub const KEEP_DAILY_SECS: i64 = 90 * 86_400;

const SUFFIX: &str = ".json.gz";
/// A snapshot of `/` is a few MB of JSON; anything far bigger is not one.
const MAX_JSON_BYTES: u64 = 512 << 20;

/// `$XDG_STATE_HOME/diskwhy/snapshots`, else `$HOME/.local/state/diskwhy/snapshots`.
pub fn default_dir() -> Option<PathBuf> {
    Some(crate::system::state_dir()?.join("snapshots"))
}

/// Builds the snapshot of a finished scan. `docker` is the daemon's state
/// when the Docker detectors fetched it.
pub fn build(
    report: &ScanReport,
    tree: &ScanTree,
    docker: Option<&docker::Snapshot>,
    min_dir_bytes: u64,
) -> Snapshot {
    let mut dirs: Vec<SnapshotDir> = tree
        .ids()
        .filter_map(|id| {
            let n = tree.node(id);
            (n.is_dir && n.total.allocated >= min_dir_bytes).then(|| SnapshotDir {
                path: tree.path(id).to_string_lossy().into_owned(),
                allocated: n.total.allocated,
                apparent: n.total.apparent,
                files: n.total.files,
            })
        })
        .collect();
    dirs.sort_by(|a, b| b.allocated.cmp(&a.allocated).then(a.path.cmp(&b.path)));
    Snapshot {
        schema: SCHEMA.into(),
        tool: Tool::current(),
        host: report.host.clone(),
        uid: report.uid,
        created_at: report.generated_at.clone(),
        scan: SnapshotScan {
            roots: report.scan.roots.iter().map(|r| r.path.clone()).collect(),
            one_filesystem: report.scan.one_filesystem,
            min_dir_bytes,
            totals: report.scan.totals,
            detectors: report
                .detectors
                .iter()
                .filter(|d| d.ran && d.error.is_none())
                .map(|d| d.name.clone())
                .collect(),
            skipped_mounts: report
                .scan
                .skipped_mounts
                .iter()
                .map(|m| m.path.clone())
                .collect(),
        },
        dirs,
        fs: report
            .fs
            .iter()
            .map(|f| SnapshotFs {
                mount: f.mount.clone(),
                fstype: f.fstype.clone(),
                size: f.size,
                used: f.used,
                avail: f.avail,
                scanned: f.scanned,
            })
            .collect(),
        docker: docker.map(docker_part),
        findings: report
            .findings
            .iter()
            .map(|f| SnapshotFinding {
                id: f.id.clone(),
                detector: f.detector.clone(),
                path: f.path.clone(),
                bytes: f.bytes,
                tier: f.tier,
            })
            .collect(),
    }
}

/// The Docker part of a snapshot, from the daemon's figures.
pub fn docker_part(s: &docker::Snapshot) -> SnapshotDocker {
    let pos = |v: i64| v.max(0) as u64;
    SnapshotDocker {
        usage: docker::usage(s),
        images: s
            .images()
            .iter()
            .map(|i| SnapshotImage {
                id: i.id.clone(),
                tags: i
                    .repo_tags
                    .iter()
                    .flatten()
                    .filter(|t| t.as_str() != "<none>:<none>")
                    .cloned()
                    .collect(),
                bytes: pos(i.size),
            })
            .collect(),
        containers: s
            .containers()
            .iter()
            .map(|c| SnapshotContainer {
                id: c.id.clone(),
                name: c
                    .names
                    .first()
                    .map(|n| n.trim_start_matches('/').to_string())
                    .unwrap_or_default(),
                image: c.image.clone(),
                state: c.state.clone(),
                bytes: c.size_rw.map(pos),
            })
            .collect(),
        volumes: s
            .volumes()
            .iter()
            .map(|v| SnapshotVolume {
                name: v.name.clone(),
                bytes: v
                    .usage_data
                    .as_ref()
                    .filter(|u| u.size >= 0)
                    .map(|u| u.size as u64),
            })
            .collect(),
    }
}

/// 8 hex digits identifying the host, uid, roots (in any order) and
/// `one_filesystem`.
pub fn scope(host: &str, uid: u32, roots: &[String], one_filesystem: bool) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let uid = uid.to_string();
    let mut sorted: Vec<&str> = roots.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let parts = [host, uid.as_str(), if one_filesystem { "x" } else { "c" }]
        .into_iter()
        .chain(sorted);
    for part in parts {
        for b in part.bytes().chain(std::iter::once(0u8)) {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{:08x}", h >> 32)
}

/// The scope of a snapshot's own host, uid and roots.
pub fn scope_of(s: &Snapshot) -> String {
    scope(&s.host, s.uid, &s.scan.roots, s.scan.one_filesystem)
}

/// Seconds since the epoch for an RFC 3339 time.
pub fn parse_time(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

/// `YYYYMMDDTHHMMSSZ` (UTC).
fn compact_time(secs: i64) -> String {
    let t =
        time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn parse_compact_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let p = s.get(r)?;
        p.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| p.parse().ok())?
    };
    let date = time::Date::from_calendar_date(
        digits(0..4)? as i32,
        time::Month::try_from(digits(4..6)? as u8).ok()?,
        digits(6..8)? as u8,
    )
    .ok()?;
    let tod = time::Time::from_hms(
        digits(9..11)? as u8,
        digits(11..13)? as u8,
        digits(13..15)? as u8,
    )
    .ok()?;
    Some(
        time::PrimitiveDateTime::new(date, tod)
            .assume_utc()
            .unix_timestamp(),
    )
}

/// One snapshot file in the snapshot directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The file name without `.json.gz`.
    pub id: String,
    pub path: PathBuf,
    /// Seconds since the epoch, from the name.
    pub created: i64,
    pub scope: String,
}

/// Splits an id into its creation time and scope; `None` when it is not
/// a snapshot id.
pub fn parse_id(id: &str) -> Option<(i64, String)> {
    let mut parts = id.split('-');
    let created = parse_compact_time(parts.next()?)?;
    let scope = parts.next()?;
    if scope.len() != 8 || !scope.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if let Some(n) = parts.next()
        && (n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    if parts.next().is_some() {
        return None;
    }
    Some((created, scope.to_string()))
}

/// The snapshots in `dir`, oldest first. A missing directory has none.
/// Anything that is not a regular file with a snapshot name is ignored.
pub fn list(dir: &Path) -> Result<Vec<Entry>, String> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot list {}: {e}", dir.display())),
    };
    let mut out = Vec::new();
    for ent in rd {
        let ent = ent.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let name = ent.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_suffix(SUFFIX)) else {
            continue;
        };
        let Some((created, scope)) = parse_id(id) else {
            continue;
        };
        if !ent.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        out.push(Entry {
            id: id.to_string(),
            path: ent.path(),
            created,
            scope,
        });
    }
    out.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}

/// The retention policy: which of `entries` to delete at `now`. Every
/// snapshot younger than [`KEEP_ALL_SECS`] is kept; up to
/// [`KEEP_DAILY_SECS`] the newest of each UTC day is kept, per scope;
/// anything older goes.
pub fn to_prune(entries: &[Entry], now: i64) -> Vec<&Entry> {
    let day = |e: &Entry| e.created.div_euclid(86_400);
    let mut newest: HashMap<(&str, i64), &Entry> = HashMap::new();
    for e in entries {
        let slot = newest.entry((e.scope.as_str(), day(e))).or_insert(e);
        if (e.created, &e.id) > (slot.created, &slot.id) {
            *slot = e;
        }
    }
    entries
        .iter()
        .filter(|e| {
            let age = now - e.created;
            if age < KEEP_ALL_SECS {
                false
            } else if age > KEEP_DAILY_SECS {
                true
            } else {
                newest[&(e.scope.as_str(), day(e))].id != e.id
            }
        })
        .collect()
}

/// Deletes the snapshots in `dir` the retention policy no longer keeps,
/// never `keep`. Returns how many were deleted and, when any could not be
/// listed or deleted, the first error (it keeps going after one).
pub fn prune(dir: &Path, now: i64, keep: &str) -> (u64, Option<String>) {
    let entries = match list(dir) {
        Ok(e) => e,
        Err(e) => return (0, Some(e)),
    };
    let mut n = 0;
    let mut first_err = None;
    for e in to_prune(&entries, now) {
        if e.id == keep {
            continue;
        }
        match fs::remove_file(&e.path) {
            Ok(()) => n += 1,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                first_err
                    .get_or_insert_with(|| format!("cannot prune {}: {err}", e.path.display()));
            }
        }
    }
    (n, first_err)
}

/// A saved snapshot, and why pruning failed when it did (the snapshot is
/// saved either way).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub snapshot: SavedSnapshot,
    pub prune_error: Option<String>,
}

/// Writes `snap` to `dir` (created 0700 when missing) as a new 0600 file,
/// never replacing one, then prunes old snapshots. An `Err` means nothing
/// was saved.
pub fn save(dir: &Path, snap: &Snapshot, now: i64) -> Result<Saved, String> {
    let created = parse_time(&snap.created_at)
        .ok_or_else(|| format!("bad created_at {:?}", snap.created_at))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    serde_json::to_writer(&mut enc, snap).map_err(|e| e.to_string())?;
    let data = enc.finish().map_err(|e| e.to_string())?;

    let base = format!("{}-{}", compact_time(created), scope_of(snap));
    let tmp = dir.join(format!(".tmp-{}-{base}", std::process::id()));
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(&data)?;
            f.sync_all()
        });
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", tmp.display()));
    }
    // A hard link never replaces an existing name, unlike rename.
    let mut linked = None;
    for n in 0..1000 {
        let id = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        let path = dir.join(format!("{id}{SUFFIX}"));
        match fs::hard_link(&tmp, &path) {
            Ok(()) => {
                linked = Some((id, path));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(format!("cannot save {}: {e}", path.display()));
            }
        }
    }
    let _ = fs::remove_file(&tmp);
    let (id, path) = linked.ok_or_else(|| format!("too many snapshots named {base}"))?;
    let (pruned, prune_error) = prune(dir, now, &id);
    Ok(Saved {
        snapshot: SavedSnapshot {
            id,
            path: path.to_string_lossy().into_owned(),
            pruned,
        },
        prune_error,
    })
}

/// Reads a snapshot file.
pub fn load(path: &Path) -> Result<Snapshot, String> {
    let f = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut json = Vec::new();
    GzDecoder::new(f)
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut json)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if json.len() as u64 > MAX_JSON_BYTES {
        return Err(format!("{}: too large for a snapshot", path.display()));
    }
    let snap: Snapshot = serde_json::from_slice(&json)
        .map_err(|e| format!("{}: not a diskwhy snapshot: {e}", path.display()))?;
    check_schema(&snap.schema).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(snap)
}

/// Which snapshot to compare with (`diff --since`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Since {
    /// The newest.
    Last,
    /// The newest at least this many seconds old.
    Age(i64),
    /// The newest taken at or before this time (seconds since the epoch).
    At(i64),
    /// A snapshot in the snapshot directory, by id.
    Id(String),
    /// A snapshot file anywhere.
    File(PathBuf),
}

/// Parses `last`, a snapshot id, a duration (`24h`, `7d`), an RFC 3339
/// time, or a path to a snapshot file (one containing `/` or ending in
/// `.json.gz`).
pub fn parse_since(s: &str) -> Result<Since, String> {
    if s == "last" {
        return Ok(Since::Last);
    }
    if parse_id(s).is_some() {
        return Ok(Since::Id(s.to_string()));
    }
    if s.starts_with(|c: char| c.is_ascii_digit())
        && let Ok(secs) = crate::units::parse_duration(s)
    {
        return Ok(Since::Age(secs));
    }
    if let Some(t) = parse_time(s) {
        return Ok(Since::At(t));
    }
    if s.contains('/') || s.ends_with(SUFFIX) {
        return Ok(Since::File(PathBuf::from(s)));
    }
    Err(format!(
        "--since {s:?}: expected last, a snapshot id or file, a duration such as 24h or 7d, \
         or an RFC 3339 time"
    ))
}

/// A snapshot picked to compare with.
#[derive(Debug, Clone)]
pub struct Found {
    /// Its id, when its file has a snapshot name.
    pub id: Option<String>,
    pub path: PathBuf,
    pub snapshot: Snapshot,
}

/// Roots in any order, duplicates ignored.
pub fn same_roots(a: &[String], b: &[String]) -> bool {
    fn norm(v: &[String]) -> Vec<&str> {
        let mut v: Vec<&str> = v.iter().map(String::as_str).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
    norm(a) == norm(b)
}

/// Finds the snapshot `since` names in `dir`. It must be of `host` and
/// `uid`. With `roots` (and `one_filesystem`), `last`, a duration or a time
/// pick only snapshots of exactly those roots; without, any. An id or file
/// is taken whatever its roots. Snapshots that cannot be read are skipped
/// when picking the newest.
pub fn find(
    dir: &Path,
    since: &Since,
    host: &str,
    uid: u32,
    roots: Option<(&[String], bool)>,
    now: i64,
) -> Result<Found, String> {
    let check = |s: &Snapshot, path: &Path| {
        if s.host != host {
            Err(format!(
                "{} is a snapshot of host {:?}, not {host:?}",
                path.display(),
                s.host
            ))
        } else if s.uid != uid {
            Err(format!(
                "{} is a snapshot taken as uid {}, not {uid}",
                path.display(),
                s.uid
            ))
        } else {
            Ok(())
        }
    };
    let cutoff = match since {
        Since::Id(id) => {
            let path = dir.join(format!("{id}{SUFFIX}"));
            let snapshot = load(&path)?;
            check(&snapshot, &path)?;
            return Ok(Found {
                id: Some(id.clone()),
                path,
                snapshot,
            });
        }
        Since::File(path) => {
            let snapshot = load(path)?;
            check(&snapshot, path)?;
            let id = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(SUFFIX))
                .filter(|n| parse_id(n).is_some())
                .map(str::to_string);
            return Ok(Found {
                id,
                path: path.clone(),
                snapshot,
            });
        }
        Since::Last => i64::MAX,
        Since::Age(secs) => now.saturating_sub(*secs),
        Since::At(t) => *t,
    };
    let want = roots.map(|(r, x)| scope(host, uid, r, x));
    let mut first_err = None;
    for e in list(dir)?.iter().rev() {
        if e.created > cutoff || want.as_ref().is_some_and(|w| *w != e.scope) {
            continue;
        }
        let s = match load(&e.path) {
            Ok(s) => s,
            Err(err) => {
                first_err.get_or_insert(err);
                continue;
            }
        };
        let fits = s.host == host
            && s.uid == uid
            && roots
                .is_none_or(|(r, x)| same_roots(r, &s.scan.roots) && s.scan.one_filesystem == x);
        if fits {
            return Ok(Found {
                id: Some(e.id.clone()),
                path: e.path.clone(),
                snapshot: s,
            });
        }
    }
    let which = match since {
        Since::Age(secs) => format!(" at least {} old", crate::units::age(*secs)),
        Since::At(_) => " that old".to_string(),
        _ => String::new(),
    };
    let of = match roots {
        Some((r, _)) => format!(" of {}", r.join(" ")),
        None => String::new(),
    };
    let mut msg = format!(
        "no snapshot{of}{which} in {}; save one with `dwhy scan --snapshot`",
        dir.display()
    );
    if let Some(e) = first_err {
        msg.push_str(&format!(" (some could not be read: {e})"));
    }
    Err(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_time_round_trips() {
        for secs in [0, 1_763_272_212, 1_798_761_599] {
            assert_eq!(parse_compact_time(&compact_time(secs)), Some(secs));
        }
        assert_eq!(compact_time(1_763_272_212), "20251116T055012Z");
        assert_eq!(parse_compact_time("20251316T055012Z"), None);
        assert_eq!(parse_compact_time("2025111aT055012Z"), None);
    }

    #[test]
    fn ids_parse() {
        assert_eq!(
            parse_id("20251116T055012Z-0123abcd"),
            Some((1_763_272_212, "0123abcd".into()))
        );
        assert!(parse_id("20251116T055012Z-0123abcd-2").is_some());
        assert_eq!(parse_id("20251116T055012Z-0123abc"), None);
        assert_eq!(parse_id("20251116T055012Z-0123abcd-"), None);
        assert_eq!(parse_id("20251116T055012Z-0123abcd-2-3"), None);
        assert_eq!(parse_id("audit"), None);
    }

    #[test]
    fn scope_depends_on_every_part() {
        let r = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = scope("h", 1000, &r(&["/home/u"]), true);
        assert_eq!(a.len(), 8);
        assert_eq!(a, scope("h", 1000, &r(&["/home/u"]), true));
        assert_ne!(a, scope("g", 1000, &r(&["/home/u"]), true));
        assert_ne!(a, scope("h", 1001, &r(&["/home/u"]), true));
        assert_ne!(a, scope("h", 1000, &r(&["/home/u"]), false));
        assert_ne!(a, scope("h", 1000, &r(&["/home/u", "/srv"]), true));
        // Root order does not matter.
        assert_eq!(
            scope("h", 1000, &r(&["/srv", "/opt"]), true),
            scope("h", 1000, &r(&["/opt", "/srv"]), true)
        );
    }
}
