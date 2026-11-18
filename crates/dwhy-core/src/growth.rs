//! Growth (M3): what changed between a saved snapshot and a later one
//! (`dwhy diff`), growth over a short window (`dwhy watch`), and growth
//! rates on a scan's findings.
//!
//! `diff` rates are bytes per day over the time between the two snapshots,
//! `watch` rates bytes per minute over its window. Directory changes are
//! attributed to the deepest directory that holds most of them
//! ([`deepest`]) in both.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::report::{
    Change, ChangeKind, DiffBase, DiffReport, Finding, Growth, Rate, SCHEMA, Snapshot,
    SnapshotDocker, SnapshotScan, Tool, WatchReport,
};
use crate::snapshot::parse_time;

/// `scan` puts growth on findings from the newest snapshot at least this
/// old: a rate from a shorter window, scaled to a day, is mostly noise.
pub const MIN_AGE_SECS: i64 = 3600;

/// `change` bytes over `elapsed_secs`, per day. A non-positive interval
/// counts as one second.
pub fn per_day(change: i64, elapsed_secs: i64) -> i64 {
    let r = change as i128 * 86_400 / elapsed_secs.max(1) as i128;
    r.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// `change` bytes over `elapsed_ms` milliseconds, per minute. A
/// non-positive interval counts as one millisecond.
pub fn per_minute(change: i64, elapsed_ms: u64) -> i64 {
    let r = change as i128 * 60_000 / elapsed_ms.max(1) as i128;
    r.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn delta(before: Option<u64>, after: Option<u64>) -> i64 {
    let r = after.unwrap_or(0) as i128 - before.unwrap_or(0) as i128;
    r.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn depth(path: &str) -> usize {
    Path::new(path).components().count()
}

fn within(path: &Path, roots: &[String]) -> bool {
    roots.iter().any(|r| path.starts_with(r))
}

/// The mount point the scan skipped that kept its walk from `path`, a
/// path under its roots: one between the deepest root above it and it.
fn blocked_by<'a>(path: &Path, scan: &'a SnapshotScan) -> Option<&'a str> {
    let root = scan
        .roots
        .iter()
        .filter(|r| path.starts_with(r))
        .map(|r| depth(r))
        .max()?;
    scan.skipped_mounts
        .iter()
        .filter(|m| path.starts_with(m) && depth(m) > root)
        .max_by_key(|m| depth(m))
        .map(String::as_str)
}

/// Whether the scan walked `path`: it is under a root, and no mount point
/// the walk skipped lies between that root and it.
fn walked(path: &Path, scan: &SnapshotScan) -> bool {
    within(path, &scan.roots) && blocked_by(path, scan).is_none()
}

/// Mount points `side` skipped where `other` walked something it would
/// otherwise compare.
fn left_out<'a>(side: &'a SnapshotScan, other: &'a SnapshotScan) -> impl Iterator<Item = &'a str> {
    side.skipped_mounts.iter().map(String::as_str).filter(|m| {
        let m = Path::new(m);
        other.roots.iter().any(|r| {
            let r = Path::new(r);
            let top = if r.starts_with(m) {
                r
            } else if m.starts_with(r) {
                m
            } else {
                return false;
            };
            walked(top, other) && !walked(top, side)
        })
    })
}

/// What two snapshots differ by, before rates and ranking.
struct Compared {
    fs: Vec<Change>,
    dirs: Vec<Change>,
    /// `None` when one side has no Docker figures.
    docker: Option<Vec<Change>>,
    findings: Vec<Change>,
    /// Mount points that kept something out of the comparison.
    mounts_note: Option<String>,
    /// Detectors that ran on one side only.
    findings_note: Option<String>,
}

/// Compares `old` with `new`, a later snapshot. `size_now` gives the
/// current allocated size of a directory `new` does not record (one that
/// shrank below its threshold), `None` when it no longer exists. Only
/// paths both scans walked are compared: inside the roots of both, and not
/// at or below a mount point either skipped. When the two differ in
/// `one_filesystem`, directories above a mount point one side skipped and
/// the other walked are left out too: their totals cover different ground.
/// Rates are left at 0.
fn compare(
    old: &Snapshot,
    new: &Snapshot,
    size_now: &dyn Fn(&str) -> Option<u64>,
    min_change: u64,
    excluded: &dyn Fn(&str) -> bool,
) -> Compared {
    let above: Vec<&str> = if old.scan.one_filesystem != new.scan.one_filesystem {
        left_out(&old.scan, &new.scan)
            .chain(left_out(&new.scan, &old.scan))
            .collect()
    } else {
        Vec::new()
    };
    // The mount points that keep a path inside the roots of both out.
    let blockers = |path: &str| {
        let p = Path::new(path);
        let mut v: Vec<&str> = [blocked_by(p, &old.scan), blocked_by(p, &new.scan)]
            .into_iter()
            .flatten()
            .collect();
        v.extend(above.iter().filter(|m| Path::new(m).starts_with(p)));
        v
    };
    let in_roots = |path: &str| {
        let p = Path::new(path);
        within(p, &old.scan.roots) && within(p, &new.scan.roots)
    };
    let both = |path: &str| in_roots(path) && blockers(path).is_empty() && !excluded(path);
    let mut mounts: Vec<&str> = old
        .dirs
        .iter()
        .chain(&new.dirs)
        .map(|d| d.path.as_str())
        .chain(
            old.findings
                .iter()
                .chain(&new.findings)
                .map(|f| f.path.as_str()),
        )
        .filter(|p| p.starts_with('/') && in_roots(p))
        .flat_map(&blockers)
        .collect();
    mounts.sort_unstable();
    mounts.dedup();
    let mounts_note = (!mounts.is_empty()).then(|| {
        format!(
            "not compared, because one side did not enter these mount points: {}",
            mounts.join(", ")
        )
    });
    let change = |kind: ChangeKind, name: String, before: Option<u64>, after: Option<u64>| Change {
        kind,
        name,
        id: None,
        detector: None,
        before,
        after,
        change: delta(before, after),
        at_least: false,
        bytes_per_day: 0,
    };
    let big = |c: &Change| c.change != 0 && c.change.unsigned_abs() >= min_change;

    // Filesystems in both, changed or not.
    let fs: Vec<Change> = new
        .fs
        .iter()
        .filter_map(|n| {
            let o = old.fs.iter().find(|o| o.mount == n.mount)?;
            Some(change(
                ChangeKind::Fs,
                n.mount.clone(),
                Some(o.used),
                Some(n.used),
            ))
        })
        .collect();

    // Directories.
    let new_dirs: HashMap<&str, u64> = new
        .dirs
        .iter()
        .map(|d| (d.path.as_str(), d.allocated))
        .collect();
    let old_dirs: HashSet<&str> = old.dirs.iter().map(|d| d.path.as_str()).collect();
    let mut dirs: Vec<Change> = Vec::new();
    for d in old.dirs.iter().filter(|d| both(&d.path)) {
        let after = new_dirs
            .get(d.path.as_str())
            .copied()
            .or_else(|| size_now(&d.path));
        dirs.push(change(
            ChangeKind::Dir,
            d.path.clone(),
            Some(d.allocated),
            after,
        ));
    }
    let floor = old.scan.min_dir_bytes;
    for d in new.dirs.iter() {
        if old_dirs.contains(d.path.as_str()) || !both(&d.path) || d.allocated < floor {
            continue;
        }
        // It was below the snapshot's threshold: at least this much growth.
        // (With no threshold, every directory was recorded: it is new.)
        let mut c = change(ChangeKind::Dir, d.path.clone(), None, Some(d.allocated));
        c.change = delta(Some(floor), Some(d.allocated));
        c.at_least = floor > 0;
        dirs.push(c);
    }
    dirs.retain(big);
    let dirs = deepest(dirs);

    // Docker.
    let docker = match (&old.docker, &new.docker) {
        (Some(o), Some(n)) => {
            let mut v = docker_changes(o, n, &change);
            v.retain(big);
            Some(v)
        }
        _ => None,
    };

    // Findings, by id, where the detector ran on both sides.
    let ran_old: HashSet<&str> = old.scan.detectors.iter().map(String::as_str).collect();
    let ran_new: HashSet<&str> = new.scan.detectors.iter().map(String::as_str).collect();
    let in_scope = |path: &str| !path.starts_with('/') || both(path);
    let mut findings = Vec::new();
    let mut skipped: Vec<&str> = Vec::new();
    let old_f: HashMap<&str, _> = old.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let new_f: HashMap<&str, _> = new.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    for f in &old.findings {
        if !in_scope(&f.path) {
            continue;
        }
        let after = match new_f.get(f.id.as_str()) {
            Some(n) => Some(n.bytes),
            None if ran_new.contains(f.detector.as_str()) => None,
            None => {
                skipped.push(&f.detector);
                continue;
            }
        };
        let mut c = change(ChangeKind::Finding, f.path.clone(), Some(f.bytes), after);
        c.id = Some(f.id.clone());
        c.detector = Some(f.detector.clone());
        findings.push(c);
    }
    for f in &new.findings {
        if old_f.contains_key(f.id.as_str()) || !in_scope(&f.path) {
            continue;
        }
        if !ran_old.contains(f.detector.as_str()) {
            skipped.push(&f.detector);
            continue;
        }
        let mut c = change(ChangeKind::Finding, f.path.clone(), None, Some(f.bytes));
        c.id = Some(f.id.clone());
        c.detector = Some(f.detector.clone());
        findings.push(c);
    }
    findings.retain(big);
    skipped.sort_unstable();
    skipped.dedup();
    let findings_note = (!skipped.is_empty()).then(|| {
        format!(
            "findings not compared (detector ran on one side only): {}",
            skipped.join(", ")
        )
    });
    Compared {
        fs,
        dirs,
        docker,
        findings,
        mounts_note,
        findings_note,
    }
}

/// Compares `old` with `new`, a snapshot of a fresh scan (see [`compare`]
/// for what is compared), with rates in bytes per day.
pub fn diff(
    old: &Snapshot,
    old_id: Option<String>,
    old_path: String,
    new: &Snapshot,
    size_now: &dyn Fn(&str) -> Option<u64>,
    min_change: u64,
) -> DiffReport {
    let elapsed = match (parse_time(&new.created_at), parse_time(&old.created_at)) {
        (Some(n), Some(o)) => n - o,
        _ => 0,
    };
    let c = compare(old, new, size_now, min_change, &|_| false);
    let mut notes: Vec<String> = c.mounts_note.into_iter().collect();
    match (&old.docker, &new.docker) {
        (Some(_), Some(_)) => {}
        (None, Some(_)) => notes.push("Docker not compared: the snapshot has no Docker figures".into()),
        (Some(_), None) => notes.push(
            "Docker not compared: no Docker figures now (daemon unreachable, or Docker detectors not run)"
                .into(),
        ),
        (None, None) => {
            notes.push("Docker not compared: neither side has Docker figures".into())
        }
    }
    notes.extend(c.findings_note);
    let docker_compared = c.docker.is_some();
    let [mut fs, mut dirs, mut docker, mut findings] =
        [c.fs, c.dirs, c.docker.unwrap_or_default(), c.findings];
    for list in [&mut fs, &mut dirs, &mut docker, &mut findings] {
        for x in list.iter_mut() {
            x.bytes_per_day = per_day(x.change, elapsed);
        }
        rank(list);
    }
    DiffReport {
        schema: SCHEMA.into(),
        tool: Tool::current(),
        host: new.host.clone(),
        uid: new.uid,
        generated_at: new.created_at.clone(),
        since: DiffBase {
            id: old_id,
            path: old_path,
            created_at: old.created_at.clone(),
            roots: old.scan.roots.clone(),
            one_filesystem: old.scan.one_filesystem,
            min_dir_bytes: old.scan.min_dir_bytes,
        },
        roots: new.scan.roots.clone(),
        one_filesystem: new.scan.one_filesystem,
        elapsed_secs: elapsed,
        min_change,
        fs,
        dirs,
        docker_compared,
        docker,
        findings,
        notes,
        snapshot: None,
    }
}

/// Growth over a `watch` window: `start` and `end` are snapshots of two
/// walks of the same roots that record every directory (`min_dir_bytes`
/// 0), taken `elapsed_ms` apart (from the start of one walk to the start
/// of the next). Compared as in [`diff`], with rates in bytes per minute.
/// `notes` says nothing about Docker; the caller knows why it is missing.
pub fn watch(
    start: &Snapshot,
    end: &Snapshot,
    for_secs: u64,
    elapsed_ms: u64,
    min_change: u64,
    unreadable: [&[String]; 2],
) -> WatchReport {
    let [old_unreadable, new_unreadable] =
        unreadable.map(|paths| paths.iter().map(String::as_str).collect::<HashSet<_>>());
    let changed_coverage: HashSet<&str> = old_unreadable
        .symmetric_difference(&new_unreadable)
        .copied()
        .collect();
    let [old_mounts, new_mounts] = [start, end].map(|s| {
        s.scan
            .skipped_mounts
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>()
    });
    let changed_mounts: Vec<&str> = old_mounts
        .symmetric_difference(&new_mounts)
        .copied()
        .collect();
    let uncertain_hardlinks = (!changed_coverage.is_empty() || !changed_mounts.is_empty())
        && [start, end]
            .iter()
            .any(|s| s.scan.totals.hardlinks_deduped > 0);
    let all_unreadable: HashSet<&str> = old_unreadable.union(&new_unreadable).copied().collect();
    let blockers = |path: &str| {
        let path = Path::new(path);
        all_unreadable
            .iter()
            .copied()
            .filter(|failed| {
                path.starts_with(failed)
                    || (changed_coverage.contains(failed) && Path::new(failed).starts_with(path))
            })
            .collect::<Vec<_>>()
    };
    let mount_blockers = |path: &str| {
        let path = Path::new(path);
        changed_mounts
            .iter()
            .copied()
            .filter(|mount| Path::new(mount).starts_with(path) && Path::new(mount) != path)
            .collect::<Vec<_>>()
    };
    let c = compare(start, end, &|_| None, min_change, &|path| {
        uncertain_hardlinks || !blockers(path).is_empty() || !mount_blockers(path).is_empty()
    });
    let mut omitted: Vec<&str> = start
        .dirs
        .iter()
        .chain(&end.dirs)
        .filter(|d| {
            let path = Path::new(&d.path);
            within(path, &start.scan.roots) && within(path, &end.scan.roots)
        })
        .flat_map(|d| blockers(&d.path))
        .collect();
    omitted.sort_unstable();
    omitted.dedup();
    let mut omitted_mounts: Vec<&str> = start
        .dirs
        .iter()
        .chain(&end.dirs)
        .filter(|d| {
            let path = Path::new(&d.path);
            within(path, &start.scan.roots) && within(path, &end.scan.roots)
        })
        .flat_map(|d| mount_blockers(&d.path))
        .collect();
    omitted_mounts.sort_unstable();
    omitted_mounts.dedup();
    let mut notes: Vec<String> = c.mounts_note.into_iter().collect();
    if !omitted.is_empty() {
        notes.push(format!(
            "not compared, because a sample could not read these paths: {}",
            omitted.join(", ")
        ));
    }
    if !omitted_mounts.is_empty() {
        notes.push(format!(
            "not compared, because a mount changed during the window: {}",
            omitted_mounts.join(", ")
        ));
    }
    if uncertain_hardlinks {
        notes.push(
            "directories not compared: coverage changed during the window, and files with several hard links may be counted in different places"
                .into(),
        );
    }
    let rates = |list: Vec<Change>| {
        let mut v: Vec<Rate> = list
            .into_iter()
            .map(|x| Rate {
                kind: x.kind,
                name: x.name,
                id: x.id,
                before: x.before,
                after: x.after,
                change: x.change,
                bytes_per_minute: per_minute(x.change, elapsed_ms),
            })
            .collect();
        v.sort_by(|a, b| {
            b.bytes_per_minute
                .cmp(&a.bytes_per_minute)
                .then_with(|| b.change.cmp(&a.change))
                .then_with(|| a.name.cmp(&b.name))
        });
        v
    };
    WatchReport {
        schema: SCHEMA.into(),
        tool: Tool::current(),
        host: end.host.clone(),
        uid: end.uid,
        started_at: start.created_at.clone(),
        generated_at: end.created_at.clone(),
        roots: end.scan.roots.clone(),
        one_filesystem: end.scan.one_filesystem,
        for_secs,
        elapsed_ms,
        min_change,
        fs: rates(c.fs),
        dirs: rates(c.dirs),
        docker_compared: c.docker.is_some(),
        docker: rates(c.docker.unwrap_or_default()),
        notes,
    }
}

fn docker_changes(
    o: &SnapshotDocker,
    n: &SnapshotDocker,
    change: &dyn Fn(ChangeKind, String, Option<u64>, Option<u64>) -> Change,
) -> Vec<Change> {
    // Each side: (kind, id) -> (name, bytes); bytes is `None` when the
    // daemon did not compute the size.
    type Objects = HashMap<(u8, String), (ChangeKind, String, Option<u64>)>;
    let objects = |d: &SnapshotDocker| {
        let mut v: Objects = HashMap::new();
        for i in &d.images {
            let short = i.id.trim_start_matches("sha256:");
            let name = i
                .tags
                .first()
                .cloned()
                .unwrap_or_else(|| short.chars().take(12).collect());
            let k = ChangeKind::Image;
            v.insert((k as u8, i.id.clone()), (k, name, Some(i.bytes)));
        }
        for c in &d.containers {
            let k = ChangeKind::Container;
            v.insert((k as u8, c.id.clone()), (k, c.name.clone(), c.bytes));
        }
        for vol in &d.volumes {
            let k = ChangeKind::Volume;
            v.insert(
                (k as u8, vol.name.clone()),
                (k, vol.name.clone(), vol.bytes),
            );
        }
        v
    };
    let (ov, nv) = (objects(o), objects(n));
    let mut out = Vec::new();
    // An object whose size is unknown on a side it is on is left out.
    let mut keys: Vec<&(u8, String)> = ov.keys().chain(nv.keys()).collect();
    keys.sort_unstable();
    keys.dedup();
    for key in keys {
        let (before, after) = (ov.get(key), nv.get(key));
        if before.is_some_and(|b| b.2.is_none()) || after.is_some_and(|a| a.2.is_none()) {
            continue;
        }
        let (kind, name) = match after.or(before) {
            Some((k, name, _)) => (*k, name.clone()),
            None => continue,
        };
        let mut c = change(
            kind,
            name,
            before.and_then(|b| b.2),
            after.and_then(|a| a.2),
        );
        if kind != ChangeKind::Volume {
            c.id = Some(key.1.clone());
        }
        out.push(c);
    }
    out.push(change(
        ChangeKind::BuildCache,
        "build cache".into(),
        Some(o.usage.build_cache.bytes),
        Some(n.usage.build_cache.bytes),
    ));
    out
}

/// Fastest growth first, fastest shrinkage last.
fn rank(list: &mut [Change]) {
    list.sort_by(|a, b| {
        b.bytes_per_day
            .cmp(&a.bytes_per_day)
            .then_with(|| b.change.cmp(&a.change))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// Attributes directory changes to the deepest directory that holds most
/// of them: a directory is dropped when a directory below it (the nearest
/// listed one on that branch) changed by more than half as much in the
/// same direction. `dirs` are named by absolute path.
pub fn deepest(dirs: Vec<Change>) -> Vec<Change> {
    let index: HashMap<&str, usize> = dirs
        .iter()
        .enumerate()
        .map(|(i, c)| (c.name.as_str(), i))
        .collect();
    let mut dropped = vec![false; dirs.len()];
    for c in &dirs {
        let parent = Path::new(&c.name)
            .ancestors()
            .skip(1)
            .find_map(|a| a.to_str().and_then(|a| index.get(a)));
        if let Some(&p) = parent {
            let outer = dirs[p].change;
            if c.change.signum() == outer.signum()
                && c.change != 0
                && c.change.unsigned_abs() as u128 * 2 > outer.unsigned_abs() as u128
            {
                dropped[p] = true;
            }
        }
    }
    dirs.into_iter()
        .zip(dropped)
        .filter_map(|(c, d)| (!d).then_some(c))
        .collect()
}

/// Sets `growth` on each finding `old` also has (matched by id), measured
/// from `old` to `now` (RFC 3339). Nothing is set when `old` is not older.
pub fn fill_growth(findings: &mut [Finding], old: &Snapshot, now: &str) {
    let (Some(t_now), Some(t_old)) = (parse_time(now), parse_time(&old.created_at)) else {
        return;
    };
    let elapsed = t_now - t_old;
    if elapsed <= 0 {
        return;
    }
    let before: HashMap<&str, u64> = old
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f.bytes))
        .collect();
    for f in findings {
        if let Some(&b) = before.get(f.id.as_str()) {
            f.growth = Some(Growth {
                bytes_per_day: per_day(delta(Some(b), Some(f.bytes)), elapsed),
                since: old.created_at.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str, change: i64) -> Change {
        Change {
            kind: ChangeKind::Dir,
            name: name.into(),
            id: None,
            detector: None,
            before: None,
            after: None,
            change,
            at_least: false,
            bytes_per_day: change,
        }
    }

    fn names(v: &[Change]) -> Vec<&str> {
        v.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn rates() {
        assert_eq!(per_day(1000, 86_400), 1000);
        assert_eq!(per_day(1000, 3600), 24_000);
        assert_eq!(per_day(-500, 43_200), -1000);
        assert_eq!(per_day(5, 0), 432_000);
        assert_eq!(per_day(i64::MAX, 1), i64::MAX);
        assert_eq!(per_minute(1000, 60_000), 1000);
        assert_eq!(per_minute(1000, 30_000), 2000);
        assert_eq!(per_minute(-600, 61_000), -590);
        assert_eq!(per_minute(5, 0), 300_000);
        assert_eq!(per_minute(i64::MIN, 1), i64::MIN);
    }

    #[test]
    fn growth_goes_to_the_deepest_dir_holding_most_of_it() {
        // One cause deep down: only the deepest is listed.
        let v = deepest(vec![dir("/h", 100), dir("/h/c", 98), dir("/h/c/pip", 97)]);
        assert_eq!(names(&v), ["/h/c/pip"]);
        // Split 6/4: both children, not the parent.
        let v = deepest(vec![dir("/h", 10), dir("/h/a", 6), dir("/h/b", 4)]);
        assert_eq!(names(&v), ["/h/a", "/h/b"]);
        // Spread 3/3/4: no child holds most, so the parent stays too.
        let v = deepest(vec![
            dir("/h", 10),
            dir("/h/a", 3),
            dir("/h/b", 3),
            dir("/h/c", 4),
        ]);
        assert_eq!(names(&v), ["/h", "/h/a", "/h/b", "/h/c"]);
        // Opposite directions never hide the parent.
        let v = deepest(vec![dir("/h", 10), dir("/h/a", -20)]);
        assert_eq!(names(&v), ["/h", "/h/a"]);
        // Exactly half is not "more than half".
        let v = deepest(vec![dir("/h", 10), dir("/h/a", 5)]);
        assert_eq!(names(&v), ["/h", "/h/a"]);
        // The nearest listed dir on the branch counts, not only a child;
        // a sibling with a common name prefix is not below it.
        let v = deepest(vec![dir("/h", 10), dir("/h/x/y", 9), dir("/hh", 50)]);
        assert_eq!(names(&v), ["/h/x/y", "/hh"]);
    }
}
