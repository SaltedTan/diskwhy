//! Growth (M3): what changed between a saved snapshot and a later one
//! (`dwhy diff`), and growth rates on a scan's findings.
//!
//! Rates are bytes per day over the time between the two snapshots.
//! Directory changes are attributed to the deepest directory that holds
//! most of them ([`deepest`]), the rule `watch` shares.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::report::{
    Change, ChangeKind, DiffBase, DiffReport, Finding, Growth, SCHEMA, Snapshot, SnapshotDocker,
    SnapshotScan, Tool,
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

fn delta(before: Option<u64>, after: Option<u64>) -> i64 {
    let r = after.unwrap_or(0) as i128 - before.unwrap_or(0) as i128;
    r.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Whether the scan walked `path`: it is under a root, and no mount point
/// the walk skipped lies between that root and it.
fn walked(path: &Path, scan: &SnapshotScan) -> bool {
    let deepest = |v: &[String]| {
        v.iter()
            .filter(|a| path.starts_with(a))
            .map(|a| Path::new(a).components().count())
            .max()
    };
    match (deepest(&scan.roots), deepest(&scan.skipped_mounts)) {
        (Some(root), Some(mount)) => root >= mount,
        (root, _) => root.is_some(),
    }
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

/// Compares `old` with `new`, a snapshot of a fresh scan. `size_now` gives
/// the current allocated size of a directory `new` does not record (one
/// that shrank below its threshold), `None` when it no longer exists.
/// Only paths both scans walked are compared: inside the roots of both,
/// and not at or below a mount point either skipped. Directories above a
/// mount point one side skipped and the other walked are left out too:
/// their totals cover different ground.
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
    let mut mounts: Vec<&str> = left_out(&old.scan, &new.scan)
        .chain(left_out(&new.scan, &old.scan))
        .collect();
    mounts.sort_unstable();
    mounts.dedup();
    let both = |path: &str| {
        let p = Path::new(path);
        walked(p, &old.scan)
            && walked(p, &new.scan)
            && !mounts.iter().any(|m| Path::new(m).starts_with(p))
    };
    let mut notes = Vec::new();
    if !mounts.is_empty() {
        notes.push(format!(
            "not compared: paths at, below or above mount points one side did not enter: {}",
            mounts.join(", ")
        ));
    }
    let change = |kind: ChangeKind, name: String, before: Option<u64>, after: Option<u64>| {
        let c = delta(before, after);
        Change {
            kind,
            name,
            id: None,
            detector: None,
            before,
            after,
            change: c,
            at_least: false,
            bytes_per_day: per_day(c, elapsed),
        }
    };
    let big = |c: &Change| c.change != 0 && c.change.unsigned_abs() >= min_change;

    // Filesystems in both, changed or not.
    let mut fs: Vec<Change> = new
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
        let mut c = change(ChangeKind::Dir, d.path.clone(), None, Some(d.allocated));
        c.change = delta(Some(floor), Some(d.allocated));
        c.bytes_per_day = per_day(c.change, elapsed);
        c.at_least = true;
        dirs.push(c);
    }
    dirs.retain(big);
    let mut dirs = deepest(dirs);

    // Docker.
    let mut docker = Vec::new();
    match (&old.docker, &new.docker) {
        (Some(o), Some(n)) => docker = docker_changes(o, n, &change),
        (None, Some(_)) => notes.push("Docker not compared: the snapshot has no Docker figures".into()),
        (Some(_), None) => notes.push(
            "Docker not compared: no Docker figures now (daemon unreachable, or Docker detectors not run)"
                .into(),
        ),
        (None, None) => {
            notes.push("Docker not compared: neither side has Docker figures".into())
        }
    }
    docker.retain(big);

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
    if !skipped.is_empty() {
        notes.push(format!(
            "findings not compared (detector ran on one side only): {}",
            skipped.join(", ")
        ));
    }

    for list in [&mut fs, &mut dirs, &mut docker, &mut findings] {
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
        docker_compared: old.docker.is_some() && new.docker.is_some(),
        docker,
        findings,
        notes,
        snapshot: None,
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
