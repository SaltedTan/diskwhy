//! Snapshots: what a snapshot records, saving and loading, and retention.
//! Docker comes from the fixed snapshot in tests/data; no daemon is contacted.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use dwhy_core::account::{self, ReportEnv};
use dwhy_core::docker::{self, Info};
use dwhy_core::mounts::{FsStats, MountTable};
use dwhy_core::report::{
    Action, ActionKind, Finding, Recovery, SCHEMA, ScanReport, SkipReason, SkippedMount, Snapshot,
    Tier,
};
use dwhy_core::scan::{self, Progress, ScanOptions, ScanResult};
use dwhy_core::snapshot::{self, Entry, KEEP_DAILY_SECS};
use dwhy_core::system::DeletedOpenScan;

const DAY: i64 = 86_400;

/// A fake mount table in which `root` is a filesystem's mount point.
fn table_with_mount_at(root: &Path) -> MountTable {
    let dev = fs::metadata(root).unwrap().dev();
    let (ma, mi) = (rustix::fs::major(dev), rustix::fs::minor(dev));
    MountTable::parse(&format!(
        "1 0 {ma}:{mi} / {} rw shared:1 - ext4 /dev/fake rw\n",
        root.display()
    ))
}

fn scan_of(root: &Path) -> (ScanResult, MountTable) {
    let mounts = table_with_mount_at(root);
    let roots = scan::prepare_roots(&[root.to_path_buf()], true).unwrap();
    let opts = ScanOptions {
        threads: 2,
        ..ScanOptions::default()
    };
    let res = scan::scan(&roots, &opts, &mounts, &Progress::default()).unwrap();
    (res, mounts)
}

fn report_of(res: &ScanResult, mounts: &MountTable) -> ScanReport {
    let env = ReportEnv {
        host: "testhost".into(),
        uid: 1000,
        root: false,
        generated_at: "2026-11-16T06:00:00Z".into(),
        users: Vec::new(),
        deleted_open: DeletedOpenScan::default(),
        exe: "/usr/local/bin/dwhy".into(),
        docker_access: false,
    };
    let stats = |_: &Path| {
        Some(FsStats {
            size: 10 << 30,
            used: 4 << 30,
            avail: 6 << 30,
        })
    };
    account::build_scan_report(res, mounts, &env, &stats)
}

fn finding(path: &str, bytes: u64) -> Finding {
    Finding {
        id: dwhy_core::detect::finding_id("cargo-target", path),
        detector: "cargo-target".into(),
        probe: None,
        evidence: None,
        path: path.into(),
        bytes,
        nested_bytes: None,
        last_modified: None,
        growth: None,
        tier: Tier::Rebuildable,
        reason: "r".into(),
        guards: Vec::new(),
        action: Action {
            kind: ActionKind::RemovePath,
            text: "t".into(),
            argv: None,
        },
        recovery: Recovery {
            cost: "c".into(),
            how: None,
        },
    }
}

fn docker_fixture() -> docker::Snapshot {
    docker::Snapshot {
        df: docker::parse_system_df(include_bytes!("data/docker-system-df.json")).unwrap(),
        info: Info {
            driver: "overlayfs".into(),
            driver_status: None,
            docker_root_dir: "/var/lib/docker".into(),
        },
    }
}

/// big/ holds 3 MiB, small/ 16 KiB, and links/ a second link to big/'s file.
fn fixture() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir_all(r.join("big/inner")).unwrap();
    fs::create_dir_all(r.join("small")).unwrap();
    fs::create_dir_all(r.join("links")).unwrap();
    fs::write(r.join("big/inner/blob"), vec![7u8; 3 << 20]).unwrap();
    fs::write(r.join("small/f"), vec![1u8; 16 << 10]).unwrap();
    fs::hard_link(r.join("big/inner/blob"), r.join("links/blob")).unwrap();
    t
}

#[test]
fn build_records_large_dirs_fs_findings_and_docker() {
    let t = fixture();
    let r = fs::canonicalize(t.path()).unwrap();
    let (res, mounts) = scan_of(&r);
    let mut rep = report_of(&res, &mounts);
    let root = r.to_string_lossy().into_owned();
    rep.findings = vec![finding(&format!("{root}/big"), 3 << 20)];
    rep.scan.skipped_mounts = vec![SkippedMount {
        path: format!("{root}/mnt"),
        fstype: Some("ext4".into()),
        reason: SkipReason::OtherFilesystem,
    }];
    let dock = docker_fixture();
    let s = snapshot::build(&rep, &res.tree, Some(&dock), 1 << 20);

    assert_eq!(s.schema, SCHEMA);
    assert_eq!(s.host, "testhost");
    assert_eq!(s.created_at, "2026-11-16T06:00:00Z");
    assert_eq!(s.scan.roots, vec![root.clone()]);
    assert!(s.scan.one_filesystem);
    assert_eq!(s.scan.min_dir_bytes, 1 << 20);
    assert_eq!(s.scan.totals, rep.scan.totals);
    assert_eq!(s.scan.skipped_mounts, vec![format!("{root}/mnt")]);

    // The hardlinked blob counts once, under big/ (the smallest path), so
    // links/ stays below the threshold; small/ is below it too.
    let paths: Vec<&str> = s.dirs.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            root.as_str(),
            &format!("{root}/big"),
            &format!("{root}/big/inner")
        ]
    );
    assert!(s.dirs[1].allocated >= 3 << 20);
    assert!(s.dirs.windows(2).all(|w| w[0].allocated >= w[1].allocated));
    assert_eq!(s.dirs[0].allocated, rep.scan.totals.allocated);

    assert_eq!(s.fs.len(), rep.fs.len());
    assert_eq!(s.fs[0].used, 4 << 30);
    assert_eq!(s.findings.len(), 1);
    assert_eq!(s.findings[0].id, rep.findings[0].id);
    assert_eq!(s.findings[0].tier, Tier::Rebuildable);

    let d = s.docker.as_ref().unwrap();
    assert_eq!(d.usage, docker::usage(&dock));
    assert_eq!(d.images.len(), dock.images().len());
    assert_eq!(d.volumes.len(), dock.volumes().len());
    assert_eq!(d.containers.len(), dock.containers().len());
    assert!(d.containers.iter().all(|c| !c.name.starts_with('/')));
    assert!(
        d.images
            .iter()
            .all(|i| i.tags.iter().all(|t| t != "<none>:<none>"))
    );
    for v in &d.volumes {
        let src = dock.volumes().iter().find(|x| x.name == v.name).unwrap();
        let size = src.usage_data.as_ref().map_or(-1, |u| u.size);
        assert_eq!(v.bytes, (size >= 0).then_some(size as u64));
    }

    // Without the daemon's state there is no Docker part.
    assert_eq!(snapshot::build(&rep, &res.tree, None, 1 << 20).docker, None);
}

fn sample(created_at: &str, roots: &[&str]) -> Snapshot {
    Snapshot {
        schema: SCHEMA.into(),
        tool: dwhy_core::report::Tool::current(),
        host: "testhost".into(),
        uid: 1000,
        created_at: created_at.into(),
        scan: dwhy_core::report::SnapshotScan {
            roots: roots.iter().map(|r| r.to_string()).collect(),
            one_filesystem: true,
            min_dir_bytes: snapshot::MIN_DIR_BYTES,
            totals: Default::default(),
            detectors: vec!["cargo-target".into()],
            skipped_mounts: Vec::new(),
        },
        dirs: Vec::new(),
        fs: Vec::new(),
        docker: None,
        findings: Vec::new(),
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn save_writes_a_private_compressed_file_and_never_replaces_one() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("state/diskwhy/snapshots");
    let snap = sample("2026-11-16T06:00:00Z", &["/home/u"]);
    let now = snapshot::parse_time("2026-11-16T06:00:01Z").unwrap();

    let saved = snapshot::save(&dir, &snap, now).unwrap();
    assert_eq!(saved.prune_error, None);
    let a = saved.snapshot;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(Path::new(&a.path)), 0o600);
    assert_eq!(a.pruned, 0);
    let scope = snapshot::scope_of(&snap);
    assert_eq!(a.id, format!("20261116T060000Z-{scope}"));
    assert_eq!(
        Path::new(&a.path),
        dir.join(format!("{}.json.gz", a.id)).as_path()
    );
    // gzip magic.
    assert_eq!(&fs::read(&a.path).unwrap()[..2], &[0x1f, 0x8b]);
    assert_eq!(snapshot::load(Path::new(&a.path)).unwrap(), snap);

    // Same second, same scope: a new name, the first file untouched.
    let ino = fs::metadata(&a.path).unwrap().ino();
    let b = snapshot::save(&dir, &snap, now).unwrap().snapshot;
    assert_eq!(b.id, format!("{}-1", a.id));
    assert_eq!(fs::metadata(&a.path).unwrap().ino(), ino);

    // Only the two snapshots are left: no temp files.
    let names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    let listed: Vec<String> = snapshot::list(&dir)
        .unwrap()
        .into_iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(listed, vec![a.id, b.id]);
}

#[test]
fn load_rejects_what_is_not_a_snapshot() {
    let t = tempfile::tempdir().unwrap();
    let plain = t.path().join("plain.json.gz");
    fs::write(&plain, b"{}").unwrap();
    assert!(snapshot::load(&plain).is_err());

    let dir = t.path().join("s");
    let mut snap = sample("2026-11-16T06:00:00Z", &["/"]);
    snap.schema = "diskwhy/v9".into();
    let saved = snapshot::save(&dir, &snap, 0).unwrap().snapshot;
    let err = snapshot::load(Path::new(&saved.path)).unwrap_err();
    assert!(err.contains("unsupported schema"), "{err}");
}

#[test]
fn a_snapshot_saved_before_skipped_mounts_loads_as_skipping_none() {
    let snap = sample("2026-11-16T06:00:00Z", &["/home/u"]);
    let mut json = serde_json::to_value(&snap).unwrap();
    json["scan"]
        .as_object_mut()
        .unwrap()
        .remove("skipped_mounts");
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("old.json.gz");
    let mut gz = flate2::write::GzEncoder::new(
        fs::File::create(&path).unwrap(),
        flate2::Compression::default(),
    );
    std::io::Write::write_all(&mut gz, json.to_string().as_bytes()).unwrap();
    gz.finish().unwrap();
    assert_eq!(snapshot::load(&path).unwrap(), snap);
}

fn entry(created: i64, scope: &str) -> Entry {
    let id = format!("{created}-{scope}");
    Entry {
        path: PathBuf::from(&id),
        id,
        created,
        scope: scope.into(),
    }
}

#[test]
fn retention_keeps_two_days_then_one_per_day_then_nothing() {
    let now = 1000 * DAY + 12 * 3600; // noon
    let entries = vec![
        // Within 48 hours: all kept, even several on one day.
        entry(now - 60, "aaaaaaaa"),
        entry(now - 3600, "aaaaaaaa"),
        entry(now - 47 * 3600, "aaaaaaaa"),
        // Day 997 (all older than 48 h): only the newest is kept.
        entry(997 * DAY + 100, "aaaaaaaa"),
        entry(997 * DAY + 5000, "aaaaaaaa"),
        // The same day for another scope is kept on its own.
        entry(997 * DAY + 200, "bbbbbbbb"),
        // Older than 90 days: gone, even when alone on its day.
        entry(now - KEEP_DAILY_SECS - 1, "aaaaaaaa"),
        // Exactly 90 days old is still kept.
        entry(now - KEEP_DAILY_SECS, "bbbbbbbb"),
        // Snapshots from the future (clock changes) are kept.
        entry(now + 3600, "aaaaaaaa"),
    ];
    let gone: Vec<&str> = snapshot::to_prune(&entries, now)
        .into_iter()
        .map(|e| e.id.as_str())
        .collect();
    let expect = [
        format!("{}-aaaaaaaa", 997 * DAY + 100),
        format!("{}-aaaaaaaa", now - KEEP_DAILY_SECS - 1),
    ];
    assert_eq!(gone, expect.iter().map(String::as_str).collect::<Vec<_>>());

    // A day straddling the 48 h line ends up with its newest snapshot only.
    let day = (now - 48 * 3600).div_euclid(DAY);
    let early = entry(day * DAY + 1, "aaaaaaaa");
    let late = entry(now - 47 * 3600, "aaaaaaaa");
    assert_eq!(late.created.div_euclid(DAY), day);
    let both = [early.clone(), late];
    let gone = snapshot::to_prune(&both, now);
    assert_eq!(gone, vec![&early]);
}

#[test]
fn saving_prunes_only_snapshot_files() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("snapshots");
    let old = sample("2026-01-01T00:00:00Z", &["/home/u"]);
    let new = sample("2026-11-16T06:00:00Z", &["/home/u"]);
    let other = sample("2026-11-10T06:00:00Z", &["/srv"]);
    let early = snapshot::parse_time("2026-01-01T00:00:01Z").unwrap();
    let old_saved = snapshot::save(&dir, &old, early).unwrap().snapshot;
    let other_saved = snapshot::save(&dir, &other, early).unwrap().snapshot;

    // Lookalikes that must survive: a symlink with a snapshot name pointing
    // at a file outside, an unrelated file, and a directory.
    let outside = t.path().join("precious");
    fs::write(&outside, b"keep").unwrap();
    let link = dir.join("20250101T000000Z-0000abcd.json.gz");
    symlink(&outside, &link).unwrap();
    fs::write(dir.join("notes.txt"), b"x").unwrap();
    fs::create_dir(dir.join("20250101T000000Z-0000abce.json.gz")).unwrap();

    let now = snapshot::parse_time("2026-11-16T06:00:01Z").unwrap();
    let saved = snapshot::save(&dir, &new, now).unwrap().snapshot;
    assert_eq!(saved.pruned, 1);
    assert!(!Path::new(&old_saved.path).exists());
    assert!(Path::new(&other_saved.path).exists());
    assert!(Path::new(&saved.path).exists());
    assert!(fs::symlink_metadata(&link).is_ok());
    assert_eq!(fs::read(&outside).unwrap(), b"keep");
    assert!(dir.join("notes.txt").exists());
    assert!(dir.join("20250101T000000Z-0000abce.json.gz").is_dir());
}

#[test]
fn a_snapshot_older_than_the_policy_still_saves() {
    // The clock may be wrong; the snapshot just written is never pruned.
    let t = tempfile::tempdir().unwrap();
    let snap = sample("2020-01-01T00:00:00Z", &["/"]);
    let now = snapshot::parse_time("2026-11-16T00:00:00Z").unwrap();
    let saved = snapshot::save(t.path(), &snap, now).unwrap().snapshot;
    assert!(Path::new(&saved.path).exists());
}

/// Restores a directory's mode when dropped, so the temp dir can be removed.
struct RestoreMode(PathBuf, u32);

impl Drop for RestoreMode {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
    }
}

#[test]
fn a_pruning_failure_does_not_unsave_the_snapshot() {
    if rustix::process::geteuid().is_root() {
        return; // root reads any directory
    }
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("snapshots");
    fs::create_dir(&dir).unwrap();
    // Writable and searchable but not listable: linking works, listing fails.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();
    let _restore = RestoreMode(dir.clone(), 0o700);
    let snap = sample("2026-11-16T06:00:00Z", &["/"]);
    let saved = snapshot::save(&dir, &snap, 0).unwrap();
    assert!(saved.prune_error.is_some());
    assert_eq!(saved.snapshot.pruned, 0);
    assert_eq!(
        snapshot::load(Path::new(&saved.snapshot.path)).unwrap(),
        snap
    );
}

#[test]
fn since_parses_last_ids_durations_times_and_files() {
    use snapshot::{Since, parse_since};
    assert_eq!(parse_since("last"), Ok(Since::Last));
    assert_eq!(
        parse_since("20261116T060000Z-0123abcd"),
        Ok(Since::Id("20261116T060000Z-0123abcd".into()))
    );
    assert_eq!(parse_since("24h"), Ok(Since::Age(DAY)));
    assert_eq!(parse_since("7d"), Ok(Since::Age(7 * DAY)));
    assert_eq!(
        parse_since("2026-11-16T06:00:00Z"),
        snapshot::parse_time("2026-11-16T06:00:00Z")
            .map(Since::At)
            .ok_or(String::new())
    );
    assert_eq!(
        parse_since("./old.json.gz"),
        Ok(Since::File("./old.json.gz".into()))
    );
    assert_eq!(
        parse_since("x.json.gz"),
        Ok(Since::File("x.json.gz".into()))
    );
    for bad in ["yesterday", "3y", "", "2026-11-16"] {
        assert!(parse_since(bad).is_err(), "{bad}");
    }
}

#[test]
fn find_picks_the_newest_matching_snapshot() {
    use snapshot::{Since, find};
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    let t0 = snapshot::parse_time("2026-11-16T00:00:00Z").unwrap();
    let at = |secs: i64| {
        time::OffsetDateTime::from_unix_timestamp(t0 + secs)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let now = t0 + 5 * 3600;
    let save = |s: &Snapshot| snapshot::save(dir, s, now).unwrap().snapshot.id;
    let h = sample(&at(0), &["/h"]);
    let ids_h: Vec<String> = [0, 3600, 3 * 3600]
        .iter()
        .map(|&off| save(&sample(&at(off), &["/h"])))
        .collect();
    let id_srv = save(&sample(&at(4 * 3600), &["/srv"]));
    let mut other = sample(&at(4 * 3600 + 60), &["/h"]);
    other.host = "otherhost".into();
    let id_other = save(&other);
    // Newest of all, with a snapshot name but not a snapshot inside.
    let scope_h = snapshot::scope("testhost", 1000, &["/h".to_string()], true);
    fs::write(
        dir.join(format!("20261116T043000Z-{scope_h}.json.gz")),
        b"garbage",
    )
    .unwrap();

    let roots = vec!["/h".to_string()];
    let h_roots = Some((roots.as_slice(), true));
    let pick = |since: &Since, roots: Option<(&[String], bool)>| {
        find(dir, since, "testhost", 1000, roots, now).map(|f| f.id.unwrap())
    };
    // Unreadable and other-host snapshots are skipped.
    assert_eq!(pick(&Since::Last, h_roots), Ok(ids_h[2].clone()));
    // Without roots: the newest of this host and uid, whatever its roots.
    assert_eq!(pick(&Since::Last, None), Ok(id_srv.clone()));
    // At least 2h old: taken by 03:00.
    assert_eq!(pick(&Since::Age(2 * 3600), h_roots), Ok(ids_h[2].clone()));
    assert_eq!(pick(&Since::Age(3 * 3600), h_roots), Ok(ids_h[1].clone()));
    assert_eq!(pick(&Since::At(t0 + 1800), h_roots), Ok(ids_h[0].clone()));
    // -x matters, and so do the roots.
    assert!(pick(&Since::Last, Some((roots.as_slice(), false))).is_err());
    let err = pick(&Since::At(t0 - 1), h_roots).unwrap_err();
    assert!(err.contains("no snapshot of /h"), "{err}");
    // An id or a file is taken whatever its roots...
    assert_eq!(
        pick(&Since::Id(id_srv.clone()), h_roots),
        Ok(id_srv.clone())
    );
    let f = find(
        dir,
        &Since::File(dir.join(format!("{}.json.gz", ids_h[0]))),
        "testhost",
        1000,
        None,
        now,
    )
    .unwrap();
    assert_eq!(f.id.as_deref(), Some(ids_h[0].as_str()));
    assert_eq!(f.snapshot, h);
    // ...but not from another host or uid.
    let err = pick(&Since::Id(id_other), None).unwrap_err();
    assert!(err.contains("host \"otherhost\""), "{err}");
    let err = find(dir, &Since::Id(ids_h[0].clone()), "testhost", 0, None, now).unwrap_err();
    assert!(err.contains("uid 1000"), "{err}");

    // Nothing in a missing directory.
    let err = find(&dir.join("none"), &Since::Last, "testhost", 1000, None, now).unwrap_err();
    assert!(err.contains("dwhy scan --snapshot"), "{err}");
}

#[test]
fn scan_growth_comes_from_the_newest_snapshot_of_the_same_roots_an_hour_old() {
    let t = fixture();
    let (res, mounts) = scan_of(t.path());
    let mut report = report_of(&res, &mounts);
    let root = report.scan.roots[0].path.clone();
    let path = format!("{root}/big");
    report.findings = vec![
        finding(&path, 400 << 20),
        finding(&format!("{root}/new"), 1 << 20),
    ];
    let state = tempfile::tempdir().unwrap();
    let dir = state.path().join("snapshots");
    let now = snapshot::parse_time(&report.generated_at).unwrap();

    // Nothing to read yet: no growth, and no error.
    assert_eq!(
        dwhy_core::growth::fill_scan_growth(&mut report, &dir, now),
        None
    );
    assert!(report.findings.iter().all(|f| f.growth.is_none()));

    let listing = |created_at: &str, roots: &[&str], bytes: u64| {
        let mut s = sample(created_at, roots);
        s.findings = vec![dwhy_core::report::SnapshotFinding {
            id: dwhy_core::detect::finding_id("cargo-target", &path),
            detector: "cargo-target".into(),
            path: path.clone(),
            bytes,
            tier: Tier::Rebuildable,
        }];
        s
    };
    // 06:00 now: 04:00 is used. 05:30 is too recent, 03:00 older, and
    // 05:00 of other roots or (cross filesystems) do not count.
    let mut crossing = listing("2026-11-16T05:00:00Z", &[&root], 0);
    crossing.scan.one_filesystem = false;
    for s in [
        listing("2026-11-16T03:00:00Z", &[&root], 0),
        listing("2026-11-16T04:00:00Z", &[&root], 300 << 20),
        listing("2026-11-16T05:00:00Z", &["/elsewhere"], 0),
        crossing,
        listing("2026-11-16T05:30:00Z", &[&root], 0),
    ] {
        snapshot::save(&dir, &s, now).unwrap();
    }
    let saved = snapshot::list(&dir).unwrap().len();

    let mut sampled_earlier = report.clone();
    for sampled_at in ["2026-11-16T03:30:00Z", "2026-11-16T04:00:00Z", "invalid"] {
        sampled_earlier.generated_at = sampled_at.into();
        assert_eq!(
            dwhy_core::growth::fill_scan_growth(&mut sampled_earlier, &dir, now),
            None
        );
        assert!(sampled_earlier.findings.iter().all(|f| f.growth.is_none()));
    }

    let base = dwhy_core::growth::fill_scan_growth(&mut report, &dir, now);
    assert_eq!(base.as_deref(), Some("2026-11-16T04:00:00Z"));
    let g = report.findings[0].growth.as_ref().unwrap();
    // 100M in two hours.
    assert_eq!(g.bytes_per_day, 1200 << 20);
    assert_eq!(g.since, "2026-11-16T04:00:00Z");
    assert_eq!(report.findings[1].growth, None, "not in the snapshot");
    // It only reads.
    assert_eq!(snapshot::list(&dir).unwrap().len(), saved);

    // A report without findings reads nothing.
    report.findings.clear();
    assert_eq!(
        dwhy_core::growth::fill_scan_growth(&mut report, &dir, now),
        None
    );
}
