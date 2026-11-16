//! Snapshots: what a snapshot records, saving and loading, and retention.
//! Docker comes from the fixed snapshot in tests/data; no daemon is contacted.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use dwhy_core::account::{self, ReportEnv};
use dwhy_core::docker::{self, Info};
use dwhy_core::mounts::{FsStats, MountTable};
use dwhy_core::report::{
    Action, ActionKind, Finding, Recovery, SCHEMA, ScanReport, Snapshot, Tier,
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
    let dock = docker_fixture();
    let s = snapshot::build(&rep, &res.tree, Some(&dock), 1 << 20);

    assert_eq!(s.schema, SCHEMA);
    assert_eq!(s.host, "testhost");
    assert_eq!(s.created_at, "2026-11-16T06:00:00Z");
    assert_eq!(s.scan.roots, vec![root.clone()]);
    assert!(s.scan.one_filesystem);
    assert_eq!(s.scan.min_dir_bytes, 1 << 20);
    assert_eq!(s.scan.totals, rep.scan.totals);

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
