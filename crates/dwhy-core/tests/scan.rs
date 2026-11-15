//! Scanner behaviour on temp-dir fixtures. Nothing outside the fixtures is
//! modified; the `/dev` test only reads.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use dwhy_core::account::{self, ReportEnv};
use dwhy_core::mounts::{FsStats, MountTable};
use dwhy_core::report::{HintKind, SkipReason, UnreadableReason};
use dwhy_core::scan::{self, Progress, ScanOptions, ScanResult};
use dwhy_core::system::DeletedOpenScan;

fn opts() -> ScanOptions {
    ScanOptions {
        min_dir_bytes: 0,
        threads: 4,
        ..ScanOptions::default()
    }
}

fn run(roots: &[&Path], opts: &ScanOptions) -> ScanResult {
    let roots: Vec<PathBuf> = roots.iter().map(|p| p.to_path_buf()).collect();
    let roots = scan::prepare_roots(&roots, opts.one_filesystem).unwrap();
    let mounts = MountTable::read().unwrap();
    scan::scan(&roots, opts, &mounts, &Progress::default()).unwrap()
}

/// Writes `len` bytes of real (non-sparse) data.
fn write_file(p: &Path, len: usize) {
    fs::write(p, vec![0xa5u8; len]).unwrap();
}

fn alloc(p: &Path) -> u64 {
    fs::symlink_metadata(p).unwrap().blocks() * 512
}

fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[test]
fn hardlinks_are_counted_once() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir_all(r.join("a")).unwrap();
    fs::create_dir_all(r.join("b/c")).unwrap();
    write_file(&r.join("a/big"), 1 << 20);
    fs::hard_link(r.join("a/big"), r.join("a/big2")).unwrap();
    fs::hard_link(r.join("a/big"), r.join("b/c/big3")).unwrap();
    write_file(&r.join("b/small"), 100);

    let res = run(&[r], &opts());
    let tot = res.totals();
    assert_eq!(tot.files, 2, "big counted once, plus small");
    assert_eq!(tot.hardlinks_deduped, 2);
    assert_eq!(tot.hardlink_bytes_deduped, 2 * alloc(&r.join("a/big")));
    // Directories count 0 apparent bytes, like GNU du.
    assert_eq!(tot.apparent, (1 << 20) + 100);
    let dirs_alloc: u64 = [r.to_path_buf(), r.join("a"), r.join("b"), r.join("b/c")]
        .iter()
        .map(|d| alloc(d))
        .sum();
    assert_eq!(
        tot.allocated,
        dirs_alloc + alloc(&r.join("a/big")) + alloc(&r.join("b/small"))
    );
    assert_eq!(tot.dirs, 4);
    // The per-device figure (used for `unaccounted`) agrees with the total.
    let dev = fs::metadata(r).unwrap().dev();
    assert_eq!(res.per_dev[&dev].allocated, tot.allocated);
}

#[test]
fn hardlinks_are_attributed_to_the_smallest_path() {
    let t = tempfile::tempdir().unwrap();
    let r = fs::canonicalize(t.path()).unwrap();
    // Many sibling dirs so threads race for the links.
    for i in 0..32 {
        fs::create_dir(r.join(format!("d{i:02}"))).unwrap();
    }
    write_file(&r.join("d17/f"), 512 << 10);
    for i in 0..32 {
        if i != 17 {
            fs::hard_link(r.join("d17/f"), r.join(format!("d{i:02}/f"))).unwrap();
        }
    }
    for _ in 0..10 {
        let res = run(&[&r], &opts());
        let d00 = res.dirs.iter().find(|d| d.path == r.join("d00")).unwrap();
        assert_eq!(d00.totals.files, 1);
        assert_eq!(d00.totals.hardlinks_deduped, 31);
        for d in res
            .dirs
            .iter()
            .filter(|d| d.depth == 1 && d.path != r.join("d00"))
        {
            assert_eq!(d.totals.files, 0, "{}", d.path.display());
        }
    }
}

#[test]
fn hardlinks_across_roots_are_counted_once() {
    let t = tempfile::tempdir().unwrap();
    let (a, b) = (t.path().join("a"), t.path().join("b"));
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    write_file(&a.join("f"), 64 << 10);
    fs::hard_link(a.join("f"), b.join("f")).unwrap();
    let res = run(&[&a, &b], &opts());
    assert_eq!(res.totals().files, 1);
    assert_eq!(res.totals().hardlinks_deduped, 1);
}

#[test]
fn symlinks_are_never_followed() {
    let t = tempfile::tempdir().unwrap();
    let outside = t.path().join("outside");
    let root = t.path().join("root");
    fs::create_dir_all(outside.join("deep")).unwrap();
    write_file(&outside.join("deep/huge"), 4 << 20);
    fs::create_dir(&root).unwrap();
    symlink(&outside, root.join("to_dir")).unwrap();
    symlink(outside.join("deep/huge"), root.join("to_file")).unwrap();
    symlink("nowhere", root.join("dangling")).unwrap();
    symlink("loop", root.join("loop")).unwrap();
    symlink(".", root.join("self")).unwrap();

    let res = run(&[&root], &opts());
    let tot = res.totals();
    assert_eq!(tot.symlinks, 5);
    assert_eq!(tot.files, 0);
    assert_eq!(tot.dirs, 1);
    assert!(tot.allocated < 1 << 20, "target data was counted: {tot:?}");
    let link_bytes: u64 = ["to_dir", "to_file", "dangling", "loop", "self"]
        .iter()
        .map(|n| fs::symlink_metadata(root.join(n)).unwrap().size())
        .sum();
    assert_eq!(tot.apparent, link_bytes);
    assert_eq!(res.error_count, 0);
    assert!(res.dirs.iter().all(|d| d.path == root));

    // A root that is itself a symlink is counted as the link, not its target.
    let res = run(&[&root.join("to_dir")], &opts());
    assert_eq!(res.totals().symlinks, 1);
    assert_eq!(res.totals().files, 0);
    assert_eq!(res.roots[0].path, root.join("to_dir"));
}

/// Restores permissions so the temp dir can be cleaned up even if a test fails.
struct Chmod(PathBuf, u32);
impl Drop for Chmod {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
    }
}

#[test]
fn unreadable_directories_are_recorded() {
    if running_as_root() {
        eprintln!("skipped: root can read everything");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    let locked = r.join("locked");
    let noexec = r.join("noexec");
    fs::create_dir_all(locked.join("inner")).unwrap();
    write_file(&locked.join("inner/secret"), 256 << 10);
    fs::create_dir(&noexec).unwrap();
    for n in ["x", "y", "z"] {
        write_file(&noexec.join(n), 10);
    }
    write_file(&r.join("visible"), 1000);
    let locked_alloc = alloc(&locked);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let _g1 = Chmod(locked.clone(), 0o755);
    fs::set_permissions(&noexec, fs::Permissions::from_mode(0o600)).unwrap();
    let _g2 = Chmod(noexec.clone(), 0o755);

    let res = run(&[r], &opts());
    assert_eq!(res.unreadable.len(), 2, "{:?}", res.unreadable);
    let l = res.unreadable.iter().find(|u| u.path == locked).unwrap();
    assert_eq!(l.reason, UnreadableReason::PermissionDenied);
    assert_eq!(l.known_bytes, locked_alloc);
    assert_eq!(l.owner_uid, rustix::process::geteuid().as_raw());
    let n = res.unreadable.iter().find(|u| u.path == noexec).unwrap();
    assert_eq!(n.reason, UnreadableReason::EntriesDenied);
    assert_eq!(n.entries_unknown, 3);
    // Visible data is still counted; the locked contents are not.
    let tot = res.totals();
    assert_eq!(tot.files, 1);
    assert_eq!(tot.apparent, 1000);
    // Permission problems are not "errors".
    assert_eq!(res.error_count, 0);
}

#[test]
fn nested_roots_are_not_double_counted() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir(r.join("sub")).unwrap();
    write_file(&r.join("sub/f"), 8192);
    let roots =
        scan::prepare_roots(&[r.join("sub"), r.to_path_buf(), r.join("sub/.")], true).unwrap();
    assert_eq!(roots, vec![fs::canonicalize(r).unwrap()]);
    assert!(scan::prepare_roots(&[r.join("missing")], true).is_err());
}

/// Mounts stacked directly on `/dev` in this mount namespace.
fn dev_child_mounts() -> Vec<(PathBuf, String)> {
    let t = MountTable::read().unwrap();
    let Some(dev) = t.at(Path::new("/dev")) else {
        return Vec::new();
    };
    t.children_of(dev)
        .filter(|m| m.mount_point.parent() == Some(Path::new("/dev")))
        .map(|m| (m.mount_point.clone(), m.fstype.clone()))
        .collect()
}

#[test]
fn one_filesystem_skips_mount_points() {
    let kids = dev_child_mounts();
    if kids.is_empty() {
        eprintln!("skipped: no mounts directly below /dev here");
        return;
    }
    let res = run(&[Path::new("/dev")], &opts());
    for (mp, fstype) in &kids {
        let s = res
            .skipped_mounts
            .iter()
            .find(|s| &s.path == mp)
            .unwrap_or_else(|| {
                panic!(
                    "{} ({fstype}) not skipped: {:?}",
                    mp.display(),
                    res.skipped_mounts
                )
            });
        let want = if dwhy_core::mounts::is_virtual_fstype(fstype) {
            SkipReason::Virtual
        } else {
            SkipReason::OtherFilesystem
        };
        assert_eq!(s.reason, want, "{}", mp.display());
        assert!(
            res.dirs.iter().all(|d| !d.path.starts_with(mp)),
            "walked into {}",
            mp.display()
        );
    }
    // Only /dev's own filesystem was counted.
    let dev = fs::symlink_metadata("/dev").unwrap().dev();
    assert_eq!(res.per_dev.keys().copied().collect::<Vec<_>>(), vec![dev]);
}

#[test]
fn crossing_filesystems_still_skips_virtual_ones() {
    let kids = dev_child_mounts();
    if kids.is_empty() {
        eprintln!("skipped: no mounts directly below /dev here");
        return;
    }
    let o = ScanOptions {
        one_filesystem: false,
        ..opts()
    };
    let res = run(&[Path::new("/dev")], &o);
    for (mp, fstype) in &kids {
        let skipped = res.skipped_mounts.iter().find(|s| &s.path == mp);
        if dwhy_core::mounts::is_virtual_fstype(fstype) {
            assert_eq!(
                skipped.map(|s| s.reason),
                Some(SkipReason::Virtual),
                "{}",
                mp.display()
            );
        } else {
            assert!(skipped.is_none(), "{} should be entered", mp.display());
        }
    }
}

fn env(root: bool) -> ReportEnv {
    ReportEnv {
        host: "testhost".into(),
        uid: if root { 0 } else { 1000 },
        root,
        generated_at: "2026-11-15T00:00:00Z".into(),
        users: Vec::new(),
        deleted_open: DeletedOpenScan::default(),
        exe: "/usr/local/bin/dwhy".into(),
        docker_access: false,
    }
}

/// A fake mount table in which `root` is a filesystem's mount point.
fn table_with_mount_at(root: &Path) -> MountTable {
    let dev = fs::metadata(root).unwrap().dev();
    let (ma, mi) = (rustix::fs::major(dev), rustix::fs::minor(dev));
    MountTable::parse(&format!(
        "1 0 {ma}:{mi} / {} rw shared:1 - ext4 /dev/fake rw\n",
        root.display()
    ))
}

#[test]
fn unaccounted_is_df_used_minus_scanned_when_root_is_the_mount() {
    let t = tempfile::tempdir().unwrap();
    let r = fs::canonicalize(t.path()).unwrap();
    write_file(&r.join("f"), 100 << 10);
    let mounts = table_with_mount_at(&r);
    let res = scan::scan(
        std::slice::from_ref(&r),
        &opts(),
        &mounts,
        &Progress::default(),
    )
    .unwrap();
    let scanned = res.totals().allocated;
    let gib = 1u64 << 30;
    let stats = |_: &Path| {
        Some(FsStats {
            size: 10 * gib,
            used: scanned + 5 * gib,
            avail: 4 * gib,
        })
    };

    let rep = account::build_scan_report(&res, &mounts, &env(false), &stats);
    assert_eq!(rep.fs.len(), 1);
    let f = &rep.fs[0];
    assert!(f.full_coverage);
    assert_eq!(f.scanned, scanned);
    assert_eq!(f.unaccounted, Some(5 * gib));
    assert!(f.unaccounted_large);
    let rerun = f.rerun.as_deref().unwrap();
    assert!(
        rerun.starts_with("sudo /usr/local/bin/dwhy scan "),
        "{rerun}"
    );
    assert!(rerun.contains(r.file_name().unwrap().to_str().unwrap()));

    // As root there is nothing to rerun with.
    let rep = account::build_scan_report(&res, &mounts, &env(true), &stats);
    assert_eq!(rep.fs[0].rerun, None);

    // A small gap is reported but not flagged.
    let small = |_: &Path| {
        Some(FsStats {
            size: 10 * gib,
            used: scanned + (100 << 20),
            avail: 4 * gib,
        })
    };
    let rep = account::build_scan_report(&res, &mounts, &env(false), &small);
    assert_eq!(rep.fs[0].unaccounted, Some(100 << 20));
    assert!(!rep.fs[0].unaccounted_large);
    assert_eq!(rep.fs[0].rerun, None);
}

#[test]
fn unaccounted_is_absent_for_a_subtree() {
    let t = tempfile::tempdir().unwrap();
    let r = fs::canonicalize(t.path()).unwrap();
    fs::create_dir(r.join("sub")).unwrap();
    let mounts = table_with_mount_at(&r);
    let res = scan::scan(&[r.join("sub")], &opts(), &mounts, &Progress::default()).unwrap();
    let stats = |_: &Path| {
        Some(FsStats {
            size: 100 << 30,
            used: 50 << 30,
            avail: 50 << 30,
        })
    };
    let rep = account::build_scan_report(&res, &mounts, &env(false), &stats);
    assert!(!rep.fs[0].full_coverage);
    assert_eq!(rep.fs[0].unaccounted, None);
    assert!(rep.fs[0].hints.is_empty());
    assert_eq!(rep.fs[0].rerun, None);
}

#[test]
fn unreadable_dirs_become_hints() {
    if running_as_root() {
        eprintln!("skipped: root can read everything");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let r = fs::canonicalize(t.path()).unwrap();
    let locked = r.join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let _g = Chmod(locked.clone(), 0o755);
    let mounts = table_with_mount_at(&r);
    let res = scan::scan(
        std::slice::from_ref(&r),
        &opts(),
        &mounts,
        &Progress::default(),
    )
    .unwrap();
    let stats = |_: &Path| {
        Some(FsStats {
            size: 10 << 30,
            used: 8 << 30,
            avail: 2 << 30,
        })
    };
    let rep = account::build_scan_report(&res, &mounts, &env(false), &stats);
    let h = &rep.fs[0].hints;
    assert_eq!(h.len(), 1, "{h:?}");
    assert_eq!(h[0].kind, HintKind::Unreadable);
    assert_eq!(h[0].path.as_deref(), Some(locked.to_str().unwrap()));
    assert_eq!(rep.scan.unreadable.count, 1);
}
