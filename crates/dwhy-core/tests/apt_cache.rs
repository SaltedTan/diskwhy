//! `apt-cache` on temp-dir fixtures: what `apt-get clean` removes from an
//! apt cache directory. The layouts follow what apt 3.2's `apt-get clean`,
//! pinned to a temp dir, removed and left.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::apply::{self, Audit, Env, Policy};
use dwhy_core::detect::{self, DetectContext, Detector, finding_id, rfc3339};
use dwhy_core::detectors::AptCache;
use dwhy_core::guard::{Proc, Processes};
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::report::{
    ActionKind, ApplyOutcome, DetectorAvailability, DockerSocket, Finding, GuardStatus, PlanScan,
    Tier, ToolStatus,
};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

const DAY: u64 = 86_400;
const MIB: usize = 1 << 20;

fn base() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn scan_tree(root: &Path) -> ScanTree {
    let roots = scan::prepare_roots(&[root.to_path_buf()], true).unwrap();
    let opts = ScanOptions {
        min_dir_bytes: 0,
        threads: 2,
        ..ScanOptions::default()
    };
    scan::scan(
        &roots,
        &opts,
        &MountTable::read().unwrap(),
        &Progress::default(),
    )
    .unwrap()
    .tree
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn tool(name: &str, path: Option<&str>, off_path: Option<&str>) -> ToolStatus {
    ToolStatus {
        name: name.into(),
        path: path.map(String::from),
        off_path: off_path.map(String::from),
        enables: vec![],
    }
}

fn ctx(root: bool, tools: Vec<ToolStatus>) -> DetectContext {
    DetectContext {
        uid: if root { 0 } else { 1000 },
        root,
        home: None,
        now: now(),
        tools,
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: dwhy_core::docker::Source::none(),
        cancel: Default::default(),
        scratch_paths: Vec::new(),
        scratch_stale_days: dwhy_core::detectors::SCRATCH_STALE_DAYS,
    }
}

fn apt_get() -> Vec<ToolStatus> {
    vec![tool("apt-get", Some("/usr/bin/apt-get"), None)]
}

fn root_ctx() -> DetectContext {
    ctx(true, apt_get())
}

/// Writes `bytes` of data to `p`, last modified `days_ago` days ago.
fn write(p: &Path, bytes: usize, days_ago: u64) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, vec![7u8; bytes]).unwrap();
    let t = SystemTime::now() - Duration::from_secs(days_ago * DAY);
    fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

fn allocated(p: &Path) -> u64 {
    fs::symlink_metadata(p).unwrap().blocks() * 512
}

fn mtime(p: &Path) -> i64 {
    fs::symlink_metadata(p).unwrap().mtime()
}

fn cache_root(b: &Path) -> PathBuf {
    b.join("var/cache/apt")
}

fn detect(b: &Path, scanned: &Path) -> Vec<Finding> {
    AptCache::with_root(cache_root(b))
        .detect(&scan_tree(scanned), &root_ctx())
        .unwrap()
}

fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// The argv the action pins for the cache directory `path`.
fn pinned_argv(apt_get: &str, path: &str) -> Vec<String> {
    [
        apt_get,
        "-o",
        &format!("Dir::Cache={path}"),
        "-o",
        "Dir::Cache::archives=archives/",
        "-o",
        "Dir::Cache::pkgcache=pkgcache.bin",
        "-o",
        "Dir::Cache::srcpkgcache=srcpkgcache.bin",
        "clean",
    ]
    .map(String::from)
    .to_vec()
}

#[test]
fn finds_what_apt_get_clean_removes_and_nothing_else() {
    let (_t, b) = base();
    let c = cache_root(&b);
    let a = c.join("archives");
    let removed = [
        a.join("vim_9.1.0016-1ubuntu7_amd64.deb"),
        a.join("libfoo-dbgsym_1.0_amd64.ddeb"),
        // apt-get clean removes every file in archives/, not just packages.
        a.join("notes.txt"),
        a.join(".hidden"),
        a.join("partial/bash_5.2.21-2ubuntu4_amd64.deb"),
        c.join("pkgcache.bin"),
        c.join("srcpkgcache.bin"),
        // Left by an interrupted cache build.
        c.join("pkgcache.bin.Xa3_b-9"),
    ];
    for (i, p) in removed.iter().enumerate() {
        write(p, MIB, 3 + i as u64);
    }
    // What apt-get clean leaves.
    write(&a.join("lock"), 2 * MIB, 1);
    write(&a.join("auxfiles"), MIB, 1);
    write(&a.join("lost+found"), MIB, 1);
    write(&a.join("partial/lock"), MIB, 1);
    write(&a.join("partial/auxfiles"), MIB, 1);
    write(&a.join("sub/inner.deb"), 2 * MIB, 1);
    write(&a.join("partial/sub/inner.deb"), 2 * MIB, 1);
    write(&c.join("keep.bin"), 2 * MIB, 1);
    write(&c.join("pkgcache.binX"), MIB, 1);
    write(&c.join("pkgcache.bin."), MIB, 1);
    write(&c.join("pkgcache.bin.a~b"), MIB, 1);
    write(&c.join("other/pkgcache.bin"), MIB, 1);
    // A symlink apt-get unlinks: it frees nothing, and its target stays.
    write(&b.join("elsewhere.deb"), 2 * MIB, 1);
    symlink(b.join("elsewhere.deb"), a.join("link.deb")).unwrap();

    let found = detect(&b, &b);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    let path = c.to_str().unwrap();
    assert_eq!(f.detector, "apt-cache");
    assert_eq!(f.path, path);
    assert_eq!(f.id, finding_id("apt-cache", path));
    assert_eq!(f.tier, Tier::Regenerable);
    assert_eq!(f.bytes, removed.iter().map(|p| allocated(p)).sum::<u64>());
    // The newest is the first, 3 days old.
    assert_eq!(f.last_modified, Some(rfc3339(mtime(&removed[0]))));
    assert!(
        f.reason.starts_with(&format!(
            "5 downloaded package files and 3 binary package cache files in {path} ("
        )),
        "{}",
        f.reason
    );
    assert!(
        f.reason.contains("the newest written 3 days ago"),
        "{}",
        f.reason
    );
    assert!(!f.reason.contains("hardlinked"), "{}", f.reason);
    assert_eq!(f.action.kind, ActionKind::Command);
    assert_eq!(
        f.action.argv.as_deref().unwrap(),
        pinned_argv("apt-get", path)
    );
    assert_eq!(
        f.action.text,
        format!(
            "apt-get -o Dir::Cache={path} -o Dir::Cache::archives=archives/ -o Dir::Cache::pkgcache=pkgcache.bin -o Dir::Cache::srcpkgcache=srcpkgcache.bin clean"
        )
    );
    assert!(
        f.recovery
            .cost
            .contains("rebuilds its binary package cache")
    );
    assert_eq!(f.recovery.how, None);
}

#[test]
fn action_uses_the_resolved_command_and_quotes_the_path() {
    let (_t, b) = base();
    let b = b.join("my cache");
    let c = cache_root(&b);
    write(&c.join("archives/a.deb"), 2 * MIB, 1);
    let cx = ctx(true, vec![tool("apt-get", None, Some("/usr/bin/apt-get"))]);
    let found = AptCache::with_root(c.clone())
        .detect(&scan_tree(&b), &cx)
        .unwrap();
    let path = c.to_str().unwrap();
    let f = &found[0];
    assert_eq!(
        f.action.argv.as_deref().unwrap(),
        pinned_argv("/usr/bin/apt-get", path)
    );
    assert!(
        f.action.text.starts_with(&format!(
            "/usr/bin/apt-get -o 'Dir::Cache={path}' -o Dir::Cache::archives=archives/"
        )),
        "{}",
        f.action.text
    );
    assert!(
        f.reason.starts_with("1 downloaded package file in"),
        "{}",
        f.reason
    );
}

#[test]
fn no_finding_when_empty_or_only_kept_files() {
    let (_t, b) = base();
    let c = cache_root(&b);
    fs::create_dir_all(c.join("archives/partial")).unwrap();
    assert!(detect(&b, &b).is_empty());
    write(&c.join("archives/lock"), 4 * MIB, 1);
    write(&c.join("archives/partial/lock"), 4 * MIB, 1);
    write(&c.join("archives/sub/a.deb"), 4 * MIB, 1);
    write(&c.join("keep.bin"), 4 * MIB, 1);
    assert!(detect(&b, &b).is_empty());
}

#[test]
fn no_finding_below_one_mib() {
    let (_t, b) = base();
    let c = cache_root(&b);
    write(&c.join("archives/lock"), 4 * MIB, 1);
    write(&c.join("archives/a.deb"), 256 << 10, 1);
    write(&c.join("pkgcache.bin"), 256 << 10, 1);
    assert!(detect(&b, &b).is_empty());
}

#[test]
fn no_finding_when_the_cache_is_outside_the_scan() {
    let (_t, b) = base();
    write(&cache_root(&b).join("archives/a.deb"), 4 * MIB, 1);
    write(&b.join("home/me/file"), 10, 0);
    assert!(detect(&b, &b.join("home")).is_empty());
    // A cache "directory" that is a file.
    let (_u, c) = base();
    write(&cache_root(&c), 4 * MIB, 1);
    assert!(detect(&c, &c).is_empty());
}

#[test]
fn without_archives_only_the_binary_caches_count() {
    // apt-get clean succeeds without archives/ and still removes the
    // binary caches; it does not create archives/.
    let (_t, b) = base();
    let c = cache_root(&b);
    write(&c.join("pkgcache.bin"), 256 << 10, 1);
    assert!(detect(&b, &b).is_empty());
    write(&c.join("srcpkgcache.bin"), 2 * MIB, 1);
    let found = detect(&b, &b);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(
        f.bytes,
        allocated(&c.join("pkgcache.bin")) + allocated(&c.join("srcpkgcache.bin"))
    );
    assert!(
        f.reason.starts_with("2 binary package cache files in"),
        "{}",
        f.reason
    );
}

/// A cache directory with enough in it for a finding.
fn populated(b: &Path) -> PathBuf {
    let c = cache_root(b);
    write(&c.join("archives/a.deb"), 2 * MIB, 1);
    write(&c.join("archives/partial/b.deb"), 2 * MIB, 1);
    write(&c.join("pkgcache.bin"), 2 * MIB, 1);
    c
}

#[test]
fn fails_closed_when_apt_get_clean_would_follow_a_symlink() {
    // apt-get clean opens archives/ and archives/partial/ following
    // symlinks and empties their targets, so nothing is reported, not even
    // the binary caches.
    for link in ["archives", "archives/partial"] {
        let (_t, b) = base();
        let c = populated(&b);
        let real = b.join("real");
        fs::rename(c.join(link), &real).unwrap();
        symlink(&real, c.join(link)).unwrap();
        assert!(detect(&b, &b).is_empty(), "{link}");
        // Dangling, too.
        fs::remove_dir_all(&real).unwrap();
        assert!(detect(&b, &b).is_empty(), "{link} dangling");
    }
    // The cache directory itself a symlink.
    let (_t, b) = base();
    let c = populated(&b.join("real"));
    fs::create_dir_all(b.join("var/cache")).unwrap();
    symlink(&c, cache_root(&b)).unwrap();
    assert!(detect(&b, &b).is_empty());
}

#[test]
fn fails_closed_when_archives_or_partial_is_not_a_directory() {
    // With archives/partial a file, apt-get clean fails and removes
    // nothing; a file archives/ is treated the same.
    for file in ["archives", "archives/partial"] {
        let (_t, b) = base();
        let c = populated(&b);
        fs::remove_dir_all(c.join(file)).unwrap();
        write(&c.join(file), 10, 1);
        assert!(detect(&b, &b).is_empty(), "{file}");
    }
}

/// Restores a directory's mode when dropped.
struct Chmod(PathBuf, u32);

impl Drop for Chmod {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
    }
}

#[test]
fn fails_closed_when_archives_cannot_be_read() {
    if running_as_root() {
        eprintln!("skipped: root can read everything");
        return;
    }
    // apt-get clean fails on an unreadable archives/ and removes nothing.
    for dir in ["archives", "archives/partial"] {
        let (_t, b) = base();
        let c = populated(&b);
        let tree = scan_tree(&b);
        let p = c.join(dir);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o300)).unwrap();
        let _restore = Chmod(p, 0o755);
        let found = AptCache::with_root(c).detect(&tree, &root_ctx()).unwrap();
        assert!(found.is_empty(), "{dir}: {found:?}");
    }
}

#[test]
fn hardlinks_count_once_and_outside_links_are_not_freed() {
    let (_t, b) = base();
    let c = cache_root(&b);
    let a = c.join("archives");
    let alone = a.join("alone.deb");
    let linked_in = a.join("in.deb");
    let linked_out = a.join("out.deb");
    let linked_kept = a.join("kept.deb");
    for p in [&alone, &linked_in, &linked_out, &linked_kept] {
        write(p, 2 * MIB, 1);
    }
    fs::create_dir_all(a.join("partial")).unwrap();
    fs::create_dir_all(a.join("sub")).unwrap();
    // Both names removed: counted once.
    fs::hard_link(&linked_in, a.join("partial/in.deb")).unwrap();
    // "zz-out" sorts after "var", so the scan attributes the inode to the
    // cache directory and counts it as shared.
    fs::create_dir_all(b.join("zz-out")).unwrap();
    fs::hard_link(&linked_out, b.join("zz-out/out.deb")).unwrap();
    // A name apt-get clean keeps, inside the cache directory.
    fs::hard_link(&linked_kept, a.join("sub/kept.deb")).unwrap();

    let tree = scan_tree(&b);
    let node = tree.node(tree.find(&c).unwrap());
    let found = AptCache::with_root(c.clone())
        .detect(&tree, &root_ctx())
        .unwrap();
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!(f.bytes, allocated(&alone) + allocated(&linked_in));
    assert!(
        f.bytes <= node.freeable(),
        "{} > {}",
        f.bytes,
        node.freeable()
    );
    assert!(
        f.reason.starts_with("3 downloaded package files in"),
        "{}",
        f.reason
    );
    assert!(
        f.reason.contains("hardlinked elsewhere and is not freed"),
        "{}",
        f.reason
    );
}

#[test]
fn bytes_never_exceed_what_the_walk_attributes() {
    let (_t, b) = base();
    let file = cache_root(&b).join("archives/a.deb");
    write(&file, 4 * MIB, 1);
    // "aa-out" sorts before "var": the walk attributes the inode outside,
    // so the cache directory frees almost nothing.
    fs::create_dir_all(b.join("aa-out")).unwrap();
    fs::hard_link(&file, b.join("aa-out/a.deb")).unwrap();
    assert!(detect(&b, &b).is_empty());
}

#[test]
fn runs_only_as_root_with_apt_get() {
    let (_t, b) = base();
    let c = populated(&b);
    let tree = scan_tree(&b);
    let built: Vec<Box<dyn Detector>> = vec![Box::new(AptCache::with_root(c))];
    let run = |cx: &DetectContext| {
        let (found, runs) = detect::run_with(&tree, cx, &built, None);
        let r = runs.into_iter().find(|r| r.name == "apt-cache").unwrap();
        (found.len(), r)
    };

    let (n, r) = run(&ctx(false, apt_get()));
    assert_eq!(
        (n, r.ran, r.status),
        (0, false, DetectorAvailability::Unavailable)
    );
    assert!(r.detail.contains("root"), "{}", r.detail);

    let (n, r) = run(&ctx(true, vec![]));
    assert_eq!(
        (n, r.ran, r.status),
        (0, false, DetectorAvailability::Unavailable)
    );
    assert!(r.detail.contains("apt-get"), "{}", r.detail);

    let (n, r) = run(&ctx(true, apt_get()));
    assert_eq!(
        (n, r.ran, r.status),
        (1, true, DetectorAvailability::Available)
    );
    assert_eq!(r.findings, 1);
}

#[test]
fn registered_in_the_registry() {
    assert!(
        dwhy_core::detectors::registry()
            .iter()
            .any(|d| d.name() == "apt-cache")
    );
}

#[test]
fn a_cache_under_a_non_utf8_name_is_blocked() {
    let (_t, b) = base();
    let lossy = b.join(OsStr::from_bytes(b"root\xff"));
    if let Err(e) = fs::create_dir(&lossy) {
        eprintln!("skipped: the filesystem refuses {lossy:?}: {e}");
        return;
    }
    let c = populated(&lossy);
    let built: Vec<Box<dyn Detector>> = vec![Box::new(AptCache::with_root(c))];
    let (found, _) = detect::run_with(&scan_tree(&b), &root_ctx(), &built, None);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(
        f.path,
        format!("{}/root\u{FFFD}/var/cache/apt", b.to_str().unwrap())
    );
    assert_eq!(f.tier, Tier::Blocked);
    assert_eq!(f.action.kind, ActionKind::Advice);
    assert_eq!(f.action.argv, None);
    let g = f.guards.iter().find(|g| g.name == "path-not-utf8").unwrap();
    assert_eq!(g.status, GuardStatus::Block);
}

/// A fake `apt-get` that writes its arguments to `out`. Returns `None`
/// when the temp dir cannot run programs (mounted noexec).
fn fake_apt_get(dir: &Path, out: &Path) -> Option<PathBuf> {
    let script = dir.join("apt-get");
    fs::write(
        &script,
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", out.display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    // Another test thread may still hold the script open across a fork.
    for _ in 0..50 {
        match std::process::Command::new(&script).arg("warm-up").status() {
            Ok(_) => return Some(script),
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(e) => panic!("{e}"),
        }
    }
    panic!("the fake apt-get never stopped being busy");
}

#[test]
fn plan_blocks_while_apt_holds_the_lock_and_apply_runs_the_pinned_clean() {
    let (_t, b) = base();
    let (_bin, bin) = base();
    let out = bin.join("argv");
    let Some(script) = fake_apt_get(&bin, &out) else {
        return;
    };
    let c = populated(&b);
    let lock = c.join("archives/lock");
    write(&lock, 0, 1);
    let cx = ctx(
        true,
        vec![tool("apt-get", None, Some(script.to_str().unwrap()))],
    );
    let det = AptCache::with_root(c.clone());
    let plan_with = |procs: &Processes| {
        let tree = scan_tree(&b);
        let found = det.detect(&tree, &cx).unwrap();
        assert_eq!(found.len(), 1);
        plan::build(
            found,
            &Selection {
                tier: None,
                select: vec![],
                free: None,
            },
            &tree,
            &cx,
            procs,
            "host".into(),
            PlanScan {
                roots: vec![b.to_string_lossy().into_owned()],
                one_filesystem: true,
                detectors: None,
            },
        )
        .unwrap()
    };

    // apt holding archives/lock open: blocked.
    let busy = Processes {
        procs: vec![Proc {
            pid: 4242,
            name: "apt-get".into(),
            cwd: Some(PathBuf::from("/")),
            open: vec![lock.clone()],
        }],
        unreadable: 0,
    };
    let plan = plan_with(&busy);
    assert!(plan.items.is_empty(), "{plan:?}");
    assert_eq!(plan.blocked.len(), 1);
    let blocked = &plan.blocked[0];
    assert_eq!(blocked.tier, Tier::Blocked);
    let g = blocked
        .guards
        .iter()
        .find(|g| g.name == "in-use-open")
        .unwrap();
    assert_eq!(g.status, GuardStatus::Block);
    assert!(g.detail.contains("apt-get"), "{}", g.detail);

    // Idle: planned under the default ceiling and applied without --confirm.
    let idle = Processes {
        procs: vec![],
        unreadable: 0,
    };
    let plan = plan_with(&idle);
    assert_eq!(plan.items.len(), 1, "{plan:?}");
    let planned = &plan.items[0];
    assert_eq!(planned.finding.tier, Tier::Regenerable);
    let names: Vec<&str> = planned
        .finding
        .guards
        .iter()
        .map(|g| g.name.as_str())
        .collect();
    assert!(names.contains(&"in-use-open"), "{names:?}");
    assert!(names.contains(&"in-use-cwd"), "{names:?}");
    assert!(names.iter().all(|n| !n.starts_with("git")), "{names:?}");
    assert!(planned.fingerprint.inode.is_some());
    assert!(planned.fingerprint.newest_mtime.is_some());

    let tree = scan_tree(&b);
    let fresh = det.detect(&tree, &cx).unwrap();
    let mut checks = apply::evaluate(&plan, fresh, &tree, &cx, &idle, &Policy::default());
    assert_eq!(
        checks[0].item.outcome,
        ApplyOutcome::WouldRemove,
        "{}",
        checks[0].item.detail
    );

    let (_s, state) = base();
    let mut audit = Audit::open(&state.join("audit.jsonl")).unwrap();
    let env = Env {
        host: "host".into(),
        uid: 0,
        now: || "2026-11-24T00:00:00Z".to_string(),
        invocation: None,
    };
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &MountTable::default(),
        &env,
        &mut |_| {},
    );
    assert_eq!(
        checks[0].item.outcome,
        ApplyOutcome::Removed,
        "{}",
        checks[0].item.detail
    );
    let want = pinned_argv("", c.to_str().unwrap())[1..].join("\n") + "\n";
    assert_eq!(fs::read_to_string(&out).unwrap(), want);
    // The fake removed nothing.
    assert!(c.join("archives/a.deb").exists());
}
