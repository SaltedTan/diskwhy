//! `snap-revisions` on temp-dir fixtures: disabled snap revisions that
//! `snap remove --revision` frees. The revision list is a fixed
//! `GET /v2/snaps?select=all` body (`tests/data/snapd-snaps-all.json`,
//! snapd 2.78), never the machine's snapd.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::apply::{self, Audit, Env, Policy};
use dwhy_core::detect::{self, DetectContext, Detector, finding_id, rfc3339};
use dwhy_core::detectors::SnapRevisions;
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
const FIXTURE: &str = include_str!("data/snapd-snaps-all.json");

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

fn snap_tool() -> Vec<ToolStatus> {
    vec![tool("snap", Some("/usr/bin/snap"), None)]
}

fn root_ctx() -> DetectContext {
    ctx(true, snap_tool())
}

/// Writes `bytes` of data to `p`, last modified `days_ago` days ago.
fn write(p: &Path, bytes: usize, days_ago: u64) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, vec![7u8; bytes]).unwrap();
    touch(p, days_ago);
}

/// Sets the mtime of `p` (and every link to it) `days_ago` days back.
fn touch(p: &Path, days_ago: u64) {
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

fn snapd_root(b: &Path) -> PathBuf {
    b.join("var/lib/snapd")
}

fn snaps(b: &Path) -> PathBuf {
    snapd_root(b).join("snaps")
}

/// A download cache entry name: a SHA3-384 digest in hex.
fn cache_entry(b: &Path, n: u8) -> PathBuf {
    snapd_root(b)
        .join("cache")
        .join(format!("{:02x}", n).repeat(48))
}

/// The fixture listing with its paths moved under `b`.
fn listing(b: &Path) -> Vec<u8> {
    FIXTURE
        .replace(
            "\"/var/lib/snapd/",
            &format!("\"{}/", snapd_root(b).display()),
        )
        .into_bytes()
}

fn detector(b: &Path) -> SnapRevisions {
    SnapRevisions::with_listing(snapd_root(b), Ok(listing(b)))
}

fn detect(b: &Path, scanned: &Path) -> Vec<Finding> {
    detector(b)
        .detect(&scan_tree(scanned), &root_ctx())
        .unwrap()
}

fn paths(found: &[Finding]) -> Vec<&str> {
    found.iter().map(|f| f.path.as_str()).collect()
}

fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// A `.snap` file for every revision the fixture lists, 2 MiB each: the
/// disabled revisions are firefox 9057, core22 2955, core24 1643,
/// desktop-security-center 188, gnome-46-2404 164, hwctl 123,
/// prompting-client 222, snapd 28254, firmware-updater 258,
/// canonical-livepatch 414 and snap-store 1504.
fn populated(b: &Path) {
    for (name, rev) in [
        ("snap-store", "1504"),
        ("snap-store", "1509"),
        ("core24", "1643"),
        ("core24", "2124"),
        ("gtk-common-themes", "1535"),
        ("core26", "750"),
        ("desktop-security-center", "188"),
        ("desktop-security-center", "206"),
        ("snapd-desktop-integration", "391"),
        ("prompting-client", "222"),
        ("prompting-client", "228"),
        ("firefox", "9057"),
        ("firefox", "9137"),
        ("lxd", "41228"),
        ("core22", "2955"),
        ("core22", "2987"),
        ("mesa-2404", "1839"),
        ("gnome-46-2404", "164"),
        ("gnome-46-2404", "177"),
        ("hwctl", "123"),
        ("hwctl", "131"),
        ("bare", "5"),
        ("snapd", "28254"),
        ("snapd", "28332"),
        ("firmware-updater", "258"),
        ("firmware-updater", "262"),
        ("canonical-livepatch", "414"),
        ("canonical-livepatch", "418"),
    ] {
        write(&snaps(b).join(format!("{name}_{rev}.snap")), 2 * MIB, 50);
    }
}

#[test]
fn finds_disabled_revisions_snapd_lists_and_removing_frees() {
    let (_t, b) = base();
    populated(&b);
    let s = snaps(&b);
    // Hardlinked into the download cache, as snapd downloads are; the
    // entry is over 30 days old, so snapd's cleanup frees it.
    fs::create_dir_all(cache_entry(&b, 1).parent().unwrap()).unwrap();
    fs::hard_link(s.join("core22_2955.snap"), cache_entry(&b, 1)).unwrap();
    touch(&s.join("core22_2955.snap"), 40);
    // Cached too, but only 10 days old: the cache keeps it.
    fs::hard_link(s.join("core24_1643.snap"), cache_entry(&b, 2)).unwrap();
    touch(&s.join("core24_1643.snap"), 10);
    // In the cache and linked elsewhere as well.
    fs::hard_link(s.join("gnome-46-2404_164.snap"), cache_entry(&b, 3)).unwrap();
    fs::create_dir_all(b.join("backup")).unwrap();
    fs::hard_link(
        s.join("gnome-46-2404_164.snap"),
        b.join("backup/gnome.snap"),
    )
    .unwrap();
    // Linked outside the cache only.
    fs::hard_link(s.join("snapd_28254.snap"), b.join("backup/snapd.snap")).unwrap();
    // Too small.
    write(&s.join("hwctl_123.snap"), 256 << 10, 50);
    // Gone, a symlink, and a directory.
    fs::remove_file(s.join("canonical-livepatch_414.snap")).unwrap();
    fs::remove_file(s.join("snap-store_1504.snap")).unwrap();
    write(&b.join("elsewhere.snap"), 2 * MIB, 50);
    symlink(b.join("elsewhere.snap"), s.join("snap-store_1504.snap")).unwrap();
    fs::remove_file(s.join("prompting-client_222.snap")).unwrap();
    write(&s.join("prompting-client_222.snap/inner"), 2 * MIB, 50);
    // Files snapd does not list as a disabled revision.
    for name in [
        "foo_x1.snap",
        "firefox_9000.snap",
        "firefox_9057.snap.partial",
        "partial/firefox_9057.snap",
        "firefox_9057.snap~",
        "bare_4.snap",
    ] {
        write(&s.join(name), 2 * MIB, 50);
    }
    // Revision data directories are not counted.
    write(&b.join("var/snap/firefox/9057/x"), 4 * MIB, 50);

    let found = detect(&b, &b);
    let dir = s.to_str().unwrap();
    assert_eq!(
        paths(&found),
        [
            format!("{dir}/core22_2955.snap"),
            format!("{dir}/desktop-security-center_188.snap"),
            format!("{dir}/firefox_9057.snap"),
            format!("{dir}/firmware-updater_258.snap"),
        ],
        "{found:#?}"
    );
    for f in &found {
        let p = Path::new(&f.path);
        assert_eq!(f.detector, "snap-revisions");
        assert_eq!(f.id, finding_id("snap-revisions", &f.path));
        assert_eq!(f.tier, Tier::Review);
        assert_eq!(f.bytes, allocated(p));
        assert_eq!(f.last_modified, Some(rfc3339(mtime(p))));
        assert!(f.guards.is_empty());
        assert_eq!(f.action.kind, ActionKind::Command);
        assert_eq!(f.recovery.how, None);
    }

    let firefox = &found[2];
    assert_eq!(
        firefox.action.argv.as_deref().unwrap(),
        ["snap", "remove", "--revision=9057", "firefox"]
    );
    assert_eq!(firefox.action.text, "snap remove --revision=9057 firefox");
    assert!(
        firefox.reason.starts_with(&format!(
            "disabled revision 9057 of snap firefox (active revision 9137): {dir}/firefox_9057.snap ("
        )),
        "{}",
        firefox.reason
    );
    assert!(
        firefox.reason.contains(
            "nothing else links to it, so `snap remove --revision=9057 firefox` frees it"
        ),
        "{}",
        firefox.reason
    );
    assert!(
        firefox.reason.contains("/var/snap/firefox/9057") && firefox.reason.contains("not counted"),
        "{}",
        firefox.reason
    );
    assert!(
        firefox
            .recovery
            .cost
            .starts_with("`snap revert firefox` can no longer return to revision 9057"),
        "{}",
        firefox.recovery.cost
    );

    let core22 = &found[0];
    assert_eq!(
        core22.action.argv.as_deref().unwrap(),
        ["snap", "remove", "--revision=2955", "core22"]
    );
    assert!(
        core22
            .reason
            .contains("its only other link is in snapd's download cache and is over 30 days old"),
        "{}",
        core22.reason
    );
}

#[test]
fn ids_are_stable_and_the_file_identity_is_recorded() {
    let (_t, b) = base();
    populated(&b);
    let a = detect(&b, &b);
    let again = detect(&b, &b);
    assert_eq!(
        a.iter().map(|f| &f.id).collect::<Vec<_>>(),
        again.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    let f = a
        .iter()
        .find(|f| f.path.ends_with("firefox_9057.snap"))
        .unwrap();
    let md = fs::symlink_metadata(&f.path).unwrap();
    let id = f.file_identity.unwrap();
    assert_eq!((id.dev, id.ino, id.mtime), (md.dev(), md.ino(), md.mtime()));
}

#[test]
fn local_revisions_and_instance_names() {
    let (_t, b) = base();
    let dir = snaps(&b);
    let body = format!(
        r#"{{"type":"sync","status-code":200,"result":[
            {{"name":"mytool","revision":"x1","status":"installed","type":"app","mounted-from":"{d}/mytool_x1.snap"}},
            {{"name":"mytool","revision":"x2","status":"active","type":"app","mounted-from":"{d}/mytool_x2.snap"}},
            {{"name":"hello_foo","revision":"10","status":"installed","type":"app","mounted-from":"{d}/hello_foo_10.snap"}},
            {{"name":"hello_foo","revision":"11","status":"active","type":"app","mounted-from":"{d}/hello_foo_11.snap"}}
        ]}}"#,
        d = dir.display()
    );
    for name in [
        "mytool_x1.snap",
        "mytool_x2.snap",
        "hello_foo_10.snap",
        "hello_foo_11.snap",
    ] {
        write(&dir.join(name), 2 * MIB, 3);
    }
    let found = SnapRevisions::with_listing(snapd_root(&b), Ok(body.into_bytes()))
        .detect(&scan_tree(&b), &root_ctx())
        .unwrap();
    let d = dir.to_str().unwrap();
    assert_eq!(
        paths(&found),
        [
            format!("{d}/hello_foo_10.snap"),
            format!("{d}/mytool_x1.snap")
        ]
    );
    assert_eq!(
        found[0].action.argv.as_deref().unwrap(),
        ["snap", "remove", "--revision=10", "hello_foo"]
    );
    assert_eq!(
        found[1].action.argv.as_deref().unwrap(),
        ["snap", "remove", "--revision=x1", "mytool"]
    );
    assert!(
        found[1]
            .recovery
            .cost
            .contains("installed from a local file"),
        "{}",
        found[1].recovery.cost
    );
}

#[test]
fn a_parallel_instance_running_from_its_disabled_revision_blocks() {
    let (_t, b) = base();
    let dir = snaps(&b);
    let body = r#"{"type":"sync","status-code":200,"result":[
        {"name":"firefox_work","revision":"9057","status":"installed","type":"app"},
        {"name":"firefox_work","revision":"9137","status":"active","type":"app"}
    ]}"#;
    for name in ["firefox_work_9057.snap", "firefox_work_9137.snap"] {
        write(&dir.join(name), 2 * MIB, 3);
    }
    let det = SnapRevisions::with_listing(snapd_root(&b), Ok(body.as_bytes().to_vec()));
    let tree = scan_tree(&b);
    let cx = root_ctx();
    let plan_with = |open: &str| {
        let found = det.detect(&tree, &cx).unwrap();
        assert_eq!(
            found[0].action.argv.as_deref().unwrap(),
            ["snap", "remove", "--revision=9057", "firefox_work"]
        );
        let id = found[0].id.clone();
        plan::build(
            found,
            &Selection {
                tier: None,
                select: vec![id],
                free: None,
            },
            &tree,
            &cx,
            &Processes {
                procs: vec![Proc {
                    pid: 4545,
                    name: "firefox".into(),
                    cwd: Some(PathBuf::from("/")),
                    open: vec![PathBuf::from(open)],
                }],
                unreadable: 0,
            },
            "host".into(),
            PlanScan {
                roots: vec![b.to_string_lossy().into_owned()],
                one_filesystem: true,
                detectors: None,
            },
        )
        .unwrap()
    };

    // Inside the instance's namespace snap-confine maps /snap/firefox_work
    // onto /snap/firefox, so that is what its maps show; the host path
    // blocks too.
    for open in [
        "/snap/firefox/9057/usr/lib/firefox/libxul.so",
        "/var/snap/firefox/9057/.mozilla/lock",
        "/snap/firefox_work/9057/usr/lib/firefox/libxul.so",
    ] {
        let plan = plan_with(open);
        assert!(plan.items.is_empty(), "{open}: {plan:?}");
        let g = plan.blocked[0]
            .guards
            .iter()
            .find(|g| g.name == "in-use-open")
            .unwrap();
        assert_eq!(g.status, GuardStatus::Block, "{open}");
    }
    assert_eq!(
        plan_with("/snap/firefox/9137/usr/lib/firefox/libxul.so")
            .items
            .len(),
        1
    );
}

#[test]
fn action_uses_the_resolved_command() {
    let (_t, b) = base();
    populated(&b);
    let cx = ctx(true, vec![tool("snap", None, Some("/usr/bin/snap"))]);
    let found = detector(&b).detect(&scan_tree(&b), &cx).unwrap();
    let f = found
        .iter()
        .find(|f| f.path.ends_with("firefox_9057.snap"))
        .unwrap();
    assert_eq!(
        f.action.argv.as_deref().unwrap(),
        ["/usr/bin/snap", "remove", "--revision=9057", "firefox"]
    );
    assert_eq!(
        f.action.text,
        "/usr/bin/snap remove --revision=9057 firefox"
    );
}

#[test]
fn nothing_when_the_snaps_dir_is_outside_the_scan_and_snapd_is_not_asked() {
    let (_t, b) = base();
    populated(&b);
    write(&b.join("home/me/file"), 10, 0);
    let asked = SnapRevisions::with_listing(snapd_root(&b), Err("snapd was asked".into()));
    assert!(
        asked
            .detect(&scan_tree(&b.join("home")), &root_ctx())
            .unwrap()
            .is_empty()
    );
    // A "snaps directory" that is a file.
    let (_u, c) = base();
    write(&snaps(&c), 4 * MIB, 1);
    assert!(detect(&c, &c).is_empty());
}

#[test]
fn a_failed_or_garbled_listing_fails_closed() {
    let (_t, b) = base();
    populated(&b);
    let tree = scan_tree(&b);
    for listing in [
        Err("snapd API /v2/snaps?select=all: connection refused".to_string()),
        Ok(b"<html>".to_vec()),
        Ok(br#"{"type":"error","status-code":401,"result":{"message":"access denied"}}"#.to_vec()),
        Ok(
            br#"{"type":"sync","status-code":200,"result":[{"name":"firefox","revision":"9057"}]}"#
                .to_vec(),
        ),
    ] {
        let built: Vec<Box<dyn Detector>> = vec![Box::new(SnapRevisions::with_listing(
            snapd_root(&b),
            listing.clone(),
        ))];
        let (found, runs) = detect::run_with(&tree, &root_ctx(), &built, None);
        assert!(found.is_empty(), "{listing:?}: {found:?}");
        let r = runs.iter().find(|r| r.name == "snap-revisions").unwrap();
        assert!(r.error.is_some(), "{listing:?}");
    }
}

#[test]
fn nothing_when_the_snaps_dir_is_a_symlink_or_was_replaced() {
    // A symlinked snaps directory: the walk does not follow it.
    let (_t, b) = base();
    populated(&b.join("real"));
    fs::create_dir_all(snapd_root(&b)).unwrap();
    symlink(snaps(&b.join("real")), snaps(&b)).unwrap();
    assert!(detect(&b, &b).is_empty());

    // Replaced between the walk and detection.
    let (_u, c) = base();
    populated(&c);
    let tree = scan_tree(&c);
    fs::rename(snaps(&c), c.join("old")).unwrap();
    populated(&c);
    assert!(detector(&c).detect(&tree, &root_ctx()).unwrap().is_empty());

    // The snapd directory itself a symlink.
    let (_v, d) = base();
    populated(&d.join("real"));
    fs::create_dir_all(d.join("var/lib")).unwrap();
    symlink(snapd_root(&d.join("real")), snapd_root(&d)).unwrap();
    assert!(detect(&d, &d).is_empty());
}

/// A cache-linked old revision: firefox 9057 in the download cache.
fn cached_firefox(b: &Path) -> PathBuf {
    populated(b);
    let f = snaps(b).join("firefox_9057.snap");
    fs::create_dir_all(cache_entry(b, 1).parent().unwrap()).unwrap();
    fs::hard_link(&f, cache_entry(b, 1)).unwrap();
    touch(&f, 40);
    f
}

fn has_firefox(found: &[Finding]) -> bool {
    found.iter().any(|f| f.path.ends_with("firefox_9057.snap"))
}

#[test]
fn a_cache_link_counts_only_in_a_cache_read_safely() {
    let (_t, b) = base();
    cached_firefox(&b);
    assert!(has_firefox(&detect(&b, &b)));

    // The cache directory a symlink to where the link really is.
    let (_u, c) = base();
    cached_firefox(&c);
    let cache = snapd_root(&c).join("cache");
    fs::rename(&cache, c.join("real-cache")).unwrap();
    symlink(c.join("real-cache"), &cache).unwrap();
    assert!(!has_firefox(&detect(&c, &c)));

    // The cache entry a symlink to the snap file: frees nothing.
    let (_v, d) = base();
    populated(&d);
    let f = snaps(&d).join("firefox_9057.snap");
    fs::create_dir_all(cache_entry(&d, 1).parent().unwrap()).unwrap();
    fs::hard_link(&f, d.join("elsewhere.snap")).unwrap();
    symlink(&f, cache_entry(&d, 1)).unwrap();
    touch(&f, 40);
    assert!(!has_firefox(&detect(&d, &d)));

    // The cache entry in a subdirectory of the cache.
    let (_w, e) = base();
    populated(&e);
    let f = snaps(&e).join("firefox_9057.snap");
    let nested = snapd_root(&e).join("cache/sub/entry");
    fs::create_dir_all(nested.parent().unwrap()).unwrap();
    fs::hard_link(&f, &nested).unwrap();
    touch(&f, 40);
    assert!(!has_firefox(&detect(&e, &e)));
}

/// Restores a directory's mode when dropped.
struct Chmod(PathBuf, u32);

impl Drop for Chmod {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
    }
}

#[test]
fn an_unreadable_cache_counts_nothing_linked_into_it() {
    if running_as_root() {
        eprintln!("skipped: root can read everything");
        return;
    }
    let (_t, b) = base();
    cached_firefox(&b);
    let tree = scan_tree(&b);
    let cache = snapd_root(&b).join("cache");
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o300)).unwrap();
    let _restore = Chmod(cache, 0o755);
    let found = detector(&b).detect(&tree, &root_ctx()).unwrap();
    assert!(!has_firefox(&found), "{found:?}");
    // Files with no other link still count.
    assert!(
        found
            .iter()
            .any(|f| f.path.ends_with("desktop-security-center_188.snap"))
    );
}

#[test]
fn a_cache_entry_counts_after_thirty_days() {
    let (_t, b) = base();
    let f = cached_firefox(&b);
    touch(&f, 29);
    assert!(!has_firefox(&detect(&b, &b)));
    touch(&f, 31);
    assert!(has_firefox(&detect(&b, &b)));
}

#[test]
fn runs_only_as_root_with_snap() {
    let (_t, b) = base();
    populated(&b);
    let tree = scan_tree(&b);
    let built: Vec<Box<dyn Detector>> = vec![Box::new(detector(&b))];
    let run = |cx: &DetectContext| {
        let (found, runs) = detect::run_with(&tree, cx, &built, None);
        let r = runs
            .into_iter()
            .find(|r| r.name == "snap-revisions")
            .unwrap();
        (found.len(), r)
    };

    let (n, r) = run(&ctx(false, snap_tool()));
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
    assert!(r.detail.contains("snap"), "{}", r.detail);

    let (n, r) = run(&ctx(true, snap_tool()));
    assert_eq!(
        (n, r.ran, r.status),
        (11, true, DetectorAvailability::Available)
    );
    assert_eq!(r.findings, 11);
}

#[test]
fn registered_in_the_registry() {
    assert!(
        dwhy_core::detectors::registry()
            .iter()
            .any(|d| d.name() == "snap-revisions")
    );
}

#[test]
fn a_snaps_dir_under_a_non_utf8_name_is_blocked() {
    let (_t, b) = base();
    let lossy = b.join(OsStr::from_bytes(b"root\xff"));
    if let Err(e) = fs::create_dir(&lossy) {
        eprintln!("skipped: the filesystem refuses {lossy:?}: {e}");
        return;
    }
    let dir = snaps(&lossy);
    write(&dir.join("firefox_9057.snap"), 2 * MIB, 3);
    write(&dir.join("firefox_9137.snap"), 2 * MIB, 3);
    let body = br#"{"type":"sync","status-code":200,"result":[
        {"name":"firefox","revision":"9057","status":"installed","type":"app"},
        {"name":"firefox","revision":"9137","status":"active","type":"app"}]}"#;
    let built: Vec<Box<dyn Detector>> = vec![Box::new(SnapRevisions::with_listing(
        snapd_root(&lossy),
        Ok(body.to_vec()),
    ))];
    let (found, _) = detect::run_with(&scan_tree(&b), &root_ctx(), &built, None);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(
        f.path,
        format!(
            "{}/root\u{FFFD}/var/lib/snapd/snaps/firefox_9057.snap",
            b.to_str().unwrap()
        )
    );
    assert_eq!(f.tier, Tier::Blocked);
    assert_eq!(f.action.kind, ActionKind::Advice);
    let g = f.guards.iter().find(|g| g.name == "path-not-utf8").unwrap();
    assert_eq!(g.status, GuardStatus::Block);
}

/// A fake `snap` that writes its arguments to `out`. Returns `None` when
/// the temp dir cannot run programs (mounted noexec).
fn fake_snap(dir: &Path, out: &Path) -> Option<PathBuf> {
    let script = dir.join("snap");
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
    panic!("the fake snap never stopped being busy");
}

#[test]
fn plan_and_apply_remove_one_revision_and_skip_it_once_reverted() {
    let (_t, b) = base();
    let (_bin, bin) = base();
    let out = bin.join("argv");
    let Some(script) = fake_snap(&bin, &out) else {
        return;
    };
    populated(&b);
    let file = snaps(&b).join("firefox_9057.snap");
    let cx = ctx(
        true,
        vec![tool("snap", None, Some(script.to_str().unwrap()))],
    );
    let det = detector(&b);
    let tree = scan_tree(&b);
    let found = det.detect(&tree, &cx).unwrap();
    let id = found
        .iter()
        .find(|f| f.path == file.to_str().unwrap())
        .unwrap()
        .id
        .clone();
    let plan_with = |procs: &Processes| {
        plan::build(
            det.detect(&tree, &cx).unwrap(),
            &Selection {
                tier: None,
                select: vec![id.clone()],
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

    // A process with the .snap file open: blocked.
    let busy = Processes {
        procs: vec![Proc {
            pid: 4242,
            name: "unsquashfs".into(),
            cwd: Some(PathBuf::from("/")),
            open: vec![file.clone()],
        }],
        unreadable: 0,
    };
    let plan = plan_with(&busy);
    assert!(plan.items.is_empty(), "{plan:?}");
    let g = plan.blocked[0]
        .guards
        .iter()
        .find(|g| g.name == "in-use-open")
        .unwrap();
    assert_eq!(g.status, GuardStatus::Block);

    // An app still running from the disabled revision: the loop device
    // holds the .snap file, so only paths under the revision's mount or
    // data directory show it.
    for (cwd, open) in [
        ("/", "/snap/firefox/9057/usr/lib/firefox/libxul.so"),
        (
            "/",
            "/var/lib/snapd/snap/firefox/9057/usr/lib/firefox/firefox",
        ),
        ("/var/snap/firefox/9057", "/usr/lib/libc.so.6"),
    ] {
        let running = Processes {
            procs: vec![Proc {
                pid: 4343,
                name: "firefox".into(),
                cwd: Some(PathBuf::from(cwd)),
                open: vec![PathBuf::from(open)],
            }],
            unreadable: 0,
        };
        let plan = plan_with(&running);
        assert!(plan.items.is_empty(), "{cwd} {open}: {plan:?}");
        assert!(
            plan.blocked[0]
                .guards
                .iter()
                .any(|g| g.name.starts_with("in-use") && g.status == GuardStatus::Block),
            "{cwd} {open}: {plan:?}"
        );
    }

    // The active revision's mount and data, and a revision sharing a
    // prefix, do not block the disabled one.
    let other = Processes {
        procs: vec![Proc {
            pid: 4444,
            name: "firefox".into(),
            cwd: Some(PathBuf::from("/var/snap/firefox/9137")),
            open: vec![
                PathBuf::from("/snap/firefox/9137/usr/lib/firefox/libxul.so"),
                PathBuf::from("/snap/firefox/90570/usr/lib/firefox/libxul.so"),
                PathBuf::from("/var/snap/firefox/common/cache"),
            ],
        }],
        unreadable: 0,
    };
    assert_eq!(plan_with(&other).items.len(), 1);

    let idle = Processes {
        procs: vec![],
        unreadable: 0,
    };
    let plan = plan_with(&idle);
    assert_eq!(plan.items.len(), 1, "{plan:?}");
    let planned = &plan.items[0];
    assert_eq!(planned.finding.tier, Tier::Review);
    let names: Vec<&str> = planned
        .finding
        .guards
        .iter()
        .map(|g| g.name.as_str())
        .collect();
    assert!(names.contains(&"in-use-open"), "{names:?}");
    assert!(names.iter().all(|n| !n.starts_with("git")), "{names:?}");
    let md = fs::symlink_metadata(&file).unwrap();
    assert_eq!(
        (planned.fingerprint.dev, planned.fingerprint.inode),
        (Some(md.dev()), Some(md.ino()))
    );
    assert_eq!(planned.fingerprint.newest_mtime, Some(md.mtime()));

    let evaluate = |det: &SnapRevisions, policy: &Policy| {
        let tree = scan_tree(&b);
        let fresh = det.detect(&tree, &cx).unwrap();
        apply::evaluate(&plan, fresh, &tree, &cx, &idle, policy)
    };
    // A review item: refused without --confirm.
    let checks = evaluate(&det, &Policy::default());
    assert_eq!(checks[0].item.outcome, ApplyOutcome::Refused);
    let confirmed = Policy {
        confirm: vec![id.clone()],
        ..Policy::default()
    };

    // `snap revert firefox` since the plan: 9057 is active, 9137 disabled.
    let mut reverted: serde_json::Value = serde_json::from_slice(&listing(&b)).unwrap();
    for e in reverted["result"].as_array_mut().unwrap() {
        if e["name"] == "firefox" {
            let active = e["revision"] == "9057";
            e["status"] = (if active { "active" } else { "installed" }).into();
        }
    }
    let reverted = serde_json::to_vec(&reverted).unwrap();
    let after_revert = SnapRevisions::with_listing(snapd_root(&b), Ok(reverted));
    let checks = evaluate(&after_revert, &confirmed);
    assert_eq!(
        checks[0].item.outcome,
        ApplyOutcome::Skipped,
        "{}",
        checks[0].item.detail
    );
    assert!(
        checks[0].item.detail.starts_with("gone"),
        "{}",
        checks[0].item.detail
    );

    // The file replaced since the plan (another inode at the path).
    fs::rename(&file, b.join("moved.snap")).unwrap();
    write(&file, 2 * MIB, 50);
    let checks = evaluate(&det, &confirmed);
    assert_eq!(checks[0].item.outcome, ApplyOutcome::Skipped);
    fs::remove_file(&file).unwrap();
    fs::rename(b.join("moved.snap"), &file).unwrap();

    let mut checks = evaluate(&det, &confirmed);
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
    assert_eq!(
        fs::read_to_string(&out).unwrap(),
        "remove\n--revision=9057\nfirefox\n"
    );
    // The fake removed nothing.
    assert!(file.exists());
}
