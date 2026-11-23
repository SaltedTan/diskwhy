//! Plans: selection, guards, fingerprints, expiry, on temp-dir fixtures.
//! Needs `git` on PATH.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{DetectContext, finding_id};
use dwhy_core::docker::Source;
use dwhy_core::guard::{Proc, Processes};
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection, TTL_SECS, Unusable};
use dwhy_core::report::{
    Action, ActionKind, DockerSocket, Finding, GuardResult, GuardStatus, HigherTierAvailable, Plan,
    PlanItem, PlanScan, Recovery, Tier, ToolStatus,
};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

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

fn ctx() -> DetectContext {
    DetectContext {
        uid: 1000,
        root: false,
        home: None,
        now: now(),
        tools: vec![ToolStatus {
            name: "git".into(),
            path: Some("/usr/bin/git".into()),
            off_path: None,
            enables: vec![],
        }],
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: Source::none(),
        cancel: Default::default(),
        scratch_paths: Vec::new(),
        scratch_stale_days: dwhy_core::detectors::SCRATCH_STALE_DAYS,
    }
}

fn finding(detector: &str, path: &Path, bytes: u64, tier: Tier) -> Finding {
    let path = path.to_string_lossy().into_owned();
    Finding {
        file_identity: None,
        id: finding_id(detector, &path),
        detector: detector.into(),
        probe: None,
        evidence: None,
        path,
        bytes,
        nested_bytes: None,
        last_modified: None,
        growth: None,
        tier,
        reason: String::new(),
        guards: Vec::new(),
        action: Action {
            kind: ActionKind::RemovePath,
            text: String::new(),
            argv: None,
        },
        recovery: Recovery {
            cost: String::new(),
            how: None,
        },
    }
}

fn base() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn dir(p: &Path) -> PathBuf {
    fs::create_dir_all(p).unwrap();
    fs::write(p.join("file"), "x").unwrap();
    p.to_path_buf()
}

fn scan_meta(root: &Path) -> PlanScan {
    PlanScan {
        roots: vec![root.to_string_lossy().into_owned()],
        one_filesystem: true,
        detectors: None,
    }
}

fn build(root: &Path, findings: Vec<Finding>, sel: &Selection, procs: &Processes) -> Plan {
    plan::build(
        findings,
        sel,
        &scan_tree(root),
        &ctx(),
        procs,
        "host".into(),
        scan_meta(root),
    )
    .unwrap()
}

fn ids(p: &Plan) -> Vec<&str> {
    let mut v: Vec<&str> = p
        .items
        .iter()
        .map(|i| i.finding.detector.as_str())
        .collect();
    v.sort();
    v
}

/// One finding of each tier, plus one a detector blocked.
fn tiers(b: &Path) -> Vec<Finding> {
    vec![
        finding("user-cache", &dir(&b.join("cache")), 100, Tier::Regenerable),
        finding(
            "cargo-target",
            &dir(&b.join("target")),
            200,
            Tier::Rebuildable,
        ),
        finding("stale-tree", &dir(&b.join("old")), 300, Tier::Review),
        finding("trash", &dir(&b.join("trash")), 400, Tier::Blocked),
    ]
}

#[test]
fn default_selection_is_regenerable_only() {
    let (_t, b) = base();
    let p = build(&b, tiers(&b), &Selection::default(), &Processes::default());
    assert_eq!(ids(&p), ["user-cache"]);
    assert_eq!(p.selection.tier, Some(Tier::Regenerable));
    assert!(
        p.blocked.is_empty(),
        "detector-blocked findings need --select"
    );
    assert_eq!(p.bytes, 100);
}

#[test]
fn tier_ceiling_includes_cheaper_tiers() {
    let (_t, b) = base();
    let sel = Selection {
        tier: Some(Tier::Rebuildable),
        select: vec![],
        free: None,
    };
    let p = build(&b, tiers(&b), &sel, &Processes::default());
    assert_eq!(ids(&p), ["cargo-target", "user-cache"]);
    let sel = Selection {
        tier: Some(Tier::Review),
        select: vec![],
        free: None,
    };
    let p = build(&b, tiers(&b), &sel, &Processes::default());
    assert_eq!(ids(&p), ["cargo-target", "stale-tree", "user-cache"]);
    assert_eq!(p.bytes, 600);
    // Largest first.
    assert_eq!(p.items[0].finding.detector, "stale-tree");
}

#[test]
fn select_by_id_or_path_lifts_the_default_ceiling() {
    let (_t, b) = base();
    let found = tiers(&b);
    let review_id = found[2].id.clone();
    let target = b.join("target").to_string_lossy().into_owned();
    let sel = Selection {
        tier: None,
        select: vec![review_id, target.clone()],
        free: None,
    };
    let p = build(&b, found.clone(), &sel, &Processes::default());
    assert_eq!(ids(&p), ["cargo-target", "stale-tree"]);
    assert_eq!(p.selection.tier, None);

    // With --tier too, a finding must match both.
    let sel = Selection {
        tier: Some(Tier::Rebuildable),
        select: sel.select.clone(),
        free: None,
    };
    let p = build(&b, found.clone(), &sel, &Processes::default());
    assert_eq!(ids(&p), ["cargo-target"]);

    // A trailing slash names the same path.
    let sel = Selection {
        tier: None,
        select: vec![format!("{target}/")],
        free: None,
    };
    let p = build(&b, found, &sel, &Processes::default());
    assert_eq!(ids(&p), ["cargo-target"]);
}

#[test]
fn selected_blocked_finding_is_listed_not_planned() {
    let (_t, b) = base();
    let found = tiers(&b);
    let sel = Selection {
        tier: None,
        select: vec![found[3].id.clone()],
        free: None,
    };
    let p = build(&b, found, &sel, &Processes::default());
    assert!(p.items.is_empty());
    assert_eq!(p.blocked.len(), 1);
    assert_eq!(p.blocked[0].detector, "trash");
    assert_eq!(p.bytes, 0);
}

#[test]
fn unknown_or_advice_selection_is_an_error() {
    let (_t, b) = base();
    let sel = Selection {
        tier: None,
        select: vec!["f_000000000000".into()],
        free: None,
    };
    let err = plan::select(tiers(&b), &sel).unwrap_err();
    assert!(err.contains("f_000000000000"), "{err}");

    let mut advice = finding("docker-volume", Path::new("/x"), 5, Tier::Review);
    advice.path = "docker://volume/pg".into();
    advice.id = finding_id("docker-volume", &advice.path);
    advice.action.kind = ActionKind::Advice;
    let sel = Selection {
        tier: None,
        select: vec![advice.id.clone()],
        free: None,
    };
    let err = plan::select(vec![advice.clone()], &sel).unwrap_err();
    assert!(err.contains("only advice"), "{err}");
    // Not picked by a ceiling either.
    let sel = Selection {
        tier: Some(Tier::Review),
        select: vec![],
        free: None,
    };
    let (picked, _) = plan::select(vec![advice], &sel).unwrap();
    assert!(picked.is_empty());
}

#[test]
fn guard_blocked_finding_moves_to_blocked() {
    let (_t, b) = base();
    let busy = dir(&b.join("cache"));
    let procs = Processes {
        procs: vec![Proc {
            pid: 4242,
            name: "uv".into(),
            cwd: Some(busy.join("sub")),
            open: vec![],
        }],
        unreadable: 0,
    };
    let p = build(&b, tiers(&b), &Selection::default(), &procs);
    assert!(p.items.is_empty());
    assert_eq!(p.blocked.len(), 1);
    let f = &p.blocked[0];
    assert_eq!(f.tier, Tier::Blocked);
    assert!(
        f.guards
            .iter()
            .any(|g| g.name == "in-use-cwd" && g.detail.contains("uv (pid 4242)")),
        "{:?}",
        f.guards
    );
}

#[test]
fn only_a_named_blocked_finding_counts_as_selected_blocked() {
    let (_t, b) = base();
    let busy = dir(&b.join("cache"));
    let procs = Processes {
        procs: vec![Proc {
            pid: 4242,
            name: "uv".into(),
            cwd: Some(busy.clone()),
            open: vec![],
        }],
        unreadable: 0,
    };
    // Picked by the default ceiling: listed as blocked, not a skip.
    let by_tier = build(&b, tiers(&b), &Selection::default(), &procs);
    assert_eq!(by_tier.blocked.len(), 1);
    assert!(!plan::selected_blocked(&by_tier));

    // Named by --select, by id or by path: a skip.
    let found = tiers(&b);
    let cache = found.iter().find(|f| f.detector == "user-cache").unwrap();
    for entry in [cache.id.clone(), busy.to_string_lossy().into_owned()] {
        let sel = Selection {
            tier: None,
            select: vec![entry],
            free: None,
        };
        let p = build(&b, found.clone(), &sel, &procs);
        assert!(p.items.is_empty());
        assert!(plan::selected_blocked(&p));
    }

    // A detector-blocked finding named by --select is a skip too.
    let trash = found.iter().find(|f| f.detector == "trash").unwrap();
    let sel = Selection {
        tier: None,
        select: vec![trash.id.clone()],
        free: None,
    };
    assert!(plan::selected_blocked(&build(
        &b,
        found.clone(),
        &sel,
        &Processes::default()
    )));

    // Nothing blocked: no skip.
    let p = build(&b, found, &Selection::default(), &Processes::default());
    assert!(p.blocked.is_empty());
    assert!(!plan::selected_blocked(&p));
}

#[test]
fn guard_results_are_kept_on_items() {
    let (_t, b) = base();
    let p = build(&b, tiers(&b), &Selection::default(), &Processes::default());
    let names: Vec<&str> = p.items[0]
        .finding
        .guards
        .iter()
        .map(|g| g.name.as_str())
        .collect();
    assert_eq!(names, ["in-use-cwd", "in-use-open"]);
}

#[test]
fn nested_items_count_once() {
    let (_t, b) = base();
    let outer = dir(&b.join("scratch"));
    let inner = dir(&outer.join("app/target"));
    let found = vec![
        finding("stale-tree", &outer, 500, Tier::Review),
        finding("cargo-target", &inner, 200, Tier::Rebuildable),
    ];
    let sel = Selection {
        tier: Some(Tier::Review),
        select: vec![],
        free: None,
    };
    let p = build(&b, found, &sel, &Processes::default());
    assert_eq!(p.items.len(), 2);
    assert_eq!(p.bytes, 500);
}

/// A scan of `outer` and `outer/child` as two roots, as when `child` is
/// another filesystem in a one-filesystem scan: the mount table names
/// `child` as a mount point, so the outer walk does not enter it.
fn tree_with_mounted_child(outer: &Path) -> ScanTree {
    let child = outer.join("child");
    let mounts = MountTable {
        mounts: vec![dwhy_core::mounts::Mount {
            id: 1,
            parent: 0,
            major: 0,
            minor: 0,
            root: "/".into(),
            mount_point: child.clone(),
            fstype: "ext4".into(),
            source: "/dev/fixture".into(),
        }],
    };
    let opts = ScanOptions {
        min_dir_bytes: 0,
        threads: 2,
        ..ScanOptions::default()
    };
    let result = scan::scan(
        &[outer.to_path_buf(), child.clone()],
        &opts,
        &mounts,
        &Progress::default(),
    )
    .unwrap();
    assert_eq!(result.skipped_mounts.len(), 1, "the outer walk skips child");
    let tree = result.tree;
    assert_eq!(tree.roots().len(), 2);
    let child_node = tree.find(&child).unwrap();
    assert_eq!(tree.parent(child_node), None, "child is its own root");
    tree
}

#[test]
fn a_separately_scanned_mount_below_another_root_counts_on_its_own() {
    let (_t, b) = base();
    let outer = dir(&b.join("outer"));
    let child = dir(&outer.join("child"));
    let sub = dir(&outer.join("sub"));
    let tree = tree_with_mounted_child(&outer);
    let s = |p: &Path| p.to_string_lossy().into_owned();
    let (outer_s, child_s, sub_s) = (s(&outer), s(&child), s(&sub));
    let (child_file, sub_file) = (s(&child.join("file")), s(&sub.join("file")));
    let items = [
        (outer_s.as_str(), 1000),
        (child_s.as_str(), 300),
        // A directory inside the outer root's walk: counted in its bytes.
        (sub_s.as_str(), 100),
        // Single files (no tree node) nest by their directory in the tree.
        (child_file.as_str(), 10),
        (sub_file.as_str(), 20),
        ("docker://volume/v", 7),
    ];
    assert_eq!(plan::distinct_bytes_in_tree(&tree, items), 1307);
    // Without the tree, nesting is by path only: child is dropped.
    assert_eq!(plan::distinct_bytes(items), 1007);
    // Paths no root covers nest by path, as distinct_bytes does.
    let elsewhere = [("/nowhere/a", 5), ("/nowhere/a/b", 3)];
    assert_eq!(plan::distinct_bytes_in_tree(&tree, elsewhere), 5);

    let found = vec![
        finding("stale-tree", &outer, 1000, Tier::Review),
        finding("stale-tree", &child, 300, Tier::Review),
        finding("cargo-target", &sub, 100, Tier::Rebuildable),
    ];
    let sel = Selection {
        tier: Some(Tier::Review),
        select: vec![],
        free: None,
    };
    let p = build_from(&tree, &b, found, &sel);
    assert_eq!(p.items.len(), 3, "{:?}", p.blocked);
    assert_eq!(p.bytes, 1300, "child counts; sub is inside outer");
}

/// A plan of `outer` (1000), `outer/child` (300, its own scan root) and
/// `outer/sub` (100, inside the outer root's walk), with both roots listed
/// in `plan.scan.roots`, as `dwhy plan` writes it.
fn plan_with_mounted_child(b: &Path) -> (Plan, PathBuf, PathBuf) {
    let outer = dir(&b.join("outer"));
    let child = dir(&outer.join("child"));
    let sub = dir(&outer.join("sub"));
    let tree = tree_with_mounted_child(&outer);
    let found = vec![
        finding("user-cache", &outer, 1000, Tier::Regenerable),
        finding("user-cache", &child, 300, Tier::Regenerable),
        finding("user-cache", &sub, 100, Tier::Regenerable),
    ];
    let mut p = build_from(&tree, &outer, found, &Selection::default());
    p.scan.roots = [&outer, &child]
        .iter()
        .map(|r| r.to_string_lossy().into_owned())
        .collect();
    assert_eq!(p.items.len(), 3, "{:?}", p.blocked);
    assert_eq!(p.bytes, 1300, "child counts on its own; sub is in outer");
    (p, outer, child)
}

fn item_at<'a>(p: &'a mut Plan, path: &Path) -> &'a mut PlanItem {
    let path = path.to_string_lossy();
    p.items.iter_mut().find(|i| i.finding.path == path).unwrap()
}

#[test]
fn plan_bytes_without_a_tree_count_a_separately_scanned_root_on_its_own() {
    let (_t, b) = base();
    let (mut p, outer, child) = plan_with_mounted_child(&b);
    // By the plan's roots: child is the deepest root above itself, so it is
    // not inside outer; sub shares outer's root and counts once.
    assert_eq!(plan::distinct_bytes_in_plan(&p, &p.items), p.bytes);
    // Path-only nesting would drop child.
    let pairs = p
        .items
        .iter()
        .map(|i| (i.finding.path.as_str(), i.finding.bytes));
    assert_eq!(plan::distinct_bytes(pairs), 1000);

    // Pseudo-paths never nest; paths no root covers nest by path.
    let mut extra = Vec::new();
    for (path, bytes) in [
        ("docker://volume/v", 7),
        ("docker://volume/v/x", 5),
        ("/nowhere/a", 20),
        ("/nowhere/a/b", 3),
    ] {
        let mut i = p.items[0].clone();
        i.finding.path = path.into();
        i.finding.bytes = bytes;
        i.fingerprint.dev = None;
        extra.push(i);
    }
    let all: Vec<&PlanItem> = p.items.iter().chain(&extra).collect();
    assert_eq!(
        plan::distinct_bytes_in_plan(&p, all.iter().copied()),
        1300 + 7 + 5 + 20
    );

    // Without child in the plan's roots, nesting falls to the devices: the
    // fixture's child is on outer's device, so it nests by path.
    p.scan.roots = vec![outer.to_string_lossy().into_owned()];
    assert_eq!(plan::distinct_bytes_in_plan(&p, &p.items), 1000);
    // A one-filesystem walk never crosses devices: another device recorded
    // for child means outer's bytes do not hold it.
    let other = item_at(&mut p, &outer).fingerprint.dev.unwrap() + 1;
    item_at(&mut p, &child).fingerprint.dev = Some(other);
    assert_eq!(plan::distinct_bytes_in_plan(&p, &p.items), 1300);
    // A walk that crosses filesystems holds every device below the root.
    p.scan.one_filesystem = false;
    assert_eq!(plan::distinct_bytes_in_plan(&p, &p.items), 1000);
    // Only the given items count.
    let just_child = p
        .items
        .iter()
        .filter(|i| Path::new(&i.finding.path) == child);
    assert_eq!(plan::distinct_bytes_in_plan(&p, just_child), 300);
}

fn fingerprint_of(root: &Path, f: &Finding) -> dwhy_core::report::Fingerprint {
    plan::fingerprint(f, &scan_tree(root), &ctx())
}

/// Sets the mtime of `p` (a file or directory) to `secs` ago.
fn age(p: &Path, secs: u64) {
    let t = SystemTime::now() - std::time::Duration::from_secs(secs);
    fs::File::open(p).unwrap().set_modified(t).unwrap();
}

#[test]
fn fingerprint_tracks_inode_mtime_and_size() {
    let (_t, b) = base();
    let d = dir(&b.join("cache"));
    age(&d.join("file"), 3600);
    age(&d, 3600);
    let f = finding("user-cache", &d, 10 << 20, Tier::Regenerable);
    let fp = fingerprint_of(&b, &f);
    assert!(fp.dev.is_some() && fp.inode.is_some());
    assert_eq!(fp.newest_mtime, Some(now() - 3600));
    assert_eq!(fp.git, None);
    assert_eq!(fp.docker_id, None);
    assert_eq!(fingerprint_of(&b, &f), fp, "nothing changed");

    // A write anywhere inside moves the newest mtime.
    fs::write(d.join("new"), "y").unwrap();
    let fp2 = fingerprint_of(&b, &f);
    assert_eq!(plan::differences(&fp, &fp2), ["newest mtime"]);

    // A replaced directory has another inode. The old one stays alive
    // until then so the filesystem cannot hand its inode number back.
    let old = b.join("cache.old");
    fs::rename(&d, &old).unwrap();
    dir(&d);
    age(&d.join("file"), 3600);
    age(&d, 3600);
    let fp3 = fingerprint_of(&b, &f);
    assert!(
        plan::differences(&fp, &fp3).contains(&"inode"),
        "{fp:?} {fp3:?}"
    );
    fs::remove_dir_all(&old).unwrap();

    // A big change in size is a change; a small one is not.
    let mut bigger = f.clone();
    bigger.bytes = 20 << 20;
    assert_eq!(
        plan::differences(&fp3, &fingerprint_of(&b, &bigger)),
        ["size"]
    );
    bigger.bytes = (10 << 20) + 4096;
    assert!(plan::differences(&fp3, &fingerprint_of(&b, &bigger)).is_empty());

    // A finding whose root is gone has no inode.
    fs::remove_dir_all(&d).unwrap();
    let gone = fingerprint_of(&b, &f);
    assert_eq!(
        (gone.dev, gone.inode, gone.newest_mtime),
        (None, None, None)
    );
}

/// Replaces directory `d` (holding only `file`) with a new directory of the
/// same contents and mtimes, as a build restoring `target` from an archive
/// would. The old one is renamed to `<d>.old` and kept, so its inode stays
/// alive and cannot be handed to the new one.
fn replace_same_contents(d: &Path) -> PathBuf {
    let file_mtime = fs::metadata(d.join("file")).unwrap().modified().unwrap();
    let dir_mtime = fs::metadata(d).unwrap().modified().unwrap();
    let old = d.with_extension("old");
    fs::rename(d, &old).unwrap();
    dir(d);
    fs::File::open(d.join("file"))
        .unwrap()
        .set_modified(file_mtime)
        .unwrap();
    fs::File::open(d).unwrap().set_modified(dir_mtime).unwrap();
    old
}

fn live_inode(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(p).unwrap().ino()
}

fn changed_guard(f: &Finding) -> Option<&str> {
    f.guards
        .iter()
        .find(|g| g.name == "changed-since-scan")
        .map(|g| {
            assert_eq!(g.status, GuardStatus::Block);
            g.detail.as_str()
        })
}

fn build_from(tree: &ScanTree, root: &Path, found: Vec<Finding>, sel: &Selection) -> Plan {
    plan::build(
        found,
        sel,
        tree,
        &ctx(),
        &Processes::default(),
        "host".into(),
        scan_meta(root),
    )
    .unwrap()
}

#[test]
fn a_stable_root_is_planned_with_the_walked_identity() {
    let (_t, b) = base();
    let d = dir(&b.join("cache"));
    let f = finding("user-cache", &d, 4096, Tier::Regenerable);
    let tree = scan_tree(&b);
    let node = tree.node(tree.find(&d).unwrap());
    let p = build_from(&tree, &b, vec![f], &Selection::default());
    assert!(p.blocked.is_empty(), "{:?}", p.blocked);
    assert_eq!(p.items.len(), 1);
    let fp = &p.items[0].fingerprint;
    assert_eq!((fp.dev, fp.inode), (Some(node.dev), Some(node.ino)));
    assert_eq!(fp.inode, Some(live_inode(&d)));
    assert_eq!(changed_guard(&p.items[0].finding), None);
}

#[test]
fn a_root_replaced_after_the_walk_is_blocked() {
    let (_t, b) = base();
    let d = dir(&b.join("target"));
    age(&d.join("file"), 3600);
    age(&d, 3600);
    let f = finding("cargo-target", &d, 4096, Tier::Rebuildable);
    let tree = scan_tree(&b);
    let walked = tree.node(tree.find(&d).unwrap()).ino;
    let _old = replace_same_contents(&d);
    let now_ino = live_inode(&d);
    assert_ne!(walked, now_ino);

    // The replacement matches the walk in everything but identity: only the
    // walked inode tells them apart.
    let fp = plan::fingerprint(&f, &tree, &ctx());
    assert_eq!(fp.inode, Some(walked), "from the walk, not a live stat");
    assert_eq!(
        plan::differences(&fp, &plan::fingerprint(&f, &scan_tree(&b), &ctx())),
        ["inode"]
    );

    // Selected by id, by path and by the tier ceiling: never an item.
    let by_id = Selection {
        tier: None,
        select: vec![f.id.clone()],
        free: None,
    };
    let by_tier = Selection {
        tier: Some(Tier::Rebuildable),
        select: vec![],
        free: None,
    };
    for sel in [&by_id, &by_tier] {
        let p = build_from(&tree, &b, vec![f.clone()], sel);
        assert!(p.items.is_empty(), "{:?}", p.items);
        assert_eq!(p.blocked.len(), 1);
        let blocked = &p.blocked[0];
        assert_eq!(blocked.tier, Tier::Blocked);
        assert_eq!(
            changed_guard(blocked),
            Some(
                format!(
                    "{} was replaced after the scan (device/inode differ)",
                    d.display()
                )
                .as_str()
            )
        );
        // `dwhy plan` exits 2 when the selection named it, 0 otherwise.
        assert_eq!(plan::selected_blocked(&p), !sel.select.is_empty());
        assert_eq!(p.bytes, 0);
    }
}

#[test]
fn a_root_gone_or_turned_symlink_after_the_walk_is_blocked() {
    let (_t, b) = base();
    let d = dir(&b.join("cache"));
    let f = finding("user-cache", &d, 4096, Tier::Regenerable);
    let tree = scan_tree(&b);
    let old = b.join("cache.old");
    fs::rename(&d, &old).unwrap();
    let p = build_from(&tree, &b, vec![f.clone()], &Selection::default());
    assert!(p.items.is_empty());
    assert_eq!(
        changed_guard(&p.blocked[0]),
        Some(format!("{} is gone since the scan", d.display()).as_str())
    );

    // A symlink to the very directory the walk measured is still refused.
    std::os::unix::fs::symlink(&old, &d).unwrap();
    let p = build_from(&tree, &b, vec![f], &Selection::default());
    assert!(p.items.is_empty());
    assert!(
        changed_guard(&p.blocked[0]).is_some_and(|g| g.contains("is a symlink now")),
        "{:?}",
        p.blocked[0].guards
    );
}

#[test]
fn an_already_blocked_selected_root_is_checked_against_the_walk() {
    let (_t, b) = base();
    let parent = dir(&b.join("venv"));
    let d = dir(&parent.join("cache"));
    let outer = finding("venv", &parent, 8192, Tier::Rebuildable);
    let mut f = finding("user-cache", &d, 4096, Tier::Blocked);
    let recent_write = GuardResult {
        name: "recent-write".into(),
        status: GuardStatus::Block,
        detail: "written recently".into(),
    };
    f.guards.push(recent_write.clone());
    let sel = Selection {
        tier: None,
        select: vec![outer.id.clone(), f.id.clone()],
        free: None,
    };
    let tree = scan_tree(&b);
    replace_same_contents(&d);

    let p = build_from(&tree, &b, vec![outer.clone(), f], &sel);
    assert_eq!(p.items.len(), 1, "{:?}", p.blocked);
    assert_eq!(p.items[0].finding.id, outer.id);
    assert_eq!(p.blocked.len(), 1);
    assert!(p.blocked[0].guards.contains(&recent_write));
    assert!(changed_guard(&p.blocked[0]).is_some_and(|g| g.contains("was replaced")));
    assert!(plan::selected_blocked(&p));
}

#[test]
fn a_detector_blocked_selection_checks_only_its_own_root() {
    let (_t, b) = base();
    let cache = dir(&b.join("cache"));
    let target = dir(&cache.join("target"));
    let mut outer = finding("user-cache", &cache, 8192, Tier::Blocked);
    let detector_block = GuardResult {
        name: "recent-write".into(),
        status: GuardStatus::Block,
        detail: "written recently".into(),
    };
    outer.guards.push(detector_block.clone());
    let inner = finding("cargo-target", &target, 4096, Tier::Rebuildable);
    let sel = Selection {
        tier: None,
        select: vec![outer.id.clone(), inner.id.clone()],
        free: None,
    };
    let tree = scan_tree(&b);
    replace_same_contents(&target);

    let p = build_from(&tree, &b, vec![outer.clone(), inner.clone()], &sel);
    assert!(p.items.is_empty(), "{:?}", p.items);
    let blocked = |id: &str| p.blocked.iter().find(|f| f.id == id).unwrap();
    // The selected child that changed is blocked for it...
    assert!(
        changed_guard(blocked(&inner.id)).is_some_and(|g| g.contains("was replaced")),
        "{:?}",
        blocked(&inner.id).guards
    );
    // ...and the cache the detector blocked keeps only its own reasons.
    assert_eq!(blocked(&outer.id).guards, [detector_block]);
    assert!(plan::selected_blocked(&p));

    // Its own root is still checked.
    replace_same_contents(&cache);
    let p = build_from(&tree, &b, vec![outer.clone()], &sel_of(&outer));
    assert!(
        changed_guard(&p.blocked[0]).is_some_and(|g| g.contains("was replaced")),
        "{:?}",
        p.blocked[0].guards
    );
}

fn sel_of(f: &Finding) -> Selection {
    Selection {
        tier: None,
        select: vec![f.id.clone()],
        free: None,
    }
}

#[test]
fn a_finding_outside_the_walk_is_blocked() {
    let (_t, b) = base();
    let scanned = dir(&b.join("scanned"));
    let elsewhere = dir(&b.join("elsewhere"));
    let f = finding("user-cache", &elsewhere, 4096, Tier::Regenerable);
    let p = build_from(
        &scan_tree(&scanned),
        &scanned,
        vec![f],
        &Selection::default(),
    );
    assert!(p.items.is_empty());
    assert!(
        changed_guard(&p.blocked[0]).is_some_and(|g| g.contains("is not in the scan")),
        "{:?}",
        p.blocked[0].guards
    );
}

fn git(dir: &Path, args: &[&str]) {
    let st = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?}");
}

#[test]
fn fingerprint_of_a_work_tree_tracks_head_and_status() {
    let (_t, b) = base();
    let repo = b.join("wt");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    let f = finding("git-worktree", &repo, 1, Tier::Review);
    let unborn = fingerprint_of(&b, &f).git.expect("git fingerprint");
    assert_eq!(unborn.head, "unborn");

    fs::write(repo.join("a"), "a").unwrap();
    git(&repo, &["add", "a"]);
    git(&repo, &["commit", "-q", "-m", "a"]);
    let clean = fingerprint_of(&b, &f).git.unwrap();
    assert_eq!(clean.head.len(), 40);

    // An untracked file changes the status hash, not HEAD.
    fs::write(repo.join("notes"), "n").unwrap();
    let dirty = fingerprint_of(&b, &f).git.unwrap();
    assert_eq!(dirty.head, clean.head);
    assert_ne!(dirty.status_hash, clean.status_hash);

    // A commit changes HEAD.
    git(&repo, &["add", "notes"]);
    git(&repo, &["commit", "-q", "-m", "n"]);
    let next = fingerprint_of(&b, &f).git.unwrap();
    assert_ne!(next.head, clean.head);
    assert_eq!(next.status_hash, clean.status_hash);

    // Tool caches get no git fingerprint, like they get no git guards.
    let cache = finding("user-cache", &repo, 1, Tier::Regenerable);
    assert_eq!(fingerprint_of(&b, &cache).git, None);
}

fn plan_at(created: i64) -> Plan {
    let (_t, b) = base();
    let mut c = ctx();
    c.now = created;
    plan::build(
        vec![],
        &Selection::default(),
        &scan_tree(&b),
        &c,
        &Processes::default(),
        "host".into(),
        scan_meta(&b),
    )
    .unwrap()
}

#[test]
fn plans_expire_after_an_hour() {
    let t = now();
    let p = plan_at(t);
    assert_eq!(plan::usable(&p, "host", 1000, t), Ok(()));
    assert_eq!(plan::usable(&p, "host", 1000, t + TTL_SECS - 1), Ok(()));
    assert!(matches!(
        plan::usable(&p, "host", 1000, t + TTL_SECS),
        Err(Unusable::Expired(_))
    ));
    // Editing expires_at does not extend a plan's life.
    let mut edited = p.clone();
    edited.expires_at = "2999-01-01T00:00:00Z".into();
    assert!(matches!(
        plan::usable(&edited, "host", 1000, t + TTL_SECS + 5),
        Err(Unusable::Expired(_))
    ));
    // Nor does moving created_at into the future, even by a second.
    let mut future = p.clone();
    future.created_at = "2999-01-01T00:00:00Z".into();
    assert!(matches!(
        plan::usable(&future, "host", 1000, t),
        Err(Unusable::Expired(_))
    ));
    let ahead = plan_at(t + 1);
    assert!(matches!(
        plan::usable(&ahead, "host", 1000, t),
        Err(Unusable::Expired(_))
    ));
    assert_eq!(plan::usable(&ahead, "host", 1000, t + 1), Ok(()));
}

#[test]
fn plans_belong_to_their_host_and_uid() {
    let t = now();
    let p = plan_at(t);
    assert!(matches!(
        plan::usable(&p, "other", 1000, t),
        Err(Unusable::Elsewhere(_))
    ));
    assert!(matches!(
        plan::usable(&p, "host", 0, t),
        Err(Unusable::Elsewhere(_))
    ));
}

#[test]
fn plan_files_round_trip_and_check_the_schema() {
    let p = plan_at(now());
    let text = serde_json::to_string_pretty(&p).unwrap();
    assert_eq!(plan::parse(&text).unwrap(), p);
    let v2 = text.replace("diskwhy/v1", "diskwhy/v2");
    assert!(plan::parse(&v2).unwrap_err().contains("unsupported schema"));
    assert!(plan::parse("{}").is_err());
    assert!(plan::parse("not json").is_err());
}

#[test]
fn building_a_plan_writes_nothing() {
    let (_t, b) = base();
    let found = tiers(&b);
    let before = listing(&b);
    let sel = Selection {
        tier: Some(Tier::Review),
        select: vec![],
        free: None,
    };
    build(&b, found, &sel, &Processes::default());
    assert_eq!(listing(&b), before);
}

/// (path, size, mtime) of everything under `p`.
fn listing(p: &Path) -> Vec<(String, u64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let md = fs::symlink_metadata(&d).unwrap();
        out.push((d.display().to_string(), md.size(), md.mtime()));
        if md.is_dir() {
            for e in fs::read_dir(&d).unwrap() {
                stack.push(e.unwrap().path());
            }
        }
    }
    out.sort();
    out
}

/// A plan item at `path` holding `bytes`, measured on device `dev`, with
/// the device of the scan root that measured it when that differs.
fn item_on(p: &Plan, path: &str, bytes: u64, dev: u64, scan_root_dev: Option<u64>) -> PlanItem {
    let mut i = p.items[0].clone();
    i.finding.path = path.into();
    i.finding.bytes = bytes;
    i.fingerprint.dev = Some(dev);
    i.scan_root_dev = scan_root_dev;
    i
}

/// A hand-made plan of a one-filesystem scan of `roots`, with no items.
fn plan_of(roots: &[&str]) -> Plan {
    let (_t, b) = base();
    let (mut p, _, _) = plan_with_mounted_child(&b);
    p.scan.roots = roots.iter().map(|r| r.to_string()).collect();
    p.scan.one_filesystem = true;
    p
}

#[test]
fn plan_bytes_without_a_tree_nest_items_in_btrfs_subvolumes_the_walk_entered() {
    // A -x scan of /mnt/b (device 28) walked into unmounted btrfs
    // subvolumes: sub (31) and, inside it, deeper (32).
    let p = plan_of(&["/mnt/b"]);
    let outer = item_on(&p, "/mnt/b/x", 1000, 28, None);
    let sub = item_on(&p, "/mnt/b/x/sub", 300, 31, Some(28));
    let deeper = item_on(&p, "/mnt/b/x/sub/deeper", 50, 32, Some(28));
    let bytes = |items: &[&PlanItem]| plan::distinct_bytes_in_plan(&p, items.iter().copied());
    assert_eq!(bytes(&[&outer, &sub]), 1000, "sub is inside outer");
    assert_eq!(bytes(&[&sub, &deeper]), 300, "deeper is inside sub");
    assert_eq!(bytes(&[&outer, &sub, &deeper]), 1000);
    // Siblings still add up.
    let other = item_on(&p, "/mnt/b/y", 20, 31, Some(28));
    assert_eq!(bytes(&[&outer, &sub, &other]), 1020);

    // A plan written before scan_root_dev existed falls back to the
    // fingerprints' devices, which differ.
    let mut old_sub = sub.clone();
    old_sub.scan_root_dev = None;
    assert_eq!(bytes(&[&outer, &old_sub]), 1300);
}

#[test]
fn plan_bytes_without_a_tree_count_a_separately_mounted_child_on_its_own() {
    // /mnt/b/mounted is mounted on its own (device 32), so the walk of
    // /mnt/b stopped there; scanned as its own root or not at all, it
    // records no scan root device of /mnt/b.
    for roots in [&["/mnt/b", "/mnt/b/mounted"][..], &["/mnt/b"][..]] {
        let p = plan_of(roots);
        let outer = item_on(&p, "/mnt/b", 1000, 28, None);
        let child = item_on(&p, "/mnt/b/mounted", 300, 32, None);
        let inside_child = item_on(&p, "/mnt/b/mounted/x", 30, 32, None);
        assert_eq!(
            plan::distinct_bytes_in_plan(&p, [&outer, &child, &inside_child]),
            1300,
            "{roots:?}"
        );
    }
}

#[test]
fn scan_root_dev_is_optional_in_plan_files() {
    let (_t, b) = base();
    let (mut p, outer, child) = plan_with_mounted_child(&b);
    assert!(p.items.iter().all(|i| i.scan_root_dev.is_none()));
    let text = plan::to_json(&p).unwrap();
    assert!(!text.contains("scan_root_dev"), "omitted when absent");
    item_at(&mut p, &child).scan_root_dev = Some(7);
    let text = plan::to_json(&p).unwrap();
    assert!(text.contains("\"scan_root_dev\": 7"), "{text}");
    let back = plan::parse(&text).unwrap();
    assert_eq!(back, p);
    let outer = outer.to_string_lossy();
    let read = back.items.iter().find(|i| i.finding.path == outer).unwrap();
    assert_eq!(read.scan_root_dev, None);
}

#[test]
fn plan_records_the_scan_root_device_of_an_item_on_another_device() {
    use std::os::unix::fs::MetadataExt;
    // A walk that crosses from /dev into a filesystem mounted below it
    // stands in for a -x walk entering a btrfs subvolume: either way the
    // tree holds a node on another device below the root.
    let Some(mounted) = MountTable::read()
        .unwrap()
        .mounts
        .iter()
        .filter(|m| m.mount_point.parent() == Some(Path::new("/dev")) && !m.is_virtual())
        .map(|m| m.mount_point.clone())
        .find(|m| fs::read_dir(m).is_ok())
    else {
        eprintln!("skipped: no readable disk mount directly below /dev here");
        return;
    };
    let root = Path::new("/dev");
    let opts = ScanOptions {
        one_filesystem: false,
        min_dir_bytes: 0,
        threads: 2,
        ..ScanOptions::default()
    };
    let tree = scan::scan(
        &[root.to_path_buf()],
        &opts,
        &MountTable::read().unwrap(),
        &Progress::default(),
    )
    .unwrap()
    .tree;
    let found = vec![
        finding("user-cache", root, 1000, Tier::Regenerable),
        finding("user-cache", &mounted, 10, Tier::Regenerable),
    ];
    let mut p = build_from(&tree, root, found, &Selection::default());
    assert_eq!(p.items.len(), 2, "{:?}", p.blocked);
    assert_eq!(p.bytes, 1000, "the mount was walked from /dev");
    let root_dev = fs::symlink_metadata(root).unwrap().dev();
    assert_eq!(
        item_at(&mut p, root).scan_root_dev,
        None,
        "on the root's device"
    );
    let inner = item_at(&mut p, &mounted);
    assert_ne!(inner.fingerprint.dev, Some(root_dev));
    assert_eq!(inner.scan_root_dev, Some(root_dev));
    // Read back as a -x plan, the items still nest as the walk saw them.
    p.scan.one_filesystem = true;
    assert_eq!(plan::distinct_bytes_in_plan(&p, &p.items), p.bytes);
}

fn goal(tier: Tier, free: u64) -> Selection {
    Selection {
        tier: Some(tier),
        select: vec![],
        free: Some(free),
    }
}

/// The paths of a plan's items, in plan order (largest first).
fn item_paths(p: &Plan) -> Vec<&str> {
    p.items.iter().map(|i| i.finding.path.as_str()).collect()
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn free_takes_the_cheapest_tier_first_and_stops_at_the_target() {
    let (_t, b) = base();
    let found = || {
        vec![
            finding("user-cache", &dir(&b.join("cache")), 100, Tier::Regenerable),
            finding("user-cache", &dir(&b.join("cache2")), 50, Tier::Regenerable),
            finding(
                "cargo-target",
                &dir(&b.join("target")),
                200,
                Tier::Rebuildable,
            ),
            finding("stale-tree", &dir(&b.join("old")), 300, Tier::Review),
        ]
    };
    let p = build(&b, found(), &goal(Tier::Review, 120), &Processes::default());
    assert_eq!(
        item_paths(&p),
        [s(&b.join("cache")), s(&b.join("cache2"))],
        "regenerable covers the target: nothing costlier"
    );
    assert_eq!(p.bytes, 150);
    assert_eq!(p.selection.free_target, Some(120));
    assert_eq!(p.selection.tier, Some(Tier::Review));
    let g = p.goal.as_ref().unwrap();
    assert_eq!(
        (g.target_bytes, g.planned_bytes, g.met, g.shortfall_bytes),
        (120, 150, true, 0)
    );
    assert!(g.higher_tiers.is_empty(), "nothing above review");

    let p = build(&b, found(), &goal(Tier::Review, 160), &Processes::default());
    assert_eq!(
        item_paths(&p),
        [
            s(&b.join("target")),
            s(&b.join("cache")),
            s(&b.join("cache2"))
        ],
        "all of regenerable, then rebuildable; review is not needed"
    );
    assert_eq!(p.bytes, 350);
    assert!(p.goal.unwrap().met);
}

#[test]
fn free_takes_the_largest_first_within_a_tier() {
    let (_t, b) = base();
    let found = || {
        vec![
            finding("user-cache", &dir(&b.join("a")), 50, Tier::Regenerable),
            finding("user-cache", &dir(&b.join("b")), 300, Tier::Regenerable),
            finding("user-cache", &dir(&b.join("c")), 100, Tier::Regenerable),
        ]
    };
    let free = |n| {
        build(
            &b,
            found(),
            &goal(Tier::Regenerable, n),
            &Processes::default(),
        )
    };
    assert_eq!(item_paths(&free(250)), [s(&b.join("b"))]);
    assert_eq!(item_paths(&free(300)), [s(&b.join("b"))], "exactly met");
    let p = free(350);
    assert_eq!(item_paths(&p), [s(&b.join("b")), s(&b.join("c"))]);
    assert_eq!(p.bytes, 400);
}

#[test]
fn free_counts_only_the_bytes_a_finding_adds() {
    let (_t, b) = base();
    // A cheaper inner finding already chosen leaves its outer finding only
    // what lies outside it: the smaller `other` adds more.
    let outer = dir(&b.join("outer"));
    let inner = dir(&outer.join("inner"));
    let other = dir(&b.join("other"));
    let found = vec![
        finding("user-cache", &inner, 400, Tier::Regenerable),
        finding("cargo-target", &outer, 500, Tier::Rebuildable),
        finding("cargo-target", &other, 150, Tier::Rebuildable),
    ];
    let p = build(
        &b,
        found,
        &goal(Tier::Rebuildable, 520),
        &Processes::default(),
    );
    assert_eq!(item_paths(&p), [s(&inner), s(&other)]);
    assert_eq!(p.bytes, 550);

    // A finding inside one already chosen adds nothing and is left out.
    let (_t, b) = base();
    let big = dir(&b.join("big"));
    let within = dir(&big.join("in"));
    let small = dir(&b.join("small"));
    let found = vec![
        finding("user-cache", &big, 1000, Tier::Regenerable),
        finding("user-cache", &within, 900, Tier::Regenerable),
        finding("user-cache", &small, 10, Tier::Regenerable),
    ];
    let p = build(
        &b,
        found,
        &goal(Tier::Regenerable, 1005),
        &Processes::default(),
    );
    assert_eq!(item_paths(&p), [s(&big), s(&small)]);
    assert_eq!(p.bytes, 1010);
    let g = p.goal.unwrap();
    assert_eq!((g.planned_bytes, g.met), (1010, true));

    // Empty findings add nothing either.
    let (_t, b) = base();
    let found = vec![finding(
        "user-cache",
        &dir(&b.join("e")),
        0,
        Tier::Regenerable,
    )];
    let p = build(
        &b,
        found,
        &goal(Tier::Regenerable, 1),
        &Processes::default(),
    );
    assert!(p.items.is_empty());
    assert_eq!(p.goal.unwrap().shortfall_bytes, 1);
}

#[test]
fn free_counts_a_separately_scanned_mount_on_its_own() {
    let (_t, b) = base();
    let outer = dir(&b.join("outer"));
    let child = dir(&outer.join("child"));
    let sub = dir(&outer.join("sub"));
    let tree = tree_with_mounted_child(&outer);
    let found = vec![
        finding("user-cache", &outer, 1000, Tier::Regenerable),
        finding("user-cache", &child, 300, Tier::Regenerable),
        finding("user-cache", &sub, 100, Tier::Regenerable),
    ];
    let p = build_from(&tree, &b, found, &goal(Tier::Regenerable, 1200));
    assert_eq!(item_paths(&p), [s(&outer), s(&child)], "sub adds nothing");
    assert_eq!(p.bytes, 1300);
    assert!(p.goal.unwrap().met);
}

#[test]
fn free_skips_guard_blocked_and_advice_only_findings() {
    let (_t, b) = base();
    let busy = dir(&b.join("busy"));
    let procs = Processes {
        procs: vec![Proc {
            pid: 4242,
            name: "uv".into(),
            cwd: Some(busy.clone()),
            open: vec![],
        }],
        unreadable: 0,
    };
    let mut advice = finding(
        "user-cache",
        &dir(&b.join("advice")),
        1000,
        Tier::Regenerable,
    );
    advice.action.kind = ActionKind::Advice;
    let found = vec![
        finding("user-cache", &busy, 500, Tier::Regenerable),
        advice,
        finding("user-cache", &dir(&b.join("ok")), 100, Tier::Regenerable),
    ];
    let p = build(&b, found, &goal(Tier::Regenerable, 600), &procs);
    assert_eq!(item_paths(&p), [s(&b.join("ok"))]);
    assert_eq!(p.blocked.len(), 1);
    assert_eq!(p.blocked[0].path, s(&busy));
    assert!(!plan::selected_blocked(&p), "a goal names no finding");
    let g = p.goal.unwrap();
    assert_eq!(
        (g.planned_bytes, g.met, g.shortfall_bytes),
        (100, false, 500)
    );
}

#[test]
fn free_reports_the_shortfall_and_what_higher_tiers_hold() {
    let (_t, b) = base();
    let mut found = tiers(&b);
    // Own bytes only: 50 of the target's 200 belong to a finding inside it.
    found[1].nested_bytes = Some(50);
    found.push(finding(
        "cargo-target",
        &dir(&b.join("target2")),
        70,
        Tier::Rebuildable,
    ));
    let mut advice = finding("stale-tree", &dir(&b.join("advice")), 5000, Tier::Review);
    advice.action.kind = ActionKind::Advice;
    found.push(advice);
    let p = build(
        &b,
        found,
        &goal(Tier::Regenerable, 1000),
        &Processes::default(),
    );
    assert_eq!(ids(&p), ["user-cache"]);
    let g = p.goal.as_ref().unwrap();
    assert_eq!(
        (g.target_bytes, g.planned_bytes, g.met, g.shortfall_bytes),
        (1000, 100, false, 900)
    );
    assert_eq!(
        g.higher_tiers,
        [
            HigherTierAvailable {
                tier: Tier::Rebuildable,
                count: 2,
                bytes: 220,
            },
            HigherTierAvailable {
                tier: Tier::Review,
                count: 1,
                bytes: 300,
            },
        ],
        "advice-only and detector-blocked findings are left out"
    );

    // A rebuildable ceiling reports review only.
    let p = build(
        &b,
        tiers(&b),
        &goal(Tier::Rebuildable, 1000),
        &Processes::default(),
    );
    let g = p.goal.unwrap();
    assert_eq!((g.planned_bytes, g.shortfall_bytes), (300, 700));
    assert_eq!(g.higher_tiers.len(), 1);
    assert_eq!(g.higher_tiers[0].tier, Tier::Review);
}

#[test]
fn a_goal_round_trips_and_is_absent_without_free() {
    let (_t, b) = base();
    let p = build(
        &b,
        tiers(&b),
        &goal(Tier::Regenerable, 1000),
        &Processes::default(),
    );
    let text = plan::to_json(&p).unwrap();
    assert!(text.contains("\"free_target\": 1000"), "{text}");
    assert_eq!(plan::parse(&text).unwrap(), p);

    let p = build(&b, tiers(&b), &Selection::default(), &Processes::default());
    assert_eq!((p.selection.free_target, &p.goal), (None, &None));
    let text = plan::to_json(&p).unwrap();
    assert!(
        !text.contains("free_target") && !text.contains("goal"),
        "{text}"
    );
}

#[test]
fn free_must_be_positive_and_excludes_select() {
    let (_t, b) = base();
    let run = |sel: &Selection| {
        plan::build(
            tiers(&b),
            sel,
            &scan_tree(&b),
            &ctx(),
            &Processes::default(),
            "host".into(),
            scan_meta(&b),
        )
    };
    let err = run(&goal(Tier::Regenerable, 0)).unwrap_err();
    assert!(err.contains("greater than 0"), "{err}");
    let found = tiers(&b);
    let sel = Selection {
        tier: None,
        select: vec![found[0].id.clone()],
        free: Some(10),
    };
    let err = run(&sel).unwrap_err();
    assert!(err.contains("--select"), "{err}");
}
