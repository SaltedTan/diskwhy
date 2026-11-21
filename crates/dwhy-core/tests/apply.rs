//! Apply: safe path removal, the tier policy, re-checks against the plan,
//! and the audit log. Everything removed lives in a temp dir.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::apply::{self, Audit, Check, Env, Policy};
use dwhy_core::detect::{DetectContext, finding_id};
use dwhy_core::docker::Source;
use dwhy_core::guard::{Proc, Processes};
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::remove::remove_tree;
use dwhy_core::report::{
    Action, ActionKind, ApplyOutcome, AuditEvent, AuditRecord, DockerSocket, Finding, GuardResult,
    GuardStatus, Plan, PlanScan, Recovery, Tier, ToolStatus,
};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

fn base() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn no_mounts() -> MountTable {
    MountTable::default()
}

fn write(p: &Path, body: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

/// Restores write permission so a test failure leaves a removable temp dir.
struct Writable(PathBuf);

impl Drop for Writable {
    fn drop(&mut self) {
        let mut stack = vec![self.0.clone()];
        while let Some(d) = stack.pop() {
            let _ = fs::set_permissions(&d, fs::Permissions::from_mode(0o755));
            if let Ok(rd) = fs::read_dir(&d) {
                for e in rd.flatten() {
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        stack.push(e.path());
                    }
                }
            }
        }
    }
}

fn is_root() -> bool {
    rustix_euid() == 0
}

fn rustix_euid() -> u32 {
    // The test binary's uid, read from /proc to avoid another dependency.
    let s = fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|u| u.parse().ok())
        .unwrap()
}

// ---------------------------------------------------------------------------
// remove_tree
// ---------------------------------------------------------------------------

#[test]
fn removes_a_tree_and_only_that_tree() {
    let (_t, b) = base();
    let root = b.join("target");
    write(&root.join("debug/deep/a"), "aaaa");
    write(&root.join("b"), "b");
    write(&b.join("outside/keep"), "keep");
    write(&b.join("sibling-target/x"), "x");
    // Symlinks inside, to a file and a directory outside: unlinked, not followed.
    symlink(b.join("outside/keep"), root.join("link-to-file")).unwrap();
    symlink(b.join("outside"), root.join("debug/link-to-dir")).unwrap();
    // A hardlink to a file outside: the outside name keeps the data.
    fs::hard_link(b.join("outside/keep"), root.join("hard")).unwrap();

    let r = remove_tree(&root, None, &no_mounts()).unwrap();
    assert!(!root.exists());
    assert_eq!(fs::read_to_string(b.join("outside/keep")).unwrap(), "keep");
    assert!(b.join("sibling-target/x").exists());
    assert_eq!((r.files, r.dirs), (5, 3), "{r:?}");
}

#[test]
fn a_symlink_root_is_refused() {
    let (_t, b) = base();
    write(&b.join("real/data"), "d");
    symlink(b.join("real"), b.join("target")).unwrap();
    let err = remove_tree(&b.join("target"), None, &no_mounts()).unwrap_err();
    assert!(err.contains("is a symlink"), "{err}");
    assert!(b.join("real/data").exists());
    assert!(fs::symlink_metadata(b.join("target")).is_ok());
}

#[test]
fn a_symlink_in_the_path_is_refused() {
    let (_t, b) = base();
    write(&b.join("real/target/data"), "d");
    symlink(b.join("real"), b.join("via")).unwrap();
    let err = remove_tree(&b.join("via/target"), None, &no_mounts()).unwrap_err();
    assert!(err.contains("symlinks are never followed"), "{err}");
    assert!(b.join("real/target/data").exists());
}

#[test]
fn another_inode_than_the_plans_is_refused() {
    let (_t, b) = base();
    let root = b.join("cache");
    write(&root.join("f"), "f");
    let err = remove_tree(&root, Some((1, 2)), &no_mounts()).unwrap_err();
    assert!(err.contains("not the inode the plan recorded"), "{err}");
    assert!(root.join("f").exists());
}

#[test]
fn a_mount_point_inside_is_refused_before_anything_is_removed() {
    let (_t, b) = base();
    let root = b.join("scratch");
    write(&root.join("a/file"), "x");
    write(&root.join("mnt/inner"), "y");
    let table = MountTable::parse(&format!(
        "36 35 98:0 / {} rw,noatime - ext4 /dev/sdb1 rw\n",
        root.join("mnt").display()
    ));
    let err = remove_tree(&root, None, &table).unwrap_err();
    assert!(
        err.contains("refusing to cross a filesystem boundary"),
        "{err}"
    );
    assert!(root.join("a/file").exists() && root.join("mnt/inner").exists());
    // The root being a mount point itself counts too.
    let table = MountTable::parse(&format!(
        "36 35 98:0 / {} rw - ext4 /dev/sdb1 rw\n",
        root.display()
    ));
    assert!(remove_tree(&root, None, &table).is_err());
    assert!(root.join("a/file").exists());
}

#[test]
fn read_only_directories_of_ours_are_removed() {
    if is_root() {
        return;
    }
    let (_t, b) = base();
    let root = b.join("go-mod");
    write(&root.join("pkg@v1/file.go"), "package x");
    write(&root.join("locked/secret"), "s");
    let _w = Writable(root.clone());
    fs::set_permissions(root.join("pkg@v1"), fs::Permissions::from_mode(0o555)).unwrap();
    fs::set_permissions(root.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    remove_tree(&root, None, &no_mounts()).unwrap();
    assert!(!root.exists());
}

#[test]
fn a_single_file_root_is_removed() {
    let (_t, b) = base();
    let f = b.join("dir/file.bin");
    write(&f, "data");
    let r = remove_tree(&f, None, &no_mounts()).unwrap();
    assert_eq!(r.files, 1);
    assert!(!f.exists() && b.join("dir").exists());
}

// ---------------------------------------------------------------------------
// evaluate / execute
// ---------------------------------------------------------------------------

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
    }
}

fn finding(detector: &str, path: &Path, tier: Tier) -> Finding {
    let path = path.to_string_lossy().into_owned();
    Finding {
        file_identity: None,
        id: finding_id(detector, &path),
        detector: detector.into(),
        probe: None,
        evidence: None,
        path: path.clone(),
        bytes: 4096,
        nested_bytes: None,
        last_modified: None,
        growth: None,
        tier,
        reason: String::new(),
        guards: Vec::new(),
        action: Action {
            kind: ActionKind::RemovePath,
            text: format!("remove {path}"),
            argv: None,
        },
        recovery: Recovery {
            cost: String::new(),
            how: None,
        },
    }
}

/// The three tiers a plan can hold, each a directory with a file in it.
fn fixture(b: &Path) -> Vec<Finding> {
    for d in ["cache", "target", "scratch"] {
        write(&b.join(d).join("file"), d);
    }
    vec![
        finding("user-cache", &b.join("cache"), Tier::Regenerable),
        finding("cargo-target", &b.join("target"), Tier::Rebuildable),
        finding("stale-tree", &b.join("scratch"), Tier::Review),
    ]
}

fn make_plan(b: &Path, findings: Vec<Finding>) -> Plan {
    make_plan_from_tree(b, findings, &scan_tree(b))
}

fn make_plan_from_tree(b: &Path, findings: Vec<Finding>, tree: &ScanTree) -> Plan {
    plan::build(
        findings,
        &Selection {
            tier: Some(Tier::Review),
            select: vec![],
        },
        tree,
        &ctx(),
        &Processes::default(),
        "host".into(),
        PlanScan {
            roots: vec![b.to_string_lossy().into_owned()],
            one_filesystem: true,
            detectors: None,
        },
    )
    .unwrap()
}

fn evaluate(b: &Path, plan: &Plan, fresh: Vec<Finding>, policy: &Policy) -> Vec<Check> {
    apply::evaluate(
        plan,
        fresh,
        &scan_tree(b),
        &ctx(),
        &Processes::default(),
        policy,
    )
}

fn outcomes(checks: &[Check]) -> Vec<(&str, ApplyOutcome)> {
    checks
        .iter()
        .map(|c| (c.item.detector.as_str(), c.item.outcome))
        .collect()
}

fn policy(max: Tier, confirm: &[&str]) -> Policy {
    Policy {
        max_tier: max,
        confirm: confirm.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn default_policy_allows_regenerable_only() {
    let (_t, b) = base();
    let found = fixture(&b);
    let plan = make_plan(&b, found.clone());
    let checks = evaluate(&b, &plan, found, &Policy::default());
    let mut got = outcomes(&checks);
    got.sort_by_key(|(d, _)| *d);
    assert_eq!(
        got,
        [
            ("cargo-target", ApplyOutcome::Refused),
            ("stale-tree", ApplyOutcome::Refused),
            ("user-cache", ApplyOutcome::WouldRemove),
        ]
    );
    let refused = checks
        .iter()
        .find(|c| c.item.detector == "cargo-target")
        .unwrap();
    assert!(refused.item.detail.contains("above --max-tier regenerable"));
    let review = checks
        .iter()
        .find(|c| c.item.detector == "stale-tree")
        .unwrap();
    assert!(
        review.item.detail.contains("--confirm"),
        "{}",
        review.item.detail
    );
}

#[test]
fn max_tier_and_confirm() {
    let (_t, b) = base();
    let found = fixture(&b);
    let plan = make_plan(&b, found.clone());
    let review_id = found[2].id.clone();

    let checks = evaluate(&b, &plan, found.clone(), &policy(Tier::Rebuildable, &[]));
    let ready: Vec<&str> = checks
        .iter()
        .filter(|c| c.ready())
        .map(|c| c.item.detector.as_str())
        .collect();
    assert_eq!(ready.len(), 2);
    assert!(!ready.contains(&"stale-tree"));

    // --max-tier review alone still refuses a review item.
    let checks = evaluate(&b, &plan, found.clone(), &policy(Tier::Review, &[]));
    assert!(
        checks
            .iter()
            .any(|c| c.item.detector == "stale-tree" && c.item.outcome == ApplyOutcome::Refused)
    );

    // --confirm alone lets that review item through, but no rebuildable one.
    let checks = evaluate(&b, &plan, found, &policy(Tier::Regenerable, &[&review_id]));
    let mut got = outcomes(&checks);
    got.sort_by_key(|(d, _)| *d);
    assert_eq!(
        got,
        [
            ("cargo-target", ApplyOutcome::Refused),
            ("stale-tree", ApplyOutcome::WouldRemove),
            ("user-cache", ApplyOutcome::WouldRemove),
        ]
    );
}

#[test]
fn a_changed_fingerprint_skips_the_item() {
    let (_t, b) = base();
    let found = fixture(&b);
    let plan = make_plan(&b, found.clone());
    // Something writes into the cache after the plan.
    write(&b.join("cache/new"), "new");
    fs::File::open(b.join("cache/new"))
        .unwrap()
        .set_modified(SystemTime::now() + std::time::Duration::from_secs(5))
        .unwrap();
    let checks = evaluate(&b, &plan, found, &Policy::default());
    let c = checks
        .iter()
        .find(|c| c.item.detector == "user-cache")
        .unwrap();
    assert_eq!(c.item.outcome, ApplyOutcome::Skipped);
    assert!(c.item.detail.contains("newest mtime"), "{}", c.item.detail);
}

#[test]
fn a_replaced_root_skips_the_item() {
    let (_t, b) = base();
    let found = fixture(&b);
    let plan = make_plan(&b, found.clone());
    // Keep the old inode alive so the new directory cannot reuse it.
    fs::rename(b.join("cache"), b.join("cache.old")).unwrap();
    write(&b.join("cache/file"), "cache");
    let checks = evaluate(&b, &plan, found, &Policy::default());
    let c = &checks
        .iter()
        .find(|c| c.item.detector == "user-cache")
        .unwrap()
        .item;
    assert_eq!(c.outcome, ApplyOutcome::Skipped);
    assert!(c.detail.contains("inode"), "{}", c.detail);
}

#[test]
fn a_root_replaced_after_applys_own_scan_is_skipped() {
    let (_t, b) = base();
    let mut found = fixture(&b);
    found.retain(|f| f.detector == "user-cache");
    let plan = make_plan(&b, found.clone());
    // Apply's own walk still sees the planned directory, so its fresh
    // fingerprint matches the plan...
    let tree = scan_tree(&b);
    let cache = b.join("cache");
    let file_mtime = fs::metadata(cache.join("file"))
        .unwrap()
        .modified()
        .unwrap();
    let dir_mtime = fs::metadata(&cache).unwrap().modified().unwrap();
    // ...and then the root is swapped for a copy with the same contents and
    // mtimes. The old one is kept so its inode cannot be reused.
    fs::rename(&cache, b.join("cache.old")).unwrap();
    write(&cache.join("file"), "cache");
    fs::File::open(cache.join("file"))
        .unwrap()
        .set_modified(file_mtime)
        .unwrap();
    fs::File::open(&cache)
        .unwrap()
        .set_modified(dir_mtime)
        .unwrap();
    let checks = apply::evaluate(
        &plan,
        found,
        &tree,
        &ctx(),
        &Processes::default(),
        &Policy::default(),
    );
    let c = checks
        .iter()
        .find(|c| c.item.detector == "user-cache")
        .unwrap();
    assert_eq!(c.item.outcome, ApplyOutcome::Skipped);
    assert_eq!(
        c.item.detail,
        format!(
            "changed since the scan: {} was replaced after the scan (device/inode differ)",
            cache.display()
        )
    );
    assert!(
        c.item
            .guards
            .iter()
            .any(|g| g.name == "changed-since-scan" && g.status == GuardStatus::Block),
        "{:?}",
        c.item.guards
    );
    // A dry run: nothing ran, and the exit code is the skip's.
    assert!(cache.join("file").exists());
    let r = apply::report(&plan, &checks, &Policy::default(), true, &env());
    assert_eq!(apply::exit_code(&r), 2);
}

fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args([
            "--no-optional-locks",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn survey_skips_a_symlink_replacement_without_reporting_its_git_worktrees() {
    let (_t, b) = base();
    let (_other, other) = base();
    let mut found = fixture(&b);
    found.retain(|f| f.detector != "cargo-target");
    let detector_guard = GuardResult {
        name: "fixture-detector".into(),
        status: GuardStatus::Warn,
        detail: "reported during detection".into(),
    };
    found[1].guards.push(detector_guard.clone());
    let scratch = b.join("scratch");
    let original = scratch.join("repo");
    let replacement = other.join("tree/repo");
    let linked = other.join("linked");
    for repo in [&original, &replacement] {
        fs::create_dir_all(repo).unwrap();
        git(repo, &["init", "-q"]);
    }
    git(&replacement, &["commit", "--allow-empty", "-qm", "fixture"]);
    git(
        &replacement,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            linked.to_str().unwrap(),
        ],
    );
    let plan = make_plan(&b, found.clone());
    assert_eq!(plan.items.len(), 2);
    let tree = scan_tree(&b);
    fs::rename(&scratch, scratch.with_extension("old")).unwrap();
    symlink(other.join("tree"), &scratch).unwrap();

    let pol = policy(Tier::Regenerable, &[&found[1].id]);
    let checks = apply::evaluate(&plan, found, &tree, &ctx(), &Processes::default(), &pol);
    let report = apply::report(&plan, &checks, &pol, true, &env());
    assert_eq!(apply::exit_code(&report), 2);
    let skipped = report
        .items
        .iter()
        .find(|i| i.detector == "stale-tree")
        .unwrap();
    assert_eq!(skipped.outcome, ApplyOutcome::Skipped);
    assert_eq!(skipped.guards.len(), 2, "{:?}", skipped.guards);
    assert_eq!(skipped.guards[0], detector_guard);
    assert_eq!(skipped.guards[1].name, "changed-since-scan");
    assert_eq!(skipped.guards[1].status, GuardStatus::Block);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains(other.to_str().unwrap())
    );
    let ready = checks.iter().find(|c| c.ready()).unwrap();
    assert!(ready.item.guards.iter().any(|g| g.name == "in-use-cwd"));
}

#[test]
fn a_skipped_replacement_still_blocks_removal_of_its_git_dir() {
    let (_t, b) = base();
    let (_other, other) = base();
    let scratch = b.join("scratch");
    let original = scratch.join("repo");
    let metadata = b.join("metadata");
    let git_dir = metadata.join("repo.git");
    let replacement = other.join("tree/repo");
    for dir in [&original, &metadata, &replacement] {
        fs::create_dir_all(dir).unwrap();
    }
    git(&original, &["init", "-q"]);
    git(
        &replacement,
        &[
            "init",
            "-q",
            "--separate-git-dir",
            git_dir.to_str().unwrap(),
        ],
    );
    let scratch_finding = finding("stale-tree", &scratch, Tier::Review);
    let metadata_finding = finding("stale-tree", &metadata, Tier::Review);
    let pol = policy(
        Tier::Regenerable,
        &[&scratch_finding.id, &metadata_finding.id],
    );
    let found = vec![scratch_finding, metadata_finding];
    let plan = make_plan(&b, found.clone());
    assert_eq!(plan.items.len(), 2, "{:?}", plan.blocked);
    let tree = scan_tree(&b);
    fs::rename(&scratch, scratch.with_extension("old")).unwrap();
    symlink(other.join("tree"), &scratch).unwrap();

    let checks = apply::evaluate(&plan, found, &tree, &ctx(), &Processes::default(), &pol);
    let report = apply::report(&plan, &checks, &pol, true, &env());
    assert_eq!(apply::exit_code(&report), 2);
    let item_at = |path: &Path| {
        report
            .items
            .iter()
            .find(|i| Path::new(&i.path) == path)
            .unwrap()
    };
    let skipped = item_at(&scratch);
    assert_eq!(skipped.outcome, ApplyOutcome::Skipped);
    assert_eq!(skipped.guards.len(), 1, "{:?}", skipped.guards);
    assert_eq!(skipped.guards[0].name, "changed-since-scan");
    let dependency = item_at(&metadata);
    assert_eq!(dependency.outcome, ApplyOutcome::Skipped);
    let guard = dependency
        .guards
        .iter()
        .find(|g| g.name == "git-linked-worktrees")
        .unwrap();
    assert_eq!(guard.status, GuardStatus::Block);
    assert!(guard.detail.contains(original.to_str().unwrap()));
}

#[test]
fn nested_checkout_swap_protects_the_outer_roots_git_metadata() {
    let (_temp, b) = base();
    let (_outside, outside) = base();
    let scratch = b.join("scratch");
    let target = scratch.join("target");
    let checkout = outside.join("checkout");
    let metadata = scratch.join("checkout.git");
    for dir in [&target, &checkout] {
        fs::create_dir_all(dir).unwrap();
    }
    git(&target, &["init", "-q"]);
    git(
        &checkout,
        &[
            "init",
            "-q",
            "--separate-git-dir",
            metadata.to_str().unwrap(),
        ],
    );
    let outer = finding("stale-tree", &scratch, Tier::Review);
    let inner = finding("cargo-target", &target, Tier::Rebuildable);
    let pol = policy(Tier::Rebuildable, &[&outer.id]);
    let found = vec![outer, inner];
    let plan = make_plan(&b, found.clone());
    assert_eq!(plan.items.len(), 2, "{:?}", plan.blocked);
    let tree = scan_tree(&b);
    let procs = Processes::default();
    let mut ready = apply::evaluate(&plan, found.clone(), &tree, &ctx(), &procs, &pol);
    let preview = apply::report(&plan, &ready, &pol, true, &env());
    assert_eq!(apply::exit_code(&preview), 0);
    assert!(ready.iter().all(Check::ready));

    fs::rename(&target, outside.join("original")).unwrap();
    symlink(&checkout, &target).unwrap();
    let mut surveyed = apply::evaluate(&plan, found, &tree, &ctx(), &procs, &pol);
    assert!(
        surveyed
            .iter()
            .all(|c| c.item.outcome == ApplyOutcome::Skipped)
    );
    let mut audit = Audit::open(&b.join("audit.jsonl")).unwrap();
    for checks in [&mut surveyed, &mut ready] {
        apply::execute(&plan, checks, &mut audit, &no_mounts(), &env(), &mut |_| {});
        let report = apply::report(&plan, checks, &pol, false, &env());
        assert_eq!(apply::exit_code(&report), 2);
        assert_eq!(report.freed, 0);
        for item in &report.items {
            assert_eq!(item.outcome, ApplyOutcome::Skipped, "{item:?}");
            assert!(
                item.guards.iter().any(|g| {
                    g.name == "changed-since-scan"
                        && g.status == GuardStatus::Block
                        && g.detail.contains(target.to_str().unwrap())
                }),
                "{item:?}"
            );
        }
        assert_eq!(fs::read_link(&target).unwrap(), checkout);
        assert!(metadata.join("HEAD").is_file());
        git(&checkout, &["rev-parse", "--git-dir"]);
    }
}

#[test]
fn an_unselected_nested_git_root_can_block_the_outer_root() {
    let (_temp, b) = base();
    let (_outside, outside) = base();
    let scratch = b.join("scratch");
    let worktree = scratch.join("project");
    let checkout = outside.join("checkout");
    for dir in [&worktree, &checkout] {
        fs::create_dir_all(dir).unwrap();
    }
    git(
        &worktree,
        &[
            "init",
            "-q",
            "--separate-git-dir",
            outside.join("original.git").to_str().unwrap(),
        ],
    );
    git(&checkout, &["init", "-q"]);
    let found = vec![finding("stale-tree", &scratch, Tier::Review)];
    let plan = make_plan(&b, found.clone());
    assert_eq!(plan.items.len(), 1);
    let tree = scan_tree(&b);
    fs::rename(&worktree, outside.join("original")).unwrap();
    symlink(&checkout, &worktree).unwrap();

    let rebuilt = make_plan_from_tree(&b, found.clone(), &tree);
    assert!(rebuilt.items.is_empty());
    assert_eq!(rebuilt.blocked.len(), 1);
    let pol = policy(Tier::Regenerable, &[&found[0].id]);
    let checks = apply::evaluate(&plan, found, &tree, &ctx(), &Processes::default(), &pol);
    assert_eq!(checks[0].item.outcome, ApplyOutcome::Skipped);
    for guards in [&rebuilt.blocked[0].guards, &checks[0].item.guards] {
        assert!(
            guards.iter().any(|g| {
                g.name == "changed-since-scan"
                    && g.status == GuardStatus::Block
                    && g.detail.contains(worktree.to_str().unwrap())
            }),
            "{guards:?}"
        );
    }
}

#[test]
fn a_symlink_ancestor_cannot_hide_a_nested_checkout() {
    let (_temp, b) = base();
    let (_outside, outside) = base();
    let scratch = b.join("scratch");
    let live = scratch.join("live");
    let checkout = live.join("project");
    let metadata = scratch.join("repo.git");
    fs::create_dir_all(&checkout).unwrap();
    git(
        &checkout,
        &[
            "init",
            "-q",
            "--separate-git-dir",
            metadata.to_str().unwrap(),
        ],
    );
    let finding = finding("stale-tree", &scratch, Tier::Review);
    let pol = policy(Tier::Regenerable, &[&finding.id]);
    let plan = make_plan(&b, vec![finding.clone()]);
    assert_eq!(plan.items.len(), 1, "{:?}", plan.blocked);
    let tree = scan_tree(&b);
    let procs = Processes::default();
    let mut ready = apply::evaluate(&plan, vec![finding.clone()], &tree, &ctx(), &procs, &pol);
    assert!(ready[0].ready(), "{:?}", ready[0].item);

    let moved = outside.join("live");
    fs::rename(&live, &moved).unwrap();
    symlink(&moved, &live).unwrap();
    let replanned = make_plan_from_tree(&b, vec![finding.clone()], &tree);
    assert!(replanned.items.is_empty());
    assert_eq!(replanned.blocked.len(), 1);
    let surveyed = apply::evaluate(&plan, vec![finding], &tree, &ctx(), &procs, &pol);
    assert_eq!(surveyed[0].item.outcome, ApplyOutcome::Skipped);

    let mut audit = Audit::open(&b.join("audit.jsonl")).unwrap();
    apply::execute(
        &plan,
        &mut ready,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |_| {},
    );
    let report = apply::report(&plan, &ready, &pol, false, &env());
    assert_eq!(apply::exit_code(&report), 2);
    assert_eq!(report.freed, 0);
    for guards in [
        &replanned.blocked[0].guards,
        &surveyed[0].item.guards,
        &report.items[0].guards,
    ] {
        assert!(
            guards.iter().any(|g| {
                g.name == "changed-since-scan"
                    && g.status == GuardStatus::Block
                    && g.detail.contains(checkout.to_str().unwrap())
            }),
            "{guards:?}"
        );
    }
    assert!(metadata.join("HEAD").is_file());
    git(&moved.join("project"), &["rev-parse", "--git-dir"]);
}

#[test]
fn the_plans_action_and_tier_are_not_trusted() {
    let (_t, b) = base();
    let found = fixture(&b);
    let mut plan = make_plan(&b, found.clone());
    // An edited plan: the rebuildable target claims to be regenerable, and
    // the cache's action is swapped for another command.
    for item in &mut plan.items {
        if item.finding.detector == "cargo-target" {
            item.finding.tier = Tier::Regenerable;
        }
        if item.finding.detector == "user-cache" {
            item.finding.action = Action {
                kind: ActionKind::Command,
                text: "rm -rf ~".into(),
                argv: Some(vec!["rm".into(), "-rf".into(), "/".into()]),
            };
        }
    }
    let checks = evaluate(&b, &plan, found, &Policy::default());
    for c in checks.iter().filter(|c| c.item.detector != "stale-tree") {
        assert_eq!(c.item.outcome, ApplyOutcome::Skipped, "{:?}", c.item);
        assert!(c.item.detail.starts_with("changed:"), "{}", c.item.detail);
        // What the report shows is the action detected now.
        assert_eq!(c.item.action.kind, ActionKind::RemovePath);
    }
}

#[test]
fn gone_or_now_blocked_findings_are_skipped() {
    let (_t, b) = base();
    let found = fixture(&b);
    let plan = make_plan(&b, found.clone());
    // The cache is no longer detected; the target is blocked by a detector.
    let mut fresh: Vec<Finding> = found
        .into_iter()
        .filter(|f| f.detector != "user-cache")
        .collect();
    fresh[0].tier = Tier::Blocked;
    let checks = evaluate(&b, &plan, fresh, &policy(Tier::Rebuildable, &[]));
    let get = |d: &str| &checks.iter().find(|c| c.item.detector == d).unwrap().item;
    assert_eq!(get("user-cache").outcome, ApplyOutcome::Skipped);
    assert!(get("user-cache").detail.starts_with("gone"));
    assert_eq!(get("cargo-target").outcome, ApplyOutcome::Skipped);
    assert!(get("cargo-target").detail.starts_with("blocked"));
}

#[test]
fn guards_run_again_at_apply() {
    let (_t, b) = base();
    let found = fixture(&b);
    let plan = make_plan(&b, found.clone());
    let procs = Processes {
        procs: vec![Proc {
            pid: 777,
            name: "pip".into(),
            cwd: Some(b.join("cache")),
            open: vec![],
        }],
        unreadable: 0,
    };
    let checks = apply::evaluate(
        &plan,
        found,
        &scan_tree(&b),
        &ctx(),
        &procs,
        &Policy::default(),
    );
    let c = &checks
        .iter()
        .find(|c| c.item.detector == "user-cache")
        .unwrap()
        .item;
    assert_eq!(c.outcome, ApplyOutcome::Skipped);
    assert!(
        c.detail.contains("in-use-cwd") && c.detail.contains("pip (pid 777)"),
        "{}",
        c.detail
    );
    assert!(c.guards.iter().any(|g| g.name == "in-use-cwd"));
}

fn env() -> Env {
    Env {
        host: "host".into(),
        uid: 1000,
        now: || "2026-11-16T05:00:00Z".to_string(),
    }
}

fn audit_lines(p: &Path) -> Vec<AuditRecord> {
    fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn execute_removes_ready_items_and_audits_everything() {
    let (_t, b) = base();
    let found = fixture(&b);
    let plan = make_plan(&b, found.clone());
    let mut checks = evaluate(&b, &plan, found, &Policy::default());
    let (_s, state) = base();
    let log = state.join("diskwhy/audit.jsonl");
    let mut audit = Audit::open(&log).unwrap();
    let mut seen = Vec::new();
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |i| seen.push(i.path.clone()),
    );
    assert!(!b.join("cache").exists(), "the regenerable cache is gone");
    assert!(b.join("target/file").exists() && b.join("scratch/file").exists());
    assert_eq!(seen, [b.join("cache").to_string_lossy()]);

    let r = apply::report(&plan, &checks, &Policy::default(), false, &env());
    assert_eq!(apply::exit_code(&r), 3, "two refused");
    assert_eq!(r.freed, 4096);

    let lines = audit_lines(&log);
    let events: Vec<(AuditEvent, Option<ApplyOutcome>, &str)> = lines
        .iter()
        .map(|l| (l.event, l.outcome, l.detector.as_str()))
        .collect();
    assert_eq!(events.len(), 4, "{events:?}");
    assert!(events.contains(&(AuditEvent::End, Some(ApplyOutcome::Refused), "cargo-target")));
    assert!(events.contains(&(AuditEvent::End, Some(ApplyOutcome::Refused), "stale-tree")));
    let start = events
        .iter()
        .position(|e| *e == (AuditEvent::Start, None, "user-cache"))
        .unwrap();
    assert_eq!(
        events[start + 1],
        (AuditEvent::End, Some(ApplyOutcome::Removed), "user-cache")
    );
    let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // A second run appends.
    let mut audit = Audit::open(&log).unwrap();
    apply::execute(
        &plan,
        &mut [],
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |_| {},
    );
    assert_eq!(audit_lines(&log).len(), 4);
}

#[test]
fn execute_skips_replaced_roots_for_commands_and_path_removal() {
    let (_t, b) = base();
    let mut found = fixture(&b);
    found.truncate(2);
    let marker = b.join("ran");
    found[1].action = Action {
        kind: ActionKind::Command,
        text: "touch marker".into(),
        argv: Some(vec!["touch".into(), marker.to_str().unwrap().into()]),
    };
    let plan = make_plan(&b, found.clone());
    let pol = policy(Tier::Rebuildable, &[]);
    let mut checks = evaluate(&b, &plan, found, &pol);
    assert_eq!(checks.len(), 2);
    assert!(checks.iter().all(Check::ready));
    let log = b.join("audit.jsonl");
    let mut audit = Audit::open(&log).unwrap();
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |item| {
            let root = Path::new(&item.path);
            fs::rename(root, root.with_extension("old")).unwrap();
            write(&root.join("file"), "replacement");
        },
    );

    assert!(!marker.exists());
    for c in &checks {
        assert_eq!(c.item.outcome, ApplyOutcome::Skipped);
        assert!(c.item.detail.starts_with("changed since the scan: "));
        assert_eq!(c.item.guards.len(), 1, "{:?}", c.item.guards);
        let changed = c
            .item
            .guards
            .iter()
            .find(|g| g.name == "changed-since-scan")
            .unwrap();
        assert_eq!(changed.status, GuardStatus::Block);
        let root = Path::new(&c.item.path);
        assert_eq!(
            fs::read_to_string(root.join("file")).unwrap(),
            "replacement"
        );
        assert!(root.with_extension("old").join("file").exists());
    }
    let report = apply::report(&plan, &checks, &pol, false, &env());
    assert_eq!(apply::exit_code(&report), 2);
    let lines = audit_lines(&log);
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.event == AuditEvent::End && l.outcome == Some(ApplyOutcome::Skipped))
            .count(),
        2
    );
}

#[test]
fn deepest_items_run_first_and_commands_report_failure() {
    let (_t, b) = base();
    write(&b.join("scratch/app/target/file"), "t");
    let outer = finding("stale-tree", &b.join("scratch"), Tier::Review);
    let mut inner = finding(
        "cargo-target",
        &b.join("scratch/app/target"),
        Tier::Rebuildable,
    );
    // A tool-native command that fails.
    inner.action = Action {
        kind: ActionKind::Command,
        text: "false".into(),
        argv: Some(vec!["false".into()]),
    };
    let found = vec![outer.clone(), inner];
    let plan = make_plan(&b, found.clone());
    let mut checks = evaluate(&b, &plan, found, &policy(Tier::Rebuildable, &[&outer.id]));
    assert!(checks.iter().all(|c| c.ready()), "{:?}", outcomes(&checks));
    let (_s, state) = base();
    let mut audit = Audit::open(&state.join("a.jsonl")).unwrap();
    let mut seen = Vec::new();
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |i| seen.push(i.detector.clone()),
    );
    assert_eq!(seen, ["cargo-target", "stale-tree"]);
    let get = |d: &str| &checks.iter().find(|c| c.item.detector == d).unwrap().item;
    assert_eq!(get("cargo-target").outcome, ApplyOutcome::Failed);
    assert!(
        get("cargo-target").detail.contains("false failed"),
        "{}",
        get("cargo-target").detail
    );
    assert_eq!(get("stale-tree").outcome, ApplyOutcome::Removed);
    assert!(!b.join("scratch").exists());
    let r = apply::report(&plan, &checks, &Policy::default(), false, &env());
    assert_eq!(apply::exit_code(&r), 1);
}

#[test]
fn stop_during_apply_audit_start_prevents_path_and_command_dispatch() {
    thread_local! {
        static STOP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    for command in [false, true] {
        STOP.with(|flag| flag.set(false));
        let (_t, b) = base();
        let target = b.join("cache");
        write(&target.join("file"), "keep");
        let mut fresh = finding("user-cache", &target, Tier::Regenerable);
        if command {
            fresh.action.kind = ActionKind::Command;
            fresh.action.argv = Some(vec![
                "/bin/rm".into(),
                "-rf".into(),
                "--".into(),
                target.to_str().unwrap().into(),
            ]);
        }
        let plan = make_plan(&b, vec![fresh.clone()]);
        let mut checks = evaluate(&b, &plan, vec![fresh], &Policy::default());
        assert!(checks[0].ready());

        let log = b.join("audit.jsonl");
        let mut audit = Audit::open(&log).unwrap();
        let env = Env {
            now: || {
                STOP.with(|flag| flag.set(true));
                "2026-11-16T05:00:00Z".into()
            },
            ..env()
        };
        let errors = apply::execute_until(
            &plan,
            &mut checks,
            &mut audit,
            &no_mounts(),
            &env,
            &mut |_| assert!(!STOP.with(std::cell::Cell::get)),
            apply::ExecuteOptions {
                stop: &|| STOP.with(std::cell::Cell::get),
                isolate_commands: false,
            },
        );
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(fs::read_to_string(target.join("file")).unwrap(), "keep");
        let records = audit_lines(&log);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].event, AuditEvent::Start);
        assert_eq!(records[1].event, AuditEvent::End);
        assert_eq!(records[1].outcome, Some(ApplyOutcome::Skipped));
        assert_eq!(
            records[1].detail.as_deref(),
            Some("not run: apply was stopped before this item")
        );
    }
}

#[test]
fn an_item_inside_another_is_counted_once() {
    let (_t, b) = base();
    write(&b.join("scratch/app/target/file"), "t");
    write(&b.join("scratch/notes"), "n");
    // The nesting rule: the outer finding's bytes already hold the inner's.
    let mut outer = finding("stale-tree", &b.join("scratch"), Tier::Review);
    outer.bytes = 10_000;
    outer.nested_bytes = Some(9_000);
    let mut inner = finding(
        "cargo-target",
        &b.join("scratch/app/target"),
        Tier::Rebuildable,
    );
    inner.bytes = 9_000;
    let found = vec![outer.clone(), inner];
    let plan = make_plan(&b, found.clone());
    assert_eq!(plan.bytes, 10_000);
    let pol = policy(Tier::Rebuildable, &[&outer.id]);
    let mut checks = evaluate(&b, &plan, found, &pol);
    assert!(checks.iter().all(|c| c.ready()), "{:?}", outcomes(&checks));

    let preview = apply::report(&plan, &checks, &pol, true, &env());
    let would = preview
        .items
        .iter()
        .filter(|i| i.outcome == ApplyOutcome::WouldRemove);
    assert_eq!(would.clone().count(), 2);
    assert_eq!(apply::total_bytes(would), 10_000, "not 19 000");
    assert_eq!(apply::total_bytes(checks.iter().map(|c| &c.item)), 10_000);

    let (_s, state) = base();
    let mut audit = Audit::open(&state.join("a.jsonl")).unwrap();
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |_| {},
    );
    assert!(!b.join("scratch").exists());
    let r = apply::report(&plan, &checks, &pol, false, &env());
    assert!(
        r.items.iter().all(|i| i.outcome == ApplyOutcome::Removed),
        "{:?}",
        r.items
    );
    assert_eq!(apply::exit_code(&r), 0);
    assert_eq!(r.freed, 10_000);
}

#[test]
fn a_nested_path_that_reappears_after_success_still_blocks_its_parent() {
    let (_t, b) = base();
    let scratch = b.join("scratch");
    let target = scratch.join("target");
    let saved = b.join("saved");
    write(&target.join("file"), "keep");
    let outer = finding("stale-tree", &scratch, Tier::Review);
    let mut inner = finding("cargo-target", &target, Tier::Rebuildable);
    inner.action = Action {
        kind: ActionKind::Command,
        text: "move target".into(),
        argv: Some(vec![
            "mv".into(),
            "--".into(),
            target.to_str().unwrap().into(),
            saved.to_str().unwrap().into(),
        ]),
    };
    let pol = policy(Tier::Rebuildable, &[&outer.id]);
    let found = vec![outer, inner];
    let plan = make_plan(&b, found.clone());
    let mut checks = evaluate(&b, &plan, found, &pol);
    assert!(checks.iter().all(Check::ready), "{:?}", outcomes(&checks));
    let mut audit = Audit::open(&b.join("audit.jsonl")).unwrap();
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |item| {
            if Path::new(&item.path) == scratch {
                assert!(!target.exists());
                fs::rename(&saved, &target).unwrap();
            }
        },
    );
    let r = apply::report(&plan, &checks, &pol, false, &env());
    assert_eq!(apply::exit_code(&r), 2);
    let parent = r
        .items
        .iter()
        .find(|i| Path::new(&i.path) == scratch)
        .unwrap();
    assert_eq!(parent.outcome, ApplyOutcome::Skipped);
    assert!(
        parent
            .guards
            .iter()
            .any(|g| { g.name == "changed-since-scan" && g.status == GuardStatus::Block })
    );
    assert!(target.join("file").is_file());
}

#[test]
fn a_removal_whose_audit_line_cannot_be_written_does_not_run() {
    if !Path::new("/dev/full").exists() {
        return;
    }
    let (_t, b) = base();
    let found = fixture(&b);
    let plan = make_plan(&b, found.clone());
    let mut checks = evaluate(&b, &plan, found, &Policy::default());
    // Every write to /dev/full fails with ENOSPC.
    let mut audit = Audit::open(Path::new("/dev/full")).unwrap();
    let errors = apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |_| {},
    );
    assert_eq!(errors.len(), 3, "one write error per item: {errors:?}");
    for name in ["cache", "target", "scratch"] {
        let path = b.join(name);
        assert!(
            errors.iter().any(|e| e.starts_with(path.to_str().unwrap())),
            "{errors:?}"
        );
    }
    assert!(b.join("cache/file").exists(), "nothing removed");
    let c = &checks
        .iter()
        .find(|c| c.item.detector == "user-cache")
        .unwrap()
        .item;
    assert_eq!(c.outcome, ApplyOutcome::Failed);
    assert!(
        c.detail.starts_with("not run: cannot write the audit log"),
        "{}",
        c.detail
    );
}

#[test]
fn the_audit_log_is_not_followed_through_a_symlink() {
    let (_t, b) = base();
    write(&b.join("elsewhere"), "");
    symlink(b.join("elsewhere"), b.join("audit.jsonl")).unwrap();
    assert!(Audit::open(&b.join("audit.jsonl")).is_err());
}

#[test]
fn a_lossy_path_or_command_is_never_applied() {
    let (_t, b) = base();
    let found = fixture(&b);
    let mut plan = make_plan(&b, found.clone());
    // A hand-edited plan: the cache's command names a lossy path.
    let lossy = format!("{}/cache\u{FFFD}", b.display());
    for item in &mut plan.items {
        if item.finding.detector == "user-cache" {
            item.finding.action = Action {
                kind: ActionKind::Command,
                text: format!("rm -rf {lossy}"),
                argv: Some(vec!["rm".into(), "-rf".into(), lossy.clone()]),
            };
        }
    }
    // A fresh finding that names a lossy path, as if a detector had
    // slipped past `detect::block_lossy`, while its plan item is clean: only
    // the fresh-side check can block it.
    let mut fresh = found.clone();
    let guard = GuardResult {
        name: "locked".into(),
        status: GuardStatus::Block,
        detail: "locked after planning".into(),
    };
    fresh
        .iter_mut()
        .find(|f| f.detector == "user-cache")
        .unwrap()
        .guards
        .push(guard.clone());
    fresh
        .iter_mut()
        .find(|f| f.detector == "cargo-target")
        .unwrap()
        .action = Action {
        kind: ActionKind::Command,
        text: format!("cargo clean --target-dir {lossy}"),
        argv: Some(vec![
            "cargo".into(),
            "clean".into(),
            "--target-dir".into(),
            lossy.clone(),
        ]),
    };
    let planned = plan
        .items
        .iter()
        .find(|i| i.finding.detector == "cargo-target")
        .unwrap();
    assert_eq!(
        planned.finding.path, found[1].path,
        "the plan item is clean"
    );
    assert_eq!(planned.finding.action, found[1].action);
    let checks = evaluate(&b, &plan, fresh, &policy(Tier::Review, &[&found[2].id]));
    for d in ["user-cache", "cargo-target"] {
        let c = checks.iter().find(|c| c.item.detector == d).unwrap();
        assert_eq!(c.item.outcome, ApplyOutcome::Skipped, "{d}: {:?}", c.item);
        assert!(
            c.item.detail.starts_with("blocked by path-not-utf8: "),
            "{}",
            c.item.detail
        );
        assert_eq!(c.item.guards.last().unwrap().name, "path-not-utf8");
        if d == "user-cache" {
            assert!(c.item.guards.contains(&guard));
        }
    }
    let stale = checks
        .iter()
        .find(|c| c.item.detector == "stale-tree")
        .unwrap();
    assert!(stale.ready(), "{:?}", stale.item);

    // The last check, right before running: a ready item whose command
    // names a lossy path is not run.
    let marker = b.join("ran\u{FFFD}");
    let mut check = stale.clone();
    check.item.action = Action {
        kind: ActionKind::Command,
        text: "touch".into(),
        argv: Some(vec!["touch".into(), marker.to_string_lossy().into_owned()]),
    };
    let mut checks = vec![check];
    let (_s, state) = base();
    let mut audit = Audit::open(&state.join("a.jsonl")).unwrap();
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |_| {},
    );
    assert_eq!(checks[0].item.outcome, ApplyOutcome::Skipped);
    assert!(
        checks[0]
            .item
            .detail
            .starts_with("blocked by path-not-utf8"),
        "{}",
        checks[0].item.detail
    );
    assert!(!marker.exists());
    assert!(
        checks[0]
            .item
            .guards
            .iter()
            .any(|g| g.name == "path-not-utf8")
    );
    assert!(b.join("scratch/file").exists());

    // The same for a path removal: a real directory whose name holds
    // U+FFFD is left alone, since diskwhy cannot tell it from a lossy one.
    let real = b.join("scratch\u{FFFD}");
    write(&real.join("file"), "keep");
    let mut check = stale.clone();
    check.item.path = real.to_string_lossy().into_owned();
    // Its own identity, so only the lossy check stands in the way.
    let md = fs::symlink_metadata(&real).unwrap();
    check.inode = Some((
        std::os::unix::fs::MetadataExt::dev(&md),
        std::os::unix::fs::MetadataExt::ino(&md),
    ));
    check.item.action = Action {
        kind: ActionKind::RemovePath,
        text: format!("remove {}", check.item.path),
        argv: None,
    };
    let mut checks = vec![check];
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |_| {},
    );
    assert_eq!(checks[0].item.outcome, ApplyOutcome::Skipped);
    assert!(
        checks[0]
            .item
            .detail
            .starts_with("blocked by path-not-utf8"),
        "{}",
        checks[0].item.detail
    );
    assert!(
        checks[0]
            .item
            .guards
            .iter()
            .any(|g| g.name == "path-not-utf8")
    );
    assert_eq!(fs::read_to_string(real.join("file")).unwrap(), "keep");
}

/// `scratch` (review) holding `scratch/target` (a path removal), which holds
/// `target/checkout`, a clean git checkout the identity checks track.
fn checkout_in_a_removed_child(b: &Path) -> (PathBuf, PathBuf, Policy, Plan, Vec<Check>) {
    let scratch = b.join("scratch");
    let target = scratch.join("target");
    let checkout = target.join("checkout");
    fs::create_dir_all(&checkout).unwrap();
    git(&checkout, &["init", "-q"]);
    write(&scratch.join("notes"), "n");
    let outer = finding("stale-tree", &scratch, Tier::Review);
    let inner = finding("cargo-target", &target, Tier::Rebuildable);
    let pol = policy(Tier::Rebuildable, &[&outer.id]);
    let found = vec![outer, inner];
    let plan = make_plan(b, found.clone());
    assert_eq!(plan.items.len(), 2, "{:?}", plan.blocked);
    let checks = evaluate(b, &plan, found, &pol);
    assert!(checks.iter().all(Check::ready), "{:?}", outcomes(&checks));
    (scratch, checkout, pol, plan, checks)
}

#[test]
fn checked_descendants_removed_with_a_child_do_not_block_the_parent() {
    let (_t, b) = base();
    let (scratch, checkout, pol, plan, mut checks) = checkout_in_a_removed_child(&b);
    let (_s, state) = base();
    let mut audit = Audit::open(&state.join("a.jsonl")).unwrap();
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |item| {
            if Path::new(&item.path) == scratch {
                assert!(!checkout.exists(), "the child runs first");
            }
        },
    );
    let r = apply::report(&plan, &checks, &pol, false, &env());
    assert!(
        r.items.iter().all(|i| i.outcome == ApplyOutcome::Removed),
        "{:?}",
        r.items
    );
    assert_eq!(apply::exit_code(&r), 0);
    assert!(!scratch.exists());
}

#[test]
fn a_checked_descendant_that_reappears_after_its_childs_removal_blocks_the_parent() {
    let (_t, b) = base();
    let (scratch, checkout, pol, plan, mut checks) = checkout_in_a_removed_child(&b);
    let (_s, state) = base();
    let mut audit = Audit::open(&state.join("a.jsonl")).unwrap();
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &no_mounts(),
        &env(),
        &mut |item| {
            if Path::new(&item.path) == scratch {
                assert!(!checkout.exists());
                fs::create_dir_all(&checkout).unwrap();
            }
        },
    );
    let r = apply::report(&plan, &checks, &pol, false, &env());
    assert_eq!(apply::exit_code(&r), 2);
    let parent = r
        .items
        .iter()
        .find(|i| Path::new(&i.path) == scratch)
        .unwrap();
    assert_eq!(parent.outcome, ApplyOutcome::Skipped);
    assert!(
        parent.guards.iter().any(|g| g.name == "changed-since-scan"
            && g.status == GuardStatus::Block
            && g.detail.contains("reappeared after removal")),
        "{:?}",
        parent.guards
    );
    assert!(checkout.is_dir() && scratch.join("notes").is_file());
}

fn docker_volume(name: &str) -> Finding {
    let path = format!("docker://volume/{name}");
    Finding {
        file_identity: None,
        id: finding_id("docker-volume", &path),
        detector: "docker-volume".into(),
        probe: None,
        evidence: None,
        path,
        bytes: 4096,
        nested_bytes: None,
        last_modified: None,
        growth: None,
        tier: Tier::Review,
        reason: String::new(),
        guards: Vec::new(),
        action: Action {
            kind: ActionKind::Command,
            text: format!("docker volume rm {name}"),
            argv: Some(vec![
                "docker".into(),
                "volume".into(),
                "rm".into(),
                name.into(),
            ]),
        },
        recovery: Recovery {
            cost: String::new(),
            how: None,
        },
    }
}

#[test]
fn skipped_docker_items_make_no_docker_api_reads() {
    use std::os::unix::net::UnixListener;
    let (_t, b) = base();
    let mut found = fixture(&b);
    found.retain(|f| f.detector == "user-cache");
    let mut plan = make_plan(&b, found.clone());
    assert_eq!(plan.items.len(), 1);
    // Planned volumes: one gone since, one a review item nobody confirmed.
    let gone = docker_volume("gone");
    let unconfirmed = docker_volume("unconfirmed");
    for f in [&gone, &unconfirmed] {
        plan.items.push(dwhy_core::report::PlanItem {
            finding: f.clone(),
            fingerprint: dwhy_core::report::Fingerprint {
                dev: None,
                inode: None,
                newest_mtime: None,
                size_bucket: plan::size_bucket(f.bytes),
                git: None,
                docker_id: Some(format!("{}@1", f.path)),
            },
        });
    }
    found.push(unconfirmed.clone());

    // A socket nobody answers: any GET connects to it and then times out.
    let (_d, dir) = base();
    let socket = dir.join("docker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let ctx = DetectContext {
        docker: Source::socket(&socket, std::time::Duration::from_millis(200)),
        ..ctx()
    };
    let checks = apply::evaluate(
        &plan,
        found,
        &scan_tree(&b),
        &ctx,
        &Processes::default(),
        &Policy::default(),
    );
    let outcome = |f: &Finding| {
        checks
            .iter()
            .find(|c| c.item.id == f.id)
            .unwrap()
            .item
            .outcome
    };
    assert_eq!(outcome(&gone), ApplyOutcome::Skipped);
    assert_eq!(outcome(&unconfirmed), ApplyOutcome::Refused);
    assert!(checks.iter().any(Check::ready), "{:?}", outcomes(&checks));
    assert!(
        listener
            .accept()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
        "a skipped Docker item read the Docker API"
    );

    // The socket does see a read when a volume's guard runs.
    let mut volume = vec![docker_volume("ready")];
    dwhy_core::guard::check(&mut volume, &scan_tree(&b), &ctx, &Processes::default());
    assert!(listener.accept().is_ok());
}

#[test]
fn a_mismatched_plan_item_is_reported_with_terminal_controls_escaped() {
    let (_t, b) = base();
    let mut found = fixture(&b);
    found.retain(|f| f.detector == "user-cache");
    let mut plan = make_plan(&b, found.clone());
    let planned = &mut plan.items[0].finding;
    planned.detector = "user-cache\u{1b}[2J".into();
    planned.path = format!("{}\n\u{1b}[31mok\\", planned.path);
    let checks = evaluate(&b, &plan, found, &Policy::default());
    let item = &checks[0].item;
    assert_eq!(item.outcome, ApplyOutcome::Skipped);
    assert_eq!(
        item.detail,
        format!(
            r"changed: planned user-cache\u{{1b}}[2J {}\n\u{{1b}}[31mok\\ does not match the live finding",
            b.join("cache").display()
        )
    );
    assert!(!item.detail.contains(char::is_control));
}
