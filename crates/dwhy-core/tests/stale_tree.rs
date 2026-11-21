//! `stale-tree` on temp scratch directories with backdated mtimes.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{self, DetectContext, Detector, finding_id};
use dwhy_core::detectors::{
    SCRATCH_LOCATIONS, SCRATCH_MARKER, SCRATCH_STALE_DAYS, StaleTree, registry,
};
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ActionKind, DockerSocket, Finding, Tier};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

const MB: usize = 1 << 20;

fn scan_tree(root: &Path) -> ScanTree {
    let roots = scan::prepare_roots(&[root.to_path_buf()], true).unwrap();
    let opts = ScanOptions {
        min_dir_bytes: 0,
        threads: 4,
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

fn ctx(home: Option<&Path>) -> DetectContext {
    DetectContext {
        uid: 1000,
        root: false,
        home: home.map(Path::to_path_buf),
        now: now(),
        tools: vec![],
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: dwhy_core::docker::Source::none(),
        cancel: Default::default(),
    }
}

fn detect(root: &Path, home: Option<&Path>) -> Vec<Finding> {
    let mut f = StaleTree
        .detect(&scan_tree(root), &ctx(home))
        .expect("stale-tree never fails");
    f.sort_by(|a, b| a.path.cmp(&b.path));
    f
}

fn paths(f: &[Finding]) -> Vec<String> {
    let mut p: Vec<String> = f.iter().map(|f| f.path.clone()).collect();
    p.sort();
    p
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Writes `size` bytes of non-zero data, so the file really takes space.
fn file(path: &Path, size: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![7u8; size]).unwrap();
}

/// A directory holding one file of `size` bytes, everything in it last
/// written `days` days ago.
fn item(dir: &Path, size: usize, days: u64) -> PathBuf {
    file(&dir.join("data.bin"), size);
    age_tree(dir, days);
    dir.to_path_buf()
}

/// Sets the mtime of `dir` and everything in it to `days` days ago.
fn age_tree(dir: &Path, days: u64) {
    let t = SystemTime::now() - Duration::from_secs(days * 86_400);
    fn walk(p: &Path, t: SystemTime) {
        let meta = fs::symlink_metadata(p).unwrap();
        if meta.is_dir() {
            for e in fs::read_dir(p).unwrap() {
                walk(&e.unwrap().path(), t);
            }
        }
        if !meta.file_type().is_symlink() {
            fs::File::open(p).unwrap().set_modified(t).unwrap();
        }
    }
    walk(dir, t);
}

/// Sets the mtime of `p` alone to `days` days ago.
fn age_one(p: &Path, days: u64) {
    let t = SystemTime::now() - Duration::from_secs(days * 86_400);
    fs::File::open(p).unwrap().set_modified(t).unwrap();
}

const OLD: u64 = SCRATCH_STALE_DAYS as u64 + 3;

#[test]
fn builtin_list_is_what_was_decided() {
    assert_eq!(SCRATCH_STALE_DAYS, 7);
    assert_eq!(SCRATCH_MARKER, ".dwhy-scratch");
    assert_eq!(
        SCRATCH_LOCATIONS,
        ["scratch", "tmp", ".t3/scratch", ".t3/scratch-*"]
    );
}

#[test]
fn stale_dirs_in_a_busy_location() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join(".t3/scratch-virgil");
    let old = item(&loc.join("jvm-464"), 3 * MB, OLD);
    item(&loc.join("jvm-465"), 3 * MB, 1);
    item(&loc.join("tiny"), 1000, OLD);
    // Written today: the location as a whole is not stale.
    file(&loc.join("notes.md"), 10);

    let found = detect(home, Some(home));
    assert_eq!(paths(&found), [s(&old)]);
    let f = &found[0];
    assert_eq!(f.detector, "stale-tree");
    assert_eq!(f.tier, Tier::Review);
    assert_eq!(f.id, finding_id("stale-tree", &s(&old)));
    assert!(f.bytes >= 3 * MB as u64, "{}", f.bytes);
    assert_eq!(f.action.kind, ActionKind::RemovePath);
    assert_eq!(f.action.text, format!("remove {}", s(&old)));
    assert!(f.action.argv.is_none());
    assert!(f.recovery.how.is_none());
    assert!(
        f.recovery.cost.contains("not regenerable"),
        "{}",
        f.recovery.cost
    );
    assert!(f.last_modified.is_some());
    assert!(
        f.reason.starts_with(&format!(
            "Scratch directory in {} (a built-in scratch location) with nothing written in it for {OLD} days",
            loc.display()
        )),
        "{}",
        f.reason
    );
    assert!(f.reason.contains("stale after 7 days"), "{}", f.reason);
    assert!(!f.reason.contains("hardlinked"), "{}", f.reason);
}

#[test]
fn a_location_stale_as_a_whole_is_one_finding() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join(".t3/scratch-council-pilot");
    file(&loc.join("dl/a.bin"), 2 * MB);
    file(&loc.join("runs/b.bin"), 2 * MB);
    file(&loc.join("top.txt"), 10);
    age_tree(&loc, OLD);

    let found = detect(home, Some(home));
    assert_eq!(paths(&found), [s(&loc)]);
    assert!(found[0].bytes >= 4 * MB as u64);
    assert!(
        found[0].reason.starts_with(&format!(
            "Scratch location {} (a built-in scratch location)",
            loc.display()
        )),
        "{}",
        found[0].reason
    );
}

#[test]
fn every_builtin_location() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let mut want = Vec::new();
    for loc in [
        "scratch",
        "tmp",
        ".t3/scratch",
        ".t3/scratch-a",
        ".t3/scratch-b",
    ] {
        let loc = home.join(loc);
        want.push(s(&item(&loc.join("old"), 2 * MB, OLD)));
        file(&loc.join("fresh.txt"), 10);
    }
    want.sort();
    assert_eq!(paths(&detect(home, Some(home))), want);
}

#[test]
fn lookalikes_are_ignored() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    // Not a built-in location: the pattern needs `scratch-` plus a name, and
    // only at the home directory's top level or in ~/.t3.
    for loc in [
        ".t3/scratchy",
        ".t3/scratch-",
        "code/scratch",
        "code/tmp",
        "Downloads",
    ] {
        let loc = home.join(loc);
        item(&loc.join("old"), 2 * MB, OLD);
        file(&loc.join("fresh.txt"), 10);
    }
    // A marker that is a directory or a symlink does not count.
    let d = home.join("code/dir-marker");
    fs::create_dir_all(d.join(SCRATCH_MARKER)).unwrap();
    item(&d.join("old"), 2 * MB, OLD);
    file(&d.join("fresh.txt"), 10);
    let l = home.join("code/link-marker");
    item(&l.join("old"), 2 * MB, OLD);
    file(&l.join("fresh.txt"), 10);
    file(&home.join("elsewhere/real"), 0);
    std::os::unix::fs::symlink(home.join("elsewhere/real"), l.join(SCRATCH_MARKER)).unwrap();
    // A symlinked location is not followed.
    let real = home.join("real-tmp");
    item(&real.join("old"), 2 * MB, OLD);
    file(&real.join("fresh.txt"), 10);
    std::os::unix::fs::symlink(&real, home.join("tmp")).unwrap();

    assert_eq!(paths(&detect(home, Some(home))), Vec::<String>::new());
}

#[test]
fn threshold_boundary() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join("scratch");
    let stale = item(&loc.join("eight"), 2 * MB, SCRATCH_STALE_DAYS as u64 + 1);
    item(&loc.join("six"), 2 * MB, SCRATCH_STALE_DAYS as u64 - 1);
    file(&loc.join("fresh.txt"), 10);
    assert_eq!(paths(&detect(home, Some(home))), [s(&stale)]);
}

#[test]
fn one_recent_write_keeps_a_directory() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join("scratch");
    let d = item(&loc.join("busy"), 2 * MB, OLD);
    file(&d.join("deep/new.log"), 10);
    age_one(&d, OLD);
    file(&loc.join("fresh.txt"), 10);
    assert_eq!(paths(&detect(home, Some(home))), Vec::<String>::new());
}

#[test]
fn marked_location_anywhere() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path();
    let loc = base.join("work/sandbox");
    file(&loc.join(SCRATCH_MARKER), 0);
    let old = item(&loc.join("try-1"), 2 * MB, OLD);
    item(&loc.join("try-2"), 2 * MB, 0);

    // No home directory needed for a marked location.
    let found = detect(base, None);
    assert_eq!(paths(&found), [s(&old)]);
    assert!(
        found[0].reason.contains(&format!(
            "in {} (marked as scratch by .dwhy-scratch)",
            loc.display()
        )),
        "{}",
        found[0].reason
    );

    // Marked and stale as a whole.
    age_tree(&loc, OLD);
    assert_eq!(paths(&detect(base, None)), [s(&loc)]);
}

#[test]
fn marker_in_a_builtin_location_does_not_duplicate() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join("scratch");
    file(&loc.join(SCRATCH_MARKER), 0);
    let old = item(&loc.join("old"), 2 * MB, OLD);
    assert_eq!(paths(&detect(home, Some(home))), [s(&old)]);
}

#[test]
fn location_outside_the_scan_is_not_looked_at() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join("scratch");
    item(&loc.join("old"), 2 * MB, OLD);
    file(&loc.join("fresh.txt"), 10);
    let other = home.join("code");
    file(&other.join("x"), 10);
    assert_eq!(paths(&detect(&other, Some(home))), Vec::<String>::new());

    // Scanning the location itself works.
    assert_eq!(paths(&detect(&loc, Some(home))), [s(&loc.join("old"))]);
}

#[test]
fn hardlinked_bytes_are_named_and_not_counted() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join("scratch");
    let d = loc.join("linked");
    file(&d.join("own.bin"), 2 * MB);
    // Sorts after the scratch path, so the inode is attributed inside it.
    file(&home.join("zkeep/big.bin"), 3 * MB);
    fs::hard_link(home.join("zkeep/big.bin"), d.join("big.bin")).unwrap();
    age_tree(&d, OLD);
    file(&loc.join("fresh.txt"), 10);

    let found = detect(home, Some(home));
    assert_eq!(paths(&found), [s(&d)]);
    let f = &found[0];
    assert!(
        f.bytes >= 2 * MB as u64 && f.bytes < 3 * MB as u64,
        "{}",
        f.bytes
    );
    assert!(
        f.reason
            .contains("more is hardlinked elsewhere and is not freed"),
        "{}",
        f.reason
    );
}

#[test]
fn paths_are_shell_quoted() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join("scratch");
    let d = item(&loc.join("it's old"), 2 * MB, OLD);
    file(&loc.join("fresh.txt"), 10);
    let found = detect(home, Some(home));
    assert_eq!(paths(&found), [s(&d)]);
    assert_eq!(
        found[0].action.text,
        format!("remove '{}'", s(&d).replace('\'', r"'\''"))
    );
}

#[test]
fn run_with_keeps_cheaper_findings_inside() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join("scratch");
    let proj = loc.join("proj");
    file(&proj.join("package.json"), 10);
    file(&proj.join("package-lock.json"), 10);
    file(&proj.join("node_modules/pkg/index.js"), 2 * MB);
    file(&proj.join("notes.bin"), 2 * MB);
    // A marked location inside a stale item is not reported on its own.
    let inner = proj.join("sandbox");
    file(&inner.join(SCRATCH_MARKER), 0);
    item(&inner.join("old"), 2 * MB, OLD);
    age_tree(&proj, OLD);
    file(&loc.join("fresh.txt"), 10);

    let tree = scan_tree(home);
    let only = vec!["stale-tree".to_string(), "node-modules".to_string()];
    let (found, runs) = detect::run_with(&tree, &ctx(Some(home)), &registry(), Some(&only));
    assert_eq!(paths(&found), [s(&proj), s(&proj.join("node_modules"))]);
    let outer = found.iter().find(|f| f.detector == "stale-tree").unwrap();
    let nm = found.iter().find(|f| f.detector == "node-modules").unwrap();
    assert_eq!(nm.tier, Tier::Rebuildable);
    assert_eq!(outer.nested_bytes, Some(nm.bytes));
    let run = runs.iter().find(|r| r.name == "stale-tree").unwrap();
    assert!(run.ran);
    assert_eq!(run.findings, 2);
}

#[test]
fn glob_location_scanned_itself() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join(".t3/scratch-a");
    let old = item(&loc.join("old"), 2 * MB, OLD);
    file(&loc.join("fresh.txt"), 10);
    assert_eq!(paths(&detect(&loc, Some(home))), [s(&old)]);
}

#[test]
fn marked_location_inside_a_location_is_reported_once() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let loc = home.join("scratch");
    file(&loc.join("fresh.txt"), 10);
    let sandbox = loc.join("sandbox");
    file(&sandbox.join(SCRATCH_MARKER), 0);
    item(&sandbox, 2 * MB, OLD);

    let found = detect(home, Some(home));
    assert_eq!(paths(&found), [s(&sandbox)]);
    assert!(
        found[0].reason.starts_with(&format!(
            "Scratch location {} (marked as scratch by .dwhy-scratch)",
            sandbox.display()
        )),
        "{}",
        found[0].reason
    );
}
