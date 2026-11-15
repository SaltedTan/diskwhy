//! `git-worktree` on temp git repositories. Needs `git` on PATH.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{self, DetectContext, Detector};
use dwhy_core::detectors::{GitWorktree, STALE_DAYS, WorktreeEntry, parse_porcelain};
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ActionKind, DockerSocket, Finding, GuardStatus, Tier, ToolStatus};
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

fn ctx(git: Option<&str>) -> DetectContext {
    ctx_with(git, None)
}

/// `git` is on PATH; `off_path` is git found only at that absolute path.
fn ctx_with(git: Option<&str>, off_path: Option<&str>) -> DetectContext {
    DetectContext {
        uid: 1000,
        root: false,
        home: None,
        now: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        tools: vec![ToolStatus {
            name: "git".into(),
            path: git.map(String::from),
            off_path: off_path.map(String::from),
            enables: vec![],
        }],
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: dwhy_core::docker::Source::none(),
    }
}

/// Runs git in `dir` with no user or system config.
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
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?}");
}

fn write(p: &Path, bytes: usize) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, vec![7u8; bytes]).unwrap();
}

/// Sets the mtime of everything under `dir` (and `dir` itself) to `days` ago.
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

fn tmp() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    (t, root)
}

/// A repo at `root/repo` with one commit.
fn repo(root: &Path) -> PathBuf {
    let r = root.join("repo");
    fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q"]);
    fs::write(r.join("README"), "hi").unwrap();
    git(&r, &["add", "README"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    r
}

/// Adds worktree `root/<name>` on a new branch, with `mb` MiB of ignored-ish
/// build output inside.
fn worktree(repo: &Path, root: &Path, name: &str, mb: usize) -> PathBuf {
    let wt = root.join(name);
    git(
        repo,
        &["worktree", "add", "-q", "-b", name, wt.to_str().unwrap()],
    );
    if mb > 0 {
        write(&wt.join("build/out.bin"), mb * MB);
    }
    wt
}

fn findings(root: &Path, git: Option<&str>) -> Vec<Finding> {
    let mut f = GitWorktree.detect(&scan_tree(root), &ctx(git)).unwrap();
    f.sort_by(|a, b| a.path.cmp(&b.path));
    f
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn stale_prunable_locked_and_fresh_worktrees() {
    let (_t, root) = tmp();
    let r = repo(&root);
    let old = worktree(&r, &root, "wt-old", 2);
    let fresh = worktree(&r, &root, "wt-fresh", 2);
    let gone = worktree(&r, &root, "wt-gone", 0);
    let locked = worktree(&r, &root, "wt-locked", 2);
    git(
        &r,
        &["worktree", "lock", "--reason", "on a USB disk", s(&locked)],
    );
    fs::remove_dir_all(&gone).unwrap();
    age_tree(&old, STALE_DAYS as u64 + 6);
    age_tree(&locked, 30);

    let found = findings(&root, Some("git"));
    let paths: Vec<&str> = found.iter().map(|f| f.path.as_str()).collect();
    let admin = r.join(".git/worktrees");
    assert_eq!(paths, [s(&admin), s(&locked), s(&old)]);
    assert!(!paths.contains(&s(&fresh)));

    // Stale: review, removed by git without --force.
    let f = &found[2];
    assert_eq!(f.detector, "git-worktree");
    assert_eq!(f.id, detect::finding_id("git-worktree", &f.path));
    assert_eq!(f.tier, Tier::Review);
    assert!(f.guards.is_empty());
    assert!(f.bytes >= 2 << 20);
    assert_eq!(f.action.kind, ActionKind::Command);
    assert_eq!(
        f.action.argv.as_deref().unwrap(),
        ["git", "-C", s(&r), "worktree", "remove", s(&old)]
    );
    assert!(!f.action.text.contains("--force"));
    assert_eq!(
        f.recovery.how.as_deref(),
        Some(format!("git -C {} worktree add {} wt-old", s(&r), s(&old)).as_str())
    );
    assert!(
        f.reason
            .starts_with(&format!("git worktree of {} on branch wt-old (", s(&r))),
        "{}",
        f.reason
    );
    assert!(
        f.reason.ends_with("nothing written for 20 days"),
        "{}",
        f.reason
    );

    // Prunable: one finding for the repo, measuring git's bookkeeping.
    let p = &found[0];
    assert_eq!(p.tier, Tier::Review);
    assert_eq!(
        p.action.argv.as_deref().unwrap(),
        ["git", "-C", s(&r), "worktree", "prune"]
    );
    assert!(p.bytes > 0, "admin dir of wt-gone");
    assert!(p.reason.starts_with("1 worktree of"), "{}", p.reason);
    assert!(p.reason.contains(s(&gone)), "{}", p.reason);

    // Locked: shown, but blocked.
    let l = &found[1];
    assert_eq!(l.tier, Tier::Blocked);
    assert_eq!(l.guards.len(), 1);
    assert_eq!(l.guards[0].name, "locked");
    assert_eq!(l.guards[0].status, GuardStatus::Block);
    assert!(l.guards[0].detail.contains("on a USB disk"));
}

#[test]
fn small_detached_and_unscanned_worktrees() {
    let (_t, root) = tmp();
    let r = repo(&root);
    // Under the minimum size.
    let tiny = worktree(&r, &root, "wt-tiny", 0);
    age_tree(&tiny, 30);
    // Detached HEAD: no branch to recreate it from.
    let det = root.join("wt-detached");
    git(&r, &["worktree", "add", "-q", "--detach", s(&det)]);
    write(&det.join("build/out.bin"), 2 * MB);
    age_tree(&det, 30);

    let found = findings(&root, Some("git"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, s(&det));
    assert!(
        found[0].reason.contains("detached at"),
        "{}",
        found[0].reason
    );
    assert_eq!(found[0].recovery.how, None);

    // Scanning only the repo: the worktrees next to it are not measured.
    assert!(findings(&r, Some("git")).is_empty());
}

#[test]
fn needs_git_and_runs_it_only_for_repos_with_worktrees() {
    let (_t, root) = tmp();
    let r = repo(&root);
    let missing = root.join("no-such-git").to_string_lossy().into_owned();
    // No worktrees: git is never run, so a broken git is not an error.
    assert!(
        GitWorktree
            .detect(&scan_tree(&root), &ctx_with(None, Some(&missing)))
            .unwrap()
            .is_empty()
    );
    // Without git, nothing is reported.
    let old = worktree(&r, &root, "wt-old", 2);
    age_tree(&old, 30);
    assert!(findings(&root, None).is_empty());
    // With worktrees, a git that cannot run is reported.
    let err = GitWorktree
        .detect(&scan_tree(&root), &ctx_with(None, Some(&missing)))
        .unwrap_err();
    assert!(err.contains("cannot run"), "{err}");
}

#[test]
fn parses_porcelain_output() {
    let out = "worktree /src/repo\nHEAD 1111111111111111111111111111111111111111\nbranch refs/heads/main\n\n\
worktree /src/wt-a\nHEAD 2222222222222222222222222222222222222222\ndetached\nlocked\n\n\
worktree /src/wt-b\nHEAD 3333333333333333333333333333333333333333\nbranch refs/heads/feat/x\n\
locked moved to USB\nprunable gitdir file points to non-existent location\n";
    let e = parse_porcelain(out);
    assert_eq!(e.len(), 3);
    assert_eq!(e[0].path, PathBuf::from("/src/repo"));
    assert_eq!(e[0].branch.as_deref(), Some("main"));
    assert_eq!(
        e[1],
        WorktreeEntry {
            path: "/src/wt-a".into(),
            head: Some("2222222222222222222222222222222222222222".into()),
            detached: true,
            locked: Some(String::new()),
            ..WorktreeEntry::default()
        }
    );
    assert_eq!(e[2].branch.as_deref(), Some("feat/x"));
    assert_eq!(e[2].locked.as_deref(), Some("moved to USB"));
    assert!(e[2].prunable.is_some());
    assert!(parse_porcelain("worktree /x/bare.git\nbare\n")[0].bare);
}

#[test]
fn run_includes_git_worktree() {
    let (_t, root) = tmp();
    let r = repo(&root);
    let old = worktree(&r, &root, "wt-old", 2);
    age_tree(&old, 30);
    let tree = scan_tree(&root);
    let only = vec!["git-worktree".to_string()];
    let (found, runs) = detect::run_with(
        &tree,
        &ctx(Some("/usr/bin/git")),
        &dwhy_core::detectors::registry(),
        Some(&only),
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, s(&old));
    let run = runs.iter().find(|r| r.name == "git-worktree").unwrap();
    assert!(run.ran, "{run:?}");
    assert_eq!(run.findings, 1);
}
