//! `git-worktree` on temp git repositories. Needs `git` on PATH.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{self, DetectContext, Detector};
use dwhy_core::detectors::{
    GitWorktree, STALE_DAYS, WorktreeEntry, parse_porcelain, parse_porcelain_z,
};
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
        cancel: Default::default(),
        scratch_paths: Vec::new(),
        scratch_stale_days: dwhy_core::detectors::SCRATCH_STALE_DAYS,
    }
}

/// Runs git in `dir` with no user or system config, ignoring any repository
/// the caller's environment points at.
fn git<S: AsRef<OsStr> + std::fmt::Debug>(dir: &Path, args: &[S]) {
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
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
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
    repo_named(root, "repo")
}

fn repo_named(root: &Path, name: &str) -> PathBuf {
    let r = root.join(name);
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

/// Whether git recorded worktree `wt` of `repo` with relative paths, in both
/// the worktree's `.git` file and the repo's `gitdir` file. Only git 2.48 and
/// later honour `worktree.useRelativePaths`.
fn recorded_relative(repo: &Path, wt: &Path) -> bool {
    let dot_git = fs::read_to_string(wt.join(".git")).unwrap();
    let to_admin = dot_git.trim().strip_prefix("gitdir:").unwrap().trim();
    let name = wt.file_name().unwrap();
    let gitdir = fs::read_to_string(repo.join(".git/worktrees").join(name).join("gitdir")).unwrap();
    Path::new(to_admin).is_relative() && Path::new(gitdir.trim()).is_relative()
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
fn worktrees_scanned_without_their_repos() {
    let (_t, root) = tmp();
    let wts = root.join("wts");
    fs::create_dir_all(&wts).unwrap();
    let a = repo_named(&root, "repo-a");
    let a_old = worktree(&a, &wts, "a-old", 2);
    let a_gone = worktree(&a, &wts, "a-gone", 0);
    fs::remove_dir_all(&a_gone).unwrap();
    // Recorded with relative paths where git supports them: the `.git` file
    // says `gitdir: ../../repo-b/...`.
    let b = repo_named(&root, "repo-b");
    git(&b, &["config", "worktree.useRelativePaths", "true"]);
    let b_old = worktree(&b, &wts, "b-old", 2);
    if !recorded_relative(&b, &b_old) {
        eprintln!("git wrote absolute worktree paths; the relative case is not covered");
    }
    age_tree(&a_old, 30);
    age_tree(&b_old, 30);

    // Scanning only where the worktrees live finds both repos through the
    // worktrees' `.git` files; prunable entries of repos outside the scan
    // are not measured, so not reported.
    let found = findings(&wts, Some("git"));
    let paths: Vec<&str> = found.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, [s(&a_old), s(&b_old)]);
    assert_eq!(
        found[1].action.argv.as_deref().unwrap(),
        ["git", "-C", s(&b), "worktree", "remove", s(&b_old)]
    );

    // The same worktrees from the root: each repo is read once.
    let found = findings(&root, Some("git"));
    let paths: Vec<&str> = found.iter().map(|f| f.path.as_str()).collect();
    let admin = a.join(".git/worktrees");
    assert_eq!(paths, [s(&admin), s(&a_old), s(&b_old)]);
}

#[test]
fn prunable_bytes_with_relative_paths() {
    let (_t, root) = tmp();
    let r = repo(&root);
    git(&r, &["config", "worktree.useRelativePaths", "true"]);
    let gone = worktree(&r, &root, "wt-gone", 0);
    worktree(&r, &root, "wt-kept", 0);
    if !recorded_relative(&r, &gone) {
        eprintln!("skipped: git wrote absolute worktree paths (needs git 2.48 or later)");
        return;
    }
    fs::remove_dir_all(&gone).unwrap();

    let found = findings(&root, Some("git"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, s(&r.join(".git/worktrees")));
    let tree = scan_tree(&root);
    let entry = tree.find(&r.join(".git/worktrees/wt-gone")).unwrap();
    // Only wt-gone's bookkeeping goes, not wt-kept's.
    assert_eq!(found[0].bytes, tree.node(entry).freeable());
}

#[test]
fn submodule_git_files_are_not_followed() {
    let (_t, root) = tmp();
    let r = repo(&root);
    fs::create_dir_all(r.join(".git/modules/sub")).unwrap();
    let sub = r.join("sub");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join(".git"), "gitdir: ../.git/modules/sub\n").unwrap();
    // git is never run, so a broken git is not an error.
    let missing = root.join("no-such-git").to_string_lossy().into_owned();
    assert!(
        GitWorktree
            .detect(&scan_tree(&root), &ctx_with(None, Some(&missing)))
            .unwrap()
            .is_empty()
    );
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

#[test]
fn a_worktree_whose_main_repository_is_not_utf8_is_blocked() {
    let (_t, root) = tmp();
    let r = root.join(OsStr::from_bytes(b"repo\xff"));
    if let Err(e) = fs::create_dir(&r) {
        eprintln!("skipped: the filesystem refuses {r:?}: {e}");
        return;
    }
    git(&r, &["init", "-q"]);
    fs::write(r.join("README"), "hi").unwrap();
    git(&r, &["add", "README"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    // The worktree's own path is ASCII; the command's repository is not.
    let old = worktree(&r, &root, "wt-old", 2);
    age_tree(&old, 30);
    let only = vec!["git-worktree".to_string()];
    let (found, _) = detect::run_with(
        &scan_tree(&root),
        &ctx(Some("/usr/bin/git")),
        &dwhy_core::detectors::registry(),
        Some(&only),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(f.path, s(&old));
    assert_eq!(f.id, detect::finding_id("git-worktree", s(&old)));
    assert_eq!(f.tier, Tier::Blocked);
    assert_eq!(f.action.kind, ActionKind::Advice);
    assert_eq!(f.action.argv, None);
    let g = f.guards.iter().find(|g| g.name == "path-not-utf8").unwrap();
    assert_eq!(g.status, GuardStatus::Block);
    assert!(
        g.detail.starts_with("the action and recovery name a path"),
        "{}",
        g.detail
    );
    assert!(
        !f.recovery.how.as_deref().is_some_and(detect::is_lossy),
        "{:?}",
        f.recovery
    );
}

#[test]
fn parses_porcelain_z_output_with_raw_path_bytes() {
    let out = b"worktree /src/repo\0HEAD 1111111111111111111111111111111111111111\0branch refs/heads/main\0\0\
worktree /src/wt\xff\0HEAD 2222222222222222222222222222222222222222\0detached\0locked\0\0\
worktree /src/wt-b\0HEAD 3333333333333333333333333333333333333333\0branch refs/heads/feat/x\0\
locked moved to\nUSB\0prunable gitdir file points to non-existent location\0\0";
    let e = parse_porcelain_z(out);
    assert_eq!(e.len(), 3);
    assert_eq!(e[0].path, PathBuf::from("/src/repo"));
    assert_eq!(e[0].branch.as_deref(), Some("main"));
    assert_eq!(
        e[1],
        WorktreeEntry {
            path: PathBuf::from(OsStr::from_bytes(b"/src/wt\xff")),
            head: Some("2222222222222222222222222222222222222222".into()),
            detached: true,
            locked: Some(String::new()),
            ..WorktreeEntry::default()
        }
    );
    assert_eq!(e[2].branch.as_deref(), Some("feat/x"));
    // With -z, a reason may hold a newline.
    assert_eq!(e[2].locked.as_deref(), Some("moved to\nUSB"));
    assert!(e[2].prunable.is_some());
    assert!(parse_porcelain_z(b"worktree /x/bare.git\0bare\0\0")[0].bare);
}

/// `root/<name>` as raw bytes, or `None` (after saying so) when the
/// filesystem refuses a name that is not valid UTF-8.
fn non_utf8_dir(root: &Path, name: &[u8]) -> Option<PathBuf> {
    let p = root.join(OsStr::from_bytes(name));
    match fs::create_dir(&p) {
        Ok(()) => {
            fs::remove_dir(&p).unwrap();
            Some(p)
        }
        Err(e) => {
            eprintln!("skipped: the filesystem refuses {p:?}: {e}");
            None
        }
    }
}

/// Adds worktree `wt` of `repo` on new branch `branch`, with `mb` MiB inside.
fn worktree_at(repo: &Path, wt: &Path, branch: &str, mb: usize) {
    git(
        repo,
        &[
            OsStr::new("worktree"),
            OsStr::new("add"),
            OsStr::new("-q"),
            OsStr::new("-b"),
            OsStr::new(branch),
            wt.as_os_str(),
        ],
    );
    if mb > 0 {
        write(&wt.join("build/out.bin"), mb * MB);
    }
}

fn candidates(tree: &ScanTree) -> Vec<dwhy_core::detect::Candidate> {
    let mut c = GitWorktree
        .detect_candidates(tree, &ctx(Some("git")))
        .unwrap();
    c.sort_by(|a, b| a.path().cmp(b.path()));
    c
}

#[test]
fn a_stale_worktree_whose_name_is_not_utf8_is_found_and_blocked() {
    let (_t, root) = tmp();
    let Some(wt) = non_utf8_dir(&root, b"wt\xff") else {
        return;
    };
    let r = repo(&root);
    worktree_at(&r, &wt, "wt-raw", 2);
    age_tree(&wt, 30);

    let tree = scan_tree(&root);
    let want = tree.node(tree.find(&wt).unwrap()).freeable();
    let found = candidates(&tree);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path(), wt.as_path());
    assert_eq!(found[0].finding.bytes, want);
    assert!(want >= 2 << 20);

    let only = vec!["git-worktree".to_string()];
    let (found, _) = detect::run_with(
        &tree,
        &ctx(Some("git")),
        &dwhy_core::detectors::registry(),
        Some(&only),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(f.path, wt.to_string_lossy());
    assert_eq!(f.bytes, want);
    assert_eq!(f.tier, Tier::Blocked);
    assert_eq!(f.action.argv, None);
    let g = f.guards.iter().find(|g| g.name == "path-not-utf8").unwrap();
    assert_eq!(g.status, GuardStatus::Block);
}

#[test]
fn a_non_utf8_worktree_is_not_confused_with_its_lossy_sibling() {
    let (_t, root) = tmp();
    let Some(wt) = non_utf8_dir(&root, b"wt\xff") else {
        return;
    };
    let r = repo(&root);
    worktree_at(&r, &wt, "wt-raw", 2);
    // A real directory spelled the way `wt\xff` is shown, much bigger.
    let sibling = root.join("wt\u{FFFD}");
    write(&sibling.join("big.bin"), 6 * MB);
    age_tree(&wt, 30);
    age_tree(&sibling, 30);

    let tree = scan_tree(&root);
    let want = tree.node(tree.find(&wt).unwrap()).freeable();
    let other = tree.node(tree.find(&sibling).unwrap()).freeable();
    assert!(other > want + (3 << 20), "{other} vs {want}");
    let found = candidates(&tree);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path(), wt.as_path());
    assert_ne!(found[0].path(), sibling.as_path());
    assert_eq!(found[0].finding.bytes, want);
}

#[test]
fn non_utf8_worktrees_through_git_files_and_prune_accounting() {
    let (_t, root) = tmp();
    let wts = root.join("wts");
    fs::create_dir_all(&wts).unwrap();
    let Some(wt) = non_utf8_dir(&wts, b"wt\xff") else {
        return;
    };
    let r = repo(&root);
    worktree_at(&r, &wt, "wt-raw", 2);
    age_tree(&wt, 30);
    // Two worktrees whose names differ only in bytes that are not UTF-8:
    // shown alike, but only `gone\xff` is gone.
    let gone = root.join(OsStr::from_bytes(b"gone\xff"));
    let kept = root.join(OsStr::from_bytes(b"gone\xfe"));
    worktree_at(&r, &gone, "gone-a", 0);
    worktree_at(&r, &kept, "gone-b", 0);
    fs::remove_dir_all(&gone).unwrap();

    // Scanning only the worktree finds its repository through its `.git`
    // file, which names `.git/worktrees/wt\xff`.
    let found = candidates(&scan_tree(&wts));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path(), wt.as_path());

    // From the root, prune frees only `gone\xff`'s bookkeeping.
    let tree = scan_tree(&root);
    let admin = r.join(".git/worktrees");
    let entry = fs::read_dir(&admin)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|e| {
            fs::read(e.join("gitdir")).unwrap().trim_ascii()
                == gone.join(".git").as_os_str().as_bytes()
        })
        .unwrap();
    let want = tree.node(tree.find(&entry).unwrap()).freeable();
    let found = candidates(&tree);
    let paths: Vec<&Path> = found.iter().map(|c| c.path()).collect();
    assert_eq!(paths, [admin.as_path(), wt.as_path()]);
    let p = &found[0].finding;
    assert_eq!(p.bytes, want);
    assert!(p.reason.starts_with("1 worktree of"), "{}", p.reason);
}

/// Git before 2.36 has no `worktree list -z`: it exits 129 with
/// "unknown switch". The detector falls back to newline-separated porcelain,
/// which such git prints with paths unquoted, so raw bytes still survive.
#[test]
fn git_without_worktree_list_z_still_finds_worktrees() {
    use std::os::unix::fs::PermissionsExt;

    let (_t, root) = tmp();
    let Some(wt) = non_utf8_dir(&root, b"wt\xff") else {
        return;
    };
    let r = repo(&root);
    worktree_at(&r, &wt, "wt-raw", 2);
    let sibling = root.join("wt\u{FFFD}");
    write(&sibling.join("big.bin"), 6 * MB);
    age_tree(&wt, 30);
    age_tree(&sibling, 30);

    let (_bin_t, bin) = tmp();
    let old_git = bin.join("old-git");
    fs::write(
        &old_git,
        "#!/bin/sh\n\
         for a in \"$@\"; do\n\
         \x20 if [ \"$a\" = -z ]; then echo \"error: unknown switch \\`z'\" >&2; exit 129; fi\n\
         done\n\
         exec git \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&old_git, fs::Permissions::from_mode(0o755)).unwrap();
    let old_git = old_git.to_str().unwrap();

    let tree = scan_tree(&root);
    let want = tree.node(tree.find(&wt).unwrap()).freeable();
    let mut found = GitWorktree
        .detect_candidates(&tree, &ctx_with(None, Some(old_git)))
        .unwrap();
    found.sort_by(|a, b| a.path().cmp(b.path()));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path(), wt.as_path());
    assert_eq!(found[0].finding.bytes, want);
    assert_eq!(found[0].finding.tier, Tier::Review);
}
