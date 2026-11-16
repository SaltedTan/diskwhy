//! Guards: each one is shown to block on a real fixture (temp git
//! repositories, child processes with their cwd or a file inside the
//! target) and to pass when there is nothing to protect. Needs `git` and
//! `sleep` on PATH.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::detect::DetectContext;
use dwhy_core::docker::{self, Info, Snapshot, Source};
use dwhy_core::guard::{self, Proc, Processes};
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{
    Action, ActionKind, DockerSocket, Finding, GuardResult, GuardStatus, Recovery, Tier, ToolStatus,
};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

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

fn ctx_with(git: Option<&str>, docker: std::sync::Arc<Source>) -> DetectContext {
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
            off_path: None,
            enables: vec![],
        }],
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker,
    }
}

fn ctx() -> DetectContext {
    ctx_with(Some("/usr/bin/git"), Source::none())
}

fn finding(path: &str, tier: Tier) -> Finding {
    Finding {
        id: "f_test".into(),
        detector: "stale-tree".into(),
        probe: None,
        path: path.into(),
        bytes: 1,
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

/// Runs the guards on one finding at `target`, scanning `root`.
fn guards_with(
    root: &Path,
    target: &Path,
    ctx: &DetectContext,
    procs: &Processes,
) -> (Tier, Vec<GuardResult>) {
    let mut f = vec![finding(&target.to_string_lossy(), Tier::Review)];
    guard::check(&mut f, &scan_tree(root), ctx, procs);
    let f = f.pop().unwrap();
    (f.tier, f.guards)
}

fn guards(root: &Path, target: &Path) -> (Tier, Vec<GuardResult>) {
    guards_with(root, target, &ctx(), &Processes::default())
}

fn get<'a>(g: &'a [GuardResult], name: &str) -> &'a GuardResult {
    g.iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no {name} guard in {g:?}"))
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
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?} in {}", dir.display());
}

fn write(p: &Path, body: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

fn commit(repo: &Path, file: &str) {
    write(&repo.join(file), file);
    git(repo, &["add", file]);
    git(repo, &["commit", "-q", "-m", file]);
}

/// A repository with one commit, pushed to a bare remote next to it.
fn pushed_repo(base: &Path, name: &str) -> PathBuf {
    let remote = base.join(format!("{name}-remote.git"));
    fs::create_dir_all(&remote).unwrap();
    git(&remote, &["init", "-q", "--bare"]);
    let repo = base.join(name);
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    commit(&repo, "README");
    git(
        &repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&repo, &["push", "-q", "-u", "origin", "main"]);
    repo
}

fn base() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

#[test]
fn clean_pushed_repo_passes() {
    let (_t, b) = base();
    let repo = pushed_repo(&b, "app");
    let (tier, g) = guards(&b, &repo);
    assert_eq!(tier, Tier::Review);
    for name in ["in-use-cwd", "in-use-open", "git-dirty", "git-unpublished"] {
        assert_eq!(get(&g, name).status, GuardStatus::Pass, "{g:?}");
    }
    assert_eq!(get(&g, "git-dirty").detail, "1 git worktree checked");
}

#[test]
fn dirty_repo_blocks() {
    let (_t, b) = base();
    let repo = pushed_repo(&b, "app");
    write(&repo.join("notes.txt"), "untracked");
    let (tier, g) = guards(&b, &repo);
    assert_eq!(tier, Tier::Blocked);
    let d = get(&g, "git-dirty");
    assert_eq!(d.status, GuardStatus::Block);
    assert!(d.detail.contains("1 changed or untracked"), "{}", d.detail);
}

#[test]
fn ignored_files_are_not_dirty() {
    let (_t, b) = base();
    let repo = pushed_repo(&b, "app");
    write(&repo.join(".gitignore"), "target/\n");
    git(&repo, &["add", ".gitignore"]);
    git(&repo, &["commit", "-q", "-m", "ignore"]);
    git(&repo, &["push", "-q"]);
    write(&repo.join("target/debug/out"), "x");
    let (tier, g) = guards(&b, &repo);
    assert_eq!(tier, Tier::Review, "{g:?}");
}

#[test]
fn local_only_commits_block() {
    let (_t, b) = base();
    let repo = b.join("local");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    commit(&repo, "a");
    commit(&repo, "b");
    let (tier, g) = guards(&b, &repo);
    assert_eq!(tier, Tier::Blocked);
    let u = get(&g, "git-unpublished");
    assert_eq!(u.status, GuardStatus::Block);
    assert!(u.detail.contains("2 commits on no remote"), "{}", u.detail);
}

#[test]
fn unpushed_commit_and_stash_block() {
    let (_t, b) = base();
    let repo = pushed_repo(&b, "app");
    commit(&repo, "later");
    let (_, g) = guards(&b, &repo);
    assert_eq!(get(&g, "git-unpublished").status, GuardStatus::Block);

    let (_t2, b2) = base();
    let repo2 = pushed_repo(&b2, "app");
    write(&repo2.join("README"), "changed");
    git(&repo2, &["stash", "-q"]);
    let (tier, g) = guards(&b2, &repo2);
    assert_eq!(tier, Tier::Blocked);
    assert_eq!(get(&g, "git-dirty").status, GuardStatus::Pass);
    assert_eq!(
        get(&g, "git-unpublished").status,
        GuardStatus::Block,
        "{g:?}"
    );
}

#[test]
fn repository_inside_a_scratch_dir_is_found() {
    let (_t, b) = base();
    let scratch = b.join("scratch/try-1");
    fs::create_dir_all(&scratch).unwrap();
    let repo = scratch.join("clone");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    commit(&repo, "a");
    let (tier, g) = guards(&b, &scratch);
    assert_eq!(tier, Tier::Blocked);
    assert!(
        get(&g, "git-unpublished")
            .detail
            .contains(&*repo.to_string_lossy()),
        "{g:?}"
    );
}

#[test]
fn linked_worktrees() {
    let (_t, b) = base();
    let repo = pushed_repo(&b, "app");
    // On a branch with an unpushed commit: the commit stays in the repo.
    let wt = b.join("wt-branch");
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "feature",
            wt.to_str().unwrap(),
        ],
    );
    commit(&wt, "feature-work");
    let (tier, g) = guards(&b, &wt);
    assert_eq!(tier, Tier::Review, "{g:?}");
    let u = get(&g, "git-unpublished");
    assert_eq!(u.status, GuardStatus::Warn);
    assert!(
        u.detail.contains("1 commit unpushed on feature"),
        "{}",
        u.detail
    );

    // Detached with a new commit: it is on no branch, so it would be lost.
    let det = b.join("wt-detached");
    git(
        &repo,
        &["worktree", "add", "-q", "--detach", det.to_str().unwrap()],
    );
    commit(&det, "orphan");
    let (tier, g) = guards(&b, &det);
    assert_eq!(tier, Tier::Blocked);
    let u = get(&g, "git-unpublished");
    assert_eq!(u.status, GuardStatus::Block);
    assert!(
        u.detail.contains("1 commit on no branch or remote"),
        "{}",
        u.detail
    );

    // The main repository has worktrees outside it: removing it breaks them.
    let (_, g) = guards(&b, &repo);
    let l = get(&g, "git-linked-worktrees");
    assert_eq!(l.status, GuardStatus::Block);
    assert!(l.detail.contains("wt-branch"), "{}", l.detail);
}

#[test]
fn submodule_whose_git_dir_goes_with_the_finding_blocks() {
    let (_t, b) = base();
    pushed_repo(&b, "lib");
    let proj = pushed_repo(&b, "proj");
    let url = b.join("lib-remote.git");
    git(
        &proj,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            url.to_str().unwrap(),
            "lib",
        ],
    );
    let lib = proj.join("lib");
    commit(&lib, "one");
    commit(&lib, "two");
    // The superproject records the new submodule commit and is pushed, so
    // only the submodule's own commits are unpublished. Its git directory
    // is proj/.git/modules/lib, removed with proj.
    git(&proj, &["add", "lib"]);
    git(&proj, &["commit", "-q", "-m", "bump lib"]);
    git(&proj, &["push", "-q"]);
    let (tier, g) = guards(&b, &proj);
    assert_eq!(tier, Tier::Blocked, "{g:?}");
    assert_eq!(get(&g, "git-dirty").status, GuardStatus::Pass, "{g:?}");
    let u = get(&g, "git-unpublished");
    assert_eq!(u.status, GuardStatus::Block);
    assert!(
        u.detail
            .contains(&format!("{} (2 commits on no remote)", lib.display())),
        "{}",
        u.detail
    );
}

#[test]
fn submodule_moved_off_its_recorded_commit_is_dirty() {
    let (_t, b) = base();
    pushed_repo(&b, "lib");
    let proj = pushed_repo(&b, "proj");
    let url = b.join("lib-remote.git");
    git(
        &proj,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            url.to_str().unwrap(),
            "lib",
        ],
    );
    git(&proj, &["commit", "-q", "-m", "add lib"]);
    git(&proj, &["push", "-q"]);
    // The submodule moves to a new, pushed commit; the superproject has not
    // recorded it.
    let lib = proj.join("lib");
    commit(&lib, "newer");
    git(&lib, &["push", "-q"]);
    let (tier, g) = guards(&b, &proj);
    assert_eq!(tier, Tier::Blocked, "{g:?}");
    assert_eq!(
        get(&g, "git-unpublished").status,
        GuardStatus::Pass,
        "{g:?}"
    );
    let d = get(&g, "git-dirty");
    assert_eq!(d.status, GuardStatus::Block);
    assert!(
        d.detail
            .contains(&format!("{} (1 changed or untracked)", proj.display())),
        "{}",
        d.detail
    );
}

#[test]
fn bare_repositories() {
    let (_t, b) = base();
    // Holds a commit pushed from `app` and is nobody's clone: no remote has
    // it.
    pushed_repo(&b, "app");
    let bare = b.join("app-remote.git");
    let (tier, g) = guards(&b, &bare);
    assert_eq!(tier, Tier::Blocked, "{g:?}");
    let u = get(&g, "git-unpublished");
    assert_eq!(u.status, GuardStatus::Block);
    assert!(
        u.detail
            .contains(&format!("{} (1 commit on no remote)", bare.display())),
        "{}",
        u.detail
    );
    assert_eq!(get(&g, "git-dirty").detail, "1 git directory checked");

    // A bare clone whose branch is on its remote loses nothing.
    let mirror = b.join("mirror.git");
    fs::create_dir_all(&mirror).unwrap();
    git(&mirror, &["init", "-q", "--bare"]);
    git(
        &mirror,
        &["remote", "add", "origin", bare.to_str().unwrap()],
    );
    git(&mirror, &["fetch", "-q", "origin", "main:main"]);
    let (tier, g) = guards(&b, &mirror);
    assert_eq!(tier, Tier::Review, "{g:?}");
    assert_eq!(get(&g, "git-unpublished").status, GuardStatus::Pass);
}

#[test]
fn separate_git_dir_as_its_own_finding_blocks() {
    let (_t, b) = base();
    let scratch = b.join("scratch");
    let work = scratch.join("proj");
    let gitdir = scratch.join("proj.git");
    fs::create_dir_all(&work).unwrap();
    git(
        &work,
        &["init", "-q", "--separate-git-dir", gitdir.to_str().unwrap()],
    );
    commit(&work, "a");
    // Stale-tree reports each scratch subdirectory on its own.
    let mut f = vec![
        finding(&work.to_string_lossy(), Tier::Review),
        finding(&gitdir.to_string_lossy(), Tier::Review),
    ];
    guard::check(&mut f, &scan_tree(&b), &ctx(), &Processes::default());
    assert_eq!(
        get(&f[0].guards, "git-unpublished").status,
        GuardStatus::Warn,
        "{:?}",
        f[0].guards
    );
    let g = &f[1].guards;
    assert_eq!(f[1].tier, Tier::Blocked, "{g:?}");
    let u = get(g, "git-unpublished");
    assert_eq!(u.status, GuardStatus::Block);
    assert!(u.detail.contains("1 commit on no remote"), "{}", u.detail);
    let l = get(g, "git-linked-worktrees");
    assert_eq!(l.status, GuardStatus::Block);
    assert!(
        l.detail.contains(&format!("{} (of", work.display())),
        "{}",
        l.detail
    );
}

#[test]
fn separate_git_dir_inside_the_finding_blocks() {
    let (_t, b) = base();
    let scratch = b.join("scratch/try-1");
    let work = scratch.join("proj");
    fs::create_dir_all(&work).unwrap();
    git(
        &work,
        &[
            "init",
            "-q",
            "--separate-git-dir",
            scratch.join("proj.git").to_str().unwrap(),
        ],
    );
    commit(&work, "a");
    let (tier, g) = guards(&b, &scratch);
    assert_eq!(tier, Tier::Blocked, "{g:?}");
    let u = get(&g, "git-unpublished");
    assert_eq!(u.status, GuardStatus::Block);
    assert!(u.detail.contains("1 commit on no remote"), "{}", u.detail);

    // Only the work tree is in the finding: the repository lives on, and
    // the commit stays on its branch.
    let (tier, g) = guards(&b, &work);
    assert_eq!(tier, Tier::Review, "{g:?}");
    assert_eq!(get(&g, "git-unpublished").status, GuardStatus::Warn);
}

#[test]
fn git_runs_none_of_the_repositorys_programs() {
    use std::os::unix::fs::PermissionsExt;
    let (_t, b) = base();
    let repo = pushed_repo(&b, "app");
    write(
        &repo.join(".gitattributes"),
        "a filter=evil\nb filter=evilproc\n",
    );
    write(&repo.join("a"), "aaaa");
    write(&repo.join("b"), "bbbb");
    git(&repo, &["add", ".gitattributes", "a", "b"]);
    git(&repo, &["commit", "-q", "-m", "files"]);
    git(&repo, &["push", "-q"]);
    let marker = |name: &str| b.join(format!("ran-{name}"));
    let fsmonitor = b.join("fsmonitor.sh");
    write(
        &fsmonitor,
        &format!("#!/bin/sh\ntouch '{}'\n", marker("fsmonitor").display()),
    );
    fs::set_permissions(&fsmonitor, fs::Permissions::from_mode(0o755)).unwrap();
    let touch = |name: &str| format!("touch '{}'; cat", marker(name).display());
    for (k, v) in [
        ("filter.evil.clean", touch("clean")),
        ("filter.evil.required", "true".into()),
        ("filter.evilproc.process", touch("process")),
        ("core.fsmonitor", fsmonitor.to_string_lossy().into_owned()),
    ] {
        git(&repo, &["config", k, &v]);
    }
    // Same size, older mtime: git has to read the files again to compare.
    for f in ["a", "b"] {
        fs::File::options()
            .write(true)
            .open(repo.join(f))
            .unwrap()
            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_000_000))
            .unwrap();
    }
    let (tier, g) = guards(&b, &repo);
    for name in ["fsmonitor", "clean", "process"] {
        assert!(!marker(name).exists(), "git ran the repository's {name}");
    }
    assert_eq!(tier, Tier::Review, "{g:?}");
}

#[test]
fn git_missing_blocks_when_there_is_a_repository() {
    let (_t, b) = base();
    let repo = pushed_repo(&b, "app");
    let c = ctx_with(None, Source::none());
    let (tier, g) = guards_with(&b, &repo, &c, &Processes::default());
    assert_eq!(tier, Tier::Blocked);
    let d = get(&g, "git-dirty");
    assert_eq!(d.status, GuardStatus::Block);
    assert!(d.detail.contains("git is not installed"), "{}", d.detail);

    // No repository: no git guards at all, and nothing blocks.
    let plain = b.join("plain");
    write(&plain.join("f"), "x");
    let (tier, g) = guards_with(&b, &plain, &c, &Processes::default());
    assert_eq!(tier, Tier::Review);
    assert!(g.iter().all(|r| !r.name.starts_with("git-")), "{g:?}");
}

/// Kills the child when dropped.
struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sleep_in(dir: &Path, stdin: Stdio) -> Kill {
    Kill(
        Command::new("sleep")
            .arg("60")
            .current_dir(dir)
            .stdin(stdin)
            .spawn()
            .unwrap(),
    )
}

/// Reads /proc until the child shows up (it may not have exec'd yet).
fn processes_with(pid: u32, ready: impl Fn(&Proc) -> bool) -> Processes {
    for _ in 0..200 {
        let p = Processes::read();
        if p.procs.iter().any(|x| x.pid == pid && ready(x)) {
            return p;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("process {pid} never showed up in /proc");
}

#[test]
fn a_process_working_inside_blocks() {
    let (_t, b) = base();
    let target = b.join("busy");
    write(&target.join("deep/f"), "x");
    let child = sleep_in(&target.join("deep"), Stdio::null());
    let procs = processes_with(child.0.id(), |p| p.name == "sleep");
    let (tier, g) = guards_with(&b, &target, &ctx(), &procs);
    assert_eq!(tier, Tier::Blocked);
    let c = get(&g, "in-use-cwd");
    assert_eq!(c.status, GuardStatus::Block);
    assert!(
        c.detail.contains(&format!("sleep (pid {})", child.0.id())),
        "{}",
        c.detail
    );

    // A sibling directory is not affected.
    let other = b.join("idle");
    write(&other.join("f"), "x");
    let (tier, _) = guards_with(&b, &other, &ctx(), &procs);
    assert_eq!(tier, Tier::Review);
}

#[test]
fn a_process_with_a_file_open_inside_blocks() {
    let (_t, b) = base();
    let target = b.join("data");
    write(&target.join("db.sqlite"), "x");
    let file = fs::File::open(target.join("db.sqlite")).unwrap();
    let child = sleep_in(&b, Stdio::from(file));
    let procs = processes_with(child.0.id(), |p| p.name == "sleep");
    let (tier, g) = guards_with(&b, &target, &ctx(), &procs);
    assert_eq!(tier, Tier::Blocked);
    assert_eq!(get(&g, "in-use-cwd").status, GuardStatus::Pass);
    let o = get(&g, "in-use-open");
    assert_eq!(o.status, GuardStatus::Block);
    assert!(o.detail.contains("db.sqlite"), "{}", o.detail);
}

#[test]
fn injected_processes_are_used() {
    let (_t, b) = base();
    let target = b.join("t");
    write(&target.join("f"), "x");
    let procs = Processes {
        procs: vec![Proc {
            pid: 7,
            name: "python3".into(),
            cwd: Some(PathBuf::from("/elsewhere")),
            open: vec![target.join("f")],
        }],
        unreadable: 2,
    };
    let (_, g) = guards_with(&b, &target, &ctx(), &procs);
    assert!(get(&g, "in-use-open").detail.contains("python3 (pid 7)"));
    let c = get(&g, "in-use-cwd");
    assert_eq!(c.status, GuardStatus::Pass);
    assert!(
        c.detail.contains("2 processes of other users"),
        "{}",
        c.detail
    );
}

fn snapshot() -> Snapshot {
    let df = docker::parse_system_df(include_bytes!("data/docker-system-df.json")).unwrap();
    let info: Info =
        serde_json::from_str(r#"{"Driver":"overlayfs","DockerRootDir":"/var/lib/docker"}"#)
            .unwrap();
    Snapshot { df, info }
}

#[test]
fn container_mount() {
    let c = ctx_with(Some("git"), Source::fixed(snapshot()));
    let tree = ScanTree::default();
    let mut f = vec![
        finding("docker://volume/app_data", Tier::Review),
        finding("docker://volume/job_cache", Tier::Review),
        finding("docker://volume/orphan_pg", Tier::Review),
    ];
    // A detector's earlier result is replaced, not duplicated.
    f[0].guards.push(GuardResult {
        name: "container-mount".into(),
        status: GuardStatus::Warn,
        detail: "old".into(),
    });
    guard::check(&mut f, &tree, &c, &Processes::default());
    let status: Vec<(Tier, GuardStatus)> = f
        .iter()
        .map(|f| (f.tier, get(&f.guards, "container-mount").status))
        .collect();
    assert_eq!(
        status,
        [
            (Tier::Blocked, GuardStatus::Block),
            (Tier::Review, GuardStatus::Warn),
            (Tier::Review, GuardStatus::Pass),
        ]
    );
    assert_eq!(f[0].guards.len(), 1);
    assert!(f[0].guards[0].detail.contains("app-1 (running)"));

    // Docker unreachable: cannot check, so it blocks.
    let mut f = vec![finding("docker://volume/orphan_pg", Tier::Review)];
    guard::check(&mut f, &tree, &ctx(), &Processes::default());
    assert_eq!(f[0].tier, Tier::Blocked);
}

#[test]
fn repositories_inside_a_cache_are_not_checked() {
    let (_t, b) = base();
    let scratch = b.join("scratch/try-1");
    let cache = scratch.join("uv-cache");
    write(
        &cache.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    // A git file git cannot read, as uv leaves in its source builds.
    write(&cache.join("sdists-v10/.git"), "not a gitfile\n");
    write(&scratch.join("notes.txt"), "x");
    let (tier, g) = guards(&b, &scratch);
    assert_eq!(tier, Tier::Review, "{g:?}");
    assert!(g.iter().all(|r| !r.name.starts_with("git-")), "{g:?}");
}

#[test]
fn tool_caches_get_no_git_guards() {
    let (_t, b) = base();
    let repo = b.join("cache/git/checkouts/dep");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    commit(&repo, "a");
    let mut f = vec![finding(
        &b.join("cache").to_string_lossy(),
        Tier::Regenerable,
    )];
    f[0].detector = "user-cache".into();
    guard::check(&mut f, &scan_tree(&b), &ctx(), &Processes::default());
    assert_eq!(f[0].tier, Tier::Regenerable, "{:?}", f[0].guards);
    assert!(f[0].guards.iter().all(|r| !r.name.starts_with("git-")));
}
