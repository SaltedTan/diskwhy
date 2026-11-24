//! Guards check proposed removals and return pass, warn or block with
//! evidence. See the Guards decision in docs/DESIGN.md.
//!
//! For a filesystem finding:
//!
//! - `in-use-cwd`: a process has its working directory inside it.
//! - `in-use-open`: a process has a file inside it open, mapped, or as its
//!   executable.
//! - `git-dirty`: a git worktree inside it (or the finding itself) has
//!   uncommitted changes, untracked files included.
//! - `git-unpublished`: removing it would lose commits. For a repository
//!   whose git directory is inside the finding (a `.git` directory, or a
//!   `.git` file pointing inside it: a submodule of a superproject in the
//!   finding, a `--separate-git-dir` clone), that is anything reachable from
//!   a local ref, stash or worktree HEAD that is on no remote branch. For a
//!   linked worktree or submodule whose git directory is outside, the
//!   repository lives on, so only commits reachable from HEAD and from no
//!   branch or remote are lost (block); unpushed commits on its branch stay
//!   in the repository (warn).
//! - `git-linked-worktrees`: a repository inside the finding has worktrees
//!   outside it, which removing the repository would break: linked
//!   worktrees, and work trees in the scan whose `.git` file points at it.
//!
//! Repositories are found from the scan tree: directories holding `.git`,
//! and git directories without one (a bare repository, or the target of
//! `--separate-git-dir`: a `HEAD` file plus `objects/` and `refs/`). A git
//! directory gets `git-unpublished` and `git-linked-worktrees` only; no
//! `git status` runs there. A git directory whose `HEAD` the enclosing work
//! tree tracks (a test fixture of a source tree) is part of that
//! repository's history and is not checked on its own; an untracked or
//! ignored one is. A bare or mirror clone has no remote-tracking refs, so
//! every commit in it counts as on no remote and it blocks; linked
//! worktrees of such a clone warn about their whole branch for the same
//! reason. A `.git` file is resolved by reading it and the `commondir` it
//! leads to, not by asking git.
//!
//! Git runs none of the repository's own programs: fsmonitor and every
//! configured filter driver are switched off, and `git status` does not look
//! inside submodules (each is checked as a repository of its own), though a
//! submodule checked out at a commit other than the recorded one still
//! makes the superproject dirty.
//!
//! For a Docker volume, `container-mount`: mounted by a running container
//! (block) or a stopped one (warn).
//!
//! Git guards skip repositories inside a cache (below a `CACHEDIR.TAG`)
//! and do not apply to `user-cache` and `tool-versions` findings: those
//! repositories are the tools' own checkouts. Neither git nor process
//! guards apply to `journald`: `systemd-journald` always has the active
//! journals open, and the vacuum removes only closed archived files. Git
//! guards do not apply to `apt-cache` either (`apt-get clean` removes only
//! apt's cache files), but process guards do: `apt` and `dpkg` hold
//! `archives/lock` open while they work.
//!
//! Identities are checked again at this boundary, before any git state is
//! read: a finding root or repository that is no longer the directory the
//! walk measured (gone, replaced, a symlink, or behind a symlink or
//! non-directory) is not read. Such a root gets a blocking
//! `changed-since-scan`, and such a repository inside a finding blocks it
//! as one git could not check. A `.git` file whose `gitdir:` or `commondir`
//! leads into a changed root or repository is not followed. A work tree in
//! the scan that changed (but is not gone) may use any git directory, so a
//! finding that holds one cannot be cleared by `git-linked-worktrees`.
//!
//! Processes are read from `/proc`; other users' processes cannot be read
//! without root, which the pass detail says. A guard that cannot check (git
//! missing or failing, Docker unreachable) blocks. A blocking guard moves
//! the finding to the `blocked` tier.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::detect::DetectContext;
use crate::gitcmd::Git;
use crate::plan::{self, Measured};
use crate::report::{Finding, GuardResult, GuardStatus, Tier};
use crate::tree::{Markers, ScanTree};

/// Most processes or repositories named in one guard's detail.
const MAX_NAMED: usize = 3;

/// One running process: what it has its cwd in and what it has open.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    /// Command name (`/proc/<pid>/comm`).
    pub name: String,
    pub cwd: Option<PathBuf>,
    /// Executable, open files and mapped files.
    pub open: Vec<PathBuf>,
}

/// The processes guards look at.
#[derive(Debug, Clone, Default)]
pub struct Processes {
    pub procs: Vec<Proc>,
    /// Processes whose details could not be read (other users' without root).
    pub unreadable: usize,
}

impl Processes {
    /// Reads every process in `/proc` except this one.
    pub fn read() -> Processes {
        let me = std::process::id();
        let mut out = Processes::default();
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return out;
        };
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if pid == me {
                continue;
            }
            let dir = e.path();
            let cwd = read_link(&dir.join("cwd"));
            let exe = read_link(&dir.join("exe"));
            if cwd.is_none() && exe.is_none() {
                // Gone, a kernel thread (empty cmdline), or another user's
                // process.
                let kernel = std::fs::read(dir.join("cmdline")).is_ok_and(|c| c.is_empty());
                if !kernel
                    && std::fs::read_link(dir.join("cwd"))
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
                {
                    out.unreadable += 1;
                }
                continue;
            }
            let mut open: Vec<PathBuf> = exe.into_iter().collect();
            if let Ok(fds) = std::fs::read_dir(dir.join("fd")) {
                open.extend(fds.flatten().filter_map(|fd| read_link(&fd.path())));
            }
            if let Ok(maps) = std::fs::read_to_string(dir.join("maps")) {
                for line in maps.lines() {
                    // address perms offset dev inode path
                    if let Some(p) = line.splitn(6, char::is_whitespace).nth(5) {
                        let p = strip_deleted(p.trim());
                        if p.starts_with('/') {
                            open.push(PathBuf::from(p));
                        }
                    }
                }
            }
            open.sort();
            open.dedup();
            let name = std::fs::read_to_string(dir.join("comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            out.procs.push(Proc {
                pid,
                name,
                cwd,
                open,
            });
        }
        out.procs.sort_by_key(|p| p.pid);
        out
    }
}

/// An absolute link target, without a ` (deleted)` suffix. Sockets, pipes
/// and anonymous inodes are not paths.
fn read_link(p: &Path) -> Option<PathBuf> {
    let t = std::fs::read_link(p).ok()?;
    let s = t.to_str()?;
    let s = strip_deleted(s);
    s.starts_with('/').then(|| PathBuf::from(s))
}

fn strip_deleted(s: &str) -> &str {
    s.strip_suffix(" (deleted)").unwrap_or(s)
}

/// Runs the guards on every finding: appends their results and moves a
/// finding with a blocking result to `blocked`. `tree` must hold the
/// scanned paths (git repositories are found through it).
pub fn check(findings: &mut [Finding], tree: &ScanTree, ctx: &DetectContext, procs: &Processes) {
    use rayon::prelude::*;
    // Identities first: nothing below a root that changed since the walk is
    // read. A root the scan did not measure has no repositories of its own
    // in the tree; those are checked one by one below.
    let root_changes: Vec<Option<String>> = findings
        .par_iter()
        .map(|f| {
            if !f.path.starts_with('/') {
                return None;
            }
            match plan::measured(&f.path, f.file_identity, tree) {
                Measured::Unknown => None,
                m => plan::changed_root(Path::new(&f.path), m, false),
            }
        })
        .collect();
    let changed_roots: Vec<&Path> = findings
        .iter()
        .zip(&root_changes)
        .filter(|(_, c)| c.is_some())
        .map(|(f, _)| Path::new(&f.path))
        .collect();
    let fs_roots: Vec<&Path> = findings
        .iter()
        .zip(&root_changes)
        .filter(|(f, c)| c.is_none() && f.path.starts_with('/') && git_guarded(f))
        .map(|(f, _)| Path::new(&f.path))
        .collect();
    let mut repos = repositories(tree);
    // The work trees (every one: their `.git` files are read for `users`)
    // and the repositories in a finding, checked against the walk.
    let changed_repos: HashMap<Repo, String> = repos
        .par_iter()
        .filter(|r| {
            matches!(r, Repo::WorkTree(_)) || fs_roots.iter().any(|root| r.path().starts_with(root))
        })
        .filter_map(|r| {
            let detail = match changed_roots.iter().find(|c| r.path().starts_with(c)) {
                Some(c) => format!("{} changed since the scan", c.display()),
                None => {
                    let id = tree.find(r.path()).map(|id| tree.node(id))?;
                    plan::changed_root(r.path(), Measured::Inode(id.dev, id.ino), false)?
                }
            };
            Some((r.clone(), detail))
        })
        .collect();
    let mut changed: Vec<PathBuf> = changed_roots.iter().map(|p| p.to_path_buf()).collect();
    changed.extend(changed_repos.keys().map(|r| r.path().to_path_buf()));
    let git_cmd = ctx.tool_command("git");
    let git = git_cmd.as_deref().map(|cmd| Git {
        cmd,
        cancel: &ctx.cancel,
    });
    if let Some(git) = git {
        let tracked: HashSet<Repo> = repos
            .par_iter()
            .filter(|r| {
                matches!(r, Repo::GitDir(_))
                    && !changed_repos.contains_key(r)
                    && fs_roots.iter().any(|root| r.path().starts_with(root))
                    && tracked_by_work_tree(git, r.path(), &repos, &changed)
            })
            .cloned()
            .collect();
        repos.retain(|r| !tracked.contains(r));
    }
    // The work trees in the scan that use each git directory through a
    // `.git` file, and those whose git directory is not known because they
    // (or what their `.git` file points into) changed since the walk. A
    // work tree that is gone uses nothing.
    let mut users: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
    let mut unknown_users: Vec<PathBuf> = Vec::new();
    for r in &repos {
        let Repo::WorkTree(dir) = r else {
            continue;
        };
        if changed_repos.contains_key(r) {
            if !plan::removal_path_absent(dir) {
                unknown_users.push(dir.clone());
            }
            continue;
        }
        match common_dir(&dir.join(".git"), &changed) {
            Ok(common) => users.entry(common).or_default().push(dir.clone()),
            Err(Pointer::IntoChanged(_)) => unknown_users.push(dir.clone()),
            Err(Pointer::Unreadable(_)) => {}
        }
    }
    let inside = |f: &Finding| -> Vec<&Repo> {
        if !f.path.starts_with('/') || !git_guarded(f) {
            return Vec::new();
        }
        let root = Path::new(&f.path);
        repos
            .iter()
            .filter(|r| r.path().starts_with(root))
            .collect()
    };
    // Every repository any finding needs, with the outermost finding it is
    // in, read once and in parallel.
    let mut needed: HashMap<&Repo, PathBuf> = HashMap::new();
    for (f, _) in findings
        .iter()
        .zip(&root_changes)
        .filter(|(_, c)| c.is_none())
    {
        for r in inside(f) {
            let root = PathBuf::from(&f.path);
            let outer = needed.entry(r).or_insert_with(|| root.clone());
            if outer.starts_with(&root) {
                *outer = root;
            }
        }
    }
    let states: HashMap<&Repo, RepoState> = needed
        .par_iter()
        .map(|(r, outer)| {
            let state = match changed_repos.get(*r) {
                Some(detail) => RepoState::Failed(detail.clone()),
                None => RepoState::read(git, r, outer, &changed),
            };
            (*r, state)
        })
        .collect();
    for (f, root_change) in findings.iter_mut().zip(root_changes) {
        let mut results = Vec::new();
        if f.path.starts_with('/') {
            let root = PathBuf::from(&f.path);
            if process_guarded(f) {
                results.push(in_use_cwd(&root, procs));
                results.push(in_use_open(&root, procs));
            }
            if let Some(detail) = root_change {
                plan::add_changed_guard(&mut results, detail);
            } else {
                let mine: Vec<(&Repo, &RepoState)> =
                    inside(f).into_iter().map(|r| (r, &states[r])).collect();
                if !mine.is_empty() {
                    results.extend(git_guards(&root, &mine, &users, &unknown_users));
                }
            }
        } else if let Some(name) = f.path.strip_prefix("docker://volume/") {
            results.push(container_mount(name, ctx));
        }
        for r in results {
            // A detector may already have set this guard (docker-volume's
            // container-mount): the fresh result replaces it.
            f.guards.retain(|g| g.name != r.name);
            f.guards.push(r);
        }
        if f.guards.iter().any(|g| g.status == GuardStatus::Block) {
            f.tier = Tier::Blocked;
        }
    }
}

/// Whether the git guards apply: not to tool-managed caches and tool
/// versions, whose repositories are the tools' own checkouts (Cargo's git
/// dependencies, uv's source builds, VS Code's servers).
///
/// Nor to `journald` and `apt-cache`: the vacuum removes only archived
/// journal files and `apt-get clean` only apt's own cache files, so
/// neither can touch a repository.
pub(crate) fn git_guarded(f: &Finding) -> bool {
    !matches!(
        f.detector.as_str(),
        "user-cache" | "tool-versions" | "journald" | "apt-cache"
    )
}

/// Whether `in-use-cwd` and `in-use-open` apply. Not to `journald`:
/// `systemd-journald` always has the active journals in `/var/log/journal`
/// open, so the guards would block every finding, and the action
/// (`journalctl --vacuum-time`) removes only closed archived files, leaving
/// the directory and the active journals in place. `changed-since-scan`
/// still applies.
fn process_guarded(f: &Finding) -> bool {
    f.detector != "journald"
}

/// What the git guards check. Work trees sort before git directories, so
/// a repository found both ways is named by its work tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Repo {
    /// A directory holding `.git` (a directory or a file).
    WorkTree(PathBuf),
    /// A git directory with no `.git` entry: a bare repository or the
    /// target of `--separate-git-dir`.
    GitDir(PathBuf),
}

impl Repo {
    fn path(&self) -> &Path {
        match self {
            Repo::WorkTree(p) | Repo::GitDir(p) => p,
        }
    }
}

/// Work trees (directories holding `.git`) and git directories (a regular
/// `HEAD` file plus `objects/` and `refs/`, other than `.git` itself) in
/// the tree, except those inside a cache (a directory above them holds
/// `CACHEDIR.TAG`): a tool's checkouts, such as uv's source builds.
fn repositories(tree: &ScanTree) -> Vec<Repo> {
    let in_cache = |mut id| {
        while let Some(p) = tree.parent(id) {
            if tree.node(p).markers.contains(Markers::CACHEDIR_TAG) {
                return true;
            }
            id = p;
        }
        false
    };
    let mut out: Vec<Repo> = tree
        .ids()
        .filter_map(|id| {
            let n = tree.node(id);
            if !n.is_dir {
                return None;
            }
            let repo = if n.markers.contains(Markers::DOT_GIT) {
                Repo::WorkTree(tree.path(id))
            } else if n.markers.contains(Markers::GIT_HEAD)
                && tree.name(id) != OsStr::new(".git")
                && ["objects", "refs"]
                    .iter()
                    .all(|c| tree.child_named(id, c).is_some())
            {
                Repo::GitDir(tree.path(id))
            } else {
                return None;
            };
            (!in_cache(id)).then_some(repo)
        })
        .collect();
    out.sort();
    out
}

/// Whether the work tree around the git directory `dir` tracks its `HEAD`:
/// a test fixture of a source tree, kept by that repository's history.
fn tracked_by_work_tree(git: Git<'_>, dir: &Path, repos: &[Repo], changed: &[PathBuf]) -> bool {
    let Some(work_tree) = repos
        .iter()
        .filter_map(|r| match r {
            Repo::WorkTree(w) if dir.starts_with(w) => Some(w),
            _ => None,
        })
        .max_by_key(|w| w.as_os_str().len())
    else {
        return false;
    };
    if changed.iter().any(|c| work_tree.starts_with(c)) {
        return false;
    }
    let git_dir = work_tree.join(".git");
    if !std::fs::symlink_metadata(&git_dir).is_ok_and(|m| m.is_dir())
        && common_dir(&git_dir, changed).is_err()
    {
        return false;
    }
    let Some(head) = dir
        .strip_prefix(work_tree)
        .ok()
        .and_then(|rel| rel.join("HEAD").to_str().map(String::from))
    else {
        return false;
    };
    crate::gitcmd::run(
        git,
        work_tree,
        &[
            "--literal-pathspecs",
            "ls-files",
            "-z",
            "--error-unmatch",
            "--",
            &head,
        ],
    )
    .is_ok()
}

fn named(procs: &[&Proc]) -> String {
    list(
        &procs
            .iter()
            .map(|p| format!("{} (pid {})", p.name, p.pid))
            .collect::<Vec<_>>(),
    )
}

fn unread_note(procs: &Processes) -> String {
    if procs.unreadable > 0 {
        format!(
            "; {} processes of other users could not be checked (needs root)",
            procs.unreadable
        )
    } else {
        String::new()
    }
}

fn in_use_cwd(root: &Path, procs: &Processes) -> GuardResult {
    let hits: Vec<&Proc> = procs
        .procs
        .iter()
        .filter(|p| p.cwd.as_deref().is_some_and(|c| c.starts_with(root)))
        .collect();
    if hits.is_empty() {
        GuardResult {
            name: "in-use-cwd".into(),
            status: GuardStatus::Pass,
            detail: format!(
                "no process has its working directory in it{}",
                unread_note(procs)
            ),
        }
    } else {
        GuardResult {
            name: "in-use-cwd".into(),
            status: GuardStatus::Block,
            detail: format!("working directory of {}", named(&hits)),
        }
    }
}

fn in_use_open(root: &Path, procs: &Processes) -> GuardResult {
    let hits: Vec<&Proc> = procs
        .procs
        .iter()
        .filter(|p| p.open.iter().any(|o| o.starts_with(root)))
        .collect();
    if hits.is_empty() {
        GuardResult {
            name: "in-use-open".into(),
            status: GuardStatus::Pass,
            detail: format!("no process has a file in it open{}", unread_note(procs)),
        }
    } else {
        let example = hits[0]
            .open
            .iter()
            .find(|o| o.starts_with(root))
            .map(|o| format!(", e.g. {}", o.display()))
            .unwrap_or_default();
        GuardResult {
            name: "in-use-open".into(),
            status: GuardStatus::Block,
            detail: format!("open in {}{example}", named(&hits)),
        }
    }
}

/// What git says about one repository or worktree.
#[derive(Debug, Clone)]
enum RepoState {
    Failed(String),
    Read {
        /// The repository's git directory (shared by all its worktrees):
        /// when it is inside a finding, the repository goes with it.
        common: PathBuf,
        dirty: usize,
        /// Commits on no remote branch, from every local ref, stash and
        /// worktree HEAD; counted when `common` is inside a finding.
        unpublished: usize,
        /// Linked worktrees of the repository (their directories); read
        /// when `common` is inside a finding.
        linked: Vec<PathBuf>,
        /// Commits reachable from HEAD and from no branch or remote.
        lost: usize,
        /// Unpushed commits on the worktree's branch (they stay in the repo).
        unpushed_kept: usize,
        branch: Option<String>,
    },
}

impl RepoState {
    /// Reads `repo`; `outer` is the outermost finding it is in, and
    /// `changed` the roots and repositories not to follow a `.git` file into.
    fn read(git: Option<Git<'_>>, repo: &Repo, outer: &Path, changed: &[PathBuf]) -> RepoState {
        let Some(git) = git else {
            return RepoState::Failed("git is not installed".into());
        };
        let read = match repo {
            Repo::WorkTree(dir) => Self::read_work_tree(git, dir, outer, changed),
            Repo::GitDir(dir) => Self::read_git_dir(git, dir),
        };
        match read {
            Ok(s) => s,
            Err(e) => RepoState::Failed(e),
        }
    }

    /// A bare repository or separate git dir: no work tree to look at.
    fn read_git_dir(git: Git<'_>, dir: &Path) -> Result<RepoState, String> {
        Ok(RepoState::Read {
            common: dir.to_path_buf(),
            dirty: 0,
            unpublished: count(
                git,
                dir,
                &[
                    "--git-dir=.",
                    "--work-tree=.",
                    "rev-list",
                    "--count",
                    "--all",
                    "--not",
                    "--remotes",
                ],
            )?,
            linked: linked_worktrees(dir),
            lost: 0,
            unpushed_kept: 0,
            branch: None,
        })
    }

    fn read_work_tree(
        git: Git<'_>,
        dir: &Path,
        outer: &Path,
        changed: &[PathBuf],
    ) -> Result<RepoState, String> {
        let git_dir = dir.join(".git");
        let gitfile = !std::fs::symlink_metadata(&git_dir).is_ok_and(|m| m.is_dir());
        let common = if gitfile {
            common_dir(&git_dir, changed).map_err(Pointer::into_message)?
        } else {
            git_dir
        };
        // One call for the changes, the branch and whether HEAD exists.
        let mut args = no_filters(git, dir)?;
        args.extend(
            [
                "status",
                "--porcelain=v2",
                "--branch",
                "-z",
                "--untracked-files=normal",
                "--ignore-submodules=dirty",
            ]
            .map(String::from),
        );
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let status = crate::gitcmd::run(git, dir, &args)?;
        let mut dirty = 0;
        let mut branch = None;
        let mut has_head = true;
        for entry in status.split('\0') {
            if let Some(h) = entry.strip_prefix("# branch.head ") {
                branch = (h != "(detached)").then(|| h.to_string());
            } else if entry == "# branch.oid (initial)" {
                has_head = false;
            } else if ["1 ", "2 ", "u ", "? "]
                .iter()
                .any(|p| entry.starts_with(p))
            {
                dirty += 1;
            }
        }
        let (unpublished, linked) = if common.starts_with(outer) {
            // Everything local (branches, tags, stash, every worktree's
            // HEAD) that no remote branch has.
            (
                count(
                    git,
                    dir,
                    &["rev-list", "--count", "--all", "--not", "--remotes"],
                )?,
                linked_worktrees(&common),
            )
        } else {
            (0, Vec::new())
        };
        let (lost, unpushed_kept) = if gitfile && has_head {
            let lost = count(
                git,
                dir,
                &[
                    "rev-list",
                    "--count",
                    "HEAD",
                    "--not",
                    "--branches",
                    "--remotes",
                ],
            )?;
            let unpushed = if branch.is_some() {
                count(
                    git,
                    dir,
                    &["rev-list", "--count", "HEAD", "--not", "--remotes"],
                )?
            } else {
                0
            };
            (lost, unpushed)
        } else {
            (0, 0)
        };
        Ok(RepoState::Read {
            common,
            dirty,
            unpublished,
            linked,
            lost,
            unpushed_kept,
            branch,
        })
    }
}

/// The commit id of HEAD (`"unborn"` before the first commit) and the
/// entries of `git status --porcelain=v2 -z` with untracked files, for a
/// plan's fingerprint of the work tree `dir`. The branch headers are left
/// out: ahead/behind counts change with every fetch. Runs no filter driver
/// or fsmonitor, like the guards.
pub(crate) fn work_tree_state(git: Git<'_>, dir: &Path) -> Result<(String, String), String> {
    let mut args = no_filters(git, dir)?;
    args.extend(
        [
            "status",
            "--porcelain=v2",
            "--branch",
            "-z",
            "--untracked-files=normal",
            "--ignore-submodules=dirty",
        ]
        .map(String::from),
    );
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let status = crate::gitcmd::run(git, dir, &args)?;
    let mut head = None;
    let mut entries = String::new();
    for entry in status.split('\0') {
        if let Some(oid) = entry.strip_prefix("# branch.oid ") {
            head = Some(if oid == "(initial)" { "unborn" } else { oid }.to_string());
        } else if !entry.starts_with("# ") && !entry.is_empty() {
            entries.push_str(entry);
            entries.push('\0');
        }
    }
    let head = head.ok_or_else(|| "git status printed no HEAD".to_string())?;
    Ok((head, entries))
}

/// Runs a git command that prints a count.
fn count(git: Git<'_>, dir: &Path, args: &[&str]) -> Result<usize, String> {
    let out = crate::gitcmd::run(git, dir, args)?;
    out.trim()
        .parse()
        .map_err(|_| format!("unexpected git output: {}", out.trim()))
}

/// Why a `.git` file was not resolved.
enum Pointer {
    /// It, or the `commondir` it leads to, could not be read or parsed.
    Unreadable(String),
    /// It leads into a root or repository that changed since the walk.
    IntoChanged(String),
}

impl Pointer {
    fn into_message(self) -> String {
        match self {
            Pointer::Unreadable(e) | Pointer::IntoChanged(e) => e,
        }
    }
}

/// The git directory shared by all worktrees of the repository whose `.git`
/// file is `dot_git`: the file's `gitdir:` target, or the `commondir` named
/// there. Relative paths are resolved as git does, against the directory
/// holding the file. A target inside one of the `changed` paths is not
/// read or returned.
fn common_dir(dot_git: &Path, changed: &[PathBuf]) -> Result<PathBuf, Pointer> {
    let into_changed = |p: &Path| -> Result<(), Pointer> {
        match changed.iter().find(|c| p.starts_with(c)) {
            Some(c) => Err(Pointer::IntoChanged(format!(
                "{} points into {}, which changed since the scan",
                dot_git.display(),
                c.display()
            ))),
            None => Ok(()),
        }
    };
    let gitdir = gitfile_target(dot_git).map_err(Pointer::Unreadable)?;
    into_changed(&gitdir)?;
    let commondir = gitdir.join("commondir");
    if std::fs::symlink_metadata(&commondir).is_err() {
        return Ok(gitdir);
    }
    let common = normalize(&gitdir.join(first_line(&commondir).map_err(Pointer::Unreadable)?));
    into_changed(&common)?;
    Ok(common)
}

/// The first line of the file at `p`, without a trailing newline or blanks.
fn first_line(p: &Path) -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStrExt;
    let text = crate::detectors::read_head(p, 4096)
        .ok_or_else(|| format!("cannot read {}", p.display()))?;
    let line = text.split(|&b| b == b'\n').next().unwrap_or_default();
    Ok(PathBuf::from(OsStr::from_bytes(line.trim_ascii_end())))
}

/// The `gitdir:` target of the `.git` file `dot_git`, resolved against the
/// directory holding it.
fn gitfile_target(dot_git: &Path) -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStrExt;
    let line = first_line(dot_git)?;
    let target = line
        .as_os_str()
        .as_bytes()
        .strip_prefix(b"gitdir: ")
        .filter(|t| !t.is_empty())
        .ok_or_else(|| format!("{} is not a gitfile", dot_git.display()))?;
    let base = dot_git.parent().unwrap_or(Path::new("/"));
    Ok(normalize(&base.join(OsStr::from_bytes(target))))
}

/// `-c` options switching off every filter driver in the repository's
/// config, so that `git status` runs none of their programs when it hashes
/// a file.
fn no_filters(git: Git<'_>, dir: &Path) -> Result<Vec<String>, String> {
    let keys = crate::gitcmd::run(git, dir, &["config", "--list", "--name-only", "-z"])?;
    let mut drivers: Vec<&str> = keys
        .split('\0')
        .filter_map(|k| Some(k.strip_prefix("filter.")?.rsplit_once('.')?.0))
        .collect();
    drivers.sort();
    drivers.dedup();
    let mut out = Vec::new();
    for d in drivers {
        if d.contains('=') {
            return Err(format!("cannot switch off filter driver {d:?}"));
        }
        for kv in ["clean=", "smudge=", "process=", "required=false"] {
            out.push("-c".to_string());
            out.push(format!("filter.{d}.{kv}"));
        }
    }
    Ok(out)
}

/// Directories of the linked worktrees that still exist, from each
/// `<git dir>/worktrees/<name>/gitdir` (the path of the worktree's `.git`
/// file, relative to that admin directory when git wrote it relative).
fn linked_worktrees(git_dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(git_dir.join("worktrees")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let Some(text) = crate::detectors::read_head(&e.path().join("gitdir"), 4096) else {
            continue;
        };
        let p = PathBuf::from(String::from_utf8_lossy(&text).trim());
        let p = if p.is_absolute() {
            p
        } else {
            normalize(&e.path().join(p))
        };
        if let Some(wt) = p.parent()
            && std::fs::symlink_metadata(&p).is_ok()
        {
            out.push(wt.to_path_buf());
        }
    }
    out.sort();
    out
}

/// Resolves `.` and `..` without touching the filesystem.
fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn list(dirs: &[String]) -> String {
    let mut s = dirs
        .iter()
        .take(MAX_NAMED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if dirs.len() > MAX_NAMED {
        s.push_str(&format!(" and {} more", dirs.len() - MAX_NAMED));
    }
    s
}

/// `users` maps a git directory to the work trees in the scan that use it;
/// `unknown_users` are the work trees in the scan whose git directory is
/// not known because they changed since the walk.
fn git_guards(
    root: &Path,
    repos: &[(&Repo, &RepoState)],
    users: &HashMap<PathBuf, Vec<PathBuf>>,
    unknown_users: &[PathBuf],
) -> Vec<GuardResult> {
    let mut failed = Vec::new();
    let mut dirty = Vec::new();
    let mut lost = Vec::new();
    let mut kept = Vec::new();
    let mut linked_out = Vec::new();
    // A repository going with the finding is reported once, under its
    // first work tree, however many of its work trees are inside.
    let mut gone: HashSet<&PathBuf> = HashSet::new();
    for (repo, state) in repos {
        let d = repo.path().display();
        match state {
            RepoState::Failed(e) => failed.push(format!("{d}: {e}")),
            RepoState::Read {
                common,
                dirty: n_dirty,
                unpublished,
                linked,
                lost: n_lost,
                unpushed_kept,
                branch,
            } => {
                if *n_dirty > 0 {
                    dirty.push(format!("{d} ({n_dirty} changed or untracked)"));
                }
                if common.starts_with(root) {
                    if !gone.insert(common) {
                        continue;
                    }
                    if *unpublished > 0 {
                        lost.push(format!("{d} ({} on no remote)", commits(*unpublished)));
                    }
                    let mut outside: Vec<&PathBuf> = linked
                        .iter()
                        .chain(users.get(common).into_iter().flatten())
                        .filter(|w| !w.starts_with(root))
                        .collect();
                    outside.sort();
                    outside.dedup();
                    for w in outside {
                        linked_out.push(format!("{} (of {d})", w.display()));
                    }
                } else {
                    if *n_lost > 0 {
                        lost.push(format!("{d} ({} on no branch or remote)", commits(*n_lost)));
                    }
                    if *unpushed_kept > 0 {
                        kept.push(format!(
                            "{d} ({} unpushed on {})",
                            commits(*unpushed_kept),
                            branch.as_deref().unwrap_or("its branch")
                        ));
                    }
                }
            }
        }
    }
    let trees = repos
        .iter()
        .filter(|(r, _)| matches!(r, Repo::WorkTree(_)))
        .count();
    let dirs = repos.len() - trees;
    let checked = [
        (trees, "git worktree", "git worktrees"),
        (dirs, "git directory", "git directories"),
    ]
    .into_iter()
    .filter(|(n, ..)| *n > 0)
    .map(|(n, one, many)| format!("{n} {}", if n == 1 { one } else { many }))
    .collect::<Vec<_>>()
    .join(" and ")
        + " checked";
    let result = |name: &str, block: &[String], what: &str| {
        if !failed.is_empty() {
            GuardResult {
                name: name.into(),
                status: GuardStatus::Block,
                detail: format!("could not check: {}", list(&failed)),
            }
        } else if !block.is_empty() {
            GuardResult {
                name: name.into(),
                status: GuardStatus::Block,
                detail: format!("{what}: {}", list(block)),
            }
        } else {
            GuardResult {
                name: name.into(),
                status: GuardStatus::Pass,
                detail: checked.clone(),
            }
        }
    };
    let mut out = vec![
        result("git-dirty", &dirty, "uncommitted changes in"),
        result("git-unpublished", &lost, "commits would be lost in"),
    ];
    if failed.is_empty() && lost.is_empty() && !kept.is_empty() {
        out[1] = GuardResult {
            name: "git-unpublished".into(),
            status: GuardStatus::Warn,
            detail: format!(
                "unpushed commits stay in the repository's branch: {}",
                list(&kept)
            ),
        };
    }
    let unknown: Vec<String> = unknown_users
        .iter()
        .filter(|w| !gone.is_empty() && !w.starts_with(root))
        .map(|w| w.display().to_string())
        .collect();
    if !unknown.is_empty() {
        out.push(GuardResult {
            name: "git-linked-worktrees".into(),
            status: GuardStatus::Block,
            detail: format!(
                "could not check: work trees changed since the scan, so the git directories they use are not known: {}",
                list(&unknown)
            ),
        });
    } else if !linked_out.is_empty() {
        out.push(GuardResult {
            name: "git-linked-worktrees".into(),
            status: GuardStatus::Block,
            detail: format!(
                "the repository has worktrees outside it that removal would break: {}",
                list(&linked_out)
            ),
        });
    }
    out
}

fn container_mount(volume: &str, ctx: &DetectContext) -> GuardResult {
    let snap = match ctx.docker.get() {
        Ok(s) => s,
        Err(e) => {
            return GuardResult {
                name: "container-mount".into(),
                status: GuardStatus::Block,
                detail: format!("could not check: {e}"),
            };
        }
    };
    let users: Vec<(String, bool)> = snap
        .containers()
        .iter()
        .filter(|c| {
            c.mounts
                .iter()
                .any(|m| m.kind == "volume" && m.name == volume)
        })
        .map(|c| {
            let name = c
                .names
                .first()
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_else(|| c.id.chars().take(12).collect());
            (format!("{name} ({})", c.state), c.state == "running")
        })
        .collect();
    let who = || list(&users.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>());
    if users.iter().any(|(_, running)| *running) {
        GuardResult {
            name: "container-mount".into(),
            status: GuardStatus::Block,
            detail: format!("mounted by {}", who()),
        }
    } else if !users.is_empty() {
        GuardResult {
            name: "container-mount".into(),
            status: GuardStatus::Warn,
            detail: format!("mounted by stopped {}", who()),
        }
    } else {
        GuardResult {
            name: "container-mount".into(),
            status: GuardStatus::Pass,
            detail: "not mounted by any container".into(),
        }
    }
}

fn commits(n: usize) -> String {
    format!("{n} commit{}", if n == 1 { "" } else { "s" })
}
