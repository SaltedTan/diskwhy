//! Guards: checks that run before removal and end in pass, warn or block,
//! with evidence (docs/DESIGN.md "Guard"). They run at `plan` and `apply`,
//! not during `scan`, because they read every process and run git.
//!
//! For a filesystem finding:
//!
//! - `in-use-cwd`: a process has its working directory inside it.
//! - `in-use-open`: a process has a file inside it open, mapped, or as its
//!   executable.
//! - `git-dirty`: a git worktree inside it (or the finding itself) has
//!   uncommitted changes, untracked files included.
//! - `git-unpublished`: removing it would lose commits. For a repository
//!   whose `.git` directory is inside the finding, that is anything
//!   reachable from a local ref, stash or worktree HEAD that is on no remote
//!   branch. For a linked worktree or submodule (a `.git` file), the
//!   repository lives on, so only commits reachable from HEAD and from no
//!   branch or remote are lost (block); unpushed commits on its branch stay
//!   in the repository (warn).
//! - `git-linked-worktrees`: a repository inside the finding has linked
//!   worktrees outside it, which removing the repository would break.
//!
//! For a Docker volume, `container-mount`: mounted by a running container
//! (block) or a stopped one (warn).
//!
//! Git guards skip repositories inside a cache (below a `CACHEDIR.TAG`)
//! and do not apply to `user-cache` and `tool-versions` findings: those
//! repositories are the tools' own checkouts.
//!
//! Processes are read from `/proc`; other users' processes cannot be read
//! without root, which the pass detail says. A guard that cannot check (git
//! missing or failing, Docker unreachable) blocks. A blocking guard moves
//! the finding to the `blocked` tier.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::detect::DetectContext;
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
    let repos = repositories(tree);
    let git = ctx.tool_command("git");
    let inside = |f: &Finding| -> Vec<&PathBuf> {
        if !f.path.starts_with('/') || !git_guarded(f) {
            return Vec::new();
        }
        let root = Path::new(&f.path);
        repos.iter().filter(|r| r.starts_with(root)).collect()
    };
    // Every repository any finding needs, read once and in parallel.
    let mut needed: Vec<&PathBuf> = findings.iter().flat_map(&inside).collect();
    needed.sort();
    needed.dedup();
    let states: HashMap<&PathBuf, RepoState> = needed
        .par_iter()
        .map(|r| (*r, RepoState::read(git.as_deref(), r)))
        .collect();
    for f in findings.iter_mut() {
        let mut results = Vec::new();
        if f.path.starts_with('/') {
            let root = PathBuf::from(&f.path);
            results.push(in_use_cwd(&root, procs));
            results.push(in_use_open(&root, procs));
            let mine: Vec<(&PathBuf, &RepoState)> =
                inside(f).into_iter().map(|r| (r, &states[r])).collect();
            if !mine.is_empty() {
                results.extend(git_guards(&root, &mine));
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
fn git_guarded(f: &Finding) -> bool {
    !matches!(f.detector.as_str(), "user-cache" | "tool-versions")
}

/// Directories in the tree that hold a `.git` (a directory or a file),
/// except those inside a cache (a directory above them holds
/// `CACHEDIR.TAG`): a tool's checkouts, such as uv's source builds.
fn repositories(tree: &ScanTree) -> Vec<PathBuf> {
    let in_cache = |mut id| {
        while let Some(p) = tree.parent(id) {
            if tree.node(p).markers.contains(Markers::CACHEDIR_TAG) {
                return true;
            }
            id = p;
        }
        false
    };
    let mut out: Vec<PathBuf> = tree
        .ids()
        .filter(|&id| {
            let n = tree.node(id);
            n.is_dir && n.markers.contains(Markers::DOT_GIT) && !in_cache(id)
        })
        .map(|id| tree.path(id))
        .collect();
    out.sort();
    out
}

fn named(procs: &[&Proc]) -> String {
    let mut s = procs
        .iter()
        .take(MAX_NAMED)
        .map(|p| format!("{} (pid {})", p.name, p.pid))
        .collect::<Vec<_>>()
        .join(", ");
    if procs.len() > MAX_NAMED {
        s.push_str(&format!(" and {} more", procs.len() - MAX_NAMED));
    }
    s
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
        /// `.git` is a directory: the repository itself lives here.
        owns_repo: bool,
        dirty: usize,
        /// Commits lost if the directory goes.
        lost: usize,
        /// Unpushed commits on the worktree's branch (they stay in the repo).
        unpushed_kept: usize,
        branch: Option<String>,
        /// Linked worktrees of this repository (their directories).
        linked: Vec<PathBuf>,
    },
}

impl RepoState {
    fn read(git: Option<&str>, dir: &Path) -> RepoState {
        let Some(git) = git else {
            return RepoState::Failed("git is not installed".into());
        };
        match Self::try_read(git, dir) {
            Ok(s) => s,
            Err(e) => RepoState::Failed(e),
        }
    }

    fn try_read(git: &str, dir: &Path) -> Result<RepoState, String> {
        let owns_repo = std::fs::symlink_metadata(dir.join(".git")).is_ok_and(|m| m.is_dir());
        // One call for the changes, the branch and whether HEAD exists.
        let status = crate::gitcmd::run(
            git,
            dir,
            &[
                "status",
                "--porcelain=v2",
                "--branch",
                "-z",
                "--untracked-files=normal",
            ],
        )?;
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
        let count = |args: &[&str]| -> Result<usize, String> {
            let out = crate::gitcmd::run(git, dir, args)?;
            out.trim()
                .parse()
                .map_err(|_| format!("unexpected git output: {}", out.trim()))
        };
        let (lost, unpushed_kept, linked) = if owns_repo {
            // Everything local (branches, tags, stash, every worktree's
            // HEAD) that no remote branch has.
            let lost = count(&["rev-list", "--count", "--all", "--not", "--remotes"])?;
            (lost, 0, linked_worktrees(&dir.join(".git")))
        } else if has_head {
            let lost = count(&[
                "rev-list",
                "--count",
                "HEAD",
                "--not",
                "--branches",
                "--remotes",
            ])?;
            let unpushed = if branch.is_some() {
                count(&["rev-list", "--count", "HEAD", "--not", "--remotes"])?
            } else {
                0
            };
            (lost, unpushed, Vec::new())
        } else {
            (0, 0, Vec::new())
        };
        Ok(RepoState::Read {
            owns_repo,
            dirty,
            lost,
            unpushed_kept,
            branch,
            linked,
        })
    }
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

fn git_guards(root: &Path, repos: &[(&PathBuf, &RepoState)]) -> Vec<GuardResult> {
    let mut failed = Vec::new();
    let mut dirty = Vec::new();
    let mut lost = Vec::new();
    let mut kept = Vec::new();
    let mut linked_out = Vec::new();
    for (dir, state) in repos {
        let d = dir.display();
        match state {
            RepoState::Failed(e) => failed.push(format!("{d}: {e}")),
            RepoState::Read {
                owns_repo,
                dirty: n_dirty,
                lost: n_lost,
                unpushed_kept,
                branch,
                linked,
            } => {
                if *n_dirty > 0 {
                    dirty.push(format!("{d} ({n_dirty} changed or untracked)"));
                }
                if *n_lost > 0 {
                    lost.push(if *owns_repo {
                        format!("{d} ({} on no remote)", commits(*n_lost))
                    } else {
                        format!("{d} ({} on no branch or remote)", commits(*n_lost))
                    });
                }
                if *unpushed_kept > 0 {
                    kept.push(format!(
                        "{d} ({} unpushed on {})",
                        commits(*unpushed_kept),
                        branch.as_deref().unwrap_or("its branch")
                    ));
                }
                for w in linked {
                    if !w.starts_with(root) {
                        linked_out.push(format!("{} (of {d})", w.display()));
                    }
                }
            }
        }
    }
    let n = repos.len();
    let checked = format!("{n} git worktree{} checked", if n == 1 { "" } else { "s" });
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
    if !linked_out.is_empty() {
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
