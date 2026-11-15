//! `git-worktree`: linked git worktrees that are stale or prunable.
//!
//! Repositories are found in the scan tree: a directory whose `.git` is a
//! directory holding `worktrees/` has linked worktrees. For each one, diskwhy
//! runs `git --no-optional-locks -C <repo> worktree list --porcelain` and
//! looks at every linked worktree (never the main one):
//!
//! - **stale**: the worktree is in the scan and nothing in it was written for
//!   [`STALE_DAYS`] days. Action: `git -C <repo> worktree remove <path>`,
//!   never `--force`, so git itself refuses a worktree with changes; the M2
//!   guards (`git-unpublished`, `git-dirty`) decide whether it is safe.
//! - **prunable**: git reports its directory gone. One finding per repo,
//!   whatever its size, with `git -C <repo> worktree prune`, which removes
//!   only the bookkeeping git keeps for missing worktrees.
//! - **locked** (`git worktree lock`): reported as `blocked` with a `locked`
//!   guard, never offered, since someone locked it on purpose.
//!
//! Everything is `review`: a worktree can hold work that exists nowhere else.
//! Bare repositories are not looked at yet.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::detect::{DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, GuardResult, GuardStatus, Recovery, Tier};
use crate::tree::{Markers, NodeId, ScanTree};
use crate::units::human;

use super::read_head;

/// A worktree with nothing written for this many days is stale.
pub const STALE_DAYS: i64 = 14;

/// Stale worktrees smaller than this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// One linked worktree from `git worktree list --porcelain`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WorktreeEntry {
    pub path: PathBuf,
    pub head: Option<String>,
    /// Short branch name, without `refs/heads/`.
    pub branch: Option<String>,
    pub detached: bool,
    pub bare: bool,
    /// `Some(reason)` when locked; the reason may be empty.
    pub locked: Option<String>,
    pub prunable: Option<String>,
}

/// Parses `git worktree list --porcelain` output. The first entry is the
/// main worktree.
pub fn parse_porcelain(out: &str) -> Vec<WorktreeEntry> {
    let mut entries = Vec::new();
    let mut cur: Option<WorktreeEntry> = None;
    for line in out.lines() {
        if line.is_empty() {
            entries.extend(cur.take());
            continue;
        }
        let (key, val) = line.split_once(' ').unwrap_or((line, ""));
        if key == "worktree" {
            entries.extend(cur.take());
            cur = Some(WorktreeEntry {
                path: PathBuf::from(val),
                ..WorktreeEntry::default()
            });
            continue;
        }
        let Some(e) = cur.as_mut() else {
            continue;
        };
        match key {
            "HEAD" => e.head = Some(val.to_string()),
            "branch" => e.branch = Some(val.strip_prefix("refs/heads/").unwrap_or(val).to_string()),
            "detached" => e.detached = true,
            "bare" => e.bare = true,
            "locked" => e.locked = Some(val.to_string()),
            "prunable" => e.prunable = Some(val.to_string()),
            _ => {}
        }
    }
    entries.extend(cur);
    entries
}

pub struct GitWorktree;

impl Detector for GitWorktree {
    fn name(&self) -> &'static str {
        "git-worktree"
    }

    fn detect(&self, tree: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let Some(git) = ctx.tool_command("git") else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut errors = Vec::new();
        for repo in repos_with_worktrees(tree) {
            let repo_dir = tree.path(repo);
            match list(&git, &repo_dir) {
                Ok(entries) => out.extend(self.findings(tree, ctx, &git, &repo_dir, &entries)),
                Err(e) => errors.push(format!("{}: {e}", repo_dir.display())),
            }
        }
        // A repo git cannot read (e.g. owned by another user) is skipped; it
        // is an error only when no repo could be read at all.
        if out.is_empty() && !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(out)
    }
}

/// Directories whose `.git` directory holds a `worktrees/` directory.
fn repos_with_worktrees(tree: &ScanTree) -> Vec<NodeId> {
    tree.ids()
        .filter(|&id| {
            let n = tree.node(id);
            n.is_dir
                && n.markers.contains(Markers::DOT_GIT)
                && tree
                    .child_named(id, ".git")
                    .and_then(|g| tree.child_named(g, "worktrees"))
                    .is_some()
        })
        .collect()
}

fn list(git: &str, repo: &Path) -> Result<Vec<WorktreeEntry>, String> {
    let out = Command::new(git)
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(repo)
        .args(["worktree", "list", "--porcelain"])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {git}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err
            .lines()
            .next()
            .unwrap_or("git failed")
            .trim()
            .to_string());
    }
    Ok(parse_porcelain(&String::from_utf8_lossy(&out.stdout)))
}

fn git_action(git: &str, repo: &Path, args: &[&str]) -> Action {
    let mut argv = vec![
        git.to_string(),
        "-C".into(),
        repo.to_string_lossy().into_owned(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    Action {
        kind: ActionKind::Command,
        text: argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
        argv: Some(argv),
    }
}

fn describe(e: &WorktreeEntry) -> String {
    match (&e.branch, &e.head) {
        (Some(b), _) => format!("on branch {b}"),
        (None, Some(h)) => format!("detached at {}", &h[..h.len().min(12)]),
        _ => "with no checkout".into(),
    }
}

impl GitWorktree {
    fn findings(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
        git: &str,
        repo: &Path,
        entries: &[WorktreeEntry],
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut prunable = Vec::new();
        for e in entries.iter().skip(1).filter(|e| !e.bare) {
            if e.prunable.is_some() && e.locked.is_none() {
                prunable.push(e);
                continue;
            }
            let Some(id) = tree.find(&e.path) else {
                continue;
            };
            let n = tree.node(id);
            let idle = ctx.now - n.newest_mtime;
            let bytes = n.freeable();
            if !n.is_dir || idle < STALE_DAYS * 86_400 || bytes < MIN_BYTES {
                continue;
            }
            let path_s = e.path.to_string_lossy().into_owned();
            let mut reason = format!(
                "git worktree of {} {} ({}",
                repo.display(),
                describe(e),
                human(bytes)
            );
            if n.shared > 0 {
                reason.push_str(&format!(
                    "; {} more is hardlinked elsewhere and is not freed",
                    human(n.shared)
                ));
            }
            reason.push_str(&format!(
                "); nothing written for {}",
                age(ctx.now, n.newest_mtime)
            ));
            let mut guards = Vec::new();
            let tier = match &e.locked {
                Some(why) => {
                    reason.push_str("; locked, so not offered");
                    guards.push(GuardResult {
                        name: "locked".into(),
                        status: GuardStatus::Block,
                        detail: if why.is_empty() {
                            "locked with `git worktree lock`".into()
                        } else {
                            format!("locked with `git worktree lock`: {why}")
                        },
                    });
                    Tier::Blocked
                }
                None => Tier::Review,
            };
            out.push(Finding {
                id: finding_id(self.name(), &path_s),
                detector: self.name().into(),
                probe: None,
                bytes,
                last_modified: Some(rfc3339(n.newest_mtime)),
                growth: None,
                tier,
                reason,
                guards,
                action: git_action(git, repo, &["worktree", "remove", &path_s]),
                recovery: Recovery {
                    cost: "git worktree add recreates the checkout; uncommitted or unpushed work in it is lost, and git refuses the removal while it has changes".into(),
                    how: e
                        .branch
                        .as_ref()
                        .map(|b| format!(
                            "git -C {} worktree add {} {}",
                            shell_quote(&repo.to_string_lossy()),
                            shell_quote(&path_s),
                            shell_quote(b)
                        )),
                },
                path: path_s,
            });
        }
        if !prunable.is_empty() {
            let admin = repo.join(".git/worktrees");
            let path_s = admin.to_string_lossy().into_owned();
            let node = tree.find(&admin).map(|id| tree.node(id));
            let bytes = admin_bytes(tree, &admin, &prunable);
            let names: Vec<String> = prunable
                .iter()
                .map(|e| e.path.display().to_string())
                .collect();
            out.push(Finding {
                id: finding_id(self.name(), &path_s),
                detector: self.name().into(),
                probe: None,
                bytes,
                last_modified: node.map(|n| rfc3339(n.newest_mtime)),
                growth: None,
                tier: Tier::Review,
                reason: format!(
                    "{} worktree{} of {} no longer exist on disk: {}",
                    prunable.len(),
                    if prunable.len() == 1 { "" } else { "s" },
                    repo.display(),
                    names.join(", ")
                ),
                guards: Vec::new(),
                action: git_action(git, repo, &["worktree", "prune"]),
                recovery: Recovery {
                    cost: "only git's records of the missing worktrees go; if one is on a drive that is not mounted, lock it (`git worktree lock`) instead".into(),
                    how: None,
                },
                path: path_s,
            });
        }
        out
    }
}

/// Bytes of the `.git/worktrees/<name>` entries whose `gitdir` file points
/// into one of the missing worktrees: what `git worktree prune` removes.
fn admin_bytes(tree: &ScanTree, admin: &Path, missing: &[&WorktreeEntry]) -> u64 {
    let Some(id) = tree.find(admin) else {
        return 0;
    };
    tree.children(id)
        .iter()
        .filter(|&&c| {
            let gitdir = tree.path(c).join("gitdir");
            read_head(&gitdir, 4096).is_some_and(|b| {
                let target = PathBuf::from(String::from_utf8_lossy(&b).trim());
                missing
                    .iter()
                    .any(|e| target.parent() == Some(e.path.as_path()))
            })
        })
        .map(|&c| tree.node(c).freeable())
        .sum()
}
