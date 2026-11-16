//! Applying a plan (docs/DESIGN.md "Safety rules"). The plan file is a
//! selection plus the state to compare against, never a source of commands:
//! [`evaluate`] takes the findings detected now, matches them to the plan's
//! items by id, and decides each one.
//!
//! An item is
//! - skipped (exit 2) when it is no longer detected, a detector or guard
//!   blocks it now, its tier or action differs from the plan's, or its
//!   fingerprint changed;
//! - refused (exit 3) when its tier is above `--max-tier`, or it is a
//!   `review` item whose id `--confirm` did not name (`--confirm` alone lets
//!   a review item through; it never lifts a rebuildable one);
//! - otherwise ready.
//!
//! [`execute`] runs the ready items, deepest path first, each with its
//! tool-native command (argv, no shell) or [`crate::remove::remove_tree`],
//! and writes the audit log: a `start` line before each removal (a removal
//! whose `start` line cannot be written does not run), an `end` line after,
//! and an `end` line for each skipped or refused item.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::detect::DetectContext;
use crate::guard::{self, Processes};
use crate::mounts::MountTable;
use crate::report::{
    ActionKind, ApplyItem, ApplyOutcome, ApplyReport, AuditEvent, AuditRecord, Finding,
    GuardStatus, Plan, PlanItem, SCHEMA, Tier, Tool,
};
use crate::tree::ScanTree;

/// What `dwhy apply` may remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// `--max-tier` (default `regenerable`).
    pub max_tier: Tier,
    /// `--confirm`: ids of review items a person confirmed.
    pub confirm: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_tier: Tier::Regenerable,
            confirm: Vec::new(),
        }
    }
}

impl Policy {
    /// `Err` with the reason when `f` is not allowed.
    pub fn allows(&self, f: &Finding) -> Result<(), String> {
        match f.tier {
            Tier::Review if self.confirm.contains(&f.id) => Ok(()),
            Tier::Review => Err(format!("review items need a person's --confirm {}", f.id)),
            Tier::Blocked => Err("blocked items are never applied".into()),
            t if t <= self.max_tier => Ok(()),
            t => Err(format!(
                "{} is above --max-tier {} (--max-tier {} allows it)",
                tier_name(t),
                tier_name(self.max_tier),
                tier_name(t)
            )),
        }
    }
}

pub fn tier_name(t: Tier) -> &'static str {
    match t {
        Tier::Regenerable => "regenerable",
        Tier::Rebuildable => "rebuildable",
        Tier::Review => "review",
        Tier::Blocked => "blocked",
    }
}

/// One plan item and what apply decided for it. `fresh` is the finding as
/// detected now; it is what runs.
#[derive(Debug, Clone)]
pub struct Check {
    pub item: ApplyItem,
    pub fresh: Option<Finding>,
    /// The plan's fingerprint of the root, `(st_dev, st_ino)`, checked again
    /// right before a path removal.
    pub inode: Option<(u64, u64)>,
}

impl Check {
    /// Ready to remove (`would_remove` until it runs).
    pub fn ready(&self) -> bool {
        self.item.outcome == ApplyOutcome::WouldRemove
    }
}

/// Decides every item of `plan` against `fresh`, the findings detected now
/// in a scan (`tree`) of the plan's roots. Runs the guards on the items the
/// policy allows. Returns one check per item, in plan order.
pub fn evaluate(
    plan: &Plan,
    fresh: Vec<Finding>,
    tree: &ScanTree,
    ctx: &DetectContext,
    procs: &Processes,
    policy: &Policy,
) -> Vec<Check> {
    let mut checks: Vec<Check> = plan
        .items
        .iter()
        .map(|item| {
            decide(
                item,
                fresh.iter().find(|f| f.id == item.finding.id),
                tree,
                ctx,
                policy,
            )
        })
        .collect();
    // The guards, once, on everything still ready.
    let ready: Vec<usize> = (0..checks.len()).filter(|&i| checks[i].ready()).collect();
    let mut guarded: Vec<Finding> = ready
        .iter()
        .filter_map(|&i| checks[i].fresh.clone())
        .collect();
    guard::check(&mut guarded, tree, ctx, procs);
    for (i, f) in ready.into_iter().zip(guarded) {
        let c = &mut checks[i];
        c.item.guards = f.guards.clone();
        if f.tier == Tier::Blocked {
            c.item.outcome = ApplyOutcome::Skipped;
            c.item.detail = format!("blocked by {}", blocks(&f));
        }
        c.fresh = Some(f);
    }
    checks
}

fn decide(
    item: &PlanItem,
    fresh: Option<&Finding>,
    tree: &ScanTree,
    ctx: &DetectContext,
    policy: &Policy,
) -> Check {
    let planned = &item.finding;
    let base = |f: &Finding, outcome, detail: String| Check {
        item: ApplyItem {
            id: planned.id.clone(),
            detector: f.detector.clone(),
            path: f.path.clone(),
            tier: f.tier,
            bytes: f.bytes,
            action: f.action.clone(),
            outcome,
            detail,
            guards: Vec::new(),
        },
        fresh: fresh.cloned(),
        inode: item.fingerprint.dev.zip(item.fingerprint.inode),
    };
    let Some(f) = fresh else {
        return base(
            planned,
            ApplyOutcome::Skipped,
            "gone: the detectors no longer report it".into(),
        );
    };
    let skip = |detail: String| {
        let mut c = base(f, ApplyOutcome::Skipped, detail);
        c.item.guards = f.guards.clone();
        c
    };
    if f.tier == Tier::Blocked {
        return skip(format!("blocked by {}", blocks(f)));
    }
    if f.tier != planned.tier {
        return skip(format!(
            "changed: it is {} now, {} in the plan",
            tier_name(f.tier),
            tier_name(planned.tier)
        ));
    }
    if f.action != planned.action {
        return skip(format!(
            "changed: the action is `{}` now, `{}` in the plan",
            f.action.text, planned.action.text
        ));
    }
    if f.action.kind == ActionKind::Advice {
        return skip("advice only: nothing to run".into());
    }
    if let Err(why) = policy.allows(f) {
        return base(f, ApplyOutcome::Refused, why);
    }
    let now = crate::plan::fingerprint(f, tree, ctx);
    let diff = crate::plan::differences(&item.fingerprint, &now);
    if !diff.is_empty() {
        return skip(format!("changed since the plan: {}", diff.join(", ")));
    }
    base(f, ApplyOutcome::WouldRemove, "ready".into())
}

/// The blocking guards of `f`, as "name: detail; …".
fn blocks(f: &Finding) -> String {
    let b: Vec<String> = f
        .guards
        .iter()
        .filter(|g| g.status == GuardStatus::Block)
        .map(|g| format!("{}: {}", g.name, g.detail))
        .collect();
    if b.is_empty() {
        "the detector".into()
    } else {
        b.join("; ")
    }
}

/// Appends [`AuditRecord`]s to the audit log, one JSON object per line.
pub struct Audit {
    path: PathBuf,
    file: std::fs::File,
}

impl Audit {
    /// `$XDG_STATE_HOME/diskwhy/audit.jsonl`, else
    /// `$HOME/.local/state/diskwhy/audit.jsonl`.
    pub fn default_path() -> Option<PathBuf> {
        Some(crate::system::state_dir()?.join("audit.jsonl"))
    }

    /// Opens `path` for appending, creating it (mode 0600) and its
    /// directory (0700) when missing.
    pub fn open(path: &Path) -> Result<Audit, String> {
        if let Some(dir) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|e| format!("cannot open the audit log {}: {e}", path.display()))?;
        Ok(Audit {
            path: path.to_path_buf(),
            file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one record as a single write.
    pub fn record(&mut self, rec: &AuditRecord) -> Result<(), String> {
        let mut line = serde_json::to_vec(rec).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .and_then(|_| self.file.sync_data())
            .map_err(|e| format!("cannot write the audit log {}: {e}", self.path.display()))
    }
}

/// Who and when, for audit records.
#[derive(Debug, Clone)]
pub struct Env {
    pub host: String,
    pub uid: u32,
    /// Current time as RFC 3339; called for each record.
    pub now: fn() -> String,
}

impl Env {
    pub fn from_system() -> Env {
        Env {
            host: crate::system::hostname(),
            uid: crate::system::euid(),
            now: crate::system::now_rfc3339,
        }
    }
}

fn record(
    env: &Env,
    plan: &Plan,
    item: &ApplyItem,
    event: AuditEvent,
    outcome: Option<ApplyOutcome>,
) -> AuditRecord {
    AuditRecord {
        schema: SCHEMA.into(),
        time: (env.now)(),
        host: env.host.clone(),
        uid: env.uid,
        pid: std::process::id(),
        event,
        plan_created_at: plan.created_at.clone(),
        id: item.id.clone(),
        detector: item.detector.clone(),
        path: item.path.clone(),
        tier: item.tier,
        bytes: item.bytes,
        action: item.action.clone(),
        outcome,
        detail: outcome.map(|_| item.detail.clone()),
    }
}

/// Runs the ready checks, deepest path first, and audits every item.
/// `progress` is called with each item before it runs.
pub fn execute(
    plan: &Plan,
    checks: &mut [Check],
    audit: &mut Audit,
    mounts: &MountTable,
    env: &Env,
    progress: &mut dyn FnMut(&ApplyItem),
) {
    for c in checks.iter().filter(|c| !c.ready()) {
        // A failure to record a skip removes nothing; the report has it.
        let _ = audit.record(&record(
            env,
            plan,
            &c.item,
            AuditEvent::End,
            Some(c.item.outcome),
        ));
    }
    let mut order: Vec<usize> = (0..checks.len()).filter(|&i| checks[i].ready()).collect();
    // Deepest first, so a tool-native command inside runs before a path
    // removal around it; pseudo-paths (docker://) last.
    order.sort_by_key(|&i| {
        let p = Path::new(&checks[i].item.path);
        (!p.is_absolute(), std::cmp::Reverse(p.components().count()))
    });
    for i in order {
        let c = &mut checks[i];
        progress(&c.item);
        if let Err(e) = audit.record(&record(env, plan, &c.item, AuditEvent::Start, None)) {
            c.item.outcome = ApplyOutcome::Failed;
            c.item.detail = format!("not run: {e}");
            continue;
        }
        let (outcome, detail) = run(c, mounts);
        c.item.outcome = outcome;
        c.item.detail = detail;
        if let Err(e) = audit.record(&record(env, plan, &c.item, AuditEvent::End, Some(outcome))) {
            c.item.detail.push_str(&format!(" (and {e})"));
        }
    }
}

fn run(c: &Check, mounts: &MountTable) -> (ApplyOutcome, String) {
    let item = &c.item;
    if item.path.starts_with('/') && std::fs::symlink_metadata(&item.path).is_err() {
        return (
            ApplyOutcome::Skipped,
            "gone: removed since it was checked (by an item around it?)".into(),
        );
    }
    match item.action.kind {
        ActionKind::RemovePath => {
            match crate::remove::remove_tree(Path::new(&item.path), c.inode, mounts) {
                Ok(r) => (
                    ApplyOutcome::Removed,
                    format!(
                        "removed {} files and {} directories, {}",
                        r.files,
                        r.dirs,
                        crate::units::human(r.bytes)
                    ),
                ),
                Err(e) => (ApplyOutcome::Failed, e),
            }
        }
        ActionKind::Command => {
            let Some((prog, args)) = item.action.argv.as_deref().and_then(|a| a.split_first())
            else {
                return (ApplyOutcome::Failed, "the command has no argv".into());
            };
            match Command::new(prog)
                .args(args)
                .current_dir("/")
                .stdin(Stdio::null())
                .output()
            {
                Ok(out) if out.status.success() => {
                    (ApplyOutcome::Removed, format!("ran {}", item.action.text))
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    let last = err
                        .lines()
                        .rev()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("");
                    (
                        ApplyOutcome::Failed,
                        format!(
                            "{} failed ({}): {}",
                            item.action.text,
                            out.status,
                            last.trim()
                        ),
                    )
                }
                Err(e) => (ApplyOutcome::Failed, format!("cannot run {prog}: {e}")),
            }
        }
        ActionKind::Advice => (ApplyOutcome::Skipped, "advice only: nothing to run".into()),
    }
}

/// The bytes `items` hold together, counting an item inside another item
/// once (see [`crate::plan::distinct_bytes`]).
pub fn total_bytes<'a>(items: impl IntoIterator<Item = &'a ApplyItem>) -> u64 {
    crate::plan::distinct_bytes(items.into_iter().map(|i| (i.path.as_str(), i.bytes)))
}

/// The report for `checks`.
pub fn report(
    plan: &Plan,
    checks: &[Check],
    policy: &Policy,
    dry_run: bool,
    env: &Env,
) -> ApplyReport {
    let items: Vec<ApplyItem> = checks.iter().map(|c| c.item.clone()).collect();
    let freed = total_bytes(items.iter().filter(|i| i.outcome == ApplyOutcome::Removed));
    ApplyReport {
        schema: SCHEMA.into(),
        tool: Tool::current(),
        host: env.host.clone(),
        uid: env.uid,
        generated_at: (env.now)(),
        plan_created_at: plan.created_at.clone(),
        dry_run,
        max_tier: policy.max_tier,
        confirm: policy.confirm.clone(),
        items,
        freed,
    }
}

/// The exit code for a report: 1 when something failed, else 3 when
/// something was refused, else 2 when something was skipped, else 0.
pub fn exit_code(r: &ApplyReport) -> u8 {
    let has = |o| r.items.iter().any(|i| i.outcome == o);
    if has(ApplyOutcome::Failed) {
        1
    } else if has(ApplyOutcome::Refused) {
        3
    } else if has(ApplyOutcome::Skipped) {
        2
    } else {
        0
    }
}
