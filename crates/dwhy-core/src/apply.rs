//! Applying a plan (docs/DESIGN.md "Safety rules"). The plan file is a
//! selection plus the state to compare against, never a source of commands:
//! [`evaluate`] takes the findings detected now, matches them to the plan's
//! items by id, and decides each one.
//!
//! [`execute`] and [`execute_until`] run the ready items and write
//! [`AuditRecord`]s. See the Plans and Apply decisions in `docs/DESIGN.md`
//! for the checks, tier policy and exit codes.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::detect::{
    DetectContext, PATH_NOT_UTF8, add_lossy_guard, escape_controls, lossy_argv, lossy_detail,
};
use crate::guard::{self, Processes};
use crate::mounts::MountTable;
use crate::plan::{
    self, MeasuredRoot, add_changed_guard, changed_removal_root, changed_since_scan,
    measured_roots, nested_roots, removal_path_absent,
};
use crate::report::{
    Action, ActionKind, ApplyItem, ApplyOutcome, ApplyReport, AuditEvent, AuditRecord, Finding,
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
            Tier::Review => Err("a review item needs the user's approval".into()),
            Tier::Blocked => Err("blocked items are never applied".into()),
            t if t <= self.max_tier => Ok(()),
            t => Err(format!(
                "{} is above --max-tier {} (needs the user's approval)",
                tier_name(t),
                tier_name(self.max_tier),
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

/// A guard result's status as `dwhy explain` and the TUI show it.
pub fn guard_status_name(s: GuardStatus) -> &'static str {
    match s {
        GuardStatus::Pass => "pass",
        GuardStatus::Warn => "warn",
        GuardStatus::Block => "BLOCK",
    }
}

/// What kind of action a finding has, as `dwhy explain` and the TUI show it.
pub fn action_kind_name(k: ActionKind) -> &'static str {
    match k {
        ActionKind::Advice => "advice, nothing to run",
        ActionKind::Command => "command",
        ActionKind::RemovePath => "path removal",
    }
}

/// One plan item and what apply decided for it. `fresh` is the finding as
/// detected now; it is what runs.
#[derive(Debug, Clone)]
pub struct Check {
    pub item: ApplyItem,
    pub fresh: Option<Finding>,
    /// The apply scan's root identity, `(st_dev, st_ino)`, for ready filesystem items.
    pub inode: Option<(u64, u64)>,
    /// Whether [`execute_until`] started this item's action: called the
    /// path removal or spawned the command. False for an item it never
    /// reached, one stopped or skipped before dispatch, and one whose audit
    /// `start` line could not be written. Not part of the report.
    pub dispatched: bool,
    /// The root of the apply scan's tree that holds this item's path (the
    /// node at the path, or at its nearest ancestor in the tree); `None`
    /// for a path the tree does not cover, such as a Docker pseudo-path.
    /// A path, not a node id, so checks from two scans of the same roots
    /// compare. [`total_bytes_for_checks`] uses it to count a root mounted
    /// below another root on its own.
    pub tree_root: Option<PathBuf>,
    nested: Vec<MeasuredRoot>,
}

impl Check {
    /// Ready to remove (`would_remove` until it runs).
    pub fn ready(&self) -> bool {
        self.item.outcome == ApplyOutcome::WouldRemove
    }

    fn skip_changed(&mut self, detail: String) -> (ApplyOutcome, String) {
        if let Some(f) = &self.fresh {
            self.item.guards.clone_from(&f.guards);
        } else {
            self.item.guards.clear();
        }
        let message = format!("changed since the scan: {detail}");
        add_changed_guard(&mut self.item.guards, detail);
        (ApplyOutcome::Skipped, message)
    }
}

/// Decides every item of `plan` against `fresh`, the findings detected now
/// in a scan (`tree`) of the plan's roots. Runs the guards on the planned
/// roots. Returns one check per item, in plan order.
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
    // Every filesystem root goes to the guards, so a skipped item still
    // protects Git metadata it depends on. Other items (Docker's) are
    // guarded only when ready: their guards protect nothing else.
    let batch: Vec<usize> = (0..checks.len())
        .filter(|&i| checks[i].ready() || Path::new(&checks[i].item.path).is_absolute())
        .collect();
    let mut guarded: Vec<Finding> = batch
        .iter()
        .map(|&i| {
            checks[i]
                .fresh
                .as_ref()
                .unwrap_or(&plan.items[i].finding)
                .clone()
        })
        .collect();
    guard::check(&mut guarded, tree, ctx, procs);
    let roots = measured_roots(
        tree,
        checks.iter().map(|c| {
            (
                c.item.path.as_str(),
                c.fresh.as_ref().and_then(|f| f.file_identity),
            )
        }),
    );
    for (i, f) in batch.into_iter().zip(guarded) {
        let c = &mut checks[i];
        if !c.ready() {
            continue;
        }
        let nested = nested_roots(&roots, &f.path);
        if let Some(detail) = changed_removal_root(&f.path, c.inode.into(), nested, |_| false) {
            (c.item.outcome, c.item.detail) = c.skip_changed(detail);
            continue;
        }
        if f.tier == Tier::Blocked {
            c.item.outcome = ApplyOutcome::Skipped;
            c.item.detail = format!("blocked by {}", blocks(&f));
        } else {
            c.nested = nested.to_vec();
        }
        c.item.guards = f.guards;
    }
    for c in &mut checks {
        c.tree_root = tree_root(tree, Path::new(&c.item.path));
    }
    checks
}

/// The path of the root of `tree` that holds `path`: the root above the
/// node at `path`, or at its nearest ancestor in the tree. `None` when the
/// tree does not cover `path` or it is not absolute.
fn tree_root(tree: &ScanTree, path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut id = path.ancestors().find_map(|a| tree.find(a))?;
    while let Some(parent) = tree.parent(id) {
        id = parent;
    }
    Some(tree.path(id))
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
        inode: None,
        dispatched: false,
        tree_root: None,
        nested: Vec::new(),
    };
    // Backstop for `detect::block_lossy`: never act on a path or command
    // spelled with U+FFFD, whether the plan file or the fresh finding has it.
    if let Some(detail) = lossy(&planned.path, &planned.action)
        .or_else(|| fresh.and_then(|f| lossy(&f.path, &f.action)))
    {
        let mut c = base(
            fresh.unwrap_or(planned),
            ApplyOutcome::Skipped,
            format!("blocked by {PATH_NOT_UTF8}: {detail}"),
        );
        if let Some(f) = fresh {
            c.item.guards.clone_from(&f.guards);
        }
        add_lossy_guard(&mut c.item.guards, detail);
        return c;
    }
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
    if f.path != planned.path || f.detector != planned.detector {
        // The planned fields come from the plan file: escaped, since this
        // detail is shown on terminals.
        return skip(format!(
            "changed: planned {} {} does not match the live finding",
            escape_controls(&planned.detector),
            escape_controls(&planned.path)
        ));
    }
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
    if let Some(detail) = changed_since_scan(f, tree) {
        let mut c = base(f, ApplyOutcome::Skipped, String::new());
        (c.item.outcome, c.item.detail) = c.skip_changed(detail);
        return c;
    }
    let now = plan::fingerprint(f, tree, ctx);
    let diff = plan::differences(&item.fingerprint, &now);
    if !diff.is_empty() {
        return skip(format!("changed since the plan: {}", diff.join(", ")));
    }
    Check {
        inode: now.dev.zip(now.inode),
        ..base(f, ApplyOutcome::WouldRemove, "ready".into())
    }
}

fn lossy(path: &str, action: &Action) -> Option<String> {
    lossy_detail(path, lossy_argv(action), false)
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

/// Why there is no audit log when [`Audit::default_path`] finds no place.
pub const AUDIT_UNPLACED: &str =
    "cannot place the audit log: neither XDG_STATE_HOME nor HOME is an absolute path";

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

    /// [`Audit::open`] on `path`, the log's place as
    /// [`Audit::default_path`] found it; `None` fails with [`AUDIT_UNPLACED`].
    pub fn open_placed(path: Option<&Path>) -> Result<Audit, String> {
        Audit::open(path.ok_or(AUDIT_UNPLACED)?)
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

/// Runs the ready checks, deepest path first, and attempts to audit every item.
/// Calls `progress` before attempting each ready item. Returns audit write errors.
pub fn execute(
    plan: &Plan,
    checks: &mut [Check],
    audit: &mut Audit,
    mounts: &MountTable,
    env: &Env,
    progress: &mut dyn FnMut(&ApplyItem),
) -> Vec<String> {
    execute_until(
        plan,
        checks,
        audit,
        mounts,
        env,
        progress,
        ExecuteOptions {
            stop: &|| false,
            isolate_commands: false,
        },
    )
}

/// The detail of a ready item that [`execute_until`] did not start.
pub const NOT_RUN_STOPPED: &str = "not run: apply was stopped before this item";

pub struct ExecuteOptions<'a> {
    /// A stop request, checked between items and again just before dispatch.
    pub stop: &'a dyn Fn() -> bool,
    /// Use a separate process group for each cleanup command so a signal to
    /// the TUI's foreground group leaves the command running.
    pub isolate_commands: bool,
}

/// Like [`execute`], with cancellation between dispatches. A stop request
/// leaves a running action to finish. Ready items skipped because of the
/// request get [`NOT_RUN_STOPPED`] as their detail and an attempted `end`
/// record. Returns audit write errors.
pub fn execute_until(
    plan: &Plan,
    checks: &mut [Check],
    audit: &mut Audit,
    mounts: &MountTable,
    env: &Env,
    progress: &mut dyn FnMut(&ApplyItem),
    options: ExecuteOptions<'_>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut write_record = |item: &ApplyItem, event, outcome| {
        audit
            .record(&record(env, plan, item, event, outcome))
            .inspect_err(|e| {
                errors.push(format!("{}: {e}", item.path));
            })
    };
    for c in checks.iter().filter(|c| !c.ready()) {
        let _ = write_record(&c.item, AuditEvent::End, Some(c.item.outcome));
    }
    let mut order: Vec<usize> = (0..checks.len()).filter(|&i| checks[i].ready()).collect();
    // Deepest first, so a tool-native command inside runs before a path
    // removal around it; pseudo-paths (docker://) last.
    order.sort_by_key(|&i| {
        let p = Path::new(&checks[i].item.path);
        (!p.is_absolute(), std::cmp::Reverse(p.components().count()))
    });
    let mut removed_paths = HashSet::new();
    for i in order {
        let c = &mut checks[i];
        if (options.stop)() {
            c.item.outcome = ApplyOutcome::Skipped;
            c.item.detail = NOT_RUN_STOPPED.into();
        } else {
            progress(&c.item);
            if let Err(e) = write_record(&c.item, AuditEvent::Start, None) {
                c.item.outcome = ApplyOutcome::Failed;
                c.item.detail = format!("not run: {e}");
                continue;
            }
            let (outcome, detail) = run(c, mounts, &removed_paths, &options);
            let path = Path::new(&c.item.path);
            if outcome == ApplyOutcome::Removed
                && path.is_absolute()
                && (c.item.action.kind == ActionKind::RemovePath || removal_path_absent(path))
            {
                removed_paths.insert(path.to_path_buf());
                // The checked descendants went with it. One that is back
                // (`removal_path_absent` fails) is not recorded, and one
                // that reappears later still blocks an enclosing item.
                removed_paths.extend(
                    c.nested
                        .iter()
                        .map(|root| &root.path)
                        .filter(|p| removal_path_absent(p))
                        .cloned(),
                );
            }
            c.item.outcome = outcome;
            c.item.detail = detail;
        }
        if let Err(e) = write_record(&c.item, AuditEvent::End, Some(c.item.outcome)) {
            c.item.detail.push_str(&format!(" (and {e})"));
        }
    }
    errors
}

fn run(
    c: &mut Check,
    mounts: &MountTable,
    removed_paths: &HashSet<PathBuf>,
    options: &ExecuteOptions<'_>,
) -> (ApplyOutcome, String) {
    let item = &mut c.item;
    if let Some(detail) = lossy(&item.path, &item.action) {
        let outcome = format!("blocked by {PATH_NOT_UTF8}: {detail}; not run");
        add_lossy_guard(&mut item.guards, detail);
        return (ApplyOutcome::Skipped, outcome);
    }
    if let Some(detail) = changed_removal_root(&item.path, c.inode.into(), &c.nested, |path| {
        removed_paths.contains(path)
    }) {
        return c.skip_changed(detail);
    }
    if (options.stop)() {
        return (ApplyOutcome::Skipped, NOT_RUN_STOPPED.into());
    }
    match item.action.kind {
        ActionKind::RemovePath => {
            c.dispatched = true;
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
            let mut command = Command::new(prog);
            command.args(args).current_dir("/").stdin(Stdio::null());
            if options.isolate_commands {
                command.process_group(0);
            }
            c.dispatched = true;
            match command.output() {
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

/// What `dwhy apply` and the TUI show for an item's outcome.
pub fn outcome_label(o: ApplyOutcome) -> &'static str {
    match o {
        ApplyOutcome::Removed => "removed",
        ApplyOutcome::Failed => "FAILED",
        ApplyOutcome::Skipped => "skipped",
        ApplyOutcome::Refused => "refused",
        ApplyOutcome::WouldRemove => "would remove",
    }
}

/// What an exit status of `dwhy apply` ([`exit_code`]) means.
pub fn exit_meaning(code: u8) -> &'static str {
    match code {
        0 => "ok",
        1 => "failed",
        2 => "something was skipped",
        3 => "refused",
        _ => "",
    }
}

/// The one-line summary `dwhy apply` and the TUI show under a report:
/// what was (or would be) removed and freed, then the counts of failed,
/// refused and skipped items. A dry run's bytes are the report's
/// `would_free`; for a report without one (an older file), items nest by
/// path ([`total_bytes`]).
pub fn summary(r: &ApplyReport) -> String {
    summary_with_would_free(r, None)
}

/// [`summary`], with `would_free` as a dry run's bytes when known: the
/// [`total_bytes_for_checks`] of its `would_remove` checks, which counts a
/// root mounted below another root on its own as `plan.bytes` does.
pub fn summary_with_would_free(r: &ApplyReport, would_free: Option<u64>) -> String {
    let count = |o| r.items.iter().filter(|i| i.outcome == o).count();
    let rest: Vec<String> = [
        (ApplyOutcome::Failed, "failed"),
        (ApplyOutcome::Refused, "refused"),
        (ApplyOutcome::Skipped, "skipped"),
    ]
    .into_iter()
    .filter_map(|(o, word)| {
        let n = count(o);
        (n > 0).then(|| format!("{n} {word}"))
    })
    .collect();
    let rest = if rest.is_empty() {
        String::new()
    } else {
        format!("; {}", rest.join(", "))
    };
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    if r.dry_run {
        let n = count(ApplyOutcome::WouldRemove);
        let bytes = would_free.or(r.would_free).unwrap_or_else(|| {
            total_bytes(
                r.items
                    .iter()
                    .filter(|i| i.outcome == ApplyOutcome::WouldRemove),
            )
        });
        format!(
            "would remove {n} item{} ({}){rest}; nothing removed",
            plural(n),
            crate::units::human(bytes)
        )
    } else {
        let n = count(ApplyOutcome::Removed);
        format!(
            "removed {n} item{}, freed about {}{rest}",
            plural(n),
            crate::units::human(r.freed)
        )
    }
}

/// The bytes `items` hold together, counting an item inside another item
/// once (see [`crate::plan::distinct_bytes`]).
pub fn total_bytes<'a>(items: impl IntoIterator<Item = &'a ApplyItem>) -> u64 {
    crate::plan::distinct_bytes(items.into_iter().map(|i| (i.path.as_str(), i.bytes)))
}

/// The bytes the items of `checks` hold together, counting an item inside
/// another item once. An item is inside another only within the same root
/// of the apply scan ([`Check::tree_root`]): a root mounted below another
/// root counts on its own, as in [`crate::plan::distinct_bytes_in_tree`].
/// Items without a tree root nest by path, and pseudo-paths never nest.
pub fn total_bytes_for_checks<'a>(checks: impl IntoIterator<Item = &'a Check>) -> u64 {
    let items: Vec<(&Path, u64, Option<&Path>)> = checks
        .into_iter()
        .map(|c| {
            (
                Path::new(&c.item.path),
                c.item.bytes,
                c.tree_root.as_deref(),
            )
        })
        .collect();
    let same_root = |a: Option<&Path>, b: Option<&Path>| match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    items
        .iter()
        .filter(|(p, _, root)| {
            !p.is_absolute()
                || !items.iter().any(|(o, _, o_root)| {
                    o.is_absolute() && o != p && p.starts_with(o) && same_root(*root, *o_root)
                })
        })
        .map(|(_, b, _)| b)
        .sum()
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
    let freed = total_bytes_for_checks(
        checks
            .iter()
            .filter(|c| c.item.outcome == ApplyOutcome::Removed),
    );
    let would_free = dry_run.then(|| total_bytes_for_checks(checks.iter().filter(|c| c.ready())));
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
        would_free,
        audit_log: None,
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
