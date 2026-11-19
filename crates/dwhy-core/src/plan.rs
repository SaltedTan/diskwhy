//! Plans (docs/DESIGN.md "Plans"): the findings selected for removal, each
//! with a fingerprint, and an expiry an hour after the plan is made.
//!
//! A plan selects by tier ceiling (`--tier`, `regenerable` when nothing is
//! named) and by finding id or path (`--select`); with both, a finding must
//! match both. The guards run on the selected findings only, and a finding
//! they block, or one a detector already marked `blocked` that `--select`
//! names, goes to the plan's `blocked` list instead of its items.
//!
//! The fingerprint records what must not change before `apply`: the root's
//! device and inode, the newest mtime under it, its size in quarter-doubling
//! buckets, HEAD and a hash of `git status` when the root is a git work
//! tree, and the object id of a Docker finding. The device, inode, mtime and
//! size come from the walk or one detector stat of a file. A missing root,
//! a symlink, or a live identity mismatch blocks the finding with a
//! `changed-since-scan` guard.
//!
//! `apply` does not trust a plan's actions or tiers: it re-detects and acts
//! on the fresh finding with the same id. A plan is a selection plus the
//! state to compare against, so editing one can make it stale but cannot
//! widen what apply may do.

use std::path::{Component, Path, PathBuf};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use crate::detect::{DetectContext, is_lossy, rfc3339};
use crate::guard::{self, Processes};
use crate::report::{
    ActionKind, FileIdentity, Finding, Fingerprint, GitFingerprint, GuardResult, GuardStatus, Plan,
    PlanItem, PlanScan, PlanSelection, SCHEMA, Tier, Tool, check_schema,
};
use crate::tree::{Markers, ScanTree, TreeNode};

/// The guard that blocks a finding whose live root differs from the measured root.
const CHANGED_SINCE_SCAN: &str = "changed-since-scan";

/// A plan expires this long after it is made.
pub const TTL_SECS: i64 = 3600;

/// The tier ceiling when neither `--tier` nor `--select` is given: the same
/// as `apply`'s default `--max-tier`.
pub const DEFAULT_TIER: Tier = Tier::Regenerable;

/// What `dwhy plan` was asked to select.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// `--tier`: the highest tier to select.
    pub tier: Option<Tier>,
    /// `--select`: finding ids or paths.
    pub select: Vec<String>,
}

impl Selection {
    /// The tier ceiling in force: `--tier`, else [`DEFAULT_TIER`] unless
    /// `--select` named the findings.
    pub fn ceiling(&self) -> Option<Tier> {
        self.tier
            .or_else(|| self.select.is_empty().then_some(DEFAULT_TIER))
    }

    fn named(&self, f: &Finding) -> bool {
        self.select.is_empty() || self.select.iter().any(|s| matches(f, s))
    }
}

/// Whether `entry` (a `--select` value) names `f`: its id, its path as
/// written, or a relative path that resolves to it (resolved the way scan
/// roots are: parent canonicalized, a final symlink not followed).
fn matches(f: &Finding, entry: &str) -> bool {
    if f.id == entry || f.path == entry {
        return true;
    }
    f.path.starts_with('/')
        && crate::scan::absolute_nofollow(Path::new(entry)).is_ok_and(|p| p == Path::new(&f.path))
}

/// Whether a finding that `--select` named ended up in the plan's `blocked`
/// list. A finding only the tier ceiling picked does not count.
pub fn selected_blocked(plan: &Plan) -> bool {
    !plan.selection.select.is_empty() && !plan.blocked.is_empty()
}

/// Splits `findings` into the selected ones that may go into a plan and the
/// selected ones a detector already blocked. A detector-blocked finding is
/// listed only when `--select` names it: its tier before the block is not
/// known, so a tier ceiling cannot pick it. Advice-only findings have
/// nothing to apply and are never selected. Errors when a `--select` entry
/// names no finding, or only an advice-only one.
pub fn select(
    findings: Vec<Finding>,
    sel: &Selection,
) -> Result<(Vec<Finding>, Vec<Finding>), String> {
    if let Some(bad) = sel
        .select
        .iter()
        .find(|s| !findings.iter().any(|f| matches(f, s)))
    {
        return Err(format!(
            "--select {bad}: no finding has that id or path (`dwhy scan` lists them)"
        ));
    }
    if let Some(f) = findings
        .iter()
        .find(|f| f.action.kind == ActionKind::Advice && sel.select.iter().any(|s| matches(f, s)))
    {
        return Err(format!(
            "--select {}: {} has no removal action, only advice: {}",
            f.id, f.path, f.action.text
        ));
    }
    let ceiling = sel.ceiling();
    let mut picked = Vec::new();
    let mut blocked = Vec::new();
    for f in findings
        .into_iter()
        .filter(|f| sel.named(f) && f.action.kind != ActionKind::Advice)
    {
        if f.tier == Tier::Blocked {
            if !sel.select.is_empty() {
                blocked.push(f);
            }
        } else if ceiling.is_none_or(|c| f.tier <= c) {
            picked.push(f);
        }
    }
    Ok((picked, blocked))
}

/// Builds a plan from the findings of a scan: selects, runs the guards on
/// the selection, fingerprints eligible findings from their measurements,
/// and blocks selected roots that fail the live identity check (`changed-since-scan`).
/// `tree` is the scan the findings came from; `ctx.now` is the
/// creation time.
pub fn build(
    findings: Vec<Finding>,
    sel: &Selection,
    tree: &ScanTree,
    ctx: &DetectContext,
    procs: &Processes,
    host: String,
    scan: PlanScan,
) -> Result<Plan, String> {
    let (mut picked, already_blocked) = select(findings, sel)?;
    guard::check(&mut picked, tree, ctx, procs);
    let roots = measured_roots(
        tree,
        picked.iter().map(|f| (f.path.as_str(), f.file_identity)),
    );
    let mut items = Vec::new();
    let mut blocked = Vec::new();
    for mut f in already_blocked.into_iter().chain(picked) {
        let fingerprint = (f.tier != Tier::Blocked).then(|| fingerprint(&f, tree, ctx));
        let changed = changed_removal_root(
            &f.path,
            measured_inode(&f.path, f.file_identity, tree),
            nested_roots(&roots, &f.path),
            |_| false,
        );
        f.file_identity = None;
        if let Some(detail) = changed {
            add_changed_guard(&mut f.guards, detail);
            f.tier = Tier::Blocked;
        } else if let Some(fingerprint) = fingerprint {
            items.push(PlanItem {
                finding: f,
                fingerprint,
            });
            continue;
        }
        blocked.push(f);
    }
    let largest = |a: &Finding, b: &Finding| b.bytes.cmp(&a.bytes).then_with(|| a.id.cmp(&b.id));
    items.sort_by(|a, b| largest(&a.finding, &b.finding));
    blocked.sort_by(largest);
    let bytes = items_bytes(&items);
    Ok(Plan {
        schema: SCHEMA.into(),
        tool: Tool::current(),
        host,
        uid: ctx.uid,
        created_at: rfc3339(ctx.now),
        expires_at: rfc3339(ctx.now + TTL_SECS),
        scan,
        selection: PlanSelection {
            tier: sel.ceiling(),
            select: sel.select.clone(),
        },
        items,
        blocked,
        bytes,
    })
}

/// The bytes of the items, leaving out any item inside another item.
fn items_bytes(items: &[PlanItem]) -> u64 {
    distinct_bytes(
        items
            .iter()
            .map(|i| (i.finding.path.as_str(), i.finding.bytes)),
    )
}

/// The sum of `(path, bytes)` pairs, leaving out any pair whose absolute
/// path lies inside another pair's: an outer finding's bytes already hold
/// those of findings nested in it. Pseudo-paths (`docker://…`) never nest.
pub fn distinct_bytes<'a>(items: impl IntoIterator<Item = (&'a str, u64)>) -> u64 {
    let items: Vec<(&Path, u64)> = items.into_iter().map(|(p, b)| (Path::new(p), b)).collect();
    items
        .iter()
        .filter(|(p, _)| {
            !p.is_absolute()
                || !items
                    .iter()
                    .any(|(o, _)| o.is_absolute() && o != p && p.starts_with(o))
        })
        .map(|(_, b)| b)
        .sum()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MeasuredRoot {
    path: PathBuf,
    inode: Option<(u64, u64)>,
}

pub(crate) fn measured_roots<'a>(
    tree: &ScanTree,
    planned: impl Iterator<Item = (&'a str, Option<FileIdentity>)>,
) -> Vec<MeasuredRoot> {
    let mut roots: Vec<_> = planned
        .filter(|(path, _)| path.starts_with('/'))
        .map(|(path, file)| MeasuredRoot {
            path: PathBuf::from(path),
            inode: measured_inode(path, file, tree),
        })
        .collect();
    roots.extend(tree.ids().filter_map(|id| {
        let node = tree.node(id);
        (node.is_dir && node.markers.contains(Markers::DOT_GIT)).then(|| MeasuredRoot {
            path: tree.path(id),
            inode: Some((node.dev, node.ino)),
        })
    }));
    roots.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.inode.cmp(&b.inode)));
    roots.dedup();
    roots
}

pub(crate) fn nested_roots<'a>(roots: &'a [MeasuredRoot], path: &str) -> &'a [MeasuredRoot] {
    let path = Path::new(path);
    let later = &roots[roots.partition_point(|root| root.path.as_path() <= path)..];
    &later[..later.partition_point(|root| root.path.starts_with(path))]
}

pub(crate) fn changed_removal_root(
    path: &str,
    inode: Option<(u64, u64)>,
    nested: &[MeasuredRoot],
    expected_absent: impl Fn(&Path) -> bool,
) -> Option<String> {
    changed_root(Path::new(path), inode, false).or_else(|| {
        nested.iter().find_map(|root| {
            changed_root(&root.path, root.inode, expected_absent(&root.path))
                .map(|detail| format!("{detail} (inside {path})"))
        })
    })
}

/// Why a finding's live root differs from the measured root.
pub(crate) fn changed_since_scan(f: &Finding, tree: &ScanTree) -> Option<String> {
    changed_root(
        Path::new(&f.path),
        measured_inode(&f.path, f.file_identity, tree),
        false,
    )
}

fn measured_inode(path: &str, file: Option<FileIdentity>, tree: &ScanTree) -> Option<(u64, u64)> {
    if !path.starts_with('/') {
        return None;
    }
    let node = tree.find(Path::new(path)).map(|id| tree.node(id));
    root_identity(file, node).map(|id| (id.dev, id.ino))
}

fn root_identity(file: Option<FileIdentity>, node: Option<&TreeNode>) -> Option<FileIdentity> {
    file.or_else(|| {
        node.map(|n| FileIdentity {
            dev: n.dev,
            ino: n.ino,
            mtime: n.newest_mtime,
        })
    })
}

fn changed_root(path: &Path, inode: Option<(u64, u64)>, expected_absent: bool) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    let display = path.display();
    let Some(inode) = inode else {
        return Some(format!(
            "{display} is not in the scan, so its device/inode are not known"
        ));
    };
    match stat_nofollow(path) {
        Err(Errno::NOENT) if expected_absent => None,
        Err(Errno::NOENT) => Some(format!("{display} is gone since the scan")),
        Err(Errno::NOTDIR | Errno::LOOP) => {
            Some(format!("{display} has a symlink or non-directory ancestor"))
        }
        Err(e) => Some(format!("{display} cannot be checked against the scan: {e}")),
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Symlink => {
            Some(format!("{display} is a symlink now"))
        }
        Ok(_) if expected_absent => Some(format!("{display} reappeared after removal")),
        Ok(st) if (st.st_dev, st.st_ino) != inode => Some(format!(
            "{display} was replaced after the scan (device/inode differ)"
        )),
        Ok(_) => None,
    }
}

pub(crate) fn removal_path_absent(path: &Path) -> bool {
    matches!(stat_nofollow(path), Err(Errno::NOENT))
}

fn stat_nofollow(path: &Path) -> Result<Stat, Errno> {
    let mut parts = path.components().peekable();
    if parts.next() != Some(Component::RootDir) {
        return Err(Errno::INVAL);
    }
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = fs::open("/", flags, Mode::empty())?;
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(Errno::INVAL);
        };
        if parts.peek().is_none() {
            return fs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW);
        }
        dir = fs::openat(&dir, name, flags, Mode::empty())?;
    }
    fs::fstat(&dir)
}

/// Adds (or replaces) the blocking [`CHANGED_SINCE_SCAN`] guard.
pub(crate) fn add_changed_guard(guards: &mut Vec<GuardResult>, detail: String) {
    guards.retain(|g| g.name != CHANGED_SINCE_SCAN);
    guards.push(GuardResult {
        name: CHANGED_SINCE_SCAN.into(),
        status: GuardStatus::Block,
        detail,
    });
}

/// The fingerprint of `f` from the scan tree or the detector's file measurement.
/// Only Git and Docker state are read live.
pub fn fingerprint(f: &Finding, tree: &ScanTree, ctx: &DetectContext) -> Fingerprint {
    let mut fp = Fingerprint {
        dev: None,
        inode: None,
        newest_mtime: None,
        size_bucket: size_bucket(f.bytes),
        git: None,
        docker_id: None,
    };
    if f.path.starts_with('/') {
        let p = Path::new(&f.path);
        let node = tree.find(p).map(|id| tree.node(id));
        if let Some(id) = root_identity(f.file_identity, node) {
            fp.dev = Some(id.dev);
            fp.inode = Some(id.ino);
            fp.newest_mtime = Some(id.mtime);
        }
        if node.is_some_and(|n| n.is_dir && n.markers.contains(Markers::DOT_GIT))
            && guard::git_guarded(f)
            && let Some(git) = ctx.tool_command("git")
        {
            fp.git = guard::work_tree_state(&git, p)
                .ok()
                .map(|(head, status)| GitFingerprint {
                    head,
                    status_hash: format!("{:016x}", fnv1a(status.as_bytes())),
                });
        }
    } else if f.path.starts_with("docker://") {
        fp.docker_id = ctx
            .docker
            .get()
            .ok()
            .and_then(|snap| crate::detectors::object_id(&snap, &f.path));
    }
    fp
}

/// Four buckets per power of two (each 12–25% wide): `4·⌊log2 b⌋` plus the
/// two bits after the leading one. Sizes below 4 are their own bucket.
pub fn size_bucket(bytes: u64) -> u32 {
    if bytes < 4 {
        return bytes as u32;
    }
    let log = 63 - bytes.leading_zeros();
    4 * log + ((bytes >> (log - 2)) & 3) as u32
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The fields of two fingerprints that differ, for a "changed" message.
pub fn differences(planned: &Fingerprint, now: &Fingerprint) -> Vec<&'static str> {
    let mut out = Vec::new();
    if planned.dev != now.dev || planned.inode != now.inode {
        out.push("inode");
    }
    if planned.newest_mtime != now.newest_mtime {
        out.push("newest mtime");
    }
    if planned.size_bucket != now.size_bucket {
        out.push("size");
    }
    if planned.git.as_ref().map(|g| &g.head) != now.git.as_ref().map(|g| &g.head) {
        out.push("git HEAD");
    }
    if planned.git.as_ref().map(|g| &g.status_hash) != now.git.as_ref().map(|g| &g.status_hash) {
        out.push("git status");
    }
    if planned.docker_id != now.docker_id {
        out.push("docker object");
    }
    out
}

/// A plan as `dwhy plan -o` writes it: pretty JSON and a final newline.
/// The TUI's `w` writes the same bytes.
pub fn to_json(plan: &Plan) -> serde_json::Result<String> {
    let mut text = serde_json::to_string_pretty(plan)?;
    text.push('\n');
    Ok(text)
}

/// Parses a plan file and checks its schema.
pub fn parse(text: &str) -> Result<Plan, String> {
    #[derive(serde::Deserialize)]
    struct Head {
        schema: String,
    }
    let head: Head = serde_json::from_str(text).map_err(|e| format!("not a diskwhy plan: {e}"))?;
    check_schema(&head.schema)?;
    serde_json::from_str(text).map_err(|e| format!("not a diskwhy plan: {e}"))
}

/// Why a plan cannot be applied at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// Past `expires_at` (or the time cannot be read).
    Expired(String),
    /// Made on another host or as another user.
    Elsewhere(String),
    LossyRoot(String),
}

impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unusable::Expired(s) | Unusable::Elsewhere(s) => f.write_str(s),
            Unusable::LossyRoot(root) => {
                write!(f, "plan root {root} is not valid UTF-8; nothing applied")
            }
        }
    }
}

/// Checks that `plan` was made here, by this uid, and has not expired at
/// `now` (seconds since the epoch).
pub fn usable(plan: &Plan, host: &str, uid: u32, now: i64) -> Result<(), Unusable> {
    if plan.host != host {
        return Err(Unusable::Elsewhere(format!(
            "the plan was made on {}, not {host}",
            plan.host
        )));
    }
    if plan.uid != uid {
        return Err(Unusable::Elsewhere(format!(
            "the plan was made by uid {}, not {uid}",
            plan.uid
        )));
    }
    let (created, expires) = validity_window(plan)?;
    if now >= expires {
        return Err(Unusable::Expired(format!(
            "the plan expired at {} (plans last {} minutes); make a new one with `dwhy plan`",
            rfc3339(expires),
            TTL_SECS / 60
        )));
    }
    if created > now {
        return Err(Unusable::Expired(format!(
            "the plan was created in the future ({})",
            plan.created_at
        )));
    }
    if let Some(root) = plan.scan.roots.iter().find(|root| is_lossy(root)) {
        return Err(Unusable::LossyRoot(root.clone()));
    }
    Ok(())
}

/// The plan's creation time and capped expiry, in seconds since the epoch.
pub fn validity_window(plan: &Plan) -> Result<(i64, i64), Unusable> {
    let expires = parse_time(&plan.expires_at)
        .ok_or_else(|| Unusable::Expired(format!("bad expires_at {:?}", plan.expires_at)))?;
    let created = parse_time(&plan.created_at)
        .ok_or_else(|| Unusable::Expired(format!("bad created_at {:?}", plan.created_at)))?;
    Ok((created, expires.min(created + TTL_SECS)))
}

fn parse_time(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_buckets_are_monotonic_quarter_octaves() {
        assert_eq!(size_bucket(0), 0);
        assert_eq!(size_bucket(3), 3);
        assert_eq!(size_bucket(4), 8);
        assert_eq!(size_bucket(1 << 30), 120);
        assert_eq!(size_bucket((1 << 30) + (1 << 28)), 121);
        assert_eq!(size_bucket((1 << 31) - 1), 123);
        let mut last = 0;
        for b in (0..40).flat_map(|s| [(1u64 << s), (1u64 << s) * 5 / 4, (1u64 << s) * 3 / 2]) {
            let k = size_bucket(b);
            assert!(k >= last, "{b}");
            last = k;
        }
        // A few percent either way stays in the bucket, mostly.
        assert_eq!(size_bucket(10 << 30), size_bucket((10 << 30) + (100 << 20)));
    }
}
