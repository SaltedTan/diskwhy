//! Plans (docs/DESIGN.md "Plans"): the findings selected for removal, each
//! with a fingerprint, and an expiry an hour after the plan is made.
//!
//! A plan selects by tier ceiling (`--tier`, `regenerable` when nothing is
//! named) and by finding id or path (`--select`); with both, a finding must
//! match both. The guards run on the selected findings only, and a finding
//! they block, or one a detector already marked `blocked` that `--select`
//! names, goes to the plan's `blocked` list instead of its items.
//!
//! See [`Fingerprint`] for the saved fields and the safety rules in
//! `docs/DESIGN.md` for the live identity checks.
//!
//! `apply` does not trust a plan's actions or tiers: it re-detects and acts
//! on the fresh finding with the same id. A plan is a selection plus the
//! state to compare against, so editing one can make it stale but cannot
//! widen what apply may do.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use crate::detect::{DetectContext, is_lossy, rfc3339};
use crate::guard::{self, Processes};
use crate::report::{
    ActionKind, FileIdentity, Finding, Fingerprint, GitFingerprint, GuardResult, GuardStatus, Plan,
    PlanItem, PlanScan, PlanSelection, SCHEMA, Tier, Tool, check_schema,
};
use crate::tree::{Markers, NodeId, ScanTree, TreeNode};

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
}

/// A `--select` value, with the path it resolves to (the way scan roots are
/// resolved: parent canonicalized, a final symlink not followed). Each entry
/// is resolved once, so a rename while selecting cannot drop a finding that
/// an earlier check matched.
struct Entry<'a> {
    text: &'a str,
    resolved: Option<PathBuf>,
}

impl Entry<'_> {
    /// Whether this entry names `f`: its id, its path as written, or a path
    /// that resolves to it.
    fn matches(&self, f: &Finding) -> bool {
        f.id == self.text
            || f.path == self.text
            || (f.path.starts_with('/')
                && self
                    .resolved
                    .as_deref()
                    .is_some_and(|p| p == Path::new(&f.path)))
    }
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
    select_with(findings, sel, |entry| {
        crate::scan::absolute_nofollow(Path::new(entry)).ok()
    })
}

/// [`select`], resolving each `--select` path with `resolve`, once.
fn select_with(
    findings: Vec<Finding>,
    sel: &Selection,
    mut resolve: impl FnMut(&str) -> Option<PathBuf>,
) -> Result<(Vec<Finding>, Vec<Finding>), String> {
    let entries: Vec<Entry> = sel
        .select
        .iter()
        .map(|text| Entry {
            text,
            resolved: resolve(text),
        })
        .collect();
    // Which findings the entries name, decided once for every check below.
    let named: Vec<bool> = findings
        .iter()
        .map(|f| entries.is_empty() || entries.iter().any(|e| e.matches(f)))
        .collect();
    if let Some(bad) = entries
        .iter()
        .find(|e| !findings.iter().any(|f| e.matches(f)))
    {
        return Err(format!(
            "--select {}: no finding has that id or path (`dwhy scan` lists them)",
            bad.text
        ));
    }
    if let Some(f) = findings
        .iter()
        .zip(&named)
        .find(|(f, named)| !entries.is_empty() && **named && f.action.kind == ActionKind::Advice)
        .map(|(f, _)| f)
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
        .zip(named)
        .filter(|(f, named)| *named && f.action.kind != ActionKind::Advice)
        .map(|(f, _)| f)
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
/// and blocks findings that fail the live identity check (`changed-since-scan`).
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
    let already_blocked = already_blocked.into_iter().map(|f| (f, true));
    for (mut f, detector_blocked) in already_blocked.chain(picked.into_iter().map(|f| (f, false))) {
        let fingerprint = (f.tier != Tier::Blocked).then(|| fingerprint(&f, tree, ctx));
        // A finding a detector already blocked is never applied, so only its
        // own root is checked: a change below it says nothing about it.
        let nested = if detector_blocked {
            &[][..]
        } else {
            nested_roots(&roots, &f.path)
        };
        let changed = changed_removal_root(
            &f.path,
            measured(&f.path, f.file_identity, tree),
            nested,
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
    let bytes = distinct_bytes_in_tree(
        tree,
        items
            .iter()
            .map(|i| (i.finding.path.as_str(), i.finding.bytes)),
    );
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

/// [`distinct_bytes`] for findings of the scan in `tree`: a pair is left
/// out only when it also lies inside another pair in the tree, below that
/// pair's node. A scan root mounted below another root (scanned as its own
/// root because a one-filesystem walk does not enter it) is not inside the
/// outer root's node, so its bytes count on their own. A path the tree has
/// no node for (a single file) is placed at its nearest ancestor in the
/// tree; paths the tree does not cover at all nest by path, as in
/// [`distinct_bytes`].
pub fn distinct_bytes_in_tree<'a>(
    tree: &ScanTree,
    items: impl IntoIterator<Item = (&'a str, u64)>,
) -> u64 {
    let items: Vec<(&Path, u64, Option<NodeId>)> = items
        .into_iter()
        .map(|(p, b)| {
            let p = Path::new(p);
            let at = p
                .is_absolute()
                .then(|| p.ancestors().find_map(|a| tree.find(a)))
                .flatten();
            (p, b, at)
        })
        .collect();
    let inside = |inner: Option<NodeId>, outer: Option<NodeId>| match (inner, outer) {
        (Some(i), Some(o)) => tree.is_within(i, o),
        _ => true,
    };
    items
        .iter()
        .filter(|(p, _, at)| {
            !p.is_absolute()
                || !items.iter().any(|(o, _, o_at)| {
                    o.is_absolute() && o != p && p.starts_with(o) && inside(*at, *o_at)
                })
        })
        .map(|(_, b, _)| b)
        .sum()
}

/// What the scan measured at a filesystem root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Measured {
    /// Nothing: the path is not in the scan.
    Unknown,
    /// The walk recorded a node there, and the detector then measured a
    /// different file at the same path.
    Conflict,
    /// `(st_dev, st_ino)`.
    Inode(u64, u64),
}

impl From<Option<(u64, u64)>> for Measured {
    fn from(inode: Option<(u64, u64)>) -> Measured {
        inode.map_or(Measured::Unknown, |(dev, ino)| Measured::Inode(dev, ino))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MeasuredRoot {
    pub(crate) path: PathBuf,
    pub(crate) inode: Measured,
}

pub(crate) fn measured_roots<'a>(
    tree: &ScanTree,
    planned: impl Iterator<Item = (&'a str, Option<FileIdentity>)>,
) -> Vec<MeasuredRoot> {
    let mut roots: Vec<_> = planned
        .filter(|(path, _)| path.starts_with('/'))
        .map(|(path, file)| MeasuredRoot {
            path: PathBuf::from(path),
            inode: measured(path, file, tree),
        })
        .collect();
    roots.extend(tree.ids().filter_map(|id| {
        let node = tree.node(id);
        (node.is_dir && node.markers.contains(Markers::DOT_GIT)).then(|| MeasuredRoot {
            path: tree.path(id),
            inode: Measured::Inode(node.dev, node.ino),
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
    inode: Measured,
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
        measured(&f.path, f.file_identity, tree),
        false,
    )
}

pub(crate) fn measured(path: &str, file: Option<FileIdentity>, tree: &ScanTree) -> Measured {
    if !path.starts_with('/') {
        return Measured::Unknown;
    }
    let node = tree.find(Path::new(path)).map(|id| tree.node(id));
    match root_identity(file, node) {
        Ok(id) => id.map(|id| (id.dev, id.ino)).into(),
        Err(Conflict) => Measured::Conflict,
    }
}

/// The walk and a detector measured different files at one path.
struct Conflict;

/// The identity of a root: the walk's node when it recorded one, else the
/// detector's measurement of a file the walk does not keep. Both present
/// and naming different files is a [`Conflict`]: the path changed between
/// the walk and detection.
fn root_identity(
    file: Option<FileIdentity>,
    node: Option<&TreeNode>,
) -> Result<Option<FileIdentity>, Conflict> {
    match (file, node) {
        (Some(f), Some(n)) if (f.dev, f.ino) != (n.dev, n.ino) => Err(Conflict),
        (_, Some(n)) => Ok(Some(FileIdentity {
            dev: n.dev,
            ino: n.ino,
            mtime: n.newest_mtime,
        })),
        (file, None) => Ok(file),
    }
}

pub(crate) fn changed_root(path: &Path, inode: Measured, expected_absent: bool) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    let display = path.display();
    let inode = match inode {
        Measured::Inode(dev, ino) => (dev, ino),
        Measured::Unknown => {
            return Some(format!(
                "{display} is not in the scan, so its device/inode are not known"
            ));
        }
        Measured::Conflict => {
            return Some(format!(
                "{display} changed between the walk and detection (device/inode differ)"
            ));
        }
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
        if let Ok(Some(id)) = root_identity(f.file_identity, node) {
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

/// Parses a plan file, checking its schema and the [`Plan::items`] ID constraint.
pub fn parse(text: &str) -> Result<Plan, String> {
    #[derive(serde::Deserialize)]
    struct Head {
        schema: String,
    }
    let head: Head = serde_json::from_str(text).map_err(|e| format!("not a diskwhy plan: {e}"))?;
    check_schema(&head.schema)?;
    let plan: Plan = serde_json::from_str(text).map_err(|e| format!("not a diskwhy plan: {e}"))?;
    let mut ids = HashSet::new();
    for item in &plan.items {
        if !ids.insert(&item.finding.id) {
            return Err(format!(
                "duplicate finding ID in plan items: {}",
                crate::detect::escape_controls(&item.finding.id)
            ));
        }
    }
    Ok(plan)
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
                write!(
                    f,
                    "plan root {} is not valid UTF-8; nothing applied",
                    crate::detect::escape_controls(root)
                )
            }
        }
    }
}

/// Checks the plan's host, uid, validity window and root path encoding.
/// `now` is in seconds since the epoch.
pub fn usable(plan: &Plan, host: &str, uid: u32, now: i64) -> Result<(), Unusable> {
    if plan.host != host {
        return Err(Unusable::Elsewhere(format!(
            "the plan was made on {}, not {host}",
            crate::detect::escape_controls(&plan.host)
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

    fn finding(path: &str) -> Finding {
        Finding {
            file_identity: None,
            id: crate::detect::finding_id("stale-tree", path),
            detector: "stale-tree".into(),
            probe: None,
            evidence: None,
            path: path.into(),
            bytes: 1,
            nested_bytes: None,
            last_modified: None,
            growth: None,
            tier: Tier::Review,
            reason: String::new(),
            guards: Vec::new(),
            action: crate::report::Action {
                kind: ActionKind::RemovePath,
                text: String::new(),
                argv: None,
            },
            recovery: crate::report::Recovery {
                cost: String::new(),
                how: None,
            },
        }
    }

    #[test]
    fn a_select_path_is_resolved_once_for_checking_and_picking() {
        // The path resolves to the finding only the first time, as if it
        // were renamed right after: the finding the check matched is still
        // the one picked, so the live check sees it.
        let sel = Selection {
            tier: None,
            select: vec!["scratch".into()],
        };
        let mut calls = 0;
        let (picked, blocked) = select_with(vec![finding("/b/scratch")], &sel, |entry| {
            assert_eq!(entry, "scratch");
            calls += 1;
            (calls == 1).then(|| PathBuf::from("/b/scratch"))
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(picked.len(), 1);
        assert!(blocked.is_empty());

        // Resolving to nothing is an error, also checked once.
        let mut calls = 0;
        let err = select_with(vec![finding("/b/scratch")], &sel, |_| {
            calls += 1;
            None
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(err.contains("--select scratch: no finding"), "{err}");
    }

    #[test]
    fn a_duplicate_id_error_escapes_terminal_controls() {
        let mut item = PlanItem {
            finding: finding("/b/scratch"),
            fingerprint: Fingerprint {
                dev: None,
                inode: None,
                newest_mtime: None,
                size_bucket: 0,
                git: None,
                docker_id: None,
            },
        };
        item.finding.id = "f_dup\n\u{1b}[31mred\\".into();
        let plan = Plan {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: "h".into(),
            uid: 1000,
            created_at: rfc3339(0),
            expires_at: rfc3339(TTL_SECS),
            scan: PlanScan {
                roots: vec!["/b".into()],
                one_filesystem: true,
                detectors: None,
            },
            selection: PlanSelection {
                tier: None,
                select: Vec::new(),
            },
            items: vec![item.clone(), item],
            blocked: Vec::new(),
            bytes: 0,
        };
        let err = parse(&to_json(&plan).unwrap()).unwrap_err();
        assert_eq!(
            err,
            r"duplicate finding ID in plan items: f_dup\n\u{1b}[31mred\\"
        );
        assert!(!err.contains(char::is_control), "{err:?}");
    }

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
