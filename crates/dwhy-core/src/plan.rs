//! Plans (docs/DESIGN.md "Plans"): the findings selected for removal, each
//! with a fingerprint, and an expiry an hour after the plan is made.
//!
//! A plan selects by tier ceiling (`--tier`, `regenerable` when nothing is
//! named) and by finding id or path (`--select`); with both, a finding must
//! match both. The guards run on the selected findings only, and a finding
//! they block, or one a detector already marked `blocked` that `--select`
//! names, goes to the plan's `blocked` list instead of its items.
//!
//! With a goal (`--free SIZE`), the plan keeps only as many of the eligible
//! findings within the tier ceiling as it takes to reach the target: the
//! cheapest tier first and, within a tier, the finding that adds the most
//! bytes not already planned. [`PlanGoal`] records how close it got and what
//! the tiers above the ceiling hold.
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
    ActionKind, FileIdentity, Finding, Fingerprint, GitFingerprint, GuardResult, GuardStatus,
    HigherTierAvailable, Plan, PlanGoal, PlanItem, PlanScan, PlanSelection, SCHEMA, Tier, Tool,
    check_schema,
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
    /// `--free`: plan the cheapest findings within the tier ceiling until at
    /// least this many bytes are planned. Must be above 0, and cannot be
    /// combined with `select`.
    pub free: Option<u64>,
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
    match sel.free {
        Some(0) => return Err("--free must be greater than 0".into()),
        Some(_) if !sel.select.is_empty() => {
            return Err("--free cannot be combined with --select".into());
        }
        _ => {}
    }
    let higher_tiers = sel
        .free
        .map(|_| higher_tiers(&findings, sel.ceiling()))
        .unwrap_or_default();
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
            let scan_root_dev = scan_root_dev(tree, &f.path, fingerprint.dev);
            items.push(PlanItem {
                finding: f,
                fingerprint,
                scan_root_dev,
            });
            continue;
        }
        blocked.push(f);
    }
    if let Some(target) = sel.free {
        items = toward_goal(items, target, tree);
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
    let goal = sel.free.map(|target| PlanGoal {
        target_bytes: target,
        planned_bytes: bytes,
        met: bytes >= target,
        shortfall_bytes: target.saturating_sub(bytes),
        higher_tiers,
    });
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
            free_target: sel.free,
        },
        items,
        blocked,
        bytes,
        goal,
    })
}

/// The removable findings in each tier above `ceiling`, which a `--free`
/// plan does not consider. Guards have not run on them.
fn higher_tiers(findings: &[Finding], ceiling: Option<Tier>) -> Vec<HigherTierAvailable> {
    let Some(ceiling) = ceiling else {
        return Vec::new();
    };
    [Tier::Rebuildable, Tier::Review]
        .into_iter()
        .filter(|&tier| tier > ceiling)
        .filter_map(|tier| {
            let in_tier = findings
                .iter()
                .filter(|f| f.tier == tier && f.is_reclaimable());
            let (count, bytes) = in_tier.fold((0, 0u64), |(n, b), f| {
                (n + 1, b.saturating_add(f.own_bytes()))
            });
            (count > 0).then_some(HigherTierAvailable { tier, count, bytes })
        })
        .collect()
}

/// The items a `--free target` plan keeps: tier by tier, cheapest first,
/// the item that adds the most bytes to those already chosen (counted as
/// [`distinct_bytes_in_tree`] counts them; ties go to the larger finding,
/// then the smaller id), until the chosen items reach `target`. An item
/// that adds nothing (inside a chosen item, or empty) is never chosen.
fn toward_goal(items: Vec<PlanItem>, target: u64, tree: &ScanTree) -> Vec<PlanItem> {
    let paths: Vec<&str> = items.iter().map(|i| i.finding.path.as_str()).collect();
    let n = items.len();
    let inside = inside_matrix(tree, &paths);
    let within = |i: usize, j: usize| inside[i * n + j];
    let mut chosen = vec![false; n];
    // Whether a chosen item lies inside another chosen item, so its bytes
    // are already counted in that one's.
    let mut covered = vec![false; n];
    let mut planned = 0u64;
    // What adding item `x` adds to the distinct bytes of the chosen items:
    // its own bytes unless a chosen item holds it, less the bytes of the
    // uncovered chosen items it holds.
    let gain = |x: usize, chosen: &[bool], covered: &[bool]| -> u64 {
        let held = (0..n).any(|j| chosen[j] && within(x, j));
        let own = if held { 0 } else { items[x].finding.bytes };
        let absorbed: u64 = (0..n)
            .filter(|&m| chosen[m] && !covered[m] && within(m, x))
            .map(|m| items[m].finding.bytes)
            .sum();
        own.saturating_sub(absorbed)
    };
    'tiers: for tier in [Tier::Regenerable, Tier::Rebuildable, Tier::Review] {
        loop {
            if planned >= target {
                break 'tiers;
            }
            let best = (0..n)
                .filter(|&x| !chosen[x] && items[x].finding.tier == tier)
                .map(|x| (x, gain(x, &chosen, &covered)))
                .filter(|&(_, g)| g > 0)
                .max_by(|&(a, ga), &(b, gb)| {
                    let (fa, fb) = (&items[a].finding, &items[b].finding);
                    ga.cmp(&gb)
                        .then_with(|| fa.bytes.cmp(&fb.bytes))
                        .then_with(|| fb.id.cmp(&fa.id))
                });
            let Some((x, g)) = best else {
                continue 'tiers;
            };
            for m in 0..n {
                if chosen[m] && within(m, x) {
                    covered[m] = true;
                }
            }
            covered[x] = (0..n).any(|j| chosen[j] && within(x, j));
            chosen[x] = true;
            planned = planned.saturating_add(g);
        }
    }
    items
        .into_iter()
        .zip(chosen)
        .filter_map(|(item, chosen)| chosen.then_some(item))
        .collect()
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
    let (paths, bytes): (Vec<&str>, Vec<u64>) = items.into_iter().unzip();
    let n = paths.len();
    let inside = inside_matrix(tree, &paths);
    (0..n)
        .filter(|&i| !(0..n).any(|j| inside[i * n + j]))
        .map(|i| bytes[i])
        .sum()
}

/// For paths `p` and `o` of `paths`, whether [`distinct_bytes_in_tree`]
/// counts `p` as inside `o`: at index `p * paths.len() + o`.
fn inside_matrix(tree: &ScanTree, paths: &[&str]) -> Vec<bool> {
    let located: Vec<(&Path, Option<NodeId>)> = paths
        .iter()
        .map(|p| {
            let p = Path::new(*p);
            let at = p
                .is_absolute()
                .then(|| p.ancestors().find_map(|a| tree.find(a)))
                .flatten();
            (p, at)
        })
        .collect();
    let in_tree = |inner: Option<NodeId>, outer: Option<NodeId>| match (inner, outer) {
        (Some(i), Some(o)) => tree.is_within(i, o),
        _ => true,
    };
    located
        .iter()
        .flat_map(|&(p, at)| {
            located.iter().map(move |&(o, o_at)| {
                p.is_absolute()
                    && o.is_absolute()
                    && o != p
                    && p.starts_with(o)
                    && in_tree(at, o_at)
            })
        })
        .collect()
}

/// The device of the root of `tree` whose walk holds `path` (the node at
/// it, or at its nearest ancestor in the tree), when that differs from
/// `dev`, the device recorded for the finding: [`PlanItem::scan_root_dev`].
fn scan_root_dev(tree: &ScanTree, path: &str, dev: Option<u64>) -> Option<u64> {
    let dev = dev?;
    let p = Path::new(path);
    if !p.is_absolute() {
        return None;
    }
    let mut id = p.ancestors().find_map(|a| tree.find(a))?;
    while let Some(parent) = tree.parent(id) {
        id = parent;
    }
    Some(tree.node(id).dev).filter(|&root| root != dev)
}

/// [`distinct_bytes`] for items of `plan`, without the scan's tree (as for
/// a plan read from a file): an item is left out only when it also lies
/// inside another item of the same scan. Each path belongs to the deepest
/// of `plan.scan.roots` above it, and items under different roots do not
/// nest: a root mounted below another root was scanned on its own, so its
/// bytes are not in the outer root's. In a one-filesystem scan, items on
/// different devices do not nest either. An item's device is that of the
/// root whose walk measured it ([`PlanItem::scan_root_dev`]) when the plan
/// records one, so items in btrfs subvolumes that walk entered nest in it;
/// else the device its fingerprint records. Paths no root covers nest by
/// path, and pseudo-paths (`docker://…`) never nest, as in
/// [`distinct_bytes`]. Agrees with [`distinct_bytes_in_tree`], which
/// `plan.bytes` comes from.
pub fn distinct_bytes_in_plan<'a>(
    plan: &Plan,
    items: impl IntoIterator<Item = &'a PlanItem>,
) -> u64 {
    let roots: Vec<&Path> = plan.scan.roots.iter().map(Path::new).collect();
    let owner = |p: &Path| {
        roots
            .iter()
            .copied()
            .filter(|r| p.starts_with(r))
            .max_by_key(|r| r.as_os_str().len())
    };
    let items: Vec<(&Path, u64, Option<&Path>, Option<u64>)> = items
        .into_iter()
        .map(|i| {
            let p = Path::new(&i.finding.path);
            let dev = i.scan_root_dev.or(i.fingerprint.dev);
            (p, i.finding.bytes, owner(p), dev)
        })
        .collect();
    let same_scan = |(p_root, p_dev): (Option<&Path>, Option<u64>),
                     (o_root, o_dev): (Option<&Path>, Option<u64>)| {
        let roots_agree = match (p_root, o_root) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        let devs_agree = match (p_dev, o_dev) {
            (Some(a), Some(b)) if plan.scan.one_filesystem => a == b,
            _ => true,
        };
        roots_agree && devs_agree
    };
    items
        .iter()
        .filter(|(p, _, root, dev)| {
            !p.is_absolute()
                || !items.iter().any(|(o, _, o_root, o_dev)| {
                    o.is_absolute()
                        && o != p
                        && p.starts_with(o)
                        && same_scan((*root, *dev), (*o_root, *o_dev))
                })
        })
        .map(|(_, b, _, _)| b)
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
/// Only Git, Docker and (for `old-kernels`) dpkg state are read live.
pub fn fingerprint(f: &Finding, tree: &ScanTree, ctx: &DetectContext) -> Fingerprint {
    let mut fp = Fingerprint {
        dev: None,
        inode: None,
        newest_mtime: None,
        size_bucket: size_bucket(f.bytes),
        git: None,
        docker_id: None,
        packages: None,
    };
    if f.path.starts_with('/') {
        let p = Path::new(&f.path);
        let node = tree.find(p).map(|id| tree.node(id));
        if let Ok(Some(id)) = root_identity(f.file_identity, node) {
            fp.dev = Some(id.dev);
            fp.inode = Some(id.ino);
            // Not for `journald`: systemd-journald writes the active
            // journals all the time, which moves the directory's newest
            // mtime and would invalidate every plan before `apply`. The
            // vacuum leaves the active journals alone; device/inode, the
            // size bucket of the old archived files and the removal-root
            // check still tell whether the directory is the one planned.
            if f.detector != "journald" {
                fp.newest_mtime = Some(id.mtime);
            }
        }
        if f.detector == "old-kernels" {
            fp.packages = crate::detectors::package_state(f, ctx);
        }
        if node.is_some_and(|n| n.is_dir && n.markers.contains(Markers::DOT_GIT))
            && guard::git_guarded(f)
            && let Some(git) = ctx.tool_command("git")
        {
            let git = crate::gitcmd::Git {
                cmd: &git,
                cancel: &ctx.cancel,
            };
            fp.git = guard::work_tree_state(git, p)
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
    if planned.packages != now.packages {
        out.push("packages");
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
            free: None,
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
                packages: None,
            },
            scan_root_dev: None,
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
                free_target: None,
            },
            items: vec![item.clone(), item],
            blocked: Vec::new(),
            bytes: 0,
            goal: None,
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
