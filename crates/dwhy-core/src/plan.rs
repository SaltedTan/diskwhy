//! Plans (docs/DESIGN.md "Plan"): the findings selected for removal, each
//! with a fingerprint, and an expiry an hour after the plan is made.
//!
//! A plan selects by tier ceiling (`--tier`, `regenerable` when nothing is
//! named) and by finding id or path (`--select`); with both, a finding must
//! match both. The guards run on the selected findings only, and a finding
//! they block, or one a detector already marked `blocked`, goes to the
//! plan's `blocked` list instead of its items.
//!
//! The fingerprint records what must not change before `apply`: the root's
//! device and inode, the newest mtime under it, its size in quarter-doubling
//! buckets, HEAD and a hash of `git status` when the root is a git work
//! tree, and the object id of a Docker finding.
//!
//! `apply` does not trust a plan's actions or tiers: it re-detects and acts
//! on the fresh finding with the same id. A plan is a selection plus the
//! state to compare against, so editing one can make it stale but cannot
//! widen what apply may do.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::detect::{DetectContext, rfc3339};
use crate::guard::{self, Processes};
use crate::report::{
    ActionKind, Finding, Fingerprint, GitFingerprint, Plan, PlanItem, PlanScan, PlanSelection,
    SCHEMA, Tier, Tool, check_schema,
};
use crate::tree::{Markers, ScanTree};

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
/// written, or a relative path that resolves to it.
fn matches(f: &Finding, entry: &str) -> bool {
    if f.id == entry || f.path == entry {
        return true;
    }
    f.path.starts_with('/') && absolute(entry).is_some_and(|p| p == Path::new(&f.path))
}

/// `entry` made absolute, with the parent canonicalized but not a final
/// symlink (scan roots are made absolute the same way).
fn absolute(entry: &str) -> Option<PathBuf> {
    let abs = std::path::absolute(entry).ok()?;
    match (abs.parent(), abs.file_name()) {
        (Some(parent), Some(name)) => Some(
            std::fs::canonicalize(parent)
                .map(|p| p.join(name))
                .unwrap_or(abs.clone()),
        ),
        _ => Some(abs),
    }
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
/// the selection, fingerprints each item. `tree` is the scan the findings
/// came from; `ctx.now` is the creation time.
pub fn build(
    findings: Vec<Finding>,
    sel: &Selection,
    tree: &ScanTree,
    ctx: &DetectContext,
    procs: &Processes,
    host: String,
    scan: PlanScan,
) -> Result<Plan, String> {
    let (mut picked, mut blocked) = select(findings, sel)?;
    guard::check(&mut picked, tree, ctx, procs);
    let mut items = Vec::new();
    for f in picked {
        if f.tier == Tier::Blocked {
            blocked.push(f);
        } else {
            let fingerprint = fingerprint(&f, tree, ctx);
            items.push(PlanItem {
                finding: f,
                fingerprint,
            });
        }
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
    let paths: Vec<&Path> = items
        .iter()
        .map(|i| Path::new(&i.finding.path))
        .filter(|p| p.is_absolute())
        .collect();
    items
        .iter()
        .filter(|i| {
            let p = Path::new(&i.finding.path);
            !p.is_absolute() || !paths.iter().any(|o| *o != p && p.starts_with(o))
        })
        .map(|i| i.finding.bytes)
        .sum()
}

/// The fingerprint of `f` now. `tree` must be a scan covering its path.
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
        if let Ok(md) = std::fs::symlink_metadata(p) {
            fp.dev = Some(md.dev());
            fp.inode = Some(md.ino());
        }
        if let Some(id) = tree.find(p) {
            let n = tree.node(id);
            fp.newest_mtime = Some(n.newest_mtime);
            if n.is_dir
                && n.markers.contains(Markers::DOT_GIT)
                && guard::git_guarded(f)
                && let Some(git) = ctx.tool_command("git")
            {
                fp.git =
                    guard::work_tree_state(&git, p)
                        .ok()
                        .map(|(head, status)| GitFingerprint {
                            head,
                            status_hash: format!("{:016x}", fnv1a(status.as_bytes())),
                        });
            }
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
}

impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unusable::Expired(s) | Unusable::Elsewhere(s) => f.write_str(s),
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
    let expires = parse_time(&plan.expires_at)
        .ok_or_else(|| Unusable::Expired(format!("bad expires_at {:?}", plan.expires_at)))?;
    let created = parse_time(&plan.created_at)
        .ok_or_else(|| Unusable::Expired(format!("bad created_at {:?}", plan.created_at)))?;
    // An edited plan cannot live longer than TTL_SECS from its creation.
    if now >= expires.min(created + TTL_SECS) {
        return Err(Unusable::Expired(format!(
            "the plan expired at {} (plans last {} minutes); make a new one with `dwhy plan`",
            rfc3339(expires.min(created + TTL_SECS)),
            TTL_SECS / 60
        )));
    }
    if created > now + 300 {
        return Err(Unusable::Expired(format!(
            "the plan was created in the future ({})",
            plan.created_at
        )));
    }
    Ok(())
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
