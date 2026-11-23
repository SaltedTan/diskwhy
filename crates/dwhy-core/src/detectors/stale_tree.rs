//! `stale-tree`: scratch directories nobody has written to for a while.
//!
//! A **scratch location** is a directory meant for throwaway work:
//!
//! - one of [`SCRATCH_LOCATIONS`] under the home directory,
//! - one of the `[scratch] paths` of the policy config
//!   ([`DetectContext::scratch_paths`]: absolute, `~/…`, or relative to the
//!   home directory, with the same trailing `*` as the built-in ones), or
//! - any directory holding a regular file named [`SCRATCH_MARKER`] (an empty
//!   file is enough), so other places can opt in without a config file.
//!
//! A location with nothing written anywhere in it for
//! [`DetectContext::scratch_stale_days`] days (default
//! [`SCRATCH_STALE_DAYS`]) is one finding. Otherwise each of its subdirectories with nothing
//! written for that long is a finding; scratch locations such as
//! `~/.t3/scratch-virgil` get new work every day, so the location as a whole
//! is never stale even when most of what is in it is. Files directly in a
//! location are not reported one by one (the scan tree keeps directories
//! only). "Written" means modified: reading does not count, since access
//! times are not reliable.
//!
//! Everything is `review`: scratch work is not regenerable, and anything in
//! it that was not kept elsewhere is lost. A location is looked at only when
//! it is inside the scanned paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::detect::{Candidate, DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, Recovery, Tier};
use crate::tree::{Markers, NodeId, ScanTree};
use crate::units::human;

/// A scratch directory with nothing written for this many days is stale.
pub const SCRATCH_STALE_DAYS: i64 = 7;

/// A regular file with this name makes its directory a scratch location.
pub const SCRATCH_MARKER: &str = ".dwhy-scratch";

/// Built-in scratch locations, relative to the home directory. A last
/// component ending in `*` matches every directory whose name starts with
/// what comes before it (and is longer).
pub const SCRATCH_LOCATIONS: &[&str] = &["scratch", "tmp", ".t3/scratch", ".t3/scratch-*"];

/// Stale directories smaller than this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    BuiltIn,
    Configured,
    Marked,
}

impl Origin {
    fn describe(self) -> String {
        match self {
            Origin::BuiltIn => "a built-in scratch location".into(),
            Origin::Configured => "configured in policy.toml".into(),
            Origin::Marked => format!("marked as scratch by {SCRATCH_MARKER}"),
        }
    }
}

pub struct StaleTree;

impl Detector for StaleTree {
    fn name(&self) -> &'static str {
        "stale-tree"
    }

    fn detect_candidates(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
    ) -> Result<Vec<Candidate>, String> {
        let mut locations: BTreeMap<NodeId, Origin> = BTreeMap::new();
        for id in tree.ids() {
            let n = tree.node(id);
            if n.is_dir && n.markers.contains(Markers::SCRATCH) {
                locations.insert(id, Origin::Marked);
            }
        }
        if let Some(home) = &ctx.home {
            let builtin = SCRATCH_LOCATIONS.iter().map(|p| home.join(p));
            for id in matching(tree, builtin) {
                locations.entry(id).or_insert(Origin::BuiltIn);
            }
        }
        let configured = ctx
            .scratch_paths
            .iter()
            .filter_map(|p| configured_pattern(p, ctx.home.as_deref()));
        for id in matching(tree, configured) {
            locations.entry(id).or_insert(Origin::Configured);
        }

        let stale_after = ctx.scratch_stale_days.max(1).saturating_mul(86_400);
        let is_stale = |id: NodeId| ctx.now - tree.node(id).newest_mtime >= stale_after;
        let mut out = Vec::new();
        for (&loc, &origin) in &locations {
            if is_stale(loc) {
                out.extend(self.finding(tree, ctx, loc, None, origin));
                continue;
            }
            for &child in tree.children(loc) {
                if tree.node(child).is_dir && !locations.contains_key(&child) && is_stale(child) {
                    out.extend(self.finding(tree, ctx, child, Some(loc), origin));
                }
            }
        }
        Ok(out)
    }
}

impl StaleTree {
    /// The finding for stale directory `id`: a whole location when
    /// `location` is `None`, else a directory inside `location`.
    fn finding(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
        id: NodeId,
        location: Option<NodeId>,
        origin: Origin,
    ) -> Option<Candidate> {
        let n = tree.node(id);
        let bytes = n.freeable();
        if bytes < MIN_BYTES {
            return None;
        }
        let path = tree.path(id);
        let path_s = path.to_string_lossy().into_owned();

        let mut reason = match location {
            None => format!(
                "Scratch location {} ({}) with nothing written in it for {} ({}",
                path.display(),
                origin.describe(),
                age(ctx.now, n.newest_mtime),
                human(bytes)
            ),
            Some(loc) => format!(
                "Scratch directory in {} ({}) with nothing written in it for {} ({}",
                tree.path(loc).display(),
                origin.describe(),
                age(ctx.now, n.newest_mtime),
                human(bytes)
            ),
        };
        if n.shared > 0 {
            reason.push_str(&format!(
                "; {} more is hardlinked elsewhere and is not freed",
                human(n.shared)
            ));
        }
        let days = ctx.scratch_stale_days.max(1);
        reason.push_str(&format!(
            "); scratch counts as stale after {days} day{}",
            if days == 1 { "" } else { "s" }
        ));

        let finding = Finding {
            file_identity: None,
            id: finding_id(self.name(), &path_s),
            detector: self.name().into(),
            probe: None,
            evidence: None,
            bytes,
            nested_bytes: None,
            last_modified: Some(rfc3339(n.newest_mtime)),
            growth: None,
            tier: Tier::Review,
            reason,
            guards: Vec::new(),
            action: Action {
                kind: ActionKind::RemovePath,
                text: format!("remove {}", shell_quote(&path_s)),
                argv: None,
            },
            recovery: Recovery {
                cost: "none: scratch work is not regenerable, and anything in it that is not kept elsewhere is lost".into(),
                how: None,
            },
            path: path_s,
        };
        Some(Candidate::new(path, finding))
    }
}

/// A `[scratch] paths` entry as an absolute pattern: `~/…` and relative
/// entries are under `home` (`None` without one).
fn configured_pattern(p: &str, home: Option<&Path>) -> Option<PathBuf> {
    if let Some(rest) = p.strip_prefix("~/") {
        Some(home?.join(rest))
    } else if p.starts_with('/') {
        Some(PathBuf::from(p))
    } else {
        Some(home?.join(p))
    }
}

/// Directories in the tree that match `patterns`: absolute paths whose last
/// component may end in `*`, which matches every directory whose name
/// starts with what comes before it (and is longer).
fn matching(tree: &ScanTree, patterns: impl Iterator<Item = PathBuf>) -> Vec<NodeId> {
    let mut out = Vec::new();
    for pattern in patterns {
        // Drops a trailing `/` and `.` components, as the tree's paths have none.
        let pattern: PathBuf = pattern.components().collect();
        let Some(name) = pattern.file_name() else {
            continue;
        };
        match name.as_encoded_bytes().strip_suffix(b"*") {
            Some(prefix) => {
                let Some(parent) = pattern.parent() else {
                    continue;
                };
                let children = tree.find(parent).map_or(&[][..], |pid| tree.children(pid));
                let roots = tree
                    .roots()
                    .iter()
                    .filter(|&&r| Path::new(tree.name(r)).parent() == Some(parent));
                for &id in children.iter().chain(roots) {
                    let path = tree.path(id);
                    let name = path.file_name().unwrap_or_default().as_encoded_bytes();
                    if tree.node(id).is_dir && name.len() > prefix.len() && name.starts_with(prefix)
                    {
                        out.push(id);
                    }
                }
            }
            None => {
                if let Some(id) = tree.find(&pattern)
                    && tree.node(id).is_dir
                {
                    out.push(id);
                }
            }
        }
    }
    out
}
