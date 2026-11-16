//! `stale-tree`: scratch directories nobody has written to for a while.
//!
//! A **scratch location** is a directory meant for throwaway work:
//!
//! - one of [`SCRATCH_LOCATIONS`] under the home directory, or
//! - any directory holding a regular file named [`SCRATCH_MARKER`] (an empty
//!   file is enough), so other places can opt in without a config file.
//!
//! A location with nothing written anywhere in it for [`SCRATCH_STALE_DAYS`]
//! days is one finding. Otherwise each of its subdirectories with nothing
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
use std::path::Path;

use crate::detect::{DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
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
    Marked,
}

impl Origin {
    fn describe(self) -> String {
        match self {
            Origin::BuiltIn => "a built-in scratch location".into(),
            Origin::Marked => format!("marked as scratch by {SCRATCH_MARKER}"),
        }
    }
}

pub struct StaleTree;

impl Detector for StaleTree {
    fn name(&self) -> &'static str {
        "stale-tree"
    }

    fn detect(&self, tree: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let mut locations: BTreeMap<NodeId, Origin> = BTreeMap::new();
        for id in tree.ids() {
            let n = tree.node(id);
            if n.is_dir && n.markers.contains(Markers::SCRATCH) {
                locations.insert(id, Origin::Marked);
            }
        }
        if let Some(home) = &ctx.home {
            for id in builtin_locations(tree, home) {
                locations.entry(id).or_insert(Origin::BuiltIn);
            }
        }

        let stale_after = SCRATCH_STALE_DAYS * 86_400;
        let is_stale = |id: NodeId| ctx.now - tree.node(id).newest_mtime >= stale_after;
        let mut out = Vec::new();
        for (&loc, &origin) in &locations {
            if is_stale(loc) {
                out.extend(self.finding(tree, ctx, loc, None, origin));
                continue;
            }
            for &child in tree.children(loc) {
                if tree.node(child).is_dir && is_stale(child) {
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
    ) -> Option<Finding> {
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
        reason.push_str(&format!(
            "); scratch counts as stale after {SCRATCH_STALE_DAYS} days"
        ));

        Some(Finding {
            id: finding_id(self.name(), &path_s),
            detector: self.name().into(),
            probe: None,
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
        })
    }
}

/// Directories in the tree that match [`SCRATCH_LOCATIONS`] under `home`.
fn builtin_locations(tree: &ScanTree, home: &Path) -> Vec<NodeId> {
    let mut out = Vec::new();
    for pattern in SCRATCH_LOCATIONS {
        match pattern.strip_suffix('*') {
            Some(stem) => {
                let (parent, prefix) = match stem.rsplit_once('/') {
                    Some((dir, prefix)) => (home.join(dir), prefix),
                    None => (home.to_path_buf(), stem),
                };
                let Some(pid) = tree.find(&parent) else {
                    continue;
                };
                for &child in tree.children(pid) {
                    let name = tree.name(child).as_encoded_bytes();
                    if tree.node(child).is_dir
                        && name.len() > prefix.len()
                        && name.starts_with(prefix.as_bytes())
                    {
                        out.push(child);
                    }
                }
            }
            None => {
                if let Some(id) = tree.find(&home.join(pattern))
                    && tree.node(id).is_dir
                {
                    out.push(id);
                }
            }
        }
    }
    out
}
