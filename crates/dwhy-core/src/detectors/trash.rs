//! `trash`: desktop trash directories (the freedesktop.org Trash spec).
//!
//! Looks at the user's trash directories that are inside the scan:
//!
//! - the home trash, `$XDG_DATA_HOME/Trash` (default `~/.local/share/Trash`)
//! - at the root of each mount, `.Trash-<uid>`, and `.Trash/<uid>` when
//!   `.Trash` is a real directory with the sticky bit set (the spec says to
//!   ignore it otherwise)
//!
//! Each trash directory is one finding. The action removes the whole
//! directory, so `files/` and `info/` go together; the spec has file
//! managers create it again when something is next trashed. The age comes
//! from the `DeletionDate` of each `info/*.trashinfo` (read as UTC, since
//! the spec stores local time without a zone; an error of hours does not
//! matter for a gate of days), falling back to the `.trashinfo` file's own
//! mtime when the date is missing or unreadable. When anything was trashed
//! within [`TRASH_RECENT_DAYS`] days, the finding is `blocked` with a
//! `recent-delete` guard: it may still be wanted back. Otherwise it is
//! `review`, since someone may still want something back. Only the
//! scanning user's own trash directories are looked at.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::detect::{DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::mounts::MountTable;
use crate::report::{Action, ActionKind, Finding, GuardResult, GuardStatus, Recovery, Tier};
use crate::tree::ScanTree;
use crate::units::human;

use super::read_head;

/// Anything trashed more recently than this blocks the trash's finding.
pub const TRASH_RECENT_DAYS: i64 = 7;

/// Trash directories smaller than this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// Largest `.trashinfo` read.
const MAX_INFO: usize = 16 << 10;

/// `trash`. Holds the environment and, for tests, the mount roots.
pub struct Trash {
    xdg_data_home: Option<PathBuf>,
    mount_roots: Option<Vec<PathBuf>>,
}

impl Trash {
    /// Reads the process environment; mount roots come from
    /// `/proc/self/mountinfo` when the detector runs.
    pub fn from_system() -> Trash {
        Trash::with_env(std::env::vars_os())
    }

    /// Uses the given variables instead of the process environment.
    pub fn with_env<I, K, V>(vars: I) -> Trash
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        let xdg_data_home = vars
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .find(|(k, _)| k == "XDG_DATA_HOME")
            .map(|(_, v)| PathBuf::from(v))
            .filter(|p| p.is_absolute());
        Trash {
            xdg_data_home,
            mount_roots: None,
        }
    }

    /// Uses these directories as the mount roots instead of the mount table.
    pub fn with_mount_roots(mut self, roots: Vec<PathBuf>) -> Trash {
        self.mount_roots = Some(roots);
        self
    }

    /// Every trash directory of user `uid`, whether or not it exists.
    /// Mount roots are only looked at where the scan went.
    fn candidates(&self, tree: &ScanTree, ctx: &DetectContext) -> BTreeSet<PathBuf> {
        let mut out = BTreeSet::new();
        if let Some(d) = self
            .xdg_data_home
            .clone()
            .or_else(|| ctx.home.as_ref().map(|h| h.join(".local/share")))
        {
            out.insert(d.join("Trash"));
        }
        let roots = match &self.mount_roots {
            Some(r) => r.clone(),
            None => MountTable::read()
                .map(|t| {
                    t.mounts
                        .into_iter()
                        .filter(|m| !m.is_virtual())
                        .map(|m| m.mount_point)
                        .collect()
                })
                .unwrap_or_default(),
        };
        for root in roots {
            out.insert(root.join(format!(".Trash-{}", ctx.uid)));
            let shared = root.join(".Trash");
            if is_dir(tree, &shared)
                && std::fs::symlink_metadata(&shared)
                    .is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o1000 != 0)
            {
                out.insert(shared.join(ctx.uid.to_string()));
            }
        }
        out
    }
}

impl Detector for Trash {
    fn name(&self) -> &'static str {
        "trash"
    }

    fn detect(&self, tree: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let mut out = Vec::new();
        for dir in self.candidates(tree, ctx) {
            let Some(id) = tree.find(&dir) else {
                continue;
            };
            let n = tree.node(id);
            if !n.is_dir {
                continue;
            }
            let bytes = n.freeable();
            if bytes < MIN_BYTES {
                continue;
            }
            let info = dir.join("info");
            let dates = if is_dir(tree, &info) {
                deletion_dates(&info)
            } else {
                Vec::new()
            };
            let path_s = dir.to_string_lossy().into_owned();

            let mut reason = format!("Trash {} ({}", dir.display(), human(bytes));
            if n.shared > 0 {
                reason.push_str(&format!(
                    "; {} more is hardlinked elsewhere and is not freed",
                    human(n.shared)
                ));
            }
            reason.push(')');
            let (oldest, newest) = (dates.iter().min(), dates.iter().max());
            match (oldest, newest) {
                (Some(&o), Some(&nw)) => reason.push_str(&format!(
                    ": {} item{}, trashed between {} and {} ago",
                    dates.len(),
                    if dates.len() == 1 { "" } else { "s" },
                    age(ctx.now, o),
                    age(ctx.now, nw)
                )),
                _ => reason.push_str(": no trash records in info/"),
            }

            let mut tier = Tier::Review;
            let mut guards = Vec::new();
            if let Some(&nw) = newest
                && ctx.now - nw < TRASH_RECENT_DAYS * 86_400
            {
                tier = Tier::Blocked;
                reason.push_str(&format!(
                    "; something was trashed in the last {TRASH_RECENT_DAYS} days, so not offered yet"
                ));
                guards.push(GuardResult {
                    name: "recent-delete".into(),
                    status: GuardStatus::Block,
                    detail: format!(
                        "last item trashed {} ago (gate: {TRASH_RECENT_DAYS} days); it may still be wanted back",
                        age(ctx.now, nw)
                    ),
                });
            }

            out.push(Finding {
                id: finding_id(self.name(), &path_s),
                detector: self.name().into(),
                probe: None,
                bytes,
                nested_bytes: None,
                last_modified: Some(rfc3339(newest.copied().unwrap_or(n.newest_mtime))),
                growth: None,
                tier,
                reason,
                guards,
                action: Action {
                    kind: ActionKind::RemovePath,
                    text: format!("remove {}", shell_quote(&path_s)),
                    argv: None,
                },
                recovery: Recovery {
                    cost: "none: emptied items are gone for good; restore anything you want first (`gio trash --list` shows what is there)".into(),
                    how: None,
                },
                path: path_s,
            });
        }
        Ok(out)
    }
}

/// Whether `path` is a directory in the scan (a symlink never is).
fn is_dir(tree: &ScanTree, path: &Path) -> bool {
    tree.find(path).is_some_and(|id| tree.node(id).is_dir)
}

/// Deletion times (seconds since the epoch) of the `.trashinfo` records in
/// `info`.
fn deletion_dates(info: &Path) -> Vec<i64> {
    let Ok(rd) = std::fs::read_dir(info) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "trashinfo") {
            continue;
        }
        let Ok(md) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if !md.is_file() {
            continue;
        }
        let date = read_head(&p, MAX_INFO).and_then(|b| {
            String::from_utf8_lossy(&b)
                .lines()
                .find_map(|l| l.trim().strip_prefix("DeletionDate=").map(str::to_string))
                .and_then(|d| parse_date(d.trim()))
        });
        out.push(date.unwrap_or(md.mtime()));
    }
    out
}

/// `YYYY-MM-DDThh:mm:ss`, read as UTC.
fn parse_date(s: &str) -> Option<i64> {
    let (d, t) = s.split_once('T')?;
    let mut dp = d.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, mo, da) = (dp.next()??, dp.next()??, dp.next()??);
    let t = t.get(..8).unwrap_or(t);
    let mut tp = t.splitn(3, ':').map(|p| p.parse::<i64>().ok());
    let (h, mi, se) = (tp.next()??, tp.next()??, tp.next()??);
    let month = time::Month::try_from(u8::try_from(mo).ok()?).ok()?;
    let date =
        time::Date::from_calendar_date(i32::try_from(y).ok()?, month, u8::try_from(da).ok()?)
            .ok()?;
    let time = time::Time::from_hms(
        u8::try_from(h).ok()?,
        u8::try_from(mi).ok()?,
        u8::try_from(se).ok()?,
    )
    .ok()?;
    Some(
        time::PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp(),
    )
}
