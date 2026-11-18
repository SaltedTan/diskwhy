//! `dwhy explain` (docs/DESIGN.md, Explain): what the argument names, how
//! a finding id becomes a path through the saved snapshots, what is walked
//! for a path, and which finding of the rescan is the one explained. The
//! CLI rescans, runs the detectors, the probes and the guards; nothing here
//! writes.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::detect::{self, CATALOG, Needs};
use crate::mounts::MountTable;
use crate::report::{
    DetectorAvailability, DetectorRun, ExplainSnapshot, Finding, FindingRef, Snapshot,
    SnapshotFinding,
};
use crate::snapshot::{self, Entry};
use crate::tree::ScanTree;

pub const PATH_HINT: &str = "run `dwhy explain <path>` with its path";

/// What `dwhy explain` was asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// A finding id (`f_…`), resolved through the snapshots.
    Id(String),
    Place(Place),
}

/// A place a finding can be: what explain rescans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// A pseudo-path such as `docker://volume/<name>`.
    Docker(String),
    /// A filesystem path, as given.
    Path(PathBuf),
}

/// Whether `arg` matches the format of [`crate::detect::finding_id`].
pub fn is_finding_id(arg: &str) -> bool {
    let len = crate::detect::finding_id("", "").len();
    arg.len() == len
        && arg.strip_prefix("f_").is_some_and(|hex| {
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub fn classify(arg: impl AsRef<OsStr>) -> Query {
    let arg = arg.as_ref();
    if let Some(id) = arg.to_str().filter(|s| is_finding_id(s)) {
        Query::Id(id.to_owned())
    } else {
        Query::Place(place(arg))
    }
}

/// A finding's path (as a snapshot records it) or a path argument.
pub fn place(path: impl AsRef<OsStr>) -> Place {
    let path = path.as_ref();
    if let Some(pseudo) = path.to_str().filter(|s| s.starts_with("docker://")) {
        Place::Docker(pseudo.to_owned())
    } else {
        Place::Path(PathBuf::from(path))
    }
}

/// What explain walks for a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Walk {
    /// The path's parent directory, one level up, so that detectors which
    /// recognise a directory from its parent (a `target/` next to its
    /// `Cargo.toml`, a project's `node_modules`) see it.
    Parent(PathBuf),
    /// The path itself, with a note when that is because the parent could
    /// not be used.
    Itself(Option<String>),
}

/// Decides what to walk for `abs`, an absolute path whose parent is
/// canonical (as [`crate::scan::prepare_roots`] makes it). Walking a file's
/// parent would leave the query without its own node in the tree. Walking
/// a mount point's parent could skip the query at the filesystem boundary.
pub fn walk_for(abs: &Path, mounts: &MountTable) -> Walk {
    if mounts.at(abs).is_some() {
        return Walk::Itself(Some(format!(
            "{} is a mount point; scanned it alone",
            abs.display()
        )));
    }
    let Ok(md) = std::fs::symlink_metadata(abs) else {
        // The scan of the path reports the error.
        return Walk::Itself(None);
    };
    let Some(parent) = abs.parent() else {
        return Walk::Itself(None);
    };
    let parent_md = std::fs::symlink_metadata(parent);
    if parent_md.as_ref().is_ok_and(|pmd| pmd.dev() != md.dev()) {
        return Walk::Itself(Some(format!(
            "{} is a mount point and its parent is on another filesystem; scanned it alone",
            abs.display()
        )));
    }
    if !md.is_dir() {
        return Walk::Itself(None);
    }
    match parent_md.and_then(|_| std::fs::read_dir(parent)) {
        Ok(_) => Walk::Parent(parent.to_path_buf()),
        Err(e) => Walk::Itself(Some(format!(
            "cannot open its parent {}: {e}; scanned {} alone",
            parent.display(),
            abs.display()
        ))),
    }
}

struct Listing {
    entry: Entry,
    snapshot: Snapshot,
    finding: SnapshotFinding,
}

/// The newest snapshot listing `id` for this host and uid. A growth
/// cutoff also limits the search to one-filesystem snapshots.
fn newest_listing(
    dir: &Path,
    host: &str,
    uid: u32,
    id: &str,
    cutoff: Option<OffsetDateTime>,
) -> Result<(Option<Listing>, Option<String>), String> {
    let mut first_err = None;
    let mut newest: Option<(OffsetDateTime, Listing)> = None;
    for entry in snapshot::list(dir)?.into_iter().rev() {
        if cutoff.is_some_and(|c| entry.created > c.unix_timestamp()) {
            continue;
        }
        if newest
            .as_ref()
            .is_some_and(|(t, _)| entry.created < t.unix_timestamp())
        {
            break;
        }
        let s = match snapshot::load(&entry.path) {
            Ok(s) => s,
            Err(err) => {
                first_err.get_or_insert(err);
                continue;
            }
        };
        if s.host != host || s.uid != uid || (cutoff.is_some() && !s.scan.one_filesystem) {
            continue;
        }
        let Some(finding) = s.findings.iter().find(|f| f.id == id).cloned() else {
            continue;
        };
        let Ok(created) = OffsetDateTime::parse(&s.created_at, &Rfc3339) else {
            first_err.get_or_insert_with(|| {
                format!(
                    "{}: bad created_at {:?}",
                    entry.path.display(),
                    s.created_at
                )
            });
            continue;
        };
        if cutoff.is_none_or(|c| created <= c) && newest.as_ref().is_none_or(|(t, _)| created > *t)
        {
            newest = Some((
                created,
                Listing {
                    entry,
                    snapshot: s,
                    finding,
                },
            ));
        }
    }
    Ok((newest.map(|(_, listing)| listing), first_err))
}

/// Turns a finding id into its path: the newest snapshot of this host and
/// uid that lists it, and the finding's path there.
pub fn resolve_id(
    dir: &Path,
    host: &str,
    uid: u32,
    id: &str,
) -> Result<(ExplainSnapshot, SnapshotFinding), String> {
    match newest_listing(dir, host, uid, id, None).map_err(|e| format!("{e}; {PATH_HINT}"))? {
        (Some(found), _) => Ok((
            ExplainSnapshot {
                id: found.entry.id,
                path: found.entry.path.to_string_lossy().into_owned(),
                created_at: found.snapshot.created_at,
            },
            found.finding,
        )),
        (None, err) => {
            let mut msg = format!(
                "no snapshot lists finding {id}; {PATH_HINT}, \
                 or save snapshots with `dwhy scan --snapshot`"
            );
            if let Some(e) = err {
                msg.push_str(&format!(" (some could not be read: {e})"));
            }
            Err(msg)
        }
    }
}

/// The snapshot to measure a finding's growth from: the newest at least
/// [`crate::growth::MIN_AGE_SECS`] old at `now` that lists `id`, whatever
/// its roots, from snapshots that walked one filesystem. Best effort:
/// `None` when there is none or the directory cannot be read.
pub fn growth_base(dir: &Path, host: &str, uid: u32, id: &str, now: &str) -> Option<Snapshot> {
    let cutoff =
        OffsetDateTime::parse(now, &Rfc3339).ok()? - Duration::seconds(crate::growth::MIN_AGE_SECS);
    let (found, _) = newest_listing(dir, host, uid, id, Some(cutoff)).ok()?;
    Some(found?.snapshot)
}

/// `--detectors` for a `docker://` query: the Docker detectors, limited
/// to `only` when given.
pub fn docker_selection(only: Option<&[String]>) -> Vec<String> {
    CATALOG
        .iter()
        .filter(|d| d.needs == Needs::Docker && only.is_none_or(|o| o.iter().any(|n| n == d.name)))
        .map(|d| d.name.to_string())
        .collect()
}

pub fn exclude_lossy_paths(findings: &mut Vec<Finding>, tree: &ScanTree) {
    if !findings
        .iter()
        .any(|f| f.path.contains(char::REPLACEMENT_CHARACTER))
    {
        return;
    }
    let lossy: HashSet<PathBuf> = tree
        .ids()
        .filter(|&id| tree.name(id).to_str().is_none())
        .map(|id| PathBuf::from(tree.path(id).to_string_lossy().into_owned()))
        .collect();
    findings.retain(|f| !Path::new(&f.path).ancestors().any(|p| lossy.contains(p)));
}

/// Picks the finding explained from a rescan's `findings`: the one with
/// `id` when given, else the cheapest tier at `path`. When there is none,
/// also lists the findings at or below `path`, largest first.
pub fn pick(
    mut findings: Vec<Finding>,
    path: &str,
    id: Option<&str>,
) -> (Option<Finding>, Vec<FindingRef>) {
    let at = match id {
        Some(id) => findings.iter().position(|f| f.id == id && f.path == path),
        None => findings
            .iter()
            .enumerate()
            .filter(|(_, f)| f.path == path)
            .min_by(|(_, a), (_, b)| {
                a.tier
                    .cmp(&b.tier)
                    .then_with(|| a.detector.cmp(&b.detector))
            })
            .map(|(i, _)| i),
    };
    if let Some(i) = at {
        return (Some(findings.swap_remove(i)), Vec::new());
    }
    findings.retain(|f| within(&f.path, path));
    let inside = detect::outermost(findings)
        .iter()
        .map(finding_ref)
        .collect();
    (None, inside)
}

/// `p` is `root` or, both being absolute paths, lies below it.
fn within(p: &str, root: &str) -> bool {
    p == root || (root.starts_with('/') && p.starts_with('/') && Path::new(p).starts_with(root))
}

pub fn finding_ref(f: &Finding) -> FindingRef {
    FindingRef {
        id: f.id.clone(),
        path: f.path.clone(),
        detector: f.detector.clone(),
        bytes: f.bytes,
        tier: f.tier,
    }
}

/// Notes on the selected detectors that could not run or failed. `only`
/// is the selection passed to [`crate::detect::run_candidates`].
pub fn detector_notes(runs: &[DetectorRun], only: Option<&[String]>) -> Vec<String> {
    let selected = |r: &&DetectorRun| only.is_none_or(|o| o.contains(&r.name));
    let unavailable: Vec<&str> = runs
        .iter()
        .filter(selected)
        .filter(|r| !r.ran && r.status == DetectorAvailability::Unavailable)
        .map(|r| r.name.as_str())
        .collect();
    let mut notes: Vec<String> = runs
        .iter()
        .filter(selected)
        .filter_map(|r| Some(format!("{} failed: {}", r.name, r.error.as_ref()?)))
        .collect();
    if !unavailable.is_empty() {
        notes.push(format!(
            "not run: {} (see `dwhy doctor`)",
            unavailable.join(", ")
        ));
    }
    notes
}

pub fn detector_gap(runs: &[DetectorRun], only: Option<&[String]>, name: &str) -> Option<String> {
    if only.is_some_and(|o| !o.iter().any(|n| n == name)) {
        return Some(format!("detector {name} not selected by --detectors"));
    }
    match runs.iter().find(|r| r.name == name) {
        Some(r) if !r.ran => Some(format!("detector {name} did not run: {}", r.detail)),
        Some(r) => r
            .error
            .as_ref()
            .map(|e| format!("detector {name} failed: {e}")),
        None => Some(format!("detector {name} is unknown")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Action, ActionKind, Recovery, Tier};

    fn f(det: &str, path: &str, bytes: u64) -> Finding {
        Finding {
            id: crate::detect::finding_id(det, path),
            detector: det.into(),
            probe: None,
            evidence: None,
            path: path.into(),
            bytes,
            nested_bytes: None,
            last_modified: None,
            growth: None,
            tier: Tier::Rebuildable,
            reason: String::new(),
            guards: vec![],
            action: Action {
                kind: ActionKind::RemovePath,
                text: String::new(),
                argv: None,
            },
            recovery: Recovery {
                cost: String::new(),
                how: None,
            },
        }
    }

    #[test]
    fn classifies_ids_pseudo_paths_and_paths() {
        let id = crate::detect::finding_id("cargo-target", "/p/target");
        assert_eq!(classify(&id), Query::Id(id.clone()));
        assert_eq!(
            classify("f_0123456789ab"),
            Query::Id("f_0123456789ab".into())
        );
        let path = |p: &str| Query::Place(Place::Path(p.into()));
        // Only the exact format is an id: not shorter, longer, other
        // digits or upper case.
        for not_id in [
            "f_x",
            "f_zz",
            "f_",
            "f_0123456789a",
            "f_0123456789abc",
            "f_0123456789aG",
            "f_0123456789AB",
            "f_0123456789ab/",
            "F_0123456789ab",
        ] {
            assert_eq!(classify(not_id), path(not_id), "{not_id}");
        }
        // A path named like an id inside a directory is a path.
        assert_eq!(classify("dir/f_0123456789ab"), path("dir/f_0123456789ab"));
        assert_eq!(classify("./f_0123456789ab"), path("./f_0123456789ab"));
        assert_eq!(
            classify("docker://volume/pg"),
            Query::Place(Place::Docker("docker://volume/pg".into()))
        );
        assert_eq!(classify("./f_dir"), path("./f_dir"));
        assert_eq!(classify("app/target"), path("app/target"));
        assert_eq!(classify("/"), path("/"));
        assert_eq!(classify("F_abc"), path("F_abc"));
        // A path from a snapshot is never an id.
        assert_eq!(place("f_x"), Place::Path("f_x".into()));
    }

    #[test]
    fn classifies_non_utf8_as_a_native_path() {
        use std::os::unix::ffi::OsStrExt;
        for bytes in [b"f_0123456789a\xff".as_slice(), b"docker://volume/\xff"] {
            let arg = OsStr::from_bytes(bytes);
            assert_eq!(classify(arg), Query::Place(Place::Path(arg.into())));
        }
    }

    #[test]
    fn walks_the_parent_of_a_directory() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let dir = root.join("app");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(root.join("file"), b"x").unwrap();
        let mounts = MountTable::read().unwrap_or_default();
        assert_eq!(walk_for(&dir, &mounts), Walk::Parent(root.clone()));
        // A file, a missing path and / are walked themselves, with no note.
        assert_eq!(walk_for(&root.join("file"), &mounts), Walk::Itself(None));
        assert_eq!(walk_for(&root.join("nope"), &mounts), Walk::Itself(None));
        assert_eq!(
            walk_for(Path::new("/"), &MountTable::default()),
            Walk::Itself(None)
        );
    }

    #[test]
    fn walks_a_mount_point_itself_with_a_note() {
        let mounts = MountTable::read().unwrap_or_default();
        for is_dir in [true, false] {
            let Some(m) = mounts.mounts.iter().find(|m| {
                m.mount_point.starts_with("/dev/")
                    && std::fs::symlink_metadata(&m.mount_point)
                        .is_ok_and(|md| md.is_dir() == is_dir)
            }) else {
                continue;
            };
            assert_eq!(
                walk_for(&m.mount_point, &mounts),
                Walk::Itself(Some(format!(
                    "{} is a mount point; scanned it alone",
                    m.mount_point.display()
                )))
            );
        }
    }

    #[test]
    fn walks_the_path_itself_when_its_parent_cannot_be_opened() {
        use std::os::unix::fs::PermissionsExt;
        if crate::system::euid() == 0 {
            return;
        }
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            }
        }
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let parent = root.join("locked");
        std::fs::create_dir_all(parent.join("app")).unwrap();
        // Searchable, not readable: the path can be statted, its parent not listed.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o311)).unwrap();
        let _restore = Restore(parent.clone());
        let Walk::Itself(Some(note)) =
            walk_for(&parent.join("app"), &MountTable::read().unwrap_or_default())
        else {
            panic!("the parent cannot be opened");
        };
        assert!(note.contains("cannot open its parent"), "{note}");
    }

    #[test]
    fn picks_the_finding_at_the_path_or_lists_those_inside() {
        let all = || {
            vec![
                f("venv", "/p/app/.venv", 30),
                f("cargo-target", "/p/app/target", 20),
                f("cargo-target", "/p/apple/target", 10),
                f("docker-volume", "docker://volume/v", 5),
            ]
        };
        let (got, inside) = pick(all(), "/p/app/target", None);
        assert_eq!(got.unwrap().path, "/p/app/target");
        assert!(inside.is_empty());

        let (got, inside) = pick(all(), "/p/app", None);
        assert!(got.is_none());
        let paths: Vec<&str> = inside.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/p/app/.venv", "/p/app/target"], "not /p/apple");
        assert_eq!(
            inside[1].id,
            crate::detect::finding_id("cargo-target", "/p/app/target")
        );
        assert_eq!(inside[1].bytes, 20);

        // By id: another detector's finding at the same path does not count.
        let id = crate::detect::finding_id("node-modules", "/p/app/target");
        let (got, inside) = pick(all(), "/p/app/target", Some(&id));
        assert!(got.is_none());
        assert_eq!(inside.len(), 1, "what is at the path now");

        let (got, _) = pick(all(), "docker://volume/v", None);
        assert_eq!(got.unwrap().detector, "docker-volume");
        let (got, inside) = pick(all(), "docker://volume/w", None);
        assert!(got.is_none() && inside.is_empty());

        let nested = vec![
            f("stale-tree", "/p/app/scratch", 100),
            f("stale-tree", "/p/app/scratch/child", 50),
        ];
        let (got, inside) = pick(nested, "/p/app", None);
        assert!(got.is_none());
        assert_eq!(inside.len(), 1);
        assert_eq!(inside[0].path, "/p/app/scratch");

        let nested = vec![
            f("stale-tree", "/p", 100),
            f("stale-tree", "/p/app/scratch", 50),
            f("stale-tree", "/p/app/scratch/child", 10),
        ];
        let (got, inside) = pick(nested, "/p/app", None);
        assert!(got.is_none());
        assert_eq!(inside.len(), 1);
        assert_eq!(inside[0].path, "/p/app/scratch");
    }

    #[test]
    fn docker_selection_intersects_with_detectors() {
        assert_eq!(
            docker_selection(None),
            [
                "docker-image",
                "docker-build-cache",
                "docker-container",
                "docker-volume"
            ]
        );
        let only = vec!["cargo-target".to_string(), "docker-volume".to_string()];
        assert_eq!(docker_selection(Some(&only)), ["docker-volume"]);
        assert!(docker_selection(Some(&only[..1])).is_empty());
    }

    #[test]
    fn notes_name_selected_detectors_that_did_not_run() {
        let run = |name: &str, ran: bool, status, error: Option<&str>| DetectorRun {
            name: name.into(),
            status,
            detail: String::new(),
            ran,
            findings: 0,
            elapsed_ms: 0,
            error: error.map(String::from),
        };
        let runs = vec![
            run("cargo-target", true, DetectorAvailability::Available, None),
            run(
                "git-worktree",
                false,
                DetectorAvailability::Unavailable,
                None,
            ),
            run(
                "docker-image",
                true,
                DetectorAvailability::Available,
                Some("no answer"),
            ),
            run(
                "journald",
                false,
                DetectorAvailability::NotImplemented,
                None,
            ),
        ];
        assert_eq!(
            detector_notes(&runs, None),
            [
                "docker-image failed: no answer",
                "not run: git-worktree (see `dwhy doctor`)"
            ]
        );
        let only = vec!["cargo-target".to_string()];
        assert!(detector_notes(&runs, Some(&only)).is_empty());
        assert_eq!(detector_gap(&runs, Some(&only), "cargo-target"), None);
        assert_eq!(
            detector_gap(&runs, Some(&only), "docker-image").as_deref(),
            Some("detector docker-image not selected by --detectors")
        );
        assert_eq!(
            detector_gap(&runs, None, "docker-image").as_deref(),
            Some("detector docker-image failed: no answer")
        );
    }
}
