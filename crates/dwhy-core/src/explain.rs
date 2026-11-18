//! `dwhy explain` (docs/DESIGN.md, Explain): what the argument names, how
//! a finding id becomes a path through the saved snapshots, what is walked
//! for a path, and which finding of the rescan is the one explained. The
//! CLI rescans, runs the detectors, the probes and the guards; nothing here
//! writes.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::mounts::MountTable;
use crate::report::{DetectorAvailability, DetectorRun, Finding, FindingRef};
use crate::snapshot::{self, Found};

/// The detectors a `docker://` pseudo-path can come from.
pub const DOCKER_DETECTORS: &[&str] = &[
    "docker-image",
    "docker-build-cache",
    "docker-container",
    "docker-volume",
];

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

/// Whether `arg` is taken as a finding id: exactly the format of
/// [`crate::detect::finding_id`], `f_` and as many lowercase hex digits.
/// Anything else is a path; a file named like an id can be given as `./f_…`.
pub fn is_finding_id(arg: &str) -> bool {
    let len = crate::detect::finding_id("", "").len();
    arg.len() == len
        && arg.strip_prefix("f_").is_some_and(|hex| {
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub fn classify(arg: &str) -> Query {
    if is_finding_id(arg) {
        Query::Id(arg.to_string())
    } else {
        Query::Place(place(arg))
    }
}

/// A finding's path (as a snapshot records it) or a path argument.
pub fn place(path: &str) -> Place {
    if path.starts_with("docker://") {
        Place::Docker(path.to_string())
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
/// canonical (as [`crate::scan::prepare_roots`] makes it). The path itself
/// when it is `/` or has no parent, is not a directory (no detector reports
/// a file, and the parent's tree has no node for one), is a mount point
/// (its parent is on another filesystem, or it is a bind mount, which the
/// walk would not enter), or its parent cannot be opened.
pub fn walk_for(abs: &Path, mounts: &MountTable) -> Walk {
    let Ok(md) = std::fs::symlink_metadata(abs) else {
        // The scan of the path reports the error.
        return Walk::Itself(None);
    };
    let Some(parent) = abs.parent().filter(|_| md.is_dir()) else {
        return Walk::Itself(None);
    };
    let alone = |why: String| {
        Walk::Itself(Some(format!(
            "{why}: scanned {} alone, so detectors that recognise it from its parent may miss it",
            abs.display()
        )))
    };
    let open = std::fs::symlink_metadata(parent).and_then(|pmd| {
        std::fs::read_dir(parent)?;
        Ok(pmd)
    });
    match open {
        Ok(pmd) if pmd.dev() != md.dev() || mounts.at(abs).is_some() => alone(format!(
            "{} is a mount point and its parent is another filesystem",
            abs.display()
        )),
        Ok(_) => Walk::Parent(parent.to_path_buf()),
        Err(e) => alone(format!("cannot open its parent {}: {e}", parent.display())),
    }
}

/// The newest snapshot in `dir` of `host` and `uid`, created at or before
/// `cutoff` (seconds since the epoch), whose findings include `id`, whatever
/// its roots. Snapshots that cannot be read are skipped; the first such
/// error comes back alongside.
fn newest_listing(
    dir: &Path,
    host: &str,
    uid: u32,
    id: &str,
    cutoff: i64,
) -> Result<(Option<Found>, Option<String>), String> {
    let mut first_err = None;
    for e in snapshot::list(dir)?.iter().rev() {
        if e.created > cutoff {
            continue;
        }
        let s = match snapshot::load(&e.path) {
            Ok(s) => s,
            Err(err) => {
                first_err.get_or_insert(err);
                continue;
            }
        };
        if s.host == host && s.uid == uid && s.findings.iter().any(|f| f.id == id) {
            let found = Found {
                id: Some(e.id.clone()),
                path: e.path.clone(),
                snapshot: s,
            };
            return Ok((Some(found), first_err));
        }
    }
    Ok((None, first_err))
}

/// Turns a finding id into its path: the newest snapshot of this host and
/// uid that lists it, and the finding's path there.
pub fn resolve_id(dir: &Path, host: &str, uid: u32, id: &str) -> Result<(Found, String), String> {
    match newest_listing(dir, host, uid, id, i64::MAX)? {
        (Some(found), _) => {
            let path = found
                .snapshot
                .findings
                .iter()
                .find(|f| f.id == id)
                .map(|f| f.path.clone())
                .unwrap_or_default();
            Ok((found, path))
        }
        (None, err) => {
            let mut msg = format!(
                "no snapshot lists finding {id}; run `dwhy explain <path>` with its path, \
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
/// its roots (a finding's bytes do not depend on the scan root). Best
/// effort: `None` when there is none or the directory cannot be read.
pub fn growth_base(dir: &Path, host: &str, uid: u32, id: &str, now: i64) -> Option<Found> {
    newest_listing(dir, host, uid, id, now - crate::growth::MIN_AGE_SECS)
        .ok()?
        .0
}

/// `--detectors` for a `docker://` query: the Docker detectors, limited
/// to `only` when given.
pub fn docker_selection(only: Option<&[String]>) -> Vec<String> {
    DOCKER_DETECTORS
        .iter()
        .filter(|d| only.is_none_or(|o| o.iter().any(|n| n == *d)))
        .map(|d| d.to_string())
        .collect()
}

/// Picks the finding explained from a rescan's `findings`: the one with
/// `id` when given, else the first (largest) at `path`. When there is none,
/// also lists the findings at or below `path`, largest first.
pub fn pick(
    mut findings: Vec<Finding>,
    path: &str,
    id: Option<&str>,
) -> (Option<Finding>, Vec<FindingRef>) {
    let at = findings.iter().position(|f| match id {
        Some(id) => f.id == id,
        None => f.path == path,
    });
    if let Some(i) = at {
        return (Some(findings.swap_remove(i)), Vec::new());
    }
    let inside = findings
        .iter()
        .filter(|f| within(&f.path, path))
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
/// is the selection passed to [`crate::detect::run_with`].
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
        assert_eq!(walk_for(Path::new("/"), &mounts), Walk::Itself(None));
    }

    #[test]
    fn walks_a_mount_point_itself_with_a_note() {
        let mounts = MountTable::read().unwrap_or_default();
        let Some(m) = mounts.mounts.iter().find(|m| {
            m.mount_point.starts_with("/dev/")
                && std::fs::symlink_metadata(&m.mount_point).is_ok_and(|md| md.is_dir())
        }) else {
            return;
        };
        let Walk::Itself(Some(note)) = walk_for(&m.mount_point, &mounts) else {
            panic!("{} is a mount point", m.mount_point.display());
        };
        assert!(note.contains("is a mount point"), "{note}");
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
    }

    #[test]
    fn docker_selection_intersects_with_detectors() {
        assert_eq!(docker_selection(None).len(), 4);
        let only = vec!["cargo-target".to_string(), "docker-volume".to_string()];
        assert_eq!(docker_selection(Some(&only)), ["docker-volume"]);
        assert!(docker_selection(Some(&only[..1])).is_empty());
        let names: Vec<String> = DOCKER_DETECTORS.iter().map(|d| d.to_string()).collect();
        assert!(crate::detect::validate_selection(&names).is_ok());
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
    }
}
