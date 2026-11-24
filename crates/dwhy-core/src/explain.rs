//! `dwhy explain` (docs/DESIGN.md, Explain): what the argument names, how
//! a finding id becomes a path through the saved snapshots, what is walked
//! for a path, and which finding of the rescan is the one explained. The
//! CLI rescans, runs the detectors, the probes and the guards; nothing here
//! writes.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::detect::{self, CATALOG, Needs};
use crate::detectors::DockerPresence;
use crate::docker;
use crate::mounts::MountTable;
use crate::report::{
    DetectorAvailability, DetectorRun, ExplainSnapshot, Finding, FindingRef, Snapshot,
    SnapshotFinding,
};
use crate::snapshot::{self, Entry};
use crate::tree::ScanTree;

pub const PATH_HINT: &str = "run `dwhy explain <path>` with its path";

/// How a note on withheld growth starts when the daemon did not give what
/// confirms a volume's identity.
pub const GROWTH_OMITTED: &str = "growth omitted: ";
/// How a note on withheld growth starts when the snapshot recorded a
/// different object at the finding's pseudo-path.
pub const GROWTH_NOT_COMPUTED: &str = "growth not computed: ";

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

/// What an argument names. The CLI refuses arguments that are not UTF-8
/// before asking.
pub fn classify(arg: &str) -> Query {
    if is_finding_id(arg) {
        Query::Id(arg.to_owned())
    } else {
        Query::Place(place(arg))
    }
}

/// A finding's path (as a snapshot records it) or a path argument.
pub fn place(path: &str) -> Place {
    if path.starts_with("docker://") {
        Place::Docker(path.to_owned())
    } else {
        Place::Path(PathBuf::from(path))
    }
}

/// What explain walks for a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Walk {
    /// A directory above the path, so that detectors which recognise it
    /// from around it see that context: its parent, one level up (a
    /// `target/` next to its `Cargo.toml`, a project's `node_modules`), or
    /// a context root farther up that holds it (a `tool-versions` version
    /// directory such as `~/.vscode-server`). `note` says why a context
    /// root that holds the path could not be walked.
    Above { dir: PathBuf, note: Option<String> },
    /// The path itself, with a note when that is because the directory
    /// above could not be used.
    Itself(Option<String>),
}

/// Decides what to walk for `abs`, an absolute path whose parent is
/// canonical (as [`crate::scan::prepare_roots`] makes it). `context` lists
/// directories detectors read a path's context from, each with how many
/// levels below it that context reaches
/// ([`crate::detectors::ToolVersions::context_roots`]).
///
/// A path that lies within reach of a context root is walked from there,
/// file or directory, when every directory from the path up to that root
/// is a real directory on the path's filesystem, none of those between is
/// a mount point, and the root can be opened. Otherwise a directory's
/// parent is walked, and a file is walked on its own: walking its parent
/// would find no context for it. Walking a mount point's parent could skip
/// the query at the filesystem boundary.
pub fn walk_for(abs: &Path, mounts: &MountTable, context: &[(PathBuf, usize)]) -> Walk {
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
    let mut context_note = None;
    if let Some(root) = context_root(abs, context) {
        match usable_context(abs, md.dev(), root, mounts) {
            Ok(()) => {
                return Walk::Above {
                    dir: root.to_path_buf(),
                    note: None,
                };
            }
            Err(reason) => {
                context_note = Some(format!(
                    "could not walk its context from {}: {reason}",
                    root.display()
                ));
            }
        }
    }
    let itself = |note: Option<String>| {
        Walk::Itself(match (&context_note, note) {
            (Some(c), Some(n)) => Some(format!("{c}; {n}")),
            (c, n) => n.or_else(|| c.clone()),
        })
    };
    let Some(parent) = abs.parent() else {
        return itself(None);
    };
    let parent_md = std::fs::symlink_metadata(parent);
    if parent_md.as_ref().is_ok_and(|pmd| pmd.dev() != md.dev()) {
        return itself(Some(format!(
            "{} is a mount point and its parent is on another filesystem; scanned it alone",
            abs.display()
        )));
    }
    if !md.is_dir() {
        return itself(None);
    }
    match parent_md.and_then(|_| std::fs::read_dir(parent)) {
        Ok(_) => Walk::Above {
            dir: parent.to_path_buf(),
            note: context_note,
        },
        Err(e) => itself(Some(format!(
            "cannot open its parent {}: {e}; scanned {} alone",
            parent.display(),
            abs.display()
        ))),
    }
}

/// The deepest context root that holds `abs` strictly below it, within
/// its reach.
fn context_root<'a>(abs: &Path, context: &'a [(PathBuf, usize)]) -> Option<&'a Path> {
    context
        .iter()
        .filter(|(root, reach)| {
            abs.strip_prefix(root)
                .is_ok_and(|rest| (1..=*reach).contains(&rest.components().count()))
        })
        .map(|(root, _)| root.as_path())
        .max_by_key(|root| root.components().count())
}

/// Whether the walk can start at `root` and still reach `abs` (on device
/// `dev`): every directory from `abs`'s parent up to `root` is a directory
/// (not a symlink) on that device, none below `root` is a mount point, and
/// `root` can be opened.
fn usable_context(abs: &Path, dev: u64, root: &Path, mounts: &MountTable) -> Result<(), String> {
    for dir in abs.ancestors().skip(1) {
        let md = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if !md.is_dir() {
            return Err(format!("{} is not a directory", dir.display()));
        }
        if md.dev() != dev {
            return Err(format!(
                "{} is on another filesystem than {}",
                dir.display(),
                abs.display()
            ));
        }
        if dir == root {
            break;
        }
        if mounts.at(dir).is_some() {
            return Err(format!("{} is a mount point", dir.display()));
        }
    }
    std::fs::read_dir(root)
        .map(|_| ())
        .map_err(|e| format!("cannot open it: {e}"))
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

/// A finding id turned into its path by [`resolve_id`].
#[derive(Debug, Clone)]
pub struct Resolved {
    pub snapshot: ExplainSnapshot,
    pub finding: SnapshotFinding,
    /// The Docker object the snapshot recorded at the finding's pseudo-path.
    /// `None` for filesystem paths, build cache, and snapshots without the
    /// object's id.
    pub docker: Option<SavedObject>,
}

/// Turns a finding id into its path: the newest snapshot of this host and
/// uid that lists it, and the finding's path there. A saved path with
/// U+FFFD is refused: v1 snapshots store a non-UTF-8 path that way, so it
/// could name another file.
pub fn resolve_id(dir: &Path, host: &str, uid: u32, id: &str) -> Result<Resolved, String> {
    match newest_listing(dir, host, uid, id, None).map_err(|e| format!("{e}; {PATH_HINT}"))? {
        (Some(found), _) => {
            if found.finding.path.contains(char::REPLACEMENT_CHARACTER) {
                return Err(format!(
                    "the saved path for {id} contains U+FFFD, which v1 snapshots also write in place \
                     of bytes that are not UTF-8, so it can't be checked reliably; if the name \
                     really contains U+FFFD, run `dwhy explain <path>` with that path; otherwise \
                     explain can't take the path (it needs UTF-8): explain its parent directory, \
                     or rename it to valid UTF-8"
                ));
            }
            Ok(Resolved {
                docker: saved_object(&found.snapshot, &found.finding.path),
                snapshot: ExplainSnapshot {
                    id: found.entry.id,
                    path: found.entry.path.to_string_lossy().into_owned(),
                    created_at: found.snapshot.created_at,
                },
                finding: found.finding,
            })
        }
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

/// The kinds of Docker object a finding can name, other than build cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerKind {
    Image,
    Container,
    Volume,
}

impl DockerKind {
    fn prefix(self) -> &'static str {
        match self {
            DockerKind::Image => "docker://image/",
            DockerKind::Container => "docker://container/",
            DockerKind::Volume => "docker://volume/",
        }
    }

    fn word(self) -> &'static str {
        match self {
            DockerKind::Image => "image",
            DockerKind::Container => "container",
            DockerKind::Volume => "volume",
        }
    }
}

/// The kind and name (image label, container or volume name) a Docker
/// pseudo-path names; `None` for build cache and other paths.
pub fn docker_kind(path: &str) -> Option<(DockerKind, &str)> {
    [DockerKind::Image, DockerKind::Container, DockerKind::Volume]
        .into_iter()
        .find_map(|k| Some((k, path.strip_prefix(k.prefix())?)))
}

/// The Docker object a snapshot recorded at a pseudo-path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedObject {
    pub kind: DockerKind,
    /// The image label, or the container or volume name, in the pseudo-path.
    pub name: String,
    /// The immutable id: the image or container id, or a volume's creation
    /// time (a volume has none; a volume recreated under its name is
    /// created again).
    pub id: String,
}

/// The object `snap` recorded at the Docker pseudo-path `path`, the way
/// the detectors name it. `None` when the snapshot has no Docker figures,
/// or (for volumes) no creation times.
pub fn saved_object(snap: &Snapshot, path: &str) -> Option<SavedObject> {
    let (kind, name) = docker_kind(path)?;
    let docker = snap.docker.as_ref()?;
    let id = match kind {
        DockerKind::Image => docker
            .images
            .iter()
            .find(|i| crate::detectors::image_label_from_tags(&i.tags, &i.id) == name)
            .map(|i| i.id.clone()),
        DockerKind::Container => docker
            .containers
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.id.clone()),
        DockerKind::Volume => docker
            .volumes
            .iter()
            .find(|v| v.name == name)
            .and_then(|v| v.created_at.as_ref())
            .filter(|time| !time.is_empty())
            .cloned(),
    }?;
    Some(SavedObject {
        kind,
        name: name.to_string(),
        id,
    })
}

/// What the daemon lists now for a [`SavedObject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// `path` is the listed object's current pseudo-path. A volume can be
    /// present by name alone if the daemon omitted its creation time.
    /// `measured` is false when the daemon gave no size for it.
    Present { path: String, measured: bool },
    /// The saved id is not listed, but its name now names another object:
    /// its short id (a volume's creation time) and the pseudo-path the
    /// detectors give it, which for an image matched by a later tag is
    /// its first tag.
    Replaced {
        replacement_id: String,
        replacement_path: String,
    },
    /// Neither the id nor the name is listed.
    Gone,
    /// The daemon did not report the list to look in.
    Unknown,
}

/// Checks the daemon's lists for the saved object or a replacement.
pub fn identity(saved: &SavedObject, now: &docker::Snapshot) -> Identity {
    use crate::detectors::{container_name, image_label, image_named, short_id};
    let at = |name: String| format!("{}{name}", saved.kind.prefix());
    match saved.kind {
        DockerKind::Image => {
            let Some(images) = now.df.images.as_ref() else {
                return Identity::Unknown;
            };
            if let Some(img) = images.iter().find(|i| i.id == saved.id) {
                Identity::Present {
                    path: at(image_label(img)),
                    measured: img.size >= 0,
                }
            } else if let Some(img) = images.iter().find(|i| image_named(i, &saved.name)) {
                Identity::Replaced {
                    replacement_id: short_id(&img.id),
                    replacement_path: at(image_label(img)),
                }
            } else {
                Identity::Gone
            }
        }
        DockerKind::Container => {
            let Some(containers) = now.df.containers.as_ref() else {
                return Identity::Unknown;
            };
            if let Some(c) = containers.iter().find(|c| c.id == saved.id) {
                Identity::Present {
                    path: at(container_name(c)),
                    measured: c.size_rw.is_some_and(|s| s >= 0),
                }
            } else if let Some(c) = containers.iter().find(|c| container_name(c) == saved.name) {
                Identity::Replaced {
                    replacement_id: short_id(&c.id),
                    replacement_path: at(container_name(c)),
                }
            } else {
                Identity::Gone
            }
        }
        DockerKind::Volume => {
            let Some(volumes) = now.df.volumes.as_ref() else {
                return Identity::Unknown;
            };
            match volumes.iter().find(|v| v.name == saved.name) {
                Some(v)
                    if !saved.id.is_empty()
                        && !v.created_at.is_empty()
                        && v.created_at != saved.id =>
                {
                    Identity::Replaced {
                        replacement_id: v.created_at.clone(),
                        replacement_path: at(v.name.clone()),
                    }
                }
                Some(v) => Identity::Present {
                    path: at(v.name.clone()),
                    measured: v.usage_data.as_ref().is_some_and(|u| u.size >= 0),
                },
                None => Identity::Gone,
            }
        }
    }
}

/// The immutable id the daemon lists now at a Docker pseudo-path, in
/// [`SavedObject::id`]'s terms: the image or container id, or a volume's
/// creation time. `None` when nothing is listed there or a volume's
/// creation time is missing.
fn live_id(now: &docker::Snapshot, path: &str) -> Option<String> {
    use crate::detectors::{container_name, image_label};
    let (kind, name) = docker_kind(path)?;
    match kind {
        DockerKind::Image => now
            .images()
            .iter()
            .find(|i| image_label(i) == name)
            .map(|i| i.id.clone()),
        DockerKind::Container => now
            .containers()
            .iter()
            .find(|c| container_name(c) == name)
            .map(|c| c.id.clone()),
        DockerKind::Volume => now
            .volumes()
            .iter()
            .find(|v| v.name == name)
            .map(|v| v.created_at.clone())
            .filter(|time| !time.is_empty()),
    }
}

/// Fills growth for a selected finding, or returns a note when Docker
/// identity prevents the comparison. `explained` is the object the
/// snapshot that resolved an id recorded ([`Resolved::docker`]).
///
/// Growth is withheld when the growth baseline recorded a different object
/// at the finding's pseudo-path than the daemon lists there now (a
/// container renamed away and another given its name, a tag moved to
/// another image, a volume recreated). A volume is checked by creation
/// time: when the explained object or the baseline recorded one but the
/// daemon omits it now, its identity can't be confirmed. Snapshots without
/// volume creation times compare by name.
pub fn fill_growth(
    finding: &mut Finding,
    base: Option<&Snapshot>,
    now: &str,
    daemon: Option<&docker::Snapshot>,
    explained: Option<&SavedObject>,
) -> Option<String> {
    let baseline = base.and_then(|b| saved_object(b, &finding.path));
    if let Some((DockerKind::Volume, name)) = docker_kind(&finding.path)
        && (explained.is_some_and(|o| o.kind == DockerKind::Volume) || baseline.is_some())
        && daemon.is_some_and(|d| {
            d.volumes()
                .iter()
                .any(|v| v.name == name && v.created_at.is_empty())
        })
    {
        return Some(format!(
            "{GROWTH_OMITTED}the daemon did not report this volume's creation time, so its identity can't be confirmed"
        ));
    }
    let base = base?;
    if let (Some(old), Some(d)) = (&baseline, daemon) {
        let different = live_id(d, &finding.path).is_some_and(|id| id != old.id)
            || match identity(old, d) {
                Identity::Replaced { .. } => true,
                Identity::Present { path, .. } => path != finding.path,
                Identity::Gone | Identity::Unknown => false,
            };
        if different {
            return Some(format!(
                "{GROWTH_NOT_COMPUTED}{} {} was a different object in the snapshot of {}",
                old.kind.word(),
                old.name,
                base.created_at
            ));
        }
    }
    crate::growth::fill_growth(std::slice::from_mut(finding), base, now);
    None
}

/// The reason growth was withheld, from one of [`fill_growth`]'s notes:
/// what follows [`GROWTH_OMITTED`] or [`GROWTH_NOT_COMPUTED`].
pub fn withheld_growth(note: &str) -> Option<&str> {
    note.strip_prefix(GROWTH_OMITTED)
        .or_else(|| note.strip_prefix(GROWTH_NOT_COMPUTED))
}

/// The outcome of explaining a saved id whose path is a Docker pseudo-path.
#[derive(Debug, Clone, Default)]
pub struct DockerExplained {
    /// The pseudo-path examined: the object's current one when renamed.
    pub path: String,
    pub finding: Option<Finding>,
    pub inside: Vec<FindingRef>,
    pub gone: bool,
    pub notes: Vec<String>,
}

/// Explains the saved finding `saved` at a Docker pseudo-path from the
/// Docker detectors' `findings` and the daemon's lists `now` (`None` when
/// the daemon did not answer or was not asked). `object` is what the
/// snapshot recorded there ([`Resolved::docker`]). `detector_issue` is the
/// saved detector's gap, as [`detector_gap`] gives it.
pub fn explain_docker_id(
    saved: &SnapshotFinding,
    object: Option<&SavedObject>,
    now: Option<&docker::Snapshot>,
    findings: Vec<Finding>,
    detector_issue: Option<String>,
) -> DockerExplained {
    let mut out = DockerExplained {
        path: saved.path.clone(),
        ..Default::default()
    };
    let identity = match (object, now) {
        (Some(object), Some(now)) => identity(object, now),
        _ => Identity::Unknown,
    };
    if object.is_none() && now.is_some() && docker_kind(&saved.path).is_some() {
        out.notes
            .push("identity not checked: the snapshot has no Docker ids".into());
    }
    match identity {
        Identity::Present { path, measured } => {
            if path != saved.path {
                let (_, name) = docker_kind(&path).unwrap_or((DockerKind::Image, &path));
                out.notes.push(format!("renamed: now {name}"));
            }
            let id = detect::finding_id(&saved.detector, &path);
            (out.finding, out.inside) = pick(findings, &path, Some(&id));
            if out.finding.is_none() {
                let size_issue =
                    (!measured).then(|| "the Docker daemon did not report a size".to_string());
                absence(
                    &path,
                    Ok(true),
                    detector_issue,
                    None,
                    size_issue,
                    &mut out.notes,
                );
            }
            out.path = path;
        }
        Identity::Replaced {
            replacement_id,
            replacement_path,
        } => {
            out.gone = true;
            out.notes.push(format!(
                "{} now belongs to a different object (id {replacement_id}); the saved finding's \
                 object is no longer listed. Run `dwhy explain {replacement_path}` to see the current one.",
                saved.path
            ));
        }
        Identity::Gone => {
            out.gone = absence(&saved.path, Ok(false), None, None, None, &mut out.notes);
        }
        // Today's name match: the snapshot has no id, the list is missing
        // or the daemon did not answer.
        Identity::Unknown => {
            (out.finding, out.inside) = pick(findings, &saved.path, Some(&saved.id));
            if out.finding.is_none() {
                let (exists, size_issue) = match now {
                    Some(now) => match crate::detectors::docker_presence(now, &saved.path) {
                        Some(DockerPresence::Missing) => (Ok(false), None),
                        Some(DockerPresence::Present) => (Ok(true), None),
                        Some(DockerPresence::Unmeasured) => (
                            Ok(true),
                            Some("the Docker daemon did not report a size".to_string()),
                        ),
                        None => (
                            Err("the Docker daemon did not report the relevant list".to_string()),
                            None,
                        ),
                    },
                    None => (
                        Err(detector_issue
                            .clone()
                            .unwrap_or_else(|| "no answer from the Docker daemon".into())),
                        None,
                    ),
                };
                out.gone = absence(
                    &saved.path,
                    exists,
                    detector_issue,
                    None,
                    size_issue,
                    &mut out.notes,
                );
            }
        }
    }
    out
}

/// Notes on an unmatched saved id from whether its path exists (`Err`
/// when that could not be checked). Returns whether it is gone.
pub fn absence(
    path: &str,
    exists: Result<bool, String>,
    detector_issue: Option<String>,
    scan_issue: Option<String>,
    size_issue: Option<String>,
    notes: &mut Vec<String>,
) -> bool {
    match exists {
        Ok(false) => {
            notes.push(format!("{path} no longer exists"));
            true
        }
        Ok(true) => {
            notes.push(format!("still present at {path}, but not detected now"));
            if detector_issue.is_none() && scan_issue.is_none() && size_issue.is_none() {
                notes.push("it may be below the detector's size or age threshold, covered by a finding above it, or need context above the walked directory".into());
            }
            notes.extend(detector_issue);
            notes.extend(scan_issue);
            notes.extend(size_issue);
            false
        }
        Err(reason) => {
            notes.push(format!("could not check: {reason}"));
            false
        }
    }
}

/// `--detectors` for a `docker://` query: the Docker detectors, limited
/// to `only` when given.
pub fn docker_selection(only: Option<&[String]>) -> Vec<String> {
    selection(only, |needs| needs == Needs::Docker)
}

/// `--detectors` for a filesystem path: every detector but Docker's,
/// limited to `only` when given. Docker detectors never claim a filesystem
/// path, so the daemon is not asked.
pub fn filesystem_selection(only: Option<&[String]>) -> Vec<String> {
    selection(only, |needs| needs != Needs::Docker)
}

fn selection(only: Option<&[String]>, keep: impl Fn(Needs) -> bool) -> Vec<String> {
    CATALOG
        .iter()
        .filter(|d| keep(d.needs) && only.is_none_or(|o| o.iter().any(|n| n == d.name)))
        .map(|d| d.name.to_string())
        .collect()
}

/// Drops findings whose path is a lossy spelling of a name in `tree`, so a
/// query for a real path spelled with U+FFFD is never answered with a
/// different directory's finding. Detection already blocks such findings
/// (`detect::block_lossy`); this is about which finding a path names, not
/// about what may run.
pub fn exclude_lossy_paths(findings: &mut Vec<Finding>, tree: &ScanTree) {
    let lossy = lossy_finding_paths(findings, tree);
    findings.retain(|f| !lossy.contains(&f.path));
}

pub fn lossy_finding_paths(findings: &[Finding], tree: &ScanTree) -> HashSet<String> {
    if !findings
        .iter()
        .any(|f| f.path.contains(char::REPLACEMENT_CHARACTER))
    {
        return HashSet::new();
    }
    let lossy: HashSet<PathBuf> = tree
        .ids()
        .filter(|&id| tree.name(id).to_str().is_none())
        .map(|id| PathBuf::from(tree.path(id).to_string_lossy().into_owned()))
        .collect();
    findings
        .iter()
        .filter(|f| Path::new(&f.path).ancestors().any(|p| lossy.contains(p)))
        .map(|f| f.path.clone())
        .collect()
}

/// Picks the finding explained from a rescan's `findings`: the one with
/// `id` when given, else the cheapest tier at `path`. When there is none,
/// also lists the findings below `path`, largest first. A finding at `path`
/// itself (another detector's, when `id` names a different one) is not
/// inside it.
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
            .min_by(|(_, a), (_, b)| detect::compare_priority(a, b))
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

/// Both being absolute paths, `p` lies strictly below `root`.
fn within(p: &str, root: &str) -> bool {
    root.starts_with('/')
        && p.starts_with('/')
        && Path::new(p) != Path::new(root)
        && Path::new(p).starts_with(root)
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
            file_identity: None,
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
        assert_eq!(
            walk_for(&dir, &mounts, &[]),
            Walk::Above {
                dir: root.clone(),
                note: None
            }
        );
        // A file, a missing path and / are walked themselves, with no note.
        assert_eq!(
            walk_for(&root.join("file"), &mounts, &[]),
            Walk::Itself(None)
        );
        assert_eq!(
            walk_for(&root.join("nope"), &mounts, &[]),
            Walk::Itself(None)
        );
        assert_eq!(
            walk_for(Path::new("/"), &MountTable::default(), &[]),
            Walk::Itself(None)
        );
    }

    #[test]
    fn walks_from_a_context_root_that_holds_the_path() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let vscode = root.join(".vscode-server");
        let server = vscode.join("cli/servers/Stable-abc");
        let legacy = vscode.join("bin/abc");
        std::fs::create_dir_all(&server).unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(vscode.join("code-abc"), b"x").unwrap();
        std::fs::create_dir_all(server.join("server")).unwrap();
        std::fs::write(server.join("server/deep-file"), b"x").unwrap();
        let claude = root.join("share/claude/versions");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(claude.join("2.1.0"), b"x").unwrap();
        let context = vec![(vscode.clone(), 3), (claude.clone(), 1)];
        let mounts = MountTable::read().unwrap_or_default();
        let above = |dir: &Path| Walk::Above {
            dir: dir.to_path_buf(),
            note: None,
        };
        // Versions further down, files included, are walked from the root.
        assert_eq!(walk_for(&server, &mounts, &context), above(&vscode));
        assert_eq!(walk_for(&legacy, &mounts, &context), above(&vscode));
        assert_eq!(
            walk_for(&vscode.join("code-abc"), &mounts, &context),
            above(&vscode)
        );
        assert_eq!(
            walk_for(&claude.join("2.1.0"), &mounts, &context),
            above(&claude)
        );
        // Out of reach, or the root itself: the usual rules.
        assert_eq!(
            walk_for(&server.join("server/deep-file"), &mounts, &context),
            Walk::Itself(None)
        );
        assert_eq!(
            walk_for(&vscode, &mounts, &context),
            above(&root),
            "the root itself is walked from its parent"
        );
    }

    #[test]
    fn falls_back_with_a_note_when_the_context_root_cannot_be_walked() {
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
        let vscode = root.join(".vscode-server");
        let servers = vscode.join("cli/servers");
        std::fs::create_dir_all(servers.join("Stable-abc")).unwrap();
        std::fs::write(vscode.join("code-abc"), b"x").unwrap();
        // Searchable, not readable: paths below can be statted, the root not listed.
        std::fs::set_permissions(&vscode, std::fs::Permissions::from_mode(0o311)).unwrap();
        let _restore = Restore(vscode.clone());
        let context = vec![(vscode.clone(), 3)];
        let mounts = MountTable::read().unwrap_or_default();
        let Walk::Above {
            dir,
            note: Some(note),
        } = walk_for(&servers.join("Stable-abc"), &mounts, &context)
        else {
            panic!("the parent is walked, with a note");
        };
        assert_eq!(dir, servers);
        assert!(
            note.starts_with(&format!(
                "could not walk its context from {}: cannot open it",
                vscode.display()
            )),
            "{note}"
        );
        let Walk::Itself(Some(note)) = walk_for(&vscode.join("code-abc"), &mounts, &context) else {
            panic!("a file is scanned alone, with a note");
        };
        assert!(note.contains("could not walk its context"), "{note}");
        // A symlinked directory on the way is not followed.
        std::fs::set_permissions(&vscode, std::fs::Permissions::from_mode(0o755)).unwrap();
        let real = root.join("real-bin");
        std::fs::create_dir_all(real.join("abc")).unwrap();
        std::os::unix::fs::symlink(&real, vscode.join("bin")).unwrap();
        let Walk::Above {
            note: Some(note), ..
        } = walk_for(&vscode.join("bin/abc"), &mounts, &context)
        else {
            panic!("bin is a symlink");
        };
        assert!(note.contains("is not a directory"), "{note}");
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
                walk_for(&m.mount_point, &mounts, &[]),
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
        let Walk::Itself(Some(note)) = walk_for(
            &parent.join("app"),
            &MountTable::read().unwrap_or_default(),
            &[],
        ) else {
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

        // By id: another detector's finding at the same path does not
        // count, and is not inside the path either.
        let id = crate::detect::finding_id("node-modules", "/p/app/target");
        let (got, inside) = pick(all(), "/p/app/target", Some(&id));
        assert!(got.is_none());
        assert!(inside.is_empty(), "{inside:?}");

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
    fn inside_lists_strict_descendants_only() {
        let all = vec![
            f("stale-tree", "/p/app", 100),
            f("cargo-target", "/p/app/target", 20),
            f("venv", "/p/app/sub/.venv", 10),
            f("cargo-target", "/p/apple/target", 5),
        ];
        // An id for another detector at /p/app: the stale-tree finding there
        // is neither picked nor listed inside; what lies below it is.
        let id = crate::detect::finding_id("node-modules", "/p/app");
        let (got, inside) = pick(all, "/p/app", Some(&id));
        assert!(got.is_none());
        let paths: Vec<&str> = inside.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/p/app/target", "/p/app/sub/.venv"]);
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
    fn filesystem_selection_leaves_out_docker_detectors() {
        let all = filesystem_selection(None);
        assert!(all.iter().any(|n| n == "cargo-target"), "{all:?}");
        assert_eq!(
            all.len() + docker_selection(None).len(),
            CATALOG.len(),
            "every detector is one or the other"
        );
        assert!(
            all.iter().all(|n| CATALOG
                .iter()
                .any(|d| d.name == n && d.needs != Needs::Docker)),
            "{all:?}"
        );
        assert!(all.iter().any(|n| n == "docker-logs"), "{all:?}");
        let only = vec!["cargo-target".to_string(), "docker-volume".to_string()];
        assert_eq!(filesystem_selection(Some(&only)), ["cargo-target"]);
        assert!(filesystem_selection(Some(&only[1..])).is_empty());
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
