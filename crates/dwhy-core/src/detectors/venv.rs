//! `venv`: Python virtual environments (venv, virtualenv, uv).
//!
//! A directory counts when it directly holds a regular `pyvenv.cfg`, whatever
//! it is named. The walk does not look inside a venv, so only the outermost
//! one is reported. The recovery comes from the project files in the
//! directory that holds the venv:
//!
//! - one lockfile (`uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`):
//!   that tool's install command; several: no command, the cost names them
//! - `requirements.txt`: recreate the venv with the same Python and install it
//! - `pyproject.toml` or `setup.py` without a lockfile: reinstall the project,
//!   which resolves dependencies again
//!
//! A venv with none of these next to it holds packages installed by hand, so
//! removing it loses that list: it is reported as `review`, with the command
//! to record its packages first.
//!
//! Skipped: venvs inside a cache directory (an ancestor holds `CACHEDIR.TAG`,
//! as uv's cache does; `user-cache` reports the cache), and the tools that
//! `uv tool` and pipx install (`uv/tools/<name>`, `pipx/venvs/<name>`), which
//! are installed programs rather than project environments.
//!
//! The action is a path removal limited to the venv. uv hardlinks package
//! files from its cache, so `bytes` is what removal frees (`freeable()`).

use std::ffi::OsStr;
use std::path::Path;

use crate::detect::{DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, Recovery, Tier};
use crate::tree::{Markers, NodeId, ScanTree};
use crate::units::human;

use super::read_head;

/// Venvs smaller than this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// Lockfiles, the tool that reads each, and its install command.
const LOCKS: &[(&str, &str, &str)] = &[
    ("uv.lock", "uv", "uv sync"),
    ("poetry.lock", "poetry", "poetry install"),
    ("pdm.lock", "pdm", "pdm install"),
    ("Pipfile.lock", "pipenv", "pipenv sync"),
];

/// What `pyvenv.cfg` says about the venv.
#[derive(Debug, Default)]
struct Cfg {
    /// `major.minor`, from `version_info` (venv, uv) or `version` (older venv).
    python: Option<String>,
    /// Created by uv (it writes a `uv = <version>` line).
    uv: bool,
}

fn read_cfg(path: &Path) -> Cfg {
    let Some(head) = read_head(path, 16 << 10) else {
        return Cfg::default();
    };
    let text = String::from_utf8_lossy(&head);
    let mut cfg = Cfg::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "uv" => cfg.uv = true,
            "version_info" | "version" if cfg.python.is_none() || k == "version_info" => {
                let mm: Vec<&str> = v.split('.').take(2).collect();
                if mm.len() == 2 && mm.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit())) {
                    cfg.python = Some(mm.join("."));
                }
            }
            _ => {}
        }
    }
    cfg
}

fn is_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file())
}

/// The project files next to a venv, read from disk without following symlinks.
struct Project {
    locks: Vec<(&'static str, &'static str, &'static str)>,
    requirements: bool,
    /// Other `requirements*.txt` files, sorted.
    other_requirements: Vec<String>,
    pyproject: bool,
    setup_py: bool,
}

impl Project {
    fn read(dir: &Path) -> Project {
        let mut other_requirements: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().into_string().ok()?;
                (name.starts_with("requirements")
                    && name.ends_with(".txt")
                    && name != "requirements.txt"
                    && e.file_type().ok()?.is_file())
                .then_some(name)
            })
            .collect();
        other_requirements.sort();
        Project {
            locks: LOCKS
                .iter()
                .copied()
                .filter(|(f, _, _)| is_file(&dir.join(f)))
                .collect(),
            requirements: is_file(&dir.join("requirements.txt")),
            other_requirements,
            pyproject: is_file(&dir.join("pyproject.toml")),
            setup_py: is_file(&dir.join("setup.py")),
        }
    }

    fn is_empty(&self) -> bool {
        self.locks.is_empty()
            && !self.requirements
            && self.other_requirements.is_empty()
            && !self.pyproject
            && !self.setup_py
    }
}

pub struct Venv;

impl Detector for Venv {
    fn name(&self) -> &'static str {
        "venv"
    }

    fn detect(&self, tree: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let mut out = Vec::new();
        let mut stack: Vec<NodeId> = tree.roots().to_vec();
        while let Some(id) = stack.pop() {
            let n = tree.node(id);
            if !n.is_dir {
                continue;
            }
            if n.markers.contains(Markers::PYVENV_CFG) {
                if let Some(f) = self.finding(tree, ctx, id) {
                    out.push(f);
                }
                continue;
            }
            stack.extend_from_slice(tree.children(id));
        }
        Ok(out)
    }
}

/// True if a directory strictly above `id` holds `CACHEDIR.TAG`. Ancestors
/// above the scan root are checked on disk.
fn in_cache(tree: &ScanTree, id: NodeId) -> bool {
    let mut cur = id;
    while let Some(p) = tree.parent(cur) {
        if tree.node(p).markers.contains(Markers::CACHEDIR_TAG) {
            return true;
        }
        cur = p;
    }
    tree.path(cur)
        .ancestors()
        .skip(1)
        .any(|d| is_file(&d.join("CACHEDIR.TAG")))
}

/// `uv/tools/<name>` or `pipx/venvs/<name>`.
fn is_tool_env(venv: &Path) -> bool {
    let parent = venv.parent();
    let a = parent.and_then(Path::file_name);
    let b = parent.and_then(Path::parent).and_then(Path::file_name);
    matches!(
        (a, b),
        (Some(a), Some(b)) if (a == "tools" && b == "uv") || (a == "venvs" && b == "pipx")
    )
}

impl Venv {
    fn finding(&self, tree: &ScanTree, ctx: &DetectContext, id: NodeId) -> Option<Finding> {
        let n = tree.node(id);
        let bytes = n.freeable();
        if bytes < MIN_BYTES {
            return None;
        }
        let path = tree.path(id);
        let project_dir = path.parent()?.to_path_buf();
        if is_tool_env(&path) || in_cache(tree, id) {
            return None;
        }
        let cfg = read_cfg(&path.join("pyvenv.cfg"));
        let project = Project::read(&project_dir);
        let path_s = path.to_string_lossy().into_owned();
        let name = path.file_name().unwrap_or(OsStr::new("")).to_string_lossy();
        let (tier, recovery) = recovery(&project, &project_dir, &name, &path_s, &cfg);

        let made_by = if cfg.uv { "uv" } else { "venv/virtualenv" };
        let python = cfg
            .python
            .as_deref()
            .map(|v| format!(", Python {v}"))
            .unwrap_or_default();
        let mut reason = if project.is_empty() {
            format!(
                "Python virtualenv in {} with no project file next to it (created by {made_by}{python}; {}",
                project_dir.display(),
                human(bytes)
            )
        } else {
            format!(
                "Python virtualenv for {} (created by {made_by}{python}; {}",
                project_dir.display(),
                human(bytes)
            )
        };
        if n.shared > 0 {
            reason.push_str(&format!(
                "; {} more is hardlinked elsewhere, e.g. from the uv cache, and is not freed",
                human(n.shared)
            ));
        }
        reason.push_str(&format!(
            "); last written {} ago",
            age(ctx.now, n.newest_mtime)
        ));

        Some(Finding {
            id: finding_id(self.name(), &path_s),
            detector: self.name().into(),
            probe: None,
            bytes,
            nested_bytes: None,
            last_modified: Some(rfc3339(n.newest_mtime)),
            growth: None,
            tier,
            reason,
            guards: Vec::new(),
            action: Action {
                kind: ActionKind::RemovePath,
                text: format!("remove {}", shell_quote(&path_s)),
                argv: None,
            },
            recovery,
            path: path_s,
        })
    }
}

/// The tier and recovery for a venv named `name` in `dir`.
fn recovery(p: &Project, dir: &Path, name: &str, venv: &str, cfg: &Cfg) -> (Tier, Recovery) {
    let cd = format!("cd {} && ", shell_quote(&dir.to_string_lossy()));
    let q = shell_quote(name);
    let py = cfg.python.as_deref();
    let py_text = py
        .map(|v| format!("Python {v}"))
        .unwrap_or("the same Python".into());
    // uv sync installs into .venv unless told otherwise.
    let uv_sync = if name == ".venv" {
        "uv sync".to_string()
    } else {
        format!("UV_PROJECT_ENVIRONMENT={q} uv sync")
    };
    // Recreate the venv the way it was made, then run `install` in it.
    let recreate = |install_uv: &str, install_pip: &str| {
        if cfg.uv {
            let pyflag = py.map(|v| format!(" --python {v}")).unwrap_or_default();
            format!("{cd}uv venv{pyflag} {q} && uv pip install --python {q} {install_uv}")
        } else {
            let python = py.map(|v| format!("python{v}")).unwrap_or("python3".into());
            format!("{cd}{python} -m venv {q} && {q}/bin/pip install {install_pip}")
        }
    };
    let rebuild = |how: Option<String>, cost: String| (Tier::Rebuildable, Recovery { cost, how });

    match p.locks.as_slice() {
        [(file, tool, cmd)] => {
            let how = if *tool == "uv" {
                format!("{cd}{uv_sync}")
            } else {
                format!("{cd}{cmd}")
            };
            return rebuild(
                Some(how),
                format!(
                    "{cmd} reinstalls the packages pinned in {file}, downloading what its cache no longer holds"
                ),
            );
        }
        [] => {}
        many => {
            return rebuild(
                None,
                format!(
                    "{} has lockfiles for {}; reinstall with the one the project uses",
                    dir.display(),
                    many.iter().map(|l| l.1).collect::<Vec<_>>().join(" and ")
                ),
            );
        }
    }
    if p.requirements {
        let mut cost = format!(
            "recreates the venv with {py_text} and installs requirements.txt; anything it does not pin resolves again"
        );
        if !p.other_requirements.is_empty() {
            cost.push_str(&format!(
                "; also next to it: {}",
                p.other_requirements.join(", ")
            ));
        }
        return rebuild(
            Some(recreate("-r requirements.txt", "-r requirements.txt")),
            cost,
        );
    }
    if !p.other_requirements.is_empty() {
        return rebuild(
            None,
            format!(
                "no requirements.txt, but {} has {}: recreate the venv with {py_text} and install the ones it used",
                dir.display(),
                p.other_requirements.join(", ")
            ),
        );
    }
    if p.pyproject && cfg.uv {
        return rebuild(
            Some(format!("{cd}{uv_sync}")),
            "no uv.lock, so uv sync resolves the dependencies again (possibly to newer versions) and writes one".into(),
        );
    }
    if p.pyproject || p.setup_py {
        return rebuild(
            Some(recreate("-e .", "-e .")),
            format!(
                "recreates the venv with {py_text} and installs the project (editable assumed); its dependencies resolve again, possibly to newer versions"
            ),
        );
    }
    let freeze = if cfg.uv {
        format!("uv pip freeze --python {}", shell_quote(venv))
    } else {
        format!("{}/bin/python -m pip freeze", shell_quote(venv))
    };
    (
        Tier::Review,
        Recovery {
            cost: format!(
                "no project file lists its packages, so they were installed by hand: record them first (the command below), then recreate the venv with {py_text} and install that list"
            ),
            how: Some(freeze),
        },
    )
}
