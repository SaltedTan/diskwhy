//! `dwhy doctor`: permissions, optional tools, and which detectors they enable.
//!
//! Only looks things up; it runs no external commands.

use std::env;
use std::path::{Path, PathBuf};

use crate::report::{
    self, DetectorAvailability, DetectorStatus, DockerSocket, DoctorReport, Tool, ToolStatus,
};
use crate::system;

/// Optional external tools and what each one enables.
pub const TOOLS: &[(&str, &[&str])] = &[
    (
        "git",
        &["git-worktree", "guard:git-unpublished", "guard:git-dirty"],
    ),
    (
        "docker",
        &[
            "docker-image",
            "docker-build-cache",
            "docker-container",
            "docker-volume",
        ],
    ),
    ("cargo", &["cargo-target (removal via `cargo clean`)"]),
    ("go", &["user-cache: go build/module caches (`go clean`)"]),
    ("journalctl", &["journald (root only)"]),
];

#[derive(Debug, Clone, Copy)]
enum Needs {
    Nothing,
    /// Works without the tool, but removal is not tool-native.
    Prefers(&'static str),
    Requires(&'static str),
    Docker,
    RootAnd(&'static str),
}

const DETECTORS: &[(&str, &str, Needs)] = &[
    ("cargo-target", "M1", Needs::Prefers("cargo")),
    ("node-modules", "M1", Needs::Nothing),
    ("venv", "M1", Needs::Nothing),
    ("user-cache", "M1", Needs::Prefers("go")),
    ("git-worktree", "M1", Needs::Requires("git")),
    ("stale-tree", "M1", Needs::Nothing),
    ("tool-versions", "M1", Needs::Nothing),
    ("trash", "M1", Needs::Nothing),
    ("docker-image", "M1", Needs::Docker),
    ("docker-build-cache", "M1", Needs::Docker),
    ("docker-container", "M1", Needs::Docker),
    ("docker-volume", "M1", Needs::Docker),
    ("journald", "post-MVP", Needs::RootAnd("journalctl")),
];

/// Resolves `name` on `path_var` the way a shell would (first executable hit).
pub fn find_on_path(name: &str, path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let path_var = path_var?;
    env::split_paths(path_var)
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join(name))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    p.is_file() && rustix::fs::access(p, rustix::fs::Access::EXEC_OK).is_ok()
}

/// Well-known install locations that are often missing from `$PATH` in
/// non-interactive shells (ssh commands, cron, agents).
fn off_path_candidates(name: &str) -> Vec<PathBuf> {
    let home = env::var_os("HOME").map(PathBuf::from);
    let mut v = Vec::new();
    match name {
        "cargo" => {
            if let Some(ch) = env::var_os("CARGO_HOME") {
                v.push(PathBuf::from(ch).join("bin/cargo"));
            }
            if let Some(h) = &home {
                v.push(h.join(".cargo/bin/cargo"));
            }
        }
        "go" => {
            v.push(PathBuf::from("/usr/local/go/bin/go"));
            if let Some(h) = &home {
                v.push(h.join(".local/go/bin/go"));
                v.push(h.join("go/bin/go"));
            }
        }
        "git" | "docker" | "journalctl" => {
            v.push(PathBuf::from("/usr/bin").join(name));
            v.push(PathBuf::from("/bin").join(name));
        }
        _ => {}
    }
    v
}

fn docker_socket() -> DockerSocket {
    let path = match env::var("DOCKER_HOST") {
        Ok(h) if h.starts_with("unix://") => h.trim_start_matches("unix://").to_string(),
        _ => "/var/run/docker.sock".to_string(),
    };
    let p = Path::new(&path);
    let exists = p.exists();
    let accessible = exists
        && rustix::fs::access(
            p,
            rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK,
        )
        .is_ok();
    DockerSocket {
        path,
        exists,
        accessible,
    }
}

pub fn doctor() -> DoctorReport {
    let uid = system::uid();
    let euid = system::euid();
    let root = euid == 0;
    let path_var = env::var_os("PATH");

    let tools: Vec<ToolStatus> = TOOLS
        .iter()
        .map(|(name, enables)| {
            let on_path = find_on_path(name, path_var.as_deref());
            let off_path = if on_path.is_none() {
                off_path_candidates(name)
                    .into_iter()
                    .find(|p| is_executable(p))
            } else {
                None
            };
            ToolStatus {
                name: (*name).into(),
                path: on_path.map(|p| p.to_string_lossy().into_owned()),
                off_path: off_path.map(|p| p.to_string_lossy().into_owned()),
                enables: enables.iter().map(|s| (*s).into()).collect(),
            }
        })
        .collect();
    let has = |n: &str| tools.iter().any(|t| t.name == n && t.path.is_some());
    let off = |n: &str| {
        tools
            .iter()
            .find(|t| t.name == n)
            .and_then(|t| t.off_path.clone())
    };
    let missing = |n: &str| match off(n) {
        Some(p) => format!("`{n}` is not on PATH (found at {p}; add its directory to PATH)"),
        None => format!("`{n}` is not installed"),
    };

    let docker_group = system::group("docker")
        .map(|(gid, _)| system::in_group(gid))
        .unwrap_or(false);
    let sock = docker_socket();

    let detectors = DETECTORS
        .iter()
        .map(|(name, milestone, needs)| {
            let (status, detail) = match needs {
                Needs::Nothing => (
                    DetectorAvailability::Available,
                    "no external tool needed".into(),
                ),
                Needs::Prefers(t) if has(t) => (
                    DetectorAvailability::Available,
                    format!("uses `{t}` for removal"),
                ),
                Needs::Prefers(t) => (
                    DetectorAvailability::Degraded,
                    format!(
                        "{}; detection works, removal falls back to path removal",
                        missing(t)
                    ),
                ),
                Needs::Requires(t) if has(t) => {
                    (DetectorAvailability::Available, format!("uses `{t}`"))
                }
                Needs::Requires(t) => (DetectorAvailability::Unavailable, missing(t)),
                Needs::Docker if !has("docker") => {
                    (DetectorAvailability::Unavailable, missing("docker"))
                }
                Needs::Docker if !sock.exists => (
                    DetectorAvailability::Unavailable,
                    format!("no Docker socket at {}", sock.path),
                ),
                Needs::Docker if !sock.accessible => (
                    DetectorAvailability::Unavailable,
                    format!(
                        "cannot use {} (not root and not in the docker group)",
                        sock.path
                    ),
                ),
                Needs::Docker => (
                    DetectorAvailability::Available,
                    "uses the docker CLI and socket".into(),
                ),
                Needs::RootAnd(t) if !has(t) => (DetectorAvailability::Unavailable, missing(t)),
                Needs::RootAnd(_) if !root => (
                    DetectorAvailability::Unavailable,
                    "system detector; run as root".into(),
                ),
                Needs::RootAnd(t) => (DetectorAvailability::Available, format!("uses `{t}`")),
            };
            DetectorStatus {
                name: (*name).into(),
                milestone: (*milestone).into(),
                status,
                detail,
            }
        })
        .collect();

    let mut notes = Vec::new();
    if root {
        notes.push(
            "running as root: every directory is readable; other users' files are still never removed without --all-users"
                .to_string(),
        );
    } else {
        notes.push(format!(
            "running as uid {euid}: directories you cannot read are reported as unaccounted space; `sudo dwhy scan /` measures them"
        ));
    }
    if docker_group && !root {
        notes.push(
            "you are in the docker group, which is root-equivalent; Docker findings default to the review tier"
                .to_string(),
        );
    }

    DoctorReport {
        schema: report::SCHEMA.into(),
        tool: Tool::current(),
        host: system::hostname(),
        uid,
        euid,
        root,
        docker_group,
        docker_socket: sock,
        tools,
        detectors,
        notes,
    }
}

/// Whether Docker can be queried without sudo (used for scan hints).
pub fn docker_access() -> bool {
    let s = docker_socket();
    s.accessible
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn path_lookup_respects_order_and_exec_bit() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let mk = |dir: &Path, mode: u32| {
            let p = dir.join("faketool");
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        };
        mk(a.path(), 0o644); // not executable: skipped
        let want = mk(b.path(), 0o755);
        let path = env::join_paths([a.path(), b.path()]).unwrap();
        assert_eq!(find_on_path("faketool", Some(&path)), Some(want));
        assert_eq!(find_on_path("nosuchtool", Some(&path)), None);
        assert_eq!(find_on_path("faketool", None), None);
    }

    #[test]
    fn doctor_lists_every_tool_and_detector() {
        let d = doctor();
        assert_eq!(d.schema, report::SCHEMA);
        let names: Vec<_> = d.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["git", "docker", "cargo", "go", "journalctl"]);
        assert_eq!(d.detectors.len(), DETECTORS.len());
        assert_eq!(d.root, d.euid == 0);
    }
}
