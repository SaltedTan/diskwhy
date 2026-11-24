//! `dwhy doctor`: permissions, optional tools, and which detectors and probes they enable.
//!
//! Only looks things up; it runs no external commands.

use std::env;
use std::path::{Path, PathBuf};

use crate::detect::{CATALOG, DetectContext, availability};
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
            "probe:postgres-wal (psql through `docker exec`)",
        ],
    ),
    ("cargo", &["cargo-target (removal via `cargo clean`)"]),
    ("go", &["user-cache: Go build/module caches (`go clean`)"]),
    (
        "uv",
        &[
            "user-cache: uv cache (`uv cache clean`)",
            "tool-versions: uv Pythons (`uv python uninstall`)",
        ],
    ),
    ("pip", &["user-cache: pip cache (`pip cache purge`)"]),
    ("npm", &["user-cache: npm cache (`npm cache clean`)"]),
    ("pnpm", &["user-cache: pnpm store (`pnpm store prune`)"]),
    (
        "yarn",
        &["user-cache: Yarn classic cache (`yarn cache clean`)"],
    ),
    (
        "rustup",
        &["tool-versions: Rust toolchains (`rustup toolchain uninstall`)"],
    ),
    (
        "pyenv",
        &["tool-versions: pyenv Pythons (`pyenv uninstall`)"],
    ),
    (
        "fnm",
        &["tool-versions: fnm Node versions (`fnm uninstall`)"],
    ),
    ("journalctl", &["journald (root only)"]),
    ("apt-get", &["apt-cache (root only)"]),
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
        "rustup" => {
            if let Some(ch) = env::var_os("CARGO_HOME") {
                v.push(PathBuf::from(ch).join("bin/rustup"));
            }
            if let Some(h) = &home {
                v.push(h.join(".cargo/bin/rustup"));
            }
        }
        "pyenv" => {
            if let Some(r) = env::var_os("PYENV_ROOT") {
                v.push(PathBuf::from(r).join("bin/pyenv"));
            }
            if let Some(h) = &home {
                v.push(h.join(".pyenv/bin/pyenv"));
            }
        }
        "fnm" => {
            if let Some(d) = env::var_os("FNM_DIR") {
                v.push(PathBuf::from(d).join("fnm"));
            }
            if let Some(h) = &home {
                v.push(h.join(".local/share/fnm/fnm"));
                v.push(h.join(".cargo/bin/fnm"));
            }
        }
        "uv" => {
            if let Some(h) = &home {
                v.push(h.join(".local/bin/uv"));
                v.push(h.join(".cargo/bin/uv"));
            }
        }
        "git" | "docker" | "journalctl" | "apt-get" => {
            v.push(PathBuf::from("/usr/bin").join(name));
            v.push(PathBuf::from("/bin").join(name));
        }
        _ => {}
    }
    v
}

/// The Docker socket from `DOCKER_HOST` (unix only) or the default path.
pub fn docker_socket() -> DockerSocket {
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

/// The optional tools in [`TOOLS`]: where each is on `$PATH`, or found off it.
pub fn resolve_tools() -> Vec<ToolStatus> {
    let path_var = env::var_os("PATH");
    TOOLS
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
        .collect()
}

pub fn doctor() -> DoctorReport {
    let ctx = DetectContext::from_system();
    let uid = system::uid();
    let euid = ctx.uid;
    let root = ctx.root;
    let docker_group = system::group("docker")
        .map(|(gid, _)| system::in_group(gid))
        .unwrap_or(false);
    let built: Vec<&str> = crate::detectors::registry()
        .iter()
        .map(|d| d.name())
        .collect();
    let detectors = CATALOG
        .iter()
        .map(|info| {
            let (status, detail) = availability(info, &ctx);
            let (status, detail) = if built.contains(&info.name) {
                (status, detail)
            } else {
                (
                    DetectorAvailability::NotImplemented,
                    format!("not implemented yet; when built: {detail}"),
                )
            };
            DetectorStatus {
                name: info.name.into(),
                milestone: info.milestone.into(),
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
        docker_socket: ctx.docker_socket.clone(),
        tools: ctx.tools.clone(),
        detectors,
        probes: crate::probes::statuses(&ctx),
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
        assert_eq!(
            names,
            [
                "git",
                "docker",
                "cargo",
                "go",
                "uv",
                "pip",
                "npm",
                "pnpm",
                "yarn",
                "rustup",
                "pyenv",
                "fnm",
                "journalctl",
                "apt-get"
            ]
        );
        assert_eq!(d.detectors.len(), CATALOG.len());
        assert_eq!(d.root, d.euid == 0);
    }
}
