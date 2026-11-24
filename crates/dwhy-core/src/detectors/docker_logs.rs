//! `docker-logs`: container logs that grow without limit (docs/DESIGN.md,
//! Decisions → Docker logs).
//!
//! Docker's default `json-file` log driver keeps one file per container,
//! `<DockerRootDir>/containers/<id>/<id>-json.log`, and never rotates it
//! unless `max-size` is set. Running containers have no other finding, so
//! this is a detector rather than a probe: one advice-only `review` finding
//! per log of [`MIN_LOG_BYTES`] or more that the scan holds. Rootful Docker
//! keeps the directory root-only, so those logs need a root scan; rootless
//! Docker's are the user's own.
//!
//! It reads the scan tree, `fstatat`s the log file without following
//! symlinks, and sends only Engine API GETs (`/info`, `/containers/json`,
//! `/containers/{id}/json`). It asks the daemon only when the scan holds a
//! `containers/<64 hex>` directory, so scans and `explain` elsewhere never
//! wait on it. It never runs a command: capping a log means recreating the
//! container, which is the user's call.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use serde::Deserialize;

use crate::detect::{Candidate, DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::docker::{Api, GetError};
use crate::report::{Action, ActionKind, FileIdentity, Finding, Recovery, Tier};
use crate::tree::{NodeId, ScanTree};
use crate::units::human;

pub const NAME: &str = "docker-logs";

/// Smaller logs are not worth a finding.
pub const MIN_LOG_BYTES: u64 = 100 << 20;

/// Engine API timeout for each GET; none of them sizes anything.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The advice's suggested caps: 3 files of 10 MiB.
const SUGGESTED: &str = "max-size 10m, max-file 3";

pub struct DockerLogs {
    api: Responder,
    min_bytes: u64,
}

enum Responder {
    /// The daemon at the context's socket.
    Socket,
    /// Recorded responses by request path, for tests; other paths are 404.
    Fixed(BTreeMap<String, Result<Vec<u8>, GetError>>),
}

impl DockerLogs {
    pub fn from_system() -> DockerLogs {
        DockerLogs {
            api: Responder::Socket,
            min_bytes: MIN_LOG_BYTES,
        }
    }

    /// Answers Engine API GETs from `responses` (by path, such as
    /// `/containers/json?all=1`) instead of a daemon, and reports logs of
    /// `min_bytes` or more instead of [`MIN_LOG_BYTES`].
    pub fn with_responses(
        responses: BTreeMap<String, Result<Vec<u8>, GetError>>,
        min_bytes: u64,
    ) -> DockerLogs {
        DockerLogs {
            api: Responder::Fixed(responses),
            min_bytes,
        }
    }

    fn get(&self, ctx: &DetectContext, path: &str) -> Result<Vec<u8>, GetError> {
        match &self.api {
            Responder::Socket => Api {
                socket: PathBuf::from(&ctx.docker_socket.path),
                timeout: TIMEOUT,
            }
            .get(path),
            Responder::Fixed(map) => map
                .get(path)
                .cloned()
                .unwrap_or_else(|| Err(GetError::Http(404, format!("docker API {path}: 404")))),
        }
    }

    /// The directory `dwhy explain` walks from for `path`, with how many
    /// levels below it the log lies: `containers` when `path` is
    /// `…/containers/<64 hex>/<file>`. Needs no daemon.
    pub fn context_root(path: &Path) -> Option<(PathBuf, usize)> {
        let dir = path.parent()?;
        let containers = dir.parent()?;
        (is_id(dir.file_name()?.as_bytes())
            && containers.file_name().map(OsStrExt::as_bytes) == Some(b"containers"))
        .then(|| (containers.to_path_buf(), 2))
    }
}

/// A full container id: 64 lowercase hex digits.
fn is_id(s: &[u8]) -> bool {
    s.len() == 64 && s.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// A name Docker or Compose would accept, safe to show and quote:
/// `[A-Za-z0-9][A-Za-z0-9_.-]*`, at most 128 bytes.
fn plain_name(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Listed {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Inspect {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    log_path: String,
    #[serde(default)]
    state: State,
    #[serde(default)]
    host_config: HostConfig,
    #[serde(default)]
    config: ContainerConfig,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct State {
    #[serde(default)]
    status: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    #[serde(default)]
    log_config: LogConfig,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LogConfig {
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(default)]
    config: Option<HashMap<String, String>>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerConfig {
    #[serde(default)]
    labels: Option<HashMap<String, String>>,
}

/// A log file the walk holds that is big enough to report.
struct Big {
    id: String,
    path: PathBuf,
    st: Stat,
    bytes: u64,
}

impl Detector for DockerLogs {
    fn name(&self) -> &'static str {
        NAME
    }

    fn detect_candidates(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
    ) -> Result<Vec<Candidate>, String> {
        if !holds_container_dir(tree) {
            return Ok(Vec::new());
        }
        let info: crate::docker::Info =
            serde_json::from_slice(&self.get(ctx, "/info").map_err(|e| e.to_string())?)
                .map_err(|e| format!("docker API /info: {e}"))?;
        if info.docker_root_dir.is_empty() || !info.docker_root_dir.starts_with('/') {
            return Ok(Vec::new());
        }
        let containers = Path::new(&info.docker_root_dir).join("containers");
        let Some(node) = tree.find(&containers) else {
            return Ok(Vec::new());
        };
        if !tree.node(node).is_dir || ctx.cancel.is_canceled() {
            return Ok(Vec::new());
        }
        let listed: Vec<Listed> = serde_json::from_slice(
            &self
                .get(ctx, "/containers/json?all=1")
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("docker API /containers/json: {e}"))?;
        let big = big_logs(tree, node, &containers, &listed, self.min_bytes);

        let mut out = Vec::new();
        for b in big {
            if ctx.cancel.is_canceled() {
                break;
            }
            let body = match self.get(ctx, &format!("/containers/{}/json", b.id)) {
                Ok(body) => body,
                // Removed since the listing.
                Err(GetError::Http(404, _)) => continue,
                Err(e) => return Err(e.to_string()),
            };
            let c: Inspect = serde_json::from_slice(&body)
                .map_err(|e| format!("docker API /containers/{{id}}/json: {e}"))?;
            if c.id != b.id
                || c.host_config.log_config.kind != "json-file"
                || Path::new(&c.log_path) != b.path
            {
                continue;
            }
            out.push(candidate(ctx, &c, b));
        }
        out.sort_by(|a, b| a.path().cmp(b.path()));
        Ok(out)
    }
}

/// Whether the walk holds a `containers/<64 hex>` directory, the shape of
/// Docker's container state, wherever the docker root is.
fn holds_container_dir(tree: &ScanTree) -> bool {
    tree.ids().any(|id| {
        tree.node(id).is_dir
            && is_id(tree.name(id).as_bytes())
            && tree
                .parent(id)
                .is_some_and(|p| tree.name(p).as_bytes() == b"containers")
    })
}

/// The `<id>-json.log` files of listed containers that the walk holds and
/// that are at least `min_bytes`: regular, one link, on the walked
/// filesystem, in the container directory the walk measured.
fn big_logs(
    tree: &ScanTree,
    node: NodeId,
    containers: &Path,
    listed: &[Listed],
    min_bytes: u64,
) -> Vec<Big> {
    let Some(dir) = open_measured(containers, tree, node) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for l in listed {
        if !is_id(l.id.as_bytes()) {
            continue;
        }
        let Some(child) = tree.child_named(node, &l.id) else {
            continue;
        };
        let n = tree.node(child);
        if !n.is_dir {
            continue;
        }
        let Some(cdir) = subdir(&dir, l.id.as_bytes(), (n.dev, n.ino)) else {
            continue;
        };
        let file = format!("{}-json.log", l.id);
        let st = match rustix::fs::statat(
            &cdir,
            OsStr::from_bytes(file.as_bytes()),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(st) => st,
            Err(_) => continue,
        };
        #[allow(clippy::unnecessary_cast)]
        let links = st.st_nlink as u64;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            || st.st_dev != n.dev
            || links != 1
        {
            continue;
        }
        let bytes = st.st_blocks.max(0) as u64 * 512;
        if bytes < min_bytes {
            continue;
        }
        out.push(Big {
            id: l.id.clone(),
            path: containers.join(&l.id).join(file),
            st,
            bytes,
        });
    }
    out
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// `path` opened as a directory, when it is the one the walk measured at `node`.
fn open_measured(path: &Path, tree: &ScanTree, node: NodeId) -> Option<OwnedFd> {
    let fd = rustix::fs::open(path, DIR_FLAGS, Mode::empty()).ok()?;
    let st = rustix::fs::fstat(&fd).ok()?;
    let n = tree.node(node);
    ((st.st_dev, st.st_ino) == (n.dev, n.ino)).then_some(fd)
}

/// The directory `name` in `dir`, when it is the inode `(dev, ino)`.
fn subdir(dir: &OwnedFd, name: &[u8], (dev, ino): (u64, u64)) -> Option<OwnedFd> {
    let fd = rustix::fs::openat(dir, OsStr::from_bytes(name), DIR_FLAGS, Mode::empty()).ok()?;
    let st = rustix::fs::fstat(&fd).ok()?;
    ((st.st_dev, st.st_ino) == (dev, ino)).then_some(fd)
}

/// mtime in seconds; `st_mtime` is narrower than i64 on 32-bit targets.
#[allow(clippy::unnecessary_cast)]
fn mtime(st: &Stat) -> i64 {
    st.st_mtime as i64
}

/// A `json-file` size option that caps the file: set, and not `-1` or empty.
fn cap(opts: Option<&HashMap<String, String>>, key: &str) -> Option<String> {
    opts.and_then(|o| o.get(key))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v != "-1")
}

fn candidate(ctx: &DetectContext, c: &Inspect, b: Big) -> Candidate {
    let short = &b.id[..12];
    let name = c.name.trim_start_matches('/');
    let who = if plain_name(name) {
        format!("container {name} ({short})")
    } else {
        format!("container {short}")
    };
    let state = if plain_name(&c.state.status) {
        c.state.status.as_str()
    } else {
        "unknown"
    };
    let opts = c.host_config.log_config.config.as_ref();
    let max_size = cap(opts, "max-size").filter(|v| plain_name(v));
    let max_file = cap(opts, "max-file").filter(|v| plain_name(v));
    let labels = c.config.labels.as_ref();
    let label = |k: &str| {
        labels
            .and_then(|l| l.get(k))
            .filter(|v| plain_name(v))
            .cloned()
    };
    let compose = label("com.docker.compose.project").zip(label("com.docker.compose.service"));

    let mut reason = format!(
        "{who}, {state}, logs with the json-file driver to {} ({}), written {} ago; ",
        b.path.display(),
        human(b.bytes),
        age(ctx.now, mtime(&b.st)),
    );
    match &max_size {
        None => reason.push_str("no max-size is set, so Docker never rotates it"),
        Some(size) => reason.push_str(&format!(
            "Docker rotates it at max-size {size} and keeps max-file {} files",
            max_file.as_deref().unwrap_or("1")
        )),
    }

    let cap_how = match &max_size {
        None => format!("cap it ({SUGGESTED})"),
        Some(_) => format!("lower its caps (for example {SUGGESTED})"),
    };
    let mut advice = match &compose {
        Some((project, service)) => format!(
            "{cap_how} under `logging: options:` for service {service} in Compose project {project}, then recreate it from the project's directory with `docker compose up -d --force-recreate {}`",
            shell_quote(service)
        ),
        None => format!(
            "{cap_how} with `--log-opt max-size=10m --log-opt max-file=3` when you next create the container, or with `log-opts` in the daemon's daemon.json for containers created after a daemon restart, then recreate it"
        ),
    };
    advice.push_str(
        "; Docker deletes this log with the old container, and the new one starts a fresh log",
    );
    if state != "running" {
        advice.push_str(&format!(
            "; the container is {state}, so `docker rm {}` also deletes the log",
            shell_quote(short)
        ));
    }

    let path_s = b.path.to_string_lossy().into_owned();
    let finding = Finding {
        file_identity: Some(FileIdentity {
            dev: b.st.st_dev,
            ino: b.st.st_ino,
            mtime: mtime(&b.st),
        }),
        id: finding_id(NAME, &path_s),
        detector: NAME.into(),
        probe: None,
        evidence: None,
        bytes: b.bytes,
        nested_bytes: None,
        last_modified: Some(rfc3339(mtime(&b.st))),
        growth: None,
        tier: Tier::Review,
        reason,
        guards: Vec::new(),
        action: Action {
            kind: ActionKind::Advice,
            text: advice,
            argv: None,
        },
        recovery: Recovery {
            cost: "recreating or removing the container loses the output in this log: `docker logs` shows only what the new container writes"
                .into(),
            how: None,
        },
        path: path_s,
    };
    Candidate::new(b.path, finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_walks_from_containers_for_a_log() {
        let id = "a".repeat(64);
        let p = PathBuf::from(format!("/var/lib/docker/containers/{id}/{id}-json.log"));
        assert_eq!(
            DockerLogs::context_root(&p),
            Some((PathBuf::from("/var/lib/docker/containers"), 2))
        );
        assert_eq!(
            DockerLogs::context_root(Path::new("/var/lib/docker/containers/abc/x.log")),
            None
        );
        let other = PathBuf::from(format!("/srv/other/{id}/{id}-json.log"));
        assert_eq!(DockerLogs::context_root(&other), None);
    }

    #[test]
    fn caps_ignore_unlimited_and_empty() {
        let mut o = HashMap::new();
        o.insert("max-size".to_string(), "-1".to_string());
        o.insert("max-file".to_string(), " ".to_string());
        assert_eq!(cap(Some(&o), "max-size"), None);
        assert_eq!(cap(Some(&o), "max-file"), None);
        o.insert("max-size".to_string(), "50m".to_string());
        assert_eq!(cap(Some(&o), "max-size").as_deref(), Some("50m"));
    }

    #[test]
    fn names_shown_are_plain() {
        assert!(plain_name("bmc-prod-test-postgres-1"));
        assert!(!plain_name("-x"));
        assert!(!plain_name("a\u{1b}[31m"));
        assert!(!plain_name(""));
    }
}
