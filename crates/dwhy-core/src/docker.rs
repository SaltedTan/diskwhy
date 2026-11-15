//! Read-only access to the Docker Engine API over its unix socket.
//!
//! Only `GET /system/df` and `GET /info` are used. They give exact byte
//! counts (the CLI's `docker system df` prints rounded strings). Removal
//! commands that findings suggest use the docker CLI instead.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::Deserialize;

use crate::report::{DockerUsage, UsageLine};

/// `GET /system/df` (only the fields diskwhy uses; all optional).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SystemDf {
    pub layers_size: i64,
    pub images: Option<Vec<Image>>,
    pub containers: Option<Vec<Container>>,
    pub volumes: Option<Vec<Volume>>,
    pub build_cache: Option<Vec<BuildCacheRecord>>,
}

/// Parses a `GET /system/df` body. A body with none of the `Images`,
/// `Containers`, `Volumes` and `BuildCache` keys is a schema diskwhy does not
/// know, not an empty daemon (an empty list, or `null`, is fine).
pub fn parse_system_df(body: &[u8]) -> Result<SystemDf, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if !["Images", "Containers", "Volumes", "BuildCache"]
        .iter()
        .any(|k| v.get(k).is_some())
    {
        return Err(
            "the response has no Images, Containers, Volumes or BuildCache lists (unsupported API schema)"
                .into(),
        );
    }
    serde_json::from_value(v).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Image {
    pub id: String,
    pub repo_tags: Option<Vec<String>>,
    pub repo_digests: Option<Vec<String>>,
    /// Seconds since the epoch.
    pub created: i64,
    pub size: i64,
    /// -1 when the daemon did not compute it.
    pub shared_size: i64,
    /// Containers using the image; -1 when not computed.
    pub containers: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Container {
    pub id: String,
    pub names: Vec<String>,
    pub image: String,
    pub state: String,
    pub status: String,
    pub created: i64,
    pub size_rw: Option<i64>,
    pub mounts: Vec<Mount>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Mount {
    #[serde(rename = "Type")]
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Volume {
    pub name: String,
    pub driver: String,
    pub created_at: String,
    pub usage_data: Option<VolumeUsage>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct VolumeUsage {
    /// -1 when not computed.
    pub size: i64,
    /// Containers referencing the volume; -1 when not computed.
    pub ref_count: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct BuildCacheRecord {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Type")]
    pub kind: String,
    pub description: String,
    pub in_use: bool,
    pub shared: bool,
    pub size: i64,
    pub last_used_at: Option<String>,
}

/// `GET /info` (only what diskwhy uses).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Info {
    pub driver: String,
    pub driver_status: Option<Vec<Vec<String>>>,
    pub docker_root_dir: String,
}

impl Info {
    /// Image data lives in containerd (`/var/lib/containerd`), not under the docker root.
    pub fn containerd_image_store(&self) -> bool {
        self.driver_status.iter().flatten().any(|kv| {
            kv.first().map(String::as_str) == Some("driver-type")
                && kv
                    .get(1)
                    .is_some_and(|v| v.starts_with("io.containerd.snapshotter"))
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub df: SystemDf,
    pub info: Info,
}

impl Snapshot {
    pub fn images(&self) -> &[Image] {
        self.df.images.as_deref().unwrap_or_default()
    }
    pub fn containers(&self) -> &[Container] {
        self.df.containers.as_deref().unwrap_or_default()
    }
    pub fn volumes(&self) -> &[Volume] {
        self.df.volumes.as_deref().unwrap_or_default()
    }
    pub fn build_cache(&self) -> &[BuildCacheRecord] {
        self.df.build_cache.as_deref().unwrap_or_default()
    }
}

/// Totals for the report and the unaccounted-space hints.
pub fn usage(s: &Snapshot) -> DockerUsage {
    let pos = |v: i64| v.max(0) as u64;
    let images = UsageLine {
        count: s.images().len() as u64,
        active: s.images().iter().filter(|i| i.containers > 0).count() as u64,
        bytes: pos(s.df.layers_size),
    };
    let containers = UsageLine {
        count: s.containers().len() as u64,
        active: s
            .containers()
            .iter()
            .filter(|c| c.state == "running")
            .count() as u64,
        bytes: s
            .containers()
            .iter()
            .map(|c| pos(c.size_rw.unwrap_or(0)))
            .sum(),
    };
    let volumes = UsageLine {
        count: s.volumes().len() as u64,
        active: s
            .volumes()
            .iter()
            .filter(|v| v.usage_data.as_ref().is_some_and(|u| u.ref_count > 0))
            .count() as u64,
        bytes: s
            .volumes()
            .iter()
            .map(|v| pos(v.usage_data.as_ref().map_or(0, |u| u.size)))
            .sum(),
    };
    let build_cache = UsageLine {
        count: s.build_cache().len() as u64,
        active: s.build_cache().iter().filter(|b| b.in_use).count() as u64,
        bytes: s.build_cache().iter().map(|b| pos(b.size)).sum(),
    };
    DockerUsage {
        root_dir: s.info.docker_root_dir.clone(),
        containerd_image_store: s.info.containerd_image_store(),
        total: images.bytes + containers.bytes + volumes.bytes + build_cache.bytes,
        images,
        containers,
        volumes,
        build_cache,
    }
}

/// A minimal HTTP/1.0 client for the Engine API socket.
#[derive(Debug, Clone)]
pub struct Api {
    pub socket: PathBuf,
    pub timeout: Duration,
}

impl Api {
    pub fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        let err = |e: std::io::Error| format!("{}: {e}", self.socket.display());
        let mut s = UnixStream::connect(&self.socket).map_err(err)?;
        s.set_read_timeout(Some(self.timeout)).map_err(err)?;
        s.set_write_timeout(Some(self.timeout)).map_err(err)?;
        write!(
            s,
            "GET {path} HTTP/1.0\r\nHost: docker\r\nUser-Agent: diskwhy\r\n\r\n"
        )
        .map_err(err)?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).map_err(|e| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) {
                format!("docker API {path}: no response within {:?}", self.timeout)
            } else {
                err(e)
            }
        })?;
        parse_http(&raw).map_err(|e| format!("docker API {path}: {e}"))
    }
}

fn parse_http(raw: &[u8]) -> Result<Vec<u8>, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("truncated response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = &raw[split + 4..];
    let status = head.lines().next().unwrap_or("");
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        let msg = String::from_utf8_lossy(body);
        return Err(format!("{status}: {}", msg.trim()));
    }
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if chunked {
        dechunk(body)
    } else {
        Ok(body.to_vec())
    }
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n").ok_or("bad chunk")?;
        let size_s = String::from_utf8_lossy(&b[..eol]);
        let size = usize::from_str_radix(size_s.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "bad chunk size")?;
        b = &b[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size {
            return Err("truncated chunk".into());
        }
        out.extend_from_slice(&b[..size]);
        b = b.get(size + 2..).ok_or("truncated chunk")?;
    }
}

/// One Docker snapshot per run, fetched on first use and shared by all
/// Docker detectors.
pub struct Source {
    api: Option<Api>,
    cell: OnceLock<Result<Arc<Snapshot>, String>>,
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("docker::Source")
            .field("api", &self.api)
            .field("fetched", &self.cell.get().map(|r| r.is_ok()))
            .finish()
    }
}

/// Wait at most this long for the daemon: `system/df` sizes every volume.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

impl Source {
    pub fn socket(path: &Path, timeout: Duration) -> Arc<Source> {
        Arc::new(Source {
            api: Some(Api {
                socket: path.to_path_buf(),
                timeout,
            }),
            cell: OnceLock::new(),
        })
    }

    /// A source that never talks to a daemon.
    pub fn none() -> Arc<Source> {
        Arc::new(Source {
            api: None,
            cell: OnceLock::new(),
        })
    }

    /// A fixed snapshot, for tests.
    pub fn fixed(s: Snapshot) -> Arc<Source> {
        let cell = OnceLock::new();
        let _ = cell.set(Ok(Arc::new(s)));
        Arc::new(Source { api: None, cell })
    }

    pub fn get(&self) -> Result<Arc<Snapshot>, String> {
        self.cell
            .get_or_init(|| {
                let api = self.api.as_ref().ok_or("no Docker socket configured")?;
                let df = parse_system_df(&api.get("/system/df")?)
                    .map_err(|e| format!("docker API /system/df: {e}"))?;
                let info: Info = serde_json::from_slice(&api.get("/info")?)
                    .map_err(|e| format!("docker API /info: {e}"))?;
                Ok(Arc::new(Snapshot { df, info }))
            })
            .clone()
    }

    /// The snapshot if a detector already fetched it successfully; never fetches.
    pub fn fetched(&self) -> Option<Arc<Snapshot>> {
        self.cell.get().and_then(|r| r.as_ref().ok().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn serve(reply: &'static [u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("d.sock");
        let l = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let mut c = conn.unwrap();
                // Read the whole request head (the client may send it in several
                // writes): closing with unread bytes makes the client's read fail
                // with ECONNRESET instead of seeing the reply.
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                if reply.is_empty() {
                    std::thread::sleep(Duration::from_secs(5));
                } else {
                    c.write_all(reply).unwrap();
                }
            }
        });
        (dir, sock)
    }

    #[test]
    fn plain_and_chunked_bodies() {
        let (_d, sock) =
            serve(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}");
        let api = Api {
            socket: sock,
            timeout: Duration::from_secs(5),
        };
        assert_eq!(api.get("/x").unwrap(), b"{\"a\":1}");

        let (_d2, sock2) = serve(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
        );
        let api2 = Api {
            socket: sock2,
            timeout: Duration::from_secs(5),
        };
        assert_eq!(api2.get("/x").unwrap(), b"{\"a\":1}");
    }

    #[test]
    fn errors_are_reported_not_hidden() {
        let (_d, sock) = serve(b"HTTP/1.0 500 Internal Server Error\r\n\r\n{\"message\":\"boom\"}");
        let api = Api {
            socket: sock,
            timeout: Duration::from_secs(5),
        };
        let e = api.get("/system/df").unwrap_err();
        assert!(e.contains("500") && e.contains("boom"), "{e}");

        let (_d2, slow) = serve(b"");
        let api = Api {
            socket: slow,
            timeout: Duration::from_millis(200),
        };
        let e = api.get("/system/df").unwrap_err();
        assert!(e.contains("no response within"), "{e}");

        let api = Api {
            socket: "/nonexistent/docker.sock".into(),
            timeout: Duration::from_secs(1),
        };
        assert!(api.get("/x").is_err());
        assert!(Source::none().get().is_err());
    }

    #[test]
    fn unknown_system_df_schema_is_an_error_not_an_empty_daemon() {
        let (_d, sock) = serve(
            b"HTTP/1.0 200 OK\r\n\r\n{\"ImageUsage\":{\"TotalSize\":5,\"Reclaimable\":1},\"BuildCacheUsage\":{\"TotalSize\":2}}",
        );
        let e = Source::socket(&sock, Duration::from_secs(5))
            .get()
            .unwrap_err();
        assert!(
            e.contains("/system/df") && e.contains("unsupported API schema"),
            "{e}"
        );

        let empty = parse_system_df(
            br#"{"LayersSize":0,"Images":[],"Containers":null,"Volumes":null,"BuildCache":null}"#,
        )
        .unwrap();
        assert!(empty.images.unwrap().is_empty());
        assert!(empty.containers.is_none());
    }

    #[test]
    fn containerd_store_detection() {
        let info: Info = serde_json::from_str(
            r#"{"Driver":"overlayfs","DriverStatus":[["driver-type","io.containerd.snapshotter.v1"]],"DockerRootDir":"/var/lib/docker"}"#,
        )
        .unwrap();
        assert!(info.containerd_image_store());
        let classic: Info = serde_json::from_str(
            r#"{"Driver":"overlay2","DriverStatus":[["Backing Filesystem","extfs"]]}"#,
        )
        .unwrap();
        assert!(!classic.containerd_image_store());
    }
}
