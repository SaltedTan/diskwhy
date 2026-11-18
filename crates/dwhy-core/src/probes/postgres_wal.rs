//! `postgres-wal`: why a Docker volume holding a Postgres data directory is
//! big. The usual answer on a dev box is WAL piling up in `pg_wal` because
//! `archive_command` keeps failing, often because the archive target (a
//! fake S3 container, say) has exited.
//!
//! It probes a `docker-volume` finding only when a **running** container
//! mounts the volume at its Postgres data directory (`PGDATA` from the
//! container's environment, `/var/lib/postgresql/data` by default) or at a
//! parent of it.
//!
//! Everything it does is read-only:
//!
//! * Engine API GETs: `/containers/json?all=1`, `/containers/{id}/json`, and
//!   a capped log tail (`/containers/{id}/logs`, [`LOG_TAIL`] lines).
//! * `docker exec <id> psql` as the database user from the container's
//!   environment, over the local socket (`PGHOST` empty), with
//!   `PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10s`,
//!   and the query inside
//!   `BEGIN READ ONLY`, under a timeout ([`EXEC_TIMEOUT`]).
//!
//! When exec or psql fails, the evidence comes from
//! the GETs alone (`source: api-only`): settings from the container's
//! command line and archive failures from the log tail.
//!
//! The system is behind the [`Docker`] trait so tests can replay recorded
//! responses.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::detect::{DetectContext, rfc3339};
use crate::docker::Api;
use crate::report::{
    ActionKind, ArchiveTarget, DetectorAvailability, EvidenceSource, Finding, PostgresWal,
};
use crate::units::human;

pub const NAME: &str = "postgres-wal";
/// The data directory of the official image when `PGDATA` is not set.
pub const DEFAULT_PGDATA: &str = "/var/lib/postgresql/data";
/// Log lines read when psql cannot be used.
pub const LOG_TAIL: u32 = 200;
/// How long `docker exec … psql` may take.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one Engine API GET may take.
pub const API_TIMEOUT: Duration = Duration::from_secs(10);
/// WAL at least this large and [`WAL_RATIO`] times the data, with archiving
/// on, is worth advice even when the archiver reports no failure.
const BIG_WAL: u64 = 1 << 30;
const WAL_RATIO: u64 = 4;

/// The read-only queries, as one row. Fields are separated by
/// [`FIELD_SEP`]; times are seconds since the epoch.
pub const QUERY: &str = "SELECT \
(SELECT coalesce(sum(size), 0) FROM pg_ls_waldir()), \
(SELECT sum(pg_database_size(oid)) FROM pg_database), \
a.failed_count, \
extract(epoch FROM a.last_archived_time)::bigint, \
extract(epoch FROM a.last_failed_time)::bigint, \
a.last_failed_wal, \
current_setting('archive_mode'), \
current_setting('archive_command'), \
current_setting('archive_timeout') \
FROM pg_stat_archiver a";

/// psql's field separator (`-F`): ASCII unit separator, which settings and
/// WAL file names do not contain.
pub const FIELD_SEP: char = '\x1f';

/// What the probe needs from the system. Every method only reads.
pub trait Docker {
    /// An Engine API GET; the response body.
    fn get(&self, path: &str) -> Result<Vec<u8>, String>;
    /// Runs [`QUERY`]-style SQL with psql in the container, read-only, as
    /// `user` on database `db`; psql's stdout.
    fn psql(&self, container_id: &str, user: &str, db: &str, sql: &str) -> Result<String, String>;
}

/// The real daemon and docker CLI.
#[derive(Debug, Clone)]
pub struct Live {
    pub api: Api,
    /// How to invoke `docker`; `None` when it is not installed.
    pub docker: Option<String>,
    pub exec_timeout: Duration,
}

impl Live {
    pub fn from_context(ctx: &DetectContext) -> Live {
        Live {
            api: Api {
                socket: ctx.docker_socket.path.clone().into(),
                timeout: API_TIMEOUT,
            },
            docker: ctx.tool_command("docker"),
            exec_timeout: EXEC_TIMEOUT,
        }
    }
}

impl Docker for Live {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        self.api.get(path)
    }

    fn psql(&self, container_id: &str, user: &str, db: &str, sql: &str) -> Result<String, String> {
        let docker = self
            .docker
            .as_deref()
            .ok_or("`docker` is not installed, so psql cannot be run in the container")?;
        let argv = psql_argv(
            docker,
            &self.api.socket.to_string_lossy(),
            container_id,
            user,
            db,
            sql,
        );
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]).current_dir("/");
        let out = run_with_timeout(cmd, self.exec_timeout)?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let line = err
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("no error message");
            return Err(format!("docker exec psql failed ({}): {line}", out.status));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// The `docker exec` command line: psql without a psqlrc, never prompting
/// for a password, over the container's local socket, every transaction
/// read-only and each statement limited to 10 s (`PGOPTIONS`, so a query
/// outlives a killed `docker exec` by at most that), and the query inside
/// `BEGIN READ ONLY`. Run as argv, never through a shell.
pub fn psql_argv(
    docker: &str,
    socket: &str,
    container_id: &str,
    user: &str,
    db: &str,
    sql: &str,
) -> Vec<String> {
    let db = format!("dbname='{}'", db.replace('\\', "\\\\").replace('\'', "\\'"));
    [
        docker,
        "-H",
        &format!("unix://{socket}"),
        "exec",
        "-e",
        "PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10s",
        "-e",
        "PGCONNECT_TIMEOUT=5",
        // Empty: the local socket, never a server PGHOST names.
        "-e",
        "PGHOST=",
        "-e",
        "PGHOSTADDR=",
        "-e",
        "PGSERVICE=",
        "-e",
        "PGSERVICEFILE=/dev/null",
        container_id,
        "psql",
        "-X",
        "-w",
        "-q",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-F",
        &FIELD_SEP.to_string(),
        "-U",
        user,
        "-d",
        &db,
        "-c",
        "BEGIN READ ONLY",
        "-c",
        sql,
        "-c",
        "COMMIT",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Runs `cmd` with no stdin, killing it after `timeout`.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Output, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run docker: {e}"))?;
    let drain = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(r) = r {
                let _ = r.take(1 << 20).read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = drain(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = drain(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "docker exec psql gave no answer within {timeout:?}"
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("docker exec psql: {e}")),
        }
    };
    Ok(Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// Whether the probe looks at a finding: an in-use `docker-volume` one.
pub fn applies_to(f: &Finding) -> bool {
    f.detector == "docker-volume"
        && f.path.starts_with("docker://volume/")
        && f.action.kind == ActionKind::Advice
}

/// For `dwhy doctor`.
pub fn availability(ctx: &DetectContext) -> (DetectorAvailability, String) {
    let volume = crate::detect::CATALOG
        .iter()
        .find(|info| info.name == "docker-volume")
        .expect("docker-volume is in the detector catalog");
    let (status, detail) = crate::detect::availability(volume, ctx);
    if status != DetectorAvailability::Available {
        return (
            status,
            format!("docker-volume findings unavailable: {detail}"),
        );
    }
    (
        DetectorAvailability::Available,
        "uses docker-volume findings, the Engine API and read-only psql through `docker exec`"
            .into(),
    )
}

// ---------------------------------------------------------------------------
// Engine API shapes (only what the probe reads)
// ---------------------------------------------------------------------------

/// An entry of `GET /containers/json?all=1`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Listed {
    pub id: String,
    pub names: Vec<String>,
    pub state: String,
    pub labels: Option<HashMap<String, String>>,
    pub mounts: Vec<MountPoint>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MountPoint {
    #[serde(rename = "Type")]
    pub kind: String,
    pub name: String,
    pub destination: String,
}

/// `GET /containers/{id}/json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Inspect {
    pub id: String,
    pub name: String,
    /// Arguments after the entrypoint's program (the command, usually).
    pub args: Vec<String>,
    pub state: InspectState,
    pub config: InspectConfig,
    pub mounts: Vec<MountPoint>,
    pub network_settings: NetworkSettings,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct InspectState {
    pub status: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct InspectConfig {
    pub env: Option<Vec<String>>,
    pub tty: bool,
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetworkSettings {
    pub networks: Option<HashMap<String, Endpoint>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Endpoint {
    pub aliases: Option<Vec<String>>,
    #[serde(rename = "DNSNames")]
    pub dns_names: Option<Vec<String>>,
}

const COMPOSE_SERVICE: &str = "com.docker.compose.service";
const COMPOSE_PROJECT: &str = "com.docker.compose.project";

fn name_of(names: &[String], id: &str) -> String {
    names
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_else(|| id.chars().take(12).collect())
}

impl Inspect {
    pub fn env(&self, key: &str) -> Option<&str> {
        self.config
            .env
            .iter()
            .flatten()
            .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
    }

    fn label(&self, key: &str) -> Option<&str> {
        self.config.labels.as_ref()?.get(key).map(String::as_str)
    }

    fn display_name(&self) -> String {
        let n = self.name.trim_start_matches('/');
        if n.is_empty() {
            self.id.chars().take(12).collect()
        } else {
            n.to_string()
        }
    }

    fn aliases(&self) -> impl Iterator<Item = &str> {
        self.network_settings
            .networks
            .iter()
            .flat_map(|m| m.values())
            .flat_map(|e| {
                e.aliases
                    .iter()
                    .flatten()
                    .chain(e.dns_names.iter().flatten())
            })
            .map(String::as_str)
    }
}

impl Listed {
    fn label(&self, key: &str) -> Option<&str> {
        self.labels.as_ref()?.get(key).map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

/// Probes every finding [`applies_to`] matches. Gives up quietly when the
/// container list cannot be fetched: the findings stay as detected.
pub fn probe_all(findings: &mut [Finding], docker: &dyn Docker) {
    if !findings.iter().any(applies_to) {
        return;
    }
    let Ok(listed) = docker
        .get("/containers/json?all=1")
        .and_then(|b| serde_json::from_slice::<Vec<Listed>>(&b).map_err(|e| e.to_string()))
    else {
        return;
    };
    let mut cache = Inspects::default();
    for f in findings.iter_mut().filter(|f| applies_to(f)) {
        let Some(volume) = f.path.strip_prefix("docker://volume/") else {
            continue;
        };
        if let Some(ev) = probe_volume(volume, &listed, docker, &mut cache) {
            annotate(f, ev);
        }
    }
}

/// Inspect responses, fetched once per container.
#[derive(Default)]
struct Inspects(HashMap<String, Option<Inspect>>);

impl Inspects {
    fn get(&mut self, docker: &dyn Docker, id: &str) -> Option<&Inspect> {
        self.0
            .entry(id.to_string())
            .or_insert_with(|| {
                docker
                    .get(&format!("/containers/{id}/json"))
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
            })
            .as_ref()
    }
}

fn probe_volume(
    volume: &str,
    listed: &[Listed],
    docker: &dyn Docker,
    cache: &mut Inspects,
) -> Option<PostgresWal> {
    for c in listed.iter().filter(|c| {
        c.state == "running"
            && c.mounts
                .iter()
                .any(|m| m.kind == "volume" && m.name == volume)
    }) {
        let Some(insp) = cache.get(docker, &c.id).cloned() else {
            continue;
        };
        if insp.state.status != "running" {
            continue;
        }
        let pgdata = insp.env("PGDATA").unwrap_or(DEFAULT_PGDATA);
        let at_data_dir = insp
            .mounts
            .iter()
            .filter(|m| {
                m.destination.starts_with('/')
                    && Path::new(pgdata).starts_with(Path::new(&m.destination))
            })
            .max_by_key(|m| Path::new(&m.destination).components().count())
            .is_some_and(|m| m.kind == "volume" && m.name == volume);
        if at_data_dir {
            return Some(gather(&insp, listed, docker, cache));
        }
    }
    None
}

fn gather(
    insp: &Inspect,
    listed: &[Listed],
    docker: &dyn Docker,
    cache: &mut Inspects,
) -> PostgresWal {
    let mut ev = PostgresWal {
        container: insp.display_name(),
        wal_bytes: None,
        data_bytes: None,
        failed_count: None,
        last_archived_at: None,
        last_failed_at: None,
        last_failed_wal: None,
        archive_mode: None,
        archive_command: None,
        archive_timeout: None,
        targets: Vec::new(),
        source: EvidenceSource::Psql,
        notes: Vec::new(),
    };
    let user = insp
        .env("POSTGRES_USER")
        .filter(|u| !u.is_empty())
        .unwrap_or("postgres");
    let db = insp
        .env("POSTGRES_DB")
        .filter(|d| !d.is_empty())
        .unwrap_or(user);
    match docker
        .psql(&insp.id, user, db, QUERY)
        .and_then(|out| parse_psql(&out))
    {
        Ok(row) => {
            ev.wal_bytes = row.wal_bytes;
            ev.data_bytes = row.data_bytes;
            ev.failed_count = row.failed_count;
            ev.last_archived_at = row.last_archived_at;
            ev.last_failed_at = row.last_failed_at;
            ev.last_failed_wal = row.last_failed_wal;
            ev.archive_mode = row.archive_mode;
            ev.archive_command = row.archive_command;
            ev.archive_timeout = row.archive_timeout;
        }
        Err(e) => {
            ev.source = EvidenceSource::ApiOnly;
            ev.notes.push(format!(
                "psql not used: {e}; settings come from the container's command line and \
                 failures from its last {LOG_TAIL} log lines"
            ));
            api_only(insp, docker, &mut ev);
        }
    }
    let project = insp.label(COMPOSE_PROJECT).map(str::to_string);
    let hosts = ev
        .archive_command
        .as_deref()
        .map(archive_hosts)
        .unwrap_or_default();
    ev.targets = hosts
        .into_iter()
        .map(|h| resolve_target(&h, project.as_deref(), listed, docker, cache))
        .collect();
    ev
}

/// Settings from the command line, failures from the log tail.
fn api_only(insp: &Inspect, docker: &dyn Docker, ev: &mut PostgresWal) {
    let settings = command_settings(&insp.args);
    ev.archive_mode = settings.get("archive_mode").cloned();
    ev.archive_command = settings.get("archive_command").cloned();
    ev.archive_timeout = settings.get("archive_timeout").cloned();
    let path = format!(
        "/containers/{}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}",
        insp.id
    );
    match docker.get(&path) {
        Ok(raw) => {
            let text = if insp.config.tty {
                raw
            } else {
                crate::docker::demux_logs(&raw)
            };
            let scan = scan_log(&String::from_utf8_lossy(&text));
            ev.failed_count = Some(scan.failures);
            ev.last_failed_at = scan.last_failure.map(rfc3339);
            ev.last_failed_wal = scan.last_failed_wal;
            if ev.archive_command.is_none() {
                ev.archive_command = scan.failed_command;
            }
            if scan.failures > 0 {
                ev.notes.push(format!(
                    "failed_count counts failures in the last {LOG_TAIL} log lines only"
                ));
            }
        }
        Err(e) => ev.notes.push(format!("log tail not read: {e}")),
    }
}

/// One row of [`QUERY`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PsqlRow {
    pub wal_bytes: Option<u64>,
    pub data_bytes: Option<u64>,
    pub failed_count: Option<u64>,
    pub last_archived_at: Option<String>,
    pub last_failed_at: Option<String>,
    pub last_failed_wal: Option<String>,
    pub archive_mode: Option<String>,
    pub archive_command: Option<String>,
    pub archive_timeout: Option<String>,
}

/// Parses psql's output for [`QUERY`] (`-A -t -F` [`FIELD_SEP`]).
pub fn parse_psql(out: &str) -> Result<PsqlRow, String> {
    let row = out.trim_end_matches(['\n', '\r']);
    let fields: Vec<&str> = row.split(FIELD_SEP).collect();
    if fields.len() != 9 {
        return Err(format!(
            "unexpected psql output ({} fields, expected 9)",
            fields.len()
        ));
    }
    let text = |s: &str| (!s.is_empty()).then(|| s.to_string());
    let num = |s: &str| -> Result<Option<u64>, String> {
        if s.is_empty() {
            return Ok(None);
        }
        // sum() of bigint is numeric; it prints without a fraction.
        let int = s.split('.').next().unwrap_or(s);
        int.parse()
            .map(Some)
            .map_err(|_| format!("unexpected psql output: {s:?} is not a number"))
    };
    let time = |s: &str| -> Result<Option<String>, String> {
        if s.is_empty() {
            return Ok(None);
        }
        s.parse::<i64>()
            .map(|t| Some(rfc3339(t)))
            .map_err(|_| format!("unexpected psql output: {s:?} is not a time"))
    };
    Ok(PsqlRow {
        wal_bytes: num(fields[0])?,
        data_bytes: num(fields[1])?,
        failed_count: num(fields[2])?,
        last_archived_at: time(fields[3])?,
        last_failed_at: time(fields[4])?,
        last_failed_wal: text(fields[5]),
        archive_mode: text(fields[6]),
        archive_command: text(fields[7]),
        archive_timeout: text(fields[8]),
    })
}

/// `-c name=value` and `--name=value` settings from a `postgres` command
/// line (names with `-` read as `_`, as Postgres does).
pub fn command_settings(args: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut put = |kv: &str| {
        if let Some((k, v)) = kv.split_once('=') {
            out.insert(k.trim().replace('-', "_"), v.to_string());
        }
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-c" {
            if let Some(kv) = it.next() {
                put(kv);
            }
        } else if let Some(kv) = a.strip_prefix("-c") {
            put(kv);
        } else if let Some(kv) = a.strip_prefix("--") {
            put(kv);
        }
    }
    out
}

/// What the log tail says about archiving.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogScan {
    /// `archive command failed …` lines.
    pub failures: u64,
    /// Seconds since the epoch of the earliest and latest failure line that
    /// carried a time.
    pub first_failure: Option<i64>,
    pub last_failure: Option<i64>,
    /// From `archiving write-ahead log file "…" failed too many times`.
    pub last_failed_wal: Option<String>,
    /// From `The failed archive command was: …`.
    pub failed_command: Option<String>,
}

/// Reads Postgres log lines (each optionally prefixed by Docker's
/// RFC 3339 timestamp, as `timestamps=1` gives) for archiver failures.
pub fn scan_log(text: &str) -> LogScan {
    let mut s = LogScan::default();
    for line in text.lines() {
        let when = line_time(line);
        if line.contains("archive command failed")
            || line.contains("archive command was terminated")
        {
            s.failures += 1;
            if let Some(t) = when {
                s.first_failure = Some(s.first_failure.map_or(t, |f| f.min(t)));
                s.last_failure = Some(s.last_failure.map_or(t, |l| l.max(t)));
            }
        }
        if let Some(rest) = line.split("archiving write-ahead log file \"").nth(1)
            && let Some((wal, _)) = rest.split_once('"')
        {
            s.last_failed_wal = Some(wal.to_string());
        }
        if let Some((_, cmd)) = line.split_once("The failed archive command was: ") {
            s.failed_command = Some(cmd.trim().to_string());
        }
    }
    s
}

/// The time a log line was written: Docker's timestamp prefix, or
/// Postgres's own `YYYY-MM-DD HH:MM:SS[.fff] UTC` prefix.
fn line_time(line: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let first = line.split_whitespace().next()?;
    if let Ok(t) = time::OffsetDateTime::parse(first, &Rfc3339) {
        return Some(t.unix_timestamp());
    }
    let mut w = line.split_whitespace();
    let (date, clock, zone) = (w.next()?, w.next()?, w.next()?);
    if zone != "UTC" {
        return None;
    }
    let clock = clock.split('.').next()?;
    time::OffsetDateTime::parse(&format!("{date}T{clock}Z"), &Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

/// Hosts `archive_command` sends WAL to: URL hosts (`http://s3test:9000`),
/// `host:port` words, and the values of `--endpoint-url`, `--endpoint`,
/// `--host` and `-h`. In order, without repeats.
pub fn archive_hosts(cmd: &str) -> Vec<String> {
    let words: Vec<&str> = cmd
        .split(|c: char| c.is_whitespace() || "'\"`;|&()<>".contains(c))
        .filter(|w| !w.is_empty())
        .collect();
    let mut out: Vec<String> = Vec::new();
    let mut add = |h: Option<String>| {
        if let Some(h) = h
            && !out.contains(&h)
        {
            out.push(h);
        }
    };
    const VALUE_FLAGS: &[&str] = &["--endpoint-url", "--endpoint", "--host", "-h"];
    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        if VALUE_FLAGS.contains(&w) {
            if let Some(v) = words.get(i + 1) {
                add(host_of(v));
            }
            i += 2;
            continue;
        }
        if let Some(v) = VALUE_FLAGS
            .iter()
            .filter(|f| f.starts_with("--"))
            .find_map(|f| w.strip_prefix(f)?.strip_prefix('='))
        {
            add(host_of(v));
        } else if w.contains("://") {
            let parts: Vec<&str> = w.split("://").collect();
            for (before, part) in parts.iter().zip(&parts[1..]) {
                let scheme = before
                    .rsplit(|c: char| !(c.is_ascii_alphanumeric() || "+.-".contains(c)))
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                // Bucket and path URLs name no host.
                if !NO_HOST_SCHEMES.contains(&scheme.as_str()) {
                    add(host_of(part));
                }
            }
        } else if let Some((h, port)) = w.split_once(':') {
            let port = port.split('/').next().unwrap_or("");
            if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                add(valid_host(h));
            }
        }
        i += 1;
    }
    out
}

/// URL schemes whose authority is a bucket or nothing, not a host.
const NO_HOST_SCHEMES: &[&str] = &["s3", "s3a", "gs", "az", "file"];

/// The host of `[scheme://][user@]host[:port][/path]`.
fn host_of(s: &str) -> Option<String> {
    let s = s.rsplit("://").next().unwrap_or(s);
    let authority = s.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(v6) = authority.strip_prefix('[') {
        return v6
            .split(']')
            .next()
            .filter(|h| !h.is_empty())
            .map(String::from);
    }
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    };
    valid_host(host)
}

fn valid_host(h: &str) -> Option<String> {
    (!h.is_empty()
        && h.as_bytes()[0].is_ascii_alphanumeric()
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'))
    .then(|| h.to_string())
}

fn is_ip(h: &str) -> bool {
    h.parse::<std::net::IpAddr>().is_ok()
}

/// Matches `host` with a container by name, Compose service or network
/// alias, preferring a running one, then one of the same Compose project.
fn resolve_target(
    host: &str,
    project: Option<&str>,
    listed: &[Listed],
    docker: &dyn Docker,
    cache: &mut Inspects,
) -> ArchiveTarget {
    let unresolved = || ArchiveTarget {
        host: host.into(),
        container: None,
        state: "unresolved".into(),
    };
    let rank = |c: &Listed| {
        (
            c.state == "running",
            project.is_some() && c.label(COMPOSE_PROJECT) == project,
        )
    };
    let mut matches = Vec::new();
    let mut incomplete = false;
    for c in listed {
        let aliases_match = match cache.get(docker, &c.id) {
            Some(i) => i.aliases().any(|a| a == host),
            None => {
                incomplete = true;
                false
            }
        };
        if c.names.iter().any(|n| n.trim_start_matches('/') == host)
            || c.label(COMPOSE_SERVICE) == Some(host)
            || aliases_match
        {
            matches.push(c);
        }
    }
    if incomplete {
        return unresolved();
    }
    matches.sort_by_key(|c| std::cmp::Reverse(rank(c)));
    match matches.first() {
        Some(c) => ArchiveTarget {
            host: host.into(),
            container: Some(name_of(&c.names, &c.id)),
            state: c.state.clone(),
        },
        None if host.contains('.') || host == "localhost" || is_ip(host) => unresolved(),
        None => ArchiveTarget {
            host: host.into(),
            container: None,
            state: "missing".into(),
        },
    }
}

// ---------------------------------------------------------------------------
// Diagnosis
// ---------------------------------------------------------------------------

fn archiving_on(ev: &PostgresWal) -> bool {
    matches!(ev.archive_mode.as_deref(), Some("on" | "always"))
}

/// The archiver is failing now: failures and none succeeded since.
pub fn failing(ev: &PostgresWal) -> bool {
    if ev.failed_count.unwrap_or(0) == 0 {
        return false;
    }
    match (&ev.last_failed_at, &ev.last_archived_at) {
        (Some(f), Some(a)) => f > a,
        // pg_stat_archiver failures without a time, or never archived.
        (_, None) => true,
        (None, Some(_)) => ev.source == EvidenceSource::ApiOnly,
    }
}

/// WAL far larger than the data with archiving on.
pub fn wal_heavy(ev: &PostgresWal) -> bool {
    match (ev.wal_bytes, ev.data_bytes) {
        (Some(w), Some(d)) => archiving_on(ev) && w >= BIG_WAL && w > d.saturating_mul(WAL_RATIO),
        _ => false,
    }
}

/// Targets that cannot be receiving WAL: a container not running, or a
/// container name nothing answers to.
pub fn dead_targets(ev: &PostgresWal) -> Vec<&ArchiveTarget> {
    ev.targets
        .iter()
        .filter(|t| !matches!(t.state.as_str(), "running" | "unresolved"))
        .collect()
}

fn describe_target(t: &ArchiveTarget) -> String {
    match &t.container {
        Some(c) if *c != t.host => format!("{} ({c}) {}", t.host, t.state),
        _ => format!("{} {}", t.host, t.state),
    }
}

fn date(rfc: &str) -> &str {
    rfc.split('T').next().unwrap_or(rfc)
}

/// The one-line diagnosis that leads the finding's reason, e.g. "pg_wal
/// holds 29G vs 53M data; archive_command has failed 151x (last failure
/// 2026-11-15, last success 2026-11-07) (target s3test exited)".
pub fn diagnosis(ev: &PostgresWal) -> String {
    let mut parts = Vec::new();
    match (ev.wal_bytes, ev.data_bytes) {
        (Some(w), Some(d)) => parts.push(format!("pg_wal holds {} vs {} data", human(w), human(d))),
        (Some(w), None) => parts.push(format!("pg_wal holds {}", human(w))),
        _ => {}
    }
    if ev.source == EvidenceSource::ApiOnly && ev.failed_count.is_none() {
        parts.push(format!(
            "archive failures unknown ({})",
            ev.notes.join("; ")
        ));
    } else if failing(ev) {
        let n = ev.failed_count.unwrap_or(0);
        let mut s = format!("archive_command has failed {n}x");
        if ev.source == EvidenceSource::ApiOnly {
            s.push_str(&format!(" in the last {LOG_TAIL} log lines"));
        } else {
            s.push_str(&format!(
                " (last failure {}, last success {})",
                ev.last_failed_at.as_deref().map(date).unwrap_or("unknown"),
                ev.last_archived_at.as_deref().map(date).unwrap_or("none"),
            ));
        }
        let dead = dead_targets(ev);
        if !dead.is_empty() {
            let list: Vec<String> = dead.iter().map(|t| describe_target(t)).collect();
            s.push_str(&format!(
                " (target{} {})",
                if dead.len() == 1 { "" } else { "s" },
                list.join(", ")
            ));
        }
        parts.push(s);
    } else if wal_heavy(ev) {
        let ratio = ev.wal_bytes.unwrap_or(0) / ev.data_bytes.unwrap_or(1).max(1);
        parts.push(format!(
            "WAL is {ratio}x the data with archiving on, though the archiver reports no failure"
        ));
    } else if !archiving_on(ev) && ev.archive_mode.is_some() {
        parts.push(format!(
            "archiving is {}",
            ev.archive_mode.as_deref().unwrap_or("off")
        ));
    } else if ev.source == EvidenceSource::Psql {
        parts.push("the archiver reports no failure".into());
    } else {
        parts.push(format!(
            "no archive failures in the last {LOG_TAIL} log lines"
        ));
    }
    parts.join("; ")
}

/// The advice that replaces the detector's, when WAL is the problem. Never
/// removing the volume: it holds the database.
pub fn advice(ev: &PostgresWal) -> Option<String> {
    if failing(ev) {
        let dead: Vec<&str> = dead_targets(ev).iter().map(|t| t.host.as_str()).collect();
        Some(if dead.is_empty() {
            "fix archive_command so archiving succeeds; WAL is freed at the next checkpoint \
             once it is archived (do not remove the volume: it holds the database)"
                .into()
        } else {
            format!(
                "restore the archive target {}; WAL is freed at the next checkpoint once it is \
                 archived (do not remove the volume: it holds the database)",
                dead.join(", ")
            )
        })
    } else if wal_heavy(ev) {
        Some(
            "check what holds WAL back (pg_replication_slots, max_wal_size, a slow archiver); \
             WAL is freed at the next checkpoint once nothing needs it (do not remove the \
             volume: it holds the database)"
                .into(),
        )
    } else {
        None
    }
}

/// A line of detail for text output: where the evidence came from and the
/// settings behind the diagnosis.
pub fn summary(ev: &PostgresWal) -> String {
    let mut bits = vec![format!(
        "{} in {}",
        match ev.source {
            EvidenceSource::Psql => "psql",
            EvidenceSource::ApiOnly => "api-only",
        },
        ev.container
    )];
    if let Some(m) = &ev.archive_mode {
        bits.push(format!("archive_mode {m}"));
    }
    if let Some(t) = &ev.archive_timeout {
        bits.push(format!("archive_timeout {t}"));
    }
    if let Some(a) = &ev.last_archived_at {
        bits.push(format!("last archived {a}"));
    }
    if let Some(f) = &ev.last_failed_at {
        bits.push(format!("last failed {f}"));
    }
    if let Some(w) = &ev.last_failed_wal {
        bits.push(format!("failed WAL {w}"));
    }
    if !ev.targets.is_empty() {
        let t: Vec<String> = ev.targets.iter().map(describe_target).collect();
        bits.push(format!("archive target {}", t.join(", ")));
    }
    let mut s = bits.join(", ");
    if ev.source == EvidenceSource::ApiOnly && !ev.notes.is_empty() {
        s.push_str(&format!(" ({})", ev.notes.join("; ")));
    }
    s
}

/// Puts the evidence on the finding: the probe's name, the evidence, the
/// diagnosis ahead of the detector's reason, and the advice when WAL is
/// the problem. The tier is left alone.
pub fn annotate(f: &mut Finding, ev: PostgresWal) {
    f.probe = Some(NAME.into());
    f.reason = format!("{}; {}", diagnosis(&ev), f.reason);
    if let Some(text) = advice(&ev) {
        f.action.kind = ActionKind::Advice;
        f.action.text = text;
        f.action.argv = None;
        f.recovery.cost = "n/a: nothing is removed; Postgres recycles WAL itself".into();
    }
    f.evidence.get_or_insert_with(Default::default).postgres_wal = Some(ev);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_from_archive_commands() {
        assert_eq!(
            archive_hosts("aws --endpoint-url http://s3test:9000 s3 cp %p s3://wal/%f && echo ok"),
            ["s3test"]
        );
        assert_eq!(
            archive_hosts("wal-g wal-push %p gs://bucket/x file:///mnt/wal"),
            Vec::<String>::new()
        );
        assert_eq!(
            archive_hosts("AWS_ENDPOINT_URL=https://minio.local:9000/x wal-g wal-push %p"),
            ["minio.local"]
        );
        assert_eq!(
            archive_hosts("curl -fsS -T %p 'http://user:pw@archive:8080/put/%f'"),
            ["archive"]
        );
        assert_eq!(archive_hosts("pg_receivewal -h backup -p 5432"), ["backup"]);
        assert_eq!(
            archive_hosts("x --host=db2 --endpoint-url=s3test:9000"),
            ["db2", "s3test"]
        );
        assert_eq!(archive_hosts("nc store:7000 < %p"), ["store"]);
        assert_eq!(
            archive_hosts("rsync -ah %p /mnt/wal/%f"),
            Vec::<String>::new()
        );
        assert_eq!(
            archive_hosts("test ! -f /wal/%f && cp %p /wal/%f"),
            Vec::<String>::new()
        );
        assert_eq!(archive_hosts("curl http://[::1]:9000/x"), ["::1"]);
    }

    #[test]
    fn settings_from_the_command_line() {
        let args: Vec<String> = [
            "postgres",
            "-c",
            "archive_mode=on",
            "-carchive_timeout=10s",
            "--archive-command=curl -T %p http://s3test:9000/%f",
            "-c",
        ]
        .map(String::from)
        .to_vec();
        let s = command_settings(&args);
        assert_eq!(s["archive_mode"], "on");
        assert_eq!(s["archive_timeout"], "10s");
        assert_eq!(s["archive_command"], "curl -T %p http://s3test:9000/%f");
    }

    #[test]
    fn psql_rows() {
        let sep = FIELD_SEP;
        let out = format!(
            "31138512896{sep}55574528{sep}151{sep}1794040000{sep}1794700000{sep}000000010000000000000097{sep}on{sep}curl http://s3test:9000/%f{sep}10s\n"
        );
        let r = parse_psql(&out).unwrap();
        assert_eq!(r.wal_bytes, Some(31_138_512_896));
        assert_eq!(r.failed_count, Some(151));
        assert_eq!(r.last_archived_at.as_deref(), Some("2026-11-07T08:26:40Z"));
        assert_eq!(r.archive_timeout.as_deref(), Some("10s"));
        let empty = format!("0{sep}100{sep}0{sep}{sep}{sep}{sep}off{sep}{sep}0\n");
        let r = parse_psql(&empty).unwrap();
        assert_eq!(r.last_archived_at, None);
        assert_eq!(r.archive_command, None);
        assert!(parse_psql("ERROR\n").is_err());
        assert!(parse_psql(&format!("x{}", format!("{sep}").repeat(8))).is_err());
    }

    #[test]
    fn psql_is_read_only_and_never_prompts() {
        let a = psql_argv("docker", "/run/d.sock", "abc", "app", "appdb", QUERY);
        let s: Vec<&str> = a.iter().map(String::as_str).collect();
        assert_eq!(&s[..4], ["docker", "-H", "unix:///run/d.sock", "exec"]);
        assert!(
            s.contains(&"PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10s")
        );
        for setting in [
            "PGHOST=",
            "PGHOSTADDR=",
            "PGSERVICE=",
            "PGSERVICEFILE=/dev/null",
        ] {
            assert!(s.windows(2).any(|w| w == ["-e", setting]), "{setting}");
        }
        assert_eq!(
            s[s.iter().position(|x| *x == "-d").unwrap() + 1],
            "dbname='appdb'"
        );
        // No terminal and no stdin for docker exec (psql's own -t comes after "psql").
        let psql = s.iter().position(|x| *x == "psql").unwrap();
        assert!(
            s[..psql]
                .iter()
                .all(|x| !matches!(*x, "-i" | "-t" | "-it" | "--interactive" | "--tty"))
        );
        let begin = s.iter().position(|x| *x == "BEGIN READ ONLY").unwrap();
        let q = s.iter().position(|x| *x == QUERY).unwrap();
        assert!(begin < q);
        assert!(s.contains(&"-X") && s.contains(&"-w"));
        assert_eq!(s[s.iter().position(|x| *x == "-U").unwrap() + 1], "app");
    }

    #[test]
    fn psql_database_is_a_literal_libpq_name() {
        for (db, expected) in [
            ("appdb", "dbname='appdb'"),
            ("x host=10.0.0.5", "dbname='x host=10.0.0.5'"),
            (
                r"x\' host=10.0.0.5 options='-c default_transaction_read_only=off'",
                r"dbname='x\\\' host=10.0.0.5 options=\'-c default_transaction_read_only=off\''",
            ),
            (
                "postgresql://10.0.0.5/app",
                "dbname='postgresql://10.0.0.5/app'",
            ),
        ] {
            let a = psql_argv("docker", "/run/d.sock", "abc", "app", db, QUERY);
            let d = a.iter().position(|x| x == "-d").unwrap();
            assert_eq!(a[d + 1], expected);
        }
    }

    #[test]
    fn log_lines() {
        let log = "\
2026-11-13T02:09:00.1Z 2026-11-13 02:09:00.100 UTC [61] LOG:  archive command failed with exit code 6
2026-11-13T02:09:00.1Z 2026-11-13 02:09:00.100 UTC [61] DETAIL:  The failed archive command was: curl -T pg_wal/000000010000000000000097 http://s3test:9000/wal/000000010000000000000097
2026-11-13T02:10:00.5Z 2026-11-13 02:10:00.500 UTC [61] LOG:  archive command failed with exit code 6
2026-11-13T02:10:00.6Z 2026-11-13 02:10:00.600 UTC [61] WARNING:  archiving write-ahead log file \"000000010000000000000097\" failed too many times, will try again later
";
        let s = scan_log(log);
        assert_eq!(s.failures, 2);
        assert_eq!(
            s.first_failure.map(rfc3339).as_deref(),
            Some("2026-11-13T02:09:00Z")
        );
        assert_eq!(
            s.last_failure.map(rfc3339).as_deref(),
            Some("2026-11-13T02:10:00Z")
        );
        assert_eq!(
            s.last_failed_wal.as_deref(),
            Some("000000010000000000000097")
        );
        assert!(s.failed_command.unwrap().contains("http://s3test:9000"));
        // Postgres's own prefix when Docker adds none.
        let s = scan_log(
            "2026-11-13 02:09:00.100 UTC [61] LOG:  archive command failed with exit code 1",
        );
        assert_eq!(
            s.last_failure.map(rfc3339).as_deref(),
            Some("2026-11-13T02:09:00Z")
        );
    }

    #[test]
    fn run_with_timeout_kills_a_hung_command() {
        let mut c = Command::new("sleep");
        c.arg("5");
        let start = Instant::now();
        let e = run_with_timeout(c, Duration::from_millis(200)).unwrap_err();
        assert!(e.contains("no answer within"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(3));
        let mut c = Command::new("echo");
        c.arg("hi");
        let out = run_with_timeout(c, Duration::from_secs(5)).unwrap();
        assert_eq!(out.stdout, b"hi\n");
    }
}
