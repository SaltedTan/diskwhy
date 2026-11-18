//! `postgres-wal`: why a Docker volume holding a Postgres data directory is
//! big. The usual answer on a dev box is WAL piling up in `pg_wal` because
//! `archive_command` keeps failing, often because the archive target (a
//! fake S3 container, say) has exited.
//!
//! The read-only probe is specified under Decisions taken in `docs/DESIGN.md`.
//!
//! The system is behind the [`Docker`] trait so tests can replay recorded
//! responses.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::detect::DetectContext;
use crate::docker::{Api, GetError};
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
/// WAL at least this large and more than [`WAL_RATIO`] times the data, with
/// archiving on, is worth advice even when the archiver reports no failure.
const BIG_WAL: u64 = 1 << 30;
const WAL_RATIO: u64 = 4;

const UNSET_PG_ENV: [&str; 3] = ["PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"];

/// The read-only queries, as one row. Fields are separated by
/// [`FIELD_SEP`]; times are seconds since the epoch.
pub const QUERY: &str = "SELECT \
(SELECT coalesce(sum(size), 0) FROM pg_catalog.pg_ls_waldir()), \
(SELECT sum(pg_catalog.pg_database_size(oid)) FROM pg_catalog.pg_database), \
a.failed_count, \
extract(epoch FROM a.last_archived_time), \
extract(epoch FROM a.last_failed_time), \
a.last_failed_wal, \
pg_catalog.current_setting('archive_mode'), \
pg_catalog.current_setting('archive_command'), \
pg_catalog.current_setting('archive_timeout') \
FROM pg_catalog.pg_stat_archiver a";

/// psql's field separator (`-F`): ASCII unit separator, which settings and
/// WAL file names do not contain.
pub const FIELD_SEP: char = '\x1f';

/// What the probe needs from the system. Every method only reads.
pub trait Docker {
    /// An Engine API GET; the response body.
    fn get(&self, path: &str) -> Result<Vec<u8>, GetError>;
    /// Runs [`QUERY`]-style SQL with psql in the container, read-only, as
    /// `user` on database `db`; psql's stdout.
    fn psql(
        &self,
        container_id: &str,
        user: &str,
        db: &str,
        sql: &str,
    ) -> Result<String, PsqlError>;
}

#[derive(Debug, Clone)]
pub enum PsqlError {
    Exec,
    Timeout,
    Failed,
}

impl PsqlError {
    fn category(&self) -> &'static str {
        match self {
            Self::Exec => "docker exec failed",
            Self::Timeout => "psql: timed out",
            Self::Failed => "psql failed",
        }
    }
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
    fn get(&self, path: &str) -> Result<Vec<u8>, GetError> {
        self.api.get(path)
    }

    fn psql(
        &self,
        container_id: &str,
        user: &str,
        db: &str,
        sql: &str,
    ) -> Result<String, PsqlError> {
        let docker = self.docker.as_deref().ok_or(PsqlError::Exec)?;
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
        for name in UNSET_PG_ENV {
            cmd.env_remove(name);
        }
        let out = run_with_timeout(cmd, self.exec_timeout)?;
        if !out.status.success() {
            return Err(if out.stderr.starts_with(b"Error response from daemon:") {
                PsqlError::Exec
            } else {
                PsqlError::Failed
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// The `docker exec` command line: psql without a psqlrc, never prompting
/// for a password, over the container's local socket. On timeout, diskwhy
/// kills the Docker CLI. Inside the container, psql has its own limits:
/// `PGCONNECT_TIMEOUT` (5 s) for connecting and `statement_timeout` (10 s)
/// per statement. The query only reads and runs inside `BEGIN READ ONLY`.
/// Run as argv, never through a shell.
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
        "PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10s -c search_path=pg_catalog",
        "-e",
        "PGCONNECT_TIMEOUT=5",
        // Empty: the local socket, never a server PGHOST names.
        "-e",
        "PGHOST=",
        "-e",
        UNSET_PG_ENV[0],
        "-e",
        UNSET_PG_ENV[1],
        "-e",
        UNSET_PG_ENV[2],
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
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Output, PsqlError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| PsqlError::Exec)?;
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
                return Err(PsqlError::Timeout);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return Err(PsqlError::Exec),
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
    pub host_config: HostConfig,
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
pub struct HostConfig {
    pub tmpfs: Option<HashMap<String, String>>,
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
}

impl Endpoint {
    fn matching_name(&self, host: &str) -> Option<&str> {
        self.aliases
            .iter()
            .flatten()
            .chain(self.dns_names.iter().flatten())
            .find(|alias| alias.eq_ignore_ascii_case(host))
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
    let Some(listed) = docker
        .get("/containers/json?all=1")
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<Listed>>(&b).ok())
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
struct Inspects(HashMap<String, Result<Option<Inspect>, ()>>);

impl Inspects {
    fn get(&mut self, docker: &dyn Docker, id: &str) -> Result<Option<&Inspect>, ()> {
        self.0
            .entry(id.to_string())
            .or_insert_with(|| match docker.get(&format!("/containers/{id}/json")) {
                Ok(body) => serde_json::from_slice(&body).map(Some).map_err(|_| ()),
                Err(GetError::Http(404, _)) => Ok(None),
                Err(_) => Err(()),
            })
            .as_ref()
            .map(Option::as_ref)
            .map_err(|_| ())
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
        let Ok(Some(insp)) = cache.get(docker, &c.id) else {
            continue;
        };
        let insp = insp.clone();
        if insp.state.status != "running" {
            continue;
        }
        let pgdata = insp.env("PGDATA").unwrap_or(DEFAULT_PGDATA);
        let at_data_dir = insp
            .mounts
            .iter()
            .map(|m| {
                (
                    m.destination.as_str(),
                    m.kind == "volume" && m.name == volume,
                )
            })
            .chain(
                insp.host_config
                    .tmpfs
                    .iter()
                    .flat_map(|m| m.keys())
                    .map(|path| (path.as_str(), false)),
            )
            .filter(|(path, _)| path.starts_with('/') && Path::new(pgdata).starts_with(path))
            .max_by_key(|(path, _)| Path::new(path).components().count())
            .is_some_and(|(_, is_volume)| is_volume);
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
        archive_program: None,
        archive_timeout: None,
        targets: Vec::new(),
        unmatched_hosts: 0,
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
    let raw_command = match docker
        .psql(&insp.id, user, db, QUERY)
        .and_then(|out| parse_psql(&out).map_err(|_| PsqlError::Failed))
    {
        Ok(row) => {
            ev.wal_bytes = row.wal_bytes;
            ev.data_bytes = row.data_bytes;
            ev.failed_count = row.failed_count;
            ev.last_archived_at = row.last_archived_at;
            ev.last_failed_at = row.last_failed_at;
            ev.last_failed_wal = row.last_failed_wal;
            ev.archive_mode = row.archive_mode;
            ev.archive_timeout = row.archive_timeout;
            row.archive_command
        }
        Err(error) => {
            ev.source = EvidenceSource::ApiOnly;
            let category = error.category();
            ev.notes.push(format!(
                "psql not used: {category}; fallback reads command-line settings and up to {LOG_TAIL} log lines"
            ));
            api_only(insp, docker, &mut ev)
        }
    };
    if let Some(raw) = raw_command {
        let (program, hosts) = analyze_archive_command(&raw);
        for host in &hosts {
            match resolve_target(host, insp, listed, docker, cache) {
                Ok(Some(target)) => ev.targets.push(target),
                Ok(None) => ev.unmatched_hosts += 1,
                Err(()) => break,
            }
        }
        ev.archive_program = Some(program);
    }
    ev
}

/// Settings from the command line, failures from the log tail.
fn api_only(insp: &Inspect, docker: &dyn Docker, ev: &mut PostgresWal) -> Option<String> {
    let mut settings = command_settings(&insp.args);
    ev.archive_mode = settings.remove("archive_mode");
    ev.archive_timeout = settings.remove("archive_timeout");
    let command = settings.remove("archive_command");
    let path = format!(
        "/containers/{}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}",
        insp.id
    );
    let logs = docker
        .get(&path)
        .map_err(|error| match error {
            GetError::Http(status, _) => Some(status),
            GetError::Other(_) => None,
        })
        .and_then(|raw| {
            let body = if insp.config.tty {
                raw
            } else {
                crate::docker::demux_logs(&raw).map_err(|_| None)?
            };
            let text = String::from_utf8_lossy(&body);
            if insp.config.tty
                && text.lines().any(|line| {
                    !line.trim().is_empty()
                        && docker_log_message(line)
                            .is_none_or(|message| message.starts_with("Error grabbing logs:"))
                })
            {
                return Err(None);
            }
            Ok(scan_log(&text))
        });
    match logs {
        Ok(scan) => {
            ev.failed_count = Some(scan.failures);
            ev.last_failed_at = scan.last_failure.and_then(|t| t.format(&Rfc3339).ok());
            ev.last_failed_wal = scan.last_failed_wal;
            if scan.failures > 0 {
                ev.notes.push(format!(
                    "failed_count counts failures in the last {LOG_TAIL} log lines only"
                ));
            }
            command.or(scan.failed_command)
        }
        Err(status) => {
            ev.notes.push(match status {
                Some(status) => format!("log tail unreadable (HTTP {status})"),
                None => "log tail unreadable (daemon error)".into(),
            });
            command
        }
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
        epoch_time(s)
            .and_then(|t| t.format(&Rfc3339).ok())
            .map(Some)
            .ok_or_else(|| "unexpected psql output: invalid archiver time".into())
    };
    Ok(PsqlRow {
        wal_bytes: num(fields[0])?,
        data_bytes: num(fields[1])?,
        failed_count: num(fields[2])?,
        last_archived_at: time(fields[3])?,
        last_failed_at: time(fields[4])?,
        last_failed_wal: archive_file_name(fields[5]),
        archive_mode: archive_mode_value(fields[6]),
        archive_command: text(fields[7]),
        archive_timeout: archive_timeout_value(fields[8]),
    })
}

fn archive_mode_value(value: &str) -> Option<String> {
    let mode = value.to_ascii_lowercase();
    matches!(mode.as_str(), "on" | "off" | "always").then_some(mode)
}

fn archive_timeout_value(value: &str) -> Option<String> {
    let integer = value.trim_start_matches(|c: char| c.is_ascii_digit());
    if integer.len() == value.len() {
        return None;
    }
    let unit = if let Some(fraction) = integer.strip_prefix('.') {
        let rest = fraction.trim_start_matches(|c: char| c.is_ascii_digit());
        if rest.len() == fraction.len() {
            return None;
        }
        rest
    } else {
        integer
    };
    matches!(
        unit.trim_start(),
        "" | "us" | "ms" | "s" | "min" | "h" | "d"
    )
    .then(|| value.to_string())
}

fn archive_file_name(name: &str) -> Option<String> {
    let hex = |text: &str, width| {
        text.len() == width
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    };
    let valid = if let Some(timeline) = name.strip_suffix(".history") {
        hex(timeline, 8)
    } else if let Some(backup) = name.strip_suffix(".backup") {
        backup
            .split_once('.')
            .is_some_and(|(segment, offset)| hex(segment, 24) && hex(offset, 8))
    } else {
        hex(name.strip_suffix(".partial").unwrap_or(name), 24)
    };
    valid.then(|| name.to_string())
}

fn epoch_time(s: &str) -> Option<OffsetDateTime> {
    let magnitude = s.strip_prefix('-').unwrap_or(s);
    let (seconds, fraction) = magnitude.split_once('.').unwrap_or((magnitude, ""));
    if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seconds = seconds.parse::<u64>().ok()? as i128;
    let scale = 10_i128.pow(9 - fraction.len() as u32);
    let fraction = fraction.parse::<u32>().unwrap_or(0) as i128;
    let nanos = seconds * 1_000_000_000 + fraction * scale;
    OffsetDateTime::from_unix_timestamp_nanos(if s.starts_with('-') { -nanos } else { nanos }).ok()
}

/// `-c name=value` and `--name=value` settings from a `postgres` command
/// line (names with `-` read as `_`, as Postgres does).
pub fn command_settings(args: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut put = |kv: &str| {
        if let Some((k, v)) = kv.split_once('=') {
            let key = k.trim().to_ascii_lowercase().replace('-', "_");
            let value = match key.as_str() {
                "archive_mode" => archive_mode_value(v),
                "archive_timeout" => archive_timeout_value(v),
                _ => Some(v.to_string()),
            };
            if let Some(value) = value {
                out.insert(key, value);
            } else {
                out.remove(&key);
            }
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
    /// The latest timestamped failure.
    pub last_failure: Option<OffsetDateTime>,
    /// From `archiving write-ahead log file "…" failed too many times`.
    pub last_failed_wal: Option<String>,
    /// From `The failed archive command was: …`.
    pub failed_command: Option<String>,
}

/// Reads Postgres log lines (each optionally prefixed by Docker's
/// RFC 3339 timestamp, as `timestamps=1` gives) for archiver failures.
pub fn scan_log(text: &str) -> LogScan {
    let mut s = LogScan::default();
    let mut command_detail = false;
    let mut previous_failure = false;
    for line in text.lines() {
        let message = docker_log_message(line).unwrap_or(line);
        let record = postgres_log_record(message);
        if command_detail
            && record.is_none()
            && let Some(command) = &mut s.failed_command
        {
            command.push('\n');
            command.push_str(message);
            continue;
        }
        command_detail = false;
        let Some((level, body)) = record else {
            previous_failure = false;
            continue;
        };
        if previous_failure
            && level == "DETAIL"
            && let Some(command) = body.strip_prefix("The failed archive command was: ")
        {
            s.failed_command = Some(command.trim().to_string());
            command_detail = true;
        }
        previous_failure = false;
        if !matches!(level, "LOG" | "WARNING" | "FATAL") {
            continue;
        }
        if body.starts_with("archive command failed")
            || body.starts_with("archive command was terminated")
        {
            previous_failure = true;
            s.failures += 1;
            if let Some(t) = line_time(line) {
                s.last_failure = Some(s.last_failure.map_or(t, |l| l.max(t)));
            }
        }
        if let Some(rest) = body.strip_prefix("archiving write-ahead log file \"")
            && let Some((wal, _)) = rest.split_once('"')
        {
            s.last_failed_wal = archive_file_name(wal);
        }
    }
    s
}

fn postgres_log_record(mut message: &str) -> Option<(&str, &str)> {
    if message.starts_with([' ', '\t']) {
        return None;
    }
    while let Some((prefix, body)) = message.split_once(": ") {
        if let Some(
            level @ ("DEBUG" | "INFO" | "NOTICE" | "WARNING" | "ERROR" | "LOG" | "FATAL" | "PANIC"
            | "DETAIL" | "HINT" | "CONTEXT" | "STATEMENT"),
        ) = prefix.split_ascii_whitespace().next_back()
        {
            let body = body.trim_start();
            let body = body
                .split_once(": ")
                .filter(|(code, _)| {
                    code.len() == 5
                        && code
                            .bytes()
                            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
                })
                .map_or(body, |(_, message)| message.trim_start());
            return Some((level, body));
        }
        message = body;
    }
    None
}

fn docker_log_message(line: &str) -> Option<&str> {
    let (timestamp, message) = line.split_once(' ')?;
    OffsetDateTime::parse(timestamp, &Rfc3339).ok()?;
    Some(message)
}

/// The time a log line was written: Docker's timestamp prefix, or
/// Postgres's own `YYYY-MM-DD HH:MM:SS[.fff] UTC` prefix.
fn line_time(line: &str) -> Option<OffsetDateTime> {
    let first = line.split_whitespace().next()?;
    if let Ok(t) = OffsetDateTime::parse(first, &Rfc3339) {
        return Some(t);
    }
    let mut w = line.split_whitespace();
    let (date, clock, zone) = (w.next()?, w.next()?, w.next()?);
    if zone != "UTC" {
        return None;
    }
    OffsetDateTime::parse(&format!("{date}T{clock}Z"), &Rfc3339).ok()
}

const ENDPOINT_FLAGS: &[&str] = &["--endpoint-url", "--endpoint", "--host"];
const AUTH_FLAGS: &[&str] = &[
    "-u",
    "-p",
    "--user",
    "--password",
    "--pass",
    "--secret",
    "--token",
    "--key",
];
const NETWORK_SCHEMES: &[&str] = &[
    "http",
    "https",
    "ssh",
    "sftp",
    "ftp",
    "ftps",
    "rsync",
    "tcp",
    "postgres",
    "postgresql",
];

fn shell_separator(c: char) -> bool {
    c.is_whitespace() || ";|&()<>".contains(c)
}

fn command_word(input: &str) -> (usize, String, bool) {
    let mut value = String::new();
    let mut quote = None;
    let mut chars = input.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match (quote, c) {
            (None, c) if shell_separator(c) => return (i, value, true),
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if q == c => quote = None,
            (q, '\\') if q != Some('\'') => {
                if let Some(&(_, next)) = chars.peek()
                    && (q.is_none() || "\"\\$`\n".contains(next))
                {
                    chars.next();
                    if next != '\n' {
                        value.push(next);
                    }
                } else {
                    value.push(c);
                }
            }
            _ => value.push(c),
        }
    }
    (input.len(), value, quote.is_none())
}

fn assignment_name(word: &str) -> Option<&str> {
    let (name, _) = word.split_once('=')?;
    let mut bytes = name.bytes();
    let first = bytes.next()?;
    ((first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    .then_some(name)
}

fn archive_program(mut input: &str, expanded: bool) -> String {
    loop {
        input = input.trim_start_matches(char::is_whitespace);
        let (len, word, closed) = command_word(input);
        if !closed || len == 0 {
            return "***".into();
        }
        if !expanded && assignment_name(&input[..len]).is_some() {
            input = &input[len..];
        } else if !word.is_empty()
            && word
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./+-".contains(&b))
        {
            return word;
        } else {
            return "***".into();
        }
    }
}

fn analyze_archive_command(mut input: &str) -> (String, Vec<String>) {
    let expanded = input.contains("$(") || input.contains('`') || input.contains("${");
    let program = archive_program(input, expanded);
    let mut hosts: Vec<String> = Vec::new();
    if expanded {
        return (program, hosts);
    }
    let mut seen_program = false;
    let mut endpoint_next = false;
    let mut auth_next = false;
    while !input.is_empty() {
        let sep = input.len() - input.trim_start_matches(shell_separator).len();
        let separators = &input[..sep];
        if separators.chars().any(|c| !c.is_whitespace() || c == '\n') {
            endpoint_next = false;
            auth_next = false;
        }
        input = &input[sep..];
        if input.is_empty() {
            break;
        }
        let (len, word, closed) = command_word(input);
        input = &input[len..];
        let endpoint_value = std::mem::take(&mut endpoint_next);
        if std::mem::take(&mut auth_next) || assignment_name(&word).is_some() {
            continue;
        }
        if !closed {
            break;
        }
        if !seen_program {
            seen_program = true;
            continue;
        }
        let (key, value) = word
            .split_once('=')
            .map_or((word.as_str(), None), |(key, value)| (key, Some(value)));
        if AUTH_FLAGS.contains(&key) {
            auth_next = value.is_none();
            continue;
        }
        if word.starts_with("-u") || word.starts_with("-p") {
            continue;
        }
        let endpoint_flag = ENDPOINT_FLAGS.contains(&key);
        let address = if endpoint_flag {
            let Some(value) = value else {
                endpoint_next = true;
                continue;
            };
            value
        } else {
            word.as_str()
        };
        let host = if let Some((scheme, rest)) = address.split_once("://") {
            if NETWORK_SCHEMES
                .iter()
                .any(|s| s.eq_ignore_ascii_case(scheme))
            {
                let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
                let host_port = authority
                    .rsplit_once('@')
                    .map_or(authority, |(_, host)| host);
                endpoint_host(host_port, false)
            } else {
                None
            }
        } else if endpoint_value || endpoint_flag {
            endpoint_host(address, true)
        } else {
            None
        };
        if let Some(host) = host
            && !hosts.iter().any(|h| h.eq_ignore_ascii_case(&host))
        {
            hosts.push(host);
        }
    }
    (program, hosts)
}

fn endpoint_host(authority: &str, port_required: bool) -> Option<String> {
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, port) = ipv6.split_once(']')?;
        host.parse::<std::net::Ipv6Addr>().ok()?;
        (host.to_string(), port)
    } else {
        let end = authority.find(':').unwrap_or(authority.len());
        (valid_host(&authority[..end])?, &authority[end..])
    };
    if port.is_empty() && !port_required
        || port
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .is_some()
    {
        Some(host)
    } else {
        None
    }
}

fn valid_host(h: &str) -> Option<String> {
    (!h.is_empty()
        && h.as_bytes()[0].is_ascii_alphanumeric()
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'))
    .then(|| h.to_string())
}

fn resolve_target(
    host: &str,
    source: &Inspect,
    listed: &[Listed],
    docker: &dyn Docker,
    cache: &mut Inspects,
) -> Result<Option<ArchiveTarget>, ()> {
    let project = source.label(COMPOSE_PROJECT);
    let source_networks = source.network_settings.networks.as_ref();
    let mut best = None;
    for c in listed {
        let Some(inspect) = cache.get(docker, &c.id)? else {
            continue;
        };
        if inspect.state.status.is_empty() {
            return Err(());
        }
        let name_or_service = c
            .names
            .iter()
            .map(|name| name.trim_start_matches('/'))
            .chain(c.label(COMPOSE_SERVICE))
            .find(|name| name.eq_ignore_ascii_case(host));
        let mut matched = name_or_service.map(|name| (false, name));
        for (network, endpoint) in inspect.network_settings.networks.iter().flatten() {
            if let Some(name) = name_or_service.or_else(|| endpoint.matching_name(host)) {
                let shared = source_networks.is_some_and(|nets| nets.contains_key(network));
                let candidate = (shared, name);
                if matched.is_none_or(|previous| candidate > previous) {
                    matched = Some(candidate);
                }
            }
        }
        if let Some((shared_match, name)) = matched {
            let rank = (
                shared_match,
                inspect.state.status == "running",
                project.is_some() && c.label(COMPOSE_PROJECT) == project,
            );
            if best.as_ref().is_none_or(|(current, _)| rank > *current) {
                let container = c
                    .names
                    .first()
                    .map(String::as_str)
                    .into_iter()
                    .chain([inspect.name.as_str()])
                    .map(|name| name.trim_start_matches('/'))
                    .find(|name| !name.is_empty())
                    .unwrap_or(name);
                best = Some((
                    rank,
                    ArchiveTarget {
                        host: name.into(),
                        container: Some(container.into()),
                        state: inspect.state.status.clone(),
                    },
                ));
            }
        }
    }
    Ok(best.map(|(_, target)| target))
}

// ---------------------------------------------------------------------------
// Diagnosis
// ---------------------------------------------------------------------------

fn archiving_on(ev: &PostgresWal) -> bool {
    matches!(ev.archive_mode.as_deref(), Some("on" | "always"))
}

/// Whether SQL evidence shows the latest archive attempt failed.
pub fn failing(ev: &PostgresWal) -> bool {
    if ev.source != EvidenceSource::Psql || !archiving_on(ev) || ev.failed_count.unwrap_or(0) == 0 {
        return false;
    }
    match (&ev.last_failed_at, &ev.last_archived_at) {
        (_, None) => true,
        (Some(f), Some(a)) => OffsetDateTime::parse(f, &Rfc3339)
            .ok()
            .zip(OffsetDateTime::parse(a, &Rfc3339).ok())
            .is_some_and(|(failure, archived)| failure >= archived),
        (None, Some(_)) => false,
    }
}

fn needs_archive_repair(ev: &PostgresWal) -> bool {
    failing(ev)
        || (ev.source == EvidenceSource::ApiOnly
            && ev.archive_mode.as_deref() != Some("off")
            && ev.failed_count.is_some_and(|n| n > 0)
            && !dead_targets(ev).is_empty())
}

/// WAL far larger than the data with archiving on.
pub fn wal_heavy(ev: &PostgresWal) -> bool {
    match (ev.wal_bytes, ev.data_bytes) {
        (Some(w), Some(d)) => {
            ev.source == EvidenceSource::Psql
                && archiving_on(ev)
                && w >= BIG_WAL
                && w > d.saturating_mul(WAL_RATIO)
        }
        _ => false,
    }
}

/// Matched containers that have stopped.
pub fn dead_targets(ev: &PostgresWal) -> Vec<&ArchiveTarget> {
    ev.targets
        .iter()
        .filter(|t| matches!(t.state.as_str(), "exited" | "dead"))
        .collect()
}

fn describe_target(t: &ArchiveTarget) -> String {
    match &t.container {
        Some(c) if *c != t.host => format!("{} ({c}) {}", t.host, t.state),
        _ => format!("{} {}", t.host, t.state),
    }
}

/// The one-line diagnosis that leads the finding's reason.
pub fn diagnosis(ev: &PostgresWal) -> String {
    let mut parts = Vec::new();
    match (ev.wal_bytes, ev.data_bytes) {
        (Some(w), Some(d)) => parts.push(format!("pg_wal holds {} vs {} data", human(w), human(d))),
        (Some(w), None) => parts.push(format!("pg_wal holds {}", human(w))),
        _ => {}
    }
    let failure = ev.last_failed_at.as_deref();
    let success = ev.last_archived_at.as_deref();
    let mut archive = match (ev.source, ev.failed_count) {
        (EvidenceSource::ApiOnly, None) => {
            format!("archive failures unknown ({})", ev.notes.join("; "))
        }
        (EvidenceSource::ApiOnly, Some(n)) => {
            let last = failure
                .map(|t| format!(" (last failure {t})"))
                .unwrap_or_default();
            let observed = if n == 0 {
                format!("no archive failures in the last {LOG_TAIL} log lines")
            } else {
                format!("observed {n} archive failures in the last {LOG_TAIL} log lines{last}")
            };
            format!("{observed}; current archiver health unknown")
        }
        (EvidenceSource::Psql, Some(n)) if failing(ev) => format!(
            "archiving is failing, with {n} failures in total (last failure {}, last success {})",
            failure.unwrap_or("unknown"),
            success.unwrap_or("none"),
        ),
        (EvidenceSource::Psql, _) if !archiving_on(ev) && ev.archive_mode.is_some() => {
            format!(
                "archiving is {}",
                ev.archive_mode.as_deref().unwrap_or("off")
            )
        }
        (EvidenceSource::Psql, Some(n)) if n > 0 => {
            let success = success.unwrap_or("unknown");
            match failure {
                Some(failure) => format!(
                    "archiving works again (last success {success}; {n} failures in total, last {failure})"
                ),
                None => format!(
                    "{n} archive failures in total (last failure unknown, last success {success})"
                ),
            }
        }
        (EvidenceSource::Psql, _) => "the archiver reports no failure".into(),
    };
    if needs_archive_repair(ev) {
        let dead = dead_targets(ev);
        if !dead.is_empty() {
            let list: Vec<String> = dead.iter().map(|t| describe_target(t)).collect();
            archive.push_str(&format!(
                " (target{} {})",
                if dead.len() == 1 { "" } else { "s" },
                list.join(", ")
            ));
        }
    } else if wal_heavy(ev) {
        let ratio = ev.wal_bytes.unwrap_or(0) / ev.data_bytes.unwrap_or(1).max(1);
        parts.push(format!("WAL is {ratio}x the data with archiving on"));
    }
    parts.push(archive);
    match ev.unmatched_hosts {
        0 => {}
        1 => parts.push("archive_command names 1 host that matches no container".into()),
        n => parts.push(format!(
            "archive_command names {n} hosts that match no container"
        )),
    }
    parts.join("; ")
}

/// The advice that replaces the detector's, when WAL is the problem. Never
/// removing the volume: it holds the database.
pub fn advice(ev: &PostgresWal) -> Option<String> {
    if needs_archive_repair(ev) {
        let dead: Vec<&str> = dead_targets(ev).iter().map(|t| t.host.as_str()).collect();
        Some(if dead.is_empty() && ev.unmatched_hosts > 0 {
            let unmatched = match ev.unmatched_hosts {
                1 => "1 host matches no container".into(),
                n => format!("{n} hosts match no container"),
            };
            format!(
                "fix archive_command or start its target ({unmatched}); WAL is freed at the next checkpoint \
                 once it is archived (do not remove the volume: it holds the database)"
            )
        } else if dead.is_empty() {
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
        for (command, expected) in [
            (
                "aws --endpoint-url http://minio:9000 s3 cp %p s3://wal/%f",
                &["minio"][..],
            ),
            ("curl 'http://user:pw@archive:8080/put/%f'", &["archive"]),
            (
                "AWS_ENDPOINT_URL=https://minio.local:9000/x wal-g wal-push %p",
                &[],
            ),
            (
                "x --host=db2:5432 --endpoint minio:9000 --endpoint-url=s3test:9000",
                &["db2", "minio", "s3test"],
            ),
            ("curl http://[::1]:9000/x", &["::1"]),
            ("cp %p backup:2026/%f", &[]),
            ("pg_receivewal -h backup -p 5432", &[]),
            (
                "x --host backup --endpoint-url s3://bucket --endpoint=gs://bucket",
                &[],
            ),
            (
                "x --endpoint-url=abfs://bucket --host wasb://bucket file:///tmp/backup",
                &[],
            ),
            ("x s3://bucket/https://unrelated httpx://guessed", &[]),
            ("https://program x --other=https://argument", &[]),
            (
                "x X=https://assignment --endpoint-url https://endpoint",
                &["endpoint"],
            ),
            (
                "tool --password https://private.example --endpoint https://store",
                &["store"],
            ),
        ] {
            assert_eq!(analyze_archive_command(command).1, expected, "{command}");
        }
    }

    #[test]
    fn settings_from_the_command_line() {
        let args: Vec<String> = [
            "postgres",
            "-c",
            "Archive_Mode=On",
            "-cArchive_Timeout=10s",
            "--ARCHIVE-COMMAND=curl -T %p http://s3test:9000/%f",
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
            s.contains(&"PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10s -c search_path=pg_catalog")
        );
        for setting in ["PGHOST=", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"] {
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
            s.last_failure.unwrap().format(&Rfc3339).unwrap(),
            "2026-11-13T02:10:00.5Z"
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
            s.last_failure.unwrap().format(&Rfc3339).unwrap(),
            "2026-11-13T02:09:00.1Z"
        );
    }

    #[test]
    fn run_with_timeout_kills_a_hung_command() {
        let mut c = Command::new("sleep");
        c.arg("5");
        let start = Instant::now();
        let e = run_with_timeout(c, Duration::from_millis(200)).unwrap_err();
        assert!(matches!(e, PsqlError::Timeout), "{e:?}");
        assert!(start.elapsed() < Duration::from_secs(3));
        let mut c = Command::new("echo");
        c.arg("hi");
        let out = run_with_timeout(c, Duration::from_secs(5)).unwrap();
        assert_eq!(out.stdout, b"hi\n");
    }
}
