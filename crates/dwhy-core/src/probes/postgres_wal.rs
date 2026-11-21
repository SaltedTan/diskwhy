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
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use serde::Deserialize;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::cancel::{Cancel, RunError};
use crate::detect::{DetectContext, PATH_NOT_UTF8};
use crate::docker::{Api, GetError};
use crate::report::{
    ActionKind, ArchiveTarget, DetectorAvailability, EvidenceSource, Finding, GuardStatus,
    PostgresWal,
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
    /// The run was cancelled ([`Cancel`]): its caller has gone.
    Canceled,
}

impl PsqlError {
    fn category(&self) -> &'static str {
        match self {
            Self::Exec => "docker exec failed",
            Self::Timeout => "psql: timed out",
            Self::Failed => "psql failed",
            Self::Canceled => "psql: canceled",
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
    /// Kills `docker exec` when cancelled.
    pub cancel: Cancel,
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
            cancel: ctx.cancel.clone(),
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
            sql,
        );
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .env("PGUSER", user)
            .env("PGDATABASE", db)
            .current_dir("/");
        for name in UNSET_PG_ENV {
            cmd.env_remove(name);
        }
        let out = run_with_timeout(cmd, self.exec_timeout, &self.cancel)?;
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
pub fn psql_argv(docker: &str, socket: &str, container_id: &str, sql: &str) -> Vec<String> {
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
        "-e",
        "PGUSER",
        "-e",
        "PGDATABASE",
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

/// Runs `cmd` with no stdin, killing it after `timeout` or when `cancel`
/// is cancelled. Keeps up to 1 MiB of stdout and of stderr.
fn run_with_timeout(
    mut cmd: Command,
    timeout: Duration,
    cancel: &Cancel,
) -> Result<Output, PsqlError> {
    crate::cancel::output(&mut cmd, cancel, Some(timeout), 1 << 20).map_err(|e| match e {
        RunError::Canceled => PsqlError::Canceled,
        RunError::Timeout => PsqlError::Timeout,
        RunError::Spawn(_) | RunError::Wait(_) => PsqlError::Exec,
    })
}

/// Whether the probe looks at a finding: an in-use `docker-volume` one.
pub fn applies_to(f: &Finding) -> bool {
    f.detector == "docker-volume"
        && f.path.starts_with("docker://volume/")
        && f.action.kind == ActionKind::Advice
        && !f
            .guards
            .iter()
            .any(|g| g.name == PATH_NOT_UTF8 && g.status == GuardStatus::Block)
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
    /// The program the container runs (the entrypoint's, usually).
    pub path: String,
    /// Arguments after [`path`](Self::path) (the command, usually).
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
    probe_all_with(findings, docker, None);
}

/// [`probe_all`], checking each volume against `listed`, the `/system/df`
/// snapshot its finding came from: when that recorded the volume's
/// `CreatedAt`, evidence is kept only if `GET /volumes/{name}` still gives
/// the same time after probing. A volume recreated under its name in the
/// meantime (`docker compose down -v && up`) is another volume, and its
/// WAL says nothing about the finding.
pub fn probe_all_with(
    findings: &mut [Finding],
    docker: &dyn Docker,
    listed: Option<&crate::docker::Snapshot>,
) {
    if !findings.iter().any(applies_to) {
        return;
    }
    let Some(containers) = docker
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
        if let Some(ev) = probe_volume(volume, &containers, docker, &mut cache)
            && same_volume(volume, listed, docker)
        {
            annotate(f, ev);
        }
    }
}

/// `GET /volumes/{name}` (only what the probe reads).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct VolumeInspect {
    created_at: String,
}

/// Whether `volume` is still the one `listed` recorded. Nothing to compare
/// (no snapshot, or no creation time on either side) counts as the same;
/// a volume the daemon no longer gives, or cannot, does not.
fn same_volume(
    volume: &str,
    listed: Option<&crate::docker::Snapshot>,
    docker: &dyn Docker,
) -> bool {
    let Some(created) = listed
        .and_then(|l| l.volumes().iter().find(|v| v.name == volume))
        .map(|v| v.created_at.as_str())
        .filter(|t| !t.is_empty())
    else {
        return true;
    };
    docker
        .get(&format!("/volumes/{}", path_segment(volume)))
        .ok()
        .and_then(|body| serde_json::from_slice::<VolumeInspect>(&body).ok())
        .is_some_and(|now| now.created_at.is_empty() || now.created_at == created)
}

/// `s` percent-encoded for one URL path segment.
fn path_segment(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
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
    let mut settings = command_settings(&insp.path, &insp.args);
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

/// Postgres's upper limit for `archive_timeout`: `INT_MAX / 2` seconds.
const ARCHIVE_TIMEOUT_MAX: f64 = (i32::MAX / 2) as f64;

/// C's `isspace`.
fn c_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// `value` (without surrounding whitespace) when Postgres would accept it
/// as `archive_timeout`: an integer setting in seconds, read as its
/// `parse_int` reads one. That is a decimal, octal (`010`) or hex (`0x1e`)
/// integer, or a decimal number with a fraction or exponent (`1e2`, `10.`,
/// `.5`). An optional unit (`us`, `ms`, `s`, `min`, `h`, `d`) may follow
/// after optional whitespace. The value is rounded to whole seconds and
/// must be from 0 to [`ARCHIVE_TIMEOUT_MAX`]. Hex fractions, which
/// Postgres also reads, are refused.
fn archive_timeout_value(value: &str) -> Option<String> {
    let text = value.trim_start_matches(c_space);
    let (number, rest) = c_number(text)?;
    let rest = rest.trim_start_matches(c_space);
    let (unit, trailing) = rest.split_at(rest.find(c_space).unwrap_or(rest.len()));
    if !trailing.trim_start_matches(c_space).is_empty() {
        return None;
    }
    // Each unit's size in seconds, then the next smaller unit's, which a
    // fraction is rounded to first.
    let (size, next) = match unit {
        "" => (1.0, None),
        "d" => (86_400.0, Some(3_600.0)),
        "h" => (3_600.0, Some(60.0)),
        "min" => (60.0, Some(1.0)),
        "s" => (1.0, Some(1e-3)),
        "ms" => (1e-3, Some(1e-6)),
        "us" => (1e-6, None),
        _ => return None,
    };
    let mut seconds = number * size;
    if let (false, Some(next)) = (unit.is_empty(), next) {
        seconds = (seconds / next).round_ties_even() * next;
    }
    (0.0..=ARCHIVE_TIMEOUT_MAX)
        .contains(&seconds.round_ties_even())
        .then(|| value.trim_matches(c_space).to_string())
}

/// The number at the start of `s` as `strtol(s, _, 0)` reads it, or
/// `strtod` when that stops at `.`, `e` or `E`; the text after it.
fn c_number(s: &str) -> Option<(f64, &str)> {
    let digits = |s: &str, radix: u32| s.find(|c: char| !c.is_digit(radix)).unwrap_or(s.len());
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    let sign = s.len() - unsigned.len();
    let negative = s.starts_with('-');
    let signed = |v: f64| if negative { -v } else { v };
    let hex = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
        .filter(|h| h.starts_with(|c: char| c.is_ascii_hexdigit()));
    let (radix, start) = match hex {
        Some(_) => (16, 2),
        None if unsigned.starts_with('0') => (8, 0),
        None => (10, 0),
    };
    let body = &unsigned[start..];
    let len = digits(body, radix);
    let after = &body[len..];
    if !after.starts_with(['.', 'e', 'E']) {
        if len == 0 {
            return None;
        }
        let v = body[..len].chars().fold(0.0, |v, c| {
            v * radix as f64 + c.to_digit(radix).unwrap_or(0) as f64
        });
        return Some((signed(v), after));
    }
    if radix == 16 {
        return None;
    }
    // strtod, from the start: [sign] digits [. digits] [e [sign] digits].
    let int = digits(unsigned, 10);
    let mut end = int;
    let mut fraction = 0;
    if unsigned[end..].starts_with('.') {
        fraction = digits(&unsigned[end + 1..], 10);
        end += 1 + fraction;
    }
    if int + fraction == 0 {
        return None;
    }
    let mantissa = &unsigned[..end];
    if let Some(exp) = unsigned[end..].strip_prefix(['e', 'E']) {
        let exp_digits = exp.strip_prefix(['+', '-']).unwrap_or(exp);
        let n = digits(exp_digits, 10);
        if n > 0 {
            end += 1 + (exp.len() - exp_digits.len()) + n;
        }
    }
    let v: f64 = unsigned[..end].parse().ok()?;
    // strtod reports overflow and underflow as range errors.
    if !v.is_finite()
        || v.is_subnormal()
        || v == 0.0 && mantissa.contains(['1', '2', '3', '4', '5', '6', '7', '8', '9'])
    {
        return None;
    }
    Some((signed(v), &s[sign + end..]))
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

/// Shells, whose `-c` takes a script rather than a Postgres setting.
const SHELLS: &[&str] = &["sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "busybox"];

/// Programs that start Postgres with the options after them.
const POSTGRES_PROGRAMS: &[&str] = &["postgres", "postmaster", "docker-entrypoint.sh"];

/// The Postgres options in a container's command line: `args`, the
/// arguments after `path`, when they start Postgres. That is when the
/// first is one of [`POSTGRES_PROGRAMS`], or is an option (`-c …`) and
/// `path` is one of them (or empty), as when the official image's
/// `docker-entrypoint.sh` passes `Cmd` options to `postgres`. A shell
/// `path` never counts.
fn postgres_options<'a>(path: &str, args: &'a [String]) -> Option<&'a [String]> {
    let base = |s: &'a str| s.rsplit('/').next().unwrap_or(s);
    let path = path.rsplit('/').next().unwrap_or(path);
    if SHELLS.contains(&path) {
        return None;
    }
    let first = args.first()?;
    if POSTGRES_PROGRAMS.contains(&base(first)) {
        Some(&args[1..])
    } else if first.starts_with('-')
        && first != "--"
        && (path.is_empty() || POSTGRES_PROGRAMS.contains(&path))
    {
        Some(args)
    } else {
        None
    }
}

/// `archive_mode`, `archive_timeout` and `archive_command` from the
/// `-c name=value` and `--name=value` options of a container that starts
/// `postgres` (see [`postgres_options`]; names with `-` read as `_`, as
/// Postgres does). Other settings are not kept.
pub fn command_settings(path: &str, args: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(args) = postgres_options(path, args) else {
        return out;
    };
    let mut put = |kv: &str| {
        if let Some((k, v)) = kv.split_once('=') {
            let key = k.trim().to_ascii_lowercase().replace('-', "_");
            let value = match key.as_str() {
                "archive_mode" => archive_mode_value(v),
                "archive_timeout" => archive_timeout_value(v),
                "archive_command" => Some(v.to_string()),
                _ => return,
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
            // Only a file named for this failure goes with its time.
            s.last_failed_wal = None;
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

const ENDPOINT_FLAGS: &[&str] = &["--endpoint-url", "--endpoint", "--host", "--url"];
/// Options whose operand is a credential or names something other than the
/// archive destination (request metadata, a proxy, a request body), for any
/// program. Their operands never name a target.
const OPERAND_FLAGS: &[&str] = &[
    "-u",
    "-p",
    "--user",
    "--password",
    "--pass",
    "--secret",
    "--token",
    "--key",
    "--proxy-user",
    "--oauth2-bearer",
    "--referer",
    "--user-agent",
    "--header",
    "--proxy-header",
    "--cookie",
    "--cookie-jar",
    "--proxy",
    "--preproxy",
    "--socks5",
    "--socks5-hostname",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--form",
];
/// curl's short forms of such options, as the next word or attached
/// (`-H value`, `-Hvalue`). Other programs give these letters other
/// meanings, some without an operand.
const CURL_OPERAND_FLAGS: &[&str] = &["-U", "-e", "-A", "-H", "-b", "-c", "-x", "-d", "-F"];
/// How deep shell scripts (`sh -c '…'`) are read as commands.
const MAX_NESTING: usize = 2;
/// How deep quotes and expansions may nest in one word before it is
/// treated as left open.
const MAX_WORD_NESTING: usize = 64;
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

/// A shell token, as written: nothing is expanded or run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    /// A word with its quotes and expansions.
    Word(&'a str),
    /// A redirection (`2>/dev/null`, `>> log`, `>&2`); its target word.
    Redirect(&'a str),
    /// `;`, `&`, `|`, `(`, `)` or a newline: the next word starts a command.
    Break,
}

fn word_end(b: u8) -> bool {
    b.is_ascii_whitespace() || b";|&()<>".contains(&b)
}

/// The index after the character at `b[i]`, which starts one.
fn after_char(b: &[u8], i: usize) -> usize {
    let width = match b[i] {
        0..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    (i + width).min(b.len())
}

/// Skips the character, quoted string or expansion that starts at `b[i]`,
/// `depth` quotes and expansions down; `None` when it is left open or
/// nests deeper than [`MAX_WORD_NESTING`].
fn skip_unit(b: &[u8], i: usize, depth: usize) -> Option<usize> {
    if depth > MAX_WORD_NESTING {
        return None;
    }
    match (b[i], b.get(i + 1)) {
        (b'\\', Some(_)) => Some(after_char(b, i + 1)),
        (b'\'', _) => find_close(b, i + 1, b'\'', false),
        (b'"', _) => skip_double(b, i + 1, depth + 1),
        (b'`', _) => find_close(b, i + 1, b'`', true),
        (b'$', Some(b'(')) => skip_nested(b, i + 2, b'(', b')', depth + 1),
        (b'$', Some(b'{')) => skip_nested(b, i + 2, b'{', b'}', depth + 1),
        (b'$', Some(b'\'')) => find_close(b, i + 2, b'\'', true),
        _ => Some(after_char(b, i)),
    }
}

/// The index after the first `close` at or after `i`; backslash escapes
/// the next character when `escapes`.
fn find_close(b: &[u8], mut i: usize, close: u8, escapes: bool) -> Option<usize> {
    while i < b.len() {
        match b[i] {
            c if c == close => return Some(i + 1),
            b'\\' if escapes && i + 1 < b.len() => i = after_char(b, i + 1),
            _ => i += 1,
        }
    }
    None
}

fn skip_double(b: &[u8], mut i: usize, depth: usize) -> Option<usize> {
    while i < b.len() {
        i = match (b[i], b.get(i + 1)) {
            (b'"', _) => return Some(i + 1),
            (b'\\', Some(_)) => after_char(b, i + 1),
            (b'`' | b'$', _) => skip_unit(b, i, depth)?,
            _ => i + 1,
        };
    }
    None
}

fn skip_nested(b: &[u8], mut i: usize, open: u8, close: u8, depth: usize) -> Option<usize> {
    let mut open_brackets = 1;
    while i < b.len() {
        if b[i] == close {
            open_brackets -= 1;
            if open_brackets == 0 {
                return Some(i + 1);
            }
            i += 1;
        } else if b[i] == open {
            open_brackets += 1;
            i += 1;
        } else {
            i = skip_unit(b, i, depth)?;
        }
    }
    None
}

/// The length of the word at the start of `s`; `None` when a quote or
/// expansion in it is left open.
fn word_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && !word_end(b[i]) {
        i = skip_unit(b, i, 0)?;
    }
    Some(i)
}

/// The length of a redirection operator (with its file descriptor) at the
/// start of `s`.
fn redirect_len(s: &str) -> Option<usize> {
    if s.starts_with("&>>") {
        return Some(3);
    }
    if s.starts_with("&>") {
        return Some(2);
    }
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    let rest = &s[digits..];
    [">>", ">|", ">&", "<<<", "<&", "<>", ">", "<"]
        .iter()
        .find(|op| rest.starts_with(**op))
        .map(|op| digits + op.len())
}

/// Splits a shell command into tokens without expanding anything. Unquoted
/// `#` comments are dropped. The second value is the text left unread at a
/// quote or expansion left open, or a here-document, which is not read.
fn shell_tokens(input: &str) -> (Vec<Token<'_>>, &str) {
    let b = input.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    let blank =
        |i: usize| b[i] == b' ' || b[i] == b'\t' || b[i] == b'\\' && b.get(i + 1) == Some(&b'\n');
    loop {
        while i < b.len() {
            if b[i] == b'\n' {
                if tokens.last().is_some_and(|t| *t != Token::Break) {
                    tokens.push(Token::Break);
                }
                i += 1;
            } else if b[i] == b'\\' && b.get(i + 1) == Some(&b'\n') {
                i += 2;
            } else if b[i].is_ascii_whitespace() {
                i += 1;
            } else {
                break;
            }
        }
        if i >= b.len() {
            return (tokens, "");
        }
        let rest = &input[i..];
        if b[i] == b'#' {
            i += rest.find('\n').unwrap_or(rest.len());
            continue;
        }
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if rest[digits..].starts_with("<<") && !rest[digits..].starts_with("<<<") {
            return (tokens, rest);
        }
        if let Some(op) = redirect_len(rest) {
            i += op;
            while i < b.len() && blank(i) {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            let target = &input[i..];
            match word_len(target) {
                Some(len) if len > 0 => {
                    tokens.push(Token::Redirect(&target[..len]));
                    i += len;
                }
                _ => return (tokens, rest),
            }
            continue;
        }
        if word_end(b[i]) {
            tokens.push(Token::Break);
            i += 1;
            continue;
        }
        let Some(len) = word_len(rest) else {
            return (tokens, rest);
        };
        tokens.push(Token::Word(&rest[..len]));
        i += len;
    }
}

/// Whether the command could expand something (`$(`, a backtick, `${`)
/// outside a comment. Quoting is not trusted to prevent it.
fn expands(tokens: &[Token], rest: &str) -> bool {
    let expansion = |s: &str| s.contains("$(") || s.contains('`') || s.contains("${");
    expansion(rest)
        || tokens.iter().any(|t| match t {
            Token::Word(s) | Token::Redirect(s) => expansion(s),
            Token::Break => false,
        })
}

/// A word's value after quote removal. Expansions stay as written: callers
/// only act on words of commands without one.
fn unquote(raw: &str) -> String {
    let mut value = String::new();
    let mut quote = None;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if q == c => quote = None,
            (q, '\\') if q != Some('\'') => {
                if let Some(&next) = chars.peek()
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
    value
}

fn assignment_name(word: &str) -> Option<&str> {
    let (name, _) = word.split_once('=')?;
    let mut bytes = name.bytes();
    let first = bytes.next()?;
    ((first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    .then_some(name)
}

/// The first command's program: the first word after leading assignments
/// (whatever their values hold, never expanded) and redirections. `***`
/// when there is none or it is not a plain path.
fn archive_program(tokens: &[Token]) -> String {
    for token in tokens {
        match token {
            Token::Redirect(_) => {}
            Token::Word(raw) if assignment_name(raw).is_some() => {}
            Token::Word(raw) => {
                let word = unquote(raw);
                return if !word.is_empty()
                    && word
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_./+-".contains(&b))
                {
                    word
                } else {
                    "***".into()
                };
            }
            Token::Break => break,
        }
    }
    "***".into()
}

fn analyze_archive_command(input: &str) -> (String, Vec<String>) {
    let (tokens, _) = shell_tokens(input);
    let mut hosts = Vec::new();
    collect_hosts(input, 0, &mut hosts);
    (archive_program(&tokens), hosts)
}

/// Adds the hosts `input`'s commands name to `hosts`. A shell's script
/// (the operand of `-c`, `-lc` and the like) and a quoted `ssh` argument
/// with whitespace in it (the remote command) are read as commands too, at
/// most [`MAX_NESTING`] levels down (`depth` is this level).
fn collect_hosts(input: &str, depth: usize, hosts: &mut Vec<String>) {
    let (tokens, rest) = shell_tokens(input);
    if expands(&tokens, rest) {
        return;
    }
    let mut program: Option<String> = None;
    let mut endpoint_next = false;
    let mut skip_next = false;
    let mut script_next = false;
    for token in tokens {
        let raw = match token {
            Token::Word(raw) => raw,
            Token::Redirect(_) => continue,
            Token::Break => {
                program = None;
                endpoint_next = false;
                skip_next = false;
                script_next = false;
                continue;
            }
        };
        let word = unquote(raw);
        let endpoint_value = std::mem::take(&mut endpoint_next);
        if std::mem::take(&mut skip_next) {
            continue;
        }
        let script = std::mem::take(&mut script_next)
            || program.as_deref() == Some("ssh")
                && raw.starts_with(['\'', '"'])
                && word.contains(|c: char| c.is_ascii_whitespace());
        if script {
            if depth < MAX_NESTING {
                collect_hosts(&word, depth + 1, hosts);
            }
            continue;
        }
        if assignment_name(&word).is_some() {
            continue;
        }
        let Some(program) = &program else {
            let name = word.rsplit('/').next().unwrap_or(&word);
            if name != "busybox" {
                program = Some(name.to_string());
            }
            continue;
        };
        if SHELLS.contains(&program.as_str()) && word.starts_with('-') && !word.starts_with("--") {
            script_next = word.contains('c');
            continue;
        }
        let (key, value) = word
            .split_once('=')
            .map_or((word.as_str(), None), |(key, value)| (key, Some(value)));
        let curl = program == "curl";
        if OPERAND_FLAGS.contains(&key) || curl && CURL_OPERAND_FLAGS.contains(&word.as_str()) {
            skip_next = value.is_none();
            continue;
        }
        if word.starts_with("-u")
            || word.starts_with("-p")
            || curl && CURL_OPERAND_FLAGS.iter().any(|f| word.starts_with(f))
        {
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

/// What happens to WAL once archiving works again. Neither archiving nor a
/// checkpoint frees WAL a replication slot still needs, and a recycled
/// segment keeps its space.
const ARCHIVED_WAL: &str = "once archived and no longer needed by replication slots, WAL is \
     freed or recycled at the next checkpoint (do not remove the volume: it holds the database)";

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
            format!("fix archive_command or start its target ({unmatched}); {ARCHIVED_WAL}")
        } else if dead.is_empty() {
            format!("fix archive_command so archiving succeeds; {ARCHIVED_WAL}")
        } else {
            format!(
                "restore the archive target {}; {ARCHIVED_WAL}",
                dead.join(", ")
            )
        })
    } else if wal_heavy(ev) {
        Some(
            "check what holds WAL back (pg_replication_slots, max_wal_size, a slow archiver); \
             once nothing needs it, WAL is freed or recycled at the next checkpoint (do not \
             remove the volume: it holds the database)"
                .into(),
        )
    } else {
        None
    }
}

/// A line of detail for text output: where the evidence came from and the
/// settings behind the diagnosis.
/// One line of evidence for list views; API-only evidence carries its
/// notes in parentheses. Views that print the notes on their own lines use
/// [`headline`].
pub fn summary(ev: &PostgresWal) -> String {
    let mut s = headline(ev);
    if ev.source == EvidenceSource::ApiOnly && !ev.notes.is_empty() {
        s.push_str(&format!(" ({})", ev.notes.join("; ")));
    }
    s
}

/// The evidence in one line, without its notes.
pub fn headline(ev: &PostgresWal) -> String {
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
    bits.join(", ")
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
    use std::time::Instant;

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
    fn shell_comments_name_no_hosts() {
        for (command, expected) in [
            (
                "curl -T %p https://live/wal/%f # old https://retired/wal/",
                &["live"][..],
            ),
            ("curl -T %p https://live/wal/%f #https://retired", &["live"]),
            (
                "# https://retired\ncurl -T %p https://live/wal/%f",
                &["live"],
            ),
            ("curl -T %p https://live/wal/%f # $(cat /secret)", &["live"]),
            ("curl -T %p https://live/wal/%f # `x` ${Y}", &["live"]),
            ("curl -T %p https://live/wal#frag", &["live"]),
            ("curl -T %p '#' https://live/wal", &["live"]),
            ("curl -T %p \"#\" https://live/wal", &["live"]),
            (
                "curl -T %p \"https://live/#x\" \\#https://escaped",
                &["live"],
            ),
            (
                "curl -T %p https://live/wal/%f # x\ncurl https://next",
                &["live", "next"],
            ),
            // Expansions outside a comment still stop host lookups.
            ("curl https://live/$(x) # https://retired", &[]),
        ] {
            assert_eq!(analyze_archive_command(command).1, expected, "{command}");
        }
        assert_eq!(analyze_archive_command("# curl https://x").0, "***");
    }

    #[test]
    fn program_after_assignments_and_redirections() {
        for (command, program) in [
            (
                "PGPASSWORD=$(cat /run/secrets/pg) archive-wal %p",
                "archive-wal",
            ),
            (
                "TOKEN=${TOKEN:-x} A=`cat /k` B=\"$(printf '%s' ')')\" curl -T %p",
                "curl",
            ),
            ("X='a b' Y=\"c d\" rsync %p backup::wal", "rsync"),
            ("2>/dev/null curl -T %p https://minio/wal/%f", "curl"),
            ("2> /dev/null curl -T %p", "curl"),
            (
                ">>/var/log/archive.log 2>&1 /usr/bin/curl -T %p",
                "/usr/bin/curl",
            ),
            ("&>/dev/null curl -T %p", "curl"),
            ("&>> log <%p curl -T -", "curl"),
            ("A=1 >/dev/null B=2 wal-g wal-push %p", "wal-g"),
            ("curl >/dev/null -T %p", "curl"),
            // Fails closed.
            ("X='unclosed curl -T %p", "***"),
            ("X=$(cat /secret curl -T %p", "***"),
            ("2> curl", "***"),
            (">", "***"),
            ("$(which curl) -T %p", "***"),
            ("cu$X -T %p", "***"),
            ("'KEY=value' SECRET", "***"),
            ("; curl", "***"),
            ("<<EOF curl", "***"),
            ("", "***"),
        ] {
            assert_eq!(analyze_archive_command(command).0, program, "{command}");
        }
        // Redirections never name a host, and the program after one is
        // still the program.
        assert_eq!(
            analyze_archive_command("2>/dev/null https://program x https://store").1,
            ["store"]
        );
    }

    #[test]
    fn hosts_inside_nested_shell_words() {
        for (command, expected) in [
            ("sh -c 'curl -T %p https://minio/wal/%f'", &["minio"][..]),
            ("bash -lc \"curl -T %p https://minio/wal/%f\"", &["minio"]),
            (
                "/bin/sh -c 'test ! -f x && curl -T %p https://minio/wal/%f'",
                &["minio"],
            ),
            (
                "sh -c 'curl -T %p https://minio/wal/%f # https://retired'",
                &["minio"],
            ),
            (
                "sh -c 'curl --referer https://old -T %p https://store/wal/%f'",
                &["store"],
            ),
            ("sh -c 'X=https://assigned curl https://store'", &["store"]),
            ("sh -c 'https://program https://store'", &["store"]),
            (
                "ssh backup 'sh -c \"curl -T - https://minio/wal/%f\"'",
                &["minio"],
            ),
            (
                "bash -o pipefail -ec 'curl -T %p https://minio/wal/%f'",
                &["minio"],
            ),
            ("busybox sh -c 'curl https://minio/wal/%f'", &["minio"]),
            ("bash -u -c 'curl -T %p https://minio/wal/%f'", &["minio"]),
            ("sh -p -c 'curl -T %p https://minio/wal/%f'", &["minio"]),
            ("busybox wget -c https://store/wal/%f", &["store"]),
            // Quoted arguments of other programs are not scripts.
            (
                "curl -T %p https://minio/wal/%f || { echo \"upload to https://backup failed\" >&2; exit 1; }",
                &["minio"],
            ),
            ("curl -w 'see https://docs' https://store", &["store"]),
            (
                "archive-wal 'sh -c curl https://other' https://store",
                &["store"],
            ),
            ("sh --login 'curl https://other'", &[]),
            // Bounded depth.
            ("sh -c 'sh -c \"sh -c \\\"curl https://deep\\\"\"'", &[]),
            // Expansions anywhere stop host lookups.
            ("sh -c 'curl -T %p https://minio/$(cat /k)'", &[]),
            ("sh -c 'curl -T %p https://minio/${K}'", &[]),
            ("sh -c 'curl -T %p https://minio/`k`'", &[]),
            ("sh -c 'curl https://minio/\\$(k)'", &[]),
            ("sh -c '$''(k) https://minio'", &[]),
        ] {
            assert_eq!(analyze_archive_command(command).1, expected, "{command}");
        }
        assert_eq!(
            analyze_archive_command("sh -c 'curl -T %p https://minio/wal/%f'").0,
            "sh"
        );
    }

    #[test]
    fn deeply_nested_words_fail_closed() {
        for unit in ["$(", "\"$(", "${"] {
            let command = format!("curl https://store {}", unit.repeat(100_000));
            assert_eq!(
                analyze_archive_command(&command),
                ("curl".to_string(), Vec::<String>::new()),
                "{unit}"
            );
        }
        let deep = format!("{}curl{}", "$(".repeat(100), ")".repeat(100));
        assert_eq!(analyze_archive_command(&deep).0, "***");
        assert_eq!(
            analyze_archive_command("X=\"$(cat \"$(echo \"$(k)\")\")\" archive-wal %p").0,
            "archive-wal"
        );
    }

    #[test]
    fn only_curl_destination_operands_name_hosts() {
        for (command, expected) in [
            ("curl --url=https://archive/wal/%f -T %p", &["archive"][..]),
            ("curl --url https://archive/wal/%f -T %p", &["archive"]),
            ("curl --url archive:9000 -T %p", &["archive"]),
            (
                "curl --referer https://old-archive -T %p https://store/wal/%f",
                &["store"],
            ),
            (
                "curl --referer=https://old-archive -T %p https://store/wal/%f",
                &["store"],
            ),
            (
                "curl -e https://old-archive -T %p https://store/wal/%f",
                &["store"],
            ),
            (
                "curl -ehttps://old-archive -T %p https://store/wal/%f",
                &["store"],
            ),
            (
                "curl --proxy-user 'https://SECRET' -T %p https://store/wal/%f",
                &["store"],
            ),
            (
                "curl -U https://SECRET -T %p https://store/wal/%f",
                &["store"],
            ),
            (
                "curl -Uhttps://SECRET -T %p https://store/wal/%f",
                &["store"],
            ),
            (
                "curl -A https://agent -H 'Origin: https://origin' https://store",
                &["store"],
            ),
            (
                "curl --header 'Origin: https://origin' https://store",
                &["store"],
            ),
            (
                "curl -b https://cookie -x http://proxy:3128 https://store",
                &["store"],
            ),
            (
                "curl --proxy http://proxy:3128 --oauth2-bearer https://t https://store",
                &["store"],
            ),
            (
                "curl -d https://body -F f=https://form https://store",
                &["store"],
            ),
            // Other programs keep these letters' own meanings.
            ("wget -b https://store/wal/%f", &["store"]),
            ("wget -H https://store/wal/%f", &["store"]),
            ("wget --referer=https://old https://store", &["store"]),
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
        for path in [
            "",
            "docker-entrypoint.sh",
            "/usr/local/bin/docker-entrypoint.sh",
        ] {
            let s = command_settings(path, &args);
            assert_eq!(s["archive_mode"], "on");
            assert_eq!(s["archive_timeout"], "10s");
            assert_eq!(s["archive_command"], "curl -T %p http://s3test:9000/%f");
        }
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn settings_only_from_a_postgres_command_line() {
        // Docker `Cmd` options for the official entrypoint, which adds `postgres`.
        let s = command_settings("docker-entrypoint.sh", &strings(&["-c", "archive_mode=on"]));
        assert_eq!(s["archive_mode"], "on");
        for (path, args) in [
            (
                "docker-entrypoint.sh",
                &["postgres", "-c", "archive_mode=on"][..],
            ),
            (
                "",
                &[
                    "/usr/lib/postgresql/17/bin/postgres",
                    "-c",
                    "archive_mode=on",
                ],
            ),
            ("env", &["postmaster", "-c", "archive_mode=on"]),
            (
                "tini",
                &["docker-entrypoint.sh", "postgres", "-c", "archive_mode=on"],
            ),
        ] {
            assert_eq!(
                command_settings(path, &strings(args))
                    .get("archive_mode")
                    .map(String::as_str),
                Some("on"),
                "{path} {args:?}"
            );
        }
        let script = "archive_command=curl https://SECRET; archive_mode=on; \
                      exec docker-entrypoint.sh postgres -c archive_mode=on";
        for (path, args) in [
            ("docker-entrypoint.sh", &["sh", "-c", script][..]),
            ("docker-entrypoint.sh", &["/bin/bash", "-lc", script]),
            ("docker-entrypoint.sh", &["env", "sh", "-c", script]),
            ("sh", &["-c", script]),
            ("/bin/dash", &["-c", script]),
            ("/usr/bin/env", &["-S", script]),
            ("env", &["sh", "-c", script]),
            ("tini", &["--", "sh", "-c", script]),
            ("/start.sh", &["archive_mode=on"]),
            ("/start.sh", &["-c", "archive_mode=on"]),
            ("python3", &["-c", "archive_mode=on"]),
            ("tini", &["-c", "archive_mode=on"]),
            ("env", &["-c", "archive_mode=on"]),
            ("sh", &["postgres", "-c", "archive_mode=on"]),
        ] {
            assert!(
                command_settings(path, &strings(args)).is_empty(),
                "{path} {args:?}"
            );
        }
    }

    #[test]
    fn settings_keep_only_the_archive_settings() {
        let s = command_settings(
            "",
            &strings(&[
                "postgres",
                "-c",
                "primary_conninfo=host=primary password=SECRET",
                "--shared-buffers=1GB",
                "-carchive_command=pgbackrest archive-push %p",
            ]),
        );
        assert_eq!(
            s.keys().map(String::as_str).collect::<Vec<_>>(),
            ["archive_command"]
        );
        assert!(!s.contains_key("primary_conninfo"));
    }

    #[test]
    fn archive_timeout_reads_like_postgres() {
        for (value, expected) in [
            ("0", Some("0")),
            ("10s", Some("10s")),
            ("+60s", Some("+60s")),
            ("1e2s", Some("1e2s")),
            ("1E2", Some("1E2")),
            ("1e+2 s", Some("1e+2 s")),
            ("10. ms", Some("10. ms")),
            ("10.", Some("10.")),
            (".5min", Some(".5min")),
            ("1.5min", Some("1.5min")),
            ("1.5 min", Some("1.5 min")),
            (" 10s ", Some("10s")),
            ("10\ts", Some("10\ts")),
            ("010", Some("010")),
            ("0x1e", Some("0x1e")),
            ("500us", Some("500us")),
            ("1h", Some("1h")),
            ("12427d", Some("12427d")),
            ("1073741823", Some("1073741823")),
            ("1073741823s", Some("1073741823s")),
            ("1073741823.4", Some("1073741823.4")),
            ("17895697min", Some("17895697min")),
            ("-0", Some("-0")),
            ("-0.4", Some("-0.4")),
            // Outside 0 ..= INT_MAX / 2 seconds.
            ("-10s", None),
            ("-1", None),
            ("1073741824", None),
            ("1073741823.5", None),
            ("17895698min", None),
            ("12428d", None),
            ("1e10", None),
            ("1e999", None),
            ("1e-400", None),
            // Not a number with a time unit.
            ("", None),
            ("s", None),
            ("+", None),
            (".", None),
            ("e2", None),
            ("1e", None),
            ("08", None),
            ("0x1.8p1", None),
            ("10S", None),
            ("10 sec", None),
            ("10kB", None),
            ("10s x", None),
            ("10s; SECRET=timeout", None),
            ("inf", None),
            ("nan", None),
        ] {
            assert_eq!(
                archive_timeout_value(value).as_deref(),
                expected,
                "{value:?}"
            );
        }
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
        let a = psql_argv("docker", "/run/d.sock", "abc", QUERY);
        let s: Vec<&str> = a.iter().map(String::as_str).collect();
        assert_eq!(&s[..4], ["docker", "-H", "unix:///run/d.sock", "exec"]);
        assert!(
            s.contains(&"PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10s -c search_path=pg_catalog")
        );
        for setting in [
            "PGHOST=",
            "PGHOSTADDR",
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGCONNECT_TIMEOUT=5",
            "PGUSER",
            "PGDATABASE",
        ] {
            assert!(s.windows(2).any(|w| w == ["-e", setting]), "{setting}");
        }
        assert!(!s.contains(&"-U") && !s.contains(&"-d"));
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
        // A newer failure without a file name of its own clears the older one.
        let s = scan_log(&format!(
            "{log}2026-11-13T02:11:00Z 2026-11-13 02:11:00.000 UTC [61] LOG:  archive command failed with exit code 6\n"
        ));
        assert_eq!(s.failures, 3);
        assert_eq!(
            s.last_failure.unwrap().format(&Rfc3339).unwrap(),
            "2026-11-13T02:11:00Z"
        );
        assert_eq!(s.last_failed_wal, None);
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
        let cancel = Cancel::default();
        let mut c = Command::new("sleep");
        c.arg("5");
        let start = Instant::now();
        let e = run_with_timeout(c, Duration::from_millis(200), &cancel).unwrap_err();
        assert!(matches!(e, PsqlError::Timeout), "{e:?}");
        assert!(start.elapsed() < Duration::from_secs(3));
        let mut c = Command::new("echo");
        c.arg("hi");
        let out = run_with_timeout(c, Duration::from_secs(5), &cancel).unwrap();
        assert_eq!(out.stdout, b"hi\n");
    }

    #[test]
    fn cancel_kills_docker_exec_at_once() {
        use crate::cancel::tests::{gone, read_pid, sleeper, within};
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let docker = sleeper(dir.path(), &pid_file);
        let cancel = Cancel::default();
        let worker = {
            let cancel = cancel.clone();
            std::thread::spawn(move || {
                run_with_timeout(Command::new(docker), Duration::from_secs(60), &cancel)
            })
        };
        assert!(within(Duration::from_secs(10), || read_pid(&pid_file).is_some()));
        let pid = read_pid(&pid_file).unwrap();
        let start = Instant::now();
        cancel.cancel();
        assert!(start.elapsed() < Duration::from_millis(500));
        let e = worker.join().unwrap().unwrap_err();
        assert!(matches!(e, PsqlError::Canceled), "{e:?}");
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(within(Duration::from_secs(1), || gone(pid)));
    }

    #[test]
    fn a_cancelled_token_runs_no_docker_exec() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let docker = dir.path().join("docker");
        std::fs::write(
            &docker,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o700)).unwrap();
        let cancel = Cancel::default();
        cancel.cancel();
        let live = Live {
            api: Api {
                socket: dir.path().join("unused.sock"),
                timeout: API_TIMEOUT,
            },
            docker: Some(docker.to_string_lossy().into_owned()),
            exec_timeout: EXEC_TIMEOUT,
            cancel,
        };
        let e = live.psql("pg", "postgres", "postgres", QUERY).unwrap_err();
        assert!(matches!(e, PsqlError::Canceled), "{e:?}");
        assert!(!marker.exists());
    }
}
