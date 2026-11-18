//! The `postgres-wal` probe against recorded Engine API responses and psql
//! output (tests/data/postgres-wal/). No daemon is contacted.

use std::cell::RefCell;
use std::collections::HashMap;

use dwhy_core::detect::finding_id;
use dwhy_core::docker::{Api, GetError, demux_logs};
use dwhy_core::probes::postgres_wal::{self, Docker, LOG_TAIL, Live, PsqlError};
use dwhy_core::report::*;
use serde_json::Value;

const PG: &str = "aa11000000000000000000000000000000000000000000000000000000000001";
const S3: &str = "bb22000000000000000000000000000000000000000000000000000000000002";
const APP: &str = "cc33000000000000000000000000000000000000000000000000000000000003";
const VOLUME: &str = "pgwal_pg_data";

fn data(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/data/postgres-wal/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn json(name: &str) -> Value {
    serde_json::from_slice(&data(name)).unwrap()
}

/// Replays recorded responses and records what was asked for.
struct Fake {
    gets: HashMap<String, Result<Vec<u8>, GetError>>,
    psql: Result<String, PsqlError>,
    asked: RefCell<Vec<String>>,
}

impl Fake {
    /// The recorded daemon: Postgres running with the volume at its data
    /// directory, its archive target `s3test` exited.
    fn recorded(psql: &str) -> Fake {
        let mut f = Fake {
            gets: HashMap::new(),
            psql: Ok(String::from_utf8(data(psql)).unwrap()),
            asked: RefCell::new(Vec::new()),
        };
        f.set_json("/containers/json?all=1", json("containers.json"));
        f.set_json(
            &format!("/containers/{PG}/json"),
            json("inspect-postgres.json"),
        );
        f.set_json(
            &format!("/containers/{S3}/json"),
            json("inspect-s3test.json"),
        );
        f.set_json(&format!("/containers/{APP}/json"), json("inspect-app.json"));
        f.gets.insert(
            format!("/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}"),
            Ok(data("logs-postgres.bin")),
        );
        f
    }

    fn set_json(&mut self, path: &str, v: Value) {
        self.gets
            .insert(path.into(), Ok(serde_json::to_vec(&v).unwrap()));
    }

    fn edit(&mut self, path: &str, edit: impl FnOnce(&mut Value)) {
        let mut v: Value = serde_json::from_slice(self.gets[path].as_ref().unwrap()).unwrap();
        edit(&mut v);
        self.set_json(path, v);
    }

    fn edit_listed(&mut self, id: &str, edit: impl FnOnce(&mut Value)) {
        self.edit("/containers/json?all=1", |v| {
            let c = v
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|c| c["Id"] == id)
                .unwrap();
            edit(c);
        });
    }

    fn remove_container(&mut self, id: &str) {
        self.edit("/containers/json?all=1", |v| {
            v.as_array_mut().unwrap().retain(|c| c["Id"] != id);
        });
        self.gets.remove(&format!("/containers/{id}/json"));
    }

    fn asked_for(&self, prefix: &str) -> bool {
        self.asked.borrow().iter().any(|a| a.starts_with(prefix))
    }
}

impl Docker for Fake {
    fn get(&self, path: &str) -> Result<Vec<u8>, GetError> {
        self.asked.borrow_mut().push(format!("GET {path}"));
        self.gets
            .get(path)
            .cloned()
            .unwrap_or_else(|| Err(GetError::Http(404, format!("404 {path}"))))
    }

    fn psql(&self, id: &str, user: &str, db: &str, _sql: &str) -> Result<String, PsqlError> {
        self.asked
            .borrow_mut()
            .push(format!("psql {id} user={user} db={db}"));
        self.psql.clone()
    }
}

/// The `docker-volume` detector's finding for an in-use volume.
fn volume_finding(name: &str) -> Finding {
    let path = format!("docker://volume/{name}");
    Finding {
        id: finding_id("docker-volume", &path),
        detector: "docker-volume".into(),
        probe: None,
        evidence: None,
        path,
        bytes: 33_041_965_056,
        nested_bytes: None,
        last_modified: None,
        growth: None,
        tier: Tier::Review,
        reason: format!(
            "volume {name} holds 30.8G and is mounted by pgwal-postgres-1 (running) (a running container uses it)"
        ),
        guards: vec![GuardResult {
            name: "container-mount".into(),
            status: GuardStatus::Warn,
            detail: "mounted by pgwal-postgres-1 (running)".into(),
        }],
        action: Action {
            kind: ActionKind::Advice,
            text: "in use: if the data is no longer needed, remove the containers first, then the volume".into(),
            argv: None,
        },
        recovery: Recovery {
            cost: "n/a while in use".into(),
            how: None,
        },
    }
}

fn probe(fake: &Fake) -> Finding {
    let mut f = vec![volume_finding(VOLUME)];
    postgres_wal::probe_all(&mut f, fake);
    f.pop().unwrap()
}

fn evidence(f: &Finding) -> &PostgresWal {
    f.evidence
        .as_ref()
        .and_then(|e| e.postgres_wal.as_ref())
        .expect("probe ran")
}

fn assert_untouched(f: &Finding) {
    let before = volume_finding(VOLUME);
    assert_eq!(f, &before, "the finding must stay as the detector made it");
}

#[test]
fn failing_archiver_with_an_exited_target() {
    let fake = Fake::recorded("psql-failing.txt");
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(f.probe.as_deref(), Some("postgres-wal"));
    assert_eq!(ev.source, EvidenceSource::Psql);
    assert_eq!(ev.container, "pgwal-postgres-1");
    assert_eq!(ev.wal_bytes, Some(31_138_512_896));
    assert_eq!(ev.data_bytes, Some(55_574_528));
    assert_eq!(ev.failed_count, Some(151));
    assert_eq!(ev.last_archived_at.as_deref(), Some("2026-11-07T07:25:00Z"));
    assert_eq!(ev.last_failed_at.as_deref(), Some("2026-11-15T02:10:00Z"));
    assert_eq!(
        ev.last_failed_wal.as_deref(),
        Some("000000010000000000000097")
    );
    assert_eq!(ev.archive_mode.as_deref(), Some("on"));
    assert_eq!(ev.archive_timeout.as_deref(), Some("10s"));
    assert_eq!(
        ev.targets,
        [ArchiveTarget {
            host: "s3test".into(),
            container: Some("pgwal-s3test-1".into()),
            state: "exited".into(),
        }]
    );
    assert!(ev.notes.is_empty(), "{:?}", ev.notes);
    assert!(
        f.reason.starts_with(
            "pg_wal holds 29.0G vs 53.0M data; archiving is failing, with 151 failures in total (last failure 2026-11-15T02:10:00Z, last success 2026-11-07T07:25:00Z) \
             (target s3test (pgwal-s3test-1) exited); volume pgwal_pg_data holds"
        ),
        "{}",
        f.reason
    );
    assert_eq!(f.tier, Tier::Review);
    assert_eq!(f.action.kind, ActionKind::Advice);
    assert!(
        f.action
            .text
            .starts_with("restore the archive target s3test; WAL is freed at the next checkpoint"),
        "{}",
        f.action.text
    );
    assert!(!f.action.text.contains("remove the containers"));
    assert_eq!(f.guards, volume_finding(VOLUME).guards);
    // Ran as the database user from the container's environment, and never
    // read the logs: psql answered.
    assert!(fake.asked_for(&format!("psql {PG} user=app db=appdb")));
    assert!(!fake.asked_for(&format!("GET /containers/{PG}/logs")));
}

#[test]
fn unmatched_targets_are_counted_without_names() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.remove_container(S3);
    let f = probe(&fake);
    let ev = evidence(&f);
    assert!(ev.targets.is_empty());
    assert_eq!(ev.unmatched_hosts, 1);
    assert!(
        f.reason
            .contains("archive_command names 1 host that matches no container"),
        "{}",
        f.reason
    );
    assert!(
        f.action
            .text
            .starts_with("fix archive_command or start its target (1 host matches no container);")
    );
    assert!(!serde_json::to_string(&f).unwrap().contains("s3test"));
}

#[test]
fn target_found_by_network_alias_only() {
    let mut fake = Fake::recorded("psql-failing.txt");
    // Not a container name or Compose service: only a network alias says it.
    fake.edit_listed(S3, |c| {
        c["Names"] = serde_json::json!(["/minio-dev"]);
        c["Labels"] = serde_json::json!({});
    });
    let f = probe(&fake);
    assert_eq!(
        evidence(&f).targets,
        [ArchiveTarget {
            host: "s3test".into(),
            container: Some("minio-dev".into()),
            state: "exited".into(),
        }]
    );
}

#[test]
fn running_target_gives_generic_advice() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.edit(&format!("/containers/{S3}/json"), |v| {
        v["State"]["Status"] = "running".into()
    });
    let f = probe(&fake);
    assert_eq!(evidence(&f).targets[0].state, "running");
    assert!(!f.reason.contains("(target"), "{}", f.reason);
    assert!(
        f.action
            .text
            .starts_with("fix archive_command so archiving succeeds;"),
        "{}",
        f.action.text
    );
}

#[test]
fn healthy_archiver_gives_no_advice() {
    let fake = Fake::recorded("psql-healthy.txt");
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(f.probe.as_deref(), Some("postgres-wal"));
    assert_eq!(ev.source, EvidenceSource::Psql);
    assert_eq!(ev.failed_count, Some(0));
    assert_eq!(ev.last_failed_at, None);
    assert!(
        f.reason.starts_with(
            "pg_wal holds 192.0M vs 1.2G data; the archiver reports no failure; volume pgwal_pg_data"
        ),
        "{}",
        f.reason
    );
    let before = volume_finding(VOLUME);
    assert_eq!(f.action, before.action, "the detector's advice stays");
    assert_eq!(f.recovery, before.recovery);
    assert_eq!(f.tier, Tier::Review);
}

#[test]
fn psql_failure_falls_back_to_the_api_and_the_log_tail() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err(PsqlError::Failed);
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.source, EvidenceSource::ApiOnly);
    assert_eq!(ev.wal_bytes, None);
    assert_eq!(ev.data_bytes, None);
    // Three failure lines in the recorded tail.
    assert_eq!(ev.failed_count, Some(3));
    assert_eq!(ev.last_failed_at.as_deref(), Some("2026-11-13T02:10:00.3Z"));
    assert_eq!(
        ev.last_failed_wal.as_deref(),
        Some("000000010000000000000097")
    );
    // Settings from the container's command line.
    assert_eq!(ev.archive_mode.as_deref(), Some("on"));
    assert_eq!(ev.archive_timeout.as_deref(), Some("10s"));
    assert_eq!(ev.archive_program.as_deref(), Some("aws"));
    assert_eq!(ev.targets[0].state, "exited");
    assert!(ev.notes[0].starts_with("psql not used: psql failed;"));
    assert!(!ev.notes[0].contains("role"));
    assert!(
        f.reason.starts_with(&format!(
            "observed 3 archive failures in the last {LOG_TAIL} log lines (last failure 2026-11-13T02:10:00.3Z); current archiver health unknown (target s3test (pgwal-s3test-1) exited)"
        )),
        "{}",
        f.reason
    );
    assert!(
        f.action
            .text
            .starts_with("restore the archive target s3test;")
    );
    assert!(fake.asked_for(&format!(
        "GET /containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}"
    )));
}

#[test]
fn fallback_notes_export_only_psql_failure_categories() {
    let sep = postgres_wal::FIELD_SEP;
    for (reply, category) in [
        (Err(PsqlError::Timeout), "psql: timed out"),
        (Err(PsqlError::Exec), "docker exec failed"),
        (Err(PsqlError::Failed), "psql failed"),
        (
            Ok(format!(
                "permission denied for tenant_a{sep}0{sep}0{sep}{sep}{sep}{sep}on{sep}aws{sep}1s"
            )),
            "psql failed",
        ),
    ] {
        let mut fake = Fake::recorded("psql-failing.txt");
        fake.psql = reply;
        fake.gets.retain(|k, _| !k.contains("/logs"));
        let f = probe(&fake);
        let ev = evidence(&f);
        assert_eq!(ev.source, EvidenceSource::ApiOnly);
        assert_eq!(
            ev.notes[0],
            format!(
                "psql not used: {category}; fallback reads command-line settings and up to {LOG_TAIL} log lines"
            )
        );
        for output in [
            serde_json::to_string(&f).unwrap(),
            postgres_wal::summary(ev),
        ] {
            assert!(output.contains(category));
            assert!(!output.contains("tenant_a"));
        }
    }
}

#[test]
fn docker_exec_passes_role_and_literal_database_only_by_environment() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    fs::write(
        &docker,
        "#!/bin/sh\nprintf '%s\\n' \"$PGUSER\" \"$PGDATABASE\" \"${PGHOSTADDR+x}${PGSERVICE+x}${PGSERVICEFILE+x}\" \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o700)).unwrap();
    let runner = Live {
        api: Api {
            socket: dir.path().join("unused.sock"),
            timeout: postgres_wal::API_TIMEOUT,
        },
        docker: Some(docker.to_string_lossy().into_owned()),
        exec_timeout: postgres_wal::EXEC_TIMEOUT,
    };

    let user = "operator@example.test";
    let database = "archive host=10.0.0.5";
    let observed = runner.psql(PG, user, database, "SELECT 1").unwrap();
    let mut lines = observed.lines();
    assert_eq!(lines.next(), Some(user));
    assert_eq!(lines.next(), Some(database));
    assert_eq!(lines.next(), Some(""));
    let args: Vec<_> = lines.collect();
    for setting in ["PGHOST=", "PGUSER", "PGDATABASE"] {
        assert!(args.windows(2).any(|pair| pair == ["-e", setting]));
    }
    assert!(!args.iter().any(|arg| {
        arg.contains(user)
            || arg.contains(database)
            || arg.contains("10.0.0.5")
            || matches!(
                *arg,
                "-U" | "-d" | "-h" | "--host" | "--username" | "--dbname"
            )
    }));
}

#[test]
fn docker_exec_failure_uses_only_fixed_categories() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    let runner = Live {
        api: Api {
            socket: dir.path().join("unused.sock"),
            timeout: postgres_wal::API_TIMEOUT,
        },
        docker: Some(docker.to_string_lossy().into_owned()),
        exec_timeout: postgres_wal::EXEC_TIMEOUT,
    };
    for (stderr, category) in [
        (
            r#"FATAL: role "team"permission denied"x" does not exist"#,
            "psql failed",
        ),
        (
            r#"FATAL: role "Error response from daemon: secret" does not exist"#,
            "psql failed",
        ),
        (
            "Error response from daemon: container secret has stopped",
            "docker exec failed",
        ),
    ] {
        fs::write(
            &docker,
            format!("#!/bin/sh\nprintf '%s\\n' '{stderr}' >&2\nexit 1\n"),
        )
        .unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o700)).unwrap();
        let mut fake = Fake::recorded("psql-failing.txt");
        fake.psql = runner.psql(PG, "app", "appdb", "SELECT 1");
        let f = probe(&fake);
        assert!(evidence(&f).notes[0].starts_with(&format!("psql not used: {category};")));
        assert!(!serde_json::to_string(&f).unwrap().contains(stderr));
        assert!(!postgres_wal::summary(evidence(&f)).contains(stderr));
    }
}

#[test]
fn api_only_takes_the_command_from_the_log_when_the_command_line_has_none() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err(PsqlError::Exec);
    // archive settings in postgresql.conf instead of on the command line
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        v["Args"] = serde_json::json!(["postgres"]);
    });
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.archive_mode, None);
    assert_eq!(ev.archive_program.as_deref(), Some("aws"));
    assert_eq!(ev.targets[0].host, "s3test");
    assert_eq!(ev.failed_count, Some(3));
}

#[test]
fn archive_settings_only_export_modes_and_durations() {
    let sep = postgres_wal::FIELD_SEP;
    for (mode, timeout, expected_mode, expected_timeout) in [
        ("On", "10s", Some("on"), Some("10s")),
        ("ALWAYS", "1.5 min", Some("always"), Some("1.5 min")),
        ("OFF", "0", Some("off"), Some("0")),
        ("on; SECRET=mode", "10s; SECRET=timeout", None, None),
        ("", "-10s", None, None),
        ("off", "10. ms", Some("off"), None),
    ] {
        let mut fake = Fake::recorded("psql-failing.txt");
        let mut row: Vec<_> = fake.psql.as_ref().unwrap().split(sep).collect();
        row[6] = mode;
        row[8] = timeout;
        fake.psql = Ok(row.join(&sep.to_string()));
        let sql = probe(&fake);
        assert_eq!(evidence(&sql).source, EvidenceSource::Psql);

        fake.psql = Err(PsqlError::Failed);
        fake.edit(&format!("/containers/{PG}/json"), |v| {
            v["Args"] = serde_json::json!([
                "postgres",
                "-c",
                format!("archive_mode={mode}"),
                format!("--archive-timeout={timeout}")
            ]);
        });
        let fallback = probe(&fake);
        assert_eq!(evidence(&fallback).source, EvidenceSource::ApiOnly);
        for f in [&sql, &fallback] {
            let ev = evidence(f);
            assert_eq!(ev.archive_mode.as_deref(), expected_mode);
            assert_eq!(ev.archive_timeout.as_deref(), expected_timeout);
            assert!(!serde_json::to_string(f).unwrap().contains("SECRET"));
            assert!(!postgres_wal::summary(ev).contains("SECRET"));
        }
    }
}

#[test]
fn shell_entrypoint_timeout_does_not_export_script() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err(PsqlError::Failed);
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        v["Path"] = "sh".into();
        v["Args"] = serde_json::json!(["-c", "archive_timeout=10s; SECRET=private; exec postgres"]);
    });
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.source, EvidenceSource::ApiOnly);
    assert_eq!(ev.archive_timeout, None);
    assert!(!serde_json::to_string(&f).unwrap().contains("SECRET"));
    assert!(!postgres_wal::summary(ev).contains("SECRET"));
}

#[test]
fn fallback_counts_verbose_and_fatal_archiver_records_only() {
    for (fixture, expected_time, expected_wal) in [
        (
            "logs-postgres-verbose.txt",
            "2026-11-13T02:10:00Z",
            Some("000000010000000000000097"),
        ),
        ("logs-postgres-fatal.txt", "2026-11-13T02:11:00Z", None),
        ("logs-postgres-signal.txt", "2026-11-13T02:12:00Z", None),
    ] {
        let mut fake = Fake::recorded("psql-failing.txt");
        fake.psql = Err(PsqlError::Failed);
        fake.edit(&format!("/containers/{PG}/json"), |v| {
            v["Args"] = serde_json::json!(["postgres"]);
            v["Config"]["Tty"] = true.into();
        });
        fake.gets.insert(
            format!("/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}"),
            Ok(data(fixture)),
        );
        let f = probe(&fake);
        let ev = evidence(&f);
        assert_eq!(ev.source, EvidenceSource::ApiOnly, "{fixture}");
        assert_eq!(ev.failed_count, Some(1), "{fixture}");
        assert_eq!(
            ev.last_failed_at.as_deref(),
            Some(expected_time),
            "{fixture}"
        );
        assert_eq!(ev.last_failed_wal.as_deref(), expected_wal, "{fixture}");
        assert_eq!(ev.archive_program.as_deref(), Some("curl"), "{fixture}");
        assert_eq!(ev.targets[0].host, "s3test", "{fixture}");
    }
}

#[test]
fn api_only_with_an_unreadable_log_says_so() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err(PsqlError::Exec);
    let secret = "/daemon/private/rotated.log";
    fake.gets.insert(
        format!("/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}"),
        Err(GetError::Http(404, format!("log not found at {secret}"))),
    );
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.source, EvidenceSource::ApiOnly);
    assert_eq!(ev.failed_count, None);
    let category = "log tail unreadable (HTTP 404)";
    assert!(ev.notes.iter().any(|note| note == category));
    assert!(
        f.reason.contains("archive failures unknown"),
        "{}",
        f.reason
    );
    assert!(f.reason.contains(category), "{}", f.reason);
    assert!(!f.reason.contains("no archive failures"), "{}", f.reason);
    let summary = postgres_wal::summary(ev);
    assert!(summary.contains(category), "{summary}");
    assert!(summary.contains("psql not used:"), "{summary}");
    assert!(!summary.contains(secret));
    assert!(!serde_json::to_string(&f).unwrap().contains(secret));
    assert_eq!(f.action, volume_finding(VOLUME).action);
}

#[test]
fn volume_of_a_stopped_container_is_not_probed() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.edit_listed(PG, |c| c["State"] = "exited".into());
    let f = probe(&fake);
    assert_untouched(&f);
    assert!(!fake.asked_for("psql"));
    assert!(!fake.asked_for(&format!("GET /containers/{PG}/json")));
}

#[test]
fn volume_not_at_the_data_directory_is_not_probed() {
    let mut fake = Fake::recorded("psql-failing.txt");
    let moved = |v: &mut Value| {
        v["Mounts"][0]["Destination"] = "/var/lib/postgresql/data/backups".into();
    };
    fake.edit_listed(PG, moved);
    fake.edit(&format!("/containers/{PG}/json"), moved);
    let f = probe(&fake);
    assert_untouched(&f);
    assert!(!fake.asked_for("psql"));
    // other-app-1 mounts it too, at /backup: not a data directory either.
    assert!(fake.asked_for(&format!("GET /containers/{APP}/json")));
}

#[test]
fn custom_pgdata_below_the_mount_point() {
    let mut fake = Fake::recorded("psql-failing.txt");
    // postgres:18 style: the volume at /var/lib/postgresql, PGDATA below it.
    let edit_mount = |v: &mut Value| v["Mounts"][0]["Destination"] = "/srv/pg".into();
    fake.edit_listed(PG, edit_mount);
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        edit_mount(v);
        let env = v["Config"]["Env"].as_array_mut().unwrap();
        env.retain(|e| !e.as_str().unwrap().starts_with("PGDATA="));
        env.push("PGDATA=/srv/pg/16/data".into());
    });
    assert_eq!(evidence(&probe(&fake)).source, EvidenceSource::Psql);

    // The same mount without PGDATA: the default data directory is elsewhere.
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        let env = v["Config"]["Env"].as_array_mut().unwrap();
        env.retain(|e| !e.as_str().unwrap().starts_with("PGDATA="));
    });
    assert_untouched(&probe(&fake));
}

#[test]
fn default_user_is_postgres() {
    let mut fake = Fake::recorded("psql-healthy.txt");
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        let env = v["Config"]["Env"].as_array_mut().unwrap();
        env.retain(|e| !e.as_str().unwrap().starts_with("POSTGRES_"));
    });
    probe(&fake);
    assert!(fake.asked_for(&format!("psql {PG} user=postgres db=postgres")));
}

#[test]
fn other_findings_are_left_alone() {
    let fake = Fake::recorded("psql-failing.txt");
    let mut unused = volume_finding("old_data");
    unused.action.kind = ActionKind::Command;
    let mut img = volume_finding("x");
    img.detector = "docker-image".into();
    img.path = "docker://image/x".into();
    let mut found = vec![unused.clone(), img.clone()];
    postgres_wal::probe_all(&mut found, &fake);
    assert_eq!(found, [unused, img]);
    assert!(fake.asked.borrow().is_empty(), "{:?}", fake.asked.borrow());
}

#[test]
fn an_unreachable_daemon_leaves_findings_as_detected() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.gets.clear();
    assert_untouched(&probe(&fake));
}

#[test]
fn heavy_wal_without_failures_gets_advice() {
    let mut fake = Fake::recorded("psql-healthy.txt");
    let s = '\x1f';
    fake.psql = Ok(format!(
        "8589934592{s}104857600{s}0{s}1794708590{s}{s}{s}on{s}/bin/true{s}0\n"
    ));
    let f = probe(&fake);
    assert!(
        f.reason
            .starts_with("pg_wal holds 8.0G vs 100.0M data; WAL is 81x the data"),
        "{}",
        f.reason
    );
    assert!(
        f.action.text.contains("pg_replication_slots"),
        "{}",
        f.action.text
    );
    assert!(evidence(&f).targets.is_empty());
}

#[test]
fn log_frames_are_demultiplexed() {
    let raw = data("logs-postgres.bin");
    let text = String::from_utf8(demux_logs(&raw).unwrap()).unwrap();
    assert_eq!(text.lines().count(), 7);
    assert!(text.starts_with("2026-11-07T07:00:02.000000000Z "));
    assert!(!text.contains('\0'));

    assert!(demux_logs(b"plain text\n").is_err());
    assert!(demux_logs(&raw[..raw.len() - 1]).is_err());
    assert_eq!(demux_logs(b"").unwrap(), b"");
}

#[test]
fn special_hosts_use_docker_identifiers_or_only_count() {
    for host in ["archive.example.com", "127.0.0.1", "localhost", "::1"] {
        let mut fake = Fake::recorded("psql-failing.txt");
        let url = if host == "::1" {
            format!("http://[{host}]:9000")
        } else {
            format!("http://{host}:9000")
        };
        let output = fake
            .psql
            .as_ref()
            .unwrap()
            .replace("http://s3test:9000", &url);
        fake.psql = Ok(output);
        let f = probe(&fake);
        assert!(evidence(&f).targets.is_empty());
        assert_eq!(evidence(&f).unmatched_hosts, 1);
        assert!(!f.reason.contains("(target"), "{}", f.reason);
        assert!(f.action.text.starts_with("fix archive_command"));
    }
    for identifier in ["name", "service", "alias", "dns-name"] {
        let mut fake = Fake::recorded("psql-failing.txt");
        fake.psql = Ok(fake
            .psql
            .as_ref()
            .unwrap()
            .replace("s3test:9000", "archive.example.com:9000"));
        match identifier {
            "name" => fake.edit_listed(S3, |v| {
                v["Names"] = serde_json::json!(["/ARCHIVE.example.com"])
            }),
            "service" => fake.edit_listed(S3, |v| {
                v["Labels"]["com.docker.compose.service"] = "ARCHIVE.example.com".into()
            }),
            field => fake.edit(&format!("/containers/{S3}/json"), |v| {
                let key = if field == "alias" {
                    "Aliases"
                } else {
                    "DNSNames"
                };
                v["NetworkSettings"]["Networks"]["pgwal_default"][key] =
                    serde_json::json!(["ARCHIVE.example.com"]);
            }),
        }
        let f = probe(&fake);
        assert_eq!(evidence(&f).targets[0].state, "exited", "{identifier}");
        assert_eq!(evidence(&f).targets[0].host, "ARCHIVE.example.com");
        assert_eq!(evidence(&f).unmatched_hosts, 0);
        assert!(
            f.reason.contains("(target ARCHIVE.example.com"),
            "{}",
            f.reason
        );
    }
}

#[test]
fn running_alias_wins_over_an_exited_name_or_service() {
    for identifier in ["name", "service"] {
        let mut fake = Fake::recorded("psql-failing.txt");
        fake.edit_listed(S3, |v| {
            v["Names"] = serde_json::json!(["/old-archive"]);
            v["Labels"]["com.docker.compose.service"] = "old-archive".into();
            if identifier == "name" {
                v["Names"] = serde_json::json!(["/s3test"]);
            } else {
                v["Labels"]["com.docker.compose.service"] = "s3test".into();
            }
        });
        fake.edit(&format!("/containers/{APP}/json"), |v| {
            v["NetworkSettings"]["Networks"] = serde_json::json!({
                "pgwal_default": { "Aliases": ["s3test"] }
            });
        });
        let f = probe(&fake);
        assert_eq!(
            evidence(&f).targets[0].container.as_deref(),
            Some("other-app-1")
        );
        assert_eq!(evidence(&f).targets[0].state, "running");
        assert!(f.action.text.starts_with("fix archive_command"));
    }
}

#[test]
fn alias_lookup_checks_containers_beyond_the_old_limit() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.edit_listed(S3, |v| {
        v["Names"] = serde_json::json!(["/minio-dev"]);
        v["Labels"] = serde_json::json!({});
    });
    for n in 0..65 {
        let id = format!("unrelated-{n}");
        fake.edit("/containers/json?all=1", |v| {
            v.as_array_mut().unwrap().insert(
                0,
                serde_json::json!({
                    "Id": id, "Names": [format!("/{id}")], "State": "running"
                }),
            );
        });
        fake.set_json(
            &format!("/containers/{id}/json"),
            serde_json::json!({"Id": id, "State": {"Status": "running"}}),
        );
    }
    let f = probe(&fake);
    assert_eq!(
        evidence(&f).targets[0].container.as_deref(),
        Some("minio-dev")
    );
    assert_eq!(evidence(&f).targets[0].state, "exited");
}

#[test]
fn incomplete_inspection_never_proves_a_dead_or_missing_target() {
    for present in [false, true] {
        for invalid_json in [false, true] {
            let mut fake = Fake::recorded("psql-failing.txt");
            if !present {
                fake.remove_container(S3);
            }
            let response = if invalid_json {
                Ok(b"not json".to_vec())
            } else {
                Err(GetError::Other("inspection denied".into()))
            };
            fake.gets
                .insert(format!("/containers/{APP}/json"), response);
            let f = probe(&fake);
            assert!(evidence(&f).targets.is_empty());
            assert_eq!(evidence(&f).unmatched_hosts, 0);
            assert!(!f.reason.contains("(target"), "{}", f.reason);
            assert!(f.action.text.starts_with("fix archive_command"));
        }
    }
}

#[test]
fn a_disappeared_container_does_not_hide_an_exited_target() {
    for api_only in [false, true] {
        let mut fake = Fake::recorded("psql-failing.txt");
        fake.edit("/containers/json?all=1", |v| {
            let listed = v.as_array_mut().unwrap();
            let disappeared = listed.iter().position(|c| c["Id"] == APP).unwrap();
            listed.rotate_left(disappeared);
        });
        fake.gets.remove(&format!("/containers/{APP}/json"));
        if api_only {
            fake.psql = Err(PsqlError::Failed);
        }
        let f = probe(&fake);
        let ev = evidence(&f);
        assert_eq!(
            ev.source,
            if api_only {
                EvidenceSource::ApiOnly
            } else {
                EvidenceSource::Psql
            }
        );
        assert_eq!(ev.targets[0].host, "s3test");
        assert_eq!(ev.targets[0].state, "exited");
        assert_eq!(ev.unmatched_hosts, 0);
        assert!(f.reason.contains("(target s3test (pgwal-s3test-1) exited)"));
        assert!(
            f.action
                .text
                .starts_with("restore the archive target s3test;")
        );
    }
}

#[test]
fn only_the_deepest_mount_owns_the_postgres_evidence() {
    for kind in ["volume", "bind", "tmpfs", "tmpfs-host-config"] {
        let mut fake = Fake::recorded("psql-failing.txt");
        let edit = |v: &mut Value| {
            v["Mounts"][0]["Destination"] = "/var/lib/postgresql".into();
            if kind != "tmpfs-host-config" {
                v["Mounts"].as_array_mut().unwrap().push(serde_json::json!({
                    "Type": kind, "Name": "inner-data", "Destination": "/var/lib/postgresql/data"
                }));
            }
        };
        fake.edit_listed(PG, edit);
        fake.edit(&format!("/containers/{PG}/json"), edit);
        if kind == "tmpfs-host-config" {
            fake.edit(&format!("/containers/{PG}/json"), |v| {
                v["HostConfig"]["Tmpfs"] =
                    serde_json::json!({"/var/lib/postgresql/data": "size=1g"});
            });
        }
        let f = probe(&fake);
        assert_untouched(&f);
        assert!(!fake.asked_for("psql"), "{kind}");
        if kind == "volume" {
            let mut findings = vec![volume_finding(VOLUME), volume_finding("inner-data")];
            postgres_wal::probe_all(&mut findings, &fake);
            assert_untouched(&findings[0]);
            assert_eq!(evidence(&findings[1]).container, "pgwal-postgres-1");
        }
    }
}

#[test]
fn an_empty_readable_log_tail_reports_zero_failures() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err(PsqlError::Exec);
    fake.gets.insert(
        format!("/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}"),
        Ok(Vec::new()),
    );
    let f = probe(&fake);
    assert_eq!(evidence(&f).failed_count, Some(0));
    assert!(
        f.reason
            .starts_with("no archive failures in the last 200 log lines"),
        "{}",
        f.reason
    );
    assert_eq!(f.action, volume_finding(VOLUME).action);
}

#[test]
fn doctor_requires_the_volume_detectors_docker_cli() {
    use dwhy_core::{detect::DetectContext, probes};
    let mut ctx = DetectContext {
        uid: 1000,
        root: false,
        home: None,
        now: 0,
        tools: Vec::new(),
        docker_socket: DockerSocket {
            path: "/fixture/docker.sock".into(),
            exists: true,
            accessible: true,
        },
        docker: dwhy_core::docker::Source::none(),
    };
    let status = probes::statuses(&ctx).pop().unwrap();
    assert_eq!(status.status, DetectorAvailability::Unavailable);
    assert!(
        status.detail.contains("`docker` is not installed"),
        "{}",
        status.detail
    );
    ctx.tools.push(ToolStatus {
        name: "docker".into(),
        path: None,
        off_path: Some("/fixture/bin/docker".into()),
        enables: vec![],
    });
    assert_eq!(
        probes::statuses(&ctx)[0].status,
        DetectorAvailability::Unavailable
    );
    ctx.tools[0].path = Some("/fixture/bin/docker".into());
    assert_eq!(
        probes::statuses(&ctx)[0].status,
        DetectorAvailability::Available
    );
    ctx.docker_socket.exists = false;
    assert_eq!(
        probes::statuses(&ctx)[0].status,
        DetectorAvailability::Unavailable
    );
    ctx.docker_socket.exists = true;
    ctx.docker_socket.accessible = false;
    assert_eq!(
        probes::statuses(&ctx)[0].status,
        DetectorAvailability::Unavailable
    );
}

#[test]
fn other_networks_are_only_considered_without_a_shared_match() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.edit(&format!("/containers/{APP}/json"), |v| {
        v["NetworkSettings"]["Networks"] = serde_json::json!({
            "pgwal_default": { "Aliases": ["other-app-1"] },
            "unrelated": { "Aliases": ["S3TEST"] }
        });
    });
    let f = probe(&fake);
    assert_eq!(evidence(&f).targets[0].state, "exited");
    assert_eq!(
        evidence(&f).targets[0].container.as_deref(),
        Some("pgwal-s3test-1")
    );
    fake.remove_container(S3);
    let f = probe(&fake);
    assert_eq!(evidence(&f).targets[0].state, "running");
    assert_eq!(
        evidence(&f).targets[0].container.as_deref(),
        Some("other-app-1")
    );
}

#[test]
fn archiver_events_within_one_second_preserve_order() {
    let s = postgres_wal::FIELD_SEP;
    for (success, failure, failing) in [
        ("0.000001", "0.000002", true),
        ("0.000001", "0.000001", true),
        ("0.000002", "0.000001", false),
    ] {
        let mut fake = Fake::recorded("psql-healthy.txt");
        fake.psql = Ok(format!(
            "8589934592{s}104857600{s}151{s}{success}{s}{failure}{s}{s}on{s}/bin/true{s}0\n"
        ));
        let f = probe(&fake);
        assert_eq!(postgres_wal::failing(evidence(&f)), failing);
        assert!(f.reason.contains("151"), "{}", f.reason);
        if failing {
            assert!(
                f.action.text.starts_with("fix archive_command"),
                "{}",
                f.action.text
            );
        } else {
            assert!(f.reason.contains("archiving works again"), "{}", f.reason);
            assert!(
                f.reason.contains("1970-01-01T00:00:00.000002Z"),
                "{}",
                f.reason
            );
            assert!(f.action.text.contains("max_wal_size"), "{}", f.action.text);
        }
    }
}

#[test]
fn historical_log_failures_do_not_prompt_repairs_to_running_targets() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err(PsqlError::Exec);
    fake.edit(&format!("/containers/{S3}/json"), |v| {
        v["State"]["Status"] = "running".into()
    });
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.failed_count, Some(3));
    assert!(!postgres_wal::failing(ev));
    assert!(
        f.reason.contains("last failure 2026-11-13T02:10:00.3Z"),
        "{}",
        f.reason
    );
    assert!(
        f.reason.contains("current archiver health unknown"),
        "{}",
        f.reason
    );
    assert_eq!(f.action, volume_finding(VOLUME).action);
}

#[test]
fn only_tty_logs_are_read_raw_and_bad_frames_keep_counts_unknown() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err(PsqlError::Exec);
    let path = format!("/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}");
    let mut error = vec![3, 0, 0, 0, 0, 0, 0, 11];
    error.extend_from_slice(b"reader down");
    let mut late_error = data("logs-postgres.bin");
    late_error.extend_from_slice(&error);
    for payload in [
        error,
        late_error,
        vec![1, 1, 0, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0, 0, 2, b'x'],
    ] {
        fake.gets.insert(path.clone(), Ok(payload));
        assert_unreadable_daemon_log(&probe(&fake), "reader down");
    }
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        v["Config"]["Tty"] = true.into()
    });
    let failure = "2026-11-13T02:10:00Z LOG: archive command failed with exit code 6\n";
    fake.gets
        .insert(path.clone(), Ok(failure.as_bytes().to_vec()));
    assert_eq!(evidence(&probe(&fake)).failed_count, Some(1));

    for body in [
        "Error grabbing logs: cannot open /private/reader.log".to_string(),
        format!("{failure}Error grabbing logs: cannot open /private/reader.log"),
        "cannot read /private/reader.log".to_string(),
    ] {
        fake.gets.insert(path.clone(), Ok(body.into_bytes()));
        assert_unreadable_daemon_log(&probe(&fake), "/private/reader.log");
    }
}

fn assert_unreadable_daemon_log(f: &Finding, private: &str) {
    let ev = evidence(f);
    assert_eq!(ev.failed_count, None);
    let category = "log tail unreadable (daemon error)";
    assert!(ev.notes.iter().any(|note| note == category));
    assert!(f.reason.contains(category), "{}", f.reason);
    let summary = postgres_wal::summary(ev);
    assert!(summary.contains(category), "{summary}");
    assert!(!summary.contains(private));
    assert!(!serde_json::to_string(f).unwrap().contains(private));
    assert_eq!(f.action, volume_finding(VOLUME).action);
}

#[test]
fn failed_wal_evidence_accepts_only_postgres_archive_filenames() {
    let sep = postgres_wal::FIELD_SEP;
    for (wal, expected) in [
        ("000000010000000A0000009F", Some("000000010000000A0000009F")),
        (
            "000000010000000A0000009F.partial",
            Some("000000010000000A0000009F.partial"),
        ),
        ("0000000A.history", Some("0000000A.history")),
        (
            "000000010000000A0000009F.0000008E.backup",
            Some("000000010000000A0000009F.0000008E.backup"),
        ),
        ("/private/storage/000000010000000A0000009F", None),
        ("000000010000000a0000009f", None),
        ("000000010000000A0000009F.0000008E.partial", None),
        ("0000000G.history", None),
        ("000000010000000A0000009F.0000008.backup", None),
    ] {
        let mut fake = Fake::recorded("psql-failing.txt");
        let mut fields: Vec<_> = fake.psql.as_ref().unwrap().split(sep).collect();
        fields[5] = wal;
        fake.psql = Ok(fields.join(&sep.to_string()));
        let sql = probe(&fake);
        assert_eq!(evidence(&sql).last_failed_wal.as_deref(), expected, "{wal}");
        assert_eq!(evidence(&sql).source, EvidenceSource::Psql);

        fake.psql = Err(PsqlError::Failed);
        fake.edit(&format!("/containers/{PG}/json"), |v| {
            v["Config"]["Tty"] = true.into()
        });
        let log = format!(
            "2026-11-13T02:10:00Z WARNING: archiving write-ahead log file \"{wal}\" failed too many times, will try again later\n"
        );
        fake.gets.insert(
            format!("/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}"),
            Ok(log.into_bytes()),
        );
        let fallback = probe(&fake);
        assert_eq!(
            evidence(&fallback).last_failed_wal.as_deref(),
            expected,
            "{wal}"
        );
        if expected.is_none() {
            for f in [&sql, &fallback] {
                assert!(!serde_json::to_string(f).unwrap().contains(wal));
                assert!(!postgres_wal::summary(evidence(f)).contains(wal));
            }
        }
    }
}

#[test]
fn statements_and_unrelated_details_do_not_supply_archiver_evidence() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err(PsqlError::Failed);
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        v["Config"]["Tty"] = true.into();
        v["Args"] = serde_json::json!(["postgres"]);
    });
    let log = b"2026-11-13T02:10:00Z ERROR: statement failed\n\
                2026-11-13T02:10:00Z DETAIL: The failed archive command was: curl https://s3test\n\
                2026-11-13T02:10:00Z DETAIL: LOG: archive command failed with exit code 6\n\
                2026-11-13T02:10:00Z STATEMENT: WARNING: archiving write-ahead log file \"000000010000000A0000009F\" failed too many times\n";
    fake.gets.insert(
        format!("/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}"),
        Ok(log.to_vec()),
    );
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.failed_count, Some(0));
    assert_eq!(ev.last_failed_at, None);
    assert_eq!(ev.last_failed_wal, None);
    assert_eq!(ev.archive_program, None);
    assert!(ev.targets.is_empty());
    assert_eq!(f.action, volume_finding(VOLUME).action);
}

#[test]
fn curl_operands_only_name_hosts_backed_by_docker() {
    let mut fake = Fake::recorded("psql-failing.txt");
    let mut fields: Vec<_> = fake
        .psql
        .as_ref()
        .unwrap()
        .split(postgres_wal::FIELD_SEP)
        .collect();
    fields[7] = "curl --proxy-user 'https://SECRET' -T %p https://minio/wal/%f";
    fake.psql = Ok(fields.join(&postgres_wal::FIELD_SEP.to_string()));

    let f = probe(&fake);
    assert!(evidence(&f).targets.is_empty());
    assert_eq!(evidence(&f).unmatched_hosts, 2);
    assert!(!f.reason.contains("minio"));
    let json = serde_json::to_string(&f).unwrap();
    assert!(!json.contains("SECRET"));
    assert!(!json.contains("minio"));

    fake.edit_listed(S3, |c| c["Names"] = serde_json::json!(["/MINIO"]));
    let f = probe(&fake);
    assert_eq!(evidence(&f).unmatched_hosts, 1);
    assert_eq!(
        evidence(&f).targets,
        [ArchiveTarget {
            host: "MINIO".into(),
            container: Some("MINIO".into()),
            state: "exited".into(),
        }]
    );
    assert!(
        f.action
            .text
            .starts_with("restore the archive target MINIO;")
    );
    assert!(!serde_json::to_string(&f).unwrap().contains("SECRET"));
    assert!(!postgres_wal::summary(evidence(&f)).contains("SECRET"));
}

#[test]
fn multiline_failed_log_command_does_not_hide_expansions() {
    for tty in [false, true] {
        let mut fake = Fake::recorded("psql-failing.txt");
        fake.psql = Err(PsqlError::Exec);
        fake.edit(&format!("/containers/{PG}/json"), |v| {
            v["Args"] = serde_json::json!(["postgres"]);
            v["Config"]["Tty"] = tty.into();
        });
        let path = format!("/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}");
        for (header, expected_targets) in [("Bearer literal", 1), ("Bearer ${TOKEN_SECRET}", 0)] {
            let log = format!(
                "2026-11-13T02:10:00Z LOG: archive command failed with exit code 6\n\
                 2026-11-13T02:10:00Z DETAIL: The failed archive command was: curl -T %p https://s3test/wal/%f \\\n\
                 2026-11-13T02:10:00Z \t-H 'Authorization: {header}'\n\
                 2026-11-13T02:10:01Z LOG: checkpoint starting\n"
            );
            let bytes = if tty {
                log.into_bytes()
            } else {
                let mut framed = vec![2, 0, 0, 0];
                framed.extend_from_slice(&(log.len() as u32).to_be_bytes());
                framed.extend_from_slice(log.as_bytes());
                framed
            };
            fake.gets.insert(path.clone(), Ok(bytes));
            let f = probe(&fake);
            let ev = evidence(&f);
            assert_eq!(ev.failed_count, Some(1));
            assert_eq!(ev.archive_program.as_deref(), Some("curl"));
            assert_eq!(ev.targets.len(), expected_targets);
            assert_eq!(ev.unmatched_hosts, 0);
            assert!(!serde_json::to_string(&f).unwrap().contains("TOKEN_SECRET"));
            if expected_targets == 0 {
                assert_eq!(f.action, volume_finding(VOLUME).action);
            } else {
                assert!(
                    f.action
                        .text
                        .starts_with("restore the archive target s3test;")
                );
            }
        }
    }
}

#[test]
fn every_archive_command_source_exports_only_program_and_hosts() {
    for (command, program, host, unmatched) in [
        (
            r#"curl -H 'Authorization: Bearer SECRET' https://s3test:9000/wal"#,
            "curl",
            "s3test",
            0,
        ),
        (
            r#"curl -H "X-Auth-Token: SECRET" https://s3test:9000/wal"#,
            "curl",
            "s3test",
            0,
        ),
        (
            "mc alias set archive http://s3test:9000 admin SECRET",
            "mc",
            "s3test",
            0,
        ),
        (
            "PGPASSWORD=$(printf '%s' 'https://SECRET') /usr/local/bin/archive-wal %p",
            "***",
            "",
            0,
        ),
        (
            "curl --user $(printf '%s' 'https://SECRET') https://minio/wal/%f",
            "curl",
            "",
            0,
        ),
        (
            "curl --user `printf '%s' 'https://SECRET'` https://minio/wal/%f",
            "curl",
            "",
            0,
        ),
        (
            "PGPASSWORD=SECRET curl --user ${VAR} https://minio/wal/%f",
            "***",
            "",
            0,
        ),
        (
            "curl --user ${VAR} https://SECRET https://minio/wal/%f",
            "curl",
            "",
            0,
        ),
        (
            "azcopy copy %p 'https://account.blob.core.windows.net/archive/%f?sp=w&sig=SECRET'",
            "azcopy",
            "",
            1,
        ),
        (
            "curl https://user:SECRET@s3test:9000/wal",
            "curl",
            "s3test",
            0,
        ),
        (
            r#"AWS_SECRET_ACCESS_KEY=SECRET REGION='local dev' '/opt/bin/wal-g+2.0' https://s3test:9000/wal"#,
            "/opt/bin/wal-g+2.0",
            "s3test",
            0,
        ),
        ("'bad$SECRET' https://s3test:9000/wal", "***", "s3test", 0),
        (
            "'KEY=value' SECRET https://s3test:9000/wal",
            "***",
            "s3test",
            0,
        ),
        (
            "PGPASSWORD='https://SECRET' /usr/local/bin/archive-wal %p",
            "/usr/local/bin/archive-wal",
            "",
            0,
        ),
        (
            "X=http://SECRET:9000 curl -T %p https://minio:9000/wal/%f",
            "curl",
            "",
            1,
        ),
        (
            "curl X=http://SECRET:9000 --other=https://SECRET --endpoint-url=https://minio:9000",
            "curl",
            "",
            1,
        ),
    ] {
        for source in ["sql", "inspect", "log"] {
            let mut fake = Fake::recorded("psql-failing.txt");
            if source == "sql" {
                let output = fake.psql.as_ref().unwrap();
                let mut fields: Vec<_> = output.split(postgres_wal::FIELD_SEP).collect();
                fields[7] = command;
                fake.psql = Ok(fields.join(&postgres_wal::FIELD_SEP.to_string()));
            } else {
                fake.psql = Err(PsqlError::Exec);
                fake.edit(&format!("/containers/{PG}/json"), |v| {
                    if source == "inspect" {
                        v["Args"] = serde_json::json!([
                            "postgres",
                            "-c",
                            format!("archive_command={command}")
                        ]);
                    } else {
                        v["Args"] = serde_json::json!(["postgres"]);
                        v["Config"]["Tty"] = true.into();
                    }
                });
                if source == "log" {
                    let log = format!(
                        "2026-11-13T02:10:00Z LOG: archive command failed with exit code 6\n2026-11-13T02:10:00Z DETAIL: The failed archive command was: {command}\n"
                    );
                    fake.gets.insert(
                        format!(
                            "/containers/{PG}/logs?stdout=1&stderr=1&timestamps=1&tail={LOG_TAIL}"
                        ),
                        Ok(log.into_bytes()),
                    );
                }
            }
            let f = probe(&fake);
            let report = serde_json::to_string(&f).unwrap();
            assert!(
                !report.contains("SECRET"),
                "credential exported for {source} and {program}"
            );
            assert_eq!(
                evidence(&f).archive_program.as_deref(),
                Some(program),
                "{source}"
            );
            let hosts: Vec<_> = evidence(&f)
                .targets
                .iter()
                .map(|target| target.host.as_str())
                .collect();
            assert_eq!(
                hosts,
                (!host.is_empty()).then_some(host).as_slice(),
                "{source}"
            );
            assert_eq!(evidence(&f).unmatched_hosts, unmatched, "{source}");
            if host == "s3test" {
                assert!(f.reason.contains("target s3test"), "{}", f.reason);
            } else if host.is_empty() {
                assert!(!f.reason.contains("(target"), "{}", f.reason);
                if source == "sql" {
                    assert!(
                        f.action.text.starts_with("fix archive_command"),
                        "{}",
                        f.action.text
                    );
                } else {
                    assert_eq!(f.action, volume_finding(VOLUME).action);
                }
            }
        }
    }
}

#[test]
fn disabled_archiving_keeps_history_without_repair_advice() {
    let mut fake = Fake::recorded("psql-failing.txt");
    let output = fake.psql.as_ref().unwrap();
    let mut fields: Vec<_> = output.split(postgres_wal::FIELD_SEP).collect();
    fields[6] = "off";
    fake.psql = Ok(fields.join(&postgres_wal::FIELD_SEP.to_string()));
    let f = probe(&fake);
    assert!(f.reason.contains("archiving is off"), "{}", f.reason);
    assert!(!f.reason.contains("archiving is failing"), "{}", f.reason);
    assert!(!f.reason.contains("archiving works again"), "{}", f.reason);
    assert!(!f.reason.contains("(target"), "{}", f.reason);
    assert_eq!(f.action, volume_finding(VOLUME).action);
    assert_eq!(evidence(&f).failed_count, Some(151));
    assert_eq!(
        evidence(&f).last_failed_at.as_deref(),
        Some("2026-11-15T02:10:00Z")
    );
    assert_eq!(
        evidence(&f).last_archived_at.as_deref(),
        Some("2026-11-07T07:25:00Z")
    );

    fake.psql = Err(PsqlError::Exec);
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        let arg = v["Args"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|arg| **arg == "archive_mode=on")
            .unwrap();
        *arg = "ARCHIVE_MODE=OFF".into();
    });
    let f = probe(&fake);
    assert_eq!(evidence(&f).archive_mode.as_deref(), Some("off"));
    assert_eq!(evidence(&f).failed_count, Some(3));
    assert_eq!(
        evidence(&f).last_failed_at.as_deref(),
        Some("2026-11-13T02:10:00.3Z")
    );
    assert_eq!(evidence(&f).targets[0].state, "exited");
    assert!(!f.reason.contains("(target"), "{}", f.reason);
    assert_eq!(f.action, volume_finding(VOLUME).action);
}
