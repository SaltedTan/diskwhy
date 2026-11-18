//! The `postgres-wal` probe against recorded Engine API responses and psql
//! output (tests/data/postgres-wal/). No daemon is contacted and nothing
//! is executed.

use std::cell::RefCell;
use std::collections::HashMap;

use dwhy_core::detect::finding_id;
use dwhy_core::docker::demux_logs;
use dwhy_core::probes::postgres_wal::{self, Docker, LOG_TAIL};
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
    gets: HashMap<String, Result<Vec<u8>, String>>,
    psql: Result<String, String>,
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
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        self.asked.borrow_mut().push(format!("GET {path}"));
        self.gets
            .get(path)
            .cloned()
            .unwrap_or_else(|| Err(format!("404 {path}")))
    }

    fn psql(&self, id: &str, user: &str, db: &str, sql: &str) -> Result<String, String> {
        assert_eq!(sql, postgres_wal::QUERY);
        self.asked
            .borrow_mut()
            .push(format!("psql {id} -U {user} -d {db}"));
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
            "pg_wal holds 29.0G vs 53.0M data; archive_command failing 151x since 2026-11-07 \
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
    assert!(fake.asked_for(&format!("psql {PG} -U app -d appdb")));
    assert!(!fake.asked_for(&format!("GET /containers/{PG}/logs")));
}

#[test]
fn missing_target_is_named() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.remove_container(S3);
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(
        ev.targets,
        [ArchiveTarget {
            host: "s3test".into(),
            container: None,
            state: "missing".into(),
        }]
    );
    assert!(f.reason.contains("(target s3test missing)"), "{}", f.reason);
    assert!(
        f.action
            .text
            .starts_with("restore the archive target s3test;")
    );
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
    fake.edit_listed(S3, |c| c["State"] = "running".into());
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
    fake.psql = Err(
        "docker exec psql failed (exit status: 2): psql: error: FATAL: role \"app\" does not exist"
            .into(),
    );
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.source, EvidenceSource::ApiOnly);
    assert_eq!(ev.wal_bytes, None);
    assert_eq!(ev.data_bytes, None);
    // Three failure lines in the recorded tail.
    assert_eq!(ev.failed_count, Some(3));
    assert_eq!(ev.last_failed_at.as_deref(), Some("2026-11-13T02:10:00Z"));
    assert_eq!(
        ev.last_failed_wal.as_deref(),
        Some("000000010000000000000097")
    );
    // Settings from the container's command line.
    assert_eq!(ev.archive_mode.as_deref(), Some("on"));
    assert_eq!(ev.archive_timeout.as_deref(), Some("10s"));
    assert_eq!(
        ev.archive_command.as_deref(),
        Some("aws --endpoint-url http://s3test:9000 s3 cp %p s3://wal/%f")
    );
    assert_eq!(ev.targets[0].state, "exited");
    assert!(
        ev.notes[0].starts_with("psql not used: docker exec psql failed")
            && ev.notes[0].contains("role \"app\" does not exist"),
        "{:?}",
        ev.notes
    );
    assert!(
        f.reason.starts_with(&format!(
            "archive_command failing 3x in the last {LOG_TAIL} log lines (target s3test (pgwal-s3test-1) exited)"
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
fn api_only_takes_the_command_from_the_log_when_the_command_line_has_none() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err("`docker` is not installed".into());
    // archive settings in postgresql.conf instead of on the command line
    fake.edit(&format!("/containers/{PG}/json"), |v| {
        v["Args"] = serde_json::json!(["postgres"]);
    });
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.archive_mode, None);
    assert!(
        ev.archive_command
            .as_deref()
            .unwrap()
            .starts_with("aws --endpoint-url http://s3test:9000 s3 cp pg_wal/"),
        "{:?}",
        ev.archive_command
    );
    assert_eq!(ev.targets[0].host, "s3test");
    assert_eq!(ev.failed_count, Some(3));
}

#[test]
fn api_only_with_an_unreadable_log_says_so() {
    let mut fake = Fake::recorded("psql-failing.txt");
    fake.psql = Err("`docker` is not installed".into());
    fake.gets.retain(|k, _| !k.contains("/logs"));
    let f = probe(&fake);
    let ev = evidence(&f);
    assert_eq!(ev.source, EvidenceSource::ApiOnly);
    assert_eq!(ev.failed_count, None);
    assert!(
        ev.notes.iter().any(|n| n.starts_with("log tail not read")),
        "{:?}",
        ev.notes
    );
    // Nothing shows a failure, so the detector's advice stays.
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
    assert!(fake.asked_for(&format!("psql {PG} -U postgres -d postgres")));
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
    let text = String::from_utf8(demux_logs(&raw)).unwrap();
    assert_eq!(text.lines().count(), 7);
    assert!(text.starts_with("2026-11-07T07:00:02.000000000Z "));
    assert!(!text.contains('\0'));

    // A TTY container's raw stream passes through.
    assert_eq!(demux_logs(b"plain text\n"), b"plain text\n");
    // A truncated last frame keeps what arrived.
    let mut cut = vec![1, 0, 0, 0, 0, 0, 0, 3];
    cut.extend_from_slice(b"abc");
    cut.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 10]);
    cut.extend_from_slice(b"de");
    assert_eq!(demux_logs(&cut), b"abcde");
    assert_eq!(demux_logs(b""), b"");
}
