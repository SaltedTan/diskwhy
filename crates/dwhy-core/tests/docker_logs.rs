//! `docker-logs` on temp-dir fixtures: a docker root built in a temp dir and
//! Engine API answers recorded from Docker 29 (`/info`, `/containers/json`,
//! `/containers/{id}/json`, trimmed to the fields diskwhy reads), never the
//! machine's daemon.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{self, CATALOG, DetectContext, Detector, finding_id, rfc3339};
use dwhy_core::detectors::{DockerLogs, MIN_LOG_BYTES};
use dwhy_core::docker::GetError;
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ActionKind, DetectorAvailability, DockerSocket, Tier};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;
use serde_json::json;

const MIB: u64 = 1 << 20;
/// The threshold most tests use, so fixtures stay small.
const MIN: u64 = MIB;

fn base() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn scan_tree(root: &Path) -> ScanTree {
    let roots = scan::prepare_roots(&[root.to_path_buf()], true).unwrap();
    let opts = ScanOptions {
        min_dir_bytes: 0,
        threads: 2,
        ..ScanOptions::default()
    };
    scan::scan(
        &roots,
        &opts,
        &MountTable::read().unwrap(),
        &Progress::default(),
    )
    .unwrap()
    .tree
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn ctx(root: bool, socket: DockerSocket) -> DetectContext {
    DetectContext {
        uid: if root { 0 } else { 1000 },
        root,
        home: None,
        now: now(),
        tools: Vec::new(),
        docker_socket: socket,
        docker: dwhy_core::docker::Source::none(),
        cancel: Default::default(),
        scratch_paths: Vec::new(),
        scratch_stale_days: dwhy_core::detectors::SCRATCH_STALE_DAYS,
    }
}

fn socket(exists: bool, accessible: bool) -> DockerSocket {
    DockerSocket {
        path: "/run/docker.sock".into(),
        exists,
        accessible,
    }
}

fn root_ctx() -> DetectContext {
    ctx(true, socket(true, true))
}

fn id(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn docker_root(b: &Path) -> PathBuf {
    b.join("var/lib/docker")
}

fn log_path(b: &Path, id: &str) -> PathBuf {
    docker_root(b)
        .join("containers")
        .join(id)
        .join(format!("{id}-json.log"))
}

/// Writes `bytes` of data to `p` (and the container's small config file).
fn write(p: &Path, bytes: u64) {
    let dir = p.parent().unwrap();
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("config.v2.json"), b"{}").unwrap();
    fs::write(p, vec![b'{'; bytes as usize]).unwrap();
}

fn allocated(p: &Path) -> u64 {
    fs::symlink_metadata(p).unwrap().blocks() * 512
}

/// One container as `/containers/{id}/json` reports it.
struct C {
    id: String,
    name: &'static str,
    state: &'static str,
    driver: &'static str,
    opts: serde_json::Value,
    labels: serde_json::Value,
    log_path: Option<String>,
}

impl C {
    fn new(b: &Path, id: String, name: &'static str) -> C {
        C {
            log_path: Some(log_path(b, &id).to_string_lossy().into_owned()),
            id,
            name,
            state: "running",
            driver: "json-file",
            opts: json!({}),
            labels: json!({}),
        }
    }

    fn inspect(&self) -> serde_json::Value {
        json!({
            "Id": self.id,
            "Name": format!("/{}", self.name),
            "LogPath": self.log_path.clone().unwrap_or_default(),
            "State": {"Status": self.state, "Running": self.state == "running"},
            "HostConfig": {"LogConfig": {"Type": self.driver, "Config": self.opts}},
            "Config": {"Labels": self.labels},
        })
    }
}

fn responses(
    b: &Path,
    listed: &[&C],
    inspected: &[&C],
) -> BTreeMap<String, Result<Vec<u8>, GetError>> {
    let mut m = BTreeMap::new();
    let info = json!({
        "DockerRootDir": docker_root(b).to_string_lossy(),
        "Driver": "overlayfs",
    });
    m.insert("/info".into(), Ok(info.to_string().into_bytes()));
    let list: Vec<_> = listed
        .iter()
        .map(|c| json!({"Id": c.id, "Names": [format!("/{}", c.name)], "State": c.state}))
        .collect();
    m.insert(
        "/containers/json?all=1".into(),
        Ok(serde_json::to_vec(&list).unwrap()),
    );
    for c in inspected {
        m.insert(
            format!("/containers/{}/json", c.id),
            Ok(c.inspect().to_string().into_bytes()),
        );
    }
    m
}

fn detect_with(
    b: &Path,
    resp: BTreeMap<String, Result<Vec<u8>, GetError>>,
    min: u64,
) -> Result<Vec<dwhy_core::report::Finding>, String> {
    let tree = scan_tree(b);
    DockerLogs::with_responses(resp, min)
        .detect_candidates(&tree, &root_ctx())
        .map(|cs| cs.into_iter().map(|c| c.finding).collect())
}

#[test]
fn reports_an_uncapped_log_of_a_running_compose_container() {
    let (_t, b) = base();
    let mut c = C::new(&b, id(1), "shop-db-1");
    c.labels = json!({
        "com.docker.compose.project": "shop",
        "com.docker.compose.service": "db",
        "com.docker.compose.project.working_dir": "/srv/shop",
    });
    let p = log_path(&b, &c.id);
    write(&p, 3 * MIB);

    let found = detect_with(&b, responses(&b, &[&c], &[&c]), MIN).unwrap();
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = &found[0];
    let path = p.to_str().unwrap();
    assert_eq!(f.path, path);
    assert_eq!(f.id, finding_id("docker-logs", path));
    assert_eq!(f.detector, "docker-logs");
    assert_eq!(f.bytes, allocated(&p));
    assert_eq!(f.tier, Tier::Review);
    assert_eq!(
        f.last_modified.as_deref(),
        Some(rfc3339(fs::metadata(&p).unwrap().mtime()).as_str())
    );
    assert!(f.guards.is_empty());
    assert_eq!(f.action.kind, ActionKind::Advice);
    assert!(f.action.argv.is_none());
    assert!(
        f.reason
            .contains("container shop-db-1 (010101010101), running")
            && f.reason
                .contains("no max-size is set, so Docker never rotates it"),
        "{}",
        f.reason
    );
    assert!(
        f.action.text.contains("service db in Compose project shop")
            && f.action
                .text
                .contains("docker compose up -d --force-recreate db")
            && !f.action.text.contains("docker rm"),
        "{}",
        f.action.text
    );
    assert!(f.recovery.cost.contains("docker logs"));
}

#[test]
fn reports_at_the_default_threshold_and_not_below() {
    let (_t, b) = base();
    let small = C::new(&b, id(1), "small");
    let big = C::new(&b, id(2), "big");
    write(&log_path(&b, &small.id), MIN_LOG_BYTES - 64 * 1024);
    write(&log_path(&b, &big.id), MIN_LOG_BYTES);

    let found = detect_with(
        &b,
        responses(&b, &[&small, &big], &[&small, &big]),
        MIN_LOG_BYTES,
    )
    .unwrap();
    let paths: Vec<_> = found.iter().map(|f| f.path.clone()).collect();
    assert_eq!(
        paths,
        [log_path(&b, &big.id).to_string_lossy().into_owned()]
    );
}

#[test]
fn a_capped_stopped_container_gets_rotation_advice() {
    let (_t, b) = base();
    let mut c = C::new(&b, id(3), "batch");
    c.state = "exited";
    c.opts = json!({"max-size": "500m", "max-file": "4"});
    write(&log_path(&b, &c.id), 2 * MIB);

    let found = detect_with(&b, responses(&b, &[&c], &[&c]), MIN).unwrap();
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert!(
        f.reason.contains("exited")
            && f.reason
                .contains("Docker rotates it at max-size 500m and keeps max-file 4 files"),
        "{}",
        f.reason
    );
    assert!(
        f.action.text.contains("lower its caps")
            && f.action.text.contains("--log-opt max-size=10m"),
        "{}",
        f.action.text
    );
}

#[test]
fn a_cap_that_is_not_plain_still_counts_as_set() {
    let (_t, b) = base();
    let mut c = C::new(&b, id(5), "api");
    c.opts = json!({"max-size": "200 MB", "max-file": "4 "});
    write(&log_path(&b, &c.id), 2 * MIB);
    let found = detect_with(&b, responses(&b, &[&c], &[&c]), MIN).unwrap();
    let f = &found[0];
    assert!(
        f.reason
            .contains("Docker rotates it at its max-size and keeps max-file 4 files")
            && !f.reason.contains("200 MB")
            && !f.reason.contains("no max-size"),
        "{}",
        f.reason
    );
    assert!(
        f.action.text.contains("lower its caps"),
        "{}",
        f.action.text
    );

    c.opts = json!({"max-size": "50m", "max-file": "3 files"});
    let found = detect_with(&b, responses(&b, &[&c], &[&c]), MIN).unwrap();
    assert!(
        found[0]
            .reason
            .contains("Docker rotates it at max-size 50m and keeps as many files as its max-file")
            && !found[0].reason.contains("3 files"),
        "{}",
        found[0].reason
    );
}

#[test]
fn reports_from_a_walk_of_the_containers_directory_itself() {
    // `dwhy explain` on a log walks from `containers`, so that directory is
    // the walk's root and its node is named by its full path.
    let (_t, b) = base();
    let c = C::new(&b, id(1), "web");
    let p = log_path(&b, &c.id);
    write(&p, 2 * MIB);
    let tree = scan_tree(&docker_root(&b).join("containers"));
    let found = DockerLogs::with_responses(responses(&b, &[&c], &[&c]), MIN)
        .detect_candidates(&tree, &root_ctx())
        .unwrap();
    let paths: Vec<_> = found.iter().map(|c| c.finding.path.clone()).collect();
    assert_eq!(paths, [p.to_string_lossy().into_owned()]);
}

#[test]
fn unlimited_max_size_counts_as_uncapped() {
    let (_t, b) = base();
    let mut c = C::new(&b, id(4), "web");
    c.opts = json!({"max-size": "-1"});
    write(&log_path(&b, &c.id), 2 * MIB);
    let found = detect_with(&b, responses(&b, &[&c], &[&c]), MIN).unwrap();
    assert!(found[0].reason.contains("no max-size is set"), "{found:#?}");
}

#[test]
fn ignores_lookalikes() {
    let (_t, b) = base();
    // Not listed by the daemon.
    let stray = C::new(&b, id(1), "stray");
    write(&log_path(&b, &stray.id), 2 * MIB);
    // Another log driver.
    let mut local = C::new(&b, id(2), "local");
    local.driver = "local";
    write(&log_path(&b, &local.id), 2 * MIB);
    // The daemon logs somewhere else.
    let mut moved = C::new(&b, id(3), "moved");
    moved.log_path = Some("/elsewhere/x-json.log".into());
    write(&log_path(&b, &moved.id), 2 * MIB);
    // Removed since the listing: the inspect is a 404.
    let gone = C::new(&b, id(4), "gone");
    write(&log_path(&b, &gone.id), 2 * MIB);
    // A symlink to a big file.
    let linked = C::new(&b, id(5), "linked");
    let target = b.join("big.log");
    write(&target, 2 * MIB);
    fs::create_dir_all(log_path(&b, &linked.id).parent().unwrap()).unwrap();
    symlink(&target, log_path(&b, &linked.id)).unwrap();
    // A hardlinked log: removing the container would not free it.
    let hard = C::new(&b, id(6), "hard");
    write(&log_path(&b, &hard.id), 2 * MIB);
    fs::hard_link(log_path(&b, &hard.id), b.join("copy.log")).unwrap();
    // The log is a directory.
    let dir = C::new(&b, id(7), "dir");
    fs::create_dir_all(log_path(&b, &dir.id)).unwrap();
    write(&log_path(&b, &dir.id).join("x"), 2 * MIB);
    // Not a container id.
    let short = C {
        id: "abc".into(),
        ..C::new(&b, id(8), "short")
    };
    write(
        &docker_root(&b).join("containers/abc/abc-json.log"),
        2 * MIB,
    );

    // The control: a log that is reported.
    let ok = C::new(&b, id(9), "ok");
    write(&log_path(&b, &ok.id), 2 * MIB);

    let listed = [&local, &moved, &gone, &linked, &hard, &dir, &short, &ok];
    let inspected = [&local, &moved, &linked, &hard, &dir, &short, &ok];
    let found = detect_with(&b, responses(&b, &listed, &inspected), MIN).unwrap();
    let paths: Vec<_> = found.iter().map(|f| f.path.clone()).collect();
    assert_eq!(paths, [log_path(&b, &ok.id).to_string_lossy().into_owned()]);
}

#[test]
fn another_docker_root_is_not_read() {
    let (_t, b) = base();
    let c = C::new(&b, id(1), "web");
    write(&log_path(&b, &c.id), 2 * MIB);
    let mut resp = responses(&b, &[&c], &[&c]);
    resp.insert(
        "/info".into(),
        Ok(json!({"DockerRootDir": "/srv/docker"})
            .to_string()
            .into_bytes()),
    );
    assert!(detect_with(&b, resp, MIN).unwrap().is_empty());
    assert_eq!(
        detect_with(&b, responses(&b, &[&c], &[&c]), MIN)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn asks_the_daemon_only_when_the_walk_holds_a_container_directory() {
    let (_t, b) = base();
    // A big file, but no `containers/<id>` directory: no request at all,
    // so an empty set of answers (every GET a 404) is no error.
    write(&b.join("var/lib/docker/other/app.log"), 2 * MIB);
    assert!(detect_with(&b, BTreeMap::new(), MIN).unwrap().is_empty());

    // With one, an unreachable daemon is the detector's error.
    let c = C::new(&b, id(1), "web");
    write(&log_path(&b, &c.id), 2 * MIB);
    let mut resp = BTreeMap::new();
    resp.insert(
        "/info".into(),
        Err(GetError::Other("docker API: connection refused".into())),
    );
    let err = detect_with(&b, resp, MIN).unwrap_err();
    assert!(err.contains("connection refused"), "{err}");
}

#[test]
fn an_inspect_failure_other_than_404_is_an_error() {
    let (_t, b) = base();
    let c = C::new(&b, id(1), "web");
    write(&log_path(&b, &c.id), 2 * MIB);
    let mut resp = responses(&b, &[&c], &[]);
    resp.insert(
        format!("/containers/{}/json", c.id),
        Err(GetError::Http(500, "docker API: 500".into())),
    );
    assert!(detect_with(&b, resp, MIN).is_err());
}

#[test]
fn names_that_are_not_plain_are_left_out() {
    let (_t, b) = base();
    let mut c = C::new(&b, id(1), "x\u{1b}[31m");
    c.labels = json!({
        "com.docker.compose.project": "p q",
        "com.docker.compose.service": "db",
    });
    write(&log_path(&b, &c.id), 2 * MIB);
    let found = detect_with(&b, responses(&b, &[&c], &[&c]), MIN).unwrap();
    let f = &found[0];
    assert!(
        f.reason.starts_with("container 010101010101, "),
        "{}",
        f.reason
    );
    assert!(!f.reason.contains('\u{1b}'));
    // Without a plain project name the advice is not Compose's.
    assert!(f.action.text.contains("--log-opt"), "{}", f.action.text);
}

#[test]
fn needs_a_usable_socket_but_not_the_cli() {
    let info = CATALOG.iter().find(|d| d.name == "docker-logs").unwrap();
    let status = |c: &DetectContext| detect::availability(info, c).0;
    assert_eq!(
        status(&ctx(true, socket(false, false))),
        DetectorAvailability::Unavailable
    );
    assert_eq!(
        status(&ctx(false, socket(true, false))),
        DetectorAvailability::Unavailable
    );
    assert_eq!(
        status(&ctx(true, socket(true, true))),
        DetectorAvailability::Available
    );
    let (s, detail) = detect::availability(info, &ctx(false, socket(true, true)));
    assert_eq!(s, DetectorAvailability::Available);
    assert!(detail.contains("root scan"), "{detail}");
}
