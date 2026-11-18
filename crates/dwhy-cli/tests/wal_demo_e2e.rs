//! The M3 WAL demo (docs/ACCEPTANCE-M3.md) against the real Docker daemon.
//!
//! Opt-in and run by hand, never in CI:
//!
//! ```text
//! DWHY_DOCKER_E2E=1 cargo test -p dwhy-cli --test wal_demo_e2e -- --ignored --nocapture
//! ```
//!
//! It starts `tests/data/wal-demo/compose.yaml` under a project name of its
//! own and removes that project (containers, volume, network) on every path.
//! It never runs `scan` with the `docker-volume` detector: the postgres-wal
//! probe would then `docker exec` into every big in-use Postgres volume on
//! the machine. `watch` and `diff` skip probes, and `explain` probes only the
//! finding it explains.

use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

const COMPOSE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/wal-demo/compose.yaml"
);
const GIB: u64 = 1 << 30;
const MIB: i64 = 1 << 20;
/// The docker-volume detector reports an in-use volume from 1 GiB; wait
/// for a margin above it, as du in the container and the daemon's sizing
/// can differ slightly.
const WAIT_FOR_BYTES: u64 = GIB + GIB / 10;
const GROW_TIMEOUT: Duration = Duration::from_secs(600);

fn run(cmd: &mut Command) -> Output {
    let out = cmd.output().unwrap_or_else(|e| panic!("run {cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed ({}):\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A Compose project that is taken down, volume included, when dropped.
struct Project {
    name: String,
}

impl Project {
    fn up() -> Project {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let p = Project {
            name: format!("dwhye2e{}{secs}", std::process::id()),
        };
        // From here on, Drop tears down whatever `up` managed to create.
        run(p.compose().args(["up", "-d"]));
        p
    }

    fn compose(&self) -> Command {
        let mut c = Command::new("docker");
        c.args(["compose", "-p", &self.name, "-f", COMPOSE]);
        c
    }

    fn volume(&self) -> String {
        format!("{}_pgdata", self.name)
    }

    fn wait_healthy(&self) {
        let id = stdout(&run(self.compose().args(["ps", "-q", "postgres"])));
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let health = stdout(&run(Command::new("docker").args([
                "inspect",
                "-f",
                "{{.State.Health.Status}}",
                &id,
            ])));
            if health == "healthy" {
                return;
            }
            assert!(Instant::now() < deadline, "postgres not healthy: {health}");
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Allocated bytes in the volume, measured inside this project's own
    /// Postgres container.
    fn volume_bytes(&self) -> u64 {
        let out = run(self.compose().args([
            "exec",
            "-T",
            "postgres",
            "du",
            "-sk",
            "/var/lib/postgresql/data",
        ]));
        let kib: u64 = stdout(&out)
            .split_whitespace()
            .next()
            .and_then(|k| k.parse().ok())
            .expect("du output");
        kib * 1024
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let status = self
            .compose()
            .args(["down", "-v", "--remove-orphans"])
            .status();
        eprintln!("teardown of {}: {status:?}", self.name);
    }
}

/// What Docker still holds for Compose project `name`, one line per object.
fn leftovers(name: &str) -> Vec<String> {
    let label = format!("label=com.docker.compose.project={name}");
    let mut v = Vec::new();
    for what in [
        &["ps", "-a", "-q"][..],
        &["volume", "ls", "-q"],
        &["network", "ls", "-q"],
    ] {
        let out = run(Command::new("docker").args(what).args(["--filter", &label]));
        v.extend(
            stdout(&out)
                .lines()
                .map(|l| format!("{} {l}", what.join(" "))),
        );
    }
    v
}

/// Runs `dwhy` with its state dir in `state` and parses its JSON output.
fn dwhy(state: &Path, args: &[&str]) -> Value {
    let out = run(Command::new(env!("CARGO_BIN_EXE_dwhy"))
        .args(args)
        .arg("--quiet")
        .env("XDG_STATE_HOME", state));
    serde_json::from_slice(&out.stdout).expect("dwhy JSON")
}

/// The Docker change or rate entry for volume `name`.
fn volume_entry<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["docker"]
        .as_array()
        .expect("docker list")
        .iter()
        .find(|c| c["kind"] == "volume" && c["name"] == name)
        .unwrap_or_else(|| panic!("no entry for volume {name} in {:#}", report["docker"]))
}

#[test]
#[ignore = "needs Docker; run by hand with DWHY_DOCKER_E2E=1"]
fn wal_demo_is_flagged_and_explained() {
    if std::env::var_os("DWHY_DOCKER_E2E").is_none_or(|v| v != "1") {
        eprintln!("skipped: set DWHY_DOCKER_E2E=1 to run the WAL demo against Docker");
        return;
    }
    let started = Instant::now();
    let state = tempfile::tempdir().unwrap();
    let walk = tempfile::tempdir().unwrap();
    let walk = walk.path().to_str().unwrap();

    let project = Project::up();
    let name = project.name.clone();
    let volume = project.volume();
    eprintln!("project {name}, volume {volume}");
    project.wait_healthy();

    // First snapshot. docker-build-cache reads /system/df, so the snapshot
    // records every volume; no docker-volume finding means no probe.
    let scan = dwhy(
        state.path(),
        &[
            "scan",
            walk,
            "--snapshot",
            "--detectors",
            "docker-build-cache",
            "--json",
        ],
    );
    assert!(scan["snapshot"].is_object(), "no snapshot saved");

    let grow_start = Instant::now();
    loop {
        let bytes = project.volume_bytes();
        eprintln!("volume holds {} MiB", bytes >> 20);
        if bytes >= WAIT_FOR_BYTES {
            break;
        }
        assert!(
            grow_start.elapsed() < GROW_TIMEOUT,
            "volume {volume} reached only {} MiB in {GROW_TIMEOUT:?}; is the writer running?",
            bytes >> 20
        );
        std::thread::sleep(Duration::from_secs(10));
    }
    eprintln!("reached 1.1 GiB in {:?}", grow_start.elapsed());

    let watch = dwhy(state.path(), &["watch", walk, "--for", "30s", "--json"]);
    assert_eq!(watch["docker_compared"], true, "notes: {}", watch["notes"]);
    let rate = volume_entry(&watch, &volume);
    let per_min = rate["bytes_per_minute"].as_i64().unwrap();
    eprintln!("watch: {rate}");
    assert!(per_min > 20 * MIB, "volume grows only {per_min} B/min");

    let diff = dwhy(
        state.path(),
        &["diff", "--detectors", "docker-build-cache", "--json"],
    );
    assert_eq!(diff["docker_compared"], true, "notes: {}", diff["notes"]);
    let change = volume_entry(&diff, &volume);
    eprintln!("diff: {change}");
    assert!(
        change["change"].as_i64().unwrap() > 512 * MIB,
        "volume did not grow"
    );

    let path = format!("docker://volume/{volume}");
    let explain = dwhy(state.path(), &["explain", &path, "--json"]);
    let f = &explain["finding"];
    eprintln!(
        "explain: reason: {}\nexplain: advice: {}\nexplain: evidence: {:#}",
        f["reason"], f["action"]["text"], f["evidence"]
    );
    assert_eq!(f["detector"], "docker-volume", "{explain:#}");
    assert_eq!(f["path"], path.as_str());
    let wal = &f["evidence"]["postgres_wal"];
    assert!(wal["failed_count"].as_u64().unwrap_or(0) > 0, "{wal:#}");
    assert_eq!(wal["archive_mode"], "on");
    let dead = wal["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["host"] == "s3test")
        .unwrap_or_else(|| panic!("s3test not among the targets: {wal:#}"));
    assert_eq!(dead["state"], "exited");
    assert_eq!(dead["container"], format!("{name}-s3test-1").as_str());
    let advice = f["action"]["text"].as_str().unwrap();
    assert!(
        advice.starts_with("restore the archive target s3test"),
        "{advice}"
    );

    drop(project);
    let left = leftovers(&name);
    assert!(left.is_empty(), "left behind: {left:?}");
    eprintln!("done in {:?}", started.elapsed());
}
