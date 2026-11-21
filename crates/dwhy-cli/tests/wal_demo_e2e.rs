//! The M3 WAL demo (docs/ACCEPTANCE-M3.md) against the real Docker daemon.
//!
//! Opt-in and run by hand, never in CI:
//!
//! ```text
//! DWHY_DOCKER_E2E=1 cargo test -p dwhy-cli --test wal_demo_e2e -- --ignored --nocapture
//! ```
//!
//! It starts `tests/data/wal-demo/compose.yaml` under a project name of its
//! own. See the acceptance record for teardown instructions.
//! It never runs `scan` with the `docker-volume` detector: the postgres-wal
//! probe would then `docker exec` into every big in-use Postgres volume on
//! the machine. `watch` and `diff` skip probes, and `explain` probes only the
//! finding it explains.

use std::any::Any;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serde_json::Value;

const COMPOSE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/wal-demo/compose.yaml"
);
const GIB: u64 = 1 << 30;
const MIB: i64 = 1 << 20;
/// The docker-volume detector reports an in-use volume from 1 GiB; wait
/// for a margin above it, as the container's apparent-size sample can
/// differ slightly from the daemon's volume size.
const WAIT_FOR_BYTES: u64 = GIB + GIB / 10;
const GROW_TIMEOUT: Duration = Duration::from_secs(600);

/// Runs `cmd`; an error if it cannot start or exits unsuccessfully.
fn try_run(cmd: &mut Command) -> Result<Output, String> {
    let out = cmd.output().map_err(|e| format!("run {cmd:?}: {e}"))?;
    if out.status.success() {
        Ok(out)
    } else {
        Err(format!(
            "{cmd:?} failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn run(cmd: &mut Command) -> Output {
    try_run(cmd).unwrap_or_else(|e| panic!("{e}"))
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn docker_command(program: impl AsRef<OsStr>, docker_host: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("DOCKER_HOST", docker_host)
        .env_remove("DOCKER_CONTEXT");
    cmd
}

/// The demo talks to the daemon over a Unix socket only. An error explains
/// why an inherited `DOCKER_HOST` cannot be used.
fn check_docker_host(value: Option<&OsStr>) -> Result<(), String> {
    const NEED: &str =
        "the WAL demo needs DOCKER_HOST unset or set to an absolute Unix socket URL (unix:///...)";
    match value.map(OsStr::to_str) {
        None => Ok(()),
        Some(Some(s)) if s.starts_with("unix:///") => Ok(()),
        Some(Some(s)) => Err(format!("unsupported DOCKER_HOST={s:?}: {NEED}")),
        Some(None) => Err(format!(
            "unsupported DOCKER_HOST={:?} (not UTF-8): {NEED}",
            value.unwrap_or_default()
        )),
    }
}

/// How the test reaches Docker: the CLI (with any leading arguments) and
/// the daemon URL passed to it as `DOCKER_HOST`.
struct Docker {
    program: OsString,
    leading_args: Vec<OsString>,
    host: String,
}

impl Docker {
    fn new(host: String) -> Self {
        Self {
            program: "docker".into(),
            leading_args: Vec::new(),
            host,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = docker_command(&self.program, &self.host);
        cmd.args(&self.leading_args);
        cmd
    }
}

/// A Compose project name of the test's own, unique to this run.
fn project_name() -> String {
    let mut random = [0; 8];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .expect("read random project suffix from /dev/urandom");
    let suffix = u64::from_ne_bytes(random);
    format!("dwhye2e{}{suffix:016x}", std::process::id())
}

/// A Compose project that is taken down, volume included, when dropped.
struct Project<'a> {
    name: String,
    docker: &'a Docker,
}

impl<'a> Project<'a> {
    fn up(docker: &'a Docker, name: &str) -> Self {
        let p = Self {
            name: name.to_string(),
            docker,
        };
        let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
        eprintln!(
            "To clean up after an interrupt, run: env -u DOCKER_CONTEXT DOCKER_HOST={host} COMPOSE_PROJECT_NAME={name} docker compose -p {name} -f {file} down -v --remove-orphans",
            host = quote(&docker.host),
            name = p.name,
            file = quote(COMPOSE),
        );
        // From here on, Drop tears down whatever `up` managed to create.
        run(p.compose().args(["up", "-d", "--pull", "never"]));
        p
    }

    fn compose(&self) -> Command {
        let mut c = self.docker.command();
        c.env("COMPOSE_PROJECT_NAME", &self.name)
            .args(["compose", "-p", &self.name, "-f", COMPOSE]);
        c
    }

    fn volume(&self) -> String {
        format!("{}_pgdata", self.name)
    }

    fn wait_healthy(&self) {
        let id = stdout(&run(self.compose().args(["ps", "-q", "postgres"])));
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let health = stdout(&run(self.docker.command().args([
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

    /// Apparent file bytes in the volume, measured inside this project's
    /// own Postgres container.
    fn volume_bytes(&self) -> u64 {
        let mut cmd = self.compose();
        cmd.args([
            "exec",
            "-T",
            "postgres",
            "find",
            "/var/lib/postgresql/data",
            "-type",
            "f",
            "-exec",
            "stat",
            "-c",
            "%s",
            "{}",
            "+",
        ]);
        let out = cmd.output().unwrap_or_else(|e| panic!("run {cmd:?}: {e}"));
        let sizes = stdout(&out);
        assert!(
            !sizes.is_empty(),
            "{cmd:?} returned no file sizes ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        sizes
            .lines()
            .map(|size| size.parse::<u64>().expect("stat size in bytes"))
            .sum()
    }
}

impl Drop for Project<'_> {
    /// Never panics (Rust's stderr ignores a closed descriptor), so it is
    /// safe while a panic unwinds.
    fn drop(&mut self) {
        let status = self
            .compose()
            .args(["down", "-v", "--remove-orphans"])
            .status();
        eprintln!("teardown of {}: {status:?}", self.name);
    }
}

/// What Docker still holds for Compose project `name`, one line per object.
fn leftovers(docker: &Docker, name: &str) -> Result<Vec<String>, String> {
    let label = format!("label=com.docker.compose.project={name}");
    let mut v = Vec::new();
    for what in [
        &["ps", "-a", "-q"][..],
        &["volume", "ls", "-q"],
        &["network", "ls", "-q"],
    ] {
        let out = try_run(docker.command().args(what).args(["--filter", &label]))?;
        v.extend(
            stdout(&out)
                .lines()
                .map(|l| format!("{} {l}", what.join(" "))),
        );
    }
    Ok(v)
}

fn panic_summary(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

/// Starts Compose project `name`, runs `body` against it, takes the project
/// down and then checks that Docker holds nothing labelled with `name`,
/// whether or not `up` or `body` panicked.
///
/// A panic with nothing left behind propagates unchanged. A panic that also
/// leaves objects behind (or whose leftover check fails) is reported as one
/// panic naming both.
fn with_project(docker: &Docker, name: &str, body: impl FnOnce(&Project<'_>)) {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        let project = Project::up(docker, name);
        body(&project);
    }));
    let left = leftovers(docker, name);
    match (outcome, left) {
        (Ok(()), Ok(left)) => assert!(left.is_empty(), "left behind: {left:?}"),
        (Ok(()), Err(e)) => panic!("leftover check failed: {e}"),
        (Err(payload), Ok(left)) if left.is_empty() => panic::resume_unwind(payload),
        (Err(payload), Ok(left)) => panic!(
            "test panicked ({}) and left behind: {left:?}",
            panic_summary(&*payload)
        ),
        (Err(payload), Err(e)) => panic!(
            "test panicked ({}) and the leftover check failed: {e}",
            panic_summary(&*payload)
        ),
    }
}

/// Runs `dwhy` with its state dir in `state` and parses its JSON output.
fn dwhy(docker_host: &str, state: &Path, args: &[&str]) -> Value {
    let out = run(docker_command(env!("CARGO_BIN_EXE_dwhy"), docker_host)
        .args(args)
        .arg("--quiet")
        .env("XDG_STATE_HOME", state));
    serde_json::from_slice(&out.stdout).expect("dwhy JSON")
}

/// The Docker change or rate entry for volume `name`.
fn volume_entry<'a>(report: &'a Value, name: &str) -> &'a Value {
    let entry = report["docker"]
        .as_array()
        .expect("docker list")
        .iter()
        .find(|c| c["kind"] == "volume" && c["name"] == name)
        .unwrap_or_else(|| panic!("no entry for volume {name}"));
    assert!(
        entry["before"]
            .as_u64()
            .zip(entry["after"].as_u64())
            .is_some_and(|(before, after)| after > before),
        "expected measured growth for volume {name}: {entry}"
    );
    entry
}

#[test]
#[ignore = "needs Docker; run by hand with DWHY_DOCKER_E2E=1"]
fn wal_demo_is_flagged_and_explained() {
    if std::env::var_os("DWHY_DOCKER_E2E").is_none_or(|v| v != "1") {
        eprintln!("skipped: set DWHY_DOCKER_E2E=1 to run the WAL demo against Docker");
        return;
    }
    if let Err(e) = check_docker_host(std::env::var_os("DOCKER_HOST").as_deref()) {
        panic!("{e}");
    }
    let socket = dwhy_core::doctor::docker_socket();
    assert!(
        socket.accessible,
        "cannot use Docker socket {}",
        socket.path
    );
    let docker = Docker::new(format!("unix://{}", socket.path));
    let docker_host = docker.host.as_str();
    let started = Instant::now();
    let state = tempfile::tempdir().unwrap();
    let walk = tempfile::tempdir().unwrap();
    let walk = walk.path().to_str().unwrap();

    let name = project_name();
    with_project(&docker, &name, |project| {
        demo(project, docker_host, state.path(), walk)
    });
    eprintln!("done in {:?}", started.elapsed());
}

/// The demo itself, against a project that is up.
fn demo(project: &Project<'_>, docker_host: &str, state: &Path, walk: &str) {
    let name = &project.name;
    let volume = project.volume();
    eprintln!("project {name}, volume {volume}");
    project.wait_healthy();

    // First snapshot. docker-build-cache reads /system/df, so the snapshot
    // records every volume; no docker-volume finding means no probe.
    let scan = dwhy(
        docker_host,
        state,
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

    let watch = dwhy(
        docker_host,
        state,
        &["watch", walk, "--for", "30s", "--json"],
    );
    assert_eq!(watch["docker_compared"], true, "notes: {}", watch["notes"]);
    let rate = volume_entry(&watch, &volume);
    let per_min = rate["bytes_per_minute"].as_i64().unwrap();
    eprintln!("watch: {rate}");
    assert!(per_min > 20 * MIB, "volume grows only {per_min} B/min");

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

    let diff = dwhy(
        docker_host,
        state,
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
    let explain = dwhy(docker_host, state, &["explain", &path, "--json"]);
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
    let s3test = stdout(&run(project.compose().args([
        "ps",
        "-a",
        "--format",
        "{{.Name}}",
        "s3test",
    ])));
    assert!(!s3test.is_empty(), "no s3test container in project {name}");
    assert_eq!(dead["container"], s3test.as_str());
    let advice = f["action"]["text"].as_str().unwrap();
    assert!(
        advice.starts_with("restore the archive target s3test"),
        "{advice}"
    );
}

// Fast checks of the harness itself: no Docker, no environment changes.

#[test]
fn docker_host_check_accepts_only_absolute_unix_sockets() {
    use std::os::unix::ffi::OsStrExt;

    assert_eq!(check_docker_host(None), Ok(()));
    assert_eq!(
        check_docker_host(Some(OsStr::new("unix:///var/run/docker.sock"))),
        Ok(())
    );
    for bad in [
        OsStr::new("tcp://127.0.0.1:2375"),
        OsStr::new("ssh://user@host"),
        OsStr::new("unix://relative.sock"),
        OsStr::new(""),
        OsStr::from_bytes(b"unix:///run/\xffdocker.sock"),
    ] {
        let err = check_docker_host(Some(bad)).expect_err("must be rejected");
        assert!(err.contains("unsupported DOCKER_HOST"), "{bad:?}: {err}");
        assert!(err.contains("absolute Unix socket URL"), "{bad:?}: {err}");
    }
}

/// A stand-in `docker` CLI that logs each call's arguments. It fails
/// `compose ... up` when `fail-up` exists in its directory, fails the
/// leftover listings when `fail-ls` exists, and lists one object per kind
/// when `leftover` exists.
struct FakeDocker {
    dir: tempfile::TempDir,
    docker: Docker,
}

const FAKE_DOCKER: &str = r#"dir=$(dirname "$0")
printf '%s\n' "$*" >> "$dir/log"
case "$*" in
  compose*" up -d --pull never")
    if [ -e "$dir/fail-up" ]; then echo "fake up failed" >&2; exit 1; fi ;;
  "ps -a -q --filter "*|"volume ls -q --filter "*|"network ls -q --filter "*)
    if [ -e "$dir/fail-ls" ]; then echo "fake daemon gone" >&2; exit 1; fi
    if [ -e "$dir/leftover" ]; then echo "left-$1"; fi ;;
esac
exit 0
"#;

impl FakeDocker {
    fn new(flags: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("docker");
        std::fs::write(&script, FAKE_DOCKER).unwrap();
        for flag in flags {
            File::create(dir.path().join(flag)).unwrap();
        }
        // Run through sh: the script need not be executable, and no fork in
        // a parallel test can catch it open for writing (ETXTBSY).
        let docker = Docker {
            program: "/bin/sh".into(),
            leading_args: vec![script.into()],
            host: "unix:///fake/docker.sock".into(),
        };
        Self { dir, docker }
    }

    fn log(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The calls a full run makes: `up` if `with_up`, then teardown and the
    /// three leftover listings.
    fn expect_calls(&self, name: &str, with_up: bool) {
        let compose = format!("compose -p {name} -f {COMPOSE}");
        let label = format!("--filter label=com.docker.compose.project={name}");
        let mut want = Vec::new();
        if with_up {
            want.push(format!("{compose} up -d --pull never"));
        }
        want.extend([
            format!("{compose} down -v --remove-orphans"),
            format!("ps -a -q {label}"),
            format!("volume ls -q {label}"),
            format!("network ls -q {label}"),
        ]);
        assert_eq!(self.log(), want);
    }
}

/// Runs `with_project` against `fake` and returns its panic message, if any.
fn run_with_project(fake: &FakeDocker, body: impl FnOnce(&Project<'_>)) -> Option<String> {
    panic::catch_unwind(AssertUnwindSafe(|| {
        with_project(&fake.docker, "dwhye2etest", body)
    }))
    .err()
    .map(|payload| panic_summary(&*payload).to_string())
}

#[test]
fn finished_body_tears_down_and_passes_with_nothing_left() {
    let fake = FakeDocker::new(&[]);
    let mut ran = false;
    let failure = run_with_project(&fake, |project| {
        assert_eq!(project.name, "dwhye2etest");
        ran = true;
    });
    assert_eq!(failure, None);
    assert!(ran);
    fake.expect_calls("dwhye2etest", true);
}

#[test]
fn finished_body_fails_when_objects_are_left() {
    let fake = FakeDocker::new(&["leftover"]);
    let failure = run_with_project(&fake, |_| {}).expect("leftovers must fail the test");
    assert!(failure.contains("left behind"), "{failure}");
    for object in [
        "ps -a -q left-ps",
        "volume ls -q left-volume",
        "network ls -q left-network",
    ] {
        assert!(failure.contains(object), "{failure}");
    }
    fake.expect_calls("dwhye2etest", true);
}

#[test]
fn finished_body_fails_when_the_leftover_check_fails() {
    let fake = FakeDocker::new(&["fail-ls"]);
    let failure = run_with_project(&fake, |_| {}).expect("a failed check must fail the test");
    assert!(failure.contains("leftover check failed"), "{failure}");
    assert!(failure.contains("fake daemon gone"), "{failure}");
}

#[test]
fn panic_in_body_propagates_unchanged_when_nothing_is_left() {
    let fake = FakeDocker::new(&[]);
    let payload = panic::catch_unwind(AssertUnwindSafe(|| {
        with_project(&fake.docker, "dwhye2etest", |_| {
            panic::panic_any(42_u32);
        })
    }))
    .expect_err("the body's panic must propagate");
    // resume_unwind keeps the original payload, not a re-formatted message.
    assert_eq!(payload.downcast_ref::<u32>(), Some(&42));
    fake.expect_calls("dwhye2etest", true);
}

#[test]
fn panic_in_body_with_objects_left_reports_both() {
    let fake = FakeDocker::new(&["leftover"]);
    let failure =
        run_with_project(&fake, |_| panic!("volume did not grow")).expect("the test must fail");
    assert!(failure.contains("volume did not grow"), "{failure}");
    assert!(failure.contains("left behind"), "{failure}");
    for object in [
        "ps -a -q left-ps",
        "volume ls -q left-volume",
        "network ls -q left-network",
    ] {
        assert!(failure.contains(object), "{failure}");
    }
    fake.expect_calls("dwhye2etest", true);
}

#[test]
fn panic_in_body_with_failed_leftover_check_reports_both() {
    let fake = FakeDocker::new(&["fail-ls"]);
    let failure =
        run_with_project(&fake, |_| panic!("volume did not grow")).expect("the test must fail");
    assert!(failure.contains("volume did not grow"), "{failure}");
    assert!(failure.contains("leftover check failed"), "{failure}");
    assert!(failure.contains("fake daemon gone"), "{failure}");
}

#[test]
fn panic_in_up_still_tears_down_and_checks_leftovers() {
    let fake = FakeDocker::new(&["fail-up"]);
    let mut ran = false;
    let failure = run_with_project(&fake, |_| ran = true).expect("a failed up must fail");
    assert!(!ran, "the body must not run after a failed up");
    assert!(failure.contains("fake up failed"), "{failure}");
    fake.expect_calls("dwhye2etest", true);

    let fake = FakeDocker::new(&["fail-up", "leftover"]);
    let failure = run_with_project(&fake, |_| {}).expect("a failed up must fail");
    assert!(failure.contains("fake up failed"), "{failure}");
    assert!(failure.contains("left behind"), "{failure}");
    assert!(failure.contains("volume ls -q left-volume"), "{failure}");
    fake.expect_calls("dwhye2etest", true);
}

#[test]
fn dropping_a_project_directly_tears_it_down() {
    let fake = FakeDocker::new(&[]);
    let project = Project::up(&fake.docker, "dwhye2etest");
    drop(project);
    let compose = format!("compose -p dwhye2etest -f {COMPOSE}");
    assert_eq!(
        fake.log(),
        [
            format!("{compose} up -d --pull never"),
            format!("{compose} down -v --remove-orphans"),
        ]
    );

    // A teardown that cannot even start is reported, not a panic.
    let missing = Docker {
        program: fake.dir.path().join("no-such-docker").into(),
        leading_args: Vec::new(),
        host: "unix:///fake/docker.sock".into(),
    };
    drop(Project {
        name: "dwhye2etest".into(),
        docker: &missing,
    });
}
