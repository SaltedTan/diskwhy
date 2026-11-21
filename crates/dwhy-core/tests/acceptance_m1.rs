//! M1 acceptance (docs/ACCEPTANCE-M1.md): the items the 2026-11-13 cleanup
//! on pc-ubuntu removed, rebuilt in one temp home, must all be found by the
//! M1 detectors running together. Needs `git` on PATH. Docker comes from
//! the fixed snapshot in tests/data; no daemon is contacted.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{DetectContext, Detector, run_with};
use dwhy_core::detectors::{
    CargoTarget, DockerBuildCache, DockerContainer, DockerImage, DockerVolume, GitWorktree,
    NodeModules, StaleTree, ToolVersions, Trash, UserCache, Venv,
};
use dwhy_core::docker::{self, Info, Snapshot, Source};
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{DockerSocket, Finding, Tier, ToolStatus};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

const MB: usize = 1 << 20;

const CARGO_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
# This file is a cache directory tag created by cargo.\n";

fn scan_tree(root: &Path) -> ScanTree {
    let roots = scan::prepare_roots(&[root.to_path_buf()], true).unwrap();
    let opts = ScanOptions {
        min_dir_bytes: 0,
        threads: 4,
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

fn snapshot() -> Snapshot {
    let df = docker::parse_system_df(include_bytes!("data/docker-system-df.json")).unwrap();
    let info: Info = serde_json::from_str(
        r#"{"Driver":"overlayfs","DriverStatus":[["driver-type","io.containerd.snapshotter.v1"]],"DockerRootDir":"/var/lib/docker"}"#,
    )
    .unwrap();
    Snapshot { df, info }
}

fn ctx(home: &Path) -> DetectContext {
    let tool = |name: &str| ToolStatus {
        name: name.into(),
        path: Some(format!("/usr/bin/{name}")),
        off_path: None,
        enables: vec![],
    };
    DetectContext {
        uid: 1000,
        root: false,
        home: Some(home.to_path_buf()),
        now: now(),
        tools: vec![tool("git"), tool("docker")],
        docker_socket: DockerSocket {
            path: "/var/run/docker.sock".into(),
            exists: true,
            accessible: true,
        },
        docker: Source::fixed(snapshot()),
        cancel: Default::default(),
    }
}

fn file(path: &Path, size: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![7u8; size]).unwrap();
}

fn text(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

/// Sets the mtime of `dir` and everything in it to `days` days ago.
fn age_tree(dir: &Path, days: u64) {
    let t = SystemTime::now() - Duration::from_secs(days * 86_400);
    fn walk(p: &Path, t: SystemTime) {
        let meta = fs::symlink_metadata(p).unwrap();
        if meta.is_dir() {
            for e in fs::read_dir(p).unwrap() {
                walk(&e.unwrap().path(), t);
            }
        }
        if !meta.file_type().is_symlink() {
            fs::File::open(p).unwrap().set_modified(t).unwrap();
        }
    }
    walk(dir, t);
}

/// Runs git in `dir` with no user or system config.
fn git(dir: &Path, args: &[&str]) {
    let st = Command::new("git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?}");
}

/// `YYYY-MM-DDThh:mm:ss` for `days` days ago, in UTC.
fn trash_date(days: u64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(now() - (days * 86_400) as i64).unwrap();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// One expected finding: the row of docs/ACCEPTANCE-M1.md, the detector,
/// the path, and the tier.
struct Want {
    row: u32,
    detector: &'static str,
    path: PathBuf,
    tier: Tier,
}

/// Rebuilds the M1-covered items of the 2026-11-13 cleanup under `h`.
fn rebuild_cleanup(h: &Path) -> Vec<Want> {
    let mut want = Vec::new();
    let mut add = |row, detector, path: PathBuf, tier| {
        want.push(Want {
            row,
            detector,
            path,
            tier,
        })
    };

    // Row 2: Go build, npm, uv and pip caches, last written days ago.
    for (rel, file_rel) in [
        (".cache/go-build", "00/abc-d"),
        (".npm/_cacache", "content-v2/sha512/aa"),
        (".cache/uv", "archive-v0/x/lib.so"),
        (".cache/pip", "http-v2/a/b"),
    ] {
        file(&h.join(rel).join(file_rel), 2 * MB);
        age_tree(&h.join(rel), 3);
        add(2, "user-cache", h.join(rel), Tier::Regenerable);
    }

    // Row 4: Rust target/ of lspcheck and one of its worktrees.
    for p in ["projects/lspcheck", ".t3/worktrees/lspcheck/t3-b324d8d2"] {
        let dir = h.join(p);
        file(&dir.join("Cargo.toml"), 40);
        file(&dir.join("target/debug/deps/liblsp.rlib"), 3 * MB);
        text(&dir.join("target/CACHEDIR.TAG"), CARGO_TAG);
        add(4, "cargo-target", dir.join("target"), Tier::Rebuildable);
    }

    // Row 5: old Claude Code, Codex and T3 runtime versions.
    let claude = h.join(".local/share/claude/versions");
    for v in ["2.1.318", "2.1.319", "2.1.322"] {
        file(&claude.join(v), 2 * MB);
    }
    fs::create_dir_all(h.join(".local/bin")).unwrap();
    symlink(claude.join("2.1.322"), h.join(".local/bin/claude")).unwrap();
    for v in ["2.1.318", "2.1.319"] {
        add(5, "tool-versions", claude.join(v), Tier::Rebuildable);
    }
    let sa = h.join(".codex/packages/standalone");
    let rel = |v: &str| {
        sa.join("releases")
            .join(format!("{v}-x86_64-unknown-linux-musl"))
    };
    for v in ["0.167.2", "0.169.0"] {
        file(&rel(v).join("codex"), 2 * MB);
    }
    symlink(rel("0.169.0"), sa.join("current")).unwrap();
    add(5, "tool-versions", rel("0.167.2"), Tier::Rebuildable);
    let t3 = h.join(".t3/runtime/versions");
    for v in ["0.1.3-nightly.20261025.3682", "0.1.4-nightly.20261112.4100"] {
        file(&t3.join(v).join("t3"), 2 * MB);
    }
    add(
        5,
        "tool-versions",
        t3.join("0.1.3-nightly.20261025.3682"),
        Tier::Rebuildable,
    );

    // Row 6: the desktop trash, last used a month ago.
    let trash = h.join(".local/share/Trash");
    file(&trash.join("files/old.iso"), 2 * MB);
    text(
        &trash.join("info/old.iso.trashinfo"),
        &format!(
            "[Trash Info]\nPath=/home/u/old.iso\nDeletionDate={}\n",
            trash_date(30)
        ),
    );
    add(6, "trash", trash, Tier::Review);

    // Row 8: scratch-virgil dirs untouched for 8 days, next to new work.
    let sv = h.join(".t3/scratch-virgil");
    for d in ["memclear-upstream", "jvm-464"] {
        file(&sv.join(d).join("build.bin"), 3 * MB);
        age_tree(&sv.join(d), 8);
        add(8, "stale-tree", sv.join(d), Tier::Review);
    }
    file(&sv.join("jvm-465/build.bin"), 3 * MB);
    file(&sv.join("notes.md"), 10);

    // Row 9: a T3 worktree with nothing written for 20 days.
    let repo = h.join("code/floodroute");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    text(&repo.join("README"), "x\n");
    git(&repo, &["add", "README"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    let wt = h.join(".t3/worktrees/floodroute/t3-0a1b2c3d");
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "t3-0a1b2c3d",
            wt.to_str().unwrap(),
        ],
    );
    file(&wt.join("build/out.bin"), 2 * MB);
    age_tree(&wt, 20);
    add(9, "git-worktree", wt, Tier::Review);

    // Row 10: TTS engine venvs with a requirements file, and ep03's venv
    // in a uv project.
    let engines = h.join("code/ai-content-studio/voice/audition/engines");
    for e in ["cosyvoice", "voxcpm"] {
        let dir = engines.join(e);
        text(&dir.join("requirements.txt"), "torch\n");
        text(
            &dir.join(".venv/pyvenv.cfg"),
            "home = /usr/bin\nversion_info = 3.12.3\n",
        );
        file(
            &dir.join(".venv/lib/python3.12/site-packages/torch/lib.so"),
            3 * MB,
        );
        add(10, "venv", dir.join(".venv"), Tier::Rebuildable);
    }
    let ep03 = h.join("code/ai-content-studio/episodes/ep03-gpu-roofline");
    text(&ep03.join("pyproject.toml"), "[project]\nname = \"ep03\"\n");
    text(&ep03.join("uv.lock"), "version = 1\n");
    text(
        &ep03.join(".venv/pyvenv.cfg"),
        "home = /usr/bin\nversion_info = 3.12.3\nuv = 0.9.0\n",
    );
    file(
        &ep03.join(".venv/lib/python3.12/site-packages/x/lib.so"),
        3 * MB,
    );
    add(10, "venv", ep03.join(".venv"), Tier::Rebuildable);

    want
}

#[test]
fn m1_detectors_find_the_2026_11_13_cleanup() {
    let home = tempfile::tempdir().unwrap();
    let h = fs::canonicalize(home.path()).unwrap();
    let want = rebuild_cleanup(&h);

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(CargoTarget),
        Box::new(NodeModules),
        Box::new(Venv),
        Box::new(UserCache::with_env(Vec::<(String, String)>::new())),
        Box::new(GitWorktree),
        Box::new(StaleTree),
        Box::new(ToolVersions::with_env(Vec::<(String, String)>::new()).with_running_exes(vec![])),
        Box::new(Trash::with_env(Vec::<(String, String)>::new()).with_mount_roots(vec![])),
        Box::new(DockerImage),
        Box::new(DockerBuildCache),
        Box::new(DockerContainer),
        Box::new(DockerVolume),
    ];
    let tree = scan_tree(&h);
    let (found, runs) = run_with(&tree, &ctx(&h), &detectors, None);
    for r in runs.iter().filter(|r| r.ran) {
        assert!(r.error.is_none(), "{}: {:?}", r.name, r.error);
    }

    let find = |w: &Want| -> Option<&Finding> {
        found
            .iter()
            .find(|f| f.detector == w.detector && Path::new(&f.path) == w.path)
    };
    let mut missing = Vec::new();
    for w in &want {
        match find(w) {
            None => missing.push(format!(
                "row {}: {} did not report {}",
                w.row,
                w.detector,
                w.path.display()
            )),
            Some(f) if f.tier != w.tier => missing.push(format!(
                "row {}: {} reported {} as {:?}, expected {:?}",
                w.row,
                w.detector,
                w.path.display(),
                f.tier,
                w.tier
            )),
            Some(_) => {}
        }
    }
    // Row 7: Docker images no container uses, an exited container, and
    // build cache, from the fixed Engine API snapshot.
    for det in ["docker-image", "docker-container", "docker-build-cache"] {
        if !found.iter().any(|f| f.detector == det) {
            missing.push(format!("row 7: {det} reported nothing"));
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));

    // Kept on purpose: the work in progress next to the stale scratch dirs,
    // and the versions in use.
    for kept in [
        h.join(".t3/scratch-virgil/jvm-465"),
        h.join(".local/share/claude/versions/2.1.322"),
        h.join(".codex/packages/standalone/releases/0.169.0-x86_64-unknown-linux-musl"),
        h.join(".t3/runtime/versions/0.1.4-nightly.20261112.4100"),
    ] {
        assert!(
            !found.iter().any(|f| Path::new(&f.path) == kept),
            "{} should not be reported",
            kept.display()
        );
    }
}
