//! End-to-end tests of the `dwhy` binary on temp-dir fixtures.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn dwhy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dwhy"))
        .args(args)
        .output()
        .expect("run dwhy")
}

fn fixture() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir_all(r.join("a/deep")).unwrap();
    fs::create_dir_all(r.join("b")).unwrap();
    fs::write(r.join("a/data"), vec![1u8; 5000]).unwrap();
    fs::write(r.join("a/deep/more"), vec![2u8; 300]).unwrap();
    fs::hard_link(r.join("a/data"), r.join("b/data-link")).unwrap();
    symlink("../a/data", r.join("b/sym")).unwrap();
    t
}

/// Replaces values that depend on the machine, filesystem or clock.
fn normalize(v: &mut Value, root: &str) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                match k.as_str() {
                    "allocated"
                    | "hardlink_bytes_deduped"
                    | "known_bytes"
                    | "scanned"
                    | "size"
                    | "used"
                    | "avail"
                    | "unaccounted"
                    | "elapsed_ms"
                    | "host"
                    | "uid"
                    | "root"
                    | "generated_at"
                    | "created_at"
                    | "expires_at"
                    | "plan_created_at"
                    | "time"
                    | "pid"
                    | "freed"
                    | "dev"
                    | "inode"
                    | "newest_mtime"
                    | "size_bucket"
                    | "version"
                    | "mount"
                    | "fstype"
                    | "source"
                    | "full_coverage"
                    // Detector output that depends on the machine or the clock.
                    | "status"
                    | "detail"
                    | "id"
                    | "reason"
                    | "action"
                    | "last_modified"
                    | "bytes"
                    | "deleted_open" => {
                        *val = Value::String(format!("[{k}]"));
                    }
                    _ => normalize(val, root),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| normalize(x, root)),
        Value::String(s) if s.starts_with(root) => {
            *s = s.replacen(root, "[root]", 1);
        }
        _ => {}
    }
}

#[test]
fn scan_json_shape_on_fixture() {
    let t = fixture();
    let root = fs::canonicalize(t.path()).unwrap();
    let root_s = root.to_str().unwrap();
    let out = dwhy(&[
        "scan",
        root_s,
        "--json",
        "--min-size",
        "0",
        "--detectors",
        "cargo-target",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "diskwhy/v1");
    assert_eq!(v["findings"], Value::Array(vec![]));
    // A subtree scan never claims to account for the whole filesystem.
    assert_eq!(v["fs"][0]["unaccounted"], Value::Null);

    // Order of equally sized directories depends on the filesystem; sort by path.
    v["scan"]["dirs"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    normalize(&mut v, root_s);
    insta::assert_json_snapshot!(v);
}

const CARGO_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag created by cargo.\n";

#[test]
fn scan_json_findings_on_fixture() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir_all(r.join("app/target/debug")).unwrap();
    fs::write(r.join("app/Cargo.toml"), "[package]\nname = \"app\"\n").unwrap();
    fs::write(r.join("app/target/CACHEDIR.TAG"), CARGO_TAG).unwrap();
    fs::write(r.join("app/target/debug/app"), vec![1u8; 3 << 20]).unwrap();
    let root = fs::canonicalize(r).unwrap();
    let root_s = root.to_str().unwrap();

    let out = dwhy(&[
        "scan",
        root_s,
        "--json",
        "-q",
        "--detectors",
        "cargo-target",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0]["bytes"].as_u64().unwrap() >= 3 << 20);
    let mut v = serde_json::json!({
        "findings": v["findings"].take(),
        "detectors": v["detectors"].take(),
    });
    normalize(&mut v, root_s);
    insta::assert_json_snapshot!(v);

    let text = dwhy(&["scan", root_s, "-q", "--detectors", "cargo-target"]);
    let s = String::from_utf8(text.stdout).unwrap();
    assert!(s.contains("findings: 1 ("), "{s}");
    assert!(s.contains("rebuildable"), "{s}");
    assert!(
        s.contains(&format!("cargo-target  {root_s}/app/target")),
        "{s}"
    );

    let quiet = dwhy(&["scan", root_s, "--json", "-q", "--no-detectors"]);
    let v: Value = serde_json::from_slice(&quiet.stdout).unwrap();
    assert_eq!(v["findings"], Value::Array(vec![]));
    assert_eq!(v["detectors"], Value::Array(vec![]));
}

#[test]
fn scan_text_output() {
    let t = fixture();
    let out = dwhy(&[
        "scan",
        t.path().to_str().unwrap(),
        "--min-size",
        "0",
        "-q",
        "--no-detectors",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("largest directories"), "{s}");
    assert!(s.contains("hardlinks   1 extra links counted once"), "{s}");
    assert!(s.contains("├─ ") || s.contains("└─ "), "{s}");
}

#[test]
fn exit_codes() {
    // Missing path: error.
    let out = dwhy(&["scan", "/definitely/not/here", "--no-detectors"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("error"));
    // Usage errors are 1, not clap's default 2 (2 means "skipped by a guard").
    assert_eq!(dwhy(&["scan", "--no-such-flag"]).status.code(), Some(1));
    assert_eq!(dwhy(&["frobnicate"]).status.code(), Some(1));
    assert_eq!(
        dwhy(&["scan", "-x", "--cross-filesystems", "."])
            .status
            .code(),
        Some(1)
    );
    // Unknown detector names are errors, not silently empty runs.
    let out = dwhy(&["scan", ".", "--detectors", "cargo-target,nope"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown detector \"nope\""));
    // Help and version are not errors.
    assert_eq!(dwhy(&["--help"]).status.code(), Some(0));
    assert_eq!(dwhy(&["--version"]).status.code(), Some(0));
}

#[test]
fn tui_needs_a_terminal() {
    // Bare `dwhy` and `dwhy tui` open the TUI; here stdin and stdout are not
    // terminals, so both refuse and point to `dwhy scan`.
    for args in [&[][..], &["tui", "."][..]] {
        let out = dwhy(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("needs a terminal") && err.contains("dwhy scan"),
            "{err}"
        );
        assert!(out.stdout.is_empty(), "no escape codes on a pipe");
    }
    // Paths go after `dwhy tui`, not bare `dwhy`.
    let out = dwhy(&["."]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unexpected argument '.'") || err.contains("unrecognized subcommand '.'"),
        "{err}"
    );
    let out = dwhy(&["tui", "-x", "--cross-filesystems"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot be used with")
            && err.contains("--cross-filesystems")
            && (err.contains("--one-file-system") || err.contains("'-x'")),
        "{err}"
    );
}

#[test]
fn tui_plan_conflicts_and_bad_files() {
    let (_t, root) = cargo_fixture();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("p.json");
    let out = dwhy(&[
        "plan",
        &root,
        "-q",
        "--detectors",
        "cargo-target",
        "--tier",
        "rebuildable",
        "-o",
        file.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let f = file.to_str().unwrap();
    // The plan names its own roots and -x.
    for args in [
        &["tui", "--plan", f, "."][..],
        &["tui", "--plan", f, "-x"][..],
        &["tui", "--plan", f, "--cross-filesystems"][..],
    ] {
        let out = dwhy(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("cannot be used with"), "{err}");
    }
    // A good plan gets as far as needing a terminal.
    let out = dwhy(&["tui", "--plan", f]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("needs a terminal"));

    // A bad or missing file fails before the terminal check, as apply does,
    // with control characters escaped.
    let bad = dir.path().join("bad\nname.json");
    fs::write(&bad, "{\"schema\": \"diskwhy/v1\"}").unwrap();
    let missing = dir.path().join("gone\nplan.json");
    for (path, want) in [(&bad, "not a diskwhy plan"), (&missing, "cannot read")] {
        let out = dwhy(&["tui", "--plan", path.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(want), "{err}");
        assert!(!err.contains("needs a terminal"), "{err}");
        assert_eq!(err.lines().count(), 1, "{err}");
    }
    assert!(
        String::from_utf8_lossy(&dwhy(&["tui", "--plan", missing.to_str().unwrap()]).stderr)
            .contains("gone\\nplan.json")
    );
}

/// The TUI's plan (marks → `plan::build` → `w`) is the plan `dwhy plan
/// --select` makes from the same findings, and a CLI plan opens in the TUI.
#[test]
fn tui_and_cli_plans_round_trip() {
    use dwhy_core::guard::Processes;
    use dwhy_core::plan;
    use dwhy_tui::job::{self, PlanJob};

    let (_t, root) = cargo_fixture();
    fs::create_dir_all(format!("{root}/lib/target/debug")).unwrap();
    fs::write(
        format!("{root}/lib/Cargo.toml"),
        "[package]\nname = \"lib\"\n",
    )
    .unwrap();
    fs::write(format!("{root}/lib/target/CACHEDIR.TAG"), CARGO_TAG).unwrap();
    fs::write(format!("{root}/lib/target/debug/lib"), vec![2u8; 1 << 20]).unwrap();
    let opts = dwhy_tui::Options {
        paths: vec![root.clone().into()],
        detectors: Some(vec!["cargo-target".into()]),
        threads: 2,
        ..Default::default()
    };
    let scanned = job::scan(&opts, &dwhy_core::scan::Progress::default(), &mut |_| {}).unwrap();
    let ids: Vec<String> = scanned
        .report
        .findings
        .iter()
        .map(|f| f.id.clone())
        .collect();
    assert_eq!(ids.len(), 2);
    let built = PlanJob {
        options: scanned.plan_options,
        progress: Default::default(),
        marks: scanned.report.findings.iter().map(Into::into).collect(),
    }
    .build(Processes::read, dwhy_core::system::hostname())
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let tui_file = dir.path().join("tui.json");
    job::write_plan(&tui_file, &built.plan).unwrap();
    let tui_text = fs::read_to_string(&tui_file).unwrap();
    let tui_plan = plan::parse(&tui_text).unwrap();
    let mut expected = serde_json::to_string_pretty(&tui_plan).unwrap();
    expected.push('\n');
    assert_eq!(
        tui_text, expected,
        "TUI plan files use pretty JSON with a final newline"
    );
    let env = dwhy_core::apply::Env::from_system();
    let now = job::now();
    plan::usable(&tui_plan, &env.host, env.uid, now).unwrap();

    let cli_file = dir.path().join("cli.json");
    let out = dwhy(&[
        "plan",
        &root,
        "-q",
        "--json",
        "--detectors",
        "cargo-target",
        "--select",
        &ids.join(","),
        "-o",
        cli_file.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let cli_text = fs::read_to_string(&cli_file).unwrap();
    assert_eq!(cli_text.as_bytes(), out.stdout.as_slice());
    let cli_plan = plan::parse(&cli_text).unwrap();

    let summary = |p: &dwhy_core::report::Plan| {
        let items: Vec<_> = p
            .items
            .iter()
            .map(|i| {
                let f = &i.finding;
                (
                    f.id.clone(),
                    f.bytes,
                    f.tier,
                    f.action.clone(),
                    f.guards.clone(),
                )
            })
            .collect();
        let blocked: Vec<_> = p.blocked.iter().map(|f| f.id.clone()).collect();
        (
            items,
            blocked,
            p.bytes,
            p.scan.clone(),
            p.selection.clone(),
            p.host.clone(),
            p.uid,
        )
    };
    assert_eq!(summary(&tui_plan), summary(&cli_plan));
    assert_eq!(tui_plan.items.len(), 2);
    let fp = |p: &dwhy_core::report::Plan| -> Vec<_> {
        p.items.iter().map(|i| i.fingerprint.clone()).collect()
    };
    assert_eq!(fp(&tui_plan), fp(&cli_plan));

    // `dwhy apply --dry-run` accepts the TUI's file.
    let out = dwhy(&[
        "apply",
        tui_file.to_str().unwrap(),
        "--dry-run",
        "-q",
        "--max-tier",
        "rebuildable",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        fs::metadata(format!("{root}/app/target")).is_ok(),
        "dry run removes nothing"
    );

    // The CLI's file opens in the TUI's preview, usable here.
    let app = dwhy_tui::App::open_plan(cli_plan, cli_file, &env.host, env.uid);
    let view = app.plan_view().unwrap();
    assert_eq!(view.unusable(job::now()), None);
    assert_eq!(view.plan().items.len(), 2);
}

#[test]
fn doctor_json() {
    let out = dwhy(&["doctor", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "diskwhy/v1");
    let tools: Vec<&str> = v["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        tools,
        [
            "git",
            "docker",
            "cargo",
            "go",
            "uv",
            "pip",
            "npm",
            "pnpm",
            "yarn",
            "rustup",
            "pyenv",
            "fnm",
            "journalctl"
        ]
    );
    assert!(v["detectors"].as_array().unwrap().len() >= 12);
    let text = dwhy(&["doctor"]);
    assert_eq!(text.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&text.stdout).contains("detectors"));
}

#[test]
fn scan_is_read_only() {
    let t = fixture();
    let before = listing(t.path());
    assert_eq!(
        dwhy(&["scan", t.path().to_str().unwrap(), "-q", "--no-detectors"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(listing(t.path()), before);
}

#[test]
fn scan_snapshot_writes_only_under_the_state_dir() {
    let t = fixture();
    let root = fs::canonicalize(t.path()).unwrap();
    let root_s = root.to_str().unwrap();
    let state = tempfile::tempdir().unwrap();
    let before = listing(&root);
    let run = |state: &Path, extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_dwhy"))
            .args(["scan", root_s, "-q", "--detectors", "cargo-target"])
            .args(extra)
            .env("XDG_STATE_HOME", state)
            .output()
            .expect("run dwhy")
    };

    // Without --snapshot nothing is written.
    let out = run(state.path(), &["--json"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(json_of(&out).get("snapshot").is_none());
    assert!(!state.path().join("diskwhy").exists());

    let out = run(state.path(), &["--json", "--snapshot"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    let dir = state.path().join("diskwhy/snapshots");
    let id = v["snapshot"]["id"].as_str().unwrap();
    let path = Path::new(v["snapshot"]["path"].as_str().unwrap());
    assert_eq!(path, dir.join(format!("{id}.json.gz")));
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    let snap = dwhy_core::snapshot::load(path).unwrap();
    assert_eq!(snap.scan.roots, vec![root_s.to_string()]);
    assert_eq!(snap.scan.detectors, vec!["cargo-target".to_string()]);
    assert_eq!(snap.created_at, v["generated_at"].as_str().unwrap());
    assert_eq!(listing(&root), before);

    let out = run(state.path(), &["--snapshot"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("snapshot saved: "));

    // When it cannot be saved, the report is still printed and dwhy exits 1.
    let file = state.path().join("not-a-dir");
    fs::write(&file, b"").unwrap();
    let out = run(&file, &["--json", "--snapshot"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(json_of(&out).get("snapshot").is_none());
    assert!(String::from_utf8_lossy(&out.stderr).contains("snapshot not saved"));
}

#[test]
fn scan_snapshot_refuses_a_relative_home() {
    let t = fixture();
    let root = fs::canonicalize(t.path()).unwrap();
    for home in ["", "relative/home"] {
        let out = Command::new(env!("CARGO_BIN_EXE_dwhy"))
            .args(["scan", ".", "-q", "--json", "--snapshot", "--no-detectors"])
            .current_dir(&root)
            .env("HOME", home)
            .env_remove("XDG_STATE_HOME")
            .output()
            .expect("run dwhy");
        assert_eq!(out.status.code(), Some(1), "HOME={home:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(
                "cannot place snapshots: neither XDG_STATE_HOME nor HOME is an absolute path"
            ),
            "HOME={home:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!root.join(".local").exists());
        assert!(!root.join("relative").exists());
    }
}

/// (path, size, mtime) of everything under `p`.
fn listing(p: &Path) -> Vec<(String, u64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let md = fs::symlink_metadata(&d).unwrap();
        out.push((d.display().to_string(), md.size(), md.mtime()));
        if md.is_dir() {
            for e in fs::read_dir(&d).unwrap() {
                stack.push(e.unwrap().path());
            }
        }
    }
    out.sort();
    out
}

/// A crate with a 3 MiB `target/` (a `rebuildable` cargo-target finding).
fn cargo_fixture() -> (tempfile::TempDir, String) {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir_all(r.join("app/target/debug")).unwrap();
    fs::write(r.join("app/Cargo.toml"), "[package]\nname = \"app\"\n").unwrap();
    fs::write(r.join("app/target/CACHEDIR.TAG"), CARGO_TAG).unwrap();
    fs::write(r.join("app/target/debug/app"), vec![1u8; 3 << 20]).unwrap();
    let root = fs::canonicalize(r).unwrap().to_str().unwrap().to_string();
    (t, root)
}

/// Runs dwhy with its state (snapshots) in `state`.
fn dwhy_in(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dwhy"))
        .args(args)
        .env("XDG_STATE_HOME", state)
        .output()
        .expect("run dwhy")
}

#[test]
fn diff_reports_growth_since_a_snapshot() {
    let (_t, root) = cargo_fixture();
    let target = format!("{root}/app/target");
    let state = tempfile::tempdir().unwrap();
    let st = state.path();
    let det = ["-q", "--detectors", "cargo-target"];

    // No snapshot yet.
    let out = dwhy_in(st, &[&["diff", &root][..], &det].concat());
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no snapshot of") && err.contains("dwhy scan --snapshot"),
        "{err}"
    );

    let out = dwhy_in(
        st,
        &[&["scan", &root, "--json", "--snapshot"][..], &det].concat(),
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let id = json_of(&out)["snapshot"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    fs::write(format!("{target}/debug/more"), vec![3u8; 1 << 20]).unwrap();
    let before = listing(Path::new(&root));

    // Without PATH: the newest snapshot's roots are rescanned.
    let out = dwhy_in(
        st,
        &[&["diff", "--json", "--min-change", "0"][..], &det].concat(),
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["schema"], "diskwhy/v1");
    assert_eq!(v["since"]["id"], id.as_str());
    assert_eq!(v["roots"], serde_json::json!([root]));
    assert_eq!(v["docker_compared"], false);
    let f = &v["findings"][0];
    assert_eq!(f["kind"], "finding");
    assert_eq!(f["name"], target.as_str());
    assert_eq!(f["detector"], "cargo-target");
    assert!(f["change"].as_i64().unwrap() >= 1 << 20, "{f}");
    assert!(f["bytes_per_day"].as_i64().unwrap() > 0, "{f}");
    assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    assert!(v.get("snapshot").is_none());

    // The default --min-change (10M) hides a 1M change.
    let out = dwhy_in(st, &[&["diff", "--json"][..], &det].concat());
    assert_eq!(json_of(&out)["findings"], serde_json::json!([]));

    // By id, as text, saving the fresh scan too.
    let out = dwhy_in(
        st,
        &[
            &[
                "diff",
                &root,
                "--since",
                &id,
                "--min-change",
                "0",
                "--snapshot",
            ][..],
            &det,
        ]
        .concat(),
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("dwhy diff · "), "{text}");
    assert!(text.contains(&format!("since {id}")), "{text}");
    assert!(text.contains(&format!("cargo-target {target}")), "{text}");
    assert!(text.contains("docker: not compared"), "{text}");
    assert!(text.contains("snapshot saved: "), "{text}");
    let saved = fs::read_dir(st.join("diskwhy/snapshots")).unwrap().count();
    assert_eq!(saved, 2);

    // diff reads the tree and writes only its own state.
    assert_eq!(listing(Path::new(&root)), before);

    let out = dwhy_in(st, &["diff", "--since", "yesterday", "-q"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--since \"yesterday\""));
}

#[test]
fn scan_shows_growth_from_a_snapshot_an_hour_old() {
    let (_t, root) = cargo_fixture();
    let target = format!("{root}/app/target");
    let state = tempfile::tempdir().unwrap();
    let st = state.path();
    let scan = |extra: &[&str]| {
        dwhy_in(
            st,
            &[
                &["scan", &root, "-q", "--detectors", "cargo-target"][..],
                extra,
            ]
            .concat(),
        )
    };
    let out = scan(&["--json", "--snapshot"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    let path = v["snapshot"]["path"].as_str().unwrap().to_string();
    assert_eq!(v["findings"][0]["growth"], Value::Null);

    // A snapshot seconds old gives no rate.
    let v = json_of(&scan(&["--json"]));
    assert_eq!(v["findings"][0]["growth"], Value::Null);

    // Make it two hours old, from when the finding was 1 MiB smaller.
    let mut snap = dwhy_core::snapshot::load(Path::new(&path)).unwrap();
    let then = dwhy_core::snapshot::parse_time(&snap.created_at).unwrap() - 7200;
    snap.created_at = time::OffsetDateTime::from_unix_timestamp(then)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let f = snap.findings.iter_mut().find(|f| f.path == target).unwrap();
    f.bytes -= 1 << 20;
    fs::remove_file(&path).unwrap();
    dwhy_core::snapshot::save(Path::new(&path).parent().unwrap(), &snap, then + 7200).unwrap();

    let v = json_of(&scan(&["--json"]));
    let g = &v["findings"][0]["growth"];
    assert_eq!(g["since"], snap.created_at.as_str());
    // 1 MiB in two hours, give or take the seconds between the scans.
    let rate = g["bytes_per_day"].as_i64().unwrap();
    assert!((11 << 20..=12 << 20).contains(&rate), "{rate}");

    let out = scan(&[]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("M/day)"), "{text}");
}

#[test]
fn plan_json_on_fixture() {
    let (_t, root) = cargo_fixture();
    let out_dir = tempfile::tempdir().unwrap();
    let file = out_dir.path().join("plan.json");
    let before = listing(Path::new(&root));
    let out = dwhy(&[
        "plan",
        &root,
        "-q",
        "--detectors",
        "cargo-target",
        "--tier",
        "rebuildable",
        "-o",
        file.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(listing(Path::new(&root)), before, "plan writes nothing");
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    let written: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(printed, written);
    assert_eq!(written["items"].as_array().unwrap().len(), 1);
    let fp = &written["items"][0]["fingerprint"];
    assert!(fp["inode"].as_u64().is_some() && fp["newest_mtime"].as_i64().is_some());
    let mut v = written;
    normalize(&mut v, &root);
    insta::assert_json_snapshot!(v);
}

#[test]
fn plan_selection_on_fixture() {
    let (_t, root) = cargo_fixture();
    let target = format!("{root}/app/target");

    // Default: regenerable only, so the rebuildable target is left out.
    let out = dwhy(&["plan", &root, "-q", "--detectors", "cargo-target"]);
    assert_eq!(out.status.code(), Some(0));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        s.contains("plan: nothing to remove (tier ≤ regenerable)"),
        "{s}"
    );
    assert!(
        s.contains("1 finding above regenerable not selected"),
        "{s}"
    );
    assert!(s.contains("no plan file written"), "{s}");

    // --select by path (relative to the working directory too) or by id.
    let json = |args: &[&str]| -> Value {
        let mut a = vec!["plan", &root, "-q", "--detectors", "cargo-target", "--json"];
        a.extend(args);
        let out = Command::new(env!("CARGO_BIN_EXE_dwhy"))
            .args(&a)
            .current_dir(format!("{root}/app"))
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let by_path = json(&["--select", &target]);
    assert_eq!(by_path["items"][0]["finding"]["path"], target.as_str());
    assert_eq!(by_path["selection"]["tier"], Value::Null);
    let id = by_path["items"][0]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        json(&["--select", "target"])["items"][0]["finding"]["id"],
        id.as_str()
    );
    assert_eq!(
        json(&["--select", &id])["items"].as_array().unwrap().len(),
        1
    );

    // Text output names the item and the command to apply it.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("p.json");
    let out = dwhy(&[
        "plan",
        &root,
        "-q",
        "--detectors",
        "cargo-target",
        "--select",
        &id,
        "-o",
        file.to_str().unwrap(),
    ]);
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("plan: 1 item, "), "{s}");
    assert!(s.contains(&format!("cargo-target  {target}")), "{s}");
    assert!(s.contains(&format!("{id} → ")), "{s}");
    assert!(s.contains("dwhy apply "), "{s}");

    // Naming nothing is an error, not an empty plan.
    let out = dwhy(&[
        "plan",
        &root,
        "-q",
        "--detectors",
        "cargo-target",
        "--select",
        "f_000000000000",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--select f_000000000000"));
    // `blocked` is not a tier you can select.
    let out = dwhy(&["plan", &root, "-q", "--tier", "blocked"]);
    assert_eq!(out.status.code(), Some(1));
}

/// A child process, killed when dropped.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn plan_exits_2_only_when_a_selected_finding_is_blocked() {
    let (_t, root) = cargo_fixture();
    let target = format!("{root}/app/target");
    let Ok(child) = Command::new("sleep")
        .arg("600")
        .current_dir(format!("{target}/debug"))
        .spawn()
    else {
        eprintln!("skipping: cannot run sleep");
        return;
    };
    let _child = Child(child);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("p.json");
    let plan = |args: &[&str]| {
        let mut a = vec![
            "plan",
            &root,
            "-q",
            "--detectors",
            "cargo-target",
            "--json",
            "-o",
            file.to_str().unwrap(),
        ];
        a.extend(args);
        let out = dwhy(&a);
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        (out.status.code(), v)
    };

    // Named by --select and blocked by the sleeping process: exit 2, and the
    // plan is still written.
    let (code, v) = plan(&["--select", &target]);
    assert_eq!(code, Some(2), "{v}");
    assert!(v["items"].as_array().unwrap().is_empty());
    assert_eq!(v["blocked"][0]["path"], target.as_str());
    assert_eq!(v["blocked"][0]["tier"], "blocked");
    let written: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(written, v);

    // Reached only by the tier ceiling: still listed, but exit 0.
    fs::remove_file(&file).unwrap();
    let (code, v) = plan(&["--tier", "rebuildable"]);
    assert_eq!(code, Some(0), "{v}");
    assert_eq!(v["blocked"][0]["path"], target.as_str());
    assert!(file.exists());
}

// ---------------------------------------------------------------------------
// apply: real removal happens only inside these temp dirs.
// ---------------------------------------------------------------------------

/// A fake home with a 3 MiB pip cache (regenerable, untouched for 3 days)
/// and a 2 MiB scratch dir (review, untouched for 30 days), plus a state dir, an empty
/// PATH dir and a dir for plan files, all outside the home.
struct Home {
    _t: tempfile::TempDir,
    base: std::path::PathBuf,
}

impl Home {
    fn new() -> Home {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        for d in ["home", "state", "bin", "plans"] {
            fs::create_dir_all(base.join(d)).unwrap();
        }
        let h = Home { _t: t, base };
        let pip = h.home().join(".cache/pip/http/blob");
        let scratch = h.home().join("scratch/old/blob");
        // Different sizes, so the plan's order (largest first) is fixed.
        for (f, size) in [(&pip, 3 << 20), (&scratch, 2 << 20)] {
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, vec![7u8; size]).unwrap();
        }
        age_tree(&h.home().join(".cache"), 3 * 86_400);
        age_tree(&h.home().join("scratch"), 30 * 86_400);
        h
    }
    fn home(&self) -> std::path::PathBuf {
        self.base.join("home")
    }
    fn plan_file(&self, name: &str) -> String {
        self.base
            .join("plans")
            .join(name)
            .to_str()
            .unwrap()
            .to_string()
    }
    fn audit(&self) -> std::path::PathBuf {
        self.base.join("state/diskwhy/audit.jsonl")
    }
    /// Runs dwhy with only this home's environment and no tools on PATH.
    fn dwhy(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_dwhy"))
            .args(args)
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", self.base.join("bin"))
            .env("XDG_STATE_HOME", self.base.join("state"))
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run dwhy")
    }
    /// `dwhy plan` of the home with the two detectors the fixture feeds
    /// (never Docker or the machine's own caches).
    fn plan(&self, name: &str, extra: &[&str]) -> String {
        let file = self.plan_file(name);
        let home = self.home();
        let mut args = vec![
            "plan",
            home.to_str().unwrap(),
            "-q",
            "--detectors",
            "user-cache,stale-tree",
            "-o",
            &file,
        ];
        args.extend(extra);
        let out = self.dwhy(&args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        file
    }
}

/// Sets the mtime of everything under `p` (and `p`) to `secs` ago.
fn age_tree(p: &Path, secs: u64) {
    let t = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
    let mut all = Vec::new();
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        if d.is_dir() {
            for e in fs::read_dir(&d).unwrap() {
                stack.push(e.unwrap().path());
            }
        }
        all.push(d);
    }
    // Children before parents, so setting a file's time never touches a
    // directory already set.
    for f in all.iter().rev() {
        fs::File::open(f).unwrap().set_modified(t).unwrap();
    }
}

fn json_of(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn audit_events(h: &Home) -> Vec<(String, String, String)> {
    fs::read_to_string(h.audit())
        .unwrap_or_default()
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            (
                v["event"].as_str().unwrap().to_string(),
                v["detector"].as_str().unwrap().to_string(),
                v["outcome"].as_str().unwrap_or("-").to_string(),
            )
        })
        .collect()
}

#[test]
fn an_agent_clears_regenerable_items_alone_and_is_refused_review_items() {
    let h = Home::new();
    let pip = h.home().join(".cache/pip");
    let scratch = h.home().join("scratch");
    let plan = h.plan("all.json", &["--tier", "review"]);
    let p: Value = serde_json::from_slice(&fs::read(&plan).unwrap()).unwrap();
    assert_eq!(p["items"].as_array().unwrap().len(), 2, "{p}");

    // An agent: --yes, default --max-tier regenerable.
    let out = h.dwhy(&["apply", &plan, "--yes", "--json", "-q"]);
    assert_eq!(out.status.code(), Some(3), "the review item is refused");
    assert!(!pip.exists(), "the regenerable pip cache is removed");
    assert!(scratch.join("old/blob").exists(), "the review item is not");
    let mut r = json_of(&out);
    assert_eq!(r["dry_run"], false);
    assert!(r["freed"].as_u64().unwrap() >= 2 << 20);
    let root = h.base.to_str().unwrap().to_string();
    normalize(&mut r, &root);
    insta::assert_json_snapshot!(r);

    let mut events = audit_events(&h);
    events.sort();
    assert_eq!(
        events,
        [
            ("end".into(), "stale-tree".into(), "refused".into()),
            ("end".into(), "user-cache".into(), "removed".into()),
            ("start".into(), "user-cache".into(), "-".into()),
        ]
    );

    // A person confirms the review item by id.
    let id = p["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["finding"]["detector"] == "stale-tree")
        .unwrap()["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let plan2 = h.plan("review.json", &["--select", &id]);
    let out = h.dwhy(&["apply", &plan2, "--yes", "--confirm", &id, "-q"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(!scratch.exists());
    assert!(text.contains("removed 1 item, freed about"), "{text}");
    assert!(text.contains("audit log: "), "{text}");
    assert!(h.home().exists());
}

#[test]
fn apply_refuses_without_a_terminal_an_expired_plan_and_another_host() {
    let h = Home::new();
    let pip = h.home().join(".cache/pip/http/blob");
    let plan = h.plan("p.json", &[]);

    // No --yes and no terminal: refused, nothing removed.
    let out = h.dwhy(&["apply", &plan]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no terminal to confirm on"));
    assert!(pip.exists());

    let edit = |name: &str, f: &dyn Fn(&mut Value)| -> String {
        let mut v: Value = serde_json::from_slice(&fs::read(&plan).unwrap()).unwrap();
        f(&mut v);
        let file = h.plan_file(name);
        fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
        file
    };
    let expired = edit("expired.json", &|v| {
        v["created_at"] = "2026-01-01T00:00:00Z".into();
        v["expires_at"] = "2026-01-01T01:00:00Z".into();
    });
    let out = h.dwhy(&["apply", &expired, "--yes"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("expired"));
    // --dry-run does not get around expiry either.
    assert_eq!(
        h.dwhy(&["apply", &expired, "--dry-run"]).status.code(),
        Some(3)
    );
    let elsewhere = edit("elsewhere.json", &|v| v["host"] = "some-other-host".into());
    let out = h.dwhy(&["apply", &elsewhere, "--yes"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("some-other-host"));
    assert!(pip.exists());
    assert!(
        !h.audit().exists(),
        "refusing the whole plan writes nothing"
    );

    // Errors: an id not in the plan, a file that is not a plan.
    assert_eq!(
        h.dwhy(&["apply", &plan, "--yes", "--confirm", "f_000000000000"])
            .status
            .code(),
        Some(1)
    );
    let junk = h.plan_file("junk.json");
    fs::write(&junk, "{}").unwrap();
    assert_eq!(h.dwhy(&["apply", &junk, "--yes"]).status.code(), Some(1));
    assert_eq!(
        h.dwhy(&["apply", "/definitely/not/here.json"])
            .status
            .code(),
        Some(1)
    );
    assert!(pip.exists());
}

#[test]
fn dry_run_shows_everything_and_removes_nothing() {
    let h = Home::new();
    let plan = h.plan("p.json", &["--tier", "review"]);
    let out = h.dwhy(&["apply", &plan, "--dry-run", "--json", "-q"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "the review item would be refused"
    );
    let r = json_of(&out);
    assert_eq!(r["dry_run"], true);
    let mut outcomes: Vec<&str> = r["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["outcome"].as_str().unwrap())
        .collect();
    outcomes.sort();
    assert_eq!(outcomes, ["refused", "would_remove"]);
    assert!(h.home().join(".cache/pip/http/blob").exists());
    assert!(h.home().join("scratch/old/blob").exists());
    assert!(!h.audit().exists(), "dry runs write nothing");

    let text = h.dwhy(&["apply", &plan, "--dry-run", "-q"]);
    let s = String::from_utf8_lossy(&text.stdout);
    assert!(s.contains("would remove"), "{s}");
    assert!(s.contains("nothing removed"), "{s}");
    assert!(s.contains("--confirm"), "{s}");
}

#[test]
fn an_item_that_changed_since_the_plan_is_skipped() {
    let (_t, root) = cargo_fixture();
    let dir = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let plan = dir.path().join("p.json");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_dwhy"))
            .args(args)
            .env_clear()
            .env("HOME", dir.path())
            .env("PATH", bin.path())
            .env("XDG_STATE_HOME", state.path())
            .output()
            .unwrap()
    };
    let out = run(&[
        "plan",
        &root,
        "-q",
        "--detectors",
        "cargo-target",
        "--tier",
        "rebuildable",
        "-o",
        plan.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let new = Path::new(&root).join("app/target/debug/new");
    fs::write(&new, vec![0u8; 4096]).unwrap();
    fs::File::open(&new)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
        .unwrap();
    let out = run(&[
        "apply",
        plan.to_str().unwrap(),
        "--yes",
        "--max-tier",
        "rebuildable",
        "--json",
        "-q",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let r = json_of(&out);
    assert_eq!(r["items"][0]["outcome"], "skipped");
    assert!(
        r["items"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("changed since the plan: newest mtime"),
        "{r}"
    );
    assert!(Path::new(&root).join("app/target/debug/app").exists());
}

#[test]
fn watch_ignores_permission_changes_during_the_window() {
    use std::os::unix::fs::PermissionsExt;

    if dwhy_core::system::euid() == 0 {
        return;
    }
    struct RestorePermissions(Vec<std::path::PathBuf>);
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
            }
        }
    }

    let t = tempfile::tempdir().unwrap();
    let root = t.path().canonicalize().unwrap();
    let locked = root.join("data");
    let noexec = root.join("entries");
    fs::create_dir_all(locked.join("logs")).unwrap();
    fs::create_dir(&noexec).unwrap();
    fs::create_dir(root.join("quiet")).unwrap();
    fs::write(locked.join("logs/data"), vec![1u8; 6 << 20]).unwrap();
    fs::write(noexec.join("data"), vec![1u8; 6 << 20]).unwrap();
    let _restore = RestorePermissions(vec![locked.clone(), noexec.clone()]);
    let state = tempfile::tempdir().unwrap();

    for readable_after in [false, true] {
        let (locked_path, noexec_path, quiet) =
            (locked.clone(), noexec.clone(), root.join("quiet"));
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            fs::set_permissions(
                locked_path,
                fs::Permissions::from_mode(if readable_after { 0o755 } else { 0o000 }),
            )
            .unwrap();
            fs::set_permissions(
                noexec_path,
                fs::Permissions::from_mode(if readable_after { 0o755 } else { 0o600 }),
            )
            .unwrap();
            let name = if readable_after { "second" } else { "first" };
            fs::write(quiet.join(name), vec![2u8; 4 << 20]).unwrap();
        });
        let out = dwhy_in(
            state.path(),
            &[
                "watch",
                root.to_str().unwrap(),
                "--for",
                "4s",
                "--json",
                "-q",
                "--no-docker",
            ],
        );
        writer.join().unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let r: Value = serde_json::from_slice(&out.stdout).unwrap();
        let dirs = r["dirs"].as_array().unwrap();
        assert_eq!(dirs.len(), 1, "{r}");
        assert_eq!(dirs[0]["name"], root.join("quiet").to_str().unwrap());
        assert!(dirs[0]["change"].as_i64().unwrap() >= 4 << 20, "{r}");
        assert_eq!(
            r["notes"][0],
            format!(
                "not compared, because a sample could not read these paths: {}, {}",
                locked.display(),
                noexec.display(),
            )
        );
        assert_eq!(fs::read_dir(state.path()).unwrap().count(), 0);
    }
}

#[test]
fn watch_reports_a_dir_written_during_the_window() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().canonicalize().unwrap();
    fs::create_dir_all(root.join("app/logs")).unwrap();
    fs::create_dir_all(root.join("quiet")).unwrap();
    fs::write(root.join("quiet/data"), vec![1u8; 4 << 20]).unwrap();
    let state = tempfile::tempdir().unwrap();

    // The first walk of this small tree is over well before the write; the
    // second starts 4 s after the first did.
    let logs = root.join("app/logs");
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));
        fs::write(logs.join("run.log"), vec![7u8; 6 << 20]).unwrap();
    });
    let r = root.to_str().unwrap();
    let out = dwhy_in(
        state.path(),
        &["watch", r, "--for", "4s", "--json", "-q", "--no-docker"],
    );
    writer.join().unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "diskwhy/v1");
    assert_eq!(v["for_secs"], 4);
    let elapsed = v["elapsed_ms"].as_u64().unwrap();
    assert!((4000..10_000).contains(&elapsed), "{elapsed}");
    // Only the directory that grew, and the deepest one holding it.
    let dirs = v["dirs"].as_array().unwrap();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let d = &dirs[0];
    assert_eq!(d["kind"], "dir");
    assert_eq!(d["name"], format!("{r}/app/logs"));
    let change = d["change"].as_i64().unwrap();
    assert!(change >= 6 << 20, "{d}");
    let rate = d["bytes_per_minute"].as_i64().unwrap();
    assert_eq!(rate, (change as i128 * 60_000 / elapsed as i128) as i64);
    assert_eq!(v["docker_compared"], false);
    assert_eq!(v["notes"][0], "Docker not compared: --no-docker given");

    // Text output, over a window in which nothing changed.
    let out = dwhy_in(
        state.path(),
        &["watch", r, "--for", "1s", "-q", "--no-docker"],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("dwhy watch · "), "{text}");
    assert!(text.contains("directories (the deepest that holds most of each change): nothing changed by 1.0M or more"), "{text}");

    // watch writes nothing, not even a snapshot.
    assert_eq!(fs::read_dir(state.path()).unwrap().count(), 0);

    // --for needs at least a second.
    let out = dwhy_in(state.path(), &["watch", r, "--for", "0s"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least 1s"));
}

/// Everything under the state dir: what explain must leave alone.
fn state_listing(state: &Path) -> Vec<(String, u64, i64)> {
    if state.join("diskwhy").exists() {
        listing(state)
    } else {
        Vec::new()
    }
}

#[test]
fn explain_a_finding_by_path() {
    let (_t, root) = cargo_fixture();
    let target = format!("{root}/app/target");
    let state = tempfile::tempdir().unwrap();
    let st = state.path();
    let before = listing(Path::new(&root));
    let out = dwhy_in(
        st,
        &[
            "explain",
            &target,
            "--json",
            "-q",
            "--detectors",
            "cargo-target",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["schema"], "diskwhy/v1");
    assert_eq!(v["query"], target.as_str());
    assert_eq!(v["resolved"], serde_json::json!({"via": "path"}));
    assert_eq!(v["path"], target.as_str());
    assert_eq!(v["gone"], false);
    assert_eq!(v["inside"], serde_json::json!([]));
    assert!(v["size"]["allocated"].as_u64().unwrap() >= 3 << 20, "{v}");
    assert!(v["size"]["apparent"].as_u64().unwrap() >= 3 << 20, "{v}");
    let f = &v["finding"];
    assert_eq!(f["detector"], "cargo-target");
    assert_eq!(f["path"], target.as_str());
    assert_eq!(
        f["id"],
        dwhy_core::detect::finding_id("cargo-target", &target).as_str()
    );
    assert_eq!(f["tier"], "rebuildable");
    assert_eq!(f["growth"], Value::Null);
    assert!(f["last_modified"].is_string());
    assert!(f["recovery"]["cost"].is_string());
    let guards: Vec<&str> = f["guards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert!(
        guards.contains(&"in-use-cwd") && guards.contains(&"in-use-open"),
        "{guards:?}"
    );

    // Text: the header, the finding, every guard, growth, action and recovery.
    let out = dwhy_in(
        st,
        &["explain", &target, "-q", "--detectors", "cargo-target"],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("dwhy explain · "), "{text}");
    assert!(text.lines().next().unwrap().ends_with(&target), "{text}");
    for want in [
        "· cargo-target · rebuildable",
        "guards:",
        "in-use-cwd",
        "no eligible snapshot (one filesystem, at least an hour old) lists this finding",
        "action (",
        "recovery:",
        "how:  cargo build",
    ] {
        assert!(text.contains(want), "{want:?} in {text}");
    }

    // Relative paths work too.
    let out = Command::new(env!("CARGO_BIN_EXE_dwhy"))
        .args([
            "explain",
            "target",
            "--json",
            "-q",
            "--detectors",
            "cargo-target",
        ])
        .current_dir(format!("{root}/app"))
        .env("XDG_STATE_HOME", st)
        .output()
        .unwrap();
    assert_eq!(json_of(&out)["path"], target.as_str());

    assert_eq!(listing(Path::new(&root)), before, "explain writes nothing");
    assert!(state_listing(st).is_empty(), "explain writes no state");
}

#[test]
fn explain_a_node_modules_dir_through_its_parent() {
    // node-modules recognises node_modules from the project holding it, so
    // explain finds it only by walking the parent.
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let web = root.join("web");
    fs::create_dir_all(web.join("node_modules/left-pad")).unwrap();
    fs::write(web.join("package.json"), r#"{"name":"web"}"#).unwrap();
    fs::write(web.join("package-lock.json"), "{}").unwrap();
    fs::write(
        web.join("node_modules/left-pad/index.js"),
        vec![1u8; 2 << 20],
    )
    .unwrap();
    // A sibling outside the queried path is not listed.
    fs::write(web.join("big.bin"), vec![1u8; 4 << 20]).unwrap();
    let nm = web.join("node_modules").to_str().unwrap().to_string();
    let state = tempfile::tempdir().unwrap();
    let before = listing(&root);
    let out = dwhy_in(
        state.path(),
        &[
            "explain",
            &nm,
            "--json",
            "-q",
            "--detectors",
            "node-modules",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["path"], nm.as_str());
    assert_eq!(v["notes"], serde_json::json!([]), "{v}");
    let f = &v["finding"];
    assert_eq!(f["detector"], "node-modules", "{v}");
    assert_eq!(f["path"], nm.as_str());
    assert_eq!(
        f["id"],
        dwhy_core::detect::finding_id("node-modules", &nm).as_str()
    );
    assert!(!f["guards"].as_array().unwrap().is_empty(), "{v}");
    // The size is the node_modules dir's own, not its parent's.
    let allocated = v["size"]["allocated"].as_u64().unwrap();
    assert!((2 << 20..4 << 20).contains(&allocated), "{v}");
    let apparent = v["size"]["apparent"].as_u64().unwrap();
    assert!((2 << 20..3 << 20).contains(&apparent), "{v}");
    assert_eq!(listing(&root), before, "explain writes nothing");
    assert!(state_listing(state.path()).is_empty());
}

#[test]
fn explain_a_path_no_detector_claims_lists_the_findings_inside() {
    let (_t, root) = cargo_fixture();
    let app = format!("{root}/app");
    let target = format!("{app}/target");
    let state = tempfile::tempdir().unwrap();
    let out = dwhy_in(
        state.path(),
        &[
            "explain",
            &app,
            "--json",
            "-q",
            "--detectors",
            "cargo-target",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["finding"], Value::Null);
    assert_eq!(v["gone"], false);
    assert!(v["size"]["allocated"].as_u64().unwrap() >= 3 << 20);
    let inside = v["inside"].as_array().unwrap();
    assert_eq!(inside.len(), 1, "{v}");
    assert_eq!(inside[0]["path"], target.as_str());
    assert_eq!(inside[0]["detector"], "cargo-target");
    assert_eq!(inside[0]["tier"], "rebuildable");
    assert_eq!(
        inside[0]["id"],
        dwhy_core::detect::finding_id("cargo-target", &target).as_str()
    );
    assert!(inside[0]["bytes"].as_u64().unwrap() >= 3 << 20);

    let out = dwhy_in(
        state.path(),
        &["explain", &app, "-q", "--detectors", "cargo-target"],
    );
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("no detector claims this path"), "{text}");
    assert!(text.contains("size: "), "{text}");
    assert!(text.contains(&target), "{text}");

    // A path that does not exist is an error.
    let out = dwhy_in(
        state.path(),
        &[
            "explain",
            &format!("{root}/nope"),
            "-q",
            "--detectors",
            "cargo-target",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn explain_an_unknown_id_suggests_the_path() {
    let (_t, root) = cargo_fixture();
    let state = tempfile::tempdir().unwrap();
    let st = state.path();
    let out = Command::new(env!("CARGO_BIN_EXE_dwhy"))
        .args([
            "explain",
            "f_000000000000",
            "-q",
            "--detectors",
            "cargo-target",
        ])
        .env_remove("XDG_STATE_HOME")
        .env_remove("HOME")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot find snapshots") && err.contains("dwhy explain <path>"),
        "{err}"
    );

    // No snapshots at all, then one that does not list the id.
    for _ in 0..2 {
        let out = dwhy_in(
            st,
            &[
                "explain",
                "f_000000000000",
                "-q",
                "--detectors",
                "cargo-target",
            ],
        );
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        assert!(out.stdout.is_empty());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("no snapshot lists finding f_000000000000")
                && err.contains("dwhy explain <path>")
                && err.contains("dwhy scan --snapshot"),
            "{err}"
        );
        let out = dwhy_in(
            st,
            &[
                "scan",
                &root,
                "-q",
                "--snapshot",
                "--detectors",
                "cargo-target",
            ],
        );
        assert_eq!(out.status.code(), Some(0));
    }
}

#[test]
fn explain_an_id_through_a_snapshot_then_when_it_is_gone() {
    let (_t, root) = cargo_fixture();
    let target = format!("{root}/app/target");
    let id = dwhy_core::detect::finding_id("cargo-target", &target);
    let state = tempfile::tempdir().unwrap();
    let st = state.path();
    let out = dwhy_in(
        st,
        &[
            "scan",
            &root,
            "-q",
            "--json",
            "--snapshot",
            "--detectors",
            "cargo-target",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let saved = json_of(&out)["snapshot"].clone();
    assert_eq!(json_of(&out)["findings"][0]["id"], id.as_str());

    let explain = |extra: &[&str]| {
        dwhy_in(
            st,
            &[
                &["explain", &id, "-q", "--detectors", "cargo-target"][..],
                extra,
            ]
            .concat(),
        )
    };
    let mut state_before = state_listing(st);
    let out = explain(&["--json"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["query"], id.as_str());
    assert_eq!(v["resolved"]["via"], "id");
    assert_eq!(v["resolved"]["snapshot"]["id"], saved["id"]);
    assert_eq!(v["resolved"]["snapshot"]["path"], saved["path"]);
    assert!(v["resolved"]["snapshot"]["created_at"].is_string());
    assert_eq!(v["path"], target.as_str());
    assert_eq!(v["gone"], false);
    assert_eq!(v["finding"]["id"], id.as_str());
    assert!(!v["finding"]["guards"].as_array().unwrap().is_empty());
    // The snapshot is seconds old: no rate.
    assert_eq!(v["finding"]["growth"], Value::Null);
    let text = String::from_utf8_lossy(&explain(&[]).stdout).into_owned();
    assert!(text.contains("resolved through snapshot"), "{text}");
    assert_eq!(state_listing(st), state_before, "explain writes no state");

    let out = dwhy_in(
        st,
        &["explain", &id, "-q", "--json", "--detectors", "stale-tree"],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["gone"], false);
    assert_eq!(v["finding"], Value::Null);
    assert_eq!(
        v["notes"],
        serde_json::json!([
            format!("still present at {target}, but not detected now"),
            "detector cargo-target not selected by --detectors"
        ])
    );
    let out = dwhy_in(st, &["explain", &id, "-q", "--detectors", "stale-tree"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!("still present at {target}, but not detected now")),
        "{text}"
    );

    if dwhy_core::system::euid() != 0 {
        use std::os::unix::fs::PermissionsExt;

        struct Restore<'a>(&'a Path, fs::Permissions);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                let _ = fs::set_permissions(self.0, self.1.clone());
            }
        }

        let path = Path::new(&target);
        let debug = path.join("debug");
        for (locked, mode, present) in [
            (debug.as_path(), 0o000, true),
            (path, 0o000, true),
            (path.parent().unwrap(), 0o311, true),
            (path.parent().unwrap(), 0o000, false),
        ] {
            let _restore = Restore(locked, fs::metadata(locked).unwrap().permissions());
            fs::set_permissions(locked, fs::Permissions::from_mode(mode)).unwrap();
            let out = explain(&["--json"]);
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            let report = json_of(&out);
            assert_eq!(report["gone"], false);
            assert_eq!(report["finding"], Value::Null);
            assert!(
                report["notes"].as_array().unwrap().iter().any(|n| {
                    n.as_str().is_some_and(|s| {
                        s.contains(locked.to_str().unwrap())
                            && if present {
                                s.contains("could not be read") || s.contains("cannot open")
                            } else {
                                s.starts_with("could not check: ")
                            }
                    })
                }),
                "{report}"
            );
            assert_eq!(
                report["notes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|n| n == &format!("still present at {target}, but not detected now")),
                present
            );
        }
    }

    // Make the snapshot two hours old, from when the finding was 1 MiB smaller.
    let path = saved["path"].as_str().unwrap();
    let mut snap = dwhy_core::snapshot::load(Path::new(path)).unwrap();
    let then = dwhy_core::snapshot::parse_time(&snap.created_at).unwrap() - 7200;
    snap.created_at = time::OffsetDateTime::from_unix_timestamp(then)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    snap.findings.iter_mut().find(|f| f.id == id).unwrap().bytes -= 1 << 20;
    fs::remove_file(path).unwrap();
    dwhy_core::snapshot::save(Path::new(path).parent().unwrap(), &snap, then + 7200).unwrap();
    state_before = state_listing(st);

    let v = json_of(&explain(&["--json"]));
    let g = &v["finding"]["growth"];
    assert_eq!(g["since"], snap.created_at.as_str());
    let rate = g["bytes_per_day"].as_i64().unwrap();
    assert!((11 << 20..=12 << 20).contains(&rate), "{rate}");
    let text = String::from_utf8_lossy(&explain(&[]).stdout).into_owned();
    assert!(
        text.contains(&format!("/day since {}", snap.created_at)),
        "{text}"
    );

    // Gone: the target dir was removed since the snapshot.
    fs::remove_dir_all(&target).unwrap();
    let out = explain(&["--json"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["gone"], true);
    assert_eq!(v["finding"], Value::Null);
    assert_eq!(v["path"], target.as_str());
    assert!(v.get("size").is_none());
    let notes = v["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap().contains("no longer exists")),
        "{v}"
    );
    let out = explain(&[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(&format!("finding {id} is gone")), "{text}");

    // The directory is back without any build artifacts.
    fs::create_dir(&target).unwrap();
    fs::write(format!("{target}/leftover"), b"x").unwrap();
    let v = json_of(&explain(&["--json"]));
    assert_eq!(v["gone"], false);
    assert_eq!(v["finding"], Value::Null);
    assert_eq!(
        v["notes"],
        serde_json::json!([
            format!("still present at {target}, but not detected now"),
            "it may be below the detector's size or age threshold, covered by a finding above it, or need context above the walked directory"
        ])
    );
    assert!(v["size"]["apparent"].as_u64().unwrap() >= 1, "{v}");
    assert_eq!(v["inside"], serde_json::json!([]));

    let parent = Path::new(&target).parent().unwrap();
    fs::remove_dir_all(parent).unwrap();
    fs::write(parent, b"now a file").unwrap();
    let out = explain(&["--json"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["gone"], true);
    assert_eq!(v["finding"], Value::Null);

    // explain writes nothing in the state dir.
    assert_eq!(state_listing(st), state_before);
}

#[test]
fn explain_finds_a_nested_scratch_directory_by_path_and_id() {
    let data = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(data.path()).unwrap().join("scratch");
    let child = parent.join("child");
    fs::create_dir_all(&child).unwrap();
    fs::write(parent.join(".dwhy-scratch"), b"").unwrap();
    fs::write(child.join(".dwhy-scratch"), b"").unwrap();
    fs::write(child.join("data"), vec![1; 2 << 20]).unwrap();
    age_tree(&child, 8 * 86_400);

    let out = dwhy_in(
        state.path(),
        &[
            "scan",
            parent.to_str().unwrap(),
            "-q",
            "--json",
            "--snapshot",
            "--detectors",
            "stale-tree",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let scan = json_of(&out);
    let saved = &scan["findings"][0];
    assert_eq!(saved["path"], child.to_str().unwrap());
    let id = saved["id"].as_str().unwrap();
    age_tree(&parent, 8 * 86_400);

    for arg in [child.to_str().unwrap(), id] {
        let out = dwhy_in(
            state.path(),
            &["explain", arg, "-q", "--json", "--detectors", "stale-tree"],
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let report = json_of(&out);
        assert_eq!(report["finding"]["id"], id, "{report}");
        assert_eq!(report["gone"], false);
    }
}

#[test]
fn explain_uses_full_snapshot_times_and_matching_growth_coverage() {
    let (_data, root) = cargo_fixture();
    let state = tempfile::tempdir().unwrap();
    let target = format!("{root}/app/target");
    let out = dwhy_in(
        state.path(),
        &[
            "scan",
            &root,
            "-q",
            "--json",
            "--snapshot",
            "--detectors",
            "cargo-target",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let scan = json_of(&out);
    let id = scan["findings"][0]["id"].as_str().unwrap();
    let path = Path::new(scan["snapshot"]["path"].as_str().unwrap());
    let mut snap = dwhy_core::snapshot::load(path).unwrap();
    fs::remove_file(path).unwrap();

    let now = time::OffsetDateTime::now_utc();
    let t = now.replace_nanosecond(0).unwrap() - time::Duration::hours(2);
    let timestamp = |t: time::OffsetDateTime| {
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    snap.created_at = timestamp(t + time::Duration::milliseconds(900));
    let newest_one_fs =
        dwhy_core::snapshot::save(path.parent().unwrap(), &snap, now.unix_timestamp()).unwrap();
    let growth_since = snap.created_at.clone();
    snap.created_at = timestamp(t + time::Duration::milliseconds(100));
    dwhy_core::snapshot::save(path.parent().unwrap(), &snap, now.unix_timestamp()).unwrap();

    let explain = |arg: &str| {
        let out = dwhy_in(
            state.path(),
            &[
                "explain",
                arg,
                "-q",
                "--json",
                "--detectors",
                "cargo-target",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        json_of(&out)
    };
    let report = explain(id);
    assert_eq!(
        report["resolved"]["snapshot"]["id"],
        newest_one_fs.snapshot.id
    );
    assert_eq!(report["finding"]["growth"]["since"], growth_since);

    snap.scan.one_filesystem = false;
    snap.created_at = timestamp(t + time::Duration::minutes(1));
    let cross_fs =
        dwhy_core::snapshot::save(path.parent().unwrap(), &snap, now.unix_timestamp()).unwrap();
    let report = explain(id);
    assert_eq!(report["resolved"]["snapshot"]["id"], cross_fs.snapshot.id);
    assert_eq!(report["finding"]["growth"]["since"], growth_since);
    assert_eq!(explain(&target)["finding"]["growth"]["since"], growth_since);
}

#[test]
fn explain_rejects_non_utf8_paths() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let data = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let path = data.path().join(OsStr::from_bytes(b"dir\xff"));
    fs::create_dir(&path).unwrap();
    fs::write(path.join("file"), b"x").unwrap();
    symlink(&path, data.path().join("link")).unwrap();
    for (arg, cwd) in [
        (path.as_path(), data.path()),
        (Path::new("file"), path.as_path()),
        (Path::new("link/file"), data.path()),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_dwhy"))
            .arg("explain")
            .arg(arg)
            .args(["-q", "--json", "--detectors", "cargo-target"])
            .current_dir(cwd)
            .env("XDG_STATE_HOME", state.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        assert!(out.stdout.is_empty());
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(
            text.contains("explain needs a UTF-8 path (diskwhy/v1 reports paths as UTF-8)"),
            "{text}"
        );
    }
}

#[test]
fn explain_does_not_alias_a_lossy_finding_to_a_utf8_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let (_data, root) = cargo_fixture();
    let state = tempfile::tempdir().unwrap();
    let app = Path::new(&root).join("app");
    fs::rename(
        app.join("target"),
        app.join(OsStr::from_bytes(b"target\xff")),
    )
    .unwrap();
    let other = app.join("target�");
    fs::create_dir(&other).unwrap();

    for path in [other, app] {
        let out = dwhy_in(
            state.path(),
            &[
                "explain",
                path.to_str().unwrap(),
                "-q",
                "--json",
                "--detectors",
                "cargo-target",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let report = json_of(&out);
        assert_eq!(report["finding"], Value::Null);
        assert_eq!(report["inside"], serde_json::json!([]));
    }
}

#[test]
fn explain_refuses_an_id_whose_saved_path_was_lossy() {
    let (_data, root) = cargo_fixture();
    let state = tempfile::tempdir().unwrap();
    let out = dwhy_in(
        state.path(),
        &[
            "scan",
            &root,
            "-q",
            "--json",
            "--snapshot",
            "--detectors",
            "cargo-target",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let scan = json_of(&out);
    let path = Path::new(scan["snapshot"]["path"].as_str().unwrap());
    // What v1 saves for a target dir named `target\xff`.
    let mut snap = dwhy_core::snapshot::load(path).unwrap();
    let lossy = format!("{root}/app/target\u{FFFD}");
    let id = dwhy_core::detect::finding_id("cargo-target", &lossy);
    snap.findings[0].path = lossy;
    snap.findings[0].id = id.clone();
    fs::remove_file(path).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    dwhy_core::snapshot::save(path.parent().unwrap(), &snap, now).unwrap();

    let out = dwhy_in(
        state.path(),
        &[
            "explain",
            &id,
            "-q",
            "--json",
            "--detectors",
            "cargo-target",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "the saved path for {id} was not valid UTF-8 and can't be checked reliably; \
             run `dwhy explain <path>` with the real path"
        )),
        "{err}"
    );
}
