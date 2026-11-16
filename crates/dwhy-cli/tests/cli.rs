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
    let out = dwhy(&["scan", t.path().to_str().unwrap(), "--min-size", "0", "-q"]);
    assert_eq!(out.status.code(), Some(0));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("largest directories"), "{s}");
    assert!(s.contains("hardlinks   1 extra links counted once"), "{s}");
    assert!(s.contains("├─ ") || s.contains("└─ "), "{s}");
}

#[test]
fn exit_codes() {
    // Missing path: error.
    let out = dwhy(&["scan", "/definitely/not/here"]);
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
    // No TUI yet.
    assert_eq!(dwhy(&[]).status.code(), Some(1));
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
        dwhy(&["scan", t.path().to_str().unwrap(), "-q"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(listing(t.path()), before);
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
