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
