//! `user-cache` on a temp-dir home.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{DetectContext, Detector};
use dwhy_core::detectors::UserCache;
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ActionKind, DockerSocket, Finding, GuardStatus, Tier, ToolStatus};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

const MB: usize = 1 << 20;

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

/// `tools`: names installed on PATH.
fn ctx(home: &Path, tools: &[&str]) -> DetectContext {
    DetectContext {
        uid: 1000,
        root: false,
        home: Some(home.to_path_buf()),
        now: now(),
        tools: ["uv", "pip", "npm", "pnpm", "yarn", "go"]
            .iter()
            .map(|n| ToolStatus {
                name: (*n).into(),
                path: tools.contains(n).then(|| format!("/usr/bin/{n}")),
                off_path: None,
                enables: vec![],
            })
            .collect(),
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: dwhy_core::docker::Source::none(),
    }
}

fn write(p: &Path, bytes: usize) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, vec![7u8; bytes]).unwrap();
}

/// Sets the mtime of everything under `dir` (and `dir` itself) to `days` ago.
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

fn detect(home: &Path, env: &[(&str, String)], tools: &[&str]) -> HashMap<PathBuf, Finding> {
    let tree = scan_tree(home);
    UserCache::with_env(env.iter().map(|(k, v)| (k.to_string(), v.clone())))
        .detect(&tree, &ctx(home, tools))
        .unwrap()
        .into_iter()
        .map(|f| (PathBuf::from(&f.path), f))
        .collect()
}

fn argv(f: &Finding) -> Vec<&str> {
    f.action
        .argv
        .as_ref()
        .unwrap()
        .iter()
        .map(String::as_str)
        .collect()
}

/// A home with a typical set of caches, all last written 3 days ago.
fn home_with_caches() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    write(&h.join(".cache/uv/archive-v0/x/lib.so"), 3 * MB);
    write(&h.join(".cache/pip/http-v2/a/b"), 2 * MB);
    write(&h.join(".npm/_cacache/content-v2/sha512/aa"), 2 * MB);
    write(
        &h.join(".npm/_npx/15c61037b1978c83/node_modules/x/index.js"),
        2 * MB,
    );
    write(&h.join(".npm/_logs/debug.log"), 2 * MB);
    write(&h.join(".cache/go-build/00/abc-d"), 2 * MB);
    write(&h.join("go/pkg/mod/github.com/x/y@v1/y.go"), 2 * MB);
    write(&h.join(".cargo/registry/cache/index/serde.crate"), 2 * MB);
    write(&h.join(".cache/ms-playwright/chromium-1200/chrome"), 2 * MB);
    write(
        &h.join(".cache/huggingface/hub/models--a--b/blobs/x"),
        2 * MB,
    );
    write(&h.join(".cache/huggingface/token"), 40);
    // Lookalikes: not a known cache; a known name that is too small.
    write(&h.join(".cache/some-app/blob"), 5 * MB);
    write(&h.join(".cache/yarn/v6/tiny"), 1000);
    age_tree(h, 3);
    d
}

#[test]
fn finds_known_caches_and_ignores_lookalikes() {
    let d = home_with_caches();
    let h = d.path();
    let found = detect(h, &[], &[]);
    let mut paths: Vec<String> = found
        .keys()
        .map(|p| p.strip_prefix(h).unwrap().display().to_string())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        [
            ".cache/go-build",
            ".cache/huggingface/hub",
            ".cache/ms-playwright",
            ".cache/pip",
            ".cache/uv",
            ".cargo/registry",
            ".npm/_cacache",
            ".npm/_npx",
            "go/pkg/mod",
        ]
    );

    let uv = &found[&h.join(".cache/uv")];
    assert_eq!(uv.detector, "user-cache");
    assert_eq!(uv.tier, Tier::Regenerable);
    assert!(uv.bytes >= 3 * MB as u64);
    assert!(uv.reason.starts_with("uv cache ("), "{}", uv.reason);
    assert!(uv.guards.is_empty());
    assert!(uv.last_modified.is_some());

    // Hugging Face is review, and only hub/ is offered: the token next to it stays.
    let hf = &found[&h.join(".cache/huggingface/hub")];
    assert_eq!(hf.tier, Tier::Review);
    assert_eq!(found[&h.join(".npm/_npx")].tier, Tier::Review);
}

#[test]
fn tool_native_commands_are_pinned_to_the_measured_directory() {
    let d = home_with_caches();
    let h = d.path();
    let found = detect(h, &[], &["uv", "pip", "npm", "go"]);
    let s = |p: &str| h.join(p).display().to_string();

    let uv = &found[&h.join(".cache/uv")];
    assert_eq!(uv.action.kind, ActionKind::Command);
    assert_eq!(
        argv(uv),
        ["uv", "cache", "clean", "--cache-dir", &s(".cache/uv")]
    );
    assert_eq!(
        argv(&found[&h.join(".cache/pip")]),
        ["pip", "--cache-dir", &s(".cache/pip"), "cache", "purge"]
    );
    // npm takes the cache root, not the _cacache inside it.
    assert_eq!(
        argv(&found[&h.join(".npm/_cacache")]),
        ["npm", "cache", "clean", "--force", "--cache", &s(".npm")]
    );
    let gocache = format!("GOCACHE={}", s(".cache/go-build"));
    assert_eq!(
        argv(&found[&h.join(".cache/go-build")]),
        ["env", gocache.as_str(), "go", "clean", "-cache"]
    );
    let modcache = format!("GOMODCACHE={}", s("go/pkg/mod"));
    assert_eq!(
        argv(&found[&h.join("go/pkg/mod")]),
        ["env", modcache.as_str(), "go", "clean", "-modcache"]
    );
    // No tool-native command: path removal limited to the cache root.
    let cargo = &found[&h.join(".cargo/registry")];
    assert_eq!(cargo.action.kind, ActionKind::RemovePath);
    assert!(cargo.action.argv.is_none());
    assert_eq!(
        cargo.action.text,
        format!("remove {}", s(".cargo/registry"))
    );
}

#[test]
fn falls_back_to_path_removal_without_the_tool() {
    let d = home_with_caches();
    let h = d.path();
    let found = detect(h, &[], &[]);
    let uv = &found[&h.join(".cache/uv")];
    assert_eq!(uv.action.kind, ActionKind::RemovePath);
    assert!(uv.action.argv.is_none());
    assert_eq!(
        uv.action.text,
        format!("remove {} (uv not found)", h.join(".cache/uv").display())
    );
}

#[test]
fn recently_written_caches_are_blocked_not_offered() {
    let d = home_with_caches();
    let h = d.path();
    // uv ran a minute ago.
    write(&h.join(".cache/uv/archive-v0/new/file"), 10);
    let found = detect(h, &[], &["uv"]);
    let uv = &found[&h.join(".cache/uv")];
    assert_eq!(uv.tier, Tier::Blocked);
    assert_eq!(uv.guards.len(), 1);
    assert_eq!(uv.guards[0].name, "recent-write");
    assert_eq!(uv.guards[0].status, GuardStatus::Block);
    assert!(uv.reason.contains("not offered yet"), "{}", uv.reason);
    // The others were last written 3 days ago.
    assert_eq!(found[&h.join(".cache/pip")].tier, Tier::Regenerable);
    assert!(found[&h.join(".cache/pip")].guards.is_empty());
}

#[test]
fn environment_overrides_move_the_caches() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    write(&h.join("xdg/uv/blob"), 2 * MB);
    write(&h.join("custom-gocache/aa/b"), 2 * MB);
    write(&h.join("gopath1/pkg/mod/m/x.go"), 2 * MB);
    write(&h.join("hf/hub/models--a--b/blobs/x"), 2 * MB);
    write(&h.join("npmcache/_cacache/x"), 2 * MB);
    // The defaults exist too, but the variables point elsewhere.
    write(&h.join(".cache/uv/blob"), 2 * MB);
    age_tree(h, 3);
    let p = |s: &str| h.join(s).display().to_string();
    let env = [
        ("XDG_CACHE_HOME", p("xdg")),
        ("GOCACHE", p("custom-gocache")),
        ("GOPATH", format!("{}:{}", p("gopath1"), p("gopath2"))),
        ("HF_HOME", p("hf")),
        ("npm_config_cache", p("npmcache")),
    ];
    let found = detect(h, &env, &[]);
    let mut paths: Vec<String> = found
        .keys()
        .map(|k| k.strip_prefix(h).unwrap().display().to_string())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        [
            "custom-gocache",
            "gopath1/pkg/mod",
            "hf/hub",
            "npmcache/_cacache",
            "xdg/uv"
        ]
    );
}

#[test]
fn implausible_or_relative_overrides_are_ignored() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    write(&h.join("projects/big/file"), 5 * MB);
    write(&h.join(".cache/uv/blob"), 2 * MB);
    age_tree(h, 3);
    let env = [
        // Never offer the home itself, an ancestor of it, or `/`.
        ("PIP_CACHE_DIR", h.display().to_string()),
        ("GOCACHE", h.parent().unwrap().display().to_string()),
        ("YARN_CACHE_FOLDER", "/".into()),
        // Relative values are not used; uv falls back to its default.
        ("UV_CACHE_DIR", "relative/uv".into()),
    ];
    let found = detect(h, &env, &[]);
    let paths: Vec<&PathBuf> = found.keys().collect();
    assert_eq!(paths, [&h.join(".cache/uv")]);
}

#[test]
fn symlinked_caches_and_caches_outside_the_scan_are_skipped() {
    let d = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let h = d.path();
    write(&elsewhere.path().join("uv/blob"), 3 * MB);
    fs::create_dir_all(h.join(".cache")).unwrap();
    symlink(elsewhere.path().join("uv"), h.join(".cache/uv")).unwrap();
    // GOCACHE points outside the scanned tree.
    write(&elsewhere.path().join("gocache/x"), 3 * MB);
    age_tree(h, 3);
    age_tree(elsewhere.path(), 3);
    let env = [(
        "GOCACHE",
        elsewhere.path().join("gocache").display().to_string(),
    )];
    assert!(detect(h, &env, &["uv", "go"]).is_empty());
}

#[test]
fn no_home_means_no_findings() {
    let d = home_with_caches();
    let tree = scan_tree(d.path());
    let mut c = ctx(d.path(), &[]);
    c.home = None;
    assert!(
        UserCache::with_env(Vec::<(String, String)>::new())
            .detect(&tree, &c)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn non_utf8_variables_are_skipped() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    write(&h.join("custom-gocache/aa/b"), 2 * MB);
    write(&h.join(".cache/uv/blob"), 2 * MB);
    age_tree(h, 3);
    let bad = OsString::from_vec(vec![0xff, 0xfe]);
    let mut uv_cache = h.join("bad-uv").into_os_string().into_vec();
    uv_cache.push(0xff);
    let env: Vec<(OsString, OsString)> = vec![
        ("FOO".into(), bad.clone()),
        (bad, "x".into()),
        ("UV_CACHE_DIR".into(), OsString::from_vec(uv_cache)),
        ("GOCACHE".into(), h.join("custom-gocache").into_os_string()),
    ];
    let tree = scan_tree(h);
    let mut paths: Vec<PathBuf> = UserCache::with_env(env)
        .detect(&tree, &ctx(h, &[]))
        .unwrap()
        .into_iter()
        .map(|f| PathBuf::from(f.path))
        .collect();
    paths.sort();
    assert_eq!(paths, [h.join(".cache/uv"), h.join("custom-gocache")]);
}

#[test]
fn bytes_hardlinked_into_projects_are_not_counted() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    write(&h.join(".cache/uv/archive-v0/x/lib.so"), 3 * MB);
    write(&h.join(".cache/uv/wheels-v5/w"), 2 * MB);
    fs::create_dir_all(h.join("code/app/.venv/lib")).unwrap();
    fs::hard_link(
        h.join(".cache/uv/archive-v0/x/lib.so"),
        h.join("code/app/.venv/lib/lib.so"),
    )
    .unwrap();
    // Everything in pip's cache is also used by the venv: nothing to free.
    write(&h.join(".cache/pip/http-v2/a"), 3 * MB);
    fs::hard_link(h.join(".cache/pip/http-v2/a"), h.join("code/app/.venv/a")).unwrap();
    age_tree(h, 3);
    let found = detect(h, &[], &[]);
    let paths: Vec<&PathBuf> = found.keys().collect();
    assert_eq!(paths, [&h.join(".cache/uv")]);
    let uv = &found[&h.join(".cache/uv")];
    assert!(
        (2 * MB as u64..3 * MB as u64).contains(&uv.bytes),
        "{}",
        uv.bytes
    );
    assert!(uv.reason.contains("hardlinked elsewhere"), "{}", uv.reason);
}

#[test]
fn hugging_face_overrides_never_cover_the_token() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    write(
        &h.join(".cache/huggingface/hub/models--a--b/blobs/x"),
        2 * MB,
    );
    write(&h.join(".cache/huggingface/token"), 40);
    write(&h.join(".cache/pip-other/big"), 2 * MB);
    age_tree(h, 3);
    let hf_home = h.join(".cache/huggingface");
    let env = [
        ("HF_HUB_CACHE", hf_home.display().to_string()),
        ("HF_XET_CACHE", h.join(".cache").display().to_string()),
    ];
    let found = detect(h, &env, &[]);
    let paths: Vec<&PathBuf> = found.keys().collect();
    assert_eq!(paths, [&hf_home.join("hub")]);
}
