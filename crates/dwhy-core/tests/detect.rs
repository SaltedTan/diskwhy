//! Detector framework and `cargo-target` on temp-dir fixtures.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{self, DetectContext, Detector};
use dwhy_core::detectors::CargoTarget;
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{
    ActionKind, DetectorAvailability, DockerSocket, Finding, Tier, ToolStatus,
};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::{Markers, ScanTree};

const CARGO_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
# This file is a cache directory tag created by cargo.\n\
# For information about cache directory tags see https://bford.info/cachedir/\n";

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

fn ctx(cargo: Option<&str>) -> DetectContext {
    DetectContext {
        uid: 1000,
        root: false,
        home: None,
        now: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        tools: vec![ToolStatus {
            name: "cargo".into(),
            path: cargo.map(String::from),
            off_path: None,
            enables: vec![],
        }],
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

/// A crate at `dir` with a target dir `target_name` holding `mb` MiB.
fn cargo_crate(dir: &Path, target_name: &str, mb: usize, tag: Option<&str>) -> PathBuf {
    write(&dir.join("Cargo.toml"), 40);
    let target = dir.join(target_name);
    write(&target.join("debug/deps/libbig.rlib"), mb << 20);
    if let Some(tag) = tag {
        fs::write(target.join("CACHEDIR.TAG"), tag).unwrap();
    }
    target
}

fn cargo_findings(root: &Path, cargo: Option<&str>) -> Vec<Finding> {
    let tree = scan_tree(root);
    let mut f = CargoTarget.detect(&tree, &ctx(cargo)).unwrap();
    f.sort_by(|a, b| a.path.cmp(&b.path));
    f
}

#[test]
fn finds_a_tagged_target_dir() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let target = cargo_crate(&root.join("app"), "target", 2, Some(CARGO_TAG));

    let tree = scan_tree(&root);
    let found = CargoTarget
        .detect(&tree, &ctx(Some("/usr/bin/cargo")))
        .unwrap();
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!(f.path, target.to_str().unwrap());
    assert_eq!(f.detector, "cargo-target");
    assert_eq!(f.tier, Tier::Rebuildable);
    assert_eq!(f.id, detect::finding_id("cargo-target", &f.path));
    let node = tree.find(&target).unwrap();
    assert_eq!(f.bytes, tree.node(node).total.allocated);
    assert!(f.bytes >= 2 << 20);
    assert_eq!(f.action.kind, ActionKind::Command);
    let argv = f.action.argv.as_ref().unwrap();
    let manifest = root.join("app/Cargo.toml");
    assert_eq!(
        argv,
        &[
            "cargo",
            "clean",
            "--manifest-path",
            manifest.to_str().unwrap(),
            "--target-dir",
            target.to_str().unwrap()
        ]
    );
    assert_eq!(f.recovery.how.as_deref(), Some("cargo build"));
    assert!(f.reason.contains("Cargo build output of"), "{}", f.reason);
}

#[test]
fn action_text_is_shell_quoted_but_argv_is_raw() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let crate_dir = root.join("my app $(echo x)");
    let target = cargo_crate(&crate_dir, "target", 2, Some(CARGO_TAG));
    let manifest = crate_dir.join("Cargo.toml");
    let (manifest_s, target_s) = (manifest.to_str().unwrap(), target.to_str().unwrap());

    let f = cargo_findings(&root, Some("/usr/bin/cargo"));
    assert_eq!(f.len(), 1);
    assert_eq!(
        f[0].action.argv.as_deref().unwrap(),
        &[
            "cargo",
            "clean",
            "--manifest-path",
            manifest_s,
            "--target-dir",
            target_s
        ]
    );
    assert_eq!(
        f[0].action.text,
        format!("cargo clean --manifest-path '{manifest_s}' --target-dir '{target_s}'")
    );

    let f = cargo_findings(&root, None);
    assert_eq!(
        f[0].action.text,
        format!("remove '{target_s}' (cargo not found)")
    );
}

#[test]
fn falls_back_to_path_removal_without_cargo() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    cargo_crate(&root.join("app"), "target", 2, Some(CARGO_TAG));
    let f = cargo_findings(&root, None);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].action.kind, ActionKind::RemovePath);
    assert!(f[0].action.argv.is_none());
}

#[test]
fn recognises_renamed_and_untagged_target_dirs() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    // Renamed target dir (e.g. CARGO_TARGET_DIR=build-out) with cargo's tag.
    let renamed = cargo_crate(&root.join("a"), "build-out", 2, Some(CARGO_TAG));
    // `target/` whose tag was removed, but with cargo's .rustc_info.json.
    let untagged = cargo_crate(&root.join("b"), "target", 2, None);
    fs::write(untagged.join(".rustc_info.json"), "{}").unwrap();
    // .rustc_info.json in a dir not named `target`: not enough on its own.
    let other = cargo_crate(&root.join("c"), "out", 2, None);
    fs::write(other.join(".rustc_info.json"), "{}").unwrap();

    let paths: Vec<String> = cargo_findings(&root, Some("cargo"))
        .into_iter()
        .map(|f| f.path)
        .collect();
    assert_eq!(
        paths,
        [renamed.to_str().unwrap(), untagged.to_str().unwrap()]
    );
}

#[test]
fn ignores_lookalikes() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    // A cache tag written by some other tool.
    cargo_crate(
        &root.join("other-tool"),
        "target",
        2,
        Some("Signature: 8a477f597d28d172789f06886806bc55\n# created by ccache\n"),
    );
    // A tag that is not a cachedir tag at all.
    cargo_crate(&root.join("bad-sig"), "target", 2, Some("hello, cargo\n"));
    // A cargo tag, but no Cargo.toml next to the dir.
    let lone = root.join("lone/target");
    write(&lone.join("big"), 2 << 20);
    fs::write(lone.join("CACHEDIR.TAG"), CARGO_TAG).unwrap();
    // CACHEDIR.TAG is a symlink to a real cargo tag: never followed.
    let real_tag = root.join("real-tag");
    fs::write(&real_tag, CARGO_TAG).unwrap();
    let sym = cargo_crate(&root.join("symlinked"), "target", 2, None);
    symlink(&real_tag, sym.join("CACHEDIR.TAG")).unwrap();
    // Too small to report.
    cargo_crate(&root.join("tiny"), "target", 0, Some(CARGO_TAG));

    assert!(cargo_findings(&root, Some("cargo")).is_empty());
}

#[test]
fn finds_a_target_dir_that_is_the_scan_root() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let target = cargo_crate(&root.join("app"), "target", 2, Some(CARGO_TAG));
    let f = cargo_findings(&target, Some("cargo"));
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].path, target.to_str().unwrap());
    assert_eq!(f[0].id, detect::finding_id("cargo-target", &f[0].path));
    // The same finding as when the crate is scanned.
    assert_eq!(cargo_findings(&root, Some("cargo")), f);
}

#[test]
fn a_root_target_dir_needs_a_real_manifest_next_to_it() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    // No Cargo.toml next to it.
    let lone = root.join("lone/target");
    write(&lone.join("big"), 2 << 20);
    fs::write(lone.join("CACHEDIR.TAG"), CARGO_TAG).unwrap();
    assert!(cargo_findings(&lone, Some("cargo")).is_empty());
    // Cargo.toml is a symlink: not followed.
    fs::write(root.join("real.toml"), "[package]\n").unwrap();
    symlink(root.join("real.toml"), root.join("lone/Cargo.toml")).unwrap();
    assert!(cargo_findings(&lone, Some("cargo")).is_empty());
    // Cargo.toml is a directory.
    let dir_manifest = root.join("d/target");
    write(&dir_manifest.join("big"), 2 << 20);
    fs::write(dir_manifest.join("CACHEDIR.TAG"), CARGO_TAG).unwrap();
    fs::create_dir(root.join("d/Cargo.toml")).unwrap();
    assert!(cargo_findings(&dir_manifest, Some("cargo")).is_empty());
}

#[test]
fn nested_target_dirs_yield_only_the_outermost() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let outer = cargo_crate(&root.join("ws"), "target", 2, Some(CARGO_TAG));
    // `cargo package` unpacks a crate with its own target inside target/package/.
    cargo_crate(
        &outer.join("package/ws-0.1.0"),
        "target",
        2,
        Some(CARGO_TAG),
    );
    let tree = scan_tree(&root);
    let raw = CargoTarget.detect(&tree, &ctx(Some("cargo"))).unwrap();
    assert_eq!(raw.len(), 2);
    let kept = detect::outermost(raw);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].path, outer.to_str().unwrap());
}

#[test]
fn last_modified_is_the_newest_file_in_the_target() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let target = cargo_crate(&root.join("app"), "target", 2, Some(CARGO_TAG));
    let old = SystemTime::now() - Duration::from_secs(10 * 86_400);
    let newer = SystemTime::now() - Duration::from_secs(3 * 86_400);
    for p in [
        target.join("CACHEDIR.TAG"),
        target.join("debug/deps/libbig.rlib"),
    ] {
        fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    write(&target.join("debug/fresh.o"), 10);
    fs::File::options()
        .write(true)
        .open(target.join("debug/fresh.o"))
        .unwrap()
        .set_modified(newer)
        .unwrap();
    // Directories themselves were just modified, so set them old too.
    for d in [
        target.join("debug/deps"),
        target.join("debug"),
        target.clone(),
    ] {
        fs::File::open(&d).unwrap().set_modified(old).unwrap();
    }

    let tree = scan_tree(&root);
    let id = tree.find(&target).unwrap();
    let want = newer.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    assert_eq!(tree.node(id).newest_mtime, want);
    let f = CargoTarget.detect(&tree, &ctx(Some("cargo"))).unwrap();
    assert_eq!(
        f[0].last_modified.as_deref(),
        Some(detect::rfc3339(want).as_str())
    );
    assert!(
        f[0].reason.ends_with("last written 3 days ago"),
        "{}",
        f[0].reason
    );
}

#[test]
fn the_walk_records_markers_per_directory() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    write(&root.join("proj/Cargo.toml"), 1);
    write(&root.join("proj/package.json"), 1);
    fs::create_dir_all(root.join("proj/.git")).unwrap();
    write(&root.join("venv/pyvenv.cfg"), 1);
    write(&root.join("wt/.git"), 1); // a worktree's .git file
    symlink(root.join("proj/Cargo.toml"), root.join("venv/Cargo.toml")).unwrap();

    let tree = scan_tree(&root);
    let m = |p: &str| tree.node(tree.find(&root.join(p)).unwrap()).markers;
    let proj = m("proj");
    assert!(proj.contains(Markers::CARGO_TOML));
    assert!(proj.contains(Markers::PACKAGE_JSON));
    assert!(proj.contains(Markers::DOT_GIT));
    assert!(!proj.contains(Markers::PYVENV_CFG));
    let venv = m("venv");
    assert!(venv.contains(Markers::PYVENV_CFG));
    assert!(
        !venv.contains(Markers::CARGO_TOML),
        "symlinks are not markers"
    );
    assert!(m("wt").contains(Markers::DOT_GIT));
    assert_eq!(m("proj/.git"), Markers::empty());
}

#[test]
fn run_reports_every_catalog_detector() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    cargo_crate(&root.join("app"), "target", 2, Some(CARGO_TAG));
    let tree = scan_tree(&root);
    let (found, runs) = detect::run(&tree, &ctx(Some("cargo")));
    assert_eq!(found.len(), 1);
    assert_eq!(runs.len(), detect::CATALOG.len());
    let cargo = runs.iter().find(|r| r.name == "cargo-target").unwrap();
    assert!(cargo.ran);
    assert_eq!(cargo.findings, 1);
    let journald = runs.iter().find(|r| r.name == "journald").unwrap();
    assert!(!journald.ran);
    assert_eq!(journald.status, DetectorAvailability::NotImplemented);
}

#[test]
fn bytes_leave_out_files_hardlinked_outside_the_target_dir() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let target = cargo_crate(&root.join("app"), "target", 2, Some(CARGO_TAG));
    // Linked outside: still alive after removing target/. The outside path
    // sorts after target's, so the file is attributed to target/.
    write(&target.join("debug/big"), 3 << 20);
    fs::create_dir_all(root.join("zz-out")).unwrap();
    fs::hard_link(target.join("debug/big"), root.join("zz-out/big")).unwrap();
    // Linked inside: removing target/ frees it.
    write(&target.join("debug/deps/libx.rlib"), 1 << 20);
    fs::hard_link(
        target.join("debug/deps/libx.rlib"),
        target.join("debug/libx.rlib"),
    )
    .unwrap();

    let tree = scan_tree(&root);
    let node = tree.node(tree.find(&target).unwrap());
    assert!(
        node.shared >= 3 << 20 && node.shared < 4 << 20,
        "shared = {}",
        node.shared
    );
    let found = cargo_findings(&root, Some("/usr/bin/cargo"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].bytes, node.freeable());
    assert_eq!(found[0].bytes, node.total.allocated - node.shared);
    // The 2 MiB rlib and the internally linked 1 MiB file are both freed.
    assert!(found[0].bytes >= 3 << 20, "{}", found[0].bytes);
    assert!(
        found[0].reason.contains("hardlinked elsewhere"),
        "{}",
        found[0].reason
    );
}
