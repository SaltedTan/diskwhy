//! `tool-versions` on fake home directories.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{self, DetectContext, Detector, finding_id};
use dwhy_core::detectors::{ToolVersions, registry};
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ActionKind, DockerSocket, Finding, Tier, ToolStatus};
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

/// `tools`: (name, on PATH at) for each tool that is installed.
fn ctx(home: &Path, tools: &[(&str, &str)]) -> DetectContext {
    DetectContext {
        uid: 1000,
        root: false,
        home: Some(home.to_path_buf()),
        now: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        tools: tools
            .iter()
            .map(|(n, p)| ToolStatus {
                name: (*n).into(),
                path: Some((*p).into()),
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

fn detect_with(
    root: &Path,
    home: &Path,
    env: &[(&str, &str)],
    tools: &[(&str, &str)],
) -> Vec<Finding> {
    let d = ToolVersions::with_env(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let mut f = d
        .detect(&scan_tree(root), &ctx(home, tools))
        .expect("tool-versions never fails");
    f.sort_by(|a, b| a.path.cmp(&b.path));
    f
}

fn detect(home: &Path) -> Vec<Finding> {
    detect_with(home, home, &[], &[])
}

fn paths(f: &[Finding]) -> Vec<String> {
    let mut p: Vec<String> = f.iter().map(|f| f.path.clone()).collect();
    p.sort();
    p
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn file(path: &Path, size: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![7u8; size]).unwrap();
}

fn text(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

/// An installed version: a directory holding 2 MiB.
fn install(dir: &Path) -> PathBuf {
    file(&dir.join("bin/tool"), 2 * MB);
    dir.to_path_buf()
}

/// A venv in `dir` whose interpreter is `home_bin`.
fn venv(dir: &Path, home_bin: &Path) {
    text(
        &dir.join("pyvenv.cfg"),
        &format!("home = {}\nversion_info = 3.12.15\n", home_bin.display()),
    );
}

const HOST: &str = "x86_64-unknown-linux-gnu";

fn rustup_home(home: &Path, default: &str, toolchains: &[&str]) -> PathBuf {
    let r = home.join(".rustup");
    text(
        &r.join("settings.toml"),
        &format!(
            "version = \"12\"\ndefault_toolchain = \"{default}\"\nprofile = \"minimal\"\n\n[overrides]\n"
        ),
    );
    for t in toolchains {
        install(&r.join("toolchains").join(t));
    }
    r
}

fn tc(name: &str) -> String {
    format!("{name}-{HOST}")
}

#[test]
fn rust_toolchains_default_pins_and_newest() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let names = [
        tc("stable"),
        tc("nightly"),
        tc("1.80.0"),
        tc("1.85.1"),
        tc("1.90.0"),
        tc("1.95.0"),
        tc("nightly-2025-01-01"),
        tc("nightly-2025-06-01"),
    ];
    let r = rustup_home(
        home,
        &tc("stable"),
        &names.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    // Pinned by a project (toml), a legacy file, and nothing else.
    text(
        &home.join("code/a/rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.85.1\" # pinned\ncomponents = [\"clippy\"]\n",
    );
    text(&home.join("code/b/rust-toolchain"), "1.90.0\n");

    let found = detect(home);
    let t = r.join("toolchains");
    assert_eq!(
        paths(&found),
        [
            s(&t.join(tc("1.80.0"))),
            s(&t.join(tc("nightly-2025-01-01")))
        ]
    );
    let f = &found[0];
    assert_eq!(f.detector, "tool-versions");
    assert_eq!(f.tier, Tier::Rebuildable);
    assert_eq!(f.id, finding_id("tool-versions", &f.path));
    // No rustup found: removal by path, recovery still names rustup.
    assert_eq!(f.action.kind, ActionKind::RemovePath);
    assert_eq!(f.action.text, format!("remove {}", f.path));
    assert_eq!(
        f.recovery.how.as_deref(),
        Some(format!("rustup toolchain install {}", tc("1.80.0")).as_str())
    );
    assert!(
        f.reason
            .starts_with(&format!("Rust toolchain {} (", tc("1.80.0"))),
        "{}",
        f.reason
    );
    assert!(
        f.reason
            .contains(&format!("not the default ({})", tc("stable"))),
        "{}",
        f.reason
    );
    assert!(
        !f.recovery.cost.contains("not scanned"),
        "{}",
        f.recovery.cost
    );
}

#[test]
fn rustup_command_overrides_and_rustup_home() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let r = home.join("rh");
    text(
        &r.join("settings.toml"),
        &format!(
            "default_toolchain = \"stable\"\n[overrides]\n\"/srv/proj\" = \"{}\"\n",
            tc("1.70.0")
        ),
    );
    for t in [tc("stable"), tc("1.70.0"), tc("1.75.0"), tc("1.79.0")] {
        install(&r.join("toolchains").join(t));
    }
    let found = detect_with(
        home,
        home,
        &[("RUSTUP_HOME", &s(&r))],
        &[("rustup", "/usr/bin/rustup")],
    );
    assert_eq!(paths(&found), [s(&r.join("toolchains").join(tc("1.75.0")))]);
    let f = &found[0];
    assert_eq!(f.action.kind, ActionKind::Command);
    let want = vec![
        "env".to_string(),
        format!("RUSTUP_HOME={}", r.display()),
        "rustup".into(),
        "toolchain".into(),
        "uninstall".into(),
        tc("1.75.0"),
    ];
    assert_eq!(f.action.argv.as_ref(), Some(&want));
    assert_eq!(
        f.action.text,
        format!(
            "env RUSTUP_HOME={} rustup toolchain uninstall {}",
            r.display(),
            tc("1.75.0")
        )
    );
}

#[test]
fn channel_pins_do_not_match_dated_toolchains() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let r = rustup_home(
        home,
        &tc("stable"),
        &[
            &tc("stable"),
            &tc("nightly-2025-01-01"),
            &tc("nightly-2025-02-01"),
        ],
    );
    text(
        &home.join("p/rust-toolchain.toml"),
        "[toolchain]\nchannel = \"nightly\"\n",
    );
    // `nightly` names the rolling nightly, not a dated one: the older dated
    // toolchain is still reported.
    assert_eq!(
        paths(&detect(home)),
        [s(&r.join("toolchains").join(tc("nightly-2025-01-01")))]
    );
    text(
        &home.join("q/rust-toolchain.toml"),
        "[toolchain]\nchannel = \"nightly-2025-01-01\"\n",
    );
    assert_eq!(paths(&detect(home)), Vec::<String>::new());
}

fn uv_root(home: &Path) -> PathBuf {
    home.join(".local/share/uv/python")
}

#[test]
fn uv_pythons_venvs_pins_and_shims() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = uv_root(home);
    let k = |v: &str| format!("cpython-{v}-linux-x86_64-gnu");
    for v in ["3.9.25", "3.10.4", "3.11.2", "3.11.9", "3.12.15", "3.13.1"] {
        install(&root.join(k(v)));
    }
    fs::create_dir_all(root.join(".temp")).unwrap();
    // Minor-version link, as recent uv makes; a venv made through it.
    symlink(
        root.join(k("3.12.15")),
        root.join("cpython-3.12-linux-x86_64-gnu"),
    )
    .unwrap();
    venv(
        &home.join("code/app/.venv"),
        &root.join("cpython-3.12-linux-x86_64-gnu/bin"),
    );
    // A project pinning 3.11: keeps the newest 3.11 only.
    text(&home.join("code/lib/.python-version"), "3.11\n");
    // uv's global pin.
    text(&home.join(".config/uv/.python-version"), "cpython@3.10.4\n");
    // The shim for 3.9 in ~/.local/bin.
    fs::create_dir_all(home.join(".local/bin")).unwrap();
    symlink(
        root.join(k("3.9.25")).join("bin/python3.9"),
        home.join(".local/bin/python3.9"),
    )
    .unwrap();

    let found = detect_with(home, home, &[], &[("uv", "/usr/bin/uv")]);
    assert_eq!(
        paths(&found),
        [s(&root.join(k("3.11.2"))), s(&root.join(k("3.9.25")))]
    );
    let f = found
        .iter()
        .find(|f| f.path.ends_with(&k("3.9.25")))
        .unwrap();
    assert_eq!(f.action.kind, ActionKind::Command);
    assert_eq!(
        f.action.text,
        format!(
            "uv python uninstall --install-dir {} {}",
            root.display(),
            k("3.9.25")
        )
    );
    assert_eq!(
        f.recovery.how.as_deref(),
        Some(
            format!(
                "uv python install --install-dir {} {}",
                root.display(),
                k("3.9.25")
            )
            .as_str()
        )
    );
    assert!(
        f.recovery.cost.contains(&format!(
            "also removes {}",
            home.join(".local/bin/python3.9").display()
        )),
        "{}",
        f.recovery.cost
    );
    let g = found
        .iter()
        .find(|f| f.path.ends_with(&k("3.11.2")))
        .unwrap();
    assert!(
        !g.recovery.cost.contains("also removes"),
        "{}",
        g.recovery.cost
    );
}

#[test]
fn uv_default_shim_keeps_its_python() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = uv_root(home);
    let k = |v: &str| format!("cpython-{v}-linux-x86_64-gnu");
    for v in ["3.9.1", "3.10.1", "3.12.1"] {
        install(&root.join(k(v)));
    }
    symlink(
        root.join(k("3.10.1")),
        root.join("cpython-3.10-linux-x86_64-gnu"),
    )
    .unwrap();
    // `uv python install --default 3.10`: python3 runs 3.10 through the
    // minor-version link; python3.9 is only a versioned shim.
    let bin = home.join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    symlink(
        root.join("cpython-3.10-linux-x86_64-gnu/bin/python3.10"),
        bin.join("python3"),
    )
    .unwrap();
    symlink(
        root.join(k("3.9.1")).join("bin/python3.9"),
        bin.join("python3.9"),
    )
    .unwrap();
    let found = detect(home);
    assert_eq!(paths(&found), [s(&root.join(k("3.9.1")))]);
    assert!(
        found[0]
            .recovery
            .cost
            .contains(&format!("also removes {}", bin.join("python3.9").display())),
        "{}",
        found[0].recovery.cost
    );
}

/// uv installs 3.13.1, 3.14.0 and free-threaded 3.13.2 and 3.14.0, with
/// one project pinning `pin`.
fn uv_variants(pin: &str) -> (Vec<String>, impl Fn(&str) -> String) {
    let home = tempfile::tempdir().unwrap();
    let root = uv_root(home.path());
    let k = move |v: &str| s(&root.join(format!("cpython-{v}-linux-x86_64-gnu")));
    for v in [
        "3.13.1",
        "3.14.0",
        "3.13.2+freethreaded",
        "3.14.0+freethreaded",
    ] {
        install(Path::new(&k(v)));
    }
    text(
        &home.path().join("code/p/.python-version"),
        &format!("{pin}\n"),
    );
    (paths(&detect(home.path())), k)
}

#[test]
fn uv_python_pins_match_only_their_variant() {
    // uv resolves `3.13` to the plain build, `3.13t` to the free-threaded one.
    let (found, k) = uv_variants("3.13");
    assert_eq!(found, [k("3.13.2+freethreaded")]);
    let (found, k) = uv_variants("3.13t");
    assert_eq!(found, [k("3.13.1")]);
}

#[test]
fn pyenv_python_pins_match_only_their_variant() {
    for (pin, reported) in [("3.13", "3.13.2t"), ("3.13t", "3.13.1")] {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        let versions = home.join(".pyenv/versions");
        for v in ["3.13.1", "3.14.0", "3.13.2t", "3.14.0t"] {
            install(&versions.join(v));
        }
        text(&home.join("code/p/.python-version"), &format!("{pin}\n"));
        assert_eq!(paths(&detect(home)), [s(&versions.join(reported))], "{pin}");
    }
}

#[test]
fn pyenv_pypy_prefix_pin_keeps_the_matching_release() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let versions = home.join(".pyenv/versions");
    for v in ["pypy3.9-7.3.15", "pypy3.10-7.3.15", "3.12.1", "3.13-dev"] {
        install(&versions.join(v));
    }
    // pyenv resolves `pypy3.9` to the newest installed pypy3.9-*.
    text(&home.join("code/p/.python-version"), "pypy3.9\n3.12\n");
    assert_eq!(paths(&detect(home)), Vec::<String>::new());
}

#[test]
fn uv_key_pin_with_a_platform() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = uv_root(home);
    let k = |v: &str| root.join(format!("cpython-{v}-linux-x86_64-gnu"));
    for v in ["3.12.1", "3.12.4", "3.13.0"] {
        install(&k(v));
    }
    text(
        &home.join("code/p/.python-version"),
        "cpython-3.12-linux-x86_64-gnu\n",
    );
    assert_eq!(paths(&detect(home)), [s(&k("3.12.1"))]);
}

#[test]
fn uv_python_install_dir_from_env() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = home.join("pythons");
    install(&root.join("cpython-3.10.1-linux-x86_64-gnu"));
    install(&root.join("cpython-3.12.1-linux-x86_64-gnu"));
    // Not uv's: the default location is ignored when the variable is set.
    install(&uv_root(home).join("cpython-3.8.1-linux-x86_64-gnu"));
    install(&uv_root(home).join("cpython-3.9.1-linux-x86_64-gnu"));
    let found = detect_with(home, home, &[("UV_PYTHON_INSTALL_DIR", &s(&root))], &[]);
    assert_eq!(
        paths(&found),
        [s(&root.join("cpython-3.10.1-linux-x86_64-gnu"))]
    );
    assert_eq!(found[0].action.kind, ActionKind::RemovePath);
}

#[test]
fn pyenv_versions() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = home.join(".pyenv");
    for v in ["3.8.18", "3.10.13", "3.11.7", "3.12.1", "pypy3.10-7.3.15"] {
        install(&root.join("versions").join(v));
    }
    text(&root.join("version"), "3.10.13\n");
    // A pyenv-virtualenv env made from 3.11.7, inside its version dir.
    venv(
        &root.join("versions/3.11.7/envs/tools"),
        &root.join("versions/3.11.7/bin"),
    );
    let found = detect_with(home, home, &[], &[("pyenv", "/usr/bin/pyenv")]);
    assert_eq!(paths(&found), [s(&root.join("versions/3.8.18"))]);
    assert_eq!(found[0].action.text, "pyenv uninstall -f 3.8.18");
    assert_eq!(
        found[0].recovery.how.as_deref(),
        Some("pyenv install 3.8.18")
    );
}

#[test]
fn nvm_versions_and_aliases() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = home.join(".nvm");
    let v = |n: &str| root.join("versions/node").join(n);
    for n in [
        "v16.20.2", "v18.19.0", "v18.20.4", "v20.10.0", "v20.18.0", "v22.11.0", "v23.1.0",
    ] {
        install(&v(n));
    }
    // default -> lts/* -> lts/iron -> v20.18.0
    text(&root.join("alias/default"), "lts/*\n");
    text(&root.join("alias/lts/*"), "lts/iron\n");
    text(&root.join("alias/lts/iron"), "v20.18.0\n");
    // A user alias for 18 keeps the newest 18.
    text(&root.join("alias/old"), "18\n");
    // A project pin on 22.
    text(&home.join("code/web/.nvmrc"), "v22.11.0 # pinned\n");

    let found = detect(home);
    assert_eq!(
        paths(&found),
        [s(&v("v16.20.2")), s(&v("v18.19.0")), s(&v("v20.10.0"))]
    );
    let f = &found[0];
    assert_eq!(f.action.kind, ActionKind::RemovePath);
    assert_eq!(f.recovery.how.as_deref(), Some("nvm install v16.20.2"));
    assert!(f.recovery.cost.contains("globally"), "{}", f.recovery.cost);
}

#[test]
fn nvm_with_an_unresolvable_default_reports_nothing() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = home.join(".nvm");
    for n in ["v16.20.2", "v20.18.0"] {
        install(&root.join("versions/node").join(n));
    }
    text(&root.join("alias/default"), "lts/zzz\n");
    assert_eq!(paths(&detect(home)), Vec::<String>::new());
}

#[test]
fn nvm_project_lts_pin_without_an_alias_file_uses_the_codename() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = home.join(".nvm");
    let v = |n: &str| root.join("versions/node").join(n);
    for n in ["v20.18.0", "v22.10.0", "v22.11.0", "v23.1.0"] {
        install(&v(n));
    }
    text(&root.join("alias/default"), "23\n");
    // jod is the 22.x LTS line; nvm has no alias/lts/jod file here.
    text(&home.join("code/web/.nvmrc"), "lts/jod\n");
    assert_eq!(paths(&detect(home)), [s(&v("v20.18.0")), s(&v("v22.10.0"))]);
}

#[test]
fn fnm_versions_and_aliases() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = home.join(".local/share/fnm");
    let v = |n: &str| root.join("node-versions").join(n);
    for n in ["v18.20.4", "v20.18.0", "v21.7.3", "v22.11.0"] {
        install(&v(n).join("installation"));
    }
    fs::create_dir_all(root.join("aliases")).unwrap();
    symlink(
        v("v20.18.0").join("installation"),
        root.join("aliases/default"),
    )
    .unwrap();
    text(&home.join("code/x/.node-version"), "21\n");
    let found = detect_with(home, home, &[], &[("fnm", "/usr/bin/fnm")]);
    assert_eq!(paths(&found), [s(&v("v18.20.4"))]);
    assert_eq!(found[0].action.text, "fnm uninstall v18.20.4");
    assert_eq!(
        found[0].recovery.how.as_deref(),
        Some("fnm install v18.20.4")
    );
}

fn fnm_home(home: &Path, versions: &[&str]) -> PathBuf {
    let root = home.join(".local/share/fnm");
    for n in versions {
        install(&root.join("node-versions").join(n).join("installation"));
    }
    root.join("node-versions")
}

#[test]
fn fnm_lts_codename_pin() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let v = fnm_home(home, &["v18.20.4", "v20.17.0", "v20.18.0", "v23.1.0"]);
    // iron is the 20.x LTS line (nodejs.org release schedule).
    text(&home.join("code/x/.nvmrc"), "lts/Iron\n");
    assert_eq!(
        paths(&detect(home)),
        [s(&v.join("v18.20.4")), s(&v.join("v20.17.0"))]
    );
}

#[test]
fn fnm_lts_star_pin_keeps_the_newest_even_major() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let v = fnm_home(home, &["v18.20.4", "v20.18.0", "v22.11.0", "v23.1.0"]);
    text(&home.join("code/x/.nvmrc"), "lts/*\n");
    assert_eq!(
        paths(&detect(home)),
        [s(&v.join("v18.20.4")), s(&v.join("v20.18.0"))]
    );
}

#[test]
fn fnm_with_an_unknown_lts_codename_reports_nothing() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    fnm_home(home, &["v18.20.4", "v20.18.0", "v23.1.0"]);
    text(&home.join("code/x/.nvmrc"), "lts/zzz\n");
    text(&home.join("code/y/.nvmrc"), "20\n");
    assert_eq!(paths(&detect(home)), Vec::<String>::new());
}

#[test]
fn go_sdks() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let sdk = home.join("sdk");
    for n in ["go1.20.14", "go1.21.5", "go1.22.0", "go1.23.4"] {
        install(&sdk.join(n));
    }
    install(&sdk.join("android"));
    let go = s(&sdk.join("go1.21.5/bin/go"));
    let found = detect_with(home, home, &[], &[("go", &go)]);
    assert_eq!(
        paths(&found),
        [s(&sdk.join("go1.20.14")), s(&sdk.join("go1.22.0"))]
    );
    assert_eq!(found[0].action.kind, ActionKind::RemovePath);
    assert_eq!(
        found[0].recovery.how.as_deref(),
        Some("go install golang.org/dl/go1.20.14@latest && go1.20.14 download")
    );
}

#[test]
fn go_on_path_through_a_symlink_keeps_its_sdk() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let sdk = home.join("sdk");
    for n in ["go1.20.14", "go1.21.5", "go1.22.0"] {
        install(&sdk.join(n));
    }
    file(&sdk.join("go1.21.5/bin/go"), 10);
    fs::create_dir_all(home.join("bin")).unwrap();
    symlink(sdk.join("go1.21.5/bin/go"), home.join("bin/go")).unwrap();
    let found = detect_with(home, home, &[], &[("go", &s(&home.join("bin/go")))]);
    assert_eq!(paths(&found), [s(&sdk.join("go1.20.14"))]);
}

const C1: &str = "1111111111111111111111111111111111111111";
const C2: &str = "2222222222222222222222222222222222222222";
const C3: &str = "3333333333333333333333333333333333333333";

#[test]
fn vscode_servers_and_clis() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = home.join(".vscode-server");
    let servers = root.join("cli/servers");
    for c in [C1, C2, C3] {
        install(&servers.join(format!("Stable-{c}")));
        file(&root.join(format!("code-{c}")), 2 * MB);
    }
    install(&servers.join("not-a-server"));
    // C2 is the most recently used, although C3 is newer on disk.
    text(
        &servers.join("lru.json"),
        &format!("[\"Stable-{C2}\",\"Stable-{C3}\",\"Stable-{C1}\"]"),
    );
    let found = detect(home);
    assert_eq!(
        paths(&found),
        [
            s(&servers.join(format!("Stable-{C1}"))),
            s(&servers.join(format!("Stable-{C3}"))),
            s(&root.join(format!("code-{C1}"))),
            s(&root.join(format!("code-{C3}"))),
        ]
    );
    for f in &found {
        assert_eq!(f.action.kind, ActionKind::RemovePath);
        assert!(f.recovery.how.is_none());
        assert!(f.reason.contains(C2), "{}", f.reason);
        assert!(f.bytes >= 2 * MB as u64, "{}", f.bytes);
    }
}

#[test]
fn vscode_without_lru_keeps_the_newest() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let root = home.join(".vscode-server");
    let old = install(&root.join(format!("bin/{C1}")));
    install(&root.join(format!("bin/{C2}")));
    let t = SystemTime::now() - Duration::from_secs(30 * 86_400);
    for p in [old.join("bin/tool"), old.join("bin"), old.clone()] {
        fs::File::open(&p).unwrap().set_modified(t).unwrap();
    }
    assert_eq!(paths(&detect(home)), [s(&old)]);
}

#[test]
fn notes_unscanned_home_and_skips_small_versions() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let r = rustup_home(
        home,
        &tc("stable"),
        &[&tc("stable"), &tc("1.80.0"), &tc("1.81.0")],
    );
    // Too small to report.
    fs::create_dir_all(r.join("toolchains").join(tc("1.70.0"))).unwrap();
    // The pin is in a project outside the scan: not seen.
    text(
        &home.join("code/a/rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.80.0\"\n",
    );
    let found = detect_with(&r, home, &[], &[]);
    assert_eq!(paths(&found), [s(&r.join("toolchains").join(tc("1.80.0")))]);
    assert!(
        found[0]
            .recovery
            .cost
            .contains("home directory was not scanned"),
        "{}",
        found[0].recovery.cost
    );
}

#[test]
fn shell_quotes_paths() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path().join("it's home");
    let sdk = home.join("sdk");
    install(&sdk.join("go1.20.1"));
    install(&sdk.join("go1.21.1"));
    let found = detect(&home);
    assert_eq!(paths(&found), [s(&sdk.join("go1.20.1"))]);
    assert_eq!(
        found[0].action.text,
        format!(
            "remove '{}'",
            s(&sdk.join("go1.20.1")).replace('\'', r"'\''")
        )
    );
}

#[test]
fn run_with_via_the_registry() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let sdk = home.join("sdk");
    install(&sdk.join("go1.20.1"));
    install(&sdk.join("go1.21.1"));
    let tree = scan_tree(home);
    let only = vec!["tool-versions".to_string()];
    let (_, runs) = detect::run_with(&tree, &ctx(home, &[]), &registry(), Some(&only));
    let run = runs.iter().find(|r| r.name == "tool-versions").unwrap();
    assert!(run.ran);
    assert!(run.error.is_none());
}

#[test]
fn claude_code_versions_keep_current_and_newest() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let dir = home.join(".local/share/claude/versions");
    for v in ["2.1.9", "2.1.10", "2.1.11", "2.1.12"] {
        file(&dir.join(v), 2 * MB);
    }
    // The launcher runs 2.1.10, not the newest.
    fs::create_dir_all(home.join(".local/bin")).unwrap();
    symlink(dir.join("2.1.10"), home.join(".local/bin/claude")).unwrap();
    // A symlink and a non-version name are not versions.
    symlink(dir.join("2.1.12"), dir.join("2.1.8")).unwrap();
    file(&dir.join("notes"), 2 * MB);

    let found = detect(home);
    assert_eq!(
        paths(&found),
        [s(&dir.join("2.1.11")), s(&dir.join("2.1.9"))]
    );
    let f = &found[0];
    assert_eq!(f.tier, Tier::Rebuildable);
    assert_eq!(f.action.kind, ActionKind::RemovePath);
    assert_eq!(f.action.text, format!("remove {}", f.path));
    assert!(f.recovery.how.is_none());
    assert!(f.bytes >= 2 * MB as u64, "{}", f.bytes);
    assert!(
        f.reason.starts_with("Claude Code version 2.1.11 ("),
        "{}",
        f.reason
    );
    assert!(
        f.recovery.cost.contains("rolling back"),
        "{}",
        f.recovery.cost
    );
}

#[test]
fn codex_releases_follow_the_current_link_and_codex_home() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let ch = home.join("codex-home");
    let sa = ch.join("packages/standalone");
    let rel = |v: &str| {
        sa.join("releases")
            .join(format!("{v}-x86_64-unknown-linux-musl"))
    };
    for v in ["0.160.0", "0.167.2", "0.169.0"] {
        install(&rel(v));
    }
    symlink(rel("0.160.0"), sa.join("current")).unwrap();
    // Not Codex's when $CODEX_HOME points elsewhere.
    install(&home.join(".codex/packages/standalone/releases/0.1.0-x86_64-unknown-linux-musl"));
    install(&home.join(".codex/packages/standalone/releases/0.2.0-x86_64-unknown-linux-musl"));
    let found = detect_with(home, home, &[("CODEX_HOME", &s(&ch))], &[]);
    assert_eq!(paths(&found), [s(&rel("0.167.2"))]);
    assert!(
        found[0].reason.starts_with("Codex version 0.167.2-"),
        "{}",
        found[0].reason
    );
}

#[test]
fn t3_runtime_versions_compare_numerically() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let rt = home.join(".t3/runtime");
    let v = |n: &str| rt.join("versions").join(n);
    // 0.1.10 is newer than 0.1.9 even though it sorts first as text.
    for n in [
        "0.1.3-nightly.20261025.3682",
        "0.1.9-nightly.20261110.4500",
        "0.1.10-nightly.20261115.4749",
    ] {
        install(&v(n));
    }
    text(
        &rt.join("service-state.json"),
        "{\"protocol\":3,\"activeVersion\":\"0.1.3-nightly.20261025.3682\"}",
    );
    assert_eq!(paths(&detect(home)), [s(&v("0.1.9-nightly.20261110.4500"))]);
}
