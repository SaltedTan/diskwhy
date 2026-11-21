//! `venv` on temp-dir fixtures.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{self, DetectContext, Detector};
use dwhy_core::detectors::Venv;
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ActionKind, DockerSocket, Finding, Tier};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

const MB: usize = 1 << 20;

const UV_CFG: &str = "home = /opt/uv/python/cpython-3.12-linux-x86_64-gnu/bin\n\
implementation = CPython\nuv = 0.13.1\nversion_info = 3.12.4\n\
include-system-site-packages = false\n";
const VENV_CFG: &str = "home = /usr/bin\ninclude-system-site-packages = false\n\
version = 3.14.4\nexecutable = /usr/bin/python3.14\n";

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

fn ctx() -> DetectContext {
    DetectContext {
        uid: 1000,
        root: false,
        home: None,
        now: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        tools: vec![],
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: dwhy_core::docker::Source::none(),
        cancel: Default::default(),
    }
}

fn write(p: &Path, bytes: usize) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, vec![7u8; bytes]).unwrap();
}

fn tmp() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    (t, root)
}

/// A venv at `dir/name` with `cfg` and `mb` MiB of packages, next to the
/// given project files (a `pyproject.toml` declares a project). Returns the
/// venv path.
fn venv(dir: &Path, name: &str, cfg: &str, files: &[&str], mb: usize) -> PathBuf {
    let v = dir.join(name);
    write(
        &v.join("lib/python3.12/site-packages/numpy/core.so"),
        mb * MB,
    );
    fs::write(v.join("pyvenv.cfg"), cfg).unwrap();
    for f in files {
        let body = if *f == "pyproject.toml" {
            "[project]\nname = \"app\"\n"
        } else {
            "x"
        };
        fs::write(dir.join(f), body).unwrap();
    }
    v
}

fn findings_in(tree: &ScanTree) -> Vec<Finding> {
    let mut f = Venv.detect(tree, &ctx()).unwrap();
    f.sort_by(|a, b| a.path.cmp(&b.path));
    f
}

fn findings(root: &Path) -> Vec<Finding> {
    findings_in(&scan_tree(root))
}

fn paths(f: &[Finding]) -> Vec<&str> {
    f.iter().map(|f| f.path.as_str()).collect()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn how(f: &Finding) -> &str {
    f.recovery.how.as_deref().unwrap_or("<none>")
}

#[test]
fn finds_a_uv_project_venv() {
    let (_t, root) = tmp();
    let app = root.join("app");
    let v = venv(&app, ".venv", UV_CFG, &["pyproject.toml", "uv.lock"], 2);
    // uv writes CACHEDIR.TAG into its venvs: that must not hide the venv itself.
    fs::write(
        v.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    )
    .unwrap();

    let tree = scan_tree(&root);
    let found = findings_in(&tree);
    assert_eq!(paths(&found), [s(&v)]);
    let f = &found[0];
    assert_eq!(f.detector, "venv");
    assert_eq!(f.id, detect::finding_id("venv", &f.path));
    assert_eq!(f.tier, Tier::Rebuildable);
    let node = tree.node(tree.find(&v).unwrap());
    assert_eq!(f.bytes, node.freeable());
    assert_eq!(f.bytes, node.total.allocated);
    assert!(f.bytes >= 2 << 20);
    assert_eq!(f.action.kind, ActionKind::RemovePath);
    assert!(f.action.argv.is_none());
    assert_eq!(f.action.text, format!("remove {}", s(&v)));
    assert_eq!(how(f), format!("cd {} && uv sync", s(&app)));
    assert!(f.recovery.cost.contains("uv.lock"), "{}", f.recovery.cost);
    assert!(
        f.reason.starts_with(&format!(
            "Python virtualenv for {} (created by uv, Python 3.12; ",
            s(&app)
        )),
        "{}",
        f.reason
    );
    assert!(f.reason.contains("last written"), "{}", f.reason);
    assert!(f.guards.is_empty());
}

#[test]
fn matches_on_the_marker_not_the_name() {
    let (_t, root) = tmp();
    let a = venv(&root.join("a"), "env-py312", UV_CFG, &["uv.lock"], 2);
    let b = venv(&root.join("b"), "venv", VENV_CFG, &["requirements.txt"], 2);
    // Named like a venv, but no pyvenv.cfg.
    write(&root.join("c/.venv/lib/big"), 2 * MB);
    fs::write(root.join("c/uv.lock"), "x").unwrap();
    let found = findings(&root);
    assert_eq!(paths(&found), [s(&a), s(&b)]);
    // A venv not named .venv is pinned for uv sync.
    assert_eq!(
        how(&found[0]),
        format!(
            "cd {} && UV_PROJECT_ENVIRONMENT=env-py312 uv sync",
            s(&root.join("a"))
        )
    );
}

#[test]
fn recovery_follows_the_project_files() {
    let (_t, root) = tmp();
    let d = |n: &str| root.join(n);
    let cases: &[(&str, &str, &[&str], &str)] = &[
        ("uv", UV_CFG, &["uv.lock", "requirements.txt"], "uv sync"),
        (
            "poetry",
            VENV_CFG,
            &["poetry.lock", "pyproject.toml"],
            "POETRY_VIRTUALENVS_IN_PROJECT=true poetry install",
        ),
        ("pdm", VENV_CFG, &["pdm.lock"], "pdm install"),
        (
            "pipenv",
            VENV_CFG,
            &["Pipfile.lock"],
            "PIPENV_VENV_IN_PROJECT=1 pipenv sync",
        ),
        (
            "req-uv",
            UV_CFG,
            &["requirements.txt", "requirements-dev.txt"],
            "uv venv --python 3.12 .venv && uv pip install --python .venv -r requirements.txt",
        ),
        (
            "req-pip",
            VENV_CFG,
            &["requirements.txt"],
            "python3.14 -m venv .venv && .venv/bin/pip install -r requirements.txt",
        ),
        ("pyproject-uv", UV_CFG, &["pyproject.toml"], "uv sync"),
        (
            "pyproject-pip",
            VENV_CFG,
            &["pyproject.toml"],
            "python3.14 -m venv .venv && .venv/bin/pip install -e .",
        ),
        (
            "setup-py",
            VENV_CFG,
            &["setup.py"],
            "python3.14 -m venv .venv && .venv/bin/pip install -e .",
        ),
    ];
    for (name, cfg, files, _) in cases {
        venv(&d(name), ".venv", cfg, files, 2);
    }
    let found = findings(&root);
    assert_eq!(found.len(), cases.len());
    for (name, _, _, cmd) in cases {
        let f = found
            .iter()
            .find(|f| f.path == s(&d(name).join(".venv")))
            .unwrap();
        assert_eq!(f.tier, Tier::Rebuildable, "{name}");
        assert_eq!(how(f), format!("cd {} && {cmd}", s(&d(name))), "{name}");
    }
    let req = found
        .iter()
        .find(|f| f.path == s(&d("req-uv").join(".venv")))
        .unwrap();
    assert!(
        req.recovery
            .cost
            .contains("also next to it: requirements-dev.txt"),
        "{}",
        req.recovery.cost
    );
    let fresh = found
        .iter()
        .find(|f| f.path == s(&d("pyproject-uv").join(".venv")))
        .unwrap();
    assert!(
        fresh.recovery.cost.contains("no uv.lock"),
        "{}",
        fresh.recovery.cost
    );
}

#[test]
fn lockfile_venvs_not_named_dot_venv_are_recreated_and_installed_with_virtual_env() {
    let (_t, root) = tmp();
    // Run as is, Poetry and Pipenv install into their central env and pdm into
    // .venv: the venv is recreated at its own path and made active instead.
    let p = venv(&root.join("p"), "venv", VENV_CFG, &["poetry.lock"], 2);
    let e = venv(&root.join("e"), "env", VENV_CFG, &["Pipfile.lock"], 2);
    let d = venv(&root.join("d"), "venv", UV_CFG, &["pdm.lock"], 2);
    let found = findings(&root);
    assert_eq!(paths(&found), [s(&d), s(&e), s(&p)]);
    let expect = [
        (
            &d,
            "pdm",
            "uv venv --python 3.12 venv && VIRTUAL_ENV={} pdm install",
        ),
        (
            &e,
            "pipenv",
            "python3.14 -m venv env && VIRTUAL_ENV={} pipenv sync",
        ),
        (
            &p,
            "poetry",
            "python3.14 -m venv venv && VIRTUAL_ENV={} poetry install",
        ),
    ];
    for (f, (v, tool, cmd)) in found.iter().zip(expect) {
        assert_eq!(f.tier, Tier::Rebuildable, "{}", f.path);
        assert_eq!(
            how(f),
            format!(
                "cd {} && {}",
                s(v.parent().unwrap()),
                cmd.replace("{}", s(v))
            )
        );
        assert!(
            f.recovery
                .cost
                .contains(&format!("relies on {tool} using the active venv")),
            "{}",
            f.recovery.cost
        );
    }
}

#[test]
fn a_setup_cfg_with_metadata_is_a_project() {
    let (_t, root) = tmp();
    let build = "[build-system]\nrequires = [\"setuptools\"]\n";
    let pip_e = "python3.14 -m venv .venv && .venv/bin/pip install -e .";
    for (dir, cfg) in [
        ("metadata", "[metadata]\nname = app\n"),
        ("options", "[options]\ninstall_requires =\n    requests\n"),
    ] {
        venv(&root.join(dir), ".venv", VENV_CFG, &[], 2);
        fs::write(root.join(dir).join("pyproject.toml"), build).unwrap();
        fs::write(root.join(dir).join("setup.cfg"), cfg).unwrap();
    }
    // Only tool settings in setup.cfg, and old flit metadata: not a project.
    // Nor is a setup.cfg alone: pip needs a setup.py or pyproject.toml to build.
    let lone = venv(&root.join("lone-cfg"), "venv", VENV_CFG, &[], 2);
    fs::write(root.join("lone-cfg/setup.cfg"), "[metadata]\nname = app\n").unwrap();
    let lint = venv(&root.join("lint-only"), ".venv", VENV_CFG, &[], 2);
    fs::write(
        root.join("lint-only/setup.cfg"),
        "[flake8]\nmax-line-length = 100\n",
    )
    .unwrap();
    let flit = venv(&root.join("old-flit"), ".venv", VENV_CFG, &[], 2);
    fs::write(
        root.join("old-flit/pyproject.toml"),
        "[tool.flit.metadata]\nmodule = \"app\"\n",
    )
    .unwrap();

    let found = findings(&root);
    assert_eq!(found.len(), 5);
    for f in &found {
        let dir = Path::new(&f.path).parent().unwrap();
        if [s(&lint), s(&flit), s(&lone)].contains(&f.path.as_str()) {
            assert_eq!(f.tier, Tier::Review, "{}", f.path);
            assert!(how(f).ends_with("/bin/python -m pip freeze"), "{}", how(f));
        } else {
            assert_eq!(f.tier, Tier::Rebuildable, "{}", f.path);
            assert_eq!(how(f), format!("cd {} && {pip_e}", s(dir)));
        }
    }
}

#[test]
fn a_pyproject_that_only_configures_tools_is_not_a_project() {
    let (_t, root) = tmp();
    let ruff = "[tool.ruff]\nline-length = 100\n\n[tool.mypy]\nstrict = true\n";
    // uv sync would fail with no [project] table: the packages were added by hand.
    let a = venv(&root.join("tool-config"), ".venv", UV_CFG, &[], 2);
    fs::write(root.join("tool-config/pyproject.toml"), ruff).unwrap();
    // With setup.py next to it, that describes the project.
    let b = venv(
        &root.join("with-setup"),
        ".venv",
        VENV_CFG,
        &["setup.py"],
        2,
    );
    fs::write(root.join("with-setup/pyproject.toml"), ruff).unwrap();
    // Poetry 1 declares the project in [tool.poetry].
    let c = venv(&root.join("poetry1"), ".venv", VENV_CFG, &[], 2);
    fs::write(
        root.join("poetry1/pyproject.toml"),
        "[build-system]\nrequires = [\"poetry-core\"]\n\n[ tool . poetry ]  # metadata\nname = \"x\"\n",
    )
    .unwrap();

    let found = findings(&root);
    assert_eq!(paths(&found), [s(&c), s(&a), s(&b)]);
    assert_eq!(found[1].tier, Tier::Review);
    assert_eq!(how(&found[1]), format!("uv pip freeze --python {}", s(&a)));
    let pip_e = "python3.14 -m venv .venv && .venv/bin/pip install -e .";
    for (f, dir) in [(&found[0], "poetry1"), (&found[2], "with-setup")] {
        assert_eq!(f.tier, Tier::Rebuildable, "{}", f.path);
        assert_eq!(how(f), format!("cd {} && {pip_e}", s(&root.join(dir))));
    }
}

#[test]
fn central_tool_envs_are_review_without_a_command() {
    let (_t, root) = tmp();
    let poetry = venv(
        &root.join(".cache/pypoetry/virtualenvs"),
        "app-AbCd1234-py3.12",
        VENV_CFG,
        &[],
        2,
    );
    let pipenv = venv(
        &root.join(".local/share/virtualenvs"),
        "app-AbCd1234",
        VENV_CFG,
        &[],
        2,
    );
    let hatch = venv(
        &root.join(".local/share/hatch/env/virtual/app/AbCd1234"),
        "app",
        VENV_CFG,
        &[],
        2,
    );
    let found = findings(&root);
    assert_eq!(paths(&found), [s(&poetry), s(&hatch), s(&pipenv)]);
    for (f, tool, cmd) in [
        (&found[0], "Poetry", "poetry install"),
        (&found[1], "Hatch", "hatch env create"),
        (&found[2], "Pipenv", "pipenv sync"),
    ] {
        assert_eq!(f.tier, Tier::Review, "{}", f.path);
        assert_eq!(f.recovery.how, None, "{}", f.path);
        assert!(
            f.reason
                .starts_with(&format!("{tool}-managed Python virtualenv in ")),
            "{}",
            f.reason
        );
        assert!(f.recovery.cost.contains(cmd), "{}", f.recovery.cost);
        assert!(!f.recovery.cost.contains("by hand"), "{}", f.recovery.cost);
    }
}

#[test]
fn tox_and_nox_envs_are_recreated_without_running_tests() {
    let (_t, root) = tmp();
    let app = root.join("my app");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("tox.ini"), "[tox]\nenv_list = py312\n").unwrap();
    // `docs` is outside env_list: a bare `tox` would not rebuild it.
    let docs = venv(&app.join(".tox"), "docs", VENV_CFG, &[], 2);
    // tox's internal envs are not run envs: `-e` cannot rebuild them.
    let pkg = venv(&app.join(".tox"), ".pkg", VENV_CFG, &[], 2);
    let wheel = venv(&app.join(".tox"), ".pkg-cpython312", VENV_CFG, &[], 2);
    let nox = venv(&app.join(".nox"), "tests-3-12", VENV_CFG, &[], 2);
    let found = findings(&root);
    assert_eq!(paths(&found), [s(&nox), s(&pkg), s(&wheel), s(&docs)]);
    assert!(
        found[0].recovery.cost.contains("default sessions"),
        "{}",
        found[0].recovery.cost
    );
    for (f, tool, cmd) in [
        (&found[0], "nox", "nox --install-only"),
        (&found[1], "tox", "tox --notest"),
        (&found[2], "tox", "tox --notest"),
        (&found[3], "tox", "tox -e docs --notest"),
    ] {
        assert_eq!(f.tier, Tier::Rebuildable, "{}", f.path);
        assert_eq!(how(f), format!("cd '{}' && {cmd}", s(&app)));
        assert!(
            f.recovery.cost.contains("without running"),
            "{}",
            f.recovery.cost
        );
        assert!(
            f.reason
                .starts_with(&format!("{tool} environment for {}", s(&app))),
            "{}",
            f.reason
        );
        assert!(!f.recovery.cost.contains("by hand"), "{}", f.recovery.cost);
    }
}

#[test]
fn uv_sync_needs_a_project_table() {
    let (_t, root) = tmp();
    // Poetry 1 metadata only: uv sync would fail with no [project] table.
    let v = venv(&root.join("app"), ".venv", UV_CFG, &[], 2);
    fs::write(
        root.join("app/pyproject.toml"),
        "[build-system]\nrequires = [\"poetry-core\"]\n\n[tool.poetry]\nname = \"app\"\n",
    )
    .unwrap();
    let found = findings(&root);
    assert_eq!(paths(&found), [s(&v)]);
    assert_eq!(found[0].tier, Tier::Rebuildable);
    assert_eq!(
        how(&found[0]),
        format!(
            "cd {} && uv venv --python 3.12 .venv && uv pip install --python .venv -e .",
            s(&root.join("app"))
        )
    );
}

#[test]
fn ambiguous_project_files_give_no_command() {
    let (_t, root) = tmp();
    let a = venv(
        &root.join("two-locks"),
        ".venv",
        UV_CFG,
        &["uv.lock", "poetry.lock"],
        2,
    );
    let b = venv(
        &root.join("variants"),
        ".venv",
        VENV_CFG,
        &["requirements-gpu.txt", "requirements-cpu.txt"],
        2,
    );
    let found = findings(&root);
    assert_eq!(paths(&found), [s(&a), s(&b)]);
    for f in &found {
        assert_eq!(f.tier, Tier::Rebuildable);
        assert_eq!(f.recovery.how, None, "{}", f.path);
    }
    assert!(
        found[0]
            .recovery
            .cost
            .contains("lockfiles for uv and poetry")
    );
    assert!(
        found[1]
            .recovery
            .cost
            .contains("requirements-cpu.txt, requirements-gpu.txt"),
        "{}",
        found[1].recovery.cost
    );
}

#[test]
fn a_venv_with_no_project_file_is_review_with_a_freeze_hint() {
    let (_t, root) = tmp();
    let uv = venv(&root.join("audition"), "metrics-env", UV_CFG, &[], 2);
    let plain = venv(&root.join("tools/lint"), "venv", VENV_CFG, &[], 2);
    let found = findings(&root);
    assert_eq!(paths(&found), [s(&uv), s(&plain)]);
    for f in &found {
        assert_eq!(f.tier, Tier::Review, "{}", f.path);
        assert!(
            f.reason.contains("with no project file next to it"),
            "{}",
            f.reason
        );
        assert!(f.recovery.cost.contains("record them first"));
    }
    assert_eq!(how(&found[0]), format!("uv pip freeze --python {}", s(&uv)));
    assert_eq!(
        how(&found[1]),
        format!("{}/bin/python -m pip freeze", s(&plain))
    );
    assert!(found[1].recovery.cost.contains("Python 3.14"));
}

#[test]
fn ignores_lookalikes_caches_and_tool_envs() {
    let (_t, root) = tmp();
    let tag = "Signature: 8a477f597d28d172789f06886806bc55\n";
    // uv's cache holds ephemeral envs (uvx, uv run --with); user-cache reports it.
    let cache = root.join("cache/uv");
    write(&cache.join("CACHEDIR.TAG"), 0);
    fs::write(cache.join("CACHEDIR.TAG"), tag).unwrap();
    venv(
        &cache.join("archive-v0"),
        "SkC4E9GUvXAe37kG",
        UV_CFG,
        &[],
        2,
    );
    // Installed tools.
    venv(&root.join("share/uv/tools"), "ruff", UV_CFG, &[], 2);
    venv(&root.join("share/pipx/venvs"), "black", VENV_CFG, &[], 2);
    venv(&root.join("share/pipx"), "shared", VENV_CFG, &[], 2);
    venv(
        &root.join("share/pipx/.cache"),
        "0123abcd",
        VENV_CFG,
        &[],
        2,
    );
    // pyvenv.cfg as a symlink or a directory: not a marker.
    let sym = venv(&root.join("sym"), ".venv", UV_CFG, &["uv.lock"], 2);
    fs::remove_file(sym.join("pyvenv.cfg")).unwrap();
    symlink(root.join("real/.venv/pyvenv.cfg"), sym.join("pyvenv.cfg")).unwrap();
    let dir = venv(&root.join("dircfg"), ".venv", UV_CFG, &["uv.lock"], 2);
    fs::remove_file(dir.join("pyvenv.cfg")).unwrap();
    fs::create_dir(dir.join("pyvenv.cfg")).unwrap();
    // A symlinked venv: never followed.
    let real = venv(&root.join("real"), ".venv", UV_CFG, &["uv.lock"], 2);
    fs::create_dir_all(root.join("linked")).unwrap();
    symlink(&real, root.join("linked/.venv")).unwrap();
    // Too small.
    venv(&root.join("tiny"), ".venv", UV_CFG, &["uv.lock"], 0);

    assert_eq!(paths(&findings(&root)), [s(&real)]);
}

#[test]
fn a_cache_above_the_scan_root_still_hides_its_envs() {
    let (_t, root) = tmp();
    let cache = root.join("uv-cache");
    write(&cache.join("CACHEDIR.TAG"), 10);
    let env = venv(&cache.join("archive-v0"), "abc", UV_CFG, &[], 2);
    assert!(findings(&cache.join("archive-v0")).is_empty());
    assert!(findings(&env).is_empty());
}

#[test]
fn a_venv_scanned_as_the_root_reads_its_project_from_disk() {
    let (_t, root) = tmp();
    let app = root.join("app");
    let v = venv(&app, ".venv", UV_CFG, &["uv.lock"], 2);
    let found = findings(&v);
    assert_eq!(paths(&found), [s(&v)]);
    assert_eq!(how(&found[0]), format!("cd {} && uv sync", s(&app)));
}

#[test]
fn only_the_outermost_venv_is_reported() {
    let (_t, root) = tmp();
    let outer = venv(&root.join("app"), ".venv", UV_CFG, &["uv.lock"], 2);
    // A package that vendors a venv (e.g. test fixtures) inside site-packages.
    venv(
        &outer.join("lib/python3.12/site-packages/pkg"),
        "venv",
        VENV_CFG,
        &[],
        2,
    );
    assert_eq!(paths(&findings(&root)), [s(&outer)]);
    // Scanning inside the outer venv does not surface the vendored one.
    assert!(findings(&outer.join("lib")).is_empty());
}

#[test]
fn bytes_hardlinked_from_the_uv_cache_are_not_freeable() {
    for cache in ["zz-uv-cache", "a-uv-cache"] {
        let (_t, root) = tmp();
        let v = venv(&root.join("app"), ".venv", UV_CFG, &["uv.lock"], 2);
        let blob = root.join(cache).join("archive-v0/x/torch.so");
        write(&blob, 3 * MB);
        fs::hard_link(&blob, v.join("lib/python3.12/site-packages/torch.so")).unwrap();
        // Linked only inside the venv: freed.
        let inner = v.join("lib/python3.12/site-packages/a.so");
        write(&inner, MB);
        fs::hard_link(&inner, v.join("lib/python3.12/site-packages/b.so")).unwrap();

        let tree = scan_tree(&root);
        let node = tree.node(tree.find(&v).unwrap());
        let found = findings_in(&tree);
        assert_eq!(paths(&found), [s(&v)], "{cache}");
        let f = &found[0];
        assert_eq!(f.bytes, node.freeable());
        assert!(
            f.bytes >= 3 << 20 && f.bytes < 4 << 20,
            "{cache}: bytes = {}",
            f.bytes
        );
        if cache.starts_with("zz") {
            assert!(node.shared >= 3 << 20 && node.shared < 4 << 20);
            assert!(
                f.reason.contains("more is hardlinked elsewhere"),
                "{}",
                f.reason
            );
        } else {
            assert_eq!(node.shared, 0);
        }
    }
}

#[test]
fn quotes_paths_in_text() {
    let (_t, root) = tmp();
    let app = root.join("my app $(x)");
    let v = venv(&app, "my env", VENV_CFG, &["requirements.txt"], 2);
    let f = findings(&root);
    assert_eq!(f[0].action.text, format!("remove '{}'", s(&v)));
    assert_eq!(
        how(&f[0]),
        format!(
            "cd '{}' && python3.14 -m venv 'my env' && 'my env'/bin/pip install -r requirements.txt",
            s(&app)
        )
    );
}

#[test]
fn run_includes_venv() {
    let (_t, root) = tmp();
    let v = venv(&root.join("app"), ".venv", UV_CFG, &["uv.lock"], 2);
    let tree = scan_tree(&root);
    let only = vec!["venv".to_string()];
    let (found, runs) = detect::run_with(
        &tree,
        &ctx(),
        &dwhy_core::detectors::registry(),
        Some(&only),
    );
    assert_eq!(paths(&found), [s(&v)]);
    let run = runs.iter().find(|r| r.name == "venv").unwrap();
    assert!(run.ran);
    assert_eq!(run.findings, 1);
}
