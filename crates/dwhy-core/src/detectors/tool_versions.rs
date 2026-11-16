//! `tool-versions`: toolchain and runtime versions nothing uses any more.
//!
//! Looks at what version managers installed, when their directory is in the
//! scan:
//!
//! - rustup toolchains (`$RUSTUP_HOME`, default `~/.rustup`)
//! - uv-managed Pythons (`$UV_PYTHON_INSTALL_DIR`, default
//!   `~/.local/share/uv/python`) and pyenv versions (`$PYENV_ROOT`, default
//!   `~/.pyenv`)
//! - nvm (`$NVM_DIR`, default `~/.nvm`) and fnm (`$FNM_DIR`, default
//!   `~/.local/share/fnm`) Node versions
//! - Go SDKs from `golang.org/dl` (`~/sdk/go*`)
//! - VS Code Server versions (`~/.vscode-server`, `~/.vscode-server-insiders`,
//!   or `$VSCODE_AGENT_FOLDER`)
//!
//! A version is kept, and not reported, when it is the tool's default, is
//! pinned by a project in the scan (`rust-toolchain.toml`, `rust-toolchain`,
//! `.python-version`, `.nvmrc`, `.node-version`) or a rustup override, is the
//! Python a scanned venv was made from, or is the newest one installed of its
//! kind. A pin like `3.12` or `20` keeps the newest matching version, which is
//! what the tools resolve it to. For VS Code Server the most recently used
//! server (first in `cli/servers/lru.json`) and its `code-<commit>` CLI are
//! kept. Go toolchains that `GOTOOLCHAIN` downloads live in the module cache,
//! which `user-cache` reports.
//!
//! Everything reported is `rebuildable`: the version can be installed again.
//! The action is the tool's own uninstall command when the tool was found
//! (`rustup toolchain uninstall`, `uv python uninstall`, `pyenv uninstall`,
//! `fnm uninstall`), else a removal limited to that version's directory; nvm
//! (a shell function), Go SDKs and VS Code Server have no command and are
//! always removed by path. When the home directory is not in the scan, pins
//! and venvs in projects there were not seen, which the recovery cost says.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::detect::{DetectContext, Detector, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, Recovery, Tier};
use crate::tree::{Markers, NodeId, ScanTree};
use crate::units::human;

use super::read_head;

/// Versions smaller than this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// Largest pin, settings or `pyvenv.cfg` file read.
const MAX_SMALL_FILE: usize = 64 << 10;

/// `tool-versions`. Holds the environment it resolves install locations from.
pub struct ToolVersions {
    env: HashMap<String, String>,
}

/// Version pins found in the scanned projects.
#[derive(Default)]
struct Pins {
    rust: Vec<String>,
    python: Vec<String>,
    node: Vec<String>,
    /// Interpreter paths (`home`, `executable`) from scanned `pyvenv.cfg`.
    venv_pythons: Vec<PathBuf>,
}

/// One installed version.
struct Install {
    name: String,
    path: PathBuf,
    bytes: u64,
    shared: u64,
    newest_mtime: i64,
    /// Versions of the same group are comparable; the newest one is kept.
    group: Option<(String, Vec<u64>)>,
}

impl Install {
    fn from_node(tree: &ScanTree, id: NodeId, group: Option<(String, Vec<u64>)>) -> Install {
        let n = tree.node(id);
        Install {
            name: tree.name(id).to_string_lossy().into_owned(),
            path: tree.path(id),
            bytes: n.freeable(),
            shared: n.shared,
            newest_mtime: n.newest_mtime,
            group,
        }
    }
}

/// How a reported version is removed and reinstalled.
struct Plan {
    what: String,
    why: String,
    action: Action,
    cost: String,
    how: Option<String>,
}

impl Detector for ToolVersions {
    fn name(&self) -> &'static str {
        "tool-versions"
    }

    fn detect(&self, tree: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let pins = collect_pins(tree);
        let home_scanned = ctx.home.as_deref().is_some_and(|h| tree.find(h).is_some());
        let mut out = Vec::new();
        self.rustup(tree, ctx, &pins, home_scanned, &mut out);
        self.uv_python(tree, ctx, &pins, home_scanned, &mut out);
        self.pyenv(tree, ctx, &pins, home_scanned, &mut out);
        self.nvm(tree, ctx, &pins, home_scanned, &mut out);
        self.fnm(tree, ctx, &pins, home_scanned, &mut out);
        self.go_sdk(tree, ctx, &mut out);
        self.vscode(tree, ctx, &mut out);
        Ok(out)
    }
}

impl ToolVersions {
    /// Reads the process environment.
    pub fn from_system() -> ToolVersions {
        ToolVersions::with_env(std::env::vars_os())
    }

    /// Uses the given variables instead of the process environment.
    /// Pairs whose name or value is not UTF-8 are skipped.
    pub fn with_env<I, K, V>(vars: I) -> ToolVersions
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        ToolVersions {
            env: vars
                .into_iter()
                .filter_map(|(k, v)| {
                    Some((k.into().into_string().ok()?, v.into().into_string().ok()?))
                })
                .collect(),
        }
    }

    /// An absolute path from `$name`; relative or empty values are ignored.
    fn var(&self, name: &str) -> Option<PathBuf> {
        let v = self.env.get(name)?;
        let p = Path::new(v);
        p.is_absolute().then(|| p.to_path_buf())
    }

    /// `$name`, else `rel` under the home directory.
    fn dir(&self, ctx: &DetectContext, name: &str, rel: &str) -> Option<PathBuf> {
        self.var(name)
            .or_else(|| ctx.home.as_ref().map(|h| h.join(rel)))
    }

    fn xdg_data(&self, ctx: &DetectContext) -> Option<PathBuf> {
        self.var("XDG_DATA_HOME")
            .or_else(|| ctx.home.as_ref().map(|h| h.join(".local/share")))
    }

    /// `env NAME=<value> ` prefix for a command, when `$name` was set.
    fn env_prefix(&self, name: &str) -> Vec<String> {
        match self.var(name) {
            Some(v) => vec!["env".into(), format!("{name}={}", v.display())],
            None => Vec::new(),
        }
    }

    fn rustup(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
        pins: &Pins,
        home_scanned: bool,
        out: &mut Vec<Finding>,
    ) {
        let Some(root) = self.dir(ctx, "RUSTUP_HOME", ".rustup") else {
            return;
        };
        let installs = installs_in(tree, &root.join("toolchains"), rust_group);
        if installs.is_empty() {
            return;
        }
        let settings = read_text(&root.join("settings.toml")).unwrap_or_default();
        let (default, overrides) = rustup_settings(&settings);
        let mut requests: Vec<&str> = pins.rust.iter().map(String::as_str).collect();
        requests.extend(overrides.iter().map(String::as_str));
        let mut keep = newest(&installs);
        for (i, t) in installs.iter().enumerate() {
            if default
                .as_deref()
                .is_some_and(|d| channel_matches(&t.name, d))
                || requests.iter().any(|r| channel_matches(&t.name, r))
            {
                keep.insert(i);
            }
        }
        let rustup = ctx.tool_command("rustup");
        for (i, t) in installs.iter().enumerate() {
            if keep.contains(&i) {
                continue;
            }
            let pre = self.env_prefix("RUSTUP_HOME");
            let cmd = |verb: &str| {
                let mut v = pre.clone();
                v.push(rustup.clone().unwrap_or_else(|| "rustup".into()));
                v.extend(["toolchain".into(), verb.into(), t.name.clone()]);
                v
            };
            let mut cost = "rustup downloads and installs the toolchain again; components added to it since (rust-src, rust-analyzer, other targets) need adding again".to_string();
            if !home_scanned {
                cost.push_str(PINS_NOTE);
            }
            let why = format!(
                "not the default ({}), not pinned by a rust-toolchain file or rustup override in the scan, and not the newest of its kind",
                default.as_deref().unwrap_or("none set")
            );
            out.extend(self.finding(
                t,
                Plan {
                    what: format!("Rust toolchain {}", t.name),
                    why,
                    action: command_or_remove(rustup.is_some().then(|| cmd("uninstall")), t),
                    cost,
                    how: Some(join_argv(&cmd("install"))),
                },
            ));
        }
    }

    fn uv_python(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
        pins: &Pins,
        home_scanned: bool,
        out: &mut Vec<Finding>,
    ) {
        let Some(root) = self
            .var("UV_PYTHON_INSTALL_DIR")
            .or_else(|| self.xdg_data(ctx).map(|d| d.join("uv/python")))
        else {
            return;
        };
        let installs = installs_in(tree, &root, uv_group);
        if installs.is_empty() {
            return;
        }
        // Minor-version links (cpython-3.12-linux-x86_64-gnu -> the newest
        // 3.12 install), which venvs made by recent uv versions point at.
        let links = symlinks_in(&root);
        let mut keep = newest(&installs);
        for p in &pins.venv_pythons {
            let Ok(rest) = p.strip_prefix(&root) else {
                continue;
            };
            let Some(first) = rest.components().next() else {
                continue;
            };
            let name = first.as_os_str().to_string_lossy();
            let target = links
                .get(name.as_ref())
                .map_or(name.as_ref(), String::as_str);
            if let Some(i) = installs.iter().position(|t| t.name == target) {
                keep.insert(i);
            }
        }
        let mut requests = pins.python.clone();
        let global_pin = self
            .var("XDG_CONFIG_HOME")
            .or_else(|| ctx.home.as_ref().map(|h| h.join(".config")))
            .map(|c| c.join("uv/.python-version"));
        if let Some(text) = global_pin.as_deref().and_then(read_text) {
            requests.extend(python_pin_lines(&text));
        }
        keep.extend(resolve_python(&installs, &requests, "cpython"));

        let uv = ctx.tool_command("uv");
        let shims = self.uv_shims(ctx, &root);
        for (i, t) in installs.iter().enumerate() {
            if keep.contains(&i) {
                continue;
            }
            let root_s = root.to_string_lossy().into_owned();
            let cmd = |verb: &str| {
                vec![
                    uv.clone().unwrap_or_else(|| "uv".into()),
                    "python".into(),
                    verb.into(),
                    "--install-dir".into(),
                    root_s.clone(),
                    t.name.clone(),
                ]
            };
            let mut cost =
                "uv downloads the Python build again when you install it or a project asks for it"
                    .to_string();
            let mine: Vec<&String> = shims
                .iter()
                .filter(|(_, target)| {
                    target == &t.name || links.get(target.as_str()) == Some(&t.name)
                })
                .map(|(shim, _)| shim)
                .collect();
            if !mine.is_empty() {
                cost.push_str(&format!(
                    "; uninstalling also removes {}, which runs it",
                    mine.iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !home_scanned {
                cost.push_str(PINS_NOTE);
            }
            out.extend(self.finding(
                t,
                Plan {
                    what: format!("uv-managed Python {}", t.name),
                    why: "no venv in the scan was made from it, no .python-version in the scan pins it, and it is not the newest of its kind".into(),
                    action: command_or_remove(uv.is_some().then(|| cmd("uninstall")), t),
                    cost,
                    how: Some(join_argv(&cmd("install"))),
                },
            ));
        }
    }

    /// `python*` links in uv's executable directory: (link path, name of
    /// the install or minor-version link it points into).
    fn uv_shims(&self, ctx: &DetectContext, root: &Path) -> Vec<(String, String)> {
        let Some(bin) = self
            .var("UV_PYTHON_BIN_DIR")
            .or_else(|| self.var("XDG_BIN_HOME"))
            .or_else(|| ctx.home.as_ref().map(|h| h.join(".local/bin")))
        else {
            return Vec::new();
        };
        let Ok(rd) = std::fs::read_dir(&bin) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for e in rd.flatten() {
            if !e.file_name().to_string_lossy().starts_with("python") {
                continue;
            }
            let Ok(target) = std::fs::read_link(e.path()) else {
                continue;
            };
            if let Ok(rest) = target.strip_prefix(root)
                && let Some(first) = rest.components().next()
            {
                out.push((
                    e.path().to_string_lossy().into_owned(),
                    first.as_os_str().to_string_lossy().into_owned(),
                ));
            }
        }
        out.sort();
        out
    }

    fn pyenv(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
        pins: &Pins,
        home_scanned: bool,
        out: &mut Vec<Finding>,
    ) {
        let Some(root) = self.dir(ctx, "PYENV_ROOT", ".pyenv") else {
            return;
        };
        let versions = root.join("versions");
        let installs = installs_in(tree, &versions, plain_group);
        if installs.is_empty() {
            return;
        }
        let mut keep = newest(&installs);
        let mut requests = pins.python.clone();
        if let Some(text) = read_text(&root.join("version")) {
            requests.extend(python_pin_lines(&text));
        }
        for (i, t) in installs.iter().enumerate() {
            if requests.iter().any(|r| r == &t.name)
                || pins.venv_pythons.iter().any(|p| p.starts_with(&t.path))
            {
                keep.insert(i);
            }
        }
        keep.extend(resolve_python(&installs, &requests, ""));

        let pyenv = ctx.tool_command("pyenv");
        for (i, t) in installs.iter().enumerate() {
            if keep.contains(&i) {
                continue;
            }
            let pre = self.env_prefix("PYENV_ROOT");
            let cmd = |args: &[&str]| {
                let mut v = pre.clone();
                v.push(pyenv.clone().unwrap_or_else(|| "pyenv".into()));
                v.extend(args.iter().map(|s| s.to_string()));
                v.push(t.name.clone());
                v
            };
            let mut cost = "pyenv builds this Python from source again, which takes minutes and needs the build dependencies".to_string();
            if !home_scanned {
                cost.push_str(PINS_NOTE);
            }
            out.extend(self.finding(
                t,
                Plan {
                    what: format!("pyenv Python {}", t.name),
                    why: "not the global version, no venv in the scan was made from it, no .python-version in the scan pins it, and it is not the newest of its kind".into(),
                    action: command_or_remove(
                        pyenv.is_some().then(|| cmd(&["uninstall", "-f"])),
                        t,
                    ),
                    cost,
                    how: Some(join_argv(&cmd(&["install"]))),
                },
            ));
        }
    }

    fn nvm(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
        pins: &Pins,
        home_scanned: bool,
        out: &mut Vec<Finding>,
    ) {
        let Some(root) = self.dir(ctx, "NVM_DIR", ".nvm") else {
            return;
        };
        let installs = installs_in(tree, &root.join("versions/node"), node_group);
        if installs.is_empty() {
            return;
        }
        let alias_dir = root.join("alias");
        let mut keep = newest(&installs);
        // The default must resolve, or nothing is reported: it is the
        // version every new shell uses.
        if let Some(default) = read_text(&alias_dir.join("default")) {
            match nvm_resolve(&installs, &alias_dir, default.trim(), 0) {
                Some(r) => keep.extend(r),
                None => return,
            }
        }
        let mut requests: Vec<String> = pins.node.clone();
        if let Ok(rd) = std::fs::read_dir(&alias_dir) {
            for e in rd.flatten() {
                if e.file_type().is_ok_and(|t| t.is_file())
                    && let Some(text) = read_text(&e.path())
                {
                    requests.push(text.trim().to_string());
                }
            }
        }
        for r in &requests {
            keep.extend(nvm_resolve(&installs, &alias_dir, r, 0).unwrap_or_default());
        }
        for (i, t) in installs.iter().enumerate() {
            if keep.contains(&i) {
                continue;
            }
            let mut cost = "nvm downloads that Node version again; npm packages installed globally under it are not reinstalled".to_string();
            if !home_scanned {
                cost.push_str(PINS_NOTE);
            }
            out.extend(self.finding(
                t,
                Plan {
                    what: format!("nvm Node {}", t.name),
                    why: "not the default, not named by an nvm alias or a .nvmrc/.node-version in the scan, and not the newest installed".into(),
                    action: remove(t),
                    cost,
                    how: Some(format!("nvm install {}", shell_quote(&t.name))),
                },
            ));
        }
    }

    fn fnm(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
        pins: &Pins,
        home_scanned: bool,
        out: &mut Vec<Finding>,
    ) {
        let Some(root) = self
            .var("FNM_DIR")
            .or_else(|| self.xdg_data(ctx).map(|d| d.join("fnm")))
        else {
            return;
        };
        let installs = installs_in(tree, &root.join("node-versions"), node_group);
        if installs.is_empty() {
            return;
        }
        let mut keep = newest(&installs);
        // Aliases (default included) are links into node-versions/<v>/.
        for target in symlinks_in(&root.join("aliases")).values() {
            if let Some(i) = installs.iter().position(|t| &t.name == target) {
                keep.insert(i);
            }
        }
        for r in &pins.node {
            keep.extend(node_request(&installs, r));
        }
        let fnm = ctx.tool_command("fnm");
        for (i, t) in installs.iter().enumerate() {
            if keep.contains(&i) {
                continue;
            }
            let pre = self.env_prefix("FNM_DIR");
            let cmd = |verb: &str| {
                let mut v = pre.clone();
                v.push(fnm.clone().unwrap_or_else(|| "fnm".into()));
                v.extend([verb.into(), t.name.clone()]);
                v
            };
            let mut cost = "fnm downloads that Node version again; npm packages installed globally under it are not reinstalled".to_string();
            if !home_scanned {
                cost.push_str(PINS_NOTE);
            }
            out.extend(self.finding(
                t,
                Plan {
                    what: format!("fnm Node {}", t.name),
                    why: "not the default or another fnm alias, not named by a .nvmrc/.node-version in the scan, and not the newest installed".into(),
                    action: command_or_remove(fnm.is_some().then(|| cmd("uninstall")), t),
                    cost,
                    how: Some(join_argv(&cmd("install"))),
                },
            ));
        }
    }

    fn go_sdk(&self, tree: &ScanTree, ctx: &DetectContext, out: &mut Vec<Finding>) {
        let Some(root) = ctx.home.as_ref().map(|h| h.join("sdk")) else {
            return;
        };
        let installs = installs_in(tree, &root, |name| {
            let v = name.strip_prefix("go")?;
            v.starts_with(|c: char| c.is_ascii_digit())
                .then(|| version_group(v))
                .flatten()
        });
        let mut keep = newest(&installs);
        let go_on_path = ctx
            .tools
            .iter()
            .find(|t| t.name == "go")
            .and_then(|t| t.path.clone().or_else(|| t.off_path.clone()));
        for (i, t) in installs.iter().enumerate() {
            if t.group.is_none()
                || go_on_path
                    .as_deref()
                    .is_some_and(|p| Path::new(p).starts_with(&t.path))
            {
                keep.insert(i);
            }
        }
        for (i, t) in installs.iter().enumerate() {
            if keep.contains(&i) {
                continue;
            }
            out.extend(self.finding(
                t,
                Plan {
                    what: format!("Go SDK {} from golang.org/dl", t.name),
                    why: "not the go on PATH and not the newest SDK installed".into(),
                    action: remove(t),
                    cost: "the Go SDK is downloaded again".into(),
                    how: Some(format!(
                        "go install golang.org/dl/{0}@latest && {0} download",
                        t.name
                    )),
                },
            ));
        }
    }

    fn vscode(&self, tree: &ScanTree, ctx: &DetectContext, out: &mut Vec<Finding>) {
        let roots: Vec<PathBuf> = match self.var("VSCODE_AGENT_FOLDER") {
            Some(p) => vec![p],
            None => match &ctx.home {
                Some(h) => vec![h.join(".vscode-server"), h.join(".vscode-server-insiders")],
                None => return,
            },
        };
        for root in roots {
            if tree.find(&root).is_none() {
                continue;
            }
            let servers_dir = root.join("cli/servers");
            let servers = only_grouped(installs_in(tree, &servers_dir, |name| {
                let (_, commit) = name.split_once('-')?;
                is_commit(commit).then(|| (String::new(), Vec::new()))
            }));
            let lru: Vec<String> = read_head(&servers_dir.join("lru.json"), MAX_SMALL_FILE)
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            let kept_server = lru
                .iter()
                .find_map(|n| servers.iter().position(|s| &s.name == n))
                .or_else(|| newest_by_mtime(&servers));
            let kept_commit = kept_server
                .and_then(|i| servers[i].name.split_once('-'))
                .map(|(_, c)| c.to_string());
            for (i, s) in servers.iter().enumerate() {
                if Some(i) != kept_server {
                    out.extend(self.vscode_finding(
                        s,
                        "server",
                        kept_server.map(|k| &servers[k].name),
                    ));
                }
            }
            // Servers from VS Code before the CLI layout: bin/<commit>.
            let legacy = only_grouped(installs_in(tree, &root.join("bin"), |name| {
                is_commit(name).then(|| (String::new(), Vec::new()))
            }));
            let kept_legacy = newest_by_mtime(&legacy);
            for (i, s) in legacy.iter().enumerate() {
                if Some(i) != kept_legacy {
                    out.extend(self.vscode_finding(
                        s,
                        "server",
                        kept_legacy.map(|k| &legacy[k].name),
                    ));
                }
            }
            // The CLI each server version ships: code-<commit>, a file.
            let clis = cli_files(&root);
            let kept_cli = match &kept_commit {
                Some(c) => clis.iter().position(|f| f.name == format!("code-{c}")),
                None => newest_by_mtime(&clis),
            };
            for (i, f) in clis.iter().enumerate() {
                if Some(i) != kept_cli {
                    out.extend(self.vscode_finding(f, "CLI", kept_cli.map(|k| &clis[k].name)));
                }
            }
        }
    }

    fn vscode_finding(&self, t: &Install, kind: &str, kept: Option<&String>) -> Option<Finding> {
        let why = match kept {
            Some(k) => format!("not the most recently used one ({k})"),
            None => "not the most recently used one".into(),
        };
        self.finding(
            t,
            Plan {
                what: format!("VS Code Server {kind} {}", t.name),
                why,
                action: remove(t),
                cost: "VS Code downloads it again if a client of that version connects; newer clients never use it".into(),
                how: None,
            },
        )
    }

    fn finding(&self, t: &Install, plan: Plan) -> Option<Finding> {
        if t.bytes < MIN_BYTES {
            return None;
        }
        let path_s = t.path.to_string_lossy().into_owned();
        let mut reason = format!("{} ({}", plan.what, human(t.bytes));
        if t.shared > 0 {
            reason.push_str(&format!(
                "; {} more is hardlinked elsewhere and is not freed",
                human(t.shared)
            ));
        }
        reason.push_str(&format!("): {}", plan.why));
        Some(Finding {
            id: finding_id(self.name(), &path_s),
            detector: self.name().into(),
            probe: None,
            bytes: t.bytes,
            nested_bytes: None,
            last_modified: Some(rfc3339(t.newest_mtime)),
            growth: None,
            tier: Tier::Rebuildable,
            reason,
            guards: Vec::new(),
            action: plan.action,
            recovery: Recovery {
                cost: plan.cost,
                how: plan.how,
            },
            path: path_s,
        })
    }
}

const PINS_NOTE: &str =
    "; the home directory was not scanned, so pins and venvs in projects there were not checked";

/// Pins and venv interpreters from every scanned directory that has them.
fn collect_pins(tree: &ScanTree) -> Pins {
    let mut pins = Pins::default();
    for id in tree.ids() {
        let n = tree.node(id);
        if !n.is_dir
            || !n
                .markers
                .intersects(Markers::TOOL_PIN.union(Markers::PYVENV_CFG))
        {
            continue;
        }
        let dir = tree.path(id);
        if n.markers.contains(Markers::PYVENV_CFG)
            && let Some(text) = read_text(&dir.join("pyvenv.cfg"))
        {
            for line in text.lines() {
                if let Some((k, v)) = line.split_once('=')
                    && matches!(k.trim(), "home" | "executable" | "base-executable")
                {
                    pins.venv_pythons.push(PathBuf::from(v.trim()));
                }
            }
        }
        if !n.markers.contains(Markers::TOOL_PIN) {
            continue;
        }
        for name in ["rust-toolchain.toml", "rust-toolchain"] {
            if let Some(text) = read_text(&dir.join(name))
                && let Some(c) = rust_channel(&text)
            {
                pins.rust.push(c);
            }
        }
        if let Some(text) = read_text(&dir.join(".python-version")) {
            pins.python.extend(python_pin_lines(&text));
        }
        for name in [".nvmrc", ".node-version"] {
            if let Some(text) = read_text(&dir.join(name))
                && let Some(line) = text
                    .lines()
                    .map(|l| l.split('#').next().unwrap_or("").trim())
                    .find(|l| !l.is_empty())
            {
                pins.node.push(line.to_string());
            }
        }
    }
    pins
}

fn read_text(path: &Path) -> Option<String> {
    read_head(path, MAX_SMALL_FILE).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// The channel of a `rust-toolchain.toml`, or of a legacy one-line
/// `rust-toolchain` file.
fn rust_channel(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == "channel"
        {
            return Some(unquote(v));
        }
    }
    let first = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    (!first.contains(['=', '[', ' '])).then(|| first.to_string())
}

fn unquote(v: &str) -> String {
    let v = v.split('#').next().unwrap_or("").trim();
    v.trim_matches(|c| c == '"' || c == '\'').to_string()
}

/// `default_toolchain` and the `[overrides]` toolchains of rustup's
/// `settings.toml`.
fn rustup_settings(text: &str) -> (Option<String>, Vec<String>) {
    let mut default = None;
    let mut overrides = Vec::new();
    let mut table = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            table = line
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_string();
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if table.is_empty() && k.trim() == "default_toolchain" {
            default = Some(unquote(v));
        } else if table == "overrides" {
            overrides.push(unquote(v));
        }
    }
    (default, overrides)
}

/// True if toolchain `name` is what `request` names: the same, or the
/// request plus a host triple (`stable` matches
/// `stable-x86_64-unknown-linux-gnu`, not `stable-2025-01-01-…`).
fn channel_matches(name: &str, request: &str) -> bool {
    if request.is_empty() {
        return false;
    }
    if name == request {
        return true;
    }
    name.strip_prefix(request)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|triple| triple.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// Groups rustup toolchains: numbered releases together, dated toolchains
/// by channel. Rolling channels (`stable`, `nightly`) are their own newest.
fn rust_group(name: &str) -> Option<(String, Vec<u64>)> {
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        let v: String = name
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        return Some(("release".into(), num_version(&v)?));
    }
    let (channel, rest) = name.split_once('-')?;
    let date: Vec<&str> = rest.splitn(4, '-').take(3).collect();
    if date.len() == 3
        && date
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Some((
            channel.to_string(),
            date.iter().filter_map(|p| p.parse().ok()).collect(),
        ));
    }
    None
}

/// uv install keys: `<impl>-<version>[+variant]-<os>-<arch>-<libc>`.
fn uv_group(name: &str) -> Option<(String, Vec<u64>)> {
    let mut parts = name.splitn(3, '-');
    let imp = parts.next()?;
    let ver = parts.next()?;
    let platform = parts.next()?;
    let (num, variant) = ver.split_once('+').unwrap_or((ver, ""));
    let digits: String = num
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let suffix = &num[digits.len()..];
    Some((
        format!("{imp}+{variant}{suffix}-{platform}"),
        num_version(&digits)?,
    ))
}

/// Names like `3.12.3`, `v20.1.0`, `pypy3.10-7.3.15`: the text before the
/// first number and after it make the group.
fn plain_group(name: &str) -> Option<(String, Vec<u64>)> {
    version_group(name)
}

fn node_group(name: &str) -> Option<(String, Vec<u64>)> {
    num_version(name).map(|v| (String::new(), v))
}

fn version_group(name: &str) -> Option<(String, Vec<u64>)> {
    let start = name.find(|c: char| c.is_ascii_digit())?;
    let digits: String = name[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let digits = digits.trim_end_matches('.');
    let suffix = &name[start + digits.len()..];
    Some((format!("{}#{suffix}", &name[..start]), num_version(digits)?))
}

/// `20.1.0`, `v20.1.0` → [20, 1, 0].
fn num_version(s: &str) -> Option<Vec<u64>> {
    let s = s.strip_prefix('v').unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    s.split('.').map(|p| p.parse().ok()).collect()
}

/// Directories under `dir` in the tree, each grouped by `group`.
fn installs_in(
    tree: &ScanTree,
    dir: &Path,
    group: impl Fn(&str) -> Option<(String, Vec<u64>)>,
) -> Vec<Install> {
    let Some(id) = tree.find(dir) else {
        return Vec::new();
    };
    tree.children(id)
        .iter()
        .filter(|&&c| tree.node(c).is_dir)
        .map(|&c| {
            let name = tree.name(c).to_string_lossy();
            let g = group(&name);
            Install::from_node(tree, c, g)
        })
        .collect()
}

/// Indexes of the newest install in each group, plus every install
/// without one (nothing to compare it with).
fn newest(installs: &[Install]) -> BTreeSet<usize> {
    let mut best: BTreeMap<&str, usize> = BTreeMap::new();
    let mut keep = BTreeSet::new();
    for (i, t) in installs.iter().enumerate() {
        match &t.group {
            None => {
                keep.insert(i);
            }
            Some((g, v)) => {
                let e = best.entry(g.as_str()).or_insert(i);
                let cur = installs[*e].group.as_ref().map(|(_, v)| v);
                if cur.is_some_and(|c| v > c) {
                    *e = i;
                }
            }
        }
    }
    keep.extend(best.into_values());
    keep
}

/// Drops directories that are not versions of the tool.
fn only_grouped(installs: Vec<Install>) -> Vec<Install> {
    installs.into_iter().filter(|t| t.group.is_some()).collect()
}

fn newest_by_mtime(items: &[Install]) -> Option<usize> {
    (0..items.len()).max_by_key(|&i| (items[i].newest_mtime, items[i].name.clone()))
}

/// The newest install in a group compatible with `group_hint` whose
/// version starts with `req`.
fn newest_matching(
    installs: &[Install],
    req: &[u64],
    accept: impl Fn(&str) -> bool,
) -> Option<usize> {
    installs
        .iter()
        .enumerate()
        .filter_map(|(i, t)| {
            let (g, v) = t.group.as_ref()?;
            (accept(g) && v.starts_with(req)).then_some((v, i))
        })
        .max()
        .map(|(_, i)| i)
}

fn python_pin_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// Installs that Python requests (`3.12`, `cpython@3.12`, `pypy3.10`, a
/// full name) resolve to. `default_impl` is the implementation a bare
/// version means for this tool's group names.
fn resolve_python(installs: &[Install], requests: &[String], default_impl: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for r in requests {
        let r = r.trim().to_ascii_lowercase();
        if let Some(i) = installs.iter().position(|t| t.name == r) {
            out.push(i);
            continue;
        }
        let (imp, rest) = match r.split_once('@') {
            Some((i, v)) => (i.to_string(), v.to_string()),
            None => {
                let i: String = r.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
                let rest = r[i.len()..].trim_start_matches('-').to_string();
                (i, rest)
            }
        };
        let imp = if imp.is_empty() || imp == "python" {
            default_impl.to_string()
        } else {
            imp
        };
        let digits: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let Some(req) = num_version(digits.trim_end_matches('.')) else {
            continue;
        };
        out.extend(newest_matching(installs, &req, |g| {
            // uv groups start with "<impl>+", pyenv groups with "<prefix>#".
            g.starts_with(&format!("{imp}+")) || g.starts_with(&format!("{imp}#"))
        }));
    }
    out
}

/// A Node request: `v20.1.0`, `20`, `20.1`. Anything else keeps nothing.
fn node_request(installs: &[Install], r: &str) -> Option<usize> {
    let req = num_version(r.trim())?;
    newest_matching(installs, &req, |_| true)
}

/// What an nvm alias or request resolves to. `None` when it can't be
/// resolved (so nothing should be reported); an empty list for `system`.
fn nvm_resolve(installs: &[Install], alias_dir: &Path, r: &str, depth: u8) -> Option<Vec<usize>> {
    if depth > 5 || r.is_empty() || r.starts_with('/') || r.split('/').any(|c| c == "..") {
        return None;
    }
    match r {
        "system" | "iojs" | "none" => return Some(Vec::new()),
        "node" | "stable" => {
            return Some(
                newest_matching(installs, &[], |_| true)
                    .into_iter()
                    .collect(),
            );
        }
        _ => {}
    }
    if num_version(r).is_some() {
        return Some(node_request(installs, r).into_iter().collect());
    }
    // Another alias: alias/<name>, or alias/lts/<name> (lts/* included).
    let file = alias_dir.join(r);
    let text = read_text(&file)?;
    nvm_resolve(installs, alias_dir, text.trim(), depth + 1)
}

/// Symlinks in `dir`: link name → the first component of its target after
/// `dir` (or the target's file name when it points elsewhere).
fn symlinks_in(dir: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let Ok(target) = std::fs::read_link(e.path()) else {
            continue;
        };
        let abs = if target.is_absolute() {
            target
        } else {
            dir.join(target)
        };
        // fnm: aliases/<name> -> <root>/node-versions/<v>/installation.
        let name = abs
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let pick = if name.last().is_some_and(|n| n == "installation") && name.len() >= 2 {
            name[name.len() - 2].clone()
        } else {
            name.last().cloned().unwrap_or_default()
        };
        out.insert(e.file_name().to_string_lossy().into_owned(), pick);
    }
    out
}

/// `code-<commit>` regular files directly in the VS Code Server folder.
fn cli_files(root: &Path) -> Vec<Install> {
    let Ok(rd) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(commit) = name.strip_prefix("code-") else {
            continue;
        };
        if !is_commit(commit) {
            continue;
        }
        let Ok(md) = std::fs::symlink_metadata(e.path()) else {
            continue;
        };
        if !md.is_file() || md.nlink() != 1 {
            continue;
        }
        out.push(Install {
            name,
            path: e.path(),
            bytes: md.blocks() * 512,
            shared: 0,
            newest_mtime: md.mtime(),
            group: None,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn is_commit(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn remove(t: &Install) -> Action {
    let p = t.path.to_string_lossy();
    Action {
        kind: ActionKind::RemovePath,
        text: format!("remove {}", shell_quote(&p)),
        argv: None,
    }
}

fn command_or_remove(argv: Option<Vec<String>>, t: &Install) -> Action {
    match argv {
        Some(argv) => Action {
            kind: ActionKind::Command,
            text: join_argv(&argv),
            argv: Some(argv),
        },
        None => remove(t),
    }
}

fn join_argv(argv: &[String]) -> String {
    argv.iter()
        .enumerate()
        .map(|(i, a)| {
            // `env NAME=value`: quote only the value.
            if i == 1 && argv[0] == "env" && a.contains('=') {
                let (k, v) = a.split_once('=').unwrap_or((a, ""));
                format!("{k}={}", shell_quote(v))
            } else {
                shell_quote(a)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
