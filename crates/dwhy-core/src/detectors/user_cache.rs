//! `user-cache`: well-known per-user caches (pip, uv, npm, pnpm, yarn, Go,
//! Cargo, Playwright, Hugging Face).
//!
//! Each cache is located the way its tool locates it by default (its
//! environment variable, then the XDG default) and sized from the scan tree,
//! so a cache outside the scanned paths yields nothing. When the tool is
//! installed, the action is its own clean command, pinned to the measured
//! directory (`--cache-dir`, `GOCACHE=…`) so it acts on exactly what was
//! reported, wherever it is run from. Otherwise the action is a path removal
//! limited to the cache directory.
//!
//! Age gate: a cache written in the last [`RECENT_HOURS`] hours is still
//! reported, but in the `blocked` tier with a `recent-write` guard, because
//! a running tool may be using it.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::detect::{DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, GuardResult, GuardStatus, Recovery, Tier};
use crate::tree::ScanTree;
use crate::units::human;

/// Caches smaller than this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;
/// A cache written more recently than this is not offered for removal.
pub const RECENT_HOURS: i64 = 24;

/// Where a cache lives, relative to the directories its tool uses.
enum Locate {
    /// `$VAR` if set, else `<XDG_CACHE_HOME>/<rel>`.
    XdgCache(&'static [&'static str], &'static str),
    /// `$VAR` if set, else `<XDG_DATA_HOME>/<rel>`.
    XdgData(&'static [&'static str], &'static str),
    /// `$VAR` if set, else `~/<rel>`.
    Home(&'static [&'static str], &'static str),
    /// npm's cache (`$npm_config_cache`, else `~/.npm`) joined with `<rel>`.
    Npm(&'static str),
    /// `$GOMODCACHE`, else the first `$GOPATH` entry (default `~/go`) + `pkg/mod`.
    GoModCache,
    /// `$CARGO_HOME` (default `~/.cargo`) joined with `<rel>`.
    Cargo(&'static str),
    /// `$HF_HOME` (default `<XDG_CACHE_HOME>/huggingface`) joined with
    /// `<rel>`, unless one of the variables names the directory itself. A
    /// variable naming the HF home or one of its ancestors (which hold the
    /// login token) is ignored.
    HuggingFace(&'static [&'static str], &'static str),
}

/// How the tool removes the cache, given the tool command and the directory.
enum Clean {
    /// No tool-native command: path removal only.
    None,
    /// `<tool> <args…>` with `{}` replaced by the directory.
    Args(&'static str, &'static [&'static str]),
    /// `env VAR=<dir> <tool> <args…>`.
    Env(&'static str, &'static str, &'static [&'static str]),
    /// npm takes the cache root, the parent of the reported `_cacache`.
    NpmParent,
}

struct Cache {
    what: &'static str,
    tier: Tier,
    locate: Locate,
    clean: Clean,
    cost: &'static str,
    how: Option<&'static str>,
}

const CACHES: &[Cache] = &[
    Cache {
        what: "pip download and wheel cache",
        tier: Tier::Regenerable,
        locate: Locate::XdgCache(&["PIP_CACHE_DIR"], "pip"),
        clean: Clean::Args("pip", &["--cache-dir", "{}", "cache", "purge"]),
        cost: "pip downloads and builds packages again on the next install",
        how: None,
    },
    Cache {
        what: "uv cache",
        tier: Tier::Regenerable,
        locate: Locate::XdgCache(&["UV_CACHE_DIR"], "uv"),
        clean: Clean::Args("uv", &["cache", "clean", "--cache-dir", "{}"]),
        cost: "uv downloads and builds packages again on the next sync",
        how: None,
    },
    Cache {
        what: "npm package cache",
        tier: Tier::Regenerable,
        locate: Locate::Npm("_cacache"),
        clean: Clean::NpmParent,
        cost: "npm downloads packages again on the next install",
        how: None,
    },
    Cache {
        what: "packages installed by npx (running npx tools, such as MCP servers, load code from here)",
        tier: Tier::Review,
        locate: Locate::Npm("_npx"),
        clean: Clean::None,
        cost: "the next npx run of each tool downloads it again; stop running npx tools first",
        how: None,
    },
    Cache {
        what: "pnpm content-addressable store (prune removes only packages no project references)",
        tier: Tier::Regenerable,
        locate: Locate::XdgData(&[], "pnpm/store"),
        clean: Clean::Args("pnpm", &["store", "prune", "--store-dir", "{}"]),
        cost: "pnpm downloads pruned packages again when a project needs them",
        how: None,
    },
    Cache {
        what: "Yarn (classic) cache",
        tier: Tier::Regenerable,
        locate: Locate::XdgCache(&["YARN_CACHE_FOLDER"], "yarn"),
        clean: Clean::Env("YARN_CACHE_FOLDER", "yarn", &["cache", "clean"]),
        cost: "yarn downloads packages again on the next install",
        how: None,
    },
    Cache {
        what: "Yarn (berry) global cache",
        tier: Tier::Regenerable,
        locate: Locate::Home(&[], ".yarn/berry/cache"),
        clean: Clean::None,
        cost: "yarn downloads packages again on the next install",
        how: None,
    },
    Cache {
        what: "Go build cache",
        tier: Tier::Regenerable,
        locate: Locate::XdgCache(&["GOCACHE"], "go-build"),
        clean: Clean::Env("GOCACHE", "go", &["clean", "-cache"]),
        cost: "the next go build or test recompiles packages",
        how: None,
    },
    Cache {
        what: "Go module cache",
        tier: Tier::Regenerable,
        locate: Locate::GoModCache,
        clean: Clean::Env("GOMODCACHE", "go", &["clean", "-modcache"]),
        cost: "go downloads modules again (its files are read-only, so prefer `go clean -modcache` to rm)",
        how: Some("go mod download"),
    },
    Cache {
        what: "Cargo registry (downloaded crates, sources and index)",
        tier: Tier::Regenerable,
        locate: Locate::Cargo("registry"),
        clean: Clean::None,
        cost: "cargo downloads crates again on the next build",
        how: Some("cargo fetch"),
    },
    Cache {
        what: "Cargo git dependency checkouts",
        tier: Tier::Regenerable,
        locate: Locate::Cargo("git"),
        clean: Clean::None,
        cost: "cargo clones git dependencies again on the next build",
        how: Some("cargo fetch"),
    },
    Cache {
        what: "Playwright browser downloads",
        tier: Tier::Regenerable,
        locate: Locate::XdgCache(&["PLAYWRIGHT_BROWSERS_PATH"], "ms-playwright"),
        clean: Clean::None,
        cost: "Playwright downloads its browsers again",
        how: Some("npx playwright install"),
    },
    Cache {
        what: "Hugging Face model cache",
        tier: Tier::Review,
        locate: Locate::HuggingFace(&["HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE"], "hub"),
        clean: Clean::None,
        cost: "models download again, which can be slow and large",
        how: None,
    },
    Cache {
        what: "Hugging Face Xet chunk cache",
        tier: Tier::Review,
        locate: Locate::HuggingFace(&["HF_XET_CACHE"], "xet"),
        clean: Clean::None,
        cost: "model downloads fetch their chunks again",
        how: None,
    },
];

/// `user-cache`. Holds the environment it resolves cache locations from.
pub struct UserCache {
    env: HashMap<String, String>,
}

impl UserCache {
    /// Reads the process environment.
    pub fn from_system() -> UserCache {
        UserCache::with_env(std::env::vars_os())
    }

    /// Uses the given variables instead of the process environment.
    /// Pairs whose name or value is not UTF-8 are skipped.
    pub fn with_env<I, K, V>(vars: I) -> UserCache
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        UserCache {
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

    fn first_var(&self, names: &[&str]) -> Option<PathBuf> {
        names.iter().find_map(|n| self.var(n))
    }

    fn xdg_cache(&self, home: &Path) -> PathBuf {
        self.var("XDG_CACHE_HOME")
            .unwrap_or_else(|| home.join(".cache"))
    }

    fn locate(&self, how: &Locate, home: &Path) -> PathBuf {
        match how {
            Locate::XdgCache(vars, rel) => self
                .first_var(vars)
                .unwrap_or_else(|| self.xdg_cache(home).join(rel)),
            Locate::XdgData(vars, rel) => self.first_var(vars).unwrap_or_else(|| {
                self.var("XDG_DATA_HOME")
                    .unwrap_or_else(|| home.join(".local/share"))
                    .join(rel)
            }),
            Locate::Home(vars, rel) => self.first_var(vars).unwrap_or_else(|| home.join(rel)),
            Locate::Npm(rel) => self
                .first_var(&["npm_config_cache", "NPM_CONFIG_CACHE"])
                .unwrap_or_else(|| home.join(".npm"))
                .join(rel),
            Locate::GoModCache => match self.var("GOMODCACHE") {
                Some(p) => p,
                None => {
                    let gopath = self
                        .env
                        .get("GOPATH")
                        .and_then(|v| std::env::split_paths(v).next())
                        .filter(|p| p.is_absolute())
                        .unwrap_or_else(|| home.join("go"));
                    gopath.join("pkg/mod")
                }
            },
            Locate::Cargo(rel) => self
                .var("CARGO_HOME")
                .unwrap_or_else(|| home.join(".cargo"))
                .join(rel),
            Locate::HuggingFace(vars, rel) => {
                let hf_home = self
                    .var("HF_HOME")
                    .unwrap_or_else(|| self.xdg_cache(home).join("huggingface"));
                self.first_var(vars)
                    .filter(|p| !hf_home.starts_with(p))
                    .unwrap_or_else(|| hf_home.join(rel))
            }
        }
    }
}

/// A cache directory must be a real subdirectory: never `/`, never `$HOME`
/// or one of its ancestors, whatever an environment variable says.
fn plausible(dir: &Path, home: &Path) -> bool {
    dir.components().count() >= 3 && !home.starts_with(dir)
}

fn action(cache: &Cache, dir: &Path, ctx: &DetectContext) -> Action {
    let dir_s = dir.to_string_lossy().into_owned();
    let argv: Option<Vec<String>> = match &cache.clean {
        Clean::None => None,
        Clean::Args(tool, args) => ctx.tool_command(tool).map(|t| {
            std::iter::once(t)
                .chain(args.iter().map(|a| {
                    if *a == "{}" {
                        dir_s.clone()
                    } else {
                        a.to_string()
                    }
                }))
                .collect()
        }),
        Clean::Env(var, tool, args) => ctx.tool_command(tool).map(|t| {
            ["env".to_string(), format!("{var}={dir_s}"), t]
                .into_iter()
                .chain(args.iter().map(|a| a.to_string()))
                .collect()
        }),
        Clean::NpmParent => ctx.tool_command("npm").map(|t| {
            let root = dir.parent().unwrap_or(dir).to_string_lossy().into_owned();
            vec![
                t,
                "cache".into(),
                "clean".into(),
                "--force".into(),
                "--cache".into(),
                root,
            ]
        }),
    };
    match argv {
        Some(argv) => Action {
            kind: ActionKind::Command,
            text: argv
                .iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" "),
            argv: Some(argv),
        },
        None => {
            let why = match &cache.clean {
                Clean::None => String::new(),
                Clean::Args(t, _) | Clean::Env(_, t, _) => format!(" ({t} not found)"),
                Clean::NpmParent => " (npm not found)".into(),
            };
            Action {
                kind: ActionKind::RemovePath,
                text: format!("remove {}{why}", shell_quote(&dir_s)),
                argv: None,
            }
        }
    }
}

impl Detector for UserCache {
    fn name(&self) -> &'static str {
        "user-cache"
    }

    fn detect(&self, tree: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let Some(home) = ctx.home.as_deref().filter(|h| h.is_absolute()) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut seen: Vec<PathBuf> = Vec::new();
        for cache in CACHES {
            let dir = self.locate(&cache.locate, home);
            if !plausible(&dir, home) || seen.contains(&dir) {
                continue;
            }
            let Some(id) = tree.find(&dir) else {
                continue;
            };
            let n = tree.node(id);
            let bytes = n.freeable();
            if !n.is_dir || bytes < MIN_BYTES {
                continue;
            }
            seen.push(dir.clone());
            let path = dir.to_string_lossy().into_owned();
            let recent = ctx.now - n.newest_mtime < RECENT_HOURS * 3600;
            let mut guards = Vec::new();
            let mut reason = format!("{} ({}", cache.what, human(bytes));
            if n.shared > 0 {
                reason.push_str(&format!(
                    "; {} more is hardlinked elsewhere, e.g. into virtualenvs, and is not freed",
                    human(n.shared)
                ));
            }
            reason.push_str(&format!(
                "); last written {} ago",
                age(ctx.now, n.newest_mtime)
            ));
            if recent {
                reason.push_str(&format!(
                    "; written in the last {RECENT_HOURS} hours, so not offered yet"
                ));
                guards.push(GuardResult {
                    name: "recent-write".into(),
                    status: GuardStatus::Block,
                    detail: format!(
                        "last written {} ago (gate: {RECENT_HOURS} hours); a running tool may be using it",
                        age(ctx.now, n.newest_mtime)
                    ),
                });
            }
            out.push(Finding {
                id: finding_id(self.name(), &path),
                detector: self.name().into(),
                probe: None,
                bytes,
                nested_bytes: None,
                last_modified: Some(rfc3339(n.newest_mtime)),
                growth: None,
                tier: if recent { Tier::Blocked } else { cache.tier },
                reason,
                guards,
                action: action(cache, &dir, ctx),
                recovery: Recovery {
                    cost: cache.cost.into(),
                    how: cache.how.map(String::from),
                },
                path,
            });
        }
        Ok(out)
    }
}
