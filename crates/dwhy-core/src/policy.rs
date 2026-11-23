//! The policy config (docs/DESIGN.md "Policy config"): limits on what
//! `dwhy apply` and the TUI may remove, and extra scratch locations for the
//! `stale-tree` detector.
//!
//! Two files, both optional: [`SYSTEM_POLICY_PATH`] (root-owned, the
//! machine's ceiling) and [`user_policy_path`]. The user file and the
//! command line can only tighten what `/etc` allows, never loosen it:
//! `max_tier` is the lowest of the two, `confirm` the strictest, and
//! `scratch.stale_days` the longest. `scratch.paths` is the union.
//!
//! A file that exists but cannot be read or parsed is an error, never
//! ignored: a typo must not silently drop a limit.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::detectors::SCRATCH_STALE_DAYS;
use crate::report::Tier;

/// The machine-wide policy file. Only root should be able to write it.
pub const SYSTEM_POLICY_PATH: &str = "/etc/diskwhy/policy.toml";

/// The user's policy file: `$XDG_CONFIG_HOME/diskwhy/policy.toml`, else
/// `$HOME/.config/diskwhy/policy.toml` ([`crate::system::config_dir`]).
pub fn user_policy_path() -> Option<PathBuf> {
    Some(crate::system::config_dir()?.join("policy.toml"))
}

/// How review items are confirmed. Ordered from loosest to strictest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmMode {
    /// `--confirm ID` (or a tick in the TUI's dialog) is enough.
    #[default]
    Flag,
    /// As `flag`, and a person must confirm on a terminal: `dwhy apply`
    /// refuses review items with `--yes` or without a terminal.
    Interactive,
    /// Review items are never applied.
    Never,
}

/// The name of a [`ConfirmMode`] as the policy file spells it.
pub fn confirm_mode_name(m: ConfirmMode) -> &'static str {
    match m {
        ConfirmMode::Flag => "flag",
        ConfirmMode::Interactive => "interactive",
        ConfirmMode::Never => "never",
    }
}

/// One policy file as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    max_tier: Option<Tier>,
    confirm: Option<ConfirmMode>,
    scratch: Option<ScratchFile>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScratchFile {
    paths: Option<Vec<String>>,
    stale_days: Option<i64>,
}

/// The effective policy: the system and user files merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    /// The highest tier apply may remove without per-item confirmation, and
    /// the highest tier it may remove at all (a lower ceiling refuses review
    /// items too). `None`: no limit beyond `--max-tier`.
    pub max_tier: Option<Tier>,
    /// The file that set [`PolicyConfig::max_tier`].
    pub max_tier_source: Option<PathBuf>,
    pub confirm: ConfirmMode,
    /// The file that set [`PolicyConfig::confirm`]; `None` for the default.
    pub confirm_source: Option<PathBuf>,
    /// Scratch locations added to the built-in ones, as written (absolute,
    /// `~/…`, or relative to the home directory; a last component ending in
    /// `*` is a prefix).
    pub scratch_paths: Vec<String>,
    /// Days with nothing written after which scratch is stale.
    pub scratch_stale_days: i64,
    /// The files read, system first.
    pub loaded: Vec<PathBuf>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            max_tier: None,
            max_tier_source: None,
            confirm: ConfirmMode::Flag,
            confirm_source: None,
            scratch_paths: Vec::new(),
            scratch_stale_days: SCRATCH_STALE_DAYS,
            loaded: Vec::new(),
        }
    }
}

impl PolicyConfig {
    /// Reads [`SYSTEM_POLICY_PATH`] and [`user_policy_path`]. Missing files
    /// are skipped; any other problem with either file is an error.
    pub fn load() -> Result<PolicyConfig, String> {
        let user = user_policy_path();
        PolicyConfig::load_from(Some(Path::new(SYSTEM_POLICY_PATH)), user.as_deref())
    }

    /// [`PolicyConfig::load`] with the two paths given.
    pub fn load_from(system: Option<&Path>, user: Option<&Path>) -> Result<PolicyConfig, String> {
        let mut merged = Merge::default();
        for path in [system, user].into_iter().flatten() {
            if let Some(file) = read(path)? {
                merged.add(file, path);
            }
        }
        Ok(merged.finish())
    }

    /// Parses one policy file's text; `path` names it in errors.
    pub fn parse(text: &str, path: &Path) -> Result<PolicyConfig, String> {
        let mut merged = Merge::default();
        merged.add(parse_file(text, path)?, path);
        Ok(merged.finish())
    }
}

/// Policy files merged in order, each only tightening the ones before.
#[derive(Default)]
struct Merge {
    config: PolicyConfig,
    stale_days: Option<i64>,
}

impl Merge {
    fn add(&mut self, file: PolicyFile, path: &Path) {
        let config = &mut self.config;
        config.loaded.push(path.to_path_buf());
        if let Some(t) = file.max_tier
            && config.max_tier.is_none_or(|cur| t < cur)
        {
            config.max_tier = Some(t);
            config.max_tier_source = Some(path.to_path_buf());
        }
        if let Some(c) = file.confirm
            && c > config.confirm
        {
            config.confirm = c;
            config.confirm_source = Some(path.to_path_buf());
        }
        if let Some(scratch) = file.scratch {
            for p in scratch.paths.unwrap_or_default() {
                if !config.scratch_paths.contains(&p) {
                    config.scratch_paths.push(p);
                }
            }
            if let Some(d) = scratch.stale_days {
                self.stale_days = Some(self.stale_days.map_or(d, |cur| cur.max(d)));
            }
        }
    }

    fn finish(mut self) -> PolicyConfig {
        if let Some(d) = self.stale_days {
            self.config.scratch_stale_days = d;
        }
        self.config
    }
}

/// Reads and checks the policy file at `path`; `None` when there is none.
fn read(path: &Path) -> Result<Option<PolicyFile>, String> {
    let text = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read policy file {}: {e}", show(path))),
    };
    let text = String::from_utf8(text)
        .map_err(|_| format!("invalid policy file {}: not UTF-8", show(path)))?;
    parse_file(&text, path).map(Some)
}

fn parse_file(text: &str, path: &Path) -> Result<PolicyFile, String> {
    let invalid = |what: String| format!("invalid policy file {}: {what}", show(path));
    let file: PolicyFile = toml::from_str(text).map_err(|e| {
        let at = e.span().map(|span| {
            let before = &text[..span.start.min(text.len())];
            let line = before.matches('\n').count() + 1;
            let col = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
            format!(" (line {line}, column {col})")
        });
        invalid(format!("{}{}", e.message().trim(), at.unwrap_or_default()))
    })?;
    if file.max_tier == Some(Tier::Blocked) {
        return Err(invalid(
            "max_tier = \"blocked\" is not allowed: blocked items are never applied; \
             use regenerable, rebuildable or review"
                .into(),
        ));
    }
    if let Some(s) = &file.scratch {
        if let Some(d) = s.stale_days
            && d < 1
        {
            return Err(invalid(format!(
                "scratch.stale_days = {d}: must be at least 1"
            )));
        }
        for p in s.paths.iter().flatten() {
            check_scratch_path(p).map_err(|why| {
                invalid(format!(
                    "scratch.paths entry {:?}: {why}",
                    crate::detect::escape_controls(p)
                ))
            })?;
        }
    }
    Ok(file)
}

/// A scratch path must name a directory below `/` or the home directory:
/// absolute, `~/…`, or relative to the home directory, with no `.` or `..`
/// components, and `*` only at the end.
fn check_scratch_path(p: &str) -> Result<(), &'static str> {
    if p.trim().is_empty() {
        return Err("must not be empty");
    }
    if p.contains('\0') {
        return Err("must not contain NUL");
    }
    let rest = if let Some(rest) = p.strip_prefix("~/") {
        rest
    } else if p.starts_with('~') {
        return Err("only ~/ is expanded (not ~ alone or ~user)");
    } else {
        p.strip_prefix('/').unwrap_or(p)
    };
    let parts: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    if parts.is_empty() {
        return Err("must name a directory below / or the home directory");
    }
    if parts.iter().any(|c| *c == "." || *c == "..") {
        return Err("must not contain . or .. components");
    }
    let (last, dirs) = parts.split_last().expect("not empty");
    if dirs.iter().any(|c| c.contains('*')) || last.trim_end_matches('*').contains('*') {
        return Err("* is allowed only at the end of the last component");
    }
    if *last == "*" {
        return Err("a * needs a prefix before it (such as scratch-*)");
    }
    Ok(())
}

fn show(path: &Path) -> std::borrow::Cow<'static, str> {
    crate::detect::escape_controls(&path.to_string_lossy())
        .into_owned()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn parses_a_full_file() {
        let c = PolicyConfig::parse(
            "max_tier = \"rebuildable\"\nconfirm = \"interactive\"\n\n[scratch]\n\
             paths = [\"~/work/scratch\", \"/srv/scratch\", \"tmp-*\"]\nstale_days = 14\n",
            Path::new("/p.toml"),
        )
        .unwrap();
        assert_eq!(c.max_tier, Some(Tier::Rebuildable));
        assert_eq!(c.confirm, ConfirmMode::Interactive);
        assert_eq!(c.scratch_paths, ["~/work/scratch", "/srv/scratch", "tmp-*"]);
        assert_eq!(c.scratch_stale_days, 14);
    }

    #[test]
    fn an_empty_file_is_the_default() {
        let c = PolicyConfig::parse("", Path::new("/p.toml")).unwrap();
        assert_eq!(
            c,
            PolicyConfig {
                loaded: vec!["/p.toml".into()],
                ..PolicyConfig::default()
            }
        );
        assert_eq!(c.scratch_stale_days, SCRATCH_STALE_DAYS);
        assert_eq!(c.confirm, ConfirmMode::Flag);
    }

    #[test]
    fn rejects_what_it_does_not_know() {
        let p = Path::new("/etc/diskwhy/policy.toml");
        for (text, want) in [
            ("max_teir = \"regenerable\"", "unknown field"),
            ("[scratch]\npath = [\"x\"]", "unknown field"),
            ("max_tier = \"blocked\"", "blocked"),
            ("max_tier = \"everything\"", "unknown variant"),
            ("confirm = \"sometimes\"", "unknown variant"),
            ("[scratch]\nstale_days = 0", "at least 1"),
            ("[scratch]\nstale_days = -3", "at least 1"),
            ("[scratch]\npaths = [\"\"]", "must not be empty"),
            ("[scratch]\npaths = [\"~\"]", "only ~/"),
            ("[scratch]\npaths = [\"/\"]", "below /"),
            ("[scratch]\npaths = [\"~/../x\"]", ".."),
            ("[scratch]\npaths = [\"a*/b\"]", "only at the end"),
            ("[scratch]\npaths = [\"*\"]", "prefix"),
            ("max_tier = ", "line 1"),
            ("max_tier = \"review\"\nmax_tier = \"review\"", "duplicate"),
        ] {
            let e = PolicyConfig::parse(text, p).unwrap_err();
            assert!(
                e.contains("invalid policy file /etc/diskwhy/policy.toml"),
                "{e}"
            );
            assert!(e.contains(want), "{text:?}: {e}");
            assert!(!e.contains('\n'), "{e:?}");
        }
    }

    #[test]
    fn missing_files_are_skipped_and_others_fail_closed() {
        let t = tempfile::tempdir().unwrap();
        let none = t.path().join("none.toml");
        assert_eq!(
            PolicyConfig::load_from(Some(&none), Some(&none)).unwrap(),
            PolicyConfig::default()
        );
        // A directory where the file should be: not NotFound, so an error.
        let e = PolicyConfig::load_from(Some(t.path()), None).unwrap_err();
        assert!(e.starts_with("cannot read policy file"), "{e}");
        let bad = write(t.path(), "bad.toml", "max_tier = [");
        let e = PolicyConfig::load_from(Some(&none), Some(&bad)).unwrap_err();
        assert!(e.contains("bad.toml"), "{e}");
        let e = PolicyConfig::load_from(Some(&bad), Some(&none)).unwrap_err();
        assert!(e.contains("bad.toml"), "{e}");
    }

    #[test]
    fn the_system_file_is_a_ceiling_the_user_file_can_only_lower() {
        let t = tempfile::tempdir().unwrap();
        let sys = write(
            t.path(),
            "sys.toml",
            "max_tier = \"rebuildable\"\nconfirm = \"interactive\"\n\
             [scratch]\npaths = [\"/srv/scratch\", \"~/a\"]\nstale_days = 14\n",
        );
        // The user file tries to loosen everything.
        let loose = write(
            t.path(),
            "loose.toml",
            "max_tier = \"review\"\nconfirm = \"flag\"\n\
             [scratch]\npaths = [\"~/a\", \"~/b\"]\nstale_days = 3\n",
        );
        let c = PolicyConfig::load_from(Some(&sys), Some(&loose)).unwrap();
        assert_eq!(c.max_tier, Some(Tier::Rebuildable));
        assert_eq!(c.max_tier_source.as_deref(), Some(sys.as_path()));
        assert_eq!(c.confirm, ConfirmMode::Interactive);
        assert_eq!(c.confirm_source.as_deref(), Some(sys.as_path()));
        assert_eq!(c.scratch_paths, ["/srv/scratch", "~/a", "~/b"]);
        assert_eq!(c.scratch_stale_days, 14);
        assert_eq!(c.loaded, [sys.clone(), loose.clone()]);

        // And to tighten everything.
        let tight = write(
            t.path(),
            "tight.toml",
            "max_tier = \"regenerable\"\nconfirm = \"never\"\n[scratch]\nstale_days = 30\n",
        );
        let c = PolicyConfig::load_from(Some(&sys), Some(&tight)).unwrap();
        assert_eq!(c.max_tier, Some(Tier::Regenerable));
        assert_eq!(c.max_tier_source.as_deref(), Some(tight.as_path()));
        assert_eq!(c.confirm, ConfirmMode::Never);
        assert_eq!(c.confirm_source.as_deref(), Some(tight.as_path()));
        assert_eq!(c.scratch_stale_days, 30);

        // The user file alone sets what it sets.
        let c = PolicyConfig::load_from(None, Some(&loose)).unwrap();
        assert_eq!(c.max_tier, Some(Tier::Review));
        assert_eq!(c.confirm, ConfirmMode::Flag);
        assert_eq!(c.confirm_source, None);
        assert_eq!(c.scratch_stale_days, 3);

        // A tie keeps the system file as the source.
        let same = write(t.path(), "same.toml", "max_tier = \"rebuildable\"\n");
        let c = PolicyConfig::load_from(Some(&sys), Some(&same)).unwrap();
        assert_eq!(c.max_tier_source.as_deref(), Some(sys.as_path()));
    }

    #[test]
    fn confirm_modes_order_loose_to_strict() {
        assert!(ConfirmMode::Flag < ConfirmMode::Interactive);
        assert!(ConfirmMode::Interactive < ConfirmMode::Never);
        assert_eq!(ConfirmMode::default(), ConfirmMode::Flag);
    }
}
