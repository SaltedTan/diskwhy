//! Detector framework: the catalog of detectors and their requirements
//! (shared with `dwhy doctor`), the [`Detector`] trait, stable finding IDs,
//! and the rule for nested findings.
//!
//! Detectors only read: they look at the [`ScanTree`] and may read small
//! files, run read-only tool commands, or make read-only Docker API GETs
//! (see [`crate::docker`]). They never remove anything.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::detectors;
use crate::report::{
    Action, ActionKind, DetectorAvailability, DetectorRun, DockerSocket, Finding, GuardResult,
    GuardStatus, Tier, ToolStatus,
};
use crate::tree::ScanTree;

/// What a detector needs from the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    Nothing,
    /// Works without the tool, but removal is not tool-native.
    Prefers(&'static str),
    Requires(&'static str),
    /// The docker CLI and a usable socket.
    Docker,
    RootAnd(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectorInfo {
    pub name: &'static str,
    pub milestone: &'static str,
    pub needs: Needs,
}

/// Every detector in docs/DESIGN.md, built or not.
pub const CATALOG: &[DetectorInfo] = &[
    info("cargo-target", "M1", Needs::Prefers("cargo")),
    info("node-modules", "M1", Needs::Nothing),
    info("venv", "M1", Needs::Nothing),
    info("user-cache", "M1", Needs::Nothing),
    info("git-worktree", "M1", Needs::Requires("git")),
    info("stale-tree", "M1", Needs::Nothing),
    info("tool-versions", "M1", Needs::Nothing),
    info("trash", "M1", Needs::Nothing),
    info("docker-image", "M1", Needs::Docker),
    info("docker-build-cache", "M1", Needs::Docker),
    info("docker-container", "M1", Needs::Docker),
    info("docker-volume", "M1", Needs::Docker),
    info("journald", "post-MVP", Needs::RootAnd("journalctl")),
];

const fn info(name: &'static str, milestone: &'static str, needs: Needs) -> DetectorInfo {
    DetectorInfo {
        name,
        milestone,
        needs,
    }
}

/// What detectors may know about the system.
#[derive(Debug, Clone)]
pub struct DetectContext {
    pub uid: u32,
    pub root: bool,
    pub home: Option<PathBuf>,
    /// Seconds since the epoch, fixed for the whole run.
    pub now: i64,
    pub tools: Vec<ToolStatus>,
    pub docker_socket: DockerSocket,
    /// The Docker snapshot, fetched once on first use.
    pub docker: Arc<crate::docker::Source>,
}

impl DetectContext {
    /// The real system: euid, `$HOME`, the clock, tools on PATH, the Docker socket.
    pub fn from_system() -> DetectContext {
        let euid = crate::system::euid();
        let docker_socket = crate::doctor::docker_socket();
        let docker = if docker_socket.accessible {
            crate::docker::Source::socket(
                Path::new(&docker_socket.path),
                crate::docker::DEFAULT_TIMEOUT,
            )
        } else {
            crate::docker::Source::none()
        };
        DetectContext {
            uid: euid,
            root: euid == 0,
            home: std::env::var_os("HOME").map(PathBuf::from),
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            tools: crate::doctor::resolve_tools(),
            docker_socket,
            docker,
        }
    }

    /// The command to invoke a tool: its bare name when it is on PATH, the
    /// absolute path when it was only found off PATH, `None` when absent.
    pub fn tool_command(&self, name: &str) -> Option<String> {
        let t = self.tools.iter().find(|t| t.name == name)?;
        if t.path.is_some() {
            Some(name.to_string())
        } else {
            t.off_path.clone()
        }
    }

    fn on_path(&self, name: &str) -> bool {
        self.tools
            .iter()
            .any(|t| t.name == name && t.path.is_some())
    }

    fn missing(&self, name: &str) -> String {
        match self
            .tools
            .iter()
            .find(|t| t.name == name)
            .and_then(|t| t.off_path.as_ref())
        {
            Some(p) => format!("`{name}` is not on PATH (found at {p}; add its directory to PATH)"),
            None => format!("`{name}` is not installed"),
        }
    }
}

/// Whether a detector's requirements are met, with a one-line reason.
pub fn availability(info: &DetectorInfo, ctx: &DetectContext) -> (DetectorAvailability, String) {
    use DetectorAvailability::*;
    let sock = &ctx.docker_socket;
    match info.needs {
        Needs::Nothing => (Available, "no external tool needed".into()),
        Needs::Prefers(t) if ctx.on_path(t) => (Available, format!("uses `{t}` for removal")),
        Needs::Prefers(t) if ctx.tool_command(t).is_some() => (
            Available,
            format!(
                "uses {} for removal (not on PATH)",
                ctx.tool_command(t).unwrap_or_default()
            ),
        ),
        Needs::Prefers(t) => (
            Degraded,
            format!(
                "{}; detection works, removal falls back to path removal",
                ctx.missing(t)
            ),
        ),
        Needs::Requires(t) if ctx.on_path(t) => (Available, format!("uses `{t}`")),
        Needs::Requires(t) => (Unavailable, ctx.missing(t)),
        Needs::Docker if !ctx.on_path("docker") => (Unavailable, ctx.missing("docker")),
        Needs::Docker if !sock.exists => {
            (Unavailable, format!("no Docker socket at {}", sock.path))
        }
        Needs::Docker if !sock.accessible => (
            Unavailable,
            format!(
                "cannot use {} (not root and not in the docker group)",
                sock.path
            ),
        ),
        Needs::Docker => (Available, "uses the docker CLI and socket".into()),
        Needs::RootAnd(t) if !ctx.on_path(t) => (Unavailable, ctx.missing(t)),
        Needs::RootAnd(_) if !ctx.root => (Unavailable, "system detector; run as root".into()),
        Needs::RootAnd(t) => (Available, format!("uses `{t}`")),
    }
}

/// One kind of reclaimable thing.
pub trait Detector: Send + Sync {
    /// Must match a [`CATALOG`] entry.
    fn name(&self) -> &'static str;
    /// An `Err` is reported in the run's `error` and yields no findings.
    fn detect(&self, tree: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String>;
}

/// Stable across runs and machines: `f_` + 12 hex digits of FNV-1a over
/// the detector name and path.
pub fn finding_id(detector: &str, path: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in detector
        .bytes()
        .chain(std::iter::once(0u8))
        .chain(path.bytes())
    {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("f_{:012x}", h >> 16)
}

/// Quotes `s` for a POSIX shell when it holds anything outside a safe set.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+:@=,".contains(&b))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The guard on a finding that names a path that is not valid UTF-8.
pub const PATH_NOT_UTF8: &str = "path-not-utf8";

/// The advice that replaces the action of a finding [`block_lossy`] blocks.
pub const PATH_NOT_UTF8_ADVICE: &str =
    "rename the path that is not valid UTF-8 to valid UTF-8 and scan again, or remove it by hand";

/// Whether `s` holds U+FFFD, the stand-in `to_string_lossy` puts in place
/// of bytes that are not valid UTF-8.
pub fn is_lossy(s: &str) -> bool {
    s.contains(char::REPLACEMENT_CHARACTER)
}

/// Why diskwhy cannot act on `f` exactly: which of its path, action
/// (argv or text) and recovery (command or cost) hold U+FFFD, as the
/// `path-not-utf8` guard's detail. `None` when none does.
pub fn lossy_detail(f: &Finding) -> Option<String> {
    let action = f.action.argv.iter().flatten().any(|a| is_lossy(a)) || is_lossy(&f.action.text);
    let recovery = f.recovery.how.as_deref().is_some_and(is_lossy) || is_lossy(&f.recovery.cost);
    let what = if is_lossy(&f.path) {
        "the path is not valid UTF-8 (shown with U+FFFD)"
    } else {
        match (action, recovery) {
            (true, true) => {
                "the action and recovery name a path that is not valid UTF-8 (shown with U+FFFD)"
            }
            (true, false) => "the action names a path that is not valid UTF-8 (shown with U+FFFD)",
            (false, true) => {
                "the recovery names a path that is not valid UTF-8 (shown with U+FFFD)"
            }
            (false, false) => return None,
        }
    };
    Some(format!("{what}; diskwhy cannot act on it exactly"))
}

/// Blocks every finding whose path, action or recovery holds U+FFFD: a
/// command or path built from a lossy spelling can name a different, real
/// path. The finding keeps its id, path, bytes and detector, so the space
/// is still accounted for; its tier becomes `blocked`, it gets a
/// `path-not-utf8` guard, its action becomes advice with no argv, and a
/// recovery command or cost that holds U+FFFD is replaced by a note. A
/// real name that holds U+FFFD is blocked too: diskwhy cannot tell it from
/// a lossy one. Idempotent. Run on every detection result, before the
/// nesting rule, so a blocked finding keeps the findings inside it.
pub fn block_lossy(findings: &mut [Finding]) {
    for f in findings {
        let Some(detail) = lossy_detail(f) else {
            continue;
        };
        f.tier = Tier::Blocked;
        f.guards.retain(|g| g.name != PATH_NOT_UTF8);
        f.guards.push(GuardResult {
            name: PATH_NOT_UTF8.into(),
            status: GuardStatus::Block,
            detail,
        });
        f.action = Action {
            kind: ActionKind::Advice,
            text: PATH_NOT_UTF8_ADVICE.into(),
            argv: None,
        };
        if f.recovery.how.as_deref().is_some_and(is_lossy) {
            f.recovery.how = Some(
                "by hand: the command names a path that is not valid UTF-8, so it is not shown"
                    .into(),
            );
        }
        if is_lossy(&f.recovery.cost) {
            f.recovery.cost = "not shown: it names a path that is not valid UTF-8".into();
        }
        const NOTE: &str = "; a path it names is not valid UTF-8, so not offered";
        if !f.reason.ends_with(NOTE) {
            f.reason.push_str(NOTE);
        }
    }
}

/// Applies the nesting rule to filesystem findings, so no byte is counted
/// twice. A finding whose path lies inside another kept finding's path is
/// dropped, unless its tier is cheaper than that finding's or that finding
/// is `blocked`: then it is kept, and its bytes go into the nearest kept
/// finding around it as `nested_bytes`, named in that one's reason. Of two
/// findings at the same path the cheaper tier is the outer one.
/// Pseudo-paths such as `docker://...` never nest. Returns the survivors,
/// largest first.
pub fn outermost(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        Path::new(&a.path)
            .cmp(Path::new(&b.path))
            .then_with(|| a.tier.cmp(&b.tier))
            .then_with(|| a.detector.cmp(&b.detector))
    });
    let mut kept: Vec<Finding> = Vec::new();
    let mut nested: Vec<(u64, usize)> = Vec::new();
    let mut chain: Vec<usize> = Vec::new();
    for f in findings {
        if f.path.starts_with('/') {
            let p = Path::new(&f.path);
            while chain
                .last()
                .is_some_and(|&i| !p.starts_with(Path::new(&kept[i].path)))
            {
                chain.pop();
            }
            if let Some(&outer) = chain.last() {
                let t = kept[outer].tier;
                if f.tier >= t && t != Tier::Blocked {
                    continue;
                }
                nested[outer].0 += f.bytes;
                nested[outer].1 += 1;
            }
            chain.push(kept.len());
        }
        kept.push(f);
        nested.push((0, 0));
    }
    for (f, (bytes, n)) in kept.iter_mut().zip(nested) {
        if n > 0 {
            f.nested_bytes = Some(bytes);
            f.reason.push_str(&format!(
                "; {} of it is in {n} finding{} inside it, reported separately",
                crate::units::human(bytes),
                if n == 1 { "" } else { "s" }
            ));
        }
    }
    kept.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.id.cmp(&b.id)));
    kept
}

/// Runs every built detector whose requirements are met.
pub fn run(tree: &ScanTree, ctx: &DetectContext) -> (Vec<Finding>, Vec<DetectorRun>) {
    run_with(tree, ctx, &detectors::registry(), None)
}

/// Checks `--detectors` names against the catalog.
pub fn validate_selection(names: &[String]) -> Result<(), String> {
    match names
        .iter()
        .find(|n| !CATALOG.iter().any(|d| d.name == n.as_str()))
    {
        Some(bad) => Err(format!(
            "unknown detector {bad:?}; known: {}",
            CATALOG
                .iter()
                .map(|d| d.name)
                .collect::<Vec<_>>()
                .join(", ")
        )),
        None => Ok(()),
    }
}

/// Runs the detectors (all, or `only`), then the probes when `probe`, and
/// puts their findings and Docker's totals in `report`. Returns the Docker
/// state when it was fetched. What `dwhy scan` and the TUI both run.
pub fn detect_into(
    report: &mut crate::report::ScanReport,
    tree: &ScanTree,
    only: Option<&[String]>,
    probe: bool,
) -> Option<Arc<crate::docker::Snapshot>> {
    detect_into_with(report, tree, &DetectContext::from_system(), only, probe)
}

/// [`detect_into`] with the caller's context.
pub fn detect_into_with(
    report: &mut crate::report::ScanReport,
    tree: &ScanTree,
    ctx: &DetectContext,
    only: Option<&[String]>,
    probe: bool,
) -> Option<Arc<crate::docker::Snapshot>> {
    let (mut findings, runs) = run_with(tree, ctx, &detectors::registry(), only);
    if probe {
        crate::probes::run(&mut findings, ctx);
        // Probes may rewrite a reason or advice; check what they wrote too.
        block_lossy(&mut findings);
    }
    report.findings = findings;
    report.detectors = runs;
    let snap = ctx.docker.fetched()?;
    crate::account::attach_docker(report, &crate::docker::usage(&snap));
    Some(snap)
}

/// Like [`run`], limited to the named detectors when `only` is given.
pub fn run_with(
    tree: &ScanTree,
    ctx: &DetectContext,
    built: &[Box<dyn Detector>],
    only: Option<&[String]>,
) -> (Vec<Finding>, Vec<DetectorRun>) {
    let (findings, runs) = run_candidates(tree, ctx, built, only);
    (outermost(findings), runs)
}

/// Runs the detectors (all, or `only`) and returns every finding, before
/// the nesting rule, with [`block_lossy`] applied: the detection that
/// `dwhy scan`, `explain`, `plan`, `apply` and the TUI all go through.
pub fn run_candidates(
    tree: &ScanTree,
    ctx: &DetectContext,
    built: &[Box<dyn Detector>],
    only: Option<&[String]>,
) -> (Vec<Finding>, Vec<DetectorRun>) {
    let mut all = Vec::new();
    let mut runs = Vec::new();
    for info in CATALOG {
        let (status, detail) = availability(info, ctx);
        let det = built.iter().find(|d| d.name() == info.name);
        let mut run = DetectorRun {
            name: info.name.into(),
            status,
            detail,
            ran: false,
            findings: 0,
            elapsed_ms: 0,
            error: None,
        };
        let selected = only.is_none_or(|o| o.iter().any(|n| n == info.name));
        match det {
            None => {
                run.status = DetectorAvailability::NotImplemented;
                run.detail = format!("not implemented yet ({})", info.milestone);
            }
            _ if !selected => {
                run.detail = format!("not selected (--detectors); {}", run.detail);
            }
            Some(_) if status == DetectorAvailability::Unavailable => {}
            Some(d) => {
                let start = Instant::now();
                let result = d.detect(tree, ctx);
                run.ran = true;
                run.elapsed_ms = start.elapsed().as_millis() as u64;
                match result {
                    Ok(found) => {
                        run.findings = found.len() as u64;
                        all.extend(found);
                    }
                    Err(e) => run.error = Some(e),
                }
            }
        }
        runs.push(run);
    }
    block_lossy(&mut all);
    (all, runs)
}

/// RFC 3339 (UTC) for seconds since the epoch.
pub fn rfc3339(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}

/// "3 days", "5 hours", "just now".
pub fn age(now: i64, then: i64) -> String {
    let s = (now - then).max(0);
    let (n, unit) = match s {
        s if s < 3600 => return "less than an hour".into(),
        s if s < 86_400 => (s / 3600, "hour"),
        s if s < 86_400 * 60 => (s / 86_400, "day"),
        s => (s / (86_400 * 30), "month"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::*;

    pub(crate) fn ctx(tools: &[(&str, Option<&str>, Option<&str>)]) -> DetectContext {
        DetectContext {
            uid: 1000,
            root: false,
            home: Some("/home/me".into()),
            now: 1_800_000_000,
            tools: tools
                .iter()
                .map(|(n, p, off)| ToolStatus {
                    name: (*n).into(),
                    path: p.map(String::from),
                    off_path: off.map(String::from),
                    enables: vec![],
                })
                .collect(),
            docker_socket: DockerSocket {
                path: "/var/run/docker.sock".into(),
                exists: false,
                accessible: false,
            },
            docker: crate::docker::Source::none(),
        }
    }

    fn f(det: &str, path: &str, bytes: u64) -> Finding {
        Finding {
            id: finding_id(det, path),
            detector: det.into(),
            probe: None,
            evidence: None,
            path: path.into(),
            bytes,
            nested_bytes: None,
            last_modified: None,
            growth: None,
            tier: Tier::Rebuildable,
            reason: String::new(),
            guards: vec![],
            action: Action {
                kind: ActionKind::RemovePath,
                text: String::new(),
                argv: None,
            },
            recovery: Recovery {
                cost: String::new(),
                how: None,
            },
        }
    }

    #[test]
    fn ids_are_stable_and_distinct() {
        let a = finding_id("cargo-target", "/home/me/x/target");
        assert_eq!(a, finding_id("cargo-target", "/home/me/x/target"));
        assert_eq!(a.len(), 14);
        assert!(a.starts_with("f_"));
        assert_ne!(a, finding_id("node-modules", "/home/me/x/target"));
        assert_ne!(a, finding_id("cargo-target", "/home/me/y/target"));
        // Pinned: IDs must not change between releases.
        assert_eq!(a, "f_c2b7afdaa165");
    }

    #[test]
    fn outermost_finding_wins() {
        let kept = outermost(vec![
            f("node-modules", "/p/scratch/app/node_modules", 10),
            f("stale-tree", "/p/scratch", 50),
            f("cargo-target", "/p/scratchy/target", 5),
            f("cargo-target", "/p/scratch-x/target", 3),
            f("docker-volume", "docker://volume/v", 99),
            f("venv", "/q/.venv", 7),
        ]);
        let paths: Vec<&str> = kept.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "docker://volume/v",
                "/p/scratch",
                "/q/.venv",
                "/p/scratchy/target",
                "/p/scratch-x/target"
            ]
        );
    }

    fn ft(det: &str, path: &str, bytes: u64, tier: Tier) -> Finding {
        Finding {
            tier,
            reason: "why".into(),
            ..f(det, path, bytes)
        }
    }

    fn by_path(kept: &[Finding]) -> Vec<(&str, Option<u64>)> {
        let mut v: Vec<_> = kept
            .iter()
            .map(|f| (f.path.as_str(), f.nested_bytes))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn review_finding_keeps_cheaper_findings_inside_it() {
        let kept = outermost(vec![
            ft("git-worktree", "/w/x", 100, Tier::Review),
            ft("cargo-target", "/w/x/target", 30, Tier::Rebuildable),
            ft("venv", "/w/x/.venv", 20, Tier::Regenerable),
        ]);
        assert_eq!(
            by_path(&kept),
            [
                ("/w/x", Some(50)),
                ("/w/x/.venv", None),
                ("/w/x/target", None)
            ]
        );
        let outer = kept.iter().find(|f| f.path == "/w/x").unwrap();
        assert_eq!(outer.bytes, 100, "bytes still say what removing it frees");
        assert_eq!(
            outer.reason,
            "why; 50B of it is in 2 findings inside it, reported separately"
        );
        let inner = kept.iter().find(|f| f.path == "/w/x/target").unwrap();
        assert_eq!(inner.reason, "why");
    }

    #[test]
    fn blocked_finding_keeps_any_finding_inside_it() {
        let kept = outermost(vec![
            ft("git-worktree", "/w/locked", 100, Tier::Blocked),
            ft("stale-tree", "/w/locked/scratch", 40, Tier::Review),
            ft("user-cache", "/w/locked/cache", 10, Tier::Blocked),
        ]);
        assert_eq!(
            by_path(&kept),
            [
                ("/w/locked", Some(50)),
                ("/w/locked/cache", None),
                ("/w/locked/scratch", None)
            ]
        );
    }

    #[test]
    fn same_or_dearer_tier_inside_is_dropped() {
        let kept = outermost(vec![
            ft("git-worktree", "/w/x", 100, Tier::Review),
            ft("stale-tree", "/w/x/old", 40, Tier::Review),
            ft("cargo-target", "/w/t", 50, Tier::Rebuildable),
            ft(
                "cargo-target",
                "/w/t/package/c/target",
                5,
                Tier::Rebuildable,
            ),
            ft("stale-tree", "/w/t/tmp", 5, Tier::Review),
        ]);
        assert_eq!(by_path(&kept), [("/w/t", None), ("/w/x", None)]);
        assert!(kept.iter().all(|f| f.reason == "why"));
    }

    #[test]
    fn same_path_keeps_the_cheaper_tier() {
        let kept = outermost(vec![
            ft("a-review", "/w/x", 100, Tier::Review),
            ft("z-rebuildable", "/w/x", 100, Tier::Rebuildable),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].detector, "z-rebuildable");
        assert_eq!(kept[0].nested_bytes, None);
    }

    #[test]
    fn nested_bytes_of_a_chain_count_each_byte_once() {
        let kept = outermost(vec![
            ft("git-worktree", "/w/locked", 100, Tier::Blocked),
            ft("stale-tree", "/w/locked/proj", 60, Tier::Review),
            ft(
                "cargo-target",
                "/w/locked/proj/target",
                25,
                Tier::Rebuildable,
            ),
            ft("venv", "/w/locked/proj/target/.venv", 5, Tier::Regenerable),
        ]);
        assert_eq!(
            by_path(&kept),
            [
                ("/w/locked", Some(60)),
                ("/w/locked/proj", Some(25)),
                ("/w/locked/proj/target", Some(5)),
                ("/w/locked/proj/target/.venv", None)
            ]
        );
        let own: u64 = kept
            .iter()
            .map(|f| f.bytes - f.nested_bytes.unwrap_or(0))
            .sum();
        assert_eq!(own, 100);
    }

    fn cmd(det: &str, path: &str, bytes: u64, tier: Tier, argv: &[&str]) -> Finding {
        let mut f = ft(det, path, bytes, tier);
        f.action = Action {
            kind: ActionKind::Command,
            text: argv.join(" "),
            argv: Some(argv.iter().map(|a| a.to_string()).collect()),
        };
        f
    }

    #[test]
    fn findings_naming_a_lossy_path_are_blocked_with_advice() {
        let mut found = vec![
            // Its own path is lossy.
            cmd(
                "cargo-target",
                "/w/app\u{FFFD}/target",
                10,
                Tier::Rebuildable,
                &["cargo", "clean", "--target-dir", "/w/app\u{FFFD}/target"],
            ),
            // Only its command is (git-worktree's main repository, #61).
            cmd(
                "git-worktree",
                "/w/wt",
                20,
                Tier::Review,
                &[
                    "git",
                    "-C",
                    "/w/repo\u{FFFD}",
                    "worktree",
                    "remove",
                    "/w/wt",
                ],
            ),
            // Only its recovery is.
            {
                let mut f = ft("venv", "/w/v/.venv", 5, Tier::Regenerable);
                f.recovery.how = Some("cd /w/v\u{FFFD} && uv sync".into());
                f
            },
            // Valid UTF-8 that is not ASCII stays actionable.
            cmd(
                "cargo-target",
                "/w/café/target",
                7,
                Tier::Rebuildable,
                &["cargo", "clean", "--target-dir", "/w/café/target"],
            ),
        ];
        let before = found.clone();
        block_lossy(&mut found);
        for (f, was) in found.iter().zip(&before).take(3) {
            assert_eq!(f.tier, Tier::Blocked, "{f:?}");
            assert_eq!((&f.id, &f.path, f.bytes), (&was.id, &was.path, was.bytes));
            assert_eq!(f.detector, was.detector);
            assert_eq!(f.action.kind, ActionKind::Advice);
            assert_eq!(f.action.argv, None);
            assert_eq!(f.action.text, PATH_NOT_UTF8_ADVICE);
            assert!(!is_lossy(&f.action.text));
            assert!(!f.recovery.how.as_deref().is_some_and(is_lossy));
            let g: Vec<_> = f
                .guards
                .iter()
                .map(|g| (g.name.as_str(), g.status))
                .collect();
            assert_eq!(g, [(PATH_NOT_UTF8, GuardStatus::Block)]);
            assert!(f.reason.ends_with("so not offered"), "{}", f.reason);
        }
        assert_eq!(
            found[0].guards[0].detail,
            "the path is not valid UTF-8 (shown with U+FFFD); diskwhy cannot act on it exactly"
        );
        assert_eq!(
            found[1].guards[0].detail,
            "the action names a path that is not valid UTF-8 (shown with U+FFFD); \
             diskwhy cannot act on it exactly"
        );
        assert!(found[2].guards[0].detail.starts_with("the recovery names"));
        assert_eq!(found[3], before[3], "café is valid UTF-8");

        // Running it again changes nothing.
        let once = found.clone();
        block_lossy(&mut found);
        assert_eq!(found, once);
    }

    #[test]
    fn a_lossy_finding_does_not_hide_cheaper_findings_inside_it() {
        // The worktree is blocked because its command names a lossy main
        // repository; the build output inside it is still offered.
        let mut found = vec![
            cmd(
                "git-worktree",
                "/w/wt",
                100,
                Tier::Review,
                &[
                    "git",
                    "-C",
                    "/w/repo\u{FFFD}",
                    "worktree",
                    "remove",
                    "/w/wt",
                ],
            ),
            ft("stale-tree", "/w/wt/old", 30, Tier::Review),
            ft("cargo-target", "/w/wt/target", 40, Tier::Rebuildable),
        ];
        block_lossy(&mut found);
        let kept = outermost(found);
        assert_eq!(
            by_path(&kept),
            [
                ("/w/wt", Some(70)),
                ("/w/wt/old", None),
                ("/w/wt/target", None)
            ]
        );

        // A lossy finding inside an exact one is covered by it: removing
        // the outer path, which is exact, frees it.
        let mut found = vec![
            ft("stale-tree", "/w/scratch", 100, Tier::Review),
            ft(
                "cargo-target",
                "/w/scratch/app\u{FFFD}/target",
                40,
                Tier::Rebuildable,
            ),
        ];
        block_lossy(&mut found);
        assert_eq!(by_path(&outermost(found)), [("/w/scratch", None)]);
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(shell_quote("/"), "/");
        assert_eq!(shell_quote("--target-dir"), "--target-dir");
        assert_eq!(shell_quote("/mnt/my disk"), "'/mnt/my disk'");
        assert_eq!(shell_quote("/a'b"), r"'/a'\''b'");
        assert_eq!(shell_quote("/x/$(echo x)"), "'/x/$(echo x)'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn availability_rules() {
        let none = ctx(&[]);
        let cargo = CATALOG.iter().find(|d| d.name == "cargo-target").unwrap();
        assert_eq!(availability(cargo, &none).0, DetectorAvailability::Degraded);
        let off = ctx(&[("cargo", None, Some("/home/me/.cargo/bin/cargo"))]);
        assert_eq!(availability(cargo, &off).0, DetectorAvailability::Available);
        assert_eq!(
            off.tool_command("cargo").as_deref(),
            Some("/home/me/.cargo/bin/cargo")
        );
        let on = ctx(&[("cargo", Some("/usr/bin/cargo"), None)]);
        assert_eq!(on.tool_command("cargo").as_deref(), Some("cargo"));
        let git = CATALOG.iter().find(|d| d.name == "git-worktree").unwrap();
        assert_eq!(
            availability(git, &none).0,
            DetectorAvailability::Unavailable
        );
        let dock = CATALOG.iter().find(|d| d.name == "docker-image").unwrap();
        let with_cli = ctx(&[("docker", Some("/usr/bin/docker"), None)]);
        assert_eq!(
            availability(dock, &with_cli).0,
            DetectorAvailability::Unavailable,
            "no socket"
        );
    }

    #[test]
    fn unbuilt_detectors_are_reported_not_run() {
        let tree = ScanTree::default();
        let (found, runs) = run_with(&tree, &ctx(&[]), &[], None);
        assert!(found.is_empty());
        assert_eq!(runs.len(), CATALOG.len());
        assert!(
            runs.iter()
                .all(|r| !r.ran && r.status == DetectorAvailability::NotImplemented)
        );

        let only = vec!["cargo-target".to_string()];
        let (_, runs) = run_with(&tree, &ctx(&[]), &[], Some(&only));
        assert!(
            runs.iter()
                .all(|r| !r.ran && r.status == DetectorAvailability::NotImplemented),
            "{runs:?}"
        );
    }

    #[test]
    fn ages() {
        assert_eq!(age(100_000, 100_000 - 60), "less than an hour");
        assert_eq!(age(100_000, 100_000 - 7200), "2 hours");
        assert_eq!(age(10_000_000, 10_000_000 - 86_400), "1 day");
        assert_eq!(age(100_000_000, 100_000_000 - 86_400 * 90), "3 months");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    }
}
