//! `dwhy-mcp`: a thin MCP server over `dwhy-core` for agent clients without
//! a shell. Six tools (`scan`, `explain`, `diff`, `watch`, `plan`, `apply`)
//! run the same code as `dwhy` ([`dwhy_core::ops`]) and return `diskwhy/v1`
//! JSON as text; failures return an `ErrorReport` with `isError: true`.
//!
//! The person who launches the server sets what `apply` may do: the
//! highest tier it removes (`--max-tier`, `regenerable` or `rebuildable`)
//! and whether it exists at all (`--read-only`). The model cannot raise
//! either: `apply` takes no tier and no confirmations, so review items are
//! never removed through MCP, and the policy config
//! (`/etc/diskwhy/policy.toml`, then the user's) can lower the ceiling.
//!
//! stdout carries the protocol. Nothing here writes to it; warnings go to
//! stderr.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use dwhy_core::apply::{self, Audit, AuditInvocation, Policy};
use dwhy_core::detect;
use dwhy_core::mounts::MountTable;
use dwhy_core::ops;
use dwhy_core::plan::{self, Selection};
use dwhy_core::report::{
    ApplyReport, DEFAULT_SUMMARY_DEPTH, DEFAULT_SUMMARY_DIRS, DEFAULT_SUMMARY_FINDINGS, ErrorKind,
    ErrorReport, SummaryLimits, Tier,
};
use dwhy_core::scan::{Progress, ScanError, ScanResult};
use dwhy_core::units;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Exit code of an `ErrorReport` for a usage error or a failure.
pub const EXIT_ERROR: u8 = 1;
/// Exit code of an `ErrorReport` for a refusal.
pub const EXIT_REFUSED: u8 = 3;

/// The highest tier the server's `apply` removes. Review items always need
/// a person's confirmation, which an MCP model cannot give, so `review` is
/// not a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum MaxTier {
    /// Caches a tool recreates on demand.
    #[default]
    Regenerable,
    /// Build outputs and environments that cost a rebuild.
    Rebuildable,
}

impl From<MaxTier> for Tier {
    fn from(t: MaxTier) -> Tier {
        match t {
            MaxTier::Regenerable => Tier::Regenerable,
            MaxTier::Rebuildable => Tier::Rebuildable,
        }
    }
}

/// What the person launching the server decided.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The highest tier `apply` removes (the policy config can lower it).
    pub max_tier: MaxTier,
    /// No `apply` tool: it is not listed, and calls to it are refused.
    pub read_only: bool,
}

/// The MCP server.
#[derive(Debug, Clone)]
pub struct Server {
    options: Arc<Options>,
    tool_router: ToolRouter<Server>,
    /// One apply at a time.
    apply_lock: Arc<tokio::sync::Mutex<()>>,
}

const INSTRUCTIONS: &str = "\
diskwhy answers why a Linux disk is filling up and what is safe to remove. Tools return \
diskwhy/v1 JSON (sizes in bytes); a failure is an ErrorReport (kind usage|error|refused, \
message, hint, exit_code) with isError set. Workflow: `scan` a path (a compact summary by \
default), `explain` a finding by id or path, `plan` findings, then pass the returned Plan \
object unchanged to `apply` (try dry_run first). Tiers: regenerable (caches) < rebuildable \
(build outputs) < review (needs a person) < blocked. `apply` removes at most the tier this \
server was started with and never review items; for more, show the user the plan and let \
them run `dwhy apply` themselves. `diff` compares with a snapshot saved by `scan` with \
snapshot: true; `watch` measures growth over a short window.";

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("dwhy-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if self.options.read_only && request.name == "apply" {
            return Ok(error_result(&read_only_refusal()).into());
        }
        let tcc = ToolCallContext::new(self, request, context);
        let mut response = self.tool_router.call(tcc).await?;
        // Arguments that do not deserialize come back as plain text: say
        // so as a usage ErrorReport, like every other failure.
        if let CallToolResponse::Complete(result) = &mut response
            && result.is_error == Some(true)
            && let [ContentBlock::Text(text)] = result.content.as_slice()
            && serde_json::from_str::<ErrorReport>(&text.text).is_err()
        {
            *result = error_result(&usage(text.text.clone()));
        }
        Ok(response)
    }
}

/// `scan`'s arguments.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanParams {
    /// Directories to scan (default: the server's current directory).
    pub paths: Option<Vec<String>>,
    /// Compact report (default true): keep the largest directories (`depth`
    /// deep, 25 at most) and `max_findings` findings, and add
    /// `findings_summary` totals over every finding. false returns every
    /// directory above `min_size` and every finding, which can be large.
    pub summary: Option<bool>,
    /// Only report findings in these tiers.
    pub tier: Option<Vec<ScanTier>>,
    /// Run only these detectors (names as `dwhy doctor` lists them).
    pub detectors: Option<Vec<String>>,
    /// Only measure; do not run detectors.
    pub no_detectors: Option<bool>,
    /// With summary: the most findings kept (default 20).
    pub max_findings: Option<usize>,
    /// With summary: the deepest directory level kept (default 3).
    pub depth: Option<u32>,
    /// Smallest directory to report, e.g. "100M" (default: 1% of the
    /// scanned total, at most 100M).
    pub min_size: Option<String>,
    /// Descend into other filesystems mounted below the paths (default
    /// false).
    pub cross_filesystems: Option<bool>,
    /// Save a snapshot of the whole scan for `diff` in diskwhy's state
    /// directory (default false).
    pub snapshot: Option<bool>,
}

/// A tier `scan` can filter on.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanTier {
    Regenerable,
    Rebuildable,
    Review,
    Blocked,
}

impl From<ScanTier> for Tier {
    fn from(t: ScanTier) -> Tier {
        match t {
            ScanTier::Regenerable => Tier::Regenerable,
            ScanTier::Rebuildable => Tier::Rebuildable,
            ScanTier::Review => Tier::Review,
            ScanTier::Blocked => Tier::Blocked,
        }
    }
}

/// `explain`'s arguments.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExplainParams {
    /// A finding id (f_…, looked up in the snapshots), a path, or a
    /// pseudo-path such as docker://volume/NAME.
    pub target: String,
    /// Run only these detectors.
    pub detectors: Option<Vec<String>>,
}

/// `diff`'s arguments.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffParams {
    /// Directories to rescan (default: the roots of the snapshot compared
    /// with).
    pub paths: Option<Vec<String>>,
    /// Snapshot to compare with: "last" (default, the newest), an id, a
    /// duration ("24h", "7d": the newest at least that old) or an RFC 3339
    /// time (the newest taken by then).
    pub since: Option<String>,
    /// Leave out what changed by less than this, either way (default "10M").
    pub min_change: Option<String>,
    /// Descend into other filesystems mounted below `paths` (needs `paths`).
    pub cross_filesystems: Option<bool>,
    /// Run only these detectors.
    pub detectors: Option<Vec<String>>,
    /// Only measure; findings are not compared.
    pub no_detectors: Option<bool>,
    /// Also save the fresh scan as a snapshot (default false).
    pub snapshot: Option<bool>,
}

/// `watch`'s arguments.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchParams {
    /// Directories to watch (default: the server's current directory).
    pub paths: Option<Vec<String>>,
    /// How long to watch, at least "1s" (default "60s"); the call takes
    /// that long.
    pub duration: Option<String>,
    /// Leave out what changed by less than this (default "1M").
    pub min_change: Option<String>,
    /// Descend into other filesystems mounted below the paths.
    pub cross_filesystems: Option<bool>,
    /// Do not ask the Docker daemon for its figures.
    pub no_docker: Option<bool>,
}

/// `plan`'s arguments.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanParams {
    /// Directories to scan (default: the server's current directory).
    pub paths: Option<Vec<String>>,
    /// Highest tier to select (default: regenerable, or no limit with
    /// `select`).
    pub tier: Option<PlanTier>,
    /// Select these findings only: ids or paths.
    pub select: Option<Vec<String>>,
    /// Select the cheapest tiers first (largest within each tier) until at
    /// least this much is planned, e.g. "20G". Not with `select`.
    pub free: Option<String>,
    /// Run only these detectors.
    pub detectors: Option<Vec<String>>,
    /// Descend into other filesystems mounted below the paths.
    pub cross_filesystems: Option<bool>,
}

/// A tier `plan` can select up to (`blocked` is never selected).
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    Regenerable,
    Rebuildable,
    Review,
}

impl From<PlanTier> for Tier {
    fn from(t: PlanTier) -> Tier {
        match t {
            PlanTier::Regenerable => Tier::Regenerable,
            PlanTier::Rebuildable => Tier::Rebuildable,
            PlanTier::Review => Tier::Review,
        }
    }
}

/// `apply`'s arguments. There is deliberately no tier and no confirmation:
/// the server's launch flags and the policy config decide those.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyParams {
    /// The diskwhy/v1 Plan object `plan` returned, unchanged.
    pub plan: serde_json::Map<String, serde_json::Value>,
    /// Show what would be removed; remove nothing (default false).
    pub dry_run: Option<bool>,
}

#[tool_router(router = tool_router)]
impl Server {
    pub fn new(options: Options) -> Server {
        let mut tool_router = Self::tool_router();
        if options.read_only {
            tool_router.remove_route("apply");
        }
        Server {
            options: Arc::new(options),
            tool_router,
            apply_lock: Arc::default(),
        }
    }

    /// The server's options.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// Measure disk usage under paths and find what is reclaimable: sizes,
    /// findings (tier, bytes, action), unreadable directories, and space df
    /// counts but the scan cannot see. Returns a diskwhy/v1 ScanReport,
    /// compact by default (`summary`). Writes nothing unless `snapshot` is
    /// true. Its guards are the detectors' only: `plan` and `explain` run
    /// the pre-removal guards.
    #[tool(
        name = "scan",
        annotations(
            title = "Scan disk usage",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn scan(&self, Parameters(p): Parameters<ScanParams>) -> CallToolResult {
        let fe = Quiet;
        blocking(move || {
            if p.no_detectors == Some(true) && p.detectors.is_some() {
                return Err(usage("'no_detectors' cannot be used with 'detectors'"));
            }
            let min_size = size_arg("min_size", p.min_size.as_deref())?;
            let req = ops::ScanRequest {
                paths: paths(p.paths),
                cross_filesystems: p.cross_filesystems.unwrap_or(false),
                min_size,
                no_detectors: p.no_detectors.unwrap_or(false),
                detectors: p.detectors,
                tiers: p.tier.map(|t| t.into_iter().map(Tier::from).collect()),
                summary: p.summary.unwrap_or(true).then_some(SummaryLimits {
                    max_findings: p.max_findings.unwrap_or(DEFAULT_SUMMARY_FINDINGS),
                    max_dirs: DEFAULT_SUMMARY_DIRS,
                    max_depth: p.depth.unwrap_or(DEFAULT_SUMMARY_DEPTH),
                }),
                snapshot: p.snapshot.unwrap_or(false),
            };
            let out = ops::scan(&req, &fe).map_err(error)?;
            with_snapshot_error(&out.report, out.snapshot_error)
        })
        .await
    }

    /// Explain one finding, by id (f_…, from a scan) or path, or a docker://
    /// pseudo-path: evidence, pre-removal guards, growth, action and recovery
    /// cost. Returns a diskwhy/v1 ExplainReport. Writes nothing.
    #[tool(
        name = "explain",
        annotations(
            title = "Explain a finding",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn explain(&self, Parameters(p): Parameters<ExplainParams>) -> CallToolResult {
        let fe = Quiet;
        blocking(move || {
            let report = ops::explain(&p.target, p.detectors.as_deref(), &fe).map_err(error)?;
            content(&report)
        })
        .await
    }

    /// Show what grew since a snapshot saved by `scan` with snapshot: true.
    /// Rescans now and compares directories (snapshots record those of at
    /// least 100 MiB), Docker objects and findings. Returns a diskwhy/v1
    /// DiffReport. Writes nothing unless `snapshot` is true.
    #[tool(
        name = "diff",
        annotations(
            title = "Compare with a snapshot",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn diff(&self, Parameters(p): Parameters<DiffParams>) -> CallToolResult {
        let fe = Quiet;
        blocking(move || {
            if p.no_detectors == Some(true) && p.detectors.is_some() {
                return Err(usage("'no_detectors' cannot be used with 'detectors'"));
            }
            let paths = paths(p.paths);
            let cross_filesystems = p.cross_filesystems.unwrap_or(false);
            if cross_filesystems && paths.is_empty() {
                return Err(usage("'cross_filesystems' needs 'paths'"));
            }
            let req = ops::DiffRequest {
                paths,
                since: p.since.unwrap_or_else(|| "last".into()),
                min_change: size_arg("min_change", Some(p.min_change.as_deref().unwrap_or("10M")))?
                    .unwrap_or_default(),
                cross_filesystems,
                no_detectors: p.no_detectors.unwrap_or(false),
                detectors: p.detectors,
                snapshot: p.snapshot.unwrap_or(false),
            };
            let out = ops::diff(&req, &fe).map_err(error)?;
            with_snapshot_error(&out.report, out.snapshot_error)
        })
        .await
    }

    /// Measure growth now: walks the paths twice, `duration` apart, and
    /// reports bytes per minute for directories and Docker objects. Returns a
    /// diskwhy/v1 WatchReport. Writes nothing; the call takes `duration`.
    #[tool(
        name = "watch",
        annotations(title = "Watch growth", read_only_hint = true, open_world_hint = false)
    )]
    async fn watch(&self, Parameters(p): Parameters<WatchParams>) -> CallToolResult {
        let fe = Quiet;
        blocking(move || {
            let duration = p.duration.as_deref().unwrap_or("60s");
            let window_secs =
                parse_arg("duration", duration, |s| match units::parse_duration(s)? {
                    n if n >= 1 => Ok(n as u64),
                    _ => Err("must be at least 1s".into()),
                })?;
            let req = ops::WatchRequest {
                paths: paths(p.paths),
                window_secs,
                min_change: size_arg("min_change", Some(p.min_change.as_deref().unwrap_or("1M")))?
                    .unwrap_or_default(),
                cross_filesystems: p.cross_filesystems.unwrap_or(false),
                no_docker: p.no_docker.unwrap_or(false),
            };
            let report = ops::watch(&req, &fe).map_err(error)?;
            content(&report)
        })
        .await
    }

    /// Select findings for removal and check the pre-removal guards (git,
    /// processes, containers); nothing is removed or written. Returns a
    /// diskwhy/v1 Plan: pass it unchanged to `apply`. Plans expire.
    #[tool(
        name = "plan",
        annotations(
            title = "Plan a cleanup",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn plan(&self, Parameters(p): Parameters<PlanParams>) -> CallToolResult {
        let fe = Quiet;
        blocking(move || {
            let select = p.select.unwrap_or_default();
            if p.free.is_some() && !select.is_empty() {
                return Err(usage("'free' cannot be used with 'select'"));
            }
            let free = p
                .free
                .as_deref()
                .map(|s| {
                    parse_arg("free", s, |s| match units::parse_size(s)? {
                        0 => Err("must be greater than 0".into()),
                        n => Ok(n),
                    })
                })
                .transpose()?;
            let req = ops::PlanRequest {
                paths: paths(p.paths),
                cross_filesystems: p.cross_filesystems.unwrap_or(false),
                detectors: p.detectors,
                selection: Selection {
                    tier: p.tier.map(Tier::from),
                    select,
                    free,
                },
            };
            let out = ops::plan(&req, &fe).map_err(error)?;
            content(&out.plan)
        })
        .await
    }

    /// Carry out a Plan from `plan`: rescans its roots, re-detects, re-runs
    /// the guards, and removes the items the server's tier ceiling allows.
    /// Review items are never removed here (they need the user), nor
    /// anything above the ceiling the server was started with or the policy
    /// config sets: those come back `refused`. Returns a diskwhy/v1
    /// ApplyReport; each removal is recorded in the audit log.
    #[tool(
        name = "apply",
        annotations(
            title = "Apply a cleanup plan",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn apply(&self, Parameters(p): Parameters<ApplyParams>) -> CallToolResult {
        // Not routed when read-only; refused here too, whatever calls it.
        if self.options.read_only {
            return error_result(&read_only_refusal());
        }
        let _one_at_a_time = self.apply_lock.lock().await;
        let max_tier = self.options.max_tier;
        blocking(move || run_apply(p, max_tier, &Quiet)).await
    }
}

/// The refusal of `apply` on a `--read-only` server.
fn read_only_refusal() -> ErrorReport {
    ErrorReport::new(
        ErrorKind::Refused,
        "apply is disabled: this server was started with --read-only",
        Some("show the user the plan; they can run `dwhy apply` themselves".into()),
        EXIT_REFUSED,
    )
}

/// `apply` under the server's ceiling: no confirmations, no terminal, as if
/// `dwhy apply --yes` ran with no terminal.
fn run_apply(p: ApplyParams, max_tier: MaxTier, fe: &Quiet) -> Result<Vec<ContentBlock>, Failure> {
    let text = serde_json::to_string(&p.plan).map_err(|e| error(e.to_string()))?;
    let plan = plan::parse(&text).map_err(error)?;
    if let Some(names) = &plan.scan.detectors {
        detect::validate_selection(names).map_err(error)?;
    }
    let config = ops::policy_config().map_err(error)?;
    let policy = Policy::with_config(max_tier.into(), Vec::new(), &config, false);
    let env = apply::Env::from_system().with_invocation(AuditInvocation {
        max_tier: policy.max_tier,
        confirm: Vec::new(),
        yes: true,
        tty: false,
    });
    if let Err(e) = plan::usable(&plan, &env.host, env.uid, ops::now_secs()) {
        return Err(Box::new(ErrorReport::new(
            ErrorKind::Refused,
            mcp_wording(&e.to_string()),
            ops::unusable_hint(&e).map(mcp_wording),
            EXIT_REFUSED,
        )));
    }
    let mut checks = ops::survey(&plan, &policy, &config, fe).map_err(error)?;
    if p.dry_run.unwrap_or(false) {
        return content(&apply::report(&plan, &checks, &policy, true, &env));
    }
    let mut audit = Audit::open_placed(Audit::default_path().as_deref()).map_err(error)?;
    let mounts =
        MountTable::read().map_err(|e| error(format!("cannot read the mount table: {e}")))?;
    let audit_errors = apply::execute(&plan, &mut checks, &mut audit, &mounts, &env, &mut |_| {});
    for e in audit_errors {
        log("error", &e);
    }
    let mut r: ApplyReport = apply::report(&plan, &checks, &policy, false, &env);
    r.audit_log = Some(audit.path().to_string_lossy().into_owned());
    content(&r)
}

/// Core messages name the `dwhy plan` command; an MCP client calls the tool.
fn mcp_wording(s: &str) -> String {
    s.replace("`dwhy plan`", "the `plan` tool")
}

/// How the server walks: no progress, no status lines, warnings on stderr.
struct Quiet;

impl ops::Frontend for Quiet {
    fn measure(
        &self,
        paths: &[PathBuf],
        one_filesystem: bool,
        min_dir_bytes: u64,
        mounts: &MountTable,
    ) -> Result<ScanResult, ScanError> {
        ops::walk(
            paths,
            one_filesystem,
            min_dir_bytes,
            0,
            mounts,
            &Progress::default(),
            &|msg| self.warn(msg),
        )
    }

    fn warn(&self, msg: &str) {
        log("warning", msg);
    }
}

/// Writes `dwhy-mcp: LEVEL: msg` on stderr, never stdout.
fn log(level: &str, msg: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "dwhy-mcp: {level}: {}",
        msg.escape_debug()
    );
}

/// Runs `f` on a blocking thread: walks, detectors and guards block.
async fn blocking<F>(f: F) -> CallToolResult
where
    F: FnOnce() -> Result<Vec<ContentBlock>, Failure> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(blocks)) => CallToolResult::success(blocks),
        Ok(Err(report)) => error_result(&report),
        Err(e) => error_result(&error(format!("internal error: {e}"))),
    }
}

/// `value` as one JSON text block.
fn content(value: &impl Serialize) -> Result<Vec<ContentBlock>, Failure> {
    let text = serde_json::to_string(value).map_err(|e| error(e.to_string()))?;
    Ok(vec![ContentBlock::text(text)])
}

/// `report`, then, when the snapshot asked for was not saved, an
/// ErrorReport saying why (the report is still good, as `dwhy` prints it
/// and exits 1).
fn with_snapshot_error(
    report: &impl Serialize,
    snapshot_error: Option<String>,
) -> Result<Vec<ContentBlock>, Failure> {
    let mut blocks = content(report)?;
    if let Some(e) = snapshot_error {
        blocks.extend(content(&error(format!("snapshot not saved: {e}")))?);
    }
    Ok(blocks)
}

/// A failed call: `report` as JSON text, with `isError`.
fn error_result(report: &ErrorReport) -> CallToolResult {
    let text = serde_json::to_string(report).unwrap_or_else(|_| report.message.clone());
    CallToolResult::error(vec![ContentBlock::text(text)])
}

/// Why a call failed, as its ErrorReport.
type Failure = Box<ErrorReport>;

fn error(message: impl Into<String>) -> Failure {
    Box::new(ErrorReport::new(
        ErrorKind::Error,
        message,
        None,
        EXIT_ERROR,
    ))
}

fn usage(message: impl Into<String>) -> Failure {
    Box::new(ErrorReport::new(
        ErrorKind::Usage,
        message,
        None,
        EXIT_ERROR,
    ))
}

/// `parse(value)`, or a usage error naming the argument.
fn parse_arg<T>(
    name: &str,
    value: &str,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Result<T, Failure> {
    parse(value).map_err(|e| usage(format!("invalid value '{value}' for '{name}': {e}")))
}

/// A size argument ("10M", "1.5G", bytes).
fn size_arg(name: &str, value: Option<&str>) -> Result<Option<u64>, Failure> {
    value
        .map(|s| parse_arg(name, s, units::parse_size))
        .transpose()
}

/// `paths` as given; none means the command's default.
fn paths(paths: Option<Vec<String>>) -> Vec<PathBuf> {
    paths
        .unwrap_or_default()
        .into_iter()
        .map(PathBuf::from)
        .collect()
}
