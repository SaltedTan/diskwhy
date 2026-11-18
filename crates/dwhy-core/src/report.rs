//! The `diskwhy/v1` JSON contract.
//!
//! These types are the API that agents, the MCP server and the TUI consume.
//! Rules for changing them:
//!
//! * Adding an optional field or a new enum variant is allowed within `v1`.
//! * Renaming, removing, or changing the meaning or unit of a field needs a
//!   new schema version (`diskwhy/v2`).
//!
//! All sizes are bytes. "Allocated" means `st_blocks * 512` (what deleting
//! frees); "apparent" means `st_size` of non-directories (directories count
//! 0, as in GNU du >= 9.2). Paths are rendered lossily as UTF-8.

use serde::{Deserialize, Serialize};

/// Value of the `schema` field in every top-level document.
pub const SCHEMA: &str = "diskwhy/v1";

/// Returns an error message if `schema` is not one this build understands.
pub fn check_schema(schema: &str) -> Result<(), String> {
    if schema == SCHEMA {
        Ok(())
    } else {
        Err(format!(
            "unsupported schema {schema:?}, expected {SCHEMA:?}"
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

impl Tool {
    pub fn current() -> Self {
        Tool {
            name: "diskwhy".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// Output of `dwhy scan --json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    /// Effective uid the scan ran as.
    pub uid: u32,
    pub root: bool,
    /// RFC 3339, UTC.
    pub generated_at: String,
    pub scan: ScanSummary,
    pub fs: Vec<FsReport>,
    /// What each detector found, largest first. A finding whose path lies
    /// inside another finding's path is dropped, unless its tier is cheaper
    /// than the outer one's or the outer one is `blocked`; then both are kept
    /// and the outer one's `nested_bytes` counts it.
    pub findings: Vec<Finding>,
    /// Every known detector, whether it ran, and why not.
    #[serde(default)]
    pub detectors: Vec<DetectorRun>,
    /// Docker's own accounting, when the Docker detectors could query the daemon.
    #[serde(default)]
    pub docker: Option<DockerUsage>,
    /// The snapshot `--snapshot` saved; absent without `--snapshot`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SavedSnapshot>,
}

/// Where `scan --snapshot` saved its snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSnapshot {
    /// The file name without `.json.gz`; what `diff --since` accepts.
    pub id: String,
    pub path: String,
    /// Older snapshots deleted by the retention policy while saving.
    pub pruned: u64,
}

/// From the Engine API (`GET /system/df`, `GET /info`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerUsage {
    /// `DockerRootDir`, usually `/var/lib/docker`.
    pub root_dir: String,
    /// Images are stored by containerd (`/var/lib/containerd`), not under `root_dir`.
    pub containerd_image_store: bool,
    /// Image layers, counted once however many images share them.
    pub images: UsageLine,
    /// Containers' writable layers.
    pub containers: UsageLine,
    pub volumes: UsageLine,
    pub build_cache: UsageLine,
    pub total: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageLine {
    pub count: u64,
    /// In use: images with containers, running containers, mounted volumes, in-use cache.
    pub active: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorRun {
    pub name: String,
    pub status: DetectorAvailability,
    pub detail: String,
    /// False when the detector is unavailable or not implemented yet.
    pub ran: bool,
    /// Findings it reported before the nesting rule was applied.
    pub findings: u64,
    pub elapsed_ms: u64,
    /// Set when the detector ran but failed (e.g. the Docker daemon did not answer).
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub roots: Vec<RootReport>,
    /// True when the walk did not cross into other filesystems (`-x`).
    pub one_filesystem: bool,
    pub elapsed_ms: u64,
    /// Totals over all roots, each hardlinked inode counted once.
    pub totals: Totals,
    /// Directories whose recursive allocated size is at least `min_dir_bytes`,
    /// largest first.
    pub dirs: Vec<DirEntry>,
    pub min_dir_bytes: u64,
    pub unreadable: Unreadable,
    /// Mount points found under a root that were not entered.
    pub skipped_mounts: Vec<SkippedMount>,
    /// Errors other than permission problems (e.g. I/O errors), capped.
    pub errors: Vec<ScanErrorEntry>,
    pub error_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RootReport {
    pub path: String,
    /// Mount point of the filesystem the root lives on.
    pub mount: String,
    pub totals: Totals,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub allocated: u64,
    pub apparent: u64,
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    /// Sockets, fifos, device nodes.
    pub other: u64,
    /// Extra links to an inode already counted, which were not counted again.
    pub hardlinks_deduped: u64,
    /// Allocated bytes those extra links would have added if counted naively.
    pub hardlink_bytes_deduped: u64,
}

impl std::ops::AddAssign for Totals {
    fn add_assign(&mut self, o: Self) {
        self.allocated += o.allocated;
        self.apparent += o.apparent;
        self.files += o.files;
        self.dirs += o.dirs;
        self.symlinks += o.symlinks;
        self.other += o.other;
        self.hardlinks_deduped += o.hardlinks_deduped;
        self.hardlink_bytes_deduped += o.hardlink_bytes_deduped;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub path: String,
    /// Depth below its scan root (the root itself is 0).
    pub depth: u32,
    pub allocated: u64,
    pub apparent: u64,
    /// Files (non-directories) below this directory, recursively.
    pub files: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unreadable {
    /// Number of directories whose contents could not be fully measured.
    pub count: u64,
    /// Entries seen by name but not measurable (summed over `entries_denied` dirs).
    pub entries_unknown: u64,
    /// Allocated bytes that are known (the unreadable directories' own inodes).
    /// The contents are unknown; see `fs[].unaccounted`.
    pub known_bytes: u64,
    /// The first unreadable directories, sorted by path (capped).
    pub dirs: Vec<UnreadableDir>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnreadableDir {
    pub path: String,
    pub reason: UnreadableReason,
    /// For `entries_denied`: entries listed but not measurable.
    pub entries_unknown: u64,
    /// Allocated bytes of the directory inode itself.
    pub known_bytes: u64,
    /// Owner uid of the directory, when known.
    pub owner_uid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnreadableReason {
    /// The directory could not be listed (`opendir`/`getdents` failed with EACCES/EPERM).
    PermissionDenied,
    /// The directory could be listed, but `entries_unknown` of its entries could not be
    /// `lstat`ed (typically: readable but not searchable, no `x` bit).
    EntriesDenied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedMount {
    pub path: String,
    pub fstype: Option<String>,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Another filesystem and the scan is `-x`.
    OtherFilesystem,
    /// A virtual filesystem (proc, sysfs, ...); never entered.
    Virtual,
    /// A bind mount of the same filesystem; never entered, to avoid double counting.
    BindMount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanErrorEntry {
    pub path: String,
    pub error: String,
}

/// `df` figures for one filesystem plus how much of it the scan saw.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FsReport {
    pub mount: String,
    pub fstype: String,
    pub source: String,
    /// `statvfs`: f_blocks * f_frsize.
    pub size: u64,
    /// `statvfs`: (f_blocks - f_bfree) * f_frsize, i.e. what `df` calls Used.
    pub used: u64,
    /// `statvfs`: f_bavail * f_frsize.
    pub avail: u64,
    /// Allocated bytes the scan counted on this filesystem.
    pub scanned: u64,
    /// True when a scan root was this filesystem's mount point, so `scanned`
    /// can be compared with `used`.
    pub full_coverage: bool,
    /// `used - scanned` (saturating), only when `full_coverage`.
    pub unaccounted: Option<u64>,
    /// True when `unaccounted` exceeds the reporting threshold.
    pub unaccounted_large: bool,
    /// Likely locations of the unaccounted bytes, most likely first.
    pub hints: Vec<Hint>,
    /// Space held by deleted files that processes visible to this user still hold open.
    pub deleted_open: DeletedOpen,
    /// Command to rerun with full permissions, set when the gap is large and not root.
    pub rerun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hint {
    pub kind: HintKind,
    pub path: Option<String>,
    pub detail: String,
    /// Unreadable directories this hint groups.
    pub unreadable_dirs: u64,
    /// Bytes attributed to this hint, when measurable.
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HintKind {
    Docker,
    Containerd,
    VirtualMachines,
    Database,
    OtherUserHome,
    RootHome,
    Logs,
    Snap,
    Cache,
    SystemPrivate,
    Unreadable,
    DeletedOpen,
    ShadowedByMount,
    FilesystemOverhead,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedOpen {
    pub files: u64,
    pub bytes: u64,
    /// Processes whose fds could not be inspected (other users'), so the figure is a lower bound.
    pub processes_unreadable: u64,
}

// ---------------------------------------------------------------------------
// Findings (produced from M1 on; the shape is fixed now so consumers can rely on it)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub detector: String,
    pub probe: Option<String>,
    /// Filesystem path, or a pseudo-path such as `docker://volume/<name>`.
    pub path: String,
    /// What removing the finding is expected to free. For a filesystem path:
    /// allocated bytes under it, each hardlinked file counted once, leaving
    /// out files kept alive by links outside it (`TreeNode::freeable`). For a
    /// pseudo-path such as `docker://…`: what the tool reports removal frees.
    pub bytes: u64,
    /// Part of `bytes` held by other findings inside `path`, reported
    /// separately (each byte counted once, by its outermost such finding).
    /// `None` when there are none.
    #[serde(default)]
    pub nested_bytes: Option<u64>,
    /// Newest mtime under `path`, RFC 3339 (UTC).
    #[serde(default)]
    pub last_modified: Option<String>,
    pub growth: Option<Growth>,
    pub tier: Tier,
    pub reason: String,
    pub guards: Vec<GuardResult>,
    pub action: Action,
    pub recovery: Recovery,
    /// What the probe named in `probe` found; absent when no probe ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

/// Evidence probes gathered about a finding, one member per probe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres_wal: Option<PostgresWal>,
}

/// The `postgres-wal` probe: why a Postgres data volume is big. Read with
/// read-only queries through `docker exec … psql` (`source: psql`), or,
/// when that is not possible, from the container's inspect data and the
/// tail of its log only (`source: api-only`, `notes` says why).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresWal {
    /// The running Postgres container that mounts the volume.
    pub container: String,
    /// Bytes in `pg_wal` (`pg_ls_waldir()`).
    #[serde(default)]
    pub wal_bytes: Option<u64>,
    /// Sum of `pg_database_size` over all databases.
    #[serde(default)]
    pub data_bytes: Option<u64>,
    /// `pg_stat_archiver.failed_count`; with `api-only`, failures in the
    /// log tail (a lower bound).
    #[serde(default)]
    pub failed_count: Option<u64>,
    /// RFC 3339 (UTC).
    #[serde(default)]
    pub last_archived_at: Option<String>,
    /// RFC 3339 (UTC).
    #[serde(default)]
    pub last_failed_at: Option<String>,
    #[serde(default)]
    pub last_failed_wal: Option<String>,
    #[serde(default)]
    pub archive_mode: Option<String>,
    /// The program `archive_command` runs (its first word). Arguments are
    /// never reported, as they can hold credentials.
    #[serde(default)]
    pub archive_program: Option<String>,
    #[serde(default)]
    pub archive_timeout: Option<String>,
    /// Hosts `archive_command` sends WAL to, matched with containers.
    #[serde(default)]
    pub targets: Vec<ArchiveTarget>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unmatched_hosts: u64,
    pub source: EvidenceSource,
    #[serde(default)]
    pub notes: Vec<String>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveTarget {
    /// The matched name, service, alias or DNS name reported by Docker.
    pub host: String,
    /// The container it names (by name, Compose service or network alias).
    pub container: Option<String>,
    /// The matched container's state (`running`, `exited`, …).
    pub state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    /// Read-only queries through `docker exec … psql`.
    Psql,
    /// Engine API GETs only: inspect and the log tail.
    ApiOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Growth {
    pub bytes_per_day: i64,
    /// RFC 3339.
    pub since: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Regenerable,
    Rebuildable,
    Review,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardResult {
    pub name: String,
    pub status: GuardStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    Pass,
    Warn,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub kind: ActionKind,
    /// Human-readable description.
    pub text: String,
    /// argv of a tool-native command, for `kind = command`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Nothing to run; a person has to act (e.g. fix an archive target).
    Advice,
    /// Run a tool-native command.
    Command,
    /// Remove a path limited to the finding's root.
    RemovePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recovery {
    pub cost: String,
    pub how: Option<String>,
}

// ---------------------------------------------------------------------------
// Plans (M2): written by `dwhy plan`, read by `dwhy apply`
// ---------------------------------------------------------------------------

/// A plan: the findings selected for removal, each with a fingerprint, and
/// an expiry. `dwhy apply` does not take the plan's word for what to run:
/// it rescans `scan.roots`, re-runs the detectors and guards, and acts only
/// on the fresh finding with each item's id, skipping it when the fresh
/// tier, action or fingerprint differs from the plan's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    /// Effective uid the plan was made as; apply refuses another uid.
    pub uid: u32,
    /// RFC 3339, UTC.
    pub created_at: String,
    /// RFC 3339, UTC. apply refuses the plan after this.
    pub expires_at: String,
    /// What apply rescans and re-detects.
    pub scan: PlanScan,
    pub selection: PlanSelection,
    /// Findings to remove, largest first. None is `blocked`.
    pub items: Vec<PlanItem>,
    /// Selected findings that a guard or detector blocked: listed so the
    /// reason is visible, never applied.
    pub blocked: Vec<Finding>,
    /// What removing every item is expected to free, each byte counted once
    /// (an item inside another item adds nothing).
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanScan {
    /// Scan roots, absolute.
    pub roots: Vec<String>,
    /// True when the walk did not cross into other filesystems (`-x`).
    pub one_filesystem: bool,
    /// The detectors that ran (`--detectors`); `None` means all of them.
    pub detectors: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSelection {
    /// Highest tier selected (`--tier`). `None` when `--select` named the
    /// findings and no `--tier` was given.
    pub tier: Option<Tier>,
    /// Finding ids or paths given with `--select`.
    pub select: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanItem {
    /// The finding as detected, with its guard results.
    pub finding: Finding,
    pub fingerprint: Fingerprint,
}

/// What must not have changed between `plan` and `apply`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// `st_dev` of the finding's root (not following a symlink), for a
    /// filesystem finding whose root exists.
    pub dev: Option<u64>,
    /// `st_ino` of the finding's root.
    pub inode: Option<u64>,
    /// Newest mtime under the root, seconds since the epoch.
    pub newest_mtime: Option<i64>,
    /// `bytes` in buckets of a quarter of a doubling (4 per power of two):
    /// small changes in size do not count, large ones do.
    pub size_bucket: u32,
    /// For a finding whose root is a git work tree.
    pub git: Option<GitFingerprint>,
    /// For a Docker finding: the image or container id, or the volume name
    /// and creation time.
    pub docker_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitFingerprint {
    /// Commit id of HEAD, or `"unborn"` before the first commit.
    pub head: String,
    /// FNV-1a (64-bit, hex) of the entries of `git status --porcelain=v2 -z`
    /// with untracked files, branch headers left out: any change to the work
    /// tree changes it, a fetch does not.
    pub status_hash: String,
}

// ---------------------------------------------------------------------------
// Apply (M2): `dwhy apply --json` and the audit log
// ---------------------------------------------------------------------------

/// Output of `dwhy apply --json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplyReport {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    pub uid: u32,
    /// RFC 3339, UTC.
    pub generated_at: String,
    /// `created_at` of the plan applied.
    pub plan_created_at: String,
    /// `--dry-run`: nothing was removed; ready items are `would_remove`.
    pub dry_run: bool,
    /// `--max-tier`.
    pub max_tier: Tier,
    /// `--confirm`: review items a person confirmed.
    pub confirm: Vec<String>,
    /// One per plan item, in plan order.
    pub items: Vec<ApplyItem>,
    /// What the removed items were expected to free (their `bytes`, an item
    /// inside another removed item counted once).
    pub freed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplyItem {
    pub id: String,
    pub detector: String,
    pub path: String,
    /// The tier detected at apply time (the plan's when the finding is gone).
    pub tier: Tier,
    pub bytes: u64,
    /// The action run or that would run: the one detected at apply time,
    /// never taken from the plan file.
    pub action: Action,
    pub outcome: ApplyOutcome,
    /// Why it was skipped or refused, what failed, or what was removed.
    pub detail: String,
    /// Guard results at apply time (empty when the guards did not run).
    pub guards: Vec<GuardResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyOutcome {
    Removed,
    /// The action ran and failed (exit 1).
    Failed,
    /// A guard blocked it, its fingerprint, tier or action changed, or it is
    /// gone (exit 2).
    Skipped,
    /// Above `--max-tier`, or a `review` item without `--confirm` (exit 3).
    Refused,
    /// `--dry-run`: it would have been removed.
    WouldRemove,
}

/// One line of `~/.local/state/diskwhy/audit.jsonl`. A removal writes a
/// `start` line before it runs and an `end` line with its outcome after; a
/// skipped or refused item gets one `end` line. Dry runs write nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub schema: String,
    /// RFC 3339, UTC.
    pub time: String,
    pub host: String,
    pub uid: u32,
    /// Process id of the `dwhy apply` that wrote it.
    pub pid: u32,
    pub event: AuditEvent,
    pub plan_created_at: String,
    pub id: String,
    pub detector: String,
    pub path: String,
    pub tier: Tier,
    pub bytes: u64,
    pub action: Action,
    /// Set on `end`.
    pub outcome: Option<ApplyOutcome>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    Start,
    End,
}

// ---------------------------------------------------------------------------
// Snapshots (M3): written by `dwhy scan --snapshot`, read by `dwhy diff`
// ---------------------------------------------------------------------------

/// A compact record of one scan, kept so later runs can tell what grew.
/// Stored as gzip-compressed JSON in
/// `$XDG_STATE_HOME/diskwhy/snapshots/<id>.json.gz`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    /// Effective uid the scan ran as.
    pub uid: u32,
    /// RFC 3339, UTC.
    pub created_at: String,
    pub scan: SnapshotScan,
    /// Directories whose recursive allocated size (each hardlinked file
    /// counted once) is at least `scan.min_dir_bytes`, largest first.
    pub dirs: Vec<SnapshotDir>,
    /// `df` figures per filesystem the scan touched.
    pub fs: Vec<SnapshotFs>,
    /// Docker objects and their sizes, when the Docker detectors queried the daemon.
    pub docker: Option<SnapshotDocker>,
    /// Every finding of the scan, largest first.
    pub findings: Vec<SnapshotFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotScan {
    /// Scan roots, absolute.
    pub roots: Vec<String>,
    pub one_filesystem: bool,
    /// Smallest directory recorded in `dirs`.
    pub min_dir_bytes: u64,
    /// Totals over all roots.
    pub totals: Totals,
    /// Detectors that ran, so a finding missing later can be told apart
    /// from one whose detector did not run.
    pub detectors: Vec<String>,
    /// Mount points under the roots that the walk did not enter, absolute.
    /// Snapshots saved without it count as having skipped none.
    #[serde(default)]
    pub skipped_mounts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDir {
    pub path: String,
    pub allocated: u64,
    pub apparent: u64,
    /// Files (non-directories) below it, recursively.
    pub files: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFs {
    pub mount: String,
    pub fstype: String,
    /// As in [`FsReport`].
    pub size: u64,
    pub used: u64,
    pub avail: u64,
    pub scanned: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotDocker {
    /// Totals as in [`ScanReport::docker`] (build cache is recorded only here).
    pub usage: DockerUsage,
    pub images: Vec<SnapshotImage>,
    pub containers: Vec<SnapshotContainer>,
    pub volumes: Vec<SnapshotVolume>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotImage {
    pub id: String,
    pub tags: Vec<String>,
    /// The image's size, layers shared with other images included.
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    /// Writable layer; `None` when the daemon did not compute it.
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotVolume {
    pub name: String,
    /// `None` when the daemon did not compute it.
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFinding {
    pub id: String,
    pub detector: String,
    pub path: String,
    pub bytes: u64,
    pub tier: Tier,
}

// ---------------------------------------------------------------------------
// Growth (M3): `dwhy diff` and `dwhy watch`
// ---------------------------------------------------------------------------

/// Output of `dwhy diff --json`: what changed between a saved snapshot and
/// a fresh scan. Each list is ranked by `bytes_per_day`, fastest growth
/// first and fastest shrinkage last.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffReport {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    pub uid: u32,
    /// When the fresh scan ran, RFC 3339 (UTC).
    pub generated_at: String,
    /// The snapshot compared with.
    pub since: DiffBase,
    /// Roots of the fresh scan, absolute.
    pub roots: Vec<String>,
    pub one_filesystem: bool,
    /// Seconds between the snapshot and the fresh scan.
    pub elapsed_secs: i64,
    /// Directories, Docker objects and findings that changed by less than
    /// this many bytes are left out.
    pub min_change: u64,
    /// `df` used per filesystem in both, whether it changed or not.
    pub fs: Vec<Change>,
    /// Directories, each change attributed to the deepest directory that
    /// holds most of it: a directory is left out when one directory below it
    /// changed by more than half as much in the same direction. Entries can
    /// still nest when a change is spread over several directories.
    pub dirs: Vec<Change>,
    /// False when one side has no Docker figures (see `notes`).
    pub docker_compared: bool,
    /// Docker images, containers and volumes (by id or name; ones whose size
    /// the daemon did not compute are left out), and build cache.
    pub docker: Vec<Change>,
    /// Findings matched by id. A finding only on one side is listed only
    /// when its detector ran on both.
    pub findings: Vec<Change>,
    /// What could not be compared, and why.
    pub notes: Vec<String>,
    /// The snapshot `--snapshot` saved of the fresh scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SavedSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffBase {
    /// The snapshot's id, when it was found in the snapshot directory or its
    /// file has a snapshot name.
    pub id: Option<String>,
    pub path: String,
    pub created_at: String,
    pub roots: Vec<String>,
    pub one_filesystem: bool,
    /// Smallest directory the snapshot recorded.
    pub min_dir_bytes: u64,
}

/// How one thing's size changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    /// A path, mount point, image tag, container or volume name.
    pub name: String,
    /// Finding, image or container id.
    #[serde(default)]
    pub id: Option<String>,
    /// The detector, for findings.
    #[serde(default)]
    pub detector: Option<String>,
    /// `None`: not there, or (for a directory) below the snapshot's
    /// `min_dir_bytes` and so not recorded.
    pub before: Option<u64>,
    /// `None`: gone.
    pub after: Option<u64>,
    /// `after - before`, absent sides counting 0. A directory new above the
    /// snapshot's threshold counts that threshold as its size before, so its
    /// change is a lower bound (`at_least`).
    pub change: i64,
    pub at_least: bool,
    pub bytes_per_day: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    /// `df` used of a filesystem.
    Fs,
    Dir,
    Image,
    Container,
    Volume,
    BuildCache,
    Finding,
}

/// Output of `dwhy watch --json`: growth over a short window, from two
/// walks of the roots (and Docker's figures) `elapsed_ms` apart. Each list
/// is ranked by `bytes_per_minute`, fastest growth first and fastest
/// shrinkage last.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchReport {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    pub uid: u32,
    /// When the first walk started, RFC 3339 (UTC).
    pub started_at: String,
    /// When the second walk finished.
    pub generated_at: String,
    /// The roots walked, absolute.
    pub roots: Vec<String>,
    pub one_filesystem: bool,
    /// The window asked for (`--for`): the second walk starts this long
    /// after the first one started, or right away if the first took longer.
    pub for_secs: u64,
    /// Milliseconds from the start of the first walk to the start of the
    /// second; rates are over this.
    pub elapsed_ms: u64,
    /// Directories and Docker objects that changed by less than this many
    /// bytes are left out.
    pub min_change: u64,
    /// `df` used per filesystem present in both samples, whether it changed or not.
    pub fs: Vec<Rate>,
    /// Directories, each change attributed to the deepest directory that
    /// holds most of it, as in `diff`.
    pub dirs: Vec<Rate>,
    /// False when Docker's figures are missing at either end (see `notes`).
    pub docker_compared: bool,
    /// Docker images, containers and volumes (by id or name; ones whose size
    /// the daemon did not compute are left out), and build cache.
    pub docker: Vec<Rate>,
    /// What could not be compared, and why.
    pub notes: Vec<String>,
}

/// How one thing's size changed over a `watch` window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rate {
    pub kind: ChangeKind,
    /// A path, mount point, image tag, container or volume name.
    pub name: String,
    /// Image or container id.
    #[serde(default)]
    pub id: Option<String>,
    /// `None`: not there at the start.
    pub before: Option<u64>,
    /// `None`: gone by the end.
    pub after: Option<u64>,
    /// `after - before`, absent sides counting 0.
    pub change: i64,
    pub bytes_per_minute: i64,
}

/// Output of `dwhy doctor --json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    pub uid: u32,
    pub euid: u32,
    pub root: bool,
    /// Member of the `docker` group (root-equivalent).
    pub docker_group: bool,
    pub docker_socket: DockerSocket,
    pub tools: Vec<ToolStatus>,
    pub detectors: Vec<DetectorStatus>,
    /// Probes (`postgres-wal`, …), which add evidence to findings.
    #[serde(default)]
    pub probes: Vec<DetectorStatus>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerSocket {
    pub path: String,
    pub exists: bool,
    pub accessible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStatus {
    pub name: String,
    /// Resolved via `$PATH`.
    pub path: Option<String>,
    /// Found at a well-known location that is not on `$PATH` (e.g. `~/.cargo/bin`).
    pub off_path: Option<String>,
    pub enables: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorStatus {
    pub name: String,
    pub milestone: String,
    pub status: DetectorAvailability,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorAvailability {
    Available,
    /// Can detect but not remove the tool-native way, or works with reduced evidence.
    Degraded,
    Unavailable,
    /// Listed in the design but not built yet.
    NotImplemented,
}
