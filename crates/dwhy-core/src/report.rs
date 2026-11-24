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
//! 0, as in GNU du >= 9.2). Paths are UTF-8 strings. A filesystem path
//! can be rendered lossily.

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
    /// Aggregate finding counts and reclaimable bytes across all detected
    /// findings, before any tier filter or cap; populated by `--summary`
    /// ([`ScanReport::summarize`]), absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings_summary: Option<FindingsSummary>,
}

/// Default cap on `scan.dirs` under `--summary`.
pub const DEFAULT_SUMMARY_DIRS: usize = 25;
/// Default cap on `findings` under `--summary` (`--max-findings` overrides it).
pub const DEFAULT_SUMMARY_FINDINGS: usize = 20;
/// Default deepest `scan.dirs` level kept under `--summary` (`--depth` overrides it).
pub const DEFAULT_SUMMARY_DEPTH: u32 = 3;

/// Finding counts and bytes over every finding a scan reported, so a capped
/// or tier-filtered `findings` list still says what the whole scan found.
///
/// Bytes are each finding's own bytes: `bytes` less `nested_bytes`, so a
/// byte held by a finding nested in another is counted once.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingsSummary {
    /// Findings the scan reported, before any tier filter or cap.
    pub total: u64,
    /// Findings left out of `findings` (by the tier filter or the cap).
    pub omitted: u64,
    /// What the findings' actions can free: findings that are neither
    /// blocked nor advice-only.
    pub reclaimable_bytes: u64,
    pub by_tier: TierBreakdown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierBreakdown {
    pub regenerable: TierSummary,
    pub rebuildable: TierSummary,
    pub review: TierSummary,
    pub blocked: TierSummary,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierSummary {
    pub count: u64,
    /// Own bytes of every finding in the tier.
    pub bytes: u64,
    /// Own bytes of the tier's findings that are not advice-only (always 0
    /// for `blocked`).
    pub reclaimable_bytes: u64,
    /// Advice-only findings in the tier (e.g. an in-use volume), which are
    /// not counted in `reclaimable_bytes`. Absent when 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub advice_count: u64,
}

/// Caps applied by [`ScanReport::summarize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryLimits {
    /// Most findings kept in `findings`.
    pub max_findings: usize,
    /// Most directories kept in `scan.dirs`, roots included.
    pub max_dirs: usize,
    /// Deepest directory level kept in `scan.dirs` (roots are 0).
    pub max_depth: u32,
}

impl Default for SummaryLimits {
    fn default() -> Self {
        SummaryLimits {
            max_findings: DEFAULT_SUMMARY_FINDINGS,
            max_dirs: DEFAULT_SUMMARY_DIRS,
            max_depth: DEFAULT_SUMMARY_DEPTH,
        }
    }
}

impl TierBreakdown {
    pub fn get(&self, tier: Tier) -> &TierSummary {
        match tier {
            Tier::Regenerable => &self.regenerable,
            Tier::Rebuildable => &self.rebuildable,
            Tier::Review => &self.review,
            Tier::Blocked => &self.blocked,
        }
    }

    fn get_mut(&mut self, tier: Tier) -> &mut TierSummary {
        match tier {
            Tier::Regenerable => &mut self.regenerable,
            Tier::Rebuildable => &mut self.rebuildable,
            Tier::Review => &mut self.review,
            Tier::Blocked => &mut self.blocked,
        }
    }
}

impl Finding {
    /// `bytes` less those held by findings inside it, which are counted on
    /// their own.
    pub fn own_bytes(&self) -> u64 {
        self.bytes.saturating_sub(self.nested_bytes.unwrap_or(0))
    }

    /// True when acting on the finding frees its bytes: it is not blocked
    /// and its action is not advice-only.
    pub fn is_reclaimable(&self) -> bool {
        self.tier != Tier::Blocked && self.action.kind != ActionKind::Advice
    }

    /// True for an advice-only finding that is not blocked.
    pub fn is_advice(&self) -> bool {
        self.tier != Tier::Blocked && self.action.kind == ActionKind::Advice
    }
}

impl FindingsSummary {
    /// Counts and bytes over `findings`; `omitted` is 0.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = FindingsSummary {
            total: findings.len() as u64,
            ..Default::default()
        };
        for f in findings {
            let own = f.own_bytes();
            let t = s.by_tier.get_mut(f.tier);
            t.count += 1;
            t.bytes += own;
            if f.is_reclaimable() {
                t.reclaimable_bytes += own;
                s.reclaimable_bytes += own;
            }
            if f.is_advice() {
                t.advice_count += 1;
            }
        }
        s
    }
}

impl ScanReport {
    /// Keeps only findings in `tiers`.
    pub fn filter_tiers(&mut self, tiers: &[Tier]) {
        self.findings.retain(|f| tiers.contains(&f.tier));
    }

    /// Compacts the report for agents (`scan --summary`): records a
    /// [`FindingsSummary`] over every finding, then keeps only findings in
    /// `tiers` (all when `None`), at most `limits.max_findings` of them,
    /// largest first. `scan.dirs` keeps the roots, then the largest
    /// directories at most `limits.max_depth` deep, `limits.max_dirs` in
    /// all, and `scan.dirs_omitted` says how many were dropped.
    ///
    /// A directory is at least as large as any directory below it and sorts
    /// before it on ties, so every kept directory's parent is kept too.
    pub fn summarize(&mut self, tiers: Option<&[Tier]>, limits: SummaryLimits) {
        let mut summary = FindingsSummary::from_findings(&self.findings);
        if let Some(tiers) = tiers {
            self.filter_tiers(tiers);
        }
        self.findings.truncate(limits.max_findings);
        summary.omitted = summary.total.saturating_sub(self.findings.len() as u64);
        self.findings_summary = Some(summary);

        let dirs = std::mem::take(&mut self.scan.dirs);
        let orig_len = dirs.len();
        let (roots, rest): (Vec<DirEntry>, Vec<DirEntry>) =
            dirs.into_iter().partition(|d| d.depth == 0);
        let mut kept: Vec<DirEntry> = roots.into_iter().take(limits.max_dirs).collect();
        let room = limits.max_dirs - kept.len();
        kept.extend(
            rest.into_iter()
                .filter(|d| d.depth <= limits.max_depth)
                .take(room),
        );
        // Largest first, as `scan.dirs` always is.
        kept.sort_by(|a, b| {
            b.allocated
                .cmp(&a.allocated)
                .then_with(|| a.path.cmp(&b.path))
        });
        self.scan.dirs_omitted = Some((orig_len - kept.len()) as u64);
        self.scan.dirs = kept;
    }
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
    /// Directories at least `min_dir_bytes` left out of `dirs` by
    /// `--summary`; absent without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirs_omitted: Option<u64>,
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
    /// A btrfs subvolume, not mounted on its own, that is a snapshot or
    /// read-only; never entered, even when crossing filesystems. A snapshot
    /// shares its extents with its source, so walking both would count
    /// them twice, and nothing in a read-only subvolume can be removed. A
    /// scan root inside one is still scanned.
    BtrfsSnapshot,
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
    /// Allocated bytes the scan counted on this filesystem, across every
    /// `st_dev` it has (btrfs subvolumes each have their own).
    pub scanned: u64,
    /// True when the scan walked this filesystem whole, so `scanned` can be
    /// compared with `used`: a scan root (or a mount entered with
    /// `--cross-filesystems`) was the mount point of a mount showing the
    /// whole filesystem (mountinfo root `/`, so not a subdirectory bind mount
    /// or a btrfs subvolume other than the top level). Unless a scan root is
    /// such a mount point, walks reaching the filesystem through more than one
    /// mount make it false.
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
    /// Identity captured by a detector when it measures a standalone file.
    /// Omitted from serialized findings.
    #[serde(skip)]
    pub file_identity: Option<FileIdentity>,
    pub id: String,
    pub detector: String,
    /// The probe that added evidence to this finding, when one did.
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
    /// Evidence from the probe named in `probe`, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub mtime: i64,
}

/// Evidence probes gathered about a finding, one member per probe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres_wal: Option<PostgresWal>,
}

/// WAL and archiving evidence from the `postgres-wal` probe. See [`EvidenceSource`]
/// for how it was collected.
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
    /// `pg_stat_archiver.failed_count`. With `api-only`, this counts observed
    /// failures in the log tail and is null if the tail could not be read.
    #[serde(default)]
    pub failed_count: Option<u64>,
    /// RFC 3339 (UTC).
    #[serde(default)]
    pub last_archived_at: Option<String>,
    /// RFC 3339 (UTC).
    #[serde(default)]
    pub last_failed_at: Option<String>,
    /// Failed archive filename, if available and in a recognized Postgres
    /// format (WAL segment, partial segment, timeline history or backup history).
    #[serde(default)]
    pub last_failed_wal: Option<String>,
    /// Lowercase `on`, `off` or `always` when recognized, otherwise null.
    #[serde(default)]
    pub archive_mode: Option<String>,
    /// The program word extracted from `archive_command`. Reported words
    /// contain only ASCII letters, digits or `_./+-`, with `***` used when
    /// extraction fails. The raw command and its arguments are omitted.
    #[serde(default)]
    pub archive_program: Option<String>,
    /// Duration as reported by the source, or null if missing or unrecognized.
    #[serde(default)]
    pub archive_timeout: Option<String>,
    /// Inferred archive hosts that match Docker container identifiers.
    #[serde(default)]
    pub targets: Vec<ArchiveTarget>,
    /// Count of inferred hosts with a completed lookup and no Docker match.
    /// Host names are omitted, as is the field when the count is zero.
    /// The count can be partial if inspection fails.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unmatched_hosts: u64,
    pub source: EvidenceSource,
    #[serde(default)]
    pub notes: Vec<String>,
    /// `archive_library` (Postgres 15+), with the same character rules as
    /// [`archive_program`](Self::archive_program) (`***` when it breaks
    /// them). Absent when unset or unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_library: Option<String>,
    /// WAL files waiting to be archived (`.ready` files in
    /// `pg_wal/archive_status`). Only with `psql`; absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_wal_files: Option<u64>,
    /// True when `pg_wal` lives on another mount than the volume
    /// (`POSTGRES_INITDB_WALDIR`): `wal_bytes` is then the cluster's WAL,
    /// not bytes in this volume. Absent when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub wal_on_other_mount: bool,
    /// With `api-only`: true when the failed command in the log tail is not
    /// confirmed as the configured `archive_command` (the container's
    /// command line sets none, an empty one or a different one), so the
    /// logged failures may be historical. Absent when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub historical_command: bool,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveTarget {
    /// The matched name, service, alias or DNS name reported by Docker.
    pub host: String,
    /// The name of the matched container.
    pub container: Option<String>,
    /// The matched container's state (`running`, `exited`, …).
    pub state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    /// Read-only queries through `docker exec … psql`.
    Psql,
    /// Engine API GETs only. WAL bytes, data bytes and the latest archive
    /// success time are null. `notes` describes why the probe fell back.
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
/// an expiry. Apply uses [`crate::apply::evaluate`] to match the items
/// against freshly detected findings before deciding what can run.
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
    /// [`crate::plan::parse`] requires a distinct finding ID for each item.
    pub items: Vec<PlanItem>,
    /// Selected findings that a guard or detector blocked: listed so the
    /// reason is visible, never applied.
    pub blocked: Vec<Finding>,
    /// What removing every item is expected to free, each byte counted once
    /// (an item inside another item in the scan's tree adds nothing; see
    /// [`crate::plan::distinct_bytes_in_tree`]).
    pub bytes: u64,
    /// Goal progress for `dwhy plan --free SIZE`. Absent when `--free` was not used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal: Option<PlanGoal>,
}

/// How far a `dwhy plan --free SIZE` plan gets towards its target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanGoal {
    /// The `--free` target.
    pub target_bytes: u64,
    /// What the plan's items are expected to free: the same as `Plan::bytes`.
    pub planned_bytes: u64,
    /// True when `planned_bytes >= target_bytes`.
    pub met: bool,
    /// `target_bytes - planned_bytes`, or 0 when the target is met.
    pub shortfall_bytes: u64,
    /// Removable findings in tiers above the plan's tier ceiling, which the
    /// plan did not consider. Absent when there are none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub higher_tiers: Vec<HigherTierAvailable>,
}

/// Removable findings in one tier above a `--free` plan's tier ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HigherTierAvailable {
    pub tier: Tier,
    pub count: u64,
    /// Own bytes across removable findings in this tier (`bytes - nested_bytes`),
    /// before pre-removal guards (which run on selected tiers only).
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
    /// Target bytes requested via `--free`. Absent when `--free` was not used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_target: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanItem {
    /// The finding as detected, with its guard results.
    pub finding: Finding,
    pub fingerprint: Fingerprint,
    /// `st_dev` of the scan root whose walk measured the finding, present
    /// only when it differs from `fingerprint.dev`: the finding lies in a
    /// btrfs subvolume, not mounted on its own, below that root (or, when
    /// crossing filesystems, on another filesystem). Lets
    /// [`crate::plan::distinct_bytes_in_plan`] count a finding inside
    /// another finding's subvolume once, as the walk did, from the plan
    /// alone. Absent in plans written before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_root_dev: Option<u64>,
}

/// What must not have changed between `plan` and `apply`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// `st_dev` recorded for the finding's root during the walk or the
    /// detector's standalone-file measurement. `None` without a filesystem identity.
    pub dev: Option<u64>,
    /// Recorded `st_ino` of the same root.
    pub inode: Option<u64>,
    /// Newest measured mtime under the root, or the measured file's mtime,
    /// in seconds since the epoch.
    pub newest_mtime: Option<i64>,
    /// `bytes` in buckets of a quarter of a doubling (4 per power of two):
    /// small changes in size do not count, large ones do.
    pub size_bucket: u32,
    /// Git state when available for a guarded Git worktree at the finding's root.
    pub git: Option<GitFingerprint>,
    /// For a Docker finding: the image or container id, or the volume name
    /// and creation time. Docker build cache has no object ID for fingerprinting.
    pub docker_id: Option<String>,
    /// For an `old-kernels` finding: FNV-1a (64-bit, hex) of the name,
    /// version and status `dpkg-query` reports for the action's packages,
    /// so a package upgraded, reinstalled or removed since the plan
    /// re-plans. Absent for other findings, when dpkg could not be read,
    /// and in plans written before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packages: Option<String>,
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
    /// inside another removed item under the same scan root counted once; a
    /// root mounted below another root counts on its own, as in `plan.bytes`;
    /// see [`crate::apply::total_bytes_for_checks`]).
    pub freed: u64,
    /// Dry runs only: what the ready (`would_remove`) items would free,
    /// nested as in `freed`. Absent when `dry_run` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub would_free: Option<u64>,
    /// The audit log this apply appended to. Absent on dry runs, which
    /// write none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<String>,
}

/// Output on stdout of a command given `--json` that fails or refuses
/// before it has a report to print. stderr still says the same in text,
/// and the process exits with `exit_code`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorReport {
    pub schema: String,
    pub tool: Tool,
    pub kind: ErrorKind,
    /// What went wrong, unescaped (JSON escapes it).
    pub message: String,
    /// What to do about it, when there is something to suggest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// The process exit code: 1 for `usage` and `error`, 3 for `refused`.
    pub exit_code: u8,
}

impl ErrorReport {
    pub fn new(
        kind: ErrorKind,
        message: impl Into<String>,
        hint: Option<String>,
        exit_code: u8,
    ) -> Self {
        ErrorReport {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            kind,
            message: message.into(),
            hint,
            exit_code,
        }
    }
}

/// What kind of failure an [`ErrorReport`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The command line did not parse (unknown flag, bad value).
    Usage,
    /// The command ran and failed (missing path, bad plan file, no snapshot).
    Error,
    /// Policy refused to go on (stale plan, no terminal to confirm on).
    Refused,
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
    /// Guard results recorded at apply time, including any path encoding block.
    pub guards: Vec<GuardResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyOutcome {
    Removed,
    /// The action failed or could not be started (exit 1).
    Failed,
    /// Apply ruled out the item during its checks or stopped before dispatching
    /// it (exit 2). See [`crate::apply::evaluate`] and [`crate::apply::execute_until`].
    Skipped,
    /// Above `--max-tier`, or a `review` item without `--confirm` (exit 3).
    Refused,
    /// `--dry-run`: it would have been removed.
    WouldRemove,
}

/// One line of the audit log shared by the CLI and TUI. See [`crate::apply::Audit::default_path`].
/// A removal requires a `start` record before dispatch. An `end` record carries
/// the outcome and can be the only record for an item that was skipped or refused.
/// A skip during the final dispatch checks can also follow a `start` record.
/// Dry runs write no records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub schema: String,
    /// RFC 3339, UTC.
    pub time: String,
    pub host: String,
    pub uid: u32,
    /// Process ID of the `dwhy` process that wrote it.
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
    /// Effective `max_tier` of the apply invocation: `--max-tier` (the
    /// TUI's `review`) lowered to the policy config's `max_tier`. Absent in
    /// records written before diskwhy recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tier: Option<Tier>,
    /// `--confirm` ids passed to the apply invocation (the review items
    /// ticked in the TUI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<Vec<String>>,
    /// Whether `--yes` was passed (false in the TUI, whose dialog confirms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yes: Option<bool>,
    /// Whether apply ran with an interactive terminal (stdin and stderr for
    /// `dwhy apply`; always true in the TUI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
}

/// Output of `dwhy audit --json`: the audit log's records, newest first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditReport {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    pub uid: u32,
    /// The audit log read.
    pub path: String,
    /// True when there is no audit log yet (nothing was ever applied).
    pub missing: bool,
    /// Records in the log.
    pub total: u64,
    /// Records left out by `--limit` (the oldest ones).
    pub omitted: u64,
    /// Lines that are not an audit record (cut short or edited); skipped.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub malformed_lines: u64,
    /// The newest records, newest first (the reverse of file order).
    pub records: Vec<AuditRecord>,
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
    /// Docker's `CreatedAt`, as the daemon reported it. Omitted when the
    /// daemon supplies no creation time and in snapshots saved before
    /// this field was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
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

// ---------------------------------------------------------------------------
// Explain (M3): `dwhy explain`
// ---------------------------------------------------------------------------

/// Output of `dwhy explain --json`: one finding with its probe evidence,
/// guards and growth, or what is at a path no detector claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplainReport {
    pub schema: String,
    pub tool: Tool,
    pub host: String,
    pub uid: u32,
    /// When the rescan began, RFC 3339 (UTC).
    pub generated_at: String,
    /// The argument as given: a finding id, a path or a `docker://` pseudo-path.
    /// For an id query this stays the requested id, even when the finding
    /// now has another one (`finding.id`).
    pub query: String,
    pub resolved: ExplainResolved,
    /// The path examined: absolute for a filesystem path, else the
    /// pseudo-path (for a saved Docker object renamed or retagged since,
    /// its current one).
    pub path: String,
    /// The finding at `path`. For an id query its id is the requested one,
    /// except after a Docker rename or retag: ids derive from the path, so
    /// `finding.id` is then the current, path-based id and `query` holds
    /// the requested one. Guards, growth and probe evidence are included
    /// when available. `None` when no finding matched.
    #[serde(default)]
    pub finding: Option<Finding>,
    /// True when the saved filesystem path or saved Docker object is
    /// confirmed absent.
    #[serde(default)]
    pub gone: bool,
    /// Measured totals for a filesystem `path`, including when a finding
    /// matches. Omitted when the path has no measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<ExplainSize>,
    /// Findings below `path`, when `finding` is `None`; largest first.
    #[serde(default)]
    pub inside: Vec<FindingRef>,
    /// Detectors that did not run or failed, and other caveats.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// How `dwhy explain` found the path it examined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainResolved {
    pub via: ExplainVia,
    /// The snapshot that turned the id into a path (`via = id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<ExplainSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplainVia {
    /// A finding id, looked up in the newest snapshot that lists it.
    Id,
    /// A filesystem path or a `docker://` pseudo-path.
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainSnapshot {
    pub id: String,
    pub path: String,
    pub created_at: String,
}

/// Allocated and apparent bytes of the queried path, as `du -s` of that
/// path alone gives them: each hardlinked inode inside it is counted once,
/// even when it also has a link elsewhere in the wider walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainSize {
    pub allocated: u64,
    pub apparent: u64,
}

/// A finding named by id, for lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRef {
    pub id: String,
    pub path: String,
    pub detector: String,
    pub bytes: u64,
    pub tier: Tier,
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
    /// Probe availability. Reports written before this field was added read
    /// back with an empty list.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        path: &str,
        bytes: u64,
        nested: Option<u64>,
        tier: Tier,
        kind: ActionKind,
    ) -> Finding {
        Finding {
            file_identity: None,
            id: format!("f_{path}"),
            detector: "test".into(),
            probe: None,
            evidence: None,
            path: path.into(),
            bytes,
            nested_bytes: nested,
            last_modified: None,
            growth: None,
            tier,
            reason: String::new(),
            guards: vec![],
            action: Action {
                kind,
                text: String::new(),
                argv: None,
            },
            recovery: Recovery {
                cost: String::new(),
                how: None,
            },
        }
    }

    fn dir(path: &str, depth: u32, allocated: u64) -> DirEntry {
        DirEntry {
            path: path.into(),
            depth,
            allocated,
            apparent: allocated,
            files: 0,
        }
    }

    fn report(findings: Vec<Finding>, dirs: Vec<DirEntry>) -> ScanReport {
        ScanReport {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: "h".into(),
            uid: 1000,
            root: false,
            generated_at: String::new(),
            scan: ScanSummary {
                roots: vec![],
                one_filesystem: true,
                elapsed_ms: 0,
                totals: Totals::default(),
                dirs,
                min_dir_bytes: 0,
                unreadable: Unreadable::default(),
                skipped_mounts: vec![],
                errors: vec![],
                error_count: 0,
                dirs_omitted: None,
            },
            fs: vec![],
            findings,
            detectors: vec![],
            docker: None,
            snapshot: None,
            findings_summary: None,
        }
    }

    #[test]
    fn nested_bytes_are_counted_once() {
        let s = FindingsSummary::from_findings(&[
            finding("/a", 100, Some(30), Tier::Rebuildable, ActionKind::Command),
            finding("/a/b", 30, None, Tier::Regenerable, ActionKind::RemovePath),
        ]);
        assert_eq!(s.total, 2);
        assert_eq!(s.reclaimable_bytes, 100);
        assert_eq!(s.by_tier.rebuildable.bytes, 70);
        assert_eq!(s.by_tier.regenerable.bytes, 30);
    }

    #[test]
    fn advice_only_findings_are_counted_but_not_reclaimable() {
        let s = FindingsSummary::from_findings(&[
            finding("/v", 500, None, Tier::Review, ActionKind::Advice),
            finding("/w", 50, None, Tier::Review, ActionKind::RemovePath),
        ]);
        let review = &s.by_tier.review;
        assert_eq!(review.count, 2);
        assert_eq!(review.bytes, 550);
        assert_eq!(review.reclaimable_bytes, 50);
        assert_eq!(review.advice_count, 1);
        assert_eq!(s.reclaimable_bytes, 50);
    }

    #[test]
    fn blocked_findings_have_bytes_but_nothing_reclaimable() {
        let s = FindingsSummary::from_findings(&[
            finding("/t", 70, None, Tier::Blocked, ActionKind::RemovePath),
            finding("/u", 30, None, Tier::Blocked, ActionKind::Advice),
        ]);
        let blocked = &s.by_tier.blocked;
        assert_eq!(blocked.count, 2);
        assert_eq!(blocked.bytes, 100);
        assert_eq!(blocked.reclaimable_bytes, 0);
        // A blocked advice finding counts as blocked, not as advice.
        assert_eq!(blocked.advice_count, 0);
        assert_eq!(s.reclaimable_bytes, 0);
    }

    #[test]
    fn summarize_caps_dirs_by_depth_and_count_keeping_roots() {
        let dirs = vec![
            dir("/r", 0, 1000),
            dir("/r/a", 1, 600),
            dir("/r/a/b", 2, 500),
            dir("/r/a/b/c", 3, 450),
            dir("/s", 0, 400),
            dir("/r/x", 1, 300),
            dir("/r/y", 1, 200),
        ];
        let mut r = report(vec![], dirs.clone());
        r.summarize(
            None,
            SummaryLimits {
                max_findings: 10,
                max_dirs: 4,
                max_depth: 2,
            },
        );
        let kept: Vec<&str> = r.scan.dirs.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(kept, ["/r", "/r/a", "/r/a/b", "/s"]);
        assert_eq!(r.scan.dirs_omitted, Some(3));

        // Roots win over larger deeper directories.
        let mut r = report(vec![], dirs);
        r.summarize(
            None,
            SummaryLimits {
                max_findings: 10,
                max_dirs: 2,
                max_depth: 5,
            },
        );
        let kept: Vec<&str> = r.scan.dirs.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(kept, ["/r", "/s"]);
        assert_eq!(r.scan.dirs_omitted, Some(5));
    }

    #[test]
    fn summarize_counts_every_finding_before_the_tier_filter_and_cap() {
        let mut r = report(
            vec![
                finding("/a", 400, None, Tier::Review, ActionKind::RemovePath),
                finding("/b", 300, None, Tier::Rebuildable, ActionKind::Command),
                finding("/c", 200, None, Tier::Rebuildable, ActionKind::Command),
                finding("/d", 100, None, Tier::Regenerable, ActionKind::RemovePath),
            ],
            vec![],
        );
        r.summarize(
            Some(&[Tier::Rebuildable, Tier::Regenerable]),
            SummaryLimits {
                max_findings: 2,
                max_dirs: 10,
                max_depth: 3,
            },
        );
        let kept: Vec<&str> = r.findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(kept, ["/b", "/c"]);
        let s = r.findings_summary.as_ref().unwrap();
        assert_eq!(s.total, 4);
        assert_eq!(s.omitted, 2);
        assert_eq!(s.reclaimable_bytes, 1000);
        assert_eq!(s.by_tier.review.count, 1);
        assert_eq!(r.scan.dirs_omitted, Some(0));
    }

    #[test]
    fn filter_tiers_keeps_only_those_tiers() {
        let mut r = report(
            vec![
                finding("/a", 3, None, Tier::Review, ActionKind::RemovePath),
                finding("/b", 2, None, Tier::Blocked, ActionKind::RemovePath),
                finding("/c", 1, None, Tier::Review, ActionKind::RemovePath),
            ],
            vec![],
        );
        r.filter_tiers(&[Tier::Review]);
        let kept: Vec<&str> = r.findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(kept, ["/a", "/c"]);
        assert!(r.findings_summary.is_none());
    }
}
