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
    /// inside another finding's path is dropped: the outermost finding wins.
    pub findings: Vec<Finding>,
    /// Every known detector, whether it ran, and why not.
    #[serde(default)]
    pub detectors: Vec<DetectorRun>,
    /// Docker's own accounting, when the Docker detectors could query the daemon.
    #[serde(default)]
    pub docker: Option<DockerUsage>,
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
    /// Allocated bytes under `path`, each hardlinked file counted once.
    /// `user-cache` also leaves out files kept alive by links elsewhere, so
    /// its figure is what removing the cache is expected to free.
    pub bytes: u64,
    /// Newest mtime under `path`, RFC 3339 (UTC).
    #[serde(default)]
    pub last_modified: Option<String>,
    pub growth: Option<Growth>,
    pub tier: Tier,
    pub reason: String,
    pub guards: Vec<GuardResult>,
    pub action: Action,
    pub recovery: Recovery,
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
