//! Built detectors. Each one matches a [`crate::detect::CATALOG`] entry.

mod apt_cache;
mod cargo_target;
mod docker;
mod docker_logs;
mod git_worktree;
mod journald;
mod node_modules;
mod old_kernels;
mod snap_revisions;
mod stale_tree;
mod tool_versions;
mod trash;
mod user_cache;
mod venv;

use std::io::Read;
use std::path::Path;

use crate::detect::Detector;

pub use apt_cache::AptCache;
pub use cargo_target::CargoTarget;
pub use docker::{
    BUILD_CACHE_AGE_HOURS, DockerBuildCache, DockerContainer, DockerImage, DockerPresence,
    DockerVolume, docker_presence, object_id,
};
pub(crate) use docker::{
    container_name, image_label, image_label_from_tags, image_named, short_id,
};
pub use docker_logs::{DockerLogs, MIN_LOG_BYTES};
pub use git_worktree::{
    GitWorktree, STALE_DAYS, WorktreeEntry, parse_porcelain, parse_porcelain_z,
};
pub use journald::Journald;
pub use node_modules::NodeModules;
pub use old_kernels::{APT_REMOVAL_SET, OldKernels, removal_set_guard, running_release};
pub(crate) use old_kernels::{package_state, process_roots as old_kernel_process_roots};
pub use snap_revisions::SnapRevisions;
pub use stale_tree::{SCRATCH_LOCATIONS, SCRATCH_MARKER, SCRATCH_STALE_DAYS, StaleTree};
pub use tool_versions::ToolVersions;
pub use trash::{TRASH_RECENT_DAYS, Trash};
pub use user_cache::{RECENT_HOURS, UserCache};
pub use venv::Venv;

/// Every detector that is built, in catalog order.
pub fn registry() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(CargoTarget),
        Box::new(NodeModules),
        Box::new(Venv),
        Box::new(UserCache::from_system()),
        Box::new(GitWorktree),
        Box::new(StaleTree),
        Box::new(ToolVersions::from_system()),
        Box::new(Trash::from_system()),
        Box::new(DockerImage),
        Box::new(DockerBuildCache),
        Box::new(DockerContainer),
        Box::new(DockerVolume),
        Box::new(Journald::from_system()),
        Box::new(AptCache::from_system()),
        Box::new(SnapRevisions::from_system()),
        Box::new(OldKernels::from_system()),
        Box::new(DockerLogs::from_system()),
    ]
}

/// Reads at most `limit` bytes of a regular file without following a symlink.
pub(crate) fn read_head(path: &Path, limit: usize) -> Option<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .ok()?;
    let st = rustix::fs::fstat(&fd).ok()?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile {
        return None;
    }
    let mut buf = Vec::with_capacity(limit.min(4096));
    std::fs::File::from(fd)
        .take(limit as u64)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}
