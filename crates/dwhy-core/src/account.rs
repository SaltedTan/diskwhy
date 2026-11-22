//! Turning a [`ScanResult`] into a `diskwhy/v1` report: per-filesystem `df`
//! figures, the unaccounted gap, and hints for where the gap probably is.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::detect::shell_quote;
use crate::mounts::{FsStats, Mount, MountTable};
use crate::report::{
    self, DeletedOpen, DirEntry, DockerUsage, FsReport, Hint, HintKind, RootReport, ScanErrorEntry,
    ScanReport, ScanSummary, SkippedMount, Tool, Totals, Unreadable, UnreadableDir,
};
use crate::scan::{ScanResult, SkippedRecord, UnreadableRecord};
use crate::system::{DeletedOpenScan, User};

/// Unreadable directories listed by path in the JSON (all are counted).
pub const MAX_UNREADABLE_LISTED: usize = 500;

/// `used - scanned`, only meaningful when the scan covered the whole filesystem.
pub fn unaccounted(used: u64, scanned: u64, full_coverage: bool) -> Option<u64> {
    full_coverage.then(|| used.saturating_sub(scanned))
}

/// A gap is worth calling out above max(1 GiB, 1% of the filesystem).
pub fn gap_is_large(unaccounted: u64, fs_size: u64) -> bool {
    unaccounted > (1u64 << 30).max(fs_size / 100)
}

/// Everything about the environment the report needs besides the scan.
#[derive(Debug, Clone)]
pub struct ReportEnv {
    pub host: String,
    pub uid: u32,
    pub root: bool,
    pub generated_at: String,
    pub users: Vec<User>,
    pub deleted_open: DeletedOpenScan,
    /// Absolute path of the running binary, for the sudo rerun hint
    /// (`sudo` resets `$PATH`, so a bare `dwhy` may not resolve).
    pub exe: String,
    /// The Docker socket is usable without sudo (docker group or rootless).
    pub docker_access: bool,
}

/// Where in the hint ordering a kind goes when no bytes are known:
/// roughly, how big such locations usually are.
fn kind_rank(k: HintKind) -> u8 {
    use HintKind::*;
    match k {
        Docker => 0,
        Containerd => 1,
        VirtualMachines => 2,
        Database => 3,
        OtherUserHome => 4,
        RootHome => 5,
        Logs => 6,
        Snap => 7,
        Cache => 8,
        Unreadable => 9,
        SystemPrivate => 10,
        DeletedOpen => 11,
        ShadowedByMount => 12,
        FilesystemOverhead => 13,
    }
}

const PREFIXES: &[(&str, HintKind, &str)] = &[
    (
        "/var/lib/docker",
        HintKind::Docker,
        "Docker data root: images, containers, volumes, build cache",
    ),
    (
        "/var/lib/containerd",
        HintKind::Containerd,
        "containerd content store and snapshots",
    ),
    (
        "/opt/containerd",
        HintKind::Containerd,
        "containerd plugins and state",
    ),
    (
        "/var/lib/libvirt",
        HintKind::VirtualMachines,
        "libvirt VM disk images",
    ),
    (
        "/var/lib/lxd",
        HintKind::VirtualMachines,
        "LXD containers and VMs",
    ),
    (
        "/var/snap/lxd",
        HintKind::VirtualMachines,
        "LXD (snap) containers and VMs",
    ),
    (
        "/var/lib/incus",
        HintKind::VirtualMachines,
        "Incus containers and VMs",
    ),
    (
        "/var/lib/postgresql",
        HintKind::Database,
        "PostgreSQL data (check WAL)",
    ),
    ("/var/lib/mysql", HintKind::Database, "MySQL/MariaDB data"),
    ("/var/lib/mongodb", HintKind::Database, "MongoDB data"),
    ("/var/lib/redis", HintKind::Database, "Redis dumps"),
    ("/root", HintKind::RootHome, "root's home directory"),
    (
        "/var/log",
        HintKind::Logs,
        "system logs, including the journal",
    ),
    ("/var/lib/snapd", HintKind::Snap, "snap revisions and seeds"),
    ("/var/snap", HintKind::Snap, "snap data"),
    ("/var/cache", HintKind::Cache, "system caches (apt, ...)"),
    (
        "/var/tmp",
        HintKind::SystemPrivate,
        "private temp dirs of system services",
    ),
    (
        "/var/lib/private",
        HintKind::SystemPrivate,
        "private state of system services",
    ),
    ("/var/spool", HintKind::SystemPrivate, "spool directories"),
    (
        "/var/lib",
        HintKind::SystemPrivate,
        "state of system services",
    ),
    (
        "/etc",
        HintKind::SystemPrivate,
        "private configuration (usually tiny)",
    ),
    (
        "/lost+found",
        HintKind::SystemPrivate,
        "fsck recovered files (usually empty)",
    ),
];

/// A person's account rather than a system service (Debian/Ubuntu/Fedora
/// `UID_MIN`..`UID_MAX`, excluding `nobody`).
fn is_login_user(u: &User) -> bool {
    (1000..60000).contains(&u.uid) && u.home != Path::new("/")
}

/// Groups unreadable directories on one filesystem into likely locations.
pub fn unreadable_hints(
    unreadable: &[&UnreadableRecord],
    users: &[User],
    my_uid: u32,
    docker_hint: bool,
) -> Vec<Hint> {
    // (kind, path) -> (detail, count, examples)
    let mut groups: BTreeMap<(u8, String), (HintKind, String, u64)> = BTreeMap::new();
    let mut other: Vec<&Path> = Vec::new();
    for u in unreadable {
        let p = u.path.as_path();
        let known = PREFIXES
            .iter()
            .find(|(pre, _, _)| p.starts_with(pre))
            .map(|(pre, k, d)| {
                let mut d = (*d).to_string();
                if *k == HintKind::Docker && docker_hint {
                    d.push_str("; `docker system df -v` sizes it without sudo");
                }
                (*k, pre.to_string(), d)
            })
            .or_else(|| {
                users
                    .iter()
                    .filter(|usr| usr.uid != my_uid && is_login_user(usr))
                    .filter(|usr| p.starts_with(&usr.home))
                    .max_by_key(|usr| usr.home.as_os_str().len())
                    .map(|usr| {
                        (
                            HintKind::OtherUserHome,
                            usr.home.to_string_lossy().into_owned(),
                            format!("home of user {} (uid {})", usr.name, usr.uid),
                        )
                    })
            });
        match known {
            Some((kind, path, detail)) => {
                groups
                    .entry((kind_rank(kind), path))
                    .or_insert((kind, detail, 0))
                    .2 += 1;
            }
            None => other.push(p),
        }
    }
    let mut hints: Vec<Hint> = groups
        .into_iter()
        .map(|((_, path), (kind, detail, n))| Hint {
            kind,
            path: Some(path),
            detail,
            unreadable_dirs: n,
            bytes: None,
        })
        .collect();
    if !other.is_empty() {
        let examples: Vec<String> = other
            .iter()
            .take(3)
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let more = other.len().saturating_sub(examples.len());
        let mut detail = format!("other unreadable directories: {}", examples.join(", "));
        if more > 0 {
            detail.push_str(&format!(" and {more} more"));
        }
        hints.push(Hint {
            kind: HintKind::Unreadable,
            path: (other.len() == 1).then(|| other[0].to_string_lossy().into_owned()),
            detail,
            unreadable_dirs: other.len() as u64,
            bytes: None,
        });
    }
    // Stable: keeps path order within a kind.
    hints.sort_by_key(|h| kind_rank(h.kind));
    hints
}

/// All hints for one filesystem, most likely first: measured hints that are a
/// real share of the gap, then unreadable locations by typical size, then the rest.
pub fn fs_hints(
    gap: u64,
    unreadable: Vec<Hint>,
    deleted: DeletedOpen,
    shadowing: &[&Mount],
    fstype: &str,
) -> Vec<Hint> {
    let mut measured = Vec::new();
    let mut tail = Vec::new();
    if deleted.files > 0 {
        let h = Hint {
            kind: HintKind::DeletedOpen,
            path: None,
            detail: format!(
                "{} deleted file(s) still held open by running processes; space returns when they close",
                deleted.files
            ),
            unreadable_dirs: 0,
            bytes: Some(deleted.bytes),
        };
        if deleted.bytes.saturating_mul(20) >= gap {
            measured.push(h);
        } else {
            tail.push(h);
        }
    }
    let real_shadowing: Vec<&&Mount> = shadowing.iter().filter(|m| !m.is_virtual()).collect();
    if !real_shadowing.is_empty() {
        let names: Vec<String> = real_shadowing
            .iter()
            .take(4)
            .map(|m| m.mount_point.to_string_lossy().into_owned())
            .collect();
        tail.push(Hint {
            kind: HintKind::ShadowedByMount,
            path: None,
            detail: format!(
                "files written under a mount point before it was mounted are hidden from any walk ({}{})",
                names.join(", "),
                if real_shadowing.len() > names.len() { ", ..." } else { "" }
            ),
            unreadable_dirs: 0,
            bytes: None,
        });
    }
    if matches!(fstype, "btrfs" | "zfs" | "bcachefs") {
        tail.push(Hint {
            kind: HintKind::FilesystemOverhead,
            path: None,
            detail: format!("{fstype} snapshots and metadata are not visible to a file walk"),
            unreadable_dirs: 0,
            bytes: None,
        });
    }
    measured.extend(unreadable);
    measured.extend(tail);
    measured
}

fn lossy(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn mount_for_dev(mounts: &MountTable, dev: u64) -> Option<&Mount> {
    mounts.mounts.iter().rev().find(|m| m.dev() == dev)
}

/// What makes two devices one filesystem in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsKey {
    /// The device the mount table gives: every mount of one filesystem
    /// (bind mounts, btrfs subvolumes) shares it, though a btrfs
    /// subvolume's own `st_dev` differs.
    Mount(u64),
    /// No mount table entry: the `st_dev` alone.
    Dev(u64),
}

/// One filesystem the scan touched.
struct FsGroup {
    key: FsKey,
    /// The mount named in the report: a whole-filesystem mount when there is one.
    mount: Mount,
    full: bool,
    /// The scan root at the whole-filesystem mount, if one is.
    whole_root: Option<usize>,
    /// Every scan root on it.
    roots: Vec<usize>,
    /// Every `st_dev` scanned on it.
    devs: BTreeSet<u64>,
    /// Ids of the mounts the scan reached it through.
    via: BTreeSet<u32>,
}

/// The filesystems the scan touched: those of the roots first (in root
/// order), then any entered while crossing filesystems.
fn fs_groups(result: &ScanResult, mounts: &MountTable) -> Vec<FsGroup> {
    let mut groups: Vec<FsGroup> = Vec::new();
    let add = |groups: &mut Vec<FsGroup>, key: FsKey, m: &Mount, full: bool| -> usize {
        match groups.iter().position(|g| g.key == key) {
            Some(i) => {
                let g = &mut groups[i];
                if full && !g.full {
                    g.full = true;
                    g.mount = m.clone();
                }
                i
            }
            None => {
                groups.push(FsGroup {
                    key,
                    mount: m.clone(),
                    full,
                    whole_root: None,
                    roots: Vec::new(),
                    devs: BTreeSet::new(),
                    via: BTreeSet::new(),
                });
                groups.len() - 1
            }
        }
    };
    for (ri, r) in result.roots.iter().enumerate() {
        let (key, m, via) = match mounts.for_path(&r.path) {
            Some(m) => (FsKey::Mount(m.dev()), m.clone(), Some(m.id)),
            None => (FsKey::Dev(r.dev), unknown_mount(&r.path), None),
        };
        // Only a walk from the mount point of a mount showing the whole
        // filesystem sees everything `statvfs` counts.
        let full = m.mount_point == r.path && m.is_whole_filesystem();
        let i = add(&mut groups, key, &m, full);
        if full && groups[i].whole_root.is_none() {
            groups[i].whole_root = Some(ri);
        }
        groups[i].roots.push(ri);
        groups[i].devs.insert(r.dev);
        groups[i].via.extend(via);
    }
    let mut entered: Vec<&Mount> = result
        .entered_mounts
        .iter()
        .filter_map(|id| mounts.by_id(*id))
        .collect();
    entered.sort_by_key(|m| (m.dev(), m.id));
    for m in entered {
        let i = add(
            &mut groups,
            FsKey::Mount(m.dev()),
            m,
            m.is_whole_filesystem(),
        );
        groups[i].via.insert(m.id);
    }
    let mut devs: Vec<u64> = result.per_dev.keys().copied().collect();
    devs.sort();
    for d in devs {
        if groups.iter().any(|g| g.devs.contains(&d)) {
            continue;
        }
        if let Some(m) = owning_mount(result, mounts, d, None) {
            // A device with no root on it and no mount entered for it: how
            // much of it the walk saw is unknown.
            let i = add(&mut groups, FsKey::Mount(m.dev()), m, false);
            groups[i].devs.insert(d);
        }
    }
    for g in &mut groups {
        g.via
            .extend(g.devs.iter().filter_map(|d| result.dev_mounts.get(d)));
        // Without a whole-filesystem root, `scanned` adds up every walk on
        // the filesystem: complete only if they all went through one mount.
        if g.whole_root.is_none() && g.via.len() > 1 {
            g.full = false;
        }
    }
    groups
}

/// Where the part of the filesystem that `root` shows lies below `whole`,
/// a root at a whole-filesystem mount of the same filesystem.
fn location(mounts: &MountTable, whole: &Path, root: &Path) -> Option<PathBuf> {
    let m = mounts.for_path(root)?;
    let below = root.strip_prefix(&m.mount_point).ok()?;
    Some(
        whole
            .join(m.root.strip_prefix("/").unwrap_or(&m.root))
            .join(below),
    )
}

/// Whether the walk of root `path`, at location `at`, reached location
/// `other`: it lies at or below `at`, with no mount point the walk did not
/// enter on the way.
fn reached_by(result: &ScanResult, path: &Path, at: &Path, other: &Path) -> bool {
    let Ok(rest) = other.strip_prefix(at) else {
        return false;
    };
    let pos = path.join(rest);
    !result
        .skipped_mounts
        .iter()
        .any(|s| s.path != path && s.path.starts_with(path) && pos.starts_with(&s.path))
}

/// The mount through which the scan reached `dev`: as the walk recorded
/// it, else the mount holding `path`, else one the mount table lists for
/// `dev`.
fn owning_mount<'a>(
    result: &ScanResult,
    mounts: &'a MountTable,
    dev: u64,
    path: Option<&Path>,
) -> Option<&'a Mount> {
    result
        .dev_mounts
        .get(&dev)
        .and_then(|id| mounts.by_id(*id))
        .or_else(|| path.and_then(|p| mounts.for_path(p)))
        .or_else(|| mount_for_dev(mounts, dev))
}

/// The group holding `dev`, if any.
fn group_of(
    groups: &[FsGroup],
    result: &ScanResult,
    mounts: &MountTable,
    dev: u64,
    path: Option<&Path>,
) -> Option<usize> {
    groups
        .iter()
        .position(|g| g.devs.contains(&dev))
        .or_else(|| {
            let key = FsKey::Mount(owning_mount(result, mounts, dev, path)?.dev());
            groups.iter().position(|g| g.key == key)
        })
}

/// The scan report for a finished walk on this system (host, uid, clock,
/// users, deleted-open files, Docker access, `statvfs`), before detectors
/// run. What `dwhy scan` and the TUI both start from.
pub fn system_scan_report(result: &ScanResult, mounts: &MountTable) -> ScanReport {
    let euid = crate::system::euid();
    let env = ReportEnv {
        host: crate::system::hostname(),
        uid: euid,
        root: euid == 0,
        generated_at: crate::system::now_rfc3339(),
        users: crate::system::users(),
        deleted_open: crate::system::deleted_open_files(),
        exe: std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "dwhy".into()),
        docker_access: crate::doctor::docker_access(),
    };
    build_scan_report(result, mounts, &env, &|p| crate::mounts::statvfs(p).ok())
}

/// Builds the JSON report. Calls `statvfs` for each filesystem the scan touched.
pub fn build_scan_report(
    result: &ScanResult,
    mounts: &MountTable,
    env: &ReportEnv,
    fs_stats: &dyn Fn(&Path) -> Option<FsStats>,
) -> ScanReport {
    let groups = fs_groups(result, mounts);
    let mut on_fs: Vec<Vec<&UnreadableRecord>> = vec![Vec::new(); groups.len()];
    for u in &result.unreadable {
        if let Some(i) = group_of(&groups, result, mounts, u.dev, Some(&u.path)) {
            on_fs[i].push(u);
        }
    }
    // Processes whose fds could not be listed are counted once per scan,
    // not once per device.
    let mut deleted = vec![
        DeletedOpen {
            processes_unreadable: env.deleted_open.processes_unreadable,
            ..DeletedOpen::default()
        };
        groups.len()
    ];
    let mut deleted_devs: Vec<(&u64, &DeletedOpen)> = env.deleted_open.per_dev.iter().collect();
    deleted_devs.sort_by_key(|(d, _)| **d);
    for (dev, d) in deleted_devs {
        if let Some(i) = group_of(&groups, result, mounts, *dev, None) {
            deleted[i].files += d.files;
            deleted[i].bytes += d.bytes;
        }
    }

    let fs: Vec<FsReport> = groups
        .into_iter()
        .zip(on_fs)
        .zip(deleted)
        .map(|((g, on_fs), deleted)| {
            let FsGroup {
                mount: m,
                full,
                whole_root,
                roots,
                devs,
                ..
            } = g;
            let stats = fs_stats(&m.mount_point).unwrap_or(FsStats {
                size: 0,
                used: 0,
                avail: 0,
            });
            let on_devs = |reached: &HashMap<u64, Totals>| -> u64 {
                devs.iter()
                    .filter_map(|d| reached.get(d))
                    .map(|t| t.allocated)
                    .sum()
            };
            // With a whole-filesystem root, count it, then each other root
            // (outer ones first) unless a root already counted reached what
            // it shows: adding that would count it twice.
            let scanned = match whole_root {
                None => on_devs(&result.per_dev),
                Some(w) => {
                    let whole = &result.roots[w].path;
                    let mut others: Vec<(PathBuf, usize)> = roots
                        .iter()
                        .filter(|&&i| i != w)
                        .filter_map(|&i| Some((location(mounts, whole, &result.roots[i].path)?, i)))
                        .collect();
                    others.sort();
                    let mut counted: Vec<(PathBuf, usize)> = vec![(whole.clone(), w)];
                    for (at, i) in others {
                        if !counted
                            .iter()
                            .any(|(c, a)| reached_by(result, &result.roots[*a].path, c, &at))
                        {
                            counted.push((at, i));
                        }
                    }
                    counted
                        .iter()
                        .map(|&(_, i)| on_devs(&result.roots[i].per_dev))
                        .sum()
                }
            };
            let gap = unaccounted(stats.used, scanned, full);
            let large = gap.is_some_and(|g| gap_is_large(g, stats.size));
            let hints = match gap {
                Some(g) if g > 0 => {
                    let shadowing: Vec<&Mount> = mounts.children_of(&m).collect();
                    fs_hints(
                        g,
                        unreadable_hints(&on_fs, &env.users, env.uid, env.docker_access),
                        deleted,
                        &shadowing,
                        &m.fstype,
                    )
                }
                _ => Vec::new(),
            };
            let rerun = (large && !env.root).then(|| {
                format!(
                    "sudo {} scan {}",
                    env.exe,
                    shell_quote(&lossy(&m.mount_point))
                )
            });
            FsReport {
                mount: lossy(&m.mount_point),
                fstype: m.fstype.clone(),
                source: m.source.clone(),
                size: stats.size,
                used: stats.used,
                avail: stats.avail,
                scanned,
                full_coverage: full,
                unaccounted: gap,
                unaccounted_large: large,
                hints,
                deleted_open: deleted,
                rerun,
            }
        })
        .collect();

    let roots = result
        .roots
        .iter()
        .map(|r| RootReport {
            path: lossy(&r.path),
            mount: mounts
                .for_path(&r.path)
                .map(|m| lossy(&m.mount_point))
                .unwrap_or_default(),
            totals: r.totals,
        })
        .collect();

    let unreadable = Unreadable {
        count: result.unreadable.len() as u64,
        entries_unknown: result.unreadable.iter().map(|u| u.entries_unknown).sum(),
        known_bytes: result.unreadable.iter().map(|u| u.known_bytes).sum(),
        dirs: result
            .unreadable
            .iter()
            .take(MAX_UNREADABLE_LISTED)
            .map(|u| UnreadableDir {
                path: lossy(&u.path),
                reason: u.reason,
                entries_unknown: u.entries_unknown,
                known_bytes: u.known_bytes,
                owner_uid: Some(u.owner_uid),
            })
            .collect(),
        truncated: result.unreadable.len() > MAX_UNREADABLE_LISTED,
    };

    ScanReport {
        schema: report::SCHEMA.into(),
        tool: Tool::current(),
        host: env.host.clone(),
        uid: env.uid,
        root: env.root,
        generated_at: env.generated_at.clone(),
        scan: ScanSummary {
            roots,
            one_filesystem: result.one_filesystem,
            elapsed_ms: result.elapsed.as_millis() as u64,
            totals: result.totals(),
            dirs: result
                .dirs
                .iter()
                .map(|d| DirEntry {
                    path: lossy(&d.path),
                    depth: d.depth,
                    allocated: d.totals.allocated,
                    apparent: d.totals.apparent,
                    files: d.totals.files,
                })
                .collect(),
            min_dir_bytes: result.min_dir_bytes,
            unreadable,
            skipped_mounts: result.skipped_mounts.iter().map(skipped).collect(),
            errors: result
                .errors
                .iter()
                .map(|(p, e)| ScanErrorEntry {
                    path: lossy(p),
                    error: e.clone(),
                })
                .collect(),
            error_count: result.error_count,
        },
        fs,
        // Filled in by the caller from `detect::run`.
        findings: Vec::new(),
        detectors: Vec::new(),
        docker: None,
        snapshot: None,
    }
}

/// Records Docker's own accounting in the report and puts its measured bytes
/// on the matching unaccounted-space hints: image layers on the
/// `/var/lib/containerd` hint when Docker uses the containerd image store,
/// everything else on the hint for Docker's root dir.
pub fn attach_docker(report: &mut ScanReport, usage: &DockerUsage) {
    attach_docker_hints(&mut report.fs, usage);
    report.docker = Some(usage.clone());
}

/// The hint half of [`attach_docker`].
pub fn attach_docker_hints(filesystems: &mut [FsReport], usage: &DockerUsage) {
    let image_bytes = usage.images.bytes;
    let rest = usage.total - image_bytes;
    let split = usage.containerd_image_store;
    for fs in filesystems {
        for h in &mut fs.hints {
            let path = h.path.as_deref().unwrap_or("");
            if h.kind == HintKind::Docker && Path::new(path) == Path::new(&usage.root_dir) {
                h.bytes = Some(if split { rest } else { usage.total });
                h.detail = if split {
                    "Docker data root: containers, volumes and build cache, as measured by Docker (images are under /var/lib/containerd)".into()
                } else {
                    "Docker data root: images, containers, volumes and build cache, as measured by Docker".into()
                };
            } else if split && h.kind == HintKind::Containerd && path == "/var/lib/containerd" {
                h.bytes = Some(image_bytes);
                h.detail =
                    "containerd content store: Docker's image layers, as measured by Docker".into();
            }
        }
    }
}

fn skipped(s: &SkippedRecord) -> SkippedMount {
    SkippedMount {
        path: lossy(&s.path),
        fstype: s.fstype.clone(),
        reason: s.reason,
    }
}

fn unknown_mount(path: &Path) -> Mount {
    Mount {
        id: u32::MAX,
        parent: u32::MAX,
        major: 0,
        minor: 0,
        root: PathBuf::from("/"),
        mount_point: path
            .ancestors()
            .last()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/")),
        fstype: "unknown".into(),
        source: "unknown".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::UnreadableReason;

    fn rec(p: &str) -> UnreadableRecord {
        UnreadableRecord {
            path: PathBuf::from(p),
            dev: 1,
            reason: UnreadableReason::PermissionDenied,
            entries_unknown: 0,
            known_bytes: 4096,
            owner_uid: 0,
        }
    }

    fn users() -> Vec<User> {
        crate::system::parse_passwd(
            "root:x:0:0::/root:/bin/sh\nme:x:1000:1000::/home/me:/bin/sh\nbob:x:1003:1003::/home/bob:/bin/sh\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\ngdm:x:975:975::/var/lib/gdm3:/bin/false\n",
        )
    }

    #[test]
    fn unaccounted_is_used_minus_scanned_only_with_full_coverage() {
        assert_eq!(unaccounted(100, 60, true), Some(40));
        assert_eq!(unaccounted(100, 60, false), None);
        // Scanned can exceed used (files written during the scan); never negative.
        assert_eq!(unaccounted(100, 120, true), Some(0));
    }

    #[test]
    fn large_gap_threshold() {
        let gib = 1u64 << 30;
        // 392G filesystem: threshold is 1% (~3.9G).
        let size = 392 * gib;
        assert!(!gap_is_large(3 * gib, size));
        assert!(gap_is_large(38 * gib, size));
        // Small filesystem: the 1 GiB floor applies.
        assert!(!gap_is_large(gib / 2, 10 * gib));
        assert!(gap_is_large(2 * gib, 10 * gib));
    }

    #[test]
    fn hints_group_known_locations_in_size_order() {
        let recs = [
            rec("/var/log/private"),
            rec("/home/bob"),
            rec("/var/lib/docker"),
            rec("/home/me/project/blocked"),
            rec("/var/lib/docker/volumes"),
            rec("/root"),
            rec("/srv/odd"),
            rec("/var/lib/gdm3/.cache"),
        ];
        let refs: Vec<&UnreadableRecord> = recs.iter().collect();
        let h = unreadable_hints(&refs, &users(), 1000, true);
        let kinds: Vec<HintKind> = h.iter().map(|h| h.kind).collect();
        assert_eq!(
            kinds,
            [
                HintKind::Docker,
                HintKind::OtherUserHome,
                HintKind::RootHome,
                HintKind::Logs,
                HintKind::Unreadable,
                HintKind::SystemPrivate,
            ]
        );
        assert_eq!(h[0].path.as_deref(), Some("/var/lib/docker"));
        assert_eq!(h[0].unreadable_dirs, 2);
        assert!(h[0].detail.contains("docker system df"));
        assert_eq!(h[1].path.as_deref(), Some("/home/bob"));
        assert!(h[1].detail.contains("bob"));
        // Our own unreadable dirs are not "another user's home".
        assert_eq!(h[4].unreadable_dirs, 2);
        assert!(h[4].detail.contains("/home/me/project/blocked"));
    }

    #[test]
    fn deleted_open_goes_first_when_it_explains_the_gap() {
        let gib = 1u64 << 30;
        let big = DeletedOpen {
            files: 2,
            bytes: 10 * gib,
            processes_unreadable: 0,
        };
        let unread = vec![Hint {
            kind: HintKind::Docker,
            path: Some("/var/lib/docker".into()),
            detail: String::new(),
            unreadable_dirs: 1,
            bytes: None,
        }];
        let h = fs_hints(20 * gib, unread.clone(), big, &[], "ext4");
        assert_eq!(h[0].kind, HintKind::DeletedOpen);
        let small = DeletedOpen {
            bytes: 1 << 20,
            ..big
        };
        let h = fs_hints(20 * gib, unread, small, &[], "btrfs");
        assert_eq!(h[0].kind, HintKind::Docker);
        assert_eq!(h[1].kind, HintKind::DeletedOpen);
        assert_eq!(h.last().unwrap().kind, HintKind::FilesystemOverhead);
    }
}
