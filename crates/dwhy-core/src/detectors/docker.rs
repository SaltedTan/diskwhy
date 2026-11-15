//! Docker detectors: unused images, old build cache, stopped containers,
//! unused (and large in-use) volumes.
//!
//! All four read one shared [`crate::docker::Snapshot`]. Findings use
//! pseudo-paths (`docker://image/…`), which never nest with filesystem
//! findings. They are `review` tier by default: being able to use the Docker
//! socket is root-equivalent (docs/DESIGN.md). The exception is build cache
//! unused for [`BUILD_CACHE_AGE_HOURS`], which is `regenerable`: it is a cache,
//! and the prune command is limited to those records.

use crate::detect::{DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::docker::{Container, Snapshot};
use crate::report::{Action, ActionKind, Finding, GuardResult, GuardStatus, Recovery, Tier};
use crate::tree::ScanTree;
use crate::units::human;

/// Smaller images, containers and volumes are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;
/// In-use volumes at least this large are reported as advice.
const BIG_VOLUME: u64 = 1 << 30;
/// Build cache unused for this long is offered for pruning.
pub const BUILD_CACHE_AGE_HOURS: i64 = 168;

fn command(ctx: &DetectContext, args: &[&str]) -> Action {
    let mut argv = vec![
        ctx.tool_command("docker")
            .unwrap_or_else(|| "docker".into()),
        "-H".into(),
        format!("unix://{}", ctx.docker_socket.path),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    Action {
        kind: ActionKind::Command,
        text: argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
        argv: Some(argv),
    }
}

fn pos(v: i64) -> u64 {
    v.max(0) as u64
}

/// Seconds since the epoch for an RFC 3339 timestamp from the API.
fn parse_time(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

fn finding(
    detector: &str,
    path: String,
    bytes: u64,
    when: Option<i64>,
    reason: String,
    action: Action,
    recovery: Recovery,
) -> Finding {
    Finding {
        id: finding_id(detector, &path),
        detector: detector.into(),
        probe: None,
        path,
        bytes,
        nested_bytes: None,
        last_modified: when.map(rfc3339),
        growth: None,
        tier: Tier::Review,
        reason,
        guards: Vec::new(),
        action,
        recovery,
    }
}

fn container_name(c: &Container) -> String {
    c.names
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_else(|| c.id.chars().take(12).collect())
}

fn short_id(id: &str) -> String {
    id.trim_start_matches("sha256:").chars().take(12).collect()
}

pub struct DockerImage;

impl Detector for DockerImage {
    fn name(&self) -> &'static str {
        "docker-image"
    }

    fn detect(&self, _: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let snap = ctx.docker.get()?;
        Ok(images(&snap, ctx))
    }
}

fn images(snap: &Snapshot, ctx: &DetectContext) -> Vec<Finding> {
    let mut out = Vec::new();
    for img in snap.images() {
        // Containers is -1 when the daemon did not count them: unknown is not "unused".
        if img.containers != 0 {
            continue;
        }
        let shared = pos(img.shared_size);
        let unique = pos(img.size).saturating_sub(shared);
        if unique < MIN_BYTES {
            continue;
        }
        let tags: Vec<&str> = img
            .repo_tags
            .iter()
            .flatten()
            .map(String::as_str)
            .filter(|t| *t != "<none>:<none>")
            .collect();
        let (label, targets): (String, Vec<&str>) = if tags.is_empty() {
            (short_id(&img.id), vec![img.id.as_str()])
        } else {
            (tags[0].to_string(), tags.clone())
        };
        let mut reason = if tags.is_empty() {
            format!("untagged (dangling) image {label}, not used by any container")
        } else {
            format!("image {} is not used by any container", tags.join(", "))
        };
        reason.push_str(&format!("; removing it frees about {}", human(unique)));
        if shared > 0 {
            reason.push_str(&format!(
                " ({} more is shared with other images)",
                human(shared)
            ));
        }
        reason.push_str(&format!("; created {} ago", age(ctx.now, img.created)));
        let mut args = vec!["image", "rm"];
        args.extend(targets);
        // Whether a tag came from a registry can't be told reliably: with the
        // containerd image store, local builds carry a RepoDigest too.
        let recovery = match tags.first() {
            Some(t) => Recovery {
                cost: "download it again, or rebuild it if it was built locally".into(),
                how: Some(format!("docker pull {t} (or docker build)")),
            },
            None => Recovery {
                cost: "none: an untagged image is usually a leftover of a rebuild".into(),
                how: None,
            },
        };
        out.push(finding(
            "docker-image",
            format!("docker://image/{label}"),
            unique,
            Some(img.created),
            reason,
            command(ctx, &args),
            recovery,
        ));
    }
    out
}

pub struct DockerBuildCache;

impl Detector for DockerBuildCache {
    fn name(&self) -> &'static str {
        "docker-build-cache"
    }

    fn detect(&self, _: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let snap = ctx.docker.get()?;
        Ok(build_cache(&snap, ctx).into_iter().collect())
    }
}

fn build_cache(snap: &Snapshot, ctx: &DetectContext) -> Option<Finding> {
    let cutoff = ctx.now - BUILD_CACHE_AGE_HOURS * 3600;
    // What `docker builder prune` can reclaim: records neither in use nor shared.
    let reclaimable: Vec<_> = snap
        .build_cache()
        .iter()
        .filter(|r| !r.in_use && !r.shared)
        .collect();
    let all: u64 = reclaimable.iter().map(|r| pos(r.size)).sum();
    let old: Vec<_> = reclaimable
        .iter()
        .filter(|r| !matches!(r.kind.as_str(), "internal" | "frontend"))
        .filter(|r| {
            r.last_used_at
                .as_deref()
                .and_then(parse_time)
                .is_none_or(|t| t < cutoff)
        })
        .collect();
    let bytes: u64 = old.iter().map(|r| pos(r.size)).sum();
    if bytes < MIN_BYTES {
        return None;
    }
    let newest = old
        .iter()
        .filter_map(|r| r.last_used_at.as_deref().and_then(parse_time))
        .max();
    let days = BUILD_CACHE_AGE_HOURS / 24;
    let until = format!("until={BUILD_CACHE_AGE_HOURS}h");
    let mut f = finding(
        "docker-build-cache",
        "docker://build-cache".into(),
        bytes,
        newest,
        format!(
            "{} build cache records not used for {days} days hold {} (all reclaimable cache: {})",
            old.len(),
            human(bytes),
            human(all)
        ),
        command(ctx, &["builder", "prune", "--force", "--filter", &until]),
        Recovery {
            cost: "the next `docker build` re-runs the steps that were cached; steps that fetch \
                   from the network (apt-get, curl) get what upstream serves then"
                .into(),
            how: None,
        },
    );
    f.tier = Tier::Regenerable;
    Some(f)
}

pub struct DockerContainer;

impl Detector for DockerContainer {
    fn name(&self) -> &'static str {
        "docker-container"
    }

    fn detect(&self, _: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let snap = ctx.docker.get()?;
        Ok(containers(&snap, ctx))
    }
}

fn containers(snap: &Snapshot, ctx: &DetectContext) -> Vec<Finding> {
    let mut out = Vec::new();
    for c in snap.containers() {
        if !matches!(c.state.as_str(), "exited" | "created" | "dead") {
            continue;
        }
        let bytes = pos(c.size_rw.unwrap_or(0));
        if bytes < MIN_BYTES {
            continue;
        }
        let name = container_name(c);
        out.push(finding(
            "docker-container",
            format!("docker://container/{name}"),
            bytes,
            Some(c.created),
            format!(
                "stopped container {name} (image {}, {}); its writable layer holds {}",
                c.image,
                c.status,
                human(bytes)
            ),
            command(ctx, &["container", "rm", &c.id]),
            Recovery {
                cost: "recreate it; files written inside the container are lost".into(),
                how: Some("docker run / docker compose up".into()),
            },
        ));
    }
    out
}

pub struct DockerVolume;

impl Detector for DockerVolume {
    fn name(&self) -> &'static str {
        "docker-volume"
    }

    fn detect(&self, _: &ScanTree, ctx: &DetectContext) -> Result<Vec<Finding>, String> {
        let snap = ctx.docker.get()?;
        Ok(volumes(&snap, ctx))
    }
}

fn volumes(snap: &Snapshot, ctx: &DetectContext) -> Vec<Finding> {
    let mut out = Vec::new();
    for v in snap.volumes() {
        let Some(u) = v.usage_data.as_ref() else {
            continue;
        };
        let bytes = pos(u.size);
        let users: Vec<(String, &str)> = snap
            .containers()
            .iter()
            .filter(|c| {
                c.mounts
                    .iter()
                    .any(|m| m.kind == "volume" && m.name == v.name)
            })
            .map(|c| (container_name(c), c.state.as_str()))
            .collect();
        let anonymous = v.name.len() == 64 && v.name.bytes().all(|b| b.is_ascii_hexdigit());
        let created = parse_time(&v.created_at);
        let path = format!("docker://volume/{}", v.name);
        if u.ref_count == 0 && users.is_empty() {
            if bytes < MIN_BYTES {
                continue;
            }
            let kind = if anonymous {
                "anonymous volume"
            } else {
                "volume"
            };
            out.push(finding(
                "docker-volume",
                path,
                bytes,
                created,
                format!(
                    "{kind} {} is not mounted by any container (running or stopped); it holds {}{}",
                    v.name,
                    human(bytes),
                    created
                        .map(|t| format!("; created {} ago", age(ctx.now, t)))
                        .unwrap_or_default()
                ),
                command(ctx, &["volume", "rm", &v.name]),
                Recovery {
                    cost: "the data is gone; only remove it if nothing needs it".into(),
                    how: None,
                },
            ));
        } else if bytes >= BIG_VOLUME && !users.is_empty() {
            let who: Vec<String> = users.iter().map(|(n, s)| format!("{n} ({s})")).collect();
            let mut f = finding(
                "docker-volume",
                path,
                bytes,
                created,
                format!(
                    "volume {} holds {} and is mounted by {}",
                    v.name,
                    human(bytes),
                    who.join(", ")
                ),
                Action {
                    kind: ActionKind::Advice,
                    text: "in use: if the data is no longer needed, remove the containers first, then the volume".into(),
                    argv: None,
                },
                Recovery {
                    cost: "n/a while in use".into(),
                    how: None,
                },
            );
            let running = users.iter().any(|(_, s)| *s == "running");
            f.guards.push(GuardResult {
                name: "container-mount".into(),
                status: GuardStatus::Warn,
                detail: format!("mounted by {}", who.join(", ")),
            });
            if running {
                f.reason.push_str(" (a running container uses it)");
            }
            out.push(f);
        }
    }
    out
}
