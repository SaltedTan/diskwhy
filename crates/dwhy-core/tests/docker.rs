//! Docker detectors and hint attribution, against a fixed Engine API
//! snapshot (tests/data/docker-system-df.json). No daemon is contacted.

use std::collections::HashMap;
use std::sync::Arc;

use dwhy_core::account;
use dwhy_core::detect::{DetectContext, Detector, run_with};
use dwhy_core::detectors::{DockerBuildCache, DockerContainer, DockerImage, DockerVolume};
use dwhy_core::docker::{self, Info, Snapshot, Source, SystemDf};
use dwhy_core::report::*;
use dwhy_core::tree::ScanTree;

/// 2026-11-15T00:26:40Z
const NOW: i64 = 1_794_700_000;

fn snapshot(containerd: bool) -> Snapshot {
    let df: SystemDf = serde_json::from_str(include_str!("data/docker-system-df.json")).unwrap();
    let driver_type = if containerd {
        "io.containerd.snapshotter.v1"
    } else {
        "overlay2"
    };
    let info: Info = serde_json::from_str(&format!(
        r#"{{"Driver":"overlayfs","DriverStatus":[["driver-type","{driver_type}"]],"DockerRootDir":"/var/lib/docker"}}"#
    ))
    .unwrap();
    Snapshot { df, info }
}

fn ctx_with(source: Arc<Source>) -> DetectContext {
    DetectContext {
        uid: 1000,
        root: false,
        home: None,
        now: NOW,
        tools: vec![ToolStatus {
            name: "docker".into(),
            path: Some("/usr/bin/docker".into()),
            off_path: None,
            enables: vec![],
        }],
        docker_socket: DockerSocket {
            path: "/var/run/docker.sock".into(),
            exists: true,
            accessible: true,
        },
        docker: source,
    }
}

fn ctx() -> DetectContext {
    ctx_with(Source::fixed(snapshot(true)))
}

fn by_path(found: Vec<Finding>) -> HashMap<String, Finding> {
    found.into_iter().map(|f| (f.path.clone(), f)).collect()
}

fn argv(f: &Finding) -> Vec<&str> {
    f.action
        .argv
        .as_ref()
        .unwrap()
        .iter()
        .map(String::as_str)
        .collect()
}

#[test]
fn images_unused_by_any_container() {
    let found = by_path(DockerImage.detect(&ScanTree::default(), &ctx()).unwrap());
    let mut paths: Vec<&str> = found.keys().map(String::as_str).collect();
    paths.sort();
    // app:latest is used, counted:never has an unknown container count,
    // alpine frees under 1 MiB: none of them is offered.
    assert_eq!(
        paths,
        [
            "docker://image/bbbb00000000",
            "docker://image/ci-runner:local",
            "docker://image/postgres:16-alpine"
        ]
    );

    let dangling = &found["docker://image/bbbb00000000"];
    assert_eq!(dangling.bytes, 2_750_000_000 - 1_630_000_000);
    assert_eq!(dangling.tier, Tier::Review);
    assert!(
        dangling.reason.starts_with("untagged (dangling) image"),
        "{}",
        dangling.reason
    );
    assert_eq!(
        argv(dangling),
        [
            "docker",
            "image",
            "rm",
            "sha256:bbbb000000000000000000000000000000000000000000000000000000000002"
        ]
    );
    assert_eq!(dangling.recovery.how, None);

    // Every tag is removed, or the image would only lose one name and free nothing.
    let multi = &found["docker://image/ci-runner:local"];
    assert_eq!(
        argv(multi),
        ["docker", "image", "rm", "ci-runner:local", "ci-runner:v2"]
    );
    assert_eq!(multi.bytes, 2_150_000_000 - 134_000_000);
    assert!(
        multi.reason.contains("shared with other images"),
        "{}",
        multi.reason
    );
    assert_eq!(multi.last_modified.as_deref(), Some("2026-11-13T20:00:00Z"));

    let pg = &found["docker://image/postgres:16-alpine"];
    assert_eq!(pg.bytes, 420_000_000);
    assert!(!pg.reason.contains("shared"));
    assert_eq!(
        pg.recovery.how.as_deref(),
        Some("docker pull postgres:16-alpine (or docker build)")
    );
}

#[test]
fn build_cache_older_than_a_week() {
    let found = DockerBuildCache
        .detect(&ScanTree::default(), &ctx())
        .unwrap();
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!(f.path, "docker://build-cache");
    // Only `old1`: `recent` was used yesterday, `old-shared` is shared, `busy` is in use.
    assert_eq!(f.bytes, 800_000_000);
    assert!(
        f.reason
            .starts_with("1 build cache records not used for 7 days"),
        "{}",
        f.reason
    );
    assert!(
        f.reason.contains("all reclaimable cache: 953.7M"),
        "{}",
        f.reason
    );
    assert_eq!(
        argv(f),
        [
            "docker",
            "builder",
            "prune",
            "--force",
            "--filter",
            "until=168h"
        ]
    );
    assert_eq!(f.last_modified.as_deref(), Some("2026-11-04T13:12:35Z"));
}

#[test]
fn stopped_containers_with_a_writable_layer() {
    let found = DockerContainer
        .detect(&ScanTree::default(), &ctx())
        .unwrap();
    // app-1 is running; never-started has an empty writable layer.
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!(f.path, "docker://container/old-job");
    assert_eq!(f.bytes, 500_000_000);
    assert!(f.reason.contains("Exited (0) 3 days ago"), "{}", f.reason);
    assert_eq!(
        argv(f),
        [
            "docker",
            "container",
            "rm",
            "c2000000000000000000000000000000000000000000000000000000000000b2"
        ]
    );
}

#[test]
fn unused_and_large_in_use_volumes() {
    let found = by_path(DockerVolume.detect(&ScanTree::default(), &ctx()).unwrap());
    let mut paths: Vec<&str> = found.keys().map(String::as_str).collect();
    paths.sort();
    // job_cache is mounted (by a stopped container) and small; unsized is unknown.
    assert_eq!(
        paths,
        [
            "docker://volume/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "docker://volume/app_data",
            "docker://volume/orphan_pg"
        ]
    );

    let orphan = &found["docker://volume/orphan_pg"];
    assert_eq!(orphan.bytes, 314_572_800);
    assert_eq!(argv(orphan), ["docker", "volume", "rm", "orphan_pg"]);
    assert!(orphan.guards.is_empty());
    assert!(orphan.recovery.cost.contains("data is gone"));
    assert!(
        found["docker://volume/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
            .reason
            .starts_with("anonymous volume")
    );

    // In use: advice only, never a removal command, with the mounting container named.
    let big = &found["docker://volume/app_data"];
    assert_eq!(big.action.kind, ActionKind::Advice);
    assert!(big.action.argv.is_none());
    assert_eq!(big.guards.len(), 1);
    assert_eq!(big.guards[0].name, "container-mount");
    assert_eq!(big.guards[0].status, GuardStatus::Warn);
    assert_eq!(big.guards[0].detail, "mounted by app-1 (running)");
    assert_eq!(big.last_modified.as_deref(), Some("2026-10-31T23:00:00Z"));
}

#[test]
fn usage_totals_match_the_api() {
    let u = docker::usage(&snapshot(true));
    assert!(u.containerd_image_store);
    assert_eq!(u.images.bytes, 9_000_000_000);
    assert_eq!((u.images.count, u.images.active), (6, 1));
    assert_eq!(u.containers.bytes, 502_900_000);
    assert_eq!((u.containers.count, u.containers.active), (3, 1));
    // -1 (unknown) sizes count as 0.
    assert_eq!(
        u.volumes.bytes,
        2_147_483_648 + 52_428_800 + 314_572_800 + 5_242_880
    );
    assert_eq!((u.volumes.count, u.volumes.active), (5, 2));
    assert_eq!(u.build_cache.bytes, 2_100_000_000);
    assert_eq!(
        u.total,
        u.images.bytes + u.containers.bytes + u.volumes.bytes + u.build_cache.bytes
    );
}

fn fs_with_hints(paths: &[(&str, HintKind)]) -> Vec<FsReport> {
    vec![FsReport {
        mount: "/".into(),
        fstype: "ext4".into(),
        source: "/dev/x".into(),
        size: 400 << 30,
        used: 200 << 30,
        avail: 200 << 30,
        scanned: 160 << 30,
        full_coverage: true,
        unaccounted: Some(40 << 30),
        unaccounted_large: true,
        hints: paths
            .iter()
            .map(|(p, k)| Hint {
                kind: *k,
                path: Some((*p).into()),
                detail: "original".into(),
                unreadable_dirs: 1,
                bytes: None,
            })
            .collect(),
        deleted_open: DeletedOpen::default(),
        rerun: None,
    }]
}

#[test]
fn docker_bytes_land_on_the_right_hints() {
    let hints = [
        ("/var/lib/docker", HintKind::Docker),
        ("/var/lib/containerd", HintKind::Containerd),
        ("/opt/containerd", HintKind::Containerd),
    ];
    let u = docker::usage(&snapshot(true));

    let mut fs = fs_with_hints(&hints);
    account::attach_docker_hints(&mut fs, &u);
    let h = &fs[0].hints;
    assert_eq!(h[0].bytes, Some(u.total - u.images.bytes));
    assert!(
        h[0].detail.contains("images are under /var/lib/containerd"),
        "{}",
        h[0].detail
    );
    assert_eq!(h[1].bytes, Some(u.images.bytes));
    assert_eq!(h[2].bytes, None, "containerd plugins dir is not measured");

    // Classic graph driver: everything is under the docker root.
    let classic = docker::usage(&snapshot(false));
    let mut fs = fs_with_hints(&hints);
    account::attach_docker_hints(&mut fs, &classic);
    assert_eq!(fs[0].hints[0].bytes, Some(classic.total));
    assert_eq!(fs[0].hints[1].bytes, None);
}

#[test]
fn one_fetch_shared_by_all_docker_detectors_and_errors_are_reported() {
    // A source with no socket: every Docker detector reports the error.
    let c = ctx_with(Source::none());
    let (found, runs) = run_with(
        &ScanTree::default(),
        &c,
        &dwhy_core::detectors::registry(),
        None,
    );
    assert!(found.is_empty());
    for name in [
        "docker-image",
        "docker-build-cache",
        "docker-container",
        "docker-volume",
    ] {
        let r = runs.iter().find(|r| r.name == name).unwrap();
        assert!(r.ran, "{name}");
        assert_eq!(r.findings, 0);
        assert!(
            r.error.as_deref().unwrap().contains("no Docker socket"),
            "{name}: {r:?}"
        );
    }
    assert!(c.docker.fetched().is_none());

    // With a snapshot, the four detectors together report every Docker finding.
    let c = ctx();
    let only: Vec<String> = ["docker-image", "docker-volume"].map(String::from).to_vec();
    let (found, runs) = run_with(
        &ScanTree::default(),
        &c,
        &dwhy_core::detectors::registry(),
        Some(&only),
    );
    assert_eq!(found.len(), 3 + 3);
    let skipped = runs
        .iter()
        .find(|r| r.name == "docker-build-cache")
        .unwrap();
    assert!(!skipped.ran);
    assert!(skipped.detail.starts_with("not selected"));
    assert!(c.docker.fetched().is_some());
}
