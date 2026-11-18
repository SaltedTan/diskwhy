//! `dwhy explain` on a saved Docker finding: the object is matched by its
//! immutable id (volumes by name and creation time), against the fixed
//! Engine API snapshot in tests/data/docker-system-df.json edited per case.
//! No daemon is contacted.

use dwhy_core::detect::{DetectContext, Detector, finding_id};
use dwhy_core::detectors::{DockerContainer, DockerImage, DockerVolume};
use dwhy_core::docker::{self, Source};
use dwhy_core::explain::{self, DockerExplained, DockerKind, Identity, SavedObject};
use dwhy_core::report::*;
use dwhy_core::snapshot;
use dwhy_core::tree::ScanTree;

/// 2026-11-15T00:26:40Z
const NOW: i64 = 1_794_700_000;
const OLD_JOB: &str = "c2000000000000000000000000000000000000000000000000000000000000b2";

fn daemon() -> docker::Snapshot {
    docker::Snapshot {
        df: docker::parse_system_df(include_bytes!("data/docker-system-df.json")).unwrap(),
        info: Default::default(),
    }
}

fn findings(d: &docker::Snapshot) -> Vec<Finding> {
    let ctx = DetectContext {
        uid: 1000,
        root: false,
        home: None,
        now: NOW,
        tools: vec![],
        docker_socket: DockerSocket {
            path: "/var/run/docker.sock".into(),
            exists: true,
            accessible: true,
        },
        docker: Source::fixed(d.clone()),
    };
    [
        &DockerImage as &dyn Detector,
        &DockerContainer,
        &DockerVolume,
    ]
    .iter()
    .flat_map(|det| det.detect(&ScanTree::default(), &ctx).unwrap())
    .collect()
}

/// A snapshot saved while the daemon listed `d`.
fn saved_snapshot(d: Option<&docker::Snapshot>) -> Snapshot {
    Snapshot {
        schema: SCHEMA.into(),
        tool: Tool::current(),
        host: "testhost".into(),
        uid: 1000,
        created_at: "2026-11-14T00:00:00Z".into(),
        scan: SnapshotScan {
            roots: vec!["/home/u".into()],
            one_filesystem: true,
            min_dir_bytes: 100 << 20,
            totals: Default::default(),
            detectors: vec!["docker-container".into(), "docker-volume".into()],
            skipped_mounts: Vec::new(),
        },
        dirs: Vec::new(),
        fs: Vec::new(),
        docker: d.map(snapshot::docker_part),
        findings: Vec::new(),
    }
}

fn saved_finding(detector: &str, path: &str) -> SnapshotFinding {
    SnapshotFinding {
        id: finding_id(detector, path),
        detector: detector.into(),
        path: path.into(),
        bytes: 1 << 20,
        tier: Tier::Review,
    }
}

/// Explains the finding `detector` reported at `path` while the daemon
/// listed the fixture, now that it lists `now`.
fn explain_now(detector: &str, path: &str, now: &docker::Snapshot) -> DockerExplained {
    let saved = saved_finding(detector, path);
    let object = explain::saved_object(&saved_snapshot(Some(&daemon())), path);
    assert!(object.is_some(), "the snapshot records {path}");
    explain::explain_docker_id(&saved, object.as_ref(), Some(now), findings(now), None)
}

fn container<'a>(d: &'a mut docker::Snapshot, id: &str) -> &'a mut docker::Container {
    d.df.containers
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|c| c.id == id)
        .unwrap()
}

#[test]
fn a_snapshot_records_each_object_by_its_immutable_id() {
    let base = saved_snapshot(Some(&daemon()));
    let got = |path| explain::saved_object(&base, path);
    assert_eq!(
        got("docker://container/old-job"),
        Some(SavedObject {
            kind: DockerKind::Container,
            name: "old-job".into(),
            id: OLD_JOB.into(),
        })
    );
    assert_eq!(
        got("docker://image/ci-runner:local").unwrap().id,
        "sha256:dddd000000000000000000000000000000000000000000000000000000000004"
    );
    // A dangling image is named by its short id.
    assert_eq!(
        got("docker://image/bbbb00000000").unwrap().id,
        "sha256:bbbb000000000000000000000000000000000000000000000000000000000002"
    );
    assert_eq!(
        got("docker://volume/orphan_pg").unwrap().id,
        "2026-10-01T00:00:00Z"
    );
    assert_eq!(got("docker://build-cache"), None);
    assert_eq!(got("docker://container/never-listed"), None);

    // Older snapshots: no Docker figures, or volumes without a creation time.
    assert_eq!(
        explain::saved_object(&saved_snapshot(None), "docker://container/old-job"),
        None
    );
    let mut old = base.clone();
    for v in &mut old.docker.as_mut().unwrap().volumes {
        v.created_at = None;
    }
    assert_eq!(
        explain::saved_object(&old, "docker://volume/orphan_pg"),
        None
    );
}

#[test]
fn a_renamed_container_is_present_under_its_new_name() {
    let mut now = daemon();
    container(&mut now, OLD_JOB).names = vec!["/old-job-kept".into()];
    let out = explain_now("docker-container", "docker://container/old-job", &now);
    assert!(!out.gone);
    assert!(out.growth);
    assert_eq!(out.path, "docker://container/old-job-kept");
    let f = out
        .finding
        .expect("the detector reports it under its new name");
    assert_eq!(f.path, "docker://container/old-job-kept");
    assert_eq!(f.id, finding_id("docker-container", &f.path));
    assert_eq!(out.notes, ["renamed: now old-job-kept"]);

    // Renamed and no longer claimed (it started running): present, no finding.
    container(&mut now, OLD_JOB).state = "running".into();
    let out = explain_now("docker-container", "docker://container/old-job", &now);
    assert!(!out.gone);
    assert!(out.finding.is_none());
    assert_eq!(out.notes[0], "renamed: now old-job-kept");
    assert_eq!(
        out.notes[1],
        "still present at docker://container/old-job-kept, but not detected now"
    );
}

#[test]
fn a_container_recreated_under_its_name_is_replaced_without_growth() {
    let mut now = daemon();
    let new_id = "c9000000000000000000000000000000000000000000000000000000000000f9";
    container(&mut now, OLD_JOB).id = new_id.into();
    let path = "docker://container/old-job";
    let out = explain_now("docker-container", path, &now);
    assert!(!out.gone);
    assert!(!out.growth, "no growth across a replacement");
    assert_eq!(out.path, path);
    // The finding at that name now is the new container's.
    let f = out.finding.expect("the new container is detected");
    assert_eq!(f.action.argv.as_ref().unwrap().last().unwrap(), new_id);
    assert_eq!(
        out.notes,
        [
            "replaced: container old-job is now a different object (was c20000000000, now c90000000000)"
        ]
    );

    // Growth from a snapshot of the old container is refused for a path
    // query too; the same container is fine.
    let base = saved_snapshot(Some(&daemon()));
    assert_eq!(
        explain::growth_across_replacement(&base, path, Some(&now)).as_deref(),
        Some(
            "growth not computed: container old-job was a different object in the snapshot of 2026-11-14T00:00:00Z"
        )
    );
    assert_eq!(
        explain::growth_across_replacement(&base, path, Some(&daemon())),
        None
    );
    assert_eq!(explain::growth_across_replacement(&base, path, None), None);
}

#[test]
fn a_removed_container_is_gone() {
    let mut now = daemon();
    now.df
        .containers
        .as_mut()
        .unwrap()
        .retain(|c| c.id != OLD_JOB);
    let out = explain_now("docker-container", "docker://container/old-job", &now);
    assert!(out.gone);
    assert!(out.finding.is_none());
    assert_eq!(out.notes, ["docker://container/old-job no longer exists"]);
}

#[test]
fn a_volume_recreated_with_a_new_creation_time_is_replaced() {
    let mut now = daemon();
    let path = "docker://volume/orphan_pg";
    for v in now.df.volumes.as_mut().unwrap() {
        if v.name == "orphan_pg" {
            v.created_at = "2026-11-14T12:00:00Z".into();
        }
    }
    let out = explain_now("docker-volume", path, &now);
    assert!(!out.gone);
    assert!(!out.growth);
    assert_eq!(out.finding.unwrap().path, path);
    assert_eq!(
        out.notes,
        [
            "replaced: volume orphan_pg is now a different object (was created 2026-10-01T00:00:00Z, now created 2026-11-14T12:00:00Z)"
        ]
    );

    // The same volume, unchanged: its finding, no notes.
    let out = explain_now("docker-volume", path, &daemon());
    assert!(out.growth && !out.gone);
    assert_eq!(out.finding.unwrap().path, path);
    assert!(out.notes.is_empty(), "{:?}", out.notes);
}

#[test]
fn images_are_matched_by_id_across_tags() {
    let mut now = daemon();
    let images = now.df.images.as_mut().unwrap();
    let ci = images.iter_mut().find(|i| i.id.contains("dddd")).unwrap();
    // ci-runner:local moved to a new build; the old image keeps ci-runner:v2.
    ci.repo_tags = Some(vec!["ci-runner:v2".into()]);
    let mut rebuilt = ci.clone();
    rebuilt.id = "sha256:9999000000000000000000000000000000000000000000000000000000000009".into();
    rebuilt.repo_tags = Some(vec!["ci-runner:local".into()]);
    images.push(rebuilt);
    let out = explain_now("docker-image", "docker://image/ci-runner:local", &now);
    assert!(!out.gone && out.growth);
    assert_eq!(out.path, "docker://image/ci-runner:v2");
    assert_eq!(out.finding.unwrap().path, "docker://image/ci-runner:v2");
    assert_eq!(out.notes, ["renamed: now ci-runner:v2"]);

    // The old image removed: its tag names another image.
    now.df
        .images
        .as_mut()
        .unwrap()
        .retain(|i| !i.id.contains("dddd"));
    let out = explain_now("docker-image", "docker://image/ci-runner:local", &now);
    assert!(!out.gone && !out.growth);
    assert_eq!(
        out.notes,
        [
            "replaced: image ci-runner:local is now a different object (was dddd00000000, now 999900000000)"
        ]
    );
}

#[test]
fn identity_needs_the_relevant_list() {
    let object = explain::saved_object(
        &saved_snapshot(Some(&daemon())),
        "docker://container/old-job",
    )
    .unwrap();
    let mut now = daemon();
    now.df.containers = None;
    assert_eq!(explain::identity(&object, &now), Identity::Unknown);
}

#[test]
fn without_saved_ids_or_a_daemon_it_falls_back_to_the_name() {
    let path = "docker://container/old-job";
    let saved = saved_finding("docker-container", path);
    // A container recreated under the name: without ids it is taken as the
    // saved one, with a note saying identity was not checked.
    let mut now = daemon();
    container(&mut now, OLD_JOB).id = "c9".repeat(32);
    let out = explain::explain_docker_id(&saved, None, Some(&now), findings(&now), None);
    assert!(!out.gone && out.growth);
    assert_eq!(out.finding.unwrap().path, path);
    assert_eq!(
        out.notes,
        ["identity not checked: the snapshot has no Docker ids"]
    );

    // No daemon: could not check, never gone.
    let object = explain::saved_object(&saved_snapshot(Some(&daemon())), path);
    let out = explain::explain_docker_id(
        &saved,
        object.as_ref(),
        None,
        Vec::new(),
        Some("detector docker-container failed: no answer".into()),
    );
    assert!(!out.gone);
    assert!(out.finding.is_none());
    assert_eq!(
        out.notes,
        ["could not check: detector docker-container failed: no answer"]
    );
}
