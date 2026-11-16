//! Growth: comparing two snapshots (`dwhy diff`) and growth on findings.
//! Snapshots are built by hand; no scan or daemon is involved.

use std::collections::HashMap;

use dwhy_core::growth::{self, per_day};
use dwhy_core::report::{
    Action, ActionKind, Change, ChangeKind, DockerUsage, Finding, Recovery, SCHEMA, Snapshot,
    SnapshotContainer, SnapshotDir, SnapshotDocker, SnapshotFinding, SnapshotFs, SnapshotImage,
    SnapshotScan, SnapshotVolume, Tier, Tool, UsageLine,
};

const M: u64 = 1 << 20;
const G: u64 = 1 << 30;
const TWO_DAYS: i64 = 2 * 86_400;

fn snap(created_at: &str, roots: &[&str], detectors: &[&str]) -> Snapshot {
    Snapshot {
        schema: SCHEMA.into(),
        tool: Tool::current(),
        host: "testhost".into(),
        uid: 1000,
        created_at: created_at.into(),
        scan: SnapshotScan {
            roots: roots.iter().map(|r| r.to_string()).collect(),
            one_filesystem: true,
            min_dir_bytes: 100 * M,
            totals: Default::default(),
            detectors: detectors.iter().map(|d| d.to_string()).collect(),
            skipped_mounts: Vec::new(),
        },
        dirs: Vec::new(),
        fs: Vec::new(),
        docker: None,
        findings: Vec::new(),
    }
}

fn dirs(list: &[(&str, u64)]) -> Vec<SnapshotDir> {
    list.iter()
        .map(|&(path, allocated)| SnapshotDir {
            path: path.into(),
            allocated,
            apparent: allocated,
            files: 1,
        })
        .collect()
}

fn fs_used(used: u64) -> Vec<SnapshotFs> {
    vec![SnapshotFs {
        mount: "/".into(),
        fstype: "ext4".into(),
        size: 100 * G,
        used,
        avail: 100 * G - used,
        scanned: used,
    }]
}

fn sfinding(id: &str, detector: &str, path: &str, bytes: u64) -> SnapshotFinding {
    SnapshotFinding {
        id: id.into(),
        detector: detector.into(),
        path: path.into(),
        bytes,
        tier: Tier::Rebuildable,
    }
}

fn docker(
    images: &[(&str, &[&str], u64)],
    containers: &[(&str, &str, Option<u64>)],
    volumes: &[(&str, Option<u64>)],
    build_cache: u64,
) -> SnapshotDocker {
    let line = |bytes| UsageLine {
        count: 1,
        active: 0,
        bytes,
    };
    SnapshotDocker {
        usage: DockerUsage {
            root_dir: "/var/lib/docker".into(),
            containerd_image_store: false,
            images: line(0),
            containers: line(0),
            volumes: line(0),
            build_cache: line(build_cache),
            total: 0,
        },
        images: images
            .iter()
            .map(|&(id, tags, bytes)| SnapshotImage {
                id: id.into(),
                tags: tags.iter().map(|t| t.to_string()).collect(),
                bytes,
            })
            .collect(),
        containers: containers
            .iter()
            .map(|&(id, name, bytes)| SnapshotContainer {
                id: id.into(),
                name: name.into(),
                image: "img".into(),
                state: "running".into(),
                bytes,
            })
            .collect(),
        volumes: volumes
            .iter()
            .map(|&(name, bytes)| SnapshotVolume {
                name: name.into(),
                bytes,
            })
            .collect(),
    }
}

/// (name, before, after, change, at_least) of one change.
type Row<'a> = (&'a str, Option<u64>, Option<u64>, i64, bool);

/// Each change as a [`Row`], in order.
fn rows(v: &[Change]) -> Vec<Row<'_>> {
    v.iter()
        .map(|c| (c.name.as_str(), c.before, c.after, c.change, c.at_least))
        .collect()
}

fn no_tree(_: &str) -> Option<u64> {
    None
}

#[test]
fn diff_ranks_changes_by_rate_and_attributes_dirs_to_the_deepest() {
    let mut old = snap(
        "2026-11-14T00:00:00Z",
        &["/h"],
        &["cargo-target", "docker-volume", "user-cache"],
    );
    old.dirs = dirs(&[
        ("/h", 1000 * M),
        ("/h/a", 500 * M),
        ("/h/a/pg", 400 * M),
        ("/h/b", 300 * M),
        ("/h/gone", 200 * M),
        ("/h/shrink", 150 * M),
    ]);
    old.fs = fs_used(10 * G);
    old.docker = Some(docker(
        &[
            ("sha256:aaaa", &["pg:16"], 400 * M),
            ("sha256:bbbb", &["old:1"], 100 * M),
        ],
        &[("c1", "db", Some(4096)), ("c2", "unsized", None)],
        &[("pgdata", Some(G)), ("blind", None)],
        500 * M,
    ));
    old.findings = vec![
        sfinding("f_target", "cargo-target", "/h/a/target", 300 * M),
        sfinding("f_vol", "docker-volume", "docker://volume/pgdata", G),
        sfinding("f_cache", "user-cache", "/h/.cache", 200 * M),
        sfinding("f_oldtarget", "cargo-target", "/h/old/target", 100 * M),
    ];

    let mut new = snap(
        "2026-11-16T00:00:00Z",
        &["/h"],
        &["cargo-target", "docker-volume", "go-build"],
    );
    // /h/shrink fell below the threshold and is not recorded; /h/gone is gone.
    new.dirs = dirs(&[
        ("/h", 1360 * M),
        ("/h/a", 900 * M),
        ("/h/a/pg", 800 * M),
        ("/h/b", 310 * M),
        ("/h/new", 250 * M),
    ]);
    new.fs = fs_used(10 * G + 512 * M);
    new.docker = Some(docker(
        &[
            ("sha256:aaaa", &["pg:16"], 400 * M),
            ("sha256:cccc0123456789abcdef", &[], 200 * M),
        ],
        &[("c1", "db", Some(60 * M)), ("c2", "unsized", Some(90 * M))],
        &[
            ("pgdata", Some(3 * G)),
            ("blind", Some(70 * M)),
            ("small", Some(20 * M)),
        ],
        500 * M,
    ));
    new.findings = vec![
        sfinding("f_target", "cargo-target", "/h/a/target", 500 * M),
        sfinding("f_vol", "docker-volume", "docker://volume/pgdata", 3 * G),
        sfinding("f_newtarget", "cargo-target", "/h/new/target", 120 * M),
        sfinding("f_go", "go-build", "/h/.cache/go-build", 900 * M),
    ];
    let now: HashMap<&str, u64> = [("/h/shrink", 50 * M)].into();
    let size_now = |p: &str| now.get(p).copied();

    let d = growth::diff(
        &old,
        Some("old-id".into()),
        "/s/old-id.json.gz".into(),
        &new,
        &size_now,
        50 * M,
    );
    assert_eq!(d.schema, SCHEMA);
    assert_eq!(d.elapsed_secs, TWO_DAYS);
    assert_eq!(d.since.id.as_deref(), Some("old-id"));
    assert_eq!(d.since.created_at, "2026-11-14T00:00:00Z");
    assert_eq!(d.since.min_dir_bytes, 100 * M);
    assert_eq!(d.generated_at, "2026-11-16T00:00:00Z");

    assert_eq!(
        rows(&d.fs),
        [(
            "/",
            Some(10 * G),
            Some(10 * G + 512 * M),
            512 * M as i64,
            false
        )]
    );
    assert_eq!(d.fs[0].kind, ChangeKind::Fs);
    assert_eq!(d.fs[0].bytes_per_day, 256 * M as i64);

    // /h and /h/a are left out: /h/a/pg holds most of their growth.
    // /h/b changed by less than --min-change. /h/new was under the
    // snapshot's 100M threshold, so its growth is a lower bound.
    assert_eq!(
        rows(&d.dirs),
        [
            (
                "/h/a/pg",
                Some(400 * M),
                Some(800 * M),
                400 * M as i64,
                false
            ),
            ("/h/new", None, Some(250 * M), 150 * M as i64, true),
            (
                "/h/shrink",
                Some(150 * M),
                Some(50 * M),
                -(100 * M as i64),
                false
            ),
            ("/h/gone", Some(200 * M), None, -(200 * M as i64), false),
        ]
    );
    assert!(d.dirs.iter().all(|c| c.kind == ChangeKind::Dir));
    assert_eq!(d.dirs[0].bytes_per_day, 200 * M as i64);
    for c in d
        .dirs
        .iter()
        .chain(&d.docker)
        .chain(&d.findings)
        .chain(&d.fs)
    {
        assert_eq!(c.bytes_per_day, per_day(c.change, TWO_DAYS), "{}", c.name);
    }

    // The unchanged image and build cache, the small volume, and objects
    // whose size was not computed on one side are left out.
    assert!(d.docker_compared);
    assert_eq!(
        rows(&d.docker),
        [
            ("pgdata", Some(G), Some(3 * G), 2 * G as i64, false),
            ("cccc01234567", None, Some(200 * M), 200 * M as i64, false),
            (
                "db",
                Some(4096),
                Some(60 * M),
                (60 * M - 4096) as i64,
                false
            ),
            ("old:1", Some(100 * M), None, -(100 * M as i64), false),
        ]
    );
    let kinds: Vec<ChangeKind> = d.docker.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        [
            ChangeKind::Volume,
            ChangeKind::Image,
            ChangeKind::Container,
            ChangeKind::Image
        ]
    );
    assert_eq!(
        d.docker[1].id.as_deref(),
        Some("sha256:cccc0123456789abcdef")
    );
    assert_eq!(d.docker[2].id.as_deref(), Some("c1"));
    assert_eq!(d.docker[0].id, None);

    // user-cache did not run now and go-build did not run then: their
    // findings are not compared.
    assert_eq!(
        rows(&d.findings),
        [
            (
                "docker://volume/pgdata",
                Some(G),
                Some(3 * G),
                2 * G as i64,
                false
            ),
            (
                "/h/a/target",
                Some(300 * M),
                Some(500 * M),
                200 * M as i64,
                false
            ),
            ("/h/new/target", None, Some(120 * M), 120 * M as i64, false),
            (
                "/h/old/target",
                Some(100 * M),
                None,
                -(100 * M as i64),
                false
            ),
        ]
    );
    assert_eq!(d.findings[1].id.as_deref(), Some("f_target"));
    assert_eq!(d.findings[1].detector.as_deref(), Some("cargo-target"));
    assert_eq!(
        d.notes,
        ["findings not compared (detector ran on one side only): go-build, user-cache"]
    );
}

#[test]
fn only_paths_inside_both_scans_are_compared() {
    let mut old = snap("2026-11-15T00:00:00Z", &["/h"], &["cargo-target"]);
    old.dirs = dirs(&[("/h", 1000 * M), ("/h/a", 500 * M), ("/h/b", 300 * M)]);
    old.findings = vec![
        sfinding("f_a", "cargo-target", "/h/a/target", 200 * M),
        sfinding("f_b", "cargo-target", "/h/b/target", 200 * M),
    ];
    let mut new = snap("2026-11-16T00:00:00Z", &["/h/a", "/srv"], &["cargo-target"]);
    new.dirs = dirs(&[("/h/a", 700 * M), ("/srv", 400 * M)]);
    new.findings = vec![sfinding("f_a", "cargo-target", "/h/a/target", 300 * M)];

    let d = growth::diff(&old, None, "f".into(), &new, &no_tree, 10 * M);
    assert_eq!(
        rows(&d.dirs),
        [("/h/a", Some(500 * M), Some(700 * M), 200 * M as i64, false)]
    );
    assert_eq!(
        rows(&d.findings),
        [(
            "/h/a/target",
            Some(200 * M),
            Some(300 * M),
            100 * M as i64,
            false
        )]
    );
    assert_eq!(d.since.roots, ["/h"]);
    assert_eq!(d.roots, ["/h/a", "/srv"]);
}

const HOME_NOTE: &str = "not compared, because one side did not enter these mount points: /home";

/// The notes about mount points (Docker notes left out).
fn mount_notes(d: &dwhy_core::report::DiffReport) -> Vec<&str> {
    d.notes
        .iter()
        .map(String::as_str)
        .filter(|n| !n.starts_with("Docker"))
        .collect()
}

fn skipping(mut s: Snapshot, mounts: &[&str]) -> Snapshot {
    s.scan.skipped_mounts = mounts.iter().map(|m| m.to_string()).collect();
    s
}

#[test]
fn a_mount_the_snapshot_did_not_enter_is_not_reported_as_new() {
    // `dwhy scan / --snapshot` with -x never enters /home, its own
    // filesystem; `dwhy diff ~ --since <that id>` then rescans ~.
    let mut old = skipping(
        snap("2026-11-15T00:00:00Z", &["/"], &["cargo-target"]),
        &["/home", "/proc"],
    );
    old.dirs = dirs(&[("/", 50 * G), ("/usr", 10 * G)]);
    let mut new = snap("2026-11-16T00:00:00Z", &["/home/u"], &["cargo-target"]);
    new.dirs = dirs(&[("/home/u", 5 * G), ("/home/u/.cache", 2 * G)]);
    new.findings = vec![sfinding("f_t", "cargo-target", "/home/u/p/target", G)];

    let d = growth::diff(&old, None, "f".into(), &new, &no_tree, 10 * M);
    assert_eq!(rows(&d.dirs), []);
    assert_eq!(rows(&d.findings), []);
    assert_eq!(mount_notes(&d), [HOME_NOTE]);
}

#[test]
fn a_mount_the_rescan_did_not_enter_is_not_reported_as_gone() {
    // A snapshot of ~, then `dwhy diff / --since <id>` with -x: the
    // rescan stops at /home and finds nothing below it.
    let mut old = snap("2026-11-15T00:00:00Z", &["/home/u"], &["cargo-target"]);
    old.dirs = dirs(&[("/home/u", 5 * G), ("/home/u/.cache", 2 * G)]);
    old.findings = vec![sfinding("f_t", "cargo-target", "/home/u/p/target", G)];
    let mut new = skipping(
        snap("2026-11-16T00:00:00Z", &["/"], &["cargo-target"]),
        &["/home"],
    );
    new.dirs = dirs(&[("/", 50 * G)]);

    let d = growth::diff(&old, None, "f".into(), &new, &no_tree, 10 * M);
    assert_eq!(rows(&d.dirs), []);
    assert_eq!(rows(&d.findings), []);
    assert_eq!(mount_notes(&d), [HOME_NOTE]);
}

#[test]
fn a_mount_entered_on_one_side_only_leaves_out_the_dirs_above_it() {
    // Same roots, but the snapshot was -x and the rescan crossed into
    // /home. Both left out /proc, which changes nothing.
    let mut old = skipping(
        snap("2026-11-15T00:00:00Z", &["/"], &["cargo-target"]),
        &["/home", "/proc"],
    );
    old.dirs = dirs(&[("/", 50 * G), ("/usr", 10 * G)]);
    old.findings = vec![sfinding("f_u", "cargo-target", "/usr/src/x/target", G)];
    let mut new = skipping(
        snap("2026-11-16T00:00:00Z", &["/"], &["cargo-target"]),
        &["/proc"],
    );
    new.scan.one_filesystem = false;
    new.dirs = dirs(&[("/", 82 * G), ("/usr", 12 * G), ("/home", 30 * G)]);
    new.findings = vec![
        sfinding("f_u", "cargo-target", "/usr/src/x/target", 2 * G),
        sfinding("f_t", "cargo-target", "/home/u/p/target", G),
    ];

    let d = growth::diff(&old, None, "f".into(), &new, &no_tree, 10 * M);
    assert_eq!(
        rows(&d.dirs),
        [("/usr", Some(10 * G), Some(12 * G), 2 * G as i64, false)]
    );
    assert_eq!(
        rows(&d.findings),
        [("/usr/src/x/target", Some(G), Some(2 * G), G as i64, false)]
    );
    assert_eq!(mount_notes(&d), [HOME_NOTE]);

    // With the same mounts skipped on both sides, / is compared.
    let mut new = skipping(new, &["/home", "/proc"]);
    new.scan.one_filesystem = true;
    new.findings.pop();
    new.dirs = dirs(&[("/", 54 * G), ("/usr", 12 * G)]);
    let d = growth::diff(&old, None, "f".into(), &new, &no_tree, 10 * M);
    assert_eq!(
        rows(&d.dirs),
        [
            ("/", Some(50 * G), Some(54 * G), 4 * G as i64, false),
            ("/usr", Some(10 * G), Some(12 * G), 2 * G as i64, false)
        ]
    );
    assert_eq!(mount_notes(&d), [] as [&str; 0]);
}

#[test]
fn with_the_same_x_a_mount_skipped_on_one_side_leaves_the_dirs_above_it_compared() {
    // Both -x on /. A snap refresh mounted /snap/x/1 between the scans, and
    // the snapshot was saved before skipped mounts were recorded: neither
    // side's totals include what any of those mounts hold.
    let mut old = snap("2026-11-15T00:00:00Z", &["/"], &["cargo-target"]);
    old.dirs = dirs(&[("/", 50 * G), ("/snap", 4 * G), ("/usr", 10 * G)]);
    let mut new = skipping(
        snap("2026-11-16T00:00:00Z", &["/"], &["cargo-target"]),
        &["/home", "/proc", "/snap/x/1"],
    );
    new.dirs = dirs(&[("/", 56 * G), ("/snap", 7 * G), ("/usr", 13 * G)]);

    let d = growth::diff(&old, None, "f".into(), &new, &no_tree, 10 * M);
    assert_eq!(
        rows(&d.dirs),
        [
            ("/", Some(50 * G), Some(56 * G), 6 * G as i64, false),
            ("/snap", Some(4 * G), Some(7 * G), 3 * G as i64, false),
            ("/usr", Some(10 * G), Some(13 * G), 3 * G as i64, false)
        ]
    );
    assert_eq!(mount_notes(&d), [] as [&str; 0]);
}

#[test]
fn a_root_inside_a_skipped_mount_is_walked() {
    // Roots / and /home with -x: the walk of / skips /home, which is
    // walked as a root of its own.
    let mut old = skipping(
        snap("2026-11-15T00:00:00Z", &["/", "/home"], &["cargo-target"]),
        &["/home"],
    );
    old.dirs = dirs(&[("/home/u", 5 * G)]);
    let mut new = old.clone();
    new.created_at = "2026-11-16T00:00:00Z".into();
    new.dirs = dirs(&[("/home/u", 6 * G)]);
    let d = growth::diff(&old, None, "f".into(), &new, &no_tree, 10 * M);
    assert_eq!(
        rows(&d.dirs),
        [("/home/u", Some(5 * G), Some(6 * G), G as i64, false)]
    );
    assert_eq!(mount_notes(&d), [] as [&str; 0]);
}

#[test]
fn docker_is_compared_only_when_both_sides_have_it() {
    let old = snap("2026-11-15T00:00:00Z", &["/h"], &[]);
    let mut new = snap("2026-11-16T00:00:00Z", &["/h"], &[]);
    new.docker = Some(docker(&[("sha256:aa", &["x:1"], G)], &[], &[], 0));
    let d = growth::diff(&old, None, "f".into(), &new, &no_tree, 0);
    assert!(!d.docker_compared);
    assert!(d.docker.is_empty());
    assert_eq!(
        d.notes,
        ["Docker not compared: the snapshot has no Docker figures"]
    );
    let d = growth::diff(&new, None, "f".into(), &old, &no_tree, 0);
    assert!(!d.docker_compared);
    assert!(d.notes[0].starts_with("Docker not compared: no Docker figures now"));
}

fn finding(id: &str, bytes: u64) -> Finding {
    Finding {
        id: id.into(),
        detector: "cargo-target".into(),
        probe: None,
        path: format!("/h/{id}"),
        bytes,
        nested_bytes: None,
        last_modified: None,
        growth: None,
        tier: Tier::Rebuildable,
        reason: "r".into(),
        guards: Vec::new(),
        action: Action {
            kind: ActionKind::RemovePath,
            text: "t".into(),
            argv: None,
        },
        recovery: Recovery {
            cost: "c".into(),
            how: None,
        },
    }
}

#[test]
fn findings_get_growth_from_an_older_snapshot_by_id() {
    let mut old = snap("2026-11-15T12:00:00Z", &["/h"], &["cargo-target"]);
    old.findings = vec![
        sfinding("f_grew", "cargo-target", "/h/f_grew", 100 * M),
        sfinding("f_shrank", "cargo-target", "/h/f_shrank", 300 * M),
    ];
    let mut findings = vec![
        finding("f_grew", 400 * M),
        finding("f_shrank", 200 * M),
        finding("f_new", 50 * M),
    ];
    growth::fill_growth(&mut findings, &old, "2026-11-16T00:00:00Z");
    let g: Vec<Option<(i64, &str)>> = findings
        .iter()
        .map(|f| {
            f.growth
                .as_ref()
                .map(|g| (g.bytes_per_day, g.since.as_str()))
        })
        .collect();
    assert_eq!(
        g,
        [
            Some((600 * M as i64, "2026-11-15T12:00:00Z")),
            Some((-(200 * M as i64), "2026-11-15T12:00:00Z")),
            None,
        ]
    );

    // A snapshot that is not older gives no rate.
    let mut findings = vec![finding("f_grew", 400 * M)];
    growth::fill_growth(&mut findings, &old, "2026-11-15T12:00:00Z");
    assert_eq!(findings[0].growth, None);
}
