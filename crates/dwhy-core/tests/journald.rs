//! `journald` on temp-dir fixtures: archived journals started more than
//! 14 days ago in a journal directory and its `<machine-id>/`
//! subdirectories. File names follow journald's archive naming, the format
//! systemd's journal-vacuum.c parses to decide what `journalctl
//! --vacuum-time` removes.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::apply::{self, Audit, Env, Policy};
use dwhy_core::detect::{self, DetectContext, Detector, finding_id, rfc3339};
use dwhy_core::detectors::Journald;
use dwhy_core::guard::{Proc, Processes};
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::report::{
    ActionKind, ApplyOutcome, DetectorAvailability, DockerSocket, Finding, PlanScan, Tier,
    ToolStatus,
};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

const MID: &str = "70c2d3c15eb342d091269c9ee491d117";
const SEQNUM_ID: &str = "4f3c1e2d5a6b7c8d9e0f1a2b3c4d5e6f";
const DAY: u64 = 86_400;

/// Head realtime, in microseconds, `days_ago` days ago.
fn head_usec(days_ago: u64) -> u64 {
    (SystemTime::now() - Duration::from_secs(days_ago * DAY))
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

/// An archived journal's name, its first entry `days_ago` days ago:
/// `<prefix>@<seqnum id>-<head seqnum>-<head realtime>.journal`.
fn archived(prefix: &str, seq: u64, days_ago: u64) -> String {
    format!(
        "{prefix}@{SEQNUM_ID}-{seq:016x}-{:016x}.journal",
        head_usec(days_ago)
    )
}

/// An uncleanly closed journal's name, its first entry `days_ago` days ago:
/// `<prefix>@<head realtime>-<random>.journal~`.
fn corrupt(prefix: &str, seq: u64, days_ago: u64) -> String {
    format!("{prefix}@{:016x}-{seq:016x}.journal~", head_usec(days_ago))
}

fn base() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn scan_tree(root: &Path) -> ScanTree {
    let roots = scan::prepare_roots(&[root.to_path_buf()], true).unwrap();
    let opts = ScanOptions {
        min_dir_bytes: 0,
        threads: 2,
        ..ScanOptions::default()
    };
    scan::scan(
        &roots,
        &opts,
        &MountTable::read().unwrap(),
        &Progress::default(),
    )
    .unwrap()
    .tree
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn tool(name: &str, path: Option<&str>, off_path: Option<&str>) -> ToolStatus {
    ToolStatus {
        name: name.into(),
        path: path.map(String::from),
        off_path: off_path.map(String::from),
        enables: vec![],
    }
}

fn ctx(root: bool, tools: Vec<ToolStatus>) -> DetectContext {
    DetectContext {
        uid: if root { 0 } else { 1000 },
        root,
        home: None,
        now: now(),
        tools,
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: dwhy_core::docker::Source::none(),
        cancel: Default::default(),
        scratch_paths: Vec::new(),
        scratch_stale_days: dwhy_core::detectors::SCRATCH_STALE_DAYS,
    }
}

fn root_ctx() -> DetectContext {
    ctx(
        true,
        vec![tool("journalctl", Some("/usr/bin/journalctl"), None)],
    )
}

/// Writes `bytes` of data to `p`, last modified `days_ago` days ago.
fn write(p: &Path, bytes: usize, days_ago: u64) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, vec![7u8; bytes]).unwrap();
    set_age(p, days_ago);
}

fn set_age(p: &Path, days_ago: u64) {
    let t = SystemTime::now() - Duration::from_secs(days_ago * DAY);
    fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

fn allocated(p: &Path) -> u64 {
    fs::symlink_metadata(p).unwrap().blocks() * 512
}

fn mtime(p: &Path) -> i64 {
    fs::symlink_metadata(p).unwrap().mtime()
}

fn journal_root(b: &Path) -> PathBuf {
    b.join("var/log/journal")
}

fn detect(b: &Path, scanned: &Path) -> Vec<Finding> {
    Journald::with_root(journal_root(b))
        .detect(&scan_tree(scanned), &root_ctx())
        .unwrap()
}

const MIB: usize = 1 << 20;

#[test]
fn finds_old_archived_journals_and_nothing_else() {
    let (_t, b) = base();
    let j = journal_root(&b);
    let m = j.join(MID);
    let old = [
        m.join(archived("system", 1, 20)),
        m.join(corrupt("system", 2, 21)),
        m.join(archived("user-1000", 3, 22)),
        // Directly in the journal directory.
        j.join(archived("system", 4, 23)),
    ];
    for (i, p) in old.iter().enumerate() {
        write(p, 2 * MIB, 20 + i as u64);
    }
    // Active journals, however old their mtime, and recent archived ones.
    write(&m.join("system.journal"), 3 * MIB, 30);
    write(&m.join("user-1000.journal"), MIB, 30);
    write(&m.join(archived("system", 9, 2)), 2 * MIB, 2);
    // Lookalikes, including names journalctl's vacuum treats as active.
    for name in [
        "README",
        "foo.log",
        "system.journal.bak",
        "foo@bar.txt",
        "system@x.journal",
        "system@x.journal~",
        "system@0123abcd-0000000000000001-0005f0a1b2c3d4e5.journal",
    ] {
        write(&m.join(name), MIB, 30);
    }
    // Deeper than one subdirectory level.
    write(&m.join("deep").join(archived("system", 5, 30)), 2 * MIB, 30);
    // Subdirectories not named by a 128-bit ID, which journalctl does not
    // vacuum: systemd-journal-remote's default `remote/`, and a short ID.
    write(
        &j.join("remote").join(archived("remote-host", 6, 30)),
        2 * MIB,
        30,
    );
    write(
        &j.join(&MID[..31]).join(archived("system", 7, 30)),
        2 * MIB,
        30,
    );

    let found = detect(&b, &b);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    let path = j.to_str().unwrap();
    assert_eq!(f.detector, "journald");
    assert_eq!(f.path, path);
    assert_eq!(f.id, finding_id("journald", path));
    assert_eq!(f.tier, Tier::Review);
    assert_eq!(f.bytes, old.iter().map(|p| allocated(p)).sum::<u64>());
    // The newest old one is the 20-day-old file.
    assert_eq!(f.last_modified, Some(rfc3339(mtime(&old[0]))));
    assert!(
        f.reason.starts_with(&format!(
            "4 archived journal files started over 14 days ago in {path} ("
        )),
        "{}",
        f.reason
    );
    assert!(
        f.reason
            .contains("active journals and archived ones started in the last 14 days are kept"),
        "{}",
        f.reason
    );
    assert!(f.reason.contains(" total)"), "{}", f.reason);
    assert_eq!(f.action.kind, ActionKind::Command);
    assert_eq!(
        f.action.argv.as_deref().unwrap(),
        ["journalctl", "--directory", path, "--vacuum-time=14d"]
    );
    assert_eq!(
        f.action.text,
        format!("journalctl --directory {path} --vacuum-time=14d")
    );
    assert!(f.recovery.cost.contains("cannot be recovered"));
    assert_eq!(f.recovery.how, None);
}

#[test]
fn action_uses_the_resolved_command_and_quotes_the_path() {
    let (_t, b) = base();
    let b = b.join("my journal");
    let j = journal_root(&b);
    write(&j.join(MID).join(archived("system", 1, 30)), 2 * MIB, 30);
    let c = ctx(
        true,
        vec![tool("journalctl", None, Some("/opt/sd/journalctl"))],
    );
    let found = Journald::with_root(j.clone())
        .detect(&scan_tree(&b), &c)
        .unwrap();
    let path = j.to_str().unwrap();
    let f = &found[0];
    assert_eq!(
        f.action.argv.as_deref().unwrap(),
        [
            "/opt/sd/journalctl",
            "--directory",
            path,
            "--vacuum-time=14d"
        ]
    );
    assert_eq!(
        f.action.text,
        format!("/opt/sd/journalctl --directory '{path}' --vacuum-time=14d")
    );
}

#[test]
fn no_finding_with_only_active_or_recent_journals() {
    let (_t, b) = base();
    let m = journal_root(&b).join(MID);
    write(&m.join("system.journal"), 8 * MIB, 40);
    write(&m.join("user-1000.journal"), 4 * MIB, 40);
    write(&m.join(archived("system", 1, 13)), 8 * MIB, 13);
    write(&m.join(corrupt("system", 2, 1)), 8 * MIB, 1);
    assert!(detect(&b, &b).is_empty());
}

#[test]
fn a_file_started_over_14_days_ago_counts_though_written_since() {
    // journalctl judges an archived file by the head realtime in its name,
    // so it removes this one whole, the last 3 days of entries included.
    let (_t, b) = base();
    let j = journal_root(&b);
    let started = j.join(MID).join(archived("system", 1, 20));
    write(&started, 2 * MIB, 3);
    write(&j.join(MID).join(corrupt("system", 2, 20)), 2 * MIB, 3);
    let found = detect(&b, &b);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert!(
        f.reason.starts_with("2 archived journal files"),
        "{}",
        f.reason
    );
    assert!(f.reason.contains("last written 3 days ago"), "{}", f.reason);
    assert_eq!(f.last_modified, Some(rfc3339(mtime(&started))));
}

#[test]
fn an_old_file_after_a_recent_one_in_seqnum_order_is_kept() {
    // The clock went back between rotations 2 and 3. journalctl 259's
    // vacuum goes through a directory's archived files in seqnum order and
    // stops at the first recent one: run on this layout, it removed only
    // seqnum 1 and kept the 20-day-old seqnum 3.
    let (_t, b) = base();
    let m = journal_root(&b).join(MID);
    let first = m.join(archived("system", 1, 30));
    write(&first, 2 * MIB, 30);
    write(&m.join(archived("system", 2, 2)), 2 * MIB, 2);
    write(&m.join(archived("system", 3, 20)), 2 * MIB, 20);
    write(&m.join("system.journal"), MIB, 0);
    let found = detect(&b, &b);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(f.bytes, allocated(&first));
    assert!(
        f.reason.starts_with("1 archived journal file started"),
        "{}",
        f.reason
    );
}

#[test]
fn no_finding_below_one_mib() {
    let (_t, b) = base();
    let m = journal_root(&b).join(MID);
    write(&m.join("system.journal"), 8 * MIB, 0);
    write(&m.join(archived("system", 1, 30)), 256 << 10, 30);
    write(&m.join(archived("system", 2, 30)), 256 << 10, 30);
    assert!(detect(&b, &b).is_empty());
}

#[test]
fn no_finding_when_the_journal_is_outside_the_scan() {
    let (_t, b) = base();
    write(
        &journal_root(&b).join(MID).join(archived("system", 1, 30)),
        4 * MIB,
        30,
    );
    write(&b.join("home/me/file"), 10, 0);
    assert!(detect(&b, &b.join("home")).is_empty());
    // A journal "directory" that is a file.
    let (_u, c) = base();
    write(&journal_root(&c), 4 * MIB, 30);
    assert!(detect(&c, &c).is_empty());
}

#[test]
fn symlinks_are_not_followed() {
    let (_t, b) = base();
    let j = journal_root(&b);
    let outside = b.join("elsewhere");
    let a = archived("system", 1, 30);
    let bb = archived("system", 2, 30);
    write(&outside.join(MID).join(&a), 4 * MIB, 30);
    write(&outside.join(&bb), 4 * MIB, 30);
    fs::create_dir_all(&j).unwrap();
    // A symlinked machine-id directory and a symlinked archived journal.
    symlink(outside.join(MID), j.join(MID)).unwrap();
    symlink(outside.join(&bb), j.join(&bb)).unwrap();
    assert!(detect(&b, &b).is_empty());
    // The journal directory itself a symlink.
    let (_u, c) = base();
    write(&c.join("real").join(&a), 4 * MIB, 30);
    fs::create_dir_all(c.join("var/log")).unwrap();
    symlink(c.join("real"), journal_root(&c)).unwrap();
    assert!(detect(&c, &c).is_empty());
}

#[test]
fn hardlinks_count_once_and_outside_links_are_not_freed() {
    let (_t, b) = base();
    let j = journal_root(&b);
    let m = j.join(MID);
    let alone = m.join(archived("system", 1, 30));
    let linked_out = m.join(archived("system", 2, 30));
    let linked_in = m.join(archived("system", 3, 30));
    write(&alone, 2 * MIB, 30);
    write(&linked_out, 2 * MIB, 30);
    write(&linked_in, 2 * MIB, 30);
    // "zz-out" sorts after "var", so the scan attributes b to the journal
    // directory and counts it as shared.
    fs::create_dir_all(b.join("zz-out")).unwrap();
    fs::hard_link(&linked_out, b.join("zz-out/b")).unwrap();
    fs::hard_link(&linked_in, j.join(archived("system", 4, 30))).unwrap();

    let tree = scan_tree(&b);
    let node = tree.node(tree.find(&j).unwrap());
    let found = Journald::with_root(j.clone())
        .detect(&tree, &root_ctx())
        .unwrap();
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!(f.bytes, allocated(&alone) + allocated(&linked_in));
    assert!(
        f.bytes <= node.freeable(),
        "{} > {}",
        f.bytes,
        node.freeable()
    );
    assert!(
        f.reason.contains("hardlinked elsewhere and is not freed"),
        "{}",
        f.reason
    );
}

#[test]
fn bytes_never_exceed_what_the_walk_attributes() {
    let (_t, b) = base();
    let j = journal_root(&b);
    let file = j.join(MID).join(archived("system", 1, 30));
    write(&file, 4 * MIB, 30);
    // "aa-out" sorts before "var": the walk attributes the inode outside,
    // so the journal directory frees almost nothing.
    fs::create_dir_all(b.join("aa-out")).unwrap();
    fs::hard_link(&file, b.join("aa-out/b")).unwrap();
    assert!(detect(&b, &b).is_empty());
}

#[test]
fn runs_only_as_root_with_journalctl() {
    let (_t, b) = base();
    let j = journal_root(&b);
    write(&j.join(MID).join(archived("system", 1, 30)), 2 * MIB, 30);
    let tree = scan_tree(&b);
    let built: Vec<Box<dyn Detector>> = vec![Box::new(Journald::with_root(j))];
    let journalctl = || vec![tool("journalctl", Some("/usr/bin/journalctl"), None)];
    let run = |c: &DetectContext| {
        let (found, runs) = detect::run_with(&tree, c, &built, None);
        let r = runs.into_iter().find(|r| r.name == "journald").unwrap();
        (found.len(), r)
    };

    let (n, r) = run(&ctx(false, journalctl()));
    assert_eq!(
        (n, r.ran, r.status),
        (0, false, DetectorAvailability::Unavailable)
    );
    assert!(r.detail.contains("root"), "{}", r.detail);

    let (n, r) = run(&ctx(true, vec![]));
    assert_eq!(
        (n, r.ran, r.status),
        (0, false, DetectorAvailability::Unavailable)
    );
    assert!(r.detail.contains("journalctl"), "{}", r.detail);

    let (n, r) = run(&ctx(true, journalctl()));
    assert_eq!(
        (n, r.ran, r.status),
        (1, true, DetectorAvailability::Available)
    );
    assert_eq!(r.findings, 1);
}

#[test]
fn registered_in_the_registry() {
    assert!(
        dwhy_core::detectors::registry()
            .iter()
            .any(|d| d.name() == "journald")
    );
}

/// A fake `journalctl` that writes its arguments to `out`. Returns `None`
/// when the temp dir cannot run programs (mounted noexec).
fn fake_journalctl(dir: &Path, out: &Path) -> Option<PathBuf> {
    let script = dir.join("journalctl");
    fs::write(
        &script,
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", out.display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    // Another test thread may still hold the script open across a fork.
    for _ in 0..50 {
        match std::process::Command::new(&script).arg("warm-up").status() {
            Ok(_) => return Some(script),
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(e) => panic!("{e}"),
        }
    }
    panic!("the fake journalctl never stopped being busy");
}

#[test]
fn plan_and_apply_ignore_journald_holding_the_active_journal() {
    let (_t, b) = base();
    let (_bin, bin) = base();
    let out = bin.join("argv");
    let Some(script) = fake_journalctl(&bin, &out) else {
        return;
    };
    let j = journal_root(&b);
    let m = j.join(MID);
    let active = m.join("system.journal");
    write(&m.join(archived("system", 1, 30)), 2 * MIB, 30);
    write(&active, MIB, 0);
    let c = ctx(
        true,
        vec![tool("journalctl", None, Some(script.to_str().unwrap()))],
    );
    let det = Journald::with_root(j.clone());
    // systemd-journald: working directory and the active journal open.
    let procs = Processes {
        procs: vec![Proc {
            pid: 321,
            name: "systemd-journal".into(),
            cwd: Some(j.clone()),
            open: vec![active.clone()],
        }],
        unreadable: 0,
    };

    let tree = scan_tree(&b);
    let found = det.detect(&tree, &c).unwrap();
    assert_eq!(found.len(), 1);
    let id = found[0].id.clone();
    let plan = plan::build(
        found,
        &Selection {
            tier: Some(Tier::Review),
            select: vec![],
            free: None,
        },
        &tree,
        &c,
        &procs,
        "host".into(),
        PlanScan {
            roots: vec![b.to_string_lossy().into_owned()],
            one_filesystem: true,
            detectors: None,
        },
    )
    .unwrap();
    assert_eq!(plan.items.len(), 1, "{plan:?}");
    let planned = &plan.items[0];
    assert_eq!(
        planned.finding.tier,
        Tier::Review,
        "{:?}",
        planned.finding.guards
    );
    assert!(
        planned
            .finding
            .guards
            .iter()
            .all(|g| !g.name.starts_with("in-use") && !g.name.starts_with("git")),
        "{:?}",
        planned.finding.guards
    );
    assert_eq!(planned.fingerprint.newest_mtime, None);
    assert!(planned.fingerprint.inode.is_some());

    // journald keeps writing the active journal between plan and apply.
    fs::write(&active, vec![8u8; 2 * MIB]).unwrap();
    fs::File::options()
        .write(true)
        .open(&active)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(5))
        .unwrap();

    let evaluate = |policy: &Policy| {
        let tree = scan_tree(&b);
        let fresh = det.detect(&tree, &c).unwrap();
        apply::evaluate(&plan, fresh, &tree, &c, &procs, policy)
    };
    for policy in [
        Policy::default(),
        Policy {
            max_tier: Tier::Review,
            ..Policy::default()
        },
    ] {
        let checks = evaluate(&policy);
        assert_eq!(
            checks[0].item.outcome,
            ApplyOutcome::Refused,
            "{:?}",
            checks[0].item
        );
    }
    let confirmed = Policy {
        confirm: vec![id.clone()],
        ..Policy::default()
    };
    let mut checks = evaluate(&confirmed);
    assert_eq!(
        checks[0].item.outcome,
        ApplyOutcome::WouldRemove,
        "{}",
        checks[0].item.detail
    );
    assert!(
        checks[0]
            .item
            .guards
            .iter()
            .all(|g| !g.name.starts_with("in-use")),
        "{:?}",
        checks[0].item.guards
    );

    let (_s, state) = base();
    let mut audit = Audit::open(&state.join("audit.jsonl")).unwrap();
    let env = Env {
        host: "host".into(),
        uid: 0,
        now: || "2026-11-24T00:00:00Z".to_string(),
        invocation: None,
    };
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &MountTable::default(),
        &env,
        &mut |_| {},
    );
    assert_eq!(
        checks[0].item.outcome,
        ApplyOutcome::Removed,
        "{}",
        checks[0].item.detail
    );
    assert_eq!(
        fs::read_to_string(&out).unwrap(),
        format!("--directory\n{}\n--vacuum-time=14d\n", j.display())
    );
    // The fake removed nothing; the journal directory is still there.
    assert!(active.exists());
}
