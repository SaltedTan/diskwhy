//! `trash` on fake trash directories.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dwhy_core::detect::{self, DetectContext, Detector, finding_id};
use dwhy_core::detectors::{TRASH_RECENT_DAYS, Trash, registry};
use dwhy_core::mounts::MountTable;
use dwhy_core::report::{ActionKind, DockerSocket, Finding, GuardStatus, Tier};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

const MB: usize = 1 << 20;
const UID: u32 = 4242;

fn scan_tree(root: &Path) -> ScanTree {
    let roots = scan::prepare_roots(&[root.to_path_buf()], true).unwrap();
    let opts = ScanOptions {
        min_dir_bytes: 0,
        threads: 4,
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

fn ctx(home: &Path) -> DetectContext {
    DetectContext {
        uid: UID,
        root: false,
        home: Some(home.to_path_buf()),
        now: now(),
        tools: vec![],
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: dwhy_core::docker::Source::none(),
    }
}

/// Runs the detector with no mount roots unless given.
fn detect_with(root: &Path, home: &Path, env: &[(&str, &str)], mounts: &[&Path]) -> Vec<Finding> {
    let d = Trash::with_env(env.iter().map(|(k, v)| (k.to_string(), v.to_string())))
        .with_mount_roots(mounts.iter().map(|p| p.to_path_buf()).collect());
    let mut f = d
        .detect(&scan_tree(root), &ctx(home))
        .expect("trash never fails");
    f.sort_by(|a, b| a.path.cmp(&b.path));
    f
}

fn detect(home: &Path) -> Vec<Finding> {
    detect_with(home, home, &[], &[])
}

fn paths(f: &[Finding]) -> Vec<String> {
    let mut p: Vec<String> = f.iter().map(|f| f.path.clone()).collect();
    p.sort();
    p
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn file(path: &Path, size: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![7u8; size]).unwrap();
}

/// `YYYY-MM-DDThh:mm:ss` for `days` days ago, in UTC.
fn date(days: u64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(now() - (days * 86_400) as i64).unwrap();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// A trash directory holding `items`: (name, size, days since trashed).
fn trash(dir: &Path, items: &[(&str, usize, u64)]) -> PathBuf {
    fs::create_dir_all(dir.join("files")).unwrap();
    fs::create_dir_all(dir.join("info")).unwrap();
    for (name, size, days) in items {
        file(&dir.join("files").join(name), *size);
        fs::write(
            dir.join("info").join(format!("{name}.trashinfo")),
            format!(
                "[Trash Info]\nPath=/home/u/{name}\nDeletionDate={}\n",
                date(*days)
            ),
        )
        .unwrap();
    }
    dir.to_path_buf()
}

fn home_trash(home: &Path) -> PathBuf {
    home.join(".local/share/Trash")
}

#[test]
fn old_home_trash_is_review() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let t = trash(
        &home_trash(home),
        &[("a.iso", 2 * MB, 40), ("b.tar", MB, 10)],
    );
    let found = detect(home);
    assert_eq!(paths(&found), [s(&t)]);
    let f = &found[0];
    assert_eq!(f.detector, "trash");
    assert_eq!(f.tier, Tier::Review);
    assert!(f.guards.is_empty());
    assert_eq!(f.id, finding_id("trash", &s(&t)));
    assert!(f.bytes >= 3 * MB as u64, "{}", f.bytes);
    assert_eq!(f.action.kind, ActionKind::RemovePath);
    assert_eq!(f.action.text, format!("remove {}", s(&t)));
    assert!(f.recovery.how.is_none());
    assert!(
        f.recovery.cost.contains("gone for good"),
        "{}",
        f.recovery.cost
    );
    assert!(
        f.reason
            .contains("2 items, trashed between 40 days and 10 days ago"),
        "{}",
        f.reason
    );
}

#[test]
fn recent_item_blocks_the_whole_trash() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    trash(
        &home_trash(home),
        &[
            ("old", 2 * MB, 90),
            ("new", 10, TRASH_RECENT_DAYS as u64 - 2),
        ],
    );
    let found = detect(home);
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!(f.tier, Tier::Blocked);
    assert_eq!(f.guards.len(), 1);
    assert_eq!(f.guards[0].name, "recent-delete");
    assert_eq!(f.guards[0].status, GuardStatus::Block);
    assert!(
        f.guards[0].detail.contains("5 days ago"),
        "{}",
        f.guards[0].detail
    );
    assert!(f.reason.contains("not offered yet"), "{}", f.reason);
}

#[test]
fn gate_boundary() {
    for (days, tier) in [
        (TRASH_RECENT_DAYS as u64 + 1, Tier::Review),
        (TRASH_RECENT_DAYS as u64 - 1, Tier::Blocked),
    ] {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        trash(&home_trash(home), &[("x", 2 * MB, days)]);
        assert_eq!(detect(home)[0].tier, tier, "{days} days");
    }
}

#[test]
fn xdg_data_home_moves_the_home_trash() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let data = home.join("data");
    let t = trash(&data.join("Trash"), &[("x", 2 * MB, 30)]);
    trash(&home_trash(home), &[("y", 2 * MB, 30)]);
    let found = detect_with(home, home, &[("XDG_DATA_HOME", &s(&data))], &[]);
    assert_eq!(paths(&found), [s(&t)]);
}

#[test]
fn mount_root_trashes() {
    let base = tempfile::tempdir().unwrap();
    let base = base.path();
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    let disk = base.join("disk");
    let own = trash(&disk.join(format!(".Trash-{UID}")), &[("x", 2 * MB, 30)]);
    // Another user's trash is not ours to report.
    trash(&disk.join(".Trash-1001"), &[("x", 2 * MB, 30)]);
    // Shared .Trash with the sticky bit: its <uid> subdirectory.
    let shared = disk.join(".Trash");
    let sub = trash(&shared.join(UID.to_string()), &[("y", 2 * MB, 30)]);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();

    // Without the sticky bit, .Trash is ignored; so is a symlinked one.
    let disk2 = base.join("disk2");
    trash(
        &disk2.join(".Trash").join(UID.to_string()),
        &[("z", 2 * MB, 30)],
    );
    let disk3 = base.join("disk3");
    let real = base.join("real-trash");
    trash(&real.join(UID.to_string()), &[("z", 2 * MB, 30)]);
    fs::set_permissions(&real, fs::Permissions::from_mode(0o1777)).unwrap();
    fs::create_dir_all(&disk3).unwrap();
    symlink(&real, disk3.join(".Trash")).unwrap();

    let found = detect_with(base, &home, &[], &[&disk, &disk2, &disk3]);
    assert_eq!(paths(&found), [s(&own), s(&sub)]);
}

#[test]
fn missing_or_bad_dates_fall_back_to_the_record_mtime() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let t = home_trash(home);
    file(&t.join("files/x"), 2 * MB);
    fs::create_dir_all(t.join("info")).unwrap();
    let info = t.join("info/x.trashinfo");
    fs::write(&info, "[Trash Info]\nPath=/x\nDeletionDate=garbage\n").unwrap();
    // Written just now: recent.
    assert_eq!(detect(home)[0].tier, Tier::Blocked);
    // Written long ago: old.
    let old = SystemTime::now() - Duration::from_secs(60 * 86_400);
    fs::File::open(&info).unwrap().set_modified(old).unwrap();
    assert_eq!(detect(home)[0].tier, Tier::Review);
}

#[test]
fn trash_without_records_is_review() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let t = home_trash(home);
    file(&t.join("files/orphan"), 2 * MB);
    let found = detect(home);
    assert_eq!(paths(&found), [s(&t)]);
    assert_eq!(found[0].tier, Tier::Review);
    assert!(
        found[0].reason.contains("no trash records"),
        "{}",
        found[0].reason
    );
}

#[test]
fn a_symlinked_info_dir_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let elsewhere = trash(&home.join("elsewhere"), &[("x", 10, 30), ("y", 10, 40)]);
    let t = home_trash(home);
    file(&t.join("files/z"), 2 * MB);
    symlink(elsewhere.join("info"), t.join("info")).unwrap();
    let found = detect(home);
    assert_eq!(paths(&found), [s(&t)]);
    assert_eq!(found[0].tier, Tier::Review);
    assert!(
        found[0].reason.contains("no trash records"),
        "{}",
        found[0].reason
    );
}

#[test]
fn small_or_unscanned_trash_is_ignored() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    trash(&home_trash(home), &[("x", 1000, 30)]);
    assert_eq!(paths(&detect(home)), Vec::<String>::new());

    let home2 = tempfile::tempdir().unwrap();
    let home2 = home2.path();
    trash(&home_trash(home2), &[("x", 2 * MB, 30)]);
    let other = home2.join("code");
    file(&other.join("f"), 10);
    assert_eq!(
        paths(&detect_with(&other, home2, &[], &[])),
        Vec::<String>::new()
    );
}

#[test]
fn a_symlinked_home_trash_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let real = trash(&home.join("elsewhere"), &[("x", 2 * MB, 30)]);
    fs::create_dir_all(home.join(".local/share")).unwrap();
    symlink(&real, home_trash(home)).unwrap();
    assert_eq!(paths(&detect(home)), Vec::<String>::new());
}

#[test]
fn paths_are_shell_quoted() {
    let base = tempfile::tempdir().unwrap();
    let home = base.path().join("it's me");
    let t = trash(&home_trash(&home), &[("x", 2 * MB, 30)]);
    let found = detect(&home);
    assert_eq!(
        found[0].action.text,
        format!("remove '{}'", s(&t).replace('\'', r"'\''"))
    );
}

#[test]
fn run_with_via_the_registry() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    trash(&home_trash(home), &[("x", 2 * MB, 30)]);
    let tree = scan_tree(home);
    let only = vec!["trash".to_string()];
    let (found, runs) = detect::run_with(&tree, &ctx(home), &registry(), Some(&only));
    let run = runs.iter().find(|r| r.name == "trash").unwrap();
    assert!(run.ran);
    assert!(run.error.is_none());
    // XDG_DATA_HOME of the test process may move the home trash; when it
    // does not, the fixture is found.
    if std::env::var_os("XDG_DATA_HOME").is_none() {
        assert_eq!(paths(&found), [s(&home_trash(home))]);
    }
}
