//! The TUI as a state machine on temp-dir fixtures, rendered with ratatui's
//! TestBackend. No terminal and no pty.

use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dwhy_core::guard::{Proc, Processes};
use dwhy_core::plan;
use dwhy_core::probes::postgres_wal;
use dwhy_core::report::{
    Action, ActionKind, ApplyItem, ApplyOutcome, ApplyReport, ArchiveTarget, EvidenceSource,
    Finding, Fingerprint, FsReport, Growth, GuardResult, GuardStatus, Plan, PlanItem, PlanScan,
    PlanSelection, PostgresWal, Recovery, Tier, Tool,
};
use dwhy_core::scan::Progress;
use dwhy_core::{detect, growth, snapshot, system};
use dwhy_tui::app::{App, DEFAULT_PLAN_FILE, PlanState, RowKind, SizeMode, State, View};
use dwhy_tui::job::{self, Applied, ApplyFailed, BuiltPlan, Options, PermissionMark, Scanned};
use dwhy_tui::ui;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

const MIB: usize = 1 << 20;
/// What the fixture root is replaced with on screen (same length, so
/// alignment is unchanged).
const ROOT_PLACEHOLDER: &str = "/tmp/dwhyXXXXXX";

/// A fixture under /tmp with a fixed-length name (`/tmp/dwhy` and six random
/// characters), so screens differ only in those characters.
struct Fixture {
    // Dropped first: restores permissions so the temp dir can be removed.
    _locked: Option<Unlock>,
    dir: tempfile::TempDir,
}

struct Unlock(PathBuf);

impl Drop for Unlock {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
    }
}

impl Fixture {
    fn root(&self) -> PathBuf {
        fs::canonicalize(self.dir.path()).unwrap()
    }
}

fn fixture(locked: bool) -> Fixture {
    let dir = tempfile::Builder::new()
        .prefix("dwhy")
        .rand_bytes(6)
        .tempdir_in("/tmp")
        .unwrap();
    let r = dir.path();
    fs::create_dir_all(r.join("big")).unwrap();
    fs::create_dir_all(r.join("mid/sub")).unwrap();
    fs::write(r.join("big/blob"), vec![1u8; 5 * MIB]).unwrap();
    fs::write(r.join("mid/data"), vec![2u8; 2 * MIB]).unwrap();
    fs::write(r.join("mid/sub/part"), vec![3u8; 700 << 10]).unwrap();
    fs::write(r.join("loose"), vec![4u8; 3 * MIB / 2]).unwrap();
    let locked = locked.then(|| {
        let p = r.join("mid/locked");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("secret"), b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        Unlock(p)
    });
    Fixture {
        _locked: locked,
        dir,
    }
}

fn is_root() -> bool {
    dwhy_core::system::euid() == 0
}

fn opts(paths: Vec<PathBuf>) -> Options {
    Options {
        paths,
        cross_filesystems: false,
        // Never reach the machine's Docker daemon or caches.
        detectors: Some(vec!["cargo-target".into()]),
        threads: 2,
        // Never read the machine's snapshots.
        snapshot_dir: None,
        dry_run: false,
        // Never write the machine's audit log.
        audit_log: None,
        context: None,
    }
}

fn scan(paths: &[&Path]) -> Scanned {
    let o = opts(paths.iter().map(|p| p.to_path_buf()).collect());
    job::scan(&o, &Progress::default(), &mut |_| {}).unwrap()
}

/// Replaces the machine's `df` figures with fixed ones: a whole-filesystem
/// line with an unaccounted gap, and (with `partial`) a line for a
/// filesystem only partly scanned.
fn pin_fs(data: &mut Scanned, partial: bool) {
    let mut whole: FsReport = data.report.fs[0].clone();
    whole.mount = "/".into();
    whole.fstype = "ext4".into();
    whole.source = "/dev/nvme0n1p2".into();
    whole.size = 400 << 30;
    whole.used = 120 << 30;
    whole.avail = 280 << 30;
    whole.scanned = 117 << 30;
    whole.full_coverage = true;
    whole.unaccounted = Some(3 << 30);
    whole.unaccounted_large = true;
    let mut fs = vec![whole.clone()];
    if partial {
        let mut part = whole;
        part.mount = "/home".into();
        part.fstype = "btrfs".into();
        part.scanned = 9 << 20;
        part.full_coverage = false;
        part.unaccounted = None;
        part.unaccounted_large = false;
        fs.push(part);
    }
    data.report.fs = fs;
}

fn app_with(data: Scanned) -> App {
    let mut app = App::new(Vec::new(), Arc::new(Progress::default()));
    app.finish(data);
    app
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn press(app: &mut App, codes: &[KeyCode]) {
    for &c in codes {
        assert!(!app.on_key(key(c)), "{c:?} must not quit");
    }
}

fn render(app: &mut App, w: u16, h: u16, root: Option<&Path>) -> String {
    render_at(app, w, h, root, job::now())
}

fn render_at(app: &mut App, w: u16, h: u16, root: Option<&Path>, now: i64) -> String {
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| ui::draw_at(f, app, now)).unwrap();
    let s = term.backend().to_string();
    match root {
        Some(r) => {
            let r = r.to_str().unwrap();
            assert_eq!(r.len(), ROOT_PLACEHOLDER.len(), "fixture name length");
            s.replace(r, ROOT_PLACEHOLDER)
        }
        None => s,
    }
}

/// Labels of the rows shown, in order.
fn labels(app: &App) -> Vec<String> {
    let b = app.browser().unwrap();
    b.rows.iter().map(|r| b.label(r)).collect()
}

fn selected(app: &App) -> String {
    let b = app.browser().unwrap();
    b.label(b.selected_row().unwrap())
}

#[test]
fn scanning_screen_80x24() {
    let progress = Arc::new(Progress::default());
    progress.entries.store(123_456, Ordering::Relaxed);
    progress.allocated.store(3_650_722_201, Ordering::Relaxed);
    let mut app = App::new(vec!["/home/me/projects".into()], progress);
    insta::assert_snapshot!(render(&mut app, 80, 24, None));
    // Only q (or Ctrl-C) does anything while the scan runs.
    press(
        &mut app,
        &[KeyCode::Down, KeyCode::Enter, KeyCode::Char('a')],
    );
    assert!(app.browser().is_none());
    assert_eq!(app.mode, SizeMode::Allocated);
    assert!(app.on_key(key(KeyCode::Char('q'))), "q quits mid-scan");
    assert!(app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}

#[test]
fn tree_root_80x24() {
    if is_root() {
        return; // the locked directory would be readable
    }
    let f = fixture(true);
    let root = f.root();
    let mut data = scan(&[&root]);
    pin_fs(&mut data, true);
    let mut app = app_with(data);
    let State::Browsing(b) = &mut app.state else {
        unreachable!();
    };
    let big = b.data.tree.find(&root.join("big")).unwrap();
    let mid = b.data.tree.find(&root.join("mid")).unwrap();
    for row in &mut b.rows {
        row.size = match row.kind {
            RowKind::Node(id) if id == big => 5 * MIB as u64,
            RowKind::Node(id) if id == mid => 2 * MIB as u64 + (700 << 10),
            RowKind::Files => 3 * MIB as u64 / 2,
            _ => panic!("unexpected row: {row:?}"),
        };
    }
    b.rows.sort_by_key(|row| std::cmp::Reverse(row.size));
    b.total = b.rows.iter().map(|row| row.size).sum::<u64>() + 4096;
    assert_eq!(labels(&app), ["big/", "mid/", "[files]"]);
    insta::assert_snapshot!(render(&mut app, 80, 24, Some(&root)));
}

#[test]
fn filesystem_overflow_80x24() {
    let fixture = fixture(false);
    let root = fixture.root();
    let mut data = scan(&[&root]);
    pin_fs(&mut data, true);
    data.report.fs[1].fstype = "fuse.mergerfs".into();
    data.report.fs[1].mount = format!("/data/{}/pool", "nested/".repeat(8));
    data.report.fs[1].scanned = 117 << 30;
    for n in 2..24 {
        let mut fs = data.report.fs[0].clone();
        fs.mount = format!("/mnt/volume{n}");
        fs.unaccounted = Some((n as u64) << 30);
        data.report.fs.push(fs);
    }
    let mut app = app_with(data);
    let screen = render(&mut app, 80, 24, Some(&root));
    assert!(screen.contains("scanned 117.0G (subtree only)"), "{screen}");
    assert!(screen.contains("… 22 more filesystems · f to view all"));

    press(&mut app, &[KeyCode::Char('f')]);
    let screen = render(&mut app, 80, 24, None);
    insta::assert_snapshot!(screen);
    assert!(screen.contains("unaccounted 3.0G  /mnt/volume3"));
    assert!(!screen.contains("/mnt/volume23"));
    press(&mut app, &[KeyCode::PageDown]);
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("unaccounted 23.0G  /mnt/volume23"));
    press(&mut app, &[KeyCode::PageUp]);
    assert!(render(&mut app, 80, 24, None).contains("1–21 of 24 filesystems"));
    press(&mut app, &[KeyCode::Char('f')]);
    assert!(!render(&mut app, 80, 24, None).contains("/mnt/volume3"));
}

#[test]
fn inside_a_directory_apparent_120x40() {
    if is_root() {
        return;
    }
    let f = fixture(true);
    let root = f.root();
    let mut data = scan(&[&root]);
    pin_fs(&mut data, true);
    let mut app = app_with(data);
    render(&mut app, 120, 40, Some(&root));
    press(
        &mut app,
        &[KeyCode::Char('a'), KeyCode::Down, KeyCode::Enter],
    );
    assert_eq!(app.mode, SizeMode::Apparent);
    assert_eq!(
        app.browser().unwrap().path(),
        root.join("mid").to_str().unwrap()
    );
    // Apparent sizes count no directory bytes: the locked directory is 0B
    // but still listed, marked unreadable.
    assert_eq!(labels(&app), ["[files]", "sub/", "locked/"]);
    let b = app.browser().unwrap();
    assert_eq!(
        b.rows[2].mark.unwrap().permission,
        Some(PermissionMark::Unreadable)
    );
    assert_eq!(b.rows[2].size, 0);
    insta::assert_snapshot!(render(&mut app, 120, 40, Some(&root)));
}

#[test]
fn navigation() {
    let f = fixture(false);
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
    press(&mut app, &[KeyCode::Char('a')]);
    assert_eq!(selected(&app), "big/");
    // Up at the top and Backspace at the only root stay put.
    press(&mut app, &[KeyCode::Up, KeyCode::Backspace]);
    assert_eq!(selected(&app), "big/");
    assert_eq!(app.browser().unwrap().path(), root.to_str().unwrap());

    press(&mut app, &[KeyCode::End]);
    assert_eq!(selected(&app), "[files]");
    // [files] is not a directory: Enter does nothing.
    press(&mut app, &[KeyCode::Enter]);
    assert_eq!(app.browser().unwrap().path(), root.to_str().unwrap());
    press(&mut app, &[KeyCode::Down]);
    assert_eq!(selected(&app), "[files]", "Down stops at the last row");
    press(&mut app, &[KeyCode::Home]);
    assert_eq!(selected(&app), "big/");

    // Into mid/sub and back out with both keys; the way back reselects
    // the directory left.
    press(&mut app, &[KeyCode::Down, KeyCode::Enter]);
    assert_eq!(labels(&app), ["[files]", "sub/"]);
    press(&mut app, &[KeyCode::Down, KeyCode::Right]);
    assert_eq!(
        app.browser().unwrap().path(),
        root.join("mid/sub").to_str().unwrap()
    );
    assert_eq!(labels(&app), ["[files]"]);
    press(&mut app, &[KeyCode::Left]);
    assert_eq!(selected(&app), "sub/");
    press(&mut app, &[KeyCode::Backspace]);
    assert_eq!(selected(&app), "mid/");
    assert!(app.on_key(key(KeyCode::Char('q'))));
}

#[test]
fn pages_move_by_the_rows_on_screen() {
    let t = tempfile::tempdir().unwrap();
    for i in 0..30 {
        let d = t.path().join(format!("d{i:02}"));
        fs::create_dir(&d).unwrap();
        // Distinct sizes, so the order is fixed: d29 largest.
        fs::write(d.join("f"), vec![0u8; (i + 1) * 8192]).unwrap();
    }
    let mut app = app_with(scan(&[t.path()]));
    press(&mut app, &[KeyCode::Char('a')]);
    // 80×24 with one filesystem line leaves 20 list rows.
    let screen = render(&mut app, 80, 24, None);
    assert_eq!(app.viewport, 20);
    assert!(screen.contains("d29/") && !screen.contains("d05/"));
    press(&mut app, &[KeyCode::PageDown]);
    assert_eq!(selected(&app), "d09/");
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("> "), "the selection is on screen");
    press(&mut app, &[KeyCode::PageDown, KeyCode::PageDown]);
    assert_eq!(selected(&app), "d00/");
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("d00/") && !screen.contains("d29/"));
    // From the last row (index 29) back one page: index 9.
    press(&mut app, &[KeyCode::PageUp]);
    assert_eq!(selected(&app), "d20/");
}

#[test]
fn toggle_keeps_the_selected_entry() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    fs::create_dir_all(r.join("sparse")).unwrap();
    fs::create_dir_all(r.join("dense")).unwrap();
    // A sparse file: large apparent size, almost nothing allocated.
    let sparse = fs::File::create(r.join("sparse/hole")).unwrap();
    sparse.set_len(64 * MIB as u64).unwrap();
    fs::write(r.join("dense/data"), vec![1u8; 2 * MIB]).unwrap();
    let mut app = app_with(scan(&[r]));
    assert_eq!(labels(&app), ["dense/", "sparse/"]);
    press(&mut app, &[KeyCode::Down]);
    press(&mut app, &[KeyCode::Char('a')]);
    assert_eq!(app.mode, SizeMode::Apparent);
    assert_eq!(labels(&app), ["sparse/", "dense/"]);
    assert_eq!(selected(&app), "sparse/");
    press(&mut app, &[KeyCode::Char('a')]);
    assert_eq!(app.mode, SizeMode::Allocated);
    assert_eq!(selected(&app), "sparse/");
}

#[test]
fn unreadable_directories_are_listed_and_marked() {
    if is_root() {
        return;
    }
    let f = fixture(true);
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
    press(
        &mut app,
        &[KeyCode::Char('a'), KeyCode::Down, KeyCode::Enter],
    );
    let b = app.browser().unwrap();
    let locked = b
        .rows
        .iter()
        .find(|r| b.label(r) == "locked/")
        .expect("listed, not dropped");
    assert_eq!(
        locked.mark.unwrap().permission,
        Some(PermissionMark::Unreadable)
    );
    assert!(render(&mut app, 80, 24, None).contains("locked/  [unreadable]"));
    // Inside it: nothing to list, and the screen says why.
    press(&mut app, &[KeyCode::End]);
    while selected(&app) != "locked/" {
        press(&mut app, &[KeyCode::Up]);
    }
    press(&mut app, &[KeyCode::Enter]);
    for mode in [SizeMode::Apparent, SizeMode::Allocated] {
        assert_eq!(app.mode, mode);
        assert!(labels(&app).is_empty());
        let screen = render(&mut app, 80, 24, None);
        assert!(
            screen.contains("unreadable: its contents are not counted"),
            "{screen}"
        );
        assert!(screen.contains("this directory: unreadable"), "{screen}");
        press(&mut app, &[KeyCode::Char('a')]);
    }
}

#[test]
fn files_row_counts_measured_entries_and_excludes_directory_blocks() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let a = root.join("a");
    let b = root.join("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    let mut app = app_with(scan(&[&b]));
    assert!(labels(&app).is_empty());
    assert!(render(&mut app, 80, 24, None).contains("(empty)"));

    let file = a.join("file");
    fs::write(&file, b"diskwhy").unwrap();
    fs::hard_link(&file, b.join("file")).unwrap();
    fs::File::create(root.join("empty")).unwrap();
    let allocated = fs::metadata(&file).unwrap().blocks() * 512;
    let data = scan(&[root]);
    for (label, expected) in [("a/", [allocated, 7]), ("b/", [0, 0])] {
        let mut app = app_with(data.clone());
        for _ in 0..labels(&app).iter().position(|s| s == label).unwrap() {
            press(&mut app, &[KeyCode::Down]);
        }
        press(&mut app, &[KeyCode::Enter]);
        for bytes in expected {
            assert_eq!(labels(&app), ["[files]"]);
            assert_eq!(app.browser().unwrap().rows[0].size, bytes);
            press(&mut app, &[KeyCode::Char('a')]);
        }
    }
    let mut app = app_with(data);
    press(&mut app, &[KeyCode::Char('a'), KeyCode::End]);
    assert_eq!(selected(&app), "[files]");
    assert_eq!(app.browser().unwrap().selected_row().unwrap().size, 0);
}

#[test]
fn several_roots_are_listed_together() {
    let a = fixture(false);
    let b = tempfile::tempdir().unwrap();
    fs::write(b.path().join("x"), vec![1u8; 8192]).unwrap();
    let (ra, rb) = (a.root(), fs::canonicalize(b.path()).unwrap());
    let mut app = app_with(scan(&[&rb, &ra]));
    press(&mut app, &[KeyCode::Char('a')]);
    let names = labels(&app);
    assert_eq!(names.len(), 2);
    assert_eq!(names[0], format!("{}/", ra.display()), "largest first");
    assert_eq!(app.browser().unwrap().path(), "");
    press(&mut app, &[KeyCode::Down, KeyCode::Enter]);
    assert_eq!(app.browser().unwrap().path(), rb.to_str().unwrap());
    press(&mut app, &[KeyCode::Backspace]);
    assert_eq!(app.browser().unwrap().path(), "");
    assert_eq!(selected(&app), format!("{}/", rb.display()));
}

#[test]
fn scanning_writes_nothing() {
    let f = fixture(false);
    let root = f.root();
    let list = |p: &Path| {
        let mut v: Vec<(PathBuf, u64)> = Vec::new();
        let mut stack = vec![p.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                let md = e.metadata().unwrap();
                if md.is_dir() {
                    stack.push(e.path());
                }
                v.push((e.path(), md.len()));
            }
        }
        v.sort();
        v
    };
    let before = list(&root);
    let o = opts(vec![root.clone()]);
    job::scan(&o, &Progress::default(), &mut |_| {}).unwrap();
    assert_eq!(list(&root), before);
}

#[test]
fn bad_roots_and_detectors_fail_before_scanning() {
    let o = opts(vec!["/nonexistent/dwhy-tui-test".into()]);
    let result = job::scan(&o, &Progress::default(), &mut |_| {});
    assert!(result.unwrap_err().contains("/nonexistent/dwhy-tui-test"));
    let mut o = opts(Vec::new());
    o.detectors = Some(vec!["nope".into()]);
    let result = job::scan(&o, &Progress::default(), &mut |_| {});
    assert!(result.unwrap_err().contains("unknown detector"));
}

#[test]
fn long_names_are_shortened_in_the_middle() {
    assert_eq!(ui::middle("short", 10), "short");
    let s = ui::middle("/home/someone/projects/a-very-long-directory-name", 20);
    assert_eq!(s.chars().count(), 20);
    assert!(
        s.starts_with("/home/som") && s.ends_with("ctory-name"),
        "{s}"
    );
    assert!(s.contains('…'));
    // Wide characters count two columns.
    let s = ui::middle("目录目录目录目录目录", 9);
    assert!(s.chars().count() <= 5 && s.contains('…'), "{s}");
    assert_eq!(ui::middle("👩‍💻abcdef👩‍💻", 5), "👩‍💻…👩‍💻");
    assert_eq!(ui::middle("abc", 0), "");

    // A long name in the list is cut to fit 80 columns, ends kept.
    let t = tempfile::tempdir().unwrap();
    let long = format!("start-{}-end", "x".repeat(120));
    fs::create_dir(t.path().join(&long)).unwrap();
    let mut app = app_with(scan(&[t.path()]));
    let screen = render(&mut app, 80, 24, None);
    let line = screen.lines().find(|l| l.contains("start-")).unwrap();
    assert!(line.contains('…') && line.contains("-end/"), "{line}");
}

#[test]
fn percent_and_bar() {
    assert_eq!(ui::percent(1, 3), 33);
    assert_eq!(ui::percent(2, 3), 67);
    assert_eq!(ui::percent(5, 0), 0);
    assert_eq!(ui::bar(100), "██████████");
    assert_eq!(ui::bar(55), "█████▌");
    assert_eq!(ui::bar(0), "");
}

// Findings pane and detail view (M4b). Findings are built by hand, so
// nothing depends on Docker, the machine's caches or the clock.

const GIB: u64 = 1 << 30;
const BASE: &str = "2026-11-17T09:00:00Z";

fn hand_finding(detector: &str, path: &str, bytes: u64, tier: Tier) -> Finding {
    Finding {
        file_identity: None,
        id: dwhy_core::detect::finding_id(detector, path),
        detector: detector.into(),
        probe: None,
        evidence: None,
        path: path.into(),
        bytes,
        nested_bytes: None,
        last_modified: Some("2026-11-12T08:30:00Z".into()),
        growth: None,
        tier,
        reason: format!("{detector} output"),
        guards: Vec::new(),
        action: Action {
            kind: ActionKind::RemovePath,
            text: format!("rm -rf {path}"),
            argv: None,
        },
        recovery: Recovery {
            cost: "rebuilt on next use".into(),
            how: None,
        },
    }
}

fn grows(mut f: Finding, per_day: i64) -> Finding {
    f.growth = Some(Growth {
        bytes_per_day: per_day,
        since: BASE.into(),
    });
    f
}

/// A cargo target dir with growth, as a scan with a base snapshot gives it.
fn cargo_finding() -> Finding {
    let path = "/home/me/projects/diskwhy/target";
    let mut f = grows(
        hand_finding("cargo-target", path, 3_435_973_837, Tier::Rebuildable),
        125_829_120,
    );
    f.reason =
        "Cargo build output of /home/me/projects/diskwhy (3.2G); last written 7d 2h ago".into();
    f.action = Action {
        kind: ActionKind::Command,
        text: "/usr/bin/cargo clean --manifest-path /home/me/projects/diskwhy/Cargo.toml \
               --target-dir /home/me/projects/diskwhy/target"
            .into(),
        argv: None,
    };
    f.recovery = Recovery {
        cost: "the next build recompiles the crate and all its dependencies".into(),
        how: Some("cargo build".into()),
    };
    f
}

/// An in-use Postgres volume whose WAL the `postgres-wal` probe diagnosed.
fn pg_volume_finding() -> Finding {
    let mut f = grows(
        hand_finding(
            "docker-volume",
            "docker://volume/pgdata",
            31_568_000_000,
            Tier::Review,
        ),
        1_288_490_189,
    );
    f.last_modified = None;
    f.reason = "volume pgdata holds 29.4G and is mounted by pg-1 (running) \
                (a running container uses it)"
        .into();
    f.action = Action {
        kind: ActionKind::Advice,
        text:
            "in use: if the data is no longer needed, remove the containers first, then the volume"
                .into(),
        argv: None,
    };
    f.recovery = Recovery {
        cost: "n/a while in use".into(),
        how: None,
    };
    f.guards.push(GuardResult {
        name: "container-mount".into(),
        status: GuardStatus::Warn,
        detail: "mounted by pg-1 (running)".into(),
    });
    postgres_wal::annotate(
        &mut f,
        PostgresWal {
            container: "pg-1".into(),
            wal_bytes: Some(29 << 30),
            data_bytes: Some(53 << 20),
            failed_count: Some(151),
            last_archived_at: Some("2026-11-07T07:25:00Z".into()),
            last_failed_at: Some("2026-11-13T02:10:00Z".into()),
            last_failed_wal: Some("00000001000000000000001D".into()),
            archive_mode: Some("on".into()),
            archive_program: Some("curl".into()),
            archive_timeout: Some("10s".into()),
            targets: vec![ArchiveTarget {
                host: "s3test".into(),
                container: Some("s3test".into()),
                state: "exited".into(),
            }],
            unmatched_hosts: 0,
            source: EvidenceSource::Psql,
            notes: vec!["archive target s3test is a stopped container".into()],
        },
    );
    f
}

/// One finding per tier but review twice, out of size order.
fn mixed_findings() -> Vec<Finding> {
    let mut blocked = hand_finding(
        "git-worktree",
        "/home/me/projects/old-feature",
        640 << 20,
        Tier::Blocked,
    );
    blocked.guards.push(GuardResult {
        name: "git-unpublished".into(),
        status: GuardStatus::Block,
        detail: "2 commits not on any remote".into(),
    });
    vec![
        grows(
            hand_finding(
                "trash",
                "/home/me/.local/share/Trash",
                90 << 20,
                Tier::Regenerable,
            ),
            -12 << 20,
        ),
        cargo_finding(),
        hand_finding(
            "node-modules",
            "/home/me/projects/web-dashboard-with-a-rather-long-name/packages/frontend/node_modules",
            812 << 20,
            Tier::Rebuildable,
        ),
        pg_volume_finding(),
        grows(
            hand_finding(
                "user-cache",
                "/home/me/.cache/pip",
                3 * GIB / 2,
                Tier::Regenerable,
            ),
            0,
        ),
        blocked,
        hand_finding(
            "stale-tree",
            "/home/me/scratch/2024-experiments",
            2 * GIB,
            Tier::Review,
        ),
    ]
}

/// The app on a scanned temp fixture whose findings are replaced by `findings`.
fn findings_app(findings: Vec<Finding>, base: Option<&str>) -> (Fixture, App) {
    let f = fixture(false);
    let root = f.root();
    let mut data = scan(&[&root]);
    pin_fs(&mut data, false);
    data.report.findings = findings;
    data.growth_base = base.map(str::to_string);
    (f, app_with(data))
}

fn view(app: &App) -> View {
    app.browser().unwrap().view
}

fn selected_path(app: &App) -> String {
    app.browser()
        .unwrap()
        .selected_finding()
        .unwrap()
        .path
        .clone()
}

fn shown_paths(app: &App) -> Vec<String> {
    let b = app.browser().unwrap();
    b.findings
        .shown
        .iter()
        .map(|&i| b.data.report.findings[i].path.clone())
        .collect()
}

#[test]
fn tab_switches_between_the_tree_and_the_findings() {
    let (f, mut app) = findings_app(mixed_findings(), Some(BASE));
    let root = f.root();
    assert_eq!(view(&app), View::Tree);
    press(&mut app, &[KeyCode::Down]);
    assert_eq!(selected(&app), "mid/");
    press(&mut app, &[KeyCode::Tab]);
    assert_eq!(view(&app), View::Findings);
    assert_eq!(
        selected_path(&app),
        "docker://volume/pgdata",
        "largest first"
    );
    // Tree keys do nothing here; list keys move the finding selection.
    press(
        &mut app,
        &[KeyCode::Char('a'), KeyCode::Char('f'), KeyCode::Down],
    );
    assert_eq!(app.mode, SizeMode::Allocated);
    assert_eq!(selected_path(&app), "/home/me/projects/diskwhy/target");
    press(&mut app, &[KeyCode::Tab]);
    assert_eq!(view(&app), View::Tree);
    let tree = render(&mut app, 80, 24, Some(&root));
    assert!(
        tree.contains("used 120.0G of 400.0G"),
        "f did not open the filesystems: {tree}"
    );
    // The tree is where it was, and its keys still work.
    assert_eq!(selected(&app), "mid/");
    press(&mut app, &[KeyCode::Enter]);
    assert_eq!(
        app.browser().unwrap().path(),
        root.join("mid").to_str().unwrap()
    );
    let screen = render(&mut app, 80, 24, Some(&root));
    assert!(screen.contains("Tab findings"), "{screen}");
    // Back to the findings at the same selection; Tab from the detail
    // view goes to the tree too.
    press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    assert_eq!(view(&app), View::Detail);
    press(&mut app, &[KeyCode::Tab]);
    assert_eq!(view(&app), View::Tree);
    press(&mut app, &[KeyCode::Tab]);
    assert_eq!(view(&app), View::Findings);
    assert_eq!(selected_path(&app), "/home/me/projects/diskwhy/target");
    assert!(
        app.on_key(key(KeyCode::Char('q'))),
        "q quits from the findings"
    );
}

#[test]
fn tier_filter_cycles_and_keeps_the_selection_when_it_can() {
    let (_f, mut app) = findings_app(mixed_findings(), Some(BASE));
    press(&mut app, &[KeyCode::Tab]);
    assert_eq!(
        shown_paths(&app),
        [
            "docker://volume/pgdata",
            "/home/me/projects/diskwhy/target",
            "/home/me/scratch/2024-experiments",
            "/home/me/.cache/pip",
            "/home/me/projects/web-dashboard-with-a-rather-long-name/packages/frontend/node_modules",
            "/home/me/projects/old-feature",
            "/home/me/.local/share/Trash",
        ]
    );
    // Select the cargo target dir, then cycle through every tier.
    press(&mut app, &[KeyCode::Down]);
    let expect = [
        (Some(Tier::Regenerable), 2, "regenerable · 2/7"),
        (Some(Tier::Rebuildable), 2, "rebuildable · 2/7"),
        (Some(Tier::Review), 2, "review · 2/7"),
        (Some(Tier::Blocked), 1, "blocked · 1/7"),
        (None, 7, "all tiers · 7/7"),
    ];
    for (filter, n, header) in expect {
        press(&mut app, &[KeyCode::Char('t')]);
        let b = app.browser().unwrap();
        assert_eq!(b.findings.filter, filter);
        assert_eq!(b.findings.shown.len(), n);
        assert!(
            b.findings
                .shown
                .iter()
                .all(|&i| filter.is_none_or(|t| b.data.report.findings[i].tier == t))
        );
        let screen = render(&mut app, 80, 24, None);
        assert!(screen.lines().next().unwrap().contains(header), "{screen}");
    }
    // A filter that hides the selection selects its largest finding; the
    // blocked one stayed selected back in all tiers.
    assert_eq!(selected_path(&app), "/home/me/projects/old-feature");
    // A selection the filter shows stays selected.
    press(&mut app, &[KeyCode::Up, KeyCode::Up]);
    assert_eq!(selected_path(&app), "/home/me/.cache/pip");
    press(&mut app, &[KeyCode::Char('t')]);
    assert_eq!(
        app.browser().unwrap().findings.filter,
        Some(Tier::Regenerable)
    );
    assert_eq!(selected_path(&app), "/home/me/.cache/pip");
}

#[test]
fn a_filter_that_empties_the_list_says_so() {
    let only_rebuildable = vec![cargo_finding()];
    let (_f, mut app) = findings_app(only_rebuildable, None);
    press(&mut app, &[KeyCode::Tab, KeyCode::Char('t')]);
    let b = app.browser().unwrap();
    assert_eq!(b.findings.filter, Some(Tier::Regenerable));
    assert!(b.findings.shown.is_empty());
    assert!(b.selected_finding().is_none());
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("no regenerable findings"), "{screen}");
    assert!(screen.contains("regenerable · 0/1"), "{screen}");
    // Nothing to open, and moving does nothing.
    press(&mut app, &[KeyCode::Down, KeyCode::End, KeyCode::Enter]);
    assert_eq!(view(&app), View::Findings);
    press(&mut app, &[KeyCode::Char('t')]);
    assert_eq!(selected_path(&app), "/home/me/projects/diskwhy/target");
    press(&mut app, &[KeyCode::Char('t')]);
    assert!(render(&mut app, 80, 24, None).contains("no review findings"));
}

#[test]
fn no_findings_and_failed_detectors_are_explicit() {
    let (_f, mut app) = findings_app(Vec::new(), None);
    press(&mut app, &[KeyCode::Tab]);
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("  no findings "), "{screen}");
    assert!(screen.contains("all tiers · 0/0"), "{screen}");
    // A filter on an empty report still says there are none at all.
    press(&mut app, &[KeyCode::Char('t')]);
    assert!(render(&mut app, 80, 24, None).contains("  no findings "));

    let f = fixture(false);
    let mut data = scan(&[&f.root()]);
    data.report.findings.clear();
    let run = data
        .report
        .detectors
        .iter()
        .find(|d| d.name == "cargo-target")
        .unwrap()
        .clone();
    for (name, error) in [
        ("docker-volume", "daemon did not answer"),
        ("docker-build-cache", "cache usage unavailable"),
    ] {
        let mut failed = run.clone();
        failed.name = name.into();
        failed.error = Some(error.into());
        data.report.detectors.push(failed);
    }
    let mut with_finding = data.clone();
    let mut app = app_with(data);
    press(&mut app, &[KeyCode::Tab]);
    let screen = render(&mut app, 80, 24, None);
    assert!(
        screen.contains("no findings; detectors failed:"),
        "{screen}"
    );
    assert!(
        screen.contains("    docker-volume: daemon did not answer"),
        "{screen}"
    );
    assert!(
        screen.contains("    docker-build-cache: cache usage unavailable"),
        "{screen}"
    );
    with_finding.report.findings = vec![cargo_finding()];
    let mut app = app_with(with_finding);
    press(&mut app, &[KeyCode::Tab]);
    let screen = render(&mut app, 80, 24, None);
    let status = screen.lines().nth(22).unwrap();
    assert!(
        status.contains("docker-volume, docker-build-cache failed"),
        "{screen}"
    );
    press(&mut app, &[KeyCode::Char('t')]);
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("no regenerable findings"), "{screen}");
    assert!(
        screen.contains("    docker-volume: daemon did not answer"),
        "{screen}"
    );
    assert!(
        screen.contains("    docker-build-cache: cache usage unavailable"),
        "{screen}"
    );
}

#[test]
fn detector_errors_scroll_at_45x24() {
    let f = fixture(false);
    let mut data = scan(&[&f.root()]);
    for run in &mut data.report.detectors {
        match run.name.as_str() {
            "docker-volume" => {
                run.error = Some(format!(
                    "{}retry-exhausted",
                    "request timed out. ".repeat(55)
                ));
            }
            "docker-build-cache" => run.error = Some("cache result unavailable".into()),
            _ => {}
        }
    }
    for filtered in [false, true] {
        let mut data = data.clone();
        if filtered {
            data.report.findings.push(cargo_finding());
        }
        let mut app = app_with(data);
        press(&mut app, &[KeyCode::Tab]);
        let empty = if filtered {
            let screen = render(&mut app, 45, 24, None);
            let status = screen.lines().nth(22).unwrap();
            assert!(status.contains("no growth data"), "{screen}");
            assert!(
                status.contains("docker-build-cache") && status.contains("failed"),
                "{screen}"
            );
            press(&mut app, &[KeyCode::Char('t')]);
            "no regenerable findings"
        } else {
            "no findings"
        };
        let at_top = render(&mut app, 45, 24, None);
        assert!(at_top.contains(empty), "{at_top}");
        assert!(!at_top.contains("retry-exhausted"), "{at_top}");
        assert!(
            at_top.contains("docker-build-cache: cache result"),
            "{at_top}"
        );
        press(&mut app, &[KeyCode::Down]);
        assert!(!render(&mut app, 45, 24, None).contains(empty));
        press(&mut app, &[KeyCode::Up]);
        assert!(render(&mut app, 45, 24, None).contains(empty));
        for (down, up) in [
            (KeyCode::End, KeyCode::Home),
            (KeyCode::PageDown, KeyCode::PageUp),
        ] {
            press(&mut app, &[down]);
            let later = render(&mut app, 45, 24, None);
            assert!(later.contains("retry-exhausted"), "{later}");
            assert!(!later.contains(empty), "{later}");
            press(&mut app, &[up]);
            assert!(render(&mut app, 45, 24, None).contains(empty));
        }
    }
}

#[test]
fn compact_findings_only_open_when_a_row_fits() {
    let finding = hand_finding("cargo-target", "/abc", GIB, Tier::Rebuildable);
    let (_f, mut app) = findings_app(vec![finding], None);
    press(&mut app, &[KeyCode::Tab]);
    let screen = render(&mut app, 23, 24, None);
    assert!(
        screen.contains("Widen") && !screen.contains("/abc"),
        "{screen}"
    );
    for key in [KeyCode::Enter, KeyCode::Right, KeyCode::Char('l')] {
        press(&mut app, &[key]);
        assert_eq!(view(&app), View::Findings);
    }
    press(&mut app, &[KeyCode::Char(' ')]);
    assert!(marked(&app).is_empty());
    for width in [24, 27] {
        let screen = render(&mut app, width, 24, None);
        assert!(screen.contains("rebuildable 1.0G /abc"), "{screen}");
        assert!(!screen.contains("Widen"), "{screen}");
    }
    press(&mut app, &[KeyCode::Char(' ')]);
    assert_eq!(marked(&app), ["/abc"]);
    render(&mut app, 80, 4, None);
    press(&mut app, &[KeyCode::Char(' '), KeyCode::Enter]);
    assert_eq!(marked(&app), ["/abc"]);
    assert_eq!(view(&app), View::Findings);
    render(&mut app, 80, 24, None);
    press(&mut app, &[KeyCode::Enter]);
    assert_eq!(view(&app), View::Detail);
}

#[test]
fn paging_moves_by_the_finding_rows_on_screen() {
    let findings = (1..=25)
        .map(|i| {
            hand_finding(
                "cargo-target",
                &format!("/p/{i:02}"),
                1024,
                Tier::Rebuildable,
            )
        })
        .collect();
    let (_f, mut app) = findings_app(findings, None);
    press(&mut app, &[KeyCode::Tab]);
    let first_page = render(&mut app, 80, 24, None);
    assert!(first_page.lines().nth(21).unwrap().contains("/p/20"));
    press(&mut app, &[KeyCode::PageDown]);
    assert_eq!(selected_path(&app), "/p/21");
    press(&mut app, &[KeyCode::End]);
    render(&mut app, 80, 24, None);
    press(&mut app, &[KeyCode::PageUp]);
    assert_eq!(selected_path(&app), "/p/05");
}

#[test]
fn enter_opens_the_detail_and_esc_returns_to_the_same_selection() {
    let (_f, mut app) = findings_app(mixed_findings(), Some(BASE));
    press(&mut app, &[KeyCode::Tab, KeyCode::Down, KeyCode::Down]);
    assert_eq!(selected_path(&app), "/home/me/scratch/2024-experiments");
    for back in [KeyCode::Esc, KeyCode::Backspace] {
        press(&mut app, &[KeyCode::Enter]);
        assert_eq!(view(&app), View::Detail);
        let screen = render(&mut app, 80, 24, None);
        assert!(screen.contains("finding f_"), "{screen}");
        assert!(screen.contains("stale-tree output"), "{screen}");
        // List keys scroll the detail instead of moving the selection.
        press(&mut app, &[KeyCode::Down, KeyCode::Char('t')]);
        assert_eq!(app.browser().unwrap().findings.filter, None);
        press(&mut app, &[back]);
        assert_eq!(view(&app), View::Findings);
        assert_eq!(selected_path(&app), "/home/me/scratch/2024-experiments");
    }
    // The detail view opens at its top again.
    press(&mut app, &[KeyCode::Enter]);
    assert_eq!(app.browser().unwrap().findings.scroll, 0);
}

#[test]
fn findings_list_80x24() {
    let (_f, mut app) = findings_app(mixed_findings(), Some(BASE));
    press(&mut app, &[KeyCode::Tab, KeyCode::Down]);
    let screen = render(&mut app, 80, 24, None);
    // Figures are never cut; the long path is shortened in the middle.
    assert!(
        screen.contains("rebuildable   812.0M          –  node-modules"),
        "{screen}"
    );
    assert!(screen.contains("…"), "{screen}");
    assert!(screen.contains("-12.0M/d"), "{screen}");
    insta::assert_snapshot!(screen);
}

#[test]
fn findings_list_50x24() {
    let finding = grows(
        hand_finding(
            "docker-build-cache",
            "docker://build-cache",
            4 * GIB,
            Tier::Regenerable,
        ),
        125_829_120,
    );
    let (_f, mut app) = findings_app(vec![finding], Some(BASE));
    press(&mut app, &[KeyCode::Tab]);
    let screen = render(&mut app, 50, 24, None);
    insta::assert_snapshot!(screen);

    let screen = render(&mut app, 66, 24, None);
    let header = screen.lines().nth(1).unwrap();
    let row = screen.lines().nth(2).unwrap();
    assert!(header.contains("detector") && !header.contains("growth"));
    assert!(row.contains("docker-build-cache") && !row.contains("/d"));
    assert_eq!(header.find("path"), row.find("docker://build-cache"));
}

#[test]
fn findings_list_120x40() {
    let mut findings = mixed_findings();
    for f in &mut findings {
        f.growth = None;
    }
    let (_f, mut app) = findings_app(findings, None);
    press(&mut app, &[KeyCode::Tab]);
    let screen = render(&mut app, 120, 40, None);
    assert_eq!(
        screen.lines().nth(38).unwrap().trim_matches('"').trim(),
        "1/7 · no growth data"
    );
    insta::assert_snapshot!(screen);
}

#[test]
fn detail_filesystem_finding_80x24() {
    let (_f, mut app) = findings_app(vec![cargo_finding()], Some(BASE));
    press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    let screen = render(&mut app, 80, 24, None);
    assert!(
        screen.contains("growth: +120.0M/day since 2026-11-17T09:00:00Z"),
        "{screen}"
    );
    insta::assert_snapshot!(screen);
}

#[test]
fn detail_docker_volume_with_postgres_wal_evidence_80x24() {
    let (_f, mut app) = findings_app(vec![pg_volume_finding()], Some(BASE));
    press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("evidence (postgres-wal):"), "{screen}");
    insta::assert_snapshot!(screen);
    // It does not fit: End scrolls to the last line, and no further.
    press(&mut app, &[KeyCode::End]);
    let end = render(&mut app, 80, 24, None);
    assert!(end.contains("  cost: n/a: nothing is removed"), "{end}");
    assert!(!end.contains("finding f_"), "{end}");
    assert!(end.contains("lines 4–24 of 24"), "{end}");
    let scroll = app.browser().unwrap().findings.scroll;
    assert!(scroll > 0);
    press(&mut app, &[KeyCode::Down, KeyCode::PageDown]);
    render(&mut app, 80, 24, None);
    assert_eq!(app.browser().unwrap().findings.scroll, scroll);
    press(&mut app, &[KeyCode::Home]);
    assert!(render(&mut app, 80, 24, None).contains("finding f_"));
}

#[test]
fn detail_says_when_there_is_no_growth_to_show() {
    let mut f = cargo_finding();
    f.growth = None;
    let (_x, mut app) = findings_app(vec![f.clone()], None);
    press(&mut app, &[KeyCode::Tab]);
    let list = render(&mut app, 80, 24, None);
    assert!(list.contains("          –  cargo-target"), "{list}");
    press(&mut app, &[KeyCode::Enter]);
    let screen = render(&mut app, 80, 24, None);
    assert!(
        screen
            .lines()
            .any(|l| l.trim_matches('"').trim_end() == "growth: no growth data"),
        "{screen}"
    );
    // A base snapshot that does not list the finding.
    let (_x, mut app) = findings_app(vec![f], Some(BASE));
    press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    let screen = render(&mut app, 80, 24, None);
    assert!(
        screen
            .lines()
            .any(|l| l.trim_matches('"').trim_end() == "growth: unknown"),
        "{screen}"
    );
}

#[test]
fn finding_paths_and_commands_escape_controls() {
    let path = "/p/repo\nx/target";
    let mut finding = hand_finding("cargo-target", path, 3 * GIB, Tier::Rebuildable);
    finding.action.kind = ActionKind::Command;
    finding.action.text = format!(
        "cargo clean --target-dir {}",
        dwhy_core::detect::shell_quote(path)
    );
    finding.recovery.how = Some("cd '/p/repo\nx' && cargo build".into());
    finding.reason = "Cargo build output of /p/repo\nx".into();
    let mut lookalike = hand_finding("cargo-target", r"/p/repo\nx/target", GIB, Tier::Rebuildable);
    lookalike.reason = r"Cargo build output of /p/repo\nx".into();
    lookalike.recovery.how = Some(r"cd '/p/repo\nx' && cargo build".into());
    let (_f, mut app) = findings_app(vec![finding, lookalike], None);
    press(&mut app, &[KeyCode::Tab]);
    let list = render(&mut app, 80, 24, None);
    assert!(
        list.lines().nth(2).unwrap().contains(r"/p/repo\nx/target"),
        "{list}"
    );
    assert!(
        list.lines().nth(3).unwrap().contains(r"/p/repo\\nx/target"),
        "{list}"
    );

    press(&mut app, &[KeyCode::Enter]);
    let detail = render(&mut app, 80, 24, None);
    assert!(
        detail
            .lines()
            .next()
            .unwrap()
            .contains(r"/p/repo\nx/target"),
        "{detail}"
    );
    assert!(
        detail
            .lines()
            .nth(2)
            .unwrap()
            .trim_matches('"')
            .trim_end()
            .ends_with(r"/p/repo\nx/target"),
        "{detail}"
    );
    assert!(
        detail.contains(r"cargo clean --target-dir '/p/repo\nx/target'"),
        "{detail}"
    );
    assert!(
        detail.contains(r"cd '/p/repo\nx' && cargo build"),
        "{detail}"
    );
    assert!(
        detail.contains(r"Cargo build output of /p/repo\nx"),
        "{detail}"
    );
    assert_eq!(
        detail.matches("preview — do not copy").count(),
        2,
        "{detail}"
    );
    press(&mut app, &[KeyCode::Esc, KeyCode::Down, KeyCode::Enter]);
    let detail = render(&mut app, 80, 24, None);
    assert!(
        detail.contains(r"Cargo build output of /p/repo\\nx"),
        "{detail}"
    );
    assert!(
        detail.contains(r"cd '/p/repo\\nx' && cargo build"),
        "{detail}"
    );
    assert_eq!(
        detail.matches("preview — do not copy").count(),
        2,
        "{detail}"
    );
}

#[test]
fn invisible_cargo_path_characters_are_visible_in_paths_and_previews() {
    for (character, escape) in [
        ('\u{17b4}', r"\u{17b4}"),
        ('\u{17b5}', r"\u{17b5}"),
        ('\u{200b}', r"\u{200b}"),
        ('\u{200c}', r"\u{200c}"),
        ('\u{200d}', r"\u{200d}"),
        ('\u{feff}', r"\u{feff}"),
    ] {
        let path = format!("/p/app{character}/target");
        let shown_path = format!("/p/app{escape}/target");
        let mut finding = hand_finding("cargo-target", &path, GIB, Tier::Rebuildable);
        finding.action.kind = ActionKind::Command;
        finding.action.text = format!(
            "cargo clean --target-dir {}",
            dwhy_core::detect::shell_quote(&path)
        );
        finding.recovery.how = Some(format!("cd '/p/app{character}' && cargo build"));
        let (_f, mut app) = findings_app(vec![finding], None);
        press(&mut app, &[KeyCode::Tab]);
        let list = render(&mut app, 80, 24, None);
        assert!(list.lines().nth(2).unwrap().contains(&shown_path), "{list}");

        press(&mut app, &[KeyCode::Enter]);
        let detail = render(&mut app, 80, 24, None);
        assert!(
            detail.lines().next().unwrap().contains(&shown_path),
            "{detail}"
        );
        assert!(
            detail.lines().nth(2).unwrap().contains(&shown_path),
            "{detail}"
        );
        assert!(
            detail.contains(&format!("cargo clean --target-dir '{shown_path}'")),
            "{detail}"
        );
        assert!(
            detail.contains(&format!("cd '/p/app{escape}' && cargo build")),
            "{detail}"
        );
        assert_eq!(
            detail.matches("preview — do not copy").count(),
            2,
            "{detail}"
        );
    }
}

#[test]
fn only_printable_ascii_commands_are_unlabelled_on_one_line() {
    for (project, expected_previews) in [("café", 2), ("cafe", 0)] {
        let path = format!("/p/{project}/target");
        let action = format!("cargo clean --target-dir '{path}'");
        let recovery = format!("cd '/p/{project}' && cargo build");
        let mut finding = hand_finding("cargo-target", &path, GIB, Tier::Rebuildable);
        finding.action.kind = ActionKind::Command;
        finding.action.text = action.clone();
        finding.recovery.how = Some(recovery.clone());
        let (_f, mut app) = findings_app(vec![finding], None);
        press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
        let detail = render(&mut app, 80, 24, None);
        assert!(
            detail.contains(&action) && detail.contains(&recovery),
            "{detail}"
        );
        assert_eq!(
            detail.matches("preview — do not copy").count(),
            expected_previews,
            "{detail}"
        );
    }
}

#[test]
fn halfwidth_sound_mark_at_the_right_edge_is_escaped_in_command_preview() {
    let path = format!("/p/{}ｶﾞ/target", "x".repeat(40));
    let mut finding = hand_finding("cargo-target", &path, GIB, Tier::Rebuildable);
    finding.action.kind = ActionKind::Command;
    finding.action.text = format!("cargo clean --target-dir '{path}'");
    let (_f, mut app) = findings_app(vec![finding], None);
    press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    let detail = render(&mut app, 80, 24, None);
    assert!(detail.contains("preview — do not copy"), "{detail}");
    assert!(
        detail
            .lines()
            .any(|line| line.starts_with("\"│") && line.contains(r"\u{ff9e}/target'")),
        "{detail}"
    );
}

#[test]
fn wrapped_action_and_recovery_are_previews() {
    let path = format!("/p/{}", "project".repeat(9));
    let mut finding = hand_finding("cargo-target", "/p/target", GIB, Tier::Rebuildable);
    let action = format!("cargo clean --target-dir {path}");
    let recovery = format!("cargo build --manifest-path {path}/Cargo.toml");
    finding.action.kind = ActionKind::Command;
    finding.action.text = action.clone();
    finding.recovery.how = Some(recovery.clone());
    let (_f, mut app) = findings_app(vec![finding], None);
    press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    let wrapped = render(&mut app, 80, 24, None);
    assert_eq!(
        wrapped.matches("preview — do not copy").count(),
        2,
        "{wrapped}"
    );
    assert!(
        wrapped.contains("│  cargo clean") && wrapped.contains("│  how:  cargo build"),
        "{wrapped}"
    );
    assert!(
        !wrapped.contains(&action) && !wrapped.contains(&recovery),
        "{wrapped}"
    );

    let exact = render(&mut app, 120, 24, None);
    assert!(
        exact.contains(&action) && exact.contains(&recovery),
        "{exact}"
    );
    assert!(!exact.contains("preview — do not copy"), "{exact}");
}

#[test]
fn lossy_repository_argument_is_withheld_for_an_exact_worktree() {
    for lossy_action in [false, true] {
        let path = "/work/feature";
        let mut finding = hand_finding("git-worktree", path, GIB, Tier::Review);
        let (action_repo, recovery_repo) = if lossy_action {
            ("/repo�", "/repo")
        } else {
            ("/repo", "/repo�")
        };
        finding.action.kind = ActionKind::Command;
        finding.action.text = format!("git -C {action_repo} worktree remove {path}");
        finding.recovery.how = Some(format!(
            "git -C {recovery_repo} worktree add {path} feature"
        ));
        let (_f, mut app) = findings_app(vec![finding], None);
        press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
        let detail = render(&mut app, 120, 24, None);
        assert!(detail.lines().next().unwrap().contains(path), "{detail}");
        assert!(!detail.contains("/repo�"), "{detail}");
        assert_eq!(
            detail.matches("command withheld: it names a path that is not valid UTF-8 and cannot be shown exactly").count(),
            1,
            "{detail}"
        );
        let exact = if lossy_action {
            "git -C /repo worktree add /work/feature feature"
        } else {
            "git -C /repo worktree remove /work/feature"
        };
        assert!(detail.contains(exact), "{detail}");
        assert!(!detail.contains("preview — do not copy"), "{detail}");
    }
}

#[test]
fn finding_escapes_stay_whole_at_layout_boundaries() {
    let head = format!("/{}", "x".repeat(13));
    let tail = "yyyyyyyyy/tail";
    let path = format!("{head}\n{}\n{tail}", "m".repeat(20));
    let mut finding = hand_finding("cargo-target", &path, GIB, Tier::Rebuildable);
    finding.reason = format!("project /{}\nnext", "x".repeat(74));
    let (_f, mut app) = findings_app(vec![finding], None);
    press(&mut app, &[KeyCode::Tab]);
    let list = render(&mut app, 80, 24, None);
    assert!(
        list.lines()
            .nth(2)
            .unwrap()
            .contains(&format!("{head}…{tail}")),
        "{list}"
    );
    press(&mut app, &[KeyCode::Enter]);
    let title = render(&mut app, 52, 24, None);
    assert!(
        title
            .lines()
            .next()
            .unwrap()
            .contains(&format!("{head}…{tail}")),
        "{title}"
    );
    let detail = render(&mut app, 80, 24, None);
    assert!(
        detail
            .lines()
            .any(|line| line.starts_with(r#""    \nnext"#)),
        "{detail}"
    );
}

#[test]
fn lossy_cargo_path_shows_advice_and_withholds_commands() {
    let f = fixture(false);
    let root = f.root();
    let project = root.join(OsStr::from_bytes(b"app\xff"));
    match fs::create_dir(&project) {
        Ok(()) => {}
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::InvalidInput | ErrorKind::InvalidData | ErrorKind::Unsupported
            ) =>
        {
            return;
        }
        Err(e) => panic!("cannot create non-UTF-8 path: {e}"),
    }
    fs::create_dir_all(root.join("app�/target")).unwrap();
    fs::create_dir(project.join("target")).unwrap();
    fs::write(project.join("Cargo.toml"), b"[package]\n").unwrap();
    fs::write(project.join("target/.rustc_info.json"), b"{}").unwrap();
    fs::write(project.join("target/out"), vec![5u8; 2 * MIB]).unwrap();
    let data = scan(&[&root]);
    assert_eq!(data.report.findings.len(), 1);
    let finding = &data.report.findings[0];
    assert!(finding.path.ends_with("/app�/target"));
    assert_eq!(finding.tier, Tier::Blocked);
    assert_eq!(finding.action.kind, ActionKind::Advice);
    assert!(finding.guards.iter().any(|g| g.name == "path-not-utf8"));
    let mut app = app_with(data.clone());
    press(&mut app, &[KeyCode::Tab]);
    let list = render(&mut app, 80, 24, None);
    let row = list.lines().nth(2).unwrap();
    assert!(
        row.contains("> !") && row.contains("/app�/target"),
        "{list}"
    );
    press(&mut app, &[KeyCode::Enter]);
    let detail = render(&mut app, 120, 24, None);
    assert!(
        detail.contains("path is not valid UTF-8; shown approximately — do not copy"),
        "{detail}"
    );
    assert_eq!(
        detail
            .matches("command withheld because the path cannot be shown exactly")
            .count(),
        1,
        "{detail}"
    );
    assert!(
        detail.contains("rename the path that is not valid UTF-8 to valid UTF-8"),
        "{detail}"
    );
    assert!(!detail.contains("cargo build"), "{detail}");

    let mut data = data;
    data.report.findings[0].recovery.how =
        Some("cargo build --manifest-path /app�/Cargo.toml".into());
    detect::block_lossy(&mut data.report.findings);
    let mut app = app_with(data);
    press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    let detail = render(&mut app, 120, 24, None);
    assert!(
        detail.contains("by hand: the command names a path that is not valid UTF-8"),
        "{detail}"
    );
    assert!(!detail.contains("command withheld"), "{detail}");
}

#[test]
fn detail_wrap_keeps_a_grapheme_at_the_right_edge() {
    let end_of_line = format!("/{}👩‍💻", "x".repeat(69));
    let path = format!("{end_of_line}/target");
    let finding = hand_finding("cargo-target", &path, GIB, Tier::Rebuildable);
    let (_f, mut app) = findings_app(vec![finding], None);
    press(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    let detail = render(&mut app, 80, 24, None);
    let quoted_line = format!("\"        {end_of_line}\"");
    assert!(
        detail.lines().any(|line| line.starts_with(&quoted_line)),
        "{detail}"
    );
}

/// The scan reads growth from the snapshot directory it is given, and from
/// nowhere when it is given none.
#[test]
fn scan_takes_growth_from_the_snapshot_dir_it_is_given() {
    const TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
                       # This file is a cache directory tag created by cargo.\n";
    let f = fixture(false);
    let root = f.root();
    fs::create_dir_all(root.join("app/target")).unwrap();
    fs::write(root.join("app/Cargo.toml"), b"[package]\n").unwrap();
    fs::write(root.join("app/target/CACHEDIR.TAG"), TAG).unwrap();
    fs::write(root.join("app/target/out"), vec![5u8; 2 * MIB]).unwrap();
    let plain = scan(&[&root]);
    assert_eq!(plain.report.findings.len(), 1);
    assert!(plain.growth_base.is_none());
    assert!(plain.report.findings[0].growth.is_none());

    // A snapshot of these roots old enough, listing the finding smaller.
    let state = tempfile::tempdir().unwrap();
    let dir = state.path().join("snapshots");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut old = plain.report.clone();
    old.generated_at = dwhy_core::detect::rfc3339(now - 2 * growth::MIN_AGE_SECS);
    old.findings[0].bytes /= 2;
    assert_eq!(old.host, system::hostname());
    let snap = snapshot::build(&old, &plain.tree, None, 0);
    snapshot::save(&dir, &snap, now).unwrap();
    let listed = fs::read_dir(&dir).unwrap().count();

    let mut o = opts(vec![root.clone()]);
    o.snapshot_dir = Some(dir.clone());
    let data = job::scan(&o, &Progress::default(), &mut |_| {}).unwrap();
    assert_eq!(data.growth_base.as_deref(), Some(old.generated_at.as_str()));
    let g = data.report.findings[0].growth.as_ref().unwrap();
    assert!(g.bytes_per_day > 0, "{g:?}");
    assert_eq!(g.since, old.generated_at);
    let mut app = app_with(data);
    press(
        &mut app,
        &[KeyCode::Tab, KeyCode::Char(' '), KeyCode::Char('p')],
    );
    run_build(&mut app, &Processes::default());
    assert!(plan_of(&app).items[0].finding.growth.is_none());
    // Read only: nothing saved or pruned.
    assert_eq!(fs::read_dir(&dir).unwrap().count(), listed);
}

// ---------------------------------------------------------------------------
// M4c: marks, the plan preview and plan files
// ---------------------------------------------------------------------------

const CARGO_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
                         # This file is a cache directory tag created by cargo.\n";
/// 2026-11-19T09:00:00Z, when the hand-made plans are created.
const PLAN_AT: i64 = 1_795_078_800;
const HOST: &str = "testhost";
const UID: u32 = 1000;

/// A fixture with two crates whose `target/` dirs are `cargo-target`
/// findings: `app` (3 MiB) and `lib` (1 MiB).
fn crates_fixture() -> Fixture {
    let f = fixture(false);
    let r = f.root();
    for (name, size) in [("app", 3 * MIB), ("lib", MIB)] {
        fs::create_dir_all(r.join(name).join("target/debug")).unwrap();
        fs::write(r.join(name).join("Cargo.toml"), b"[package]\n").unwrap();
        fs::write(r.join(name).join("target/CACHEDIR.TAG"), CARGO_TAG).unwrap();
        fs::write(r.join(name).join("target/debug/out"), vec![6u8; size]).unwrap();
    }
    f
}

fn marked(app: &App) -> Vec<String> {
    let b = app.browser().unwrap();
    b.marked_findings().map(|f| f.path.clone()).collect()
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        assert!(
            !app.on_key(key(KeyCode::Char(c))),
            "{c:?} is text in the prompt"
        );
    }
}

/// Runs the plan build the app asked for, as the event loop would, with
/// the given processes for the guards.
fn run_build(app: &mut App, procs: &Processes) {
    let job = app.take_request().expect("a plan build was requested");
    let result = job.build(|| procs.clone(), HOST.into());
    app.plan_built(result, HOST, system::euid());
}

fn plan_of(app: &App) -> &Plan {
    app.plan_view().expect("the plan preview is shown").plan()
}

fn guard(name: &str, status: GuardStatus, detail: &str) -> GuardResult {
    GuardResult {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

fn fingerprint() -> Fingerprint {
    Fingerprint {
        dev: Some(2049),
        inode: Some(1234),
        newest_mtime: Some(PLAN_AT - 7 * 86_400),
        size_bucket: 100,
        git: None,
        docker_id: None,
    }
}

/// A plan as `plan::build` would make it on another machine: two items (one
/// with a guard warning) and one finding a guard blocked.
fn hand_plan() -> Plan {
    let passes = || {
        vec![
            guard(
                "in-use-cwd",
                GuardStatus::Pass,
                "no process has its working directory in it",
            ),
            guard(
                "in-use-open",
                GuardStatus::Pass,
                "no process has a file in it open",
            ),
        ]
    };
    let mut cargo = cargo_finding();
    cargo.growth = None;
    cargo.guards = passes();
    cargo.guards.extend([
        guard("git-dirty", GuardStatus::Pass, "1 git worktree checked"),
        guard(
            "git-unpublished",
            GuardStatus::Warn,
            "unpushed commits stay in the repository's branch: diskwhy (main, 2 commits)",
        ),
    ]);
    let mut trash = hand_finding(
        "trash",
        "/home/me/.local/share/Trash",
        90 << 20,
        Tier::Regenerable,
    );
    trash.guards = passes();
    let mut blocked = hand_finding(
        "node-modules",
        "/home/me/projects/web-dashboard/node_modules",
        812 << 20,
        Tier::Blocked,
    );
    blocked.guards = passes();
    blocked.guards[0] = guard(
        "in-use-cwd",
        GuardStatus::Block,
        "working directory of node (pid 4242)",
    );
    let select = [&cargo, &trash, &blocked]
        .iter()
        .map(|f| f.id.clone())
        .collect();
    Plan {
        schema: "diskwhy/v1".into(),
        tool: Tool::current(),
        host: HOST.into(),
        uid: UID,
        created_at: dwhy_core::detect::rfc3339(PLAN_AT),
        expires_at: dwhy_core::detect::rfc3339(PLAN_AT + plan::TTL_SECS),
        scan: PlanScan {
            roots: vec!["/home/me".into()],
            one_filesystem: true,
            detectors: None,
        },
        selection: PlanSelection { tier: None, select },
        bytes: cargo.bytes + trash.bytes,
        items: vec![
            PlanItem {
                finding: cargo,
                fingerprint: fingerprint(),
            },
            PlanItem {
                finding: trash,
                fingerprint: fingerprint(),
            },
        ],
        blocked: vec![blocked],
    }
}

fn hand_build() -> BuiltPlan {
    BuiltPlan {
        plan: hand_plan(),
        unplanned: Vec::new(),
    }
}

/// The mixed findings with the given paths marked.
fn marked_app(paths: &[&str]) -> (Fixture, App) {
    let (f, mut app) = findings_app(mixed_findings(), Some(BASE));
    press(&mut app, &[KeyCode::Tab]);
    for p in paths {
        press(&mut app, &[KeyCode::Home]);
        while selected_path(&app) != *p {
            press(&mut app, &[KeyCode::Down]);
        }
        press(&mut app, &[KeyCode::Char(' ')]);
    }
    (f, app)
}

/// The hand plan in the preview, as if built from the marks.
fn preview_app() -> (Fixture, App) {
    let (f, mut app) = marked_app(&["/home/me/projects/diskwhy/target"]);
    press(&mut app, &[KeyCode::Char('p')]);
    assert!(app.take_request().is_some());
    app.plan_built(Ok(hand_build()), HOST, UID);
    (f, app)
}

#[test]
fn space_marks_and_unmarks_and_marks_survive_filter_and_tab() {
    let (_f, mut app) = findings_app(mixed_findings(), Some(BASE));
    press(&mut app, &[KeyCode::Tab, KeyCode::Down, KeyCode::Char(' ')]);
    assert_eq!(marked(&app), ["/home/me/projects/diskwhy/target"]);
    let screen = render(&mut app, 80, 24, None);
    assert!(
        screen.contains("all tiers · 7/7 · 1 marked 3.2G"),
        "{screen}"
    );
    assert!(
        screen.contains(">* rebuildable     3.2G"),
        "the row shows the mark: {screen}"
    );

    // Marks stay through the tier filter, and the filter's rows mark too.
    press(&mut app, &[KeyCode::Char('t'), KeyCode::Char(' ')]);
    assert_eq!(
        app.browser().unwrap().findings.filter,
        Some(Tier::Regenerable)
    );
    assert_eq!(selected_path(&app), "/home/me/.cache/pip");
    // Blocked findings can be marked: the plan lists them as blocked.
    press(
        &mut app,
        &[KeyCode::Char('t'), KeyCode::Char('t'), KeyCode::Char('t')],
    );
    assert_eq!(app.browser().unwrap().findings.filter, Some(Tier::Blocked));
    press(&mut app, &[KeyCode::Char(' '), KeyCode::Char('t')]);
    assert_eq!(app.browser().unwrap().findings.filter, None);
    press(&mut app, &[KeyCode::Tab, KeyCode::Tab]);
    assert_eq!(view(&app), View::Findings);
    assert_eq!(marked(&app).len(), 3);
    let b = app.browser().unwrap();
    assert_eq!(
        b.marked_bytes(),
        3_435_973_837 + (3 * GIB / 2) + (640 << 20)
    );

    // Space again unmarks.
    press(&mut app, &[KeyCode::Home]);
    while selected_path(&app) != "/home/me/.cache/pip" {
        press(&mut app, &[KeyCode::Down]);
    }
    press(&mut app, &[KeyCode::Char(' ')]);
    assert_eq!(
        marked(&app),
        [
            "/home/me/projects/diskwhy/target",
            "/home/me/projects/old-feature"
        ]
    );
}

#[test]
fn advice_only_findings_cannot_be_marked() {
    let (_f, mut app) = findings_app(mixed_findings(), Some(BASE));
    press(&mut app, &[KeyCode::Tab]);
    assert_eq!(selected_path(&app), "docker://volume/pgdata");
    press(&mut app, &[KeyCode::Char(' ')]);
    assert!(marked(&app).is_empty());
    let msg = app.message.clone().unwrap();
    assert!(msg.contains("advice only"), "{msg}");
    let screen = render(&mut app, 80, 24, None);
    assert!(
        screen.lines().nth(22).unwrap().contains("advice only"),
        "{screen}"
    );
    // The next key clears it.
    press(&mut app, &[KeyCode::Down]);
    assert_eq!(app.message, None);
}

#[test]
fn marked_bytes_count_nested_findings_once() {
    let outer = hand_finding("stale-tree", "/home/me/scratch", 2 * GIB, Tier::Review);
    let inner = hand_finding(
        "cargo-target",
        "/home/me/scratch/app/target",
        GIB,
        Tier::Rebuildable,
    );
    let (_f, mut app) = findings_app(vec![outer, inner], None);
    press(
        &mut app,
        &[
            KeyCode::Tab,
            KeyCode::Char(' '),
            KeyCode::Down,
            KeyCode::Char(' '),
        ],
    );
    assert_eq!(marked(&app).len(), 2);
    assert_eq!(app.browser().unwrap().marked_bytes(), 2 * GIB);
}

#[test]
fn findings_list_with_marks_80x24() {
    let (_f, mut app) = marked_app(&[
        "/home/me/projects/diskwhy/target",
        "/home/me/projects/old-feature",
        "/home/me/.local/share/Trash",
    ]);
    press(&mut app, &[KeyCode::Up]);
    insta::assert_snapshot!(render(&mut app, 80, 24, None));
}

#[test]
fn p_with_nothing_marked_says_so() {
    let (_f, mut app) = findings_app(mixed_findings(), Some(BASE));
    press(&mut app, &[KeyCode::Tab, KeyCode::Char('p')]);
    assert_eq!(view(&app), View::Findings);
    assert!(app.take_request().is_none());
    assert!(
        app.message
            .as_deref()
            .unwrap()
            .starts_with("nothing marked")
    );
}

#[test]
fn p_builds_the_plan_of_the_marks_and_esc_keeps_them() {
    let f = crates_fixture();
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
    press(&mut app, &[KeyCode::Tab]);
    assert_eq!(shown_paths(&app).len(), 2);
    press(
        &mut app,
        &[KeyCode::Char(' '), KeyCode::Down, KeyCode::Char(' ')],
    );
    press(&mut app, &[KeyCode::Char('p')]);
    assert_eq!(view(&app), View::Plan);
    assert!(matches!(
        app.browser().unwrap().plan,
        PlanState::Building { .. }
    ));
    let building = render(&mut app, 80, 24, Some(&root));
    assert!(building.contains("from 2 marked findings"), "{building}");
    assert!(building.contains("checking guards"), "{building}");
    assert!(building.contains("rescanned 0 entries"), "{building}");

    run_build(&mut app, &Processes::default());
    let p = plan_of(&app);
    let app_target = root.join("app/target");
    assert_eq!(
        p.items
            .iter()
            .map(|i| i.finding.path.as_str())
            .collect::<Vec<_>>(),
        [
            app_target.to_str().unwrap(),
            root.join("lib/target").to_str().unwrap()
        ]
    );
    assert_eq!(p.selection.tier, None, "no tier ceiling, as with --select");
    assert!(p.blocked.is_empty());
    assert!(
        p.items[0]
            .finding
            .guards
            .iter()
            .any(|g| g.name == "in-use-cwd")
    );
    assert!(p.items[0].fingerprint.inode.is_some());
    assert_eq!(app.plan_view().unwrap().unusable(job::now()), None);
    let screen = render(&mut app, 80, 24, Some(&root));
    assert!(screen.contains("2 items, frees 4.0M"), "{screen}");
    assert!(screen.contains("pass   in-use-cwd"), "{screen}");

    // Scrolls, and Esc goes back to the list with the marks kept.
    press(&mut app, &[KeyCode::Down]);
    assert_eq!(app.plan_view().unwrap().scroll, 1);
    press(&mut app, &[KeyCode::Esc]);
    assert_eq!(view(&app), View::Findings);
    assert!(matches!(app.browser().unwrap().plan, PlanState::None));
    assert_eq!(marked(&app).len(), 2);
}

#[test]
fn p_rescans_and_reports_marks_that_are_gone() {
    let f = crates_fixture();
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
    press(
        &mut app,
        &[
            KeyCode::Tab,
            KeyCode::Char(' '),
            KeyCode::Down,
            KeyCode::Char(' '),
        ],
    );
    let paths = marked(&app);
    let app_target = root.join("app/target");
    let lib_target = root.join("lib/target");
    fs::remove_file(lib_target.join("CACHEDIR.TAG")).unwrap();
    let original_bytes = app
        .browser()
        .unwrap()
        .marked_findings()
        .find(|f| Path::new(&f.path) == app_target)
        .unwrap()
        .bytes;
    fs::write(app_target.join("extra"), vec![7u8; 2 * MIB]).unwrap();
    let before = job::now();
    press(&mut app, &[KeyCode::Char('p')]);
    run_build(&mut app, &Processes::default());
    let plan = plan_of(&app);
    let (created, _) = plan::validity_window(plan).unwrap();
    assert!((before..=job::now()).contains(&created));
    let [item] = plan.items.as_slice() else {
        panic!("expected one item, got {:?}", plan.items);
    };
    assert_eq!(Path::new(&item.finding.path), app_target);
    assert!(item.finding.bytes > original_bytes);
    assert_eq!(
        plan.selection.select,
        std::slice::from_ref(&item.finding.id)
    );
    let screen = render(&mut app, 120, 40, Some(&root));
    assert!(screen.contains("gone since the scan:"), "{screen}");
    assert!(
        screen.contains(&format!("{ROOT_PLACEHOLDER}/lib/target")),
        "{screen}"
    );

    press(&mut app, &[KeyCode::Esc]);
    assert_eq!(marked(&app), paths);
    assert_eq!(shown_paths(&app).len(), 2);
    fs::remove_file(app_target.join("CACHEDIR.TAG")).unwrap();
    press(&mut app, &[KeyCode::Char('p')]);
    run_build(&mut app, &Processes::default());
    assert_eq!(view(&app), View::Findings);
    assert!(app.plan_view().is_none());
    assert!(
        app.message
            .as_deref()
            .unwrap()
            .contains("all marked findings are gone")
    );
}

#[test]
fn p_prepares_the_roots_again_before_detecting() {
    let f = crates_fixture();
    let root = f.root();
    let original_parent = root.join("original");
    let moved_parent = root.join("moved");
    let stable = root.join("app");
    fs::create_dir(&original_parent).unwrap();
    fs::rename(root.join("lib"), original_parent.join("lib")).unwrap();
    let mut app = app_with(scan(&[&stable, &original_parent.join("lib")]));
    press(
        &mut app,
        &[
            KeyCode::Tab,
            KeyCode::Char(' '),
            KeyCode::Down,
            KeyCode::Char(' '),
        ],
    );
    assert_eq!(marked(&app).len(), 2);

    fs::rename(&original_parent, &moved_parent).unwrap();
    std::os::unix::fs::symlink(&moved_parent, &original_parent).unwrap();
    press(&mut app, &[KeyCode::Char('p')]);
    run_build(&mut app, &Processes::default());

    let plan = plan_of(&app);
    assert_eq!(plan.items.len(), 1);
    assert_eq!(
        Path::new(&plan.items[0].finding.path),
        stable.join("target")
    );
    let mut roots = plan.scan.roots.iter().map(Path::new).collect::<Vec<_>>();
    roots.sort();
    assert_eq!(
        roots,
        [stable.as_path(), moved_parent.join("lib").as_path()]
    );
    let screen = render(&mut app, 120, 40, Some(&root));
    assert!(
        screen.contains(&format!(
            "gone since the scan: {ROOT_PLACEHOLDER}/original/lib/target"
        )),
        "{screen}"
    );
}

#[test]
fn p_reports_a_mark_from_a_detector_that_did_not_run() {
    let f = crates_fixture();
    let root = f.root();
    let mut data = scan(&[&root]);
    let missed_path = root.join("node_modules");
    data.report.findings.push(hand_finding(
        "node-modules",
        missed_path.to_str().unwrap(),
        4096,
        Tier::Rebuildable,
    ));
    let mut app = app_with(data);
    press(
        &mut app,
        &[
            KeyCode::Tab,
            KeyCode::Char(' '),
            KeyCode::End,
            KeyCode::Char(' '),
            KeyCode::Char('p'),
        ],
    );
    run_build(&mut app, &Processes::default());
    assert_eq!(plan_of(&app).items.len(), 1);
    let screen = render(&mut app, 120, 40, Some(&root));
    assert!(
        screen.contains("not checked: node-modules did not run"),
        "{screen}"
    );
    assert!(!screen.contains("gone since the scan"), "{screen}");

    press(
        &mut app,
        &[
            KeyCode::Esc,
            KeyCode::Home,
            KeyCode::Char(' '),
            KeyCode::Char('p'),
        ],
    );
    run_build(&mut app, &Processes::default());
    assert!(app.plan_view().is_none());
    assert_eq!(view(&app), View::Findings);
    let message = app.message.as_deref().unwrap();
    assert!(
        message.contains("not checked: node-modules did not run"),
        "{message}"
    );
    assert!(message.contains(missed_path.to_str().unwrap()), "{message}");
}

#[test]
fn a_guard_blocks_a_marked_finding_in_the_plan() {
    let f = crates_fixture();
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
    press(
        &mut app,
        &[
            KeyCode::Tab,
            KeyCode::Char(' '),
            KeyCode::Down,
            KeyCode::Char(' '),
        ],
    );
    press(&mut app, &[KeyCode::Char('p')]);
    let procs = Processes {
        procs: vec![Proc {
            pid: 4242,
            name: "cargo".into(),
            cwd: Some(root.join("lib/target/debug")),
            open: Vec::new(),
        }],
        unreadable: 0,
    };
    run_build(&mut app, &procs);
    let p = plan_of(&app);
    assert_eq!(p.items.len(), 1);
    assert_eq!(p.blocked.len(), 1);
    assert_eq!(p.blocked[0].path, root.join("lib/target").to_str().unwrap());
    let screen = render(&mut app, 120, 40, Some(&root));
    assert!(screen.contains("blocked, not in the plan (1):"), "{screen}");
    assert!(
        screen.contains("blocked by in-use-cwd: working directory of cargo"),
        "{screen}"
    );
}

#[test]
fn p_reuses_the_running_plan_worker_after_esc_and_tab() {
    let (_f, mut app) = marked_app(&["/home/me/projects/diskwhy/target"]);
    press(&mut app, &[KeyCode::Char('p')]);
    let first = app.take_request().unwrap();
    first.progress.entries.store(42, Ordering::Relaxed);
    press(&mut app, &[KeyCode::Esc]);
    assert_eq!(view(&app), View::Findings);
    press(&mut app, &[KeyCode::Char('p')]);
    assert_eq!(marked(&app), ["/home/me/projects/diskwhy/target"]);
    assert_eq!(view(&app), View::Plan);
    assert!(app.take_request().is_none());
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("from 1 marked finding"), "{screen}");
    assert!(screen.contains("rescanned 42 entries"), "{screen}");

    press(&mut app, &[KeyCode::Tab]);
    assert_eq!(view(&app), View::Tree);
    press(
        &mut app,
        &[KeyCode::Tab, KeyCode::Char('p'), KeyCode::Char('w')],
    );
    assert_eq!(view(&app), View::Plan);
    assert!(app.take_request().is_none());
    assert!(app.plan_view().is_none());
    assert!(app.on_key(key(KeyCode::Char('q'))));

    app.plan_built(Ok(hand_build()), HOST, UID);
    assert_eq!(plan_of(&app), &hand_plan());
    press(&mut app, &[KeyCode::Esc, KeyCode::Char('p')]);
    assert!(app.take_request().is_some());
    press(&mut app, &[KeyCode::Esc]);
    app.plan_built(Ok(hand_build()), HOST, UID);
    assert_eq!(view(&app), View::Findings);
    assert!(app.plan_view().is_none());

    press(&mut app, &[KeyCode::Char('p')]);
    assert!(app.take_request().is_some());
    app.plan_built(Err("scan failed".into()), HOST, UID);
    assert_eq!(view(&app), View::Findings);
    assert!(app.message.as_deref().unwrap().contains("scan failed"));
}

#[test]
fn p_waits_then_builds_for_the_changed_marks() {
    let f = crates_fixture();
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
    press(
        &mut app,
        &[KeyCode::Tab, KeyCode::Char(' '), KeyCode::Char('p')],
    );
    let first = app.take_request().unwrap();

    press(
        &mut app,
        &[KeyCode::Esc, KeyCode::Char(' '), KeyCode::Char('p')],
    );
    assert_eq!(view(&app), View::Findings);
    assert!(app.take_request().is_none());
    assert!(app.message.as_deref().unwrap().contains("nothing marked"));

    press(
        &mut app,
        &[KeyCode::Down, KeyCode::Char(' '), KeyCode::Char('p')],
    );
    assert_eq!(view(&app), View::Plan);
    assert!(app.take_request().is_none());
    let screen = render(&mut app, 80, 24, Some(&root));
    assert!(
        screen.contains("waiting for the previous build to finish"),
        "{screen}"
    );

    let previous = first.build(Processes::default, HOST.into()).unwrap();
    assert_eq!(
        Path::new(&previous.plan.items[0].finding.path),
        root.join("app/target")
    );
    app.plan_built(Ok(previous), HOST, system::euid());
    press(&mut app, &[KeyCode::Char('w')]);
    assert!(app.plan_view().is_none());
    run_build(&mut app, &Processes::default());

    let plan = plan_of(&app);
    assert_eq!(plan.items.len(), 1);
    let finding = &plan.items[0].finding;
    assert_eq!(Path::new(&finding.path), root.join("lib/target"));
    assert_eq!(plan.selection.select, std::slice::from_ref(&finding.id));
}

#[test]
fn plan_preview_80x24() {
    let (_f, mut app) = preview_app();
    insta::assert_snapshot!(render_at(&mut app, 80, 24, None, PLAN_AT));
}

#[test]
fn plan_preview_120x40() {
    let (_f, mut app) = preview_app();
    render_at(&mut app, 80, 24, None, PLAN_AT);
    let screen = render_at(&mut app, 120, 40, None, PLAN_AT);
    assert!(screen.contains("warn   git-unpublished"), "{screen}");
    assert!(
        screen.contains("blocked by in-use-cwd: working directory of node (pid 4242)"),
        "{screen}"
    );
    insta::assert_snapshot!(screen);
}

#[test]
fn write_prompt_80x24() {
    let (_f, mut app) = preview_app();
    press(&mut app, &[KeyCode::Char('w')]);
    assert_eq!(
        app.plan_view().unwrap().prompt.as_deref(),
        Some(DEFAULT_PLAN_FILE)
    );
    insta::assert_snapshot!(render_at(&mut app, 80, 24, None, PLAN_AT));
}

#[test]
fn w_writes_the_plan_file_as_dwhy_plan_does() {
    let f = crates_fixture();
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
    press(
        &mut app,
        &[KeyCode::Tab, KeyCode::Char(' '), KeyCode::Char('p')],
    );
    run_build(&mut app, &Processes::default());
    let out = tempfile::tempdir().unwrap();
    let file = out.path().join("quick-plan.json");
    let path = file.to_str().unwrap();

    // Edit the default path; Esc cancels and writes nothing.
    press(&mut app, &[KeyCode::Char('w')]);
    press(&mut app, &[KeyCode::Backspace]);
    assert_eq!(
        app.plan_view().unwrap().prompt.as_deref(),
        Some("./dwhy-plan.jso")
    );
    assert!(!app.on_key(ctrl('u')));
    type_text(&mut app, path);
    press(&mut app, &[KeyCode::Esc]);
    assert!(app.plan_view().unwrap().prompt.is_none());
    assert_eq!(app.message.as_deref(), Some("no plan file written"));
    assert!(!file.exists());

    // Enter writes; `q` in the path is text, not quit.
    press(&mut app, &[KeyCode::Char('w')]);
    assert!(!app.on_key(ctrl('u')));
    type_text(&mut app, path);
    press(&mut app, &[KeyCode::Enter]);
    assert!(app.plan_view().unwrap().prompt.is_none());
    assert_eq!(app.message, Some(format!("wrote {path}")));
    let saved = fs::read_to_string(&file).unwrap();
    assert!(saved.ends_with('\n'));
    assert_eq!(&plan::parse(&saved).unwrap(), plan_of(&app));
}

#[test]
fn w_creates_a_long_basename_through_a_parent_symlink() {
    let (_f, mut app) = preview_app();
    let out = tempfile::tempdir().unwrap();
    let parent = out.path().join("parent");
    fs::create_dir(&parent).unwrap();
    let alias = out.path().join("alias");
    std::os::unix::fs::symlink(&parent, &alias).unwrap();
    let name = "p".repeat(255);
    let file = parent.join(&name);

    press(&mut app, &[KeyCode::Char('w')]);
    assert!(!app.on_key(ctrl('u')));
    type_text(&mut app, alias.join(&name).to_str().unwrap());
    press(&mut app, &[KeyCode::Enter]);
    let saved = fs::read_to_string(&file).unwrap();
    assert_eq!(&plan::parse(&saved).unwrap(), plan_of(&app));
    assert_eq!(fs::read_dir(parent).unwrap().count(), 1);
}

#[test]
fn w_requires_an_unused_path() {
    let (_f, mut app) = preview_app();
    let out = tempfile::tempdir().unwrap();
    let real = out.path().join("real.json");
    let original = b"keep this file";
    fs::write(&real, original).unwrap();
    let inode = fs::metadata(&real).unwrap().ino();
    let hardlink = out.path().join("baseline.json");
    fs::hard_link(&real, &hardlink).unwrap();
    let link = out.path().join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let dangling = out.path().join("dangling.json");
    std::os::unix::fs::symlink(out.path().join("nowhere.json"), &dangling).unwrap();
    let dir = out.path().to_str().unwrap();
    let dir_slash = format!("{dir}/");
    press(&mut app, &[KeyCode::Char('w')]);
    for path in [
        real.to_str().unwrap(),
        hardlink.to_str().unwrap(),
        link.to_str().unwrap(),
        dangling.to_str().unwrap(),
        dir,
        &dir_slash,
    ] {
        assert!(!app.on_key(ctrl('u')));
        type_text(&mut app, path);
        press(&mut app, &[KeyCode::Enter]);
        let message = format!("{path} exists; choose another name");
        assert_eq!(app.message.as_deref(), Some(message.as_str()));
        assert_eq!(app.plan_view().unwrap().prompt.as_deref(), Some(path));
        let screen = render(&mut app, 200, 24, None);
        assert!(screen.contains("exists; choose another name"), "{screen}");
        assert!(screen.contains(" write plan to: "), "{screen}");
        assert_eq!(fs::read(&real).unwrap(), original);
        assert_eq!(fs::metadata(&real).unwrap().ino(), inode);
    }
    assert_eq!(fs::read(&hardlink).unwrap(), original);
    assert_eq!(fs::metadata(&hardlink).unwrap().ino(), inode);
    assert_eq!(fs::read_link(&link).unwrap(), real);
    assert!(!out.path().join("nowhere.json").exists());

    let unused = out.path().join("new.json");
    assert!(!app.on_key(ctrl('u')));
    type_text(&mut app, unused.to_str().unwrap());
    press(&mut app, &[KeyCode::Enter]);
    assert!(app.plan_view().unwrap().prompt.is_none());
    let saved = fs::read_to_string(unused).unwrap();
    assert_eq!(&plan::parse(&saved).unwrap(), plan_of(&app));
}

#[test]
fn plan_file_opens_in_the_preview() {
    let plan = hand_plan();
    let file = PathBuf::from("/tmp/plans/dwhy-plan.json");
    let mut app = App::open_plan(plan.clone(), file.clone(), HOST, UID);
    let view = app.plan_view().unwrap();
    assert_eq!(view.unusable(PLAN_AT + 60), None);
    assert_eq!(view.file.as_deref(), Some(file.as_path()));
    let screen = render_at(&mut app, 80, 24, None, PLAN_AT + 60);
    assert!(
        screen.contains("plan /tmp/plans/dwhy-plan.json"),
        "{screen}"
    );
    assert!(!screen.contains("NOT USABLE"), "{screen}");
    // It is already a file; Esc has nothing to go back to; q quits.
    press(&mut app, &[KeyCode::Char('w'), KeyCode::Esc, KeyCode::Down]);
    assert!(app.plan_view().unwrap().prompt.is_none());
    assert_eq!(app.plan_view().unwrap().scroll, 1);
    press(&mut app, &[KeyCode::Char('w')]);
    assert!(app.message.as_deref().unwrap().contains("already a file"));
    assert!(app.on_key(key(KeyCode::Char('q'))));

    // `plan::usable` decides, as for `dwhy apply`.
    for (host, uid, now, why) in [
        ("other", UID, PLAN_AT, "made on testhost, not other"),
        (HOST, UID + 1, PLAN_AT, "made by uid 1000, not 1001"),
        (HOST, UID, PLAN_AT + plan::TTL_SECS, "expired at"),
    ] {
        let app = App::open_plan(plan.clone(), file.clone(), host, uid);
        let got = app.plan_view().unwrap().unusable(now).unwrap().to_string();
        assert!(got.contains(why), "{got}");
    }
}

#[test]
fn lossy_plan_root_is_refused_and_preview_shows_advice() {
    let mut plan = hand_plan();
    plan.scan.roots.push("/home/me/app�".into());
    plan.items.truncate(1);
    plan.blocked.clear();
    let f = &mut plan.items[0].finding;
    f.path = "/home/me/app�/target".into();
    f.recovery.how = Some("cargo build --manifest-path /home/me/app�/Cargo.toml".into());
    detect::block_lossy(std::slice::from_mut(f));

    for blocked in [false, true] {
        let mut plan = plan.clone();
        if blocked {
            plan.blocked.push(plan.items.remove(0).finding);
        }
        let mut app = App::open_plan(plan, "edited.json".into(), HOST, UID);
        let screen = render_at(&mut app, 120, 32, None, PLAN_AT + 60);
        assert!(
            screen.contains(
                "NOT USABLE: plan root /home/me/app� is not valid UTF-8; nothing applied"
            ),
            "{screen}"
        );
        assert!(
            screen.contains("rename the path that is not valid UTF-8 to valid UTF-8"),
            "{screen}"
        );
        assert!(
            screen.contains("by hand: the command names a path that is not valid UTF-8"),
            "{screen}"
        );
        assert!(!screen.contains("command withheld"), "{screen}");
    }
}

#[test]
fn an_open_preview_shows_the_capped_deadline_and_expires_at_it() {
    let mut plan = hand_plan();
    plan.expires_at = dwhy_core::detect::rfc3339(PLAN_AT + 86_400);
    let mut app = App::open_plan(plan, "edited.json".into(), HOST, UID);
    let deadline = PLAN_AT + 3600;
    let expiry = format!("expires {}", dwhy_core::detect::rfc3339(deadline));
    let before = render_at(&mut app, 80, 24, None, deadline - 1);
    assert!(before.contains(&expiry), "{before}");
    assert!(!before.contains("NOT USABLE"), "{before}");
    let expired = render_at(&mut app, 80, 24, None, deadline);
    assert!(
        expired.contains("NOT USABLE: the plan expired at"),
        "{expired}"
    );
    assert!(expired.contains(&expiry), "{expired}");
}

#[test]
fn unusable_plan_banner_80x24() {
    let file = PathBuf::from("/tmp/plans/dwhy-plan.json");
    let mut app = App::open_plan(hand_plan(), file, HOST, UID);
    insta::assert_snapshot!(render_at(
        &mut app,
        80,
        24,
        None,
        PLAN_AT + plan::TTL_SECS + 600
    ));
}

// ---------------------------------------------------------------------------
// M4d: the confirm dialog, apply and its results. Nothing here applies: the
// state machine hands out the apply job, and tests feed results back. Real
// applies on temp fixtures are in crates/dwhy-cli/tests/cli.rs and
// src/lib.rs.
// ---------------------------------------------------------------------------

/// The hand plan with its trash item in the `review` tier, as the trash
/// detector reports it: one review item and one rebuildable item.
fn review_plan() -> Plan {
    let mut plan = hand_plan();
    plan.items[1].finding.tier = Tier::Review;
    plan
}

fn review_id() -> String {
    review_plan().items[1].finding.id.clone()
}

/// `dwhy tui --plan` on the review plan, a minute after it was made.
fn dialog_app(dry_run: bool) -> App {
    let file = PathBuf::from("/tmp/plans/dwhy-plan.json");
    let mut app = App::open_plan(review_plan(), file, HOST, UID).with_options(Options {
        dry_run,
        ..Options::default()
    });
    app.clock = || PLAN_AT + 60;
    app
}

fn confirmed(app: &App) -> Vec<String> {
    let c = app.plan_view().unwrap().confirm.as_ref().unwrap();
    c.confirmed.iter().cloned().collect()
}

/// A finished apply of the review plan: the cargo target removed by its
/// command, the review item refused, and an item skipped.
fn hand_applied() -> Applied {
    let plan = review_plan();
    let item = |f: &Finding, outcome, detail: &str| ApplyItem {
        id: f.id.clone(),
        detector: f.detector.clone(),
        path: f.path.clone(),
        tier: f.tier,
        bytes: f.bytes,
        action: f.action.clone(),
        outcome,
        detail: detail.into(),
        guards: f.guards.clone(),
    };
    let cargo = &plan.items[0].finding;
    let trash = &plan.items[1].finding;
    let venv = hand_finding(
        "venv",
        "/home/me/projects/site/.venv",
        250 << 20,
        Tier::Rebuildable,
    );
    let items = vec![
        item(
            cargo,
            ApplyOutcome::Removed,
            &format!("ran {}", cargo.action.text),
        ),
        item(
            trash,
            ApplyOutcome::Refused,
            &format!("review items need a person's --confirm {}", trash.id),
        ),
        item(
            &venv,
            ApplyOutcome::Skipped,
            "changed since the plan: newest file 2026-11-19T09:00:30Z, was 2026-11-12T08:30:00Z",
        ),
    ];
    Applied {
        report: ApplyReport {
            schema: "diskwhy/v1".into(),
            tool: Tool::current(),
            host: HOST.into(),
            uid: UID,
            generated_at: dwhy_core::detect::rfc3339(PLAN_AT + 120),
            plan_created_at: plan.created_at.clone(),
            dry_run: false,
            max_tier: Tier::Review,
            confirm: Vec::new(),
            freed: cargo.bytes,
            items,
        },
        audit: Some("/tmp/state/diskwhy/audit.jsonl".into()),
        exit: 3,
    }
}

#[test]
fn x_opens_the_dialog_only_for_a_usable_plan() {
    let mut app = dialog_app(false);
    press(&mut app, &[KeyCode::Char('x')]);
    assert!(app.plan_view().unwrap().confirm.is_some());
    press(&mut app, &[KeyCode::Esc]);
    assert!(app.plan_view().unwrap().confirm.is_none());
    assert_eq!(app.message.as_deref(), Some("nothing applied"));
    assert!(app.take_apply().is_none());

    // `plan::usable` decides, as for `dwhy apply`; the status line says why.
    let file = PathBuf::from("/tmp/plans/dwhy-plan.json");
    for (host, uid, clock, why) in [
        (
            "other",
            UID,
            (|| PLAN_AT + 60) as fn() -> i64,
            "made on testhost, not other",
        ),
        (HOST, UID + 1, || PLAN_AT + 60, "made by uid 1000, not 1001"),
        (HOST, UID, || PLAN_AT + plan::TTL_SECS, "expired at"),
    ] {
        let mut app = App::open_plan(review_plan(), file.clone(), host, uid);
        app.clock = clock;
        press(&mut app, &[KeyCode::Char('x')]);
        assert!(app.plan_view().unwrap().confirm.is_none());
        let msg = app.message.clone().unwrap();
        assert!(msg.starts_with("cannot apply: "), "{msg}");
        assert!(msg.contains(why), "{msg}");
        let screen = render_at(&mut app, 120, 24, None, PLAN_AT + 60);
        assert!(screen.contains("cannot apply: "), "{screen}");
    }

    // A preview built from marks opens it too; Tab does not leave it.
    let (_f, mut app) = preview_app();
    app.clock = || PLAN_AT + 60;
    press(&mut app, &[KeyCode::Char('x'), KeyCode::Tab]);
    assert!(app.plan_view().unwrap().confirm.is_some());
    press(&mut app, &[KeyCode::Esc]);
    assert_eq!(app.browser().unwrap().view, View::Plan);
}

#[test]
fn space_confirms_only_review_items() {
    let mut app = dialog_app(false);
    press(&mut app, &[KeyCode::Char('x'), KeyCode::Char(' ')]);
    assert!(
        confirmed(&app).is_empty(),
        "the rebuildable item has no box"
    );
    assert!(
        app.message
            .as_deref()
            .unwrap()
            .contains("only review items"),
        "{:?}",
        app.message
    );
    press(&mut app, &[KeyCode::Down, KeyCode::Char(' ')]);
    assert_eq!(confirmed(&app), [review_id()]);
    press(&mut app, &[KeyCode::Char(' ')]);
    assert!(confirmed(&app).is_empty(), "Space again unticks it");
    press(&mut app, &[KeyCode::Char(' '), KeyCode::Down, KeyCode::Up]);
    assert_eq!(confirmed(&app), [review_id()]);
}

#[test]
fn y_and_d_start_the_apply_with_the_ticked_review_items() {
    // Unticked: `--max-tier review` with no `--confirm`, so core refuses it.
    let mut app = dialog_app(false);
    press(&mut app, &[KeyCode::Char('x'), KeyCode::Char('y')]);
    let job = app.take_apply().expect("y asks for an apply");
    assert!(!job.dry_run);
    assert_eq!(job.policy.max_tier, Tier::Review);
    assert!(job.policy.confirm.is_empty());
    assert_eq!(job.plan, review_plan());
    let v = app.apply_view().expect("the apply screen is shown");
    assert!(v.result.is_none() && !v.dry_run);
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("rescanning…"), "{screen}");
    assert!(
        screen.contains("q quit after the item in progress"),
        "{screen}"
    );
    // Keys other than q do nothing while it runs.
    press(&mut app, &[KeyCode::Enter, KeyCode::Esc]);
    assert!(app.take_scan().is_none());
    assert!(app.apply_view().unwrap().result.is_none());

    // Ticked: `--confirm <id>`.
    let mut app = dialog_app(false);
    press(
        &mut app,
        &[
            KeyCode::Char('x'),
            KeyCode::End,
            KeyCode::Char(' '),
            KeyCode::Char('y'),
        ],
    );
    let job = app.take_apply().unwrap();
    assert_eq!(job.policy.confirm, [review_id()]);

    // d is a dry run with the same policy.
    let mut app = dialog_app(false);
    press(
        &mut app,
        &[
            KeyCode::Char('x'),
            KeyCode::End,
            KeyCode::Char(' '),
            KeyCode::Char('d'),
        ],
    );
    let job = app.take_apply().unwrap();
    assert!(job.dry_run);
    assert_eq!(job.policy.confirm, [review_id()]);
    assert!(app.apply_view().unwrap().dry_run);

    // Time passes in the dialog: y checks the plan again.
    let mut app = dialog_app(false);
    press(&mut app, &[KeyCode::Char('x')]);
    app.clock = || PLAN_AT + plan::TTL_SECS;
    press(&mut app, &[KeyCode::Char('y')]);
    assert!(app.take_apply().is_none());
    assert!(app.plan_view().unwrap().confirm.is_none());
    assert!(app.message.as_deref().unwrap().contains("expired at"));
}

#[test]
fn a_dry_run_session_makes_y_a_dry_run() {
    let mut app = dialog_app(true);
    assert!(render(&mut app, 80, 24, None).starts_with("\" DRY RUN  dwhy  plan "));
    press(&mut app, &[KeyCode::Char('x')]);
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("y dry run · d dry run"), "{screen}");
    press(&mut app, &[KeyCode::Char('y')]);
    assert!(app.take_apply().unwrap().dry_run);
    assert!(render(&mut app, 80, 24, None).contains(" DRY RUN "));
}

#[test]
fn enter_on_the_results_rescans_the_same_roots_and_clears_the_marks() {
    let f = crates_fixture();
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
    app.options = opts(vec![root.clone()]);
    press(
        &mut app,
        &[KeyCode::Tab, KeyCode::Char(' '), KeyCode::Char('p')],
    );
    run_build(&mut app, &Processes::default());
    press(&mut app, &[KeyCode::Char('x'), KeyCode::Char('y')]);
    assert!(app.take_apply().is_some());
    app.apply_done(Ok(hand_applied()));

    // Esc stays: the plan was applied.
    press(&mut app, &[KeyCode::Esc]);
    assert!(app.apply_view().is_some());
    assert!(app.message.as_deref().unwrap().contains("Enter rescans"));

    press(&mut app, &[KeyCode::Enter]);
    let job = app.take_scan().expect("Enter asks for a rescan");
    assert_eq!(job.options.paths, std::slice::from_ref(&root));
    assert_eq!(job.options.detectors, opts(Vec::new()).detectors);
    assert!(matches!(app.state, State::Scanning { .. }));
    let screen = render(&mut app, 80, 24, Some(&root));
    assert!(screen.contains("Scanning"), "{screen}");
    let data = job::scan(&job.options, &job.progress, &mut |_| {}).unwrap();
    app.finish(data);
    assert_eq!(view(&app), View::Tree);
    assert!(marked(&app).is_empty(), "marks are cleared");
    assert_eq!(app.browser().unwrap().data.report.findings.len(), 2);
}

#[test]
fn a_plan_session_rescans_the_plans_roots_and_esc_returns_after_a_dry_run() {
    let mut app = dialog_app(false);
    press(
        &mut app,
        &[
            KeyCode::Char('x'),
            KeyCode::End,
            KeyCode::Char(' '),
            KeyCode::Char('d'),
        ],
    );
    assert!(app.take_apply().is_some());
    let mut dry = hand_applied();
    dry.report.dry_run = true;
    dry.audit = None;
    app.apply_done(Ok(dry));
    // Nothing was removed: Esc goes back to the dialog, ticks kept.
    press(&mut app, &[KeyCode::Esc]);
    assert_eq!(confirmed(&app), [review_id()]);
    press(&mut app, &[KeyCode::Char('y')]);
    assert!(app.take_apply().is_some());
    app.apply_done(Err(ApplyFailed {
        message: "cannot read the mount table: gone".into(),
        exit: 1,
    }));
    let screen = render(&mut app, 80, 24, None);
    assert!(screen.contains("dwhy apply would exit 1"), "{screen}");
    assert!(screen.contains("Esc back to the dialog"), "{screen}");
    press(&mut app, &[KeyCode::Enter]);
    let job = app.take_scan().unwrap();
    assert_eq!(job.options.paths, [PathBuf::from("/home/me")]);
    assert!(!job.options.cross_filesystems);
    assert_eq!(job.options.detectors, None);
}

#[test]
fn confirm_dialog_80x24() {
    let mut app = dialog_app(false);
    press(&mut app, &[KeyCode::Char('x')]);
    insta::assert_snapshot!(render_at(&mut app, 80, 24, None, PLAN_AT + 60));
}

#[test]
fn confirm_dialog_confirmed_80x24() {
    let mut app = dialog_app(false);
    press(
        &mut app,
        &[KeyCode::Char('x'), KeyCode::Down, KeyCode::Char(' ')],
    );
    insta::assert_snapshot!(render_at(&mut app, 80, 24, None, PLAN_AT + 60));
}

#[test]
fn confirm_dialog_120x40() {
    let mut app = dialog_app(false);
    press(&mut app, &[KeyCode::Char('x')]);
    insta::assert_snapshot!(render_at(&mut app, 120, 40, None, PLAN_AT + 60));
}

#[test]
fn confirm_dialog_confirmed_120x40() {
    let mut app = dialog_app(false);
    press(
        &mut app,
        &[KeyCode::Char('x'), KeyCode::Down, KeyCode::Char(' ')],
    );
    insta::assert_snapshot!(render_at(&mut app, 120, 40, None, PLAN_AT + 60));
}

#[test]
fn dry_run_header_80x24() {
    let mut app = dialog_app(true);
    press(&mut app, &[KeyCode::Char('x')]);
    insta::assert_snapshot!(render_at(&mut app, 80, 24, None, PLAN_AT + 60));
}

#[test]
fn apply_results_80x24() {
    let mut app = dialog_app(false);
    press(&mut app, &[KeyCode::Char('x'), KeyCode::Char('y')]);
    assert!(app.take_apply().is_some());
    app.apply_done(Ok(hand_applied()));
    insta::assert_snapshot!(render_at(&mut app, 80, 24, None, PLAN_AT + 120));
}
