//! The TUI as a state machine on temp-dir fixtures, rendered with ratatui's
//! TestBackend. No terminal and no pty.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dwhy_core::report::FsReport;
use dwhy_core::scan::Progress;
use dwhy_tui::app::{App, SizeMode};
use dwhy_tui::job::{self, Mark, Options, Scanned};
use dwhy_tui::ui;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

const MIB: usize = 1 << 20;
/// What the fixture root is replaced with on screen (same length, so
/// alignment is unchanged).
const ROOT_PLACEHOLDER: &str = "/tmp/dwhyXXXXXX";

/// A fixture under /tmp with a fixed-length name (`/tmp/dwhy` and six random
/// characters), so screens differ only in those characters. Sizes are
/// chosen so the rounded figures do not depend on the filesystem's
/// directory block sizes.
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
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| ui::draw(f, app)).unwrap();
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
        &[KeyCode::Down, KeyCode::Enter, KeyCode::Char('a')],
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
    assert_eq!(b.rows[2].mark, Some(Mark::Unreadable));
    assert_eq!(b.rows[2].size, 0);
    insta::assert_snapshot!(render(&mut app, 120, 40, Some(&root)));
}

#[test]
fn navigation() {
    let f = fixture(false);
    let root = f.root();
    let mut app = app_with(scan(&[&root]));
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
    press(&mut app, &[KeyCode::Down, KeyCode::Enter]);
    let b = app.browser().unwrap();
    let locked = b
        .rows
        .iter()
        .find(|r| b.label(r) == "locked/")
        .expect("listed, not dropped");
    assert_eq!(locked.mark, Some(Mark::Unreadable));
    assert!(render(&mut app, 80, 24, None).contains("locked/  [unreadable]"));
    // Inside it: nothing to list, and the screen says why.
    press(&mut app, &[KeyCode::End]);
    while selected(&app) != "locked/" {
        press(&mut app, &[KeyCode::Up]);
    }
    press(&mut app, &[KeyCode::Enter]);
    for mode in [SizeMode::Allocated, SizeMode::Apparent] {
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
