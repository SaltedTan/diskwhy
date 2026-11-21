//! diskwhy terminal UI (`dwhy`, `dwhy tui`).
//!
//! [`run`] scans in a background thread with the same dwhy-core pipeline as
//! `dwhy scan` ([`job`]), then browses the directory tree and the findings.
//! The UI is a state machine ([`app::App`]) fed key events and scan messages; [`ui::draw`]
//! renders it, so tests use ratatui's `TestBackend` and no terminal.
//!
//! M4a: the tree browser. M4b: the findings list and detail view. M4c:
//! marking findings, the plan preview (built with core `plan::build` on a
//! worker thread) and plan files: `w` writes one,
//! [`run_plan`] opens one. M4d runs apply on a worker thread through
//! [`job::ApplyJob`]. See “TUI details” in `docs/DESIGN.md` for the confirmation
//! and results screens, dry runs and quitting during apply.

pub mod app;
pub mod job;
pub mod ui;

use std::io::{self, IsTerminal, Write};
use std::panic;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use crossterm::event::{self, Event};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use dwhy_core::apply;
use dwhy_core::guard::Processes;
use dwhy_core::scan::Progress;
use dwhy_core::system;
use ratatui::Terminal;
use ratatui::backend::{Backend, CrosstermBackend};
use signal_hook::SigId;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

pub use app::App;
/// The key events [`App::on_key`] takes, for driving it without a terminal.
pub use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
pub use job::{Options, Scanned, Stage};

use job::{APPLY_STOP_REQUESTED, Applied, ApplyFailed, ApplyProgress};

pub type Error = Box<dyn std::error::Error>;

/// How often the screen refreshes while waiting for keys (scan progress).
const TICK: Duration = Duration::from_millis(100);

enum Msg {
    Stage(Stage),
    Done(Result<Box<job::ScanOutcome>, String>),
}

type Built = (String, Result<job::BuiltPlan, String>);
type ApplyResult = Result<Applied, ApplyFailed>;

/// Opens the TUI: checks there is a terminal, scans `opts` in a background
/// thread, and browses the result until the person quits.
pub fn run(opts: Options) -> Result<u8, Error> {
    need_terminal()?;
    let signal = Termination::register()?;
    let progress = Arc::new(Progress::default());
    let mut app =
        App::new(app::root_labels(&opts.paths), progress.clone()).with_options(opts.clone());
    run_terminal(&mut app, &signal, || {
        spawn_scan(move |stage| {
            job::scan(&opts, &progress, stage).map(|data| job::ScanOutcome {
                scanned: Some(data),
                removed: Vec::new(),
                unavailable: Vec::new(),
            })
        })
    })
}

/// `dwhy tui --plan FILE`: reads and parses the plan (failing before the
/// terminal is touched), then previews it with no scan. `opts` gives the
/// session's settings (its paths are not used: the plan names its roots).
pub fn run_plan(file: &Path, opts: Options) -> Result<u8, Error> {
    let plan = job::read_plan(file)?;
    need_terminal()?;
    let signal = Termination::register()?;
    let mut app = App::open_plan(
        plan,
        file.to_path_buf(),
        &system::hostname(),
        system::euid(),
    )
    .with_options(opts);
    run_terminal(&mut app, &signal, || Ok(mpsc::channel().1))
}

fn need_terminal() -> Result<(), Error> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "the TUI needs a terminal (stdin and stdout); use `dwhy scan` (or `dwhy scan --json`) instead"
                .into(),
        );
    }
    Ok(())
}

fn run_terminal(
    app: &mut App,
    signal: &Termination,
    start_scan: impl FnOnce() -> io::Result<mpsc::Receiver<Msg>>,
) -> Result<u8, Error> {
    let result = (|| -> Result<(), Error> {
        let _guard = TerminalGuard::enter()?;
        let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        term.clear()?;
        let rx = start_scan()?;
        let result = event_loop(&mut term, app, &rx, signal, event::poll, event::read);
        // After a hangup the terminal is gone. Terminal's drop would then
        // fail to show the cursor and eprintln! about it, and printing to a
        // closed terminal panics.
        if term.show_cursor().is_err() {
            std::mem::forget(term);
        }
        result
    })();
    for error in &app.audit_errors {
        // Not eprintln!: it panics when the terminal has hung up.
        let _ = writeln!(io::stderr(), "dwhy: error: {}", error.escape_debug());
    }
    if !app.audit_errors.is_empty() {
        return result.map(|()| 1);
    }
    match signal.exit_code() {
        Some(code) => Ok(code),
        None => result.map(|()| 0),
    }
}

/// Scans in a background thread. Not joined: quitting mid-scan leaves it
/// to end with the process.
fn spawn_scan(
    scan: impl FnOnce(&mut dyn FnMut(Stage)) -> Result<job::ScanOutcome, String> + Send + 'static,
) -> io::Result<mpsc::Receiver<Msg>> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("dwhy-tui-scan".into())
        .spawn(move || {
            let res = scan(&mut |s| {
                let _ = tx.send(Msg::Stage(s));
            });
            let _ = tx.send(Msg::Done(res.map(Box::new)));
        })?;
    Ok(rx)
}

/// The apply worker. Dropping it asks the apply to stop and waits for it:
/// the item in progress (a removal or a command) finishes, no other runs.
/// Never left to end with the process, which would cut a removal short.
struct ApplyWorker {
    progress: Arc<ApplyProgress>,
    handle: Option<JoinHandle<ApplyResult>>,
}

impl ApplyWorker {
    fn running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    fn finish(mut self, app: &mut App) -> Result<(), Error> {
        let result = self
            .handle
            .take()
            .unwrap()
            .join()
            .map_err(|_| "the apply worker panicked")?;
        app.apply_done(result);
        Ok(())
    }
}

impl Drop for ApplyWorker {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            self.progress.stop();
            let _ = h.join();
        }
    }
}

fn event_loop<B: Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
    rx: &mpsc::Receiver<Msg>,
    signal: &Termination,
    poll: impl FnMut(Duration) -> io::Result<bool>,
    read: impl FnMut() -> io::Result<Event>,
) -> Result<(), Error>
where
    B::Error: 'static,
{
    app.apply_stop = signal.flag.clone();
    let mut workers = Workers::default();
    let result = run_loop(term, app, rx, signal, poll, read, &mut workers);
    if let Some(w) = workers.apply {
        if w.running() {
            w.progress.stop();
            app.stopping();
            let _ = term.draw(|f| ui::draw(f, app));
        }
        w.finish(app)?;
    }
    result
}

/// The workers the event loop started: the apply, and plan builds, whose
/// results arrive on `built`.
struct Workers {
    apply: Option<ApplyWorker>,
    built: (mpsc::Sender<Built>, mpsc::Receiver<Built>),
}

impl Default for Workers {
    fn default() -> Self {
        Self {
            apply: None,
            built: mpsc::channel(),
        }
    }
}

fn run_loop<B: Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
    rx: &mpsc::Receiver<Msg>,
    signal: &Termination,
    mut poll: impl FnMut(Duration) -> io::Result<bool>,
    mut read: impl FnMut() -> io::Result<Event>,
    workers: &mut Workers,
) -> Result<(), Error>
where
    B::Error: 'static,
{
    let Workers {
        apply: worker,
        built: (built_tx, built_rx),
    } = workers;
    // The rescan after an apply, once one started.
    let mut rescan: Option<mpsc::Receiver<Msg>> = None;
    while signal.exit_code().is_none() {
        term.draw(|f| ui::draw(f, app))?;
        let ready = poll(TICK)?;
        if signal.exit_code().is_some() {
            return Ok(());
        }
        // Keys first: a key pressed while a result waits acts on the screen
        // drawn above, not on a result the person has not seen.
        if ready
            && let Event::Key(key) = read()?
            && app.on_key(key)
        {
            return Ok(());
        }
        while let Ok((host, plan)) = built_rx.try_recv() {
            app.plan_built(plan, &host, system::euid());
        }
        if worker.as_ref().is_some_and(|w| !w.running()) {
            worker.take().unwrap().finish(app)?;
        }
        if let Some(job) = app.take_request() {
            let tx = built_tx.clone();
            // Guards read /proc and run git. Not joined, like the scan.
            std::thread::Builder::new()
                .name("dwhy-tui-plan".into())
                .spawn(move || {
                    let host = system::hostname();
                    let plan = job.build(Processes::read, host.clone());
                    let _ = tx.send((host, plan));
                })?;
        }
        if let Some(job) = app.take_apply() {
            let progress = job.progress.clone();
            let handle = std::thread::Builder::new()
                .name("dwhy-tui-apply".into())
                .spawn(move || {
                    let env = apply::Env::from_system();
                    job.run(Processes::read, &env)
                })?;
            *worker = Some(ApplyWorker {
                progress,
                handle: Some(handle),
            });
        }
        if let Some(job) = app.take_scan() {
            rescan = Some(spawn_scan(move |stage| job.run(stage))?);
        }
        let rx = rescan.as_ref().unwrap_or(rx);
        loop {
            match rx.try_recv() {
                Ok(Msg::Stage(s)) => app.set_stage(s),
                Ok(Msg::Done(Ok(outcome))) => app.scan_done(*outcome),
                Ok(Msg::Done(Err(e))) => return Err(format!("scan failed: {e}").into()),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if matches!(app.state, app::State::Scanning { .. }) {
                        return Err("the scan stopped unexpectedly".into());
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct Termination {
    flag: Arc<AtomicUsize>,
    registrations: Vec<SigId>,
}

impl Termination {
    fn register() -> io::Result<Self> {
        let mut signal = Self::default();
        for num in [SIGHUP, SIGINT, SIGTERM] {
            signal.registrations.push(signal_hook::flag::register_usize(
                num,
                signal.flag.clone(),
                num as usize,
            )?);
        }
        Ok(signal)
    }

    fn exit_code(&self) -> Option<u8> {
        match self.flag.load(Ordering::Relaxed) {
            0 | APPLY_STOP_REQUESTED => None,
            num => Some(128 + num as u8),
        }
    }
}

impl Drop for Termination {
    fn drop(&mut self) {
        for id in self.registrations.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

/// Raw mode and the alternate screen, undone on drop and by a panic hook
/// that restores the terminal before the panic message is printed.
struct TerminalGuard {
    prev: Arc<PanicHook>,
}

type PanicHook = Box<dyn Fn(&panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

impl TerminalGuard {
    fn enter() -> io::Result<TerminalGuard> {
        let prev: Arc<PanicHook> = Arc::new(panic::take_hook());
        let chained = prev.clone();
        panic::set_hook(Box::new(move |info| {
            restore();
            chained(info);
        }));
        // From here on, a failure must still restore what was changed.
        let guard = TerminalGuard { prev };
        terminal::enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
        // Put back the hook that was there before. Not while unwinding:
        // set_hook panics then, and a panic in a destructor aborts.
        if !std::thread::panicking() {
            let prev = self.prev.clone();
            panic::set_hook(Box::new(move |info| prev(info)));
        }
    }
}

/// Leaves the alternate screen and raw mode. Safe to call more than once.
fn restore() {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;

    #[test]
    fn termination_flag_requests_quit_with_signal_status() {
        let signal = Termination::default();
        assert_eq!(signal.exit_code(), None);
        for (num, status) in [(SIGHUP, 129), (SIGINT, 130), (SIGTERM, 143)] {
            signal.flag.store(num as usize, Ordering::Relaxed);
            assert_eq!(signal.exit_code(), Some(status));
        }
    }

    #[test]
    fn pending_signal_quits_before_drawing_or_polling() {
        let signal = Termination::default();
        signal.flag.store(SIGTERM as usize, Ordering::Relaxed);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let blank = term.backend().to_string();
        let mut app = App::new(vec![".".into()], Arc::new(Progress::default()));
        let (_tx, rx) = mpsc::channel();
        event_loop(
            &mut term,
            &mut app,
            &rx,
            &signal,
            |_| panic!("polled after termination"),
            || panic!("read after termination"),
        )
        .unwrap();
        assert_eq!(term.backend().to_string(), blank);
    }

    #[test]
    fn signal_during_poll_quits_before_reading_events_or_scan_messages() {
        for ready in [false, true] {
            let signal = Termination::default();
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            let mut app = App::new(vec![".".into()], Arc::new(Progress::default()));
            let (tx, rx) = mpsc::channel();
            tx.send(Msg::Done(Err(
                "processed scan result after termination".into()
            )))
            .unwrap();
            event_loop(
                &mut term,
                &mut app,
                &rx,
                &signal,
                |_| {
                    signal.flag.store(SIGINT as usize, Ordering::Relaxed);
                    Ok(ready)
                },
                || panic!("read after termination"),
            )
            .unwrap();
            assert!(term.backend().to_string().contains("Scanning"));
            assert!(matches!(rx.try_recv(), Ok(Msg::Done(Err(_)))));
        }
    }

    /// Two cargo targets under a temp dir, cleaned by a fake `cargo` that
    /// prints on stdout and stderr, marks that it started, takes a second,
    /// and removes only the target dir it is given inside the fixture.
    struct Crates {
        _t: tempfile::TempDir,
        base: std::path::PathBuf,
    }

    impl Crates {
        fn new() -> Crates {
            use std::os::unix::fs::PermissionsExt;
            let t = tempfile::tempdir().unwrap();
            let base = std::fs::canonicalize(t.path()).unwrap();
            let work = base.join("work");
            for (name, size) in [("app", 3 << 20), ("lib", 1 << 20)] {
                let c = work.join(name);
                std::fs::create_dir_all(c.join("target/debug")).unwrap();
                std::fs::write(c.join("Cargo.toml"), "[package]\n").unwrap();
                std::fs::write(
                    c.join("target/CACHEDIR.TAG"),
                    "Signature: 8a477f597d28d172789f06886806bc55\n# created by cargo.\n",
                )
                .unwrap();
                std::fs::write(c.join("target/debug/out"), vec![6u8; size]).unwrap();
            }
            let cargo = base.join("cargo");
            std::fs::write(
                &cargo,
                format!(
                    "#!/bin/sh\n\
                     echo \"fake-cargo-stdout $*\"\n\
                     echo \"fake-cargo-stderr $*\" >&2\n\
                     : > '{base}/started'\n\
                     while [ -e '{base}/hold' ]; do sleep 0.01; done\n\
                     sleep 1\n\
                     [ \"$1\" = clean ] && [ \"$4\" = --target-dir ] || exit 9\n\
                     case \"$5\" in\n  '{work}'/*) /bin/rm -rf -- \"$5\" ;;\n  *) exit 9 ;;\nesac\n",
                    base = base.display(),
                    work = work.display(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
            Crates { _t: t, base }
        }

        fn options(&self) -> Options {
            use dwhy_core::report::{DockerSocket, ToolStatus};
            Options {
                paths: vec![self.base.join("work")],
                detectors: Some(vec!["cargo-target".into()]),
                threads: 2,
                audit_log: Some(self.base.join("state/audit.jsonl")),
                context: Some(dwhy_core::detect::DetectContext {
                    uid: system::euid(),
                    root: false,
                    home: None,
                    now: 0,
                    tools: vec![ToolStatus {
                        name: "cargo".into(),
                        path: None,
                        off_path: Some(self.base.join("cargo").to_str().unwrap().into()),
                        enables: vec![],
                    }],
                    docker_socket: DockerSocket {
                        path: "/nonexistent".into(),
                        exists: false,
                        accessible: false,
                    },
                    docker: dwhy_core::docker::Source::none(),
                }),
                ..Options::default()
            }
        }

        /// `dwhy tui --plan` on a plan of both targets.
        fn app(&self) -> App {
            let opts = self.options();
            self.open_plan(&opts, opts.clone(), 2)
        }

        fn open_plan(&self, scope: &Options, launch: Options, items: usize) -> App {
            let scanned = job::scan(scope, &Progress::default(), &mut |_| {}).unwrap();
            assert_eq!(scanned.report.findings.len(), 2);
            let built = job::PlanJob {
                options: scanned.plan_options,
                progress: Default::default(),
                marks: scanned
                    .report
                    .findings
                    .iter()
                    .take(items)
                    .map(Into::into)
                    .collect(),
            }
            .build(Processes::default, system::hostname())
            .unwrap();
            let file = self.base.join("plan.json");
            App::open_plan(built.plan, file, &system::hostname(), system::euid())
                .with_options(launch)
        }
    }

    fn key(c: char) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    #[test]
    fn apply_progress_keys_do_not_act_on_unseen_results() {
        let fixture = Crates::new();
        for code in [KeyCode::Enter, KeyCode::Esc] {
            let mut app = fixture.app();
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            for c in ['x', 'd'] {
                term.draw(|f| ui::draw(f, &mut app)).unwrap();
                assert!(!app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)));
            }
            let progress = app.take_apply().unwrap().progress;
            let handle = std::thread::spawn(|| {
                Err(ApplyFailed {
                    message: "fixture apply failure".into(),
                    exit: 1,
                    audit_error: false,
                })
            });
            while !handle.is_finished() {
                std::thread::yield_now();
            }
            let mut workers = Workers {
                apply: Some(ApplyWorker {
                    progress,
                    handle: Some(handle),
                }),
                ..Workers::default()
            };
            let (_tx, rx) = mpsc::channel();
            let mut keys = [
                Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
                key('q'),
            ]
            .into_iter();
            run_loop(
                &mut term,
                &mut app,
                &rx,
                &Termination::default(),
                |_| Ok(true),
                || Ok(keys.next().unwrap()),
                &mut workers,
            )
            .unwrap();
            assert!(workers.apply.is_none());
            assert!(app.take_scan().is_none());
            let screen = term.backend().to_string();
            assert!(screen.contains("dry run results"), "{screen}");
            assert!(screen.contains("fixture apply failure"), "{screen}");
        }
    }

    /// Keys pressed while a finished plan build waits in the channel act
    /// on the progress screen the person saw: `w` opens no save prompt,
    /// and Esc or Tab leave the plan view, discarding the result without
    /// starting a build for marks changed meanwhile.
    #[test]
    fn plan_build_keys_do_not_act_on_an_unseen_preview() {
        use app::{PlanState, View};
        let fixture = Crates::new();
        let host = system::hostname();
        for (code, change_marks) in [
            (KeyCode::Char('w'), false),
            (KeyCode::Esc, false),
            (KeyCode::Tab, false),
            (KeyCode::Esc, true),
            (KeyCode::Tab, true),
        ] {
            let mut app = App::new(Vec::new(), Arc::new(Progress::default()));
            app.finish(job::scan(&fixture.options(), &Progress::default(), &mut |_| {}).unwrap());
            let press = |app: &mut App, codes: &[KeyCode]| {
                for &c in codes {
                    assert!(!app.on_key(KeyEvent::new(c, KeyModifiers::NONE)));
                }
            };
            press(
                &mut app,
                &[
                    KeyCode::Tab,
                    KeyCode::Char(' '),
                    KeyCode::Down,
                    KeyCode::Char(' '),
                    KeyCode::Char('p'),
                ],
            );
            let job = app.take_request().unwrap();
            if change_marks {
                // Back to the list, unmark one, and `p` again: it waits
                // for the running build.
                press(
                    &mut app,
                    &[KeyCode::Esc, KeyCode::Char(' '), KeyCode::Char('p')],
                );
                assert!(app.take_request().is_none());
            }
            let mut workers = Workers::default();
            let plan = job.build(Processes::default, host.clone());
            assert!(plan.is_ok(), "{plan:?}");
            workers.built.0.send((host.clone(), plan)).unwrap();

            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            term.draw(|f| ui::draw(f, &mut app)).unwrap();
            let progress = term.backend().to_string();
            let waiting = if change_marks {
                "waiting for the previous build"
            } else {
                "Building the plan"
            };
            assert!(progress.contains(waiting), "{progress}");
            let (_tx, rx) = mpsc::channel();
            let mut keys = [
                Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
                key('q'),
            ]
            .into_iter();
            run_loop(
                &mut term,
                &mut app,
                &rx,
                &Termination::default(),
                |_| Ok(true),
                || Ok(keys.next().unwrap()),
                &mut workers,
            )
            .unwrap();
            assert!(app.take_request().is_none());
            let b = app.browser().unwrap();
            if code == KeyCode::Char('w') {
                let view = app.plan_view().expect("the preview is shown after the key");
                assert!(view.prompt.is_none(), "w acted on an unseen preview");
                let screen = term.backend().to_string();
                assert!(screen.contains("w write plan"), "{screen}");
            } else {
                assert!(app.plan_view().is_none());
                let expected = if code == KeyCode::Tab {
                    View::Tree
                } else {
                    View::Findings
                };
                assert_eq!(b.view, expected);
                assert!(
                    matches!(b.plan, PlanState::None),
                    "the result is discarded and no build starts: {:?}",
                    b.plan
                );
            }
        }
    }

    #[test]
    fn apply_audit_path_and_open_failures_are_retained_on_quit() {
        let fixture = Crates::new();
        for (path, expected) in [
            (None, "cannot place the audit log"),
            (Some(fixture.base.join("work")), "cannot open the audit log"),
        ] {
            let mut app = fixture.app();
            app.options.audit_log = path;
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            let (_tx, rx) = mpsc::channel();
            let mut keys = [key('x'), key('y'), key('q')].into_iter();
            event_loop(
                &mut term,
                &mut app,
                &rx,
                &Termination::default(),
                |_| Ok(true),
                || Ok(keys.next().unwrap()),
            )
            .unwrap();
            assert_eq!(app.audit_errors.len(), 1, "{:?}", app.audit_errors);
            assert!(
                app.audit_errors[0].contains(expected),
                "{:?}",
                app.audit_errors
            );
            assert!(!fixture.base.join("started").exists());
        }
    }

    /// `q` while an item is being removed: that item finishes, the other
    /// does not run (it is audited as skipped), and the TUI says it is
    /// stopping. The command's output is captured by core: it is not on
    /// the screen (see the next test for stdout and stderr).
    #[test]
    fn quitting_mid_apply_finishes_the_item_and_runs_no_more() {
        let c = Crates::new();
        let mut app = c.app();
        let signal = Termination::default();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let (_tx, rx) = mpsc::channel();
        let started = c.base.join("started");
        let mut keys = [key('x'), key('y')].into_iter();
        event_loop(
            &mut term,
            &mut app,
            &rx,
            &signal,
            |_| Ok(true),
            || {
                if let Some(k) = keys.next() {
                    return Ok(k);
                }
                // Quit while the first command runs.
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while !started.exists() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the apply never started"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(key('q'))
            },
        )
        .unwrap();
        let screen = term.backend().to_string();
        assert!(
            screen.contains("stopping: the item in progress finishes"),
            "{screen}"
        );
        assert!(!screen.contains("fake-cargo"), "{screen}");
        let work = c.base.join("work");
        let left: Vec<_> = ["app", "lib"]
            .into_iter()
            .filter(|n| work.join(n).join("target").exists())
            .collect();
        assert_eq!(left.len(), 1, "exactly one target was removed: {left:?}");
        // One JSON object per line, as core writes them.
        let audit = std::fs::read_to_string(c.base.join("state/audit.jsonl")).unwrap();
        let lines: Vec<&str> = audit.lines().collect();
        assert_eq!(lines.len(), 3, "{audit}");
        assert!(lines[0].contains(r#""event":"start""#), "{audit}");
        assert!(lines[1].contains(r#""event":"end""#), "{audit}");
        assert!(lines[1].contains(r#""outcome":"removed""#), "{audit}");
        assert!(lines[2].contains(r#""event":"end""#), "{audit}");
        assert!(lines[2].contains(r#""outcome":"skipped""#), "{audit}");
        let detail = format!(r#""detail":"{}""#, apply::NOT_RUN_STOPPED);
        assert!(lines[2].contains(&detail), "{audit}");
        let path = format!("/work/{}/target", left[0]);
        assert!(lines[2].contains(&path), "{audit}");
    }

    #[test]
    fn termination_stops_apply_before_the_event_loop_wakes() {
        let fixture = Crates::new();
        let mut app = fixture.app();
        let signal = Termination::default();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let (_tx, rx) = mpsc::channel();
        let hold = fixture.base.join("hold");
        std::fs::write(&hold, "").unwrap();
        let started = fixture.base.join("started");
        let log = fixture.options().audit_log.unwrap();
        let mut polls = 0;
        let mut keys = [key('x'), key('y')].into_iter();
        let wait = |ready: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !ready() {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            true
        };
        event_loop(
            &mut term,
            &mut app,
            &rx,
            &signal,
            |_| {
                polls += 1;
                if polls <= 2 {
                    return Ok(true);
                }
                let in_progress = wait(&|| started.exists());
                signal.flag.store(SIGHUP as usize, Ordering::Relaxed);
                std::fs::remove_file(&hold)?;
                assert!(in_progress, "the first cleanup never started");
                assert!(wait(
                    &|| std::fs::read_to_string(&log).is_ok_and(|audit| audit.lines().count() >= 3)
                ));
                Ok(false)
            },
            || Ok(keys.next().unwrap()),
        )
        .unwrap();
        assert_eq!(signal.exit_code(), Some(129));
        let result = app
            .apply_view()
            .unwrap()
            .result
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap();
        use dwhy_core::report::ApplyOutcome::{Removed, Skipped};
        assert_eq!(
            result
                .report
                .items
                .iter()
                .filter(|i| i.outcome == Removed)
                .count(),
            1
        );
        assert!(
            result
                .report
                .items
                .iter()
                .any(|i| i.outcome == Skipped && i.detail == apply::NOT_RUN_STOPPED)
        );
        let audit = std::fs::read_to_string(log).unwrap();
        assert_eq!(audit.matches(r#""event":"start""#).count(), 1, "{audit}");
    }

    #[test]
    fn a_saved_plan_session_keeps_its_scan_scope_after_a_second_apply() {
        let fixture = Crates::new();
        let scope = Options {
            cross_filesystems: true,
            ..fixture.options()
        };
        let launch = Options {
            paths: vec![fixture.base.join("unused")],
            detectors: None,
            ..fixture.options()
        };
        let mut app = fixture.open_plan(&scope, launch, 1);
        let env = apply::Env::from_system();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for remaining in [1, 0] {
            for c in ['x', 'y'] {
                term.draw(|f| ui::draw(f, &mut app)).unwrap();
                assert!(!app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)));
            }
            let result = app
                .take_apply()
                .unwrap()
                .run(Processes::default, &env)
                .unwrap();
            assert_eq!(result.exit, 0, "{:?}", result.report.items);
            app.apply_done(Ok(result));
            assert!(!app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
            let scan = app.take_scan().unwrap();
            assert_eq!(scan.options.paths, scope.paths);
            assert_eq!(scan.options.cross_filesystems, scope.cross_filesystems);
            assert_eq!(scan.options.detectors, scope.detectors);
            let data = job::scan(&scan.options, &scan.progress, &mut |_| {}).unwrap();
            assert_eq!(data.report.findings.len(), remaining);
            app.finish(data);
            assert_eq!(app.browser().unwrap().marked_findings().count(), 0);
            if remaining > 0 {
                for code in [KeyCode::Tab, KeyCode::Char(' '), KeyCode::Char('p')] {
                    assert!(!app.on_key(KeyEvent::new(code, KeyModifiers::NONE)));
                }
                let plan = app
                    .take_request()
                    .unwrap()
                    .build(Processes::default, env.host.clone());
                app.plan_built(plan, &env.host, env.uid);
            }
        }
    }

    /// The previous test, run in a child process with its output captured:
    /// the fake cargo's stdout and stderr never reach the process's own
    /// stdout or stderr, the terminal the TUI owns.
    #[test]
    fn apply_command_output_never_reaches_the_terminal() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::quitting_mid_apply_finishes_the_item_and_runs_no_more",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(stdout.contains("1 passed"), "{stdout}");
        for s in [&stdout, &stderr] {
            assert!(!s.contains("fake-cargo"), "{stdout}{stderr}");
        }
    }
}
