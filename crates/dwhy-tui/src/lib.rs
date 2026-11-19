//! diskwhy terminal UI (`dwhy`, `dwhy tui`).
//!
//! [`run`] scans in a background thread with the same dwhy-core pipeline as
//! `dwhy scan` ([`job`]), then browses the directory tree and the findings.
//! The UI is a state machine ([`app::App`]) fed key events and scan messages; [`ui::draw`]
//! renders it, so tests use ratatui's `TestBackend` and no terminal.
//!
//! M4a: the tree browser. M4b: the findings list and detail view. M4c:
//! marking findings, the plan preview (built with core `plan::build` on a
//! worker thread, as `dwhy plan` builds it) and plan files: `w` writes one,
//! [`run_plan`] opens one. A plan file the person asks for is the only
//! thing the TUI writes; nothing is removed.

pub mod app;
pub mod job;
pub mod ui;

use std::io::{self, IsTerminal};
use std::panic;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crossterm::event::{self, Event};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use dwhy_core::guard::Processes;
use dwhy_core::scan::Progress;
use dwhy_core::system;
use ratatui::Terminal;
use ratatui::backend::{Backend, CrosstermBackend};
use signal_hook::SigId;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

pub use app::App;
pub use job::{Options, Scanned, Stage};

pub type Error = Box<dyn std::error::Error>;

/// How often the screen refreshes while waiting for keys (scan progress).
const TICK: Duration = Duration::from_millis(100);

enum Msg {
    Stage(Stage),
    Done(Result<Box<Scanned>, String>),
}

/// A finished plan build: its number, the host it was built for, the plan.
type Built = (u64, String, Result<job::BuiltPlan, String>);

/// Opens the TUI: checks there is a terminal, scans `opts` in a background
/// thread, and browses the result until the person quits.
pub fn run(opts: Options) -> Result<u8, Error> {
    need_terminal()?;
    let signal = Termination::register()?;
    let result = run_terminal(opts, &signal);
    match signal.exit_code() {
        Some(code) => Ok(code),
        None => result.map(|()| 0),
    }
}

/// `dwhy tui --plan FILE`: reads and parses the plan (failing before the
/// terminal is touched), then previews it with no scan.
pub fn run_plan(file: &Path) -> Result<u8, Error> {
    let plan = job::read_plan(file)?;
    need_terminal()?;
    let signal = Termination::register()?;
    let mut app = App::open_plan(
        plan,
        file.to_path_buf(),
        &system::hostname(),
        system::euid(),
    );
    let result = (|| -> Result<(), Error> {
        let _guard = TerminalGuard::enter()?;
        let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        term.clear()?;
        let (_tx, rx) = mpsc::channel();
        event_loop(&mut term, &mut app, &rx, &signal, event::poll, event::read)
    })();
    match signal.exit_code() {
        Some(code) => Ok(code),
        None => result.map(|()| 0),
    }
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

fn run_terminal(opts: Options, signal: &Termination) -> Result<(), Error> {
    let labels = if opts.paths.is_empty() {
        vec![".".into()]
    } else {
        opts.paths
            .iter()
            .map(|r| app::sanitize(&r.to_string_lossy()))
            .collect()
    };
    let progress = Arc::new(Progress::default());
    let mut app = App::new(labels, progress.clone());

    let _guard = TerminalGuard::enter()?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    term.clear()?;

    let (tx, rx) = mpsc::channel();
    // Not joined: quitting mid-scan leaves it to end with the process.
    std::thread::Builder::new()
        .name("dwhy-tui-scan".into())
        .spawn(move || {
            let res = job::scan(&opts, &progress, &mut |s| {
                let _ = tx.send(Msg::Stage(s));
            });
            let _ = tx.send(Msg::Done(res.map(Box::new)));
        })?;

    event_loop(&mut term, &mut app, &rx, signal, event::poll, event::read)
}

fn event_loop<B: Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
    rx: &mpsc::Receiver<Msg>,
    signal: &Termination,
    mut poll: impl FnMut(Duration) -> io::Result<bool>,
    mut read: impl FnMut() -> io::Result<Event>,
) -> Result<(), Error>
where
    B::Error: 'static,
{
    let (built_tx, built_rx) = mpsc::channel::<Built>();
    while signal.exit_code().is_none() {
        term.draw(|f| ui::draw(f, app))?;
        let ready = poll(TICK)?;
        if signal.exit_code().is_some() {
            return Ok(());
        }
        if ready
            && let Event::Key(key) = read()?
            && app.on_key(key)
        {
            return Ok(());
        }
        if let Some(req) = app.take_request() {
            let tx = built_tx.clone();
            // Guards read /proc and run git. Not joined, like the scan.
            std::thread::Builder::new()
                .name("dwhy-tui-plan".into())
                .spawn(move || {
                    let host = system::hostname();
                    let plan = req.job.build(Processes::read, host.clone());
                    let _ = tx.send((req.build, host, plan));
                })?;
        }
        while let Ok((build, host, plan)) = built_rx.try_recv() {
            app.plan_built(build, plan, &host, system::euid());
        }
        loop {
            match rx.try_recv() {
                Ok(Msg::Stage(s)) => app.set_stage(s),
                Ok(Msg::Done(Ok(data))) => app.finish(*data),
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
            0 => None,
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
}
