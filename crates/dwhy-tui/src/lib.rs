//! diskwhy terminal UI (`dwhy`, `dwhy tui`).
//!
//! [`run`] scans in a background thread with the same dwhy-core pipeline as
//! `dwhy scan` ([`job`]), then browses the directory tree. The UI is a state
//! machine ([`app::App`]) fed key events and scan messages; [`ui::draw`]
//! renders it, so tests use ratatui's `TestBackend` and no terminal.
//!
//! M4a: the tree browser. Nothing is written or removed.

pub mod app;
pub mod job;
pub mod ui;

use std::io::{self, IsTerminal};
use std::panic;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crossterm::event::{self, Event};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use dwhy_core::scan::Progress;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
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

/// Opens the TUI: checks there is a terminal, scans `opts` in a background
/// thread, and browses the result until the person quits.
pub fn run(opts: Options) -> Result<u8, Error> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "the TUI needs a terminal (stdin and stdout); use `dwhy scan` (or `dwhy scan --json`) instead"
                .into(),
        );
    }
    let signal = Termination::register()?;
    let result = run_terminal(opts, &signal);
    match signal.exit_code() {
        Some(code) => Ok(code),
        None => result.map(|()| 0),
    }
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

    while signal.exit_code().is_none() {
        term.draw(|f| ui::draw(f, &mut app))?;
        let ready = event::poll(TICK)?;
        if signal.exit_code().is_some() {
            return Ok(());
        }
        if ready
            && let Event::Key(key) = event::read()?
            && app.on_key(key)
        {
            return Ok(());
        }
        loop {
            match rx.try_recv() {
                Ok(Msg::Stage(s)) => app.set_stage(s),
                Ok(Msg::Done(Ok(data))) => app.finish(*data),
                Ok(Msg::Done(Err(e))) => return Err(format!("scan failed: {e}").into()),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if app.browser().is_none() {
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

    #[test]
    fn termination_flag_requests_quit_with_signal_status() {
        let signal = Termination::default();
        assert_eq!(signal.exit_code(), None);
        for (num, status) in [(SIGHUP, 129), (SIGINT, 130), (SIGTERM, 143)] {
            signal.flag.store(num as usize, Ordering::Relaxed);
            assert_eq!(signal.exit_code(), Some(status));
        }
    }
}
