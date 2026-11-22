//! Cancelling the read-only child processes a scan or a plan build runs
//! (git, `docker exec … psql`), so that a caller which abandons its worker
//! thread (the TUI, when the person quits mid-scan) leaves no child behind.
//!
//! [`Cancel::cancel`] kills every child still running under the token and
//! stops new ones from starting. It never waits for them, so quitting stays
//! immediate. Removal commands in `apply` are not run through this: an
//! apply finishes the item in progress.
//!
//! A child's PID stays registered only while the child is unreaped: the
//! runner waits with `WNOWAIT`, unregisters the PID, and only then reaps
//! it. So the PID cannot have been reused by another process when
//! [`Cancel::cancel`] signals it.

use std::collections::HashSet;
use std::io::{self, Read};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process, waitid};

/// Shared by every clone: cancelling one cancels them all. A token starts
/// out not cancelled and, once cancelled, stays so.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<Mutex<State>>);

#[derive(Debug, Default)]
struct State {
    canceled: bool,
    /// Children started under the token and not yet reaped.
    children: HashSet<u32>,
}

impl Cancel {
    /// Kills (`SIGKILL`) the children running under the token and refuses
    /// to start more. Does not wait for them to exit.
    pub fn cancel(&self) {
        let mut state = self.lock();
        state.canceled = true;
        // Under the lock: a registered child is not reaped before it is
        // unregistered, so each PID still names that child.
        for pid in state.children.drain() {
            if let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
                let _ = kill_process(pid, Signal::KILL);
            }
        }
    }

    pub fn is_canceled(&self) -> bool {
        self.lock().canceled
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stops tracking `pid`; whether the token was cancelled.
    fn unregister(&self, pid: u32) -> bool {
        let mut state = self.lock();
        state.children.remove(&pid);
        state.canceled
    }
}

/// Why [`output`] returned no output.
#[derive(Debug)]
pub(crate) enum RunError {
    /// The token was cancelled before or while the command ran.
    Canceled,
    Spawn(io::Error),
    /// It ran past the timeout and was killed.
    Timeout,
    Wait(io::Error),
}

/// Runs `cmd` with no stdin, capturing up to `max_output` bytes of stdout
/// and of stderr, killing it after `timeout` (never, when `None`) or when
/// `cancel` is cancelled.
pub(crate) fn output(
    cmd: &mut Command,
    cancel: &Cancel,
    timeout: Option<Duration>,
    max_output: u64,
) -> Result<Output, RunError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cancel.is_canceled() {
        return Err(RunError::Canceled);
    }
    let mut child = cmd.spawn().map_err(RunError::Spawn)?;
    let pid = child.id();
    {
        let mut state = cancel.lock();
        if state.canceled {
            drop(state);
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::Canceled);
        }
        state.children.insert(pid);
    }
    let out = drain(child.stdout.take(), max_output);
    let err = drain(child.stderr.take(), max_output);
    let exited = wait_unreaped(Pid::from_child(&child), timeout);
    if !matches!(exited, Ok(true)) {
        // Still unreaped, so the PID is still this child's.
        let _ = child.kill();
    }
    let canceled = cancel.unregister(pid);
    let status = child.wait();
    // A killed child's pipes may be held open by its own children: the
    // readers are not waited for then.
    if canceled {
        return Err(RunError::Canceled);
    }
    match exited {
        Ok(true) => {}
        Ok(false) => return Err(RunError::Timeout),
        Err(e) => return Err(RunError::Wait(e)),
    }
    let status: ExitStatus = status.map_err(RunError::Wait)?;
    Ok(Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// Reads up to `max` bytes on a thread of its own.
fn drain(r: Option<impl Read + Send + 'static>, max: u64) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(r) = r {
            let _ = r.take(max).read_to_end(&mut buf);
        }
        buf
    })
}

/// Waits for the child `pid` to exit without reaping it (`WNOWAIT`):
/// `Ok(false)` when `timeout` passed first.
fn wait_unreaped(pid: Pid, timeout: Option<Duration>) -> io::Result<bool> {
    let deadline = timeout.map(|t| Instant::now() + t);
    let mut options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT;
    if deadline.is_some() {
        options |= WaitIdOptions::NOHANG;
    }
    loop {
        match waitid(WaitId::Pid(pid), options) {
            Ok(Some(_)) => return Ok(true),
            Ok(None) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::Path;

    /// Whether process `pid` has exited: no such process, or a zombie.
    pub(crate) fn gone(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|s| {
                s.rsplit_once(')')
                    .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
            })
            .unwrap_or(true)
    }

    /// Polls for `pred` up to `limit`.
    pub(crate) fn within(limit: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < limit {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        pred()
    }

    /// A script that writes its PID to `pid_file`, then sleeps 30 s.
    pub(crate) fn sleeper(dir: &Path, pid_file: &Path) -> std::path::PathBuf {
        let script = dir.join("sleeper");
        write_script(
            &script,
            &format!(
                "#!/bin/sh\necho $$ > '{}.tmp'\nmv '{0}.tmp' '{0}'\nexec sleep 30\n",
                pid_file.display()
            ),
        );
        script
    }

    /// Writes an executable script at `path`.
    ///
    /// A child `sh` writes it, so this process never holds the file open for
    /// writing. Otherwise a child forked by another test thread could inherit
    /// that descriptor until its own exec, and running the script would fail
    /// with ETXTBSY ("Text file busy").
    pub(crate) fn write_script(path: &Path, body: &str) {
        use std::io::Write;
        let mut sh = Command::new("sh")
            .args(["-c", "cat > \"$1\" && chmod 700 \"$1\"", "sh"])
            .arg(path)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        sh.stdin.take().unwrap().write_all(body.as_bytes()).unwrap();
        assert!(sh.wait().unwrap().success());
    }

    pub(crate) fn read_pid(pid_file: &Path) -> Option<u32> {
        std::fs::read_to_string(pid_file).ok()?.trim().parse().ok()
    }

    #[test]
    fn cancel_kills_a_running_child_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = sleeper(dir.path(), &pid_file);
        let cancel = Cancel::default();
        let start = Instant::now();
        let worker = {
            let cancel = cancel.clone();
            std::thread::spawn(move || {
                output(&mut Command::new(script), &cancel, None, u64::MAX).map(|_| ())
            })
        };
        assert!(within(Duration::from_secs(10), || read_pid(&pid_file).is_some()));
        let pid = read_pid(&pid_file).unwrap();
        let canceling = Instant::now();
        cancel.cancel();
        assert!(canceling.elapsed() < Duration::from_millis(500));
        let result = worker.join().unwrap();
        assert!(matches!(result, Err(RunError::Canceled)), "{result:?}");
        assert!(within(Duration::from_secs(1), || gone(pid)));
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(cancel.is_canceled());
    }

    #[test]
    fn a_cancelled_token_starts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let script = dir.path().join("touch");
        write_script(
            &script,
            &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        );
        let cancel = Cancel::default();
        cancel.cancel();
        let result = output(&mut Command::new(&script), &cancel, None, u64::MAX);
        assert!(matches!(result, Err(RunError::Canceled)), "{result:?}");
        assert!(!marker.exists());
        // An unrelated token is not affected.
        let other = Cancel::default();
        output(&mut Command::new(&script), &other, None, u64::MAX).unwrap();
        assert!(marker.exists());
    }

    #[test]
    fn output_and_timeout_without_cancelling() {
        let cancel = Cancel::default();
        let out = output(
            Command::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]),
            &cancel,
            Some(Duration::from_secs(5)),
            u64::MAX,
        )
        .unwrap();
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
        assert_eq!(out.status.code(), Some(3));
        let start = Instant::now();
        let e = output(
            Command::new("sleep").arg("5"),
            &cancel,
            Some(Duration::from_millis(200)),
            u64::MAX,
        )
        .unwrap_err();
        assert!(matches!(e, RunError::Timeout), "{e:?}");
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(cancel.lock().children.is_empty());
    }
}
