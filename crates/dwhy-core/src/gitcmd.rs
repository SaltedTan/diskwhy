//! Running git the way diskwhy must: `--no-optional-locks`, no fsmonitor
//! (a program the repository's config can name), no prompts, no stdin, and
//! none of the caller's `GIT_DIR`-style variables. Every run is under a
//! [`Cancel`] token, which kills it when cancelled.

use std::path::Path;
use std::process::Command;

use crate::cancel::{self, Cancel, RunError};

/// How to invoke git, and the token its runs are cancelled with.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Git<'a> {
    pub cmd: &'a str,
    pub cancel: &'a Cancel,
}

/// The error message of a run the token cancelled.
pub(crate) const CANCELED: &str = "canceled";

/// Runs `git --no-optional-locks -c core.fsmonitor=false -C <dir> <args>`
/// and returns its stdout as text, with bytes that are not valid UTF-8
/// replaced by U+FFFD. Use [`run_bytes`] when the output names paths.
/// The error is the first line of stderr.
pub(crate) fn run(git: Git<'_>, dir: &Path, args: &[&str]) -> Result<String, String> {
    run_bytes(git, dir, args).map(|out| String::from_utf8_lossy(&out).into_owned())
}

/// Like [`run`], returning stdout's raw bytes, so a path that is not valid
/// UTF-8 survives exactly.
pub(crate) fn run_bytes(git: Git<'_>, dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new(git.cmd);
    cmd.arg("--no-optional-locks")
        .args(["-c", "core.fsmonitor=false"])
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_CEILING_DIRECTORIES");
    let out = cancel::output(&mut cmd, git.cancel, None, u64::MAX).map_err(|e| match e {
        RunError::Canceled => CANCELED.to_string(),
        RunError::Spawn(e) | RunError::Wait(e) => format!("cannot run {}: {e}", git.cmd),
        RunError::Timeout => format!("{} timed out", git.cmd),
    })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err
            .lines()
            .next()
            .unwrap_or("git failed")
            .trim()
            .to_string());
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel::tests::{gone, read_pid, sleeper, within};
    use std::time::{Duration, Instant};

    #[test]
    fn cancel_kills_a_running_git() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let git = sleeper(dir.path(), &pid_file)
            .to_string_lossy()
            .into_owned();
        let cancel = Cancel::default();
        let worker = {
            let (git, cancel, dir) = (git.clone(), cancel.clone(), dir.path().to_path_buf());
            std::thread::spawn(move || {
                let git = Git {
                    cmd: &git,
                    cancel: &cancel,
                };
                run(git, &dir, &["status"])
            })
        };
        assert!(within(Duration::from_secs(10), || read_pid(&pid_file).is_some()));
        let pid = read_pid(&pid_file).unwrap();
        let start = Instant::now();
        cancel.cancel();
        assert!(start.elapsed() < Duration::from_millis(500));
        assert_eq!(worker.join().unwrap(), Err(CANCELED.to_string()));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(within(Duration::from_secs(1), || gone(pid)));
    }

    #[test]
    fn a_cancelled_token_runs_no_git() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let script = dir.path().join("git");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let cancel = Cancel::default();
        cancel.cancel();
        let git = Git {
            cmd: &script.to_string_lossy(),
            cancel: &cancel,
        };
        assert_eq!(
            run_bytes(git, dir.path(), &["status"]),
            Err(CANCELED.to_string())
        );
        assert!(!marker.exists());
    }
}
