//! Running git the way diskwhy must: `--no-optional-locks`, no prompts, no
//! stdin, and none of the caller's `GIT_DIR`-style variables.

use std::path::Path;
use std::process::{Command, Stdio};

/// Runs `git --no-optional-locks -C <dir> <args>` and returns its stdout.
/// The error is the first line of stderr.
pub(crate) fn run(git: &str, dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(git)
        .arg("--no-optional-locks")
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
        .env_remove("GIT_CEILING_DIRECTORIES")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {git}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err
            .lines()
            .next()
            .unwrap_or("git failed")
            .trim()
            .to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
