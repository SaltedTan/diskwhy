//! `dwhy guide`: a short quickstart for agents and scripts, matched to this binary.

use std::io::Write;

use crate::{EXIT_OK, Result};

/// The guide's source; `{version}` stands for the package version.
const GUIDE: &str = include_str!("guide.md");

/// The guide text for this build.
pub fn text() -> String {
    GUIDE.replace("{version}", env!("CARGO_PKG_VERSION"))
}

/// Writes the guide to stdout. Touches nothing else: no disk, terminal or Docker.
pub fn run() -> Result<u8> {
    let mut out = std::io::stdout().lock();
    out.write_all(text().as_bytes())?;
    out.flush()?;
    Ok(EXIT_OK)
}
