//! `cargo-target`: Cargo build output directories.
//!
//! A directory next to a `Cargo.toml` counts when it holds a `CACHEDIR.TAG`
//! written by cargo (cargo tags every target dir it creates, renamed ones
//! too), or when it is named `target` and holds cargo's `.rustc_info.json`
//! (a target dir whose tag was removed). Some other `target/`, such as a
//! downloaded prebuilt binary, matches neither.

use crate::detect::{Candidate, DetectContext, Detector, age, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, Recovery, Tier};
use crate::tree::{Markers, ScanTree};
use crate::units::human;

use super::read_head;

/// Target dirs smaller than this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// The cachedir.tag signature (<https://bford.info/cachedir/>).
const SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

pub struct CargoTarget;

impl Detector for CargoTarget {
    fn name(&self) -> &'static str {
        "cargo-target"
    }

    fn detect_candidates(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
    ) -> Result<Vec<Candidate>, String> {
        let mut out = Vec::new();
        for id in tree.ids() {
            let n = tree.node(id);
            let tagged = n.markers.contains(Markers::CACHEDIR_TAG);
            let rustc_info = n.markers.contains(Markers::RUSTC_INFO) && tree.name(id) == "target";
            if !n.is_dir || !(tagged || rustc_info) {
                continue;
            }
            let Some(parent) = tree.parent(id) else {
                continue;
            };
            if !tree.node(parent).markers.contains(Markers::CARGO_TOML) {
                continue;
            }
            let bytes = n.freeable();
            if bytes < MIN_BYTES {
                continue;
            }
            let path = tree.path(id);
            if !(rustc_info || written_by_cargo(&path.join("CACHEDIR.TAG"))) {
                continue;
            }
            let crate_dir = tree.path(parent);
            let manifest = crate_dir.join("Cargo.toml");
            let path_s = path.to_string_lossy().into_owned();
            let action = match ctx.tool_command("cargo") {
                Some(cargo) => {
                    // --target-dir pins the clean to exactly this directory,
                    // even if .cargo/config.toml points cargo elsewhere.
                    let argv = vec![
                        cargo,
                        "clean".into(),
                        "--manifest-path".into(),
                        manifest.to_string_lossy().into_owned(),
                        "--target-dir".into(),
                        path_s.clone(),
                    ];
                    Action {
                        kind: ActionKind::Command,
                        text: argv
                            .iter()
                            .map(|a| shell_quote(a))
                            .collect::<Vec<_>>()
                            .join(" "),
                        argv: Some(argv),
                    }
                }
                None => Action {
                    kind: ActionKind::RemovePath,
                    text: format!("remove {} (cargo not found)", shell_quote(&path_s)),
                    argv: None,
                },
            };
            let finding = Finding {
                id: finding_id(self.name(), &path_s),
                detector: self.name().into(),
                probe: None,
                evidence: None,
                bytes,
                nested_bytes: None,
                last_modified: Some(rfc3339(n.newest_mtime)),
                growth: None,
                tier: Tier::Rebuildable,
                reason: format!(
                    "Cargo build output of {} ({}{}); last written {} ago",
                    crate_dir.display(),
                    human(bytes),
                    if n.shared > 0 {
                        format!(
                            "; {} more is hardlinked elsewhere and is not freed",
                            human(n.shared)
                        )
                    } else {
                        String::new()
                    },
                    age(ctx.now, n.newest_mtime)
                ),
                guards: Vec::new(),
                action,
                recovery: Recovery {
                    cost: "the next build recompiles the crate and all its dependencies".into(),
                    how: Some("cargo build".into()),
                },
                path: path_s,
            };
            out.push(Candidate::new(path, finding));
        }
        Ok(out)
    }
}

fn written_by_cargo(tag: &std::path::Path) -> bool {
    let Some(head) = read_head(tag, 512) else {
        return false;
    };
    head.starts_with(SIGNATURE) && head.windows(5).any(|w| w == b"cargo")
}
