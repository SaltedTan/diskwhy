//! Probes explain *why* a finding is big or growing (docs/DESIGN.md,
//! Concepts → Probe). A probe runs after the detectors, on the findings it
//! recognises, and adds evidence to them: it sets `Finding::probe`, fills
//! `Finding::evidence`, and may sharpen the reason and the advice. It never
//! changes a finding's tier, never makes one removable, and only reads.
//!
//! Built: [`postgres_wal`].

pub mod postgres_wal;

use crate::detect::DetectContext;
use crate::report::{DetectorAvailability, DetectorStatus, Finding};

/// Every built probe: name and what it adds to.
pub const PROBES: &[(&str, &str)] = &[(
    postgres_wal::NAME,
    "docker-volume findings of a running Postgres container's data directory",
)];

/// Whether a probe can run, with a one-line reason (for `dwhy doctor`).
pub fn availability(name: &str, ctx: &DetectContext) -> (DetectorAvailability, String) {
    match name {
        postgres_wal::NAME => postgres_wal::availability(ctx),
        _ => (DetectorAvailability::NotImplemented, "unknown probe".into()),
    }
}

/// `dwhy doctor`'s view of the probes.
pub fn statuses(ctx: &DetectContext) -> Vec<DetectorStatus> {
    PROBES
        .iter()
        .map(|(name, _)| {
            let (status, detail) = availability(name, ctx);
            DetectorStatus {
                name: (*name).into(),
                milestone: "M3".into(),
                status,
                detail,
            }
        })
        .collect()
}

/// Runs every probe on the findings it applies to, against the real system.
/// Best effort: a probe that cannot get evidence leaves the finding as the
/// detector made it.
pub fn run(findings: &mut [Finding], ctx: &DetectContext) {
    if findings.iter().any(postgres_wal::applies_to) && ctx.docker_socket.accessible {
        postgres_wal::probe_all(findings, &postgres_wal::Live::from_context(ctx));
    }
}
