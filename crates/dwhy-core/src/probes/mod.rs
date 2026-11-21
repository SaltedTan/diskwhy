//! Probes explain *why* a finding is big or growing (docs/DESIGN.md,
//! Concepts → Probe). A probe runs after the detectors, on the findings it
//! recognises, and adds evidence to them: it sets `Finding::probe`, fills
//! `Finding::evidence`, and may sharpen the reason and the advice. It never
//! changes a finding's tier, never makes one removable, and only reads.
//!
//! Built: [`postgres_wal`].

pub mod postgres_wal;

use crate::detect::DetectContext;
use crate::report::{DetectorStatus, Finding};

/// `dwhy doctor`'s view of the probes.
pub fn statuses(ctx: &DetectContext) -> Vec<DetectorStatus> {
    let (status, detail) = postgres_wal::availability(ctx);
    vec![DetectorStatus {
        name: postgres_wal::NAME.into(),
        milestone: "M3".into(),
        status,
        detail,
    }]
}

/// Runs every probe on the findings it applies to, against the real system.
/// Best effort: a probe that cannot get evidence leaves the finding as the
/// detector made it. Nothing runs once `ctx.cancel` is cancelled.
pub fn run(findings: &mut [Finding], ctx: &DetectContext) {
    if findings.iter().any(postgres_wal::applies_to)
        && ctx.docker_socket.accessible
        && !ctx.cancel.is_canceled()
    {
        postgres_wal::probe_all_with(
            findings,
            &postgres_wal::Live::from_context(ctx),
            ctx.docker.fetched().as_deref(),
        );
    }
}
