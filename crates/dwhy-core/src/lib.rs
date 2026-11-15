//! diskwhy engine.
//!
//! M0: the read-only scanner ([`scan`]), filesystem accounting
//! ([`account`]), `doctor` checks, and the `diskwhy/v1` JSON types
//! ([`report`]). Detectors, guards and plans arrive in later milestones.

pub mod account;
pub mod doctor;
pub mod mounts;
pub mod report;
pub mod scan;
pub mod system;
pub mod units;

pub use report::SCHEMA;
