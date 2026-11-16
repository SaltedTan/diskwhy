//! diskwhy engine.
//!
//! M0: the read-only scanner ([`scan`]), filesystem accounting
//! ([`account`]), `doctor` checks, and the `diskwhy/v1` JSON types
//! ([`report`]), plus the detector framework ([`detect`], [`detectors`]) and
//! the scan tree detectors read ([`tree`]). Guards ([`guard`]) run before removal,
//! and plans ([`plan`]) select findings for it (M2).

pub mod account;
pub mod detect;
pub mod detectors;
pub mod docker;
pub mod doctor;
mod gitcmd;
pub mod guard;
pub mod mounts;
pub mod plan;
pub mod report;
pub mod scan;
pub mod system;
pub mod tree;
pub mod units;

pub use report::SCHEMA;
