//! diskwhy engine.
//!
//! M0: the read-only scanner ([`scan`]), filesystem accounting
//! ([`account`]), `doctor` checks, and the `diskwhy/v1` JSON types
//! ([`report`]), plus the detector framework ([`detect`], [`detectors`]) and
//! the scan tree detectors read ([`tree`]). M2: guards ([`guard`]) run before
//! removal, plans ([`plan`]) select findings for it, and [`apply`] carries a
//! plan out with [`remove`] or the tools' own commands. M3: [`snapshot`]s
//! record scans so later runs can tell what grew.

pub mod account;
pub mod apply;
pub mod detect;
pub mod detectors;
pub mod docker;
pub mod doctor;
mod gitcmd;
pub mod guard;
pub mod mounts;
pub mod plan;
pub mod remove;
pub mod report;
pub mod scan;
pub mod snapshot;
pub mod system;
pub mod tree;
pub mod units;

pub use report::SCHEMA;
