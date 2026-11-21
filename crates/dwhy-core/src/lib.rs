//! diskwhy engine.
//!
//! M0: the read-only scanner ([`scan`]), filesystem accounting
//! ([`account`]), `doctor` checks, and the `diskwhy/v1` JSON types
//! ([`report`]), plus the detector framework ([`detect`], [`detectors`]) and
//! the scan tree detectors read ([`tree`]). M2: guards ([`guard`]) run before
//! removal, plans ([`plan`]) select findings for it, and [`apply`] carries a
//! plan out with [`remove`] or the tools' own commands. M3: [`snapshot`]s
//! record scans so later runs can tell what grew ([`growth`]), and
//! [`probes`] explain why a finding is big; [`explain`] picks what `dwhy
//! explain` reports. [`cancel`] stops the read-only child processes of a scan
//! or plan build that its caller abandons.

pub mod account;
pub mod apply;
pub mod cancel;
pub mod detect;
pub mod detectors;
pub mod docker;
pub mod doctor;
pub mod explain;
mod gitcmd;
pub mod growth;
pub mod guard;
pub mod mounts;
pub mod plan;
pub mod probes;
pub mod remove;
pub mod report;
pub mod scan;
pub mod snapshot;
pub mod system;
pub mod tree;
pub mod units;

pub use report::SCHEMA;
