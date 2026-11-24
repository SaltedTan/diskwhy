//! `old-kernels`: installed Linux kernel versions that apt's autoremove
//! would drop, purged one version at a time with `apt-get remove --purge`.
//! Root only, with `apt-get` and `dpkg-query` (the catalog's
//! `Needs::RootAndAll`).
//!
//! A kernel version (an ABI such as `7.0.0-43-generic`) is offered only
//! when all of these hold:
//!
//! - `apt-get -s autoremove` (a read-only simulation, run with `LANG=C`)
//!   lists its `linux-image-<ver>` in a `Remv` or `Purg` line. The output
//!   is parsed strictly: an `Inst` or `Conf` line, a missing or second
//!   summary line, a summary that counts other than the removals listed,
//!   or a failed run fails the detector, so nothing is offered.
//! - It is not the running kernel (`uname(2)`'s release).
//! - It is not among the two newest installed kernel images, by Debian
//!   version order of the `linux-image-<ver>` (and
//!   `linux-image-unsigned-<ver>`) packages, as apt groups them. With a
//!   reboot pending (the running kernel is not the newest), the newest two
//!   and the running kernel are all kept.
//! - It is not the target of `/boot/vmlinuz` or `/boot/vmlinuz.old`, read
//!   with `readlinkat` and never followed. A missing link is fine; one that
//!   is not a symlink or does not name `vmlinuz-<ver>` fails the detector.
//!
//! apt 3.2's own rule (`apt-pkg/algorithms.cc`, `GetProtectedKernelsRegex`)
//! keeps the booted version and fills up to `APT::NeverAutoRemove::KernelCount`
//! (2, never less) with the newest versions of the packages providing
//! `$kernel`, then protects `<pattern>-<uname>` for every
//! `APT::VersionedKernelPackages` pattern of those versions and of the
//! booted release. So with a reboot pending apt keeps only the booted and
//! the newest kernel; the checks here keep one more.
//!
//! Anything diskwhy cannot read exactly means no finding: a release, ABI or
//! package version that does not parse, a package listed twice, a package
//! that would belong to two installed kernels, or one of the version's
//! packages in any state but installed (`ii`) or config-files (`rc`).
//!
//! The finding sits at the version's modules directory,
//! `/usr/lib/modules/<ver>` (or `/lib/modules/<ver>` where `/lib` is not
//! the usrmerge symlink to `usr/lib`), and groups every installed package of
//! that version: `linux-<kind>-<ver>` for `image`, `image-unsigned`,
//! `modules`, `modules-extra`, `headers`, `tools`, `cloud-tools`,
//! `buildinfo` and the `modules-*`, `main-modules-*`, `objects-*` and
//! `signatures-*` families, plus the flavourless `linux-headers-<abi>`,
//! `linux-tools-<abi>` and `linux-cloud-tools-<abi>` (`<abi>` such as
//! `7.0.0-43`) when no other installed package names that ABI with another
//! flavour.
//!
//! The bytes are the regular files those packages own (`dpkg-query -L`)
//! and the version's `/boot` files (`vmlinuz`, `initrd.img`, `System.map`
//! and `config`, which the image's maintainer scripts create and purge
//! removes). A file counts only when the walk holds its directory, the
//! directory is still the one it measured (opened from `/` with
//! `O_NOFOLLOW` at every step, so a symlinked ancestor means it is not
//! counted), and it is a regular file on that directory's device, stat'ed
//! without following symlinks. A path under a usrmerge symlink (`/lib`,
//! `/bin`, ... pointing to `usr/...`) is read at its `/usr` spelling. A
//! hardlinked inode counts once, and only when every link to it is among
//! the files purged. Bytes under the modules directory are capped at its
//! freeable bytes. A file list with anything but paths (a diversion) leaves
//! the version out. Nothing under 1 MiB. Module directories no package
//! owns (left after a purge) are not findings.
//!
//! The finding is `review`: an old kernel is the fallback when a new one
//! does not boot. The action is
//! `env -u APT_CONFIG DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y --no-auto-remove <packages>`,
//! the packages sorted. Before plan and apply, the `apt-removal-set` guard
//! ([`removal_set_guard`]) checks the version and the package set again
//! and simulates that exact removal, blocking when apt would remove
//! anything else.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

use crate::cancel::{self, RunError};
use crate::detect::{Candidate, DetectContext, Detector, finding_id, rfc3339, shell_quote};
use crate::report::{Action, ActionKind, Finding, GuardResult, GuardStatus, Recovery, Tier};
use crate::tree::{ScanTree, TreeNode};
use crate::units::human;

/// Reclaimable totals below this are not worth a finding.
const MIN_BYTES: u64 = 1 << 20;

/// How long apt's simulations may take (it may rebuild its cache).
const APT_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a `dpkg-query` may take.
const DPKG_TIMEOUT: Duration = Duration::from_secs(60);

/// Output beyond this is taken as truncated, and fails the read.
const MAX_OUTPUT: u64 = 64 << 20;

/// How many of the newest installed kernel versions are always kept.
const KEEP_NEWEST: usize = 2;

/// The guard that simulates the removal.
pub const APT_REMOVAL_SET: &str = "apt-removal-set";

/// `dpkg-query -W`'s format: name, version and status, tab-separated.
const STATUS_FORMAT: &str = "-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\n";

/// The action's argv before apt-get: no `APT_CONFIG` from the caller's
/// environment (the simulations run without it too) and no debconf prompts.
const ACTION_ENV: [&str; 4] = ["env", "-u", "APT_CONFIG", "DEBIAN_FRONTEND=noninteractive"];

/// The action's arguments after apt-get, before the packages.
const ACTION_ARGS: [&str; 4] = ["remove", "--purge", "-y", "--no-auto-remove"];

/// What the simulation runs after apt-get, before the packages.
const SIMULATE_ARGS: [&str; 4] = ["-s", "remove", "--purge", "--no-auto-remove"];

/// `/boot/<name>-<ver>` files of a kernel version.
const BOOT_FILES: [&str; 4] = ["vmlinuz", "initrd.img", "System.map", "config"];

/// Where kernel modules live, below the system root.
const MODULE_DIRS: [&str; 2] = ["usr/lib/modules", "lib/modules"];

/// Top-level directories usrmerge turns into symlinks to `usr/<name>`.
const USRMERGE: [&str; 6] = ["bin", "sbin", "lib", "lib32", "lib64", "libx32"];

/// `linux-<kind>-<ver>` kinds of one kernel version.
const KINDS: &[&str] = &[
    "image",
    "image-unsigned",
    "modules",
    "modules-extra",
    "headers",
    "tools",
    "cloud-tools",
    "buildinfo",
];

/// `linux-<family><name>-<ver>` families of one kernel version.
const FAMILIES: &[&str] = &["modules-", "main-modules-", "objects-", "signatures-"];

/// `linux-<kind>-<abi>` kinds shared by every flavour of an ABI.
const SHARED_KINDS: &[&str] = &["headers", "tools", "cloud-tools"];

/// `old-kernels`. Holds the system root it looks under and where the
/// running kernel's release comes from.
pub struct OldKernels {
    root: PathBuf,
    /// `None`: `uname(2)`.
    release: Option<Result<String, String>>,
}

impl OldKernels {
    /// The system root: modules under `usr/lib/modules`, images in `boot`.
    pub const DEFAULT_ROOT: &str = "/";

    /// Looks under `/` and asks `uname(2)` for the running kernel.
    pub fn from_system() -> OldKernels {
        OldKernels {
            root: PathBuf::from(OldKernels::DEFAULT_ROOT),
            release: None,
        }
    }

    /// Looks under `root` (holding `usr/lib/modules`, `boot`, and the paths
    /// `dpkg-query -L` lists) and takes `release` as the running kernel's
    /// (fixture tests); an `Err` is a failed `uname`.
    pub fn with_root(root: PathBuf, release: Result<String, String>) -> OldKernels {
        OldKernels {
            root,
            release: Some(release),
        }
    }

    fn release(&self) -> Result<String, String> {
        match &self.release {
            Some(r) => r.clone().and_then(check_release),
            None => running_release(),
        }
    }
}

/// The running kernel's release, from `uname(2)`.
pub fn running_release() -> Result<String, String> {
    let u = rustix::system::uname();
    let r = u
        .release()
        .to_str()
        .map_err(|_| "uname's release is not UTF-8".to_string())?;
    check_release(r.to_owned())
}

fn check_release(r: String) -> Result<String, String> {
    if valid_uname(&r) {
        Ok(r)
    } else {
        Err(format!(
            "the running kernel's release {r:?} is not a version diskwhy can read"
        ))
    }
}

// ---------------------------------------------------------------------------
// Debian versions
// ---------------------------------------------------------------------------

/// A Debian version, `[epoch:]upstream[-revision]`, ordered as dpkg orders
/// them (`dpkg --compare-versions`).
#[derive(Debug, Clone)]
pub(crate) struct Version {
    epoch: u64,
    upstream: String,
    revision: String,
}

impl Version {
    /// dpkg's `parseversion`, strictly: an optional all-digit epoch, an
    /// upstream part that starts with a digit and holds only letters,
    /// digits and `.+~-:`, and an optional non-empty revision after the
    /// last `-` holding only letters, digits and `.+~`. `None` for anything
    /// else.
    pub(crate) fn parse(s: &str) -> Option<Version> {
        if s.is_empty() || s.bytes().any(|c| c.is_ascii_whitespace()) {
            return None;
        }
        let (epoch, rest) = match s.split_once(':') {
            Some((e, rest)) => {
                if e.is_empty() || !e.bytes().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                (e.parse().ok()?, rest)
            }
            None => (0, s),
        };
        let (upstream, revision) = match rest.rsplit_once('-') {
            Some((u, r)) => (u, r),
            None => (rest, ""),
        };
        if rest.contains('-') && revision.is_empty() {
            return None;
        }
        if !upstream.starts_with(|c: char| c.is_ascii_digit())
            || !upstream
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".+~-:".contains(&c))
            || !revision
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".+~".contains(&c))
        {
            return None;
        }
        Some(Version {
            epoch,
            upstream: upstream.to_owned(),
            revision: revision.to_owned(),
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Version) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| verrevcmp(self.upstream.as_bytes(), other.upstream.as_bytes()))
            .then_with(|| verrevcmp(self.revision.as_bytes(), other.revision.as_bytes()))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Version) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Version) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

/// dpkg's `order`: `~` before everything, even the end; then the end and
/// digits; then letters; then everything else.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(b'~') => -1,
        Some(c) => c as i32 + 256,
    }
}

/// dpkg's `verrevcmp`: alternating non-digit runs (by [`order`]) and digit
/// runs (numerically).
fn verrevcmp(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    let digit = |s: &[u8], k: usize| s.get(k).is_some_and(u8::is_ascii_digit);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !digit(a, i)) || (j < b.len() && !digit(b, j)) {
            let (ac, bc) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while digit(a, i) && digit(b, j) {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if digit(a, i) {
            return Ordering::Greater;
        }
        if digit(b, j) {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

// ---------------------------------------------------------------------------
// Kernel names
// ---------------------------------------------------------------------------

/// A kernel release as `uname` gives it and package names carry it: digits
/// and a `.` first (apt's `getUname` rule), then only `a-z`, `0-9`, `.`, `+`
/// and `-`, no `..`, not ending in `.` or `-`.
pub(crate) fn valid_uname(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = b.iter().take_while(|c| c.is_ascii_digit()).count();
    (3..=64).contains(&b.len())
        && digits > 0
        && b.get(digits) == Some(&b'.')
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".+-".contains(&c))
        && !s.contains("..")
        && !s.ends_with(['.', '-'])
}

/// The flavourless ABI of a release, `<upstream>-<abi>` of
/// `<upstream>-<abi>-<flavour>` (`7.0.0-43` of `7.0.0-43-generic`); `None`
/// when the release has no such shape.
pub(crate) fn upstream_abi(u: &str) -> Option<&str> {
    let (upstream, rest) = u.split_once('-')?;
    let (abi, flavour) = rest.split_once('-')?;
    let upstream_ok = upstream
        .split('.')
        .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()));
    let abi_ok = !abi.is_empty() && abi.bytes().all(|c| c.is_ascii_digit());
    let flavour_ok = flavour.starts_with(|c: char| c.is_ascii_alphanumeric());
    (upstream_ok && abi_ok && flavour_ok).then(|| &u[..upstream.len() + 1 + abi.len()])
}

/// `linux-<middle>-<suffix>`'s middle.
fn middle<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    name.strip_prefix("linux-")?
        .strip_suffix(suffix)?
        .strip_suffix('-')
}

/// Whether `name` is a package of the kernel release `u` alone.
pub(crate) fn flavoured_of(name: &str, u: &str) -> bool {
    middle(name, u).is_some_and(|m| {
        KINDS.contains(&m)
            || FAMILIES
                .iter()
                .any(|f| m.len() > f.len() && m.starts_with(f))
    })
}

/// Whether `name` is a flavourless package of the ABI `abi`.
fn shared_of(name: &str, abi: &str) -> bool {
    middle(name, abi).is_some_and(|m| SHARED_KINDS.contains(&m))
}

/// Whether `name` is a package of the release `u`, flavourless ones of its
/// ABI included.
pub(crate) fn belongs(name: &str, u: &str) -> bool {
    flavoured_of(name, u) || upstream_abi(u).is_some_and(|abi| shared_of(name, abi))
}

/// A Debian package name as dpkg accepts one.
fn valid_package_name(s: &str) -> bool {
    s.len() >= 2
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"+.-_".contains(&c))
}

/// A kernel package name diskwhy puts in an action: `linux-`, then only
/// `a-z`, `0-9`, `+`, `.` and `-`.
fn valid_kernel_package(s: &str) -> bool {
    s.len() > "linux-".len()
        && s.starts_with("linux-")
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"+.-".contains(&c))
}

// ---------------------------------------------------------------------------
// dpkg's package list
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Pkg {
    version: String,
    /// `${db:Status-Abbrev}`: desired, status, error flag.
    status: [u8; 3],
    /// Listed more than once (one per architecture, on a multiarch
    /// system): which one a name means is not known.
    dup: bool,
}

impl Pkg {
    /// Fully installed or config-files only, with no error flag.
    fn settled(&self) -> bool {
        &self.status == b"ii " || &self.status == b"rc "
    }

    /// Some of it is unpacked: anything but not-installed and config-files.
    fn installed(&self) -> bool {
        !matches!(self.status[1], b'n' | b'c')
    }
}

/// Every package dpkg knows of (not-installed ones left out), by name.
type Rows = BTreeMap<String, Pkg>;

/// `dpkg-query -W` output in [`STATUS_FORMAT`]. A line that is not three
/// fields with a valid name and status fails. A name listed twice is
/// marked [`Pkg::dup`]: an image or a version's package so marked fails
/// where it is used.
fn parse_rows(out: &[u8]) -> Result<Rows, String> {
    let text = std::str::from_utf8(out).map_err(|_| "dpkg-query's list is not UTF-8")?;
    let mut rows = Rows::new();
    for line in text.lines() {
        let bad = || format!("dpkg-query: cannot read the line {line:?}");
        let mut fields = line.split('\t');
        let (Some(name), Some(version), Some(status), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(bad());
        };
        let status: [u8; 3] = status.as_bytes().try_into().map_err(|_| bad())?;
        if !valid_package_name(name)
            || !b"uihrp".contains(&status[0])
            || !b"ncHUFWti".contains(&status[1])
            || !b" R".contains(&status[2])
        {
            return Err(bad());
        }
        if status[1] == b'n' {
            continue;
        }
        match rows.get_mut(name) {
            Some(p) => p.dup = true,
            None => {
                rows.insert(
                    name.to_owned(),
                    Pkg {
                        version: version.to_owned(),
                        status,
                        dup: false,
                    },
                );
            }
        }
    }
    Ok(rows)
}

/// An installed kernel image.
struct Image {
    uname: String,
    version: Version,
}

/// The installed (in any state but config-files) `linux-image-<ver>` and
/// `linux-image-unsigned-<ver>` packages, `-dbg` and `-dbgsym` left out as
/// apt leaves them out. A version that does not parse fails.
fn images(rows: &Rows) -> Result<Vec<Image>, String> {
    let mut out = Vec::new();
    for (name, p) in rows.iter().filter(|(_, p)| p.installed()) {
        let Some(u) = name
            .strip_prefix("linux-image-unsigned-")
            .or_else(|| name.strip_prefix("linux-image-"))
        else {
            continue;
        };
        if !valid_uname(u) || u.ends_with("-dbg") || u.ends_with("-dbgsym") {
            continue;
        }
        if p.dup {
            return Err(format!("dpkg-query lists {name} twice"));
        }
        let version = Version::parse(&p.version).ok_or_else(|| {
            format!(
                "dpkg-query: {name} has the version {:?}, which diskwhy cannot read",
                p.version
            )
        })?;
        out.push(Image {
            uname: u.to_owned(),
            version,
        });
    }
    Ok(out)
}

/// The kernel releases that are kept.
struct Protection {
    keep: BTreeSet<String>,
    /// The releases of the newest installed versions.
    newest: Vec<String>,
}

fn protection(release: &str, images: &[Image], links: &[String]) -> Protection {
    let mut versions: Vec<&Version> = images.iter().map(|i| &i.version).collect();
    versions.sort_by(|a, b| b.cmp(a));
    versions.dedup();
    let top = &versions[..versions.len().min(KEEP_NEWEST)];
    let mut newest: Vec<String> = images
        .iter()
        .filter(|i| top.contains(&&i.version))
        .map(|i| i.uname.clone())
        .collect();
    newest.sort();
    newest.dedup();
    let mut keep: BTreeSet<String> = newest.iter().cloned().collect();
    keep.insert(release.to_owned());
    keep.extend(links.iter().cloned());
    Protection { keep, newest }
}

/// The packages of release `u`, sorted: its own and, when no other
/// installed package names its ABI with another flavour, the flavourless
/// ones. `Err` when one of them is in a state other than `ii` or `rc`, or
/// would belong to another installed image's release too.
fn version_packages(rows: &Rows, u: &str, images: &[Image]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (name, p) in rows.iter().filter(|(n, _)| flavoured_of(n, u)) {
        if p.dup {
            return Err(format!("dpkg-query lists {name} twice"));
        }
        if !p.settled() {
            return Err(format!("{name} is not fully installed"));
        }
        if let Some(other) = images
            .iter()
            .find(|i| i.uname != u && flavoured_of(name, &i.uname))
        {
            return Err(format!("{name} could belong to {u} or to {}", other.uname));
        }
        out.push(name.clone());
    }
    if let Some(abi) = upstream_abi(u) {
        let needle = format!("-{abi}-");
        let shared_needed = rows
            .iter()
            .any(|(n, p)| p.installed() && n.contains(&needle) && !flavoured_of(n, u));
        for (name, p) in rows.iter().filter(|(n, _)| shared_of(n, abi)) {
            if p.dup {
                return Err(format!("dpkg-query lists {name} twice"));
            }
            if !p.settled() {
                return Err(format!("{name} is not fully installed"));
            }
            if !shared_needed {
                out.push(name.clone());
            }
        }
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// apt's simulation
// ---------------------------------------------------------------------------

/// A package a simulation removes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Removal {
    pub(crate) name: String,
    /// `Purg` rather than `Remv`.
    pub(crate) purge: bool,
}

/// The removals in `apt-get -s` output (`LANG=C`). Fails on an `Inst` or
/// `Conf` line, a malformed `Remv` or `Purg` line, a package removed twice,
/// and unless exactly one summary line says nothing is installed, upgraded,
/// reinstalled or downgraded and counts as many removals as listed.
pub(crate) fn parse_simulation(out: &[u8]) -> Result<Vec<Removal>, String> {
    let text = std::str::from_utf8(out).map_err(|_| "apt-get's output is not UTF-8")?;
    let mut removed: Vec<Removal> = Vec::new();
    let mut summary = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Remv ") {
            removed.push(Removal {
                name: simulated_name(rest).ok_or_else(|| format!("cannot read {line:?}"))?,
                purge: false,
            });
        } else if let Some(rest) = line.strip_prefix("Purg ") {
            removed.push(Removal {
                name: simulated_name(rest).ok_or_else(|| format!("cannot read {line:?}"))?,
                purge: true,
            });
        } else if line.starts_with("Inst ") || line.starts_with("Conf ") {
            return Err(format!(
                "apt would install or configure a package: {line:?}"
            ));
        } else if let Some(s) = parse_summary(line)
            && summary.replace(s).is_some()
        {
            return Err("apt-get printed two summary lines".into());
        }
    }
    let (changed, to_remove) = summary.ok_or("apt-get printed no summary line")?;
    if changed != 0 {
        return Err("apt would install, upgrade or downgrade packages too".into());
    }
    if to_remove != removed.len() as u64 {
        return Err(format!(
            "apt-get's summary counts {to_remove} removals but lists {}",
            removed.len()
        ));
    }
    let mut seen = BTreeSet::new();
    if let Some(dup) = removed.iter().find(|r| !seen.insert(&r.name)) {
        return Err(format!("apt-get lists {} twice", dup.name));
    }
    Ok(removed)
}

/// The package of a `Remv`/`Purg` line: `<name>[:<arch>]`, then nothing or
/// one or more ` [...]` groups.
fn simulated_name(rest: &str) -> Option<String> {
    let (name, tail) = match rest.split_once(' ') {
        Some((n, t)) => (n, Some(t)),
        None => (rest, None),
    };
    let (pkg, arch) = match name.split_once(':') {
        Some((p, a)) => (p, Some(a)),
        None => (name, None),
    };
    if !valid_package_name(pkg)
        || arch.is_some_and(|a| {
            a.is_empty()
                || !a
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
    {
        return None;
    }
    if let Some(mut t) = tail {
        loop {
            let (inner, after) = t.strip_prefix('[')?.split_once(']')?;
            if inner.contains('[') {
                return None;
            }
            if after.is_empty() {
                break;
            }
            t = after.strip_prefix(' ')?;
        }
    }
    Some(name.to_owned())
}

/// `N upgraded, N newly installed, [N reinstalled, ][N downgraded, ]N to
/// remove and N not upgraded.`: the packages installed, upgraded,
/// reinstalled or downgraded, and those removed.
fn parse_summary(line: &str) -> Option<(u64, u64)> {
    let num = |s: &str| -> Option<u64> {
        (!s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let body = line.strip_suffix(" not upgraded.")?;
    let (left, kept) = body.rsplit_once(" and ")?;
    num(kept)?;
    let parts: Vec<&str> = left.split(", ").collect();
    let (first, rest) = parts.split_first()?;
    let (last, middle) = rest.split_last()?;
    let mut changed = num(first.strip_suffix(" upgraded")?)?;
    let (second, extra) = middle.split_first()?;
    changed += num(second.strip_suffix(" newly installed")?)?;
    for (k, p) in extra.iter().enumerate() {
        let n = match (
            k,
            p.strip_suffix(" reinstalled"),
            p.strip_suffix(" downgraded"),
        ) {
            (0, Some(n), _) => n,
            (_, None, Some(n)) if k < 2 => n,
            _ => return None,
        };
        changed += num(n)?;
    }
    Some((changed, num(last.strip_suffix(" to remove")?)?))
}

// ---------------------------------------------------------------------------
// Running the tools
// ---------------------------------------------------------------------------

/// Runs `prog args` with no stdin, `LANG=C`, without the caller's apt and
/// dpkg location overrides, killed after `timeout` or when the context is
/// cancelled. Its stdout, or why it failed.
fn run(
    ctx: &DetectContext,
    prog: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new(prog);
    cmd.args(args)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .env_remove("APT_CONFIG")
        .env_remove("DPKG_ADMINDIR")
        .env_remove("DPKG_ROOT")
        .current_dir("/");
    let shown = std::iter::once(prog)
        .chain(args.iter().copied().take(3))
        .collect::<Vec<_>>()
        .join(" ");
    let out =
        cancel::output(&mut cmd, &ctx.cancel, Some(timeout), MAX_OUTPUT).map_err(|e| match e {
            RunError::Canceled => "canceled".to_string(),
            RunError::Spawn(e) | RunError::Wait(e) => format!("cannot run {prog}: {e}"),
            RunError::Timeout => format!("`{shown}` timed out"),
        })?;
    if out.stdout.len() as u64 >= MAX_OUTPUT {
        return Err(format!("`{shown}` printed more than diskwhy reads"));
    }
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        return Err(format!(
            "`{shown}` failed ({}): {}",
            out.status,
            last.trim()
        ));
    }
    Ok(out.stdout)
}

fn dpkg_rows(ctx: &DetectContext, dpkg: &str) -> Result<Rows, String> {
    parse_rows(&run(ctx, dpkg, &["-W", STATUS_FORMAT], DPKG_TIMEOUT)?)
}

/// The paths `dpkg-query -L` lists for `pkgs`; `None` when the list holds
/// anything else (a diversion), so the files are not known for sure.
fn file_list(ctx: &DetectContext, dpkg: &str, pkgs: &[String]) -> Option<Vec<Vec<u8>>> {
    let mut args = vec!["-L"];
    args.extend(pkgs.iter().map(String::as_str));
    let out = run(ctx, dpkg, &args, DPKG_TIMEOUT).ok()?;
    let mut paths = Vec::new();
    for line in out.split(|&b| b == b'\n') {
        if line.is_empty() || line == b"/." {
            continue;
        }
        if line.starts_with(b"/") {
            paths.push(line.to_vec());
        } else if !(line.starts_with(b"Package '")
            && line.ends_with(b"' does not contain any files (!)"))
        {
            return None;
        }
    }
    Some(paths)
}

// ---------------------------------------------------------------------------
// The filesystem
// ---------------------------------------------------------------------------

const PATH_DIR: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// The directory at the absolute `path`, opened from `/` one component at
/// a time with `O_NOFOLLOW`: `None` when any of them is a symlink, is not a
/// directory or cannot be opened.
fn open_dir_nofollow(path: &Path) -> Option<OwnedFd> {
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return None;
    }
    let mut fd = rustix::fs::open("/", PATH_DIR, Mode::empty()).ok()?;
    for part in parts {
        let Component::Normal(name) = part else {
            return None;
        };
        fd = rustix::fs::openat(&fd, name, PATH_DIR, Mode::empty()).ok()?;
    }
    Some(fd)
}

/// The top-level directories of `root` that are usrmerge's symlinks to
/// `usr/<name>`, read with `readlinkat`.
fn usrmerge_aliases(root: &Path) -> Vec<&'static str> {
    let Some(fd) = open_dir_nofollow(root) else {
        return Vec::new();
    };
    USRMERGE
        .into_iter()
        .filter(|d| {
            rustix::fs::readlinkat(&fd, *d, Vec::new())
                .is_ok_and(|t| t.as_bytes() == format!("usr/{d}").as_bytes())
        })
        .collect()
}

/// The system path `listed` (absolute) under `root`, at its `/usr`
/// spelling when it starts in a usrmerge alias. `None` for a path that is
/// not absolute, names `..` or is `/` itself.
fn resolve(root: &Path, aliases: &[&str], listed: &[u8]) -> Option<PathBuf> {
    let mut parts = Path::new(OsStr::from_bytes(listed)).components();
    if parts.next() != Some(Component::RootDir) {
        return None;
    }
    let names: Vec<&OsStr> = parts
        .map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let first = names.first()?;
    let mut out = root.to_path_buf();
    if aliases.iter().any(|a| OsStr::new(a) == *first) {
        out.push("usr");
    }
    out.extend(names);
    Some(out)
}

/// What purging one version frees.
#[derive(Default)]
struct Tally {
    bytes: u64,
    files: u64,
    /// Files purged that stay hardlinked to a name kept.
    linked: u64,
}

/// One inode among the files purged.
struct Inode {
    allocated: u64,
    nlink: u64,
    names: u64,
    under_root: bool,
}

/// Counts the regular files at `paths` the walk can vouch for: their
/// directory is a node of `tree`, still that directory (reached without
/// following a symlink), and the file is on its device. Bytes under
/// `root_dir` are capped at `root`'s freeable bytes.
fn tally(tree: &ScanTree, paths: &BTreeSet<PathBuf>, root_dir: &Path, root: &TreeNode) -> Tally {
    let mut by_dir: BTreeMap<&Path, Vec<&OsStr>> = BTreeMap::new();
    for p in paths {
        if let (Some(dir), Some(name)) = (p.parent(), p.file_name()) {
            by_dir.entry(dir).or_default().push(name);
        }
    }
    let mut inodes: HashMap<(u64, u64), Inode> = HashMap::new();
    for (dir, names) in by_dir {
        let Some(node) = tree.find(dir).map(|id| tree.node(id)) else {
            continue;
        };
        if !node.is_dir {
            continue;
        }
        let Some(fd) = open_dir_nofollow(dir) else {
            continue;
        };
        match rustix::fs::fstat(&fd) {
            Ok(st) if (st.st_dev, st.st_ino) == (node.dev, node.ino) => {}
            _ => continue,
        }
        let under_root = dir.starts_with(root_dir);
        for name in names {
            let Ok(st) = rustix::fs::statat(&fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
                continue;
            };
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile || st.st_dev != node.dev
            {
                continue;
            }
            let i = inodes.entry((st.st_dev, st.st_ino)).or_insert(Inode {
                allocated: st.st_blocks.max(0) as u64 * 512,
                nlink: nlink(&st),
                names: 0,
                under_root: false,
            });
            i.names += 1;
            i.under_root |= under_root;
        }
    }
    let mut t = Tally::default();
    let mut under = 0;
    for i in inodes.values() {
        if i.names < i.nlink {
            t.linked += i.allocated;
            continue;
        }
        t.bytes += i.allocated;
        t.files += i.names;
        if i.under_root {
            under += i.allocated;
        }
    }
    t.bytes -= under.saturating_sub(root.freeable());
    t
}

/// Link count; `st_nlink` is narrower than u64 on some targets.
#[allow(clippy::unnecessary_cast)]
fn nlink(st: &rustix::fs::Stat) -> u64 {
    st.st_nlink as u64
}

/// The releases `/boot/vmlinuz` and `/boot/vmlinuz.old` in `boot` name,
/// read with `readlinkat`. Missing links (or a missing `boot`) are fine;
/// one that is not a symlink, cannot be read or names anything but
/// `vmlinuz-<release>` (or `/boot/vmlinuz-<release>`) fails.
fn boot_links(boot: &Path) -> Result<Vec<String>, String> {
    let fd = match rustix::fs::open(boot, PATH_DIR, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", boot.display())),
    };
    let mut out = Vec::new();
    for name in ["vmlinuz", "vmlinuz.old"] {
        let shown = boot.join(name);
        let target = match rustix::fs::readlinkat(&fd, name, Vec::new()) {
            Ok(t) => t,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(rustix::io::Errno::INVAL) => {
                return Err(format!("{} is not a symlink", shown.display()));
            }
            Err(e) => return Err(format!("cannot read {}: {e}", shown.display())),
        };
        let t = target.to_str().unwrap_or("");
        let u = t
            .strip_prefix("vmlinuz-")
            .or_else(|| t.strip_prefix("/boot/vmlinuz-"))
            .filter(|u| valid_uname(u))
            .ok_or_else(|| {
                format!(
                    "{} points to {:?}, not a kernel diskwhy can read",
                    shown.display(),
                    target
                )
            })?;
        out.push(u.to_owned());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The detector
// ---------------------------------------------------------------------------

impl Detector for OldKernels {
    fn name(&self) -> &'static str {
        "old-kernels"
    }

    fn detect_candidates(
        &self,
        tree: &ScanTree,
        ctx: &DetectContext,
    ) -> Result<Vec<Candidate>, String> {
        let aliases = usrmerge_aliases(&self.root);
        let mut module_dirs: Vec<PathBuf> = MODULE_DIRS
            .iter()
            .filter_map(|d| resolve(&self.root, &aliases, format!("/{d}").as_bytes()))
            .filter(|d| tree.find(d).is_some_and(|id| tree.node(id).is_dir))
            .collect();
        module_dirs.dedup();
        if module_dirs.is_empty() {
            return Ok(Vec::new());
        }
        let release = self.release()?;
        let apt = ctx
            .tool_command("apt-get")
            .ok_or("`apt-get` is not installed")?;
        let dpkg = ctx
            .tool_command("dpkg-query")
            .ok_or("`dpkg-query` is not installed")?;
        let rows = dpkg_rows(ctx, &dpkg)?;
        let images = images(&rows)?;
        if images.is_empty() {
            return Ok(Vec::new());
        }
        let links = boot_links(&self.root.join("boot"))?;
        let protection = protection(&release, &images, &links);
        let autoremove: BTreeSet<String> =
            parse_simulation(&run(ctx, &apt, &["-s", "autoremove"], APT_TIMEOUT)?)
                .map_err(|e| format!("apt-get -s autoremove: {e}"))?
                .into_iter()
                .map(|r| r.name)
                .collect();

        let unames: BTreeSet<&str> = images.iter().map(|i| i.uname.as_str()).collect();
        let mut out = Vec::new();
        for u in unames {
            let image = format!("linux-image-{u}");
            if protection.keep.contains(u)
                || !rows.get(&image).is_some_and(|p| &p.status == b"ii ")
                || !autoremove.contains(&image)
            {
                continue;
            }
            let Ok(pkgs) = version_packages(&rows, u, &images) else {
                continue;
            };
            let Some((dir, node)) = module_dirs.iter().map(|d| d.join(u)).find_map(|d| {
                let node = tree.find(&d).map(|id| tree.node(id))?;
                node.is_dir.then_some((d, node))
            }) else {
                continue;
            };
            let Some(listed) = file_list(ctx, &dpkg, &pkgs) else {
                continue;
            };
            let mut paths: BTreeSet<PathBuf> = listed
                .iter()
                .filter_map(|p| resolve(&self.root, &aliases, p))
                .collect();
            paths.extend(
                BOOT_FILES
                    .iter()
                    .map(|f| self.root.join("boot").join(format!("{f}-{u}"))),
            );
            let t = tally(tree, &paths, &dir, node);
            if t.bytes < MIN_BYTES {
                continue;
            }
            let version = rows[&image].version.clone();
            out.push(candidate(
                &Facts {
                    apt: &apt,
                    release: &release,
                    uname: u,
                    version: &version,
                    newest: &protection.newest,
                    pkgs: &pkgs,
                    rows: &rows,
                },
                dir,
                node,
                &t,
            ));
        }
        Ok(out)
    }
}

/// What a finding says about one version.
struct Facts<'a> {
    apt: &'a str,
    release: &'a str,
    uname: &'a str,
    version: &'a str,
    newest: &'a [String],
    pkgs: &'a [String],
    rows: &'a Rows,
}

fn candidate(f: &Facts, dir: PathBuf, node: &TreeNode, t: &Tally) -> Candidate {
    let path_s = dir.to_string_lossy().into_owned();
    let argv = action_argv(f.apt, f.pkgs);
    let text = argv
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    let u = f.uname;
    let n = f.pkgs.len();
    let mut reason = format!(
        "kernel {u} (package version {}), which apt's autoremove would remove: not the running kernel ({}), not one of the {KEEP_NEWEST} newest installed ({}) and not /boot/vmlinuz or /boot/vmlinuz.old; purging its {n} package{} ({}) frees {} in {} file{} (its modules, headers, tools and /boot files)",
        f.version,
        f.release,
        f.newest.join(", "),
        if n == 1 { "" } else { "s" },
        f.pkgs.join(", "),
        human(t.bytes),
        t.files,
        if t.files == 1 { "" } else { "s" },
    );
    if t.linked > 0 {
        reason.push_str(&format!(
            "; {} more is hardlinked elsewhere and is not freed",
            human(t.linked)
        ));
    }
    reason.push_str(&format!(
        "; the {APT_REMOVAL_SET} guard simulates the removal and blocks it if apt would remove any other package"
    ));
    let installed: Vec<&str> = f
        .pkgs
        .iter()
        .filter(|p| f.rows.get(*p).is_some_and(|r| r.installed()))
        .map(String::as_str)
        .collect();
    let finding = Finding {
        file_identity: None,
        id: finding_id("old-kernels", &path_s),
        detector: "old-kernels".into(),
        probe: None,
        evidence: None,
        bytes: t.bytes,
        nested_bytes: None,
        last_modified: Some(rfc3339(node.newest_mtime)),
        growth: None,
        tier: Tier::Review,
        reason,
        guards: Vec::new(),
        action: Action {
            kind: ActionKind::Command,
            text,
            argv: Some(argv),
        },
        recovery: Recovery {
            cost: format!(
                "kernel {u} can no longer be booted as a fallback; reinstalling it needs version {} of its packages, which the archive drops once newer kernels replace it",
                f.version
            ),
            how: Some(format!("apt-get install {}", installed.join(" "))),
        },
        path: path_s,
    };
    Candidate::new(dir, finding)
}

/// The action: `env -u APT_CONFIG DEBIAN_FRONTEND=noninteractive <apt-get>
/// remove --purge -y --no-auto-remove <pkgs>`.
fn action_argv(apt: &str, pkgs: &[String]) -> Vec<String> {
    ACTION_ENV
        .iter()
        .map(|s| s.to_string())
        .chain(std::iter::once(apt.to_string()))
        .chain(ACTION_ARGS.iter().map(|s| s.to_string()))
        .chain(pkgs.iter().cloned())
        .collect()
}

/// apt-get and the packages of an action [`action_argv`] built; `None` for
/// any other argv, or packages that are not sorted, unique kernel package
/// names.
fn parse_action(argv: &[String]) -> Option<(&str, Vec<&str>)> {
    let (head, rest) = argv.split_at_checked(ACTION_ENV.len())?;
    let (apt, rest) = rest.split_first()?;
    let (args, pkgs) = rest.split_at_checked(ACTION_ARGS.len())?;
    if head.iter().zip(ACTION_ENV).any(|(a, b)| a != b)
        || args.iter().zip(ACTION_ARGS).any(|(a, b)| a != b)
        || apt.is_empty()
        || apt.contains('\0')
        || pkgs.is_empty()
        || !pkgs.iter().all(|p| valid_kernel_package(p))
        || !pkgs.windows(2).all(|w| w[0] < w[1])
    {
        return None;
    }
    Some((apt, pkgs.iter().map(String::as_str).collect()))
}

/// The system root and release of an `old-kernels` finding's path,
/// `<root>/usr/lib/modules/<release>` or `<root>/lib/modules/<release>`.
pub(crate) fn finding_kernel(path: &str) -> Option<(PathBuf, &str)> {
    let p = Path::new(path);
    let u = p.file_name()?.to_str()?;
    if !p.is_absolute() || !valid_uname(u) {
        return None;
    }
    let parent = p.parent()?;
    for d in MODULE_DIRS {
        if parent.ends_with(d) {
            let mut root = parent.to_path_buf();
            for _ in Path::new(d).components() {
                root.pop();
            }
            return Some((root, u));
        }
    }
    None
}

/// Where the process guards look for an `old-kernels` finding besides its
/// modules directory: each headers package's `/usr/src/<package>` and the
/// tools packages' `/usr/lib/linux-tools/<release>` and
/// `/usr/lib/linux-tools-<abi>`, so a DKMS build or a `perf` running from
/// them blocks.
pub(crate) fn process_roots(f: &Finding) -> Vec<PathBuf> {
    let Some((root, u)) = finding_kernel(&f.path) else {
        return Vec::new();
    };
    let Some((_, pkgs)) = parse_action(f.action.argv.as_deref().unwrap_or_default()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in pkgs {
        if p.starts_with("linux-headers-") {
            out.push(root.join("usr/src").join(p));
        } else if let Some(v) = p.strip_prefix("linux-tools-") {
            if v == u {
                out.push(root.join("usr/lib/linux-tools").join(v));
            } else {
                out.push(root.join("usr/lib").join(p));
            }
        }
    }
    out
}

/// The `apt-removal-set` guard for an `old-kernels` finding, with
/// `release` as the running kernel's ([`running_release`]). It blocks
/// unless, read afresh:
///
/// - the action is exactly the one the detector builds;
/// - the version is not the running kernel, one of the two newest
///   installed or a `/boot/vmlinuz` or `vmlinuz.old` target, and no listed
///   package belongs to such a kernel;
/// - the listed packages are exactly the version's packages `dpkg-query`
///   reports now, each installed or config-files only;
/// - `LANG=C apt-get -s remove --purge --no-auto-remove <packages>` (with
///   the action's apt-get) succeeds and purges exactly those packages and
///   nothing else, installing nothing.
///
/// A check that cannot run blocks.
pub fn removal_set_guard(
    f: &Finding,
    ctx: &DetectContext,
    release: Result<String, String>,
) -> GuardResult {
    let (status, detail) = match check_removal(f, ctx, release) {
        Ok(detail) => (GuardStatus::Pass, detail),
        Err(detail) => (GuardStatus::Block, detail),
    };
    GuardResult {
        name: APT_REMOVAL_SET.into(),
        status,
        detail,
    }
}

fn check_removal(
    f: &Finding,
    ctx: &DetectContext,
    release: Result<String, String>,
) -> Result<String, String> {
    let (apt, pkgs) = parse_action(f.action.argv.as_deref().unwrap_or_default())
        .ok_or("the action is not the `apt-get remove --purge` diskwhy builds")?;
    let (root, u) =
        finding_kernel(&f.path).ok_or("the path is not a kernel's modules directory")?;
    let release =
        release.map_err(|e| format!("cannot tell the running kernel, so cannot check: {e}"))?;
    let dpkg = ctx
        .tool_command("dpkg-query")
        .ok_or("`dpkg-query` is not installed, so cannot check")?;
    let rows = dpkg_rows(ctx, &dpkg)?;
    let images = images(&rows)?;
    let links = boot_links(&root.join("boot"))?;
    let protection = protection(&release, &images, &links);
    if protection.keep.contains(u) {
        return Err(format!(
            "{u} is kept: the running kernel ({release}), one of the {KEEP_NEWEST} newest installed or a /boot/vmlinuz target"
        ));
    }
    for p in &pkgs {
        if let Some(k) = protection.keep.iter().find(|k| belongs(p, k)) {
            return Err(format!("{p} belongs to the kept kernel {k}"));
        }
    }
    let expected = version_packages(&rows, u, &images)?;
    if expected.iter().map(String::as_str).ne(pkgs.iter().copied()) {
        return Err(format!(
            "the packages of {u} are now {}, not the listed {}",
            expected.join(", "),
            pkgs.join(", ")
        ));
    }
    let mut args: Vec<&str> = SIMULATE_ARGS.to_vec();
    args.extend(pkgs.iter().copied());
    let out = run(ctx, apt, &args, APT_TIMEOUT)
        .map_err(|e| format!("the removal's simulation failed: {e}"))?;
    let removed =
        parse_simulation(&out).map_err(|e| format!("cannot read the removal's simulation: {e}"))?;
    let extra: Vec<&str> = removed
        .iter()
        .map(|r| r.name.as_str())
        .filter(|n| !pkgs.contains(n))
        .collect();
    if !extra.is_empty() {
        return Err(format!("apt would also remove {}", extra.join(", ")));
    }
    let missing: Vec<&str> = pkgs
        .iter()
        .copied()
        .filter(|p| !removed.iter().any(|r| r.name == *p))
        .collect();
    if !missing.is_empty() {
        return Err(format!("apt would not remove {}", missing.join(", ")));
    }
    if let Some(r) = removed.iter().find(|r| !r.purge) {
        return Err(format!("apt would remove {} without purging it", r.name));
    }
    Ok(format!(
        "`apt-get -s remove --purge --no-auto-remove` purges exactly the {} listed package{} and nothing else",
        pkgs.len(),
        if pkgs.len() == 1 { "" } else { "s" }
    ))
}

/// For the plan fingerprint: FNV-1a (hex) of the name, version and status
/// `dpkg-query` reports now for an `old-kernels` finding's packages, so a
/// package upgraded, reinstalled or removed since the plan re-plans.
/// `None` when they cannot be read.
pub(crate) fn package_state(f: &Finding, ctx: &DetectContext) -> Option<String> {
    let (_, pkgs) = parse_action(f.action.argv.as_deref().unwrap_or_default())?;
    let dpkg = ctx.tool_command("dpkg-query")?;
    let mut args = vec!["-W", STATUS_FORMAT];
    args.extend(pkgs);
    let out = run(ctx, &dpkg, &args, DPKG_TIMEOUT).ok()?;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &out {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Some(format!("{h:016x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        Version::parse(a)
            .unwrap_or_else(|| panic!("{a}"))
            .cmp(&Version::parse(b).unwrap_or_else(|| panic!("{b}")))
    }

    #[test]
    fn debian_versions_order_as_dpkg_orders_them() {
        use Ordering::*;
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.0", "1.00", Equal),
            ("1.0-0", "1.0", Equal),
            ("0:1.0", "1.0", Equal),
            ("1.0", "1.1", Less),
            ("1.10", "1.9", Greater),
            ("1:0.1", "9.9", Greater),
            ("2:1", "10:0", Less),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~~", "1.0~", Less),
            ("1.0~", "1.0", Less),
            ("1.0", "1.0+b1", Less),
            ("1.0", "1.0a", Less),
            ("1.0a", "1.0+", Less),
            ("1.0-1", "1.0-2", Less),
            ("1.0-10", "1.0-9", Greater),
            ("1.0-1ubuntu1", "1.0-1", Greater),
            ("1.0-1~bpo1", "1.0-1", Less),
            ("7.0.0-43.43", "7.0.0-44.44", Less),
            ("7.0.0-44.44", "7.0.0-43.43", Greater),
            ("7.0.0-9.9", "7.0.0-10.10", Less),
            ("7.0.0-31.31+2", "7.0.0-31.31", Greater),
            ("7.0.0-31.31+1", "7.0.0-31.31+2", Less),
            ("6.1.0-28", "6.1.0-28+b1", Less),
            ("1:2.0.32-3ubuntu1", "1:2.0.32-3", Greater),
            ("1.6~rc1-1build1", "1.6-1", Less),
            ("1:1.2-3:4-5", "1:1.2-3:4-6", Less),
        ] {
            assert_eq!(cmp(a, b), want, "{a} vs {b}");
            assert_eq!(cmp(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn versions_dpkg_would_refuse_do_not_parse() {
        for bad in [
            "", " ", "1.0 ", "a1.0", ":1.0", "x:1.0", "1:", "1.0-", "-1", "1.0_1", "1.0-1_2",
            "1.0-1:2", "1.0/1", "1:a", "~1",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
        for ok in [
            "0",
            "1",
            "1.0-1",
            "1:1.0",
            "1.0~rc1-0ubuntu1~22.04",
            "7.0.0-43.43",
        ] {
            assert!(Version::parse(ok).is_some(), "{ok:?}");
        }
    }

    #[test]
    fn releases_and_their_abis() {
        for (u, abi) in [
            ("7.0.0-43-generic", Some("7.0.0-43")),
            ("6.8.0-1017-azure", Some("6.8.0-1017")),
            ("6.8.0-1015-nvidia-lowlatency", Some("6.8.0-1015")),
            ("6.1.0-28-amd64", Some("6.1.0-28")),
            ("6.1.0-28-cloud-amd64", Some("6.1.0-28")),
            ("6.12.12+bpo-amd64", None),
            ("6.12.0", None),
            ("6.12.0-1", None),
        ] {
            assert!(valid_uname(u), "{u}");
            assert_eq!(upstream_abi(u), abi, "{u}");
        }
        for bad in [
            "",
            "6",
            "6.",
            "generic",
            "a6.1",
            "6.1.0-43-Generic",
            "6.1.0-43-",
            "6..1",
            "6.1/0",
            "6.1 0",
            "6.1.0_1",
        ] {
            assert!(!valid_uname(bad), "{bad}");
        }
    }

    #[test]
    fn packages_of_a_release() {
        let u = "7.0.0-43-generic";
        for p in [
            "linux-image-7.0.0-43-generic",
            "linux-image-unsigned-7.0.0-43-generic",
            "linux-modules-7.0.0-43-generic",
            "linux-modules-extra-7.0.0-43-generic",
            "linux-modules-nvidia-595-open-7.0.0-43-generic",
            "linux-main-modules-zfs-7.0.0-43-generic",
            "linux-objects-nvidia-595-open-7.0.0-43-generic",
            "linux-signatures-nvidia-7.0.0-43-generic",
            "linux-buildinfo-7.0.0-43-generic",
            "linux-headers-7.0.0-43-generic",
            "linux-tools-7.0.0-43-generic",
            "linux-cloud-tools-7.0.0-43-generic",
        ] {
            assert!(flavoured_of(p, u), "{p}");
            assert!(belongs(p, u), "{p}");
        }
        for p in [
            "linux-headers-7.0.0-43",
            "linux-tools-7.0.0-43",
            "linux-cloud-tools-7.0.0-43",
        ] {
            assert!(!flavoured_of(p, u), "{p}");
            assert!(belongs(p, u), "{p}");
        }
        for p in [
            "linux-image-7.0.0-44-generic",
            "linux-image-7.0.0-43-generic-dbgsym",
            "linux-image-7.0.0-43-lowlatency",
            "linux-image-generic-hwe-26.04",
            "linux-generic-hwe-26.04",
            "linux-headers-7.0.0-4",
            "linux-headers-7.0.0-430",
            "linux-tools-common",
            "linux-firmware",
            "linux-modules--7.0.0-43-generic",
            "linux-modules-7.0.0-43-generic-extra",
            "linux-source-7.0.0-43-generic",
            "linux-doc-7.0.0-43",
            "linux-image-17.0.0-43-generic",
            "xlinux-image-7.0.0-43-generic",
        ] {
            assert!(!belongs(p, u), "{p}");
        }
    }

    #[test]
    fn simulation_output() {
        let ok = b"NOTE: This is only a simulation!\n\
Reading package lists...\n\
The following packages will be REMOVED:\n  a* b*\n\
0 upgraded, 0 newly installed, 3 to remove and 5 not upgraded.\n\
Purg linux-headers-7.0.0-43 [7.0.0-43.43]\n\
Purg linux-image-7.0.0-43-generic [7.0.0-43.43] [linux-main-modules-v4l2loopback-7.0.0-43-generic:amd64 ]\n\
Purg linux-image-7.0.0-31-generic\n";
        let got = parse_simulation(ok).unwrap();
        assert_eq!(
            got.iter()
                .map(|r| (r.name.as_str(), r.purge))
                .collect::<Vec<_>>(),
            [
                ("linux-headers-7.0.0-43", true),
                ("linux-image-7.0.0-43-generic", true),
                ("linux-image-7.0.0-31-generic", true),
            ]
        );
        let autoremove = b"0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n\
Remv libfoo1 [1.0-1]\nRemv libbar:i386 [2]\n";
        assert_eq!(parse_simulation(autoremove).unwrap().len(), 2);
        let nothing = b"Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
        assert_eq!(parse_simulation(nothing).unwrap(), []);
        let reinstalled =
            b"0 upgraded, 0 newly installed, 0 reinstalled, 0 downgraded, 1 to remove and 0 not upgraded.\nRemv aa [1]\n";
        assert_eq!(parse_simulation(reinstalled).unwrap().len(), 1);

        for bad in [
            &b""[..],
            b"Remv aa [1]\n",
            b"1 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv aa [1]\n",
            b"0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.\nRemv aa [1]\n",
            b"0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\nRemv aa [1]\n",
            b"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv aa [1]\nInst b [1]\n",
            b"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nConf b [1]\n",
            b"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv aa [1\n",
            b"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv aa 1\n",
            b"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv aa  [1]\n",
            b"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv aa [1] \n",
            b"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv \n",
            b"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nPurg Bad/Name [1]\n",
            b"0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\nRemv aa [1]\nPurg aa\n",
            b"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
            b"0 upgraded, 0 newly installed, x to remove and 0 not upgraded.\n",
            b"0 upgraded, 0 newly installed, 0 frobbed, 0 to remove and 0 not upgraded.\n",
            b"\xff\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
        ] {
            assert!(
                parse_simulation(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn dpkg_rows() {
        let rows = parse_rows(
            b"linux-image-7.0.0-43-generic\t7.0.0-43.43\tii \n\
linux-image-7.0.0-30-generic\t\tun \n\
linux-image-7.0.0-30-generic\t\tun \n\
linux-modules-7.0.0-31-generic\t7.0.0-31.31\trc \n\
foo\t1\tiF \n",
        )
        .unwrap();
        assert_eq!(
            rows.keys().collect::<Vec<_>>(),
            [
                "foo",
                "linux-image-7.0.0-43-generic",
                "linux-modules-7.0.0-31-generic"
            ]
        );
        assert!(rows["linux-image-7.0.0-43-generic"].settled());
        assert!(rows["linux-modules-7.0.0-31-generic"].settled());
        assert!(!rows["linux-modules-7.0.0-31-generic"].installed());
        assert!(!rows["foo"].settled());
        assert!(rows["foo"].installed());
        let rows = parse_rows(b"libc6\t2.42\tii \nlibc6\t2.42\tii \nbash\t5\tii \n").unwrap();
        assert!(rows["libc6"].dup);
        assert!(!rows["bash"].dup);
        for bad in [
            &b"a\t1\tii\n"[..],
            b"a\t1\n",
            b"a\t1\tii \tx\n",
            b"a\t1\txi \n",
            b"a\t1\tiX \n",
            b"a\t1\tiiX\n",
            b"-a\t1\tii \n",
            b"a b\t1\tii \n",
            b"\n",
        ] {
            assert!(parse_rows(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn actions_and_finding_paths() {
        let pkgs = vec![
            "linux-headers-7.0.0-43".to_string(),
            "linux-image-7.0.0-43-generic".to_string(),
        ];
        let argv = action_argv("apt-get", &pkgs);
        assert_eq!(
            argv,
            [
                "env",
                "-u",
                "APT_CONFIG",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "remove",
                "--purge",
                "-y",
                "--no-auto-remove",
                "linux-headers-7.0.0-43",
                "linux-image-7.0.0-43-generic"
            ]
        );
        let (apt, got) = parse_action(&argv).unwrap();
        assert_eq!(
            (apt, got),
            ("apt-get", vec![pkgs[0].as_str(), pkgs[1].as_str()])
        );
        let mut unsorted = argv.clone();
        unsorted.swap(9, 10);
        assert!(parse_action(&unsorted).is_none());
        let mut other = argv.clone();
        other.push("bash".into());
        assert!(parse_action(&other).is_none());
        let mut opt = argv.clone();
        opt[9] = "-o".into();
        assert!(parse_action(&opt).is_none());
        assert!(parse_action(&argv[..9]).is_none());
        let mut forced = argv.clone();
        forced[7] = "--allow-remove-essential".into();
        assert!(parse_action(&forced).is_none());

        assert_eq!(
            finding_kernel("/usr/lib/modules/7.0.0-43-generic"),
            Some((PathBuf::from("/"), "7.0.0-43-generic"))
        );
        assert_eq!(
            finding_kernel("/t/x/lib/modules/7.0.0-43-generic"),
            Some((PathBuf::from("/t/x"), "7.0.0-43-generic"))
        );
        assert_eq!(finding_kernel("/usr/lib/modules/../x"), None);
        assert_eq!(finding_kernel("/usr/lib/modules"), None);
        assert_eq!(finding_kernel("/srv/7.0.0-43-generic"), None);
        assert_eq!(finding_kernel("usr/lib/modules/7.0.0-43-generic"), None);
    }

    #[test]
    fn protection_keeps_the_running_and_the_two_newest() {
        let img = |u: &str, v: &str| Image {
            uname: u.into(),
            version: Version::parse(v).unwrap(),
        };
        let images = [
            img("7.0.0-9-generic", "7.0.0-9.9"),
            img("7.0.0-10-generic", "7.0.0-10.10"),
            img("7.0.0-11-generic", "7.0.0-11.11"),
            img("7.0.0-11-lowlatency", "7.0.0-11.11"),
            img("7.0.0-12-generic", "7.0.0-12.12"),
        ];
        let p = protection("7.0.0-12-generic", &images, &[]);
        assert_eq!(
            p.keep.iter().collect::<Vec<_>>(),
            [
                "7.0.0-11-generic",
                "7.0.0-11-lowlatency",
                "7.0.0-12-generic"
            ]
        );
        // A reboot pending: the running kernel is kept on top of the newest two.
        let p = protection("7.0.0-9-generic", &images, &["7.0.0-10-generic".into()]);
        assert_eq!(
            p.keep.iter().collect::<Vec<_>>(),
            [
                "7.0.0-10-generic",
                "7.0.0-11-generic",
                "7.0.0-11-lowlatency",
                "7.0.0-12-generic",
                "7.0.0-9-generic"
            ]
        );
    }
}
