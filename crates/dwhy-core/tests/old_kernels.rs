//! `old-kernels` on temp-dir fixtures: a system root with modules, headers,
//! tools and `/boot` files for four kernels, and fake `dpkg-query` and
//! `apt-get` scripts that answer from files the tests write; never the
//! machine's dpkg or apt.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use dwhy_core::apply::{self, Audit, Env, Policy};
use dwhy_core::detect::{self, DetectContext, Detector, finding_id};
use dwhy_core::detectors::{APT_REMOVAL_SET, OldKernels, removal_set_guard};
use dwhy_core::guard::{Proc, Processes};
use dwhy_core::mounts::MountTable;
use dwhy_core::plan::{self, Selection};
use dwhy_core::report::{
    ActionKind, ApplyOutcome, DetectorAvailability, DockerSocket, Finding, GuardStatus, PlanScan,
    Tier, ToolStatus,
};
use dwhy_core::scan::{self, Progress, ScanOptions};
use dwhy_core::tree::ScanTree;

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;

/// The fixture's kernels: `9.8.0-<n>-generic`, package version
/// `9.8.0-<n>.<n>`.
const KERNELS: [u32; 4] = [9, 10, 11, 12];

fn uname(n: u32) -> String {
    format!("9.8.0-{n}-generic")
}

fn abi(n: u32) -> String {
    format!("9.8.0-{n}")
}

fn version(n: u32) -> String {
    format!("9.8.0-{n}.{n}")
}

fn base() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn scan_tree(root: &Path) -> ScanTree {
    let roots = scan::prepare_roots(&[root.to_path_buf()], true).unwrap();
    let opts = ScanOptions {
        min_dir_bytes: 0,
        threads: 2,
        ..ScanOptions::default()
    };
    scan::scan(
        &roots,
        &opts,
        &MountTable::read().unwrap(),
        &Progress::default(),
    )
    .unwrap()
    .tree
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn tool(name: &str, path: Option<&str>, off_path: Option<&str>) -> ToolStatus {
    ToolStatus {
        name: name.into(),
        path: path.map(String::from),
        off_path: off_path.map(String::from),
        enables: vec![],
    }
}

fn ctx(root: bool, tools: Vec<ToolStatus>) -> DetectContext {
    DetectContext {
        uid: if root { 0 } else { 1000 },
        root,
        home: None,
        now: now(),
        tools,
        docker_socket: DockerSocket {
            path: "/nonexistent".into(),
            exists: false,
            accessible: false,
        },
        docker: dwhy_core::docker::Source::none(),
        cancel: Default::default(),
        scratch_paths: Vec::new(),
        scratch_stale_days: dwhy_core::detectors::SCRATCH_STALE_DAYS,
    }
}

/// Writes an executable script at `path` from a child `sh`, so this
/// process never holds it open for writing (a child forked by another test
/// thread could inherit that descriptor and make running it fail with
/// ETXTBSY).
fn write_script(path: &Path, body: &str) {
    let mut sh = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 700 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    sh.stdin.take().unwrap().write_all(body.as_bytes()).unwrap();
    assert!(sh.wait().unwrap().success());
}

/// Writes `bytes` bytes at `p`, creating its directory.
fn write(p: &Path, bytes: usize) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, vec![7u8; bytes]).unwrap();
}

fn allocated(p: &Path) -> u64 {
    fs::symlink_metadata(p).unwrap().blocks() * 512
}

/// A system root (`root`) and the fake tools' directory (`data`).
struct Fx {
    _t: tempfile::TempDir,
    root: PathBuf,
    _d: tempfile::TempDir,
    data: PathBuf,
    apt: PathBuf,
    dpkg: PathBuf,
    /// Package name → (version, status) as `dpkg-query -W` reports it.
    rows: Vec<(String, String, String)>,
}

/// How big the fixture's files are.
#[derive(Clone, Copy)]
struct Sizes {
    module: usize,
    nvidia: usize,
}

const FULL: Sizes = Sizes {
    module: 2 * MIB,
    nvidia: MIB,
};

impl Fx {
    /// Four kernels, 9 to 12, with 12 running, `/boot/vmlinuz` at 12 and
    /// `vmlinuz.old` at 11; apt's autoremove lists the images of 9, 10 and
    /// 11.
    fn new(sizes: Sizes) -> Fx {
        let (t, root) = base();
        let (d, data) = base();
        fs::create_dir_all(root.join("usr/lib/modules")).unwrap();
        symlink("usr/lib", root.join("lib")).unwrap();
        fs::create_dir_all(root.join("boot")).unwrap();
        fs::create_dir_all(data.join("lists")).unwrap();
        let mut fx = Fx {
            _t: t,
            root,
            _d: d,
            data,
            apt: PathBuf::new(),
            dpkg: PathBuf::new(),
            rows: Vec::new(),
        };
        for n in KERNELS {
            fx.kernel(n, sizes);
        }
        fx.row("linux-generic-hwe-26.04", &version(12), "ii ");
        fx.row("linux-image-generic-hwe-26.04", &version(12), "ii ");
        fx.row("linux-tools-common", &version(12), "ii ");
        fx.row("linux-image-9.8.0-5-generic", &version(5), "rc ");
        fx.row("linux-modules-9.8.0-5-generic", &version(5), "rc ");
        fx.row("bash", "5.2.37-1", "ii ");
        fx.row("linux-image-9.8.0-4-generic", "", "un ");
        fx.save_rows();
        symlink(
            format!("vmlinuz-{}", uname(12)),
            fx.root.join("boot/vmlinuz"),
        )
        .unwrap();
        symlink(
            format!("vmlinuz-{}", uname(11)),
            fx.root.join("boot/vmlinuz.old"),
        )
        .unwrap();
        fx.autoremove(&[9, 10, 11]);
        fx.apt = fx.data.join("apt-get");
        fx.dpkg = fx.data.join("dpkg-query");
        let d = fx.data.display();
        write_script(
            &fx.dpkg,
            &format!(
                r#"#!/bin/sh
D='{d}'
case "$1" in
-W)
  shift 2
  if [ $# -eq 0 ]; then cat "$D/rows"; exit 0; fi
  for p in "$@"; do
    awk -F '\t' -v p="$p" '$1 == p {{ print; f = 1 }} END {{ exit !f }}' "$D/rows" || exit 1
  done
  ;;
-L)
  shift
  for p in "$@"; do
    if [ -f "$D/lists/$p" ]; then cat "$D/lists/$p"; else echo "Package '$p' does not contain any files (!)"; fi
    echo
  done
  ;;
*) exit 2 ;;
esac
"#
            ),
        );
        write_script(
            &fx.apt,
            &format!(
                r#"#!/bin/sh
D='{d}'
if [ "$1" = -s ]; then
  echo "$@" >> "$D/simulated"
  [ "$2 $3 $4 $5" = "-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=" ] || exit 3
  shift 5
  case "$1" in
  autoremove)
    cat "$D/autoremove"
    exit "$(cat "$D/autoremove.rc" 2>/dev/null || echo 0)"
    ;;
  remove)
    if [ -f "$D/remove" ]; then cat "$D/remove"; exit "$(cat "$D/remove.rc" 2>/dev/null || echo 0)"; fi
    shift 3
    n=$#
    if [ -f "$D/extra" ]; then n=$((n + 1)); fi
    echo "Reading package lists..."
    echo "0 upgraded, 0 newly installed, $n to remove and 0 not upgraded."
    for p in "$@"; do echo "Purg $p [1.0]"; done
    if [ -f "$D/extra" ]; then echo "Purg $(cat "$D/extra") [1.0]"; fi
    exit 0
    ;;
  esac
  exit 2
fi
if [ "$1" = remove ]; then printf '%s\n' "$@" > "$D/ran"; exit 0; fi
exit 2
"#
            ),
        );
        fx
    }

    /// One kernel's packages, files and file lists.
    fn kernel(&mut self, n: u32, sizes: Sizes) {
        let (u, a, v) = (uname(n), abi(n), version(n));
        let r = self.root.clone();
        write(
            &r.join(format!("usr/lib/modules/{u}/kernel/fs/big.ko")),
            sizes.module,
        );
        write(&r.join(format!("usr/lib/modules/{u}/modules.order")), 100);
        write(
            &r.join(format!("usr/lib/modules/{u}/kernel/nvidia/nvidia.ko")),
            sizes.nvidia,
        );
        write(&r.join(format!("boot/vmlinuz-{u}")), 64 * KIB);
        write(&r.join(format!("boot/System.map-{u}")), 16 * KIB);
        write(&r.join(format!("boot/config-{u}")), 8 * KIB);
        write(&r.join(format!("boot/initrd.img-{u}")), 32 * KIB);
        write(
            &r.join(format!("usr/src/linux-headers-{u}/Makefile")),
            8 * KIB,
        );
        symlink(
            format!("../linux-headers-{a}/include"),
            r.join(format!("usr/src/linux-headers-{u}/include")),
        )
        .unwrap();
        write(
            &r.join(format!("usr/src/linux-headers-{a}/include/x.h")),
            8 * KIB,
        );
        write(&r.join(format!("usr/lib/linux-tools/{u}/perf")), 16 * KIB);
        write(
            &r.join(format!("usr/lib/linux-tools-{a}/turbostat")),
            16 * KIB,
        );

        let dirs = "/.\n/usr\n/usr/lib\n";
        self.list(
            &format!("linux-image-{u}"),
            &format!("/.\n/boot\n/boot/vmlinuz-{u}\n/usr/share/doc/linux-image-{u}\n"),
        );
        self.list(
            &format!("linux-modules-{u}"),
            &format!(
                "{dirs}/boot\n/boot/System.map-{u}\n/boot/config-{u}\n/usr/lib/modules\n/usr/lib/modules/{u}\n/usr/lib/modules/{u}/kernel/fs/big.ko\n/usr/lib/modules/{u}/modules.order\n"
            ),
        );
        // Listed under `/lib`, as some packages still list it on a
        // usrmerged system.
        self.list(
            &format!("linux-modules-nvidia-595-open-{u}"),
            &format!("/.\n/lib\n/lib/modules/{u}/kernel/nvidia/nvidia.ko\n"),
        );
        self.list(
            &format!("linux-headers-{u}"),
            &format!(
                "{dirs}/usr/src\n/usr/src/linux-headers-{u}\n/usr/src/linux-headers-{u}/Makefile\n/usr/src/linux-headers-{u}/include\n"
            ),
        );
        self.list(
            &format!("linux-headers-{a}"),
            &format!("{dirs}/usr/src\n/usr/src/linux-headers-{a}/include/x.h\n"),
        );
        self.list(
            &format!("linux-tools-{u}"),
            &format!("{dirs}/usr/lib/linux-tools/{u}/perf\n"),
        );
        self.list(
            &format!("linux-tools-{a}"),
            &format!("{dirs}/usr/lib/linux-tools-{a}/turbostat\n"),
        );
        for p in [
            format!("linux-image-{u}"),
            format!("linux-modules-{u}"),
            format!("linux-modules-nvidia-595-open-{u}"),
            format!("linux-headers-{u}"),
            format!("linux-headers-{a}"),
            format!("linux-tools-{u}"),
            format!("linux-tools-{a}"),
        ] {
            self.row(&p, &v, "ii ");
        }
    }

    fn list(&self, pkg: &str, body: &str) {
        fs::write(self.data.join("lists").join(pkg), body).unwrap();
    }

    fn row(&mut self, name: &str, version: &str, status: &str) {
        self.rows.retain(|(n, _, _)| n != name);
        self.rows.push((name.into(), version.into(), status.into()));
    }

    fn save_rows(&self) {
        let text: String = self
            .rows
            .iter()
            .map(|(n, v, s)| format!("{n}\t{v}\t{s}\n"))
            .collect();
        fs::write(self.data.join("rows"), text).unwrap();
    }

    /// Sets a package's status (and saves the rows).
    fn status(&mut self, name: &str, status: &str) {
        let v = self
            .rows
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, v, _)| v.clone())
            .unwrap_or_else(|| "1".into());
        self.row(name, &v, status);
        self.save_rows();
    }

    /// apt's autoremove lists the images of `kernels` and a library.
    fn autoremove(&self, kernels: &[u32]) {
        let mut lines = vec!["Remv libfoo1 [1.0-1]".to_string()];
        lines.extend(
            kernels
                .iter()
                .map(|&n| format!("Remv linux-image-{} [{}]", uname(n), version(n))),
        );
        let text = format!(
            "Reading package lists...\nBuilding dependency tree...\n0 upgraded, 0 newly installed, {} to remove and 0 not upgraded.\n{}\n",
            lines.len(),
            lines.join("\n")
        );
        fs::write(self.data.join("autoremove"), text).unwrap();
    }

    fn tools(&self) -> Vec<ToolStatus> {
        vec![
            tool("apt-get", None, Some(self.apt.to_str().unwrap())),
            tool("dpkg-query", None, Some(self.dpkg.to_str().unwrap())),
        ]
    }

    fn ctx(&self) -> DetectContext {
        ctx(true, self.tools())
    }

    fn detector(&self, release: u32) -> OldKernels {
        OldKernels::with_root(self.root.clone(), Ok(uname(release)))
    }

    fn detect_with(&self, release: u32) -> Result<Vec<Finding>, String> {
        self.detector(release)
            .detect(&scan_tree(&self.root), &self.ctx())
    }

    fn detect(&self) -> Vec<Finding> {
        self.detect_with(12).unwrap()
    }

    fn modules(&self, n: u32) -> PathBuf {
        self.root.join("usr/lib/modules").join(uname(n))
    }

    /// The bytes purging kernel `n` frees in the fixture as built.
    fn freed(&self, n: u32, shared: bool) -> u64 {
        let (u, a) = (uname(n), abi(n));
        let mut files = vec![
            format!("usr/lib/modules/{u}/kernel/fs/big.ko"),
            format!("usr/lib/modules/{u}/modules.order"),
            format!("usr/lib/modules/{u}/kernel/nvidia/nvidia.ko"),
            format!("boot/vmlinuz-{u}"),
            format!("boot/System.map-{u}"),
            format!("boot/config-{u}"),
            format!("boot/initrd.img-{u}"),
            format!("usr/src/linux-headers-{u}/Makefile"),
            format!("usr/lib/linux-tools/{u}/perf"),
        ];
        if shared {
            files.push(format!("usr/src/linux-headers-{a}/include/x.h"));
            files.push(format!("usr/lib/linux-tools-{a}/turbostat"));
        }
        files.iter().map(|f| allocated(&self.root.join(f))).sum()
    }

    fn simulated(&self) -> String {
        fs::read_to_string(self.data.join("simulated")).unwrap_or_default()
    }
}

fn paths(found: &[Finding]) -> Vec<String> {
    let mut v: Vec<String> = found.iter().map(|f| f.path.clone()).collect();
    v.sort();
    v
}

fn kernel_paths(fx: &Fx, kernels: &[u32]) -> Vec<String> {
    let mut v: Vec<String> = kernels
        .iter()
        .map(|&n| fx.modules(n).to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn packages(f: &Finding) -> Vec<String> {
    f.action.argv.as_ref().unwrap()[9..].to_vec()
}

fn of(found: &[Finding], fx: &Fx, n: u32) -> Finding {
    let p = fx.modules(n);
    found
        .iter()
        .find(|f| Path::new(&f.path) == p)
        .unwrap_or_else(|| panic!("no finding for {n}: {found:?}"))
        .clone()
}

#[test]
fn finds_kernels_apt_would_autoremove_except_the_newest_two() {
    let fx = Fx::new(FULL);
    let found = fx.detect();
    // apt lists 11 too; it is the second newest and stays.
    assert_eq!(paths(&found), kernel_paths(&fx, &[9, 10]));

    let f = of(&found, &fx, 9);
    let u = uname(9);
    assert_eq!(f.detector, "old-kernels");
    assert_eq!(f.tier, Tier::Review);
    assert_eq!(f.id, finding_id("old-kernels", &f.path));
    assert_eq!(f.action.kind, ActionKind::Command);
    let argv = f.action.argv.clone().unwrap();
    let mut want: Vec<String> = [
        "env",
        "-u",
        "APT_CONFIG",
        "DEBIAN_FRONTEND=noninteractive",
        fx.apt.to_str().unwrap(),
        "remove",
        "--purge",
        "-y",
        "--no-auto-remove",
    ]
    .map(String::from)
    .to_vec();
    want.extend([
        "linux-headers-9.8.0-9".to_string(),
        format!("linux-headers-{u}"),
        format!("linux-image-{u}"),
        format!("linux-modules-{u}"),
        format!("linux-modules-nvidia-595-open-{u}"),
        "linux-tools-9.8.0-9".to_string(),
        format!("linux-tools-{u}"),
    ]);
    assert_eq!(argv, want);
    assert_eq!(
        f.action.text,
        want.iter()
            .map(|a| detect::shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ")
    );
    // Modules (the nvidia one listed under the usrmerge `/lib`), headers,
    // tools, and /boot's files, the initramfs included; the headers'
    // `include` symlink and the package directories are not counted.
    assert_eq!(f.bytes, fx.freed(9, true));
    assert!(
        f.reason
            .contains("kernel 9.8.0-9-generic (package version 9.8.0-9.9)"),
        "{}",
        f.reason
    );
    assert!(
        f.reason.contains("running kernel (9.8.0-12-generic)"),
        "{}",
        f.reason
    );
    assert!(
        f.reason.contains("(9.8.0-11-generic, 9.8.0-12-generic)"),
        "{}",
        f.reason
    );
    assert!(f.reason.contains(APT_REMOVAL_SET), "{}", f.reason);
    assert_eq!(
        f.recovery.how.as_deref(),
        Some(format!("apt-get install {}", want[9..].join(" ")).as_str())
    );
    assert!(f.guards.is_empty());
    assert!(f.last_modified.is_some());
    assert_eq!(of(&found, &fx, 10).bytes, fx.freed(10, true));
}

#[test]
fn a_pending_reboot_keeps_the_running_kernel_too() {
    let fx = Fx::new(FULL);
    // Running 10 while 12 is installed: 12, 11 and 10 stay.
    assert_eq!(paths(&fx.detect_with(10).unwrap()), kernel_paths(&fx, &[9]));
    // Running a kernel no package provides changes nothing else.
    let det = OldKernels::with_root(fx.root.clone(), Ok("9.8.0-20-generic".into()));
    assert_eq!(
        paths(&det.detect(&scan_tree(&fx.root), &fx.ctx()).unwrap()),
        kernel_paths(&fx, &[9, 10])
    );
}

#[test]
fn the_newest_two_go_by_package_version_not_name() {
    let mut fx = Fx::new(FULL);
    // 10's image carries the newest package version: 10 and 12 are kept,
    // 11 is offered once apt lists it and nothing points at it.
    fx.row(&format!("linux-image-{}", uname(10)), "9.8.0-99.99", "ii ");
    fx.save_rows();
    fs::remove_file(fx.root.join("boot/vmlinuz.old")).unwrap();
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[9, 11]));
}

#[test]
fn vmlinuz_targets_are_kept_and_odd_links_fail() {
    let fx = Fx::new(FULL);
    let old = fx.root.join("boot/vmlinuz.old");
    fs::remove_file(&old).unwrap();
    symlink(format!("vmlinuz-{}", uname(10)), &old).unwrap();
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[9]));

    // An absolute target counts the same.
    fs::remove_file(&old).unwrap();
    symlink(format!("/boot/vmlinuz-{}", uname(9)), &old).unwrap();
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[10]));

    // Missing links are fine.
    fs::remove_file(&old).unwrap();
    fs::remove_file(fx.root.join("boot/vmlinuz")).unwrap();
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[9, 10]));

    // A target that names no kernel, or a link that is a file, fails.
    symlink("bzImage", &old).unwrap();
    let e = fx.detect_with(12).unwrap_err();
    assert!(e.contains("vmlinuz.old"), "{e}");
    fs::remove_file(&old).unwrap();
    write(&old, 10);
    let e = fx.detect_with(12).unwrap_err();
    assert!(e.contains("not a symlink"), "{e}");
}

#[test]
fn only_kernels_apt_would_autoremove() {
    let fx = Fx::new(FULL);
    // `apt-mark manual linux-image-9.8.0-10-generic`.
    fx.autoremove(&[9]);
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[9]));
    fx.autoremove(&[]);
    assert!(fx.detect().is_empty());
}

#[test]
fn garbled_or_failing_tools_fail_closed() {
    let mut fx = Fx::new(FULL);
    let autoremove = fs::read_to_string(fx.data.join("autoremove")).unwrap();
    for bad in [
        autoremove.replace(" 4 to remove", " 5 to remove"),
        autoremove.replace(" to remove and 0 not upgraded.", " to remove."),
        format!("{autoremove}Inst linux-image-9.8.0-13-generic [9.8.0-13.13]\n"),
        autoremove.replace(
            "Remv linux-image-9.8.0-9-generic [9.8.0-9.9]",
            "Remv linux-image-9.8.0-9-generic 9.8.0-9.9",
        ),
        String::new(),
    ] {
        fs::write(fx.data.join("autoremove"), &bad).unwrap();
        assert!(fx.detect_with(12).is_err(), "{bad}");
    }
    fs::write(fx.data.join("autoremove"), &autoremove).unwrap();
    fs::write(fx.data.join("autoremove.rc"), "100").unwrap();
    assert!(fx.detect_with(12).is_err());
    fs::remove_file(fx.data.join("autoremove.rc")).unwrap();
    assert_eq!(fx.detect().len(), 2);

    // dpkg: a garbled line, an image listed twice (two architectures), an
    // image version that does not parse.
    let rows = fs::read_to_string(fx.data.join("rows")).unwrap();
    for bad in [
        format!("{rows}garbled line\n"),
        format!("{rows}linux-image-9.8.0-12-generic\t9.8.0-12.12\tii \n"),
    ] {
        fs::write(fx.data.join("rows"), &bad).unwrap();
        assert!(fx.detect_with(12).is_err(), "{bad}");
    }
    // Another package listed twice is no matter; one of a version's leaves
    // that version out.
    fs::write(fx.data.join("rows"), format!("{rows}bash\t5.2\tii \n")).unwrap();
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[9, 10]));
    fs::write(
        fx.data.join("rows"),
        format!("{rows}linux-tools-9.8.0-9\t9.8.0-9.9\tii \n"),
    )
    .unwrap();
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[10]));
    fx.row(
        &format!("linux-image-{}", uname(10)),
        "not a version",
        "ii ",
    );
    fx.save_rows();
    assert!(fx.detect_with(12).is_err());

    // The running kernel cannot be told.
    let fx = Fx::new(FULL);
    for release in [
        Err("uname failed".to_string()),
        Ok("Linux".to_string()),
        Ok(String::new()),
    ] {
        let det = OldKernels::with_root(fx.root.clone(), release);
        assert!(det.detect(&scan_tree(&fx.root), &fx.ctx()).is_err());
    }
}

#[test]
fn a_version_with_an_unsettled_package_is_left_out() {
    for (pkg, status) in [
        (format!("linux-headers-{}", uname(9)), "iU "),
        (format!("linux-modules-{}", uname(9)), "iF "),
        ("linux-tools-9.8.0-9".to_string(), "iH "),
        (format!("linux-modules-{}", uname(9)), "hi "),
        (format!("linux-image-{}", uname(9)), "iiR"),
        // The image itself only config-files: nothing to autoremove.
        (format!("linux-image-{}", uname(9)), "rc "),
    ] {
        let mut fx = Fx::new(FULL);
        fx.status(&pkg, status);
        assert_eq!(
            paths(&fx.detect()),
            kernel_paths(&fx, &[10]),
            "{pkg} {status:?}"
        );
    }
    // A config-files-only package of the version is purged with it.
    let mut fx = Fx::new(FULL);
    let extra = format!("linux-modules-extra-{}", uname(9));
    fx.status(&extra, "rc ");
    let f = of(&fx.detect(), &fx, 9);
    assert!(packages(&f).contains(&extra));
}

#[test]
fn flavourless_packages_another_flavour_needs_stay() {
    let mut fx = Fx::new(FULL);
    fx.row("linux-headers-9.8.0-9-lowlatency", &version(9), "ii ");
    fx.save_rows();
    let f = of(&fx.detect(), &fx, 9);
    let p = packages(&f);
    assert!(!p.contains(&"linux-headers-9.8.0-9".to_string()), "{p:?}");
    assert!(!p.contains(&"linux-tools-9.8.0-9".to_string()), "{p:?}");
    assert_eq!(p.len(), 5);
    assert_eq!(f.bytes, fx.freed(9, false));
    // Only config files left of the other flavour: they go together again.
    fx.status("linux-headers-9.8.0-9-lowlatency", "rc ");
    assert_eq!(packages(&of(&fx.detect(), &fx, 9)).len(), 7);
}

#[test]
fn symlinks_are_never_followed() {
    // A modules directory that is a symlink: no finding for it.
    let fx = Fx::new(FULL);
    let dir = fx.modules(9);
    fs::rename(&dir, fx.root.join("moved")).unwrap();
    symlink("../../../moved", &dir).unwrap();
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[10]));

    // A symlinked ancestor: the headers behind it are not counted.
    let fx = Fx::new(FULL);
    let src = fx.root.join("usr/src");
    fs::rename(&src, fx.root.join("src-real")).unwrap();
    symlink("../src-real", &src).unwrap();
    let headers: u64 = [
        "src-real/linux-headers-9.8.0-9-generic/Makefile",
        "src-real/linux-headers-9.8.0-9/include/x.h",
    ]
    .iter()
    .map(|p| allocated(&fx.root.join(p)))
    .sum();
    assert_eq!(of(&fx.detect(), &fx, 9).bytes, fx.freed(9, true) - headers);

    // `/lib` pointing anywhere but `usr/lib`: paths listed under it are
    // not read through it.
    let fx = Fx::new(FULL);
    fs::remove_file(fx.root.join("lib")).unwrap();
    symlink(fx.root.join("usr/lib"), fx.root.join("lib")).unwrap();
    let nvidia = allocated(&fx.modules(9).join("kernel/nvidia/nvidia.ko"));
    assert_eq!(of(&fx.detect(), &fx, 9).bytes, fx.freed(9, true) - nvidia);
}

#[test]
fn hardlinks_count_once_and_only_when_every_link_goes() {
    let fx = Fx::new(FULL);
    let big = fx.modules(9).join("kernel/fs/big.ko");
    // A link outside the packages keeps the module alive.
    fs::create_dir_all(fx.root.join("keep")).unwrap();
    fs::hard_link(&big, fx.root.join("keep/big.ko")).unwrap();
    let f = of(&fx.detect(), &fx, 9);
    assert_eq!(f.bytes, fx.freed(9, true) - allocated(&big));
    assert!(f.reason.contains("hardlinked elsewhere"), "{}", f.reason);

    // Two listed names of one inode count once.
    let fx = Fx::new(FULL);
    let perf = fx
        .root
        .join(format!("usr/lib/linux-tools/{}/perf", uname(9)));
    let turbostat = fx.root.join("usr/lib/linux-tools-9.8.0-9/turbostat");
    fs::remove_file(&turbostat).unwrap();
    fs::hard_link(&perf, &turbostat).unwrap();
    let f = of(&fx.detect(), &fx, 9);
    let want: u64 =
        fx.freed(9, false) + allocated(&fx.root.join("usr/src/linux-headers-9.8.0-9/include/x.h"));
    assert_eq!(f.bytes, want);
}

#[test]
fn nothing_under_one_mebibyte() {
    let fx = Fx::new(Sizes {
        module: 64 * KIB,
        nvidia: 64 * KIB,
    });
    assert!(fx.detect().is_empty());
}

#[test]
fn nothing_and_no_tool_run_when_the_modules_are_not_scanned() {
    let fx = Fx::new(FULL);
    let tree = scan_tree(&fx.root.join("usr/src"));
    assert!(fx.detector(12).detect(&tree, &fx.ctx()).unwrap().is_empty());
    assert_eq!(fx.simulated(), "");
    // Leftover module directories no package owns are not findings.
    let fx = Fx::new(FULL);
    write(
        &fx.root.join("usr/lib/modules/9.8.0-3-generic/kernel/x.ko"),
        4 * MIB,
    );
    assert_eq!(paths(&fx.detect()), kernel_paths(&fx, &[9, 10]));
}

#[test]
fn runs_only_as_root_with_apt_get_and_dpkg_query() {
    // A tree without modules, so no tool runs whatever the context.
    let (_t, b) = base();
    let tree = scan_tree(&b);
    let built: Vec<Box<dyn Detector>> =
        vec![Box::new(OldKernels::with_root(b.clone(), Ok(uname(12))))];
    let run = |cx: &DetectContext| {
        let (_, runs) = detect::run_with(&tree, cx, &built, None);
        runs.into_iter().find(|r| r.name == "old-kernels").unwrap()
    };
    let both = vec![
        tool("apt-get", Some("/usr/bin/apt-get"), None),
        tool("dpkg-query", Some("/usr/bin/dpkg-query"), None),
    ];
    let r = run(&ctx(false, both.clone()));
    assert_eq!(
        (r.ran, r.status),
        (false, DetectorAvailability::Unavailable)
    );
    assert!(r.detail.contains("root"), "{}", r.detail);
    for missing in ["apt-get", "dpkg-query"] {
        let tools: Vec<ToolStatus> = both.iter().filter(|t| t.name != missing).cloned().collect();
        let r = run(&ctx(true, tools));
        assert_eq!(
            (r.ran, r.status),
            (false, DetectorAvailability::Unavailable)
        );
        assert!(r.detail.contains(missing), "{}", r.detail);
    }
    let r = run(&ctx(true, both));
    assert_eq!(
        (r.ran, r.status, r.findings),
        (true, DetectorAvailability::Available, 0)
    );
    assert!(
        r.detail.contains("`apt-get` and `dpkg-query`"),
        "{}",
        r.detail
    );
}

#[test]
fn registered_in_the_registry() {
    assert!(
        dwhy_core::detectors::registry()
            .iter()
            .any(|d| d.name() == "old-kernels")
    );
}

fn guard_of(
    fx: &Fx,
    f: &Finding,
    release: Result<String, String>,
) -> dwhy_core::report::GuardResult {
    removal_set_guard(f, &fx.ctx(), release)
}

#[test]
fn the_removal_set_guard_simulates_the_exact_removal() {
    let mut fx = Fx::new(FULL);
    let f = of(&fx.detect(), &fx, 9);
    let g = guard_of(&fx, &f, Ok(uname(12)));
    assert_eq!(
        (g.name.as_str(), g.status),
        (APT_REMOVAL_SET, GuardStatus::Pass),
        "{}",
        g.detail
    );
    let sim = fx.simulated();
    let last = sim.lines().last().unwrap();
    assert_eq!(
        last,
        format!(
            "-s -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= remove --purge --no-auto-remove {}",
            packages(&f).join(" ")
        )
    );

    let blocks = |fx: &Fx, f: &Finding, release: Result<String, String>, want: &str| {
        let g = guard_of(fx, f, release);
        assert_eq!(g.status, GuardStatus::Block, "{}", g.detail);
        assert!(g.detail.contains(want), "{want:?} in {}", g.detail);
    };
    // apt would also remove a metapackage.
    fs::write(fx.data.join("extra"), "linux-generic-hwe-26.04").unwrap();
    blocks(
        &fx,
        &f,
        Ok(uname(12)),
        "apt would also remove linux-generic-hwe-26.04",
    );
    fs::remove_file(fx.data.join("extra")).unwrap();
    // The simulation fails, or prints what diskwhy cannot read.
    fs::write(fx.data.join("remove"), "E: Unable to locate package\n").unwrap();
    fs::write(fx.data.join("remove.rc"), "100").unwrap();
    blocks(&fx, &f, Ok(uname(12)), "simulation failed");
    fs::remove_file(fx.data.join("remove.rc")).unwrap();
    blocks(
        &fx,
        &f,
        Ok(uname(12)),
        "cannot read the removal's simulation",
    );
    fs::write(
        fx.data.join("remove"),
        "0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv linux-image-9.8.0-9-generic [9.8.0-9.9]\n",
    )
    .unwrap();
    blocks(&fx, &f, Ok(uname(12)), "would not remove");
    fs::remove_file(fx.data.join("remove")).unwrap();
    // The running kernel, or none known.
    blocks(&fx, &f, Ok(uname(9)), "is kept");
    blocks(
        &fx,
        &f,
        Err("uname failed".into()),
        "cannot tell the running kernel",
    );
    // A package of the version installed since detection.
    fx.row(
        &format!("linux-modules-extra-{}", uname(9)),
        &version(9),
        "ii ",
    );
    fx.save_rows();
    blocks(&fx, &f, Ok(uname(12)), "are now");
    fx.rows
        .retain(|(n, _, _)| !n.starts_with("linux-modules-extra"));
    fx.save_rows();
    // /boot/vmlinuz.old moved to it since detection.
    let old = fx.root.join("boot/vmlinuz.old");
    fs::remove_file(&old).unwrap();
    symlink(format!("vmlinuz-{}", uname(9)), &old).unwrap();
    blocks(&fx, &f, Ok(uname(12)), "is kept");
    fs::remove_file(&old).unwrap();
    // An action that is not the one the detector builds.
    let mut edited = f.clone();
    edited
        .action
        .argv
        .as_mut()
        .unwrap()
        .push("linux-generic-hwe-26.04".into());
    blocks(
        &fx,
        &edited,
        Ok(uname(12)),
        "not the `apt-get remove --purge`",
    );
    let mut edited = f.clone();
    edited.action.argv.as_mut().unwrap()[6] = "--allow-remove-essential".into();
    blocks(
        &fx,
        &edited,
        Ok(uname(12)),
        "not the `apt-get remove --purge`",
    );
    // A listed package of a kept kernel (12's flavourless headers).
    let mut edited = f.clone();
    let argv = edited.action.argv.as_mut().unwrap();
    argv.insert(9, "linux-headers-9.8.0-12".into());
    blocks(
        &fx,
        &edited,
        Ok(uname(12)),
        "belongs to the kept kernel 9.8.0-12-generic",
    );
    // dpkg-query missing.
    let g = removal_set_guard(
        &f,
        &ctx(
            true,
            vec![tool("apt-get", None, Some(fx.apt.to_str().unwrap()))],
        ),
        Ok(uname(12)),
    );
    assert_eq!(g.status, GuardStatus::Block);
    // All restored: it passes again.
    let g = guard_of(&fx, &f, Ok(uname(12)));
    assert_eq!(g.status, GuardStatus::Pass, "{}", g.detail);
}

fn select(fx: &Fx, n: u32, procs: &Processes) -> dwhy_core::report::Plan {
    let tree = scan_tree(&fx.root);
    let found = fx.detector(12).detect(&tree, &fx.ctx()).unwrap();
    let id = of(&found, fx, n).id;
    plan::build(
        found,
        &Selection {
            tier: None,
            select: vec![id],
            free: None,
        },
        &tree,
        &fx.ctx(),
        procs,
        "host".into(),
        PlanScan {
            roots: vec![fx.root.to_string_lossy().into_owned()],
            one_filesystem: true,
            detectors: None,
        },
    )
    .unwrap()
}

fn idle() -> Processes {
    Processes {
        procs: vec![],
        unreadable: 0,
    }
}

#[test]
fn plan_blocks_what_the_guards_block() {
    let fx = Fx::new(FULL);
    // apt would also remove a metapackage.
    fs::write(fx.data.join("extra"), "linux-image-generic-hwe-26.04").unwrap();
    let plan = select(&fx, 9, &idle());
    assert!(plan.items.is_empty(), "{plan:?}");
    let g = plan.blocked[0]
        .guards
        .iter()
        .find(|g| g.name == APT_REMOVAL_SET)
        .unwrap();
    assert_eq!(g.status, GuardStatus::Block);
    assert!(
        g.detail.contains("linux-image-generic-hwe-26.04"),
        "{}",
        g.detail
    );
    fs::remove_file(fx.data.join("extra")).unwrap();

    // A process working in the version's modules directory.
    let busy = Processes {
        procs: vec![Proc {
            pid: 4242,
            name: "modinfo".into(),
            cwd: Some(fx.modules(9).join("kernel")),
            open: vec![],
        }],
        unreadable: 0,
    };
    let plan = select(&fx, 9, &busy);
    assert!(plan.items.is_empty(), "{plan:?}");
    let g = plan.blocked[0]
        .guards
        .iter()
        .find(|g| g.name == "in-use-cwd")
        .unwrap();
    assert_eq!(g.status, GuardStatus::Block);
    // ... but not in another kernel's.
    let other = Processes {
        procs: vec![Proc {
            pid: 4242,
            name: "modinfo".into(),
            cwd: Some(fx.modules(12)),
            open: vec![fx.modules(12).join("kernel/fs/big.ko")],
        }],
        unreadable: 0,
    };
    assert_eq!(select(&fx, 9, &other).items.len(), 1);
}

#[test]
fn plan_and_apply_purge_one_version_and_skip_it_once_its_packages_change() {
    let mut fx = Fx::new(FULL);
    let plan = select(&fx, 9, &idle());
    assert_eq!(plan.items.len(), 1, "{plan:?}");
    let item = &plan.items[0];
    assert_eq!(item.finding.tier, Tier::Review);
    let names: Vec<(&str, GuardStatus)> = item
        .finding
        .guards
        .iter()
        .map(|g| (g.name.as_str(), g.status))
        .collect();
    assert!(
        names.contains(&(APT_REMOVAL_SET, GuardStatus::Pass)),
        "{names:?}"
    );
    assert!(
        names.contains(&("in-use-open", GuardStatus::Pass)),
        "{names:?}"
    );
    assert!(
        names.iter().all(|(n, _)| !n.starts_with("git")),
        "{names:?}"
    );
    let md = fs::symlink_metadata(fx.modules(9)).unwrap();
    assert_eq!(
        (item.fingerprint.dev, item.fingerprint.inode),
        (Some(md.dev()), Some(md.ino()))
    );
    assert!(item.fingerprint.packages.is_some());
    let id = item.finding.id.clone();

    let evaluate = |fx: &Fx, policy: &Policy| {
        let (tree, cx) = (scan_tree(&fx.root), fx.ctx());
        let fresh = fx.detector(12).detect(&tree, &cx).unwrap();
        apply::evaluate(&plan, fresh, &tree, &cx, &idle(), policy)
    };
    let checks = evaluate(&fx, &Policy::default());
    assert_eq!(checks[0].item.outcome, ApplyOutcome::Refused);
    let confirmed = Policy {
        confirm: vec![id.clone()],
        ..Policy::default()
    };

    // apply re-runs the guard: a metapackage apt would now remove too.
    fs::write(fx.data.join("extra"), "linux-generic-hwe-26.04").unwrap();
    let checks = evaluate(&fx, &confirmed);
    assert_eq!(
        checks[0].item.outcome,
        ApplyOutcome::Skipped,
        "{}",
        checks[0].item.detail
    );
    assert!(
        checks[0].item.detail.contains(APT_REMOVAL_SET),
        "{}",
        checks[0].item.detail
    );
    fs::remove_file(fx.data.join("extra")).unwrap();

    let mut checks = evaluate(&fx, &confirmed);
    assert_eq!(
        checks[0].item.outcome,
        ApplyOutcome::WouldRemove,
        "{}",
        checks[0].item.detail
    );
    let (_s, state) = base();
    let mut audit = Audit::open(&state.join("audit.jsonl")).unwrap();
    let env = Env {
        host: "host".into(),
        uid: 0,
        now: || "2026-11-24T00:00:00Z".to_string(),
        invocation: None,
    };
    apply::execute(
        &plan,
        &mut checks,
        &mut audit,
        &MountTable::default(),
        &env,
        &mut |_| {},
    );
    assert_eq!(
        checks[0].item.outcome,
        ApplyOutcome::Removed,
        "{}",
        checks[0].item.detail
    );
    let ran = fs::read_to_string(fx.data.join("ran")).unwrap();
    let mut want = ["remove", "--purge", "-y", "--no-auto-remove"].join("\n");
    for p in packages(&item.finding) {
        want.push('\n');
        want.push_str(&p);
    }
    want.push('\n');
    assert_eq!(ran, want);
    // The fake removed nothing.
    assert!(fx.modules(9).exists());

    // A package of the version upgraded in place since the plan.
    fx.row(
        &format!("linux-modules-nvidia-595-open-{}", uname(9)),
        "9.8.0-9.9+1",
        "ii ",
    );
    fx.save_rows();
    let checks = evaluate(&fx, &confirmed);
    assert_eq!(checks[0].item.outcome, ApplyOutcome::Skipped);
    assert!(
        checks[0].item.detail.contains("packages"),
        "{}",
        checks[0].item.detail
    );
}
