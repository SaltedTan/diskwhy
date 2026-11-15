//! Text rendering for people. Agents should use `--json`.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use dwhy_core::report::{
    DetectorAvailability, DirEntry, DoctorReport, Finding, FsReport, ScanReport, SkipReason, Tier,
};
use dwhy_core::units::{human, thousands};

pub fn render_scan(
    w: &mut impl Write,
    r: &ScanReport,
    depth: u32,
    top: usize,
    max_findings: usize,
) -> io::Result<()> {
    let s = &r.scan;
    let t = &s.totals;
    writeln!(
        w,
        "dwhy scan · {} · uid {} · {} · {:.1}s",
        r.host,
        r.uid,
        if s.one_filesystem {
            "one filesystem"
        } else {
            "crossing filesystems"
        },
        s.elapsed_ms as f64 / 1000.0
    )?;
    writeln!(
        w,
        "scanned {} allocated ({} apparent) in {} files, {} dirs, {} symlinks",
        human(t.allocated),
        human(t.apparent),
        thousands(t.files),
        thousands(t.dirs),
        thousands(t.symlinks)
    )?;

    for fs in &r.fs {
        writeln!(w)?;
        render_fs(w, r, fs)?;
    }

    writeln!(w)?;
    let u = &s.unreadable;
    if u.count > 0 {
        let examples: Vec<&str> = u.dirs.iter().take(3).map(|d| d.path.as_str()).collect();
        writeln!(
            w,
            "unreadable  {} directories, contents unknown: {}{}",
            thousands(u.count),
            examples.join(", "),
            if u.count as usize > examples.len() {
                ", … (--json lists them)"
            } else {
                ""
            }
        )?;
    }
    if t.hardlinks_deduped > 0 {
        writeln!(
            w,
            "hardlinks   {} extra links counted once (would add {})",
            thousands(t.hardlinks_deduped),
            human(t.hardlink_bytes_deduped)
        )?;
    }
    let other_fs = s
        .skipped_mounts
        .iter()
        .filter(|m| m.reason == SkipReason::OtherFilesystem)
        .count();
    if other_fs > 0 {
        writeln!(
            w,
            "skipped     {other_fs} mount points of other filesystems (--cross-filesystems enters them)"
        )?;
    }
    if s.error_count > 0 {
        writeln!(
            w,
            "errors      {} (first: {}: {})",
            thousands(s.error_count),
            s.errors.first().map(|e| e.path.as_str()).unwrap_or("?"),
            s.errors.first().map(|e| e.error.as_str()).unwrap_or("?")
        )?;
    }

    render_findings(w, r, max_findings)?;

    writeln!(w)?;
    writeln!(
        w,
        "largest directories (allocated, ≥ {}):",
        human(s.min_dir_bytes)
    )?;
    render_tree(
        w,
        &s.dirs,
        &s.roots.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        depth,
        top,
    )?;
    Ok(())
}

fn tier_name(t: Tier) -> &'static str {
    match t {
        Tier::Regenerable => "regenerable",
        Tier::Rebuildable => "rebuildable",
        Tier::Review => "review",
        Tier::Blocked => "blocked",
    }
}

fn render_findings(w: &mut impl Write, r: &ScanReport, max: usize) -> io::Result<()> {
    if r.detectors.is_empty() {
        return Ok(());
    }
    writeln!(w)?;
    let total: u64 = r.findings.iter().map(|f| f.bytes).sum();
    let ran = r.detectors.iter().filter(|d| d.ran).count();
    writeln!(
        w,
        "findings: {} ({} reclaimable) from {ran} of {} detectors",
        r.findings.len(),
        human(total),
        r.detectors.len()
    )?;
    let mut shown = 0;
    for tier in [
        Tier::Regenerable,
        Tier::Rebuildable,
        Tier::Review,
        Tier::Blocked,
    ] {
        let in_tier: Vec<&Finding> = r.findings.iter().filter(|f| f.tier == tier).collect();
        if in_tier.is_empty() {
            continue;
        }
        let bytes: u64 = in_tier.iter().map(|f| f.bytes).sum();
        writeln!(w, "  {} ({})", tier_name(tier), human(bytes))?;
        for f in in_tier {
            if shown == max {
                break;
            }
            shown += 1;
            writeln!(w, "  {:>8}  {:<13} {}", human(f.bytes), f.detector, f.path)?;
            writeln!(w, "  {:>8}  {:<13} {}", "", "", f.reason)?;
            writeln!(w, "  {:>8}  {:<13} → {}", "", "", f.action.text)?;
        }
    }
    if r.findings.len() > shown {
        writeln!(
            w,
            "  … {} more (--max-findings or --json lists them)",
            r.findings.len() - shown
        )?;
    }
    let unavailable: Vec<&str> = r
        .detectors
        .iter()
        .filter(|d| !d.ran && d.status == DetectorAvailability::Unavailable)
        .map(|d| d.name.as_str())
        .collect();
    if !unavailable.is_empty() {
        writeln!(
            w,
            "  not run: {} (see `dwhy doctor`)",
            unavailable.join(", ")
        )?;
    }
    Ok(())
}

fn render_fs(w: &mut impl Write, r: &ScanReport, fs: &FsReport) -> io::Result<()> {
    writeln!(w, "filesystem {}  ({}, {})", fs.mount, fs.fstype, fs.source)?;
    writeln!(
        w,
        "  df used      {:>8} of {} ({} available)",
        human(fs.used),
        human(fs.size),
        human(fs.avail)
    )?;
    match fs.unaccounted {
        Some(gap) => {
            writeln!(w, "  scanned      {:>8}", human(fs.scanned))?;
            writeln!(
                w,
                "  unaccounted  {:>8}  df used − scanned{}",
                human(gap),
                if fs.unaccounted_large { "" } else { " (small)" }
            )?;
        }
        None => {
            let under: Vec<&str> = r
                .scan
                .roots
                .iter()
                .filter(|root| root.mount == fs.mount)
                .map(|root| root.path.as_str())
                .collect();
            writeln!(
                w,
                "  scanned      {:>8}  under {} (part of this filesystem; scan {} to account for all of it)",
                human(fs.scanned),
                under.join(", "),
                fs.mount
            )?;
        }
    }
    if fs.unaccounted_large && !fs.hints.is_empty() {
        writeln!(w, "  likely in:")?;
        let width = fs
            .hints
            .iter()
            .filter_map(|h| h.path.as_ref().map(|p| p.len()))
            .max()
            .unwrap_or(0)
            .min(28);
        for h in fs.hints.iter().take(8) {
            let mut extra = Vec::new();
            if h.unreadable_dirs > 0 {
                extra.push(format!(
                    "{} unreadable dir{}",
                    h.unreadable_dirs,
                    if h.unreadable_dirs == 1 { "" } else { "s" }
                ));
            }
            if let Some(b) = h.bytes {
                extra.push(human(b));
            }
            let extra = if extra.is_empty() {
                String::new()
            } else {
                format!("  [{}]", extra.join(", "))
            };
            match &h.path {
                Some(p) => writeln!(w, "    {p:<width$}  {}{extra}", h.detail)?,
                None => writeln!(w, "    {:<width$}  {}{extra}", "·", h.detail)?,
            }
        }
        if fs.hints.len() > 8 {
            writeln!(w, "    … {} more (--json lists them)", fs.hints.len() - 8)?;
        }
    }
    if let Some(cmd) = &fs.rerun {
        writeln!(w, "  rerun with sudo for a full count:")?;
        writeln!(w, "    {cmd}")?;
    }
    Ok(())
}

fn render_tree(
    w: &mut impl Write,
    dirs: &[DirEntry],
    roots: &[&str],
    max_depth: u32,
    top: usize,
) -> io::Result<()> {
    let mut children: HashMap<&str, Vec<&DirEntry>> = HashMap::new();
    let mut by_path: HashMap<&str, &DirEntry> = HashMap::new();
    for d in dirs {
        by_path.insert(d.path.as_str(), d);
        if d.depth > 0
            && let Some(parent) = Path::new(&d.path).parent().and_then(|p| p.to_str())
        {
            children.entry(parent).or_default().push(d);
        }
    }
    // `dirs` is sorted largest first, so each children list already is.
    for root in roots {
        match by_path.get(root) {
            Some(d) => {
                writeln!(w, "{:>8}  {}", human(d.allocated), d.path)?;
                walk(w, &children, d, "", 1, max_depth, top)?;
            }
            None => writeln!(w, "{:>8}  {} (below threshold)", "", root)?,
        }
    }
    Ok(())
}

fn walk(
    w: &mut impl Write,
    children: &HashMap<&str, Vec<&DirEntry>>,
    d: &DirEntry,
    prefix: &str,
    level: u32,
    max_depth: u32,
    top: usize,
) -> io::Result<()> {
    if level > max_depth {
        return Ok(());
    }
    let Some(kids) = children.get(d.path.as_str()) else {
        return Ok(());
    };
    let shown = kids.len().min(top);
    for (i, k) in kids.iter().take(shown).enumerate() {
        let last = i + 1 == shown && kids.len() <= shown;
        let name = Path::new(&k.path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| k.path.clone());
        writeln!(
            w,
            "{:>8}  {prefix}{}{name}",
            human(k.allocated),
            if last { "└─ " } else { "├─ " }
        )?;
        let next = format!("{prefix}{}", if last { "   " } else { "│  " });
        walk(w, children, k, &next, level + 1, max_depth, top)?;
    }
    if kids.len() > shown {
        let rest: u64 = kids[shown..].iter().map(|k| k.allocated).sum();
        writeln!(
            w,
            "{:>8}  {prefix}└─ … {} more",
            human(rest),
            kids.len() - shown
        )?;
    }
    Ok(())
}

pub fn render_doctor(w: &mut impl Write, d: &DoctorReport) -> io::Result<()> {
    writeln!(
        w,
        "dwhy doctor · {} · {} {}",
        d.host, d.tool.name, d.tool.version
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "user        uid {} euid {}{}",
        d.uid,
        d.euid,
        if d.root { " (root)" } else { " (not root)" }
    )?;
    writeln!(
        w,
        "docker      group member: {} · socket {}: {}",
        if d.docker_group { "yes" } else { "no" },
        d.docker_socket.path,
        match (d.docker_socket.exists, d.docker_socket.accessible) {
            (false, _) => "absent",
            (true, false) => "not accessible",
            (true, true) => "accessible",
        }
    )?;
    writeln!(w)?;
    writeln!(w, "tools")?;
    for t in &d.tools {
        let loc = match (&t.path, &t.off_path) {
            (Some(p), _) => p.clone(),
            (None, Some(p)) => format!("not on PATH (found {p})"),
            (None, None) => "not found".into(),
        };
        writeln!(w, "  {:<11} {loc}", t.name)?;
        writeln!(w, "  {:<11} enables {}", "", t.enables.join(", "))?;
    }
    writeln!(w)?;
    writeln!(w, "detectors")?;
    for det in &d.detectors {
        let mark = match det.status {
            DetectorAvailability::Available => "ok  ",
            DetectorAvailability::Degraded => "part",
            DetectorAvailability::Unavailable => "off ",
            DetectorAvailability::NotImplemented => "todo",
        };
        writeln!(
            w,
            "  {mark} {:<19} {:<9} {}",
            det.name, det.milestone, det.detail
        )?;
    }
    if !d.notes.is_empty() {
        writeln!(w)?;
        for n in &d.notes {
            writeln!(w, "note: {n}")?;
        }
    }
    Ok(())
}
