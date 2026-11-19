//! Text rendering for people. Agents should use `--json`.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use dwhy_core::apply::{self, action_kind_name, guard_status_name, tier_name};
use dwhy_core::probes::postgres_wal;
use dwhy_core::report::{
    ActionKind, ApplyOutcome, ApplyReport, Change, ChangeKind, DetectorAvailability, DiffReport,
    DirEntry, DoctorReport, ExplainReport, Finding, FsReport, GuardStatus, Plan, Rate, ScanReport,
    SkipReason, Tier, WatchReport,
};
use dwhy_core::units::{age, human, signed, thousands};

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
    if let Some(snap) = &r.snapshot {
        writeln!(w)?;
        write!(w, "snapshot saved: {} ({})", snap.id, snap.path)?;
        if snap.pruned > 0 {
            write!(
                w,
                "; pruned {} older snapshot{}",
                snap.pruned,
                if snap.pruned == 1 { "" } else { "s" }
            )?;
        }
        writeln!(w)?;
    }
    Ok(())
}

/// What grew since a snapshot: filesystems, then directories, Docker and
/// findings, each fastest growth first; `top` entries per section.
pub fn render_diff(w: &mut impl Write, d: &DiffReport, top: usize) -> io::Result<()> {
    let base = d.since.id.as_deref().unwrap_or(&d.since.path);
    writeln!(
        w,
        "dwhy diff · {} · since {} ({} ago) · {}",
        d.host,
        base,
        age(d.elapsed_secs),
        d.roots.join(" ")
    )?;
    if !dwhy_core::snapshot::same_roots(&d.since.roots, &d.roots) {
        writeln!(
            w,
            "  the snapshot covers {}; only paths in both are compared",
            d.since.roots.join(" ")
        )?;
    }
    let sections: [(&str, &[Change]); 4] = [
        ("filesystems (df used)", &d.fs),
        (
            "directories (the deepest that holds most of each change)",
            &d.dirs,
        ),
        ("docker", &d.docker),
        ("findings", &d.findings),
    ];
    for (i, (title, list)) in sections.into_iter().enumerate() {
        writeln!(w)?;
        if list.is_empty() {
            if i == 0 {
                writeln!(w, "{title}: none in both scans")?;
            } else if i == 2 && !d.docker_compared {
                writeln!(w, "{title}: not compared (see note)")?;
            } else {
                writeln!(
                    w,
                    "{title}: nothing changed by {} or more",
                    human(d.min_change)
                )?;
            }
            continue;
        }
        writeln!(w, "{title}:")?;
        for c in list.iter().take(top) {
            let change = if c.at_least {
                format!("≥{}", signed(c.change))
            } else {
                signed(c.change)
            };
            let span = match (c.before, c.after) {
                (Some(b), Some(a)) => format!("{} → {}", human(b), human(a)),
                (None, Some(a)) if c.at_least => format!(
                    "was under {}, now {}",
                    human(d.since.min_dir_bytes),
                    human(a)
                ),
                (None, Some(a)) => format!("new, {}", human(a)),
                (Some(b), None) => format!("gone, was {}", human(b)),
                (None, None) => String::new(),
            };
            writeln!(
                w,
                "  {:>9}  {:>12}  {}  ({span})",
                change,
                format!("{}/day", signed(c.bytes_per_day)),
                label(c.kind, &c.name, c.detector.as_deref())
            )?;
        }
        if list.len() > top {
            writeln!(
                w,
                "  … {} more (--top or --json lists them)",
                list.len() - top
            )?;
        }
    }
    if !d.notes.is_empty() {
        writeln!(w)?;
    }
    for n in &d.notes {
        writeln!(w, "note: {n}")?;
    }
    if let Some(snap) = &d.snapshot {
        writeln!(w)?;
        writeln!(w, "snapshot saved: {} ({})", snap.id, snap.path)?;
    }
    Ok(())
}

fn label(kind: ChangeKind, name: &str, detector: Option<&str>) -> String {
    match kind {
        ChangeKind::Fs | ChangeKind::Dir => name.to_string(),
        ChangeKind::Image => format!("image {name}"),
        ChangeKind::Container => format!("container {name}"),
        ChangeKind::Volume => format!("volume {name}"),
        ChangeKind::BuildCache => "build cache".into(),
        ChangeKind::Finding => format!("{} {name}", detector.unwrap_or("finding")),
    }
}

/// Growth over a watch window, per section, fastest first.
pub fn render_watch(w: &mut impl Write, r: &WatchReport, top: usize) -> io::Result<()> {
    writeln!(
        w,
        "dwhy watch · {} · {:.1}s window · {}",
        r.host,
        r.elapsed_ms as f64 / 1000.0,
        r.roots.join(" ")
    )?;
    let sections: [(&str, &[Rate]); 3] = [
        ("filesystems (df used)", &r.fs),
        (
            "directories (the deepest that holds most of each change)",
            &r.dirs,
        ),
        ("docker", &r.docker),
    ];
    for (i, (title, list)) in sections.into_iter().enumerate() {
        writeln!(w)?;
        if list.is_empty() {
            if i == 0 {
                writeln!(w, "{title}: none")?;
            } else if i == 2 && !r.docker_compared {
                writeln!(w, "{title}: not compared (see note)")?;
            } else {
                writeln!(
                    w,
                    "{title}: nothing changed by {} or more",
                    human(r.min_change)
                )?;
            }
            continue;
        }
        writeln!(w, "{title}:")?;
        for c in list.iter().take(top) {
            let span = match (c.before, c.after) {
                (Some(b), Some(a)) => format!("{} → {}", human(b), human(a)),
                (None, Some(a)) => format!("new, {}", human(a)),
                (Some(b), None) => format!("gone, was {}", human(b)),
                (None, None) => String::new(),
            };
            writeln!(
                w,
                "  {:>9}  {:>12}  {}  ({span})",
                signed(c.change),
                format!("{}/min", signed(c.bytes_per_minute)),
                label(c.kind, &c.name, None)
            )?;
        }
        if list.len() > top {
            writeln!(
                w,
                "  … {} more (--top or --json lists them)",
                list.len() - top
            )?;
        }
    }
    if !r.notes.is_empty() {
        writeln!(w)?;
    }
    for n in &r.notes {
        writeln!(w, "note: {n}")?;
    }
    Ok(())
}

/// One finding in full: what it is, the probe's evidence, every guard,
/// growth, the action and the cost of recovery. Without a finding, what is
/// at the path and the findings inside it.
pub fn render_explain(w: &mut impl Write, r: &ExplainReport) -> io::Result<()> {
    writeln!(w, "dwhy explain · {} · {}", r.host, r.path)?;
    if let Some(s) = &r.resolved.snapshot {
        writeln!(
            w,
            "  {} resolved through snapshot {} ({})",
            r.query, s.id, s.created_at
        )?;
    }
    let Some(f) = &r.finding else {
        writeln!(w)?;
        if r.gone {
            writeln!(w, "finding {} is gone", r.query)?;
        } else if r.resolved.via == dwhy_core::report::ExplainVia::Path {
            writeln!(w, "no detector claims this path")?;
        }
        if let Some(s) = &r.size {
            writeln!(
                w,
                "size: {} allocated ({} apparent)",
                human(s.allocated),
                human(s.apparent)
            )?;
        }
        if !r.inside.is_empty() {
            writeln!(w)?;
            writeln!(w, "findings inside it:")?;
            for i in &r.inside {
                writeln!(
                    w,
                    "  {:>8}  {:<13} {:<12} {}  {}",
                    human(i.bytes),
                    i.detector,
                    tier_name(i.tier),
                    i.path,
                    i.id
                )?;
            }
        }
        return render_notes(w, &r.notes);
    };

    writeln!(w)?;
    writeln!(
        w,
        "finding {} · {} · {}",
        f.id,
        f.detector,
        tier_name(f.tier)
    )?;
    writeln!(w, "  {:>8}  {}", human(f.bytes), f.path)?;
    if let Some(t) = &f.last_modified {
        writeln!(w, "  last written {t}")?;
    }
    writeln!(w, "  {}", f.reason)?;

    if let Some(ev) = f.evidence.as_ref().and_then(|e| e.postgres_wal.as_ref()) {
        writeln!(w)?;
        writeln!(w, "evidence ({}):", postgres_wal::NAME)?;
        writeln!(w, "  {}", postgres_wal::summary(ev))?;
        for n in &ev.notes {
            writeln!(w, "  note: {n}")?;
        }
    }

    writeln!(w)?;
    if f.guards.is_empty() {
        writeln!(w, "guards: none apply")?;
    } else {
        writeln!(w, "guards:")?;
        for g in &f.guards {
            let status = guard_status_name(g.status);
            writeln!(w, "  {status:<5}  {:<20} {}", g.name, g.detail)?;
        }
    }

    writeln!(w)?;
    match &f.growth {
        Some(g) => writeln!(
            w,
            "growth: {}/day since {}",
            signed(g.bytes_per_day),
            g.since
        )?,
        None => writeln!(
            w,
            "growth: unknown (no eligible snapshot (one filesystem, at least an hour old) lists this finding)"
        )?,
    }

    writeln!(w)?;
    writeln!(w, "action ({}):", action_kind_name(f.action.kind))?;
    writeln!(w, "  {}", f.action.text)?;

    writeln!(w)?;
    writeln!(w, "recovery:")?;
    writeln!(w, "  cost: {}", f.recovery.cost)?;
    if let Some(how) = &f.recovery.how {
        writeln!(w, "  how:  {how}")?;
    }
    render_notes(w, &r.notes)
}

fn render_notes(w: &mut impl Write, notes: &[String]) -> io::Result<()> {
    if !notes.is_empty() {
        writeln!(w)?;
    }
    for n in notes {
        writeln!(w, "note: {n}")?;
    }
    Ok(())
}

/// Summary of a plan: its items by tier, what is blocked, and how to apply it.
pub fn render_plan(
    w: &mut impl Write,
    p: &Plan,
    written: Option<&Path>,
    above: usize,
) -> io::Result<()> {
    let what = match (p.selection.tier, p.selection.select.len()) {
        (Some(t), 0) => format!("tier ≤ {}", tier_name(t)),
        (Some(t), n) => format!("{n} selected, tier ≤ {}", tier_name(t)),
        (None, n) => format!("{n} selected"),
    };
    if p.items.is_empty() {
        writeln!(w, "plan: nothing to remove ({what})")?;
    } else {
        writeln!(
            w,
            "plan: {} item{}, {} ({what}), expires {}",
            p.items.len(),
            if p.items.len() == 1 { "" } else { "s" },
            human(p.bytes),
            p.expires_at
        )?;
    }
    for tier in [Tier::Regenerable, Tier::Rebuildable, Tier::Review] {
        let in_tier: Vec<&Finding> = p
            .items
            .iter()
            .map(|i| &i.finding)
            .filter(|f| f.tier == tier)
            .collect();
        if in_tier.is_empty() {
            continue;
        }
        writeln!(w, "  {}", tier_name(tier))?;
        for f in in_tier {
            writeln!(w, "  {:>8}  {:<13} {}", human(f.bytes), f.detector, f.path)?;
            writeln!(w, "  {:>8}  {:<13} {} → {}", "", "", f.id, f.action.text)?;
            for g in f.guards.iter().filter(|g| g.status == GuardStatus::Warn) {
                writeln!(
                    w,
                    "  {:>8}  {:<13} warning, {}: {}",
                    "", "", g.name, g.detail
                )?;
            }
        }
    }
    if !p.blocked.is_empty() {
        writeln!(w, "  blocked (not in the plan: a guard failed)")?;
        for f in &p.blocked {
            writeln!(w, "  {:>8}  {:<13} {}", human(f.bytes), f.detector, f.path)?;
            for g in f.guards.iter().filter(|g| g.status == GuardStatus::Block) {
                writeln!(
                    w,
                    "  {:>8}  {:<13} blocked by {}: {}",
                    "", "", g.name, g.detail
                )?;
            }
        }
    }
    if above > 0
        && let Some(t) = p.selection.tier
    {
        writeln!(
            w,
            "  {above} finding{} above {} not selected (--tier or --select to include)",
            if above == 1 { "" } else { "s" },
            tier_name(t)
        )?;
    }
    match written {
        Some(path) if !p.items.is_empty() => writeln!(
            w,
            "wrote {}; apply it within an hour: dwhy apply {}",
            path.display(),
            dwhy_core::detect::shell_quote(&path.to_string_lossy())
        )?,
        Some(path) => writeln!(w, "wrote {}", path.display())?,
        None => writeln!(w, "no plan file written (-o FILE writes one)")?,
    }
    Ok(())
}

/// The items of an apply, and a summary line unless `items_only` (the
/// preview before the y/N question, which says the rest).
pub fn render_apply(
    w: &mut impl Write,
    r: &ApplyReport,
    audit: Option<&Path>,
    items_only: bool,
) -> io::Result<()> {
    let label = |o: ApplyOutcome| match o {
        ApplyOutcome::Removed => "removed",
        ApplyOutcome::Failed => "FAILED",
        ApplyOutcome::Skipped => "skipped",
        ApplyOutcome::Refused => "refused",
        ApplyOutcome::WouldRemove => "would remove",
    };
    for i in &r.items {
        writeln!(
            w,
            "  {:<12} {:>8}  {:<13} {}",
            label(i.outcome),
            human(i.bytes),
            i.detector,
            i.path
        )?;
        let note = match i.outcome {
            ApplyOutcome::WouldRemove => format!("{} → {}", tier_name(i.tier), i.action.text),
            _ => i.detail.clone(),
        };
        writeln!(w, "  {:<12} {:>8}  {:<13} {note}", "", "", "")?;
    }
    if items_only {
        return Ok(());
    }
    let count = |o| r.items.iter().filter(|i| i.outcome == o).count();
    let mut rest = Vec::new();
    for (o, word) in [
        (ApplyOutcome::Failed, "failed"),
        (ApplyOutcome::Refused, "refused"),
        (ApplyOutcome::Skipped, "skipped"),
    ] {
        let n = count(o);
        if n > 0 {
            rest.push(format!("{n} {word}"));
        }
    }
    let rest = if rest.is_empty() {
        String::new()
    } else {
        format!("; {}", rest.join(", "))
    };
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    if r.dry_run {
        let n = count(ApplyOutcome::WouldRemove);
        let bytes = apply::total_bytes(
            r.items
                .iter()
                .filter(|i| i.outcome == ApplyOutcome::WouldRemove),
        );
        writeln!(
            w,
            "would remove {n} item{} ({}){rest}; nothing removed",
            plural(n),
            human(bytes)
        )?;
    } else {
        let n = count(ApplyOutcome::Removed);
        writeln!(
            w,
            "removed {n} item{}, freed about {}{rest}",
            plural(n),
            human(r.freed)
        )?;
    }
    if let Some(p) = audit {
        writeln!(w, "audit log: {}", p.display())?;
    }
    Ok(())
}

/// A finding's bytes less those held by findings inside it, which are
/// listed and counted on their own.
fn own_bytes(f: &Finding) -> u64 {
    f.bytes.saturating_sub(f.nested_bytes.unwrap_or(0))
}

/// What the findings' actions can free, and how many findings were left
/// out of that total: advice-only ones (such as an in-use volume) and
/// blocked ones (a guard such as `recent-write` failed).
fn reclaimable(findings: &[&Finding]) -> (String, String) {
    let advice = findings
        .iter()
        .filter(|f| f.action.kind == ActionKind::Advice)
        .count();
    let blocked = findings
        .iter()
        .filter(|f| f.action.kind != ActionKind::Advice && f.tier == Tier::Blocked)
        .count();
    let bytes: u64 = findings
        .iter()
        .filter(|f| f.action.kind != ActionKind::Advice && f.tier != Tier::Blocked)
        .map(|f| own_bytes(f))
        .sum();
    let mut note = String::new();
    if advice > 0 {
        note.push_str(&format!("; {advice} in use, not counted"));
    }
    if blocked > 0 {
        note.push_str(&format!("; {blocked} blocked, not counted"));
    }
    (human(bytes), note)
}

fn render_findings(w: &mut impl Write, r: &ScanReport, max: usize) -> io::Result<()> {
    if r.detectors.is_empty() {
        return Ok(());
    }
    writeln!(w)?;
    let (total, note) = reclaimable(&r.findings.iter().collect::<Vec<_>>());
    let ran = r.detectors.iter().filter(|d| d.ran).count();
    writeln!(
        w,
        "findings: {} ({total} reclaimable{note}) from {ran} of {} detectors",
        r.findings.len(),
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
        if in_tier.is_empty() || shown == max {
            continue;
        }
        if tier == Tier::Blocked {
            let bytes: u64 = in_tier.iter().map(|f| own_bytes(f)).sum();
            writeln!(
                w,
                "  blocked ({}, not offered: a guard failed)",
                human(bytes)
            )?;
        } else {
            let (bytes, note) = reclaimable(&in_tier);
            writeln!(w, "  {} ({bytes}{note})", tier_name(tier))?;
        }
        for f in in_tier {
            if shown == max {
                break;
            }
            shown += 1;
            write!(w, "  {:>8}  {:<13} {}", human(f.bytes), f.detector, f.path)?;
            match &f.growth {
                Some(g) if g.bytes_per_day != 0 => {
                    writeln!(w, "  ({}/day)", signed(g.bytes_per_day))?
                }
                _ => writeln!(w)?,
            }
            writeln!(w, "  {:>8}  {:<13} {}", "", "", f.reason)?;
            writeln!(w, "  {:>8}  {:<13} → {}", "", "", f.action.text)?;
            if let Some(ev) = f.evidence.as_ref().and_then(|e| e.postgres_wal.as_ref()) {
                writeln!(
                    w,
                    "  {:>8}  {:<13} {}: {}",
                    "",
                    "",
                    postgres_wal::NAME,
                    postgres_wal::summary(ev)
                )?;
            }
            for g in f.guards.iter().filter(|g| g.status == GuardStatus::Block) {
                writeln!(
                    w,
                    "  {:>8}  {:<13} blocked by {}: {}",
                    "", "", g.name, g.detail
                )?;
            }
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
    for d in r.detectors.iter().filter(|d| d.error.is_some()) {
        writeln!(
            w,
            "  failed: {}: {}",
            d.name,
            d.error.as_deref().unwrap_or("")
        )?;
    }
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
    let mark = |s: DetectorAvailability| match s {
        DetectorAvailability::Available => "ok  ",
        DetectorAvailability::Degraded => "part",
        DetectorAvailability::Unavailable => "off ",
        DetectorAvailability::NotImplemented => "todo",
    };
    for det in &d.detectors {
        writeln!(
            w,
            "  {} {:<19} {:<9} {}",
            mark(det.status),
            det.name,
            det.milestone,
            det.detail
        )?;
    }
    if !d.probes.is_empty() {
        writeln!(w)?;
        writeln!(w, "probes")?;
        for p in &d.probes {
            writeln!(
                w,
                "  {} {:<19} {:<9} {}",
                mark(p.status),
                p.name,
                p.milestone,
                p.detail
            )?;
        }
    }
    if !d.notes.is_empty() {
        writeln!(w)?;
        for n in &d.notes {
            writeln!(w, "note: {n}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dwhy_core::report::*;

    fn finding(detector: &str, path: &str, bytes: u64, tier: Tier, kind: ActionKind) -> Finding {
        Finding {
            id: format!("f_{path}"),
            detector: detector.into(),
            probe: None,
            evidence: None,
            path: path.into(),
            bytes,
            nested_bytes: None,
            last_modified: None,
            growth: None,
            tier,
            reason: "why".into(),
            guards: vec![],
            action: Action {
                kind,
                text: "what".into(),
                argv: None,
            },
            recovery: Recovery {
                cost: String::new(),
                how: None,
            },
        }
    }

    fn report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: "h".into(),
            uid: 1000,
            root: false,
            generated_at: "2026-11-15T00:00:00Z".into(),
            scan: ScanSummary {
                roots: vec![],
                one_filesystem: true,
                elapsed_ms: 0,
                totals: Totals::default(),
                dirs: vec![],
                min_dir_bytes: 0,
                unreadable: Unreadable::default(),
                skipped_mounts: vec![],
                errors: vec![],
                error_count: 0,
            },
            fs: vec![],
            findings,
            detectors: vec![DetectorRun {
                name: "docker-volume".into(),
                status: DetectorAvailability::Available,
                detail: String::new(),
                ran: true,
                findings: 0,
                elapsed_ms: 0,
                error: None,
            }],
            docker: None,
            snapshot: None,
        }
    }

    #[test]
    fn probe_evidence_is_shown_under_its_finding() {
        let mut f = finding(
            "docker-volume",
            "docker://volume/pg",
            30 << 30,
            Tier::Review,
            ActionKind::Advice,
        );
        f.probe = Some("postgres-wal".into());
        f.reason = "pg_wal holds 29.0G vs 53.0M data; archiving is failing, with 151 failures in total (last failure 2026-11-13T02:10:00Z, last success 2026-11-07T07:25:00Z) (target s3test exited); volume pg holds 30.0G".into();
        f.action.text =
            "restore the archive target s3test; WAL is freed at the next checkpoint".into();
        f.evidence = Some(Evidence {
            postgres_wal: Some(PostgresWal {
                container: "pg-1".into(),
                wal_bytes: Some(29 << 30),
                data_bytes: Some(53 << 20),
                failed_count: Some(151),
                last_archived_at: Some("2026-11-07T07:25:00Z".into()),
                last_failed_at: Some("2026-11-13T02:10:00Z".into()),
                last_failed_wal: None,
                archive_mode: Some("on".into()),
                archive_program: Some("curl".into()),
                archive_timeout: Some("10s".into()),
                targets: vec![ArchiveTarget {
                    host: "s3test".into(),
                    container: Some("s3test".into()),
                    state: "exited".into(),
                }],
                unmatched_hosts: 0,
                source: EvidenceSource::Psql,
                notes: vec![],
            }),
        });
        let mut out = Vec::new();
        render_findings(&mut out, &report(vec![f]), 10).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let reason = lines
            .iter()
            .position(|l| l.starts_with("pg_wal holds 29.0G vs 53.0M data;"))
            .expect(&text);
        assert_eq!(
            lines[reason + 1],
            "→ restore the archive target s3test; WAL is freed at the next checkpoint"
        );
        assert_eq!(
            lines[reason + 2],
            "postgres-wal: psql in pg-1, archive_mode on, archive_timeout 10s, last archived \
             2026-11-07T07:25:00Z, last failed 2026-11-13T02:10:00Z, archive target s3test exited"
        );
    }

    #[test]
    fn in_use_findings_are_not_counted_as_reclaimable() {
        let r = report(vec![
            finding(
                "docker-volume",
                "docker://volume/pg",
                50 << 30,
                Tier::Review,
                ActionKind::Advice,
            ),
            finding(
                "docker-image",
                "docker://image/old",
                300 << 20,
                Tier::Review,
                ActionKind::Command,
            ),
            finding(
                "cargo-target",
                "/p/target",
                200 << 20,
                Tier::Rebuildable,
                ActionKind::RemovePath,
            ),
        ]);
        let mut out = Vec::new();
        render_findings(&mut out, &r, 10).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[1],
            "findings: 3 (500.0M reclaimable; 1 in use, not counted) from 1 of 1 detectors"
        );
        assert!(lines.contains(&"  rebuildable (200.0M)"), "{text}");
        assert!(
            lines.contains(&"  review (300.0M; 1 in use, not counted)"),
            "{text}"
        );
    }

    #[test]
    fn blocked_findings_are_shown_but_not_counted() {
        let mut uv = finding(
            "user-cache",
            "/home/me/.cache/uv",
            400 << 20,
            Tier::Blocked,
            ActionKind::Command,
        );
        uv.guards.push(GuardResult {
            name: "recent-write".into(),
            status: GuardStatus::Block,
            detail: "last written 2 hours ago".into(),
        });
        let r = report(vec![
            uv,
            finding(
                "user-cache",
                "/home/me/go/pkg/mod",
                100 << 20,
                Tier::Regenerable,
                ActionKind::Command,
            ),
        ]);
        let mut out = Vec::new();
        render_findings(&mut out, &r, 10).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[1],
            "findings: 2 (100.0M reclaimable; 1 blocked, not counted) from 1 of 1 detectors"
        );
        assert!(lines.contains(&"  regenerable (100.0M)"), "{text}");
        assert!(
            lines.contains(&"  blocked (400.0M, not offered: a guard failed)"),
            "{text}"
        );
        assert!(
            text.contains("blocked by recent-write: last written 2 hours ago"),
            "{text}"
        );
    }

    #[test]
    fn nested_findings_are_counted_once() {
        let mut wt = finding(
            "git-worktree",
            "/w/old",
            500 << 20,
            Tier::Review,
            ActionKind::Command,
        );
        wt.nested_bytes = Some(200 << 20);
        let mut locked = finding(
            "git-worktree",
            "/w/locked",
            300 << 20,
            Tier::Blocked,
            ActionKind::Command,
        );
        locked.nested_bytes = Some(100 << 20);
        let r = report(vec![
            wt,
            finding(
                "cargo-target",
                "/w/old/target",
                200 << 20,
                Tier::Rebuildable,
                ActionKind::RemovePath,
            ),
            locked,
            finding(
                "cargo-target",
                "/w/locked/target",
                100 << 20,
                Tier::Rebuildable,
                ActionKind::RemovePath,
            ),
        ]);
        let mut out = Vec::new();
        render_findings(&mut out, &r, 10).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[1],
            "findings: 4 (600.0M reclaimable; 1 blocked, not counted) from 1 of 1 detectors"
        );
        assert!(lines.contains(&"  rebuildable (300.0M)"), "{text}");
        assert!(lines.contains(&"  review (300.0M)"), "{text}");
        assert!(
            lines.contains(&"  blocked (200.0M, not offered: a guard failed)"),
            "{text}"
        );
        assert!(
            lines.contains(&"    500.0M  git-worktree  /w/old"),
            "{text}"
        );
    }
}
