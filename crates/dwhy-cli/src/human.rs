//! Text rendering for people. Agents should use `--json`.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use dwhy_core::apply::{self, action_kind_name, guard_status_name, tier_name};
use dwhy_core::detect::escape_controls;
use dwhy_core::explain;
use dwhy_core::probes::postgres_wal;
use dwhy_core::report::{
    ApplyOutcome, ApplyReport, Change, ChangeKind, DetectorAvailability, DiffReport, DirEntry,
    DoctorReport, ExplainReport, Finding, FsReport, GuardStatus, Plan, Rate, ScanReport,
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
        escape_controls(&r.host),
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
        let examples: Vec<std::borrow::Cow<'_, str>> = u
            .dirs
            .iter()
            .take(3)
            .map(|d| escape_controls(&d.path))
            .collect();
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
    let snapshots = s
        .skipped_mounts
        .iter()
        .filter(|m| m.reason == SkipReason::BtrfsSnapshot)
        .count();
    if snapshots > 0 {
        writeln!(
            w,
            "skipped     {snapshots} btrfs snapshot or read-only subvolumes (their shared extents would count twice)"
        )?;
    }
    if s.error_count > 0 {
        writeln!(
            w,
            "errors      {} (first: {}: {})",
            thousands(s.error_count),
            s.errors
                .first()
                .map(|e| escape_controls(&e.path))
                .unwrap_or("?".into()),
            s.errors
                .first()
                .map(|e| escape_controls(&e.error))
                .unwrap_or("?".into())
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
    if let Some(n) = s.dirs_omitted.filter(|n| *n > 0) {
        writeln!(
            w,
            "  … {} more director{} left out by --summary",
            thousands(n),
            if n == 1 { "y" } else { "ies" }
        )?;
    }
    if let Some(snap) = &r.snapshot {
        writeln!(w)?;
        write!(
            w,
            "snapshot saved: {} ({})",
            escape_controls(&snap.id),
            escape_controls(&snap.path)
        )?;
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
    let base = escape_controls(d.since.id.as_deref().unwrap_or(&d.since.path));
    let roots = d
        .roots
        .iter()
        .map(|r| escape_controls(r))
        .collect::<Vec<_>>();
    writeln!(
        w,
        "dwhy diff · {} · since {} ({} ago) · {}",
        escape_controls(&d.host),
        base,
        age(d.elapsed_secs),
        roots.join(" ")
    )?;
    if !dwhy_core::snapshot::same_roots(&d.since.roots, &d.roots) {
        let since_roots = d
            .since
            .roots
            .iter()
            .map(|r| escape_controls(r))
            .collect::<Vec<_>>();
        writeln!(
            w,
            "  the snapshot covers {}; only paths in both are compared",
            since_roots.join(" ")
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
        writeln!(w, "note: {}", escape_controls(n))?;
    }
    if let Some(snap) = &d.snapshot {
        writeln!(w)?;
        writeln!(
            w,
            "snapshot saved: {} ({})",
            escape_controls(&snap.id),
            escape_controls(&snap.path)
        )?;
    }
    Ok(())
}

fn label(kind: ChangeKind, name: &str, detector: Option<&str>) -> String {
    let name = escape_controls(name);
    match kind {
        ChangeKind::Fs | ChangeKind::Dir => name.into_owned(),
        ChangeKind::Image => format!("image {name}"),
        ChangeKind::Container => format!("container {name}"),
        ChangeKind::Volume => format!("volume {name}"),
        ChangeKind::BuildCache => "build cache".into(),
        ChangeKind::Finding => format!("{} {name}", escape_controls(detector.unwrap_or("finding"))),
    }
}

/// Growth over a watch window, per section, fastest first.
pub fn render_watch(w: &mut impl Write, r: &WatchReport, top: usize) -> io::Result<()> {
    let roots = r
        .roots
        .iter()
        .map(|p| escape_controls(p))
        .collect::<Vec<_>>();
    writeln!(
        w,
        "dwhy watch · {} · {:.1}s window · {}",
        escape_controls(&r.host),
        r.elapsed_ms as f64 / 1000.0,
        roots.join(" ")
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
        writeln!(w, "note: {}", escape_controls(n))?;
    }
    Ok(())
}

/// One finding in full: what it is, the probe's evidence, every guard,
/// growth, the action and the cost of recovery. Without a finding, what is
/// at the path and the findings inside it.
pub fn render_explain(w: &mut impl Write, r: &ExplainReport) -> io::Result<()> {
    writeln!(
        w,
        "dwhy explain · {} · {}",
        escape_controls(&r.host),
        escape_controls(&r.path)
    )?;
    if let Some(s) = &r.resolved.snapshot {
        writeln!(
            w,
            "  {} resolved through snapshot {} ({})",
            escape_controls(&r.query),
            escape_controls(&s.id),
            escape_controls(&s.created_at)
        )?;
    }
    let Some(f) = &r.finding else {
        writeln!(w)?;
        if r.gone {
            writeln!(w, "finding {} is gone", escape_controls(&r.query))?;
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
                    escape_controls(&i.detector),
                    tier_name(i.tier),
                    escape_controls(&i.path),
                    escape_controls(&i.id)
                )?;
            }
        }
        return render_notes(w, &r.notes);
    };

    writeln!(w)?;
    writeln!(
        w,
        "finding {} · {} · {}",
        escape_controls(&f.id),
        escape_controls(&f.detector),
        tier_name(f.tier)
    )?;
    writeln!(w, "  {:>8}  {}", human(f.bytes), escape_controls(&f.path))?;
    if let Some(t) = &f.last_modified {
        writeln!(w, "  last written {}", escape_controls(t))?;
    }
    writeln!(w, "  {}", escape_controls(&f.reason))?;

    if let Some(ev) = f.evidence.as_ref().and_then(|e| e.postgres_wal.as_ref()) {
        writeln!(w)?;
        writeln!(w, "evidence ({}):", postgres_wal::NAME)?;
        writeln!(w, "  {}", escape_controls(&postgres_wal::headline(ev)))?;
        for n in &ev.notes {
            writeln!(w, "  note: {}", escape_controls(n))?;
        }
    }

    writeln!(w)?;
    if f.guards.is_empty() {
        writeln!(w, "guards: none apply")?;
    } else {
        writeln!(w, "guards:")?;
        for g in &f.guards {
            let status = guard_status_name(g.status);
            writeln!(
                w,
                "  {status:<5}  {:<20} {}",
                escape_controls(&g.name),
                escape_controls(&g.detail)
            )?;
        }
    }

    writeln!(w)?;
    // A withheld comparison is the reason on the growth line, not a note.
    let withheld = r
        .notes
        .iter()
        .find_map(|n| explain::withheld_growth(n))
        .filter(|_| f.growth.is_none());
    match (&f.growth, withheld) {
        (Some(g), _) => writeln!(
            w,
            "growth: {}/day since {}",
            signed(g.bytes_per_day),
            escape_controls(&g.since)
        )?,
        (None, Some(reason)) => writeln!(w, "growth: unknown ({})", escape_controls(reason))?,
        (None, None) => writeln!(
            w,
            "growth: unknown (no eligible snapshot (one filesystem, at least an hour old) lists this finding)"
        )?,
    }

    writeln!(w)?;
    writeln!(w, "action ({}):", action_kind_name(f.action.kind))?;
    writeln!(w, "  {}", command(&f.action.text))?;

    writeln!(w)?;
    writeln!(w, "recovery:")?;
    writeln!(w, "  cost: {}", escape_controls(&f.recovery.cost))?;
    if let Some(how) = &f.recovery.how {
        writeln!(w, "  how:  {}", command(how))?;
    }
    let notes: Vec<String> = r
        .notes
        .iter()
        .filter(|n| withheld.is_none() || explain::withheld_growth(n).is_none())
        .cloned()
        .collect();
    render_notes(w, &notes)
}

fn render_notes(w: &mut impl Write, notes: &[String]) -> io::Result<()> {
    if !notes.is_empty() {
        writeln!(w)?;
    }
    for n in notes {
        writeln!(w, "note: {}", escape_controls(n))?;
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
            escape_controls(&p.expires_at)
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
            writeln!(
                w,
                "  {:>8}  {:<13} {}",
                human(f.bytes),
                escape_controls(&f.detector),
                escape_controls(&f.path)
            )?;
            writeln!(
                w,
                "  {:>8}  {:<13} {} → {}",
                "",
                "",
                escape_controls(&f.id),
                command(&f.action.text)
            )?;
            for g in f.guards.iter().filter(|g| g.status == GuardStatus::Warn) {
                writeln!(
                    w,
                    "  {:>8}  {:<13} warning, {}: {}",
                    "",
                    "",
                    escape_controls(&g.name),
                    escape_controls(&g.detail)
                )?;
            }
        }
    }
    if !p.blocked.is_empty() {
        writeln!(w, "  blocked (not in the plan: a guard failed)")?;
        for f in &p.blocked {
            writeln!(
                w,
                "  {:>8}  {:<13} {}",
                human(f.bytes),
                escape_controls(&f.detector),
                escape_controls(&f.path)
            )?;
            for g in f.guards.iter().filter(|g| g.status == GuardStatus::Block) {
                writeln!(
                    w,
                    "  {:>8}  {:<13} blocked by {}: {}",
                    "",
                    "",
                    escape_controls(&g.name),
                    escape_controls(&g.detail)
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
        Some(path) if !p.items.is_empty() => {
            let path = path.to_string_lossy();
            let apply = format!("dwhy apply {}", dwhy_core::detect::shell_quote(&path));
            writeln!(
                w,
                "wrote {}; apply it within an hour: {}",
                escape_controls(&path),
                command(&apply)
            )?
        }
        Some(path) => writeln!(w, "wrote {}", escape_controls(&path.to_string_lossy()))?,
        None => writeln!(w, "no plan file written (-o FILE writes one)")?,
    }
    Ok(())
}

/// The items of an apply, and a summary line unless `items_only` (the
/// preview before the y/N question, which says the rest). `would_free` is
/// a dry run's bytes from its checks ([`apply::summary_with_would_free`]).
pub fn render_apply(
    w: &mut impl Write,
    r: &ApplyReport,
    audit: Option<&Path>,
    items_only: bool,
    would_free: Option<u64>,
) -> io::Result<()> {
    for i in &r.items {
        // An item's fields can come from a hand-edited plan file (an item
        // that is gone or does not match), and paths can hold any byte but
        // NUL and `/`: no control character reaches the terminal raw.
        writeln!(
            w,
            "  {:<12} {:>8}  {:<13} {}",
            apply::outcome_label(i.outcome),
            human(i.bytes),
            escape_controls(&i.detector),
            escape_controls(&i.path)
        )?;
        // `detail` is built in `dwhy-core` and already escapes a plan file's
        // text, so escape only the control characters it may still hold.
        let note = match i.outcome {
            ApplyOutcome::WouldRemove => {
                format!("{} → {}", tier_name(i.tier), command(&i.action.text))
            }
            _ => escape_only_controls(&i.detail).into_owned(),
        };
        writeln!(w, "  {:<12} {:>8}  {:<13} {note}", "", "", "")?;
    }
    if items_only {
        return Ok(());
    }
    writeln!(w, "{}", apply::summary_with_would_free(r, would_free))?;
    if let Some(p) = audit {
        writeln!(w, "audit log: {}", escape_controls(&p.to_string_lossy()))?;
    }
    Ok(())
}

/// What the findings' actions can free, and how many findings were left
/// out of that total: advice-only ones (such as an in-use volume) and
/// blocked ones (a guard such as `recent-write` failed).
fn reclaimable(findings: &[&Finding]) -> (String, String) {
    let advice = findings.iter().filter(|f| f.is_advice()).count() as u64;
    let blocked = findings.iter().filter(|f| f.tier == Tier::Blocked).count() as u64;
    let bytes: u64 = findings
        .iter()
        .filter(|f| f.is_reclaimable())
        .map(|f| f.own_bytes())
        .sum();
    (human(bytes), reclaimable_note(advice, blocked))
}

fn reclaimable_note(advice: u64, blocked: u64) -> String {
    let mut note = String::new();
    if advice > 0 {
        note.push_str(&format!("; {advice} in use, not counted"));
    }
    if blocked > 0 {
        note.push_str(&format!("; {blocked} blocked, not counted"));
    }
    note
}

/// The findings section. With `findings_summary` (`--summary`), the totals
/// are the summary's, over every finding the scan reported, not just the
/// ones left in `findings`.
fn render_findings(w: &mut impl Write, r: &ScanReport, max: usize) -> io::Result<()> {
    if r.detectors.is_empty() {
        return Ok(());
    }
    writeln!(w)?;
    let summary = r.findings_summary.as_ref();
    let (count, total, note) = match summary {
        Some(s) => {
            let advice: u64 = [Tier::Regenerable, Tier::Rebuildable, Tier::Review]
                .iter()
                .map(|t| s.by_tier.get(*t).advice_count)
                .sum();
            (
                s.total,
                human(s.reclaimable_bytes),
                reclaimable_note(advice, s.by_tier.blocked.count),
            )
        }
        None => {
            let (total, note) = reclaimable(&r.findings.iter().collect::<Vec<_>>());
            (r.findings.len() as u64, total, note)
        }
    };
    let ran = r.detectors.iter().filter(|d| d.ran).count();
    writeln!(
        w,
        "findings: {count} ({total} reclaimable{note}) from {ran} of {} detectors",
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
        let tier_summary = summary.map(|s| s.by_tier.get(tier));
        if tier == Tier::Blocked {
            let bytes: u64 = match tier_summary {
                Some(t) => t.bytes,
                None => in_tier.iter().map(|f| f.own_bytes()).sum(),
            };
            writeln!(
                w,
                "  blocked ({}, not offered: a guard failed)",
                human(bytes)
            )?;
        } else {
            let (bytes, note) = match tier_summary {
                Some(t) => (
                    human(t.reclaimable_bytes),
                    reclaimable_note(t.advice_count, 0),
                ),
                None => reclaimable(&in_tier),
            };
            writeln!(w, "  {} ({bytes}{note})", tier_name(tier))?;
        }
        for f in in_tier {
            if shown == max {
                break;
            }
            shown += 1;
            write!(
                w,
                "  {:>8}  {:<13} {}",
                human(f.bytes),
                escape_controls(&f.detector),
                escape_controls(&f.path)
            )?;
            match &f.growth {
                Some(g) if g.bytes_per_day != 0 => {
                    writeln!(w, "  ({}/day)", signed(g.bytes_per_day))?
                }
                _ => writeln!(w)?,
            }
            writeln!(w, "  {:>8}  {:<13} {}", "", "", escape_controls(&f.reason))?;
            writeln!(w, "  {:>8}  {:<13} → {}", "", "", command(&f.action.text))?;
            if let Some(ev) = f.evidence.as_ref().and_then(|e| e.postgres_wal.as_ref()) {
                writeln!(
                    w,
                    "  {:>8}  {:<13} {}: {}",
                    "",
                    "",
                    postgres_wal::NAME,
                    escape_controls(&postgres_wal::summary(ev))
                )?;
            }
            for g in f.guards.iter().filter(|g| g.status == GuardStatus::Block) {
                writeln!(
                    w,
                    "  {:>8}  {:<13} blocked by {}: {}",
                    "",
                    "",
                    escape_controls(&g.name),
                    escape_controls(&g.detail)
                )?;
            }
        }
    }
    let more = (r.findings.len() - shown) as u64 + summary.map_or(0, |s| s.omitted);
    if more > 0 {
        let how = if summary.is_some() {
            "--json without --summary lists them"
        } else {
            "--max-findings or --json lists them"
        };
        writeln!(w, "  … {more} more ({how})")?;
    }
    let unavailable: Vec<std::borrow::Cow<'_, str>> = r
        .detectors
        .iter()
        .filter(|d| !d.ran && d.status == DetectorAvailability::Unavailable)
        .map(|d| escape_controls(&d.name))
        .collect();
    for d in r.detectors.iter().filter(|d| d.error.is_some()) {
        writeln!(
            w,
            "  failed: {}: {}",
            escape_controls(&d.name),
            d.error.as_deref().map(escape_controls).unwrap_or("".into())
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
    writeln!(
        w,
        "filesystem {}  ({}, {})",
        escape_controls(&fs.mount),
        escape_controls(&fs.fstype),
        escape_controls(&fs.source)
    )?;
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
            if under.contains(&fs.mount.as_str()) {
                // The root is this mount point, but the mount shows only part of
                // its filesystem (a subdirectory bind mount or a btrfs subvolume).
                writeln!(
                    w,
                    "  scanned      {:>8}  under {} (this mount shows only part of its filesystem; scan where the whole filesystem is mounted to account for all of it)",
                    human(fs.scanned),
                    escape_controls(&under.join(", ")),
                )?;
            } else {
                writeln!(
                    w,
                    "  scanned      {:>8}  under {} (part of this filesystem; scan {} to account for all of it)",
                    human(fs.scanned),
                    escape_controls(&under.join(", ")),
                    escape_controls(&fs.mount)
                )?;
            }
        }
    }
    if fs.unaccounted_large && !fs.hints.is_empty() {
        writeln!(w, "  likely in:")?;
        let hints = fs
            .hints
            .iter()
            .map(|h| {
                (
                    h,
                    h.path.as_deref().map(escape_controls),
                    escape_controls(&h.detail),
                )
            })
            .collect::<Vec<_>>();
        let width = hints
            .iter()
            .filter_map(|(_, p, _)| p.as_ref().map(|p| p.len()))
            .max()
            .unwrap_or(0)
            .min(28);
        for (h, path, detail) in hints.iter().take(8) {
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
            match path {
                Some(p) => writeln!(w, "    {p:<width$}  {detail}{extra}")?,
                None => writeln!(w, "    {:<width$}  {detail}{extra}", "·")?,
            }
        }
        if fs.hints.len() > 8 {
            writeln!(w, "    … {} more (--json lists them)", fs.hints.len() - 8)?;
        }
    }
    if let Some(cmd) = &fs.rerun {
        writeln!(w, "  rerun with sudo for a full count:")?;
        writeln!(w, "    {}", command(cmd))?;
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
                writeln!(w, "{:>8}  {}", human(d.allocated), escape_controls(&d.path))?;
                walk(w, &children, d, "", 1, max_depth, top)?;
            }
            None => writeln!(w, "{:>8}  {} (below threshold)", "", escape_controls(root))?,
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
        let name = escape_controls(&name);
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
        escape_controls(&d.host),
        escape_controls(&d.tool.name),
        escape_controls(&d.tool.version)
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
        escape_controls(&d.docker_socket.path),
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
            (Some(p), _) => escape_controls(p).into_owned(),
            (None, Some(p)) => format!("not on PATH (found {})", escape_controls(p)),
            (None, None) => "not found".into(),
        };
        writeln!(w, "  {:<11} {loc}", escape_controls(&t.name))?;
        let enables = t
            .enables
            .iter()
            .map(|e| escape_controls(e))
            .collect::<Vec<_>>();
        writeln!(w, "  {:<11} enables {}", "", enables.join(", "))?;
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
            escape_controls(&det.name),
            det.milestone,
            escape_controls(&det.detail)
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
                escape_controls(&p.name),
                p.milestone,
                escape_controls(&p.detail)
            )?;
        }
    }
    if !d.notes.is_empty() {
        writeln!(w)?;
        for n in &d.notes {
            writeln!(w, "note: {}", escape_controls(n))?;
        }
    }
    Ok(())
}

/// A command for the terminal (an action, a recovery, a rerun, `dwhy
/// apply …`). Without control characters it is shown verbatim, so it stays
/// exactly what to run, `'\''` from `shell_quote` included. With them it is
/// escaped like a path, every backslash doubled so `\n` cannot pass for a
/// newline.
fn command(s: &str) -> std::borrow::Cow<'_, str> {
    if s.contains(char::is_control) {
        escape_controls(s)
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// `s` with control characters (newlines, escape sequences) escaped as
/// Rust escapes (`\n`, `\u{1b}`). Backslashes are left alone: details from
/// `dwhy-core` already escape them where the text came from a plan file.
pub(crate) fn escape_only_controls(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains(char::is_control) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .map(|c| {
                if c.is_control() {
                    c.escape_default().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dwhy_core::report::*;

    fn finding(detector: &str, path: &str, bytes: u64, tier: Tier, kind: ActionKind) -> Finding {
        Finding {
            file_identity: None,
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
                dirs_omitted: None,
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
            findings_summary: None,
        }
    }

    fn partial_fs(mount: &str, root: &str) -> ScanReport {
        let mut r = report(vec![]);
        r.scan.roots = vec![RootReport {
            path: root.into(),
            mount: mount.into(),
            totals: Totals::default(),
        }];
        r.fs = vec![FsReport {
            mount: mount.into(),
            fstype: "tmpfs".into(),
            source: "tmpfs".into(),
            size: 100 << 20,
            used: 12 << 20,
            avail: 88 << 20,
            scanned: 8 << 20,
            full_coverage: false,
            unaccounted: None,
            unaccounted_large: false,
            hints: vec![],
            deleted_open: DeletedOpen::default(),
            rerun: None,
        }];
        r
    }

    fn render_fs_text(r: &ScanReport) -> String {
        let mut out = Vec::new();
        render_fs(&mut out, r, &r.fs[0]).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn partial_mount_scanned_at_its_mount_point_does_not_suggest_rescanning_it() {
        // A subdirectory bind mount scanned at its own mount point: telling the
        // user to "scan /mnt/b" again would be a no-op.
        let text = render_fs_text(&partial_fs("/mnt/b", "/mnt/b"));
        assert!(!text.contains("scan /mnt/b to account"), "{text}");
        assert!(text.contains("only part of its filesystem"), "{text}");

        // A subdirectory of an ordinary mount still points at the mount.
        let text = render_fs_text(&partial_fs("/home", "/home/u/src"));
        assert!(
            text.contains("scan /home to account for all of it"),
            "{text}"
        );
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
                archive_library: None,
                ready_wal_files: None,
                wal_on_other_mount: false,
                historical_command: false,
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

    fn explain_report(f: Finding, notes: Vec<String>) -> ExplainReport {
        ExplainReport {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: "h".into(),
            uid: 1000,
            generated_at: "2026-11-15T00:00:00Z".into(),
            query: f.path.clone(),
            resolved: ExplainResolved {
                via: ExplainVia::Path,
                snapshot: None,
            },
            path: f.path.clone(),
            finding: Some(f),
            gone: false,
            size: None,
            inside: vec![],
            notes,
        }
    }

    fn render(r: &ExplainReport) -> String {
        let mut out = Vec::new();
        render_explain(&mut out, r).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn explain_shows_api_only_evidence_notes_once() {
        let mut f = finding(
            "docker-volume",
            "docker://volume/pg",
            30 << 30,
            Tier::Review,
            ActionKind::Advice,
        );
        let note = "psql not used: docker exec failed; fallback reads command-line settings and up to 200 log lines";
        f.probe = Some("postgres-wal".into());
        f.evidence = Some(Evidence {
            postgres_wal: Some(PostgresWal {
                container: "pg-1".into(),
                wal_bytes: None,
                data_bytes: None,
                failed_count: Some(3),
                last_archived_at: None,
                last_failed_at: None,
                last_failed_wal: None,
                archive_mode: Some("on".into()),
                archive_program: None,
                archive_timeout: None,
                targets: vec![],
                unmatched_hosts: 0,
                source: EvidenceSource::ApiOnly,
                notes: vec![note.into()],
                archive_library: None,
                ready_wal_files: None,
                wal_on_other_mount: false,
                historical_command: false,
            }),
        });
        let text = render(&explain_report(f, vec![]));
        assert_eq!(text.matches(note).count(), 1, "{text}");
        assert!(
            text.contains("  api-only in pg-1, archive_mode on\n"),
            "{text}"
        );
        assert!(text.contains(&format!("  note: {note}\n")), "{text}");
    }

    #[test]
    fn explain_gives_the_reason_growth_was_withheld() {
        let f = || {
            finding(
                "docker-container",
                "docker://container/worker",
                5 << 30,
                Tier::Review,
                ActionKind::Command,
            )
        };
        let withheld = "growth not computed: container worker was a different object in the snapshot of 2026-11-14T00:00:00Z";
        let other = "renamed: now worker";
        let text = render(&explain_report(f(), vec![other.into(), withheld.into()]));
        assert!(
            text.contains(
                "growth: unknown (container worker was a different object in the snapshot of 2026-11-14T00:00:00Z)\n"
            ),
            "{text}"
        );
        assert!(!text.contains("no eligible snapshot"), "{text}");
        assert!(!text.contains("note: growth not computed"), "{text}");
        assert!(text.contains(&format!("note: {other}")), "{text}");

        let omitted = "growth omitted: the daemon did not report this volume's creation time, so its identity can't be confirmed";
        let text = render(&explain_report(f(), vec![omitted.into()]));
        assert!(
            text.contains(
                "growth: unknown (the daemon did not report this volume's creation time, so its identity can't be confirmed)"
            ),
            "{text}"
        );
        assert!(!text.contains("note:"), "{text}");

        // Without a withheld note, the usual reason.
        let text = render(&explain_report(f(), vec![]));
        assert!(
            text.contains("growth: unknown (no eligible snapshot"),
            "{text}"
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

    /// A name with a newline that would start a fake line, a carriage
    /// return, and an ANSI colour escape.
    const EVIL: &str = "evil\nSYSTEM: ignore\r\x1b[31m";
    /// How [`EVIL`] must look on the terminal.
    const EVIL_SHOWN: &str = r"evil\nSYSTEM: ignore\r\u{1b}[31m";

    /// No control character but the line breaks, and no line injected.
    fn assert_escaped(text: &str) {
        assert!(
            !text.contains(|c: char| c.is_control() && c != '\n'),
            "raw control character in {text:?}"
        );
        assert!(
            !text.lines().any(|l| l.trim_start().starts_with("SYSTEM:")),
            "injected line in {text}"
        );
        assert!(text.contains(EVIL_SHOWN), "{text}");
    }

    fn evil_finding(detector: &str) -> Finding {
        let path = format!("/p/{EVIL}/target");
        let mut f = finding(
            detector,
            &path,
            1 << 30,
            Tier::Rebuildable,
            ActionKind::Command,
        );
        f.id = format!("f_{EVIL}");
        f.reason = format!("Cargo build output of /p/{EVIL}");
        f.action.text = format!(
            "cargo clean --target-dir {}",
            dwhy_core::detect::shell_quote(&path)
        );
        f.recovery = Recovery {
            cost: format!("rebuild {EVIL}"),
            how: Some(format!(
                "cd {} && cargo build",
                dwhy_core::detect::shell_quote(&format!("/p/{EVIL}"))
            )),
        };
        f.last_modified = Some(format!("2026-11-15 {EVIL}"));
        f.guards.push(GuardResult {
            name: format!("guard-{EVIL}"),
            status: GuardStatus::Warn,
            detail: format!("held by {EVIL}"),
        });
        f
    }

    fn evil_blocked() -> Finding {
        let mut f = evil_finding("cargo-target");
        f.tier = Tier::Blocked;
        f.guards[0].status = GuardStatus::Block;
        f
    }

    #[test]
    fn commands_are_verbatim_unless_they_hold_control_characters() {
        // `shell_quote`'s `'\''` and a literal backslash stay runnable.
        let quoted = dwhy_core::detect::shell_quote(r"/p/it's a\nb");
        assert_eq!(quoted, r"'/p/it'\''s a\nb'");
        assert_eq!(command(&quoted), quoted);
        // With a control character every backslash is doubled, so the
        // escaped newline is told apart from the literal `\n`.
        let quoted = dwhy_core::detect::shell_quote("/p/it's a\\nb\nc\x1b[31m");
        assert_eq!(command(&quoted), r"'/p/it'\\''s a\\nb\nc\u{1b}[31m'");
    }

    #[test]
    fn scan_text_escapes_control_characters() {
        let mut r = report(vec![evil_finding("cargo-target"), evil_blocked()]);
        let root = format!("/p/{EVIL}");
        r.host = format!("host-{EVIL}");
        r.scan.roots = vec![RootReport {
            path: root.clone(),
            mount: "/".into(),
            totals: Totals::default(),
        }];
        r.scan.dirs = vec![
            DirEntry {
                path: root.clone(),
                depth: 0,
                allocated: 2 << 30,
                apparent: 2 << 30,
                files: 1,
            },
            DirEntry {
                path: format!("{root}/{EVIL}"),
                depth: 1,
                allocated: 1 << 30,
                apparent: 1 << 30,
                files: 1,
            },
        ];
        r.scan.unreadable = Unreadable {
            count: 1,
            dirs: vec![UnreadableDir {
                path: format!("/u/{EVIL}"),
                reason: UnreadableReason::PermissionDenied,
                entries_unknown: 0,
                known_bytes: 0,
                owner_uid: None,
            }],
            ..Unreadable::default()
        };
        r.scan.errors = vec![ScanErrorEntry {
            path: format!("/e/{EVIL}"),
            error: format!("read failed: {EVIL}"),
        }];
        r.scan.error_count = 1;
        r.detectors.push(DetectorRun {
            name: format!("det-{EVIL}"),
            status: DetectorAvailability::Available,
            detail: String::new(),
            ran: true,
            findings: 0,
            elapsed_ms: 0,
            error: Some(format!("failed: {EVIL}")),
        });
        r.fs = vec![FsReport {
            mount: format!("/m/{EVIL}"),
            fstype: format!("fs-{EVIL}"),
            source: format!("/dev/{EVIL}"),
            size: 100 << 30,
            used: 90 << 30,
            avail: 10 << 30,
            scanned: 2 << 30,
            full_coverage: true,
            unaccounted: Some(88 << 30),
            unaccounted_large: true,
            hints: vec![Hint {
                kind: HintKind::Logs,
                path: Some(format!("/var/{EVIL}")),
                detail: format!("logs of {EVIL}"),
                unreadable_dirs: 0,
                bytes: None,
            }],
            deleted_open: DeletedOpen::default(),
            rerun: Some(format!(
                "sudo dwhy scan {}",
                dwhy_core::detect::shell_quote(&format!("/m/{EVIL}"))
            )),
        }];
        r.snapshot = Some(SavedSnapshot {
            id: format!("snap-{EVIL}"),
            path: format!("/s/{EVIL}.json.gz"),
            pruned: 0,
        });
        let mut out = Vec::new();
        render_scan(&mut out, &r, 3, 10, 10).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_escaped(&text);
        for shown in [
            format!("dwhy scan · host-{EVIL_SHOWN} ·"),
            format!("filesystem /m/{EVIL_SHOWN}  (fs-{EVIL_SHOWN}, /dev/{EVIL_SHOWN})"),
            format!("/var/{EVIL_SHOWN}  logs of {EVIL_SHOWN}"),
            format!("sudo dwhy scan '/m/{EVIL_SHOWN}'"),
            format!("contents unknown: /u/{EVIL_SHOWN}"),
            format!("(first: /e/{EVIL_SHOWN}: read failed: {EVIL_SHOWN})"),
            format!("cargo-target  /p/{EVIL_SHOWN}/target"),
            format!("Cargo build output of /p/{EVIL_SHOWN}"),
            format!("→ cargo clean --target-dir '/p/{EVIL_SHOWN}/target'"),
            format!("blocked by guard-{EVIL_SHOWN}: held by {EVIL_SHOWN}"),
            format!("failed: det-{EVIL_SHOWN}: failed: {EVIL_SHOWN}"),
            format!("/p/{EVIL_SHOWN}\n"),
            format!("└─ {EVIL_SHOWN}\n"),
            format!("snapshot saved: snap-{EVIL_SHOWN} (/s/{EVIL_SHOWN}.json.gz)"),
        ] {
            assert!(text.contains(&shown), "{shown:?} not in\n{text}");
        }
    }

    fn plan_with(items: Vec<Finding>, blocked: Vec<Finding>) -> Plan {
        Plan {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: "h".into(),
            uid: 1000,
            created_at: "2026-11-15T00:00:00Z".into(),
            expires_at: "2026-11-15T01:00:00Z".into(),
            scan: PlanScan {
                roots: vec!["/p".into()],
                one_filesystem: true,
                detectors: None,
            },
            selection: PlanSelection {
                tier: Some(Tier::Rebuildable),
                select: vec![],
            },
            items: items
                .into_iter()
                .map(|finding| PlanItem {
                    finding,
                    fingerprint: Fingerprint {
                        dev: None,
                        inode: None,
                        newest_mtime: None,
                        size_bucket: 0,
                        git: None,
                        docker_id: None,
                    },
                    scan_root_dev: None,
                })
                .collect(),
            blocked,
            bytes: 1 << 30,
        }
    }

    fn render_plan_text(p: &Plan, written: Option<&Path>) -> String {
        let mut out = Vec::new();
        render_plan(&mut out, p, written, 0).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn plan_text_escapes_control_characters() {
        let p = plan_with(vec![evil_finding("cargo-target")], vec![evil_blocked()]);
        let written = format!("/tmp/{EVIL}.json");
        let text = render_plan_text(&p, Some(Path::new(&written)));
        assert_escaped(&text);
        for shown in [
            format!("cargo-target  /p/{EVIL_SHOWN}/target"),
            format!("f_{EVIL_SHOWN} → cargo clean --target-dir '/p/{EVIL_SHOWN}/target'"),
            format!("warning, guard-{EVIL_SHOWN}: held by {EVIL_SHOWN}"),
            format!("blocked by guard-{EVIL_SHOWN}: held by {EVIL_SHOWN}"),
            format!(
                "wrote /tmp/{EVIL_SHOWN}.json; apply it within an hour: dwhy apply '/tmp/{EVIL_SHOWN}.json'"
            ),
        ] {
            assert!(text.contains(&shown), "{shown:?} not in\n{text}");
        }
    }

    #[test]
    fn plan_apply_line_stays_runnable_for_quotes_and_backslashes() {
        let p = plan_with(vec![evil_finding("cargo-target")], vec![]);
        let text = render_plan_text(&p, Some(Path::new(r"/tmp/it's a\nb.json")));
        assert!(
            text.contains(
                r"wrote /tmp/it's a\\nb.json; apply it within an hour: dwhy apply '/tmp/it'\''s a\nb.json'"
            ),
            "{text}"
        );

        let empty = plan_with(vec![], vec![]);
        let text = render_plan_text(&empty, Some(Path::new(&format!("/tmp/{EVIL}"))));
        assert_escaped(&text);
    }

    #[test]
    fn explain_text_escapes_control_characters() {
        let mut f = evil_finding("cargo-target");
        f.guards[0].status = GuardStatus::Block;
        let mut r = explain_report(f, vec![format!("note about {EVIL}")]);
        r.host = format!("host-{EVIL}");
        r.query = format!("f_{EVIL}");
        r.resolved = ExplainResolved {
            via: ExplainVia::Id,
            snapshot: Some(ExplainSnapshot {
                id: format!("snap-{EVIL}"),
                path: "/s".into(),
                created_at: "2026-11-15T00:00:00Z".into(),
            }),
        };
        let text = render(&r);
        assert_escaped(&text);
        for shown in [
            format!("dwhy explain · host-{EVIL_SHOWN} · /p/{EVIL_SHOWN}/target"),
            format!("f_{EVIL_SHOWN} resolved through snapshot snap-{EVIL_SHOWN}"),
            format!("finding f_{EVIL_SHOWN} · cargo-target · rebuildable"),
            format!("last written 2026-11-15 {EVIL_SHOWN}"),
            format!("guard-{EVIL_SHOWN} held by {EVIL_SHOWN}"),
            format!("  cargo clean --target-dir '/p/{EVIL_SHOWN}/target'"),
            format!("cost: rebuild {EVIL_SHOWN}"),
            format!("how:  cd '/p/{EVIL_SHOWN}' && cargo build"),
            format!("note: note about {EVIL_SHOWN}"),
        ] {
            assert!(text.contains(&shown), "{shown:?} not in\n{text}");
        }

        // A path no detector claims, with findings inside it.
        let mut r = explain_report(evil_finding("cargo-target"), vec![]);
        r.finding = None;
        r.path = format!("/p/{EVIL}");
        r.inside = vec![FindingRef {
            id: format!("f_{EVIL}"),
            path: format!("/p/{EVIL}/target"),
            detector: format!("det-{EVIL}"),
            bytes: 1 << 30,
            tier: Tier::Rebuildable,
        }];
        let text = render(&r);
        assert_escaped(&text);
        assert!(
            text.contains(&format!(
                "det-{EVIL_SHOWN} rebuildable  /p/{EVIL_SHOWN}/target  f_{EVIL_SHOWN}"
            )),
            "{text}"
        );
    }

    fn change(kind: ChangeKind, name: &str, detector: Option<&str>) -> Change {
        Change {
            kind,
            name: name.into(),
            id: None,
            detector: detector.map(Into::into),
            before: Some(1 << 30),
            after: Some(2 << 30),
            change: 1 << 30,
            at_least: false,
            bytes_per_day: 1 << 30,
        }
    }

    #[test]
    fn diff_text_escapes_control_characters() {
        let root = format!("/p/{EVIL}");
        let d = DiffReport {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: format!("host-{EVIL}"),
            uid: 1000,
            generated_at: "2026-11-15T00:00:00Z".into(),
            since: DiffBase {
                id: Some(format!("snap-{EVIL}")),
                path: "/s".into(),
                created_at: "2026-11-14T00:00:00Z".into(),
                roots: vec![format!("/q/{EVIL}")],
                one_filesystem: true,
                min_dir_bytes: 0,
            },
            roots: vec![root.clone()],
            one_filesystem: true,
            elapsed_secs: 86_400,
            min_change: 0,
            fs: vec![change(ChangeKind::Fs, &format!("/m/{EVIL}"), None)],
            dirs: vec![change(ChangeKind::Dir, &format!("{root}/d"), None)],
            docker_compared: true,
            docker: vec![
                change(ChangeKind::Image, &format!("img-{EVIL}"), None),
                change(ChangeKind::Container, &format!("ctr-{EVIL}"), None),
                change(ChangeKind::Volume, &format!("vol-{EVIL}"), None),
            ],
            findings: vec![change(
                ChangeKind::Finding,
                &format!("{root}/target"),
                Some(&format!("det-{EVIL}")),
            )],
            notes: vec![format!("note about {EVIL}")],
            snapshot: Some(SavedSnapshot {
                id: format!("new-{EVIL}"),
                path: format!("/s/{EVIL}"),
                pruned: 0,
            }),
        };
        let mut out = Vec::new();
        render_diff(&mut out, &d, 10).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_escaped(&text);
        for shown in [
            format!(
                "dwhy diff · host-{EVIL_SHOWN} · since snap-{EVIL_SHOWN} (1d 0h ago) · /p/{EVIL_SHOWN}"
            ),
            format!("the snapshot covers /q/{EVIL_SHOWN};"),
            format!("/m/{EVIL_SHOWN}  ("),
            format!("/p/{EVIL_SHOWN}/d  ("),
            format!("image img-{EVIL_SHOWN}"),
            format!("container ctr-{EVIL_SHOWN}"),
            format!("volume vol-{EVIL_SHOWN}"),
            format!("det-{EVIL_SHOWN} /p/{EVIL_SHOWN}/target"),
            format!("note: note about {EVIL_SHOWN}"),
            format!("snapshot saved: new-{EVIL_SHOWN} (/s/{EVIL_SHOWN})"),
        ] {
            assert!(text.contains(&shown), "{shown:?} not in\n{text}");
        }
    }

    #[test]
    fn watch_text_escapes_control_characters() {
        let rate = |kind, name: String| Rate {
            kind,
            name,
            id: None,
            before: Some(1 << 20),
            after: Some(2 << 20),
            change: 1 << 20,
            bytes_per_minute: 1 << 20,
        };
        let r = WatchReport {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: format!("host-{EVIL}"),
            uid: 1000,
            started_at: "2026-11-15T00:00:00Z".into(),
            generated_at: "2026-11-15T00:01:00Z".into(),
            roots: vec![format!("/p/{EVIL}")],
            one_filesystem: true,
            for_secs: 60,
            elapsed_ms: 60_000,
            min_change: 0,
            fs: vec![rate(ChangeKind::Fs, format!("/m/{EVIL}"))],
            dirs: vec![rate(ChangeKind::Dir, format!("/p/{EVIL}/d"))],
            docker_compared: true,
            docker: vec![rate(ChangeKind::Container, format!("ctr-{EVIL}"))],
            notes: vec![format!("note about {EVIL}")],
        };
        let mut out = Vec::new();
        render_watch(&mut out, &r, 10).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_escaped(&text);
        for shown in [
            format!("dwhy watch · host-{EVIL_SHOWN} · 60.0s window · /p/{EVIL_SHOWN}"),
            format!("/m/{EVIL_SHOWN}  ("),
            format!("/p/{EVIL_SHOWN}/d  ("),
            format!("container ctr-{EVIL_SHOWN}"),
            format!("note: note about {EVIL_SHOWN}"),
        ] {
            assert!(text.contains(&shown), "{shown:?} not in\n{text}");
        }
    }

    #[test]
    fn apply_text_escapes_control_characters_once() {
        let f = evil_finding("cargo-target");
        let item = |outcome, detail: &str| ApplyItem {
            id: f.id.clone(),
            detector: format!("det-{EVIL}"),
            path: f.path.clone(),
            tier: f.tier,
            bytes: f.bytes,
            action: f.action.clone(),
            outcome,
            detail: detail.into(),
            guards: vec![],
        };
        // `dwhy-core` escapes plan text in a detail already (`\\n` for a
        // planned literal `\n`); only raw control characters are left.
        let detail = format!(r"changed: planned det /p/a\\nb, now {EVIL}");
        let r = ApplyReport {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: "h".into(),
            uid: 1000,
            generated_at: "2026-11-15T00:00:00Z".into(),
            plan_created_at: "2026-11-15T00:00:00Z".into(),
            dry_run: true,
            max_tier: Tier::Rebuildable,
            confirm: vec![],
            items: vec![
                item(ApplyOutcome::WouldRemove, "ready"),
                item(ApplyOutcome::Skipped, &detail),
            ],
            freed: 0,
        };
        let audit = format!("/a/{EVIL}.jsonl");
        let mut out = Vec::new();
        render_apply(&mut out, &r, Some(Path::new(&audit)), false, None).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_escaped(&text);
        for shown in [
            format!("det-{EVIL_SHOWN} /p/{EVIL_SHOWN}/target"),
            format!("rebuildable → cargo clean --target-dir '/p/{EVIL_SHOWN}/target'"),
            format!(r"changed: planned det /p/a\\nb, now {EVIL_SHOWN}"),
            format!("audit log: /a/{EVIL_SHOWN}.jsonl"),
        ] {
            assert!(text.contains(&shown), "{shown:?} not in\n{text}");
        }
        assert!(!text.contains(r"/p/a\\\\nb"), "escaped twice:\n{text}");
    }

    #[test]
    fn doctor_text_escapes_control_characters() {
        let status = |name: String| DetectorStatus {
            name,
            milestone: "M1".into(),
            status: DetectorAvailability::Available,
            detail: format!("detail {EVIL}"),
        };
        let d = DoctorReport {
            schema: SCHEMA.into(),
            tool: Tool::current(),
            host: format!("host-{EVIL}"),
            uid: 1000,
            euid: 1000,
            root: false,
            docker_group: false,
            docker_socket: DockerSocket {
                path: format!("/run/{EVIL}.sock"),
                exists: false,
                accessible: false,
            },
            tools: vec![
                ToolStatus {
                    name: format!("tool-{EVIL}"),
                    path: Some(format!("/bin/{EVIL}")),
                    off_path: None,
                    enables: vec![format!("det-{EVIL}")],
                },
                ToolStatus {
                    name: "other".into(),
                    path: None,
                    off_path: Some(format!("/opt/{EVIL}")),
                    enables: vec![],
                },
            ],
            detectors: vec![status(format!("det-{EVIL}"))],
            probes: vec![status(format!("probe-{EVIL}"))],
            notes: vec![format!("note about {EVIL}")],
        };
        let mut out = Vec::new();
        render_doctor(&mut out, &d).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_escaped(&text);
        for shown in [
            format!("dwhy doctor · host-{EVIL_SHOWN} ·"),
            format!("socket /run/{EVIL_SHOWN}.sock: absent"),
            format!("tool-{EVIL_SHOWN} /bin/{EVIL_SHOWN}"),
            format!("enables det-{EVIL_SHOWN}"),
            format!("not on PATH (found /opt/{EVIL_SHOWN})"),
            format!("det-{EVIL_SHOWN}"),
            format!("probe-{EVIL_SHOWN}"),
            format!("detail {EVIL_SHOWN}"),
            format!("note: note about {EVIL_SHOWN}"),
        ] {
            assert!(text.contains(&shown), "{shown:?} not in\n{text}");
        }
    }
}
