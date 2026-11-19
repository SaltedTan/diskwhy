//! Drawing the app. Laid out to stay legible at 80×24: one title line, a
//! line per filesystem (at most three, tree view only), the list, a status
//! line, key help.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::atomic::Ordering;

use dwhy_core::apply::{action_kind_name, guard_status_name, tier_name};
use dwhy_core::probes::postgres_wal;
use dwhy_core::report::{ActionKind, Finding, FsReport};
use dwhy_core::units::{human, signed, thousands};
use ratatui::Frame;
use ratatui::buffer::CellWidth;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use crate::app::{App, Browser, FindingList, SizeMode, State, View, sanitize};
use crate::job::{Mark, PermissionMark, Scanned, Stage};

/// Filesystem lines shown before "… N more".
const MAX_FS_LINES: usize = 3;
/// Width of the share bar, in cells.
const BAR: usize = 10;

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let fs_lines = match &app.state {
        State::Scanning { .. } => 1,
        State::Browsing(b) if b.view != View::Tree || b.fs_offset.is_some() => 0,
        State::Browsing(b) => b.data.report.fs.len().clamp(1, MAX_FS_LINES),
    };
    let status_lines = match &app.state {
        State::Browsing(b)
            if b.view == View::Tree && b.fs_offset.is_none() && b.mark().is_some() =>
        {
            2
        }
        _ => 1,
    };
    let [title, fs, list, status, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(fs_lines as u16),
        Constraint::Min(1),
        Constraint::Length(status_lines),
        Constraint::Length(1),
    ])
    .areas(area);
    app.viewport = list.height as usize;
    let width = area.width as usize;
    let dim = Style::new().add_modifier(Modifier::DIM);
    let bold = Style::new().add_modifier(Modifier::BOLD);

    match &mut app.state {
        State::Scanning { progress, stage } => {
            f.render_widget(title_line("scanning", "", width), title);
            f.render_widget(Paragraph::new(Span::styled(" measuring…", dim)), fs);
            let mut lines = vec![Line::raw(""), Line::raw("  Scanning")];
            lines.extend(
                app.roots
                    .iter()
                    .map(|r| Line::raw(format!("    {}", middle(r, width.saturating_sub(5))))),
            );
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "  Nothing is written or removed. q quits at any time.",
                dim,
            ));
            f.render_widget(Paragraph::new(lines), list);
            let msg = match stage {
                Stage::Walking => format!(
                    " scanning… {} entries, {}",
                    thousands(progress.entries.load(Ordering::Relaxed)),
                    human(progress.allocated.load(Ordering::Relaxed))
                ),
                Stage::Accounting => " measuring filesystems…".into(),
                Stage::Detecting => " running detectors and probes…".into(),
            };
            f.render_widget(Paragraph::new(Span::styled(msg, bold)), status);
            f.render_widget(Paragraph::new(Span::styled(" q quit", dim)), keys);
        }
        State::Browsing(b) if b.view == View::Findings => {
            let filter = b.findings.filter.map_or("all tiers", tier_name);
            let count = format!(
                "{filter} · {}/{}",
                b.findings.shown.len(),
                b.data.report.findings.len()
            );
            let failed: Vec<_> = b
                .data
                .report
                .detectors
                .iter()
                .filter_map(|d| d.error.as_deref().map(|e| (d.name.as_str(), e)))
                .collect();
            f.render_widget(title_line("findings", &count, width), title);
            app.viewport =
                draw_findings(f, &mut b.findings, &b.data, list, &failed, &b.lossy_paths);
            f.render_widget(Paragraph::new(findings_status(b, &failed, width)), status);
            let help = " ↑↓ PgUp PgDn · Enter details · t tier filter · Tab tree · q quit";
            f.render_widget(Paragraph::new(Span::styled(help, dim)), keys);
        }
        State::Browsing(b) if b.view == View::Detail => {
            let Some(finding) = b.selected_finding() else {
                return;
            };
            f.render_widget(
                title_with(tier_name(finding.tier), width, |room| {
                    middle_units(display_units(&finding.path), room)
                }),
                title,
            );
            let lossy = b.lossy_paths.contains(&finding.path);
            let lines = detail_lines(finding, lossy, b.data.growth_base.as_deref(), width);
            let height = list.height as usize;
            let scroll = b
                .findings
                .scroll
                .min(lines.len().saturating_sub(height.max(1)));
            b.findings.scroll = scroll;
            let end = (scroll + height).min(lines.len());
            let msg = format!(" lines {}–{end} of {}", scroll + 1, lines.len());
            let shown: Vec<Line> = lines.into_iter().skip(scroll).take(height).collect();
            f.render_widget(Paragraph::new(shown), list);
            f.render_widget(Paragraph::new(msg), status);
            let help = " ↑↓ PgUp PgDn scroll · Esc back to findings · Tab tree · q quit";
            f.render_widget(Paragraph::new(Span::styled(help, dim)), keys);
        }
        State::Browsing(b) => {
            let reports = &b.data.report.fs;
            if let Some(offset) = &mut b.fs_offset {
                let height = list.height as usize;
                *offset = (*offset).min(reports.len().saturating_sub(height.max(1)));
                let end = (*offset + height).min(reports.len());
                f.render_widget(title_line("filesystems", "", width), title);
                f.render_widget(Paragraph::new(fs_text(&reports[*offset..end], width)), list);
                let msg = if end > *offset {
                    format!(" {}–{end} of {} filesystems", *offset + 1, reports.len())
                } else {
                    format!(" {} filesystems", reports.len())
                };
                f.render_widget(Paragraph::new(msg), status);
                let help = " ↑↓ PgUp PgDn scroll · f back to tree · Tab findings · q quit";
                f.render_widget(Paragraph::new(Span::styled(help, dim)), keys);
                return;
            }
            let path = b.path();
            let place = if path.is_empty() {
                "scan roots".to_string()
            } else {
                sanitize(&path)
            };
            f.render_widget(title_line(&place, app.mode.label(), width), title);
            let shown = if reports.len() > MAX_FS_LINES {
                MAX_FS_LINES - 1
            } else {
                reports.len()
            };
            let mut fsl = fs_text(&reports[..shown], width);
            if shown < reports.len() {
                fsl.push(Line::raw(format!(
                    " … {} more filesystems · f to view all",
                    reports.len() - shown
                )));
            }
            f.render_widget(Paragraph::new(fsl), fs);
            draw_list(f, b, list);
            f.render_widget(Paragraph::new(status_text(b, app.mode)), status);
            let other = match app.mode {
                SizeMode::Allocated => "apparent",
                SizeMode::Apparent => "allocated",
            };
            let help = format!(
                " ↑↓ · Enter open · Bksp up · a {other} · f filesystems · Tab findings · q quit"
            );
            f.render_widget(Paragraph::new(Span::styled(help, dim)), keys);
        }
    }
}

/// ` dwhy  <place>` on the left, `<right>` on the right.
fn title_line(place: &str, right: &str, width: usize) -> Paragraph<'static> {
    title_with(right, width, |room| middle(place, room))
}

fn title_with(
    right: &str,
    width: usize,
    place: impl FnOnce(usize) -> String,
) -> Paragraph<'static> {
    const LEFT: &str = " dwhy  ";
    let right = if right.is_empty() {
        String::new()
    } else {
        format!(" {right} ")
    };
    let room = width.saturating_sub(LEFT.len() + right.len() + 1);
    let place = place(room);
    let pad = width.saturating_sub(LEFT.len() + grapheme_width(&place) + right.len());
    let style = Style::new().add_modifier(Modifier::REVERSED);
    Paragraph::new(Line::from(vec![
        Span::styled(LEFT, style.add_modifier(Modifier::BOLD)),
        Span::styled(place, style),
        Span::styled(" ".repeat(pad), style),
        Span::styled(right, style),
    ]))
}

/// One line per filesystem with `df`'s figures and the unaccounted gap,
/// the same numbers as `dwhy scan`.
fn fs_text(fs: &[FsReport], width: usize) -> Vec<Line<'static>> {
    if fs.is_empty() {
        return vec![Line::raw(" no filesystem figures")];
    }
    fs.iter()
        .map(|f| {
            let figures = format!("  used {} of {}", human(f.used), human(f.size));
            let gap = match f.unaccounted {
                Some(g) => format!(
                    "  unaccounted {}{}",
                    human(g),
                    if f.unaccounted_large { "" } else { " (small)" }
                ),
                // Only a scan of the mount point can measure the gap.
                None => format!("  scanned {} (subtree only)", human(f.scanned)),
            };
            let room = width.saturating_sub(figures.width() + gap.width() + 2);
            let mount = sanitize(&f.mount);
            let fstype = sanitize(&f.fstype);
            let location = if mount.width() + fstype.width() < room {
                format!("{mount} {fstype}")
            } else {
                middle(&mount, room)
            };
            let gap_style = if f.unaccounted_large {
                Style::new().add_modifier(Modifier::BOLD)
            } else {
                Style::new()
            };
            Line::from(vec![
                Span::raw(figures),
                Span::styled(gap, gap_style),
                Span::raw(format!("  {location}")),
            ])
        })
        .collect()
}

fn draw_list(f: &mut Frame, b: &mut Browser, area: Rect) {
    let height = area.height as usize;
    let width = area.width as usize;
    let mut lines: Vec<Line> = Vec::new();
    if b.rows.is_empty() {
        let msg = match b.mark() {
            Some(m) => format!("  {}: its contents are not counted", mark_text(m)),
            None => "  (empty)".into(),
        };
        lines.push(Line::raw(msg));
        f.render_widget(Paragraph::new(lines), area);
        return;
    }
    // Keep the selection on screen.
    if b.selected < b.offset {
        b.offset = b.selected;
    } else if height > 0 && b.selected >= b.offset + height {
        b.offset = b.selected + 1 - height;
    }
    b.offset = b.offset.min(b.rows.len().saturating_sub(height.max(1)));
    // "> " size bar pct "  "
    let fixed = 2 + 7 + 1 + BAR + 1 + 4 + 2;
    for (i, row) in b.rows.iter().enumerate().skip(b.offset).take(height) {
        let pct = percent(row.size, b.total);
        let mark = row.mark.map(|m| format!("  [{}]", mark_text(m)));
        let mark_w = mark.as_deref().map_or(0, str::width);
        let name = middle(&b.label(row), width.saturating_sub(fixed + mark_w));
        let sel = i == b.selected;
        let pct_text = match pct {
            0 if row.size > 0 => " <1%".to_string(),
            p => format!("{p:>3}%"),
        };
        let mut spans = vec![
            Span::raw(if sel { "> " } else { "  " }),
            Span::raw(format!("{:>7} ", human(row.size))),
            Span::raw(format!("{:<BAR$} ", bar(pct))),
            Span::raw(format!("{pct_text}  ")),
            Span::styled(name, Style::new().add_modifier(Modifier::BOLD)),
        ];
        if let Some(m) = mark {
            spans.push(Span::raw(m));
        }
        let mut line = Line::from(spans);
        if sel {
            line = line.style(Style::new().add_modifier(Modifier::REVERSED));
        }
        lines.push(line);
    }
    f.render_widget(Paragraph::new(lines), area);
}

/// Width of the growth column: `+999.9M/d`.
const GROWTH_W: usize = 9;
/// Width of the tier column: `rebuildable`.
const TIER_W: usize = 11;

/// One row per finding shown: tier, size, growth, detector, path. The path
/// is shortened to fit; the figures never are.
fn draw_findings(
    f: &mut Frame,
    l: &mut FindingList,
    data: &Scanned,
    area: Rect,
    failed: &[(&str, &str)],
    lossy_paths: &HashSet<String>,
) -> usize {
    const MIN_PATH_W: usize = 12;
    let width = area.width as usize;
    let height = area.height as usize;
    let all = &data.report.findings;
    if l.shown.is_empty() {
        let empty = if let Some(t) = l.filter.filter(|_| !all.is_empty()) {
            format!("  no {} findings", tier_name(t))
        } else {
            "  no findings".into()
        };
        let suffix = if failed.is_empty() {
            ""
        } else {
            "; detectors failed:"
        };
        let mut lines = vec![Line::raw(format!("{empty}{suffix}"))];
        for (name, error) in failed {
            lines.extend(
                wrap(&format!("    {name}: {error}"), width)
                    .into_iter()
                    .map(Line::raw),
            );
        }
        l.offset = l.offset.min(lines.len().saturating_sub(height.max(1)));
        let shown: Vec<_> = lines.into_iter().skip(l.offset).take(height).collect();
        f.render_widget(Paragraph::new(shown), area);
        return height;
    }
    let (gap, tier_w, size_w) = if width < 28 {
        let (tier_w, size_w) = l.shown.iter().fold((4, 4), |(tier_w, size_w), &i| {
            let finding = &all[i];
            (
                tier_w.max(tier_name(finding.tier).len()),
                size_w.max(human(finding.bytes).len()),
            )
        });
        (" ", tier_w, size_w)
    } else {
        ("  ", TIER_W, 7)
    };
    let required_w = 2 + tier_w + size_w + 2 * gap.len();
    if width < required_w + "path".len() {
        let msg = middle("  Widen to view findings", width);
        f.render_widget(Paragraph::new(msg), area);
        return 0;
    }
    let det_w = l
        .shown
        .iter()
        .map(|&i| all[i].detector.width())
        .max()
        .unwrap_or(0)
        .max("detector".len());
    let show_detector = width >= required_w + det_w + 2 + MIN_PATH_W;
    let show_growth = width >= required_w + GROWTH_W + 2 + det_w + 2 + MIN_PATH_W;
    let columns = |marker: &str, tier: &str, size: &str, growth: &str, detector: &str| {
        let mut cols = format!("{marker}{tier:<tier_w$}{gap}{size:>size_w$}{gap}");
        if show_growth {
            cols.push_str(&format!("{growth:>GROWTH_W$}  "));
        }
        if show_detector {
            cols.push_str(detector);
            cols.push_str(&" ".repeat(det_w - detector.width() + 2));
        }
        cols
    };
    let header = columns("  ", "tier", "size", "growth", "detector");
    let path_w = width - header.width();
    let mut lines = vec![Line::styled(
        format!("{header}path"),
        Style::new().add_modifier(Modifier::DIM),
    )];
    let height = height.saturating_sub(1);
    if l.selected < l.offset {
        l.offset = l.selected;
    } else if height > 0 && l.selected >= l.offset + height {
        l.offset = l.selected + 1 - height;
    }
    l.offset = l.offset.min(l.shown.len().saturating_sub(height.max(1)));
    for (row, &i) in l.shown.iter().enumerate().skip(l.offset).take(height) {
        let finding = &all[i];
        let sel = row == l.selected;
        let growth = match data.growth_base.as_ref().and(finding.growth.as_ref()) {
            Some(g) => format!("{}/d", signed(g.bytes_per_day)),
            None => "–".into(),
        };
        let marker = match (sel, lossy_paths.contains(&finding.path)) {
            (true, true) => ">!",
            (true, false) => "> ",
            (false, true) => " !",
            (false, false) => "  ",
        };
        let mut line = Line::from(vec![
            Span::raw(columns(
                marker,
                tier_name(finding.tier),
                &human(finding.bytes),
                &growth,
                &finding.detector,
            )),
            Span::styled(
                middle_units(display_units(&finding.path), path_w),
                Style::new().add_modifier(Modifier::BOLD),
            ),
        ]);
        if sel {
            line = line.style(Style::new().add_modifier(Modifier::REVERSED));
        }
        lines.push(line);
    }
    f.render_widget(Paragraph::new(lines), area);
    height
}

fn findings_status(b: &Browser, failed: &[(&str, &str)], width: usize) -> Line<'static> {
    let l = &b.findings;
    let growth = match &b.data.growth_base {
        Some(at) => format!("growth since {at}"),
        None => "no growth data".into(),
    };
    let status = if l.shown.is_empty() {
        format!(" {growth}")
    } else {
        format!(" {}/{} · {growth}", l.selected + 1, l.shown.len())
    };
    let Some(&(first, _)) = failed.first().filter(|_| !l.shown.is_empty()) else {
        return Line::raw(middle(&status, width));
    };
    let names = failed
        .iter()
        .map(|&(name, _)| name)
        .collect::<Vec<_>>()
        .join(", ");
    let overhead = " ·  failed".width();
    let min_names = first.width() + if failed.len() > 1 { " …".width() } else { 0 };
    let prefix = if status.width() + overhead + min_names <= width {
        status
    } else if 1 + growth.width() + overhead + min_names <= width {
        format!(" {growth}")
    } else {
        match &b.data.growth_base {
            Some(at) => format!(" since {}", at.split('T').next().unwrap_or(at)),
            None => format!(" {growth}"),
        }
    };
    let room = width.saturating_sub(prefix.width() + overhead);
    if names.width() > room {
        let mut shown = names.as_str();
        while let Some((head, _)) = shown.rsplit_once(", ") {
            if head.width() + " …".width() <= room {
                return Line::raw(format!("{prefix} · {head} … failed"));
            }
            shown = head;
        }
    }
    let names = middle(&names, room);
    Line::raw(middle(&format!("{prefix} · {names} failed"), width))
}

fn display_units(s: &str) -> impl DoubleEndedIterator<Item = Cow<'_, str>> + Clone {
    s.graphemes(true).map(|g| {
        const JOINER: char = '\u{200d}';
        let cells = cell_width(g);
        let escape_grapheme = cells == 0 || cells != g.width();
        let emoji_joined = cells == 2
            && g.contains(JOINER)
            && g.split(JOINER)
                .try_fold(0, |total, part| {
                    let width = part.width();
                    (width > 0).then_some(total + width)
                })
                .is_some_and(|unjoined| unjoined > cells);
        let unicode_escape = |c| {
            escape_grapheme
                || matches!(
                    c,
                    '\u{034f}'
                        | '\u{0605}'
                        | '\u{070f}'
                        | '\u{0890}'..='\u{0891}'
                        | '\u{08e2}'
                        | '\u{200c}'
                        | '\u{e0020}'..='\u{e007f}'
                )
                || (c == JOINER && !emoji_joined)
        };
        if g.contains(|c: char| c.is_control() || c == '\\' || unicode_escape(c)) {
            let mut escaped = String::new();
            for c in g.chars() {
                if c.is_control() || c == '\\' {
                    escaped.extend(c.escape_default());
                } else if unicode_escape(c) {
                    escaped.extend(c.escape_unicode());
                } else {
                    escaped.push(c);
                }
            }
            Cow::Owned(escaped)
        } else {
            Cow::Borrowed(g)
        }
    })
}

fn command_lines(
    prefix: &str,
    text: &str,
    lossy: bool,
    is_command: bool,
    width: usize,
) -> impl Iterator<Item = Line<'static>> {
    let withheld = if text.contains(char::REPLACEMENT_CHARACTER) {
        Some(
            "command withheld: it names a path that is not valid UTF-8 and cannot be shown exactly",
        )
    } else if lossy {
        Some("command withheld because the path cannot be shown exactly")
    } else {
        None
    };
    let original = format!("{prefix}{}", withheld.unwrap_or(text));
    let mut lines = wrap(&original, width);
    if withheld.is_none() && is_command && lines.as_slice() != [original.as_str()] {
        lines = wrap("  preview — do not copy", width);
        lines.extend(
            wrap(&original, width.saturating_sub(1))
                .into_iter()
                .map(|line| format!("│{line}")),
        );
    }
    lines.into_iter().map(Line::raw)
}

/// What `dwhy explain` shows for a finding, in the same order, wrapped to
/// `width`. Guards are the ones the scan recorded; growth comes from the
/// scan's base snapshot (`base`, its `created_at`).
fn detail_lines(f: &Finding, lossy: bool, base: Option<&str>, width: usize) -> Vec<Line<'static>> {
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let mut out: Vec<Line<'static>> = Vec::new();
    let render = |s: &str| wrap(s, width).into_iter().map(Line::raw);
    let mut text = |s: String| out.extend(render(&s));
    text(format!(
        "finding {} · {} · {}",
        f.id,
        f.detector,
        tier_name(f.tier)
    ));
    text(format!("  {:>8}  {}", human(f.bytes), f.path));
    if lossy {
        text("  path is not valid UTF-8; shown approximately — do not copy".into());
    }
    if let Some(t) = &f.last_modified {
        text(format!("  last written {t}"));
    }
    text(format!("  {}", f.reason));

    if let Some(ev) = f.evidence.as_ref().and_then(|e| e.postgres_wal.as_ref()) {
        text(String::new());
        text(format!("evidence ({}):", postgres_wal::NAME));
        text(format!("  {}", postgres_wal::summary(ev)));
        for n in &ev.notes {
            text(format!("  note: {n}"));
        }
    }

    text(String::new());
    if f.guards.is_empty() {
        text("guards: none from the scan (the full checks run when a plan is made)".into());
    } else {
        text("guards:".into());
        for g in &f.guards {
            text(format!(
                "  {:<5}  {:<20} {}",
                guard_status_name(g.status),
                g.name,
                g.detail
            ));
        }
    }

    text(String::new());
    text(match (base, &f.growth) {
        (Some(_), Some(g)) => format!("growth: {}/day since {}", signed(g.bytes_per_day), g.since),
        (Some(_), None) => "growth: unknown".into(),
        (None, _) => "growth: no growth data".into(),
    });

    text(String::new());
    text(format!("action ({}):", action_kind_name(f.action.kind)));
    out.extend(command_lines(
        "  ",
        &f.action.text,
        lossy,
        f.action.kind != ActionKind::Advice,
        width,
    ));

    out.extend(render(""));
    out.extend(render("recovery:"));
    out.extend(render(&format!("  cost: {}", f.recovery.cost)));
    if let Some(how) = &f.recovery.how {
        out.extend(command_lines("  how:  ", how, lossy, true, width));
    }
    if let Some(first) = out.first_mut() {
        *first = std::mem::take(first).style(bold);
    }
    out
}

/// Breaks `s` into lines of at most `width` columns, at spaces where it can
/// and anywhere in a word too long for a line. Continuation lines keep the
/// first line's indent, plus two columns.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let units: Vec<_> = display_units(s).collect();
    if units.iter().map(|g| grapheme_width(g)).sum::<usize>() <= width || width == 0 {
        return vec![units.into_iter().collect()];
    }
    let indent = s.len() - s.trim_start_matches(' ').len();
    let cont = " ".repeat((indent + 2).min(width / 2).min(width.saturating_sub(2)));
    let mut out = Vec::new();
    let mut line = String::new();
    let mut line_w = 0;
    let mut push_line = |line: &str| {
        let spaces = line.graphemes(true).rev().take_while(|g| *g == " ").count();
        if spaces < line.len() {
            out.push(line[..line.len() - spaces].to_string());
        }
    };
    for word in units.split_inclusive(|g| g == " ") {
        let word_w = word
            .iter()
            .filter(|g| *g != " ")
            .map(|g| grapheme_width(g))
            .sum::<usize>();
        if line_w + word_w > width && !line.trim().is_empty() {
            push_line(&line);
            line = cont.clone();
            line_w = cont.len();
        }
        for g in word {
            let gw = grapheme_width(g);
            let (g, gw) = if gw <= width {
                (g.as_ref(), gw)
            } else {
                ("…", 1)
            };
            if g != " " && line_w + gw > width {
                push_line(&line);
                line_w = cont.len().min(width - gw);
                line = cont[..line_w].to_string();
            }
            line.push_str(g);
            line_w += gw;
        }
    }
    push_line(&line);
    out
}

fn grapheme_width(s: &str) -> usize {
    s.graphemes(true).map(cell_width).sum()
}

fn cell_width(g: &str) -> usize {
    if g.contains(char::is_control) {
        0
    } else {
        usize::from(g.cell_width())
    }
}

fn status_text(b: &Browser, mode: SizeMode) -> Vec<Line<'static>> {
    let r = &b.data.report;
    let mut parts = vec![format!(" {} {} here", human(b.total), mode.label())];
    if !b.rows.is_empty() {
        parts.push(format!("{}/{}", b.selected + 1, b.rows.len()));
    }
    let skipped = r.scan.skipped_mounts.len();
    if skipped > 0 {
        parts.push(format!("{} in scan", skipped_mounts_text(skipped)));
    }
    let errors = r.scan.error_count;
    if errors > 0 {
        parts.push(format!(
            "{} scan error{}",
            thousands(errors),
            if errors == 1 { "" } else { "s" }
        ));
    }
    let unread = r.scan.unreadable.count;
    if unread > 0 {
        parts.push(format!(
            "{} unreadable dir{} in scan",
            thousands(unread),
            if unread == 1 { "" } else { "s" }
        ));
    }
    let n = r.findings.len();
    parts.push(format!("{n} finding{}", if n == 1 { "" } else { "s" }));
    let mut lines = vec![Line::raw(parts.join(" · "))];
    if let Some(m) = b.mark() {
        lines.push(Line::raw(format!(" this directory: {}", mark_text(m))));
    }
    lines
}

fn mark_text(m: Mark) -> String {
    let mut parts = Vec::new();
    if let Some(permission) = m.permission {
        parts.push(match permission {
            PermissionMark::Unreadable => "unreadable".into(),
            PermissionMark::EntriesDenied(n) => format!(
                "{} entr{} unreadable",
                thousands(n),
                if n == 1 { "y" } else { "ies" }
            ),
        });
    }
    if m.read_error {
        parts.push("read error".into());
    }
    if m.skipped_mounts > 0 {
        parts.push(skipped_mounts_text(m.skipped_mounts));
    }
    parts.join(", ")
}

fn skipped_mounts_text(n: usize) -> String {
    format!(
        "{} mount{} skipped",
        thousands(n as u64),
        if n == 1 { "" } else { "s" }
    )
}

/// `part` as a whole percentage of `total`, rounded.
pub fn percent(part: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((part as u128 * 100 + total as u128 / 2) / total as u128).min(100) as u64
}

/// A bar of [`BAR`] cells for a percentage, in eighths of a cell.
pub fn bar(pct: u64) -> String {
    const PARTS: [char; 7] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    let eighths = (pct.min(100) as usize * BAR * 8) / 100;
    let mut s = "█".repeat(eighths / 8);
    if !eighths.is_multiple_of(8) {
        s.push(PARTS[eighths % 8 - 1]);
    }
    s
}

/// Shortens `s` to at most `max` columns by replacing its middle with `…`,
/// keeping both ends (the start of a path and its last component).
pub fn middle(s: &str, max: usize) -> String {
    middle_units(s.graphemes(true).map(Cow::Borrowed), max)
}

fn middle_units<'a>(
    units: impl DoubleEndedIterator<Item = Cow<'a, str>> + Clone,
    max: usize,
) -> String {
    if units.clone().map(|g| grapheme_width(&g)).sum::<usize>() <= max {
        return units.collect();
    }
    if max == 0 {
        return String::new();
    }
    let keep = max - 1;
    // Favour the end: it holds the name that tells entries apart.
    let mut head_room = keep / 2;
    let mut tail_room = keep - head_room;
    let mut text: String = units
        .clone()
        .take_while(|g| take_columns(&mut head_room, g))
        .collect();
    let tail: Vec<_> = units
        .rev()
        .take_while(|g| take_columns(&mut tail_room, g))
        .collect();
    text.push('…');
    text.extend(tail.into_iter().rev());
    text
}

fn take_columns(room: &mut usize, unit: &str) -> bool {
    if let Some(left) = room.checked_sub(grapheme_width(unit)) {
        *room = left;
        true
    } else {
        false
    }
}
