//! Drawing the app. Laid out to stay legible at 80×24: one title line, a
//! line per filesystem (at most three), the list, a status line, key help.

use std::sync::atomic::Ordering;

use dwhy_core::report::FsReport;
use dwhy_core::units::{human, thousands};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{App, Browser, SizeMode, State};
use crate::job::{Mark, Stage};

/// Filesystem lines shown before "… N more".
const MAX_FS_LINES: usize = 3;
/// Width of the share bar, in cells.
const BAR: usize = 10;

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let fs_lines = match &app.state {
        State::Scanning { .. } => 1,
        State::Browsing(b) => {
            let n = b.data.report.fs.len();
            if n > MAX_FS_LINES {
                MAX_FS_LINES
            } else {
                n.max(1)
            }
        }
    };
    let [title, fs, list, status, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(fs_lines as u16),
        Constraint::Min(1),
        Constraint::Length(1),
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
        State::Browsing(b) => {
            let path = b.path();
            let place = if path.is_empty() {
                "scan roots".to_string()
            } else {
                path
            };
            f.render_widget(title_line(&place, app.mode.label(), width), title);
            let fsl = fs_text(&b.data.report.fs, width);
            f.render_widget(Paragraph::new(fsl), fs);
            draw_list(f, b, app.mode, list);
            f.render_widget(Paragraph::new(status_text(b, app.mode)), status);
            let other = match app.mode {
                SizeMode::Allocated => "apparent",
                SizeMode::Apparent => "allocated",
            };
            let help =
                format!(" ↑↓ PgUp PgDn move · Enter open · Backspace up · a {other} · q quit");
            f.render_widget(Paragraph::new(Span::styled(help, dim)), keys);
        }
    }
}

/// ` dwhy  <place>` on the left, `<right>` on the right.
fn title_line(place: &str, right: &str, width: usize) -> Paragraph<'static> {
    const LEFT: &str = " dwhy  ";
    let right = if right.is_empty() {
        String::new()
    } else {
        format!(" {right} ")
    };
    let room = width.saturating_sub(LEFT.len() + right.len() + 1);
    let place = middle(place, room);
    let pad = width.saturating_sub(LEFT.len() + place.width() + right.len());
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
    let shown = if fs.len() > MAX_FS_LINES {
        MAX_FS_LINES - 1
    } else {
        fs.len()
    };
    let mut out: Vec<Line> = fs[..shown]
        .iter()
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
            let tail = format!(" {}", f.fstype);
            let room = width.saturating_sub(1 + tail.len() + figures.len() + gap.width());
            let mount = middle(&f.mount, room.max(12));
            let gap_style = if f.unaccounted_large {
                Style::new().add_modifier(Modifier::BOLD)
            } else {
                Style::new()
            };
            Line::from(vec![
                Span::raw(format!(" {mount}{tail}{figures}")),
                Span::styled(gap, gap_style),
            ])
        })
        .collect();
    if shown < fs.len() {
        out.push(Line::raw(format!(
            " … {} more filesystems",
            fs.len() - shown
        )));
    }
    out
}

fn draw_list(f: &mut Frame, b: &mut Browser, mode: SizeMode, area: Rect) {
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
    let total = b.total(mode);
    // "> " size bar pct "  "
    let fixed = 2 + 7 + 1 + BAR + 1 + 4 + 2;
    for (i, row) in b.rows.iter().enumerate().skip(b.offset).take(height) {
        let pct = percent(row.size, total);
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

fn status_text(b: &Browser, mode: SizeMode) -> Line<'static> {
    let r = &b.data.report;
    let mut parts = vec![format!(" {} {} here", human(b.total(mode)), mode.label())];
    if !b.rows.is_empty() {
        parts.push(format!("{}/{}", b.selected + 1, b.rows.len()));
    }
    if let Some(m) = b.mark() {
        parts.push(format!("this directory: {}", mark_text(m)));
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
    Line::raw(parts.join(" · "))
}

fn mark_text(m: Mark) -> String {
    match m {
        Mark::Unreadable => "unreadable".into(),
        Mark::EntriesDenied(n) => format!(
            "{} entr{} unreadable",
            thousands(n),
            if n == 1 { "y" } else { "ies" }
        ),
        Mark::Error => "read error".into(),
    }
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
    if s.width() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let keep = max - 1;
    // Favour the end: it holds the name that tells entries apart.
    let head_w = keep / 2;
    let tail_w = keep - head_w;
    let mut head = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = c.width().unwrap_or(0);
        if w + cw > head_w {
            break;
        }
        head.push(c);
        w += cw;
    }
    let mut tail: Vec<char> = Vec::new();
    let mut w = 0;
    for c in s.chars().rev() {
        let cw = c.width().unwrap_or(0);
        if w + cw > tail_w {
            break;
        }
        tail.push(c);
        w += cw;
    }
    tail.reverse();
    format!("{head}…{}", tail.into_iter().collect::<String>())
}
