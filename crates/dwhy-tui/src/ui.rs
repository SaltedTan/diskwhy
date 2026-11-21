//! Drawing the app. Laid out to stay legible at 80×24: one title line, a
//! line per filesystem (at most three, tree view only), the list, a status
//! line, key help. A status message replaces the status line, or the key
//! help while the `w` prompt is open. A `dwhy tui --dry-run` session shows
//! `DRY RUN` at the left of the title line on every screen.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};
use std::ops::Range;
use std::sync::atomic::Ordering;

use dwhy_core::apply::{action_kind_name, guard_status_name, tier_name};
use dwhy_core::detect::{PATH_NOT_UTF8_RECOVERY_NOTE, is_lossy, rfc3339};
use dwhy_core::plan;
use dwhy_core::probes::postgres_wal;
use dwhy_core::report::{ActionKind, ApplyOutcome, Finding, FsReport, GuardStatus, Plan, Tier};
use dwhy_core::units::{human, signed, thousands};
use ratatui::Frame;
use ratatui::buffer::CellWidth;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use crate::app::{
    App, ApplyView, Browser, Confirm, FindingList, PlanState, PlanView, RootsGone, SizeMode, State,
    View, sanitize,
};
use crate::job::{self, ApplyStep, Mark, PermissionMark, Scanned, Stage};

/// Filesystem lines shown before "… N more".
const MAX_FS_LINES: usize = 3;
/// Width of the share bar, in cells.
const BAR: usize = 10;

pub fn draw(f: &mut Frame, app: &mut App) {
    draw_at(f, app, job::now());
}

pub fn draw_at(f: &mut Frame, app: &mut App, now: i64) {
    let area = f.area();
    let fs_lines = match &app.state {
        State::Scanning { .. } => 1,
        State::Plan(_) | State::RootsGone(_) | State::Applying(_) => 0,
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
    let title = if app.dry_run() {
        const BADGE: &str = " DRY RUN ";
        let [badge, rest] =
            Layout::horizontal([Constraint::Length(BADGE.len() as u16), Constraint::Min(0)])
                .areas(title);
        let style = Style::new().add_modifier(Modifier::BOLD);
        f.render_widget(Paragraph::new(Span::styled(BADGE, style)), badge);
        rest
    } else {
        title
    };
    app.viewport = list.height as usize;
    let width = area.width as usize;
    // The title line's width: less than `width` behind the DRY RUN badge.
    let tw = title.width as usize;
    let dim = Style::new().add_modifier(Modifier::DIM);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let prompt_open = app.plan_view().is_some_and(|v| v.prompt.is_some());
    let dry_session = app.dry_run();
    let areas = PlanAreas {
        title,
        list,
        status,
        keys,
    };

    match &mut app.state {
        State::RootsGone(why) => {
            let text = match why {
                RootsGone::Removed => "  all scanned roots were removed",
                RootsGone::Unavailable => "  all scanned roots are unavailable",
                RootsGone::Mixed => {
                    "  no scanned roots remain: some were removed, the others are unavailable"
                }
            };
            f.render_widget(title_line("rescan", "", tw), title);
            f.render_widget(Paragraph::new(wrap(text, width).join("\n")), list);
            f.render_widget(Paragraph::new(Span::styled(" q quit", dim)), keys);
        }
        State::Scanning { progress, stage } => {
            f.render_widget(title_line("scanning", "", tw), title);
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
        State::Plan(view) => {
            let help = " ↑↓ PgUp PgDn scroll · x apply · q quit";
            app.viewport = draw_plan(f, view, &areas, help, dry_session, now);
        }
        State::Applying(v) => {
            app.viewport = draw_apply(f, v, &areas);
        }
        State::Browsing(b) if b.view == View::Plan => match &mut b.plan {
            PlanState::Ready(view) => {
                let help =
                    " ↑↓ PgUp PgDn scroll · x apply · w write plan · Esc back · Tab tree · q quit";
                app.viewport = draw_plan(f, view, &areas, help, dry_session, now);
            }
            PlanState::Building { progress, marks } => {
                f.render_widget(title_line("plan", "", tw), title);
                let message = if *marks == b.marked {
                    let n = marks.len();
                    let lines = vec![
                        Line::raw(""),
                        Line::raw(format!(
                            "  Building the plan from {n} marked finding{}",
                            if n == 1 { "" } else { "s" }
                        )),
                        Line::raw("  Rescanning, then checking guards…"),
                    ];
                    f.render_widget(Paragraph::new(lines), list);
                    format!(
                        " rescanned {} entries, {}",
                        thousands(progress.entries.load(Ordering::Relaxed)),
                        human(progress.allocated.load(Ordering::Relaxed))
                    )
                } else {
                    " waiting for the previous build to finish".into()
                };
                f.render_widget(Paragraph::new(Span::styled(message, bold)), status);
                let help = " Esc back to findings · q quit";
                f.render_widget(Paragraph::new(Span::styled(help, dim)), keys);
            }
            PlanState::None => {}
        },
        State::Browsing(b) if b.view == View::Findings => {
            let filter = b.findings.filter.map_or("all tiers", tier_name);
            let mut count = format!(
                "{filter} · {}/{}",
                b.findings.shown.len(),
                b.data.report.findings.len()
            );
            if !b.marked.is_empty() {
                count.push_str(&format!(
                    " · {} marked {}",
                    b.marked.len(),
                    human(b.marked_bytes())
                ));
            }
            let failed: Vec<_> = b
                .data
                .report
                .detectors
                .iter()
                .filter_map(|d| d.error.as_deref().map(|e| (d.name.as_str(), e)))
                .collect();
            f.render_widget(title_line("findings", &count, tw), title);
            let marks = Marks {
                lossy: &b.lossy_paths,
                marked: &b.marked,
            };
            app.viewport = draw_findings(f, &mut b.findings, &b.data, list, &failed, marks);
            f.render_widget(Paragraph::new(findings_status(b, &failed, width)), status);
            let help =
                " ↑↓ · Enter details · Space mark · p plan · t tier filter · Tab tree · q quit";
            f.render_widget(Paragraph::new(Span::styled(help, dim)), keys);
        }
        State::Browsing(b) if b.view == View::Detail => {
            let Some(finding) = b.selected_finding() else {
                return;
            };
            f.render_widget(
                title_with(tier_name(finding.tier), tw, |room| {
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
                f.render_widget(title_line("filesystems", "", tw), title);
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
            f.render_widget(title_line(&place, app.mode.label(), tw), title);
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
    if let Some(msg) = &app.message {
        let at = if prompt_open { keys } else { status };
        let text = middle_units(display_units(&format!(" {msg}")), width);
        f.render_widget(Clear, at);
        f.render_widget(Paragraph::new(Span::styled(text, bold)), at);
    }
}

struct PlanAreas {
    title: Rect,
    list: Rect,
    status: Rect,
    keys: Rect,
}

/// The plan preview: a banner when `dwhy apply` would refuse the plan, the
/// plan's lines (scrollable), and the status line or the `w` prompt; or
/// the confirm dialog `x` opened. Returns the lines on screen.
fn draw_plan(
    f: &mut Frame,
    v: &mut PlanView,
    a: &PlanAreas,
    help: &str,
    dry_session: bool,
    now: i64,
) -> usize {
    if v.confirm.is_some() {
        return draw_confirm(f, v, a, dry_session);
    }
    let width = a.list.width as usize;
    let dim = Style::new().add_modifier(Modifier::DIM);
    let p = v.plan();
    let right = format!(
        "{} item{} · {}",
        p.items.len(),
        if p.items.len() == 1 { "" } else { "s" },
        human(p.bytes)
    );
    let place = match &v.file {
        Some(file) => format!("plan {}", file.to_string_lossy()),
        None => "plan preview".into(),
    };
    f.render_widget(
        title_with(&right, a.title.width as usize, |room| {
            middle_units(display_units(&place), room)
        }),
        a.title,
    );
    let banner: Vec<Line> = match v.unusable(now) {
        Some(why) => wrap(&format!(" NOT USABLE: {why}"), width)
            .into_iter()
            .map(|l| {
                let pad = width.saturating_sub(grapheme_width(&l));
                Line::raw(format!("{l}{}", " ".repeat(pad)))
                    .style(Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD))
            })
            .collect(),
        None => Vec::new(),
    };
    let banner_h = banner.len().min((a.list.height as usize).saturating_sub(1)) as u16;
    let [banner_area, body] =
        Layout::vertical([Constraint::Length(banner_h), Constraint::Min(0)]).areas(a.list);
    f.render_widget(Paragraph::new(banner), banner_area);

    if v.lines.as_ref().is_none_or(|(cached, _)| *cached != width) {
        v.lines = Some((width, plan_lines(v, width)));
    }
    let (_, lines) = v.lines.as_ref().unwrap();
    let height = body.height as usize;
    v.scroll = v.scroll.min(lines.len().saturating_sub(height.max(1)));
    let end = (v.scroll + height).min(lines.len());
    let status = format!(" lines {}–{end} of {}", v.scroll + 1, lines.len());
    let shown = lines[v.scroll..end].to_vec();
    f.render_widget(Paragraph::new(shown), body);

    match &v.prompt {
        Some(path) => {
            const LABEL: &str = " write plan to: ";
            let room = width.saturating_sub(LABEL.len() + 1);
            // Keep the end in sight: it is where the typing goes.
            let units: Vec<_> = display_units(path).collect();
            let mut used = 0;
            let start = units
                .iter()
                .rposition(|u| {
                    used += grapheme_width(u);
                    used > room
                })
                .map_or(0, |i| i + 1);
            let path: String = units[start..].concat();
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::raw(LABEL),
                    Span::raw(path),
                    Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)),
                ])),
                a.status,
            );
            let keys = " Enter create · Esc cancel · Backspace delete · Ctrl-U clear";
            f.render_widget(Paragraph::new(Span::styled(keys, dim)), a.keys);
        }
        None => {
            f.render_widget(Paragraph::new(status), a.status);
            f.render_widget(Paragraph::new(Span::styled(help, dim)), a.keys);
        }
    }
    height
}

/// The confirm dialog: a summary, then every item (tier, size, path,
/// action), with a checkbox on each `review` item. Returns the action page size.
fn draw_confirm(f: &mut Frame, v: &mut PlanView, a: &PlanAreas, dry_session: bool) -> usize {
    let dim = Style::new().add_modifier(Modifier::DIM);
    let (p, c) = v.confirmation().unwrap();
    let items = &p.items;
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let verb = if dry_session { "dry run" } else { "apply" };
    let right = format!(
        "{} item{} · {}",
        items.len(),
        plural(items.len()),
        human(p.bytes)
    );
    f.render_widget(
        title_line(
            &format!("{verb} this plan?"),
            &right,
            a.title.width as usize,
        ),
        a.title,
    );
    let block = Block::bordered().title(if dry_session {
        " Dry run: nothing is removed "
    } else {
        " Remove these items? "
    });
    let inner = block.inner(a.list);
    let width = inner.width as usize;
    let available = inner.height as usize;
    let y = if dry_session { "y dry run" } else { "y apply" };
    let keys = format!(" ↑↓ · PgUp/PgDn scroll · Space tick · {y} · d dry run · Esc back · q quit");
    if c.layout.as_ref().is_none_or(|layout| layout.width != width) {
        c.layout = Some(confirm_layout(p, c, width));
    }
    let layout = c.layout.as_ref().unwrap();
    let row = &layout.rows[c.selected];
    let head = layout.head.len().min(available.saturating_sub(1));
    let height = available - head;
    c.actions_visible = height > 1 + row.label_height
        && layout.head[0].width() <= width
        && row.path_visible
        && layout.lines[row.lines.start].width() <= width
        && a.keys.height > 0
        && grapheme_width(&keys) <= a.keys.width as usize;
    if !c.actions_visible {
        let notice = if a.list.height > 0 { a.list } else { a.status };
        let warning = wrap(" enlarge the terminal to confirm", notice.width as usize);
        f.render_widget(Paragraph::new(warning.join("\n")), notice);
        f.render_widget(
            Paragraph::new(Span::styled(" Esc back · q quit", dim)),
            a.keys,
        );
        return 0;
    }
    f.render_widget(block, a.list);
    let action = row.lines.start + 1 + row.label_height..row.lines.end;
    c.scroll = c
        .scroll
        .max(row.lines.end.saturating_sub(height))
        .min(row.lines.start)
        .min(layout.lines.len().saturating_sub(height));

    let mut shown = layout.head[..head].to_vec();
    let (selected, viewport) = if row.lines.len() > height {
        let footer = if c.selected + 1 == items.len() {
            &layout.lines[row.lines.end..]
        } else {
            &[]
        };
        let action_room = height - 1 - row.label_height;
        let footer = &footer[..footer.len().min(action_room - 1)];
        let action_height = action_room - footer.len();
        c.action_scroll = c.action_scroll.min(action.len() - action_height);
        let start = action.start + c.action_scroll;
        shown.extend_from_slice(&layout.lines[row.lines.start..action.start]);
        shown.extend_from_slice(&layout.lines[start..start + action_height]);
        shown.extend_from_slice(footer);
        (head, action_height)
    } else {
        c.action_scroll = 0;
        // Neighbors are shown from their header down: one cut at the top
        // would show its action without the header and any copy label or
        // withheld notice. The selected row starts at or after the window.
        if let Some(cut) = layout
            .rows
            .iter()
            .find(|r| r.lines.start < c.scroll && c.scroll < r.lines.end)
        {
            c.scroll = cut.lines.end;
        }
        let end = (c.scroll + height).min(layout.lines.len());
        shown.extend_from_slice(&layout.lines[c.scroll..end]);
        // A neighbor cut at the bottom keeps only its header when its copy
        // label or withheld notice does not fit whole.
        if let Some(cut) = layout
            .rows
            .iter()
            .find(|r| r.lines.start < end && end < r.lines.end)
            && end - cut.lines.start < 1 + cut.label_height
        {
            shown.truncate(head + cut.lines.start + 1 - c.scroll);
        }
        (head + row.lines.start - c.scroll, action.len())
    };
    let header = &mut shown[selected];
    header.spans[0].content = Cow::Borrowed("> ");
    *header = std::mem::take(header).style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_widget(Paragraph::new(shown), inner);
    let status = match p.items.get(c.selected).map(|i| &i.finding) {
        Some(f) if f.tier == Tier::Review && c.confirmed.contains(&f.id) => {
            "review: confirmed".to_string()
        }
        Some(f) if f.tier == Tier::Review => {
            "review: not confirmed, so it is refused (Space confirms it)".into()
        }
        Some(f) if f.tier == Tier::Blocked => "blocked: never applied".into(),
        Some(f) if f.action.kind == ActionKind::Advice => {
            format!("{}: advice only, nothing runs", tier_name(f.tier))
        }
        Some(f) => format!("{}: no confirmation needed", tier_name(f.tier)),
        None => String::new(),
    };
    let status = format!(" item {}/{} · {status}", c.selected + 1, p.items.len());
    f.render_widget(
        Paragraph::new(middle(&status, a.status.width as usize)),
        a.status,
    );
    f.render_widget(Paragraph::new(Span::styled(keys, dim)), a.keys);
    viewport
}

#[derive(Debug)]
pub(crate) struct ConfirmLayout {
    width: usize,
    head: Vec<Line<'static>>,
    lines: Vec<Line<'static>>,
    rows: Vec<ConfirmRow>,
}

#[derive(Debug)]
struct ConfirmRow {
    lines: Range<usize>,
    path_visible: bool,
    label_height: usize,
}

fn confirm_layout(p: &Plan, c: &Confirm, width: usize) -> ConfirmLayout {
    let dim = Style::new().add_modifier(Modifier::DIM);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let items = &p.items;
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let reviews = items
        .iter()
        .filter(|i| i.finding.tier == Tier::Review)
        .count();
    let confirmed = items
        .iter()
        .filter(|i| i.finding.tier == Tier::Review && c.confirmed.contains(&i.finding.id))
        .count();
    // What apply would run: core's tier policy for these ticks, and no
    // advice-only item (apply skips those).
    let policy = crate::app::dialog_policy(p, &c.confirmed);
    let going = plan::distinct_bytes(
        items
            .iter()
            .map(|i| &i.finding)
            .filter(|f| f.action.kind != ActionKind::Advice && policy.allows(f).is_ok())
            .map(|f| (f.path.as_str(), f.bytes)),
    );
    let mut summary = format!("{} item{}", items.len(), plural(items.len()));
    if reviews > 0 {
        summary.push_str(&format!(", {confirmed} of {reviews} review confirmed"));
    }
    summary.push_str(&format!(", frees ≈ {}", human(going)));

    let mut head = vec![Line::styled(format!(" {summary}"), bold)];
    if confirmed < reviews {
        head.extend(
            wrap(
                " Unconfirmed review items are refused, as by dwhy apply without --confirm.",
                width,
            )
            .into_iter()
            .map(|l| Line::styled(l, dim)),
        );
    }
    head.push(Line::raw(""));

    let mut rows = Vec::with_capacity(items.len());
    let mut lines = Vec::new();
    for item in items {
        let start = lines.len();
        let f = &item.finding;
        let lossy = is_lossy(&f.path);
        let check = match f.tier {
            Tier::Review if c.confirmed.contains(&f.id) => "[x] ",
            Tier::Review => "[ ] ",
            _ => "    ",
        };
        let header = format!(
            "{check}{:<TIER_W$} {:>8}  ",
            tier_name(f.tier),
            human(f.bytes),
        );
        let path = middle_units(
            display_units(&f.path),
            width.saturating_sub(2 + header.width()),
        );
        const MIN_PATH_TAIL_GRAPHEMES: usize = 8;
        let name = f.path.trim_end_matches('/').rsplit('/').next().unwrap();
        let tail: Vec<_> = display_units(name)
            .rev()
            .take(MIN_PATH_TAIL_GRAPHEMES)
            .collect();
        let tail: String = tail.into_iter().rev().collect();
        let path_visible = !path.is_empty() && path.trim_end_matches('/').ends_with(&tail);
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::raw(header),
            Span::styled(path, Style::new().add_modifier(Modifier::BOLD)),
        ]));
        let (action, label_height) = wrap_action(
            "      ",
            &f.action.text,
            lossy,
            f.action.kind != ActionKind::Advice,
            width,
        );
        lines.extend(action.into_iter().map(Line::raw));
        rows.push(ConfirmRow {
            lines: start..lines.len(),
            path_visible,
            label_height,
        });
    }
    if !p.blocked.is_empty() {
        lines.push(Line::raw(""));
        let n = p.blocked.len();
        lines.extend(
            wrap(
                &format!(
                    "  {n} blocked finding{} not in the plan: never applied",
                    plural(n)
                ),
                width,
            )
            .into_iter()
            .map(|l| Line::styled(l, dim)),
        );
    }

    ConfirmLayout {
        width,
        head,
        lines,
        rows,
    }
}

/// What `dwhy apply` prints for an item's outcome.
fn outcome_label(o: ApplyOutcome) -> &'static str {
    match o {
        ApplyOutcome::Removed => "removed",
        ApplyOutcome::Failed => "FAILED",
        ApplyOutcome::Skipped => "skipped",
        ApplyOutcome::Refused => "refused",
        ApplyOutcome::WouldRemove => "would remove",
    }
}

/// What an exit status of `dwhy apply` means.
fn exit_meaning(code: u8) -> &'static str {
    match code {
        0 => "ok",
        1 => "failed",
        2 => "something was skipped",
        3 => "refused",
        _ => "",
    }
}

/// The apply screen: progress while it runs, then the results. Returns the
/// lines on screen.
fn draw_apply(f: &mut Frame, v: &mut ApplyView, a: &PlanAreas) -> usize {
    let dim = Style::new().add_modifier(Modifier::DIM);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let tw = a.title.width as usize;
    let width = a.list.width as usize;
    let what = if v.dry_run { "dry run" } else { "apply" };
    let Some(result) = &v.result else {
        f.render_widget(title_line(&format!("{what}: running"), "", tw), a.title);
        let mut lines = vec![Line::raw("")];
        let intro = if v.dry_run {
            "  Dry run: rescanning the plan's roots and checking every item again. Nothing is removed."
        } else {
            "  Applying the plan: rescanning its roots and checking every item again, then removing the ready ones, deepest first."
        };
        lines.extend(wrap(intro, width).into_iter().map(Line::raw));
        f.render_widget(Paragraph::new(lines), a.list);
        let msg = if v.stopping {
            " stopping: the item in progress finishes; no more items run".to_string()
        } else {
            match v.progress.step() {
                ApplyStep::Rescanning => format!(
                    " rescanning… {} entries, {}",
                    thousands(v.progress.scan.entries.load(Ordering::Relaxed)),
                    human(v.progress.scan.allocated.load(Ordering::Relaxed))
                ),
                ApplyStep::Checking => " running detectors and guards…".into(),
                ApplyStep::Removing { done, total, path } => {
                    format!(" removing {} of {total}: {path}", done + 1)
                }
            }
        };
        let msg = middle_units(display_units(&msg), a.status.width as usize);
        f.render_widget(Paragraph::new(Span::styled(msg, bold)), a.status);
        let keys = if v.dry_run {
            " q quit"
        } else {
            " q quit after the item in progress (no more items run)"
        };
        f.render_widget(Paragraph::new(Span::styled(keys, dim)), a.keys);
        return a.list.height as usize;
    };

    let exit = match result {
        Ok(done) => done.exit,
        Err(e) => e.exit,
    };
    if v.lines.as_ref().is_none_or(|(cached, _)| *cached != width) {
        let lines = match result {
            Ok(done) => results_lines(done, width),
            Err(e) => {
                let mut lines: Vec<_> = wrap(&e.message, width)
                    .into_iter()
                    .map(|l| Line::styled(l, bold))
                    .collect();
                lines.push(Line::raw(format!(
                    "  dwhy apply would exit {} ({}) · nothing was removed",
                    e.exit,
                    exit_meaning(e.exit)
                )));
                lines
            }
        };
        v.lines = Some((width, lines));
    }
    let (_, lines) = v.lines.as_ref().unwrap();
    f.render_widget(
        title_line(&format!("{what} results"), &format!("exit {exit}"), tw),
        a.title,
    );
    let height = a.list.height as usize;
    v.scroll = v.scroll.min(lines.len().saturating_sub(height.max(1)));
    let end = (v.scroll + height).min(lines.len());
    let status = format!(" lines {}–{end} of {}", v.scroll + 1, lines.len());
    f.render_widget(Paragraph::new(lines[v.scroll..end].to_vec()), a.list);
    f.render_widget(Paragraph::new(status), a.status);
    let keys = if v.can_go_back() {
        " ↑↓ scroll · Enter rescan · Esc back to the dialog · q quit"
    } else {
        " ↑↓ scroll · Enter rescan · q quit"
    };
    f.render_widget(Paragraph::new(Span::styled(keys, dim)), a.keys);
    height
}

/// The results: `dwhy apply`'s summary, its exit status and the audit log,
/// then each item's outcome with the reason.
fn results_lines(done: &job::Applied, width: usize) -> Vec<Line<'static>> {
    let r = &done.report;
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let mut out: Vec<Line<'static>> = Vec::new();
    let push = |out: &mut Vec<Line<'static>>, s: &str| {
        out.extend(wrap(s, width).into_iter().map(Line::raw));
    };
    let count = |o| r.items.iter().filter(|i| i.outcome == o).count();
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let rest: Vec<String> = [
        (ApplyOutcome::Failed, "failed"),
        (ApplyOutcome::Refused, "refused"),
        (ApplyOutcome::Skipped, "skipped"),
    ]
    .into_iter()
    .filter_map(|(o, word)| {
        let n = count(o);
        (n > 0).then(|| format!("{n} {word}"))
    })
    .collect();
    let rest = if rest.is_empty() {
        String::new()
    } else {
        format!("; {}", rest.join(", "))
    };
    let summary = if r.dry_run {
        let n = count(ApplyOutcome::WouldRemove);
        let bytes = dwhy_core::apply::total_bytes(
            r.items
                .iter()
                .filter(|i| i.outcome == ApplyOutcome::WouldRemove),
        );
        format!(
            "would remove {n} item{} ({}){rest}; nothing removed",
            plural(n),
            human(bytes)
        )
    } else {
        let n = count(ApplyOutcome::Removed);
        format!(
            "removed {n} item{}, freed about {}{rest}",
            plural(n),
            human(r.freed)
        )
    };
    out.extend(
        wrap(&summary, width)
            .into_iter()
            .map(|l| Line::styled(l, bold)),
    );
    push(
        &mut out,
        &format!(
            "  dwhy apply would exit {} ({})",
            done.exit,
            exit_meaning(done.exit)
        ),
    );
    match &done.audit {
        Some(p) => push(&mut out, &format!("  audit log: {}", p.to_string_lossy())),
        None => push(&mut out, "  dry run: no audit line written"),
    }
    for i in &r.items {
        push(&mut out, "");
        let header = format!(
            "{:<12} {:>8}  {}",
            outcome_label(i.outcome),
            human(i.bytes),
            i.path
        );
        let first = out.len();
        push(&mut out, &header);
        for line in &mut out[first..] {
            *line = std::mem::take(line).style(bold);
        }
        if i.outcome == ApplyOutcome::WouldRemove {
            push(
                &mut out,
                &format!("  {} · {}, would run:", i.detector, tier_name(i.tier)),
            );
            out.extend(command_lines(
                "    ",
                &i.action.text,
                is_lossy(&i.path),
                i.action.kind != ActionKind::Advice,
                width,
            ));
        } else if let Some(rest) = (i.action.kind == ActionKind::Command)
            .then(|| command_detail(&i.detail, &i.action.text))
            .flatten()
        {
            // The command itself follows the copy rules, not the prose.
            push(&mut out, &format!("  {} · {rest}", i.detector));
            out.extend(command_lines(
                "    ",
                &i.action.text,
                is_lossy(&i.path),
                true,
                width,
            ));
        } else {
            push(&mut out, &format!("  {} · {}", i.detector, i.detail));
        }
    }
    out
}

/// Core's detail for a command it ran (`ran CMD`, `CMD failed (…): …`)
/// without the command, which is shown on its own lines.
fn command_detail(detail: &str, command: &str) -> Option<String> {
    if command.is_empty() {
        return None;
    }
    if detail.strip_prefix("ran ") == Some(command) {
        return Some("ran:".into());
    }
    let rest = detail.strip_prefix(command)?;
    Some(format!("the command{rest}:"))
}

/// The plan in `dwhy plan`'s order: a summary, the items by size with
/// their actions and every guard result, then the blocked findings with
/// what blocked them.
fn plan_lines(v: &PlanView, width: usize) -> Vec<Line<'static>> {
    let p = v.plan();
    let mut out: Vec<Line<'static>> = Vec::new();
    let push = |out: &mut Vec<Line<'static>>, s: &str| {
        out.extend(wrap(s, width).into_iter().map(Line::raw));
    };
    let blocked = match p.blocked.len() {
        0 => String::new(),
        n => format!(", {n} blocked"),
    };
    let summary = if p.items.is_empty() {
        format!("nothing to remove{blocked}")
    } else {
        format!(
            "{} item{}, frees {}{blocked}",
            p.items.len(),
            if p.items.len() == 1 { "" } else { "s" },
            human(p.bytes)
        )
    };
    out.push(Line::styled(
        middle(&summary, width),
        Style::new().add_modifier(Modifier::BOLD),
    ));
    let expires =
        plan::validity_window(p).map_or_else(|_| "unavailable".into(), |(_, t)| rfc3339(t));
    push(
        &mut out,
        &format!("  created {} · expires {expires}", p.created_at),
    );
    push(&mut out, &format!("  host {} · uid {}", p.host, p.uid));
    for root in &p.scan.roots {
        push(&mut out, &format!("  root {root}"));
    }
    let detectors = p
        .scan
        .detectors
        .as_ref()
        .map_or("all".into(), |d| d.join(", "));
    push(&mut out, &format!("  detectors: {detectors}"));

    if !v.unplanned.is_empty() {
        push(&mut out, "");
        for mark in &v.unplanned {
            push(&mut out, &format!("  {mark}"));
        }
    }

    for item in &p.items {
        let f = &item.finding;
        let lossy = is_lossy(&f.path);
        push(&mut out, "");
        let header = format!(
            "{:<TIER_W$} {:>8}  {}",
            tier_name(f.tier),
            human(f.bytes),
            f.path
        );
        let first = out.len();
        push(&mut out, &header);
        for line in &mut out[first..] {
            *line = std::mem::take(line).style(Style::new().add_modifier(Modifier::BOLD));
        }
        push(&mut out, &format!("  {} · {}", f.id, f.detector));
        if lossy {
            push(
                &mut out,
                "  path is not valid UTF-8; shown approximately — do not copy",
            );
        }
        push(
            &mut out,
            &format!("  action ({}):", action_kind_name(f.action.kind)),
        );
        out.extend(command_lines(
            "    ",
            &f.action.text,
            lossy,
            f.action.kind != ActionKind::Advice,
            width,
        ));
        if f.recovery.how.as_deref() == Some(PATH_NOT_UTF8_RECOVERY_NOTE) {
            push(
                &mut out,
                &format!("  recovery: {PATH_NOT_UTF8_RECOVERY_NOTE}"),
            );
        }
        push(&mut out, "  guards:");
        for g in &f.guards {
            push(
                &mut out,
                &format!(
                    "    {:<5}  {:<20} {}",
                    guard_status_name(g.status),
                    g.name,
                    g.detail
                ),
            );
        }
    }

    if !p.blocked.is_empty() {
        push(&mut out, "");
        push(
            &mut out,
            &format!("blocked, not in the plan ({}):", p.blocked.len()),
        );
        for f in &p.blocked {
            push(
                &mut out,
                &format!("  {:>8}  {}  {}", human(f.bytes), f.detector, f.path),
            );
            push(&mut out, &format!("            {}", f.id));
            if f.action.kind == ActionKind::Advice {
                push(&mut out, &format!("            {}", f.action.text));
            }
            if f.recovery.how.as_deref() == Some(PATH_NOT_UTF8_RECOVERY_NOTE) {
                push(
                    &mut out,
                    &format!("            recovery: {PATH_NOT_UTF8_RECOVERY_NOTE}"),
                );
            }
            let mut blocks = f
                .guards
                .iter()
                .filter(|g| g.status == GuardStatus::Block)
                .peekable();
            if blocks.peek().is_none() {
                push(&mut out, &format!("            {}", f.reason));
            }
            for g in blocks {
                push(
                    &mut out,
                    &format!("            blocked by {}: {}", g.name, g.detail),
                );
            }
        }
    }
    out
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
/// Per-row marks in the findings list.
struct Marks<'a> {
    /// Paths that may have been converted from invalid UTF-8.
    lossy: &'a HashSet<String>,
    /// Marked findings, as indices into the report's findings.
    marked: &'a BTreeSet<usize>,
}

/// Width of the tier column: `rebuildable`.
const TIER_W: usize = 11;
/// Width of the row marker: selected `>`, marked `*`, approximate path `!`.
const MARKER_W: usize = 3;

/// Reserves room for the path before adding the detector and growth columns.
fn draw_findings(
    f: &mut Frame,
    l: &mut FindingList,
    data: &Scanned,
    area: Rect,
    failed: &[(&str, &str)],
    marks: Marks,
) -> usize {
    const MIN_PATH_W: usize = 12;
    let Marks {
        lossy: lossy_paths,
        marked,
    } = marks;
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
    let required_w = MARKER_W + tier_w + size_w + 2 * gap.len();
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
    let header = columns("   ", "tier", "size", "growth", "detector");
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
        let marker: String = [
            if sel { '>' } else { ' ' },
            if marked.contains(&i) { '*' } else { ' ' },
            if lossy_paths.contains(&finding.path) {
                '!'
            } else {
                ' '
            },
        ]
        .into_iter()
        .collect();
        let mut line = Line::from(vec![
            Span::raw(columns(
                &marker,
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
                        | '\u{17b4}'..='\u{17b5}'
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
    wrap_action(prefix, text, lossy, is_command, width)
        .0
        .into_iter()
        .map(Line::raw)
}

fn wrap_action(
    prefix: &str,
    text: &str,
    lossy: bool,
    is_command: bool,
    width: usize,
) -> (Vec<String>, usize) {
    let withheld = if !is_command {
        None
    } else if is_lossy(text) {
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
    if withheld.is_some() {
        let label_height = lines.len();
        return (lines, label_height);
    }
    let copyable =
        text.bytes().all(|b| (b' '..=b'~').contains(&b)) && lines.as_slice() == [original.as_str()];
    if is_command && !copyable {
        lines = wrap("  preview — do not copy", width);
        let label_height = lines.len();
        lines.extend(
            wrap(&original, width.saturating_sub(1))
                .into_iter()
                .map(|line| format!("│{line}")),
        );
        return (lines, label_height);
    }
    (lines, 0)
}

/// Wraps a scan finding in `dwhy explain` field order. `base` is the
/// scan's growth snapshot timestamp, when available.
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
        out.extend(command_lines(
            "  how:  ",
            how,
            lossy,
            how != PATH_NOT_UTF8_RECOVERY_NOTE,
            width,
        ));
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
