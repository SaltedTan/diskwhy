//! The TUI as a state machine: scan messages and key events in, state out.
//! Nothing here touches the terminal, so tests drive it directly.

use std::collections::HashSet;
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use dwhy_core::explain::lossy_finding_paths;
use dwhy_core::report::{Finding, Tier};
use dwhy_core::scan::Progress;
use dwhy_core::tree::NodeId;

use crate::job::{Mark, Scanned, Stage};

/// Which size the tree shows and sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeMode {
    /// Blocks on disk (`st_blocks * 512`), hardlinks counted once.
    Allocated,
    /// `st_size` of non-directories.
    Apparent,
}

impl SizeMode {
    pub fn label(self) -> &'static str {
        match self {
            SizeMode::Allocated => "allocated",
            SizeMode::Apparent => "apparent",
        }
    }
}

/// One line of the tree browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub kind: RowKind,
    pub size: u64,
    /// Why the directory's contents are not fully counted.
    pub mark: Option<Mark>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    /// A directory (or a non-directory root) in the tree.
    Node(NodeId),
    /// The non-directory entries directly in this directory.
    Files,
}

/// The directory the browser shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The scan roots, when there is more than one.
    Roots,
    Dir(NodeId),
}

/// Which full-screen view is shown once the scan is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// The directory tree.
    Tree,
    /// The findings list.
    Findings,
    /// One finding, what `dwhy explain` shows for it.
    Detail,
}

/// The tier filter cycle: all, then each tier, then all again.
const FILTERS: [Option<Tier>; 5] = [
    None,
    Some(Tier::Regenerable),
    Some(Tier::Rebuildable),
    Some(Tier::Review),
    Some(Tier::Blocked),
];

/// The findings list and the detail view's scroll position.
#[derive(Debug, Default)]
pub struct FindingList {
    /// Only findings of this tier; `None`: all.
    pub filter: Option<Tier>,
    /// Indices into the report's findings that the filter lets through,
    /// largest first.
    pub shown: Vec<usize>,
    pub selected: usize,
    /// First row on screen.
    pub offset: usize,
    /// First line of the detail view on screen.
    pub scroll: usize,
}

#[derive(Debug)]
pub struct Browser {
    pub data: Scanned,
    pub(crate) lossy_paths: HashSet<String>,
    pub view: View,
    pub place: Place,
    pub rows: Vec<Row>,
    pub total: u64,
    pub selected: usize,
    /// First row on screen.
    pub offset: usize,
    pub(crate) fs_offset: Option<usize>,
    pub findings: FindingList,
}

#[derive(Debug)]
pub enum State {
    Scanning {
        progress: Arc<Progress>,
        stage: Stage,
    },
    Browsing(Box<Browser>),
}

#[derive(Debug)]
pub struct App {
    /// The roots being scanned, for the scanning screen.
    pub roots: Vec<String>,
    pub state: State,
    pub mode: SizeMode,
    /// Rows the list showed at the last draw (what PgUp/PgDn move by).
    pub viewport: usize,
}

impl App {
    /// A scan of `roots` has started; `progress` is its live counters.
    pub fn new(roots: Vec<String>, progress: Arc<Progress>) -> App {
        App {
            roots,
            state: State::Scanning {
                progress,
                stage: Stage::Walking,
            },
            mode: SizeMode::Allocated,
            viewport: 10,
        }
    }

    pub fn set_stage(&mut self, s: Stage) {
        if let State::Scanning { stage, .. } = &mut self.state {
            *stage = s;
        }
    }

    /// The scan finished: show the first root (or the roots, when several).
    pub fn finish(&mut self, data: Scanned) {
        let place = match data.tree.roots() {
            [one] if data.tree.node(*one).is_dir => Place::Dir(*one),
            _ => Place::Roots,
        };
        let mut b = Browser {
            lossy_paths: lossy_finding_paths(&data.report.findings, &data.tree),
            data,
            view: View::Tree,
            place,
            rows: Vec::new(),
            total: 0,
            selected: 0,
            offset: 0,
            fs_offset: None,
            findings: FindingList::default(),
        };
        b.refresh_rows(self.mode);
        b.refilter(None);
        self.state = State::Browsing(Box::new(b));
    }

    pub fn browser(&self) -> Option<&Browser> {
        match &self.state {
            State::Browsing(b) => Some(b),
            State::Scanning { .. } => None,
        }
    }

    /// Handles one key. Returns true when the TUI should quit.
    pub fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('c') if ctrl => return true,
            _ => {}
        }
        let page = self.viewport.max(1);
        let mode = self.mode;
        let State::Browsing(b) = &mut self.state else {
            return false;
        };
        if key.code == KeyCode::Tab {
            b.view = match b.view {
                View::Tree => View::Findings,
                View::Findings | View::Detail => View::Tree,
            };
            return false;
        }
        match b.view {
            View::Tree => {}
            View::Findings => {
                b.on_findings_key(key.code, self.viewport);
                return false;
            }
            View::Detail => {
                b.on_detail_key(key.code, page);
                return false;
            }
        }
        if key.code == KeyCode::Char('f') {
            b.fs_offset = if b.fs_offset.is_some() { None } else { Some(0) };
            return false;
        }
        if let Some(offset) = &mut b.fs_offset {
            let last = b.data.report.fs.len().saturating_sub(page);
            *offset = match key.code {
                KeyCode::Up => offset.saturating_sub(1),
                KeyCode::Down => (*offset + 1).min(last),
                KeyCode::PageUp => offset.saturating_sub(page),
                KeyCode::PageDown => (*offset + page).min(last),
                KeyCode::Home => 0,
                KeyCode::End => last,
                _ => *offset,
            };
            return false;
        }
        let last = b.rows.len().saturating_sub(1);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => b.selected = b.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => b.selected = (b.selected + 1).min(last),
            KeyCode::PageUp => b.selected = b.selected.saturating_sub(page),
            KeyCode::PageDown => b.selected = (b.selected + page).min(last),
            KeyCode::Home | KeyCode::Char('g') => b.selected = 0,
            KeyCode::End | KeyCode::Char('G') => b.selected = last,
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => b.descend(mode),
            KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => b.ascend(mode),
            KeyCode::Char('a') => {
                self.mode = match mode {
                    SizeMode::Allocated => SizeMode::Apparent,
                    SizeMode::Apparent => SizeMode::Allocated,
                };
                b.resort(self.mode);
            }
            _ => {}
        }
        false
    }
}

impl Browser {
    /// The directory shown, as a path ("" for the list of roots).
    pub fn path(&self) -> String {
        match self.place {
            Place::Roots => String::new(),
            Place::Dir(id) => self.data.tree.path(id).to_string_lossy().into_owned(),
        }
    }

    /// The mark on the directory shown, if any.
    pub fn mark(&self) -> Option<Mark> {
        match self.place {
            Place::Roots => None,
            Place::Dir(id) => self.data.marks.get(&id).copied(),
        }
    }

    /// A row's label: the directory name with a trailing `/`, the full path
    /// for a root, or `[files]`.
    pub fn label(&self, row: &Row) -> String {
        match row.kind {
            RowKind::Files => "[files]".into(),
            RowKind::Node(id) => {
                let t = &self.data.tree;
                let name = sanitize(&t.name(id).to_string_lossy());
                if t.node(id).is_dir && !name.ends_with('/') {
                    format!("{name}/")
                } else {
                    name
                }
            }
        }
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    /// The finding selected in the findings list (and shown in the detail view).
    pub fn selected_finding(&self) -> Option<&Finding> {
        let &i = self.findings.shown.get(self.findings.selected)?;
        self.data.report.findings.get(i)
    }

    fn on_findings_key(&mut self, code: KeyCode, viewport: usize) {
        let l = &mut self.findings;
        let last = l.shown.len().saturating_sub(1);
        let page = viewport.max(1);
        match code {
            KeyCode::Char('t') => {
                let at = FILTERS.iter().position(|&f| f == l.filter).unwrap_or(0);
                self.refilter(FILTERS[(at + 1) % FILTERS.len()]);
            }
            code if l.shown.is_empty() => scroll_lines(&mut l.offset, code, page),
            KeyCode::Up | KeyCode::Char('k') => l.selected = l.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => l.selected = (l.selected + 1).min(last),
            KeyCode::PageUp => l.selected = l.selected.saturating_sub(page),
            KeyCode::PageDown => l.selected = (l.selected + page).min(last),
            KeyCode::Home | KeyCode::Char('g') => l.selected = 0,
            KeyCode::End | KeyCode::Char('G') => l.selected = last,
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') if viewport > 0 => {
                l.scroll = 0;
                self.view = View::Detail;
            }
            _ => {}
        }
    }

    fn on_detail_key(&mut self, code: KeyCode, page: usize) {
        match code {
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                self.view = View::Findings;
            }
            _ => scroll_lines(&mut self.findings.scroll, code, page),
        }
    }

    /// Applies a tier filter, keeping the selected finding when it is still shown.
    fn refilter(&mut self, filter: Option<Tier>) {
        let keep = self.findings.shown.get(self.findings.selected).copied();
        let all = &self.data.report.findings;
        let mut shown: Vec<usize> = (0..all.len())
            .filter(|&i| filter.is_none_or(|t| all[i].tier == t))
            .collect();
        shown.sort_by(|&a, &b| {
            all[b]
                .bytes
                .cmp(&all[a].bytes)
                .then_with(|| all[a].path.cmp(&all[b].path))
        });
        let l = &mut self.findings;
        l.selected = keep
            .and_then(|k| shown.iter().position(|&i| i == k))
            .unwrap_or(0);
        l.offset = 0;
        l.shown = shown;
        l.filter = filter;
    }

    fn descend(&mut self, mode: SizeMode) {
        let Some(Row {
            kind: RowKind::Node(id),
            ..
        }) = self.selected_row()
        else {
            return;
        };
        let id = *id;
        if !self.data.tree.node(id).is_dir {
            return;
        }
        self.place = Place::Dir(id);
        self.refresh_rows(mode);
        self.selected = 0;
        self.offset = 0;
    }

    fn ascend(&mut self, mode: SizeMode) {
        let Place::Dir(id) = self.place else {
            return;
        };
        let up = match self.data.tree.parent(id) {
            Some(p) => Place::Dir(p),
            None if self.data.tree.roots().len() > 1 => Place::Roots,
            None => return,
        };
        self.place = up;
        self.refresh_rows(mode);
        self.selected = self
            .rows
            .iter()
            .position(|r| r.kind == RowKind::Node(id))
            .unwrap_or(0);
        self.offset = 0;
    }

    /// Re-sorts for a new size mode, keeping the same row selected.
    fn resort(&mut self, mode: SizeMode) {
        let keep = self.selected_row().map(|r| r.kind);
        self.refresh_rows(mode);
        self.selected = keep
            .and_then(|k| self.rows.iter().position(|r| r.kind == k))
            .unwrap_or(0);
    }

    fn refresh_rows(&mut self, mode: SizeMode) {
        self.rows = rows(&self.data, self.place, mode);
        self.total = match self.place {
            Place::Roots => self.rows.iter().map(|r| r.size).sum(),
            Place::Dir(id) => size(&self.data.tree.node(id).total, mode),
        };
    }
}

fn size(t: &dwhy_core::report::Totals, mode: SizeMode) -> u64 {
    match mode {
        SizeMode::Allocated => t.allocated,
        SizeMode::Apparent => t.apparent,
    }
}

/// The rows for `place`, largest first (ties by name).
fn rows(data: &Scanned, place: Place, mode: SizeMode) -> Vec<Row> {
    let t = &data.tree;
    let node_row = |id: NodeId| Row {
        kind: RowKind::Node(id),
        size: size(&t.node(id).total, mode),
        mark: data.marks.get(&id).copied(),
    };
    let mut out: Vec<Row> = match place {
        Place::Roots => t.roots().iter().map(|&id| node_row(id)).collect(),
        Place::Dir(id) => {
            let mut v: Vec<Row> = t.children(id).iter().map(|&c| node_row(c)).collect();
            let node = t.node(id);
            if node.has_direct_files {
                v.push(Row {
                    kind: RowKind::Files,
                    size: match mode {
                        SizeMode::Allocated => node.own.allocated - node.directory_allocated,
                        SizeMode::Apparent => node.own.apparent,
                    },
                    mark: None,
                });
            }
            v
        }
    };
    // Children come sorted by name; a stable sort keeps that order for ties.
    out.sort_by_key(|r| std::cmp::Reverse(r.size));
    out
}

/// Replaces control characters, which would garble the screen.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn scroll_lines(offset: &mut usize, code: KeyCode, page: usize) {
    *offset = match code {
        KeyCode::Up | KeyCode::Char('k') => offset.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => offset.saturating_add(1),
        KeyCode::PageUp => offset.saturating_sub(page),
        KeyCode::PageDown => offset.saturating_add(page),
        KeyCode::Home | KeyCode::Char('g') => 0,
        KeyCode::End | KeyCode::Char('G') => usize::MAX,
        _ => *offset,
    };
}
