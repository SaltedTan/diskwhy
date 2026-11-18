//! The TUI as a state machine: scan messages and key events in, state out.
//! Nothing here touches the terminal, so tests drive it directly.

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
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
    /// The files directly in this directory, and the directory itself.
    Files,
}

/// The directory the browser shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The scan roots, when there is more than one.
    Roots,
    Dir(NodeId),
}

#[derive(Debug)]
pub struct Browser {
    pub data: Scanned,
    pub place: Place,
    pub rows: Vec<Row>,
    pub selected: usize,
    /// First row on screen.
    pub offset: usize,
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
            data,
            place,
            rows: Vec::new(),
            selected: 0,
            offset: 0,
        };
        b.rows = rows(&b.data, place, self.mode);
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

    /// The size of what is shown, in `mode`.
    pub fn total(&self, mode: SizeMode) -> u64 {
        match self.place {
            Place::Roots => self.rows.iter().map(|r| r.size).sum(),
            Place::Dir(id) => size(&self.data.tree.node(id).total, mode),
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
        self.rows = rows(&self.data, self.place, mode);
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
        self.rows = rows(&self.data, up, mode);
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
        self.rows = rows(&self.data, self.place, mode);
        self.selected = keep
            .and_then(|k| self.rows.iter().position(|r| r.kind == k))
            .unwrap_or(0);
    }
}

fn size(t: &dwhy_core::report::Totals, mode: SizeMode) -> u64 {
    match mode {
        SizeMode::Allocated => t.allocated,
        SizeMode::Apparent => t.apparent,
    }
}

/// The rows for `place`, largest first (ties by name). A directory's own
/// files are one `[files]` row, shown when they take any space.
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
            let own = size(&t.node(id).own, mode);
            if own > 0 {
                v.push(Row {
                    kind: RowKind::Files,
                    size: own,
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
