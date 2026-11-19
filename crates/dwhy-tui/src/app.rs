//! The TUI as a state machine: scan messages and key events in, state out.
//! Nothing here touches the terminal, so tests drive it directly.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use dwhy_core::explain::lossy_finding_paths;
use dwhy_core::plan;
use dwhy_core::report::{ActionKind, Finding, Plan, Tier};
use dwhy_core::scan::Progress;
use dwhy_core::tree::NodeId;

use crate::job::{self, Mark, PlanJob, Scanned, Stage, Target};

/// Where `w` offers to write a plan, relative to the working directory.
pub const DEFAULT_PLAN_FILE: &str = "./dwhy-plan.json";

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
    /// One finding from the scan, in `dwhy explain` field order.
    Detail,
    /// The plan built from the marked findings.
    Plan,
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
    /// Marked findings, as indices into the report's findings.
    pub marked: BTreeSet<usize>,
    pub plan: PlanState,
    /// Numbers plan builds, so a result that arrives after Esc is dropped.
    plan_builds: u64,
}

/// The plan made from the marks.
#[derive(Debug, Default)]
pub enum PlanState {
    #[default]
    None,
    /// Build number `n` is running on a worker thread.
    Building(u64),
    Ready(Box<PlanView>),
}

/// A plan in the preview.
#[derive(Debug)]
pub struct PlanView {
    pub plan: Plan,
    /// Why `dwhy apply` would refuse this plan here and now (`plan::usable`).
    pub unusable: Option<String>,
    /// The file it was opened from (`dwhy tui --plan`); `None` when built here.
    pub file: Option<PathBuf>,
    pub(crate) lossy_paths: HashSet<String>,
    /// First line on screen.
    pub scroll: usize,
    /// The `w` prompt, while it is open.
    pub prompt: Option<Prompt>,
}

/// The `w` prompt: a path to write the plan to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub path: String,
    /// The path names an existing file; waiting for y or n.
    pub confirm: bool,
}

/// A plan build for the event loop to run off the UI thread.
#[derive(Debug, Clone)]
pub struct PlanRequest {
    pub build: u64,
    pub job: PlanJob,
}

#[derive(Debug)]
pub enum State {
    Scanning {
        progress: Arc<Progress>,
        stage: Stage,
    },
    Browsing(Box<Browser>),
    /// `dwhy tui --plan FILE`: a plan file and no scan.
    Plan(Box<PlanView>),
}

#[derive(Debug)]
pub struct App {
    /// The roots being scanned, for the scanning screen.
    pub roots: Vec<String>,
    pub state: State,
    pub mode: SizeMode,
    /// Rows the list showed at the last draw (what PgUp/PgDn move by).
    pub viewport: usize,
    /// A one-off status message, cleared by the next key.
    pub message: Option<String>,
    request: Option<PlanRequest>,
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
            message: None,
            request: None,
        }
    }

    /// `dwhy tui --plan FILE`: previews `plan`, read from `file`, checked
    /// with `plan::usable` against this `host`, `uid` and `now`.
    pub fn open_plan(plan: Plan, file: PathBuf, host: &str, uid: u32, now: i64) -> App {
        let mut view = PlanView::new(plan, host, uid, now, HashSet::new());
        view.file = Some(file);
        App {
            roots: Vec::new(),
            state: State::Plan(Box::new(view)),
            mode: SizeMode::Allocated,
            viewport: 10,
            message: None,
            request: None,
        }
    }

    /// The plan build the last key asked for, for the caller to run.
    pub fn take_request(&mut self) -> Option<PlanRequest> {
        self.request.take()
    }

    /// Plan build `build` finished; `host` is the one it was built for and
    /// `now` the time, to check the plan with `plan::usable`. A result for
    /// a build that was left with Esc is dropped.
    pub fn plan_built(&mut self, build: u64, result: Result<Plan, String>, host: &str, now: i64) {
        let State::Browsing(b) = &mut self.state else {
            return;
        };
        if !matches!(b.plan, PlanState::Building(n) if n == build) {
            return;
        }
        match result {
            Ok(plan) => {
                let lossy = b.lossy_paths.clone();
                let view = PlanView::new(plan, host, b.data.plan.ctx.uid, now, lossy);
                b.plan = PlanState::Ready(Box::new(view));
            }
            Err(e) => {
                b.plan = PlanState::None;
                b.view = View::Findings;
                self.message = Some(format!("no plan: {e}"));
            }
        }
    }

    /// The plan preview on screen, if any.
    pub fn plan_view(&self) -> Option<&PlanView> {
        match &self.state {
            State::Plan(p) => Some(p),
            State::Browsing(b) if b.view == View::Plan => match &b.plan {
                PlanState::Ready(p) => Some(p),
                _ => None,
            },
            _ => None,
        }
    }

    fn plan_view_mut(&mut self) -> Option<&mut PlanView> {
        match &mut self.state {
            State::Plan(p) => Some(p),
            State::Browsing(b) if b.view == View::Plan => match &mut b.plan {
                PlanState::Ready(p) => Some(p),
                _ => None,
            },
            _ => None,
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
            marked: BTreeSet::new(),
            plan: PlanState::None,
            plan_builds: 0,
        };
        b.refresh_rows(self.mode);
        b.refilter(None);
        self.state = State::Browsing(Box::new(b));
    }

    pub fn browser(&self) -> Option<&Browser> {
        match &self.state {
            State::Browsing(b) => Some(b),
            State::Scanning { .. } | State::Plan(_) => None,
        }
    }

    /// Handles one key. Returns true when the TUI should quit.
    pub fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return true;
        }
        // The prompt takes every other key, `q` included: it is text.
        if let Some(view) = self.plan_view_mut().filter(|v| v.prompt.is_some()) {
            self.message = view.on_prompt_key(key.code, ctrl);
            return false;
        }
        if key.code == KeyCode::Char('q') {
            return true;
        }
        self.message = None;
        let page = self.viewport.max(1);
        let mode = self.mode;
        let b = match &mut self.state {
            State::Browsing(b) => b,
            State::Plan(view) => {
                self.message = view.on_key(key.code, page);
                return false;
            }
            State::Scanning { .. } => return false,
        };
        if key.code == KeyCode::Tab {
            b.view = match b.view {
                View::Tree => View::Findings,
                View::Findings | View::Detail | View::Plan => View::Tree,
            };
            b.plan = PlanState::None;
            return false;
        }
        match b.view {
            View::Tree => {}
            View::Findings => {
                match b.on_findings_key(key.code, self.viewport) {
                    Effect::None => {}
                    Effect::Message(m) => self.message = Some(m),
                    Effect::Build(r) => self.request = Some(r),
                }
                return false;
            }
            View::Detail => {
                b.on_detail_key(key.code, page);
                return false;
            }
            View::Plan => {
                self.message = b.on_plan_key(key.code, page);
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

    /// The marked findings, in report order.
    pub fn marked_findings(&self) -> impl Iterator<Item = &Finding> {
        self.marked.iter().map(|&i| &self.data.report.findings[i])
    }

    /// The marked findings' bytes, leaving out findings inside other marked ones.
    pub fn marked_bytes(&self) -> u64 {
        plan::distinct_bytes(self.marked_findings().map(|f| (f.path.as_str(), f.bytes)))
    }

    fn on_findings_key(&mut self, code: KeyCode, viewport: usize) -> Effect {
        let l = &mut self.findings;
        let last = l.shown.len().saturating_sub(1);
        let page = viewport.max(1);
        match code {
            KeyCode::Char('t') => {
                let at = FILTERS.iter().position(|&f| f == l.filter).unwrap_or(0);
                self.refilter(FILTERS[(at + 1) % FILTERS.len()]);
            }
            KeyCode::Char('p') => return self.start_plan(),
            KeyCode::Char(' ') => {
                if let Some(&i) = l.shown.get(l.selected) {
                    let f = &self.data.report.findings[i];
                    if f.action.kind == ActionKind::Advice {
                        return Effect::Message(
                            "advice only: this finding has no removal action to plan".into(),
                        );
                    }
                    if !self.marked.remove(&i) {
                        self.marked.insert(i);
                    }
                }
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
        Effect::None
    }

    /// `p`: asks for the plan of the marked findings, as
    /// `dwhy plan --select <ids>` would make it.
    fn start_plan(&mut self) -> Effect {
        if self.marked.is_empty() {
            return Effect::Message("nothing marked: Space marks a finding for the plan".into());
        }
        self.plan_builds += 1;
        self.plan = PlanState::Building(self.plan_builds);
        self.view = View::Plan;
        Effect::Build(PlanRequest {
            build: self.plan_builds,
            job: PlanJob {
                source: self.data.plan.clone(),
                tree: self.data.tree.clone(),
                select: self.marked_findings().map(|f| f.id.clone()).collect(),
            },
        })
    }

    fn on_plan_key(&mut self, code: KeyCode, page: usize) -> Option<String> {
        match code {
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                self.plan = PlanState::None;
                self.view = View::Findings;
                None
            }
            _ => match &mut self.plan {
                PlanState::Ready(view) => view.on_key(code, page),
                PlanState::None | PlanState::Building(_) => None,
            },
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

/// What a findings-list key asks of the app.
enum Effect {
    None,
    Message(String),
    Build(PlanRequest),
}

impl PlanView {
    fn new(plan: Plan, host: &str, uid: u32, now: i64, lossy_paths: HashSet<String>) -> PlanView {
        PlanView {
            unusable: plan::usable(&plan, host, uid, now)
                .err()
                .map(|e| e.to_string()),
            plan,
            file: None,
            lossy_paths,
            scroll: 0,
            prompt: None,
        }
    }

    fn on_key(&mut self, code: KeyCode, page: usize) -> Option<String> {
        match code {
            KeyCode::Char('w') => match &self.file {
                Some(file) => {
                    return Some(format!("this plan is already a file: {}", file.display()));
                }
                None => {
                    self.prompt = Some(Prompt {
                        path: DEFAULT_PLAN_FILE.into(),
                        confirm: false,
                    });
                }
            },
            _ => scroll_lines(&mut self.scroll, code, page),
        }
        None
    }

    /// A key while the `w` prompt is open; returns the status message.
    fn on_prompt_key(&mut self, code: KeyCode, ctrl: bool) -> Option<String> {
        let prompt = self.prompt.as_mut()?;
        if prompt.confirm {
            match code {
                KeyCode::Char('y' | 'Y') => {
                    let path = std::mem::take(&mut prompt.path);
                    self.prompt = None;
                    return Some(self.write(&path, true));
                }
                // Back to the path, to choose another.
                KeyCode::Char('n' | 'N') | KeyCode::Esc => prompt.confirm = false,
                _ => {}
            }
            return None;
        }
        match code {
            KeyCode::Esc => {
                self.prompt = None;
                return Some("no plan file written".into());
            }
            KeyCode::Enter if prompt.path.is_empty() => {
                return Some("type a file name, or Esc to cancel".into());
            }
            KeyCode::Enter => match job::target(Path::new(&prompt.path)) {
                Ok(Target::Free) => {
                    let path = std::mem::take(&mut prompt.path);
                    self.prompt = None;
                    return Some(self.write(&path, false));
                }
                Ok(Target::File) => prompt.confirm = true,
                Ok(Target::Refused(why)) => {
                    return Some(format!("not writing {}: {why}", prompt.path));
                }
                Err(e) => return Some(format!("cannot write {}: {e}", prompt.path)),
            },
            KeyCode::Backspace => {
                prompt.path.pop();
            }
            KeyCode::Char('u') if ctrl => prompt.path.clear(),
            KeyCode::Char(c) if !ctrl => prompt.path.push(c),
            _ => {}
        }
        None
    }

    fn write(&self, path: &str, overwrite: bool) -> String {
        match job::write_plan(Path::new(path), &self.plan, overwrite) {
            Ok(()) => format!(
                "wrote {path}; dwhy apply accepts it until {}",
                self.plan.expires_at
            ),
            Err(e) => format!("cannot write {path}: {e}"),
        }
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
