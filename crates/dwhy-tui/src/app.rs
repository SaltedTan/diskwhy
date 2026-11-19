//! The TUI as a state machine: scan messages and key events in, state out.
//! Nothing here touches the terminal, so tests drive it directly.

use std::collections::{BTreeSet, HashSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use dwhy_core::apply::Policy;
use dwhy_core::explain::lossy_finding_paths;
use dwhy_core::plan;
use dwhy_core::report::{ActionKind, ApplyOutcome, Finding, Plan, Tier};
use dwhy_core::scan::Progress;
use dwhy_core::tree::NodeId;
use ratatui::text::Line;

use crate::job::{
    self, Applied, ApplyFailed, ApplyJob, ApplyProgress, BuiltPlan, Mark, Options, PlanJob,
    PlanMark, ScanJob, ScanOutcome, Scanned, Stage, UnplannedMark, WriteError,
};

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
    pub(crate) marked: BTreeSet<usize>,
    marked_bytes: u64,
    pub plan: PlanState,
}

/// The plan made from the marks.
#[derive(Debug, Default)]
pub enum PlanState {
    #[default]
    None,
    Building {
        progress: Arc<Progress>,
        marks: BTreeSet<usize>,
    },
    Ready(Box<PlanView>),
}

/// A plan in the preview.
#[derive(Debug)]
pub struct PlanView {
    plan: Plan,
    host: String,
    uid: u32,
    /// The file it was opened from (`dwhy tui --plan`); `None` when built here.
    pub file: Option<PathBuf>,
    pub(crate) unplanned: Vec<UnplannedMark>,
    pub(crate) lines: Option<(usize, Vec<Line<'static>>)>,
    /// First line on screen.
    pub scroll: usize,
    /// The path being edited in the `w` prompt.
    pub prompt: Option<String>,
    /// The confirm dialog `x` opened.
    pub confirm: Option<Confirm>,
}

/// The confirm dialog: every plan item, with a checkbox on each `review`
/// item (the TUI's `--confirm <id>`).
#[derive(Debug, Default)]
pub struct Confirm {
    /// The item the cursor is on, as an index into the plan's items.
    pub selected: usize,
    /// Ids of the review items ticked.
    pub confirmed: BTreeSet<String>,
    /// First line on screen.
    pub scroll: usize,
    pub(crate) action_scroll: usize,
    pub(crate) actions_visible: bool,
    pub(crate) layout: Option<crate::ui::ConfirmLayout>,
}

/// An apply started from the confirm dialog: running, then its results.
#[derive(Debug)]
pub struct ApplyView {
    /// The preview it was started from, with its dialog open: where Esc
    /// returns when nothing was removed.
    back: State,
    /// What Enter on the results rescans.
    rescan: Options,
    pub dry_run: bool,
    pub progress: Arc<ApplyProgress>,
    /// `None` while it runs.
    pub result: Option<Result<Applied, ApplyFailed>>,
    can_go_back: bool,
    pub(crate) lines: Option<(usize, Vec<Line<'static>>)>,
    /// First line of the results on screen.
    pub scroll: usize,
    /// The person quit while it ran: the item in progress finishes, no
    /// other runs, and nothing more is shown.
    pub stopping: bool,
}

impl ApplyView {
    /// Whether Esc on the results goes back to the dialog: only when
    /// every item is known to have been left untouched.
    pub fn can_go_back(&self) -> bool {
        self.can_go_back
    }
}

#[derive(Debug)]
pub enum State {
    Scanning {
        progress: Arc<Progress>,
        stage: Stage,
    },
    RootsRemoved,
    Browsing(Box<Browser>),
    /// `dwhy tui --plan FILE`: a plan file and no scan.
    Plan(Box<PlanView>),
    /// Applying a plan, or its results.
    Applying(Box<ApplyView>),
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
    /// The session's options, including the threads, detector context and audit log for apply.
    pub options: Options,
    /// Seconds since the epoch, for the plan checks `x` and `y` make.
    pub clock: fn() -> i64,
    pub(crate) apply_stop: Arc<AtomicUsize>,
    pub(crate) audit_errors: Vec<String>,
    request: Option<PlanJob>,
    apply_request: Option<ApplyJob>,
    scan_request: Option<ScanJob>,
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
            options: Options::default(),
            clock: job::now,
            apply_stop: Arc::default(),
            audit_errors: Vec::new(),
            request: None,
            apply_request: None,
            scan_request: None,
        }
    }

    /// Sets the session's options (see [`App::options`]).
    pub fn with_options(mut self, options: Options) -> App {
        self.options = options;
        self
    }

    /// `dwhy tui --dry-run`: applying only shows what would happen.
    pub fn dry_run(&self) -> bool {
        self.options.dry_run
    }

    /// `dwhy tui --plan FILE`: previews `plan`, read from `file`.
    pub fn open_plan(plan: Plan, file: PathBuf, host: &str, uid: u32) -> App {
        let mut view = PlanView::new(plan, host, uid, Vec::new());
        view.file = Some(file);
        let mut app = App::new(Vec::new(), Arc::default());
        app.state = State::Plan(Box::new(view));
        app
    }

    /// The plan build the last key asked for, for the caller to run.
    pub fn take_request(&mut self) -> Option<PlanJob> {
        self.request.take()
    }

    /// The apply the last key asked for, for the caller to run.
    pub fn take_apply(&mut self) -> Option<ApplyJob> {
        self.apply_request.take()
    }

    /// The rescan the last key asked for, for the caller to run.
    pub fn take_scan(&mut self) -> Option<ScanJob> {
        self.scan_request.take()
    }

    /// The apply finished (or failed before deciding items).
    pub fn apply_done(&mut self, mut result: Result<Applied, ApplyFailed>) {
        match &mut result {
            Ok(done) => self.audit_errors.append(&mut done.audit_errors),
            Err(failed) if failed.audit_error => self.audit_errors.push(failed.message.clone()),
            Err(_) => {}
        }
        if let State::Applying(v) = &mut self.state
            && v.result.is_none()
        {
            v.can_go_back = match &result {
                Ok(done) => {
                    v.dry_run
                        || done.report.items.iter().all(|item| {
                            matches!(item.outcome, ApplyOutcome::Refused | ApplyOutcome::Skipped)
                        })
                }
                Err(_) => true,
            };
            v.result = Some(result);
        }
    }

    /// The person quit while an apply ran.
    pub fn stopping(&mut self) {
        if let State::Applying(v) = &mut self.state {
            v.stopping = true;
        }
    }

    pub fn apply_view(&self) -> Option<&ApplyView> {
        match &self.state {
            State::Applying(v) => Some(v),
            _ => None,
        }
    }

    pub fn plan_built(&mut self, result: Result<BuiltPlan, String>, host: &str, uid: u32) {
        let State::Browsing(b) = &mut self.state else {
            return;
        };
        let PlanState::Building { marks, .. } = &b.plan else {
            return;
        };
        let current = *marks == b.marked;
        b.plan = PlanState::None;
        if b.view != View::Plan {
            return;
        }
        if !current {
            self.request = Some(b.begin_plan_build());
            return;
        }
        match result {
            Ok(BuiltPlan { plan, unplanned }) => {
                let view = PlanView::new(plan, host, uid, unplanned);
                b.plan = PlanState::Ready(Box::new(view));
            }
            Err(e) => {
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
            marked_bytes: 0,
            plan: PlanState::None,
        };
        b.refresh_rows(self.mode);
        b.refilter(None);
        self.state = State::Browsing(Box::new(b));
    }

    pub fn scan_done(&mut self, outcome: ScanOutcome) {
        if let Some(data) = outcome.scanned {
            self.finish(data);
        } else {
            self.state = State::RootsRemoved;
        }
        if !outcome.removed.is_empty() {
            self.message = Some(format!(
                "removed: {}",
                root_labels(&outcome.removed).join(", ")
            ));
        }
    }

    pub fn browser(&self) -> Option<&Browser> {
        match &self.state {
            State::Browsing(b) => Some(b),
            _ => None,
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
            self.message = view.on_prompt_key(key);
            return false;
        }
        if key.code == KeyCode::Char('q') {
            return true;
        }
        self.message = None;
        let viewport = self.viewport;
        let page = viewport.max(1);
        let dry_session = self.dry_run();
        if let Some(view) = self.plan_view_mut().filter(|v| v.confirm.is_some()) {
            match view.on_confirm_key(key, viewport, dry_session) {
                ConfirmKey::None => {}
                ConfirmKey::Message(m) => self.message = Some(m),
                ConfirmKey::Start { dry_run } => self.message = self.start_apply(dry_run),
            }
            return false;
        }
        if matches!(self.state, State::Applying(_)) {
            self.on_results_key(key.code, page);
            return false;
        }
        let now = (self.clock)();
        let mode = self.mode;
        let b = match &mut self.state {
            State::Browsing(b) => b,
            State::Plan(view) => {
                self.message = view.on_key(key, page, now);
                return false;
            }
            State::Scanning { .. } | State::RootsRemoved | State::Applying(_) => return false,
        };
        if key.code == KeyCode::Tab {
            b.view = match b.view {
                View::Tree => View::Findings,
                View::Findings | View::Detail | View::Plan => View::Tree,
            };
            b.drop_preview();
            return false;
        }
        match b.view {
            View::Tree => {}
            View::Findings => {
                match b.on_findings_key(key.code, self.viewport) {
                    Effect::None => {}
                    Effect::Message(m) => self.message = Some(m),
                    Effect::Build(r) => self.request = Some(*r),
                }
                return false;
            }
            View::Detail => {
                b.on_detail_key(key.code, page);
                return false;
            }
            View::Plan => {
                self.message = b.on_plan_key(key, page, now);
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

    /// `y` or `d` in the dialog: checks the plan again (time has passed)
    /// and hands the apply to the caller. Returns the status message.
    fn start_apply(&mut self, dry_run: bool) -> Option<String> {
        let now = (self.clock)();
        let view = self.plan_view_mut()?;
        if let Some(why) = view.unusable(now) {
            view.confirm = None;
            return Some(format!("cannot apply: {why}"));
        }
        let confirmed = &view.confirm.as_ref()?.confirmed;
        let policy = Policy {
            max_tier: Tier::Review,
            confirm: view
                .plan
                .items
                .iter()
                .map(|i| &i.finding)
                .filter(|f| f.tier == Tier::Review && confirmed.contains(&f.id))
                .map(|f| f.id.clone())
                .collect(),
        };
        let plan = view.plan.clone();
        let rescan = match &self.state {
            State::Plan(_) => self.options.for_plan(&plan),
            State::Browsing(b) => b.data.plan_options.clone(),
            State::Scanning { .. } | State::RootsRemoved | State::Applying(_) => unreachable!(),
        };
        let job = ApplyJob {
            plan,
            policy,
            dry_run,
            options: self.options.clone(),
            progress: Arc::new(ApplyProgress::with_stop(self.apply_stop.clone())),
        };
        let progress = job.progress.clone();
        let placeholder = State::Scanning {
            progress: Arc::default(),
            stage: Stage::Walking,
        };
        let back = std::mem::replace(&mut self.state, placeholder);
        self.state = State::Applying(Box::new(ApplyView {
            back,
            rescan,
            dry_run,
            progress,
            result: None,
            can_go_back: false,
            lines: None,
            scroll: 0,
            stopping: false,
        }));
        self.apply_request = Some(job);
        None
    }

    /// A key on the apply screen: nothing while it runs; on the results,
    /// Enter rescans, Esc goes back when nothing was removed, and the
    /// arrows scroll.
    fn on_results_key(&mut self, code: KeyCode, page: usize) {
        let State::Applying(v) = &mut self.state else {
            return;
        };
        if v.result.is_none() {
            return;
        }
        match code {
            KeyCode::Enter => {
                let options = v.rescan.clone();
                let progress = Arc::new(dwhy_core::scan::Progress::default());
                self.roots = root_labels(&options.paths);
                self.state = State::Scanning {
                    progress: progress.clone(),
                    stage: Stage::Walking,
                };
                self.scan_request = Some(ScanJob { options, progress });
            }
            KeyCode::Esc if v.can_go_back() => {
                let placeholder = State::Scanning {
                    progress: Arc::default(),
                    stage: Stage::Walking,
                };
                let State::Applying(v) = std::mem::replace(&mut self.state, placeholder) else {
                    unreachable!()
                };
                self.state = v.back;
            }
            KeyCode::Esc => {
                self.message = Some("the plan was applied: Enter rescans, q quits".into());
            }
            _ => scroll_lines(&mut v.scroll, code, page),
        }
    }
}

/// The scanning screen's labels for `paths` (`.` when there are none).
pub fn root_labels(paths: &[PathBuf]) -> Vec<String> {
    if paths.is_empty() {
        vec![".".into()]
    } else {
        paths
            .iter()
            .map(|r| sanitize(&r.to_string_lossy()))
            .collect()
    }
}

/// What a dialog key asks of the app.
enum ConfirmKey {
    None,
    Message(String),
    Start { dry_run: bool },
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
        self.marked_bytes
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
            KeyCode::Char(' ') if viewport > 0 => {
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
                    self.marked_bytes = plan::distinct_bytes(
                        self.marked_findings().map(|f| (f.path.as_str(), f.bytes)),
                    );
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

    /// `p`: requests a plan build for the current marks.
    fn start_plan(&mut self) -> Effect {
        if self.marked.is_empty() {
            return Effect::Message("nothing marked: Space marks a finding for the plan".into());
        }
        self.view = View::Plan;
        if matches!(self.plan, PlanState::Building { .. }) {
            return Effect::None;
        }
        Effect::Build(Box::new(self.begin_plan_build()))
    }

    fn begin_plan_build(&mut self) -> PlanJob {
        let progress = Arc::new(Progress::default());
        self.plan = PlanState::Building {
            progress: progress.clone(),
            marks: self.marked.clone(),
        };
        PlanJob {
            options: self.data.plan_options.clone(),
            progress,
            marks: self.marked_findings().map(PlanMark::from).collect(),
        }
    }

    fn drop_preview(&mut self) {
        if matches!(self.plan, PlanState::Ready(_)) {
            self.plan = PlanState::None;
        }
    }

    fn on_plan_key(&mut self, key: KeyEvent, page: usize, now: i64) -> Option<String> {
        match key.code {
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                self.drop_preview();
                self.view = View::Findings;
                None
            }
            _ => match &mut self.plan {
                PlanState::Ready(view) => view.on_key(key, page, now),
                PlanState::None | PlanState::Building { .. } => None,
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
    Build(Box<PlanJob>),
}

impl PlanView {
    fn new(plan: Plan, host: &str, uid: u32, unplanned: Vec<UnplannedMark>) -> PlanView {
        PlanView {
            plan,
            host: host.into(),
            uid,
            file: None,
            unplanned,
            lines: None,
            scroll: 0,
            prompt: None,
            confirm: None,
        }
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub(crate) fn confirmation(&mut self) -> Option<(&Plan, &mut Confirm)> {
        Some((&self.plan, self.confirm.as_mut()?))
    }

    pub fn unusable(&self, now: i64) -> Option<plan::Unusable> {
        plan::usable(&self.plan, &self.host, self.uid, now).err()
    }

    fn on_key(&mut self, key: KeyEvent, page: usize, now: i64) -> Option<String> {
        match key.code {
            KeyCode::Char('x') if unmodified_action(key) => {
                if let Some(why) = self.unusable(now) {
                    return Some(format!("cannot apply: {why}"));
                }
                if self.plan.items.is_empty() {
                    return Some("nothing to apply: the plan has no items".into());
                }
                self.confirm = Some(Confirm::default());
            }
            KeyCode::Char('w') => match &self.file {
                Some(file) => {
                    return Some(format!("this plan is already a file: {}", file.display()));
                }
                None => {
                    self.prompt = Some(DEFAULT_PLAN_FILE.into());
                }
            },
            _ => scroll_lines(&mut self.scroll, key.code, page),
        }
        None
    }

    /// A key while the confirm dialog is open.
    fn on_confirm_key(&mut self, key: KeyEvent, viewport: usize, dry_session: bool) -> ConfirmKey {
        let Some(c) = self.confirm.as_mut() else {
            return ConfirmKey::None;
        };
        let items = &self.plan.items;
        let last = items.len().saturating_sub(1);
        let selected = match key.code {
            KeyCode::Esc => {
                self.confirm = None;
                return ConfirmKey::Message("nothing applied".into());
            }
            KeyCode::Char(action @ ('y' | 'd')) if c.actions_visible && unmodified_action(key) => {
                c.actions_visible = false;
                return ConfirmKey::Start {
                    dry_run: dry_session || action == 'd',
                };
            }
            KeyCode::Char(' ') if c.actions_visible => {
                match items.get(c.selected).map(|i| &i.finding) {
                    Some(f) if f.tier == Tier::Review => {
                        if !c.confirmed.remove(&f.id) {
                            c.confirmed.insert(f.id.clone());
                        }
                        c.layout = None;
                        c.actions_visible = false;
                    }
                    Some(_) => {
                        return ConfirmKey::Message(
                            "only review items need a confirmation; this one goes ahead".into(),
                        );
                    }
                    None => {}
                }
                return ConfirmKey::None;
            }
            KeyCode::Up | KeyCode::Char('k') => c.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => (c.selected + 1).min(last),
            KeyCode::PageUp | KeyCode::PageDown if c.actions_visible => {
                scroll_lines(&mut c.action_scroll, key.code, viewport.max(1));
                return ConfirmKey::None;
            }
            KeyCode::Home | KeyCode::Char('g') => 0,
            KeyCode::End | KeyCode::Char('G') => last,
            _ => return ConfirmKey::None,
        };
        if c.selected != selected {
            c.action_scroll = 0;
            c.actions_visible = false;
            c.selected = selected;
        }
        ConfirmKey::None
    }

    /// A key while the `w` prompt is open; returns the status message.
    fn on_prompt_key(&mut self, key: KeyEvent) -> Option<String> {
        let path = self.prompt.as_mut()?;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => {
                self.prompt = None;
                return Some("no plan file written".into());
            }
            KeyCode::Enter if path.is_empty() => {
                return Some("type a file name, or Esc to cancel".into());
            }
            KeyCode::Enter => return self.write(),
            KeyCode::Backspace => {
                path.pop();
            }
            KeyCode::Char('u') if ctrl => path.clear(),
            KeyCode::Char(c) if !ctrl => path.push(c),
            _ => {}
        }
        None
    }

    fn write(&mut self) -> Option<String> {
        let name = self.prompt.as_deref()?;
        let path = Path::new(name);
        let message = match job::write_plan(path, &self.plan) {
            Ok(()) => {
                let message = format!("wrote {name}");
                self.prompt = None;
                message
            }
            Err(WriteError::Incomplete(e)) => {
                self.prompt = None;
                format!(
                    "write failed: {e}. File may be incomplete. dwhy apply refuses incomplete plans."
                )
            }
            Err(WriteError::BeforeWrite(e)) => {
                if e.kind() == ErrorKind::AlreadyExists
                    || (e.kind() == ErrorKind::IsADirectory
                        && std::fs::symlink_metadata(path).is_ok())
                {
                    format!("{name} exists; choose another name")
                } else {
                    format!("cannot write {name}: {e}")
                }
            }
        };
        Some(message)
    }
}

fn unmodified_action(key: KeyEvent) -> bool {
    !key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
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
