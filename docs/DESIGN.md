# diskwhy — scope and MVP design (draft)

> Working name. `diskwhy` (binary `dwhy`) is free on crates.io, as are `whyfull`, `diskdoc`, `tidyfs`, `bloatwatch`.

## Pitch

**"Why is my disk filling up, and what is safe to remove?"**

A Rust tool for Linux dev boxes, used over ssh. It finds what is big **and what is growing**, explains each item, checks whether it is safe to delete, and removes it the way the owning tool would. It has two interfaces over one engine:

- a **TUI** for people (ratatui; works in any ssh terminal)
- a **JSON CLI** for agents, built around *scan → plan → apply*, where an agent may apply a plan only within limits you set

The idea is to automate what was done by hand on pc-ubuntu on 2026-11-13: 36G free → 166G free, with one root cause (29G of Postgres WAL stuck behind a dead fake-S3 container) that no current cleaner would have found.

## What sets it apart from gdu, lysosome, Mole and others

1. **Growth, not just size.** Each run keeps a snapshot, so the next run can show what grew and how fast. A live `--watch` mode measures growth rate within one session, and probes look for known runaway patterns. No background job is needed.
2. **Accounting for hidden space.** It reports the gap between what `df` says is used and what the scan could see (e.g. "70G you can't read — rerun with sudo"). It lists Docker images, volumes and build cache by name, and counts each hardlinked file once, so sizes reflect what deleting actually frees.
3. **Safety checks that look at real state**, not just name patterns:
   - commits that exist on no remote (not only unpushed relative to the upstream branch), in nested repos too
   - uncommitted or untracked files
   - processes whose working directory or open files are inside the target
   - paths a running container or Compose project depends on
   - age gates
4. **Tool-native removal, and stating the cost of recovery.** It uses `cargo clean`, `docker builder prune --filter until=…`, `git worktree remove` without force, `go clean -cache`, and so on. Each finding says what it costs to get back ("reinstall 4 venvs, ~10 min").
5. **Agents can act, but only within a policy.** Plans carry fingerprints and are re-checked when applied. Each risk tier has its own limit, and every action is written to an audit log.

## Decisions taken

| Topic | Decision |
|---|---|
| Audience | Dev boxes like pc-ubuntu first; general servers and homelabs later |
| Language | Rust (2024 edition), Cargo workspace |
| Background job | None in the MVP. Snapshots are taken when you run it. An optional systemd timer can come later |
| Agent authority | May apply a plan, limited by `--max-tier` and config (default for agents: the `regenerable` tier only) |
| Independence | Its own scanner; gdu and ncdu are not used |
| Scratch dirs (`stale-tree`) | Both a built-in list and per-directory opt-in, with no config file in the MVP: `~/scratch`, `~/tmp`, `~/.t3/scratch` and `~/.t3/scratch-*`, plus any directory holding a `.dwhy-scratch` file. Stale means nothing written for 7 days. A location stale as a whole is one finding, otherwise each stale subdirectory is. `/tmp` and `/var/tmp` are left to systemd-tmpfiles, and `~/Downloads` is not scratch. The post-MVP TOML config extends the list and sets the age |
| Old tool versions (`tool-versions`) | A version is kept when it is the tool's default, pinned by a project in the scan (`rust-toolchain.toml`, `rust-toolchain`, `.python-version`, `.nvmrc`, `.node-version`) or a rustup override, used by a scanned venv, or the newest installed of its kind; the rest are `rebuildable`. uv's default (the install an unversioned `python`/`python3` shim in uv's bin dir runs) is kept. Node LTS pins (`lts/iron`, `lts/*`) are resolved by codename, and when any Node pin or nvm alias cannot be resolved nothing is reported for that tool. Covers rustup, uv, pyenv, nvm, fnm, `~/sdk` Go SDKs, VS Code Server (all but the most recently used server and its CLI), and Claude Code, Codex and the T3 runtime (all but the version in use and the newest). When the home directory is not scanned, the findings say pins there were not checked |
| Trash (`trash`) | One finding per trash directory (the home trash, and `.Trash-<uid>` or `.Trash/<uid>` at mount roots), removed as a whole so `files/` and `info/` go together; the spec has file managers recreate it. `review`, or `blocked` with a `recent-delete` guard when anything was trashed in the last 7 days, going by the `DeletionDate` in `info/*.trashinfo` |
| Licence | Undecided; repo is private and all rights reserved until the public release. Planned: core under MIT OR Apache-2.0, see docs/COMMERCIAL.md |

### Recommendation: root vs user

- **Run as your user by default.** Everything works without sudo.
- **Report the gap.** If `df` used minus scanned bytes is larger than a threshold, show an "unaccounted N GB" item with the likely places (`/var/lib/docker`, `/var/log`, other users' homes) and the command to rerun with sudo.
- **Running under sudo is supported, not required.** System detectors (journald vacuum, old snap revisions, old kernels, apt cache) are enabled only when running as root.
- **Never touch other users' files** unless running as root *and* `--all-users` is passed.
- **Docker** is used through its socket and CLI. Being in the `docker` group is already root-equivalent, so Docker findings default to the `review` tier. The exception is build cache unused for a week, which is `regenerable`: it is a cache, `docker builder prune --filter until=168h` removes only those records, and the cost is re-running build steps (issue #2).

### Recommendation: static binary

- **Ship static musl builds** (x86_64 and aarch64) as GitHub release assets. Rust makes this cheap, and ssh boxes run all sorts of glibc versions. A `.deb` and `cargo install` come later.
- **No runtime dependencies are required.** It calls optional external tools (`git`, `docker`, `cargo`, `go`, `journalctl` and the package managers whose caches `user-cache` reports; `dwhy doctor` lists them all) when they exist. A missing tool disables only its detectors, and `dwhy doctor` explains why.
- **Shell out to `git`** instead of linking libgit2/gix. This matches git's own behaviour exactly (worktrees, submodules, safe.directory) and keeps the binary small.

## Main concepts

- **Scan.** A parallel, single-filesystem (`-x`) walk. It counts each hardlink once by (dev, inode) and records allocated vs apparent bytes. Unreadable directories are recorded, not skipped silently.
- **Detector.** Recognises one kind of reclaimable thing and turns it into a **finding**, e.g. `cargo-target`, `node-modules`, `venv`, `user-cache` (go/npm/uv/pip/HF/playwright), `git-worktree`, `stale-tree` (scratch dirs by age), `tool-versions`, `trash`, `docker-image`, `docker-build-cache`, `docker-container`, `docker-volume`, `journald`.
- **Probe.** Explains *why* something is big or growing, e.g. `postgres-wal`: the volume holds 29G of WAL but only 50MB of data, the archiver has 151 failures, and the last success was 6 days ago.
- **Guard.** A check that runs before removal, ending in pass, warn or block, with evidence: `git-unpublished`, `git-dirty`, `in-use-cwd`, `in-use-open`, `container-mount`, `recent-write`, `git-ignored-only`.
- **Risk tier.**
  - `regenerable`: caches, including Docker build cache unused for a week; fine to remove automatically
  - `rebuildable`: costs time to restore, e.g. `target/`, venvs
  - `review`: models, worktrees, scratch dirs, volumes; needs a person
  - `blocked`: a guard failed; never applied
- **Plan.** The findings you select, plus actions, fingerprints and an expiry time. Applying it re-runs every guard and skips anything whose fingerprint has changed.

## CLI (MVP)

```
dwhy scan [PATH…] [--json] [--snapshot] [-x]      # sizes + findings + unaccounted space
dwhy diff [--since last|<snapshot>] [--json]      # growth since a snapshot
dwhy watch [PATH…] --for 60s [--json]             # live growth rate per directory/volume
dwhy explain <finding-id|path> [--json]           # evidence, guards, recovery cost
dwhy plan [--tier ≤rebuildable] [--select …] -o plan.json
dwhy apply plan.json [--max-tier regenerable] [--yes] [--json]
dwhy doctor                                       # which tools/detectors are available, permissions
dwhy                                              # opens the TUI
```

Exit codes: `0` ok · `1` error · `2` some items were skipped because of a guard or changed fingerprint · `3` refused by policy.

### JSON contract (sketch)

```json
{
  "schema": "diskwhy/v1",
  "host": "pc-ubuntu", "uid": 1000, "fs": [{"mount": "/", "size": 420906795008, "used": 360777252864, "scanned": 285615693824, "unaccounted": 75161559040}],
  "findings": [{
    "id": "f_7c1e", "detector": "docker-volume", "probe": "postgres-wal",
    "path": "docker://volume/bmc-prod-test_postgres_data",
    "bytes": 33041965056, "growth": {"bytes_per_day": 4939212390, "since": "2026-11-07T07:25:00Z"},
    "tier": "review",
    "reason": "pg_wal holds 29G vs 53M data; archive_command failing 151x since 2026-11-07 (target bmc-s3test exited)",
    "guards": [{"name": "container-mount", "status": "warn", "detail": "mounted by bmc-prod-test-postgres-1 (running)"}],
    "action": {"kind": "advice", "text": "restore the archive target; WAL is freed at the next checkpoint"},
    "recovery": {"cost": "n/a", "how": null}
  }]
}
```

Writing a stable `--json` contract with `schema` versioning is part of the MVP. It is the API that agents, the MCP server and the TUI all use.

## Growth without a background job

1. **Snapshots on each run.** `scan --snapshot` saves a compact record: directories of 100MB or more (counting hardlinked files once), Docker image/volume/cache sizes, and `df` per filesystem. They go to `~/.local/state/diskwhy/snapshots/`, are compressed, and old ones are pruned. `diff` compares two snapshots and ranks by growth rate.
2. **Signals that need no history.** Large files written in the last N days, which caught `statev2.sqlite` here. Probes for known patterns: database WAL vs data ratio, unbounded Docker `json-file` logs, journald, core dumps, `/tmp`.
3. **Watch.** Samples the top candidates twice over a short window (`--for 60s`) and reports bytes per minute. This catches active runaways right away.
4. *(later)* A systemd user timer that runs `scan --snapshot` daily and alerts through `notify` when growth crosses a threshold.

## Safety rules (non-negotiable)

- Scans write nothing except their own state. Git commands run with `--no-optional-locks`.
- Every removal is either a tool-native command or a path removal limited to the finding's root. Symlinks are never followed out of that root, and nothing crosses a filesystem boundary.
- `apply` re-runs all guards, compares fingerprints (inode, newest mtime, size bucket, git HEAD plus a status hash) and refuses expired plans.
- Agents are limited by `--max-tier` (config default `regenerable`). `review` items need the TUI or an explicit `--confirm <id>` from a person.
- Append-only audit log in `~/.local/state/diskwhy/audit.jsonl`.
- No Trash or quarantine by default: on the same filesystem they **don't free space**. Optionally, quarantine can apply to `review` items, with a purge time.
- Guard tests: every guard has fixture tests (temporary git repos with unpublished commits, a process with its cwd inside the target, and so on) proving that it blocks.

## Architecture

```
crates/
  dwhy-core     scan engine, snapshot/diff, detectors, probes, guards, plan/apply, JSON types
  dwhy-cli      clap front end, JSON output, exit codes (binary: dwhy)
  dwhy-tui      ratatui + crossterm: tree browser, findings pane, plan preview, apply
  dwhy-mcp      (later) rmcp server exposing scan/explain/plan/apply with the same policy
```

Crates likely needed: `clap`, `ratatui`, `crossterm`, `serde`/`serde_json`, `rayon` (or `jwalk`), `procfs`, `zstd`, `directories`, `time`, `insta` (snapshot tests).

## MVP milestones

| # | Deliverable | Done when |
|---|---|---|
| M0 | Workspace, `scan` (parallel, `-x`, hardlinks counted once, unaccounted space), JSON v1 types, `doctor` | `dwhy scan / --json` on pc-ubuntu matches `du`/`df`, and the gap is explained |
| M1 | Detectors: cargo-target, node-modules, venv, user-cache, git-worktree, stale-tree, tool-versions, trash, Docker (images, build cache, containers, volumes) | It finds the same items the 2026-11-13 manual cleanup found |
| M2 | Guards, `plan`, `apply` with tier policy, audit log | Guard fixture tests pass; an agent can clear the `regenerable` items alone and is refused `review` items |
| M3 | Snapshots, `diff`, `watch`, `postgres-wal` probe | **WAL demo:** a test Compose file (Postgres with a failing `archive_command` and `archive_timeout=10s`) is flagged by `watch`/`diff`, and `explain` names the dead archive target |
| M4 | TUI: tree + findings, mark, plan preview, apply with confirmation | Usable over ssh at 80×24; the same plan file works in TUI and CLI |
| M5 | Release: musl static builds, README with the pc-ubuntu story, `cargo install` | First public tag |

**After the MVP:** MCP server, Claude Code skill, `notify` alerts, systemd timer, root-only system detectors (snap, kernels, apt, journald vacuum), more probes (Docker logs, core dumps, other databases), TOML config for custom detectors and policy.

## Non-goals (for now)

Duplicate finding, a GUI or web UI, Windows/macOS (keep code portable where it's cheap), automatic deletion with no plan.

## Open questions

- Licence and paid tier: see docs/COMMERCIAL.md.
- Final name and binary name.
