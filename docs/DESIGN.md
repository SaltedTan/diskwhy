# diskwhy — scope and MVP design (draft)

> Working name. `diskwhy` (binary `dwhy`) is free on crates.io, as are `whyfull`, `diskdoc`, `tidyfs`, `bloatwatch`.

## Pitch

**"Why is my disk filling up, and what is safe to remove?"**

A Rust tool for Linux dev boxes, used over ssh. It finds what is big **and what is growing**, explains each item, checks whether it is safe to delete, and removes it the way the owning tool would. It has two interfaces over one engine:

- a **TUI** for people (ratatui; works in any ssh terminal)
- a **JSON CLI** for agents, built around *scan → plan → apply*, where an agent may apply a plan only within limits you set

The idea is to automate what was done by hand on pc-ubuntu on 2026-11-13: 36G free → 166G free, with one root cause (29G of Postgres WAL stuck behind a dead fake-S3 container) that no current cleaner would have found.

## What sets it apart from gdu, lysosome, Mole and others

1. **Growth, not just size.** A scan can keep a snapshot (`--snapshot`), so a later run can show what grew and how fast. The `watch` command measures growth rate within one session, and probes look for known runaway patterns. No background job is needed.
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
| Old tool versions (`tool-versions`) | A version is kept when it is the tool's default, pinned by a project in the scan (`rust-toolchain.toml`, `rust-toolchain`, `.python-version`, `.nvmrc`, `.node-version`) or a rustup override, used by a scanned venv, or the newest installed of its kind; the rest are `rebuildable`. uv's default (the install an unversioned `python`/`python3` shim in uv's bin dir runs) is kept. Node LTS pins (`lts/iron`, `lts/*`) are resolved by codename, and when any Node pin or nvm alias cannot be resolved nothing is reported for that tool. Covers rustup, uv, pyenv, nvm, fnm, `~/sdk` Go SDKs, VS Code Server (all but the most recently used server and its CLI), and Claude Code, Codex and the T3 runtime (all but the version in use, any version a running process executes from per `/proc/<pid>/exe`, and the newest). When the home directory is not scanned, the findings say pins there were not checked |
| Trash (`trash`) | One finding per trash directory (the home trash, and `.Trash-<uid>` or `.Trash/<uid>` at mount roots), removed as a whole so `files/` and `info/` go together; the spec has file managers recreate it. `review`, or `blocked` with a `recent-delete` guard when anything was trashed in the last 7 days, going by the `DeletionDate` in `info/*.trashinfo` |
| Guards | Run at `plan` and `apply`, not in `scan` (about 0.4 s), because the guards take about 1.3 s for a home directory with ~200 git worktrees inside findings. A guard that cannot check (git missing or failing, Docker unreachable) blocks. Git guards skip repositories inside a cache (`CACHEDIR.TAG`) and do not apply to `user-cache` and `tool-versions` findings. Removing a linked worktree or submodule whose git directory is outside the finding keeps its branch's commits in the repository, so unpushed commits there only warn; commits on no branch block. When the git directory is inside the finding (a `.git` directory, a submodule of a superproject in it, a `--separate-git-dir` clone next to it), every commit on no remote blocks. Git directories without a `.git` entry (bare repositories, `--separate-git-dir` targets: a `HEAD` file plus `objects/` and `refs/`) are guarded too: commits on no remote block, and so do work trees outside the finding that use them. A bare or mirror clone has no remote-tracking refs, so it always blocks. One whose `HEAD` the enclosing work tree tracks (a test fixture in a source tree) is part of that repository's history and is skipped. Git runs none of the repository's own programs: `core.fsmonitor` and every configured filter driver are switched off, and `git status` does not look inside submodules (each is checked as a repository of its own), though a submodule checked out at a different commit than recorded still makes the superproject dirty |
| Plans | `dwhy plan` selects by tier ceiling (`--tier`, default `regenerable`, the same as `apply`'s default `--max-tier`) and by finding id or path (`--select`, which lifts the default ceiling; with `--tier` too, a finding must match both). A `--select` entry that names no finding, or only an advice-only one, is an error. Guards run on the selection only. A finding a guard blocks, or a detector-blocked one that `--select` names, goes to the plan's `blocked` list, never its items; advice-only findings are never selected. `plan` exits 2 (the plan is still written) when a finding `--select` named ends up in `blocked`; a finding only the tier ceiling picked that a guard blocks is listed but keeps exit 0, so `dwhy plan -o p && dwhy apply p` works. Each item carries a fingerprint: the root's device and inode, the newest mtime under it, its size in buckets of a quarter of a doubling, HEAD plus a hash of `git status` (branch headers left out) when the root is a git work tree, and for Docker the image or container id, or a volume's name and creation time (build cache has none, so only its size counts). A plan expires an hour after it is made (an edited `expires_at` cannot extend that) and is refused on another host or uid. `apply` does not trust a plan's actions or tiers: it rescans the plan's roots, re-detects, re-runs the guards and acts on the fresh finding with each item's id, skipping it when the fresh tier, action or fingerprint differs. An edited plan can go stale but cannot widen what `apply` may do (decided 2026-11-16) |
| Apply | `--max-tier` defaults to `regenerable` for everyone; `--max-tier rebuildable` lets rebuildable items through. A `review` item needs `--confirm <id>` for that item, which is enough on its own (it never lifts a rebuildable item above the ceiling); `blocked` is never applied. Without `--yes` on a terminal, apply lists what it will remove and asks y/N, then rescans and re-checks before removing; only items shown and still ready run. Without `--yes` and with no terminal it refuses (exit 3). `--dry-run` shows everything, removes nothing and writes no audit line. Ready items run deepest path first (pseudo-paths last). A path removal walks from `/` with `O_NOFOLLOW`, refuses a symlink root, a root that is not the plan's inode, and a root with a mount point at or below it, and stops at an entry on another device; a read-only directory of the user's own inside the root gets `u+rwx` so it can be emptied. Each item gets one outcome: removed, failed, skipped (gone, blocked, changed), refused (tier or confirmation) or would_remove (dry run). The exit code is the worst: 1 failed, then 3 refused, then 2 skipped, else 0. The audit log (`$XDG_STATE_HOME/diskwhy/audit.jsonl`, default `~/.local/state/diskwhy/audit.jsonl`, mode 0600) gets a `start` line before each removal and an `end` line with its outcome, plus an `end` line for each skipped or refused item; a removal whose `start` line cannot be written does not run (decided 2026-11-16) |
| Snapshots | Only `scan --snapshot` saves one; `scan` alone still writes nothing. A snapshot is gzip-compressed `diskwhy/v1` JSON (`flate2` with the pure-Rust `miniz_oxide` backend, so the static musl build needs no C compiler; zstd was the first idea, and gzip compresses these files about as well) in `$XDG_STATE_HOME/diskwhy/snapshots/` (default `~/.local/state/diskwhy/snapshots/`), named `<YYYYMMDDTHHMMSSZ>-<scope>[-<n>].json.gz` (`-<n>` only when that second's name is taken), where the scope hashes the host, uid, scan roots (in any order) and `-x`. It records directories of 100 MiB or more (allocated, each hardlinked file counted once), Docker images, containers and volumes by name with their sizes plus Docker's totals, `df` per filesystem, the detectors that ran, the mount points the walk did not enter, and each finding's id, detector, path, bytes and tier (so growth can be put on findings and `explain` can turn an id into a path). A home directory on pc-ubuntu gives ~1,000 directories and ~140 findings, ~32 KB. Saving prunes, per scope: everything from the last 48 hours is kept, then the newest per UTC day up to 90 days; older ones are deleted. A new snapshot never replaces a file, and pruning removes only regular files with a snapshot name. When saving fails, the scan report is still printed and `scan` exits 1; when only pruning fails after the snapshot is saved, `scan` warns and exits 0 (decided 2026-11-16) |
| Diff | `diff` rescans now and compares with a saved snapshot (`--snapshot` also saves the fresh scan). Without `PATH` it takes the newest snapshot of this host and uid matching `--since`, whatever its roots, and rescans those roots with that snapshot's `-x`; with `PATH`, only snapshots of exactly those roots and `-x` count. `--since` takes `last` (the default), a snapshot id or file (whatever its roots; another host or uid is an error), a duration (the newest at least that old) or an RFC 3339 time (the newest taken by then). Only paths both scans walked are compared: inside the roots of both, and not at or below a mount point either skipped (each snapshot records the mount points its walk did not enter; one saved without that list counts as having skipped none). When the two differ in `-x`, a directory above a mount point one side skipped and the other entered is left out too, since its totals cover different ground; with the same `-x`, neither side's totals include a skipped mount, so a mount that appeared or went away between them leaves its ancestors compared. `notes` names a mount point only when a directory or finding either side recorded was left out because of it. It lists `df` used per filesystem, directories, Docker objects (images and containers by id, volumes by name, build cache; an object whose size the daemon did not compute on either side is left out) and findings by id (one present on one side only is listed only when its detector ran on both), each ranked by bytes per day; changes under `--min-change` (default 10M) are left out. A directory's change goes to the deepest directory that holds most of it: a directory is dropped when the nearest listed directory below it changed by more than half as much in the same direction, so entries can still nest when growth is spread out; `watch` uses the same rule. A directory new above the snapshot's 100 MiB threshold counts the threshold as its earlier size, so its growth is a lower bound (`at_least`). `scan` sets `Finding.growth` from the newest snapshot of the same roots at least an hour old (a rate from a shorter window, scaled to a day, is mostly noise), matched by finding id (decided 2026-11-16) |
| Watch | `watch` walks the roots in full at both ends of the window, every directory recorded, and reads Docker image, container, volume and build cache sizes from `GET /system/df` at both ends (volumes under /var/lib/docker are root-only on disk); `--no-docker` skips Docker. The second walk starts `--for` (default 60s, at least 1s) after the first one started, or right away if the first took longer, and rates are bytes per minute over the measured time between the two starts. It also lists `df` used per filesystem. Changes under `--min-change` (default 1M: about 1.4 GiB a day over a minute) are left out. Directories use `diff`'s deepest-directory rule and are compared only where both samples walked, using a fresh mount table for each sample. Paths unreadable or affected by a scan error in either sample, and directories below them, are excluded. Ancestors of paths that fail in only one sample are excluded within both samples' roots too; paths failing in both samples do not by themselves exclude ancestors. A mount skipped in one sample only also leaves out directories above it within both samples' roots, unlike `diff` (decided 2026-11-18). If either sample deduplicated hardlinks and either the failed-path set or skipped-mount set changes, all directory rates are suppressed because attribution can move between siblings; filesystem and Docker comparisons remain available. Notes explain coverage exclusions, naming failed paths and changed mounts when they kept recorded directories out. If scan errors exceed the recorded error paths, `watch` fails instead of comparing unknown coverage. Docker is compared only when figures are available at both ends; otherwise a note explains why. `watch --json` uses the additive `diskwhy/v1` `WatchReport` contract defined in [report.rs](../crates/dwhy-core/src/report.rs). It writes nothing; Ctrl-C ends the process (decided 2026-11-16 and 2026-11-18) |
| Probes (`postgres-wal`) | A probe runs after the detectors and adds evidence to a finding; it never changes the tier and never makes a finding removable. Probes are in `dwhy-core`'s `probes` module so `scan` and (later) `explain` share them; `scan` runs them, `diff`, `plan` and `apply` do not. `postgres-wal` looks at a `docker-volume` finding only when the volume is the deepest mount containing a running container's Postgres data directory (`PGDATA` from the container's environment, `/var/lib/postgresql/data` by default), including tmpfs when comparing mounts. Access is read-only: Engine API GETs (`/containers/json?all=1`, `/containers/{id}/json`, and a log tail of 200 lines with Docker's timestamps, demultiplexed for a container without a TTY) and `docker exec <id> psql -X -w -A -t` as `POSTGRES_USER` (default `postgres`) over the local socket, with `PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10s -c search_path=pg_catalog`. On timeout (10 s by default), diskwhy kills the Docker CLI. Inside the container, psql has its own limits: `PGCONNECT_TIMEOUT` (5 s) for connecting and `statement_timeout` (10 s) per statement. The query only reads and runs inside `BEGIN READ ONLY`. It reads `pg_stat_archiver` (failures, last archived and failed times, last failed WAL), the size of `pg_ls_waldir()`, the sum of `pg_database_size`, and `archive_mode`, `archive_command` and `archive_timeout`. The probe requires the `docker` CLI and Docker socket because it consumes `docker-volume` findings. When exec or psql fails, the evidence comes from the GETs alone (`source: api-only`, with a note saying why): settings from the container's command line (`-c name=value`), failures from the log tail. A non-TTY log with an invalid, truncated or error frame leaves the failure count unknown. A readable tail reports the observed count and latest failure time when available, with current archiver health unknown. It gives repair advice when failures were observed, a target is exited or missing, and archiving is not known to be off. Host extraction uses network URL words after the program (HTTP, HTTPS, SSH, SFTP, FTP, FTPS, rsync, TCP, Postgres and PostgreSQL) and `--endpoint-url`, `--endpoint` and `--host` values containing such a URL or `host:port`. Assignment words are skipped. Container names, Compose service names, network aliases and DNS names are compared without regard to case, preferring an identifier on a shared network, then running containers, then the same Compose project. An unmatched dotted name, IP or localhost is `unresolved`, never `missing` or named as dead. An unmatched bare name is `missing` only when all candidate inspections succeeded; an incomplete lookup is `unresolved`. The report includes only the program word (`archive_program`) and the target hosts from the command. Command arguments can carry credentials and are omitted. The evidence is typed and additive in `diskwhy/v1`: `Finding.evidence.postgres_wal`. The diagnosis leads the reason ("pg_wal holds 29G vs 53M data; archiving is failing, with 151 failures in total (last failure 2026-11-13T02:10:00Z, last success 2026-11-07T07:25:00Z) (target s3test exited)"). With archiving enabled, when SQL evidence shows a failure at or after the last successful archive, or a failure with no success recorded, the action becomes advice to restore the archive target or fix `archive_command`. When the archiver is healthy but WAL is at least 1 GiB and more than 4× the data with archiving on, the advice is to check replication slots and `max_wal_size`. WAL is freed at the next checkpoint once nothing needs it; the tier stays `review` and deleting the volume is never the fix for WAL. Otherwise a healthy archiver leaves the detector's action as it was (decided 2026-11-16 and 2026-11-18) |
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
- **Guard.** A check that runs before removal, ending in pass, warn or block, with evidence: `git-unpublished`, `git-dirty`, `git-linked-worktrees`, `in-use-cwd`, `in-use-open`, `container-mount`, `recent-write`, `git-ignored-only` (not built yet).
- **Risk tier.**
  - `regenerable`: caches, including Docker build cache unused for a week; fine to remove automatically
  - `rebuildable`: costs time to restore, e.g. `target/`, venvs
  - `review`: models, worktrees, scratch dirs, volumes; needs a person
  - `blocked`: a guard failed; never applied
- **Plan.** The findings you select, plus actions, fingerprints and an expiry time. Applying it re-runs every guard and skips anything whose fingerprint has changed.

## CLI (MVP)

```
dwhy scan [PATH…] [--json] [--snapshot] [-x]      # sizes + findings + unaccounted space
dwhy diff [PATH…] [--since last|<snapshot>|7d|<time>] [--json]  # growth since a snapshot
dwhy watch [PATH…] [--for 60s] [--json]           # live growth rate per directory/volume
dwhy explain <finding-id|path> [--json]           # evidence, guards, recovery cost
dwhy plan [PATH…] [--tier regenerable|rebuildable|review] [--select ID|PATH,…] [-o plan.json] [--json]
dwhy apply plan.json [--max-tier regenerable] [--confirm ID,…] [--yes] [--dry-run] [--json]
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
    "reason": "pg_wal holds 29G vs 53M data; archiving is failing, with 151 failures in total (last failure 2026-11-13T02:10:00Z, last success 2026-11-07T07:25:00Z) (target bmc-s3test exited)",
    "guards": [{"name": "container-mount", "status": "warn", "detail": "mounted by bmc-prod-test-postgres-1 (running)"}],
    "action": {"kind": "advice", "text": "restore the archive target; WAL is freed at the next checkpoint"},
    "recovery": {"cost": "n/a", "how": null}
  }]
}
```

Writing a stable `--json` contract with `schema` versioning is part of the MVP. It is the API that agents, the MCP server and the TUI all use.

## Growth without a background job

1. **Snapshots.** `scan --snapshot` saves a compact record: directories of 100MB or more (counting hardlinked files once), Docker image/volume/cache sizes, `df` per filesystem, and the findings. They go to `~/.local/state/diskwhy/snapshots/`, gzip-compressed, and old ones are pruned (see Snapshots under Decisions taken). `diff` rescans and compares with a snapshot, ranking by growth rate (see Diff under Decisions taken), and `scan` puts a growth rate on findings.
2. **Signals that need no history.** Large files written in the last N days, which caught `statev2.sqlite` here. Probes for known patterns: database WAL vs data ratio, unbounded Docker `json-file` logs, journald, core dumps, `/tmp`.
3. **Watch.** Walks the roots and reads Docker's figures twice over a short window (`--for 60s`) and reports bytes per minute (see Watch under Decisions taken). This catches active runaways right away.
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
  dwhy-core     scan engine, snapshot/diff/watch (growth), detectors, probes, guards, plan/apply, JSON types
  dwhy-cli      clap front end, JSON output, exit codes (binary: dwhy)
  dwhy-tui      ratatui + crossterm: tree browser, findings pane, plan preview, apply
  dwhy-mcp      (later) rmcp server exposing scan/explain/plan/apply with the same policy
```

Crates likely needed: `clap`, `ratatui`, `crossterm`, `serde`/`serde_json`, `rayon` (or `jwalk`), `procfs`, `flate2` (gzip, pure Rust), `directories`, `time`, `insta` (snapshot tests).

## MVP milestones

| # | Deliverable | Done when |
|---|---|---|
| M0 | Workspace, `scan` (parallel, `-x`, hardlinks counted once, unaccounted space), JSON v1 types, `doctor` | `dwhy scan / --json` on pc-ubuntu matches `du`/`df`, and the gap is explained |
| M1 | Detectors: cargo-target, node-modules, venv, user-cache, git-worktree, stale-tree, tool-versions, trash, Docker (images, build cache, containers, volumes) | It finds the same items the 2026-11-13 manual cleanup found (checklist and what is out of scope: [ACCEPTANCE-M1.md](ACCEPTANCE-M1.md)) |
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
