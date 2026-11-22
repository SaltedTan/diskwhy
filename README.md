# diskwhy

**Why is my disk filling up, and what is safe to remove?**

`diskwhy` (binary `dwhy`) is a Rust tool for Linux dev boxes and servers, used over ssh. It finds what is big **and what is growing**, explains each item, checks whether it is safe to delete against live system state, and removes it the way the owning tool would. It ships one engine with two interfaces:

- an **interactive TUI** for people (`dwhy`, `dwhy tui`; built with ratatui, usable over ssh at 80×24)
- a **JSON CLI** (`diskwhy/v1`) for scripts and agents built around *scan → plan → apply*, where an agent can apply a plan only within the tier policy you set

## Why diskwhy? (The pc-ubuntu story)

`diskwhy` started from a real cleanup on a Linux dev box (`pc-ubuntu`) on 2026-11-13 that took `/` from **36 GiB free to 166 GiB free** (+130 GiB reclaimed):

| What was eating space | Size | How it was resolved | What `dwhy` does |
|---|---:|---|---|
| PostgreSQL WAL backlog behind a stopped fake-S3 archive container (failing for 6 days) | ~29 GiB | Restarted the dead archive container so WAL archived and recycled | `watch` / `diff` flags the growing volume; `postgres-wal` probe inspects Postgres + Docker and names the exited archive target instead of suggesting volume deletion |
| Python virtualenvs (including 4 ML/TTS engines), old local builds and unused model weights | ~46 GiB | Removed rebuildable venvs and old local trees | `venv` detects `pyvenv.cfg` and gives the project's restore command (`uv sync`, etc.); `.dwhy-scratch` opts custom dirs into `stale-tree` |
| Language & tool caches (Go, npm, uv, pip), old CLI runtimes, desktop trash and ~8.6 GiB of local test clusters | ~24 GiB | `go clean`, `npm cache clean`, `uv cache clean`, uninstall old versions, removed test clusters | `user-cache`, `tool-versions` and `trash` report exact freeable bytes, age gates, and tool-native commands; `.dwhy-scratch` covers custom cache/test dirs |
| Stale scratch directories and 81 clean, fully pushed `git` worktrees | ~22 GiB | Removed stale scratch trees and `git worktree remove` | `stale-tree` and `git-worktree` check age; pre-removal git guards block uncommitted changes or commits on no remote |
| Unused Docker images, exited containers and stale build cache | ~10–14 GiB | `docker rmi`, `docker rm`, `docker builder prune` | Docker detectors read the Engine API socket directly (including containerd image stores) and attribute Docker usage on unaccounted-space hints |
| Rust `target/` directories across workspaces and worktrees | — | `cargo clean` | `cargo-target` finds `target/` next to `Cargo.toml` and uses `cargo clean --manifest-path … --target-dir …` |

A plain `du` browser (`gdu`, `ncdu`) shows what is big right now, not what is growing or *why* a database volume grew 29 GiB. A pattern-based disk cleaner guesses from directory names and can silently wipe unpushed commits, dirty worktrees, active virtualenvs, or an in-use database volume. `diskwhy` combines both halves: **growth + root-cause probes**, and **real-state safety guards + tool-native removal**.

## What sets it apart

- **Growth, not just size.** `scan --snapshot` saves a compact gzip-compressed JSON snapshot (~30 KB for a home directory) under `~/.local/state/diskwhy/snapshots/`. `diff` ranks what grew in bytes/day, `watch` measures live bytes/minute with no history, and the read-only `postgres-wal` probe diagnoses runaway WAL archiving.
- **Honest accounting.** Parallel single-filesystem walks never follow symlinks, count each hardlinked inode once (deterministically at its lexicographically smallest path), subtract bytes kept alive by outside hardlinks from a finding's reclaimable size, list unreadable directories explicitly, and report **unaccounted space** (`df` used − scanned) with likely locations and a `sudo` rerun command.
- **Safety checks on real state.** Before removing anything, `plan` and `apply` check live processes (`/proc` cwd and open files), git repositories (uncommitted/untracked files, commits on no remote, linked worktrees, submodules, bare/separate git dirs — always with `--no-optional-locks` and no repo hooks/filters), running container mounts, age gates, and path/inode identity fingerprints.
- **Tool-native removal and recovery cost.** Uses `cargo clean`, `git worktree remove` (never `--force`), `docker builder prune --filter until=168h`, `go clean -cache`, `uv cache clean`, `rustup toolchain uninstall`, etc., and states what each item costs to restore.
- **Bounded agent policy.** Every finding has a risk tier (`regenerable`, `rebuildable`, `review`, `blocked`). `dwhy apply` defaults to `--max-tier regenerable`, requires explicit per-item `--confirm <id>` for `review` items, never applies `blocked` items, re-scans and re-verifies fingerprints right before acting, and appends every executed action to `~/.local/state/diskwhy/audit.jsonl` (`$XDG_STATE_HOME` if set; `--dry-run` writes nothing).

## Installation

`dwhy` is a single static Linux binary with zero runtime dependencies. Optional tools (`git`, `docker`, `cargo`, `go`, `uv`, etc.) are detected automatically; missing tools disable only the detectors or probes that need them (`dwhy doctor` shows what is active).

### Prebuilt static binaries (Linux x86_64 and aarch64)

Download the archive for your architecture (`x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`) from GitHub Releases, verify `SHA256SUMS`, and put `dwhy` on your `PATH`:

```sh
# Example for x86_64 Linux (replace VERSION with the release tag)
VERSION=v0.1.0
curl -LO "https://github.com/SaltedTan/diskwhy/releases/download/${VERSION}/dwhy-${VERSION}-x86_64-unknown-linux-musl.tar.gz"
curl -LO "https://github.com/SaltedTan/diskwhy/releases/download/${VERSION}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf "dwhy-${VERSION}-x86_64-unknown-linux-musl.tar.gz"
install -Dm 0755 "dwhy-${VERSION}-x86_64-unknown-linux-musl/dwhy" ~/.local/bin/dwhy
```

### Cargo (`cargo install`)

Requires Rust 1.88+ (2024 edition).

From Git:

```sh
cargo install --git https://github.com/SaltedTan/diskwhy --locked dwhy-cli
```

From a local checkout:

```sh
cargo install --path crates/dwhy-cli --locked
```

*(v0.1.0 ships via GitHub Releases and `cargo install --git`; crates.io publishing is deferred.)*

### Building from source

```sh
cargo build --locked --release                                               # target/release/dwhy
cargo build --locked --release --target x86_64-unknown-linux-musl -p dwhy-cli  # static x86_64 binary
cargo build --locked --release --target aarch64-unknown-linux-musl -p dwhy-cli # static aarch64 binary (uses rust-lld)
```

For cross-building the static `aarch64` binary on an `x86_64` Linux host, install the Rust target once (`rustup target add aarch64-unknown-linux-musl`); `.cargo/config.toml` configures `rust-lld` with self-contained musl objects, so no C cross-compiler is needed.

## Quickstart

```sh
# 1. Interactive TUI on the current directory (or pass paths: `dwhy tui ~`)
dwhy

# 2. Read-only scan of / or ~ (add --snapshot to track growth over time)
dwhy scan ~ --snapshot
dwhy scan / --json

# 3. See what is growing right now or since an earlier snapshot
dwhy watch / --for 60s
dwhy diff --since 24h
dwhy explain docker://volume/my_postgres_data

# 4. Safe, repeatable cleanup (regenerable items only by default)
dwhy plan ~ -o plan.json
dwhy apply plan.json --dry-run
dwhy apply plan.json           # interactive y/N on a terminal
dwhy apply plan.json --yes     # unattended / agent run (refuses with exit 3 without a terminal or --yes)

# 5. Check permissions, optional tools, detectors and probes
dwhy doctor
```

## Usage

```
dwhy
dwhy tui [PATH…] [-x | --cross-filesystems] [--dry-run]
dwhy tui --plan FILE [--dry-run]
dwhy scan [PATH…] [--json] [-x | --cross-filesystems] [--min-size SIZE] [--depth N] [--top N]
          [--no-detectors | --detectors NAME,…] [--max-findings N] [--summary] [--tier TIER,…]
          [--snapshot]
dwhy diff [PATH…] [--since last|ID|FILE|24h|7d|TIME] [--json] [--snapshot] [--min-change SIZE]
          [--cross-filesystems] [--no-detectors | --detectors NAME,…] [--top N]
dwhy watch [PATH…] [--for 60s] [--json] [--min-change SIZE] [-x | --cross-filesystems] [--no-docker] [--top N]
dwhy explain ID|PATH|docker://… [--json] [--detectors NAME,…]
dwhy plan [PATH…] [--tier regenerable|rebuildable|review] [--select ID|PATH,…] [-o FILE] [--json]
          [-x | --cross-filesystems] [--detectors NAME,…]
dwhy apply PLAN [--max-tier regenerable|rebuildable|review] [--confirm ID,…] [--yes] [--dry-run] [--json]
dwhy doctor [--json]
```

### TUI

Both `dwhy` and `dwhy tui` open the current directory by default. Supply paths after `dwhy tui`.

- **Navigation:** `↑`/`↓` (or `k`/`j`) select, `Enter`/`→`/`l` open a directory or finding detail, `Backspace`/`←`/`h` go up, `PgUp`/`PgDn` page, `Home`/`End` (or `g`/`G`) jump to ends, `a` toggles allocated vs apparent size, `f` toggles the full filesystem list, `Tab` switches between the directory tree and the findings list, `t` filters findings by risk tier.
- **Planning & applying:** `Space` marks findings; `p` rescans and previews a plan; `w` writes a plan file compatible with `dwhy apply`; `x` opens the confirmation dialog (where each `review` item must be ticked with `Space`, `y` applies, `d` dry-runs, and `Esc` cancels). `dwhy tui --plan FILE` opens an existing plan written by `dwhy plan -o`. With `--dry-run`, `y` also previews without removing anything or writing to the audit log.
- **Quit:** `q` quits everywhere except the save-path prompt (where `q` types into the path, `Esc` cancels, and `Ctrl-C` quits). The TUI requires a terminal on both stdin and stdout; otherwise it exits `1` and points to `dwhy scan`. See [TUI details](docs/DESIGN.md#tui-details).

### Scanning, detectors and probes

- `scan` walks in parallel, never follows symlinks, stays on one filesystem unless `--cross-filesystems` is given (on btrfs, `-x` enters unmounted writable nested subvolumes while skipping snapshot and read-only subvolumes), and counts each hardlinked inode once. Sizes are allocated bytes (`st_blocks * 512`), which is what deleting frees; apparent sizes are reported too.
- Unreadable directories are listed explicitly. When a scan root is the mount point of a whole filesystem (not a subdirectory bind mount or non-top-level btrfs subvolume), the report includes `df` figures and **unaccounted** space (`df` used − scanned), with likely locations and a `sudo` rerun command when the gap is large.
- Built-in detectors:
  - `cargo-target` (`rebuildable`) — Rust `target/` directories next to `Cargo.toml`, removed with `cargo clean`.
  - `node-modules` (`rebuildable`) — outermost `node_modules` next to `package.json` with a lockfile (`npm ci`, `pnpm install`, `yarn install`, `bun install` recovery).
  - `venv` (`rebuildable` with project files, `review` without) — Python virtualenvs holding `pyvenv.cfg`.
  - `user-cache` (`regenerable`; `blocked` if written in the last 24h) — pip, uv, npm/npx, pnpm, yarn, Go, Cargo, Playwright, and Hugging Face caches.
  - `git-worktree` (`review`; locked ones `blocked`) — linked worktrees untouched for 14 days (`git worktree remove`, never `--force`) and prunable missing worktrees (`git worktree prune`).
  - `stale-tree` (`review`) — directories untouched for 7 days in `~/scratch`, `~/tmp`, `~/.t3/scratch`, `~/.t3/scratch-*`, or any directory containing a `.dwhy-scratch` file.
  - `tool-versions` (`rebuildable`) — old rustup toolchains, uv/pyenv Pythons, nvm/fnm Node versions, `~/sdk` Go SDKs, VS Code Server versions, and old Claude Code, Codex and T3 runtime versions not active, pinned, in use by a running process, or newest.
  - `trash` (`review`; `blocked` if anything was trashed in the last 7 days) — home trash and mount-root `.Trash-<uid>`/`.Trash/<uid>`.
  - `docker-image`, `docker-container`, `docker-volume` (`review`) and `docker-build-cache` (`regenerable` for cache unused ≥ 7 days) — queried via the Docker Engine API Unix socket.
- Built-in probe: `postgres-wal` — runs read-only during `scan` and `explain` (never `diff`, `watch`, `plan` or `apply`) on in-use `docker-volume` findings that back a running container's Postgres data directory, inspecting PostgreSQL WAL/archiver stats (or API/log fallback) and naming stopped archive target containers without changing the volume's tier or making it removable.
- `scan --tier TIER,…` lists only findings in those tiers. `scan --json --summary` gives agents a compact report: the largest directories (`--depth` deep, 25 at most), `--max-findings` findings, and `findings_summary` totals over every finding. A `--snapshot` still holds the whole scan. With `--json`, no command writes progress lines to stderr.
- `scan` removes nothing, and without `--snapshot` writes nothing. See the [safety rules](docs/DESIGN.md#safety-rules-non-negotiable) for the `path-not-utf8` guard recorded during detection.

### Growth (`--snapshot`, `diff`, `watch`) and `explain`

- `scan --snapshot` saves gzip-compressed JSON (`zcat FILE | jq`) in `~/.local/state/diskwhy/snapshots/` (`$XDG_STATE_HOME` if set) recording directories ≥ 100 MiB, Docker objects, `df`, and findings, and prunes old snapshots per scope (keeping all from the last 48h, then newest per UTC day up to 90 days).
- `diff` rescans and compares against a snapshot (`--since last|ID|FILE|24h|7d|RFC3339`), ranking `df`, deepest-changed directories, Docker objects, and findings in bytes/day (filtering changes under `--min-change`, default `10M`). `--snapshot` also saves the fresh scan.
- `watch` samples the roots and Docker twice, `--for` apart (default `60s`), and ranks live changes in bytes/minute (filtering under `--min-change`, default `1M`; `--no-docker` skips Docker). Writes nothing.
- `explain` inspects a finding id (`f_…` resolved from saved snapshots), filesystem path, or Docker pseudo-path (`docker://volume/NAME`), showing evidence, guards, growth when available, action, and recovery cost. See the [Diff, Watch, Explain and Probe decisions](docs/DESIGN.md#decisions-taken).

### Planning, applying and `doctor`

- `plan` selects findings by `--tier` (default `regenerable`) and/or `--select ID|PATH,…`, runs pre-removal guards (active processes, git state, container mounts) and live filesystem identity checks, records fingerprints, and writes a plan file (`-o FILE`) or JSON (`--json`). A finding blocked by a guard goes to `blocked` and is never planned; `plan` exits `2` only when a finding named by `--select` is blocked (tier-only selections that get blocked keep exit `0`, so `dwhy plan -o p && dwhy apply p` works). Removes nothing.
- `apply` rescans the plan's roots, re-runs detectors and guards, verifies every fingerprint and identity check, enforces `--max-tier` (default `regenerable`; `review` items require `--confirm ID`, `blocked` is never applied), asks `y/N` on a terminal (without `--yes` and with no terminal it refuses with exit `3`; `--dry-run` removes nothing and writes no audit entry), and writes start/end entries to `$XDG_STATE_HOME/diskwhy/audit.jsonl` (default `~/.local/state/diskwhy/audit.jsonl`).
- `doctor` reports user/root status, which optional tools are on `PATH` (or installed in common off-`PATH` locations), Docker socket access, and the availability of every detector and probe.

### Exit codes

`0` ok · `1` error (usage errors and failed removals included) · `2` items skipped by a guard or changed fingerprint · `3` refused by policy.

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md) — architecture, decisions, JSON contract (`diskwhy/v1`), safety rules, and milestones
- [docs/COMMERCIAL.md](docs/COMMERCIAL.md) — licence rationale and commercial notes
- [docs/ACCEPTANCE-M1.md](docs/ACCEPTANCE-M1.md) — 2026-11-13 `pc-ubuntu` cleanup checklist
- [docs/ACCEPTANCE-M3.md](docs/ACCEPTANCE-M3.md) — Postgres WAL demo end-to-end verification
- [docs/ACCEPTANCE-M4.md](docs/ACCEPTANCE-M4.md) — TUI acceptance and ssh verification

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
