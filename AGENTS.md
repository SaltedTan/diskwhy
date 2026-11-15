# AGENTS.md

Working rules for coding agents in this repo. Humans: start at [README.md](README.md).

## What this is

`diskwhy` (binary `dwhy`) answers "why is my disk filling up, and what is safe to remove?" on Linux dev boxes. [docs/DESIGN.md](docs/DESIGN.md) is the spec: decisions, concepts, CLI, JSON contract, safety rules, milestones. Read it before starting a milestone or changing behaviour. Don't change a recorded decision on your own; raise it with the user or in an issue. [docs/COMMERCIAL.md](docs/COMMERCIAL.md) explains why the repo is private.

- **Licence:** none yet, all rights reserved. Do not add a LICENSE file or licence headers.
- **Progress:** M0 (scanner, `diskwhy/v1` types, `doctor`) is done. Later milestones are tracked as GitHub issues.

## Layout

```
crates/dwhy-core   engine: scan (walker), mounts (mountinfo, statvfs), account (unaccounted + hints),
                   doctor, system (uid, users, deleted-open files), units, report (diskwhy/v1 serde types)
crates/dwhy-cli    clap front end, text rendering (human.rs), exit codes; binary `dwhy`
```

Don't create empty crates for later milestones (`dwhy-tui`, `dwhy-mcp`); add them when that work starts.

## Commands

cargo is in `~/.cargo/bin`, which non-interactive shells may not have on PATH. Use `~/.cargo/bin/cargo` or prepend it to PATH.

```
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release --target x86_64-unknown-linux-musl -p dwhy-cli   # static binary, as in CI
```

CI (`.github/workflows/ci.yml`) runs exactly these checks. All of them must pass before you push.

## Safety rules (non-negotiable)

- Scans are read-only. The walker opens directories with `O_NOFOLLOW` and stats entries with `fstatat(AT_SYMLINK_NOFOLLOW)`. Keep it that way: never follow symlinks, never write, never cross a filesystem boundary unless `--cross-filesystems` asks for it.
- Never delete or modify anything outside temp-dir test fixtures, and never run anything with `sudo`, even to "check" a number. When a figure needs root, report it as unmeasured.
- Removal code (M2+) must follow the DESIGN.md safety rules: tool-native commands or removal limited to the finding's root, guards re-run at apply time, and an audit log.
- Git commands that diskwhy runs must use `--no-optional-locks`.

## JSON contract (`diskwhy/v1`)

`crates/dwhy-core/src/report.rs` is the source of truth. Within v1 you may add optional fields and enum variants. Renaming or removing a field, or changing its meaning or unit, needs `diskwhy/v2`. Sizes are bytes. "Allocated" means `st_blocks * 512`. "Apparent" means `st_size` of non-directories (directories count 0, as in GNU du ≥ 9.2).

Insta snapshots in `crates/*/tests/snapshots/` pin the shape. When a snapshot changes, regenerate it with `INSTA_UPDATE=always cargo test` (`cargo-insta` is not installed). Read the `.snap` diff before committing; an unexpected diff is a contract break, not noise.

## Tests

- Use `tempfile` fixtures and assert behaviour through public APIs or the `dwhy` binary. Never assert on the text of source code.
- Tests that rely on permissions (mode 000 dirs) skip themselves when running as root. Restore permissions in a `Drop` guard so temp dirs can be cleaned up.
- Mount tests read the real mount table (mounts under `/dev`) and skip when nothing is there. Don't mount anything.
- Directory sizes must be deterministic. A hardlinked inode is attributed to its lexicographically smallest path, and tests rely on that.

## Checking against du/df

When changing the walker or accounting, compare against the real tools on this machine (as your normal user, no sudo):

```
du -sxB1 /                 # vs scan.totals.allocated of `dwhy scan / --json`
du -sxB1 --apparent-size / # vs scan.totals.apparent
df -B1 --output=used /     # vs fs[0].used; fs[0].unaccounted should equal used minus scanned
```

Expect differences of a few hundred KiB from files changing between runs. A bigger gap is a bug.

## Workflow

- Branch off `main`, one topic per branch, and open a PR against `main` in `SaltedTan/diskwhy` (private).
- Validate changes through no-mistakes (`/no-mistakes` skill, `no-mistakes axi run --intent "…"`), which reviews, tests, lints, pushes, opens the PR and watches CI. Repo settings are in `.no-mistakes.yaml`.
- No AI attribution in commits or PRs: no `Co-Authored-By` trailers, no "Generated with" lines, no session links.
- On pc-ubuntu, wrap any job expected to take over ~10 minutes in `notify run --name <name> -- <command>`.
