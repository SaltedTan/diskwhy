# M1 acceptance: the 2026-11-13 cleanup

DESIGN.md says M1 is done when dwhy finds the same items the manual cleanup on pc-ubuntu found on 2026-11-13. That cleanup took free space on `/` from 36G to 166G. The list below was rebuilt from the transcript of that session (the commands it ran and its own summary).

Each item that M1 covers is reproduced in a temp home by `crates/dwhy-core/tests/acceptance_m1.rs`, which runs every M1 detector together and checks that each item is reported with the expected tier. Items outside M1 are listed at the end.

## Items

| # | What the cleanup removed | How | Size then | Detector | Tier dwhy gives |
|---|---|---|---|---|---|
| 1 | Postgres WAL backlog of `bmc-prod-test` (archiving to a stopped fake-S3 container had failed for 6 days) | restarted `bmc-s3test`, so the backlog archived | ~29G | not M1: the `postgres-wal` probe (M3) | — |
| 2 | Go build cache, npm cache, uv cache, pip cache | `go clean -cache`, `npm cache clean --force`, `uv cache clean`, `rm -rf ~/.cache/pip` | ~24G with rows 3, 5, 6 | `user-cache` | `regenerable`; `blocked` (recent-write) when written in the last 24 hours |
| 3 | `~/.cache/fr-pg-tools` test clusters, logs and bench dirs | `rm` | 8.6G | not M1 (see below) | — |
| 4 | Rust `target/` in `~/projects/lspcheck` and two lspcheck worktrees | `cargo clean` | | `cargo-target` | `rebuildable` |
| 5 | Old Claude Code (`~/.local/share/claude/versions/2.1.318`, `2.1.319`), Codex (`~/.codex/packages/standalone/releases/0.167.2-…`) and T3 runtime (`~/.t3/runtime/versions/0.1.3-nightly.*`) versions | `rm` | | `tool-versions` | `rebuildable` |
| 6 | Desktop trash | `rm files/* info/*` | | `trash` | `review`; `blocked` (recent-delete) when something was trashed in the last 7 days |
| 7 | Old `bmc-*` and `bmc-inbox-ci:<sha>` images, `rclone`, dangling images, 2 exited containers, build cache older than 72h | `docker rmi`, `docker rm`, `docker image prune`, `docker builder prune --filter until=72h` | ~10–14G | `docker-image`, `docker-container`, `docker-build-cache` | images and containers `review`; build cache unused for a week `regenerable`, younger `review` |
| 8 | 131 `~/.t3/scratch-virgil` dirs untouched since Nov 5 | `rm` | ~22G with row 9 | `stale-tree` | `review` (nothing written for 7 days) |
| 9 | 81 T3 worktrees that were clean, fully pushed and had no commit since Nov 6 | `git worktree remove` | | `git-worktree` | `review` (nothing written for 14 days; whether a worktree is clean and pushed is for the M2 guards) |
| 10 | `.venv` of 4 TTS engines and of `ep03-gpu-roofline` | `rm` | 46G with rows 11, 12 | `venv` | `rebuildable` with a project file, `review` without |
| 11 | Old ninfer build and download in `~/opt/ninfer-all` | `rm` | | not M1 (see below) | — |
| 12 | Models `~/models/ornith-1.5-35b-a3b`, `~/models/capy-qwen3.8-27b-gsq3` | `rm` | | not M1 (see below) | — |

Differences in thresholds: the cleanup removed worktrees with no commit for a week, where `git-worktree` waits 14 days without writes; and it pruned build cache older than 72 hours, where `docker-build-cache` offers it as `regenerable` after a week (younger cache is `review`).

## Not covered by M1

- **Postgres WAL (row 1).** The space was not garbage but a symptom: a stuck archiver. Explaining that is the `postgres-wal` probe planned for M3, not a detector.
- **Your own directories (rows 3, 11, 12).** `~/.cache/fr-pg-tools` test clusters, `~/opt/ninfer-all` builds and `~/models` have no tool behind them that says what is safe to remove. A `.dwhy-scratch` file in such a directory makes `stale-tree` report its old contents. A detector for model folders can come after M1.

## Manual check on pc-ubuntu

```
dwhy scan ~ --json > scan.json      # as the normal user, no sudo
```

Most of what the cleanup removed is gone, so the check is that the same kinds of item are found again where they have come back. On 2026-11-16 a full `~` scan (1.2 s with Docker) reported 139 findings, 72 GiB:

| Row | Detector | Found on 2026-11-16 |
|---|---|---|
| 2 | `user-cache` | `~/.cache/go-build`, `~/.cache/uv`, `~/.npm/_cacache` (blocked: written in the last 24 hours), plus Hugging Face, Playwright, Go modules, Cargo registry, npx |
| 4 | `cargo-target` | 10 `target/` dirs, 17.6 GiB, 9 of them in lspcheck worktrees |
| 5 | `tool-versions` | Claude Code 2.1.322 and 2.1.323 (the launcher runs 2.1.325); also 4 old VS Code servers and uv Python 3.9.25 |
| 6 | `trash` | nothing: the trash is empty |
| 7 | `docker-image`, `docker-build-cache` | 20 images not used by a container (10.1 GiB, including `bmc-inbox-ci:7877d474e97f`), build cache 3.8 GiB `regenerable`; no exited containers today |
| 8 | `stale-tree` | 19 findings, 18.0 GiB, 13 of them in `~/.t3/scratch-virgil` |
| 9 | `git-worktree` | 14 stale worktrees, 2.4 GiB, 6 under `~/.t3/worktrees` |
| 10 | `venv` | 29 venvs, 6.5 GiB; the TTS engine venvs have not come back |
