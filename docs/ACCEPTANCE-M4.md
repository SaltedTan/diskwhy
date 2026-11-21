# M4 acceptance: the TUI

The [M4 criterion](DESIGN.md#mvp-milestones) is that the TUI is usable over ssh at 80×24, and that the same plan file works in the TUI and the CLI. This record covers four checks on head `a7c1740` (branch `m4d-apply`), run on pc-ubuntu on 2026-11-19 with the static musl binary (4,003,136 bytes):

1. A TUI-written plan is applied by `dwhy apply`.
2. A CLI plan is opened and applied in the TUI.
3. A `--dry-run` session removes nothing.
4. The TUI is dry-run on the real machine.

A fifth check, [over ssh](#5-over-ssh), ran on head `a786d6c` (branch `m4-hangup`) on 2026-11-21. It found that the TUI never exited once its terminal hung up, and that branch fixes it.

Every apply ran on temp fixtures. On the real machine the TUI ran only with `--dry-run`.

## Terminal

Each session ran in a real terminal: a detached tmux 3.6 session sized `-x 80 -y 24`, driven with `tmux send-keys` and recorded with `tmux capture-pane`. That is a real pty, not ratatui's TestBackend. The screens below are verbatim captures.

Checks 1–4 ran in tmux directly. Check 5 ran the same kind of session over ssh.

## Fixtures

Each part used a fresh fixture from this script, which prints the fixture directory `$B`:

```sh
#!/bin/sh
set -eu
B=$(mktemp -d /tmp/dwhy-m4d.XXXXXX)
mkdir -p "$B/home" "$B/bin" "$B/state" "$B/plans" "$B/work"
for c in app:3 lib:1; do
  n=${c%:*}; m=${c#*:}
  mkdir -p "$B/work/$n/target/debug"
  printf '[package]\n' > "$B/work/$n/Cargo.toml"
  printf 'Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag created by cargo.\n' \
    > "$B/work/$n/target/CACHEDIR.TAG"
  head -c $((m * 1048576)) /dev/zero > "$B/work/$n/target/debug/out"
done
mkdir -p "$B/work/scratch/old"
: > "$B/work/scratch/.dwhy-scratch"
head -c 2097152 /dev/zero > "$B/work/scratch/old/blob"
touch -d '30 days ago' "$B/work/scratch/old/blob" "$B/work/scratch/old"
echo "$B"
```

It creates three findings:
- `work/app/target`, 3 MiB, cargo-target, rebuildable
- `work/lib/target`, 1 MiB, cargo-target, rebuildable
- `work/scratch/old`, 2 MiB and 30 days old, stale-tree, review

Every `dwhy` call ran under the environment below. The empty `PATH` means there's no `cargo`, so the cargo targets are path removals. `XDG_STATE_HOME` keeps the audit log inside the fixture. `DOCKER_HOST` names a socket that doesn't exist, so the Docker detectors and probes are unavailable.

```sh
env -i HOME=$B/home PATH=$B/bin XDG_STATE_HOME=$B/state DOCKER_HOST=unix://$B/no-docker.sock TERM=xterm-256color
```

## 1. A TUI-written plan applied by `dwhy apply`

Steps, in `$B/plans`: `dwhy tui $B/work`, then Tab, then Space on each of the three findings, then `p`, `w`, Enter, `q`. The TUI exited 0 and wrote `./dwhy-plan.json`.

The findings list with all three marked:

```text
 dwhy  findings                               all tiers · 3/3 · 3 marked 6.0M
   tier            size     growth  detector      path
 * rebuildable     3.0M          –  cargo-target  /tmp/dwhy-m4d.…work/app/target
 * review          2.0M          –  stale-tree    /tmp/dwhy-m4d.…ork/scratch/old
>* rebuildable     1.0M          –  cargo-target  /tmp/dwhy-m4d.…work/lib/target
```

Then the CLI applied that file:

```text
$ dwhy apply dwhy-plan.json --dry-run --max-tier review
  would remove     3.0M  cargo-target  /tmp/dwhy-m4d.JpNsXn/work/app/target
  refused          2.0M  stale-tree    /tmp/dwhy-m4d.JpNsXn/work/scratch/old
                                       review items need a person's --confirm f_44bace35541c
  would remove     1.0M  cargo-target  /tmp/dwhy-m4d.JpNsXn/work/lib/target
would remove 2 items (4.0M); 1 refused; nothing removed
exit=3

$ dwhy apply dwhy-plan.json --yes --max-tier review --confirm f_44bace35541c
  removed          3.0M  cargo-target  /tmp/dwhy-m4d.JpNsXn/work/app/target
  removed          2.0M  stale-tree    /tmp/dwhy-m4d.JpNsXn/work/scratch/old
  removed          1.0M  cargo-target  /tmp/dwhy-m4d.JpNsXn/work/lib/target
removed 3 items, freed about 6.0M
audit log: /tmp/dwhy-m4d.JpNsXn/state/diskwhy/audit.jsonl
exit=0
```

(Each item's detail line is left out above.) Afterwards none of the three targets were left under `work/`, and the audit log had 6 lines, a start and an end for each item.

## 2. A CLI plan opened and applied in the TUI

The CLI wrote the plan: `dwhy plan $B/work --tier review -o $B/plans/cli.json`. It reported 3 items, 6.0M, and exited 0.

Steps: `dwhy tui --plan $B/plans/cli.json`, then `x`, Down, Space (confirms the review item), `y`, then Enter (rescan), `q`.

The confirm dialog before Space. The review item is unticked, and the total leaves it out:

```text
 dwhy  apply this plan?                                         3 items · 6.0M
┌ Remove these items? ─────────────────────────────────────────────────────────┐
│ 3 items, 0 of 1 review confirmed, frees ≈ 4.0M                               │
│ Unconfirmed review items are refused, as by dwhy apply without --confirm.    │
│                                                                              │
│>     rebuildable     3.0M  /tmp/dwhy-m4d.TUUDCj/work/app/target              │
│      remove /tmp/dwhy-m4d.TUUDCj/work/app/target (cargo not found)           │
│  [ ] review          2.0M  /tmp/dwhy-m4d.TUUDCj/work/scratch/old             │
│      remove /tmp/dwhy-m4d.TUUDCj/work/scratch/old                            │
│      rebuildable     1.0M  /tmp/dwhy-m4d.TUUDCj/work/lib/target              │
│      remove /tmp/dwhy-m4d.TUUDCj/work/lib/target (cargo not found)           │
```

After Space the box reads `[x]` and the summary says `3 items, 1 of 1 review confirmed, frees ≈ 6.0M`. The results after `y`:

```text
 dwhy  apply results                                                     exit 0
removed 3 items, freed about 6.0M
  dwhy apply would exit 0 (ok)
  audit log: /tmp/dwhy-m4d.TUUDCj/state/diskwhy/audit.jsonl

removed          3.0M  /tmp/dwhy-m4d.TUUDCj/work/app/target
  cargo-target · removed 2 files and 2 directories, 3.0M

removed          2.0M  /tmp/dwhy-m4d.TUUDCj/work/scratch/old
  stale-tree · removed 1 files and 1 directories, 2.0M

removed          1.0M  /tmp/dwhy-m4d.TUUDCj/work/lib/target
  cargo-target · removed 2 files and 2 directories, 1.0M
```

Pressing Enter rescanned the plan's root: the tree showed `8.0K allocated here · 1/3 · 0 findings`. `q` exited 0. Afterwards none of the targets were left, and the audit log had 6 lines.

## 3. A `--dry-run` session

Steps: `dwhy tui --dry-run $B/work`, then Tab, Space on the first finding, `p`, `x`, `y`, `q`. In this mode the dialog is titled "Dry run: nothing is removed", `DRY RUN` stays in the header, and `y` is labelled `y dry run`. The results said `would remove 1 item (3.0M); nothing removed` and `dry run: no audit line written`. Afterwards all three fixture directories were still there, and no audit log existed.

## 4. A dry run on the real machine

Command: `dwhy tui --dry-run <this worktree>` with `HOME` set to the real home. Two settings kept it read-only beyond the dry run itself:
- `PATH` held only symlinks to `git` and `cargo`, so no `docker` CLI was available.
- `DOCKER_HOST` named a socket that doesn't exist, so neither the Docker detectors nor the `postgres-wal` probe could reach the machine's containers.

Steps: Tab, Space on the one finding, `p`, `x`, `y`, `q`.

```text
 DRY RUN  dwhy  dry run results                                          exit 0
would remove 1 item (9.1G); nothing removed
  dwhy apply would exit 0 (ok)
  dry run: no audit line written

would remove     9.1G
  /home/sean-tan/.t3/worktrees/diskwhy/m3-snapshots-6a260faf915aa4a9/target
  cargo-target · rebuildable, would run:
  preview — do not copy
│    cargo clean --manifest-path
│      /home/sean-tan/.t3/worktrees/diskwhy/m3-snapshots-6a260faf915aa4a9/Cargo.
│      toml --target-dir
│      /home/sean-tan/.t3/worktrees/diskwhy/m3-snapshots-6a260faf915aa4a9/target
```

The command wraps across lines at 80 columns, so it carries the "preview — do not copy" label (M4b's copy rule). `du -sB1 target` read 9,735,245,824 bytes both before and after. `~/.local/state/diskwhy/audit.jsonl` still doesn't exist.

## 5. Over ssh

The machine's own sshd has no key for the maintainer's account, so a throwaway sshd ran as that user for the check. It listened on 127.0.0.1:2222 only, accepted only a temporary key, and was stopped afterwards:

```text
Port 2222
ListenAddress 127.0.0.1
HostKey <tmp>/host_key
AuthorizedKeysFile <tmp>/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
AllowUsers <maintainer>
AcceptEnv TERM
StrictModes no
```

(`StrictModes no` because the key files live under `/tmp`.) OpenSSH 10.2p1, tmux 3.6. Each session was `ssh -t` into an interactive `bash` in a detached tmux pane sized 80×24, so sshd allocated the pty. Inside it, `TERM=tmux-256color` and `stty size` read `24 80`. A script sent the keys and checked the `tmux capture-pane` text, exit codes, `du` and the audit logs. The real-machine session used the settings from check 4 (`--dry-run`, a missing Docker socket, `PATH` with only `git` and `cargo`). Applies ran on fixtures from the script above.

All 33 checks passed on `a786d6c` (static musl binary, 4,003,136 bytes):

| Group | What was checked |
|---|---|
| Real-machine dry run (17) | The tree, `a` (apparent), `f` (filesystems), Tab (findings), Enter (detail), Space (mark), `p` (plan preview) and `x` (the dialog, with "preview — do not copy"). Resizing to 80×8 over ssh shows "enlarge the terminal to confirm" and `y` does nothing; back at 80×24 the dialog returns. `y` gives "would remove 1 item … no audit line written". Enter rescans. `q` leaves the alternate screen, shows the cursor, exits 0 and restores canonical mode. `target` read 10,299,240,448 bytes before and after, and `~/.local/state/diskwhy/audit.jsonl` doesn't exist. |
| Fixture apply (5) | Mark all three findings, `p`, `x`, tick the review item, `y`: "removed 3 items, freed about 6.0M". The rescan shows no findings, the exit code is 0, both `Cargo.toml` files remain, and the audit log has 6 lines. |
| Ctrl-C (1) | Ctrl-C on the tree quits like `q`, with the terminal restored. |
| Hangup, idle (4) | The TUI exits within 3 s when the ssh client is killed (`kill -9`), when the tmux window running ssh is closed, and when a local tmux window running it without ssh is closed. Exit code 129. |
| Hangup mid-apply (5) | The fixture's `PATH` gets a fake `cargo` whose `clean` sleeps 4 s, then removes the target. The ssh client is killed while the first item's `cargo clean` runs. That command finishes and no other item runs. The audit log has the item's start and end and an end for each skipped item (4 lines). The TUI exits 129. |

The resize check, over ssh:

```text
 DRY RUN  dwhy  dry run this plan?                               1 item · 9.6G
 enlarge the terminal to confirm





 Esc back · q quit
```

### The hangup bug

The same script against the merged M4d binary (head `b5150c0`, before the fix) failed all six exit checks under the two hangup rows. The TUI stayed alive in every hangup case, reparented to init with its pty deleted. It ran at 100% of one core and ignored SIGTERM. strace showed SIGHUP arriving, after which `read(0)` returned 0 in an endless loop. crossterm 0.29's default (mio) event source only stops reading on `WouldBlock`, so `event::poll` never returned and the TUI never got back to the signal check. The bug dated back to M4a. Removal stayed safe: the apply worker reads the same stop flag, so the item in progress finished, the rest were skipped and the audit was complete (the three mid-apply file checks passed). Only the main thread was stuck.

The fix switches crossterm to its `use-dev-tty` event source, which stops reading on EOF. It also adds a quiet exit. Once the terminal is gone, ratatui's `Terminal` drop tried to show the cursor and `eprintln!`ed the failure, which panics with stderr closed (exit 101). The TUI now shows the cursor itself and forgets the `Terminal` if that fails. The TUI's audit-error print and the CLI's final error print use `writeln!` for the same reason.

The script reads screen text, so it can't judge how a particular terminal app draws the bars, box lines or colours.

## What these checks never did

- No apply ran outside `/tmp/dwhy-m4d.*` fixtures. The real-machine sessions were `--dry-run`, in which `y` is also a dry run.
- No Docker detector or probe reached the machine's daemon. `DOCKER_HOST` named a missing socket and no `docker` CLI was on `PATH`.
- Nothing ran with sudo. The throwaway sshd ran as the maintainer's own user and accepted connections only from 127.0.0.1.
