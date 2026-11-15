# diskwhy

**Why is my disk filling up, and what is safe to remove?**

`diskwhy` (binary `dwhy`) is a Rust tool for Linux dev boxes and servers, used over ssh. It finds what is big *and what is growing*, explains each item, checks whether it is safe to delete, and removes it the way the owning tool would. It has a TUI for people and a JSON CLI (scan → plan → apply) that agents can drive within limits you set.

Status: pre-MVP, private. See [docs/DESIGN.md](docs/DESIGN.md) for scope and milestones. M0 (scanner, `diskwhy/v1` JSON types, `doctor`) is in place, and M1 (detectors) is under way.

## Usage

```
dwhy scan [PATH…] [--json] [-x | --cross-filesystems] [--min-size SIZE] [--depth N] [--top N]
          [--no-detectors] [--max-findings N]
dwhy doctor [--json]
```

- `scan` walks in parallel, never follows symlinks, stays on one filesystem unless `--cross-filesystems` is given, and counts each hardlinked inode once. Sizes are allocated bytes (`st_blocks`), which is what deleting frees; apparent sizes are reported too.
- Directories it cannot read are listed, not skipped silently. When a scan root is a mount point, the report includes `df` figures and an **unaccounted** figure (`df` used − scanned), with likely locations and a `sudo` rerun command when the gap is large.
- After measuring, `scan` runs the detectors and lists **findings**: things that can be reclaimed, each with a risk tier, a reason, the tool-native command to remove it and what recovery costs. Built so far: `cargo-target`. The other M1 detectors are tracked in issue #18. Nothing is removed; `plan`/`apply` arrive in M2.
- `doctor` shows whether you are root, which optional tools (`git`, `docker`, `cargo`, `go`, `journalctl`) are on `PATH`, and which detectors each one enables.

Exit codes: `0` ok, `1` error (usage errors included), `2` items skipped by a guard, `3` refused by policy.

## Building

```
cargo build --release                                              # target/release/dwhy
cargo build --release --target x86_64-unknown-linux-musl -p dwhy-cli  # static binary
```

The workspace has `crates/dwhy-core` (engine and JSON types) and `crates/dwhy-cli` (the `dwhy` binary).
