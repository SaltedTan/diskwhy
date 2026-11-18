# M3 acceptance: the WAL demo

DESIGN.md says M3 is done when a test Compose file, Postgres with a failing `archive_command` and `archive_timeout=10s`, is flagged by `watch` and `diff`, and `explain` names the dead archive target. This is row 1 of [ACCEPTANCE-M1.md](ACCEPTANCE-M1.md) on a small scale. On 2026-11-13, `bmc-prod-test` had piled up ~29G of WAL because the fake S3 container it archived to had been stopped for 6 days.

## The demo

[`crates/dwhy-cli/tests/data/wal-demo/compose.yaml`](../crates/dwhy-cli/tests/data/wal-demo/compose.yaml) has three services, all on `postgres:16-alpine`:

- `s3test` exits at once (`entrypoint: ["true"]`). It plays the dead fake S3.
- `postgres` runs with `archive_mode=on`, `archive_command=wget -q -O /dev/null http://s3test:9000/wal/%f` and `archive_timeout=10s`, so every archive attempt fails and no WAL segment can be recycled.
- `writer` inserts 2000 rows of 1 KB every second, which keeps segments filling and switching.

[`crates/dwhy-cli/tests/wal_demo_e2e.rs`](../crates/dwhy-cli/tests/wal_demo_e2e.rs) drives the built `dwhy` binary against it:

1. `docker compose -p dwhye2e<pid><unix-secs> up -d`, then wait for `postgres` to be healthy.
2. `dwhy scan <empty temp dir> --snapshot --detectors docker-build-cache`. `docker-build-cache` reads `GET /system/df`, so the snapshot records every volume's size. No `docker-volume` finding exists, so no probe runs.
3. Poll the volume with `du` inside the project's own Postgres container until it holds 1.1 GiB. The `docker-volume` detector reports an in-use volume from 1 GiB. The test gives up after 10 minutes.
4. `dwhy watch <empty temp dir> --for 30s`. The test checks that the volume grows faster than 20 MiB a minute.
5. `dwhy diff --detectors docker-build-cache`. The test checks that the volume grew by more than 512 MiB since the snapshot.
6. `dwhy explain docker://volume/<project>_pgdata`. The test checks for a `docker-volume` finding whose `postgres_wal` evidence has `archive_mode` `on`, archive failures, and the target `s3test` in state `exited`, and whose advice starts with `restore the archive target s3test`.
7. A Drop guard runs `docker compose -p <project> down -v --remove-orphans` on every path, including a panic. The test then checks that `docker ps -a`, `docker volume ls` and `docker network ls`, filtered by `label=com.docker.compose.project=<project>`, are empty.

### What it never does

- It never runs `scan` with the `docker-volume` detector or with the default detectors. That would run the `postgres-wal` probe on every large in-use volume on the machine and `docker exec psql` into other people's Postgres containers. `watch` and `diff` skip probes, and `explain` probes only the finding it explains.
- It touches no container, volume or network outside its own Compose project, pulls no image, never uses sudo and never runs `dwhy apply`.
- Every `dwhy` call gets `XDG_STATE_HOME` set to a temp dir, so its snapshots never reach `~/.local/state/diskwhy`.

## How to run it

It needs a Docker daemon the user can reach and `postgres:16-alpine` already pulled. It takes about 6 minutes. It is `#[ignore]`d and also returns at once unless `DWHY_DOCKER_E2E=1` is set. The normal `cargo test` and CI never contact the daemon.

```
DWHY_DOCKER_E2E=1 cargo test -p dwhy-cli --test wal_demo_e2e -- --ignored --nocapture
```

`--nocapture` prints the volume size while it waits, then the watch rate, the diff change and the explain reason, advice and evidence.

## Run on pc-ubuntu

On 2026-11-18 (Docker 29.1.3, Compose 2.40.3), with the machine's own Compose projects running alongside, project `dwhye2e16837461794997736` passed in 342 s:

| Step | What it saw |
|---|---|
| Growth to 1.1 GiB | 64 MiB after start, 1168 MiB after 262 s (~250 MiB a minute) |
| `watch --for 30s` | volume 1,224,957,789 → 1,343,192,925 bytes, +118,235,136; `bytes_per_minute` 236,470,272 (~225 MiB/min) |
| `diff` | volume 67,052,885 → 1,362,313,053 bytes, +1,295,260,168 (~1.2 GiB in ~290 s); `bytes_per_day` 381,947,025,649 |
| `explain` | `docker-volume` finding, evidence from `psql`: `wal_bytes` 654,311,424, `data_bytes` 709,695,060, `failed_count` 52, `last_archived_at` null, `archive_program` `wget`, `archive_timeout` `10s`, target `s3test` (container `dwhye2e16837461794997736-s3test-1`) `exited` |
| Teardown | `down -v --remove-orphans` removed the 3 containers, the network and the volume; the three label-filtered listings were empty afterwards, and the `bmc-prod-test` containers were still up |

Explain's reason:

> pg_wal holds 624.0M vs 676.8M data; archiving is failing, with 52 failures in total (last failure 2026-11-18T10:34:25.967373Z, last success none) (target s3test (dwhye2e16837461794997736-s3test-1) exited); volume dwhye2e16837461794997736_pgdata holds 1.3G and is mounted by dwhye2e16837461794997736-postgres-1 (running) (a running container uses it)

and its advice:

> restore the archive target s3test; WAL is freed at the next checkpoint once it is archived (do not remove the volume: it holds the database)
