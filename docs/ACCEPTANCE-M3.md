# M3 acceptance: the WAL demo

The demo verifies the [M3 acceptance criterion](DESIGN.md#mvp-milestones) with a small-scale reproduction of the WAL backlog in row 1 of the [M1 cleanup record](ACCEPTANCE-M1.md#items).

## The demo

[`crates/dwhy-cli/tests/data/wal-demo/compose.yaml`](../crates/dwhy-cli/tests/data/wal-demo/compose.yaml) has three services, all using `postgres:16-alpine` on the project's internal network with an isolated bridge gateway. The bridge has no host IPv4 address.

- `s3test` exits at once (`entrypoint: ["true"]`). It plays the dead fake S3.
- `postgres` runs with `archive_mode=on`, `archive_command=wget -Y off -q -O /dev/null http://s3test:9000/wal/%f` and `archive_timeout=10s`. The archive command bypasses proxies and fails because `s3test` has exited, so WAL segments awaiting archival cannot be recycled.
- `writer` inserts 2000 rows of 1 KB about once a second to keep segments filling and switching. It exits on table creation failure, continues after a failed insert, and treats reaching its ten-minute limit as success.

[`crates/dwhy-cli/tests/wal_demo_e2e.rs`](../crates/dwhy-cli/tests/wal_demo_e2e.rs) drives the built `dwhy` binary against it. Both growth checks require measured `before` and `after` sizes for the demo volume, with `after` greater than `before`.

1. Run `docker compose -p <project> -f <Compose file> up -d --pull never` with a generated name of the form `dwhye2e<pid><16 random hex digits>`, then wait for `postgres` to be healthy over TCP.
2. `dwhy scan <empty temp dir> --snapshot --detectors docker-build-cache --json`. `docker-build-cache` reads `GET /system/df`, so the snapshot records every volume's size. No `docker-volume` finding exists, so no probe runs.
3. `dwhy watch <empty temp dir> --for 30s --json`. The test checks that the demo volume grows faster than 20 MiB a minute.
4. Poll the apparent file sizes with `find` and `stat` inside the project's own Postgres container until they total 1.1 GiB. The test uses the sizes it read even if files disappear during a walk. The threshold leaves a margin over the `docker-volume` detector's 1 GiB cutoff for in-use volumes. The poll gives up after 10 minutes.
5. `dwhy diff --detectors docker-build-cache --json`. The test checks that the demo volume grew by more than 512 MiB since the snapshot.
6. `dwhy explain docker://volume/<project>_pgdata --json`. The test checks for a `docker-volume` finding with `archive_mode` set to `on` and at least one archive failure in its `postgres_wal` evidence. It checks that the `exited` archive target matches the actual name of the project's `s3test` container and that the advice starts with `restore the archive target s3test`.
7. A Drop guard runs `down -v --remove-orphans` for the demo project when the test finishes or unwinds from a panic. Every Compose call sets `COMPOSE_PROJECT_NAME` and `-p` to the generated project name. When the demo assertions pass, the test runs teardown and checks that `docker ps -a`, `docker volume ls` and `docker network ls`, filtered by `label=com.docker.compose.project=<project>`, are empty. Ctrl-C skips the guard. After an interrupt, run the cleanup command printed at startup.

   ```text
   env -u DOCKER_CONTEXT DOCKER_HOST=<socket URL> COMPOSE_PROJECT_NAME=<project> docker compose -p <project> -f <absolute Compose path> down -v --remove-orphans
   ```

### What it never does

- It never runs `scan` with the `docker-volume` detector or with the default detectors. That would run the `postgres-wal` probe on every large in-use volume on the machine and `docker exec psql` into other people's Postgres containers. `watch` and `diff` skip probes, and `explain` probes only the finding it explains.
- It changes only its own Compose containers, named volume and internal network. The archive request stays within that network. It pulls no image, never uses sudo and never runs `dwhy apply`.
- Every `dwhy` call gets `XDG_STATE_HOME` set to a temp dir, so its snapshots never reach `~/.local/state/diskwhy`.

## How to run it

The demo needs Docker Engine 28 or later for the isolated bridge, Docker Compose, and a local copy of `postgres:16-alpine` on the daemon. Docker and `dwhy` use `/var/run/docker.sock` by default or the absolute Unix socket URL set in `DOCKER_HOST` (for example, `unix:///run/user/1000/docker.sock`), regardless of the active Docker context. With an unsupported `DOCKER_HOST`, the test prints `skipped` and returns successfully before contacting Docker. If the selected socket is inaccessible, the test fails.

The demo takes about 6 minutes. It is `#[ignore]`d and also returns at once unless `DWHY_DOCKER_E2E=1` is set. The WAL demo is disabled in normal test runs and in CI.

```
DWHY_DOCKER_E2E=1 cargo test -p dwhy-cli --test wal_demo_e2e -- --ignored --nocapture
```

`--nocapture` prints the watch rate, then the volume size while it waits, the diff change and the explain reason, advice and evidence.

## Run on pc-ubuntu

On 2026-11-18, the maintainer ran the final fixture at `0dbb25c` by hand on pc-ubuntu with Docker 29.1.3 and Compose 2.40.3. The fixture used an internal network with an isolated gateway, a ten-minute writer limit, and `--pull never`. Project `dwhye2e2927735da2d31fe95824348` passed in 322 s while the machine's `bmc-*` Compose projects were running alongside it.

| Step | What it saw |
|---|---|
| `watch --for 30s` | Right after the baseline, volume 67,052,892 → 187,630,940 bytes (+120,578,048). `bytes_per_minute` was 241,156,096 (~230 MiB/min). |
| Growth to 1.1 GiB | Reached 1168 MiB after 232 s. |
| `diff` | Volume 67,052,892 → 1,224,957,796 bytes (+1,157,904,904). `bytes_per_day` was 380,391,573,025. |
| `explain` | `docker-volume` finding with `psql` evidence. `wal_bytes` was 587,202,560, `data_bytes` was 641,791,572, `failed_count` was 47, and `last_archived_at` was null. `archive_program` was `wget` and `archive_timeout` was `10s`. Target `s3test` (container `dwhye2e2927735da2d31fe95824348-s3test-1`) was `exited`. |
| Teardown | `down -v --remove-orphans` exited 0 and removed all three containers, the `_default` network and the `_pgdata` volume. No container, volume or network named `dwhye2e*` remained, and the `bmc-*` containers were still up. |

**Explain reason**

> pg_wal holds 560.0M vs 612.1M data; archiving is failing, with 47 failures in total (last failure 2026-11-18T11:29:27.019439Z, last success none) (target s3test (dwhye2e2927735da2d31fe95824348-s3test-1) exited); volume dwhye2e2927735da2d31fe95824348_pgdata holds 1.1G and is mounted by dwhye2e2927735da2d31fe95824348-postgres-1 (running) (a running container uses it)

**Explain advice**

> restore the archive target s3test; WAL is freed at the next checkpoint once it is archived (do not remove the volume: it holds the database)
