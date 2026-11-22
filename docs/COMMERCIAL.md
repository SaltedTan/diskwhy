# Commercial feasibility and licence (2026-11-15)

> Update (2026-11-22): Decided to open-source `diskwhy` under `MIT OR Apache-2.0` (`LICENSE-MIT`, `LICENSE-APACHE`). The notes below are kept for historical context.

## Short answer

People are unlikely to pay for the **single-machine CLI/TUI**. Free tools that are good enough already exist (gdu, ncdu, Mole, lysosome's MIT CLI, and many small ratatui cleaners), and Linux terminal users rarely pay for local tools. A **fleet/team layer** could be paid, later, once the free tool has users. Keep the repo private while building the MVP, then open-source the core.

## Evidence

- **Paid disk cleaners are a Mac consumer market.** DaisyDisk sells for ~$10–12 one-time. CleanMyMac costs ~$40/yr, or ~$90 one-time; MacPaw reportedly has ~$25M ARR (unverified). Both are GUI apps for non-technical users. Nothing like them sells on Linux.
- **The closest competitor uses free CLI + paid app.** lysosome's CLI is MIT and free forever. Its Mac menu-bar app plans one-click cleanup and scheduled rules for $19–29 one-time, and a "team/fleet view" is listed for "later". So even that team is betting that the CLI itself will not sell.
- **Paid CLIs exist, but only for workflow or business tools.** Examples are Conveyor (~$45/mo), and Skeema and PHPStan (free plus a paid "pro" edition). In those HN threads, people agree "purely CLI tools are harder to monetize": the tool has to clearly beat free alternatives, and licences get shared.
- **Open-source CLI revenue estimates** (blog estimates, unverified): most stall at ~200 stars with no revenue. Sponsorships bring ~$200–800/mo at 1k–5k stars. A paid cloud/team layer brings ~$500–3,000/mo after 12–18 months. Expect 1–3% of free users to pay.
- **The server "disk full" market is served by guides and generic monitoring.** Search found many how-to guides and threshold alerts in general monitoring tools (Netdata, Datadog), but no product that diagnoses the root cause across a fleet. That gap is the only plausible paid niche.

## What could be paid (later, only if the free tool gets traction)

1. **Fleet view:** many hosts' snapshots in one place, with ranking by growth rate, "which box fills up next", and root-cause probes across hosts.
2. **Alerts with explanations:** "/ on host-x will be full in ~6 days: pg_wal on volume Y, archiver failing" sent to Slack, Telegram or email. Compare with "disk at 85%" from generic monitoring.
3. **Org policy for agents:** central limits on what agents may delete per host, plus a shared audit log.

All of these need a server component, which is the usual open-core split: a free local tool, plus a paid hosted or self-hosted service.

## Licence recommendation

- **Now:** private repo, no licence file (all rights reserved). As the sole author you can choose any licence later.
- **At public release:** put the core (`dwhy-core`, `dwhy-cli`, `dwhy-tui`, `dwhy-mcp`) under **MIT OR Apache-2.0**, the Rust ecosystem norm. That gives the most adoption, and adoption is the only route to a paid layer.
- **If a fleet service is built:** keep it in a separate repo, either closed or under a delayed-open licence such as FSL (it becomes Apache-2.0 after 2 years), so the core stays permissive.
- **Contributors:** once outside contributions arrive, require DCO sign-off at least. If relicensing the core might ever be needed, use a CLA instead; decide this before the first external PR.

## Sources

- https://news.ycombinator.com/item?id=42918140 (Ask HN: CLI-only tools that are monetised)
- https://news.ycombinator.com/item?id=42764185 (Ask HN: selling downloadable software)
- https://jakeinsight.com/side-income/2026-04-08-monetize-open-source-cli-tool-with-sponsorship-and/
- https://lysosome.dev/
- https://www.diskcleaner.pro/blog/best-one-time-purchase-mac-cleaner/
- https://mackeeper.com/blog/daisydisk-vs-cleanmymac/
- https://servercompass.app/wiki/homelab-monitoring-backups
- https://vineethnk.in/blog/the-disk-that-filled-itself/
