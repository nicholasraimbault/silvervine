# Orchestrator Status

**Lead:** Claude (main session)
**Team:** `neon-v2`
**Active phase:** Phase 1 — Core skeleton

## Current focus

Phase 1 in progress: core-engine team writing manifest parsing, browser detection, custom-paths config, error type, lockfile, and test fixtures. CLI's Phase 1 scope (clap subcommand stubs) was completed by infra during Phase 0; CLI team activates again in Phase 4.

## Decisions made (recorded for handoff)

- 2026-05-04: Cloudflare Worker lives as `cloudflare-worker/` subdirectory in main `neon` repo (not separate repo)
- 2026-05-04: Beta tester recruitment via pinned GitHub issue first; subreddits considered in Phase 6
- 2026-05-04: `homebrew-neon` tap archival happens 30 days after V2 ships (grace period)
- 2026-05-04: Orchestrator → user check-ins at end of each phase + on blockers (not per-task)

## Phase status

| Phase | Status | Notes |
|---|---|---|
| 0 — Foundation | **Done** | 6 commits on `v2-rust-rewrite`; infra agent reports complete; verified locally (build + fmt + clippy green) |
| 1 — Core skeleton | In progress | core-engine team (cli scope preempted by infra during Phase 0 stubs) |
| 2 — Widevine + patching | Pending | core-engine + platform (parallel) |
| 3 — Daemon | Pending | daemon + platform (parallel) |
| 4 — CLI completion | Pending | cli sequential |
| 5 — Distribution + docs | Pending | infra + platform |
| 6 — Beta + release | Pending | All teams on standby for fixes |

## Active blockers

**Pending Nick action items (non-blocking for code work, blocking for full V2 launch):**
1. Branch protection rules on `master` and `v2-rust-rewrite` — `gh api` commands ready in `docs/superpowers/teams/infra/handoff.md`
2. Cloudflare Worker deployment — runbook in `cloudflare-worker/README.md`; needs `wrangler login` + D1 setup
3. (Optional) Re-enable GitHub Issues on the repo; set `CODECOV_TOKEN` secret

## Decision log

(empty)
