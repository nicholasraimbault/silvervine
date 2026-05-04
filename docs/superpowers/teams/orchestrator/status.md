# Orchestrator Status

**Lead:** Claude (main session)
**Team:** `neon-v2`
**Active phase:** Phase 0 — Foundation

## Current focus

Phase 0 in progress: infra team is establishing the Cargo workspace, CI matrix, cargo-dist release pipeline, Dependabot/auto-merge config, Cloudflare Worker scaffolding, and security baselines.

## Decisions made (recorded for handoff)

- 2026-05-04: Cloudflare Worker lives as `cloudflare-worker/` subdirectory in main `neon` repo (not separate repo)
- 2026-05-04: Beta tester recruitment via pinned GitHub issue first; subreddits considered in Phase 6
- 2026-05-04: `homebrew-neon` tap archival happens 30 days after V2 ships (grace period)
- 2026-05-04: Orchestrator → user check-ins at end of each phase + on blockers (not per-task)

## Phase status

| Phase | Status | Notes |
|---|---|---|
| 0 — Foundation | In progress | infra team only |
| 1 — Core skeleton | Pending | core-engine + cli (parallel) |
| 2 — Widevine + patching | Pending | core-engine + platform (parallel) |
| 3 — Daemon | Pending | daemon + platform (parallel) |
| 4 — CLI completion | Pending | cli sequential |
| 5 — Distribution + docs | Pending | infra + platform |
| 6 — Beta + release | Pending | All teams on standby for fixes |

## Active blockers

None.

## Decision log

(empty)
