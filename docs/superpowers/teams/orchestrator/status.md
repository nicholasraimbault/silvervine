# Orchestrator Status

**Lead:** Claude (main session)
**Team:** `neon-v2`
**Active phase:** Phase 2 — Widevine + atomic patching

## Current focus

Phase 2 in progress: core-engine + platform teams in parallel.
- core-engine: Widevine download/extract/cache, atomic patch protocol, backup/rollback, browser-running detection
- platform: Linux + macOS patch impls, migration logic for old bash-installed Neon

Phase 1 complete (78 unit + integration tests passing, 95.38% coverage). MSRV bumped 1.75→1.85 (clap_lex 1.1+ requires edition2024).

## Decisions made (recorded for handoff)

- 2026-05-04: Cloudflare Worker lives as `cloudflare-worker/` subdirectory in main `neon` repo (not separate repo)
- 2026-05-04: Beta tester recruitment via pinned GitHub issue first; subreddits considered in Phase 6
- 2026-05-04: `homebrew-neon` tap archival happens 30 days after V2 ships (grace period)
- 2026-05-04: Orchestrator → user check-ins at end of each phase + on blockers (not per-task)

## Phase status

| Phase | Status | Notes |
|---|---|---|
| 0 — Foundation | **Done** | 6 commits; infra agent reports complete; verified locally (build + fmt + clippy green) |
| 1 — Core skeleton | **Done** | 8 commits; manifest, browsers, config, error, lockfile shipped; 95.38% coverage on owned modules |
| 2 — Widevine + patching | In progress | core-engine + platform (parallel) |
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
