# Orchestrator Status

**Lead:** Claude (main session)
**Team:** `neon-v2`
**Active phase:** Phase 3 — Daemon + tray + watcher (serial restart)

## Current focus

Phase 3 resumed after noctalia incident with new constraints:
- Spawn agents **serially** (platform → then daemon), not in parallel
- Every agent brief includes guardrails from `docs/superpowers/teams/orchestrator/agent-guardrails.md`
- Working tree was reset to clean Phase 2 state before resume; previous Phase 3 WIP discarded

Order:
1. **platform** first: `src/daemon/lifecycle/{mod,linux,macos}.rs` + `src/daemon/power/{mod,linux,macos}.rs`
2. **daemon** second: `src/daemon/{mod,tray,watcher,ipc}.rs` + `src/notify.rs` + `src/hooks.rs`

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
| 2 — Widevine + patching | **Done** | core-engine 87% / platform 88.7% coverage; 210 tests passing |
| 2.x — Sudo batching fix | **Done** | migration's 5+ prompts → 1 prompt via `run_as_root_script` |
| 3 — Daemon + tray + watcher | In progress (serial: platform → daemon) | restart with guardrails after noctalia crash |
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
