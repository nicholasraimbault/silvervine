# Orchestrator Status

**Lead:** Claude (main session)
**Team:** `neon-v2`
**Active phase:** V3-Phase B — Hardware capability detection (platform team)

## Current focus

V2 V1.0 ready (`v2-rust-rewrite` HEAD `4521f3d`, 456 tests passing, all docs in place). Phase 6 V2 beta deferred until V3 lands or Nick decides to ship V2 standalone first.

V3 work proceeding on `feature/v3-scaffolding` branch:

- **V3-Phase A** (scaffolding): **Done.** 6 commits (`fcb2f57..6656c2f`); CdmProvider trait + LocalFileCdm + patch flow refactor + bridge module gated stub + cli::stream stub + feature flag tests + ROADMAP/CONTRIBUTING updates. 466 tests on default, 469 with `--features experimental-bridge`. Both build paths green.
- **V3-Phase B** (hardware capability detection): in progress; platform team activated.

Known issue (not blocking): pre-existing flake in `daemon::lifecycle::tests` env_mutex poisoning under parallel test load (~10% of runs). Platform team to address as Phase B side deliverable.

## Decisions made (recorded for handoff)

- 2026-05-04: Cloudflare Worker lives as `cloudflare-worker/` subdirectory in main `neon` repo (not separate repo)
- 2026-05-04: Beta tester recruitment via pinned GitHub issue first; subreddits considered in Phase 6
- 2026-05-04: `homebrew-neon` tap archival happens 30 days after V2 ships (grace period)
- 2026-05-04: Orchestrator → user check-ins at end of each phase + on blockers (not per-task)
- 2026-05-04: Phase 3 spawned serially (platform → daemon) after parallel agent activity correlated with noctalia-shell crash
- 2026-05-04: `neon localhost-bridge` queued as **V3 stretch goal** behind Cargo feature flag `experimental-bridge`. Recipe: Win11 IoT LTSC (BYO license) + Looking Glass B7 + GPU/TPM passthrough + HEVC (free in IoT LTSC). Verified gap: WinBoat (21k⭐) abandoned Looking Glass; cloud SaaS bans VOD streaming; 50-200k addressable audience. Three blockers documented: license grey-area (mitigated by BYO posture), Looking Glass IDD paused (mitigated by $5 dummy HDMI plug), niche pricing (free / part of Neon). Build after V2.0 ships.

## Phase status

| Phase | Status | Notes |
|---|---|---|
| 0 — Foundation | **Done** | 6 commits; infra agent reports complete; verified locally (build + fmt + clippy green) |
| 1 — Core skeleton | **Done** | 8 commits; manifest, browsers, config, error, lockfile shipped; 95.38% coverage on owned modules |
| 2 — Widevine + patching | **Done** | core-engine 87% / platform 88.7% coverage; 210 tests passing |
| 2.x — Sudo batching fix | **Done** | migration's 5+ prompts → 1 prompt via `run_as_root_script` |
| 3 — Daemon + tray + watcher | **Done** | platform: lifecycle + power; daemon: tray + watcher + IPC + notify + hooks + run(); 343 tests; serial spawn, no desktop disruption |
| 4 — CLI completion | **Done** | 13 subcommands wired; EME translator (14 codes); tracing-subscriber logging; 456 tests |
| 5 — Distribution + docs | **Done** | README/MIGRATION/ROADMAP/CONTRIBUTING/SECURITY/CHANGELOG/COC/issue templates; infra agent partial (content filter), orchestrator finished |
| 6 — Beta + release | Deferred | Nick to decide whether to ship V2 standalone or wait for V3 |
| V3-A — Scaffolding | **Done** | 6 commits; CdmProvider trait; bridge stub; feature flag; 466/469 tests both paths |
| V3-B — Hardware capability detection | In progress | platform team (single agent, serial); also addressing pre-existing env_mutex flake |
| V3-C through F | Pending | Per V3 orchestration plan |
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
