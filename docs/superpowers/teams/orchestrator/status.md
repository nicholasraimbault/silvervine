# Orchestrator Status

**Lead:** Claude (main session)
**Team:** `neon-v2`
**Active phase:** V3.0 code-complete — awaiting Nick's hardware acceptance

## Current focus

**V3.0 is shipped to the branch.** All 5 V3 sub-phases (A/B/C/D/F; E deferred to V3.1) are committed on `feature/v3-scaffolding`. 744 tests passing with `--features experimental-bridge`, 494 on default (V3 fully feature-gated; default V2 install unchanged).

Only remaining gate is Nick's hardware acceptance run:

1. Install host deps: `pacman -S libvirt looking-glass looking-glass-module-dkms` (or apt equivalents)
2. Pin current 2026 Microsoft IoT LTSC URL + SHA in `~/.config/neon/bridge.toml` (Phase F bridge.toml override solves this without source edits)
3. `sudo modprobe kvmfr static_size_mb=64` (one-time)
4. Install `/etc/udev/rules.d/99-kvmfr.rules` per `bridge::kvmfr::udev_rule_text()`; `usermod -aG kvm $USER`
5. `cargo run --features experimental-bridge,experimental-bridge-libvirt -- stream init --accept-eval`
6. Wait ~30-45 min for unattended Windows install
7. `cargo run --features experimental-bridge,experimental-bridge-libvirt -- stream start netflix.com`
8. Verify Looking Glass window opens; Netflix plays at higher quality than V2's L3 720p ceiling

If hardware acceptance succeeds, tag `v1.0.0` and ship. If it surfaces issues, file them; bridge team fixes them as V3.1.

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
| V3-B — Hardware capability detection | **Done** | 5 commits; BridgeCapabilities API; per-vendor remediation; env_mutex flake fixed; 494/508 tests; **first hardware-acceptance gate passed on Nick's actual machine** |
| V3-C — Windows guest provisioning | **Done** | 4 commits; ISO + license + unattended XML + libvirt XML + libvirt orchestration + install + `neon stream init` + status; 613 tests with feature; **Nick action required** — pin Microsoft ISO + Sunshine URL/SHA-256 to 2026 values (placeholders are 2024) before end-to-end run, OR wait for Phase F bridge.toml override |
| V3-D — Looking Glass + tray growth | **Done** | 6 commits; kvmfr detection + LG client wrapper + IDD fallback + stream start/stop + tray V3 extensions (Stream Netflix/Disney+/HBO Max + Bridge submenu); 494/675 tests; default V2 menu unchanged |
| V3-F — Polish + repair | **Done** | 9 commits; bridge.toml override + repair + uninstall + license + URL nav + auto-dispatch + health monitor + tray dynamic state + wizard polish + docs/v3/; 744 tests with feature; **V3.0 code-complete** |
| V3-E — CDM forwarding | Deferred to V3.1 | Decided pre-execution |
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
