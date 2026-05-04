# Neon V2: Orchestration Plan (Long-Lived Teams)

**Date:** 2026-05-04
**Spec:** `../specs/2026-05-04-neon-rust-rewrite-design.md`
**Status:** Draft — awaiting user approval before any execution

## Plan model

This plan uses Claude Code's **Agent Teams** feature (experimental) for long-lived teammates rather than ephemeral one-shot subagents.

### Mechanism

- **Agent Teams** is a formal Claude Code feature requiring `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` in `~/.claude/settings.json` (already enabled). Requires Claude Code v2.1.32+ (Nick is on v2.1.126).
- Each team is a persistent teammate with its own context window, surviving across user-turns within a session.
- Teammates can message each other directly (no relay through the lead/orchestrator) — important for cross-team interface coordination.
- A shared task list lets teammates claim work; dependencies auto-resolve.
- Up to ~5 teammates is practical before coordination overhead dominates — this plan uses exactly 5.
- The lead (main Claude session = orchestrator) coordinates, synthesizes, runs verification gates, and produces the final integration view.
- **Teams do NOT auto-survive across sessions.** At the start of a new session, the orchestrator re-spawns teammates and re-attaches them to their accumulated context (stored in `docs/superpowers/teams/<team>/handoff.md`).

### Operating principles

- Each team has a persistent identity, scope, and file ownership.
- A team is re-engaged across phases; context accumulates in the team's handoff document.
- The orchestrator coordinates between teams: sequences work, resolves cross-team ambiguities, runs the verification gate after each phase.
- Teams hand off work via well-defined interfaces (Rust module boundaries, API contracts, file-ownership rules).
- Human (Nick) remains the final reviewer and merger; teams produce PR-ready branches, never auto-merge human-authored code.

## Team roster

Five persistent teams, each with bounded scope. A team's "context" lives in `docs/superpowers/teams/<team>/` (handoff docs, decisions, open questions).

### Team 1: Core Engine

- **Identity:** `core-engine`
- **Mission:** Widevine acquisition + browser detection + atomic patching. Pure Rust logic, no platform-specific syscalls (those live in the Platform team's modules).
- **Files owned:**
  - `src/widevine/` — manifest, download, extract, cache management
  - `src/browsers/` — known list, auto-discovery, custom-paths config
  - `src/patch/mod.rs` — atomic patch protocol (calls into platform impls)
  - `src/patch/backup.rs` — snapshot, rollback, atomic rename helpers
  - `src/lockfile.rs` — flock-based concurrent-patch protection
  - `src/error.rs` — categorized error type
- **Depends on:** Platform team (for `patch::linux` and `patch::macos` impls); Infra team (for CI matrix to test on both platforms).
- **Provides to:** CLI team (the public APIs they wrap), Daemon team (patching API).
- **Out of scope:** Tray UI, file watcher, IPC, native notifications, daemon lifecycle, install/uninstall flows.

### Team 2: Platform

- **Identity:** `platform`
- **Mission:** All platform-specific code, including bundle write semantics, codesign, xattr, privilege escalation, daemon registration (LaunchAgent / systemd-user), sleep/wake hooks. Cross-platform abstractions live here so other teams can stay platform-agnostic.
- **Files owned:**
  - `src/platform/` — paths trait, Linux + macOS impls
  - `src/patch/linux.rs` — Linux-specific patch (cp + chmod, no codesign)
  - `src/patch/macos.rs` — macOS-specific patch (xattr -cr, codesign, atomic-rename APFS)
  - `src/daemon/lifecycle.rs` — LaunchAgent / systemd-user unit registration
  - `src/daemon/power.rs` — sleep/wake hooks (`NSWorkspaceDidWakeNotification`, logind D-Bus)
  - `src/migration.rs` — detect + remove old bash-installed Neon
- **Depends on:** Core Engine team (defines the patch/backup contracts).
- **Provides to:** Daemon team (lifecycle + power hooks), CLI team (migration, escalation helpers), Core Engine team (platform-specific patch impls).
- **Out of scope:** UI, file watching, generic Rust modules.

### Team 3: Daemon

- **Identity:** `daemon`
- **Mission:** Long-running tray process. Tray icon, file watcher, IPC, native notifications, heartbeat, CDM integrity check.
- **Files owned:**
  - `src/daemon/mod.rs` — orchestration
  - `src/daemon/tray.rs` — `tray-icon` integration, menu, click handlers
  - `src/daemon/watcher.rs` — `notify` crate, debouncing, browser-running detection
  - `src/daemon/ipc.rs` — Unix socket protocol, message schema
  - `src/notify.rs` — native notifications wrapper
  - `src/hooks.rs` — `~/.config/neon/hooks/` runner
- **Depends on:** Core Engine (patching API), Platform (lifecycle + power), CLI (subcommand for `neon` no-args = run tray).
- **Provides to:** CLI team (the `neon daemon` lifecycle and IPC client API).
- **Out of scope:** First-run wizard (CLI), one-shot subcommands, install logic.

### Team 4: CLI

- **Identity:** `cli`
- **Mission:** All user-facing subcommands (`init`, `setup`, `patch`, `status`, `list-browsers`, `doctor`, `test`, `update`, `repair`, `launch`, `uninstall`, `completion`, `manpage`). EME error code translation. Interactive prompts.
- **Files owned:**
  - `src/main.rs`
  - `src/cli/` — every subcommand impl
  - `src/eme/` — EME error code map + headless-browser test harness
  - `src/log.rs` — tracing setup
  - `src/config.rs` — TOML config schema
- **Depends on:** Core Engine (all the actual logic), Platform (escalation helpers, migration), Daemon (IPC client when daemon is running).
- **Provides to:** Users (the entire CLI surface).
- **Out of scope:** Rust internals of patching, daemon process management, platform syscalls.

### Team 5: Infra

- **Identity:** `infra`
- **Mission:** Build system, CI, release pipeline, distribution, error reporting backend. Anything outside the Rust crate itself.
- **Files owned:**
  - `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`
  - `.github/workflows/ci.yml`, `.github/workflows/release.yml`
  - `.github/dependabot.yml`, `.github/auto-merge.yml`
  - `.github/ISSUE_TEMPLATE/`
  - `dist-workspace.toml` (cargo-dist config)
  - `cloudflare-worker/` — separate repo OR subdirectory; error reporting endpoint + D1 schema
  - `README.md`, `MIGRATION.md`, `ROADMAP.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`
  - `homebrew-neon/Formula/neon.rb` (final deprecation commit)
  - `src/reporter.rs` — opt-in error reporter client (talks to the Worker)
- **Depends on:** All other teams (CI must build their code; release must package it).
- **Provides to:** All other teams (CI feedback, release pipeline, dependency management).
- **Out of scope:** Application logic.

## Communication protocol

### Per-team handoff documents

Each team maintains a single living document at `docs/superpowers/teams/<team>/handoff.md` containing:

- Current focus
- Public contracts owned by this team (Rust module APIs, file paths, IPC schemas)
- Decisions log (with timestamp + rationale)
- Open questions for the orchestrator
- Dependencies awaiting from other teams
- Files most recently changed (audit trail)

### Cross-team interfaces

Teams use Agent Teams' direct teammate-to-teammate messaging for interface questions ("hey platform, what's the signature of `escalate_for_patch`?") rather than relaying through the orchestrator. The orchestrator only intervenes for cross-team conflicts or ambiguity.

When teams need each other's work, they consume only **stable interfaces** documented in their owned files. Examples:

- Core Engine exposes `patch::patch_browser(browser: &Browser, options: PatchOptions) -> Result<PatchOutcome>`. Daemon and CLI both call it; neither reaches into `patch/`'s internals.
- Platform exposes `platform::escalate_for_patch(target_path: &Path) -> Result<()>` that handles the osascript/pkexec dance. CLI and Core Engine call it; neither knows the platform-specific details.
- Daemon's IPC schema is documented in `src/daemon/ipc.rs`. CLI's IPC client (in `cli/`) consumes it from the documented contract.

If a team needs to break an interface, it raises an "interface change" issue — orchestrator coordinates with the consuming team(s) before the change lands.

### Orchestrator responsibilities

- **Sequencing:** decide which teams work in parallel vs serial based on the dependency graph.
- **Verification gate:** at the end of each phase, run `cargo test`, `cargo clippy`, `cargo audit`, integration test smoke check before declaring the phase complete.
- **Conflict resolution:** when two teams disagree on an interface, decide based on the spec; document the decision in both teams' handoffs.
- **Milestone tracking:** maintain a `docs/superpowers/teams/orchestrator/status.md` with phase progress, blocking issues, next steps.
- **Quality gate at handoff:** after a team marks a deliverable done, orchestrator independently verifies (read code, run tests, smoke-test the affected commands) before considering it complete.

### Anti-patterns to avoid

- ❌ Teams writing into other teams' files (file-ownership rules are enforced).
- ❌ Auto-merging team PRs without orchestrator review.
- ❌ A team taking on cross-cutting work outside its scope (must escalate to orchestrator first).
- ❌ Skipping a verification gate to "move faster."

## Phase plan

Six phases. Each phase has explicit team assignments, deliverables, gates, and parallelism markers.

### Phase 0: Foundation (Infra team only)

**Goal:** Empty-but-shippable Cargo project with CI green and release pipeline configured.

| Deliverable | Owner | Definition of Done |
|---|---|---|
| Initialize Cargo workspace on `v2-rust-rewrite` branch | infra | `cargo new --bin neon` style; `Cargo.toml` with metadata, `rust-version = "1.75"`, MIT license; `.gitignore` |
| Skeleton `src/main.rs` with `clap` "hello world" CLI | infra | `neon --version` prints version |
| `.github/workflows/ci.yml` with full matrix | infra | CI runs on PR; fmt, clippy, test, audit, deny, tarpaulin all green on Ubuntu + macOS |
| `dist-workspace.toml` (`cargo dist init` output) | infra | `cargo dist plan` succeeds |
| `.github/workflows/release.yml` (cargo-dist generated) | infra | Dry-run build matrix succeeds |
| `.github/dependabot.yml` | infra | Configured for cargo + actions, weekly |
| `.github/auto-merge.yml` | infra | Auto-merges Dependabot patch/minor with semver labels |
| Branch protection rules on `master` and `v2-rust-rewrite` | infra | PR required, CI required, admin can force-merge for hotfixes |
| Cloudflare Worker scaffolded (separate repo or `cloudflare-worker/` dir) | infra | Worker accepts POST `/v1/report`, validates schema, INSERT INTO D1; deployed; URL noted |
| `cargo audit` and `cargo deny` baseline configs | infra | No advisories or license violations |

**Gate:** `cargo test` green on both platforms in CI; `cargo dist plan` produces expected matrix; Cloudflare Worker accepts a test payload and rows appear in D1.

**Parallelism:** Single team; sequential.

### Phase 1: Core skeleton (Core Engine + CLI in parallel)

**Goal:** All public CLI commands defined as stubs that compile and parse correctly. Manifest parsing + browser detection working in isolation with tests.

| Deliverable | Owner | DoD |
|---|---|---|
| Define `clap` derive structs for every subcommand (per spec CLI surface) | cli | `neon --help` shows full subcommand list; each subcommand is a stub returning "not implemented" |
| Manifest parsing module (`src/widevine/manifest.rs`) | core-engine | Parses Mozilla `widevinecdm.json`; URL fallback chain; handles Linux/Darwin platform keys; tested with fixture |
| Browser detection: known list + custom-paths config | core-engine | `Browser` struct + `detect()` returns list; reads `~/.config/neon/config.toml`; tested with synthesized filesystem |
| Custom-paths TOML schema (`src/config.rs`) | core-engine | Schema documented; serde deserialization tested |
| Categorized error type (`src/error.rs`) | core-engine | All error categories from spec; `Display` shows category + message |
| Lockfile module (`src/lockfile.rs`) | core-engine | `flock` exclusive; concurrent-acquisition test |
| Unit test fixtures (sample manifest JSON, fake `/Applications` tree) | core-engine | Committed; reproducible; gitignored generated artifacts |

**Gate:** `cargo test` covers manifest, browser detection, lockfile, error categorization at ≥80% line coverage; CLI compiles and `neon --help` is correct; integration tests for manifest fallback are gated (`--ignored` flag).

**Parallelism:** Core Engine + CLI in parallel (CLI doesn't depend on engine internals; just consumes future module boundaries via type signatures).

### Phase 2: Widevine + atomic patching (Core Engine + Platform in parallel)

**Goal:** End-to-end download → extract → atomic patch → verify works on Linux and macOS.

| Deliverable | Owner | DoD |
|---|---|---|
| Widevine CRX3 download (`src/widevine/download.rs`) | core-engine | Downloads from manifest URL; verifies SHA-512; integration test with real network gated `--ignored` |
| CRX3 extract (`src/widevine/extract.rs`) | core-engine | Parses CRX3 header; extracts ZIP; output structure verified |
| Cache management (`src/widevine/cache.rs`) | core-engine | `~/.cache/neon/widevine/<version>/` layout; `current` symlink; "keep latest 3" pruning; periodic integrity check helper |
| Atomic patch protocol (`src/patch/mod.rs`) | core-engine | Public `patch_browser()` API; uses platform impls; calls `backup`; rollback on any error |
| Backup + atomic rename (`src/patch/backup.rs`) | core-engine | Snapshot to `~/.cache/neon/backups/<browser>-<ver>-<ts>/`; `renameat2` on Linux, `renameatx_np` on Mac with fallback to two-step |
| Linux patch impl (`src/patch/linux.rs`) | platform | `cp -R`-equivalent into `<browser>/WidevineCdm/`; chmod 755; tests with synthesized `/opt/fake-chromium/` |
| macOS patch impl (`src/patch/macos.rs`) | platform | Bundle write into `<app>/Contents/Frameworks/<fw>/Versions/<ver>/Libraries/WidevineCdm/`; `xattr -cr`; ad-hoc codesign; tests with synthesized `.app` bundle |
| Browser-running detection (`src/browsers/discovery.rs` extension) | core-engine | `sysinfo` scan; matches binary path; deferred-patch hook for daemon use |
| Migration module skeleton (`src/migration.rs`) | platform | Detects legacy install paths; cleanup APIs (no-op-test mode); macOS LaunchDaemon + Linux systemd path detection |

**Gate:** Manual smoke test: clone repo on Linux machine, build, run `neon patch` against a fake `/opt/fake-helium/` (no real browser); verify CDM directory present, no leftover backups, exit code 0. Same on Mac with synthesized `.app`. CI: ≥85% coverage on patch/backup paths.

**Parallelism:** Core Engine drives `patch/mod.rs` + `backup.rs` + `widevine/`; Platform team drives `patch/linux.rs` + `patch/macos.rs` + `migration.rs`. They sync at the patch interface (defined by Core Engine in phase 1).

### Phase 3: Daemon + tray + watcher (Daemon + Platform in parallel)

**Goal:** Long-running tray process with file watching, native notifications, IPC, daemon registration, sleep/wake hooks.

| Deliverable | Owner | DoD |
|---|---|---|
| Tray icon scaffolding (`src/daemon/tray.rs`) | daemon | `tray-icon` integrated; menu items per spec; click handlers fire log events |
| File watcher (`src/daemon/watcher.rs`) | daemon | `notify` crate; per-browser watch path; 2s debounce; browser-running check before triggering patch |
| IPC server (`src/daemon/ipc.rs`) | daemon | Unix socket at `~/.cache/neon/daemon.sock`, mode 0600; JSON message protocol; `status`/`patch`/`trigger_check` methods |
| Notification wrapper (`src/notify.rs`) | daemon | `notify-rust`; macOS-no-action-buttons handled via `#[cfg]`; categorized error → notification body |
| Heartbeat thread + integrity check thread | daemon | Writes `~/.cache/neon/heartbeat` every 60s; weekly CDM SHA recheck |
| Hooks runner (`src/hooks.rs`) | daemon | Shells out to `~/.config/neon/hooks/post-patch` if present; `pre-patch` deferred to V1.1 |
| LaunchAgent registration (macOS) (`src/daemon/lifecycle.rs`) | platform | Writes `~/Library/LaunchAgents/com.neon.tray.plist` with `KeepAlive` + `RunAtLoad`; `launchctl bootstrap`; reverse on uninstall |
| systemd-user unit registration (Linux) (`src/daemon/lifecycle.rs`) | platform | Writes `~/.config/systemd/user/neon.service` with `Restart=on-failure`; `systemctl --user enable --now`; reverse on uninstall |
| Sleep/wake hooks macOS (`src/daemon/power.rs`) | platform | `NSWorkspaceDidWakeNotification` via `objc` FFI; isolated `unsafe` block with safety comments |
| Sleep/wake hooks Linux (`src/daemon/power.rs`) | platform | `org.freedesktop.login1.Manager.PrepareForSleep` D-Bus subscription via `zbus` |
| `--no-tray` mode for headless Linux | daemon | If GTK / libayatana-appindicator absent, daemon runs notifications-only with warning |

**Gate:** Smoke test: launch `neon` daemon mode on Linux + Mac; tray icon visible; trigger a fake browser update (`touch /opt/fake-helium/version.123`); watcher fires; mock patch logs successful path. Confirm LaunchAgent / systemd-user unit auto-starts process at login (manual test on dev machine).

**Parallelism:** Daemon team owns tray/watcher/IPC/notifications; Platform team owns lifecycle/power hooks. Both proceed in parallel; sync at the daemon-startup orchestration in `src/daemon/mod.rs`.

### Phase 4: CLI completion (CLI team)

**Goal:** Every CLI subcommand fully implemented; `neon init` interactive wizard, `neon doctor` with EME error translation, `neon repair`, etc.

| Deliverable | Owner | DoD |
|---|---|---|
| `neon init` interactive wizard (`src/cli/init.rs`) | cli | `dialoguer` or `inquire` prompts: detect browsers → confirm → download CDM → patch → install daemon → done. Exit codes documented |
| `neon setup` (`src/cli/setup.rs`) | cli | Non-interactive equivalent of `init`; respects flags for unattended use; runs migration first |
| `neon patch` (`src/cli/patch.rs`) | cli | `--force`, `--dry-run`, optional `<browser>` filter; uses Core Engine API |
| `neon status` (`src/cli/status.rs`) | cli | `--json` for scripts; `--watch` live updating |
| `neon list-browsers` (`src/cli/list_browsers.rs`) | cli | `--all` includes auto-discovered + custom paths; `--json` |
| `neon doctor` (`src/cli/doctor.rs`) | cli | Reads daemon heartbeat, manifest cache state, browser detection, last patch results; `--json`, `--share` (issue template URL); accepts EME error code arg |
| EME error code translation (`src/eme/`) | cli | Map of Netflix N-codes, Disney+ codes, Spotify codes → category + actionable advice |
| `neon test` (`src/cli/test.rs`) | cli | Spawns headless browser against Shaka demo; parses result; per-browser EME status; documents network requirements |
| `neon update` (`src/cli/update.rs`) | cli | `widevine` + `self`; `--rollback`; `--cdm-source <url>`; self-update with privilege escalation handling |
| `neon repair` (`src/cli/repair.rs`) | cli | Composes uninstall + setup; preserves user config |
| `neon launch <browser>` (`src/cli/launch.rs`) | cli | Verifies patched, patches if needed, launches |
| `neon uninstall` (`src/cli/uninstall.rs`) | cli | Removes daemon + cache; preserves browser bundles (still patched until they auto-update) |
| `neon completion <shell>` (`src/cli/completion.rs`) | cli | `clap_complete` for bash/zsh/fish/powershell |
| `neon manpage` (`src/cli/manpage.rs`) | cli | `clap_mangen` outputs roff-formatted man page |
| Opt-in error reporter (`src/reporter.rs`) | infra | First-run `init` asks; default off; respects `--no-reporting` flag and `NEON_NO_REPORTING` env; talks to Cloudflare Worker |

**Gate:** Run every CLI subcommand on Linux + Mac on a test machine; verify outputs match spec; verify `--json` outputs are valid JSON; verify completion script generates valid bash. Coverage ≥75% on `src/cli/` overall, ≥90% on `doctor`, `repair`, `init`.

**Parallelism:** CLI team is largely sequential (later subcommands depend on earlier ones), but `completion` and `manpage` can be done at the start since they're derived from clap definitions. Reporter is implemented by Infra in parallel.

### Phase 5: Distribution + documentation (Infra + Platform)

**Goal:** Single `curl | sh` installer ready to ship; all docs in place.

| Deliverable | Owner | DoD |
|---|---|---|
| Final `cargo-dist` config tuning | infra | Multi-target builds for x86_64-apple-darwin, aarch64-apple-darwin, x86_64-unknown-linux-musl; `zipsign` enabled; installer script generated |
| `neon-installer.sh` test on fresh Mac VM + fresh Linux VM | infra | One-line install works; `neon --version` runs |
| `MIGRATION.md` | platform | Per-install-path upgrade instructions per spec |
| `README.md` rewrite | infra | New install command, V2 features, link to ROADMAP/MIGRATION |
| `ROADMAP.md` | infra | V1.1 (AUR/.deb), V2 (Windows, ARM64-with-binary-patching), V2+ |
| `CONTRIBUTING.md` | infra | Build instructions, conventional commits, PR conventions |
| `SECURITY.md` | infra | Disclosure email, supported versions, response SLA |
| `CODE_OF_CONDUCT.md` | infra | Contributor Covenant 2.1 |
| `CHANGELOG.md` (release-please) | infra | First entry generated from conventional commits since branch start |
| `.github/ISSUE_TEMPLATE/bug.yml` | infra | Auto-fill from `neon doctor --share` output via URL params |
| `.github/ISSUE_TEMPLATE/feature.yml` | infra | Standard feature request form |
| GitHub repo settings | infra | Issues re-enabled; description updated; topics added (drm, widevine, chromium, helium, rust) |
| `homebrew-neon` final formula commit + archive | infra | Formula's `caveats` deprecates the tap; README points to `curl \| sh`; repo archived |

**Gate:** Tag a `v2.0.0-rc.1` pre-release; verify GitHub Actions release workflow produces all artifacts, signs them, generates installer script; install on a fresh test machine; run smoke test.

**Parallelism:** Infra primary; Platform contributes `MIGRATION.md`. Other teams quiescent (their work is complete; available for fixes if smoke tests catch bugs).

### Phase 6: Beta → release (all teams on standby for fixes)

**Goal:** Real-user beta, fix discovered issues, tag v2.0.0.

| Deliverable | Owner | DoD |
|---|---|---|
| Pinned issue announcing V2 RC | infra | Links to spec, MIGRATION, install command; asks for testers |
| 1-2 weeks of beta with logged feedback | orchestrator | Issue tracker monitored; categorized error reports analyzed; team(s) assigned to fix categories |
| Fix high-priority bugs | various | Per category from beta feedback; each fix lands as PR with regression test |
| `v2.0.0` tag + release | infra | Final release; release notes; CHANGELOG entry |
| Post-release: archive `homebrew-neon` | infra | After confirming v2.0.0 install works for at least 5 reporters |
| Merge `v2-rust-rewrite` → `master` | orchestrator | Squash-merge with comprehensive commit message; delete `v2-rust-rewrite` branch |

**Gate:** ≥5 users on Mac and ≥5 on Linux confirm V2 install + patch works on fresh systems. Critical-severity bug count = 0. Coverage ≥70% overall.

**Parallelism:** Beta is parallel; fixes are dispatched per category to relevant team.

## Cross-cutting concerns (every team handles)

### Testing

- Unit tests in the same file as the code (Rust convention `#[cfg(test)]`).
- Integration tests in `tests/`, gated behind `--ignored` for network/system tests.
- Synthesized fixtures preferred over real network where possible.
- Coverage measured by `cargo tarpaulin`, reported to codecov.io on every CI run.

### Error handling

- Every public API returns `Result<T, neon::Error>` where `neon::Error` includes a category from the categorized enum.
- No `unwrap()` or `expect()` in production code paths; only in tests with explanatory messages.
- Errors that bubble to user-facing surfaces (`doctor`, notifications, exit code) include the category for routing.

### Logging

- `tracing` crate, structured fields.
- Log file at `~/.cache/neon/logs/neon.log`, rotated weekly, max 5MB per file, keep last 4.
- `RUST_LOG` and `-v`/`-vv` flags control verbosity.

### Documentation

- Every public function has a doc comment with `///`.
- Every module has a `//!` module-level overview.
- `cargo doc --no-deps` runs in CI; warnings fail the build.

### Security

- `cargo audit` runs on every PR; advisory equals build fail.
- `cargo deny check` for license + ban list.
- No `unsafe` outside `platform/macos.rs` (`objc` FFI for power events) and `platform/linux.rs` (only if needed for `renameat2` syscall — prefer the `nix` crate which wraps it safely).
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariant.

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `tray-icon` crate breaks on a Linux WM (e.g., sway, hyprland without tray plugin) | Medium | Medium | `--no-tray` fallback to notifications-only mode; documented in README |
| macOS `--deep` codesign deprecation removes feature in future macOS | Low (but inevitable) | High | Document as V2 work; current behavior matches existing bash; will need to migrate to inside-out signing eventually |
| Cloudflare Worker free tier exceeded | Low (Neon volume tiny) | Low | Monitor; switch to KV if D1 capacity becomes an issue; worst case rate-limit reporter at client |
| Mozilla manifest URL fallback both fail | Medium-Low (hg.mozilla.org sometimes flaky) | Medium | Cached manifest with 24h TTL; surface `--cdm-source <url>` flag for manual override |
| Existing user's bash install corrupts during migration | Low | High | Migration is non-destructive: backs up before removing; rollback path documented |
| `self_update` privilege escalation breaks on edge-case macOS configurations | Medium | Medium | Detailed integration testing on at least 3 macOS versions; document fallback to "uninstall + curl\|sh re-install" if self-update fails |
| Beta finds a category of failure we didn't anticipate | High (this is what beta is for) | Medium | Phase 6 is explicitly reserved for fixes; orchestrator triages and dispatches |
| Tray icon causes battery drain on macOS laptop (file watcher polling) | Low (FSEvents is event-driven not polled) | Medium | Profile with `powermetrics` during daemon dev; ensure no polling loops |
| Helium changes its bundle path between V2 design and ship | Medium | Low | Auto-discovery handles new paths; users can add custom paths via TOML |

## Schedule rough estimate

This is a hobbyist-pace estimate, not a commitment. Adjust to actual availability.

```
Phase 0: Foundation                 ~1 weekend
Phase 1: Core skeleton              ~1-2 weekends
Phase 2: Widevine + patching        ~2 weekends
Phase 3: Daemon + tray + watcher    ~2 weekends
Phase 4: CLI completion             ~2 weekends
Phase 5: Distribution + docs        ~1 weekend
Phase 6: Beta + release             ~2-4 weeks of calendar time

Total: ~6-8 weekends of focused work + 2-4 weeks of beta cadence
```

Phases 1-2 can partially overlap (CLI stub during Core engine work).
Phases 3 and 4 can partially overlap (CLI doesn't fully need daemon to compile, just IPC client interface defined).
Phase 5 starts when Phase 4 is in late stages.

## Decision points reserved for orchestrator (not teams)

These don't get decided inside a team; they require orchestrator (Claude in main session) input or human approval:

- Interface changes that affect more than one team
- Whether a feature gets cut for V1 vs deferred to V1.1
- Risk register updates as new risks surface
- Beta-found bug priority and team assignment
- "Are we ready to release?" final call (human Nick)
- Spec amendments (changes to the design doc itself)

## Open questions before execution

1. Does Nick want the Cloudflare Worker code as a subdirectory in the `neon` repo (`cloudflare-worker/`), or as a separate `neon-error-reporter` repo? Separate keeps `neon` code-only; subdirectory keeps everything in one place.
2. For Phase 6 beta, do we recruit testers via the pinned GitHub issue, or also post to subreddits / Discord communities (e.g., r/Helium, r/ChromiumBrowser)? More reach = more bug reports = better V2.
3. Phase 5 includes `homebrew-neon` archival — does Nick want a 30-day grace period after V2 release before archiving (in case any V1 brew users need time to migrate), or archive immediately on V2 release?
4. What's the cadence for orchestrator → user check-ins during execution? End of each phase (most coordination overhead, slowest), or only when a team is blocked or hits a decision point (least overhead, may surprise user)?

## Acceptance criteria for the plan itself

Before this plan moves to execution:

- [ ] User reads the team roster and confirms scope per team is right
- [ ] User reads the phase breakdown and confirms sequencing matches their priorities
- [ ] User answers the four open questions above
- [ ] User confirms the schedule estimate is realistic for their availability
- [ ] User approves: "begin Phase 0"

---

*This is the orchestration plan. Execution does not begin until explicit user approval. The orchestrator (Claude) will not spawn any team subagents until that approval is given.*
