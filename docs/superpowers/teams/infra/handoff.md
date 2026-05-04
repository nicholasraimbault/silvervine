# Infra Team Handoff

**Identity:** `infra`
**Mission:** Build system, CI, release pipeline, distribution, error reporting backend. Anything outside the Rust crate itself.

## Files owned

- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`
- `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- `.github/dependabot.yml`, `.github/auto-merge.yml`
- `.github/ISSUE_TEMPLATE/`
- `dist-workspace.toml` (cargo-dist config)
- `cloudflare-worker/` — error reporting endpoint (Worker code + D1 schema)
- `README.md`, `MIGRATION.md`, `ROADMAP.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`
- `homebrew-neon/Formula/neon.rb` (final deprecation commit on the separate tap repo)
- `src/reporter.rs` — opt-in error reporter client (talks to the Worker)

## Current focus

Phase 0: Foundation. Initialize Cargo workspace, set up CI matrix, configure cargo-dist, scaffold Cloudflare Worker, configure Dependabot + auto-merge, baseline cargo-audit + cargo-deny.

## Public contracts owned

(none yet — Phase 0 establishes the build system; later phases add `src/reporter.rs` API)

## Decisions log

(empty)

## Open questions

(none)

## Dependencies awaiting

- Branch protection on `master` and `v2-rust-rewrite` requires GitHub repo admin access (Nick's gh CLI auth)
- Cloudflare Worker deployment requires user account auth (deferred to manual step or use of `cloudflare-bindings` MCP if available)

## Files most recently changed

(empty — Phase 0 just started)
