# Contributing to Neon

Thanks for your interest. Neon is a small, focused project — a DRM helper for de-Googled Chromium browsers — and contributions of every size are welcome, from typo fixes to entire new browser support.

## Development setup

### Prerequisites

- **Rust 1.85+** (current MSRV; pinned in [`rust-toolchain.toml`](rust-toolchain.toml)). Install via [rustup.rs](https://rustup.rs/).
- **macOS** (x86_64 or aarch64) or **Linux** (x86_64). Other platforms compile with restrictions; see [ROADMAP.md](ROADMAP.md) for V2 / V3 platform plans.
- **On Linux:** `libgtk-3-dev` and `libayatana-appindicator3-dev` for the tray icon. (`apt install libgtk-3-dev libayatana-appindicator3-dev` on Debian/Ubuntu, `pacman -S gtk3 libayatana-appindicator` on Arch.)

### Clone + build

```sh
git clone https://github.com/nicholasraimbault/neon.git
cd neon
git switch v2-rust-rewrite
cargo build
```

### Run from source

```sh
cargo run -- --help            # full subcommand listing
cargo run -- doctor            # diagnostics
cargo run -- list-browsers     # what Neon detects on your machine
```

Use `cargo run -- <subcommand>` rather than installing locally — that way you're always running the version in the working tree.

### Tests

```sh
cargo test --lib --jobs 2      # unit tests; ~7-10s on a recent laptop
cargo test                     # add doc + integration tests
cargo test -- --ignored        # network-gated integration tests (real Mozilla manifest fetch)
```

Heavier checks (intentionally not in the default test path):

```sh
cargo tarpaulin --out Xml      # line coverage; ~1 min on a recent laptop
cargo deny check               # license + ban list
cargo audit                    # CVE database
```

### Format + lint

```sh
cargo fmt                                             # apply formatting
cargo fmt --check                                     # verify (CI gate)
cargo clippy --all-targets --jobs 2 -- -D warnings    # linter
```

`-D warnings` means **any** clippy lint fails CI. If you're adding code that legitimately can't satisfy a lint, document the `#[allow(clippy::lint_name)]` with a comment explaining why.

## Testing patterns

Neon tests heavily on Linux + macOS in CI (matrix: `ubuntu-latest`, `macos-latest`). Tests must:

1. **Never invoke the user's running compositor or D-Bus session.** No `notify-send`, no `dbus-send`, no `niri msg`, no `playerctl`, no `gsettings`. Tests that interact with these surfaces are env-var-gated to no-op by default.

2. **Never escalate privileges.** `sudo`, `pkexec`, `osascript with admin` are short-circuited via env vars. The full list of test no-op env vars:

| Env var | What it short-circuits |
|---|---|
| `NEON_TEST_ESCALATE_NOOP=1` | `platform::escalate_for_patch` and `platform::run_as_root` |
| `NEON_TEST_PATCH_NOOP=1` | `xattr -cr` and `codesign --force --deep -s -` (macOS) |
| `NEON_TEST_LIFECYCLE_NOOP=1` | `daemon::lifecycle::register/unregister` (LaunchAgent / systemd-user) |
| `NEON_TEST_POWER_NOOP=1` | `daemon::power::subscribe_wake_events` (NSWorkspace / logind D-Bus) |
| `NEON_TEST_NOTIFY_NOOP=1` | `notify::notify_*` (libnotify / NSUserNotificationCenter) |
| `NEON_TEST_DAEMON_PATCH_NOOP=1` | `daemon::drive_patch_flow` (the patch dispatcher) |
| `NEON_TEST_BROWSER_TEST_NOOP=1` | `cli::test::Plan::execute_real_browser` (headless browser spawn) |
| `NEON_TEST_LAUNCH_NOOP=1` | `cli::launch::spawn_detached` (browser launch) |

Tests set these via the `ScopedEnv` RAII guard pattern — see existing tests in `src/migration.rs` and `src/daemon/mod.rs` for the pattern. Env-mutating tests guard with a process-wide `Mutex` to avoid clobbering each other across `cargo test`'s default thread-per-test execution model.

3. **Use `tempfile::TempDir`** for any filesystem-shaped test. Never write to `~/`, `/etc/`, `/Library/`, etc. The platform team's `FsRoots` and `ScopedEnv` patterns redirect `$HOME` / `$XDG_CONFIG_HOME` to the tempdir for the test's lifetime.

4. **Synthesize fixtures** when possible. Sample CRX3 files are constructed in-test via the `zip` crate's `ZipWriter`. Fake `/Applications` trees are constructed in `TempDir`. Tests should not depend on real-world artifacts being present.

5. **Network tests are gated `#[ignore]`.** `cargo test` doesn't run them; `cargo test -- --ignored` does. Use `#[ignore = "<reason>"]` to make the gate self-documenting. Network tests verify the real Mozilla manifest URL fallback chain works against the live URL.

## Conventional commits

Neon uses [Conventional Commits](https://www.conventionalcommits.org/) for the auto-generated CHANGELOG. Commit messages must follow:

```
<type>(<scope>): <subject>

[optional body]

[optional footer]
```

**Types:**

- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation only
- `test` — adding or improving tests
- `refactor` — code change that doesn't add features or fix bugs
- `perf` — performance improvement
- `chore` — build / tooling / dependency bumps
- `ci` — CI workflow changes

**Scopes** match the team-ownership model in `docs/superpowers/teams/`:

- `core-engine`, `widevine`, `patch`, `browsers`, `lockfile`, `error`
- `platform`, `migration`
- `daemon`, `tray`, `watcher`, `ipc`, `notify`, `hooks`, `power`, `lifecycle`
- `cli`, `eme`, `log`, `config`
- `infra`, `ci`, `dist`, `worker`

**Examples:**

```
feat(cli): neon doctor --share produces pre-filled GitHub issue URL
fix(patch): restore snapshot atomically when codesign step fails
docs(roadmap): document V3 localhost-bridge stretch goal
test(widevine): boost manifest-parser fixture coverage
chore(deps): bump tray-icon to 0.24
ci: fold cargo-deny advisories check back into the deny job
```

**Breaking changes** add `!` after the type/scope and a `BREAKING CHANGE:` footer:

```
feat(ipc)!: rename Patch.force to Patch.force_while_running

BREAKING CHANGE: IPC schema. Pre-0.x clients sending `force` will get
a deserialize error. Bump your CLI to match.
```

The CHANGELOG bot uses these to auto-bump SemVer and produce the next CHANGELOG entry.

## Pull request conventions

1. **One PR, one logical change.** Don't bundle a refactor with a feature; don't bundle a typo fix with a bug fix.
2. **Title matches the conventional commit format** of the squash-merge commit. Maintainers use the PR title as the commit message; if your PR title is `feat(cli): blah`, that's the commit on master.
3. **Describe the user-visible change** in the PR body. "Why" is more important than "what."
4. **Include a test.** Bug fixes need a regression test (one that fails on master and passes on your branch). New features need test coverage proportional to surface area.
5. **CI must pass.** All four gates: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --lib`, `cargo build --release`. CI runs on Linux + macOS.
6. **Maintainers will request changes via review comments.** Address them by force-pushing to the branch (we squash-merge, so force-push history is fine). If a comment is wrong or unclear, reply — don't silently change scope.

## Filing bugs + feature requests

GitHub Issues is the bug tracker. We use templates:

- **Bug report** — `.github/ISSUE_TEMPLATE/bug.yml`. The fastest path is `neon doctor --share`, which opens a pre-filled bug template URL for you.
- **Feature request** — `.github/ISSUE_TEMPLATE/feature.yml`. Describe the use case, not the proposed solution.

Security disclosures go to the email listed in [SECURITY.md](SECURITY.md), not GitHub Issues.

## Architecture overview

Neon is a single Rust binary with two operational modes:

- **CLI mode** — `neon <subcommand>` runs one-shot operations. Each subcommand calls into the appropriate library module.
- **Daemon mode** — `neon` (no args) runs the long-lived tray daemon. Same binary, different entry point.

The codebase is split by team ownership boundary, with each team owning a slice of `src/` and an entry in `docs/superpowers/teams/<team>/handoff.md`:

| Module path | Owner | What it does |
|---|---|---|
| `src/widevine/` | core-engine | Manifest, download, extract, cache |
| `src/browsers/` | core-engine | Known list + auto-discovery + custom paths |
| `src/patch/{mod,backup}.rs` | core-engine | Atomic patch protocol, snapshot/rollback |
| `src/patch/{linux,macos}.rs` | platform | Platform-specific bundle write |
| `src/platform/` | platform | Paths trait, escalation, atomic_rename |
| `src/migration.rs` | platform | Detect + remove V0 install |
| `src/daemon/{mod,tray,watcher,ipc}.rs` | daemon | Tray + watcher + IPC |
| `src/daemon/{lifecycle,power}/` | platform | LaunchAgent / systemd / wake hooks |
| `src/notify.rs` + `src/hooks.rs` | daemon | Notifications + post-patch hooks |
| `src/cli/` | cli | Every subcommand impl |
| `src/eme/` | cli | EME error code translation |
| `src/log.rs` + `src/config.rs` | cli | Tracing + TOML config |
| `src/main.rs` | cli | Clap dispatcher |
| `src/lib.rs`, `src/error.rs`, `src/lockfile.rs` | core-engine | Library surface, error type, flock |
| `Cargo.toml`, `.github/`, `cloudflare-worker/` | infra | Build, CI, release, error reporting |

Cross-team interfaces are stable; teams don't reach into each other's internals. See the per-team handoff docs for public API contracts.

## Code of Conduct

Neon follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Be excellent to each other.

## License

By contributing, you agree your contribution is licensed under the [MIT license](LICENSE), consistent with the rest of the codebase.
