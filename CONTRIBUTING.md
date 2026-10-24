# Contributing to Silvervine

Thanks for your interest. Silvervine is a small, focused project — a DRM helper for de-Googled Chromium browsers — and contributions of every size are welcome, from typo fixes to entire new browser support.

## Development setup

### Prerequisites

- **Rust 1.88+** (current MSRV; declared in [`Cargo.toml`](Cargo.toml) and
  enforced in CI). Install via [rustup.rs](https://rustup.rs/).
- **Linux x64**, **macOS** (Intel or Apple Silicon), or **Windows x64**. Windows builds need Visual Studio Build Tools with Desktop development with C++ and a Windows SDK. The public installer needs neither.

### Clone + build

```sh
git clone https://github.com/nicholasraimbault/silvervine.git
cd silvervine
git switch master
cargo build
```

### Run from source

```sh
cargo run -- --help            # full subcommand listing
cargo run -- doctor            # diagnostics
cargo run -- list-browsers     # what Silvervine detects on your machine
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

### Performance validation

Performance-sensitive changes must be measured from
`cargo build --release --locked`; debug builds and `cargo run` are not useful
comparisons. Use the budgets and current reference results in
[docs/performance.md](docs/performance.md).

Warm each command once, then collect nine runs and report median wall time,
maximum wall time, and peak resident memory. Redirect command output so
terminal rendering is not part of the measurement:

```sh
# Linux
/usr/bin/time -v target/release/silvervine --json doctor --media-stack >/dev/null

# macOS
/usr/bin/time -lp target/release/silvervine --json doctor --media-stack >/dev/null
```

Measure `--version`, `--help`, `--json list-browsers --all`, `--json status`,
`--json doctor`, and `--json doctor --media-stack`. Record the browser set and
host hardware with the results. For daemon changes, allow startup to settle,
then sample process CPU and RSS over 60 idle seconds; CPU is reported as a
percentage of one logical core. Compare before and after on the same host.

Release footprint checks use the uncompressed executable and compressed
cargo-dist archive for all four shipping targets. A performance PR must
explain any budget regression rather than averaging it away across platforms.

## Testing patterns

Native CI runs on Linux, macOS, and Windows. The release gate covers all four shipping targets (including both macOS architectures). Tests must:

1. **Never invoke the user's running compositor or D-Bus session.** No `notify-send`, no `dbus-send`, no `niri msg`, no `playerctl`, no `gsettings`. Tests that interact with these surfaces are env-var-gated to no-op by default.

2. **Never escalate privileges.** `sudo`, `pkexec`, `osascript with admin` are short-circuited via env vars. The full list of test no-op env vars:

| Env var | What it short-circuits |
|---|---|
| `SILVERVINE_TEST_DATA_MIGRATION_NOOP=1` | startup Neon V2 data-directory migration |
| `SILVERVINE_TEST_ESCALATE_NOOP=1` | `platform::escalate_for_patch` and `platform::run_as_root` |
| `SILVERVINE_TEST_LIFECYCLE_NOOP=1` | `daemon::lifecycle::register/unregister` (LaunchAgent / systemd-user) |
| `SILVERVINE_TEST_POWER_NOOP=1` | `daemon::power::subscribe_wake_events` (NSWorkspace / logind D-Bus) |
| `SILVERVINE_TEST_NOTIFY_NOOP=1` | `notify::notify_*` (libnotify / NSUserNotificationCenter) |
| `SILVERVINE_TEST_DAEMON_PATCH_NOOP=1` | `daemon::drive_patch_flow` (the patch dispatcher) |
| `SILVERVINE_TEST_BROWSER_TEST_NOOP=1` | manual and automated `silvervine test` browser launches |
| `SILVERVINE_TEST_LAUNCH_NOOP=1` | `cli::launch::spawn_detached` (browser launch) |

Tests set these via the `ScopedEnv` RAII guard pattern — see existing tests in `src/migration.rs` and `src/daemon/mod.rs` for the pattern. Env-mutating tests guard with a process-wide `Mutex` to avoid clobbering each other across `cargo test`'s default thread-per-test execution model.

3. **Use `tempfile::TempDir`** for any filesystem-shaped test. Never write to `~/`, `/etc/`, `/Library/`, etc. The platform team's `FsRoots` and `ScopedEnv` patterns redirect `$HOME` / `$XDG_CONFIG_HOME` to the tempdir for the test's lifetime.

4. **Synthesize fixtures** when possible. Sample CRX3 files are constructed in-test via the `zip` crate's `ZipWriter`. Fake `/Applications` trees are constructed in `TempDir`. Tests should not depend on real-world artifacts being present.

5. **Network tests are gated `#[ignore]`.** `cargo test` doesn't run them; `cargo test -- --ignored` does. Use `#[ignore = "<reason>"]` to make the gate self-documenting. Network tests verify that both fixed Mozilla manifest HTTPS origins work live; mutable on-disk snapshots are never fallback trust roots.

## Conventional commits

Silvervine uses [Conventional Commits](https://www.conventionalcommits.org/) for the auto-generated CHANGELOG. Commit messages must follow:

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

**Scopes** map to the module surface in `src/`:

- `widevine`, `patch`, `browsers`, `lockfile`, `error`
- `platform`, `migration`
- `daemon`, `tray`, `watcher`, `ipc`, `notify`, `hooks`, `power`, `lifecycle`
- `cli`, `eme`, `log`, `config`
- `ci`, `dist`, `deps`

**Examples:**

```
feat(cli): silvervine doctor --share produces pre-filled GitHub issue URL
fix(patch): restore snapshot atomically when codesign step fails
docs(roadmap): document a future platform goal
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

Update CHANGELOG.md with release-facing changes. There is no release-please workflow; version bumps and RC/stable publication are explicit maintainer steps.

## Pull request conventions

1. **One PR, one logical change.** Don't bundle a refactor with a feature; don't bundle a typo fix with a bug fix.
2. **Title matches the conventional commit format** of the squash-merge commit. Maintainers use the PR title as the commit message; if your PR title is `feat(cli): blah`, that's the commit on master.
3. **Describe the user-visible change** in the PR body. "Why" is more important than "what."
4. **Include a test.** Bug fixes need a regression test (one that fails on master and passes on your branch). New features need test coverage proportional to surface area.
5. **CI must pass.** All four gates: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --lib`, `cargo build --release`. CI runs on Linux, macOS, and Windows, with dependency auditing and MSRV checks as additional gates.
6. **Maintainers will request changes via review comments.** Address them by force-pushing to the branch (we squash-merge, so force-push history is fine). If a comment is wrong or unclear, reply — don't silently change scope.

## Filing bugs + feature requests

GitHub Issues is the bug tracker. We use templates:

- **Bug report** — `.github/ISSUE_TEMPLATE/bug.yml`. The fastest path is `silvervine doctor --share`, which opens a pre-filled bug template URL for you.
- **Feature request** — `.github/ISSUE_TEMPLATE/feature.yml`. Describe the use case, not the proposed solution.

Security disclosures use the private advisory link in [SECURITY.md](SECURITY.md).

## Architecture overview

Silvervine is one Rust binary with three operational modes:

- **Terminal UI** — `silvervine tui` manages the same operations interactively, with explicit saves for configuration changes.
- **CLI mode** — `silvervine <subcommand>` runs one-shot operations. Each subcommand calls into the appropriate library module.
- **Daemon mode** — `silvervine` (no args) runs the long-lived tray daemon. Same binary, different entry point.

The codebase is split into module-level slices of `src/`:

| Module path | What it does |
|---|---|
| `src/widevine/` | Manifest, download, extract, cache |
| `src/browsers/` | Known list + auto-discovery + custom paths |
| `src/patch/{mod,backup}.rs` | Atomic CDM publication protocol and Linux snapshot/rollback |
| `src/patch/{linux,macos,windows}.rs` | Platform-specific CDM placement |
| `src/platform/` | Paths trait, escalation, atomic_rename |
| `src/migration.rs` | Detect + remove V1 install |
| `src/daemon/{mod,tray,watcher,ipc}.rs` | Tray + watcher + IPC |
| `src/daemon/{lifecycle,power}/` | LaunchAgent / systemd-user / Windows Startup / wake hooks |
| `src/notify.rs` + `src/hooks.rs` | Notifications + post-patch hooks |
| `src/cli/` | Every subcommand impl |
| `src/eme/` + `src/diagnostics/` | EME translation/live probe + source-labeled passive diagnostics |
| `src/log.rs` + `src/config.rs` | Tracing + TOML config |
| `src/main.rs` | Clap dispatcher |
| `src/lib.rs`, `src/error.rs`, `src/lockfile.rs` | Library surface, error type, flock |
| `Cargo.toml`, `.github/` | Build, CI, release |

Module interfaces are kept stable across changes; rustdoc on the public types is the contract.

## Release validation

Before tagging an RC, require formatting, strict lint, full tests, the dependency
audit, MSRV checks, and all shipping-target release builds. `dist plan
--allow-dirty --output-format=json` must mark the RC as a prerelease and include
both installers and the Windows zip. Preserve the manually hardened release
workflow; do not overwrite it with `dist init` / `dist generate`.

The latest stable installer must continue to target stable releases. Do not
promote an RC with `--latest`, or enable preview for existing configurations.
Test the normal-user [Windows checklist](docs/windows.md) on hardware before
promoting 2.3 stable. Keep manual test results distinct from automated CI results.

The former bridge experiment is preserved at
[archive/experimental-bridge](https://github.com/nicholasraimbault/silvervine/tree/archive/experimental-bridge).
It is unsupported and excluded from releases.

## Code of Conduct

Silvervine follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Be excellent to each other.

## License

By contributing, you agree your contribution is licensed under the [MIT license](LICENSE), consistent with the rest of the codebase.
