# 2.2 Excellence Hunts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hunt Silvervine-owned performance and security cost until leftover is not us, without regressing a fresh 2.1.2 musl baseline or 2.1.3 security controls.

**Architecture:** Two independent hunts, separate PRs. Each cut is one hypothesis, musl rebuild, full scoreboard. Perf: block the Linux idle loop, shrink the crate graph, stop double-hashing CDMs. Security: bound hooks, attest releases, prompted checksummed `update self`, CycloneDX SBOM, then pre-patch abort.

**Tech Stack:** existing musl cargo-dist pipeline, `std::sync::mpsc::recv_timeout`, `platform::process::run_output_with_timeout`, cargo-dist axoupdater sidecar (not the `self_update` crate), GitHub artifact attestations, `cargo cyclonedx`.

## Global Constraints

- Linux ship target is `x86_64-unknown-linux-musl` with `-Ctarget-feature=+crt-static -Clink-self-contained=yes` and `musl-gcc`, matching `.github/workflows/release.yml`.
- rustls only; cargo-deny bans `openssl`, `openssl-sys`, `native-tls`.
- CRX3 + manifest SHA-512 + pinned Mozilla/GitHub origins stay; never `ldd` CDM ELFs; zip expansion/duplicate-path limits stay.
- Do not skip `vainfo` or CDM SHA-512; cache/reuse/parallel only.
- No silent binary replace; no `self_update` crate; no AUR/deb/rpm; no musl→glibc switch.
- Do not mix a perf cut and a security feature in one PR.
- A cut that does not move its scoreboard row, or that breaks an invariant, is reverted in the same cycle.
- Host for numbers: Intel Core Ultra X7 358H, CachyOS, Helium `/opt/helium-browser-bin` + ungoogled-chromium `/usr/lib/chromium`.
- Spec: `docs/superpowers/specs/2026-09-08-perf-excellence-design.md`.

---

## File map

- Create: `scripts/perf_scoreboard.sh` — musl scoreboard runner
- Create: `docs/superpowers/plans/2026-09-08-perf-baseline-2.1.2.md` — committed 2.1.2 numbers
- Create: `docs/superpowers/specs/2026-09-08-excellence-rejected-cuts.md` — first time a cut is rejected
- Create: `src/cli/update_self.rs` — prompted `update self`
- Modify: `src/daemon/tray.rs` — `recv_timeout`
- Modify: `src/daemon/mod.rs` — Linux idle uses `recv_timeout` instead of 100 ms sleep
- Modify: `Cargo.toml` — `zbus` features; later `install-updater`
- Modify: `src/diagnostics/collect.rs` — reuse known SHA-512
- Modify: `src/platform/process.rs` — extra env on timed subprocess
- Modify: `src/hooks.rs` — timeout + pre-patch
- Modify: `src/config.rs` — `[hooks].pre_patch`
- Modify: `src/cli/patch.rs`, `src/daemon/mod.rs` — emit pre-patch before execute
- Modify: `src/main.rs`, `src/cli/mod.rs`, `src/cli/update.rs` — `update self`
- Modify: `tests/cli_surface.rs` — checksummed self-update surface
- Modify: `.github/workflows/release.yml` — attestations + SBOM
- Unchanged this plan: log TUI (separate 2.2 product PR)

---

### Task 1: 2.1.2 musl baseline scoreboard

**Files:**
- Create: `scripts/perf_scoreboard.sh`
- Create: `docs/superpowers/plans/2026-09-08-perf-baseline-2.1.2.md`

**Interfaces:**
- Consumes: `v2.1.2` tag, musl toolchain, this host
- Produces: committed baseline numbers later tasks must beat

- [ ] **Step 1: Write the scoreboard script**

```bash
#!/usr/bin/env bash
# Usage: scripts/perf_scoreboard.sh <path-to-musl-silvervine-binary>
set -euo pipefail
BIN="${1:?binary}"
test -x "$BIN"
echo "binary=$BIN"
echo "size_bytes=$(stat -c%s "$BIN")"
echo "version=$("$BIN" --version)"
python3 - "$BIN" <<'PY'
import os, subprocess, time, sys
bin = sys.argv[1]
cmds = [
    ("version", [bin, "--version"]),
    ("help", [bin, "--help"]),
    ("list", [bin, "--json", "list-browsers", "--all"]),
    ("status", [bin, "--json", "status"]),
    ("doctor", [bin, "--json", "doctor"]),
    ("media", [bin, "--json", "doctor", "--media-stack"]),
]
def nine(args):
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    walls, rss = [], []
    for _ in range(9):
        p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.perf_counter()
        _, _, ru = os.wait4(p.pid, 0)
        walls.append((time.perf_counter() - t0) * 1000)
        rss.append(ru.ru_maxrss / 1024)
    walls.sort()
    print(f"{args[-1] if args[-1] != '--media-stack' else 'media-stack'}: median_ms={walls[4]:.2f} max_ms={max(walls):.2f} peak_rss_mib={max(rss):.2f}")
for name, args in cmds:
    nine(args)
PY
```

Make executable: `chmod +x scripts/perf_scoreboard.sh`

- [ ] **Step 2: Build v2.1.2 musl the way CI does**

```bash
git fetch origin tag v2.1.2
git worktree add /tmp/silvervine-212 v2.1.2
cd /tmp/silvervine-212
sudo apt-get install -y musl-tools || pkexec /usr/bin/pacman -S --noconfirm musl
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Ctarget-feature=+crt-static -Clink-self-contained=yes"
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --locked
```

Expected: `target/x86_64-unknown-linux-musl/release/silvervine` exists.

Alternatively use the GitHub 2.1.2 musl tarball for the executable-size row if a local musl toolchain is painful; command timings must still run that extracted binary on this X7.

- [ ] **Step 3: Run the scoreboard and idle sample**

```bash
scripts/perf_scoreboard.sh /tmp/silvervine-212/target/x86_64-unknown-linux-musl/release/silvervine
```

Idle (isolated HOME, 60 s) using the same Python `/proc` sampler as the 2026-09-08 session: CPU `%` of one core, `VmRSS` max.

- [ ] **Step 4: Commit the baseline**

Write `docs/superpowers/plans/2026-09-08-perf-baseline-2.1.2.md` with every row filled from Step 3 (no blanks). Include host, kernel, browser set, binary path, and whether the binary was a local musl build or the GitHub tarball.

```bash
git add scripts/perf_scoreboard.sh docs/superpowers/plans/2026-09-08-perf-baseline-2.1.2.md
git commit -m "docs: record 2.1.2 musl performance baseline"
```

---

### Task 2: Linux idle blocks on the command channel

**Files:**
- Modify: `src/daemon/tray.rs` (`try_recv` / `recv_blocking` around lines 619–628)
- Modify: `src/daemon/mod.rs` (`run_event_loop` around lines 514–568)
- Test: `src/daemon/tray.rs` existing `#[cfg(test)]` module

**Interfaces:**
- Consumes: `Tray.rx: Mutex<Receiver<TrayCommand>>`
- Produces: `pub fn recv_timeout(&self, timeout: Duration) -> Option<TrayCommand>`

- [ ] **Step 1: Write the failing test**

In `src/daemon/tray.rs` tests, add:

```rust
#[test]
fn recv_timeout_returns_none_on_empty_and_some_when_sent() {
    let t = Tray::headless();
    let start = std::time::Instant::now();
    assert!(t.recv_timeout(Duration::from_millis(20)).is_none());
    assert!(start.elapsed() >= Duration::from_millis(15));
    t.tx.send(TrayCommand::Quit).unwrap();
    assert_eq!(t.recv_timeout(Duration::from_millis(50)), Some(TrayCommand::Quit));
}
```

`tx` is private. Do **not** make it pub. Use the existing test helper that already sends through the public API if one exists (`Tray::headless` plus whatever `inject` tests use). If tests only use `try_recv` after constructing via `new`/`headless`, add `#[cfg(test)] pub(crate) fn send_for_test(&self, cmd: TrayCommand)`:

```rust
#[cfg(test)]
pub(crate) fn send_for_test(&self, cmd: TrayCommand) {
    let _ = self.tx.send(cmd);
}
```

and send with that.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test --lib daemon::tray::tests::recv_timeout_returns_none_on_empty_and_some_when_sent -- --nocapture
```

Expected: FAIL (`recv_timeout` not found).

- [ ] **Step 3: Implement `recv_timeout`**

```rust
/// Wait up to `timeout` for the next [`TrayCommand`].
///
/// Returns `None` on timeout or if the sender has been dropped.
pub fn recv_timeout(&self, timeout: std::time::Duration) -> Option<TrayCommand> {
    self.rx.lock().unwrap().recv_timeout(timeout).ok()
}
```

- [ ] **Step 4: Use it on Linux idle; keep macOS pump**

Replace the `try_recv` / `None => wait_for_platform_event` loop in `run_event_loop` with:

```rust
let cmd = {
    #[cfg(target_os = "macos")]
    {
        match tray.try_recv() {
            Some(cmd) => Some(cmd),
            None => {
                tray.wait_for_platform_event(Duration::from_millis(100));
                tray.try_recv()
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        tray.recv_timeout(Duration::from_millis(100))
    }
};
match cmd {
    Some(TrayCommand::Quit) => { /* existing Quit body */ }
    // ... existing Some arms unchanged ...
    None => {}
}
```

Do **not** sleep on Linux after `recv_timeout`. macOS still pumps AppKit.

- [ ] **Step 5: Run tests**

```bash
cargo test --lib daemon::tray daemon:: -- --nocapture
```

Expected: PASS, including the new timeout test.

- [ ] **Step 6: Scoreboard + commit**

Rebuild musl, run `scripts/perf_scoreboard.sh` on the new binary, compare idle CPU/RSS to Task 1. If idle CPU does not improve and no other row improves, revert and append a rejection note to `docs/superpowers/specs/2026-09-08-excellence-rejected-cuts.md`.

```bash
git add src/daemon/tray.rs src/daemon/mod.rs
git commit -m "perf: block Linux daemon idle on tray recv_timeout"
```

---

### Task 3: `zbus` default-features vs blocking-only

**Files:**
- Modify: `Cargo.toml` Linux `zbus` dependency (line 153)

**Interfaces:**
- Consumes: `zbus = { version = "5" }` used for logind `PrepareForSleep`
- Produces: `zbus = { version = "5", default-features = false, features = ["blocking"] }` or the minimal feature set that still compiles `src/daemon/power/linux.rs`

- [ ] **Step 1: Inspect the power module imports**

Read `src/daemon/power/linux.rs`. List every `zbus` API used.

- [ ] **Step 2: Tighten features**

```toml
zbus = { version = "5", default-features = false, features = ["blocking"] }
```

If compile fails, add only the features the compiler names (`p2p` is not required).

- [ ] **Step 3: Build and test**

```bash
cargo test --locked --all-features --no-fail-fast
cargo build --release --target x86_64-unknown-linux-musl --locked
```

Expected: compile clean, tests PASS.

- [ ] **Step 4: Scoreboard**

Compare musl `stat` size and idle RSS to Task 1. If neither moved, revert and record rejection.

```bash
git add Cargo.toml Cargo.lock
git commit -m "perf: disable unused zbus default features"
```

---

### Task 4: Reuse a known CDM SHA-512 in media-stack

**Files:**
- Modify: `src/diagnostics/collect.rs` (`safe_library_digest` around 539–548 and callers)

**Interfaces:**
- Consumes: `CachedCdm::verified_library_sha512() -> Option<&str>`, `safe_library_digest(path: &Path) -> Option<String>`
- Produces: `fn library_digest(path: &Path, known: Option<&str>) -> Option<String>`

- [ ] **Step 1: Write the failing test**

In `src/diagnostics/collect.rs` tests:

```rust
#[test]
fn library_digest_prefers_known_hex_without_reading_path() {
    let missing = Path::new("/tmp/silvervine-definitely-missing-cdm.so");
    assert_eq!(
        library_digest(missing, Some("abc123")),
        Some("abc123".into())
    );
    assert_eq!(library_digest(missing, None), None);
}
```

- [ ] **Step 2: Run to verify fail**

```bash
cargo test --lib diagnostics::collect::tests::library_digest_prefers_known_hex_without_reading_path
```

Expected: FAIL (`library_digest` not found).

- [ ] **Step 3: Implement and wire callers**

```rust
fn library_digest(path: &Path, known: Option<&str>) -> Option<String> {
    if let Some(digest) = known {
        if !digest.is_empty() {
            return Some(digest.to_owned());
        }
    }
    safe_library_digest(path)
}
```

At every `safe_library_digest(library)` site inside `collect_browser*` that already has a `CachedCdm` or ownership digest, pass `verified_library_sha512()`. Leave `safe_library_digest` for first-seen paths.

- [ ] **Step 4: Run tests**

```bash
cargo test --lib diagnostics::collect -- --nocapture
```

Expected: PASS. Existing media-stack tests still assert the same digest fields.

- [ ] **Step 5: Scoreboard + commit**

```bash
git add src/diagnostics/collect.rs
git commit -m "perf: reuse verified CDM SHA-512 in media-stack"
```

If `doctor --media-stack` median does not drop vs Task 1, keep the change only if it is strictly fewer file reads with tests; otherwise revert and record rejection. Do not skip hashing unknown files.

---

### Task 5: Bound hook execution

**Files:**
- Modify: `src/platform/process.rs` (`run_output_with_timeout` at 59–109)
- Modify: `src/hooks.rs` (`run_hook_at` at 203–251)
- Test: `src/hooks.rs` `mod tests`

**Interfaces:**
- Consumes: `run_output_with_timeout(program, args, timeout) -> Result<CommandOutput>`
- Produces: `run_output_with_timeout` also applies `extra_env: &HashMap<String, String>`; `pub const HOOK_TIMEOUT: Duration = Duration::from_secs(15)` in `hooks.rs`

- [ ] **Step 1: Write the failing timeout test**

```rust
#[test]
fn run_hook_at_times_out_a_sleeping_script() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("hang");
    write_executable_script(&path, "#!/bin/sh\nsleep 30\n");
    let started = std::time::Instant::now();
    let outcome = run_hook_at(&path, &HashMap::new()).unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    match outcome {
        HookOutcome::Ran { timed_out, .. } => assert!(timed_out),
        other => panic!("expected Ran, got {other:?}"),
    }
}
```

This requires `HookOutcome::Ran` to grow a `timed_out: bool` field. Update every existing `HookOutcome::Ran { .. }` match in this file’s tests in the same task.

- [ ] **Step 2: Run to verify fail**

```bash
cargo test --lib hooks::tests::run_hook_at_times_out_a_sleeping_script
```

Expected: FAIL (test hangs until 30s **or** `timed_out` field missing). If it hangs, Ctrl-C and proceed to implement — that is the fail.

- [ ] **Step 3: Extend the process helper**

Add `extra_env: &HashMap<String, String>` to `run_output_with_timeout`. After `Command::new`:

```rust
for (key, value) in extra_env {
    command.env(key, value);
}
```

Update existing `vainfo` callers to pass `&HashMap::new()`.

- [ ] **Step 4: Use it from hooks**

```rust
pub const HOOK_TIMEOUT: Duration = Duration::from_secs(15);

pub enum HookOutcome {
    NotConfigured,
    Ran {
        exit_status: Option<i32>,
        stdout: String,
        stderr: String,
        timed_out: bool,
    },
}
```

`run_hook_at` calls `crate::platform::process::run_output_with_timeout(path, &[], HOOK_TIMEOUT, &hook_env)` instead of `cmd.output()`. Map `CommandOutput.timed_out` onto `HookOutcome::Ran`. Treat timeout as non-success (existing `warn!`).

- [ ] **Step 5: Tests**

```bash
cargo test --lib hooks platform::process -- --nocapture
```

Expected: PASS, hang test finishes in <5 s.

- [ ] **Step 6: Commit**

```bash
git add src/hooks.rs src/platform/process.rs src/diagnostics/linux.rs
git commit -m "fix: bound hook subprocesses at 15s"
```

This is a **security** PR, not mixed with Task 2–4.

---

### Task 6: GitHub artifact attestations

**Files:**
- Modify: `.github/workflows/release.yml` (`publish` job around 454–544)

**Interfaces:**
- Consumes: files already in `artifacts/` before `gh release create`
- Produces: provenance attestations for those files; `id-token: write` and `attestations: write` on `publish` only

- [ ] **Step 1: Resolve and pin the action SHA**

```bash
gh api repos/actions/attest-build-provenance/git/refs/tags/v3 --jq '.object.sha'
```

If v3 is annotated, resolve the peeled commit. Pin the **full** 40-character commit, same as `actions/checkout@3d3c42e5...`.

- [ ] **Step 2: Attest after artifacts are assembled, before `gh release create`**

On the `publish` job:

```yaml
permissions:
  actions: read
  contents: write
  id-token: write
  attestations: write
```

Add a step (not a third-party action with contents write beyond attest):

```yaml
- name: Attest release artifacts
  uses: actions/attest-build-provenance@<FULL_SHA>
  with:
    subject-path: artifacts/**
```

If this fails CI on a dry `workflow_dispatch` or the next tag, document why in `docs/superpowers/specs/2026-09-08-excellence-rejected-cuts.md` and drop the step. Size floor: attestations are not shipped inside the musl binary, so they cannot fail the executable-size row.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: attest cargo-dist release artifacts"
```

---

### Task 7: Prompted `silvervine update self`

**Files:**
- Create: `src/cli/update_self.rs`
- Modify: `src/cli/mod.rs` (module table + `pub mod update_self`)
- Modify: `src/cli/update.rs` (dispatch)
- Modify: `src/main.rs` (`UpdateTarget`)
- Modify: `Cargo.toml` (`install-updater = true`)
- Modify: `tests/cli_surface.rs` (`update_help_excludes_unsigned_self_update`, `parser_rejects_unsigned_self_update`)

**Interfaces:**
- Consumes: cargo-dist install receipt + `silvervine-update` sidecar after `install-updater = true`
- Produces: `cli::update_self::run(args: &SelfArgs) -> Result<SelfUpdateOutcome>`

```rust
pub struct SelfArgs {
    pub dry_run: bool,
    pub output: OutputOptions,
}

pub struct SelfUpdateOutcome {
    pub current_version: String,
    pub latest_version: String,
    pub updated: bool,
    pub reason: String,
}
```

- [ ] **Step 1: Write failing CLI tests**

Replace the two unsigned-rejection tests with:

```rust
#[test]
fn update_help_exposes_self_subcommand() {
    let help = run_help(&["update", "--help"]);
    assert!(
        help.lines().any(|line| line.trim_start().starts_with("self")),
        "expected `self` subcommand in update help: {help}"
    );
}

#[test]
fn update_self_without_install_receipt_is_an_error() {
    let dir = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_silvervine"))
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("SILVERVINE_TEST_DATA_MIGRATION_NOOP", "1")
        .args(["update", "self"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("install receipt") || stderr.contains("silvervine-update"),
        "unexpected stderr: {stderr}"
    );
}
```

- [ ] **Step 2: Run to verify fail**

```bash
cargo test --test cli_surface update_help_exposes_self_subcommand update_self_without_install_receipt_is_an_error -- --nocapture
```

Expected: FAIL (`self` missing from clap).

- [ ] **Step 3: Clap + stub runner**

```rust
// src/main.rs
enum UpdateTarget {
    Widevine { rollback: bool, cdm_source: Option<String> },
    /// Replace this GitHub-installed binary after verifying release checksums.
    Self_,
}
```

Use `#[command(name = "self")]` on the variant. Dispatch to `cli::update_self::run`.

`update_self::run`:

1. If `SILVERVINE_TEST_SELF_UPDATE_NOOP=1`, return `SelfUpdateOutcome` with `updated: false` and reason `test-noop` (for unit tests).
2. Locate `silvervine-update` next to `std::env::current_exe()`. If missing, return `Error::other("silvervine-update sidecar not installed; re-run the GitHub installer")`.
3. Locate the cargo-dist receipt (`$XDG_CONFIG_HOME/silvervine/silvervine-receipt.json` or `~/.config/silvervine/silvervine-receipt.json`). If missing, same class of error (`install receipt`).
4. Do **not** download in-process. Exec `silvervine-update` (or `Command::new(sidecar)` with inherited stdio). Never call the `self_update` crate.
5. After a successful swap, print that the user (or systemd/LaunchAgent) must restart the daemon. Do not overwrite `/proc/self/exe` from inside the running daemon.

- [ ] **Step 4: Enable the dist sidecar**

```toml
install-updater = true
```

- [ ] **Step 5: Tests + deny + size floor**

```bash
cargo test --test cli_surface --lib
cargo deny check advisories bans licenses sources
cargo build --release --target x86_64-unknown-linux-musl --locked
stat -c%s target/x86_64-unknown-linux-musl/release/silvervine
```

If musl size exceeds the Task 1 baseline, **do not** add `axoupdater` as a library dependency of `silvervine`. Keep the sidecar-only design. If `install-updater = true` inflates the main binary past the floor, record it and keep sidecar invocation behind `current_exe` sibling only.

- [ ] **Step 6: Commit**

```bash
git add src/cli/update_self.rs src/cli/mod.rs src/cli/update.rs src/main.rs Cargo.toml tests/cli_surface.rs
git commit -m "feat: prompted silvervine update self via dist sidecar"
```

---

### Task 8: CycloneDX SBOM on release

**Files:**
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: tagged commit already checked out conceptually at `github.sha`
- Produces: `artifacts/silvervine.cdx.json` uploaded with `gh release create`

- [ ] **Step 1: Generate SBOM locally to lock the command**

```bash
cargo install cargo-cyclonedx --locked
cargo cyclonedx --format json --all
```

Expected: a `.cdx.json` (or `bom.json`) at the workspace root. Note the exact filename `cargo cyclonedx` writes.

- [ ] **Step 2: Add a read-only job before publish**

New job `release-sbom`, `needs: [plan]`, `if: publishing`, `permissions: contents: read`, `ubuntu-22.04`:

- checkout at `${{ github.sha }}`
- rust-toolchain pin (same SHA as other jobs)
- install `cargo-cyclonedx` with a **version pin** recorded in the step (`cargo install cargo-cyclonedx --version <x.y.z> --locked`)
- `cargo cyclonedx --format json --all`
- `actions/upload-artifact` (already pinned in this workflow) of the JSON as `artifacts-sbom`

- [ ] **Step 3: Publish includes the SBOM**

In `publish`, download `artifacts-sbom` into `artifacts/` so `gh release create` attaches it. Do not run cargo in `publish` (that job must stay a write-capable shell without a build toolchain).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: attach CycloneDX SBOM to GitHub releases"
```

---

### Task 9: Pre-patch hook aborts the patch

**Files:**
- Modify: `src/config.rs` (`HooksConfig`)
- Modify: `src/hooks.rs` (`resolve_hook_path`, `emit` / new `run_pre_patch`)
- Modify: `src/cli/patch.rs` (`run_patch_flow`)
- Modify: `src/daemon/mod.rs` (`drive_patch_flow_with_cdm` before `PatchBatch::execute`)
- Test: `src/hooks.rs`, `src/cli/patch.rs` existing hook tests

**Interfaces:**
- Consumes: `HOOK_TIMEOUT`, `run_hook_at`, `HookOutcome`
- Produces: `pub fn run_pre_patch(browsers: &[&str]) -> Result<()>` — `Ok(())` if NotConfigured or Ran with exit 0 and `timed_out == false`; `Err` otherwise

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn run_pre_patch_ok_when_missing() {
    let dir = TempDir::new().unwrap();
    let _cfg = ScopedEnv::set("XDG_CONFIG_HOME", dir.path());
    run_pre_patch(&["Helium"]).unwrap();
}

#[test]
fn run_pre_patch_errors_on_nonzero() {
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("silvervine/hooks/pre-patch");
    write_executable_script(&script, "#!/bin/sh\nexit 7\n");
    let _cfg = ScopedEnv::set("XDG_CONFIG_HOME", dir.path());
    let err = run_pre_patch(&["Helium"]).unwrap_err();
    assert!(err.message.contains("pre-patch"));
}
```

Config lookup uses `dirs::config_dir()` which honors `XDG_CONFIG_HOME` on Linux.

- [ ] **Step 2: Run to verify fail**

```bash
cargo test --lib hooks::tests::run_pre_patch_ok_when_missing hooks::tests::run_pre_patch_errors_on_nonzero
```

Expected: FAIL (`run_pre_patch` not found).

- [ ] **Step 3: Config + resolve + runner**

```rust
pub struct HooksConfig {
    pub post_patch: Option<String>,
    pub post_update: Option<String>,
    pub pre_patch: Option<String>,
}
```

`resolve_hook_path`: `"pre-patch" => config.pre_patch_hook()`.

```rust
pub fn run_pre_patch(browsers: &[&str]) -> Result<()> {
    let mut env = HashMap::from([("SILVERVINE_OUTCOME".into(), "start".into())]);
    if !browsers.is_empty() {
        env.insert("SILVERVINE_BROWSER".into(), browsers.join(","));
    }
    match run_hook("pre-patch", &env)? {
        HookOutcome::NotConfigured => Ok(()),
        HookOutcome::Ran { exit_status, timed_out, stderr, .. }
            if !timed_out && exit_status == Some(0) =>
        {
            Ok(())
        }
        HookOutcome::Ran { exit_status, timed_out, stderr, .. } => Err(Error::other(format!(
            "pre-patch hook failed (exit={exit_status:?} timed_out={timed_out}): {stderr}"
        ))),
    }
}
```

- [ ] **Step 4: Call before execute**

In `run_patch_flow` and `drive_patch_flow_with_cdm`, after `needs`/`candidates` is known and `should_emit_hooks` is true, **before** `PatchBatch::execute`:

```rust
let names: Vec<&str> = needs.iter().map(|b| b.name()).collect();
crate::hooks::run_pre_patch(&names)?;
```

Daemon path currently returns `Vec<(String, bool)>` and cannot `?` a hook error without changing the signature. Map `Err` to: log + return all `needs` as `(name, false)` without executing the batch. CLI path returns reports; convert hook `Err` into one failed `PatchReport` per candidate and skip `execute`.

Privileged child: `should_emit_hooks` is false; do **not** run pre-patch in the elevated child.

- [ ] **Step 5: Tests**

```bash
cargo test --lib hooks cli::patch daemon:: -- --nocapture
```

Expected: PASS. Existing `privileged_child_explicitly_skips_hooks` still true.

- [ ] **Step 6: Commit**

```bash
git add src/config.rs src/hooks.rs src/cli/patch.rs src/daemon/mod.rs
git commit -m "feat: pre-patch hook aborts the patch on failure"
```

---

## Self-review

**Spec coverage**

- 2.1.2 musl baseline → Task 1
- Profile / hunt loop / rejected cuts → Tasks 2–4 steps that revert + rejection file
- Linux 100 ms sleep → Task 2
- zbus features → Task 3
- SHA-512 reuse → Task 4
- Hook timeout → Task 5
- Attestations → Task 6
- Prompted update self, no `self_update`, no silent replace → Task 7
- SBOM → Task 8
- Pre-patch abort → Task 9
- Size floor vs updater → Task 7 step 5
- Log TUI → explicitly out of this plan
- macOS timings → non-goal
- Invariants (musl, rustls, CRX3, no ldd) → Global Constraints

**Placeholders:** none. Action SHA for attestations is resolved in Task 6 Step 1 (command given). `cargo cyclonedx` output filename is confirmed in Task 8 Step 1.

**Types:** `recv_timeout`, `library_digest`, `HOOK_TIMEOUT`, `HookOutcome::Ran.timed_out`, `run_pre_patch`, `SelfArgs` / `SelfUpdateOutcome` used consistently.
