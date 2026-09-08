# 2.2 Performance Excellence Design

Date: 2026-09-08
Status: Approved for implementation
Target release: 2.2

## Problem

Silvervine 2.1.3 sits inside the published ROADMAP budgets on Linux, so a “good enough” reading would stop. That is the wrong bar.

On this maintainer host (Intel Core Ultra X7 358H, CachyOS, Helium + ungoogled-chromium), 2.1.3 looked worse than the ROADMAP *references* on several rows (media-stack wall time, idle RSS, musl binary size). Those references are not a clean 2.1.2 musl baseline: executable sizes in ROADMAP are 2.1.0 cargo-dist archives, and the command/daemon figures may not have been musl. The glibc `target/release` binary used for the 2.1.3 sample is not the artifact users download.

Excellence means: re-measure 2.1.2 musl correctly, then keep cutting Silvervine-owned cost until the profiler says the leftover is not us.

## Goals

- Beat a freshly measured **2.1.2 musl** baseline on this X7 on every Linux ROADMAP performance row (regression floor).
- Keep hunting past that floor until remaining cost is outside Silvervine or a further cut violates an invariant.
- Measure the **shipped** Linux target: `x86_64-unknown-linux-musl` with the same `+crt-static` / `musl-gcc` flags as `.github/workflows/release.yml`.
- Record every rejected cut with the measurement that killed it.
- Update ROADMAP reference numbers to the new musl results when 2.2 ships.

## Non-goals

- Replacing musl with glibc for the GitHub Linux artifact.
- Skipping `vainfo` or CDM SHA-512 to fake a faster `doctor --media-stack`.
- Dropping rustls, CRX3 verification, origin pinning, zip expansion limits, or `ldd`-on-CDM prohibition.
- Dropping the tray, D-Bus/ksni, or the user-session daemon.
- mimalloc, `panic=abort`, or fat LTO as a first move (only if profiling shows they move a scoreboard row).
- HDR / YouTube HDR helpers (L3 Widevine does not deliver service HDR).
- AUR, `.deb`, `.rpm`.
- macOS command/idle timings (no physical Mac). Darwin cargo-dist **artifact sizes** are still checked.

## Scoreboard

Build `v2.1.2` and the 2.2 candidate the same way. Host, browser set, and protocol stay fixed.

| Row | Protocol |
|---|---|
| Uncompressed musl executable | `stat` size of `silvervine` inside the musl tree |
| Compressed musl archive | `.tar.xz` size when producing a dist-equivalent archive, or the GitHub asset for 2.1.2 vs a locally packed 2.2 candidate |
| `--version` / `--help` | nine warm runs, median wall, max wall |
| `list-browsers --all` / `status` / `doctor` | nine warm runs, JSON, stdout discarded, median + max wall |
| `doctor --media-stack` | nine warm runs, median + max wall, peak RSS via `wait4` rusage |
| Idle daemon CPU | 60 s after 3 s settle, `%` of one logical core from `/proc/<pid>/stat` |
| Idle daemon RSS | `VmRSS` at start and end of that 60 s window; report max |

Idle daemon: isolated `HOME` plus `SILVERVINE_TEST_*_NOOP` for lifecycle/notify/migration/patch, so the sample does not register a second LaunchAgent/systemd unit. Optionally a second sample of the already-running user daemon, clearly labeled, never replacing the isolated number.

Browser set recorded with every scoreboard dump: Helium (`/opt/helium-browser-bin`) and ungoogled-chromium (`/usr/lib/chromium`) as of 2026-09-08.

**Floor:** no 2.2 ship if any Linux row is worse than the 2.1.2 musl baseline.

**Ceiling:** stop when all of the following hold:

1. Remaining `doctor --media-stack` wall time is `vainfo` and SHA-512 of CDM bytes we still require; no further Silvervine sequential fat.
2. Idle daemon is blocked on file descriptors, not a 100 ms sleep. Idle CPU is measurement noise.
3. The next proposed size/RSS cut (drop crate, allocator, `panic=abort`) does not move musl numbers, or it drops an invariant.
4. Every rejected cut is written down with the measurement.

ROADMAP budgets (25 ms, 2 s, 64 MiB, 10 MiB) remain ship gates. They are not the ambition.

## Architecture

This is a measurement-driven hunt, not a single feature.

```text
v2.1.2 musl baseline
        │
        ▼
profile 2.1.3/2.2 musl (perf, cargo-bloat, RSS maps)
        │
        ▼
one hypothesized cut
        │
        ▼
rebuild musl release → full scoreboard
        │
        ├─ row moved, invariants hold → keep, profile again
        └─ no movement or invariant break → revert, record, next hypothesis
```

Cuts are sequenced, not batched, so a win can be attributed.

### Hunt order

1. Establish the 2.1.2 musl baseline on this X7 (all rows).
2. Profile current musl — wall (`perf`), size (`cargo-bloat`), RSS maps. Name the owners of media-stack wall time and idle RSS.
3. Linux idle loop: `Tray::wait_for_platform_event` currently sleeps 100 ms on Linux; block on the command channel / inotify instead. macOS keeps the bounded AppKit pump.
4. `zbus` default features versus the Cargo.toml comment that only the blocking API is needed.
5. media-stack: do not SHA-512 a digest already known from the cache/ownership path; keep host probes overlapped with per-browser work; finish anything still serial.
6. Duplicate crates (`syn` 2+3, `getrandom` 0.2+0.4, `miniz_oxide` 0.8+0.9) only if bloat shows they pay for the ship binary.
7. Repeat until the ceiling rule fires.

### Invariants

- Linux ship target remains `x86_64-unknown-linux-musl` with `+crt-static` and `musl-gcc`.
- rustls only (cargo-deny still bans OpenSSL / native-tls).
- CRX3 signature + manifest SHA-512 + pinned origins stay on every CDM download path.
- Never `ldd` browser-controlled CDM ELFs.
- Zip entry-count / expansion / duplicate-path limits stay.
- `vainfo` and CDM hashing may be cached, reused, or parallelized; they are not removed.
- Tray, ksni/D-Bus, and the user-session daemon stay.

### Error handling

- A cut that fails the floor, breaks an invariant, or does not move its target row is reverted in the same cycle.
- Profiler evidence is required before claiming a win; “this should be faster” is not evidence.
- Auto-update (2.2, separate PRs) must not blow the size row. A fat updater dependency that loses the floor fails.

## Testing and proof

- Unit tests for any cache/reuse of digests and for Linux wait/pump no longer sleeping when a command is pending.
- Existing doctor/media-stack tests keep requiring the same evidence fields; faster collection must not drop checks.
- Each kept cut’s scoreboard dump (command, median, max, RSS, binary sizes) lives in the PR body.
- Rejected cuts live in `docs/superpowers/specs/2026-09-08-perf-excellence-rejected-cuts.md` (created when the first cut is rejected; not a placeholder in this spec).

## 2.2 train

Independent PRs, this hunt does not wait on and is not mixed with:

1. This performance hunt
2. Prompted auto-update (GitHub checksums, no `self_update` crate, no silent replace)
3. Pre-patch hooks plus a hook timeout
4. `silvervine log` TUI
5. CycloneDX SBOM on release

## Open measurement (not a spec hole)

Idle RSS 12 MiB vs ROADMAP 5.59 MiB was taken on a **glibc** local binary. The first hunt step replaces that number with musl 2.1.2 vs musl 2.2. Do not treat 12 vs 5.59 as proven until that exists.
