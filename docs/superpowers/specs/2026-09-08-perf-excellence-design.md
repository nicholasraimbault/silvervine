# 2.2 Excellence Design (Performance + Security)

Date: 2026-09-08
Status: Approved for implementation
Target release: 2.2

## Problem

Silvervine 2.1.3 is *fine*: Linux numbers sit inside ROADMAP budgets, `cargo deny` is clean, CDM trust is pinned, and there are no open GitHub vulnerability alerts. Fine is the wrong bar.

**Performance.** On this maintainer host (Intel Core Ultra X7 358H, CachyOS, Helium + ungoogled-chromium), 2.1.3 looked worse than ROADMAP *references* on media-stack wall time, idle RSS, and musl size. Those references are not a clean 2.1.2 musl baseline (executable sizes are 2.1.0 archives; command figures may not be musl). The glibc `target/release` sample is not what users download.

**Security.** The helper can `pkexec`, overwrite browser CDM trees, and is installed with `curl | sh`. Hooks wait forever on `Command::output`. `silvervine update self` is deliberately rejected as unsigned. cargo-dist `install-updater` is off. There is no SBOM and no artifact provenance beyond `sha256.sum` sitting next to the tarball. Distro packages (AUR/deb/rpm) are out; GitHub is the channel, so that channel has to be excellent.

Excellence: hunt Silvervine-owned cost and Silvervine-owned risk until the leftover is not us.

## Goals

- **Perf floor:** beat a freshly measured 2.1.2 musl baseline on this X7 on every Linux ROADMAP performance row.
- **Perf ceiling:** keep cutting until remaining cost is outside Silvervine or a further cut violates an invariant.
- **Security floor:** do not regress 2.1.3 controls (deny, rustls, CRX3, origins, zip limits, no `ldd` on CDM, no open alerts, no unsigned self-replace).
- **Security ceiling:** GitHub install-once can update itself with the same trust as the installer (checksums; attestations if they do not blow the size floor); hooks cannot wedge the daemon; pre-patch can abort; every release ships a CycloneDX SBOM.
- Measure the **shipped** Linux target: `x86_64-unknown-linux-musl` with `+crt-static` / `musl-gcc` as in `release.yml`.
- Record every rejected cut (perf or security) with the evidence that killed it.
- Update ROADMAP refs and SECURITY.md known-limitations when 2.2 ships.

## Non-goals

- Replacing musl with glibc for the GitHub Linux artifact.
- Skipping `vainfo` or CDM SHA-512 to fake a faster `doctor --media-stack`.
- Dropping rustls, CRX3, origin pinning, zip limits, or the `ldd`-on-CDM ban.
- Dropping the tray, D-Bus/ksni, or the user-session daemon.
- Silent auto-replace of the running binary (the helper can `pkexec`).
- The `self_update` crate (May 2026 incident).
- AUR, `.deb`, `.rpm`, crates.io-as-the-install-path.
- HDR / YouTube HDR helpers (L3 does not deliver service HDR).
- CodeQL, bug bounty, bit-reproducible builds (documented; not this cycle’s ceiling).
- mimalloc / `panic=abort` / fat LTO as a first perf move.
- macOS command/idle timings (no physical Mac). Darwin artifact **sizes** are still checked.

## Performance scoreboard

Build `v2.1.2` and the 2.2 candidate the same way. Host, browser set, and protocol stay fixed.

| Row | Protocol |
|---|---|
| Uncompressed musl executable | `stat` size of `silvervine` in the musl tree |
| Compressed musl archive | 2.1.2 GitHub `.tar.xz` vs a dist-equivalent packed 2.2 candidate |
| `--version` / `--help` | nine warm runs, median + max wall |
| `list-browsers --all` / `status` / `doctor` | nine warm runs, JSON, stdout discarded, median + max wall |
| `doctor --media-stack` | nine warm runs, median + max wall, peak RSS via `wait4` |
| Idle daemon CPU | 60 s after 3 s settle, `%` of one core from `/proc/<pid>/stat` |
| Idle daemon RSS | `VmRSS` max over that window |

Idle daemon: isolated `HOME` plus `SILVERVINE_TEST_*_NOOP` for lifecycle/notify/migration/patch. Optional second sample of the user daemon, labeled, never replacing the isolated number.

Browsers recorded with every dump: Helium (`/opt/helium-browser-bin`), ungoogled-chromium (`/usr/lib/chromium`) as of 2026-09-08.

**Perf floor:** no 2.2 ship if any Linux row is worse than the 2.1.2 musl baseline.

**Perf ceiling:** stop when all hold:

1. Remaining `doctor --media-stack` time is `vainfo` and SHA-512 of CDM bytes we still require.
2. Idle daemon is blocked on fds, not a 100 ms sleep. CPU is measurement noise.
3. The next size/RSS cut does not move musl numbers, or it drops an invariant.
4. Rejected cuts are written down.

ROADMAP budgets remain ship gates. They are not the ambition.

## Security scoreboard

| Row | Floor (must not regress) | Ceiling (keep going) |
|---|---|---|
| Dependency policy | `cargo deny check` advisories/bans/licenses/sources pass; no openssl/native-tls | Same, on every 2.2 PR |
| CDM trust | CRX3 + manifest SHA-512 + pinned Mozilla/GitHub origins + no CRX redirects | New network paths use that bar |
| Archive safety | Zip entry-count, expansion, duplicate-path, no symlink follow | Unchanged |
| Host safety | Never `ldd` CDM ELFs | Unchanged |
| Self-update | `update self` remains rejected until the new path exists | Prompted `update self` verifies GitHub checksums (and attestations if present); no silent replace; daemon restart after swap |
| Hooks | Missing hook is success | Bounded timeout via existing `run_output_with_timeout`; pre-patch non-zero **aborts** the patch |
| Release provenance | `sha256.sum` on GitHub Releases | Plus artifact attestations if they do not fail the size floor |
| SBOM | none (known gap) | CycloneDX next to the tarballs on every tag publish |
| Alerts | no open GitHub vuln alerts | Still none at ship |

**Security floor:** 2.2 must not weaken any 2.1.3 control.

**Security ceiling:** stop when GitHub is a complete dist channel (install once, prompted update, checksums, SBOM, attestations-or-documented-why-not), hooks cannot hang the daemon, and pre-patch can abort. Leftover risk that is GitHub-the-company, Widevine-the-CDM, or L3-the-product is out of scope.

## Architecture

Two hunts, same discipline: one change, rebuild, full scoreboard. Do not mix a perf cut and a security feature in one PR. A fat updater that loses the size floor fails.

```text
baseline (2.1.2 musl perf + 2.1.3 security controls)
        │
        ▼
profile / threat-review
        │
        ▼
one hypothesized cut
        │
        ▼
musl release + deny + tests + relevant scoreboard
        │
        ├─ moved the row, invariants hold → keep
        └─ no movement or invariant break → revert, record
```

### Performance hunt order

1. Establish the 2.1.2 musl baseline on this X7 (all perf rows).
2. Profile current musl — `perf`, `cargo-bloat`, RSS maps.
3. Linux idle loop: stop the 100 ms sleep; block on the command channel / inotify. macOS keeps the bounded AppKit pump.
4. `zbus` default features vs the blocking-only comment in Cargo.toml.
5. media-stack: reuse known SHA-512; finish remaining serial work.
6. Duplicate crates only if bloat shows they pay.
7. Repeat until the perf ceiling fires.

### Security hunt order

1. Record the 2.1.3 control baseline (`deny`, alerts, existing tests for unsigned `update self`).
2. Hook timeout using `platform::process::run_output_with_timeout` (already used for `vainfo`).
3. GitHub artifact attestations on `release.yml`, skipped only if they fail the size floor (document why).
4. Prompted auto-update: cargo-dist axoupdater / install receipt, checksums, `silvervine update self`, tray notice. Replace “reject unsigned self-update” tests with “refuse to swap without a matching checksum.” No `self_update` crate. No silent daemon overwrite. Restart the user unit after a successful swap. 2.1.3 users re-run the installer **once** to obtain a receipt.
5. CycloneDX SBOM generated from the tagged commit and uploaded beside the tarballs.
6. Pre-patch hook: same discovery as post-patch; non-zero or timeout aborts the patch; missing hook remains success.
7. Repeat: any new fetch path must match CDM origin/checksum rules.

### Shared invariants

- Linux ship: `x86_64-unknown-linux-musl`, `+crt-static`, `musl-gcc`.
- rustls only.
- CRX3 + SHA-512 + pinned origins on CDM download.
- Never `ldd` browser-controlled CDM ELFs.
- Zip safety limits stay.
- `vainfo` and CDM hashing stay (cache/reuse/parallel only).
- Tray / ksni / user-session daemon stay.
- No silent binary replace.

### Error handling

- Perf: no movement or invariant break → revert in the same cycle. “Should be faster” is not evidence.
- Security: a control that cannot be tested (no checksum on the update path, unbounded hook, unsigned swap) does not ship.
- Updater size cost counts on the perf floor.

## Testing and proof

- Perf: digest-reuse unit tests; Linux wait no longer sleeps while a command is pending; doctor/media-stack tests keep the same evidence fields.
- Security: hook timeout tests; pre-patch abort tests; update-self refuses mismatched checksum; deny stays in CI; SBOM artifact present on the release workflow path (tested in a dry `dist`/publish fixture or workflow unit, not only in production tags).
- Each kept cut’s scoreboard dump lives in the PR body.
- Rejected cuts live in `docs/superpowers/specs/2026-09-08-excellence-rejected-cuts.md` (created at first rejection).

## 2.2 train

Independent PRs:

1. Performance hunt
2. Security hunt (timeout → attestations → updater → SBOM → pre-patch)
3. `silvervine log` TUI (product; not a hunt)

## Open measurement (not a spec hole)

Idle RSS 12 MiB vs ROADMAP 5.59 MiB was **glibc**. First perf hunt step replaces it with musl 2.1.2 vs musl 2.2.
