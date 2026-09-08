# 2.1.2 musl performance baseline

Date: 2026-09-08
Status: Recorded. Later 2.2 perf tasks must beat every Linux row.
Source binary: GitHub v2.1.2 musl tarball (not a local musl rebuild)

This is the committed 2.1.2 musl scoreboard for the 2.2 excellence hunt.
Command timings and idle samples were taken on this maintainer host from the
extracted `silvervine` inside `silvervine-x86_64-unknown-linux-musl.tar.xz`.
There is no `musl-gcc` on this CachyOS host; the GitHub musl artifact is the
shipped Linux target.

## Host

| Field | Value |
|---|---|
| CPU | Intel(R) Core(TM) Ultra X7 358H (16 cores, 4800 MHz max) |
| OS | CachyOS (`ID=cachyos`) |
| Kernel | `7.2.2-1-cachyos` (`uname -r`) |
| Arch | `x86_64` |

## Browser set (2026-09-08)

| Browser | Path | Version |
|---|---|---|
| Helium | `/opt/helium-browser-bin` | Helium 0.16.4.1 (Chromium 152.0.7977.75) |
| ungoogled-chromium | `/usr/lib/chromium` | Chromium 152.0.7977.75 Arch Linux |

## Binary

| Field | Value |
|---|---|
| Origin | GitHub Release `v2.1.2` tarball, not a local `x86_64-unknown-linux-musl` build |
| Release URL | https://github.com/nicholasraimbault/silvervine/releases/tag/v2.1.2 |
| Archive | `silvervine-x86_64-unknown-linux-musl.tar.xz` |
| Archive bytes | 2868124 |
| Archive sha256 | `03d5c460569cbd3acba3b8c6f9cb452cf7ccf46103b2dcdee5f040171271b0b8` |
| Extracted path | `/tmp/silvervine-212-github-musl/silvervine-x86_64-unknown-linux-musl/silvervine` |
| Executable bytes | 8714416 |
| Executable sha256 | `8c1d92b1afdff836bef80fa4aa5c16cba2a7386ecfa7d680f91a9397344480c1` |
| `file` | ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped |
| `ldd` | statically linked |
| `--version` | `silvervine 2.1.2` |

Checksum verification: `sha256sum -c` against both
`silvervine-x86_64-unknown-linux-musl.tar.xz.sha256` and the matching line in
`sha256.sum` from the same release. Both OK.

## Protocol

Command rows: `scripts/perf_scoreboard.sh <binary>`. One discarded warmup, then
nine runs. Stdout and stderr discarded. Wall time is `time.perf_counter()`
around `os.wait4` after `Popen` returns. Peak RSS is Linux `wait4` `ru_maxrss`
(kB) / 1024 → MiB. Median is `walls[4]` after sort.

Idle row: isolated `HOME` plus XDG dirs, then SIGTERM of **that** child only.
The already-running user daemon `/home/nick/.cargo/bin/silvervine` (pid 933)
was not signalled.

Idle env:

```text
HOME=<tempdir>
XDG_CONFIG_HOME=<tempdir>/config
XDG_CACHE_HOME=<tempdir>/cache
XDG_DATA_HOME=<tempdir>/data
XDG_STATE_HOME=<tempdir>/state
XDG_RUNTIME_DIR=<tempdir>/runtime
SILVERVINE_TEST_DATA_MIGRATION_NOOP=1
SILVERVINE_TEST_LIFECYCLE_NOOP=1
SILVERVINE_TEST_POWER_NOOP=1
SILVERVINE_TEST_NOTIFY_NOOP=1
SILVERVINE_TEST_DAEMON_PATCH_NOOP=1
```

Idle sampler (2026-09-08 `/proc` protocol):

- 3 s settle, then 60.000 s sample, 0.2 s `VmRSS` poll
- CPU `%` of one core = `(Δutime + Δstime) / CLK_TCK / elapsed * 100` from
  `/proc/<pid>/stat` fields 14 and 15 (`CLK_TCK=100`)
- RSS = max `VmRSS` kB from `/proc/<pid>/status` over that window
- Isolated pid 2910272; exe was the extracted 2.1.2 musl binary
- SIGTERM after the window (`wait` rc `-15`); user daemon pid 933 still alive

Tick granularity at 100 Hz over 60 s is 0.0167 % of one core per tick.

## Scoreboard

MiB = bytes / 1024 / 1024.

| Row | 2.1.2 musl baseline | Notes |
|---|---|---|
| Uncompressed musl executable | **8714416 bytes (8.31 MiB)** | `stat -c%s` of extracted `silvervine` |
| Compressed musl archive | **2868124 bytes (2.74 MiB)** | GitHub `.tar.xz` |
| `--version` | **median 0.25 ms, max 0.47 ms, peak RSS 12.38 MiB** | |
| `--help` | **median 0.32 ms, max 0.37 ms, peak RSS 12.52 MiB** | |
| `list-browsers --all` | **median 6.68 ms, max 7.78 ms, peak RSS 12.52 MiB** | `--json list-browsers --all` |
| `status` | **median 6.49 ms, max 7.09 ms, peak RSS 12.52 MiB** | `--json status` |
| `doctor` | **median 7.46 ms, max 8.17 ms, peak RSS 12.52 MiB** | `--json doctor` |
| `doctor --media-stack` | **median 536.13 ms, max 785.62 ms, peak RSS 24.34 MiB** | `--json doctor --media-stack` |
| Idle daemon CPU / one core | **0.0333 %** | 2 ticks in 60.000 s after 3 s settle |
| Idle daemon RSS | **9684 kB (9.46 MiB) VmRSS max** | constant across 300 samples |

## Raw `scripts/perf_scoreboard.sh` dump

```text
binary=/tmp/silvervine-212-github-musl/silvervine-x86_64-unknown-linux-musl/silvervine
size_bytes=8714416
version=silvervine 2.1.2
--version: median_ms=0.25 max_ms=0.47 peak_rss_mib=12.38
--help: median_ms=0.32 max_ms=0.37 peak_rss_mib=12.52
--all: median_ms=6.68 max_ms=7.78 peak_rss_mib=12.52
status: median_ms=6.49 max_ms=7.09 peak_rss_mib=12.52
doctor: median_ms=7.46 max_ms=8.17 peak_rss_mib=12.52
media-stack: median_ms=536.13 max_ms=785.62 peak_rss_mib=24.34
```

## Raw idle sample

```text
isolated_home=/tmp/silvervine-212-idle-home-z4_0ehrv
idle_pid=2910272
exe=/tmp/silvervine-212-github-musl/silvervine-x86_64-unknown-linux-musl/silvervine
settle_s=3.0
sample_s_elapsed=60.000
clk_tck=100
cpu_ticks_delta=2
idle_cpu_pct_one_core=0.0333
idle_vmrss_max_kib=9684
idle_vmrss_max_mib=9.46
samples=300
interval_s=0.2
term=exited rc=-15
user_daemon_after_alive=True
```

## Reproduction

```bash
gh release download v2.1.2 --repo nicholasraimbault/silvervine \
  --pattern 'silvervine-x86_64-unknown-linux-musl.tar.xz*' \
  --pattern 'sha256.sum'
sha256sum -c silvervine-x86_64-unknown-linux-musl.tar.xz.sha256
tar -xJf silvervine-x86_64-unknown-linux-musl.tar.xz
scripts/perf_scoreboard.sh silvervine-x86_64-unknown-linux-musl/silvervine
```

Idle must keep using an isolated `HOME`, the `SILVERVINE_TEST_*_NOOP` set
above, a 3 s settle, a 60 s `/proc` window, and SIGTERM of the sampled child
only.
