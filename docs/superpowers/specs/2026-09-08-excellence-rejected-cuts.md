# 2.2 Excellence — rejected cuts

Date: 2026-09-08
Companion: `2026-09-08-perf-excellence-design.md`, `plans/2026-09-08-excellence-hunts.md`

## Idle hunt: do not revert Linux `recv_timeout`

**Decision:** Keep Linux `Tray::recv_timeout` in the daemon event loop.

**Plan said:** If idle CPU does not improve vs the 2.1.2 musl baseline, revert and append a rejection note.

**Why kept anyway:** Spec ceiling governs: “Idle daemon is blocked on file descriptors, not a 100 ms sleep.” Controller resolution: that ceiling wins over the plan’s revert-if-CPU-flat rule when CPU is already at the measurement noise floor.

**Evidence (Task 2, glibc release on this host):**

| Sample | Idle CPU (one core, 60 s) | Notes |
|---|---|---|
| Task 1 — 2.1.2 musl baseline | 0.0333 % (2 ticks) | `CLK_TCK=100`; 0 vs 2 ticks is noise |
| Task 2 — this tree, glibc | 0.0333 % (2 ticks) | Same floor; no measurable move |

- Musl rebuild of this tree was skipped (`musl-gcc` / `x86_64-unknown-linux-musl` unavailable).
- Glibc idle RSS (12.09 MiB VmRSS max) is **not** comparable to the musl baseline 9.46 MiB; do not treat the RSS delta as a `recv_timeout` regression.

**Rejected alternative:** Reverting to `try_recv` + `wait_for_platform_event` (100 ms sleep) solely because idle CPU did not improve at the 2-tick/60s floor.
