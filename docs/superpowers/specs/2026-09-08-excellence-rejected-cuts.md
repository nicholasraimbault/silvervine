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

## Perf hunt: do not keep `zbus` default-features trim

**Decision:** Leave `zbus = { version = "5" }` (defaults on). Reverted the Task 3 feature trim.

**Plan said:** `default-features = false, features = ["blocking"]` (or the minimal set that compiles). Keep if musl size/RSS moves; controller resolution: skip musl, keep on glibc only if tests pass and `cargo tree` is smaller even when release size is flat; revert if compile needs almost all default features back.

**What we tried:**

1. `features = ["blocking"]` — fails. In zbus 5, `blocking` is the optional `blocking` crate (pulled by `async-io`), not the `zbus::blocking` module. Compiler gates the module on `blocking-api`.
2. `default-features = false, features = ["blocking-api"]` — compiles. `async-io` (the other default feature) stays enabled via `ksni` / `notify-rust`, so the resolved feature set matches pre-trim defaults.

**Evidence (Task 3, glibc release on this host):**

| Metric | Before | After `blocking-api` only |
|---|---|---|
| `target/release/silvervine` bytes | 8681728 | 8681728 |
| Unique packages (`cargo tree` full) | 227 | 227 |
| Unique packages (`cargo tree -p zbus`) | 67 | 67 |
| `cargo test --lib --locked` | — | 791 passed, 5 ignored |

- Musl rebuild skipped (`musl-gcc` unavailable), same as Tasks 1–2.
- `Cargo.lock` unchanged under the trim (feature flag only).

**Why reverted:** Neither glibc release size nor `cargo tree` package count moved. The trim is a documentation-only change of silvervine’s direct feature list; the build still resolves `async-io` + `blocking-api`. Plan Step 4 / controller keep-if-tree-smaller rule not met.

**Rejected alternative:** Shipping `default-features = false, features = ["blocking-api"]` with no measurable binary or dependency-graph win.
