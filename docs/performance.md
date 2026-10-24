# Performance

## Budgets

Performance changes are measured from optimized, stripped release builds.
Command budgets use the median of nine warm runs; daemon budgets use a
60-second idle window after startup.

| Surface | Linux x86_64 budget | Linux reference | macOS budget | Apple Silicon reference |
|---|---:|---:|---:|---:|
| Distributed executable | <= 10 MiB | 8.22 MiB musl | <= 10 MiB | 4.76 MiB arm64 / 5.50 MiB x86_64 |
| Compressed release archive | <= 4 MiB | 2.70 MiB | <= 4 MiB | 1.77 MiB arm64 / 2.05 MiB x86_64 |
| `--version` / `--help` | <= 25 ms | 0.68–0.73 ms | <= 50 ms | 9.54–13.50 ms |
| List, status, or base doctor | <= 100 ms | 6.55–7.54 ms | <= 100 ms | 8.38–11.93 ms |
| `doctor --media-stack` | <= 2 s | 487 ms | <= 3 s | 1.025 s |
| Media-diagnostic peak RSS | <= 64 MiB | 27.5 MiB | <= 64 MiB | 25.2 MiB |
| Idle daemon CPU / one core | <= 0.5% | 0.05% | <= 0.5% | 0.05% |
| Idle daemon RSS | <= 64 MiB | 5.59 MiB | <= 64 MiB | 42.73 MiB |

The Linux command reference is an Intel Core Ultra X7 358H host; the macOS
reference is an Apple M2 host running macOS 26.6. Absolute comparisons use the
same host and installed browser set. The shipped-binary figures come from the
2.1.0 cargo-dist archives; the command and daemon figures include the current
unreleased optimizations. Reproduction steps live in
[CONTRIBUTING.md](../CONTRIBUTING.md#performance-validation).


These are historical reference measurements, not 2.3 measurements. Windows budgets will be set after measuring the native release build.
