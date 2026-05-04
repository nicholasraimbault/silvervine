# CLI Team Handoff

**Identity:** `cli`
**Mission:** All user-facing subcommands. EME error code translation. Interactive prompts.

## Files owned

- `src/main.rs`
- `src/cli/` — every subcommand impl
- `src/eme/` — EME error code map + headless-browser test harness
- `src/log.rs` — tracing setup
- `src/config.rs` — TOML config schema (read-only API; core-engine writes it)

## Current focus

Pending. Activates in Phase 1 (subcommand stubs via clap derive) and Phase 4 (full implementations).

## Public contracts owned (planned)

```rust
// cli/mod.rs
#[derive(clap::Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(short, long)]
    pub verbose: u8,
    #[arg(short, long)]
    pub quiet: bool,
    // ...
}

#[derive(clap::Subcommand)]
pub enum Command {
    Init, Setup, Patch(PatchArgs), Status(StatusArgs), ListBrowsers(ListArgs),
    Doctor(DoctorArgs), Test, Update(UpdateArgs), Repair, Launch { browser: String },
    Uninstall, Completion { shell: Shell }, Manpage,
}
```

## Decisions log

- **Subcommand `neon` (no args)** invokes daemon mode (tray + watcher) — matches spec.

## Open questions

- `neon test` headless browser: use Shaka Player demo or maintain own offline test page? Shaka is simpler but requires network; defer decision to Phase 4 implementation.

## Dependencies awaiting

- Core Engine team's full API surface (`patch`, `widevine`, `browsers`)
- Platform team's `migration` and `escalate_for_patch`
- Daemon team's IPC client API

## Files most recently changed

(empty)
