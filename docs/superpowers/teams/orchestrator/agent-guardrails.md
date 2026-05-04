# Agent Guardrails

Constraints for every Phase N agent brief. Include these literally in
each spawn prompt to prevent disrupting Nick's workstation.

## Don't disrupt the user's desktop session

Nick runs **niri** with the **noctalia-shell** (quickshell-based). Heavy
parallel agent activity has correlated with quickshell crashes (segfaults
in Qt; likely CPU/memory pressure exposing a Qt/QML race rather than a
direct kill). To avoid recurrence:

1. **Never** run more than one `cargo build` / `cargo test` /
   `cargo tarpaulin` at a time. If two agents are active in parallel,
   they coordinate so only one is doing a heavy build at any moment, OR
   each uses `--jobs 2` to cap CPU pressure.
2. **Never** invoke the user's running compositor or D-Bus user services
   directly. No `dbus-send`, no `notify-send`, no `niri msg`, no
   `playerctl`, no `gsettings set`. Tests that interact with these
   surfaces must be feature-gated or env-var-gated to no-op by default.
3. **Never** spawn graphical processes outside of explicit testing
   (i.e. don't open a browser to "see if EME works", don't launch a
   terminal, don't run any `*-gui` commands). Anything that needs a
   display must run in a headless test fixture.
4. **Never** modify files outside `/home/nick/Projects/neon/` unless
   explicitly asked. No `~/.config/`, no `~/.local/share/`, no
   `/etc/`, no `/usr/`.
5. **Don't run high-load commands during work hours.** If a `cargo
   tarpaulin` would peg all cores for >30 seconds, prefer to do it in a
   single-job mode or skip it during interactive sessions and verify
   coverage in CI instead.

## Don't escalate privileges

Per existing memory: "No sudo access in any Claude-driven shell — sudo
fails in the Bash tool AND via the `!` prefix."

- Never invoke `sudo`, `pkexec`, `doas`, or `osascript` "with admin".
- Never call into the project's `platform::escalate_for_patch` or
  `platform::run_as_root` outside tests that have
  `NEON_TEST_ESCALATE_NOOP=1` set.
- If a test exists that calls these without the env var, fix the test.

## Stay in your lane

- Don't write into other teams' files (file-ownership rules in
  `docs/superpowers/teams/<team>/handoff.md`).
- If you genuinely need a change in another team's territory, raise
  it via direct message; don't write across the boundary.
- The orchestrator is the only one who edits
  `docs/superpowers/teams/orchestrator/status.md`.

## Verify before claiming done

- Always run `cargo build`, `cargo fmt --check`, and `cargo clippy
  --all-targets -- -D warnings` before declaring a phase complete. If
  the working tree is broken because another team is mid-flight, that's
  fine — just say so in your completion message.
- Don't claim "tests pass" without actually running `cargo test --lib`.
- Tarpaulin can be skipped if it's load-prohibitive, but at least
  `cargo test --lib` must be green.

## Coordinate parallel work

When the orchestrator spawns two teams in parallel for the same phase:

- Read the *other* team's handoff doc first to know what interfaces
  they'll provide.
- Send them a direct message early with your expected signatures so
  they can match.
- Don't commit half-states that break the build for the other team —
  keep your work compilable on its own (use stub implementations,
  feature flags, or `unimplemented!()` placeholders that compile but
  fail at runtime).
