# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| V1.0.x and newer | Yes (security fixes backported to latest minor) |
| V0.x (bash + Swift + Go) | No (V0 is end-of-life as of V1.0 ship) |
| V1.0 pre-releases (`v0.x` during beta) | Yes during the beta period; superseded by `v1.0.0` |

V1.1 supersedes V1.0 once shipped — we do not commit to maintaining multiple LTS branches.

## Reporting a vulnerability

**Private vulnerability reporting:** https://github.com/nicholasraimbault/silvervine/security/advisories/new

Please **do not** file security issues on GitHub Issues. Public disclosure before a fix is ready hurts users who haven't yet updated.

In your report, please include:

- Affected version (output of `neon --version`).
- Affected platform + version (`uname -a` on Linux; `sw_vers` on macOS).
- A description of the vulnerability — what's the impact, who's affected, what's the attack surface.
- Reproduction steps, ideally including a minimal proof-of-concept.
- Whether you've disclosed to anyone else, and whether there's a public timeline (CVE filing, conference talk, blog post, etc.) we need to coordinate around.

## Response SLA

- **Acknowledgment:** within **48 hours** of receipt. If you don't hear back, follow up in the same private advisory.
- **Initial assessment:** within **7 days**. We tell you what we think the severity is, what the rough fix shape looks like, and our target ship date.
- **Fix target:** within **30 days** for critical / high severity; longer for medium / low (judged case-by-case). We'll ship a patch release on a minor version (`v1.x.0+1`) for backportable fixes.
- **Disclosure:** coordinated. We'll credit you in the release notes (or anonymously if you prefer). If there's a CVE, we'll file it; if you prefer to file, we'll defer to your CVE.

## What we consider a vulnerability

Things we consider security issues:

- Code execution outside the user's session via a Neon-controlled file (configs, hooks, cache).
- Privilege escalation paths that don't require a sudo prompt the user can refuse.
- Bundle-write paths that can write outside the targeted browser bundle.
- Network paths that fetch unsigned content and act on it (Widevine CDM is hash-verified against the manifest; the manifest is fetched over HTTPS but is itself signed by Mozilla).
- Race conditions in the atomic-patch protocol that can leave a browser bundle destroyed.
- Lockfile / IPC race conditions that can be triggered by an unprivileged local user to interfere with the daemon.
- Default-on telemetry. (We have **opt-in** error reporting; default-off; this should never become default-on without an explicit major-version migration.)

Things we generally don't consider security issues:

- L3 → L1 DRM bypass discussion. Neon is explicitly software-only L3; that's a feature, not a bug.
- Patched browsers being rejected by services with hardware DRM enforcement (Apple TV+, some Disney+ regions).
- The Widevine CDM itself having vulnerabilities — we ship the same CDM Mozilla ships; report those to Mozilla / Google.
- Neon being broken on a fork of a fork of a fork of Chromium that we don't auto-discover. (File a feature request, not a security report.)

## Scope: privilege model

Neon V1 runs **entirely in the user session** — the daemon is a LaunchAgent (macOS) or systemd-user unit (Linux), not a root daemon. The CDM patches require write access to browser bundles in `/Applications` (macOS) or `/opt`, `/usr/lib/`, etc. (Linux), so the patch path itself escalates via:

- `osascript -e "do shell script ... with administrator privileges"` on macOS — system password prompt.
- `pkexec` (preferred) → `sudo` (fallback) on Linux — system password prompt.

Both prompt the user. Both require user consent each time (we do not cache credentials). The escalated child runs only the bundle-write portion — never an arbitrary command — and is invoked as `neon --as-root <subcommand>` so its arguments are auditable.

User-installed browsers in `~/Applications` (macOS) or `~/.local/...` (Linux) don't require escalation. Custom-path browsers configured in `~/.config/neon/config.toml` follow the path's actual permissions.

The opt-in error reporter (V1.0 feature) sends only categorized failure metadata — no PII, no command-line arguments, no file paths beyond redacted shapes (e.g., `<HOME>/.config/neon/config.toml` becomes `~/.config/neon/config.toml`). Default off; the user opts in during `neon init`.

## Known limitations

- **macOS `--deep` codesigning is deprecated.** Apple deprecated it as of macOS 13; it still works ad-hoc but Apple may remove it in a future macOS. V2 migrates to inside-out signing. Documented in [ROADMAP.md](ROADMAP.md).
- **No SBOM yet.** V1 ships a list of dependencies via `cargo metadata`; CycloneDX SBOM generation is V1.1.
- **No reproducible builds.** cargo-dist artifacts are deterministic-ish but not bit-reproducible. Working on it.

## Bug bounty

There is no bug bounty program. Neon is a hobbyist project run on Nick's spare time; we can't pay for bugs. We **can** credit you in release notes and CVE filings, and we deeply appreciate responsible disclosure.
