# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| V2.0.x and newer | Yes (security fixes backported to latest minor) |
| V1.x (bash + Swift + Go) | No (V1 is end-of-life as of V2.0 ship) |
| V2.0 pre-releases (`v2.0.0-rc.*`) | Yes during the rc; superseded by `v2.0.0` |

V2.1 supersedes V2.0 once shipped — I don't commit to maintaining multiple LTS branches.

## Reporting a vulnerability

**Private vulnerability reporting:** https://github.com/nicholasraimbault/silvervine/security/advisories/new

Please **do not** file security issues on GitHub Issues. Public disclosure before a fix is ready hurts users who haven't yet updated.

In your report, please include:

- Affected version (output of `neon --version`).
- Affected platform + version (`uname -a` on Linux; `sw_vers` on macOS).
- A description of the vulnerability — what's the impact, who's affected, what's the attack surface.
- Reproduction steps, ideally including a minimal proof-of-concept.
- Whether you've disclosed to anyone else, and whether there's a public timeline (CVE filing, conference talk, blog post, etc.) I need to coordinate around.

## Response SLA

- **Acknowledgment:** within **48 hours** of receipt. If you don't hear back, follow up in the same private advisory.
- **Initial assessment:** within **7 days**. I'll tell you what I think the severity is, what the rough fix shape looks like, and the target ship date.
- **Fix target:** within **30 days** for critical / high severity; longer for medium / low (judged case-by-case). I'll ship a patch release on the latest minor (`v2.x.y+1`) for backportable fixes.
- **Disclosure:** coordinated. I'll credit you in the release notes (or anonymously if you prefer). If there's a CVE, I'll file it; if you prefer to file, I'll defer to your CVE.

## What counts as a vulnerability

In scope:

- Code execution outside the user's session via a Neon-controlled file (configs, hooks, cache).
- Privilege escalation paths that don't require a sudo prompt the user can refuse.
- Bundle-write paths that can write outside the targeted browser bundle.
- Network paths that fetch unsigned content and act on it (Widevine CDM is hash-verified against the manifest; the manifest is fetched over HTTPS but is itself signed by Mozilla).
- Race conditions in the atomic-patch protocol that can leave a browser bundle destroyed.
- Lockfile / IPC race conditions that can be triggered by an unprivileged local user to interfere with the daemon.
- Any default-on telemetry. Neon ships **no** telemetry or error-reporting endpoint; this should never change without an explicit major-version migration.

Out of scope:

- L3 → L1 DRM bypass discussion. Neon is explicitly software-only L3; that's a feature, not a bug.
- Patched browsers being rejected by services with hardware DRM enforcement (Apple TV+, some Disney+ regions).
- The Widevine CDM itself having vulnerabilities — Neon ships the same CDM Mozilla ships; report those to Mozilla / Google.
- Neon being broken on a fork of a fork of a fork of Chromium that the auto-discovery doesn't find. (File a feature request, not a security report.)

## Scope: privilege model

Neon V2 runs **entirely in the user session** — the daemon is a LaunchAgent (macOS) or systemd-user unit (Linux), not a root daemon. The CDM patches require write access to browser bundles in `/Applications` (macOS) or `/opt`, `/usr/lib/`, etc. (Linux), so the patch path itself escalates via:

- `osascript -e "do shell script ... with administrator privileges"` on macOS — system password prompt.
- `pkexec` (preferred) → `sudo` (fallback) on Linux — system password prompt.

Both prompt the user. Both require user consent each time (Neon does not cache credentials). The escalated child runs only the bundle-write portion — never an arbitrary command — and is invoked as `neon --as-root <subcommand>` so its arguments are auditable.

User-installed browsers in `~/Applications` (macOS) or `~/.local/...` (Linux) don't require escalation. Custom-path browsers configured in `~/.config/neon/config.toml` follow the path's actual permissions.

Neon ships **no** telemetry or error-reporting endpoint. The binary never POSTs failure metadata anywhere — bug reports go through GitHub Issues, full stop.

## Known limitations

- **macOS `--deep` codesigning is deprecated.** Apple deprecated it as of macOS 13; it still works ad-hoc but Apple may remove it in a future macOS. V2.1 migrates to inside-out signing. Documented in [ROADMAP.md](ROADMAP.md).
- **No SBOM yet.** V2 ships a list of dependencies via `cargo metadata`; CycloneDX SBOM generation is queued for V2.1.
- **No reproducible builds.** cargo-dist artifacts are deterministic-ish but not bit-reproducible. Working on it.

## Bug bounty

There is no bug bounty program. Neon is a hobbyist project run on my spare time; I can't pay for bugs. I **can** credit you in release notes and CVE filings, and I deeply appreciate responsible disclosure.
