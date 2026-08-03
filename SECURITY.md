# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| V2.0.x and newer | Yes (security fixes backported to latest minor) |
| V1.x (bash + Swift + Go) | No (V1 is end-of-life as of V2.0 ship) |
| V2.0 pre-releases (`v2.0.0-rc.*`) | Yes during the rc; superseded by `v2.0.0` |

V2.1 supersedes V2.0 once shipped — I don't commit to maintaining multiple LTS branches. Supported release versions cover the focused Widevine L3 helper shipped from master.

## Reporting a vulnerability

**Private vulnerability reporting:** https://github.com/nicholasraimbault/silvervine/security/advisories/new

Please **do not** file security issues on GitHub Issues. Public disclosure before a fix is ready hurts users who haven't yet updated.

In your report, please include:

- Affected version (output of `silvervine --version`).
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

- Code execution outside the user's session via a Silvervine-controlled file (configs, hooks, cache).
- Privilege escalation paths that don't require a sudo prompt the user can refuse.
- CDM-publication paths that can escape the selected Linux browser root or
  macOS user-profile component root.
- Race conditions in the atomic-patch protocol that can leave the active CDM
  target destroyed.
- Network paths that fetch unauthenticated content and act on it (Widevine CDM
  bytes must match a freshly fetched HTTPS manifest's SHA-512 and a CRX3
  signature from Silvervine's pinned Widevine component key).
- Lockfile / IPC race conditions that can be triggered by an unprivileged local user to interfere with the daemon.
- Any default-on telemetry. Silvervine ships **no** telemetry or error-reporting endpoint; this should never change without an explicit major-version migration.

Out of scope:

- L3 → L1 DRM bypass discussion. Silvervine is explicitly software-only L3; that's a feature, not a bug.
- Patched browsers being rejected by services with hardware DRM enforcement (Apple TV+, some Disney+ regions).
- The Widevine CDM itself having vulnerabilities — Silvervine ships the same CDM Mozilla ships; report those to Mozilla / Google.
- Silvervine being broken on a fork of a fork of a fork of Chromium that the auto-discovery doesn't find. (File a feature request, not a security report.)

## Scope: privilege model

Silvervine V2 runs **entirely in the user session** — the daemon is a
LaunchAgent (macOS) or systemd-user unit (Linux), not a root daemon.

On macOS, Silvervine publishes Widevine under the current user's
`~/Library/Application Support/<browser-id>/.../WidevineCdm/<version>/`
component tree. The patcher explicitly disables elevation: it neither writes
to `/Applications` nor modifies, clears attributes from, or re-signs the
vendor application bundle. The Widevine library retains Google's signature,
and the browser retains its vendor signature and entitlements.

Linux system installations under `/opt`, `/usr/lib`, and similar roots may
require elevation through `pkexec` (preferred) or `sudo` (fallback). Both
require a system password prompt that the user can refuse; Silvervine does not
cache credentials. The elevated child runs only the hidden filesystem-only
privileged patch operation — never discovery, configuration, network, cache,
logging, migration, or hooks. Its auditable arguments carry the parent's exact
browser path, bounded parent-authenticated CDM staging payload and version,
trusted same-filesystem backup parent, browser display name, and force
decision.

User-owned Linux browser installations do not require elevation. A custom
macOS bundle path is used only to validate the browser identity and derive its
user-profile component directory.

Executable CDM trust requires a fresh manifest from Silvervine's fixed
Mozilla/GitHub HTTPS origins (or an explicit user-selected HTTPS source with no
local/private address literal, whose redirects remain on that exact origin),
the manifest-carried SHA-512 of the exact CDM archive, and a valid CRX3
signature from the pinned Widevine component key. The signature binds both the
component ID and ZIP body.
Manifest-carried CDM URLs are restricted to the exact Google Widevine CDN
origins observed in Mozilla's manifest and do not follow redirects. HTTPS
transport integrity and the fixed manifest-origin list are the
manifest-authenticity controls; Silvervine does not claim that Mozilla signs
the manifest JSON itself. Mutable manifest
snapshots are write-only. Archives are size-bounded, preflighted for entry
count before ZIP parser allocation, opened without following symlinks, and
extracted from the exact signature-verified bytes. Duplicate normalized
outputs, special entries, and expansion-limit violations are rejected;
colocated cache metadata alone never authorizes an elevated Linux patch.

Silvervine ships **no telemetry or remote error-reporting endpoint**. The
explicit `silvervine test` command POSTs its browser capability result only to
an ephemeral server bound to `127.0.0.1`; the endpoint requires a random
single-use URL token and same-origin request, caps request size and count, and
expires after a fixed timeout. No probe result is sent off-device. Bug reports
go through GitHub Issues only when the user chooses to share them.

## Known limitations

- **No SBOM yet.** V2 ships a list of dependencies via `cargo metadata`;
  CycloneDX SBOM generation is queued for V2.2.
- **No reproducible builds.** cargo-dist artifacts are deterministic-ish but not bit-reproducible. Working on it.

## Bug bounty

There is no bug bounty program. Silvervine is a hobbyist project run on my spare time; I can't pay for bugs. I **can** credit you in release notes and CVE filings, and I deeply appreciate responsible disclosure.
