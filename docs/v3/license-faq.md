# V3 License FAQ

The Neon localhost-bridge runs Microsoft Windows 11 IoT Enterprise LTSC
inside a VM on your machine. Microsoft is the licensor; Neon never
distributes Microsoft binaries. This FAQ explains the licensing posture
and how Neon helps you stay compliant.

## TL;DR

- **Eval mode (default)**: 90-day evaluation. Free. `slmgr /rearm`
  extends up to 3 additional 90-day cycles (~360 days total). After
  that, you need a real key.
- **BYO key**: bring your own Windows product key (Volume / Retail /
  OEM). `neon stream license set --key XXXXX-...`. Activates
  permanently.
- **BYO key file**: same as BYO key but the key sits in a file rather
  than `bridge.toml` (e.g. for KMS clusters). `neon stream license
  set --key-file PATH`.

Neon **never** stores or transmits your product key beyond
`~/.config/neon/bridge.toml` (mode 0600). That file stays on your
machine.

## Q: Is "BYO eval license" legal?

Yes. Microsoft publishes Win11 IoT Enterprise LTSC evaluation media at
<https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-iot-enterprise-ltsc>
specifically for evaluation use. The 90-day-then-rearm path is the
intended workflow.

For *production* use beyond the eval period, Microsoft's terms require
a real license key. Neon's `--license-key` flag is how you opt in.

## Q: Where does Neon get the Windows ISO?

Microsoft's eval-center URL, pinned at compile time. The download URL
+ SHA-256 are stored in `bridge::iso::default_spec()` and overridable
via `~/.config/neon/bridge.toml`'s `[iso]` section (see
[troubleshooting.md](troubleshooting.md#iso-url-pinning-the-v3-phase-c-known-stub-issue)).

When Microsoft rotates the URL (~yearly), users update the override and
keep going. **Neon never bundles or redistributes Microsoft binaries.**

## Q: How do I get a Windows IoT LTSC license?

Several paths:

1. **Microsoft Volume Licensing** (for businesses, edu) — contact a
   Microsoft Solution Partner. Bulk pricing.
2. **MSDN / Visual Studio subscriptions** — include LTSC keys for
   non-production / dev use.
3. **Retail** — Microsoft sells LTSC keys directly through some
   channels; pricing varies.

Once you have a key, store it via:

```sh
neon stream license set --key XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
```

## Q: Can I use a Win10 / Win11 Pro key?

Win11 IoT LTSC has its own key SKU. Pro / Home / Enterprise keys are
tied to those SKUs and won't activate the IoT install.

Workaround: install Win10 LTSC instead (Neon's autounattend XML mostly
works with Win10 LTSC; you'd need to tweak the version-specific bits in
`src/bridge/unattended.rs`).

For V3.0 we recommend the BYO IoT LTSC route or eval mode for
non-production use.

## Q: Does eval mode prompt me to "activate Windows"?

No. The eval license accepts the EULA (via the autounattend XML's
`<AcceptEula>true</AcceptEula>`) and skips activation entirely. The
desktop just works. After day 90, Windows starts displaying expiry
warnings; `slmgr /rearm` defers them another 90 days.

`neon stream license rearm` shows the exact PowerShell command the
guest runs. The autounattend XML schedules this automatically 7 days
before expiry — you only run it manually if the scheduled task fails.

## Q: What happens after 4 rearms (~360 days)?

`slmgr /rearm` starts returning an error. The guest still boots and
runs Edge / Sunshine / Looking Glass, but Windows displays expiry
warnings and may revert to a "non-genuine" state with watermarks.

At that point:

1. Either provide a real key via `neon stream license set --key ...`,
   or
2. Re-provision from scratch via `neon stream uninstall --purge` then
   `neon stream init --accept-eval` (resets the eval clock; technically
   compliant since the new eval starts a fresh 90-day cycle).

## Q: Does Neon collect / report license data?

No. The opt-in error reporter (`neon doctor` flag) sends only
categorized error counts (e.g. "NetworkError occurred") and never
includes:

- The product key.
- The license-mode value.
- `bridge.toml` contents.
- VM names or paths.

Source: <https://github.com/imputnet/neon/blob/main/CHANGELOG.md>
(opt-in reporter section).

## Q: Can I share my key across multiple machines?

Depends on the SKU:

- **Volume Licensing**: yes, within the volume agreement.
- **OEM**: tied to one machine.
- **Retail**: typically one machine, transferable on hardware change.
- **MSDN**: dev / non-production use only.

Neon doesn't enforce or limit this; Microsoft does. If your activation
fails because you've reused a key beyond its terms, that's between you
and Microsoft.

## Q: How do I switch from eval to a key without re-installing?

```sh
neon stream license set --key XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
```

This updates `bridge.toml` immediately. Inside the guest, run:

```powershell
slmgr /ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
slmgr /ato
```

`/ipk` installs the new key; `/ato` activates against Microsoft's
servers. Future Neon versions may automate this via Sunshine's input
channel — for V3.0 it's a one-time manual step.

## Q: Can I provide multiple keys (e.g. KMS host)?

Yes. KMS cluster admins commonly distribute keys via a CSV; point Neon
at the CSV path:

```sh
neon stream license set --key-file /path/to/keys.csv
```

Neon reads the file at install time only — the CSV stays put on your
host filesystem.

## Q: I lost my key. Can I recover it from `bridge.toml`?

If you stored it via `--key`, yes — `~/.config/neon/bridge.toml`
contains it verbatim (mode 0600 to keep nosy `~/` greppers from finding
it).

If you stored a `--key-file` path, Neon doesn't keep a copy of the
file's contents — only the path. You'll need the file itself.

## Q: Does eval mode work offline?

Yes. The autounattend install requires network only briefly (to
download Sunshine; can be skipped if you pre-stage the installer). The
eval activation is local — Microsoft's servers aren't contacted.

For BYO key activation, the guest needs internet briefly (for the
`/ato` round-trip). After activation, no network needed.

## Q: What about Microsoft Edge?

Edge ships with Win11 IoT LTSC by default (no extra license). Use the
Edge inside the guest exactly like you would on a normal Windows
machine.

## Q: HEVC codec license?

Win11 IoT LTSC includes the HEVC Video Extension by default (free for
LTSC; paid for retail Win11). Netflix / Disney+ deliver HEVC at higher
quality tiers — that's why the IoT path is preferred.

## Q: Looking Glass and kvmfr licensing?

- Looking Glass client: GPL v2.0
- kvmfr kernel module: GPL v2.0

Both are open source. Neon distributes neither — you install them via
your distro's package manager.

## Q: Sunshine licensing?

GPL v3.0. Same — Neon downloads it from upstream's GitHub release page
inside the guest at install time.

## Q: Can I redistribute a Neon-built bridge VM image?

No. The VM disk image contains your installed Windows + your activated
license. Redistributing would violate Microsoft's terms. Each Neon user
provisions their own VM via `neon stream init`.

## Q: Where can I read the actual Microsoft EULA?

Inside the guest: `winver` shows version + click "Read the License
Agreement" to see the full EULA. Or download from
<https://www.microsoft.com/en-us/Useterms> and search for "Windows 11
IoT Enterprise LTSC".
