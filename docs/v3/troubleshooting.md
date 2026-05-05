# V3 Troubleshooting

If something isn't working, run:

```sh
neon doctor --bridge        # show capability snapshot + remediation
neon stream status          # show VM state, snapshot age, license expiry
neon stream repair          # detect + auto-fix common broken states
```

If the issue persists, open an issue at
<https://github.com/imputnet/neon/issues> with the output of all three
commands attached.

## Quick reference

| Symptom | First thing to try |
|---|---|
| `neon stream init` exits with capability gate failure | Read each `Issue X/N`, fix the BIOS / kernel-module / GPU issue, re-run |
| `neon stream start` complains "kvmfr not loaded" | `sudo modprobe kvmfr static_size_mb=64` (then add to `/etc/modules-load.d/`) |
| `neon stream start` shows "bridge.toml not found" | `neon stream init --accept-eval` first |
| Looking Glass window is black | Single-GPU host without dummy plug — buy a $5 4K HDMI dummy |
| Looking Glass segfaults on first run | Check `~/.cache/neon/logs/looking-glass.log`; usually kvmfr permission |
| Eval license expired | `neon stream license rearm` (eval supports 3 rearms); after that, `neon stream license set --key XXXXX-...` |
| Bridge VM seems stuck | `neon stream repair` — surfaces the exact broken state + fix |
| Microsoft ISO URL 404 | `bridge.toml` override, see "ISO URL pinning" below |

## ISO URL pinning (the V3-Phase C known-stub issue)

Microsoft's eval-center URLs include generated tokens and rotate
~yearly. The pinned URL in V1.0 binaries is captured at compile time;
when it goes stale, users will see:

```
neon: NetworkError: GET https://software-download.microsoft.com/... returned HTTP 404
```

**Fix: override the ISO descriptor in `~/.config/neon/bridge.toml`.**

1. Visit <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-iot-enterprise-ltsc>
   and grab the current download URL.
2. Note the published SHA-256 (Microsoft displays it on the same page).
3. Note the file size in bytes.
4. Edit `~/.config/neon/bridge.toml` (create if missing — `[license]`
   block lives there too):

   ```toml
   [iso]
   url = "https://software-download.microsoft.com/db/<current-token>/26100.<...>.<lang>_x64fre_en-us.iso"
   sha256 = "<64-char-hex-from-microsoft>"
   expected_size = 6500000000   # bytes; Microsoft reports MB, multiply
   ```

5. Re-run `neon stream init --accept-eval`. The override takes
   precedence over the compiled-in default.

Same pattern for the Sunshine installer:

```toml
[sunshine]
url = "https://github.com/LizardByte/Sunshine/releases/download/v0.<latest>/sunshine-windows-installer.exe"
sha256 = "<64-char-hex-from-github-release-page>"
```

## "Capability gate FAILED" (init wizard)

`neon stream init` runs `neon doctor --bridge` first. If anything is
red, it lists every issue at once with per-issue remediation. Common:

- **TPM not detected**: enable fTPM / discrete TPM in BIOS (vendor
  table in [hardware-compat.md](hardware-compat.md)).
- **IOMMU disabled**: enable VT-d (Intel) or AMD-Vi (AMD) in BIOS.
- **Virtualization off**: enable VT-x (Intel) or SVM (AMD).
- **GPU not isolated**: your GPU shares an IOMMU group with the
  chipset / USB hubs. ACS-override kernel patch may help (out of scope
  for V3.0); easiest fix is dual-GPU.
- **kvmfr not supported**: kernel < 5.10. Upgrade to a current LTS.
- **Insufficient disk**: free up space or set `[bridge].data_dir` to
  an external SSD path in `bridge.toml`.

## Looking Glass black screen

The most common cause is **single-GPU host without a dummy HDMI plug**.
The Windows guest doesn't think it has a display, so it doesn't
allocate a framebuffer for Looking Glass to read.

Fix: plug in a $5 4K HDMI dummy plug into a free port on the GPU.

If you have a dummy plug AND the screen is still black:

1. Check `~/.cache/neon/logs/looking-glass.log` for kvmfr errors.
2. Verify `/dev/kvmfr0` permissions: `ls -la /dev/kvmfr0` should show
   `crw-rw---- 1 root kvm`.
3. Verify your user is in the `kvm` group: `groups | grep kvm`.
4. Verify the kvmfr `static_size_mb` matches the IVSHMEM size in the
   libvirt domain XML (default: 64 MB). If you customized
   `[bridge].ivshmem_size_mb` in `bridge.toml`, the modprobe arg
   must match.

## "VM domain `neon-bridge` not defined"

You haven't run `neon stream init`. Run it (or `neon stream repair`
which suggests the same).

If the wizard ran successfully but the domain disappeared (e.g.
you ran `virsh undefine` manually), `neon stream init --accept-eval`
re-runs the provisioning idempotently.

## "Snapshot `fresh` not found"

Run `neon stream repair --refresh-snapshot`. This takes a new `fresh`
snapshot from the current VM state (assumes the VM is currently in a
known-good state).

If the VM itself is broken (the disk image is corrupt or the install
never finished), `neon stream init --accept-eval` re-provisions from
scratch.

## "Eval expires in N days"

`neon stream license show` reports the current posture.

For trial mode, `neon stream license rearm` shows the PowerShell command
the guest runs to re-arm the trial. The guest's autounattend setup
already schedules this 7 days before expiry (via `slmgr.vbs /rearm`),
but if the scheduled task fails you can run it manually inside the LG
window.

After 3 rearms (~360 days total trial), `slmgr /rearm` returns an
error. At that point you need a real Windows license key:

```sh
neon stream license set --key XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
```

## Bridge VM is unresponsive

```sh
neon stream stop          # graceful: snapshots + halts
sudo virsh destroy neon-bridge  # forceful (last resort)
neon stream start          # resume from `fresh`
```

If `stream start` fails, try `neon stream repair` first.

## Cold start is slow (>15 s)

Expected on older hardware (see
[hardware-compat.md](hardware-compat.md)'s performance table). If your
machine is current-gen and cold start is >15 s:

1. Check that the VM is restoring from `fresh` snapshot (not booting
   from scratch). `neon stream status` shows "Fresh snapshot: yes".
2. Verify Looking Glass is using kvmfr, not a fallback:
   `ls -la /dev/kvmfr0` should show the device.
3. Check if Sunshine is binding (the LG client probe waits up to 5s
   for it). Inside the guest: `Get-Service sunshinesvc`.

## Audio doesn't pass through

Sunshine's audio path is the ground truth — Looking Glass just renders
video. Verify:

1. Inside the guest: Sunshine service is running.
2. Sunshine's web UI (default `https://localhost:47990` from the host
   browser) shows audio devices.
3. The host's PulseAudio / PipeWire has a "Sunshine" sink.

If Sunshine UI shows no audio devices, the guest's Windows audio stack
needs a virtual audio cable (VB-Audio Cable, free from
<https://vb-audio.com/Cable/>). Install inside the guest, restart
Sunshine.

## Tray menu doesn't show V3 items

Verify you installed with the feature flag:

```sh
cargo install neon --features experimental-bridge --force
```

Default `cargo install neon` doesn't include V3 code at all (V2 binary
is unchanged for non-V3 users).

After install, restart the daemon: `pkill -SIGTERM neon` then run
`neon` again.

## Uninstall leaves orphans

`neon stream uninstall` removes:

- libvirt domain (undefine + force-stop)
- qcow2 disk image
- ISOs (Win11 + autounattend)
- snapshots (cascaded by libvirt undefine)

It deliberately preserves:

- `~/.config/neon/bridge.toml` (license posture + overrides) — pass
  `--purge` to also remove this.
- The kvmfr kernel module (requires sudo to unload).
- `/etc/udev/rules.d/99-kvmfr.rules` (requires sudo to remove).

For a fully clean state, after `neon stream uninstall --purge`:

```sh
sudo modprobe -r kvmfr
sudo rm /etc/udev/rules.d/99-kvmfr.rules
sudo udevadm control --reload-rules
```

## Reporting bugs

Capture diagnostics:

```sh
neon doctor --bridge --json > /tmp/neon-bridge-doctor.json
neon stream status --json > /tmp/neon-stream-status.json
journalctl --user -u neon -n 200 > /tmp/neon-daemon.log 2>&1
```

Open an issue with all three attached.
