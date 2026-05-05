#!/usr/bin/env bash
#
# scripts/v3-bridge-setup.sh — One-shot V3 localhost-bridge installer.
#
# Wraps every root-needing operation into a single `pkexec` invocation
# so you see one GUI password prompt, not seven. Idempotent: re-running
# is safe.
#
# Designed for Arch Linux (pacman). For Debian/Ubuntu, adapt the
# package install line manually — everything else is distro-agnostic.
#
# Steps performed (in this order):
#   1. Detect what's already installed; skip the rest if nothing needed
#   2. ONE pkexec prompt that handles ALL root operations:
#        - install missing packages (libvirt, looking-glass, swtpm, etc.)
#        - modprobe kvmfr static_size_mb=64
#        - install /etc/udev/rules.d/99-kvmfr.rules
#        - usermod -aG kvm,libvirt "$USER"
#        - reload + trigger udev
#   3. Build neon with the experimental-bridge feature (user-level)
#   4. Run `neon stream init --accept-eval` (unattended Windows install,
#      ~30-45 min walk-away)
#   5. Print next-step command for watching content
#
# Usage:
#   scripts/v3-bridge-setup.sh

set -euo pipefail

# ─── colors / output helpers ──────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
step() { printf '%b==>%b %s\n' "$GREEN" "$NC" "$1"; }
info() { printf '    %s\n' "$1"; }
warn() { printf '%b!%b %s\n' "$YELLOW" "$NC" "$1"; }
die()  { printf '%b✗%b %s\n' "$RED" "$NC" "$1" >&2; exit 1; }

# ─── preflight ────────────────────────────────────────────────────────
[ "$(id -u)" -ne 0 ] || die "Run as your normal user, NOT root. The script invokes pkexec when it needs root."

command -v pacman >/dev/null || die \
"This script supports Arch Linux only.

For Debian/Ubuntu, install manually:
  sudo apt install libvirt-daemon-system qemu-system-x86 swtpm
  # Looking Glass: see https://looking-glass.io/docs

Then run 'cargo run --features experimental-bridge,experimental-bridge-libvirt -- stream init --accept-eval'."

command -v pkexec >/dev/null || die "pkexec not installed. Run: sudo pacman -S polkit"

if [ -z "${WAYLAND_DISPLAY:-}" ] && [ -z "${DISPLAY:-}" ]; then
    die "No graphical session detected. pkexec needs a GUI to show its prompt."
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

[ -f Cargo.toml ] || die "Cargo.toml not found at $REPO_ROOT — script must run from inside the neon repo."

# ─── detect what's missing ────────────────────────────────────────────
step "Checking system prerequisites…"

MISSING_PKGS=()
for pkg in libvirt looking-glass looking-glass-module-dkms qemu-base swtpm edk2-ovmf; do
    if ! pacman -Qi "$pkg" >/dev/null 2>&1; then
        MISSING_PKGS+=("$pkg")
    fi
done

NEED_KVMFR_LOAD=false
lsmod | awk '{print $1}' | grep -qx kvmfr || NEED_KVMFR_LOAD=true

NEED_UDEV_RULE=false
[ -f /etc/udev/rules.d/99-kvmfr.rules ] || NEED_UDEV_RULE=true

NEED_KVM_GROUP=false
id -nG "$USER" | tr ' ' '\n' | grep -qx kvm || NEED_KVM_GROUP=true

NEED_LIBVIRT_GROUP=false
id -nG "$USER" | tr ' ' '\n' | grep -qx libvirt || NEED_LIBVIRT_GROUP=true

NEED_LIBVIRTD=false
if ! systemctl is-active --quiet libvirtd.service 2>/dev/null; then
    NEED_LIBVIRTD=true
fi

# ─── summarize what will happen ───────────────────────────────────────
NEEDS_ROOT=false
if [ ${#MISSING_PKGS[@]} -gt 0 ]; then NEEDS_ROOT=true; fi
$NEED_KVMFR_LOAD && NEEDS_ROOT=true
$NEED_UDEV_RULE && NEEDS_ROOT=true
$NEED_KVM_GROUP && NEEDS_ROOT=true
$NEED_LIBVIRT_GROUP && NEEDS_ROOT=true
$NEED_LIBVIRTD && NEEDS_ROOT=true

if $NEEDS_ROOT; then
    echo
    info "The following system changes will be made via a single pkexec prompt:"
    [ ${#MISSING_PKGS[@]} -gt 0 ] && info "  • Install packages: ${MISSING_PKGS[*]}"
    $NEED_KVMFR_LOAD     && info "  • Load kvmfr kernel module (static_size_mb=64)"
    $NEED_UDEV_RULE      && info "  • Install /etc/udev/rules.d/99-kvmfr.rules"
    $NEED_KVM_GROUP      && info "  • Add $USER to the kvm group"
    $NEED_LIBVIRT_GROUP  && info "  • Add $USER to the libvirt group"
    $NEED_LIBVIRTD       && info "  • Enable + start libvirtd.service"
    echo
else
    step "All system prerequisites already satisfied — skipping pkexec step."
fi

# ─── build the privileged script (one shot) ───────────────────────────
if $NEEDS_ROOT; then
    PRIVSCRIPT="$(mktemp /tmp/neon-bridge-priv.XXXXXX.sh)"
    chmod 700 "$PRIVSCRIPT"
    trap 'rm -f "$PRIVSCRIPT"' EXIT

    {
        echo '#!/bin/bash'
        echo 'set -euo pipefail'
        echo ': "${NEON_USER:?NEON_USER must be set}"'
        echo

        if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
            echo "pacman -S --noconfirm --needed ${MISSING_PKGS[*]}"
            echo
        fi

        if $NEED_KVMFR_LOAD; then
            cat <<'PRIV'
# kvmfr ships from the looking-glass-module-dkms package; ensure it's
# built for the running kernel before modprobing.
if [ ! -f /lib/modules/"$(uname -r)"/extra/kvmfr.ko* ] 2>/dev/null \
   && [ ! -f /lib/modules/"$(uname -r)"/updates/dkms/kvmfr.ko* ] 2>/dev/null \
   && [ ! -f /usr/lib/modules/"$(uname -r)"/extra/kvmfr.ko* ] 2>/dev/null; then
    dkms autoinstall --kernelver "$(uname -r)" || true
fi
modprobe kvmfr static_size_mb=64
# Persist across reboots
echo "kvmfr" > /etc/modules-load.d/kvmfr.conf
echo "options kvmfr static_size_mb=64" > /etc/modprobe.d/kvmfr.conf
PRIV
            echo
        fi

        if $NEED_UDEV_RULE; then
            cat <<PRIV
cat > /etc/udev/rules.d/99-kvmfr.rules <<'UDEV'
SUBSYSTEM=="kvmfr", OWNER="$NEON_USER", GROUP="kvm", MODE="0660"
UDEV
udevadm control --reload-rules
udevadm trigger
PRIV
            echo
        fi

        if $NEED_KVM_GROUP; then
            echo 'usermod -aG kvm "$NEON_USER"'
        fi
        if $NEED_LIBVIRT_GROUP; then
            echo 'usermod -aG libvirt "$NEON_USER"'
        fi

        if $NEED_LIBVIRTD; then
            echo 'systemctl enable --now libvirtd.service'
        fi
    } > "$PRIVSCRIPT"

    step "Invoking pkexec (single GUI prompt)…"
    pkexec env NEON_USER="$USER" bash "$PRIVSCRIPT"
    rm -f "$PRIVSCRIPT"
    trap - EXIT
fi

# ─── group-membership reminder ────────────────────────────────────────
if $NEED_KVM_GROUP || $NEED_LIBVIRT_GROUP; then
    echo
    warn "You were added to the kvm and/or libvirt group."
    warn "Group membership only takes effect on a new login session."
    warn "Either log out and back in, OR run the rest of this script in a"
    warn "subshell that picks up the new group:"
    echo
    info "  exec sg libvirt -c \"sg kvm -c '$0'\""
    echo
    if [ -t 0 ] && [ -z "${NEON_BRIDGE_NONINTERACTIVE:-}" ]; then
        warn "Press Enter to continue (group applies at next login), or Ctrl-C to exit."
        read -r
    else
        warn "(non-interactive mode: continuing; group changes apply at next login)"
    fi
fi

# ─── build neon with the experimental-bridge feature ──────────────────
echo
step "Building neon with experimental-bridge feature (release)…"
info "First build is slow (~5-10 min). Subsequent builds are fast."
cargo build --features experimental-bridge,experimental-bridge-libvirt --release --jobs 2

NEON="$REPO_ROOT/target/release/neon"
[ -x "$NEON" ] || die "Build failed — $NEON does not exist."

# ─── run hardware capability check ────────────────────────────────────
echo
step "Running 'neon doctor --bridge' to verify hardware is ready…"
"$NEON" doctor --bridge || warn "neon doctor surfaced issues. Read above; the script continues regardless."

# ─── ensure bridge.toml has a current ISO pin (skip if user has one) ──
BRIDGE_TOML="$HOME/.config/neon/bridge.toml"
if [ ! -f "$BRIDGE_TOML" ]; then
    echo
    step "No ~/.config/neon/bridge.toml found."
    info "neon stream init will use the compiled-in 2024 placeholder Microsoft URL/SHA."
    info "If that 404s during ISO download, follow docs/v3/troubleshooting.md to pin"
    info "the current 2026 IoT LTSC URL + SHA-256 in $BRIDGE_TOML."
    info "(The script continues so you can see whether the placeholder still works.)"
fi

# ─── kick off neon stream init ────────────────────────────────────────
echo
step "Running 'neon stream init --accept-eval' — this is the unattended Windows install."
info "Wall time: ~30-45 minutes. ISO download is ~6 GB. You can walk away."
echo

"$NEON" stream init --accept-eval

# ─── done ─────────────────────────────────────────────────────────────
echo
step "✓ Setup complete."
echo
info "Try it now:"
info "  $NEON stream start https://netflix.com"
echo
info "Or use the tray menu — 'Stream Netflix' / 'Stream Disney+' / 'Stream HBO Max'"
info "appear automatically when the daemon is running."
echo
