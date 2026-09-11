#!/usr/bin/env bash
# install_kvm_deps.sh — Install KVM/QEMU/libvirt dependencies on Linux
# Detects distro (apt/dnf/pacman) and installs the required packages.
# Idempotent: re-running is safe and fast.
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[FAIL]${NC} $*" >&2; }

# ── Packages required ──────────────────────────────────────────────
APPS=(
    qemu-kvm
    qemu-system-x86
    qemu-utils
    libvirt-daemon-system
    libvirt-clients
    virtinst
    bridge-utils
)

# ── Detect package manager ─────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG="apt"
elif command -v dnf &>/dev/null; then
    PKG="dnf"
elif command -v pacman &>/dev/null; then
    PKG="pacman"
else
    err "Unsupported distro — no apt/dnf/pacman found."
    err "Install manually: ${APPS[*]}"
    exit 1
fi

echo "=== LUMENOS SANDBOX — KVM Dependency Installer ==="
echo "Detected: $PKG"

# ── Install packages ───────────────────────────────────────────────
MAX_ATTEMPTS=3

install_with_retries() {
    local attempt=1
    while (( attempt <= MAX_ATTEMPTS )); do
        if sudo apt-get update && sudo apt-get install -y "${APPS[@]}"; then
            log "Packages installed successfully via apt"
            return 0
        fi
        warn "Attempt $attempt/$MAX_ATTEMPTS failed, retrying in 3s..."
        sleep 3
        ((attempt++))
    done
    return 1
}

case "$PKG" in
    apt)
        if install_with_retries; then
            log "Packages installed"
        else
            err "Failed to install packages after $MAX_ATTEMPTS attempts"
            exit 1
        fi
        ;;
    dnf)
        if sudo dnf install -y "${APPS[@]}"; then
            log "Packages installed successfully via dnf"
        else
            err "Failed to install via dnf"
            exit 1
        fi
        ;;
    pacman)
        if sudo pacman -S --noconfirm --needed "${APPS[@]}"; then
            log "Packages installed successfully via pacman"
        else
            err "Failed to install via pacman"
            exit 1
        fi
        ;;
esac

# ── Add user to groups ─────────────────────────────────────────────
CURRENT_USER="${USER:-$(id -un)}"
for grp in libvirt kvm; do
    if getent group "$grp" &>/dev/null; then
        if id -nG "$CURRENT_USER" 2>/dev/null | grep -qw "$grp"; then
            log "User $CURRENT_USER already in $grp"
        else
            sudo usermod -aG "$grp" "$CURRENT_USER"
            log "Added $CURRENT_USER to $grp (logout/login or reboot required)"
        fi
    else
        warn "Group $grp does not exist — skipping"
    fi
done

# ── Start and enable libvirtd ──────────────────────────────────────
if command -v systemctl &>/dev/null; then
    if sudo systemctl is-active libvirtd &>/dev/null; then
        log "libvirtd is running"
    else
        sudo systemctl enable --now libvirtd
        log "libvirtd started and enabled"
    fi
else
    warn "systemctl not found — start libvirtd manually"
fi

# ── Verify ─────────────────────────────────────────────────────────
echo ""
echo "=== Verification ==="
PASS=true

for bin in virsh qemu-img qemu-system-x86_64; do
    if command -v "$bin" &>/dev/null; then
        log "$bin: $(command -v "$bin")"
    else
        err "$bin: NOT FOUND"
        PASS=false
    fi
done

if [ -e /dev/kvm ]; then
    log "/dev/kvm: exists"
else
    err "/dev/kvm: NOT FOUND — hardware virtualization not available"
    PASS=false
fi

if $PASS; then
    log "All KVM dependencies are ready"
else
    err "Some dependencies are missing"
    err "After a reboot, run: lumenos status"
    exit 1
fi

echo ""
echo "=== INSTALL COMPLETE ==="
echo "Run: lumenos status   — to verify KVM is active"
echo "Note: Log out and back in (or reboot) for group changes to take effect."
