#!/usr/bin/env bash
# check_env.sh — Linux counterpart to check_env.ps1
set -e
echo "=== LUMENOS SANDBOX - ENVIRONMENT CHECK (Linux) ==="
echo "[OS]"; uname -a; echo "[CPU]"; lscpu 2>/dev/null | head -n 20 || cat /proc/cpuinfo | head -n 20
echo "[RAM]"; free -h 2>/dev/null || cat /proc/meminfo | head -n 5
echo "[KVM]"; if [ -e /dev/kvm ]; then echo "  OK: /dev/kvm exists"; ls -l /dev/kvm; else echo "  WARN: /dev/kvm not found — KVM not available"; fi
echo "[libvirt]"; if command -v virsh >/dev/null 2>&1; then virsh --version && echo "  OK: virsh available"; else echo "  WARN: virsh not found — install libvirt-clients"; fi
echo "[qemu-img]"; if command -v qemu-img >/dev/null 2>&1; then qemu-img --version | head -n1; echo "  OK: qemu-img available"; else echo "  WARN: qemu-img not found — install qemu-utils"; fi
echo "[kvm module]"; lsmod | grep -i kvm || echo "  (no kvm module loaded)"
echo "=== CHECK COMPLETE ==="
