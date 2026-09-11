#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Platform detection for cross-platform hypervisor selection."""
import sys
import shutil
from pathlib import Path
from enum import Enum


class HypervisorType(Enum):
    HYPERV = "hyperv"
    KVM = "kvm"
    MOCK = "mock"


def is_windows() -> bool:
    return sys.platform == "win32"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def has_kvm() -> bool:
    return Path("/dev/kvm").exists()


def has_libvirt() -> bool:
    return shutil.which("virsh") is not None


def has_qemu() -> bool:
    return shutil.which("qemu-img") is not None or shutil.which("qemu-system-x86_64") is not None


def detect_hypervisor() -> HypervisorType:
    """Detect the best hypervisor for the current host."""
    import os
    env = os.getenv("LUMENOS_HYPERVISOR", "").lower()
    if env == "mock":
        return HypervisorType.MOCK
    if env == "hyperv":
        return HypervisorType.HYPERV
    if env == "kvm":
        return HypervisorType.KVM
    if is_windows():
        return HypervisorType.HYPERV
    # KVM needs the hardware AND the toolchain that actually operates it.
    if has_kvm() and has_libvirt() and has_qemu():
        return HypervisorType.KVM
    return HypervisorType.MOCK
