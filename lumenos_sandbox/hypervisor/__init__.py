#!/usr/bin/env python3
"""Hypervisor factory — Strategy selection for Hyper-V / KVM / Mock."""
import os
from typing import Optional
from .base import HypervisorBackend
_backend: Optional[HypervisorBackend] = None
def get_backend() -> HypervisorBackend:
    global _backend
    env = os.getenv("LUMENOS_HYPERVISOR", "").lower()
    # Env override always takes precedence and bypasses cache
    if env == "mock":
        if _backend is None or _backend.__class__.__name__ != "MockBackend":
            from .mock_backend import MockBackend
            _backend = MockBackend()
        return _backend
    if env == "hyperv":
        if _backend is None or _backend.__class__.__name__ != "HyperVBackend":
            try:
                from .hyperv_backend import HyperVBackend
                _backend = HyperVBackend()
            except Exception:
                from .mock_backend import MockBackend
                _backend = MockBackend()
        return _backend
    if env == "kvm":
        if _backend is None or _backend.__class__.__name__ != "KvmBackend":
            from .kvm_backend import KvmBackend
            _backend = KvmBackend()
        return _backend
    # No env override — use cached if exists
    if _backend is not None:
        return _backend
    import sys
    if sys.platform == "win32":
        try:
            from .hyperv_backend import HyperVBackend
            _backend = HyperVBackend()
        except Exception:
            from .mock_backend import MockBackend
            _backend = MockBackend()
        return _backend
    from ..platform import has_kvm, has_libvirt, has_qemu
    try:
        if has_kvm() or has_libvirt() or has_qemu():
            from .kvm_backend import KvmBackend
            _backend = KvmBackend()
            if _backend.check_available():
                return _backend
    except Exception:
        pass
    from .mock_backend import MockBackend
    _backend = MockBackend()
    return _backend
def set_backend(b: Optional[HypervisorBackend]) -> None:
    global _backend
    _backend = b
def reset_backend() -> None:
    global _backend
    _backend = None
__all__ = ["get_backend","set_backend","reset_backend","HypervisorBackend"]
