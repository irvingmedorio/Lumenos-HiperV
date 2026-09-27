#!/usr/bin/env python3
"""Hypervisor factory — Strategy selection for Hyper-V / KVM / Mock."""
import os
import logging
from typing import Optional
from .base import HypervisorBackend
_backend: Optional[HypervisorBackend] = None
logger = logging.getLogger("LUMENOS_SANDBOX.hypervisor")
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
        # The concrete class is HyperVClient (HyperVBackend is an alias), so the
        # cache guard must compare against the real name or the singleton never
        # caches.
        if _backend is None or _backend.__class__.__name__ != "HyperVClient":
            from .hyperv_backend import HyperVBackend
            _backend = HyperVBackend()
            # Gate on an explicit capability probe instead of swallowing a
            # construction error: the old `except Exception` hid the fact that
            # this class could not be instantiated at all, so Windows silently
            # ran on MockBackend while claiming Hyper-V. The probe is guarded in
            # turn, so a raising probe degrades the factory instead of crashing
            # it — the failure-tolerant behaviour the old swallow provided.
            try:
                available = _backend.check_available()
            except Exception as exc:
                logger.warning(
                    "Hyper-V availability probe raised (%s) — degrading to "
                    "MockBackend", exc,
                )
                available = False
            if not available:
                logger.warning(
                    "Hyper-V requested but not available on this host — "
                    "degrading to MockBackend"
                )
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
        from .hyperv_backend import HyperVBackend
        _backend = HyperVBackend()
        # Same explicit probe as the env branch: no silent construction-failure
        # fallback, and the probe is guarded so a raising probe degrades instead
        # of crashing the factory. Mirror of the Linux branch below.
        try:
            available = _backend.check_available()
        except Exception as exc:
            logger.warning(
                "Hyper-V availability probe raised (%s) — degrading to "
                "MockBackend", exc,
            )
            available = False
        if available:
            return _backend
        logger.warning(
            "Hyper-V not available on this host — degrading to MockBackend"
        )
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
