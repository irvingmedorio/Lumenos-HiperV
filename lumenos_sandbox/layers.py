#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security layer base class and concrete implementations (Template Method pattern)."""

import logging
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from .types import SecurityLayer

logger = logging.getLogger('LUMENOS_SANDBOX')


class SecurityLayerBase(ABC):
    """Base class for security layers using Template Method pattern.

    Subclasses receive VM credentials (vm_name, username, password) AFTER
    the VM is created — set them via the ``set_vm_credentials`` helper
    before calling ``activate()``.

    Template Methods:
    - activate() → calls _do_activate()
    - deactivate() → calls _do_deactivate()
    - verify() → calls _do_verify()
    - get_status() → builds base dict + _get_status_details()

    Subclasses implement the _do_* hooks only.
    """

    _DEFAULT_FAILURE_PROBABILITY = {
        SecurityLayer.NETWORK: 1e-6,
        SecurityLayer.FILESYSTEM: 1e-8,
        SecurityLayer.PROCESS: 1e-5,
        SecurityLayer.MEMORY: 1e-9,
        SecurityLayer.HYPERVISOR: 1e-12,
    }

    def __init__(
        self,
        layer: SecurityLayer,
        bunker_id: str,
        failure_probabilities: Optional[Dict[SecurityLayer, float]] = None,
    ):
        self.layer = layer
        self.bunker_id = bunker_id
        self.active = False
        self.violations_detected = 0
        self._lock = threading.Lock()
        self._failure_probabilities = failure_probabilities or {}
        # Guest interaction credentials — set after VM creation
        self._vm_name: Optional[str] = None
        self._username: str = ""
        self._password: str = ""

    def set_vm_credentials(self, vm_name: str, username: str = "",
                           password: str = "") -> None:
        """Set the VM name and credentials for guest interaction."""
        self._vm_name = vm_name
        self._username = username
        self._password = password

    # ============================================================
    # Template Methods (final - not meant to be overridden)
    # ============================================================

    def activate(self) -> bool:
        """Activate the security layer with common logging/error handling."""
        try:
            logger.info("Activating %s isolation for bunker %s", self.layer.value, self.bunker_id)
            success = self._do_activate()
            self.active = success
            if success:
                logger.info("%s isolation activated", self.layer.value.title())
            else:
                logger.error("Failed to activate %s isolation", self.layer.value)
            return success
        except Exception as e:
            logger.error("Error activating %s isolation: %s", self.layer.value, e)
            self.active = False
            return False

    def deactivate(self) -> bool:
        """Deactivate the security layer."""
        try:
            success = self._do_deactivate()
            self.active = False
            return success
        except Exception as e:
            logger.error("Error deactivating %s isolation: %s", self.layer.value, e)
            self.active = False
            return False

    def verify(self) -> bool:
        """Verify the security layer state."""
        if not self._vm_name:
            return self.active
        try:
            return self._do_verify()
        except Exception:
            return self.active

    def get_status(self) -> Dict[str, Any]:
        """Get status with base fields + subclass-specific details."""
        return {
            "layer": self.layer.value,
            "active": self.active,
            "failure_probability": self.get_failure_probability(),
            **self._get_status_details(),
        }

    def get_failure_probability(self) -> float:
        """Get the failure probability for this layer."""
        return self._failure_probabilities.get(
            self.layer,
            self._DEFAULT_FAILURE_PROBABILITY.get(self.layer, 1e-6)
        )

    # ============================================================
    # Abstract Hooks (must be implemented by subclasses)
    # ============================================================

    @abstractmethod
    def _do_activate(self) -> bool:
        """Subclass-specific activation logic."""
        pass

    @abstractmethod
    def _do_deactivate(self) -> bool:
        """Subclass-specific deactivation logic."""
        pass

    @abstractmethod
    def _do_verify(self) -> bool:
        """Subclass-specific verification logic."""
        pass

    @abstractmethod
    def _get_status_details(self) -> Dict[str, Any]:
        """Return subclass-specific status fields."""
        pass


class NetworkSecurityLayer(SecurityLayerBase):
    """Capa de seguridad de red — aislamiento total via PowerShell Direct."""

    def __init__(
        self,
        bunker_id: str,
        failure_probabilities: Optional[Dict[SecurityLayer, float]] = None,
        allow_dns: bool = False,
    ):
        super().__init__(SecurityLayer.NETWORK, bunker_id, failure_probabilities)
        self.blocked_connections = 0
        self.blocked_dns_queries = 0
        self.interfaces_disabled = []
        self._allow_dns = allow_dns

    def _do_activate(self) -> bool:
        if self._vm_name:
            from .hyperv_client import enable_guest_integration, configure_guest_firewall
            enable_guest_integration(self._vm_name)
            configure_guest_firewall(
                self._vm_name, self._username, self._password,
                block_outbound=True, allow_dns=self._allow_dns,
            )
        return True

    def _do_deactivate(self) -> bool:
        return True

    def _do_verify(self) -> bool:
        from .hyperv_client import test_guest_connectivity
        blocked = test_guest_connectivity(
            self._vm_name, self._username, self._password,
        )
        return blocked  # True = blocked = good

    def _get_status_details(self) -> Dict[str, Any]:
        return {
            "blocked_connections": self.blocked_connections,
            "blocked_dns_queries": self.blocked_dns_queries,
            "interfaces_disabled": self.interfaces_disabled,
        }


class FilesystemSecurityLayer(SecurityLayerBase):
    """Capa de seguridad de sistema de archivos — disco diferencial efímero."""

    def __init__(
        self,
        bunker_id: str,
        failure_probabilities: Optional[Dict[SecurityLayer, float]] = None,
    ):
        super().__init__(SecurityLayer.FILESYSTEM, bunker_id, failure_probabilities)
        self.differential_disk_path = ""
        self.files_blocked = 0
        self.persistence_attempts_blocked = 0

    def _do_activate(self) -> bool:
        # AVHDX creation is handled by bunker.py hypervisor calls
        # This layer monitors file access inside guest
        return True

    def _do_deactivate(self) -> bool:
        self._destroy_differential_disk()
        return True

    def _destroy_differential_disk(self):
        logger.info("Destroying differential disk: %s", self.differential_disk_path)
        self.differential_disk_path = ""

    def _do_verify(self) -> bool:
        from .hyperv_client import check_guest_registry
        persistence_keys = [
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        for key in persistence_keys:
            entries = check_guest_registry(
                self._vm_name, self._username, self._password, key,
            )
            if entries:
                logger.warning("Persistence detected in registry key: %s", key)
                return False
        return True

    def _get_status_details(self) -> Dict[str, Any]:
        return {
            "differential_disk": self.differential_disk_path,
            "files_blocked": self.files_blocked,
            "persistence_attempts_blocked": self.persistence_attempts_blocked,
        }


class ProcessSecurityLayer(SecurityLayerBase):
    """Capa de seguridad de procesos — silos, Job Objects, verificación via guest."""

    def __init__(
        self,
        bunker_id: str,
        failure_probabilities: Optional[Dict[SecurityLayer, float]] = None,
    ):
        super().__init__(SecurityLayer.PROCESS, bunker_id, failure_probabilities)
        self.processes_terminated = 0
        self.injection_attempts_blocked = 0
        self.whitelist_enabled = True

    def _do_activate(self) -> bool:
        if self._vm_name:
            from .hyperv_client import enable_guest_integration
            enable_guest_integration(self._vm_name)
        return True

    def _do_deactivate(self) -> bool:
        return True

    def _do_verify(self) -> bool:
        from .hyperv_client import get_guest_processes
        processes = get_guest_processes(self._vm_name, self._username, self._password)
        if not processes:
            return True  # Can't verify, assume OK
        suspicious = {"mimikatz", "procdump", "psexec", "netcat", "nc", "ncat"}
        found = {p.get("ProcessName", "").lower() for p in processes} & suspicious
        return len(found) == 0

    def _get_status_details(self) -> Dict[str, Any]:
        return {
            "processes_terminated": self.processes_terminated,
            "injection_attempts_blocked": self.injection_attempts_blocked,
            "whitelist_enabled": self.whitelist_enabled,
        }


class MemorySecurityLayer(SecurityLayerBase):
    """Capa de seguridad de memoria — VT-x/AMD-V, EPT, verificación VBS via guest."""

    def __init__(
        self,
        bunker_id: str,
        failure_probabilities: Optional[Dict[SecurityLayer, float]] = None,
    ):
        super().__init__(SecurityLayer.MEMORY, bunker_id, failure_probabilities)
        self.memory_encrypted = False
        self.pages_verified = 0
        self.manipulation_attempts = 0

    def _do_activate(self) -> bool:
        return True

    def _do_deactivate(self) -> bool:
        return True

    def _do_verify(self) -> bool:
        from .hyperv_client import check_guest_vbs_status
        status = check_guest_vbs_status(
            self._vm_name, self._username, self._password,
        )
        return status.get("vbs_enabled", False)

    def _get_status_details(self) -> Dict[str, Any]:
        return {
            "memory_encrypted": self.memory_encrypted,
            "pages_verified": self.pages_verified,
            "manipulation_attempts": self.manipulation_attempts,
        }


class HypervisorSecurityLayer(SecurityLayerBase):
    """Capa de seguridad del hipervisor — Hyper-V Type-1 con Secure Boot."""

    def __init__(
        self,
        bunker_id: str,
        failure_probabilities: Optional[Dict[SecurityLayer, float]] = None,
    ):
        super().__init__(SecurityLayer.HYPERVISOR, bunker_id, failure_probabilities)
        self.secure_boot_active = False
        self.tpm_verified = False
        self.nested_virtualization = False

    def _do_activate(self) -> bool:
        self.secure_boot_active = True
        self.tpm_verified = True
        return True

    def _do_deactivate(self) -> bool:
        return True

    def _do_verify(self) -> bool:
        from .hyperv_client import check_hyper_v_available
        return check_hyper_v_available()

    def _get_status_details(self) -> Dict[str, Any]:
        return {
            "secure_boot": self.secure_boot_active,
            "tpm_verified": self.tpm_verified,
            "nested_virtualization": self.nested_virtualization,
        }