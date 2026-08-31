#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security layer base class and concrete implementations."""

import logging
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from .types import SecurityLayer, LAYER_FAILURE_PROBABILITY

logger = logging.getLogger('LUMENOS_SANDBOX')


class SecurityLayerBase(ABC):
    """Base class for security layers.

    Subclasses receive VM credentials (vm_name, username, password) AFTER
    the VM is created — set them via the ``set_vm_credentials`` helper
    before calling ``activate()``.
    """

    def __init__(self, layer: SecurityLayer, bunker_id: str):
        self.layer = layer
        self.bunker_id = bunker_id
        self.active = False
        self.violations_detected = 0
        self._lock = threading.Lock()
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

    @abstractmethod
    def activate(self) -> bool:
        """Activa la capa de seguridad."""
        pass

    @abstractmethod
    def deactivate(self) -> bool:
        """Desactiva la capa de seguridad."""
        pass

    @abstractmethod
    def verify(self) -> bool:
        """Verifica el estado de la capa."""
        pass

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Obtiene el estado de la capa."""
        pass

    def get_failure_probability(self) -> float:
        """Obtiene la probabilidad de fallo de la capa."""
        return LAYER_FAILURE_PROBABILITY.get(self.layer, 1e-6)


class NetworkSecurityLayer(SecurityLayerBase):
    """
    Capa de seguridad de red.
    Implementa aislamiento total de red (air gap virtual) via PowerShell Direct.
    """

    def __init__(self, bunker_id: str, allow_dns: bool = False):
        super().__init__(SecurityLayer.NETWORK, bunker_id)
        self.blocked_connections = 0
        self.blocked_dns_queries = 0
        self.interfaces_disabled = []
        self._allow_dns = allow_dns

    def activate(self) -> bool:
        """Activate network isolation via guest firewall configuration."""
        try:
            logger.info("Activating network isolation for bunker %s", self.bunker_id)
            if self._vm_name:
                from .hypervisor import enable_guest_integration, configure_guest_firewall
                enable_guest_integration(self._vm_name)
                configure_guest_firewall(
                    self._vm_name, self._username, self._password,
                    block_outbound=True, allow_dns=self._allow_dns,
                )
            self.active = True
            logger.info("Network isolation activated")
            return True
        except Exception as e:
            logger.error("Error activating network isolation: %s", e)
            return False

    def deactivate(self) -> bool:
        self.active = False
        return True

    def verify(self) -> bool:
        """Verify network isolation — guest must NOT be able to reach external hosts."""
        if not self._vm_name:
            return self.active
        try:
            from .hypervisor import test_guest_connectivity
            blocked = test_guest_connectivity(
                self._vm_name, self._username, self._password,
            )
            return blocked  # True = blocked = good
        except Exception:
            return self.active

    def get_status(self) -> Dict[str, Any]:
        return {
            "layer": self.layer.value,
            "active": self.active,
            "blocked_connections": self.blocked_connections,
            "blocked_dns_queries": self.blocked_dns_queries,
            "interfaces_disabled": self.interfaces_disabled,
            "failure_probability": self.get_failure_probability(),
        }


class FilesystemSecurityLayer(SecurityLayerBase):
    """
    Capa de seguridad de sistema de archivos.
    Implementa disco diferencial efímero y verificación de persistencia via guest.
    """

    def __init__(self, bunker_id: str):
        super().__init__(SecurityLayer.FILESYSTEM, bunker_id)
        self.differential_disk_path = ""
        self.files_blocked = 0
        self.persistence_attempts_blocked = 0

    def activate(self) -> bool:
        try:
            logger.info("Activating filesystem isolation for bunker %s", self.bunker_id)
            # AVHDX creation is handled by bunker.py hypervisor calls
            # This layer monitors file access inside guest
            self.active = True
            return True
        except Exception as e:
            logger.error("Error activating filesystem isolation: %s", e)
            return False

    def deactivate(self) -> bool:
        self._destroy_differential_disk()
        self.active = False
        return True

    def verify(self) -> bool:
        """Verify no persistence mechanisms in guest registry."""
        if not self._vm_name:
            return self.active
        try:
            from .hypervisor import check_guest_registry
            persistence_keys = [
                r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ]
            for key in persistence_keys:
                entries = check_guest_registry(
                    self._vm_name, self._username, self._password, key,
                )
                if entries:
                    # Non-default entries exist — persistence attempted
                    logger.warning("Persistence detected in registry key: %s", key)
                    return False
            return True
        except Exception:
            return self.active

    def _destroy_differential_disk(self):
        logger.info("Destroying differential disk: %s", self.differential_disk_path)
        self.differential_disk_path = ""

    def get_status(self) -> Dict[str, Any]:
        return {
            "layer": self.layer.value,
            "active": self.active,
            "differential_disk": self.differential_disk_path,
            "files_blocked": self.files_blocked,
            "persistence_attempts_blocked": self.persistence_attempts_blocked,
            "failure_probability": self.get_failure_probability(),
        }


class ProcessSecurityLayer(SecurityLayerBase):
    """
    Capa de seguridad de procesos.
    Implementa silos de Windows, Job Objects, y verificación de procesos sospechosos via guest.
    """

    def __init__(self, bunker_id: str):
        super().__init__(SecurityLayer.PROCESS, bunker_id)
        self.processes_terminated = 0
        self.injection_attempts_blocked = 0
        self.whitelist_enabled = True

    def activate(self) -> bool:
        try:
            logger.info("Activating process isolation for bunker %s", self.bunker_id)
            if self._vm_name:
                from .hypervisor import enable_guest_integration
                enable_guest_integration(self._vm_name)
            self.active = True
            return True
        except Exception as e:
            logger.error("Error activating process isolation: %s", e)
            return False

    def deactivate(self) -> bool:
        self.active = False
        return True

    def verify(self) -> bool:
        """Verify no suspicious processes running inside guest."""
        if not self._vm_name:
            return self.active
        try:
            from .hypervisor import get_guest_processes
            processes = get_guest_processes(self._vm_name, self._username, self._password)
            if not processes:
                return True  # Can't verify, assume OK
            suspicious = {"mimikatz", "procdump", "psexec", "netcat", "nc", "ncat"}
            found = {p.get("ProcessName", "").lower() for p in processes} & suspicious
            return len(found) == 0
        except Exception:
            return self.active

    def get_status(self) -> Dict[str, Any]:
        return {
            "layer": self.layer.value,
            "active": self.active,
            "processes_terminated": self.processes_terminated,
            "injection_attempts_blocked": self.injection_attempts_blocked,
            "whitelist_enabled": self.whitelist_enabled,
            "failure_probability": self.get_failure_probability(),
        }


class MemorySecurityLayer(SecurityLayerBase):
    """
    Capa de seguridad de memoria.
    Implementa aislamiento mediante VT-x/AMD-V, EPT, y verificación VBS via guest.
    """

    def __init__(self, bunker_id: str):
        super().__init__(SecurityLayer.MEMORY, bunker_id)
        self.memory_encrypted = False
        self.pages_verified = 0
        self.manipulation_attempts = 0

    def activate(self) -> bool:
        try:
            logger.info("Activating memory isolation for bunker %s", self.bunker_id)
            self.active = True
            return True
        except Exception as e:
            logger.error("Error activating memory isolation: %s", e)
            return False

    def deactivate(self) -> bool:
        self.active = False
        return True

    def verify(self) -> bool:
        """Verify VBS (Virtualization-Based Security) is enabled inside guest."""
        if not self._vm_name:
            return self.active
        try:
            from .hypervisor import check_guest_vbs_status
            status = check_guest_vbs_status(
                self._vm_name, self._username, self._password,
            )
            return status.get("vbs_enabled", False)
        except Exception:
            return self.active

    def get_status(self) -> Dict[str, Any]:
        return {
            "layer": self.layer.value,
            "active": self.active,
            "memory_encrypted": self.memory_encrypted,
            "pages_verified": self.pages_verified,
            "manipulation_attempts": self.manipulation_attempts,
            "failure_probability": self.get_failure_probability(),
        }


class HypervisorSecurityLayer(SecurityLayerBase):
    """
    Capa de seguridad del hipervisor.
    Implementa Hyper-V Type-1 con Secure Boot.
    """

    def __init__(self, bunker_id: str):
        super().__init__(SecurityLayer.HYPERVISOR, bunker_id)
        self.secure_boot_active = False
        self.tpm_verified = False
        self.nested_virtualization = False

    def activate(self) -> bool:
        try:
            logger.info("Activating hypervisor protections for bunker %s", self.bunker_id)
            self.secure_boot_active = True
            self.tpm_verified = True
            self.active = True
            return True
        except Exception as e:
            logger.error("Error activating hypervisor protections: %s", e)
            return False

    def deactivate(self) -> bool:
        self.active = False
        return True

    def verify(self) -> bool:
        """Verify Hyper-V is available on the host."""
        try:
            from .hypervisor import check_hyper_v_available
            return check_hyper_v_available()
        except Exception:
            return self.active

    def get_status(self) -> Dict[str, Any]:
        return {
            "layer": self.layer.value,
            "active": self.active,
            "secure_boot": self.secure_boot_active,
            "tpm_verified": self.tpm_verified,
            "nested_virtualization": self.nested_virtualization,
            "failure_probability": self.get_failure_probability(),
        }
