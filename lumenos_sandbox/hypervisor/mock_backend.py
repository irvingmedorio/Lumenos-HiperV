#!/usr/bin/env python3
"""MockBackend — safe defaults for CI without hypervisor."""
import logging
from typing import Optional, Dict, Any, List
from .base import HypervisorBackend, BackendResult
logger = logging.getLogger("LUMENOS_SANDBOX.mock")
class MockBackend(HypervisorBackend):
    def check_available(self) -> bool:
        logger.debug("MockBackend.check_available -> True (mock)")
        return True
    def get_vm_status(self, vm_name: str) -> Optional[str]: return None
    def get_vm_info(self, vm_name: str) -> Optional[Dict[str, Any]]: return None
    def create_vm(self, vm_name: str, memory_mb: int, cpu_cores: int, vhd_path=None, switch_name=None, generation=2) -> bool:
        logger.debug("MockBackend.create_vm %s mock OK", vm_name); return True
    def start_vm(self, vm_name: str) -> bool: return True
    def stop_vm(self, vm_name: str, force=False) -> bool: return True
    def remove_vm(self, vm_name: str, force=True) -> bool: return True
    def create_checkpoint(self, vm_name: str, checkpoint_name: str) -> bool: return True
    def restore_checkpoint(self, vm_name: str, checkpoint_name: str) -> bool: return True
    def create_differencing_disk(self, base_vhd: str, diff_vhd: str) -> bool: return True
    def delete_file(self, path: str) -> bool: return True
    def create_internal_switch(self, switch_name: str) -> bool: return True
    def remove_switch(self, switch_name: str) -> bool: return True
    def verify_host_integrity(self):
        return BackendResult(True, "Mock hypervisor — no host checks", "")
    def enable_guest_integration(self, vm_name: str) -> bool: return True
    def execute_in_guest(self, vm_name: str, username: str, password: str, command: str, timeout: int = 30) -> BackendResult:
        return BackendResult(False, "", "Mock backend — guest unavailable")
    def configure_guest_firewall(self, vm_name: str, username: str, password: str, block_outbound=True, allow_dns=False) -> bool: return True
    def test_guest_connectivity(self, vm_name: str, username: str, password: str, target="8.8.8.8") -> bool: return True
    def get_guest_processes(self, vm_name: str, username: str, password: str) -> List[Dict]: return []
    def kill_guest_process(self, vm_name: str, username: str, password: str, process_name: str) -> bool: return False
    def check_guest_vbs_status(self, vm_name: str, username: str, password: str) -> Dict[str, bool]: return {"vbs_enabled": False, "hvci_enabled": False, "secure_boot": False, "kvm": True}
    def read_guest_event_log(self, vm_name: str, username: str, password: str, log_name="Security", max_events=50) -> List[Dict]: return []
    def check_guest_registry(self, vm_name: str, username: str, password: str, key_path: str) -> List[Dict]: return []
    def install_sysmon_in_guest(self, vm_name: str, username: str, password: str, sysmon_path="C:\\Tools\\Sysmon64.exe") -> bool: return False
