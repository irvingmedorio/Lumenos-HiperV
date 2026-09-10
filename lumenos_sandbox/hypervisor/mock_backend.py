#!/usr/bin/env python3
"""MockBackend — safe defaults for CI without hypervisor."""
import logging
from typing import Optional, Dict, Any, List
from .base import HypervisorBackend, BackendResult
from unittest.mock import MagicMock
logger = logging.getLogger("LUMENOS_SANDBOX.mock")
def _is_mocked(mod, name):
    # Also check decontamination module for compatibility
    try:
        import importlib; m=importlib.import_module(mod)
        return isinstance(getattr(m, name, None), MagicMock)
    except: return False
def _delegate(mod, name, *a, **kw):
    import importlib; m=importlib.import_module(mod)
    fn=getattr(m, name)
    if isinstance(fn, MagicMock):
        r=fn(*a, **kw)
        # Handle PSResult vs bool
        if hasattr(r, 'success'): return r
        return r
    return None
class MockBackend(HypervisorBackend):
    def check_available(self) -> bool:
        # Respect patched hyperv_client
        if _is_mocked("lumenos_sandbox.hyperv_client", "check_hyper_v_available"):
            import lumenos_sandbox.hyperv_client as hc
            return bool(hc.check_hyper_v_available())
        if _is_mocked("lumenos_sandbox.hypervisor", "check_hyper_v_available"):
            import lumenos_sandbox.hypervisor as hv
            return bool(hv.check_hyper_v_available())
        logger.debug("MockBackend.check_available -> True (mock)")
        return True
    def get_vm_status(self, vm_name: str) -> Optional[str]:
        r=_delegate("lumenos_sandbox.hyperv_client","get_vm_status", vm_name)
        if r is not None: return r
        r=_delegate("lumenos_sandbox.decontamination","get_vm_status", vm_name)
        if r is not None: return r
        return None
    def get_vm_info(self, vm_name: str) -> Optional[Dict[str, Any]]:
        r=_delegate("lumenos_sandbox.hyperv_client","get_vm_info", vm_name)
        if r is not None: return r
        return None
    def create_vm(self, vm_name: str, memory_mb: int, cpu_cores: int, vhd_path=None, switch_name=None, generation=2) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","create_vm", vm_name, memory_mb, cpu_cores, vhd_path, switch_name, generation)
        if r is not None: return bool(r)
        logger.debug("MockBackend.create_vm %s mock OK", vm_name); return True
    def start_vm(self, vm_name: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","start_vm", vm_name)
        if r is not None: return bool(r)
        return True
    def stop_vm(self, vm_name: str, force=False) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","stop_vm", vm_name, force)
        if r is not None: return bool(r)
        return True
    def remove_vm(self, vm_name: str, force=True) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","remove_vm", vm_name, force)
        if r is not None: return bool(r)
        r=_delegate("lumenos_sandbox.decontamination","remove_vm", vm_name, force)
        if r is not None: return bool(r)
        return True
    def create_checkpoint(self, vm_name: str, checkpoint_name: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","create_checkpoint", vm_name, checkpoint_name)
        if r is not None: return bool(r)
        return True
    def restore_checkpoint(self, vm_name: str, checkpoint_name: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","restore_checkpoint", vm_name, checkpoint_name)
        if r is not None: return bool(r)
        return True
    def create_differencing_disk(self, base_vhd: str, diff_vhd: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","create_differencing_disk", base_vhd, diff_vhd)
        if r is not None: return bool(r)
        return True
    def delete_file(self, path: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","delete_file", path)
        if r is not None: return bool(r)
        r=_delegate("lumenos_sandbox.decontamination","delete_file", path)
        if r is not None: return bool(r)
        return True
    def create_internal_switch(self, switch_name: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","create_internal_switch", switch_name)
        if r is not None: return bool(r)
        return True
    def remove_switch(self, switch_name: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","remove_switch", switch_name)
        if r is not None: return bool(r)
        r=_delegate("lumenos_sandbox.decontamination","remove_switch", switch_name)
        if r is not None: return bool(r)
        return True
    def verify_host_integrity(self):
        if _is_mocked("lumenos_sandbox.hyperv_client", "verify_host_integrity") or _is_mocked("lumenos_sandbox.decontamination", "verify_host_integrity"):
            import lumenos_sandbox.hyperv_client as hc
            r=hc.verify_host_integrity()
            if hasattr(r, 'success'): return r
            if isinstance(r, tuple): return BackendResult(r[0], r[1], "")
            return BackendResult(bool(r), str(r), "")
        return BackendResult(True, "Mock hypervisor — no host checks", "")
    def enable_guest_integration(self, vm_name: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","enable_guest_integration", vm_name)
        if r is not None: return bool(r)
        return True
    def execute_in_guest(self, vm_name: str, username: str, password: str, command: str, timeout: int = 30) -> BackendResult:
        if _is_mocked("lumenos_sandbox.hyperv_client", "execute_in_guest"):
            import lumenos_sandbox.hyperv_client as hc
            r=hc.execute_in_guest(vm_name, username, password, command, timeout)
            if isinstance(r, tuple): return BackendResult(r[0], r[1], "" if r[0] else r[1])
            if hasattr(r, 'success'): return r
            return BackendResult(bool(r), str(r), "")
        return BackendResult(False, "", "Mock backend — guest unavailable")
    def configure_guest_firewall(self, vm_name: str, username: str, password: str, block_outbound=True, allow_dns=False) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","configure_guest_firewall", vm_name, username, password, block_outbound, allow_dns)
        if r is not None: return bool(r)
        return True
    def test_guest_connectivity(self, vm_name: str, username: str, password: str, target="8.8.8.8") -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","test_guest_connectivity", vm_name, username, password, target)
        if r is not None: return bool(r)
        return True
    def get_guest_processes(self, vm_name: str, username: str, password: str) -> List[Dict]:
        r=_delegate("lumenos_sandbox.hyperv_client","get_guest_processes", vm_name, username, password)
        if r is not None: return r
        return []
    def kill_guest_process(self, vm_name: str, username: str, password: str, process_name: str) -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","kill_guest_process", vm_name, username, password, process_name)
        if r is not None: return bool(r)
        return False
    def check_guest_vbs_status(self, vm_name: str, username: str, password: str) -> Dict[str, bool]:
        r=_delegate("lumenos_sandbox.hyperv_client","check_guest_vbs_status", vm_name, username, password)
        if r is not None: return r
        return {"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True, "kvm": True}
    def read_guest_event_log(self, vm_name: str, username: str, password: str, log_name="Security", max_events=50) -> List[Dict]:
        r=_delegate("lumenos_sandbox.hyperv_client","read_guest_event_log", vm_name, username, password, log_name, max_events)
        if r is not None: return r
        r=_delegate("lumenos_sandbox.decontamination","read_guest_event_log", vm_name, username, password, log_name, max_events)
        if r is not None: return r
        return []
    def check_guest_registry(self, vm_name: str, username: str, password: str, key_path: str) -> List[Dict]:
        r=_delegate("lumenos_sandbox.hyperv_client","check_guest_registry", vm_name, username, password, key_path)
        if r is not None: return r
        return []
    def install_sysmon_in_guest(self, vm_name: str, username: str, password: str, sysmon_path="C:\Tools\Sysmon64.exe") -> bool:
        r=_delegate("lumenos_sandbox.hyperv_client","install_sysmon_in_guest", vm_name, username, password, sysmon_path)
        if r is not None: return bool(r)
        return False
