#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shim — delegates to hypervisor factory for cross-platform support."""
from .hypervisor import get_backend  # type: ignore
from .hypervisor.base import BackendResult
# Re-export PSResult for compat
PSResult = BackendResult
def _run_ps(command, timeout=30):
    b = get_backend()
    # HyperVBackend has _run_ps, Mock/KVM may not; fallback
    if hasattr(b, "_run_ps"):
        return b._run_ps(command, timeout)
    import subprocess
    for exe in ("pwsh","powershell"):
        try:
            r = subprocess.run([exe,"-NoProfile","-ExecutionPolicy","Bypass","-Command",command], capture_output=True, text=True, timeout=timeout)
            if r.returncode==0: return (True, r.stdout.strip(), r.stderr.strip())
            return (False, "", r.stderr.strip())
        except FileNotFoundError: continue
        except Exception as e: return (False, "", str(e))
    return (False, "", "No PowerShell")
def _escape_ps_command(c): return c.replace("'","''")
def _get_vm_state(n): return get_backend().get_vm_status(n)
def check_hyper_v_available(): return get_backend().check_available()
def get_vm_status(n): return get_backend().get_vm_status(n)
def get_vm_info(n): return get_backend().get_vm_info(n)
def create_vm(n, m, c, vhd_path=None, switch_name=None, generation=2): return get_backend().create_vm(n,m,c,vhd_path,switch_name,generation)
def start_vm(n): return get_backend().start_vm(n)
def stop_vm(n, force=False): return get_backend().stop_vm(n,force)
def remove_vm(n, force=True): return get_backend().remove_vm(n,force)
def create_checkpoint(n,c): return get_backend().create_checkpoint(n,c)
def restore_checkpoint(n,c): return get_backend().restore_checkpoint(n,c)
def create_differencing_disk(b,d): return get_backend().create_differencing_disk(b,d)
def delete_file(p): return get_backend().delete_file(p)
def create_internal_switch(n): return get_backend().create_internal_switch(n)
def remove_switch(n): return get_backend().remove_switch(n)
def verify_host_integrity():
    r = get_backend().verify_host_integrity()
    if isinstance(r, BackendResult): return (r.success, r.stdout or r.stderr)
    return r
def enable_guest_integration(n): return get_backend().enable_guest_integration(n)
def execute_in_guest(vm,u,p,c,timeout=30):
    r = get_backend().execute_in_guest(vm,u,p,c,timeout)
    if isinstance(r, BackendResult): return (r.success, r.stdout or r.stderr)
    return r
def configure_guest_firewall(vm,u,p,block_outbound=True, allow_dns=False): return get_backend().configure_guest_firewall(vm,u,p,block_outbound,allow_dns)
def test_guest_connectivity(vm,u,p,target="8.8.8.8"): return get_backend().test_guest_connectivity(vm,u,p,target)
def get_guest_processes(vm,u,p): return get_backend().get_guest_processes(vm,u,p)
def kill_guest_process(vm,u,p,proc): return get_backend().kill_guest_process(vm,u,p,proc)
def check_guest_vbs_status(vm,u,p): return get_backend().check_guest_vbs_status(vm,u,p)
def read_guest_event_log(vm,u,p,log_name="Security",max_events=50): return get_backend().read_guest_event_log(vm,u,p,log_name,max_events)
def check_guest_registry(vm,u,p,k): return get_backend().check_guest_registry(vm,u,p,k)
def install_sysmon_in_guest(vm,u,p,sysmon_path="C:\\Tools\\Sysmon64.exe"): return get_backend().install_sysmon_in_guest(vm,u,p,sysmon_path)
