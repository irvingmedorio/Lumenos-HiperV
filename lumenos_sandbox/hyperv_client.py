#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shim — delegates to hypervisor factory (keeps old imports working)."""
from .hypervisor import get_backend
from .hypervisor.base import BackendResult as PSResult
from dataclasses import dataclass as _dataclass
# Re-export for callers that import PSResult
__all__ = ["PSResult","HyperVClient","HyperVBackend","check_hyper_v_available","get_vm_status","get_vm_info","create_vm","start_vm","stop_vm","remove_vm","create_checkpoint","restore_checkpoint","create_differencing_disk","delete_file","create_internal_switch","remove_switch","verify_host_integrity","enable_guest_integration","execute_in_guest","configure_guest_firewall","test_guest_connectivity","get_guest_processes","kill_guest_process","check_guest_vbs_status","read_guest_event_log","check_guest_registry","install_sysmon_in_guest"]
# Keep class aliases for isinstance checks
try:
    from .hypervisor.hyperv_backend import HyperVClient, HyperVBackend
    _default_client = None
    def _get_client(): return get_backend()
except Exception:
    HyperVClient = object
    HyperVBackend = object
    def _get_client(): return get_backend()
def _run_ps(*a,**k): return get_backend()._run_ps(*a,**k) if hasattr(get_backend(),"_run_ps") else (False,"","no ps")
def _escape_ps_command(c): return c.replace("'","''")
def _get_vm_state(n): return get_backend().get_vm_status(n)
def check_hyper_v_available(): return get_backend().check_available()
def get_vm_status(n): return get_backend().get_vm_status(n)
def get_vm_info(n): return get_backend().get_vm_info(n)
def create_vm(n,m,c,vhd_path=None,switch_name=None,generation=2): return get_backend().create_vm(n,m,c,vhd_path,switch_name,generation)
def start_vm(n): return get_backend().start_vm(n)
def stop_vm(n,force=False): return get_backend().stop_vm(n,force)
def remove_vm(n,force=True): return get_backend().remove_vm(n,force)
def create_checkpoint(n,c): return get_backend().create_checkpoint(n,c)
def restore_checkpoint(n,c): return get_backend().restore_checkpoint(n,c)
def create_differencing_disk(b,d): return get_backend().create_differencing_disk(b,d)
def delete_file(p): return get_backend().delete_file(p)
def create_internal_switch(n): return get_backend().create_internal_switch(n)
def remove_switch(n): return get_backend().remove_switch(n)
def verify_host_integrity():
    r=get_backend().verify_host_integrity()
    if isinstance(r, PSResult): return r
    if isinstance(r, tuple): return PSResult(r[0], r[1], "" if r[0] else r[1])
    return r
def enable_guest_integration(n): return get_backend().enable_guest_integration(n)
def execute_in_guest(vm,u,p,c,timeout=30):
    r=get_backend().execute_in_guest(vm,u,p,c,timeout)
    if isinstance(r, PSResult): return r
    if isinstance(r, tuple): return PSResult(r[0], r[1], "" if r[0] else r[1])
    return r
def configure_guest_firewall(vm,u,p,block_outbound=True,allow_dns=False): return get_backend().configure_guest_firewall(vm,u,p,block_outbound,allow_dns)
def test_guest_connectivity(vm,u,p,target="8.8.8.8"): return get_backend().test_guest_connectivity(vm,u,p,target)
def get_guest_processes(vm,u,p): return get_backend().get_guest_processes(vm,u,p)
def kill_guest_process(vm,u,p,proc): return get_backend().kill_guest_process(vm,u,p,proc)
def check_guest_vbs_status(vm,u,p): return get_backend().check_guest_vbs_status(vm,u,p)
def read_guest_event_log(vm,u,p,log_name="Security",max_events=50): return get_backend().read_guest_event_log(vm,u,p,log_name,max_events)
def check_guest_registry(vm,u,p,k): return get_backend().check_guest_registry(vm,u,p,k)
def install_sysmon_in_guest(vm,u,p,sysmon_path="C:\\Tools\\Sysmon64.exe"): return get_backend().install_sysmon_in_guest(vm,u,p,sysmon_path)
