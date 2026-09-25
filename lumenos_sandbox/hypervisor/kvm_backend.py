#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KvmBackend — KVM/QEMU/libvirt implementation of HypervisorBackend."""
import hashlib
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List
from .base import HypervisorBackend, BackendResult
logger = logging.getLogger("LUMENOS_SANDBOX.kvm")

def _isolated_network_xml(switch_name: str) -> str:
    """Build the XML for one bunker's isolated libvirt network.

    ``mode='none'`` pins the network to isolated: no NAT, no route, no LAN. An
    absent ``<forward>`` already means isolated, but stating it keeps a later
    edit from silently turning a bunker into a NAT cage.

    Bridge name and subnet are derived from the FULL switch name. The previous
    ``switch_name[:8]`` prefix was always the literal ``"lumenos_"``, so every
    network claimed the same bridge and the same 192.168.200.0/24: a second
    bunker either failed to start or landed on the first bunker's L2 segment,
    putting two samples on one wire. The hash keeps both unique and
    deterministic (so a re-define is idempotent), with the interface name
    inside the 15-character Linux limit and the address inside 10.0.0.0/8.
    """
    digest = hashlib.sha256(switch_name.encode("utf-8")).hexdigest()
    iface = "br-" + digest[:12]                      # 15 chars: IFNAMSIZ-1
    subnet = f"10.{int(digest[12:14], 16)}.{int(digest[14:16], 16)}.1"
    return (
        f"<network><name>{switch_name}</name>"
        f"<forward mode='none'/>"
        f"<bridge name='{iface}'/>"
        f"<ip address='{subnet}' netmask='255.255.255.0'/>"
        f"</network>"
    )

class KvmBackend(HypervisorBackend):
    def _run(self, cmd: List[str], timeout: int = 30):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
        except Exception as e:
            return False, "", str(e)
    def _run_virsh(self, args: str, timeout=30):
        return self._run(["virsh"] + args.split(), timeout)
    def check_available(self) -> bool:
        # /dev/kvm alone is not enough: virsh is required to operate VMs,
        # qemu-img to create disks. Without both, degrade to Mock instead of
        # selecting KVM and failing at runtime.
        if not shutil.which("virsh") or not shutil.which("qemu-img"):
            return False
        ok, _, _ = self._run(["virsh","--version"], timeout=5)
        return ok
    def get_vm_status(self, vm_name: str) -> Optional[str]:
        ok, out, _ = self._run(["virsh","domstate", vm_name], timeout=10)
        if ok and out: return out
        return None
    def get_vm_info(self, vm_name: str) -> Optional[Dict[str, Any]]:
        ok, out, _ = self._run(["virsh","dumpxml", vm_name], timeout=10)
        if ok and out: return {"xml": out, "name": vm_name}
        return None
    def create_vm(self, vm_name: str, memory_mb: int, cpu_cores: int, vhd_path: Optional[str]=None, switch_name: Optional[str]=None, generation: int=2) -> bool:
        try:
            if vhd_path:
                Path(vhd_path).parent.mkdir(parents=True, exist_ok=True)
                ok, _, err = self._run(["qemu-img","create","-f","qcow2", vhd_path, "100G"], timeout=60)
                if not ok: logger.warning("qemu-img create failed: %s", err)
            net_xml = f"<interface type='network'><source network='{switch_name}'/></interface>" if switch_name else ""
            disk_xml = f"<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='{vhd_path}'/><target dev='vda' bus='virtio'/></disk>" if vhd_path else ""
            xml = f"<domain type='kvm'><name>{vm_name}</name><memory unit='MiB'>{memory_mb}</memory><vcpu>{cpu_cores}</vcpu><os><type arch='x86_64' machine='pc'>hvm</type><boot dev='hd'/></os><devices>{disk_xml}{net_xml}<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel></devices></domain>"
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                f.write(xml); tmp=f.name
            try:
                ok, _, err = self._run(["virsh","define", tmp], timeout=30)
                if not ok: logger.warning("virsh define failed: %s", err); return False
            finally:
                try: os.unlink(tmp)
                except: pass
            logger.info("KVM VM %s created (%dMB %d CPUs)", vm_name, memory_mb, cpu_cores)
            return True
        except Exception as e:
            logger.warning("create_vm failed: %s", e); return False
    def start_vm(self, vm_name: str) -> bool:
        ok, _, err = self._run(["virsh","start", vm_name], timeout=60)
        if not ok: logger.warning("start_vm failed: %s", err)
        return ok
    def stop_vm(self, vm_name: str, force=False) -> bool:
        cmd = ["virsh","destroy", vm_name] if force else ["virsh","shutdown", vm_name]
        ok, _, err = self._run(cmd, timeout=60)
        if not ok: logger.warning("stop_vm failed: %s", err)
        return ok
    def remove_vm(self, vm_name: str, force=True) -> bool:
        self.stop_vm(vm_name, force=True)
        ok, _, err = self._run(["virsh","undefine", vm_name, "--remove-all-storage"], timeout=30)
        if not ok:
            ok2, _, _ = self._run(["virsh","undefine", vm_name], timeout=30)
            ok = ok2
        if not ok: logger.warning("remove_vm failed: %s", err)
        return ok
    def create_checkpoint(self, vm_name: str, checkpoint_name: str) -> bool:
        ok, _, err = self._run(["virsh","snapshot-create-as", vm_name, checkpoint_name], timeout=60)
        if not ok: logger.warning("checkpoint failed: %s", err)
        return ok
    def restore_checkpoint(self, vm_name: str, checkpoint_name: str) -> bool:
        ok, _, err = self._run(["virsh","snapshot-revert", vm_name, checkpoint_name], timeout=60)
        if not ok: logger.warning("restore checkpoint failed: %s", err)
        return ok
    def create_differencing_disk(self, base_vhd: str, diff_vhd: str) -> bool:
        Path(diff_vhd).parent.mkdir(parents=True, exist_ok=True)
        ok, _, err = self._run(["qemu-img","create","-f","qcow2","-b", base_vhd, diff_vhd], timeout=30)
        if not ok: logger.warning("differencing disk failed: %s", err)
        return ok
    def delete_file(self, path: str) -> bool:
        try: Path(path).unlink(missing_ok=True); return True
        except Exception as e: logger.warning("delete_file %s: %s", path, e); return False
    def create_internal_switch(self, switch_name: str) -> bool:
        """Create this bunker's isolated network (see ``_isolated_network_xml``)."""
        xml = _isolated_network_xml(switch_name)
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml); tmp=f.name
        try:
            ok, _, err = self._run(["virsh","net-define", tmp], timeout=15)
            if not ok: logger.warning("net-define failed: %s", err); return False
            self._run(["virsh","net-start", switch_name], timeout=15)
            self._run(["virsh","net-autostart", switch_name], timeout=15)
            return True
        finally:
            try: os.unlink(tmp)
            except: pass
    def remove_switch(self, switch_name: str) -> bool:
        self._run(["virsh","net-destroy", switch_name], timeout=15)
        ok, _, err = self._run(["virsh","net-undefine", switch_name], timeout=15)
        if not ok: logger.debug("remove_switch %s: %s", switch_name, err)
        return True
    def verify_host_integrity(self):
        if not self.check_available():
            return BackendResult(False, "", "KVM not available")
        return BackendResult(True, "KVM available", "")
    def enable_guest_integration(self, vm_name: str) -> bool: return True
    def execute_in_guest(self, vm_name: str, username: str, password: str, command: str, timeout: int=30) -> BackendResult:
        # Try qemu-guest-agent guest-exec
        try:
            payload = json.dumps({"execute":"guest-exec","arguments":{"path":"/bin/sh","arg":["-c", command], "capture-output": True}})
            ok, out, _ = self._run(["virsh","qemu-agent-command", vm_name, payload], timeout=timeout)
            if ok and out:
                try:
                    data = json.loads(out)
                    ret = data.get("return",{})
                    pid = ret.get("pid")
                    if pid is not None:
                        # poll guest-exec-status
                        import time
                        for _ in range(10):
                            time.sleep(0.5)
                            p2 = json.dumps({"execute":"guest-exec-status","arguments":{"pid": pid}})
                            ok2, out2, _ = self._run(["virsh","qemu-agent-command", vm_name, p2], timeout=10)
                            if ok2 and out2:
                                d2 = json.loads(out2)
                                r2 = d2.get("return",{})
                                if r2.get("exited"):
                                    stdout_b64 = r2.get("out-data","")
                                    import base64
                                    try: stdout = base64.b64decode(stdout_b64).decode()
                                    except: stdout = stdout_b64
                                    return BackendResult(r2.get("exitcode",0)==0, stdout, r2.get("err-data",""))
                except: pass
        except Exception as e: logger.debug("qemu-agent exec failed: %s", e)
        return BackendResult(False, "", "guest agent unavailable — fallback SSH not configured")
    def configure_guest_firewall(self, vm_name: str, username: str, password: str, block_outbound=True, allow_dns=False) -> bool: return True
    def test_guest_connectivity(self, vm_name: str, username: str, password: str, target="8.8.8.8") -> bool: return True
    def get_guest_processes(self, vm_name: str, username: str, password: str) -> List[Dict]: return []
    def kill_guest_process(self, vm_name: str, username: str, password: str, process_name: str) -> bool: return False
    def check_guest_vbs_status(self, vm_name: str, username: str, password: str) -> Dict[str, bool]: return {"vbs_enabled": False, "hvci_enabled": False, "secure_boot": False, "kvm": True}
    def read_guest_event_log(self, vm_name: str, username: str, password: str, log_name="Security", max_events=50) -> List[Dict]: return []
    def check_guest_registry(self, vm_name: str, username: str, password: str, key_path: str) -> List[Dict]: return []
    def install_sysmon_in_guest(self, vm_name: str, username: str, password: str, sysmon_path="C:\\Tools\\Sysmon64.exe") -> bool: return False
