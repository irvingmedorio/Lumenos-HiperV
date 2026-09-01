"""Multi-Host — Clustering of Hyper-V hosts for LUMENOS.

Manages multiple Hyper-V hosts, distributes VMs across them,
and provides unified resource management.
"""

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Any


class HostStatus(Enum):
    """Status of a Hyper-V host."""
    UNKNOWN = auto()
    ONLINE = auto()
    OFFLINE = auto()
    MAINTENANCE = auto()


class HostRole(Enum):
    """Role of a host in the cluster."""
    WORKER = auto()       # Runs VMs
    COORDINATOR = auto()  # Manages the cluster
    STORAGE = auto()      # Stores images/snapshots


@dataclass
class HostNode:
    """A Hyper-V host in the cluster."""
    name: str
    address: str  # IP or hostname
    role: HostRole = HostRole.WORKER
    status: HostStatus = HostStatus.UNKNOWN
    
    # Resources
    total_memory_mb: int = 0
    available_memory_mb: int = 0
    total_cpu_cores: int = 0
    available_cpu_cores: int = 0
    total_gpu_count: int = 0
    available_gpu_count: int = 0
    
    # VMs running on this host
    vm_count: int = 0
    vm_ids: List[str] = field(default_factory=list)
    
    # Metadata
    platform: str = "windows-x64"  # "windows-x64", "windows-arm64"
    hyper_v_version: str = ""
    last_heartbeat: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class ClusterConfig:
    """Configuration for the cluster."""
    name: str = "lumenos-cluster"
    coordinator: str = ""  # Hostname of coordinator
    load_balance: bool = True
    max_vms_per_host: int = 10
    heartbeat_interval_seconds: int = 30
    auto_evict_offline: bool = True
    gpu_sharing: bool = True


class MultiHostManager:
    """Manages a cluster of Hyper-V hosts.
    
    Features:
    - Host discovery and registration
    - Load balancing (spread VMs across hosts)
    - Failover (evict VMs from offline hosts)
    - Unified resource view
    - GPU sharing across hosts
    
    Usage:
        cluster = MultiHostManager()
        
        # Add hosts
        cluster.add_host("host1", "192.168.1.10", role=HostRole.COORDINATOR)
        cluster.add_host("host2", "192.168.1.11", role=HostRole.WORKER)
        cluster.add_host("host3", "192.168.1.12", role=HostRole.WORKER)
        
        # Find best host for a VM
        best = cluster.find_best_host(memory_mb=8192, cpu_cores=4)
        
        # Deploy VM to best host
        cluster.deploy_vm(best, vm_name="sandbox1", ...)
    """

    def __init__(self, config: Optional[ClusterConfig] = None):
        self._config = config or ClusterConfig()
        self._hosts: Dict[str, HostNode] = {}
        self._vm_hosts: Dict[str, str] = {}  # vm_id -> host_name

    # ----- Host Management -----

    def add_host(self, name: str, address: str,
                 role: HostRole = HostRole.WORKER) -> HostNode:
        """Add a host to the cluster."""
        host = HostNode(
            name=name,
            address=address,
            role=role,
            status=HostStatus.ONLINE,
        )
        self._hosts[name] = host
        if role == HostRole.COORDINATOR:
            self._config.coordinator = name
        return host

    def remove_host(self, name: str) -> bool:
        """Remove a host from the cluster."""
        if name in self._hosts:
            # Evict VMs from this host
            for vm_id in self._hosts[name].vm_ids:
                if vm_id in self._vm_hosts:
                    del self._vm_hosts[vm_id]
            del self._hosts[name]
            return True
        return False

    def get_host(self, name: str) -> Optional[HostNode]:
        """Get a host by name."""
        return self._hosts.get(name)

    def list_hosts(self) -> List[HostNode]:
        """List all hosts."""
        return list(self._hosts.values())

    def get_online_hosts(self) -> List[HostNode]:
        """Get only online hosts."""
        return [h for h in self._hosts.values() if h.status == HostStatus.ONLINE]

    # ----- Host Discovery -----

    def discover_host(self, address: str) -> Optional[HostNode]:
        """Discover a Hyper-V host and its resources."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"""
                Invoke-Command -ComputerName "{address}" -ScriptBlock {{
                    $mem = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
                    $cpu = (Get-CimInstance Win32_Processor).NumberOfCores
                    $hv = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State
                    [PSCustomObject]@{{
                        MemoryMB = [math]::Round($mem / 1MB)
                        CpuCores = $cpu
                        HyperV = $hv
                        Hostname = $env:COMPUTERNAME
                    }}
                }} | ConvertTo-Json
                """],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                data = json.loads(r.stdout.strip())
                host = HostNode(
                    name=data.get("Hostname", address),
                    address=address,
                    total_memory_mb=data.get("MemoryMB", 0),
                    available_memory_mb=data.get("MemoryMB", 0),
                    total_cpu_cores=data.get("CpuCores", 0),
                    available_cpu_cores=data.get("CpuCores", 0),
                    hyper_v_version=data.get("HyperV", "Unknown"),
                    status=HostStatus.ONLINE,
                )
                return host
        except Exception:
            pass
        return None

    def heartbeat(self) -> Dict[str, HostStatus]:
        """Check heartbeat of all hosts."""
        results = {}
        for name, host in self._hosts.items():
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"Test-Connection -ComputerName '{host.address}' -Count 1 -Quiet"],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0 and "True" in r.stdout:
                    host.status = HostStatus.ONLINE
                    host.last_heartbeat = datetime.utcnow().isoformat()
                else:
                    host.status = HostStatus.OFFLINE
            except Exception:
                host.status = HostStatus.OFFLINE
            results[name] = host.status
        return results

    # ----- Load Balancing -----

    def find_best_host(self, memory_mb: int = 0, cpu_cores: int = 0,
                       gpu_count: int = 0) -> Optional[HostNode]:
        """Find the best host for a new VM based on available resources."""
        online = self.get_online_hosts()
        if not online:
            return None

        scored = []
        for host in online:
            score = 0
            # Memory fit
            if host.available_memory_mb >= memory_mb:
                score += 40
                # Prefer hosts with just enough memory (pack efficiently)
                fit_ratio = memory_mb / max(host.available_memory_mb, 1)
                score += int(fit_ratio * 20)
            # CPU fit
            if host.available_cpu_cores >= cpu_cores:
                score += 30
            # GPU fit
            if gpu_count > 0 and host.available_gpu_count >= gpu_count:
                score += 20
            # VM density (prefer less loaded hosts)
            if host.vm_count < self._config.max_vms_per_host:
                score += 10
            # Penalize hosts at capacity
            if host.vm_count >= self._config.max_vms_per_host:
                score -= 100

            scored.append((score, host))

        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1] if scored and scored[0][0] > 0 else None

    def balance_vms(self) -> Dict[str, List[str]]:
        """Rebalance VMs across hosts (migration plan)."""
        online = self.get_online_hosts()
        if len(online) < 2:
            return {}

        # Count VMs per host
        host_vms = {h.name: list(h.vm_ids) for h in online}
        total_vms = sum(len(vms) for vms in host_vms.values())
        ideal_per_host = max(1, total_vms // len(online))

        migrations = {}
        for host in online:
            excess = len(host_vms.get(host.name, [])) - ideal_per_host
            if excess > 0:
                # Find underloaded hosts
                for other in online:
                    if other.name == host.name:
                        continue
                    deficit = ideal_per_host - len(host_vms.get(other.name, []))
                    if deficit > 0:
                        vms_to_move = host_vms[host.name][:min(excess, deficit)]
                        if vms_to_move:
                            migrations[host.name] = vms_to_move
                            break

        return migrations

    # ----- VM Management -----

    def register_vm(self, vm_id: str, host_name: str) -> bool:
        """Register a VM as running on a specific host."""
        host = self._hosts.get(host_name)
        if not host or host.status != HostStatus.ONLINE:
            return False
        if vm_id not in host.vm_ids:
            host.vm_ids.append(vm_id)
            host.vm_count = len(host.vm_ids)
        self._vm_hosts[vm_id] = host_name
        return True

    def unregister_vm(self, vm_id: str) -> bool:
        """Unregister a VM."""
        host_name = self._vm_hosts.get(vm_id)
        if host_name:
            host = self._hosts.get(host_name)
            if host and vm_id in host.vm_ids:
                host.vm_ids.remove(vm_id)
                host.vm_count = len(host.vm_ids)
            del self._vm_hosts[vm_id]
            return True
        return False

    def get_vm_host(self, vm_id: str) -> Optional[HostNode]:
        """Get the host where a VM is running."""
        host_name = self._vm_hosts.get(vm_id)
        if host_name:
            return self._hosts.get(host_name)
        return None

    # ----- Failover -----

    def evict_offline_vms(self) -> List[str]:
        """Evict VMs from offline hosts."""
        evicted = []
        for host in self._hosts.values():
            if host.status == HostStatus.OFFLINE and host.vm_ids:
                for vm_id in list(host.vm_ids):
                    self.unregister_vm(vm_id)
                    evicted.append(vm_id)
                host.vm_ids.clear()
                host.vm_count = 0
        return evicted

    # ----- Summary -----

    def get_summary(self) -> Dict[str, Any]:
        """Get cluster summary."""
        online = self.get_online_hosts()
        total_vms = sum(h.vm_count for h in self._hosts.values())
        total_mem = sum(h.total_memory_mb for h in self._hosts.values())
        avail_mem = sum(h.available_memory_mb for h in self._hosts.values())
        total_cpu = sum(h.total_cpu_cores for h in self._hosts.values())
        total_gpu = sum(h.total_gpu_count for h in self._hosts.values())

        return {
            "cluster_name": self._config.name,
            "coordinator": self._config.coordinator,
            "hosts": {
                "total": len(self._hosts),
                "online": len(online),
                "offline": len(self._hosts) - len(online),
            },
            "resources": {
                "total_memory_mb": total_mem,
                "available_memory_mb": avail_mem,
                "total_cpu_cores": total_cpu,
                "total_gpu_count": total_gpu,
            },
            "vms": {
                "total": total_vms,
                "per_host": {h.name: h.vm_count for h in self._hosts.values()},
            },
        }
