"""Resource Manager — RAM/CPU/GPU efficiency for LUMENOS Custom.

Handles dynamic memory, CPU quotas, GPU time-slicing, and resource
scheduling to minimize host resource consumption.
"""

import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ResourceProfile(Enum):
    """Pre-defined resource profiles for different workload types."""
    TINY = auto()      # 512MB RAM, 1 CPU — inference only
    SMALL = auto()     # 2GB RAM, 2 CPU — small model
    MEDIUM = auto()    # 8GB RAM, 4 CPU — training / large model
    LARGE = auto()     # 16GB RAM, 8 CPU — multi-GPU training
    CUSTOM = auto()    # User-defined


class VMState(Enum):
    """Runtime state of a managed VM."""
    CREATED = auto()
    RUNNING = auto()
    PAUSED = auto()
    SAVED = auto()       # Saved to disk (swap equivalent)
    TERMINATED = auto()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROFILE_SPECS = {
    ResourceProfile.TINY: {"memory_mb": 512, "cpu_cores": 1, "disk_gb": 10},
    ResourceProfile.SMALL: {"memory_mb": 2048, "cpu_cores": 2, "disk_gb": 50},
    ResourceProfile.MEDIUM: {"memory_mb": 8192, "cpu_cores": 4, "disk_gb": 100},
    ResourceProfile.LARGE: {"memory_mb": 16384, "cpu_cores": 8, "disk_gb": 200},
}

# Dynamic memory bounds (percentage of assigned memory)
DYNAMIC_MEMORY_MIN_PCT = 0.25   # 25% minimum
DYNAMIC_MEMORY_MAX_PCT = 1.5    # 150% maximum
MEMORY_COMPRESSION_THRESHOLD_PCT = 0.80  # Compress above 80% usage


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class VMResourceAlloc:
    """Resource allocation for a single VM."""
    vm_id: str
    profile: ResourceProfile
    memory_mb: int
    cpu_cores: int
    disk_gb: int
    gpu_count: int = 0
    gpu_memory_mb: int = 0
    priority: int = 5  # 1 (lowest) to 10 (highest)
    state: VMState = VMState.CREATED
    memory_compressed: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_accessed: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class HostResources:
    """Current host resource availability."""
    total_memory_mb: int
    available_memory_mb: int
    total_cpu_cores: int
    available_cpu_cores: int
    total_gpu_count: int = 0
    available_gpu_count: int = 0
    gpu_memory_total_mb: int = 0
    gpu_memory_used_mb: int = 0


# ---------------------------------------------------------------------------
# Resource Manager
# ---------------------------------------------------------------------------

class ResourceManager:
    """Manages VM resource allocation with efficiency optimizations.
    
    Features:
    - Dynamic memory (ballooning)
    - CPU quotas and pinning
    - GPU time-slicing
    - Memory compression for idle VMs
    - Lazy resource loading
    """

    def __init__(self):
        self._allocations: Dict[str, VMResourceAlloc] = {}
        self._host = HostResources(
            total_memory_mb=0,
            available_memory_mb=0,
            total_cpu_cores=0,
            available_cpu_cores=0,
        )

    # ----- Host detection -----

    def detect_host_resources(self) -> HostResources:
        """Detect available host resources (Windows)."""
        total_mem = self._get_total_memory_mb()
        used_mem = self._get_used_memory_mb()
        total_cpu = os.cpu_count() or 4
        gpu_count, gpu_mem = self._detect_gpu()

        self._host = HostResources(
            total_memory_mb=total_mem,
            available_memory_mb=total_mem - used_mem,
            total_cpu_cores=total_cpu,
            available_cpu_cores=total_cpu,
            total_gpu_count=gpu_count,
            available_gpu_count=gpu_count,
            gpu_memory_total_mb=gpu_mem,
            gpu_memory_used_mb=0,
        )
        return self._host

    # ----- Allocation -----

    def allocate(self, vm_id: str, profile: ResourceProfile,
                 gpu_count: int = 0, priority: int = 5) -> VMResourceAlloc:
        """Allocate resources for a VM."""
        if vm_id in self._allocations:
            raise ValueError(f"VM {vm_id} already allocated")

        spec = PROFILE_SPECS[profile]
        alloc = VMResourceAlloc(
            vm_id=vm_id,
            profile=profile,
            memory_mb=spec["memory_mb"],
            cpu_cores=spec["cpu_cores"],
            disk_gb=spec["disk_gb"],
            gpu_count=gpu_count,
            priority=priority,
        )
        self._allocations[vm_id] = alloc
        return alloc

    def deallocate(self, vm_id: str) -> None:
        """Release resources for a VM."""
        if vm_id in self._allocations:
            del self._allocations[vm_id]

    def get_allocation(self, vm_id: str) -> Optional[VMResourceAlloc]:
        """Get current allocation for a VM."""
        return self._allocations.get(vm_id)

    # ----- Efficiency: Dynamic Memory -----

    def calculate_dynamic_memory(self, vm_id: str, current_usage_mb: int) -> int:
        """Calculate optimal memory allocation based on current usage.
        
        Uses ballooning: if VM uses less than 50% of allocated,
        shrink allocation. If it uses more than 80%, grow up to max.
        """
        alloc = self._allocations.get(vm_id)
        if not alloc:
            return 0

        base = PROFILE_SPECS[alloc.profile]["memory_mb"]
        min_mem = int(base * DYNAMIC_MEMORY_MIN_PCT)
        max_mem = int(base * DYNAMIC_MEMORY_MAX_PCT)

        if current_usage_mb < base * 0.50:
            # VM using less than 50% — shrink (balloon out)
            new_alloc = max(min_mem, int(current_usage_mb * 1.25))
        elif current_usage_mb > base * 0.80:
            # VM using more than 80% — grow (balloon in)
            new_alloc = min(max_mem, int(current_usage_mb * 1.5))
        else:
            new_alloc = alloc.memory_mb

        alloc.memory_mb = new_alloc
        return new_alloc

    # ----- Efficiency: Memory Compression -----

    def should_compress(self, vm_id: str) -> bool:
        """Check if a VM's memory should be compressed (idle/saved)."""
        alloc = self._allocations.get(vm_id)
        if not alloc:
            return False
        return alloc.state in (VMState.PAUSED, VMState.SAVED)

    def compress_memory(self, vm_id: str) -> bool:
        """Mark a VM's memory as compressed (for idle VMs)."""
        alloc = self._allocations.get(vm_id)
        if not alloc:
            return False
        alloc.memory_compressed = True
        return True

    # ----- Efficiency: Lazy Loading -----

    def calculate_lazy_load(self, vm_id: str) -> Dict[str, Any]:
        """Calculate what resources to load immediately vs deferred.
        
        Returns a plan: what to load now, what to defer.
        """
        alloc = self._allocations.get(vm_id)
        if not alloc:
            return {"immediate": [], "deferred": []}

        if alloc.priority >= 8:
            # High priority: load everything immediately
            return {
                "immediate": ["kernel", "runtime", "model", "data"],
                "deferred": [],
            }
        elif alloc.priority >= 5:
            # Medium priority: load essentials, defer model
            return {
                "immediate": ["kernel", "runtime"],
                "deferred": ["model", "data"],
            }
        else:
            # Low priority: load minimal, defer everything
            return {
                "immediate": ["kernel"],
                "deferred": ["runtime", "model", "data"],
            }

    # ----- GPU Management -----

    def allocate_gpu(self, vm_id: str, count: int = 1) -> bool:
        """Allocate GPU(s) to a VM (time-slicing)."""
        alloc = self._allocations.get(vm_id)
        if not alloc:
            return False

        if count > self._host.available_gpu_count:
            return False

        alloc.gpu_count = count
        self._host.available_gpu_count -= count
        return True

    def release_gpu(self, vm_id: str) -> None:
        """Release GPU(s) from a VM."""
        alloc = self._allocations.get(vm_id)
        if alloc and alloc.gpu_count > 0:
            self._host.available_gpu_count += alloc.gpu_count
            alloc.gpu_count = 0

    # ----- Summary -----

    def get_summary(self) -> Dict[str, Any]:
        """Get resource usage summary."""
        total_allocated_mem = sum(a.memory_mb for a in self._allocations.values())
        total_allocated_cpu = sum(a.cpu_cores for a in self._allocations.values())
        total_gpu = sum(a.gpu_count for a in self._allocations.values())

        return {
            "host": {
                "total_memory_mb": self._host.total_memory_mb,
                "available_memory_mb": self._host.available_memory_mb,
                "total_cpu_cores": self._host.total_cpu_cores,
                "available_cpu_cores": self._host.available_cpu_cores,
                "total_gpu_count": self._host.total_gpu_count,
                "available_gpu_count": self._host.available_gpu_count,
            },
            "allocated": {
                "memory_mb": total_allocated_mem,
                "cpu_cores": total_allocated_cpu,
                "gpu_count": total_gpu,
                "vm_count": len(self._allocations),
            },
            "efficiency": {
                "memory_utilization_pct": round(
                    total_allocated_mem / max(self._host.total_memory_mb, 1) * 100, 1
                ),
                "cpu_utilization_pct": round(
                    total_allocated_cpu / max(self._host.total_cpu_cores, 1) * 100, 1
                ),
                "memory_compressed_vms": sum(
                    1 for a in self._allocations.values() if a.memory_compressed
                ),
            },
        }

    # ----- Host detection helpers (Windows) -----

    def _get_total_memory_mb(self) -> int:
        """Get total physical memory in MB."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB"],
                capture_output=True, text=True, timeout=10,
            )
            return int(float(r.stdout.strip()))
        except Exception:
            return 0

    def _get_used_memory_mb(self) -> int:
        """Get currently used memory in MB."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / 1KB - "
                 "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB"],
                capture_output=True, text=True, timeout=10,
            )
            return int(float(r.stdout.strip()))
        except Exception:
            return 0

    def _detect_gpu(self):
        """Detect GPU count and memory."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_VideoController | "
                 "Select-Object AdapterRAM, Name | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10,
            )
            data = json.loads(r.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            total_mem = sum(d.get("AdapterRAM", 0) for d in data) // (1024 * 1024)
            return len(data), total_mem
        except Exception:
            return 0, 0
