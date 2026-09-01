"""GPU Passthrough — Direct Device Assignment (DDA) for Hyper-V.

Manages GPU allocation to VMs for AI/ML workloads.
"""

import subprocess
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Any


class GPUVendor(Enum):
    NVIDIA = "nvidia"
    AMD = "amd"
    INTEL = "intel"
    UNKNOWN = "unknown"


@dataclass
class GPUDevice:
    """Represents a physical GPU available for passthrough."""
    device_id: str
    name: str
    vendor: GPUVendor
    memory_mb: int
    driver_version: str
    available: bool = True
    assigned_vm: Optional[str] = None


class GPUPassthrough:
    """Manages GPU passthrough (DDA) for Hyper-V VMs.
    
    Direct Device Assignment allows assigning a physical GPU
    directly to a VM, giving it near-native GPU performance.
    
    Requirements:
    - Windows Server 2016+ or Windows 10 Pro
    - GPU must support DDA (most modern GPUs)
    - GPU must be dismounted from host before assignment
    """

    def __init__(self):
        self._devices: Dict[str, GPUDevice] = {}
        self._assignments: Dict[str, str] = {}  # vm_id -> device_id

    def detect_gpus(self) -> List[GPUDevice]:
        """Detect all physical GPUs on the host."""
        self._devices.clear()
        
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", """
                Get-CimInstance Win32_VideoController | ForEach-Object {
                    [PSCustomObject]@{
                        DeviceID = $_.PNPDeviceID
                        Name = $_.Name
                        AdapterRAM = $_.AdapterRAM
                        DriverVersion = $_.DriverVersion
                    }
                } | ConvertTo-Json
                """],
                capture_output=True, text=True, timeout=15,
            )
            
            data = __import__("json").loads(r.stdout.strip())
            if isinstance(data, dict):
                data = [data]
                
            for gpu in data:
                vendor = self._detect_vendor(gpu.get("Name", ""))
                device = GPUDevice(
                    device_id=gpu.get("DeviceID", ""),
                    name=gpu.get("Name", "Unknown GPU"),
                    vendor=vendor,
                    memory_mb=gpu.get("AdapterRAM", 0) // (1024 * 1024),
                    driver_version=gpu.get("DriverVersion", "unknown"),
                )
                self._devices[device.device_id] = device
                
        except Exception:
            pass
            
        return list(self._devices.values())

    def assign_to_vm(self, device_id: str, vm_id: str) -> bool:
        """Assign a GPU to a VM via DDA.
        
        Steps:
        1. Dismount GPU from host
        2. Assign to VM
        3. VM needs GPU drivers installed
        """
        device = self._devices.get(device_id)
        if not device or not device.available:
            return False
            
        if vm_id in self._assignments:
            return False  # VM already has a GPU

        # Dismount from host
        if not self._dismount_from_host(device_id):
            return False
            
        # Assign to VM
        if not self._assign_dda(device_id, vm_id):
            return False
            
        device.available = False
        device.assigned_vm = vm_id
        self._assignments[vm_id] = device_id
        return True

    def release_from_vm(self, vm_id: str) -> bool:
        """Release a GPU from a VM and return it to the host."""
        device_id = self._assignments.get(vm_id)
        if not device_id:
            return False
            
        device = self._devices.get(device_id)
        if not device:
            return False

        # Remove from VM
        if not self._remove_dda(device_id, vm_id):
            return False
            
        # Re-mount to host
        self._mount_to_host(device_id)
        
        device.available = True
        device.assigned_vm = None
        del self._assignments[vm_id]
        return True

    def get_assignment(self, vm_id: str) -> Optional[GPUDevice]:
        """Get the GPU assigned to a VM."""
        device_id = self._assignments.get(vm_id)
        if device_id:
            return self._devices.get(device_id)
        return None

    def list_available(self) -> List[GPUDevice]:
        """List GPUs available for assignment."""
        return [d for d in self._devices.values() if d.available]

    def get_summary(self) -> Dict[str, Any]:
        """Get GPU allocation summary."""
        return {
            "total_gpus": len(self._devices),
            "available": len([d for d in self._devices.values() if d.available]),
            "assigned": len(self._assignments),
            "devices": [
                {
                    "id": d.device_id,
                    "name": d.name,
                    "vendor": d.vendor.value,
                    "memory_mb": d.memory_mb,
                    "available": d.available,
                    "assigned_vm": d.assigned_vm,
                }
                for d in self._devices.values()
            ],
        }

    # ----- Private helpers -----

    def _detect_vendor(self, name: str) -> GPUVendor:
        """Detect GPU vendor from name."""
        name_lower = name.lower()
        if "nvidia" in name_lower or "geforce" in name_lower or "quadro" in name_lower:
            return GPUVendor.NVIDIA
        elif "amd" in name_lower or "radeon" in name_lower:
            return GPUVendor.AMD
        elif "intel" in name_lower:
            return GPUVendor.INTEL
        return GPUVendor.UNKNOWN

    def _dismount_from_host(self, device_id: str) -> bool:
        """Dismount GPU from host (required before DDA)."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f'Disable-PnpDevice -InstanceId "{device_id}" -Confirm:$false'],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _mount_to_host(self, device_id: str) -> bool:
        """Re-mount GPU to host."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f'Enable-PnpDevice -InstanceId "{device_id}" -Confirm:$false'],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _assign_dda(self, device_id: str, vm_id: str) -> bool:
        """Assign GPU to VM via Direct Device Assignment."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"""
                $vm = Get-VM -Name "{vm_id}"
                $locationPath = (Get-PnpDeviceProperty -InstanceId "{device_id}" -KeyName "DEVPKEY_Device_LocationPaths").Data[0]
                Dismount-VMHostAssignableDevice -LocationPath $locationPath -Force
                Add-VMAssignableDevice -VMName "{vm_id}" -LocationPath $locationPath
                """],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _remove_dda(self, device_id: str, vm_id: str) -> bool:
        """Remove GPU assignment from VM."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"""
                $locationPath = (Get-PnpDeviceProperty -InstanceId "{device_id}" -KeyName "DEVPKEY_Device_LocationPaths").Data[0]
                Remove-VMAssignableDevice -VMName "{vm_id}" -LocationPath $locationPath
                Mount-VMHostAssignableDevice -LocationPath $locationPath
                """],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode == 0
        except Exception:
            return False
