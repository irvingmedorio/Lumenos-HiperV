"""Phone Support — WHP/KVM for ARM devices (Windows on ARM, Android).

Extends LUMENOS to ARM-based devices using:
- Windows Hypervisor Platform (WHP) on Windows on ARM
- KVM on Android (via Termux or rooted devices)
- QEMU as fallback for non-virtualizable ARM devices
"""

import json
import os
import platform
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Any


class DevicePlatform(Enum):
    """Target device platforms."""
    WINDOWS_ARM64 = "windows-arm64"   # Surface Pro X, Snapdragon laptops
    WINDOWS_X64 = "windows-x64"      # Regular Windows
    LINUX_ARM64 = "linux-arm64"       # Raspberry Pi, ARM servers
    ANDROID_ARM64 = "android-arm64"   # Android phones/tablets
    IOS_ARM64 = "ios-arm64"           # iPhones/iPads (limited)
    UNKNOWN = "unknown"


class HypervisorType(Enum):
    """Available hypervisors per platform."""
    HYPER_V = "hyper-v"       # Windows x64/ARM64
    WHP = "whp"               # Windows Hypervisor Platform (ARM64)
    KVM = "kvm"               # Linux ARM64
    QEMU = "qemu"             # Fallback (any platform)
    NONE = "none"             # No virtualization


@dataclass
class DeviceCapabilities:
    """Detected capabilities of the current device."""
    platform: DevicePlatform
    architecture: str  # "x64", "arm64", etc.
    hypervisor: HypervisorType
    total_memory_mb: int
    cpu_cores: int
    gpu_available: bool = False
    gpu_type: str = ""
    android_api_level: int = 0  # Android only
    Termux_available: bool = False  # Android only
    max_vm_count: int = 0
    features: List[str] = field(default_factory=list)


@dataclass
class PhoneVMConfig:
    """Configuration for a VM on a phone/ARM device."""
    name: str
    memory_mb: int = 512  # Phones have limited RAM
    cpu_cores: int = 2
    disk_mb: int = 4096  # 4GB max on phone
    image_path: str = ""
    gpu_passthrough: bool = False
    network_isolated: bool = True
    headless: bool = True  # No display on phone


class PhoneSupport:
    """Manages LUMENOS on ARM devices and phones.
    
    Detects the device platform and available hypervisor,
    then configures the optimal virtualization strategy.
    
    Strategies by platform:
    - Windows ARM64: WHP (native) or Hyper-V (if available)
    - Android: QEMU via Termux, or KVM if rooted
    - Linux ARM64: KVM (native)
    - iOS: Very limited — QEMU user-mode only
    
    Usage:
        phone = PhoneSupport()
        
        # Detect device
        caps = phone.detect_capabilities()
        print(f"Platform: {caps.platform.value}")
        print(f"Hypervisor: {caps.hypervisor.value}")
        
        # Create VM config
        config = phone.create_config("sandbox1", memory_mb=1024)
        
        # Start VM
        phone.start_vm(config)
    """

    def __init__(self):
        self._capabilities: Optional[DeviceCapabilities] = None
        self._vms: Dict[str, PhoneVMConfig] = {}

    def detect_capabilities(self) -> DeviceCapabilities:
        """Detect device platform and capabilities."""
        arch = platform.machine().lower()
        sys = platform.system().lower()

        # Detect platform
        if sys == "windows" and "arm" in arch:
            plat = DevicePlatform.WINDOWS_ARM64
        elif sys == "windows":
            plat = DevicePlatform.WINDOWS_X64
        elif sys == "linux" and "arm" in arch:
            # Check if Android (Termux)
            if os.path.exists("/data/data/com.termux"):
                plat = DevicePlatform.ANDROID_ARM64
            else:
                plat = DevicePlatform.LINUX_ARM64
        elif sys == "linux":
            plat = DevicePlatform.LINUX_ARM64
        elif sys == "darwin" and "arm" in arch:
            plat = DevicePlatform.IOS_ARM64
        else:
            plat = DevicePlatform.UNKNOWN

        # Detect hypervisor
        hv = self._detect_hypervisor(plat)

        # Detect memory
        mem = self._detect_memory()
        cpu = os.cpu_count() or 2

        # Detect GPU
        gpu_avail, gpu_type = self._detect_gpu(plat)

        # Android specifics
        api_level = 0
        termux = False
        if plat == DevicePlatform.ANDROID_ARM64:
            api_level = self._detect_android_api()
            termux = self._detect_termux()

        # Calculate max VMs based on available memory
        min_vm_mem = 256  # Minimum 256MB per VM
        max_vms = max(1, mem // min_vm_mem)

        self._capabilities = DeviceCapabilities(
            platform=plat,
            architecture=arch,
            hypervisor=hv,
            total_memory_mb=mem,
            cpu_cores=cpu,
            gpu_available=gpu_avail,
            gpu_type=gpu_type,
            android_api_level=api_level,
            Termux_available=termux,
            max_vm_count=max_vms,
            features=self._detect_features(plat, hv),
        )
        return self._capabilities

    def create_config(self, name: str, memory_mb: int = 512,
                      cpu_cores: int = 2) -> PhoneVMConfig:
        """Create a VM config optimized for the current device."""
        if not self._capabilities:
            self.detect_capabilities()

        caps = self._capabilities

        # Adjust for device limitations
        max_mem = min(memory_mb, caps.total_memory_mb // 4)
        max_cpu = min(cpu_cores, caps.cpu_cores // 2)

        config = PhoneVMConfig(
            name=name,
            memory_mb=max(128, max_mem),
            cpu_cores=max(1, max_cpu),
            disk_mb=min(4096, max_mem * 2),
            headless=True,
            network_isolated=True,
        )
        self._vms[name] = config
        return config

    def start_vm(self, config: PhoneVMConfig) -> bool:
        """Start a VM using the best available hypervisor."""
        if not self._capabilities:
            self.detect_capabilities()

        hv = self._capabilities.hypervisor

        if hv == HypervisorType.WHP:
            return self._start_whp(config)
        elif hv == HypervisorType.KVM:
            return self._start_kvm(config)
        elif hv == HypervisorType.QEMU:
            return self._start_qemu(config)
        elif hv == HypervisorType.HYPER_V:
            return self._start_hyper_v(config)
        else:
            return False

    def stop_vm(self, name: str) -> bool:
        """Stop a running VM."""
        if name in self._vms:
            config = self._vms[name]
            # Try to stop with the active hypervisor
            if self._capabilities and self._capabilities.hypervisor == HypervisorType.KVM:
                return self._stop_kvm(config)
            elif self._capabilities and self._capabilities.hypervisor == HypervisorType.QEMU:
                return self._stop_qemu(config)
        return False

    def list_vms(self) -> List[PhoneVMConfig]:
        """List all configured VMs."""
        return list(self._vms.values())

    def get_recommendation(self) -> Dict[str, Any]:
        """Get recommendations for the current device."""
        if not self._capabilities:
            self.detect_capabilities()

        caps = self._capabilities
        recs = {
            "platform": caps.platform.value,
            "hypervisor": caps.hypervisor.value,
            "max_vms": caps.max_vm_count,
            "recommended_vm_memory_mb": min(512, caps.total_memory_mb // 4),
            "recommended_vm_cpu_cores": min(2, caps.cpu_cores // 2),
            "gpu_passthrough": caps.gpu_available,
            "features": caps.features,
            "warnings": [],
            "tips": [],
        }

        # Platform-specific warnings
        if caps.platform == DevicePlatform.ANDROID_ARM64:
            recs["warnings"].append("Android: limited memory, use small VMs")
            if not caps.Termux_available:
                recs["warnings"].append("Termux not detected — install for QEMU support")
            recs["tips"].append("Use QEMU user-mode for lightweight analysis")
            recs["tips"].append("Keep VMs under 512MB RAM")

        elif caps.platform == DevicePlatform.WINDOWS_ARM64:
            recs["tips"].append("WHP is native — best performance")
            recs["tips"].append("GPU passthrough available for AI workloads")

        elif caps.platform == DevicePlatform.LINUX_ARM64:
            recs["tips"].append("KVM is native — excellent performance")
            recs["tips"].append("Consider containers for lightweight workloads")

        elif caps.platform == DevicePlatform.IOS_ARM64:
            recs["warnings"].append("iOS: very limited virtualization")
            recs["warnings"].append("No KVM/WHP — QEMU user-mode only")
            recs["tips"].append("Use QEMU user-mode for binary analysis")

        return recs

    # ----- Hypervisor Start Methods -----

    def _start_whp(self, config: PhoneVMConfig) -> bool:
        """Start VM using Windows Hypervisor Platform (ARM64)."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"""
                # WHP on ARM64 uses the same Hyper-V cmdlets
                New-VM -Name "{config.name}" `
                    -MemoryStartupBytes {config.memory_mb * 1024 * 1024} `
                    -Generation 2 `
                    -SwitchName "Default Switch"
                Set-VM -Name "{config.name}" -ProcessorCount {config.cpu_cores}
                Start-VM -Name "{config.name}"
                """],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _start_kvm(self, config: PhoneVMConfig) -> bool:
        """Start VM using KVM (Linux ARM64)."""
        try:
            # Create disk image
            disk_path = f"/var/lib/lumenos/{config.name}.qcow2"
            r = subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", disk_path,
                 f"{config.disk_mb}M"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                return False

            # Start QEMU with KVM
            r = subprocess.run(
                ["qemu-system-aarch64",
                 "-machine", "virt,gic-version=3",
                 "-cpu", "cortex-a72",
                 "-m", str(config.memory_mb),
                 "-smp", str(config.cpu_cores),
                 "-drive", f"file={disk_path},format=qcow2",
                 "-nographic",
                 "-enable-kvm"],
                capture_output=True, text=True, timeout=10,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _start_qemu(self, config: PhoneVMConfig) -> bool:
        """Start VM using QEMU (fallback, no KVM)."""
        try:
            disk_path = f"/tmp/lumenos/{config.name}.qcow2"
            os.makedirs(os.path.dirname(disk_path), exist_ok=True)

            r = subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", disk_path,
                 f"{config.disk_mb}M"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                return False

            r = subprocess.run(
                ["qemu-system-aarch64",
                 "-machine", "virt",
                 "-cpu", "cortex-a72",
                 "-m", str(config.memory_mb),
                 "-smp", str(config.cpu_cores),
                 "-drive", f"file={disk_path},format=qcow2",
                 "-nographic"],
                capture_output=True, text=True, timeout=10,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _start_hyper_v(self, config: PhoneVMConfig) -> bool:
        """Start VM using Hyper-V (Windows x64)."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"""
                New-VM -Name "{config.name}" `
                    -MemoryStartupBytes {config.memory_mb * 1024 * 1024} `
                    -Generation 2 `
                    -SwitchName "InternalSwitch"
                Set-VM -Name "{config.name}" -ProcessorCount {config.cpu_cores}
                Start-VM -Name "{config.name}"
                """],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _stop_kvm(self, config: PhoneVMConfig) -> bool:
        """Stop a KVM VM."""
        try:
            r = subprocess.run(
                ["pkill", "-f", f"qemu-system-aarch64.*{config.name}"],
                capture_output=True, text=True, timeout=5,
            )
            return True
        except Exception:
            return False

    def _stop_qemu(self, config: PhoneVMConfig) -> bool:
        """Stop a QEMU VM."""
        return self._stop_kvm(config)

    # ----- Detection Helpers -----

    def _detect_hypervisor(self, plat: DevicePlatform) -> HypervisorType:
        """Detect available hypervisor."""
        if plat in (DevicePlatform.WINDOWS_X64, DevicePlatform.WINDOWS_ARM64):
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State"],
                    capture_output=True, text=True, timeout=10,
                )
                if "Enabled" in r.stdout:
                    return HypervisorType.HYPER_V
                return HypervisorType.WHP
            except Exception:
                return HypervisorType.WHP

        elif plat == DevicePlatform.LINUX_ARM64:
            if os.path.exists("/dev/kvm"):
                return HypervisorType.KVM
            return HypervisorType.QEMU

        elif plat == DevicePlatform.ANDROID_ARM64:
            # Check for QEMU in Termux
            if os.path.exists("/data/data/com.termux"):
                return HypervisorType.QEMU
            return HypervisorType.NONE

        elif plat == DevicePlatform.IOS_ARM64:
            return HypervisorType.NONE  # No virtualization on iOS

        return HypervisorType.NONE

    def _detect_memory(self) -> int:
        """Detect total memory in MB."""
        try:
            if platform.system() == "Windows":
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB"],
                    capture_output=True, text=True, timeout=5,
                )
                return int(float(r.stdout.strip()))
            elif platform.system() == "Linux":
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal"):
                            return int(line.split()[1]) // 1024
        except Exception:
            pass
        return 4096  # Default 4GB

    def _detect_gpu(self, plat: DevicePlatform):
        """Detect GPU availability."""
        try:
            if plat in (DevicePlatform.WINDOWS_X64, DevicePlatform.WINDOWS_ARM64):
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance Win32_VideoController).Name"],
                    capture_output=True, text=True, timeout=5,
                )
                if r.stdout.strip():
                    return True, r.stdout.strip().split("\n")[0]
            elif plat == DevicePlatform.LINUX_ARM64:
                if os.path.exists("/dev/dri"):
                    return True, "DRM/GPU"
        except Exception:
            pass
        return False, ""

    def _detect_android_api(self) -> int:
        """Detect Android API level."""
        try:
            api = os.environ.get("ANDROID_API_LEVEL", "")
            if api:
                return int(api)
        except Exception:
            pass
        return 0

    def _detect_termux(self) -> bool:
        """Check if running in Termux."""
        return os.path.exists("/data/data/com.termux")

    def _detect_features(self, plat: DevicePlatform,
                         hv: HypervisorType) -> List[str]:
        """Detect supported features."""
        features = []
        if hv in (HypervisorType.HYPER_V, HypervisorType.WHP, HypervisorType.KVM):
            features.append("vm-isolation")
        if hv == HypervisorType.HYPER_V:
            features.append("gpu-passthrough")
            features.append("dynamic-memory")
        if hv == HypervisorType.KVM:
            features.append("gpu-passthrough")
        if plat == DevicePlatform.ANDROID_ARM64:
            features.append("mobile-analysis")
        if plat == DevicePlatform.WINDOWS_ARM64:
            features.append("arm-native")
        return features
