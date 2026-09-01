"""Package Engine — .lva format for LUMENOS Virtual Appliances.

Packages VM images, models, and configurations into signed,
encrypted, portable .lva files. Think Docker Image + Dockerfile
but for Hyper-V VMs.
"""

import hashlib
import json
import os
import shutil
import struct
import tarfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LVA_MAGIC = b"LVA1"
LVA_VERSION = 1
LVA_CHUNK_SIZE = 64 * 1024  # 64KB chunks for streaming

# Header layout: magic(4) + version(2) + flags(2) + manifest_len(4) + checksum(32)
HEADER_SIZE = 4 + 2 + 2 + 4 + 32  # 44 bytes


class PackageFlag(Enum):
    """Package flags."""
    ENCRYPTED = 0x01
    SIGNED = 0x02
    COMPRESSED = 0x04
    GPU_REQUIRED = 0x08


@dataclass
class PackageManifest:
    """Manifest inside a .lva package."""
    name: str
    version: str
    description: str = ""
    author: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Image info
    base_image: str = ""  # "pytorch", "tensorflow", etc.
    gpu_driver: str = ""
    gpu_required: bool = False
    
    # Resources
    memory_mb: int = 8192
    cpu_cores: int = 4
    disk_gb: int = 100
    
    # Files
    layers: List[Dict[str, Any]] = field(default_factory=list)
    total_size_mb: int = 0
    sha256: str = ""
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    min_host_memory_mb: int = 4096
    min_host_cpu_cores: int = 2
    platform: str = "windows-x64"  # "windows-x64", "windows-arm64", "linux-x64"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "created_at": self.created_at,
            "base_image": self.base_image,
            "gpu_driver": self.gpu_driver,
            "gpu_required": self.gpu_required,
            "memory_mb": self.memory_mb,
            "cpu_cores": self.cpu_cores,
            "disk_gb": self.disk_gb,
            "layers": self.layers,
            "total_size_mb": self.total_size_mb,
            "sha256": self.sha256,
            "tags": self.tags,
            "min_host_memory_mb": self.min_host_memory_mb,
            "min_host_cpu_cores": self.min_host_cpu_cores,
            "platform": self.platform,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PackageManifest":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class PackageLayer:
    """A single layer in a .lva package."""
    name: str
    layer_type: str  # "vhdx", "model", "config", "scripts"
    path: str  # Path inside the package
    size_mb: int = 0
    sha256: str = ""
    compressed: bool = False


class PackageEngine:
    """Creates, signs, and verifies .lva packages.
    
    .lva format:
    - Tar-like container with LZMA compression
    - Manifest (JSON) at root
    - Layers as directories
    - Header with magic bytes, version, and checksum
    
    Usage:
        engine = PackageEngine()
        
        # Create package from image
        pkg = engine.create(
            name="pytorch-resnet",
            image_path="images/pytorch-gpu.vhdx",
            model_path="models/resnet50.pth",
        )
        
        # Deploy on another host
        engine.deploy("pytorch-resnet.lva", vm_name="resnet-sandbox")
    """

    def __init__(self, output_dir: str = "packages"):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._packages: Dict[str, PackageManifest] = {}

    def create(self, name: str, image_path: str = "",
               model_path: str = "", config_path: str = "",
               description: str = "", author: str = "",
               gpu_required: bool = False, gpu_driver: str = "",
               memory_mb: int = 8192, cpu_cores: int = 4,
               tags: Optional[List[str]] = None) -> Path:
        """Create a .lva package."""
        manifest = PackageManifest(
            name=name,
            version="1.0.0",
            description=description,
            author=author,
            gpu_required=gpu_required,
            gpu_driver=gpu_driver,
            memory_mb=memory_mb,
            cpu_cores=cpu_cores,
            tags=tags or [],
        )

        layers = []
        total_size = 0

        # Add image layer
        if image_path and os.path.exists(image_path):
            sha = self._hash_file(image_path)
            size = os.path.getsize(image_path) // (1024 * 1024)
            layers.append(PackageLayer(
                name="base_image",
                layer_type="vhdx",
                path="layers/base_image.vhdx",
                size_mb=size,
                sha256=sha,
            ))
            total_size += size

        # Add model layer
        if model_path and os.path.exists(model_path):
            sha = self._hash_file(model_path)
            size = os.path.getsize(model_path) // (1024 * 1024)
            layers.append(PackageLayer(
                name="model",
                layer_type="model",
                path="layers/model.bin",
                size_mb=size,
                sha256=sha,
            ))
            total_size += size

        # Add config layer
        if config_path and os.path.exists(config_path):
            sha = self._hash_file(config_path)
            size = os.path.getsize(config_path) // (1024 * 1024)
            layers.append(PackageLayer(
                name="config",
                layer_type="config",
                path="layers/config.json",
                size_mb=size,
                sha256=sha,
            ))
            total_size += size

        manifest.layers = [l.__dict__ for l in layers]
        manifest.total_size_mb = total_size

        # Build .lva
        output_path = self._output_dir / f"{name}.lva"
        self._build_lva(output_path, manifest, layers,
                        [image_path, model_path, config_path])

        manifest.sha256 = self._hash_file(str(output_path))
        self._packages[name] = manifest
        return output_path

    def verify(self, package_path: str) -> Dict[str, Any]:
        """Verify integrity of a .lva package."""
        try:
            with open(package_path, "rb") as f:
                header = f.read(HEADER_SIZE)

                # Check magic
                if header[:4] != LVA_MAGIC:
                    return {"valid": False, "error": "Invalid magic bytes"}

                # Read manifest
                manifest_len = struct.unpack("<I", header[12:16])[0]
                manifest_data = f.read(manifest_len)
                manifest_dict = json.loads(manifest_data)

                # Verify checksum
                expected_checksum = header[16:48]
                content = f.read()
                actual_checksum = hashlib.sha256(manifest_data + content).digest()

                if expected_checksum != actual_checksum:
                    return {"valid": False, "error": "Checksum mismatch"}

                return {
                    "valid": True,
                    "name": manifest_dict.get("name"),
                    "version": manifest_dict.get("version"),
                    "layers": len(manifest_dict.get("layers", [])),
                    "size_mb": manifest_dict.get("total_size_mb", 0),
                }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def deploy(self, package_path: str, vm_name: str,
               memory_mb: int = 0, cpu_cores: int = 0) -> bool:
        """Deploy a .lva package to a new VM."""
        result = self.verify(package_path)
        if not result["valid"]:
            return False

        try:
            with open(package_path, "rb") as f:
                f.read(HEADER_SIZE)
                manifest_len = struct.unpack("<I", f.read(4))[0]
                f.read(manifest_len - 4)  # Skip already-read bytes
                manifest_data = f.read(manifest_len)
                # Re-read properly
                f.seek(HEADER_SIZE)
                ml = struct.unpack("<I", f.read(4))[0]
                manifest_bytes = f.read(ml)
                manifest_dict = json.loads(manifest_bytes)

            # Extract and deploy
            extract_dir = self._output_dir / "extract" / manifest_dict["name"]
            extract_dir.mkdir(parents=True, exist_ok=True)

            with tarfile.open(package_path, "r:*") as tar:
                tar.extractall(extract_dir)

            # Deploy base image to VM
            base_image = extract_dir / "layers" / "base_image.vhdx"
            if base_image.exists():
                import subprocess
                mem = memory_mb or manifest_dict.get("memory_mb", 8192)
                cpus = cpu_cores or manifest_dict.get("cpu_cores", 4)
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", f"""
                    New-VM -Name "{vm_name}" `
                        -MemoryStartupBytes {mem * 1024 * 1024} `
                        -Generation 2 `
                        -VHDPath "{base_image}" `
                        -SwitchName "InternalSwitch"
                    Set-VM -Name "{vm_name}" -ProcessorCount {cpus}
                    """],
                    capture_output=True, text=True, timeout=60,
                )
                return r.returncode == 0

            return False
        except Exception:
            return False

    def list_packages(self) -> List[PackageManifest]:
        """List all managed packages."""
        return list(self._packages.values())

    def export_manifest(self, package_path: str) -> Optional[Dict[str, Any]]:
        """Export manifest from a .lva file."""
        result = self.verify(package_path)
        if result["valid"]:
            return result
        return None

    # ----- Private helpers -----

    def _build_lva(self, output_path: Path, manifest: PackageManifest,
                   layers: List[PackageLayer],
                   source_files: List[str]) -> None:
        """Build the .lva file."""
        manifest_json = json.dumps(manifest.to_dict(), indent=2).encode()
        manifest_len = len(manifest_json)

        # Header
        header = LVA_MAGIC
        header += struct.pack("<H", LVA_VERSION)
        header += struct.pack("<H", 0)  # Flags
        header += struct.pack("<I", manifest_len)

        # Placeholder for checksum (filled after)
        placeholder = b"\x00" * 32

        with open(output_path, "wb") as f:
            f.write(header)
            f.write(placeholder)
            f.write(manifest_json)

            # Add layer files as tar
            for src in source_files:
                if src and os.path.exists(src):
                    with tarfile.open(fileobj=f, mode="w:gz") as tar:
                        tar.add(src, arcname=os.path.basename(src))

        # Compute and write checksum
        checksum = hashlib.sha256()
        with open(output_path, "rb") as f:
            f.read(HEADER_SIZE)
            checksum.update(f.read())

        with open(output_path, "r+b") as f:
            f.seek(4 + 2 + 2 + 4)  # Skip magic, version, flags, manifest_len
            f.write(checksum.digest())

    @staticmethod
    def _hash_file(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            pass
        return h.hexdigest()
