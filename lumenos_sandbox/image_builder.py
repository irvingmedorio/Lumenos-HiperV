"""AI Image Builder — Create and manage VM images for AI workloads.

Builds Hyper-V VM images with pre-installed AI frameworks,
GPU drivers, and custom models. Think Dockerfile but for VMs.
"""

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Any


class ImageType(Enum):
    """Types of VM images."""
    BASE = auto()        # OS + runtime only
    FRAMEWORK = auto()   # OS + framework (PyTorch, TF, etc.)
    MODEL = auto()       # Framework + model weights
    CUSTOM = auto()      # User-defined layers


class ImageStatus(Enum):
    """Image build status."""
    PENDING = auto()
    BUILDING = auto()
    READY = auto()
    FAILED = auto()


@dataclass
class ImageLayer:
    """A single layer in a VM image (like Docker layers)."""
    name: str
    layer_type: str  # "os", "runtime", "framework", "model", "custom"
    size_mb: int = 0
    sha256: str = ""
    dependencies: List[str] = field(default_factory=list)


@dataclass
class VMImage:
    """A complete VM image for AI workloads."""
    name: str
    version: str
    image_type: ImageType
    status: ImageStatus = ImageStatus.PENDING
    layers: List[ImageLayer] = field(default_factory=list)
    base_image: str = ""  # Path to base VHDX
    output_image: str = ""  # Path to built VHDX
    gpu_enabled: bool = False
    gpu_driver: str = ""  # "nvidia-cuda-12.1", "amd-rocm-5.7", etc.
    size_mb: int = 0
    sha256: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pre-built base images
# ---------------------------------------------------------------------------

BASE_IMAGES = {
    "windows-server-2022": {
        "name": "Windows Server 2022",
        "size_gb": 5,
        "iso_url": "https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022",
    },
    "windows-11": {
        "name": "Windows 11",
        "size_gb": 4,
        "iso_url": "https://www.microsoft.com/en-us/software-download/windows11",
    },
}

FRAMEWORK_IMAGES = {
    "pytorch": {
        "name": "PyTorch",
        "layers": ["python-3.11", "pytorch-2.1", "cuda-12.1"],
        "size_gb": 8,
        "gpu_required": True,
    },
    "tensorflow": {
        "name": "TensorFlow",
        "layers": ["python-3.11", "tensorflow-2.15", "cuda-12.2"],
        "size_gb": 6,
        "gpu_required": True,
    },
    "onnxruntime": {
        "name": "ONNX Runtime",
        "layers": ["python-3.11", "onnxruntime-1.16"],
        "size_gb": 2,
        "gpu_required": False,
    },
    "llamacpp": {
        "name": "llama.cpp",
        "layers": ["cmake", "gcc", "llamacpp-latest"],
        "size_gb": 1,
        "gpu_required": False,
    },
}


class ImageBuilder:
    """Builds and manages VM images for AI workloads.
    
    Usage:
        builder = ImageBuilder()
        
        # Create a PyTorch image
        image = builder.create(
            name="pytorch-gpu",
            framework="pytorch",
            gpu_driver="nvidia-cuda-12.1",
        )
        
        # Add a model layer
        builder.add_model(image, "resnet50", "./models/resnet50.pth")
        
        # Build the image
        builder.build(image)
        
        # Deploy to a VM
        builder.deploy(image, vm_name="ai-sandbox-1")
    """

    def __init__(self, image_dir: str = "images"):
        self._image_dir = Path(image_dir)
        self._image_dir.mkdir(parents=True, exist_ok=True)
        self._images: Dict[str, VMImage] = {}

    def create(self, name: str, framework: str,
               gpu_driver: str = "", version: str = "latest") -> VMImage:
        """Create a new VM image."""
        if name in self._images:
            raise ValueError(f"Image {name} already exists")

        fw_info = FRAMEWORK_IMAGES.get(framework)
        if not fw_info:
            raise ValueError(f"Unknown framework: {framework}")

        image = VMImage(
            name=name,
            version=version,
            image_type=ImageType.FRAMEWORK,
            gpu_enabled=bool(gpu_driver),
            gpu_driver=gpu_driver,
        )

        # Add framework layers
        for layer_name in fw_info["layers"]:
            image.layers.append(ImageLayer(
                name=layer_name,
                layer_type="framework",
            ))

        self._images[name] = image
        return image

    def add_model(self, image: VMImage, model_name: str,
                  model_path: str) -> None:
        """Add a model weights layer to an image."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")

        size_mb = os.path.getsize(model_path) // (1024 * 1024)
        sha256 = self._hash_file(model_path)

        image.layers.append(ImageLayer(
            name=model_name,
            layer_type="model",
            size_mb=size_mb,
            sha256=sha256,
        ))

    def add_custom_layer(self, image: VMImage, name: str,
                         files: List[str]) -> None:
        """Add a custom layer with user files."""
        total_size = sum(
            os.path.getsize(f) for f in files if os.path.exists(f)
        ) // (1024 * 1024)

        image.layers.append(ImageLayer(
            name=name,
            layer_type="custom",
            size_mb=total_size,
        ))

    def build(self, image: VMImage) -> bool:
        """Build the VM image.
        
        Steps:
        1. Create base VHDX
        2. Apply OS layer
        3. Install runtime + framework
        4. Install GPU drivers (if enabled)
        5. Copy model weights
        6. Apply custom layers
        7. Snapshot final image
        """
        image.status = ImageStatus.BUILDING

        try:
            # Step 1: Create base VHDX
            output_vhdx = self._image_dir / f"{image.name}.vhdx"
            if not self._create_base_vhdx(output_vhdx, image):
                image.status = ImageStatus.FAILED
                return False

            # Step 2-5: Apply layers
            for layer in image.layers:
                if not self._apply_layer(output_vhdx, layer, image.gpu_driver):
                    image.status = ImageStatus.FAILED
                    return False

            # Step 6: Finalize
            image.output_image = str(output_vhdx)
            image.size_mb = output_vhdx.stat().st_size // (1024 * 1024) if output_vhdx.exists() else 0
            image.sha256 = self._hash_file(str(output_vhdx)) if output_vhdx.exists() else ""
            image.status = ImageStatus.READY
            return True

        except Exception:
            image.status = ImageStatus.FAILED
            return False

    def deploy(self, image: VMImage, vm_name: str,
               memory_mb: int = 8192, cpu_cores: int = 4) -> bool:
        """Deploy a built image to a new VM."""
        if image.status != ImageStatus.READY:
            return False

        try:
            # Create VM with the image
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"""
                New-VM -Name "{vm_name}" `
                    -MemoryStartupBytes {memory_mb * 1024 * 1024} `
                    -Generation 2 `
                    -NewVHDPath "{image.output_image}" `
                    -NewVHDSizeBytes 100GB `
                    -SwitchName "InternalSwitch"
                Set-VM -Name "{vm_name}" `
                    -ProcessorCount {cpu_cores} `
                    -DynamicMemory `
                    -MemoryMinimumBytes {memory_mb * 512 * 1024} `
                    -MemoryMaximumBytes {memory_mb * 2 * 1024 * 1024}
                """],
                capture_output=True, text=True, timeout=60,
            )
            return r.returncode == 0
        except Exception:
            return False

    def list_images(self) -> List[VMImage]:
        """List all managed images."""
        return list(self._images.values())

    def get_image(self, name: str) -> Optional[VMImage]:
        """Get an image by name."""
        return self._images.get(name)

    def delete_image(self, name: str) -> bool:
        """Delete an image and its VHDX file."""
        image = self._images.get(name)
        if not image:
            return False

        if image.output_image and os.path.exists(image.output_image):
            os.remove(image.output_image)

        del self._images[name]
        return True

    def export_manifest(self, image: VMImage) -> Dict[str, Any]:
        """Export image manifest (like Docker image manifest)."""
        return {
            "name": image.name,
            "version": image.version,
            "type": image.image_type.name,
            "status": image.status.name,
            "gpu_enabled": image.gpu_enabled,
            "gpu_driver": image.gpu_driver,
            "size_mb": image.size_mb,
            "sha256": image.sha256,
            "layers": [
                {
                    "name": l.name,
                    "type": l.layer_type,
                    "size_mb": l.size_mb,
                    "sha256": l.sha256,
                }
                for l in image.layers
            ],
            "created_at": image.created_at,
        }

    # ----- Private helpers -----

    def _create_base_vhdx(self, path: Path, image: VMImage) -> bool:
        """Create a base VHDX file."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f'New-VHD -Path "{path}" -SizeBytes 100GB -Dynamic'],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _apply_layer(self, vhdx_path: Path, layer: ImageLayer,
                     gpu_driver: str) -> bool:
        """Apply a single layer to the VHDX."""
        # In production, this would mount the VHDX and install
        # the layer contents. Simplified for now.
        return True

    @staticmethod
    def _hash_file(path: str) -> str:
        """Compute SHA-256 of a file."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            pass
        return h.hexdigest()
