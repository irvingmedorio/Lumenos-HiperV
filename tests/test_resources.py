"""Tests for resource_manager.py, gpu.py, and image_builder.py."""

import unittest
from unittest.mock import patch, MagicMock
from lumenos_sandbox.resource_manager import (
    ResourceManager, ResourceProfile, VMResourceAlloc, HostResources, VMState,
)
from lumenos_sandbox.gpu import GPUPassthrough, GPUDevice, GPUVendor
from lumenos_sandbox.image_builder import (
    ImageBuilder, VMImage, ImageLayer, ImageType, ImageStatus,
)


class TestResourceManager(unittest.TestCase):

    def test_create_manager(self):
        rm = ResourceManager()
        self.assertIsNotNone(rm)

    def test_allocate(self):
        rm = ResourceManager()
        alloc = rm.allocate("vm1", ResourceProfile.SMALL)
        self.assertEqual(alloc.vm_id, "vm1")
        self.assertEqual(alloc.memory_mb, 2048)
        self.assertEqual(alloc.cpu_cores, 2)

    def test_allocate_duplicate_raises(self):
        rm = ResourceManager()
        rm.allocate("vm1", ResourceProfile.SMALL)
        with self.assertRaises(ValueError):
            rm.allocate("vm1", ResourceProfile.TINY)

    def test_deallocate(self):
        rm = ResourceManager()
        rm.allocate("vm1", ResourceProfile.SMALL)
        rm.deallocate("vm1")
        self.assertIsNone(rm.get_allocation("vm1"))

    def test_dynamic_memory_shrink(self):
        rm = ResourceManager()
        alloc = rm.allocate("vm1", ResourceProfile.MEDIUM)
        # Usage is 50% of 8192 = 4096, which is exactly 50% — no shrink
        new_size = rm.calculate_dynamic_memory("vm1", 2000)
        # 2000 < 8192*0.50 = 4096 → shrink to max(2048, 2500) = 2500
        self.assertEqual(new_size, 2500)

    def test_dynamic_memory_grow(self):
        rm = ResourceManager()
        alloc = rm.allocate("vm1", ResourceProfile.MEDIUM)
        original_size = alloc.memory_mb
        # Usage is 7000 (85% of 8192) → grow
        new_size = rm.calculate_dynamic_memory("vm1", 7000)
        self.assertGreater(new_size, original_size)

    def test_should_compress(self):
        rm = ResourceManager()
        alloc = rm.allocate("vm1", ResourceProfile.TINY)
        self.assertFalse(rm.should_compress("vm1"))
        alloc.state = VMState.PAUSED
        self.assertTrue(rm.should_compress("vm1"))

    def test_compress_memory(self):
        rm = ResourceManager()
        rm.allocate("vm1", ResourceProfile.TINY)
        self.assertTrue(rm.compress_memory("vm1"))
        alloc = rm.get_allocation("vm1")
        self.assertTrue(alloc.memory_compressed)

    def test_lazy_load_high_priority(self):
        rm = ResourceManager()
        rm.allocate("vm1", ResourceProfile.MEDIUM, priority=9)
        plan = rm.calculate_lazy_load("vm1")
        self.assertIn("kernel", plan["immediate"])
        self.assertIn("model", plan["immediate"])

    def test_lazy_load_low_priority(self):
        rm = ResourceManager()
        rm.allocate("vm1", ResourceProfile.TINY, priority=2)
        plan = rm.calculate_lazy_load("vm1")
        self.assertIn("kernel", plan["immediate"])
        self.assertIn("runtime", plan["deferred"])

    def test_allocate_gpu(self):
        rm = ResourceManager()
        rm._host = HostResources(
            total_memory_mb=16000, available_memory_mb=12000,
            total_cpu_cores=8, available_cpu_cores=8,
            total_gpu_count=2, available_gpu_count=2,
        )
        rm.allocate("vm1", ResourceProfile.MEDIUM)
        self.assertTrue(rm.allocate_gpu("vm1", 1))
        self.assertEqual(rm._host.available_gpu_count, 1)

    def test_allocate_gpu_insufficient(self):
        rm = ResourceManager()
        rm._host = HostResources(
            total_memory_mb=16000, available_memory_mb=12000,
            total_cpu_cores=8, available_cpu_cores=8,
            total_gpu_count=0, available_gpu_count=0,
        )
        rm.allocate("vm1", ResourceProfile.MEDIUM)
        self.assertFalse(rm.allocate_gpu("vm1", 1))

    def test_release_gpu(self):
        rm = ResourceManager()
        rm._host = HostResources(
            total_memory_mb=16000, available_memory_mb=12000,
            total_cpu_cores=8, available_cpu_cores=8,
            total_gpu_count=2, available_gpu_count=2,
        )
        rm.allocate("vm1", ResourceProfile.MEDIUM)
        rm.allocate_gpu("vm1", 1)
        rm.release_gpu("vm1")
        self.assertEqual(rm._host.available_gpu_count, 2)

    def test_summary(self):
        rm = ResourceManager()
        rm._host = HostResources(
            total_memory_mb=16000, available_memory_mb=12000,
            total_cpu_cores=8, available_cpu_cores=8,
        )
        rm.allocate("vm1", ResourceProfile.SMALL)
        summary = rm.get_summary()
        self.assertEqual(summary["allocated"]["vm_count"], 1)
        self.assertEqual(summary["allocated"]["memory_mb"], 2048)


class TestGPU(unittest.TestCase):

    def test_create_passthrough(self):
        gpu = GPUPassthrough()
        self.assertIsNotNone(gpu)

    @patch("lumenos_sandbox.gpu.subprocess.run")
    def test_detect_gpus(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='[{"DeviceID": "PCI\\\\VEN_10DE", "Name": "NVIDIA GeForce RTX 4090", '
                   '"AdapterRAM": 24576000000, "DriverVersion": "537.42"}]',
            returncode=0,
        )
        gpu = GPUPassthrough()
        devices = gpu.detect_gpus()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].vendor, GPUVendor.NVIDIA)

    def test_detect_vendor(self):
        gpu = GPUPassthrough()
        self.assertEqual(gpu._detect_vendor("NVIDIA GeForce RTX 4090"), GPUVendor.NVIDIA)
        self.assertEqual(gpu._detect_vendor("AMD Radeon RX 7900"), GPUVendor.AMD)
        self.assertEqual(gpu._detect_vendor("Intel UHD Graphics"), GPUVendor.INTEL)

    def test_list_available(self):
        gpu = GPUPassthrough()
        gpu._devices["d1"] = GPUDevice(
            device_id="d1", name="GPU 1", vendor=GPUVendor.NVIDIA,
            memory_mb=24000, driver_version="537.42", available=True,
        )
        gpu._devices["d2"] = GPUDevice(
            device_id="d2", name="GPU 2", vendor=GPUVendor.NVIDIA,
            memory_mb=24000, driver_version="537.42", available=False,
        )
        available = gpu.list_available()
        self.assertEqual(len(available), 1)

    def test_get_summary(self):
        gpu = GPUPassthrough()
        gpu._devices["d1"] = GPUDevice(
            device_id="d1", name="GPU 1", vendor=GPUVendor.NVIDIA,
            memory_mb=24000, driver_version="537.42", available=True,
        )
        summary = gpu.get_summary()
        self.assertEqual(summary["total_gpus"], 1)
        self.assertEqual(summary["available"], 1)


class TestImageBuilder(unittest.TestCase):

    def test_create_builder(self):
        builder = ImageBuilder("/tmp/test_images")
        self.assertIsNotNone(builder)

    def test_create_image(self):
        builder = ImageBuilder("/tmp/test_images")
        image = builder.create("test-pytorch", "pytorch")
        self.assertEqual(image.name, "test-pytorch")
        self.assertEqual(image.image_type, ImageType.FRAMEWORK)
        self.assertGreater(len(image.layers), 0)

    def test_create_unknown_framework_raises(self):
        builder = ImageBuilder("/tmp/test_images")
        with self.assertRaises(ValueError):
            builder.create("test", "unknown-framework")

    def test_create_duplicate_raises(self):
        builder = ImageBuilder("/tmp/test_images")
        builder.create("test", "pytorch")
        with self.assertRaises(ValueError):
            builder.create("test", "tensorflow")

    def test_add_custom_layer(self):
        builder = ImageBuilder("/tmp/test_images")
        image = builder.create("test", "onnxruntime")
        initial_layers = len(image.layers)
        builder.add_custom_layer(image, "my-code", [])
        self.assertEqual(len(image.layers), initial_layers + 1)

    def test_export_manifest(self):
        builder = ImageBuilder("/tmp/test_images")
        image = builder.create("test", "llamacpp")
        manifest = builder.export_manifest(image)
        self.assertEqual(manifest["name"], "test")
        self.assertIn("layers", manifest)

    def test_list_images(self):
        builder = ImageBuilder("/tmp/test_images")
        builder.create("img1", "pytorch")
        builder.create("img2", "tensorflow")
        self.assertEqual(len(builder.list_images()), 2)

    def test_get_image(self):
        builder = ImageBuilder("/tmp/test_images")
        builder.create("test", "pytorch")
        self.assertIsNotNone(builder.get_image("test"))
        self.assertIsNone(builder.get_image("nonexistent"))

    def test_delete_image(self):
        builder = ImageBuilder("/tmp/test_images")
        builder.create("test", "pytorch")
        self.assertTrue(builder.delete_image("test"))
        self.assertIsNone(builder.get_image("test"))

    def test_delete_nonexistent_returns_false(self):
        builder = ImageBuilder("/tmp/test_images")
        self.assertFalse(builder.delete_image("nonexistent"))


if __name__ == "__main__":
    unittest.main()
