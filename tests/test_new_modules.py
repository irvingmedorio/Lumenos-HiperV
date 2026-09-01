"""Tests for package_engine.py, analysis_agent.py, multi_host.py, phone_support.py."""

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from lumenos_sandbox.package_engine import (
    PackageEngine, PackageManifest, PackageLayer, PackageFlag, LVA_MAGIC,
)
from lumenos_sandbox.analysis_agent import (
    AnalysisAgent, AnalysisReport, AgentStatus, MonitorType,
    ProcessEvent, FileEvent, NetworkEvent, RegistryEvent,
)
from lumenos_sandbox.multi_host import (
    MultiHostManager, HostNode, HostRole, HostStatus, ClusterConfig,
)
from lumenos_sandbox.phone_support import (
    PhoneSupport, DeviceCapabilities, PhoneVMConfig,
    DevicePlatform, HypervisorType,
)


class TestPackageEngine(unittest.TestCase):

    def test_create_engine(self):
        engine = PackageEngine("/tmp/test_pkgs")
        self.assertIsNotNone(engine)

    def test_create_package(self):
        engine = PackageEngine("/tmp/test_pkgs")
        # Create a temp file to package
        with tempfile.NamedTemporaryFile(suffix=".vhdx", delete=False) as f:
            f.write(b"fake vhdx data")
            vhdx_path = f.name
        try:
            pkg_path = engine.create("test-pkg", image_path=vhdx_path)
            self.assertTrue(pkg_path.exists())
            self.assertTrue(pkg_path.name.endswith(".lva"))
        finally:
            os.unlink(vhdx_path)

    def test_verify_package(self):
        engine = PackageEngine("/tmp/test_pkgs")
        with tempfile.NamedTemporaryFile(suffix=".vhdx", delete=False) as f:
            f.write(b"fake vhdx data")
            vhdx_path = f.name
        try:
            pkg_path = engine.create("verify-test", image_path=vhdx_path)
            result = engine.verify(str(pkg_path))
            self.assertTrue(result["valid"])
            self.assertEqual(result["name"], "verify-test")
        finally:
            os.unlink(vhdx_path)

    def test_list_packages(self):
        engine = PackageEngine("/tmp/test_pkgs")
        with tempfile.NamedTemporaryFile(suffix=".vhdx", delete=False) as f:
            f.write(b"data")
            vhdx_path = f.name
        try:
            engine.create("pkg1", image_path=vhdx_path)
            engine.create("pkg2", image_path=vhdx_path)
            self.assertEqual(len(engine.list_packages()), 2)
        finally:
            os.unlink(vhdx_path)


class TestAnalysisAgent(unittest.TestCase):

    def test_create_agent(self):
        agent = AnalysisAgent()
        self.assertIsNotNone(agent)

    def test_get_status_stopped(self):
        agent = AnalysisAgent()
        self.assertEqual(agent.get_status("vm1"), AgentStatus.STOPPED)

    def test_ioc_detection(self):
        agent = AnalysisAgent()
        report = AnalysisReport(
            sandbox_id="test",
            start_time="2026-01-01T00:00:00",
            end_time="2026-01-01T00:01:00",
            duration_seconds=60,
            process_events=[
                ProcessEvent(
                    timestamp="2026-01-01T00:00:01",
                    pid=1234, ppid=1, name="mimikatz.exe",
                    path="C:\\temp\\mimikatz.exe",
                ),
            ],
            network_events=[
                NetworkEvent(
                    timestamp="2026-01-01T00:00:02",
                    protocol="TCP", local_addr="10.0.0.1", local_port=1234,
                    remote_addr="192.168.1.100", remote_port=4444,
                ),
            ],
            registry_events=[
                RegistryEvent(
                    timestamp="2026-01-01T00:00:03",
                    event_type="created",
                    key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                ),
            ],
        )
        iocs = agent._detect_iocs(report)
        self.assertGreater(len(iocs), 0)
        # Should detect mimikatz, suspicious port, registry persistence
        types_found = {i["type"] for i in iocs}
        self.assertIn("process", types_found)
        self.assertIn("network", types_found)
        self.assertIn("registry", types_found)

    def test_summary_generation(self):
        agent = AnalysisAgent()
        report = AnalysisReport(
            sandbox_id="test",
            start_time="2026-01-01T00:00:00",
            end_time="2026-01-01T00:01:00",
            duration_seconds=60,
            process_events=[
                ProcessEvent(timestamp="", pid=1, ppid=0, name="proc1", path=""),
                ProcessEvent(timestamp="", pid=2, ppid=0, name="proc2", path=""),
            ],
        )
        summary = agent._generate_summary(report)
        self.assertEqual(summary["total_processes"], 2)
        self.assertEqual(summary["unique_processes"], 2)


class TestMultiHost(unittest.TestCase):

    def test_create_cluster(self):
        config = ClusterConfig(name="test-cluster")
        cluster = MultiHostManager(config)
        self.assertIsNotNone(cluster)

    def test_add_host(self):
        cluster = MultiHostManager()
        host = cluster.add_host("host1", "192.168.1.10", HostRole.COORDINATOR)
        self.assertEqual(host.name, "host1")
        self.assertEqual(host.role, HostRole.COORDINATOR)

    def test_remove_host(self):
        cluster = MultiHostManager()
        cluster.add_host("host1", "192.168.1.10")
        self.assertTrue(cluster.remove_host("host1"))
        self.assertIsNone(cluster.get_host("host1"))

    def test_register_unregister_vm(self):
        cluster = MultiHostManager()
        cluster.add_host("host1", "192.168.1.10")
        self.assertTrue(cluster.register_vm("vm1", "host1"))
        host = cluster.get_vm_host("vm1")
        self.assertIsNotNone(host)
        self.assertEqual(host.name, "host1")
        self.assertTrue(cluster.unregister_vm("vm1"))
        self.assertIsNone(cluster.get_vm_host("vm1"))

    def test_find_best_host(self):
        cluster = MultiHostManager()
        h1 = cluster.add_host("host1", "192.168.1.10")
        h1.total_memory_mb = 16000
        h1.available_memory_mb = 12000
        h1.total_cpu_cores = 8
        h1.available_cpu_cores = 6
        h2 = cluster.add_host("host2", "192.168.1.11")
        h2.total_memory_mb = 4000
        h2.available_memory_mb = 2000
        h2.total_cpu_cores = 2
        h2.available_cpu_cores = 1

        # Request 8GB RAM — should pick host1
        best = cluster.find_best_host(memory_mb=8192, cpu_cores=4)
        self.assertIsNotNone(best)
        self.assertEqual(best.name, "host1")

    def test_summary(self):
        cluster = MultiHostManager()
        cluster.add_host("host1", "192.168.1.10")
        cluster.add_host("host2", "192.168.1.11")
        cluster.register_vm("vm1", "host1")
        cluster.register_vm("vm2", "host2")
        summary = cluster.get_summary()
        self.assertEqual(summary["hosts"]["total"], 2)
        self.assertEqual(summary["vms"]["total"], 2)


class TestPhoneSupport(unittest.TestCase):

    def test_create_phone_support(self):
        phone = PhoneSupport()
        self.assertIsNotNone(phone)

    def test_detect_capabilities(self):
        phone = PhoneSupport()
        caps = phone.detect_capabilities()
        self.assertIsNotNone(caps)
        self.assertIn(caps.platform, list(DevicePlatform))
        self.assertIn(caps.hypervisor, list(HypervisorType))

    def test_create_config(self):
        phone = PhoneSupport()
        phone.detect_capabilities()
        config = phone.create_config("sandbox1", memory_mb=1024)
        self.assertEqual(config.name, "sandbox1")
        self.assertGreaterEqual(config.memory_mb, 128)

    def test_recommendation(self):
        phone = PhoneSupport()
        phone.detect_capabilities()
        rec = phone.get_recommendation()
        self.assertIn("platform", rec)
        self.assertIn("hypervisor", rec)
        self.assertIn("max_vms", rec)

    def test_list_vms(self):
        phone = PhoneSupport()
        phone.detect_capabilities()
        phone.create_config("vm1")
        phone.create_config("vm2")
        self.assertEqual(len(phone.list_vms()), 2)


if __name__ == "__main__":
    unittest.main()
