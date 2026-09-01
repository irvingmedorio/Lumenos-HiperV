"""Unit tests for resource_manager — RAM/CPU/GPU allocation and efficiency."""

from unittest.mock import patch, MagicMock

import pytest

from lumenos_sandbox.resource_manager import (
    HostResources,
    PROFILE_SPECS,
    ResourceProfile,
    ResourceManager,
    VMResourceAlloc,
    VMState,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager(*, total_mem=16384, used_mem=8192, cpu_count=8,
                  gpu_count=2, gpu_mem=12288):
    """Build a ResourceManager with mocked host detection."""
    rm = ResourceManager()

    ps_total = MagicMock(stdout=f"{total_mem}\n")
    ps_used = MagicMock(stdout=f"{used_mem}\n")
    # Build GPU JSON dynamically from gpu_count / gpu_mem
    gpu_mem_each = (gpu_mem * 1024 * 1024) // max(gpu_count, 1)
    gpus = [{"AdapterRAM": gpu_mem_each, "Name": f"GPU{i}"}
            for i in range(gpu_count)] if gpu_count else []
    ps_gpu = MagicMock(stdout=json.dumps(gpus) if gpus else "")

    with patch("subprocess.run", side_effect=[ps_total, ps_used, ps_gpu]), \
         patch("os.cpu_count", return_value=cpu_count):
        rm.detect_host_resources()

    return rm


# ---------------------------------------------------------------------------
# detect_host_resources
# ---------------------------------------------------------------------------

class TestDetectHostResources:
    """Mock PowerShell calls and verify parsed values."""

    def test_returns_host_resources(self):
        rm = _make_manager(total_mem=8192, used_mem=4096, cpu_count=4)
        assert isinstance(rm._host, HostResources)

    def test_total_memory(self):
        rm = _make_manager(total_mem=16384)
        assert rm._host.total_memory_mb == 16384

    def test_available_memory(self):
        rm = _make_manager(total_mem=16384, used_mem=4096)
        assert rm._host.available_memory_mb == 12288

    def test_cpu_cores(self):
        rm = _make_manager(cpu_count=16)
        assert rm._host.total_cpu_cores == 16
        assert rm._host.available_cpu_cores == 16

    def test_gpu_detection(self):
        rm = _make_manager(gpu_count=2)
        assert rm._host.total_gpu_count == 2
        assert rm._host.available_gpu_count == 2
        assert rm._host.gpu_memory_total_mb > 0

    def test_powershell_failure_returns_zeros(self):
        rm = ResourceManager()
        with patch("subprocess.run", side_effect=Exception("ps fail")), \
             patch("os.cpu_count", return_value=None):
            host = rm.detect_host_resources()
        assert host.total_memory_mb == 0
        assert host.total_cpu_cores == 4  # fallback


# ---------------------------------------------------------------------------
# allocate / deallocate
# ---------------------------------------------------------------------------

class TestAllocate:
    def test_allocate_basic(self):
        rm = _make_manager()
        alloc = rm.allocate("vm1", ResourceProfile.SMALL)
        assert alloc.vm_id == "vm1"
        assert alloc.memory_mb == 2048
        assert alloc.cpu_cores == 2
        assert alloc.disk_gb == 50

    def test_allocate_all_profiles(self):
        rm = _make_manager()
        for profile, spec in PROFILE_SPECS.items():
            vm_id = f"vm_{profile.name}"
            alloc = rm.allocate(vm_id, profile)
            assert alloc.memory_mb == spec["memory_mb"]
            assert alloc.cpu_cores == spec["cpu_cores"]
            assert alloc.disk_gb == spec["disk_gb"]

    def test_allocate_duplicate_raises(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY)
        with pytest.raises(ValueError, match="already allocated"):
            rm.allocate("vm1", ResourceProfile.TINY)

    def test_allocate_with_gpu(self):
        rm = _make_manager()
        alloc = rm.allocate("vm1", ResourceProfile.LARGE, gpu_count=1)
        assert alloc.gpu_count == 1

    def test_allocate_with_priority(self):
        rm = _make_manager()
        alloc = rm.allocate("vm1", ResourceProfile.TINY, priority=9)
        assert alloc.priority == 9

    def test_allocate_default_state(self):
        rm = _make_manager()
        alloc = rm.allocate("vm1", ResourceProfile.TINY)
        assert alloc.state == VMState.CREATED


class TestDeallocate:
    def test_deallocate_removes_vm(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY)
        rm.deallocate("vm1")
        assert rm.get_allocation("vm1") is None

    def test_deallocate_nonexistent_is_noop(self):
        rm = _make_manager()
        rm.deallocate("ghost")  # should not raise

    def test_deallocate_preserves_others(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY)
        rm.allocate("vm2", ResourceProfile.SMALL)
        rm.deallocate("vm1")
        assert rm.get_allocation("vm2") is not None


# ---------------------------------------------------------------------------
# PROFILE_SPECS
# ---------------------------------------------------------------------------

class TestProfileSpecs:
    def test_all_profiles_present(self):
        expected = {ResourceProfile.TINY, ResourceProfile.SMALL,
                    ResourceProfile.MEDIUM, ResourceProfile.LARGE}
        assert set(PROFILE_SPECS.keys()) == expected

    def test_tiny_specs(self):
        assert PROFILE_SPECS[ResourceProfile.TINY] == {
            "memory_mb": 512, "cpu_cores": 1, "disk_gb": 10,
        }

    def test_small_specs(self):
        assert PROFILE_SPECS[ResourceProfile.SMALL] == {
            "memory_mb": 2048, "cpu_cores": 2, "disk_gb": 50,
        }

    def test_medium_specs(self):
        assert PROFILE_SPECS[ResourceProfile.MEDIUM] == {
            "memory_mb": 8192, "cpu_cores": 4, "disk_gb": 100,
        }

    def test_large_specs(self):
        assert PROFILE_SPECS[ResourceProfile.LARGE] == {
            "memory_mb": 16384, "cpu_cores": 8, "disk_gb": 200,
        }


# ---------------------------------------------------------------------------
# calculate_dynamic_memory (maps to user's "set_dynamic_memory")
# ---------------------------------------------------------------------------

class TestCalculateDynamicMemory:
    def _setup(self, profile=ResourceProfile.MEDIUM):
        rm = _make_manager()
        rm.allocate("vm1", profile)
        return rm

    def test_unknown_vm_returns_zero(self):
        rm = _make_manager()
        assert rm.calculate_dynamic_memory("ghost", 100) == 0

    def test_stays_stable_in_mid_range(self):
        rm = self._setup(ResourceProfile.MEDIUM)  # base=8192
        # 60% usage → no change
        result = rm.calculate_dynamic_memory("vm1", 4915)
        assert result == 8192

    def test_shrinks_under_low_usage(self):
        rm = self._setup(ResourceProfile.MEDIUM)  # base=8192
        # 30% usage → shrink from 8192 to something smaller
        result = rm.calculate_dynamic_memory("vm1", 2457)
        # Formula: max(min_mem, int(usage * 1.25)) = max(2048, 3071) = 3071
        assert result < 8192  # must shrink from original allocation

    def test_grows_over_high_usage(self):
        rm = self._setup(ResourceProfile.TINY)  # base=512
        # 90% usage → grow
        result = rm.calculate_dynamic_memory("vm1", 460)
        assert result > 460

    def test_bounded_by_min(self):
        rm = self._setup(ResourceProfile.TINY)
        result = rm.calculate_dynamic_memory("vm1", 1)
        # min_mem = 512 * 0.25 = 128; result = max(128, int(1*1.25)=1)
        assert result >= 128

    def test_bounded_by_max(self):
        rm = self._setup(ResourceProfile.TINY)  # base=512, max=768
        result = rm.calculate_dynamic_memory("vm1", 1000)
        assert result <= 768


# ---------------------------------------------------------------------------
# Memory compression
# ---------------------------------------------------------------------------

class TestMemoryCompression:
    def test_compress_paused(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY)
        rm._allocations["vm1"].state = VMState.PAUSED
        assert rm.should_compress("vm1") is True

    def test_compress_saved(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY)
        rm._allocations["vm1"].state = VMState.SAVED
        assert rm.should_compress("vm1") is True

    def test_no_compress_running(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY)
        assert rm.should_compress("vm1") is False

    def test_compress_marks_flag(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY)
        rm._allocations["vm1"].state = VMState.PAUSED
        assert rm.compress_memory("vm1") is True
        assert rm._allocations["vm1"].memory_compressed is True

    def test_compress_unknown_vm_returns_false(self):
        rm = _make_manager()
        assert rm.compress_memory("ghost") is False


# ---------------------------------------------------------------------------
# Lazy loading
# ---------------------------------------------------------------------------

class TestLazyLoad:
    def test_high_priority_loads_everything(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY, priority=10)
        plan = rm.calculate_lazy_load("vm1")
        assert "kernel" in plan["immediate"]
        assert "model" in plan["immediate"]
        assert plan["deferred"] == []

    def test_medium_priority_defers_model(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY, priority=5)
        plan = rm.calculate_lazy_load("vm1")
        assert "model" in plan["deferred"]
        assert "kernel" in plan["immediate"]

    def test_low_priority_minimal(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY, priority=1)
        plan = rm.calculate_lazy_load("vm1")
        assert plan["immediate"] == ["kernel"]

    def test_unknown_vm_empty_plan(self):
        rm = _make_manager()
        plan = rm.calculate_lazy_load("ghost")
        assert plan == {"immediate": [], "deferred": []}


# ---------------------------------------------------------------------------
# GPU management
# ---------------------------------------------------------------------------

class TestAllocateGPU:
    def test_allocate_gpu_success(self):
        rm = _make_manager(gpu_count=2)
        rm.allocate("vm1", ResourceProfile.LARGE)
        assert rm.allocate_gpu("vm1", count=1) is True
        assert rm._allocations["vm1"].gpu_count == 1
        assert rm._host.available_gpu_count == 1

    def test_allocate_gpu_exceeds_available(self):
        rm = _make_manager(gpu_count=1)
        rm.allocate("vm1", ResourceProfile.LARGE)
        assert rm.allocate_gpu("vm1", count=2) is False

    def test_allocate_gpu_unknown_vm(self):
        rm = _make_manager(gpu_count=2)
        assert rm.allocate_gpu("ghost", count=1) is False

    def test_allocate_multiple_gpus(self):
        rm = _make_manager(gpu_count=4)
        rm.allocate("vm1", ResourceProfile.LARGE)
        assert rm.allocate_gpu("vm1", count=3) is True
        assert rm._host.available_gpu_count == 1


class TestReleaseGPU:
    def test_release_gpu_restores_count(self):
        rm = _make_manager(gpu_count=2)
        rm.allocate("vm1", ResourceProfile.LARGE)
        rm.allocate_gpu("vm1", count=2)
        rm.release_gpu("vm1")
        assert rm._allocations["vm1"].gpu_count == 0
        assert rm._host.available_gpu_count == 2

    def test_release_gpu_unknown_vm_noop(self):
        rm = _make_manager(gpu_count=2)
        rm.release_gpu("ghost")  # should not raise

    def test_release_gpu_no_allocation_noop(self):
        rm = _make_manager(gpu_count=2)
        rm.allocate("vm1", ResourceProfile.TINY)
        rm.release_gpu("vm1")  # gpu_count is 0, nothing to release
        assert rm._host.available_gpu_count == 2


# ---------------------------------------------------------------------------
# get_summary (maps to user's "get_available")
# ---------------------------------------------------------------------------

class TestGetSummary:
    def test_empty_summary(self):
        rm = _make_manager(total_mem=8192, cpu_count=4)
        s = rm.get_summary()
        assert s["allocated"]["vm_count"] == 0
        assert s["allocated"]["memory_mb"] == 0

    def test_summary_after_allocations(self):
        rm = _make_manager(total_mem=16384, cpu_count=8)
        rm.allocate("vm1", ResourceProfile.SMALL)   # 2048, 2
        rm.allocate("vm2", ResourceProfile.MEDIUM)   # 8192, 4
        s = rm.get_summary()
        assert s["allocated"]["vm_count"] == 2
        assert s["allocated"]["memory_mb"] == 10240
        assert s["allocated"]["cpu_cores"] == 6

    def test_utilization_percentages(self):
        rm = _make_manager(total_mem=16384, cpu_count=8)
        rm.allocate("vm1", ResourceProfile.MEDIUM)  # 8192/16384 = 50%
        s = rm.get_summary()
        assert s["efficiency"]["memory_utilization_pct"] == 50.0


# ---------------------------------------------------------------------------
# get_allocation
# ---------------------------------------------------------------------------

class TestGetAllocation:
    def test_get_existing(self):
        rm = _make_manager()
        rm.allocate("vm1", ResourceProfile.TINY)
        alloc = rm.get_allocation("vm1")
        assert isinstance(alloc, VMResourceAlloc)
        assert alloc.vm_id == "vm1"

    def test_get_missing_returns_none(self):
        rm = _make_manager()
        assert rm.get_allocation("ghost") is None
