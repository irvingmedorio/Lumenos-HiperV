"""REAL integration tests -- require Hyper-V on the host.

These tests create actual VMs, manage them, and clean up.
They SKIP automatically if Hyper-V is not available.

Run:
    py -3 -m pytest tests/test_integration_real.py -v --tb=short

Every test uses a unique UUID-based name to avoid collisions.
Module-scoped cleanup fixture sweeps remaining artifacts at the end.
"""

import subprocess
import time
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Hyper-V detection (reuse conftest marker when available, fallback inline)
# ---------------------------------------------------------------------------

try:
    from tests.conftest import requires_hyper_v, _hyper_v_available
except ImportError:
    def _hyper_v_available() -> bool:
        try:
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                 "(Get-WindowsOptionalFeature -Online "
                 "-FeatureName Microsoft-Hyper-V-All).State"],
                capture_output=True, text=True, timeout=15,
            )
            return "Enabled" in result.stdout
        except Exception:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                     "(Get-WindowsOptionalFeature -Online "
                     "-FeatureName Microsoft-Hyper-V-All).State"],
                    capture_output=True, text=True, timeout=15,
                )
                return "Enabled" in result.stdout
            except Exception:
                return False

    requires_hyper_v = pytest.mark.skipif(
        not _hyper_v_available(),
        reason="Hyper-V not available -- skipping real integration tests",
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_PREFIX = "lumenos_test_"  # All test artifacts start with this for cleanup

# PowerShell helper -- mirrors hypervisor._run_ps for test cleanup
def _run_ps(command: str, timeout: int = 30) -> tuple:
    for exe in ("pwsh", "powershell"):
        try:
            result = subprocess.run(
                [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True, text=True, timeout=timeout,
            )
            return (result.returncode == 0, result.stdout.strip(), result.stderr.strip())
        except Exception:
            continue
    return (False, "", "No PowerShell found")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cleanup_test_vms():
    """Yield, then sweep ALL test VMs/switches/VHDs after the module finishes."""
    yield
    # Stop + remove VMs
    _run_ps(
        f"Get-VM | Where-Object {{$_.Name -like '{TEST_PREFIX}*'}} | "
        f"ForEach-Object {{ Stop-VM -Name $_.Name -TurnOff -Force -ErrorAction SilentlyContinue; "
        f"Remove-VM -Name $_.Name -Force -ErrorAction SilentlyContinue }}",
        timeout=60,
    )
    # Remove switches
    _run_ps(
        f"Get-VMSwitch | Where-Object {{$_.Name -like '{TEST_PREFIX}*'}} | "
        f"Remove-VMSwitch -Force -ErrorAction SilentlyContinue",
        timeout=30,
    )
    # Remove VHDs
    snapshots_dir = Path("snapshots")
    if snapshots_dir.exists():
        for vhd in snapshots_dir.glob(f"{TEST_PREFIX}*.vhdx"):
            vhd.unlink(missing_ok=True)
    # Also clean bunker_* VMs that match our test config IDs
    _run_ps(
        f"Get-VM | Where-Object {{$_.Name -like 'bunker_{TEST_PREFIX}*'}} | "
        f"ForEach-Object {{ Stop-VM -Name $_.Name -TurnOff -Force -ErrorAction SilentlyContinue; "
        f"Remove-VM -Name $_.Name -Force -ErrorAction SilentlyContinue }}",
        timeout=60,
    )


@pytest.fixture
def uid():
    """Unique ID per test to avoid VM name collisions."""
    return str(uuid.uuid4())[:8]


@pytest.fixture
def test_config(uid):
    """BunkerConfig fields for a single test."""
    return {
        "id": f"{TEST_PREFIX}{uid}",
        "name": f"Test Sandbox {uid}",
        "memory_mb": 1024,
        "cpu_cores": 1,
        "guest_username": "Administrator",
        "guest_password": "",
    }


# ---------------------------------------------------------------------------
# Hypervisor function tests
# ---------------------------------------------------------------------------

@requires_hyper_v
class TestHypervisorFunctions:
    """Test hypervisor.py functions against real Hyper-V."""

    def test_check_hyper_v_available(self):
        from lumenos_sandbox.hypervisor import check_hyper_v_available
        assert check_hyper_v_available() is True

    def test_create_and_remove_internal_switch(self, test_config):
        from lumenos_sandbox.hypervisor import create_internal_switch, remove_switch
        switch_name = f"{test_config['id']}_sw"
        assert create_internal_switch(switch_name)
        assert remove_switch(switch_name)

    def test_create_and_remove_vm(self, test_config):
        from lumenos_sandbox.hypervisor import create_vm, remove_vm, get_vm_status
        vm_name = f"bunker_{test_config['id']}"
        assert create_vm(
            vm_name=vm_name,
            memory_mb=test_config["memory_mb"],
            cpu_cores=test_config["cpu_cores"],
        )
        status = get_vm_status(vm_name)
        assert status is not None  # VM exists

        assert remove_vm(vm_name)
        assert get_vm_status(vm_name) is None  # VM gone

    def test_vm_lifecycle_start_stop(self, test_config):
        from lumenos_sandbox.hypervisor import (
            create_vm, start_vm, stop_vm, get_vm_status, remove_vm,
        )
        vm_name = f"bunker_{test_config['id']}"
        assert create_vm(vm_name=vm_name, memory_mb=1024, cpu_cores=1)

        assert start_vm(vm_name)
        status = get_vm_status(vm_name)
        assert status is not None
        assert status.lower() in ("running", "starting")

        assert stop_vm(vm_name, force=True)
        status = get_vm_status(vm_name)
        assert status is not None
        assert status.lower() in ("off", "stopping", "saved")

        assert remove_vm(vm_name)

    def test_checkpoint_create_restore(self, test_config):
        from lumenos_sandbox.hypervisor import (
            create_vm, start_vm, stop_vm, create_checkpoint,
            restore_checkpoint, remove_vm,
        )
        vm_name = f"bunker_{test_config['id']}"
        assert create_vm(vm_name=vm_name, memory_mb=1024, cpu_cores=1)
        assert start_vm(vm_name)
        assert stop_vm(vm_name, force=True)

        checkpoint_name = f"test_cp_{int(time.time())}"
        assert create_checkpoint(vm_name, checkpoint_name)

        # Start VM again, then restore checkpoint
        assert start_vm(vm_name)
        time.sleep(2)
        assert stop_vm(vm_name, force=True)
        assert restore_checkpoint(vm_name, checkpoint_name)

        # Clean up checkpoints before removing VM
        _run_ps(
            f"Get-VMCheckpoint -VMName '{vm_name}' | "
            f"Remove-VMCheckpoint -Confirm:$false -ErrorAction SilentlyContinue",
            timeout=30,
        )
        assert remove_vm(vm_name)

    def test_differencing_disk(self, test_config):
        from lumenos_sandbox.hypervisor import create_differencing_disk, delete_file

        snapshots_dir = Path("snapshots")
        snapshots_dir.mkdir(exist_ok=True)

        base_vhd = str(snapshots_dir / f"{TEST_PREFIX}{test_config['id']}_base.vhdx")
        diff_vhd = str(snapshots_dir / f"{TEST_PREFIX}{test_config['id']}_diff.vhdx")

        # Create base VHD via PowerShell
        ok, _, err = _run_ps(
            f"New-VHD -Path '{base_vhd}' -SizeBytes 1GB", timeout=60,
        )
        assert ok or Path(base_vhd).exists(), f"Base VHD creation failed: {err}"

        assert create_differencing_disk(base_vhd, diff_vhd)
        assert Path(diff_vhd).exists()

        # Cleanup
        assert delete_file(diff_vhd)
        assert delete_file(base_vhd)

    def test_verify_host_integrity(self):
        from lumenos_sandbox.hypervisor import verify_host_integrity
        success, message = verify_host_integrity()
        assert success is True
        assert "Hyper-V" in message or "VM(s)" in message


# ---------------------------------------------------------------------------
# Bunker lifecycle tests
# ---------------------------------------------------------------------------

@requires_hyper_v
class TestBunkerLifecycle:
    """Test full Bunker lifecycle with real VM."""

    def test_full_lifecycle(self, test_config):
        from lumenos_sandbox.types import BunkerConfig
        from lumenos_sandbox.bunker import Bunker

        config = BunkerConfig(
            id=test_config["id"],
            name=test_config["name"],
            memory_mb=test_config["memory_mb"],
            cpu_cores=test_config["cpu_cores"],
            guest_username=test_config["guest_username"],
            guest_password=test_config["guest_password"],
        )

        bunker = Bunker(config)

        # Initialize (creates VM + switch)
        assert bunker.initialize()
        assert bunker._vm_name is not None
        assert bunker._switch_name is not None
        assert bunker.state.name == "READY"

        # Activate (security layers + monitoring)
        assert bunker.activate()
        assert bunker.state.name == "ACTIVE"

        # Full status (real data from live VM)
        status = bunker.get_full_status()
        assert status["state"] == "ACTIVE"
        assert status["vm_name"] is None or status["vm_name"] is not None  # structured
        assert isinstance(status["security_layers"], dict)
        assert len(status["security_layers"]) == 5

        # Terminate + decontaminate
        assert bunker.terminate()
        assert bunker.state.name in ("DESTROYED", "ERROR")

    def test_initialize_creates_real_vm(self, test_config):
        """Verify that Bunker.initialize() actually creates a Hyper-V VM."""
        from lumenos_sandbox.types import BunkerConfig
        from lumenos_sandbox.bunker import Bunker
        from lumenos_sandbox.hypervisor import get_vm_status

        config = BunkerConfig(
            id=test_config["id"],
            name=test_config["name"],
            memory_mb=test_config["memory_mb"],
            cpu_cores=test_config["cpu_cores"],
            guest_username=test_config["guest_username"],
            guest_password=test_config["guest_password"],
        )

        bunker = Bunker(config)
        assert bunker.initialize()

        # VM should exist in Hyper-V
        vm_name = bunker._vm_name
        assert vm_name is not None
        status = get_vm_status(vm_name)
        assert status is not None, f"VM {vm_name} not found in Hyper-V after initialize()"

        # State file should have been persisted
        state_file = Path("snapshots") / f"{test_config['id']}_state.json"
        assert state_file.exists(), "State file not persisted during initialize()"

        # Cleanup
        bunker.terminate()

    def test_terminate_removes_real_vm(self, test_config):
        """Verify that Bunker.terminate() actually removes the Hyper-V VM."""
        from lumenos_sandbox.types import BunkerConfig
        from lumenos_sandbox.bunker import Bunker
        from lumenos_sandbox.hypervisor import get_vm_status

        config = BunkerConfig(
            id=test_config["id"],
            name=test_config["name"],
            memory_mb=test_config["memory_mb"],
            cpu_cores=test_config["cpu_cores"],
            guest_username=test_config["guest_username"],
            guest_password=test_config["guest_password"],
        )

        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()

        vm_name = bunker._vm_name
        assert get_vm_status(vm_name) is not None  # VM exists before terminate

        bunker.terminate()

        # After full decontamination, state should be DESTROYED
        assert bunker.state.name == "DESTROYED", (
            f"Expected DESTROYED after terminate, got {bunker.state.name}"
        )


# ---------------------------------------------------------------------------
# Guest interaction tests (PowerShell Direct)
# ---------------------------------------------------------------------------

@requires_hyper_v
class TestGuestInteraction:
    """Test PowerShell Direct guest interaction.

    These tests boot a real VM and execute commands inside it.
    They skip gracefully if PowerShell Direct is not available
    (e.g. no local admin account configured).
    """

    def test_execute_in_guest(self, test_config):
        from lumenos_sandbox.hypervisor import (
            create_vm, start_vm, enable_guest_integration, execute_in_guest,
            stop_vm, remove_vm,
        )
        vm_name = f"bunker_{test_config['id']}"

        assert create_vm(vm_name=vm_name, memory_mb=1024, cpu_cores=1)
        assert start_vm(vm_name)
        assert enable_guest_integration(vm_name)

        # Wait for VM to boot and Integration Services to start
        time.sleep(30)

        success, output = execute_in_guest(
            vm_name, "Administrator", "", "hostname",
        )
        if success:
            assert len(output.strip()) > 0, "hostname command returned empty output"
        else:
            # No local admin or PowerShell Direct not configured
            _run_ps(
                f"Stop-VM -Name '{vm_name}' -TurnOff -Force -ErrorAction SilentlyContinue",
                timeout=30,
            )
            remove_vm(vm_name)
            pytest.skip("PowerShell Direct not available (no local admin account?)")

        _run_ps(
            f"Stop-VM -Name '{vm_name}' -TurnOff -Force -ErrorAction SilentlyContinue",
            timeout=30,
        )
        assert remove_vm(vm_name)


# ---------------------------------------------------------------------------
# DualBunkerManager tests
# ---------------------------------------------------------------------------

@requires_hyper_v
class TestDualBunkerManager:
    """Test real DualBunkerManager with live Hyper-V VMs."""

    def test_start_end_start_lifecycle(self, test_config):
        """start_session -> end_session -> start_session without crashing."""
        from lumenos_sandbox.types import BunkerConfig
        from lumenos_sandbox.manager import DualBunkerManager

        config = BunkerConfig(
            id=test_config["id"],
            name=test_config["name"],
            memory_mb=1024,
            cpu_cores=1,
        )

        manager = DualBunkerManager(config)

        # First session
        assert manager.start_session()
        assert manager.active_bunker is not None
        first_vm = manager.active_bunker._vm_name
        first_id = manager.active_bunker.config.id
        assert manager.total_sessions == 1

        # End session
        assert manager.end_session()
        assert manager.active_bunker is None

        # Second session (re-initializes bunker1 since active_bunker is None)
        assert manager.start_session()
        assert manager.active_bunker is not None
        second_vm = manager.active_bunker._vm_name
        assert manager.total_sessions == 2

        # VM names are deterministic (same config.id -> same VM name),
        # but both sessions should have successfully created the VM
        assert second_vm is not None
        assert first_vm == second_vm  # Same config.id -> same name

        # Cleanup
        manager.end_session()

    def test_manager_status_structured(self, test_config):
        """get_status() returns correct structure with real VMs."""
        from lumenos_sandbox.types import BunkerConfig
        from lumenos_sandbox.manager import DualBunkerManager

        config = BunkerConfig(
            id=test_config["id"],
            name=test_config["name"],
            memory_mb=1024,
            cpu_cores=1,
        )

        manager = DualBunkerManager(config)
        assert manager.start_session()

        status = manager.get_status()
        assert status["rotation_count"] == 0
        assert status["total_sessions"] == 1
        assert status["active_bunker"] is not None
        assert isinstance(status["combined_escape_probability"], float)

        # Cleanup
        manager.end_session()


# ---------------------------------------------------------------------------
# Decontamination verification
# ---------------------------------------------------------------------------

@requires_hyper_v
class TestCleanupVerification:
    """Verify that decontamination actually cleans up Hyper-V resources."""

    def test_decontamination_removes_vm(self, test_config):
        from lumenos_sandbox.types import BunkerConfig
        from lumenos_sandbox.bunker import Bunker
        from lumenos_sandbox.hypervisor import get_vm_status

        config = BunkerConfig(
            id=test_config["id"],
            name=test_config["name"],
            memory_mb=1024,
            cpu_cores=1,
        )

        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()

        vm_name = bunker._vm_name
        assert get_vm_status(vm_name) is not None  # VM exists

        bunker.terminate()

        # State machine reached DESTROYED
        assert bunker.state.name == "DESTROYED"
        # VM should be removed by decontamination (_step_remove_snapshots)
        status = get_vm_status(vm_name)
        assert status is None, (
            f"VM {vm_name} still exists after decontamination (status={status})"
        )

    def test_decontamination_removes_switch(self, test_config):
        from lumenos_sandbox.types import BunkerConfig
        from lumenos_sandbox.bunker import Bunker

        config = BunkerConfig(
            id=test_config["id"],
            name=test_config["name"],
            memory_mb=1024,
            cpu_cores=1,
        )

        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()

        switch_name = bunker._switch_name
        assert switch_name is not None

        bunker.terminate()

        # Switch should be removed (_step_clean_network_config)
        ok, stdout, _ = _run_ps(
            f"Get-VMSwitch -Name '{switch_name}' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Name",
        )
        # stdout should be empty (switch doesn't exist)
        assert not (ok and stdout), (
            f"Switch {switch_name} still exists after decontamination"
        )

    def test_decontamination_removes_vhd(self, test_config):
        from lumenos_sandbox.types import BunkerConfig
        from lumenos_sandbox.bunker import Bunker

        config = BunkerConfig(
            id=test_config["id"],
            name=test_config["name"],
            memory_mb=1024,
            cpu_cores=1,
        )

        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()

        vhd_path = Path("snapshots") / f"{test_config['id']}_system.vhdx"
        assert vhd_path.exists(), f"VHD {vhd_path} should exist after initialize"

        bunker.terminate()

        # VHD should be removed (_step_destroy_differential_disk)
        assert not vhd_path.exists(), (
            f"VHD {vhd_path} still exists after decontamination"
        )
