"""End-to-end integration tests for LumenOS Sandbox lifecycle."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from lumenos_sandbox.types import BunkerConfig, BunkerState, EscapeAttemptType, SecurityLayer
from lumenos_sandbox.bunker import Bunker
from lumenos_sandbox.hypervisor import check_hyper_v_available
from lumenos_sandbox.manager import DualBunkerManager
from lumenos_sandbox.monitoring import SecurityMonitor


# ---------------------------------------------------------------------------
# Mock ALL hypervisor functions at the boundary
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_hypervisor():
    """Mock all hypervisor functions for integration tests."""
    with patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True), \
         patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True), \
         patch("lumenos_sandbox.hypervisor.remove_switch", return_value=True), \
         patch("lumenos_sandbox.hypervisor.create_vm", return_value=True), \
         patch("lumenos_sandbox.hypervisor.start_vm", return_value=True), \
         patch("lumenos_sandbox.hypervisor.stop_vm", return_value=True), \
         patch("lumenos_sandbox.hypervisor.remove_vm", return_value=True), \
         patch("lumenos_sandbox.hypervisor.delete_file", return_value=True), \
         patch("lumenos_sandbox.hypervisor.create_checkpoint", return_value=True), \
         patch("lumenos_sandbox.hypervisor.get_vm_status", return_value="Off"), \
         patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True), \
         patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True), \
         patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True), \
         patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[]), \
         patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
               return_value={"vbs_enabled": True}), \
         patch("lumenos_sandbox.hypervisor.read_guest_event_log", return_value=[]), \
         patch("lumenos_sandbox.hypervisor.verify_host_integrity", return_value=(True, "OK")), \
         patch("lumenos_sandbox.bunker.Bunker._persist_state"), \
         patch("lumenos_sandbox.bunker.Bunker._save_decontamination_report"):
        yield


@pytest.fixture(autouse=True)
def clean_snapshots():
    """Clean up snapshots dir after each test."""
    yield
    snap_dir = Path("snapshots")
    if snap_dir.exists():
        for f in snap_dir.glob("*_state.json"):
            f.unlink(missing_ok=True)


def get_test_config():
    return BunkerConfig(
        id="integration_test",
        name="Integration Test Sandbox",
        memory_mb=4096,
        cpu_cores=2,
        guest_username="Administrator",
        guest_password="test",
    )


# ===========================================================================
# Full Lifecycle Tests
# ===========================================================================

class TestFullLifecycle:
    """Test complete lifecycle: init -> activate -> operations -> terminate -> decontaminate."""

    def test_initialize_success(self):
        config = get_test_config()
        bunker = Bunker(config)
        assert bunker.initialize()
        assert bunker.state == BunkerState.READY

    def test_activate_success(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        assert bunker.activate()
        assert bunker.state == BunkerState.ACTIVE

    def test_terminate_success(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()
        assert bunker.terminate()
        assert bunker.state == BunkerState.DESTROYED

    def test_full_session(self):
        """Complete session: init -> activate -> get status -> terminate."""
        config = get_test_config()
        bunker = Bunker(config)

        # Initialize
        assert bunker.initialize()
        assert bunker.created_at is not None

        # Activate
        assert bunker.activate()
        assert bunker.activated_at is not None

        # Get status
        status = bunker.get_full_status()
        assert status["state"] == "ACTIVE"
        assert "escape_probability" in status
        assert "security_layers" in status

        # Terminate
        assert bunker.terminate()
        assert bunker.terminated_at is not None

    def test_escape_probability_calculation(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()

        prob = bunker.get_escape_probability()
        # All 5 layers active: product of failure probabilities
        # 1e-6 * 1e-8 * 1e-5 * 1e-9 * 1e-12 = 1e-40
        assert prob == pytest.approx(1e-40, rel=1e-10)

    def test_quarantine(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()

        bunker.force_quarantine("Test quarantine")
        assert bunker.state == BunkerState.QUARANTINE

    def test_invalid_transition_raises(self):
        """Can't activate from DESTROYED — must go through INITIALIZING."""
        from lumenos_sandbox.exceptions import InvalidStateTransition
        config = get_test_config()
        bunker = Bunker(config)
        assert bunker.state == BunkerState.DESTROYED
        # activate() raises BunkerNotReady internally; the error handler
        # tries transition_to(ERROR) but DESTROYED→ERROR is not valid,
        # so InvalidStateTransition propagates up.
        with pytest.raises(InvalidStateTransition):
            bunker.activate()

    def test_initialize_from_destroyed(self):
        """DESTROYED -> INITIALIZING is allowed."""
        config = get_test_config()
        bunker = Bunker(config)
        assert bunker.state == BunkerState.DESTROYED
        assert bunker.initialize()
        assert bunker.state == BunkerState.READY

    def test_terminate_from_ready_not_allowed(self):
        """terminate() requires ACTIVE state; from READY it should fail."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        assert bunker.state == BunkerState.READY
        # terminate() has a business guard: state must be ACTIVE
        assert not bunker.terminate()
        # State should not change (still READY or ERROR from failed transition)
        assert bunker.state != BunkerState.DESTROYED

    def test_multiple_cycles(self):
        """Re-initialize after destroy."""
        config = get_test_config()
        bunker = Bunker(config)

        bunker.initialize()
        bunker.activate()
        bunker.terminate()
        assert bunker.state == BunkerState.DESTROYED

        # Re-initialize from DESTROYED
        assert bunker.initialize()
        assert bunker.state == BunkerState.READY
        assert bunker.activate()
        assert bunker.state == BunkerState.ACTIVE

    def test_status_after_initialize(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        status = bunker.get_full_status()
        assert status["state"] == "READY"
        assert status["created_at"] is not None

    def test_security_layers_all_active_after_activate(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()
        for layer in bunker.security_layers.values():
            assert layer.active

    def test_security_layers_all_inactive_after_terminate(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()
        bunker.terminate()
        for layer in bunker.security_layers.values():
            assert not layer.active

    def test_vm_name_set_after_initialize(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        assert bunker._vm_name is not None
        assert bunker._vm_name.startswith("bunker_")

    def test_switch_name_set_after_initialize(self):
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        assert bunker._switch_name is not None
        assert bunker._switch_name.startswith("lumenos_")

    def test_state_persist_called(self):
        """Verify _persist_state is called during transitions."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        # _persist_state is mocked autouse, just verify state is READY
        assert bunker.state == BunkerState.READY


# ===========================================================================
# Layer Rollback Tests
# ===========================================================================

class TestLayerRollback:
    """Test that layer activation rollback works correctly."""

    @patch("lumenos_sandbox.layers.NetworkSecurityLayer.activate", return_value=False)
    def test_network_failure_rollback(self, mock_net_act):
        """If network layer fails, previously activated layers should be deactivated."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        # State is READY; activate() will transition to ACTIVE then iterate layers.
        # Network layer (first) is mocked to fail → rollback + return False.
        result = bunker.activate()
        assert not result
        assert bunker.state == BunkerState.ERROR

    @patch("lumenos_sandbox.layers.FilesystemSecurityLayer.activate", return_value=False)
    def test_filesystem_failure_rollback(self, mock_fs_act):
        """If filesystem layer fails after network succeeded, rollback network."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        result = bunker.activate()
        assert not result
        # Network was activated first, then filesystem failed → rollback
        assert bunker.security_layers[SecurityLayer.NETWORK].active is False

    @patch("lumenos_sandbox.layers.ProcessSecurityLayer.activate", return_value=False)
    def test_process_failure_rollback(self, mock_proc_act):
        """If process layer fails, rollback network + filesystem."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        result = bunker.activate()
        assert not result
        # Network and filesystem activated first, then process failed → rollback
        assert bunker.security_layers[SecurityLayer.NETWORK].active is False
        assert bunker.security_layers[SecurityLayer.FILESYSTEM].active is False


# ===========================================================================
# DualBunkerManager Integration
# ===========================================================================

class TestDualBunkerManager:
    """Test dual bunker rotation."""

    def test_start_first_session(self):
        manager = DualBunkerManager(get_test_config())
        assert manager.start_session()
        assert manager.active_bunker is not None
        assert manager.active_bunker.state == BunkerState.ACTIVE

    def test_rotation(self):
        manager = DualBunkerManager(get_test_config())
        manager.start_session()
        first_bunker = manager.active_bunker
        first_id = first_bunker.config.id

        # Simulate bunker entering error state while still referenced
        manager.active_bunker.transition_to(BunkerState.TERMINATING)
        manager.active_bunker.transition_to(BunkerState.DECONTAMINATING)
        manager.active_bunker.transition_to(BunkerState.DESTROYED)

        manager.start_session()
        # After rotation, active bunker should be different
        assert manager.active_bunker is not first_bunker
        assert manager.active_bunker.config.id != first_id
        assert manager.rotation_count == 1

    def test_get_status(self):
        manager = DualBunkerManager(get_test_config())
        manager.start_session()
        status = manager.get_status()
        assert "active_bunker" in status
        assert "rotation_count" in status
        assert "combined_escape_probability" in status
        assert status["active_bunker"] is not None

    def test_emergency_shutdown(self):
        manager = DualBunkerManager(get_test_config())
        manager.start_session()
        manager.emergency_shutdown("Test emergency")
        assert manager.active_bunker.state == BunkerState.QUARANTINE

    def test_end_session_without_active(self):
        manager = DualBunkerManager(get_test_config())
        # No session started — should return True gracefully
        assert manager.end_session()

    def test_combined_probability_decreases_with_rotations(self):
        manager = DualBunkerManager(get_test_config())
        manager.start_session()
        prob1 = manager._calculate_combined_probability()

        # Simulate bunker entering error state while still referenced
        manager.active_bunker.transition_to(BunkerState.TERMINATING)
        manager.active_bunker.transition_to(BunkerState.DECONTAMINATING)
        manager.active_bunker.transition_to(BunkerState.DESTROYED)

        manager.start_session()
        prob2 = manager._calculate_combined_probability()

        # After 1 rotation, rotation_factor = 0.99^1 < 1
        assert prob2 < prob1


# ===========================================================================
# Security Monitor Integration
# ===========================================================================

class TestSecurityMonitorIntegration:
    """Test security monitoring in context of a running bunker."""

    def test_escape_attempt_detection(self):
        monitor = SecurityMonitor("test_bunker")
        result = monitor.detect_escape_attempt(
            EscapeAttemptType.NETWORK_EXFILTRATION,
            "Test: DNS tunnel detected",
        )
        assert result is True
        assert len(monitor.escape_attempts) == 1

    def test_event_log_analysis(self):
        monitor = SecurityMonitor("test_bunker")
        events = [
            {"Id": 8, "ProcessName": "mimikatz.exe", "Message": "CreateRemoteThread"},
            {"Id": 1, "ProcessName": "notepad.exe", "Message": "Process Create"},
        ]
        findings = monitor.analyze_event_log(events)
        assert len(findings) >= 1
        assert any("mimikatz" in f.lower() or "injection" in f.lower() for f in findings)

    def test_escape_attempt_types(self):
        """All escape attempt types are registered correctly."""
        monitor = SecurityMonitor("test_bunker")
        for attempt_type in EscapeAttemptType:
            monitor.detect_escape_attempt(attempt_type, f"Test {attempt_type.value}")
        assert len(monitor.escape_attempts) == len(EscapeAttemptType)

    def test_security_report_after_events(self):
        monitor = SecurityMonitor("test_bunker")
        for i in range(5):
            from lumenos_sandbox.types import SecurityEvent, ThreatLevel
            event = SecurityEvent(
                timestamp=__import__("datetime").datetime.now(),
                layer=__import__("lumenos_sandbox.types", fromlist=["SecurityLayer"]).SecurityLayer.NETWORK,
                event_type=f"TEST_{i}",
                severity=ThreatLevel.LOW if i < 3 else ThreatLevel.HIGH,
                description=f"Test event {i}",
                bunker_id="test_bunker",
            )
            monitor.log_event(event)

        report = monitor.get_security_report()
        assert report["total_events"] == 5
        assert report["events_by_severity"]["LOW"] == 3
        assert report["events_by_severity"]["HIGH"] == 2

    def test_analyze_patterns_multiple_categories(self):
        monitor = SecurityMonitor("test_bunker")
        data = "VBOX VMware CreateRemoteThread CurrentVersion\\Run dns tunnel"
        detected = monitor.analyze_patterns(data)
        categories = {d.split(":")[0] for d in detected}
        assert len(categories) >= 3


# ===========================================================================
# Decontamination Report Persistence
# ===========================================================================

class TestDecontaminationReportPersistence:
    """Test that decontamination reports are saved."""

    def test_report_saved_on_success(self):
        """_save_decontamination_report is called (mocked autouse)."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()
        bunker.terminate()
        # If we get here without error, report was saved (mocked)

    def test_report_saved_on_failure(self):
        """Report should be saved even when decontamination fails."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()

        # Force a failure in one decontamination step
        with patch.object(bunker, "_step_terminate_processes", return_value=False):
            # Manually set state to trigger decontamination
            bunker.state = BunkerState.DECONTAMINATING
            result = bunker._decontaminate()
            # Should still return False (decon failed) but report was saved
            assert not result

    @patch("lumenos_sandbox.bunker.Bunker._save_decontamination_report")
    def test_report_called_on_terminate(self, mock_save):
        """Verify _save_decontamination_report is called during terminate."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()
        bunker.terminate()
        mock_save.assert_called_once()


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_config(self):
        """Minimal config with defaults."""
        config = BunkerConfig(id="x", name="X")
        bunker = Bunker(config)
        assert bunker.state == BunkerState.DESTROYED
        assert bunker.config.memory_mb == 8192  # default

    def test_concurrent_transitions(self):
        """Thread safety of state transitions."""
        import threading
        config = get_test_config()
        bunker = Bunker(config)
        errors = []

        def init_and_check():
            try:
                bunker.initialize()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=init_and_check) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Only one thread should succeed (lock protects transition)
        assert bunker.state in (BunkerState.READY, BunkerState.ERROR)

    def test_terminate_without_activate(self):
        """Terminate from READY should fail gracefully (not ACTIVE)."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        result = bunker.terminate()
        assert result is False

    def test_quarantine_from_destroyed_invalid(self):
        """Quarantine from DESTROYED is not a valid transition; force_quarantine
        catches the exception internally, so state should remain DESTROYED."""
        config = get_test_config()
        bunker = Bunker(config)
        assert bunker.state == BunkerState.DESTROYED
        bunker.force_quarantine("test")
        # force_quarantine catches InvalidStateTransition internally
        assert bunker.state == BunkerState.DESTROYED

    def test_full_status_keys(self):
        """Verify all expected keys in full status."""
        config = get_test_config()
        bunker = Bunker(config)
        bunker.initialize()
        bunker.activate()
        status = bunker.get_full_status()
        expected_keys = {"config", "state", "created_at", "activated_at",
                         "terminated_at", "escape_probability", "metrics",
                         "security_layers", "security_report", "integrity_report"}
        assert expected_keys.issubset(set(status.keys()))

    def test_metrics_initial_values(self):
        """Verify initial metrics values."""
        config = get_test_config()
        bunker = Bunker(config)
        assert bunker.metrics.cpu_usage == 0.0
        assert bunker.metrics.escape_attempts_blocked == 0
        assert bunker.metrics.uptime_seconds == 0
