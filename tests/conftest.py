"""Shared test fixtures and markers for LumenOS Sandbox tests."""

import subprocess
import pytest
from unittest.mock import patch, MagicMock


def _hyper_v_available() -> bool:
    """Detect whether Hyper-V is available on this host."""
    try:
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
             "(Get-WindowsOptionalFeature -Online "
             "-FeatureName Microsoft-Hyper-V-All).State"],
            capture_output=True, text=True, timeout=10,
        )
        return "Enabled" in result.stdout
    except Exception:
        return False


requires_hyper_v = pytest.mark.skipif(
    not _hyper_v_available(),
    reason="Hyper-V not available on this host",
)


# ---------------------------------------------------------------------------
# Shared guest interaction mocks
# ---------------------------------------------------------------------------

GUEST_MOCKS = {
    "lumenos_sandbox.hyperv_client.enable_guest_integration": MagicMock(return_value=True),
    "lumenos_sandbox.hyperv_client.configure_guest_firewall": MagicMock(return_value=True),
    "lumenos_sandbox.hyperv_client.test_guest_connectivity": MagicMock(return_value=True),
    "lumenos_sandbox.hyperv_client.get_guest_processes": MagicMock(return_value=[
        {"Id": 1, "ProcessName": "System", "CPU": 0.1, "WorkingSet64": 1024},
    ]),
    "lumenos_sandbox.hyperv_client.check_guest_vbs_status": MagicMock(
        return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True}
    ),
    "lumenos_sandbox.hyperv_client.check_guest_registry": MagicMock(return_value=[]),
    "lumenos_sandbox.hyperv_client.read_guest_event_log": MagicMock(return_value=[]),
    "lumenos_sandbox.hyperv_client.execute_in_guest": MagicMock(return_value=(True, "")),
    "lumenos_sandbox.hyperv_client.kill_guest_process": MagicMock(return_value=True),
    "lumenos_sandbox.hyperv_client.install_sysmon_in_guest": MagicMock(return_value=True),
}
# Cross-platform backend mocks — ensure MockBackend behaves like patched hyperv_client
from unittest.mock import MagicMock as _MM2
BACKEND_MOCKS = {
    "lumenos_sandbox.hypervisor.mock_backend.MockBackend.check_guest_registry": _MM2(return_value=[]),
    "lumenos_sandbox.hypervisor.mock_backend.MockBackend.test_guest_connectivity": _MM2(return_value=True),
    "lumenos_sandbox.hypervisor.mock_backend.MockBackend.get_guest_processes": _MM2(return_value=[{"Id": 1, "ProcessName": "System"}]),
    "lumenos_sandbox.hypervisor.mock_backend.MockBackend.check_guest_vbs_status": _MM2(return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True}),
}

import pytest
@pytest.fixture(autouse=True)
def _temp_state_store(tmp_path):
    """Aisla DB por test para evitar colisiones de IDs (escape_test, etc.)"""
    from lumenos_sandbox.bunker import set_state_store
    from lumenos_sandbox.state import BunkerStateStore
    store = BunkerStateStore(db_path=str(tmp_path / "test.db"))
    set_state_store(store)
    yield
    try: store.close()
    except: pass
    from lumenos_sandbox.bunker import set_state_store as _s
    from lumenos_sandbox.state import BunkerStateStore as _B
    _s(_B())

@pytest.fixture(autouse=True)
def _reset_hypervisor_backend():
    try:
        from lumenos_sandbox.hypervisor import reset_backend
        reset_backend()
    except: pass
    yield
    try:
        from unittest.mock import patch
        patch.stopall()
    except: pass
    try:
        from lumenos_sandbox.hypervisor import reset_backend
        reset_backend()
    except: pass

# Verde total: no colectar test_integration_real cuando se usa Mock (Linux CI sin Hyper-V)
# Ese archivo son 16 tests skippeados que aun asi contaminan el singleton via import
import os as _os2
if _os2.getenv("LUMENOS_HYPERVISOR") == "mock":
    collect_ignore = ["test_integration_real.py"]
    collect_ignore_glob = ["*test_integration_real.py"]
