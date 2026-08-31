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
    "lumenos_sandbox.hypervisor.enable_guest_integration": MagicMock(return_value=True),
    "lumenos_sandbox.hypervisor.configure_guest_firewall": MagicMock(return_value=True),
    "lumenos_sandbox.hypervisor.test_guest_connectivity": MagicMock(return_value=True),
    "lumenos_sandbox.hypervisor.get_guest_processes": MagicMock(return_value=[
        {"Id": 1, "ProcessName": "System", "CPU": 0.1, "WorkingSet64": 1024},
    ]),
    "lumenos_sandbox.hypervisor.check_guest_vbs_status": MagicMock(
        return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True}
    ),
    "lumenos_sandbox.hypervisor.check_guest_registry": MagicMock(return_value=[]),
    "lumenos_sandbox.hypervisor.read_guest_event_log": MagicMock(return_value=[]),
    "lumenos_sandbox.hypervisor.execute_in_guest": MagicMock(return_value=(True, "")),
    "lumenos_sandbox.hypervisor.kill_guest_process": MagicMock(return_value=True),
    "lumenos_sandbox.hypervisor.install_sysmon_in_guest": MagicMock(return_value=True),
}
