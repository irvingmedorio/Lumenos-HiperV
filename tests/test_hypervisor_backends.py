import os
import re

import pytest

from lumenos_sandbox.hypervisor.mock_backend import MockBackend
from lumenos_sandbox.hypervisor.base import BackendResult
from lumenos_sandbox.hypervisor import get_backend, set_backend, reset_backend
from lumenos_sandbox.hypervisor.kvm_backend import _isolated_network_xml
from lumenos_sandbox.hypervisor.hyperv_backend import _private_switch_command

def test_mock_backend_defaults():
    m=MockBackend()
    assert m.check_available() is True  # mock now returns True for lifecycle
    assert m.get_vm_status("x") is None
    assert m.create_vm("vm",1024,1) is True
    assert m.delete_file("/tmp/x") is True
    r=m.verify_host_integrity()
    assert isinstance(r, BackendResult)
    assert m.execute_in_guest("vm","u","p","cmd").success is False

def test_factory_mock_env():
    reset_backend()
    os.environ["LUMENOS_HYPERVISOR"]="mock"
    b=get_backend()
    assert isinstance(b, MockBackend)
    reset_backend()
    os.environ.pop("LUMENOS_HYPERVISOR",None)

def test_set_backend_injection():
    m=MockBackend()
    set_backend(m)
    assert get_backend() is m
    reset_backend()

def test_kvm_check_available_no_kvm(monkeypatch):
    from lumenos_sandbox.hypervisor.kvm_backend import KvmBackend
    monkeypatch.setattr("pathlib.Path.exists", lambda self: False)
    monkeypatch.setattr("shutil.which", lambda x: None)
    k=KvmBackend()
    assert k.check_available() is False


# ---------------------------------------------------------------------------
# Network isolation — each bunker gets its own bridge and its own subnet
# ---------------------------------------------------------------------------

def _attr(xml: str, name: str) -> str:
    """One XML attribute value, e.g. the generated bridge name or address."""
    return re.search(rf"{name}='([^']+)'", xml).group(1)


class TestIsolatedNetworkXml:
    """The generated XML is the observable artifact of the KVM switch.

    The switch itself is built by ``virsh`` outside this suite, so these tests
    pin the artifact. The defect they prevent: the bridge was derived from a
    fixed prefix (``switch_name[:8]``), and every switch is named
    ``lumenos_{id}_switch``, so that prefix was always the same literal and
    concurrent bunkers shared one L2 segment.
    """

    def test_forwarding_is_explicitly_disabled(self):
        xml = _isolated_network_xml("lumenos_abc_switch")
        assert "<forward mode='none'/>" in xml
        assert "mode='nat'" not in xml
        assert "mode='route'" not in xml

    def test_bridge_name_is_unique_per_switch(self):
        a = _isolated_network_xml("lumenos_abc_switch")
        b = _isolated_network_xml("lumenos_def_switch")
        assert _attr(a, "name") != _attr(b, "name")

    @pytest.mark.parametrize(
        "switch", ["lumenos_a_switch", "lumenos_" + "x" * 60 + "_switch"]
    )
    def test_bridge_name_fits_the_linux_interface_limit(self, switch):
        # IFNAMSIZ is 16, so a usable interface name is at most 15 characters.
        assert len(_attr(_isolated_network_xml(switch), "name")) <= 15

    def test_subnet_is_unique_per_switch_and_private(self):
        a = _isolated_network_xml("lumenos_abc_switch")
        b = _isolated_network_xml("lumenos_def_switch")
        assert _attr(a, "address") != _attr(b, "address")
        assert _attr(a, "address").startswith("10.")

    def test_the_same_switch_name_is_idempotent(self):
        """Re-defining one bunker's network must produce identical XML, so a
        retry cannot drift onto a different bridge or subnet."""
        assert _isolated_network_xml("lumenos_abc_switch") == _isolated_network_xml(
            "lumenos_abc_switch"
        )


def test_hyperv_switch_command_is_private_not_internal():
    """``Internal`` puts a host vEthernet adapter on the sample's wire; the
    switch must be Private so the guest cannot reach host services.

    The command is asserted directly rather than through an instance: the
    concrete Hyper-V class cannot be instantiated today because it does not
    implement the ABC's ``check_available`` (a separate, pre-existing defect).
    """
    cmd = _private_switch_command("lumenos_abc_switch")
    assert "New-VMSwitch" in cmd
    assert "-SwitchType Private" in cmd
    assert "-SwitchType Internal" not in cmd
