import os, sys
from unittest.mock import patch, MagicMock
from lumenos_sandbox.platform import is_windows, is_linux, has_kvm, has_libvirt, detect_hypervisor, HypervisorType

def test_is_windows_true(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert is_windows() is True
    assert is_linux() is False

def test_is_linux_true(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert is_linux() is True
    assert is_windows() is False

def test_detect_env_override():
    with patch.dict(os.environ, {"LUMENOS_HYPERVISOR":"mock"}):
        assert detect_hypervisor() == HypervisorType.MOCK
    with patch.dict(os.environ, {"LUMENOS_HYPERVISOR":"kvm"}):
        assert detect_hypervisor() == HypervisorType.KVM
    with patch.dict(os.environ, {"LUMENOS_HYPERVISOR":"hyperv"}):
        assert detect_hypervisor() == HypervisorType.HYPERV

def test_detect_kvm():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("LUMENOS_HYPERVISOR", None)
        with patch("lumenos_sandbox.platform.has_kvm", return_value=True):
            with patch("lumenos_sandbox.platform.has_libvirt", return_value=True):
                with patch("lumenos_sandbox.platform.has_qemu", return_value=True):
                    with patch.object(sys, "platform", "linux"):
                        assert detect_hypervisor() == HypervisorType.KVM

def test_detect_kvm_degrades_to_mock_without_toolchain():
    # /dev/kvm alone is not enough — virsh + qemu-img must also be present.
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("LUMENOS_HYPERVISOR", None)
        with patch("lumenos_sandbox.platform.has_kvm", return_value=True):
            with patch("lumenos_sandbox.platform.has_libvirt", return_value=False):
                with patch("lumenos_sandbox.platform.has_qemu", return_value=False):
                    with patch.object(sys, "platform", "linux"):
                        assert detect_hypervisor() == HypervisorType.MOCK
