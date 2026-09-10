from lumenos_sandbox.hypervisor.mock_backend import MockBackend
from lumenos_sandbox.hypervisor.base import BackendResult
from lumenos_sandbox.hypervisor import get_backend, set_backend, reset_backend
import os

def test_mock_backend_defaults():
    m=MockBackend()
    assert m.check_available() is False
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
