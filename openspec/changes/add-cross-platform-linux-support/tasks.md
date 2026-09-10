# Tasks: add-cross-platform-linux-support

## 1. Foundation — Hypervisor Abstraction [hypervisor, platform]
- [x] 1.1 Create `lumenos_sandbox/platform.py` with `is_windows`, `is_linux`, `has_kvm`, `has_libvirt`, `HypervisorType`, `detect_hypervisor()` + unit tests `tests/test_platform.py` (RED→GREEN)
- [x] 1.2 Create `lumenos_sandbox/hypervisor/base.py` — `BackendResult` + `HypervisorBackend` ABC with 22 abstract methods (REQ-01) + docstrings
- [x] 1.3 Create `lumenos_sandbox/hypervisor/hyperv_backend.py` — move `hyperv_client.HyperVClient` verbatim to `HyperVBackend(HypervisorBackend)` (REQ-02), keep `_run_ps`, `PSResult` compat alias
- [x] 1.4 Create `lumenos_sandbox/hypervisor/mock_backend.py` — `MockBackend` safe defaults + `tests/test_hypervisor_backends.py::test_mock` (RED→GREEN)
- [x] 1.5 Create `lumenos_sandbox/hypervisor/kvm_backend.py` — `KvmBackend` stub with `check_available` + `create_vm` via `qemu-img`/`virsh` + `tests/test_hypervisor_backends.py::test_kvm` (RED→GREEN→TRIANGULATE)
- [x] 1.6 Create `lumenos_sandbox/hypervisor/__init__.py` — `get_backend()` factory with env override + lazy singleton + `set_backend()` for tests (REQ-07/08)
- [x] 1.7 Complete `KvmBackend` remaining methods: `get_vm_status/info`, `start/stop/remove_vm`, `checkpoint`, `differencing_disk`, `delete_file` (Path unlink), `create/remove_internal_switch` (virsh net-define isolated), `verify_host_integrity`, `enable_guest_integration`, `execute_in_guest` (qemu-agent→fallback), `configure_guest_firewall`, `test_guest_connectivity`, `get_guest_processes`, `check_guest_vbs_status`, `read_guest_event_log`, `check_guest_registry`, `install_sysmon_in_guest` (REQ-03)
- [x] 1.8 Convert `lumenos_sandbox/hypervisor.py` and `lumenos_sandbox/hyperv_client.py` to shims delegating to `get_backend()` — preserve all existing imports/signatures (REQ-05) + verify `grep -r "hyperv_client"` still works

## 2. Secrets & Config Portability [secrets, types]
- [x] 2.1 Create `lumenos_sandbox/secrets/store.py` — `SecretStore` ABC + `WindowsStore` (keyring) + `LinuxStore` (keyring SecretService fallback Fernet file `~/.config/lumenos/secrets.fernet` 0600) + `tests/test_secrets_store.py` (REQ-09/10)
- [x] 2.2 Refactor `lumenos_sandbox/secrets.py` `SecretManager` to delegate to `SecretStore` factory (no `import keyring` at top-level outside store)
- [x] 2.3 Update `lumenos_sandbox/types.py` — `BunkerConfig.sysmon_path: Path` + `resolve_sysmon_path(platform)` helper (`C:/Tools/Sysmon64.exe` win, `/opt/sysmon/sysmon` linux) (REQ-11)
- [x] 2.4 Verify no `if sys.platform` outside `hypervisor/` + `platform.py` (`grep -r "sys.platform" --include="*.py" lumenos_sandbox/ | grep -v hypervisor | grep -v platform` must be empty) (REQ-12)

## 3. Domain Integration — Bunker/Layers/Monitoring [bunker, layers, monitoring, decontamination]
- [x] 3.1 Update `lumenos_sandbox/bunker.py` — inject `backend` param in `__init__`, use `self.backend.check_available/create_vm/create_internal_switch/enable_guest_integration` (remove direct `from .hyperv_client import ...`) + `_verify_system_requirements` via backend
- [x] 3.2 Update `lumenos_sandbox/layers.py` — `SecurityLayerBase` accepts `backend`, `verify()` delegates to backend; `Network/Filesystem/Process/Memory/Hypervisor` layers no longer import `hyperv_client` inline
- [x] 3.3 Update `lumenos_sandbox/monitoring.py` — `SecurityMonitor` accepts `backend`, `_check_*` uses `self.backend.*` instead of `from .hyperv_client import ...`
- [x] 3.4 Update `lumenos_sandbox/decontamination.py` — `DecontaminationRunner` accepts `backend`, 7 steps use backend (`delete_file`, `remove_switch`, `remove_vm`, `verify_host_integrity`)
- [x] 3.5 Update `lumenos_sandbox/cli.py` — `cmd_status` prints `"Hyper-V:"` vs `"KVM:"` based on `detect_hypervisor()` + backend `check_available()` (REQ-3.6.2)
- [x] 3.6 Update `tests/conftest.py` — patch `lumenos_sandbox.hypervisor.get_backend` to `MockBackend` instead of patching `hyperv_client.*` directly; keep existing 174 tests green

## 4. Scripts & Packaging [scripts, config]
- [x] 4.1 Create `scripts/check_env.sh` — bash mirror of `check_env.ps1`: checks `/dev/kvm`, `virsh --version`, `qemu-img --version`, `free -h`, `lscpu`, `lsmod | grep kvm` + executable chmod +x
- [x] 4.2 Create `scripts/run_tests.sh` — bash mirror of `run_tests.ps1`: `python3 -m pytest tests/ -v` with `LUMENOS_HYPERVISOR=mock` default
- [x] 4.3 Update `pyproject.toml` — add `[project.optional-dependencies] linux = ["libvirt-python; sys_platform != 'win32'"]` (REQ-15)
- [x] 4.4 Update `README.md` — add Linux requirements (`apt install qemu-kvm libvirt-daemon-system virtinst`), `check_env.sh` usage, factory env var docs; keep Windows section intact

## 5. Verification & Hardening [verify, sentinel]
- [x] 5.1 Run `LUMENOS_HYPERVISOR=mock python -m pytest tests/ -v` — 174 passed, no regression (Strict TDD verify)
- [x] 5.2 Run `grep -r "platform"` + `grep -r "hyperv_client\|hypervisor"` to verify no stray Windows-only imports outside abstraction
- [x] 5.3 Manual smoke: `lumenos status` on Linux mock (should print `KVM: [WARN] Mock`) and `lumenos start --id smoke --name smoke` with MockBackend creates state in `lumenos_state.db`
- [x] 5.4 Security review (sentinel): isolated network has no `<forward>`, secrets file 0600, no `libvirtd` TCP exposure

---

## Review Workload Forecast
- Estimated changed lines: ~380 (6 new files ~250 lines + 5 modified ~130)
- Budget: 400 — **Single PR** with `ask-on-risk` (no chain needed unless tasks 1.7 expands)
- Decision needed before apply: No — single PR is within budget; `auto` execution proceeds
- Risks: Windows shim regression mitigated by conftest + `LUMENOS_HYPERVISOR=mock` in CI
