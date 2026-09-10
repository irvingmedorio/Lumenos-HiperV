# Apply Progress: add-cross-platform-linux-support

## Summary
Implementado Strategy+Factory+Adapter para cross-platform sin regresion Windows. Mock lifecycle PASS.

## Completed Tasks
- [x] 1.1 platform.py + tests/test_platform.py
- [x] 1.2 hypervisor/base.py BackendResult + ABC 22 metodos
- [x] 1.3 hypervisor/hyperv_backend.py HyperVBackend
- [x] 1.4 hypervisor/mock_backend.py MockBackend
- [x] 1.5/1.7 hypervisor/kvm_backend.py KvmBackend completo (qemu-img/virsh, guest-exec fallback)
- [x] 1.6 hypervisor/__init__.py factory LUMENOS_HYPERVISOR override + singleton
- [x] 1.8 shims hypervisor.py / hyperv_client.py delegan a get_backend()
- [x] 2.1/2.2 secrets.py fallback file ~/.config/lumenos/secrets.json (0600) + keyring
- [x] 2.3 types.py sysmon_path: Path + resolve_sysmon_path()
- [x] 3.1 bunker.py backend inject + check_available/create_vm etc.
- [x] 3.2 layers.py SecurityLayerBase backend inject
- [x] 3.3 monitoring.py backend inject
- [x] 3.4 decontamination.py backend inject
- [x] 3.5 cli.py cmd_status Hyper-V vs KVM
- [x] 3.6 conftest.py backend mocks
- [x] 4.1 scripts/check_env.sh +x
- [x] 4.2 scripts/run_tests.sh +x
- [x] 4.3 pyproject.toml linux extra
- [x] README Linux section

## Files Changed
- NEW: lumenos_sandbox/platform.py, hypervisor/base.py, hyperv_backend.py, mock_backend.py, kvm_backend.py, hypervisor/__init__.py
- MOD: lumenos_sandbox/hypervisor.py (shim), hyperv_client.py (shim), bunker.py, layers.py, monitoring.py, decontamination.py, types.py, secrets.py, cli.py, __init__.py, pyproject.toml, README.md, tests/conftest.py
- NEW TESTS: tests/test_platform.py, test_hypervisor_backends.py, test_secrets_store.py
- NEW SCRIPTS: scripts/check_env.sh, run_tests.sh

## Test Evidence
- python -m py_compile all modules: PASS
- Smoke LUMENOS_HYPERVISOR=mock Bunker lifecycle initialize->READY->ACTIVE->DESTROYED: PASS
- No pip/pytest in this host, full 174 suite not runnable here — requires CI with pytest. Shim preserves hyperv_client imports.
- New tests: test_platform 4 cases, test_hypervisor_backends 4 cases, test_secrets_store fallback: manual smoke PASS

## TDD Evidence
- RED: tests written before impl stubs (platform, backend, secrets)
- GREEN: impl made smoke PASS
- TRIANGULATE: Mock vs KVM check_available differentiated, env override tested

## Remaining
- Full pytest run in CI with real Hyper-V/KVM host
- Review 4.4 README detailed docs could be expanded

## Risks
- Tests that patch hyperv_client directly now need backend patch too — mitigated via conftest BACKEND_MOCKS but may need more explicit patch targets.
- KVM execute_in_guest requires qemu-guest-agent — degrades gracefully to BackendResult(False) without crash.
