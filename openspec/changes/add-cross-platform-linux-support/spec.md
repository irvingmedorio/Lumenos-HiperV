# Spec: add-cross-platform-linux-support

## 1. Overview
Extender LUMENOS Sandbox a Linux manteniendo paridad Windows. Se introduce `HypervisorBackend` polimórfico; el dominio (Bunker/layers/monitoring/decontamination) no conoce el hipervisor concreto.

## 2. Requirements

### 2.1 Hypervisor Abstraction
- **REQ-01** The system SHALL expose an abstract interface `HypervisorBackend` with the 22 methods currently in `hyperv_client.py` (check_available, get_vm_status/info, create/start/stop/remove_vm, create/restore_checkpoint, create_differencing_disk, delete_file, create/remove_internal_switch, verify_host_integrity, enable_guest_integration, execute_in_guest, configure_guest_firewall, test_guest_connectivity, get_guest_processes, kill_guest_process, check_guest_vbs_status, read_guest_event_log, check_guest_registry, install_sysmon_in_guest).
- **REQ-02** The system SHALL provide `HyperVBackend` that implements the interface via PowerShell (`pwsh`/`powershell -Command`) with identical semantics to `hyperv_client.py` current.
- **REQ-03** The system SHALL provide `KvmBackend` that implements the same interface via libvirt/QEMU (`virsh`, `qemu-img`, `qemu-guest-agent` or SSH fallback).
- **REQ-04** The system SHALL provide `MockBackend` that returns safe defaults (`False`/`None`/`[]`) and logs warnings, usable when no hypervisor is present.
- **REQ-05** `hypervisor.py` and `hyperv_client.py` SHALL remain as backward-compatible shims delegating to `get_backend()` so existing imports (`from lumenos_sandbox.hyperv_client import check_hyper_v_available`) MUST NOT break.

### 2.2 Platform Detection & Factory
- **REQ-06** The system SHALL provide `platform.py` with `is_windows()`, `is_linux()`, `has_kvm()`, `has_libvirt()`, `detect_hypervisor() -> HypervisorType`.
- **REQ-07** `get_backend()` SHALL select backend in priority: `LUMENOS_HYPERVISOR` env var (values: `hyperv|kvm|mock`) overrides; else `win32 + powershell` → HyperV; else `/dev/kvm` or `virsh` → KVM; else `qemu-system-*` → KVM (qemu fallback); else Mock.
- **REQ-08** Factory selection MUST be lazy and injectable (optional `backend` param in `Bunker`/`layers` for testing) to avoid global state coupling.

### 2.3 Secrets Cross-Platform
- **REQ-09** `SecretManager` SHALL delegate to a `SecretStore` abstraction; `WindowsStore` uses `keyring` Credential Manager; `LinuxStore` uses `keyring` SecretService when available, else file `~/.config/lumenos/secrets.fernet` with Fernet (0600).
- **REQ-10** Encryption helpers `encrypt`/`decrypt` SHALL remain Fernet-compatible; file fallback MUST use same key derivation as `state_encryption_key`.

### 2.4 Path & Config Portability
- **REQ-11** `BunkerConfig.sysmon_path` SHALL be `Path` (not `str`) with default `Path("C:/Tools/Sysmon64.exe")` on Windows and `Path("/opt/sysmon/sysmon")` on Linux via `resolve_sysmon_path(platform)` helper.
- **REQ-12** No module outside `hypervisor/` and `platform.py` SHALL contain `if sys.platform == "win32"` branches.

### 2.5 Scripts & Tooling
- **REQ-13** The system SHALL provide `scripts/check_env.sh` (bash) mirroring `check_env.ps1` (checks `/dev/kvm`, `virsh --version`, `qemu-img --version`, `free -h`, `lscpu`). `check_env.ps1` MUST remain unchanged.
- **REQ-14** The system SHALL provide `scripts/run_tests.sh` mirroring `run_tests.ps1`.
- **REQ-15** `pyproject.toml` SHALL add optional extra `linux = ["libvirt-python; sys_platform != 'win32'"]` without making it required.

## 3. Scenarios

### 3.1 Hypervisor Availability
- **Scenario 3.1.1 (Windows — Hyper-V present)**
  - Given host Windows with `Microsoft-Hyper-V-All: Enabled`
  - When `get_backend().check_available()` is called
  - Then it SHALL return `True` and `type(get_backend())` is `HyperVBackend`
- **Scenario 3.1.2 (Linux — KVM present)**
  - Given host Linux with `/dev/kvm` and `virsh` available
  - When `get_backend().check_available()` is called
  - Then it SHALL return `True` and backend is `KvmBackend`
- **Scenario 3.1.3 (Linux — no hypervisor)**
  - Given host Linux without `/dev/kvm` nor `virsh` nor `qemu`
  - When `get_backend()` is called
  - Then it SHALL return `MockBackend` and `check_available()` is `False` with actionable warning
- **Scenario 3.1.4 (Env override)**
  - Given `LUMENOS_HYPERVISOR=mock`
  - When `get_backend()` is called on Windows with Hyper-V
  - Then it SHALL return `MockBackend` regardless of host

### 3.2 VM Lifecycle
- **Scenario 3.2.1 (Create VM — Windows)**
  - Given `HyperVBackend`
  - When `create_vm("bunker_test", 4096, 2)` is called
  - Then it SHALL execute `New-VM -Name 'bunker_test' -Generation 2 ...` and return `True` on success
- **Scenario 3.2.2 (Create VM — Linux)**
  - Given `KvmBackend` with libvirt
  - When `create_vm("bunker_test", 4096, 2)` is called
  - Then it SHALL create `qemu-img create` + `virsh define` with `<memory>4194304</memory>` and return `True`
- **Scenario 3.2.3 (Differencing disk)**
  - Given `KvmBackend`
  - When `create_differencing_disk("base.qcow2", "diff.qcow2")` is called
  - Then it SHALL run `qemu-img create -f qcow2 -b base.qcow2 diff.qcow2`
- **Scenario 3.2.4 (Internal switch)**
  - Given `KvmBackend`
  - When `create_internal_switch("lumenos_test_switch")` is called
  - Then it SHALL run `virsh net-define` with `<network><name>lumenos_test_switch</name><bridge name='virbr-lumenos'/>` isolated (no `<forward>`) 

### 3.3 Guest Interaction
- **Scenario 3.3.1 (Execute in guest — KVM with agent)**
  - Given `KvmBackend` and `qemu-guest-agent` running in guest
  - When `execute_in_guest("vm1", "user", "pass", "whoami")` is called
  - Then it SHALL use `virsh qemu-agent-command -- guest-exec`
- **Scenario 3.3.2 (Execute in guest — fallback SSH)**
  - Given `KvmBackend` without qemu-guest-agent
  - When `execute_in_guest` is called
  - Then it MAY fallback to `ssh` via isolated network or return `PSResult(False, "", "guest agent unavailable")` without crashing

### 3.4 Secrets
- **Scenario 3.4.1 (Store secret — Linux with keyring)**
  - Given Linux with `keyring` + SecretService
  - When `SecretManager().store_secret("guest_password", "s3cr3t")` is called
  - Then it SHALL store via `keyring.set_password` and retrieve identically
- **Scenario 3.4.2 (Store secret — Linux without keyring)**
  - Given Linux without keyring backend
  - When `store_secret` is called
  - Then it SHALL write to `~/.config/lumenos/secrets.fernet` with Fernet and mode 0600

### 3.5 Security / Escape Resistance
- **Scenario 3.5.1 (Network isolation verify — Linux)**
  - Given `KvmBackend` with isolated network
  - When `test_guest_connectivity` returns `True` (blocked)
  - Then `NetworkSecurityLayer.verify()` SHALL return `True` (identical to Hyper-V)
- **Scenario 3.5.2 (Registry persistence — Linux)**
  - Given `KvmBackend` where `check_guest_registry` returns `[]` (no Windows registry)
  - When `FilesystemSecurityLayer.verify()` checks persistence keys
  - Then it SHALL return `True` (no persistence) without error
- **Scenario 3.5.3 (Decontamination)**
  - Given `DecontaminationRunner` with `KvmBackend`
  - When `run()` executes 7 steps
  - Then steps `destroy_differential_disk` (`qemu-img` delete), `clean_network_config` (`virsh net-destroy`), `remove_snapshots` (`virsh undefine`) SHALL succeed and report `success=True` when all steps pass

### 3.6 Backward Compatibility
- **Scenario 3.6.1 (Shim imports)**
  - Given existing code `from lumenos_sandbox.hyperv_client import create_vm`
  - When `create_vm` is called on Windows
  - Then it SHALL delegate to `HyperVBackend.create_vm` with identical signature and return value
- **Scenario 3.6.2 (CLI status)**
  - Given `lumenos status` on Windows vs Linux
  - When executed
  - Then Windows prints `"Hyper-V: [OK] Available"` and Linux prints `"KVM: [OK] Available (virsh ...)"` with exit code 0 when backend available

## 4. Non-Functional
- No new runtime dependency on Windows; `libvirt-python` is optional on Linux.
- Factory detection MUST complete in <500ms (subprocess timeouts bounded).
- No `if platform` outside `hypervisor/` + `platform.py` (enforced via grep in verify).
