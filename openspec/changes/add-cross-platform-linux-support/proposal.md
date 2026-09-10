# Proposal: add-cross-platform-linux-support

## Summary
Habilitar soporte Linux (KVM/QEMU/libvirt) en LUMENOS Sandbox sin quitar ni degradar funcionalidad Windows (Hyper-V). Introduce una capa de abstracción `HypervisorBackend` (Strategy + Factory) que desacopla el dominio (Bunker, layers, monitoring) del detalle (Hyper-V vs KVM), preservando 100% del comportamiento actual en Windows y habilitando ejecución nativa en Linux.

## Motivation
Hoy LUMENOS es Windows-locked por arquitectura, no por un detalle:
- `hypervisor.py` + `hyperv_client.py` (~600 líneas) invocan `pwsh/powershell -Command Get-VM/New-VM/Invoke-Command -VMName` (PowerShell Direct/VMBus) — falla en Linux.
- `bunker.py` verifica `Get-WindowsOptionalFeature Microsoft-Hyper-V-All`, capas verifican registro `HKLM:\`, VBS, Sysmon en `C:\Tools\`.
- `secrets.py` depende de Windows Credential Manager; `gpu.py`/`resource_manager.py`/`multi_host.py`/`image_builder.py` usan `Get-CimInstance Win32_*`; scripts solo `.ps1`.
- `phone_support.py` ya contiene embriones KVM/QEMU no integrados.

El usuario exige Linux sin regresión Windows. Un `if platform == "linux"` disperso viola Dependency Inversion y eleva riesgo de regresión. Se requiere inversión de dependencia.

## Goals
- G1: LUMENOS corre en Linux (Ubuntu 22.04+/Debian 12+) con KVM/QEMU/libvirt sin modificar código Windows existente.
- G2: En Windows, comportamiento idéntico (mismos PowerShell cmdlets, mismas capas, mismos tests).
- G3: Detección automática de backend + override explícito (`LUMENOS_HYPERVISOR`, config).
- G4: Secrets cross-platform (keyring SecretService en Linux, fallback Fernet).
- G5: Scripts duales y docs actualizadas; CI matriz Windows+Linux.

## Non-Goals
- No se reescribe `layers.py`/`monitoring.py` lógica de negocio — solo se inyecta backend.
- No se soporta macOS en esta entrega (puede añadirse como tercer backend luego).
- No se reemplaza Hyper-V en Windows (Hyper-V sigue siendo default en `win32`).
- No se cambia formato de `lumenos_state.db` ni chain forense.

## Proposed Solution
### Arquitectura: Strategy + Factory + Adapter
```
lumenos_sandbox/
├── hypervisor/
│   ├── __init__.py        # factory get_backend() + detección
│   ├── base.py            # HypervisorBackend ABC (15 métodos)
│   ├── hyperv_backend.py  # HyperVBackend (mueve hyperv_client.py actual)
│   ├── kvm_backend.py     # KvmBackend (virsh/qemu-img/qemu-guest-agent/SSH)
│   └── mock_backend.py    # MockBackend para CI/tests sin hypervisor
├── platform.py            # is_windows(), is_linux(), has_kvm(), has_libvirt()
└── secrets/
    ├── __init__.py
    └── store.py           # SecretStore ABC + WindowsStore + LinuxStore
```

**HypervisorBackend ABC** expone el mismo contrato que `hyperv_client.py` hoy:
`check_available`, `create_vm`, `start_vm`, `stop_vm`, `remove_vm`, `create_checkpoint`, `restore_checkpoint`, `create_differencing_disk`, `delete_file`, `create_internal_switch`, `remove_switch`, `verify_host_integrity`, `enable_guest_integration`, `execute_in_guest`, `configure_guest_firewall`, `test_guest_connectivity`, `get_guest_processes`, `check_guest_vbs_status`, `read_guest_event_log`, `check_guest_registry`, `install_sysmon_in_guest`.

**Factory:**
```python
def get_backend() -> HypervisorBackend:
    if os.getenv("LUMENOS_HYPERVISOR") == "mock": return MockBackend()
    if sys.platform == "win32" and shutil.which("powershell"): return HyperVBackend()
    if Path("/dev/kvm").exists() or shutil.which("virsh"): return KvmBackend()
    if shutil.which("qemu-system-x86_64"): return KvmBackend(qemu_fallback=True)
    return MockBackend()
```

**KvmBackend mapping:**
| Hyper-V | KVM/Linux |
|---------|-----------|
| `New-VM` | `virt-install --import` / `virsh define` (XML template) |
| `Invoke-Command -VMName` | `virsh qemu-agent-command` (qemu-guest-agent) fallback SSH |
| `New-VHD -Differencing` | `qemu-img create -f qcow2 -b base.qcow2 diff.qcow2` |
| `New-VMSwitch Internal` | `virsh net-define` (isolated network, no forward) |
| `Test-NetConnection` | `virsh domifaddr` + `ping` guest-side |
| `Get-CimInstance Win32_*` | `/proc/meminfo`, `lscpu`, `lspci`, `virsh nodedev-list` |

**Compatibilidad:** `hypervisor.py` y `hyperv_client.py` quedan como shims que delegan a `get_backend()` para no romper imports existentes (`from lumenos_sandbox.hyperv_client import check_hyper_v_available` sigue funcionando).

**Secrets:** `SecretManager` delega a `SecretStore` según plataforma; Linux usa `keyring` SecretService si disponible, sino `~/.config/lumenos/secrets.fernet` cifrado Fernet (misma clave que `state_encryption_key`).

**Otros toques:** `types.py` `sysmon_path` pasa a `Path` + `resolve_sysmon(platform)`, `scripts/check_env.sh` + `run_tests.sh` espejos bash, `pyproject.toml` extra `linux = ["libvirt-python; sys_platform != 'win32'"]`.

## Alternatives Considered
1. **`if sys.platform` disperso** — Descartado: duplica lógica, viola OCP, alto riesgo regresión, `grep -r` demuestra 23 sitios PowerShell.
2. **Mantener solo Hyper-V + WSL2** — Descartado: WSL2 no expone Hyper-V host, no resuelve KVM nativo, bloquea servidores Linux bare-metal.
3. **Reescribir a Docker/containers** — Descartado: cambia modelo de aislamiento (no es VM escape testing), fuera de alcance.

## Risks & Mitigations
| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| Regresión Windows | Alto | Shim preserva imports; tests mocked apuntan a backend; CI Windows obligatorio |
| qemu-guest-agent no instalado en guest | Medio | Fallback SSH + documentación; `verify_host_integrity` degrada graceful |
| libvirt no disponible en host Linux | Medio | Factory retorna MockBackend; mensaje accionable `apt install qemu-kvm libvirt-daemon` |
| Secrets en Linux sin keyring | Medio | Fallback Fernet file con permisos 0600 + warning |
| Divergencia VBS/SecureBoot en KVM | Bajo | `check_guest_vbs_status` retorna `{"vbs_enabled": False, "kvm": True}` mapeado en `layers.py` |

## Hyper-V Lifecycle Implications
- VM lifecycle (create→start→checkpoint→stop→remove) permanece idéntico; KvmBackend replica semántica (virsh define/start/snapshot-create/shutdown/undefine).
- `DecontaminationRunner` (7 pasos) no cambia — solo backend cambia `remove_vm`/`delete_file`/`remove_switch`/`verify_host_integrity`.
- `Bunker` state machine (INITIALIZING→READY→ACTIVE→TERMINATING→DECONTAMINATING→DESTROYED) intacta; `_verify_system_requirements` ahora llama `backend.check_available()` polimórfico.

## Rollback Plan
- Revertir `lumenos_sandbox/hypervisor/` y restaurar `hyperv_client.py` original (shim revierte a import directo).
- `git revert` de los 2 commits planificados (1: abstracción, 2: KVM backend) — cada uno atomizado.
- Feature flag `LUMENOS_HYPERVISOR=hyperv` fuerza HyperVBackend incluso en Linux para debug.
- Estado SQLite no migra — rollback es solo código.

## Success Criteria
- `lumenos status` retorna OK en Windows (Hyper-V) y en Linux (KVM) con mensajes diferenciados.
- `pytest tests/ -v` 174 passed en ambos OS (16 skipped si hypervisor real ausente); MockBackend en CI sin KVM.
- `bunker.initialize()→activate()→terminate()` completa en Linux con qcow2 + isolated network sin tocar registro Windows.
- No se introduce `if win32` fuera de `hypervisor/` y `platform.py`.

## Estimated Scope
- Archivos nuevos: 6 (`hypervisor/*`, `platform.py`, `secrets/store.py`, scripts `.sh`)
- Archivos modificados: 5 (`hypervisor.py`, `hyperv_client.py` shim, `bunker.py`, `types.py`, `pyproject.toml`)
- Tests modificados: `conftest.py` target backend
- Riesgo revisión: ~350 líneas nuevas, debajo de 400 budget — single PR con `ask-on-risk`.
