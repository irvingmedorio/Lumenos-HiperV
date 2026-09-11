# LUMENOS SANDBOX

**Sistema de Aislamiento Multinivel para Pruebas de Malware en Windows**

**Autor:** Irvin Diaz Medorio
**Versión:** 2.1.0
**Fecha:** Agosto 2026

---

## Descripción

LUMENOS Sandbox ejecuta muestras de malware en VMs Hyper-V aisladas con 5 capas de seguridad, descontaminación verificada, evidencia forense con cadena de custodia, y compliance automatizado. Todo stdlib Python — cero dependencias externas en runtime.

---

## Alcance

### ✅ Qué hace

| Capa | Función | Estado |
|------|---------|--------|
| **Hyper-V Lifecycle** | Crear/eliminar VMs, switches, checkpoints, VHDs | Real |
| **Guest Interaction** | PowerShell Direct — ejecutar comandos dentro de la VM | Real |
| **Network Isolation** | Internal switch, sin gateway, firewall restrictivo | Real |
| **Filesystem Protection** | Disco diferencial efímero (AVHDX), sin acceso a host | Real |
| **Process Monitoring** | Sysmon integration, detección de inyección | Real |
| **Memory Protection** | VT-x/AMD-V, EPT, sin memoria compartida | Real |
| **Hypervisor Monitoring** | Monitoreo de sesión Hyper-V | Real |
| **Decontamination** | 7 pasos verificados, snapshot forense | Real |
| **State Persistence** | SQLite con WAL mode, crash recovery | Real |
| **Observability** | JSON structured logging, metrics, health checks | Real |
| **Forensics** | Evidencia con SHA-256 chain of custody | Real |
| **Compliance** | 10 controles automatizados, audit log | Real |
| **Dual Bunker** | Rotación automática entre bunkers | Real |
| **CLI** | 8 subcomandos con entry point `lumenos` | Real |

### ❌ Qué NO hace (y por qué)

| Límite | Razón |
|--------|-------|
| Análisis estático de malware | Fuera de alcance — usar YARA, PE-sieve, etc. |
| Análisis dinámico automatizado | Requiere sandbox-specific orchestration (Cuckoo, CAPE) |
| Evolución de amenazas | Las capas son estáticas — no se adaptan al malware |
| VM Escape real | Las probabilidades son teóricas (model layer), no medidas |
| Red en el guest | Air gap intencional — sin acceso a internet |
| Multi-host / clustering | Un solo host Hyper-V |
| Hardware attestation | Sin TPM sealed measurements reales |

---

## Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                   CLI / Python API                   │
├─────────────────────────────────────────────────────┤
│  DualBunkerManager → Bunker (state machine)         │
├──────────┬──────────┬──────────┬────────────────────┤
│  State   │  Observe │  Forensics│  Compliance       │
│  SQLite  │  Metrics │  Evidence│  Controls          │
├──────────┴──────────┴──────────┴────────────────────┤
│  5 Security Layers (PowerShell Direct to Guest)     │
│  Network | Filesystem | Process | Memory | Hyper-V  │
├─────────────────────────────────────────────────────┤
│  Hyper-V VMs + Internal Switches + Differential VHD │
└─────────────────────────────────────────────────────┘
```

### Módulos

```
lumenos_sandbox/
├── types.py           # Enums, dataclasses, constantes
├── exceptions.py      # 7 excepciones custom
├── hypervisor.py      # 27 funciones Hyper-V + PowerShell Direct
├── layers.py          # 5 capas de seguridad reales
├── monitoring.py      # IntegrityVerifier + SecurityMonitor
├── bunker.py          # State machine + lifecycle
├── manager.py         # DualBunkerManager
├── state.py           # SQLite persistence (WAL mode)
├── observability.py   # JSON logging, MetricsCollector, health
├── forensics.py       # Evidence chain SHA-256
├── compliance.py      # 10 controles, audit log
├── cli.py             # 8 subcomandos
└── __main__.py        # python -m lumenos_sandbox
```

---

## Instalación

### Requisitos

- **Python** ≥ 3.11
- **Windows** 10 21H2+ / 11 / Server 2022 **con Hyper-V habilitado**, o
- **Linux** (Ubuntu 20.04+ / Fedora 36+ / Arch) con virtualización por hardware

### Instalar

```bash
pip install -e ".[dev]"
```

### Configurar hipervisor

```bash
# Verificar estado
lumenos status

# Linux: instalar dependencias KVM/QEMU/libvirt (con sudo)
lumenos setup-linux

# Verificar de nuevo
lumenos status

# Windows: habilitar Hyper-V
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All
# (requiere reinicio)

# Seleccionar backend explícito (override)
LUMENOS_HYPERVISOR=kvm lumenos status   # kvm | hyperv | mock

# CI sin hipervisor
LUMENOS_HYPERVISOR=mock python -m pytest tests/ -v
```

### Verificar entorno (opcional)

```bash
./scripts/check_env.sh     # Linux
```

---

## Uso

### CLI

```bash
# Verificar sistema
lumenos status

# Instalar dependencias Linux (con sudo)
lumenos setup-linux

# Iniciar sandbox
lumenos start --id sandbox1 --name "Análisis" --memory 8192 --cpus 4

# Detener y descontaminar
lumenos stop --id sandbox1

# Listar sandboxes
lumenos list

# Verificar salud
lumenos health

# Migrar estado JSON a SQLite
lumenos migrate
```

### Python API

```python
from lumenos_sandbox import Bunker, BunkerConfig

config = BunkerConfig(
    id="sandbox1",
    name="Análisis",
    guest_username="Administrator",
    guest_password="P@ssw0rd",
)

bunker = Bunker(config)
bunker.initialize()   # Crea VM en Hyper-V
bunker.activate()     # Activa capas de seguridad

# ... análisis ...

bunker.terminate()    # Descontaminación completa
```

### Compliance

```python
from lumenos_sandbox import ComplianceReport

report = ComplianceReport()
result = report.evaluate(config)
print(f"Pass rate: {result['pass_rate']}")
```

### Forensics

```python
from lumenos_sandbox import collect_evidence, export_evidence

chain = collect_evidence("sandbox1")
export_evidence(chain, "evidence/sandbox1.json")
```

---

## Alcance de Seguridad

### Probabilidad de Escape (Modelo Teórico)

```
P(Escape) = P(Red) × P(Archivos) × P(Procesos) × P(Memoria) × P(Hipervisor)
P(Escape) = 10⁻⁶ × 10⁻⁸ × 10⁻⁵ × 10⁻⁹ × 10⁻¹² = 10⁻⁴⁰
```

> **⚠️ Nota:** Estas cifras son del modelo teórico de independencia de capas
> simuladas. Las capas reales (PowerShell Direct, Hyper-V) funcionan, pero
> las probabilidades no están medidas en runtime.

### Controles de Compliance

| ID | Control | Descripción |
|----|---------|-------------|
| SC-01 | Network Isolation | VM aislada de host y internet |
| SC-02 | Filesystem Protection | Sin acceso a discos del host |
| SC-03 | Process Monitoring | Monitoreo de inyección de procesos |
| SC-04 | Memory Protection | Integridad de memoria verificada |
| SC-05 | Hypervisor Monitoring | Sesión Hyper-V monitoreada |
| SC-06 | Decontamination | Limpieza post-análisis verificada |
| SC-07 | Integrity Verification | Hashes de componentes verificados |
| SC-08 | State Persistence | Estado persistido en SQLite |
| SC-09 | Forensic Evidence | Cadena de custodia SHA-256 |
| SC-10 | Audit Logging | Acciones registradas |

---

## Pruebas

```bash
# Suite completa
python -m pytest tests/ -v

# Solo tests mock (no necesita Hyper-V)
python -m pytest tests/test_functionality.py tests/test_security.py tests/test_integration.py -v

# Tests reales (necesita Hyper-V habilitado)
python -m pytest tests/test_integration_real.py -v
```

| Archivo | Tests | Descripción |
|---------|-------|-------------|
| `test_functionality.py` | 53 | Funcionamiento correcto |
| `test_security.py` | 36 | Resistencia a ataques |
| `test_integration.py` | 39 | Ciclo de vida completo (mocked) |
| `test_integration_real.py` | 17 | Hyper-V/KVM real (skip si no disponible) |
| `test_state.py` | 13 | SQLite persistence |
| `test_observability.py` | 14 | JSON logging, metrics, health |
| `test_forensics.py` | 13 | Evidencia forense |
| `test_compliance.py` | 9 | Controles de compliance |
| `test_platform.py` | 5 | Detección cross-platform |
| `test_hypervisor_backends.py` | 4 | Backends KVM/Mock/factory |
| `test_secrets_store.py` | 1 | Secrets fallback |
| `test_resources.py` | 29 | Image builder, recursos |
| `test_new_modules.py` | 19 | Módulos nuevos |
| `test_resource_manager.py` | 47 | Resource manager |
| **Total** | **282** | **282 passed, 16 skipped (sin hipervisor)** |

---

## Modelo de Amenazas

Ver [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) para el modelo completo.

---

## Licencia

Copyright © 2026 Irvin Diaz Medorio. Todos los derechos reservados.

---

## Contacto

**Autor:** Irvin Diaz Medorio
**Proyecto:** LUMENOS SANDBOX
**Versión:** 2.1.0
