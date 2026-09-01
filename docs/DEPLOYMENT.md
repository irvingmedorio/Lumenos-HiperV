# Guía de Despliegue — LUMENOS Sandbox

**Versión**: 2.1.0  
**Autor**: Irvin Diaz Medorio  
**Última actualización**: 2026-08-31

---

## Tabla de Contenidos

1. [Requisitos del Sistema](#1-requisitos-del-sistema)
2. [Instalación](#2-instalación)
3. [Hardening de Windows Server](#3-hardening-de-windows-server)
4. [Configuración de Red](#4-configuración-de-red)
5. [Monitoreo y Alertas](#5-monitoreo-y-alertas)
6. [Backup y Recuperación](#6-backup-y-recuperación)

---

## 1. Requisitos del Sistema

### 1.1 Sistema Operativo

| Componente | Requisito mínimo |
|---|---|
| **SO** | Windows Server 2019/2022 o Windows 10/11 Pro/Enterprise |
| **Edición** | Pro o superior (Hyper-V no disponible en Home) |
| **Arquitectura** | x64 (AMD64) |
| **PowerShell** | 5.1+ (incluido) o PowerShell 7+ (recomendado) |
| **Python** | 3.11+ |

### 1.2 Hyper-V

Hyper-V **es obligatorio**. El sandbox crea y gestiona VMs reales a través del hypervisor del host.

```powershell
# Verificar estado actual
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All

# Habilitar (requiere reinicio)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All
Restart-Computer
```

> **Nota**: En máquinas virtuales (nested virtualization), el host debe soportar VT-x/AMD-V passthrough. Para VMware: habilitar "Expose hardware-assisted virtualization to the guest". Para Hyper-V anidado: ejecutar en Azure con isolateHostPolicy=disable.

### 1.3 Hardware Mínimo

| Recurso | Mínimo | Recomendado (producción) |
|---|---|---|
| **CPU** | 4 cores | 8+ cores con soporte SLAT |
| **RAM** | 16 GB | 32+ GB |
| **Disco** | 100 GB libres | 250+ GB SSD (NVMe preferido) |
| **Red** | 1 NIC física | 2+ NICs (una para management, una para VMs) |

### 1.4 Requisitos de Red

| Puerto | Dirección | Propósito |
|---|---|---|
| TCP 445 | Entrante (restringido) | SMB para copia de archivos al guest |
| TCP 5985/5986 | Entrante (restringido) | WinRM (PowerShell Direct VMBus) |
| TCP 8080 | Saliente | Webhooks de alertas |
| UDP 53 | Saliente | DNS (si se habilita DNS en el guest) |

> **Importante**: El guest VM **no debe tener acceso a Internet** en producción. El switch virtual debe ser `Internal` o `Private`, nunca `External` a menos que se requiera análisis de red controlado.

---

## 2. Instalación

### 2.1 Desde PyPI

```bash
pip install lumenos-sandbox
```

Para dependencias opcionales de análisis:

```bash
pip install lumenos-sandbox[analysis]
```

### 2.2 Desde fuente

```bash
git clone <repositorio>
cd lumenos_windows_sandbox
pip install -e ".[dev,analysis]"
```

### 2.3 Verificación Post-Instalación

```bash
# Verificar que Hyper-V está disponible
lumenos status

# Verificar salud del sistema
lumenos health
```

### 2.4 Configuración Inicial

El archivo de configuración se encuentra en `config/lumenos_config.ini`:

```ini
[system]
system_id = lumenos_production
system_name = Lumenos Sandbox Architecture

[bunker]
default_memory_mb = 8192
default_cpu_cores = 4
default_disk_gb = 100
max_session_hours = 24
min_decontamination_minutes = 30

[security]
enable_network_isolation = true
enable_memory_encryption = true
enable_secure_boot = true
enable_tpm_verification = true

[integrity]
hash_algorithm = sha512
verification_interval_seconds = 60

[logging]
log_level = VERBOSE
log_dir = logs
max_log_size_mb = 100
log_retention_days = 30
enable_audit_log = true
```

**Ajustes recomendados para producción:**

1. Cambiar `system_id` a un identificador único del entorno.
2. Ajustar `max_concurrent_bunkers` según los recursos del host (default: 2).
3. Habilitar `enable_audit_log = true` y `enable_forensic_log = true`.
4. Configurar rutas de logs en un volumen separado del SO.

---

## 3. Hardening de Windows Server

### 3.1 Deshabilitar Servicios Innecesarios

```powershell
# Servicios seguros de deshabilitar en un host dedicado a análisis
$servicesToDisable = @(
    "wSearch"           # Windows Search (consumo de disco)
    "SysMain"           # Superfetch (innecesario en SSD)
    "DiagTrack"         # Telemetría de diagnóstico
    "dmwappushservice"  # WAP Push
    "MapsBroker"        # Descarga de mapas
    "lfsvc"             # Servicio de geolocalización
    "SharedAccess"      # ICS (Internet Connection Sharing)
    "RemoteRegistry"    # Registro remoto
    "WMPNetworkSvc"     # Windows Media Player sharing
)

foreach ($svc in $servicesToDisable) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "[OK] Deshabilitado: $svc"
}
```

### 3.2 Configurar Windows Firewall

```powershell
# Habilitar firewall en todos los perfiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Bloquear todo tráfico entrante por defecto
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Permitir solo puertos necesarios para LUMENOS
New-NetFirewallRule -DisplayName "LUMENOS-WinRM" `
    -Direction Inbound -Protocol TCP -LocalPort 5985,5986 `
    -Action Allow -Profile Domain,Private

New-NetFirewallRule -DisplayName "LUMENOS-Management" `
    -Direction Inbound -Protocol TCP -LocalPort 8080 `
    -Action Allow -Profile Domain,Private `
    -RemoteAddress "10.0.0.0/24"  # Solo red de management

# Bloquear tráfico SMB desde VMs
New-NetFirewallRule -DisplayName "Block-SMB-FromVMs" `
    -Direction Inbound -Protocol TCP -LocalPort 445 `
    -Action Block -Profile Domain,Private `
    -RemoteAddress "172.16.0.0/12"  # Rango típico de VMs Hyper-V
```

### 3.3 Habilitar Auditoría de Eventos

```powershell
# Habilitar auditoría de inicio de sesión
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Habilitar auditoría de creación de procesos
auditpol /set /subcategory:"Process Creation" /success:enable

# Habilitar auditoría de acceso a objetos
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Habilitar comando de línea en eventos de proceso (para Sysmon)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### 3.4 Cuenta de Servicio Dedicada

```powershell
# Crear cuenta de servicio dedicada
New-LocalUser -Name "svc_lumenos" `
    -Password (ConvertTo-SecureString "P@ssw0rd!Cambiar" -AsPlainText -Force) `
    -FullName "LumenOS Service Account" `
    -Description "Servicio para LUMENOS Sandbox" `
    -PasswordNeverExpires

# Agregar permisos mínimos necesarios
Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "svc_lumenos"

# Deshabilitar login interactivo (forzar servicio)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    /v SpecialAccountsUserList /t REG_MULTI_SZ /d "svc_lumenos" /f
```

### 3.5 Secure Boot y VBS

```powershell
# Verificar Secure Boot (requiere UEFI)
Confirm-SecureBootUEFI

# Habilitar VBS (Virtualization-Based Security)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f

# Habilitar HVCI (Hypervisor-protected Code Integrity)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f

# RequerirSecure Boot + VBS para todas las VMs
Set-VMHost -EnableEnhancedSessionMode $true
```

> **Nota**: El sandbox verifica automáticamente el estado de VBS y Secure Boot dentro del guest via `check_guest_vbs_status()`. Si están deshabilitados, genera eventos de severidad MEDIUM.

---

## 4. Configuración de Red

### 4.1 Virtual Switch Configuration

El sandbox usa switches `Internal` o `Private` para aislamiento:

```powershell
# Crear switch interno para análisis
New-VMSwitch -Name "LUMENOS-Internal" -SwitchType Internal

# Para aislamiento total (sin acceso ni al host)
New-VMSwitch -Name "LUMENOS-Isolated" -SwitchType Private
```

### 4.2 Aislamiento de Red

El aislamiento se configura en `config/lumenos_config.ini`:

```ini
[security]
enable_network_isolation = true
```

El sandbox verifica el aislamiento automáticamente ejecutando `Test-NetConnection` desde el guest. Si el guest puede alcanzar destinations externas, se registra un evento `ISOLATION_BREACH` de severidad **CRITICAL**.

**Política de firewall del guest** (configurable por llamada):

```powershell
# Bloquear todo tráfico saliente del guest
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# Excepción opcional: DNS
netsh advfirewall firewall add rule name="Allow DNS" `
    dir=out action=allow protocol=udp remoteport=53
```

### 4.3 Reglas de Firewall para Análisis

```powershell
# Permitir tráfico entre host y guest solo por VMBus (PowerShell Direct)
# No se necesitan reglas de red — la comunicación es por VMBus

# Si se necesita monitoreo de red del guest, habilitar WinRM en el guest
# y usar el canal VMBus para obtener logs de red
```

---

## 5. Monitoreo y Alertas

### 5.1 Observabilidad Integrada

El sandbox incluye un sistema de observabilidad con JSON estructurado:

```python
from lumenos_sandbox import MetricsCollector, check_health
from lumenos_sandbox.observability import setup_json_logging

# Configurar logging JSON para aggregation pipelines
setup_json_logging()

# Crear collector de métricas
metrics = MetricsCollector()

# Obtener snapshot de métricas
snapshot = metrics.snapshot()
# → {"counters": {...}, "gauges": {...}, "timers": {...}}
```

### 5.2 Health Check

```bash
# CLI
lumenos health

# Salida esperada (JSON)
{
  "status": "ok",
  "timestamp": "2026-08-31T12:00:00",
  "bunkers": [
    {"bunker_id": "sandbox_1", "state": "ACTIVE", "healthy": true}
  ]
}
```

### 5.3 Configurar Alertas Webhook

Configurar en `config/lumenos_config.ini`:

```ini
[alerts]
enable_email_alerts = false
enable_syslog = false
alert_on_leak_detection = true
alert_on_corruption = true
alert_on_escape_attempt = true
alert_on_integrity_failure = true
```

Para webhook, implementar un handler que consuma los eventos de `SecurityMonitor`:

```python
from lumenos_sandbox import SecurityMonitor
from lumenos_sandbox.types import ThreatLevel

monitor = SecurityMonitor("sandbox_1")

# Los eventos se registran internamente y se pueden consumir
# Revisar eventos críticos periódicamente
for event in monitor.events:
    if event.severity == ThreatLevel.CRITICAL:
        # Enviar webhook
        send_webhook(event)
```

### 5.4 Agregación de Logs

Los logs se escriben en formato JSON en `logs/lumenos_sandbox.log`:

```json
{
  "ts": "2026-08-31T12:00:00+00:00",
  "level": "CRITICAL",
  "logger": "LUMENOS_SANDBOX",
  "msg": "SECURITY EVENT: ISOLATION_BREACH - Guest can reach external network"
}
```

**Integración con herramientas externas:**

| Herramienta | Método |
|---|---|
| **ELK Stack** | Filebeat → Logstash → Elasticsearch |
| **Splunk** | Splunk Universal Forwarder en `logs/` |
| **Azure Monitor** | Azure Monitor Agent → Log Analytics |
| **Prometheus** | Exportar `MetricsCollector.snapshot()` como endpoint `/metrics` |

---

## 6. Backup y Recuperación

### 6.1 Backup de Base de Datos

La base de datos SQLite (`lumenos_state.db`) contiene el estado de todos los bunkers.

```powershell
# Backup manual
Copy-Item "lumenos_state.db" "backups/lumenos_state_$(Get-Date -Format yyyyMMdd_HHmmss).db"

# Backup programado (Task Scheduler)
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-Command Copy-Item 'C:\path\to\lumenos_state.db' 'D:\backups\lumenos_state_$(Get-Date -Format yyyyMMdd).db'"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
Register-ScheduledTask -TaskName "LUMENOS-Backup" -Action $action -Trigger $trigger
```

### 6.2 Persistencia de Estado

El estado se persiste en SQLite con el siguiente esquema:

```sql
CREATE TABLE bunkers (
    bunker_id   TEXT PRIMARY KEY,
    config      TEXT NOT NULL,     -- JSON serializado
    state       TEXT NOT NULL,
    vm_name     TEXT,
    switch_name TEXT,
    signing_key TEXT,
    created_at  TEXT,
    activated_at TEXT,
    terminated_at TEXT,
    updated_at  TEXT NOT NULL
);
```

**Migración desde JSON (si se usaba antes):**

```bash
lumenos migrate
```

### 6.3 Recuperación ante Desastres

#### Escenario 1: Host cae durante análisis

1. Reiniciar el host.
2. Verificar estado: `lumenos list`
3. Los bunkers en estado `ACTIVE` o `READY` se encuentran en estado inconsistente.
4. Forzar terminación y descontaminación:

```bash
lumenos stop --id <bunker_id>
```

5. Si la VM quedó huérfana en Hyper-V:

```powershell
# Listar VMs huérfanas
Get-VM | Where-Object { $_.Name -like "LUMENOS-*" }

# Eliminar VM huérfana
Remove-VM -Name "<vm_name>" -Force
```

#### Escenario 2: Base de datos corrupta

```bash
# Restaurar desde backup
Copy-Item "backups/lumenos_state_YYYYMMDD.db" "lumenos_state.db" -Force

# Verificar integridad
lumenos health
```

#### Escenario 3: Corrupción de imagen base

1. Verificar integridad de hashes:

```python
from lumenos_sandbox import IntegrityVerifier

verifier = IntegrityVerifier()
report = verifier.get_verification_report()
print(f"Pass rate: {report['pass_rate']:.2%}")
```

2. Si los hashes no coinciden, reconstruir la imagen base:

```bash
# Usar ImageBuilder para reconstruir
python -m lumenos_sandbox.image_builder --rebuild-base
```

#### Escenario 4: Descontaminación fallida

Si un bunker queda en estado `QUARANTINE`:

```powershell
# Forzar eliminación de VM y recursos
Get-VM -Name "LUMENOS-<bunker_id>*" | Remove-VM -Force

# Eliminar VHDs asociadas
Get-ChildItem "D:\VMs\LUMENOS-<bunker_id>*" | Remove-Item -Force

# Limpiar estado en DB
# (ejecutar desde Python o SQLite manual)
```

---

## Comandos de Referencia Rápida

| Comando | Descripción |
|---|---|
| `lumenos status` | Verificar Hyper-V y prerequisitos |
| `lumenos start --id X --name Y` | Iniciar sesión de análisis |
| `lumenos stop --id X` | Terminar y descontaminar sesión |
| `lumenos analyze --id X --sample Y` | Ejecutar muestra en el sandbox |
| `lumenos report --id X` | Ver reporte de la sesión |
| `lumenos list` | Listar sandboxes activos |
| `lumenos health` | Verificar salud del sistema |
| `lumenos migrate` | Migrar estado JSON a SQLite |
| `lumenos compliance [--id X]` | Verificar controles de compliance |
| `lumenos evidence --id X` | Recopilar evidencia forense |

---

## Seguridad — Checklist de Despliegue

- [ ] Hyper-V habilitado y funcionando
- [ ] Firewall del host configurado (bloqueo por defecto)
- [ ] Servicios innecesarios deshabilitados
- [ ] Cuenta de servicio dedicada creada
- [ ] Auditoría de eventos habilitada
- [ ] Secure Boot y VBS habilitados
- [ ] Switch virtual configurado como `Internal` o `Private`
- [ ] Aislamiento de red verificado (`test_guest_connectivity` retorna `True`)
- [ ] Logs configurados con retención mínima de 30 días
- [ ] Backup programado de `lumenos_state.db`
- [ ] Sysmon instalado en imagen base del guest
