# Modelo de Amenazas — LUMENOS Sandbox Architecture

## Alcance del Producto

LUMENOS Sandbox es un sistema de orquestación de bunkers duales para análisis de malware en entornos Windows aislados. Utiliza Hyper-V y PowerShell Direct para crear, gestionar y descontaminar VMs de análisis.

---

## Qué Protege (capas activas)

### Capa 1: Aislamiento de Red
- Switch virtual interno sin uplink externo
- Windows Firewall configurado: bloqueo total outbound excepto DNS si se autoriza
- Verificación: Test-NetConnection confirma que el guest NO alcanza hosts externos
- **Limitación**: No protege contra ataques de side-channel por red (timing, respuesta de DNS)

### Capa 2: Aislamiento de Archivos
- Disco diferencial efímero (AVHDX) — destruido en descontaminación
- Monitoreo de registry keys de persistencia (Run, RunOnce)
- **Limitación**: No implementa cifrado en-at-rest del disco diferencial durante la sesión

### Capa 3: Aislamiento de Procesos
- Detección de procesos conocidos maliciosos (mimikatz, procdump, psexec)
- Monitoreo de CreateRemoteThread (Sysmon Event ID 8)
- **Limitación**: No implementa Job Objects nativos ni AppLocker — la capa de procesos depende del agente de monitoreo (Sysmon) y no del kernel

### Capa 4: Aislamiento de Memoria
- Verificación de VBS/HVCI via registry del guest
- **Limitación**: No implementa EPT propio ni SEV-SNP — depende de las protecciones del hipervisor subyacente (Hyper-V)

### Capa 5: Aislamiento de Hipervisor
- Verificación de Hyper-V activo en el host
- **Limitación**: No verifica nested virtualization, Secure Boot, ni TPM del host en esta fase

---

## Qué NO Protege (fuera del alcance)

- **Evasión de sandbox**: El malware puede detectar que está en una VM (comandos de Hypervisors, artefactos de integración). No implementa contra-evasión.
- **Side-channel attacks**: Timing, cache, y otros ataques laterales no están mitigados.
- **Malware polimórfico/criptado**: La capa de análisis no hace unpacking — ejecuta la muestra tal cual.
- **Persistencia avanzada**: No detecta rootkits que modifican el kernel del guest.
- **Escapes de hipervisor**: La protección depende enteramente de la seguridad de Hyper-V. Si hay un CVE de Hyper-V, el sandbox está comprometido.

---

## Modelo de Confianza

- **Confiamos en**: Hyper-V como capa de aislamiento fuerte, PowerShell Direct como canal de gestión, Windows Firewall como barrera de red
- **No confiamos en**: El guest como entorno comprometido (tratamos todo dentro del VM como hostil)
- **Supuestos**: El host Windows está patcheado, Hyper-V está habilitado, el usuario tiene permisos de administrador

---

## Probabilidad Declarada vs Real

El README anterior declaraba una probabilidad de escape < 10⁻⁴⁰. Esa cifra era un modelo teórico basado en multiplicación de constantes hardcodeadas, no en un análisis formal.

**Estado actual**: No declaramos probabilidades de escape. La protección depende de la correcta configuración de Hyper-V y las capas de aislamiento del host. Recomendamos:

1. Mantener el host patcheado con las últimas actualizaciones de seguridad
2. Usar Hyper-V Generation 2 con Secure Boot habilitado
3. Habilitar VBS/HVCI en el host
4. Ejecutar el sandbox en un host dedicado, no en una estación de trabajo

---

## Incidentes Conocidos

- CVE de Hyper-V (Microsoft Security Bulletins mensuales)
- Sandbox detection por malware (.returnValue de Hypervisor, artefactos de integración)
- Side-channel via Hyper-V (publicados en conferencias de seguridad)

---

## Roadmap de Seguridad

- [ ] Verificación de Secure Boot y TPM del host
- [ ] Contra-evasión básica (ocultar artefactos de Hyper-V)
- [ ] Cifrado del disco diferencial en-at-rest
- [ ] Job Objects nativos para aislamiento de procesos
- [ ] AppLocker/WDAC para whitelist de ejecutables
