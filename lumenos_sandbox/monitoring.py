#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IntegrityVerifier and SecurityMonitor."""

import hashlib
import logging
import threading
import time
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from .types import (
    SecurityLayer, ThreatLevel, SecurityEvent, IntegrityCheck,
    EscapeAttemptType,
)
from .observability import MetricsCollector

logger = logging.getLogger('LUMENOS_SANDBOX')


# ---------------------------------------------------------------------------
# Integrity Verifier
# ---------------------------------------------------------------------------

class IntegrityVerifier:
    """
    Verificador de integridad del sistema.
    Realiza verificaciones criptográficas de componentes críticos.
    """

    CRITICAL_COMPONENTS = [
        "hypervisor_config",
        "base_image",
        "security_policies",
        "network_rules",
        "process_whitelist",
        "memory_layout",
    ]

    def __init__(self, hash_algorithm: str = "sha512"):
        self.hash_algorithm = hash_algorithm
        self.baseline_hashes: Dict[str, str] = {}
        self.verification_history: List[IntegrityCheck] = []
        self._lock = threading.Lock()

    def compute_hash(self, data: bytes) -> str:
        """Computa hash de datos."""
        h = hashlib.new(self.hash_algorithm)
        h.update(data)
        return h.hexdigest()

    def compute_file_hash(self, filepath: str) -> str:
        """Computa hash de un archivo."""
        h = hashlib.new(self.hash_algorithm)
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    def set_baseline(self, component: str, hash_value: str):
        """Establece hash base para un componente."""
        with self._lock:
            self.baseline_hashes[component] = hash_value
            logger.info(f"Baseline establecido para {component}: {hash_value[:16]}...")

    def verify_component(self, component: str, current_hash: str) -> IntegrityCheck:
        """Verifica integridad de un componente."""
        expected = self.baseline_hashes.get(component, "")
        passed = expected == current_hash and expected != ""

        check = IntegrityCheck(
            component=component,
            expected_hash=expected,
            actual_hash=current_hash,
            passed=passed,
            timestamp=datetime.now(),
            details="Hash coincide" if passed else "HASH NO COINCIDE - POSIBLE COMPROMISO"
        )

        with self._lock:
            self.verification_history.append(check)

        if not passed:
            logger.critical(f"INTEGRIDAD COMPROMETIDA: {component}")

        return check

    def verify_all(self, current_hashes: Dict[str, str]) -> Tuple[bool, List[IntegrityCheck]]:
        """Verifica todos los componentes críticos."""
        results = []
        all_passed = True

        for component in self.CRITICAL_COMPONENTS:
            if component in current_hashes:
                check = self.verify_component(component, current_hashes[component])
                results.append(check)
                if not check.passed:
                    all_passed = False

        return all_passed, results

    def get_verification_report(self) -> Dict[str, Any]:
        """Genera reporte de verificaciones."""
        with self._lock:
            total = len(self.verification_history)
            passed = sum(1 for c in self.verification_history if c.passed)

            return {
                "total_checks": total,
                "passed": passed,
                "failed": total - passed,
                "pass_rate": passed / total if total > 0 else 1.0,
                "last_check": self.verification_history[-1].timestamp.isoformat() if self.verification_history else None,
            }


# ---------------------------------------------------------------------------
# Security Monitor
# ---------------------------------------------------------------------------

class SecurityMonitor:
    """
    Monitor de seguridad en tiempo real.
    Detecta intentos de escape y violaciones de seguridad.
    """

    # Patrones de comportamiento sospechoso
    SUSPICIOUS_PATTERNS = {
        "vm_escape_indicators": [
            "VBOX", "VMWARE", "QEMU", "VIRTUALBOX",
            "vmmouse", "vmware svga", "vboxvideo",
            "hypervisor", "hyper-v", "xen"
        ],
        "debugging_indicators": [
            "kernel32.dll", "ntdll.dll", "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"
        ],
        "persistence_indicators": [
            "CurrentVersion\\Run", "Winlogon", "Shell Folders",
            "Startup", "Scheduled Tasks", "Services"
        ],
        "network_exfil_indicators": [
            "dns tunnel", "icmp tunnel", "http beacon",
            "reverse shell", "bind shell", "data exfiltration"
        ],
        "injection_indicators": [
            "CreateRemoteThread", "WriteProcessMemory",
            "DLL injection", "Process Hollowing", "APC Injection",
            "SetWindowsHookEx"
        ]
    }

    def __init__(self, bunker_id: str, *, metrics=None):
        self.bunker_id = bunker_id
        self.events: List[SecurityEvent] = []
        self.escape_attempts: List[EscapeAttemptType] = []
        self._lock = threading.Lock()
        self._monitoring_active = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._metrics = metrics  # MetricsCollector or None
        # VM credentials for hypervisor queries (set via set_vm_credentials)
        self._vm_name: Optional[str] = None
        self._username: str = ""
        self._password: str = ""

    def set_vm_credentials(self, vm_name: str, username: str = "",
                           password: str = ""):
        """Set VM name and guest credentials for hypervisor monitoring calls."""
        self._vm_name = vm_name
        self._username = username
        self._password = password

    def start_monitoring(self):
        """Inicia el monitoreo continuo."""
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        if self._metrics is not None:
            self._metrics.inc("monitoring_started")
        logger.info(f"Monitoreo de seguridad iniciado para bunker {self.bunker_id}")

    def stop_monitoring(self):
        """Detiene el monitoreo."""
        self._monitoring_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        if self._metrics is not None:
            self._metrics.inc("monitoring_stopped")
        logger.info(f"Monitoreo de seguridad detenido para bunker {self.bunker_id}")

    def _monitor_loop(self):
        """Loop principal de monitoreo."""
        while self._monitoring_active:
            try:
                self._check_system_integrity()
                self._check_network_activity()
                self._check_process_activity()
                self._check_memory_integrity()
                time.sleep(1)  # Intervalo de monitoreo
            except Exception as e:
                logger.error(f"Error en monitoreo: {e}")

    def _check_system_integrity(self):
        """Verifica integridad del sistema leyendo event log del guest."""
        if not self._vm_name:
            return

        try:
            from .hypervisor import read_guest_event_log
            events = read_guest_event_log(
                self._vm_name, self._username, self._password,
                log_name="Security", max_events=20,
            )
            if not events:
                return

            findings = self.analyze_event_log(events)
            for finding in findings:
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    layer=SecurityLayer.HYPERVISOR,
                    event_type="INTEGRITY_FINDING",
                    severity=ThreatLevel.HIGH,
                    description=finding,
                    bunker_id=self.bunker_id,
                    raw_data={"source": "event_log"},
                )
                self.log_event(event)
        except Exception as e:
            logger.debug("System integrity check failed: %s", e)

    def _check_network_activity(self):
        """Verifica actividad de red sospechosa (aislamiento del guest)."""
        if not self._vm_name:
            return

        try:
            from .hypervisor import test_guest_connectivity
            # test_guest_connectivity returns True if BLOCKED (good)
            is_blocked = test_guest_connectivity(
                self._vm_name, self._username, self._password,
            )
            if not is_blocked:
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    layer=SecurityLayer.NETWORK,
                    event_type="ISOLATION_BREACH",
                    severity=ThreatLevel.CRITICAL,
                    description="Guest can reach external network — isolation broken",
                    bunker_id=self.bunker_id,
                )
                self.log_event(event)
        except Exception as e:
            logger.debug("Network activity check failed: %s", e)

    def _check_process_activity(self):
        """Verifica actividad de procesos sospechosos en el guest."""
        if not self._vm_name:
            return

        try:
            from .hypervisor import get_guest_processes
            processes = get_guest_processes(
                self._vm_name, self._username, self._password,
            )
            if not processes:
                return

            # Scan process list for suspicious names
            suspicious_names = {
                "mimikatz", "procdump", "psexec", "nc", "ncat",
                "netcat", "meterpreter", "cobaltstrike", "inject",
            }
            for proc in processes:
                name = (proc.get("ProcessName") or "").lower()
                if any(s in name for s in suspicious_names):
                    event = SecurityEvent(
                        timestamp=datetime.now(),
                        layer=SecurityLayer.PROCESS,
                        event_type="SUSPICIOUS_PROCESS",
                        severity=ThreatLevel.HIGH,
                        description=f"Suspicious process detected: {name}",
                        bunker_id=self.bunker_id,
                        raw_data={"pid": proc.get("Id"), "process": name},
                    )
                    self.log_event(event)
        except Exception as e:
            logger.debug("Process activity check failed: %s", e)

    def _check_memory_integrity(self):
        """Verifica integridad de memoria (VBS/HVCI status) en el guest."""
        if not self._vm_name:
            return

        try:
            from .hypervisor import check_guest_vbs_status
            vbs = check_guest_vbs_status(
                self._vm_name, self._username, self._password,
            )
            if not vbs.get("vbs_enabled"):
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    layer=SecurityLayer.MEMORY,
                    event_type="VBS_DISABLED",
                    severity=ThreatLevel.MEDIUM,
                    description="Virtualization-Based Security is disabled in guest",
                    bunker_id=self.bunker_id,
                    raw_data=vbs,
                )
                self.log_event(event)
            if not vbs.get("secure_boot"):
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    layer=SecurityLayer.MEMORY,
                    event_type="SECURE_BOOT_DISABLED",
                    severity=ThreatLevel.MEDIUM,
                    description="Secure Boot is disabled in guest",
                    bunker_id=self.bunker_id,
                    raw_data=vbs,
                )
                self.log_event(event)
        except Exception as e:
            logger.debug("Memory integrity check failed: %s", e)

    def log_event(self, event: SecurityEvent):
        """Registra un evento de seguridad."""
        with self._lock:
            self.events.append(event)

        if self._metrics is not None:
            self._metrics.inc(f"security_events_{event.severity.name}")
            self._metrics.inc("security_events_total")

        # Log según severidad
        if event.severity == ThreatLevel.CRITICAL:
            logger.critical(f"SECURITY EVENT: {event.event_type} - {event.description}")
        elif event.severity == ThreatLevel.HIGH:
            logger.error(f"SECURITY EVENT: {event.event_type} - {event.description}")
        elif event.severity == ThreatLevel.MEDIUM:
            logger.warning(f"SECURITY EVENT: {event.event_type} - {event.description}")
        else:
            logger.info(f"SECURITY EVENT: {event.event_type} - {event.description}")

    def detect_escape_attempt(self, attempt_type: EscapeAttemptType, details: str) -> bool:
        """
        Detecta y registra un intento de escape.
        Retorna True si se detecta un patrón de escape.
        """
        with self._lock:
            self.escape_attempts.append(attempt_type)

        event = SecurityEvent(
            timestamp=datetime.now(),
            layer=self._get_layer_for_escape_type(attempt_type),
            event_type=f"ESCAPE_ATTEMPT_{attempt_type.value.upper()}",
            severity=ThreatLevel.CRITICAL,
            description=details,
            bunker_id=self.bunker_id,
            raw_data={"attempt_type": attempt_type.value}
        )
        self.log_event(event)

        if self._metrics is not None:
            self._metrics.inc(f"escape_attempts_{attempt_type.value}")

        return True

    def _get_layer_for_escape_type(self, attempt_type: EscapeAttemptType) -> SecurityLayer:
        """Obtiene la capa de seguridad para un tipo de escape."""
        mapping = {
            EscapeAttemptType.VM_ESCAPE: SecurityLayer.HYPERVISOR,
            EscapeAttemptType.NETWORK_EXFILTRATION: SecurityLayer.NETWORK,
            EscapeAttemptType.FILE_PERSISTENCE: SecurityLayer.FILESYSTEM,
            EscapeAttemptType.PROCESS_INJECTION: SecurityLayer.PROCESS,
            EscapeAttemptType.MEMORY_MANIPULATION: SecurityLayer.MEMORY,
            EscapeAttemptType.HYPERVISOR_ATTACK: SecurityLayer.HYPERVISOR,
            EscapeAttemptType.SIDE_CHANNEL: SecurityLayer.MEMORY,
            EscapeAttemptType.ROOTKIT_DETECTED: SecurityLayer.PROCESS,
        }
        return mapping.get(attempt_type, SecurityLayer.HYPERVISOR)

    def get_security_report(self) -> Dict[str, Any]:
        """Genera reporte de seguridad."""
        with self._lock:
            events_by_severity = {}
            for level in ThreatLevel:
                events_by_severity[level.name] = sum(
                    1 for e in self.events if e.severity == level
                )

            result = {
                "bunker_id": self.bunker_id,
                "total_events": len(self.events),
                "escape_attempts": len(self.escape_attempts),
                "events_by_severity": events_by_severity,
                "last_event": self.events[-1].timestamp.isoformat() if self.events else None,
            }

        if self._metrics is not None:
            result["collector_metrics"] = self._metrics.snapshot()

        return result

    def analyze_patterns(self, data: str) -> List[str]:
        """Analiza datos en busca de patrones sospechosos."""
        detected = []
        data_lower = data.lower()

        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in data_lower:
                    detected.append(f"{category}: {pattern}")

        return detected

    def analyze_event_log(self, events: List[Dict]) -> List[str]:
        """Analyze Windows Event Log / Sysmon entries for suspicious patterns.

        Recognized Sysmon Event IDs:
          1  — Process Create
          3  — Network Connection
          7  — Image Loaded
          8  — CreateRemoteThread
          10 — ProcessAccess
          11 — FileCreate
        """
        findings: List[str] = []

        for event in events:
            event_id = event.get("Id", 0)
            message = event.get("Message", "")
            source = event.get("ProcessName") or event.get("ProviderName", "unknown")

            # Sysmon-specific event IDs
            if event_id == 8:
                findings.append(
                    f"Process injection detected (CreateRemoteThread): {source}"
                )
            if event_id == 10:
                findings.append(
                    f"Process access attempt (ProcessAccess): {source}"
                )

            # Generic suspicious-pattern scan on the message text
            for category, patterns in self.SUSPICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in message.lower():
                        findings.append(f"{category}: {pattern}")

        return findings
