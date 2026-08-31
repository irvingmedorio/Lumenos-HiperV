#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enums, dataclasses, constants, and helper functions."""

import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Any, List
from datetime import datetime


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class BunkerState(Enum):
    """Estados posibles de un bunker."""
    INITIALIZING = auto()
    READY = auto()
    ACTIVE = auto()
    TERMINATING = auto()
    DECONTAMINATING = auto()
    DESTROYED = auto()
    QUARANTINE = auto()
    ERROR = auto()


class SecurityLayer(Enum):
    """Capas de seguridad del sistema."""
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    MEMORY = "memory"
    HYPERVISOR = "hypervisor"


class ThreatLevel(Enum):
    """Niveles de amenaza detectados."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class EscapeAttemptType(Enum):
    """Tipos de intentos de escape detectables."""
    VM_ESCAPE = "vm_escape"
    NETWORK_EXFILTRATION = "network_exfiltration"
    FILE_PERSISTENCE = "file_persistence"
    PROCESS_INJECTION = "process_injection"
    MEMORY_MANIPULATION = "memory_manipulation"
    HYPERVISOR_ATTACK = "hypervisor_attack"
    SIDE_CHANNEL = "side_channel"
    ROOTKIT_DETECTED = "rootkit_detected"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Transiciones de estado válidas
VALID_STATE_TRANSITIONS = {
    BunkerState.INITIALIZING: [BunkerState.READY, BunkerState.ERROR],
    BunkerState.READY: [BunkerState.ACTIVE, BunkerState.TERMINATING, BunkerState.ERROR],
    BunkerState.ACTIVE: [BunkerState.TERMINATING, BunkerState.QUARANTINE, BunkerState.ERROR],
    BunkerState.TERMINATING: [BunkerState.DECONTAMINATING, BunkerState.ERROR],
    BunkerState.DECONTAMINATING: [BunkerState.DESTROYED, BunkerState.ERROR],
    BunkerState.DESTROYED: [BunkerState.INITIALIZING],
    BunkerState.QUARANTINE: [BunkerState.DESTROYED, BunkerState.ERROR],
    BunkerState.ERROR: [BunkerState.DESTROYED],
}

# Probabilidades de fallo por capa (basadas en análisis formal)
LAYER_FAILURE_PROBABILITY = {
    SecurityLayer.NETWORK: 1e-6,
    SecurityLayer.FILESYSTEM: 1e-8,
    SecurityLayer.PROCESS: 1e-5,
    SecurityLayer.MEMORY: 1e-9,
    SecurityLayer.HYPERVISOR: 1e-12,
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _component_baseline_digest(component: str) -> str:
    """Deterministic digest for a component while isolation layers remain simulated.

    Single source of truth used by BOTH baseline initialization and current-hash
    computation so integrity verification is always self-consistent.
    SIMULATION-GRADE CONSISTENCY ONLY: this hashes a synthetic label, not real
    host artifacts, until scenario B wires actual artifacts (configs, base image).
    """
    return hashlib.sha512(f"lumenos-baseline:{component}".encode()).hexdigest()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BunkerConfig:
    """Configuración de un bunker."""
    id: str
    name: str
    memory_mb: int = 8192
    cpu_cores: int = 4
    disk_gb: int = 100
    max_session_hours: int = 24
    decontamination_minutes: int = 30
    snapshot_interval_minutes: int = 5
    enable_network_isolation: bool = True
    enable_memory_encryption: bool = True
    enable_secure_boot: bool = True
    log_level: str = "VERBOSE"
    guest_username: str = "Administrator"
    guest_password: str = ""
    sysmon_installed: bool = False
    sysmon_path: str = "C:\\Tools\\Sysmon64.exe"


@dataclass
class SecurityEvent:
    """Evento de seguridad registrado."""
    timestamp: datetime
    layer: SecurityLayer
    event_type: str
    severity: ThreatLevel
    description: str
    bunker_id: str
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrityCheck:
    """Resultado de verificación de integridad."""
    component: str
    expected_hash: str
    actual_hash: str
    passed: bool
    timestamp: datetime
    details: str = ""


@dataclass
class DecontaminationReport:
    """Reporte de descontaminación."""
    bunker_id: str
    start_time: datetime
    end_time: datetime
    steps_completed: List[str]
    steps_failed: List[str]
    integrity_checks: List[IntegrityCheck]
    warnings: List[str]
    success: bool
    signature: str = ""  # Firma digital del reporte


@dataclass
class BunkerMetrics:
    """Métricas del bunker en tiempo real."""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_packets_blocked: int = 0
    processes_terminated: int = 0
    escape_attempts_blocked: int = 0
    integrity_violations: int = 0
    uptime_seconds: int = 0
