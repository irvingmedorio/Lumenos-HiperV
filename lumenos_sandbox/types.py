#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enums, dataclasses, constants, and helper functions."""

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, Any, List, Union
from datetime import datetime

# tomllib is stdlib in Python 3.11+, fallback to tomli for older versions
try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib


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




# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _component_baseline_digest(component: str) -> str:
    """Hash sintético para componentes de aislamiento."""
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
    monitor_interval_seconds: float = 5.0
    failure_probabilities: Dict[SecurityLayer, float] = field(default_factory=lambda: {
        SecurityLayer.NETWORK: 1e-6,
        SecurityLayer.FILESYSTEM: 1e-8,
        SecurityLayer.PROCESS: 1e-5,
        SecurityLayer.MEMORY: 1e-9,
        SecurityLayer.HYPERVISOR: 1e-12,
    })

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "BunkerConfig":
        """Load BunkerConfig from TOML or JSON file.
        
        Args:
            path: Path to config file (.toml or .json)
            
        Returns:
            BunkerConfig instance with loaded values
            
        Raises:
            ValueError: If file format is unsupported or required fields missing
            FileNotFoundError: If config file doesn't exist
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        suffix = path.suffix.lower()
        if suffix == ".toml":
            with path.open("rb") as f:
                data = tomllib.load(f)
        elif suffix == ".json":
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            raise ValueError(f"Unsupported config format: {suffix}. Use .toml or .json")
        
        # Convert failure_probabilities keys from strings to SecurityLayer enums
        if "failure_probabilities" in data:
            fp = data["failure_probabilities"]
            if isinstance(fp, dict):
                data["failure_probabilities"] = {
                    SecurityLayer(k.lower()): v for k, v in fp.items()
                }
        
        # Ensure required fields are present
        if "id" not in data:
            raise ValueError("Required field 'id' missing from config")
        if "name" not in data:
            raise ValueError("Required field 'name' missing from config")
        
        return cls(**data)


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
