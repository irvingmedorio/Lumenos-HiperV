#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LUMENOS SANDBOX PACKAGE
Sistema de Aislamiento Multinivel para Pruebas de Malware en Windows

Autor: Irvin Diaz Medorio
Version: 2.0.0 (refactored from monolith)
"""

import os
import logging
from pathlib import Path

# Configuración de logging (anchored to this package's location)
_LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(_LOG_DIR / "lumenos_sandbox.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Re-export everything from sub-modules
from .types import (
    BunkerState,
    SecurityLayer,
    ThreatLevel,
    EscapeAttemptType,
    VALID_STATE_TRANSITIONS,
    LAYER_FAILURE_PROBABILITY,
    _component_baseline_digest,
    BunkerConfig,
    SecurityEvent,
    IntegrityCheck,
    DecontaminationReport,
    BunkerMetrics,
)

from .exceptions import (
    LumenosException,
    InvalidStateTransition,
    SecurityViolation,
    EscapeAttempt,
    DecontaminationFailure,
    IntegrityCheckFailure,
    BunkerNotReady,
)

from .monitoring import IntegrityVerifier, SecurityMonitor

from .layers import (
    SecurityLayerBase,
    NetworkSecurityLayer,
    FilesystemSecurityLayer,
    ProcessSecurityLayer,
    MemorySecurityLayer,
    HypervisorSecurityLayer,
)

from .bunker import Bunker, get_state_store, set_state_store
from .manager import DualBunkerManager
from .state import BunkerStateStore
from .observability import JSONFormatter, MetricsCollector, check_health
from .forensics import EvidenceItem, EvidenceChain, collect_evidence, export_evidence
from .compliance import Control, AuditLog, ComplianceReport, ControlStatus
from .resource_manager import ResourceManager, ResourceProfile, VMResourceAlloc, HostResources
from .gpu import GPUPassthrough, GPUDevice, GPUVendor
from .image_builder import ImageBuilder, VMImage, ImageLayer, ImageType, ImageStatus

__all__ = [
    # Enumerations
    "BunkerState",
    "SecurityLayer",
    "ThreatLevel",
    "EscapeAttemptType",
    # Constants
    "VALID_STATE_TRANSITIONS",
    "LAYER_FAILURE_PROBABILITY",
    # Exceptions
    "LumenosException",
    "InvalidStateTransition",
    "SecurityViolation",
    "EscapeAttempt",
    "DecontaminationFailure",
    "IntegrityCheckFailure",
    "BunkerNotReady",
    # Data Classes
    "BunkerConfig",
    "SecurityEvent",
    "IntegrityCheck",
    "DecontaminationReport",
    "BunkerMetrics",
    # Core classes
    "IntegrityVerifier",
    "SecurityMonitor",
    "SecurityLayerBase",
    "NetworkSecurityLayer",
    "FilesystemSecurityLayer",
    "ProcessSecurityLayer",
    "MemorySecurityLayer",
    "HypervisorSecurityLayer",
    "Bunker",
    "DualBunkerManager",
    "BunkerStateStore",
    "get_state_store",
    "set_state_store",
    "JSONFormatter",
    "MetricsCollector",
    "check_health",
    "EvidenceItem",
    "EvidenceChain",
    "collect_evidence",
    "export_evidence",
    "Control",
    "AuditLog",
    "ComplianceReport",
    "ControlStatus",
    # Resource Management
    "ResourceManager",
    "ResourceProfile",
    "VMResourceAlloc",
    "HostResources",
    # GPU Passthrough
    "GPUPassthrough",
    "GPUDevice",
    "GPUVendor",
    # Image Builder
    "ImageBuilder",
    "VMImage",
    "ImageLayer",
    "ImageType",
    "ImageStatus",
    # Helpers
    "_component_baseline_digest",
]
