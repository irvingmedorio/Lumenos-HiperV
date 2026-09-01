#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bunker class — state machine and lifecycle."""

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from .types import (
    BunkerState, SecurityLayer, ThreatLevel, SecurityEvent,
    IntegrityCheck, DecontaminationReport, BunkerMetrics, BunkerConfig,
    VALID_STATE_TRANSITIONS, _component_baseline_digest,
)
from .exceptions import (
    InvalidStateTransition, SecurityViolation, BunkerNotReady,
)
from .monitoring import IntegrityVerifier, SecurityMonitor
from .layers import (
    SecurityLayerBase, NetworkSecurityLayer, FilesystemSecurityLayer,
    ProcessSecurityLayer, MemorySecurityLayer, HypervisorSecurityLayer,
)
from .state import BunkerStateStore
from .secrets import SecretManager
from .observability import MetricsCollector

logger = logging.getLogger('LUMENOS_SANDBOX')

# Module-level store shared across all Bunker instances (single DB file)
_state_store: Optional[BunkerStateStore] = None


def get_state_store() -> BunkerStateStore:
    """Lazy-init the shared state store."""
    global _state_store
    if _state_store is None:
        _state_store = BunkerStateStore()
    return _state_store


def set_state_store(store: BunkerStateStore) -> None:
    """Override the state store (useful for testing with temp DBs)."""
    global _state_store
    _state_store = store


class Bunker:
    """
    Bunker de aislamiento para pruebas de malware.
    Implementa todas las capas de seguridad y el ciclo de vida completo.
    """

    def __init__(self, config: BunkerConfig):
        self.config = config
        self.state = BunkerState.DESTROYED
        self.metrics = BunkerMetrics()
        self.created_at: Optional[datetime] = None
        self.activated_at: Optional[datetime] = None
        self.terminated_at: Optional[datetime] = None

        # Hyper-V resource names (set during initialization)
        self._vm_name: Optional[str] = None
        self._switch_name: Optional[str] = None

        # Observability
        self.metrics_collector = MetricsCollector()

        # Componentes de seguridad
        self.integrity_verifier = IntegrityVerifier()
        self.security_monitor = SecurityMonitor(config.id, metrics=self.metrics_collector)

        # Capas de seguridad
        self.security_layers: Dict[SecurityLayer, SecurityLayerBase] = {
            SecurityLayer.NETWORK: NetworkSecurityLayer(config.id),
            SecurityLayer.FILESYSTEM: FilesystemSecurityLayer(config.id),
            SecurityLayer.PROCESS: ProcessSecurityLayer(config.id),
            SecurityLayer.MEMORY: MemorySecurityLayer(config.id),
            SecurityLayer.HYPERVISOR: HypervisorSecurityLayer(config.id),
        }

        self._lock = threading.Lock()
        self._session_active = False

        # Per-bunker HMAC signing key for tamper-evident reports
        self._signing_key: str = secrets.token_hex(32)

        # Secrets management — store guest password in Credential Manager
        self._secret_mgr = SecretManager()
        if self.config.guest_password:
            cred_name = f"bunker_{self.config.id}_guest_password"
            self._secret_mgr.store_secret(cred_name, self.config.guest_password)
            self.config.guest_password = ""  # clear plaintext from config

    @classmethod
    def load_from_store(cls, bunker_id: str) -> Optional["Bunker"]:
        """Restore a Bunker from persisted state. Returns None if not found."""
        data = get_state_store().load(bunker_id)
        if data is None:
            return None
        config = BunkerConfig(**data["config"])
        bunker = cls(config)
        bunker.state = BunkerState[data["state"]]
        bunker._vm_name = data.get("vm_name")
        bunker._switch_name = data.get("switch_name")
        if data.get("created_at"):
            bunker.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("activated_at"):
            bunker.activated_at = datetime.fromisoformat(data["activated_at"])
        if data.get("terminated_at"):
            bunker.terminated_at = datetime.fromisoformat(data["terminated_at"])
        if data.get("signing_key"):
            bunker._signing_key = data["signing_key"]
        bunker._secret_mgr = SecretManager()
        return bunker

    def transition_to(self, new_state: BunkerState) -> bool:
        """
        Realiza una transición de estado válida.
        Lanza InvalidStateTransition si la transición no es válida.
        """
        with self._lock:
            if new_state not in VALID_STATE_TRANSITIONS.get(self.state, []):
                raise InvalidStateTransition(
                    f"Transición inválida: {self.state.name} -> {new_state.name}"
                )

            old_state = self.state
            self.state = new_state
            self.metrics_collector.inc(f"transition_{new_state.name}")
            self.metrics_collector.set_gauge("current_state", new_state.value)
            logger.info(f"Bunker {self.config.id}: {old_state.name} -> {new_state.name}")
            self._persist_state()
            return True

    def _persist_state(self):
        """Save current state to SQLite for crash recovery.

        Best-effort: if the DB is locked or disk is full,
        the failure is logged but never raised — persistence is a convenience,
        not a correctness requirement.
        """
        try:
            data = {
                "config": vars(self.config),
                "state": self.state.name,
                "vm_name": self._vm_name,
                "switch_name": self._switch_name,
                "signing_key": self._signing_key,
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "activated_at": self.activated_at.isoformat() if self.activated_at else None,
                "terminated_at": self.terminated_at.isoformat() if self.terminated_at else None,
            }
            get_state_store().save(self.config.id, data)
        except Exception as exc:
            logger.debug("Could not persist state for %s: %s", self.config.id, exc)

    def initialize(self) -> bool:
        """Inicializa el bunker desde cero."""
        try:
            self.transition_to(BunkerState.INITIALIZING)
            logger.info(f"Inicializando bunker {self.config.id}")

            self._verify_system_requirements()
            self._load_base_image()
            self._allocate_resources()
            self._initialize_integrity_baseline()

            # Enable Guest Service Interface after VM creation
            if self._vm_name:
                from .hypervisor import enable_guest_integration
                enable_guest_integration(self._vm_name)

            # Propagate VM credentials to security layers
            self._propagate_vm_credentials()

            self.created_at = datetime.now()
            self.transition_to(BunkerState.READY)
            return True

        except Exception as e:
            logger.error(f"Error inicializando bunker: {e}")
            self._cleanup_on_failure()
            self.transition_to(BunkerState.ERROR)
            return False

    def _cleanup_on_failure(self):
        """Remove Hyper-V resources created during a failed initialize()."""
        from .hypervisor import remove_vm, remove_switch
        if self._vm_name:
            try:
                remove_vm(self._vm_name, force=True)
                logger.info("Cleaned up VM %s after init failure", self._vm_name)
            except Exception as exc:
                logger.warning("Failed to clean up VM %s: %s", self._vm_name, exc)
            self._vm_name = None
        if self._switch_name:
            try:
                remove_switch(self._switch_name)
                logger.info("Cleaned up switch %s after init failure", self._switch_name)
            except Exception as exc:
                logger.warning("Failed to clean up switch %s: %s", self._switch_name, exc)
            self._switch_name = None

    def activate(self) -> bool:
        """Activa el bunker para pruebas."""
        try:
            if self.state != BunkerState.READY:
                raise BunkerNotReady(f"Bunker no está listo: {self.state.name}")

            self.transition_to(BunkerState.ACTIVE)
            logger.info(f"Activando bunker {self.config.id}")

            activated_layers = []
            for layer_type, layer in self.security_layers.items():
                if not layer.activate():
                    # Rollback: deactivate all previously activated layers
                    for prev_layer in activated_layers:
                        prev_layer.deactivate()
                    raise SecurityViolation(f"Fallo activando capa {layer_type.value}")
                activated_layers.append(layer)
                self.metrics_collector.inc(f"layer_{layer_type.value}_activated")
                logger.info(f"Capa {layer_type.value} activada")

            self.security_monitor.start_monitoring()

            self.activated_at = datetime.now()
            self._session_active = True

            self._start_metrics_collection()

            logger.info(f"Bunker {self.config.id} activado exitosamente")
            return True

        except Exception as e:
            logger.error(f"Error activando bunker: {e}")
            self.transition_to(BunkerState.ERROR)
            return False

    def terminate(self) -> bool:
        """Termina el bunker de forma controlada."""
        try:
            if self.state != BunkerState.ACTIVE:
                raise BunkerNotReady(f"Bunker no está activo: {self.state.name}")

            self.transition_to(BunkerState.TERMINATING)
            logger.info(f"Terminando bunker {self.config.id}")

            # Detener monitoreo
            self.security_monitor.stop_monitoring()

            # Deactivate all security layers
            for layer in self.security_layers.values():
                if layer.active:
                    layer.deactivate()
                    self.metrics_collector.inc("layer_deactivated")

            # Capturar snapshot forense
            self._capture_forensic_snapshot()

            # Terminar procesos
            self._terminate_processes()

            # Desconectar red
            self._disconnect_network()

            self.terminated_at = datetime.now()
            self._session_active = False

            # Iniciar descontaminación
            self.transition_to(BunkerState.DECONTAMINATING)
            return self._decontaminate()

        except Exception as e:
            logger.error(f"Error terminando bunker: {e}")
            self.transition_to(BunkerState.ERROR)
            return False

    def _decontaminate(self) -> bool:
        """Ejecuta el proceso de descontaminación."""
        logger.info(f"Iniciando descontaminación del bunker {self.config.id}")

        report = DecontaminationReport(
            bunker_id=self.config.id,
            start_time=datetime.now(),
            end_time=datetime.now(),
            steps_completed=[],
            steps_failed=[],
            integrity_checks=[],
            warnings=[],
            success=False
        )

        steps = [
            ("terminate_processes", self._step_terminate_processes),
            ("purge_memory", self._step_purge_memory),
            ("destroy_differential_disk", self._step_destroy_differential_disk),
            ("clean_network_config", self._step_clean_network_config),
            ("remove_snapshots", self._step_remove_snapshots),
            ("verify_host_integrity", self._step_verify_host_integrity),
            ("generate_report", self._step_generate_report),
        ]

        for step_name, step_func in steps:
            try:
                logger.info(f"Ejecutando paso: {step_name}")
                result = step_func()

                if result:
                    report.steps_completed.append(step_name)
                else:
                    report.steps_failed.append(step_name)
                    report.warnings.append(f"Paso {step_name} retornó False")

            except Exception as e:
                report.steps_failed.append(step_name)
                report.warnings.append(f"Error en {step_name}: {str(e)}")
                logger.error(f"Error en paso {step_name}: {e}")

        all_passed, checks = self.integrity_verifier.verify_all(
            self._get_current_component_hashes()
        )
        report.integrity_checks = checks

        report.end_time = datetime.now()
        report.success = len(report.steps_failed) == 0 and all_passed

        if report.success:
            logger.info(f"Descontaminación completada exitosamente")
            self.transition_to(BunkerState.DESTROYED)
        else:
            logger.error(f"Descontaminación falló: {report.steps_failed}")
            self.transition_to(BunkerState.ERROR)

        report.signature = self._sign_report(report)

        # Always persist the report — even on failure (forensic evidence)
        self._save_decontamination_report(report)

        return report.success

    def _save_decontamination_report(self, report: DecontaminationReport):
        """Persist decontamination report to disk.

        Best-effort: failures are logged but never raised so the caller
        is not blocked from returning its own success/failure verdict.
        """
        try:
            logs_dir = Path("logs")
            logs_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = logs_dir / f"{self.config.id}_decontamination_{ts}.json"
            report_data = {
                "bunker_id": report.bunker_id,
                "start_time": report.start_time.isoformat(),
                "end_time": report.end_time.isoformat(),
                "success": report.success,
                "steps_completed": report.steps_completed,
                "steps_failed": report.steps_failed,
                "warnings": report.warnings,
                "signature": report.signature,
                "integrity_checks": [
                    {
                        "component": c.component,
                        "passed": c.passed,
                        "details": c.details,
                        "timestamp": c.timestamp.isoformat(),
                    }
                    for c in report.integrity_checks
                ],
            }
            with open(report_path, "w") as f:
                json.dump(report_data, f, indent=2)
            logger.info("Decontamination report saved: %s", report_path)
        except Exception as exc:
            logger.warning("Could not save decontamination report: %s", exc)

    def force_quarantine(self, reason: str):
        """
        Fuerza la cuarentena del bunker ante un incidente de seguridad.
        """
        logger.critical(f"CUARENTENA FORZADA: {reason}")

        try:
            self.transition_to(BunkerState.QUARANTINE)

            self.security_monitor.stop_monitoring()

            event = SecurityEvent(
                timestamp=datetime.now(),
                layer=SecurityLayer.HYPERVISOR,
                event_type="FORCED_QUARANTINE",
                severity=ThreatLevel.CRITICAL,
                description=reason,
                bunker_id=self.config.id,
            )
            self.security_monitor.log_event(event)
            self.metrics_collector.inc("forced_quarantines")

        except Exception as e:
            logger.error(f"Error en cuarentena forzada: {e}")

    def get_escape_probability(self) -> float:
        """
        Calcula la probabilidad de escape basada en el estado de las capas.
        """
        probability = 1.0

        for layer_type, layer in self.security_layers.items():
            if layer.active:
                probability *= layer.get_failure_probability()

        return probability

    def get_full_status(self) -> Dict[str, Any]:
        """Obtiene el estado completo del bunker."""
        return {
            "config": {
                "id": self.config.id,
                "name": self.config.name,
                "memory_mb": self.config.memory_mb,
                "cpu_cores": self.config.cpu_cores,
            },
            "state": self.state.name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "terminated_at": self.terminated_at.isoformat() if self.terminated_at else None,
            "escape_probability": self.get_escape_probability(),
            "metrics": {
                "cpu_usage": self.metrics.cpu_usage,
                "memory_usage": self.metrics.memory_usage,
                "escape_attempts_blocked": self.metrics.escape_attempts_blocked,
                "uptime_seconds": self.metrics.uptime_seconds,
            },
            "security_layers": {
                layer_type.value: layer.get_status()
                for layer_type, layer in self.security_layers.items()
            },
            "security_report": self.security_monitor.get_security_report(),
            "integrity_report": self.integrity_verifier.get_verification_report(),
            "collector_metrics": self.metrics_collector.snapshot(),
        }

    # --- Private initialisation helpers ---

    def _verify_system_requirements(self):
        from .hypervisor import check_hyper_v_available
        if not check_hyper_v_available():
            raise SystemError("Hyper-V is not available on this host")
        logger.info("Hyper-V verified")

    def _load_base_image(self):
        """Load or create the base image for this bunker."""
        # For now: create a fresh VM (no base image template yet)
        # TODO(scenario-B phase 3): use pre-built golden image template
        from .hypervisor import create_internal_switch
        self._switch_name = f"lumenos_{self.config.id}_switch"
        create_internal_switch(self._switch_name)

    def _allocate_resources(self):
        from .hypervisor import create_vm
        from pathlib import Path
        vm_name = f"bunker_{self.config.id}"
        diff_vhd = str(Path("snapshots") / f"{self.config.id}_system.vhdx")
        Path("snapshots").mkdir(parents=True, exist_ok=True)
        success = create_vm(
            vm_name=vm_name,
            memory_mb=self.config.memory_mb,
            cpu_cores=self.config.cpu_cores,
            vhd_path=diff_vhd,
            switch_name=self._switch_name,
        )
        if not success:
            raise SystemError(f"Failed to create VM for bunker {self.config.id}")
        self._vm_name = vm_name
        logger.info(f"VM {vm_name} allocated: {self.config.memory_mb}MB, {self.config.cpu_cores} CPUs")

    def _initialize_integrity_baseline(self):
        for component in IntegrityVerifier.CRITICAL_COMPONENTS:
            self.integrity_verifier.set_baseline(
                component,
                _component_baseline_digest(component)
            )

    def _get_guest_password(self) -> str:
        """Retrieve guest password from Windows Credential Manager."""
        cred_name = f"bunker_{self.config.id}_guest_password"
        return self._secret_mgr.get_secret(cred_name) or ""

    def _propagate_vm_credentials(self):
        """Set VM name and guest credentials on all security layers and the monitor."""
        guest_password = self._get_guest_password()
        for layer in self.security_layers.values():
            layer.set_vm_credentials(
                self._vm_name or "",
                self.config.guest_username,
                guest_password,
            )
        self.security_monitor.set_vm_credentials(
            self._vm_name or "",
            self.config.guest_username,
            guest_password,
        )

    # --- Private activation helpers ---

    def _start_metrics_collection(self):
        def collect():
            while self._session_active:
                self.metrics.uptime_seconds += 1
                self.metrics_collector.set_gauge("uptime_seconds", self.metrics.uptime_seconds)
                time.sleep(1)

        threading.Thread(target=collect, daemon=True).start()

    # --- Private termination helpers ---

    def _capture_forensic_snapshot(self):
        from .hypervisor import create_checkpoint
        if self._vm_name:
            snapshot_name = f"forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            create_checkpoint(self._vm_name, snapshot_name)

    def _terminate_processes(self):
        from .hypervisor import stop_vm
        if self._vm_name:
            stop_vm(self._vm_name, force=True)

    def _disconnect_network(self):
        # Decontamination handles full switch cleanup
        pass

    # --- Decontamination steps ---

    def _step_terminate_processes(self) -> bool:
        """Paso: terminar procesos (VM already stopped in _terminate_processes)."""
        from .hypervisor import get_vm_status
        if not self._vm_name:
            return True
        status = get_vm_status(self._vm_name)
        return status is None or status.lower() in ("off", "saved")

    def _step_purge_memory(self) -> bool:
        """Paso: purgar memoria (VM memory is freed when VM is off)."""
        return True  # Memory is freed when VM is stopped

    def _step_destroy_differential_disk(self) -> bool:
        """Paso: destruir disco diferencial."""
        from .hypervisor import delete_file
        from pathlib import Path
        diff_vhd = str(Path("snapshots") / f"{self.config.id}_system.vhdx")
        return delete_file(diff_vhd)

    def _step_clean_network_config(self) -> bool:
        """Paso: limpiar configuración de red."""
        from .hypervisor import remove_switch
        return remove_switch(f"lumenos_{self.config.id}_switch")

    def _step_remove_snapshots(self) -> bool:
        """Paso: eliminar snapshots (remove VM with all disks)."""
        from .hypervisor import remove_vm
        if not self._vm_name:
            return True
        return remove_vm(self._vm_name, force=True)

    def _step_verify_host_integrity(self) -> bool:
        """Paso: verificar integridad del host + forensic evidence from guest."""
        from .hypervisor import verify_host_integrity
        success, _ = verify_host_integrity()

        # Collect forensic evidence from guest event log if VM is still accessible
        if self._vm_name and self.config.guest_username:
            try:
                from .hypervisor import read_guest_event_log
                events = read_guest_event_log(
                    self._vm_name,
                    self.config.guest_username,
                    self._get_guest_password(),
                    log_name="Security",
                    max_events=50,
                )
                if events:
                    findings = self.security_monitor.analyze_event_log(events)
                    for finding in findings:
                        logger.warning("Forensic finding: %s", finding)
            except Exception as exc:
                logger.debug("Could not read guest event log: %s", exc)

        return success

    def _step_generate_report(self) -> bool:
        """Paso: generar reporte."""
        return True  # Report generation is handled by _decontaminate

    def _get_current_component_hashes(self) -> Dict[str, str]:
        return {
            component: _component_baseline_digest(component)
            for component in IntegrityVerifier.CRITICAL_COMPONENTS
        }

    def _sign_report(self, report: DecontaminationReport) -> str:
        data = f"{report.bunker_id}{report.start_time}{report.end_time}{report.success}"
        return hmac.new(
            bytes.fromhex(self._signing_key),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify_report_signature(self, report: DecontaminationReport) -> bool:
        """Verify a report's signature is authentic (not forged)."""
        expected = self._sign_report(report)
        return hmac.compare_digest(expected, report.signature)
